//! Periodic bidirectional sync with the shared network database.
//!
//! This is a port of `netdb_sync_once` from minecraft-server-scanner's
//! `scanner.py`. It uploads rows with `needs_sync = 1`, then pages through
//! `/api/sync` to download rows other clients found and merges them locally.
//!
//! The shared-DB URL and token come from the scanner's `netdb.json`; matscan
//! does not store any credentials of its own.

use std::{collections::HashMap, net::Ipv4Addr, path::Path, time::Duration};

use eyre::bail;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{QueryBuilder, Row, Sqlite, sqlite::SqliteRow};
use tracing::{debug, info};

use crate::database::{
    Database, decode_player_list, encode_player_list, merge_name_lists, sanitize_text,
    truncate_chars,
};

const NETDB_MAX_UPLOAD: i64 = 20_000;
const NETDB_PAGE_SIZE: usize = 50_000;
const NETDB_MAX_ROUNDS: usize = 500;
const NETDB_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct NetdbConfig {
    #[serde(default)]
    url: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    last_sync: f64,
    #[serde(default)]
    last_seq: i64,
}

#[derive(Debug, Default)]
pub struct SyncSummary {
    pub uploaded: usize,
    pub merged_on_server: i64,
    pub downloaded: usize,
    pub inserted: usize,
    pub updated: usize,
    pub total_remote: i64,
}

struct DirtyBatch {
    rows: Vec<Value>,
    ip_ports: Vec<String>,
    watermark: f64,
}

fn load_config(path: &Path) -> NetdbConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(path: &Path, cfg: &NetdbConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(path, s);
    }
}

/// Sync once. Returns `None` when no shared-DB URL/token is configured.
pub async fn sync_once(db: &Database, netdb_path: &Path) -> eyre::Result<Option<SyncSummary>> {
    let mut cfg = load_config(netdb_path);

    let url = cfg.url.trim().trim_end_matches('/').to_string();
    let token = cfg.token.trim().to_string();
    if url.is_empty() || token.is_empty() {
        debug!(
            "shared-DB sync skipped: no url/token in {}",
            netdb_path.display()
        );
        return Ok(None);
    }

    let client = reqwest::Client::builder().timeout(NETDB_TIMEOUT).build()?;

    let mut summary = SyncSummary::default();
    let since = cfg.last_sync;

    // --- upload: batch until no dirty rows remain ---
    let mut last_watermark = None;
    for _ in 0..NETDB_MAX_ROUNDS {
        let Some(batch) = collect_dirty(db).await? else {
            break;
        };
        last_watermark = Some(batch.watermark);

        let payload = json!({ "servers": batch.rows, "since": since });
        let resp = post(&client, &url, &token, &payload).await?;
        if let Some(merged) = json_i64_opt(&resp, "merged") {
            summary.merged_on_server += merged;
        }

        // Upload accepted: clear flags on rows unchanged since collection.
        mark_synced(db, &batch.ip_ports, batch.watermark).await?;

        let uploaded = batch.rows.len();
        summary.uploaded += uploaded;
        if uploaded < NETDB_MAX_UPLOAD as usize {
            break;
        }
    }

    // --- download: page until drained ---
    let mut remote_by_ip: HashMap<String, Value> = HashMap::new();
    let mut now = chrono::Utc::now().timestamp() as f64;
    let mut use_seq = false;
    let mut new_seq = cfg.last_seq;
    let mut cursor_seq = cfg.last_seq;
    let mut cursor = since;

    for _ in 0..NETDB_MAX_ROUNDS {
        let payload = json!({ "servers": [], "since": cursor, "since_seq": cursor_seq });
        let resp = post(&client, &url, &token, &payload).await?;

        if let Some(total) = json_i64_opt(&resp, "total") {
            summary.total_remote = total;
        }
        if let Some(server_now) = json_f64_opt(&resp, "now") {
            now = server_now;
        }
        if resp
            .get("has_seq")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            use_seq = true;
        }

        let batch = resp
            .get("servers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if batch.is_empty() {
            break;
        }

        let mut fresh = 0usize;
        let mut top_ts = cursor;
        let mut top_seq = cursor_seq;
        for r in &batch {
            if use_seq {
                let seq = json_i64_opt(r, "seq").unwrap_or(0);
                if seq > top_seq {
                    top_seq = seq;
                }
            } else {
                let ts = json_f64_opt(r, "last_seen").unwrap_or(0.0);
                if ts > top_ts {
                    top_ts = ts;
                }
            }
            if let Some(ip) = r.get("ip_port").and_then(Value::as_str)
                && !ip.is_empty()
            {
                if !remote_by_ip.contains_key(ip) {
                    fresh += 1;
                }
                remote_by_ip.insert(ip.to_string(), r.clone());
            }
        }

        if use_seq {
            // seq is unique per change, so advance exactly with no overlap.
            if top_seq <= cursor_seq {
                break;
            }
            cursor_seq = top_seq;
            if top_seq > new_seq {
                new_seq = top_seq;
            }
            if batch.len() < NETDB_PAGE_SIZE || fresh == 0 {
                break;
            }
            continue;
        }

        if batch.len() < NETDB_PAGE_SIZE || fresh == 0 {
            break;
        }

        // Back off 1ms only when the top timestamp is shared; a later page may
        // still hold unseen rows with it.
        let ties = batch
            .iter()
            .filter(|r| json_f64_opt(r, "last_seen").unwrap_or(0.0) == top_ts)
            .count();
        let next = if ties > 1 { top_ts - 0.001 } else { top_ts };
        if next <= cursor {
            break;
        }
        cursor = next;
    }

    let remote_all: Vec<Value> = remote_by_ip.into_values().collect();
    let (inserted, updated) = merge_remote(db, &remote_all, last_watermark).await?;

    summary.downloaded = remote_all.len();
    summary.inserted = inserted;
    summary.updated = updated;

    cfg.url = url;
    cfg.token = token;
    cfg.last_sync = now;
    if use_seq {
        cfg.last_seq = new_seq;
    }
    save_config(netdb_path, &cfg);

    Ok(Some(summary))
}

async fn post(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    payload: &Value,
) -> eyre::Result<Value> {
    let full_url = format!("{base_url}/api/sync");
    let body = serde_json::to_vec(payload)?;

    let parsed = reqwest::Url::parse(&full_url)?;
    let mut path = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let body_hash = hex(&Sha256::digest(&body));
    let message = format!("POST\n{path}\n{timestamp}\n{nonce}\n{body_hash}");
    let signature = hex(&hmac_sha256(token.as_bytes(), message.as_bytes()));

    let resp = client
        .post(&full_url)
        .header("User-Agent", "MC-Scanner")
        .header("Content-Type", "application/json")
        .header("X-Auth-Timestamp", timestamp)
        .header("X-Auth-Nonce", nonce)
        .header("Authorization", format!("HMAC {signature}"))
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;

    if !status.is_success() {
        if status.as_u16() == 401 {
            bail!("shared-DB sync rejected: wrong token?");
        }
        if status.as_u16() == 429 {
            bail!("shared-DB sync throttled: too many failed logins, wait a minute");
        }
        bail!(
            "shared-DB sync HTTP {}: {}",
            status.as_u16(),
            truncate_chars(&text, 200)
        );
    }

    if text.is_empty() {
        return Ok(json!({}));
    }
    Ok(serde_json::from_str(&text)?)
}

async fn collect_dirty(db: &Database) -> eyre::Result<Option<DirtyBatch>> {
    let rows = sqlx::query(
        "
        SELECT ip_port, host, port, motd, players_online, max_players, version,
               protocol, cracked, whitelist, first_seen, last_seen, times_seen,
               last_source, players_now, players_ever
        FROM servers
        WHERE needs_sync = 1
        ORDER BY last_seen ASC
        LIMIT ?
        ",
    )
    .bind(NETDB_MAX_UPLOAD)
    .fetch_all(&db.pool)
    .await?;

    if rows.is_empty() {
        return Ok(None);
    }

    let mut values = Vec::with_capacity(rows.len());
    let mut ip_ports = Vec::with_capacity(rows.len());
    let mut watermark: f64 = 0.0;

    for row in &rows {
        let ip_port = row_string(row, 0);
        let last_seen = row_f64(row, 11);
        watermark = watermark.max(last_seen);

        values.push(json!({
            "ip_port": ip_port,
            "host": row_string(row, 1),
            "port": row_i64(row, 2),
            "motd": row_string(row, 3),
            "players_online": row_i64(row, 4),
            "max_players": row_i64(row, 5),
            "version": row_string(row, 6),
            "protocol": row_opt_i64(row, 7),
            "cracked": row_string(row, 8),
            "whitelist": row_string(row, 9),
            "first_seen": row_f64(row, 10),
            "last_seen": last_seen,
            "times_seen": row_i64(row, 12),
            "last_source": row_string(row, 13),
            "players_now": row_string(row, 14),
            "players_ever": row_string(row, 15),
        }));
        ip_ports.push(ip_port);
    }

    Ok(Some(DirtyBatch {
        rows: values,
        ip_ports,
        watermark,
    }))
}

/// Clear the dirty flag on uploaded rows that haven't changed since collection.
async fn mark_synced(db: &Database, ip_ports: &[String], watermark: f64) -> eyre::Result<()> {
    for chunk in ip_ports.chunks(500) {
        let mut qb: QueryBuilder<'_, Sqlite> = QueryBuilder::new(
            "UPDATE servers SET needs_sync = 0 WHERE needs_sync = 1 AND last_seen <= ",
        );
        qb.push_bind(watermark);
        qb.push(" AND ip_port IN (");
        let mut separated = qb.separated(", ");
        for ip in chunk {
            separated.push_bind(ip);
        }
        separated.push_unseparated(")");
        qb.build().execute(&db.write_pool).await?;
    }
    Ok(())
}

async fn merge_remote(
    db: &Database,
    servers: &[Value],
    upload_watermark: Option<f64>,
) -> eyre::Result<(usize, usize)> {
    if servers.is_empty() {
        return Ok((0, 0));
    }

    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut pending = 0usize;
    let mut txn = db.write_pool.begin().await?;

    for raw in servers {
        let ip_port = json_str(raw, "ip_port");
        let Some((ip, port)) = parse_ip_port(ip_port) else {
            continue;
        };
        if is_bogon(ip) {
            continue;
        }
        let host = ip.to_string();

        let r_first = json_f64(raw, "first_seen", 0.0);
        let r_last = json_f64(raw, "last_seen", 0.0);
        let r_times = json_i64(raw, "times_seen", 1).max(1);
        let r_now = remote_player_list(raw, "players_now");
        let r_ever = remote_player_list(raw, "players_ever");

        let old = sqlx::query(
            "
            SELECT motd, players_online, max_players, version, protocol,
                   cracked, whitelist, first_seen, last_seen, times_seen,
                   last_source, needs_sync, players_now, players_ever
            FROM servers WHERE ip_port = ?
            ",
        )
        .bind(ip_port)
        .fetch_optional(&mut *txn)
        .await?;

        let Some(old) = old else {
            let first_seen = if r_first != 0.0 { r_first } else { r_last };
            let last_seen = if r_last != 0.0 { r_last } else { r_first };
            let res = sqlx::query(
                "
                INSERT OR IGNORE INTO servers (
                    ip_port, host, port, motd, players_online, max_players,
                    version, protocol, cracked, whitelist, first_seen,
                    last_seen, times_seen, last_source, needs_sync,
                    players_now, players_ever
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                ",
            )
            .bind(ip_port)
            .bind(&host)
            .bind(port as i64)
            .bind(truncate_chars(&sanitize_text(json_str(raw, "motd")), 500))
            .bind(json_i64(raw, "players_online", 0))
            .bind(json_i64(raw, "max_players", 0))
            .bind(truncate_chars(
                &sanitize_text(json_str(raw, "version")),
                100,
            ))
            .bind(json_opt_i64(raw, "protocol"))
            .bind(json_str(raw, "cracked"))
            .bind(json_str(raw, "whitelist"))
            .bind(first_seen)
            .bind(last_seen)
            .bind(r_times)
            .bind(non_empty_or(json_str(raw, "last_source"), "netdb"))
            .bind(encode_player_list(&r_now))
            .bind(encode_player_list(&r_ever))
            .execute(&mut *txn)
            .await?;

            if res.rows_affected() > 0 {
                inserted += 1;
            } else {
                // Appeared locally mid-sync; keep it dirty so it uploads next.
                sqlx::query("UPDATE servers SET needs_sync = 1 WHERE ip_port = ?")
                    .bind(ip_port)
                    .execute(&mut *txn)
                    .await?;
                updated += 1;
            }

            pending += 1;
            if pending >= 1000 {
                txn.commit().await?;
                txn = db.write_pool.begin().await?;
                pending = 0;
            }
            continue;
        };

        let o_motd = row_string(&old, 0);
        let o_on = row_i64(&old, 1);
        let o_max = row_i64(&old, 2);
        let o_ver = row_string(&old, 3);
        let o_proto = row_opt_i64(&old, 4);
        let o_cracked = row_string(&old, 5);
        let o_wl = row_string(&old, 6);
        let o_first = row_f64(&old, 7);
        let o_last = row_f64(&old, 8);
        let o_times = row_i64(&old, 9);
        let o_src = row_string(&old, 10);
        let o_dirty = row_i64(&old, 11);
        let o_now = row_string(&old, 12);
        let o_ever = row_string(&old, 13);

        let remote_newer = r_last > o_last;
        let first_seen = if o_first != 0.0 && r_first != 0.0 {
            o_first.min(r_first)
        } else if o_first != 0.0 {
            o_first
        } else {
            r_first
        };
        let last_seen = o_last.max(r_last);

        let (motd, online, maximum, version, protocol, src) = if remote_newer {
            (
                truncate_chars(&sanitize_text(json_str(raw, "motd")), 500),
                json_i64(raw, "players_online", 0),
                json_i64(raw, "max_players", 0),
                truncate_chars(&sanitize_text(json_str(raw, "version")), 100),
                json_opt_i64(raw, "protocol"),
                non_empty_or(json_str(raw, "last_source"), "netdb").to_string(),
            )
        } else {
            (o_motd, o_on, o_max, o_ver, o_proto, o_src)
        };

        let r_cracked = json_str(raw, "cracked");
        let cracked = if o_cracked == "Yes" || o_cracked == "Yes (cached)" {
            o_cracked.clone()
        } else if remote_newer && !r_cracked.is_empty() {
            r_cracked.to_string()
        } else if !o_cracked.is_empty() {
            o_cracked.clone()
        } else {
            r_cracked.to_string()
        };

        let r_wl = json_str(raw, "whitelist");
        let whitelist = if remote_newer && !r_wl.is_empty() {
            r_wl.to_string()
        } else if !o_wl.is_empty() {
            o_wl.clone()
        } else {
            r_wl.to_string()
        };

        let times_seen = o_times.max(r_times) + i64::from(remote_newer);

        let o_now_names = decode_player_list(&o_now);
        let o_ever_names = decode_player_list(&o_ever);
        let now_names = if remote_newer {
            r_now.clone()
        } else {
            o_now_names.clone()
        };
        let old_union = merge_name_lists(&o_ever_names, &o_now_names);
        let remote_union = merge_name_lists(&r_ever, &r_now);
        let ever_names = merge_name_lists(&old_union, &remote_union);

        let still_dirty = match upload_watermark {
            None => i64::from(o_dirty != 0),
            Some(watermark) => i64::from(o_last > watermark),
        };

        sqlx::query(
            "
            UPDATE servers SET
                host = ?, port = ?, motd = ?, players_online = ?,
                max_players = ?, version = ?, protocol = COALESCE(?, protocol),
                cracked = ?, whitelist = ?, first_seen = ?, last_seen = ?,
                times_seen = ?, last_source = ?, needs_sync = ?,
                players_now = ?, players_ever = ?
            WHERE ip_port = ?
            ",
        )
        .bind(&host)
        .bind(port as i64)
        .bind(&motd)
        .bind(online)
        .bind(maximum)
        .bind(&version)
        .bind(protocol)
        .bind(&cracked)
        .bind(&whitelist)
        .bind(first_seen)
        .bind(last_seen)
        .bind(times_seen)
        .bind(&src)
        .bind(still_dirty)
        .bind(encode_player_list(&now_names))
        .bind(encode_player_list(&ever_names))
        .bind(ip_port)
        .execute(&mut *txn)
        .await?;

        updated += 1;
        pending += 1;
        if pending >= 1000 {
            txn.commit().await?;
            txn = db.write_pool.begin().await?;
            pending = 0;
        }
    }

    txn.commit().await?;
    Ok((inserted, updated))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn json_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn json_i64(value: &Value, key: &str, default: i64) -> i64 {
    json_i64_opt(value, key).unwrap_or(default)
}

fn json_i64_opt(value: &Value, key: &str) -> Option<i64> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(v) => v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)),
    }
}

fn json_f64(value: &Value, key: &str, default: f64) -> f64 {
    json_f64_opt(value, key).unwrap_or(default)
}

fn json_f64_opt(value: &Value, key: &str) -> Option<f64> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(v) => v.as_f64(),
    }
}

fn json_opt_i64(value: &Value, key: &str) -> Option<i64> {
    json_i64_opt(value, key)
}

fn remote_player_list(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::String(s)) => decode_player_list(s),
        Some(Value::Array(_)) => {
            let json = serde_json::to_string(value.get(key).unwrap()).unwrap_or_default();
            decode_player_list(&json)
        }
        _ => Vec::new(),
    }
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn parse_ip_port(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (host, port) = s.split_once(':')?;
    if port.contains(':') {
        return None;
    }
    let ip = host.parse::<Ipv4Addr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    Some((ip, port))
}

/// Same bogon ranges minecraft-server-scanner refuses to import.
fn is_bogon(ip: Ipv4Addr) -> bool {
    const BOGONS: &[(u32, u32)] = &[
        (0x0000_0000, 0x00FF_FFFF), // 0.0.0.0/8
        (0x0A00_0000, 0x0AFF_FFFF), // 10.0.0.0/8
        (0x7F00_0000, 0x7FFF_FFFF), // 127.0.0.0/8
        (0xA9FE_0000, 0xA9FE_FFFF), // 169.254.0.0/16
        (0xAC10_0000, 0xAC1F_FFFF), // 172.16.0.0/12
        (0xC000_0000, 0xC000_00FF), // 192.0.0.0/24
        (0xC000_0200, 0xC000_02FF), // 192.0.2.0/24
        (0xC058_6300, 0xC058_63FF), // 192.88.99.0/24
        (0xC0A8_0000, 0xC0A8_FFFF), // 192.168.0.0/16
        (0xC612_0000, 0xC613_FFFF), // 198.18.0.0/15
        (0xC633_6400, 0xC633_64FF), // 198.51.100.0/24
        (0xCB00_7100, 0xCB00_71FF), // 203.0.113.0/24
        (0xE000_0000, 0xEFFF_FFFF), // 224.0.0.0/4
        (0xF000_0000, 0xFFFF_FFFF), // 240.0.0.0/4 + broadcast
    ];
    let n = u32::from(ip);
    BOGONS.iter().any(|&(lo, hi)| n >= lo && n <= hi)
}

fn row_string(row: &SqliteRow, index: usize) -> String {
    row.try_get::<Option<String>, _>(index)
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn row_i64(row: &SqliteRow, index: usize) -> i64 {
    if let Ok(Some(v)) = row.try_get::<Option<i64>, _>(index) {
        return v;
    }
    if let Ok(Some(v)) = row.try_get::<Option<f64>, _>(index) {
        return v as i64;
    }
    0
}

fn row_f64(row: &SqliteRow, index: usize) -> f64 {
    if let Ok(Some(v)) = row.try_get::<Option<f64>, _>(index) {
        return v;
    }
    if let Ok(Some(v)) = row.try_get::<Option<i64>, _>(index) {
        return v as f64;
    }
    0.0
}

fn row_opt_i64(row: &SqliteRow, index: usize) -> Option<i64> {
    if let Ok(Some(v)) = row.try_get::<Option<i64>, _>(index) {
        return Some(v);
    }
    if let Ok(Some(v)) = row.try_get::<Option<f64>, _>(index) {
        return Some(v as i64);
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// HMAC-SHA256, implemented here so we don't need another dependency.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;

    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

/// Log the result of a sync. Kept here so the caller doesn't need the fields.
pub fn log_summary(summary: &SyncSummary) {
    info!(
        "shared-DB sync: uploaded {} downloaded {} inserted {} updated {}",
        summary.uploaded, summary.downloaded, summary.inserted, summary.updated
    );
}
