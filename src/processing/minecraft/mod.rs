pub mod anti_abuse;
pub mod passive_fingerprint;
pub mod snipe;

use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::SocketAddrV4,
    sync::Arc,
};

use eyre::bail;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::Digest;
use simd_json::derived::{ValueObjectAccess, ValueObjectAccessAsArray, ValueObjectAccessAsScalar};
use sqlx::Row;
use tracing::warn;
use uuid::Uuid;

use super::{ProcessableProtocol, SharedData};
use crate::{
    config::Config,
    database::{CachedIpHash, Database, sanitize_text, truncate_chars},
    processing::minecraft::{
        passive_fingerprint::{PassiveMinecraftFingerprint, generate_passive_fingerprint},
        snipe::maybe_log_sniped,
    },
    scanner::protocols,
};

pub struct PingResponse {
    pub description_json: String,
    pub description_plaintext: String,
    pub version_name: Option<String>,
    pub version_protocol: Option<i32>,

    pub favicon: Option<String>,
    pub favicon_hash: Option<[u8; 16]>,

    pub online_players: Option<i32>,
    pub max_players: Option<i32>,
    pub is_online_mode: Option<bool>,
    pub player_sample: Vec<SamplePlayer>,
    /// Whether the sample doesn't seem real and should be ignored when
    /// inserting historical players.
    pub is_fake_sample: bool,

    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,

    pub fingerprint: PassiveMinecraftFingerprint,

    // non-vanilla fields

    // nochatreports and similar mods
    pub prevents_chat_reports: Option<bool>,
    // forge
    pub forgedata_fml_network_version: Option<i32>,
    // old forge servers
    pub modinfo_type: Option<String>,
    // neoforged
    pub is_modded: Option<bool>,
    // bettercompatibilitychecker
    pub modpackdata_project_id: Option<i32>,
    pub modpackdata_name: Option<String>,
    pub modpackdata_version: Option<String>,
}
#[derive(Clone)]
pub struct SamplePlayer {
    pub name: String,
    pub uuid: Uuid,
}

pub const ANONYMOUS_PLAYER_NAME: &str = "Anonymous Player";

impl ProcessableProtocol for protocols::Minecraft {
    async fn handle_response(
        shared: Arc<Mutex<SharedData>>,
        config: Arc<Config>,
        target: SocketAddrV4,
        data: Box<[u8]>,
        db: Database,
    ) -> eyre::Result<()> {
        let ping_res = parse_ping_response_json(&data)?;

        if !anti_abuse::should_insert(&ping_res) {
            bail!("Disallowed server response")
        }
        if let Some(&allowed_port) = db
            .shared
            .lock()
            .aliased_ips_to_allowed_port
            .get(target.ip())
            && target.port() != allowed_port
        {
            bail!("Aliased server on disallowed port");
        }

        if config.snipe.enabled {
            maybe_log_sniped(&shared, &config, target, &db, &ping_res);
        }

        insert_server_to_db(&db, &target, &ping_res).await
    }
}

pub fn parse_ping_response_json(d: &[u8]) -> eyre::Result<PingResponse> {
    let d = String::from_utf8_lossy(d);
    let d = sanitize_text(&d);
    let fingerprint = generate_passive_fingerprint(&d)?;
    let mut d = d.into_bytes();

    let v = match simd_json::to_owned_value(&mut d) {
        Ok(v) => v,
        Err(_) => {
            bail!("Failed to parse JSON: {:?}", String::from_utf8_lossy(&d));
        }
    };

    let description = v.get("description");
    let description_json = sanitize_text(&simd_json::to_string(&description)?);
    let description_plaintext = description
        .map(|description| {
            sanitize_text(
                &azalea_chat::FormattedText::deserialize(description)
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .unwrap_or_default();

    let version = v.get("version");
    let version_name = version.get_str("name").map(sanitize_text);
    let version_protocol = version.get_i32("protocol");

    let favicon = v.get_str("favicon").map(sanitize_text);
    // filter out bad favicons
    let favicon = favicon.filter(|f| f.starts_with("data:image/png;base64,"));
    let favicon_hash = favicon.as_ref().map(|s| make_favicon_hash(s));

    let players = v.get("players");

    if description.is_none() && version.is_none() && players.is_none() {
        // some servers are missing one of these fields (even description isn't
        // technically required), but if they're missing all three then it's
        // probably not even a minecraft server

        bail!("Missing description, version, and players fields");
    }

    let online_players = players.get_i32("online");
    let max_players = players.get_i32("max");
    let mut is_online_mode = None;
    let mut seen_uuids = HashSet::new();

    // servers with this motd randomize the online players
    let mut is_fake_sample = description_plaintext
        == "To protect the privacy of this server and its\nusers, you must log in once to see ping data.";

    let player_sample = players
        .get_array("sample")
        .map(|a| {
            a.iter()
                .filter_map(|v| {
                    let Some(name) = v.get_str("name").map(sanitize_text) else {
                        // name is required
                        is_fake_sample = true;
                        return None;
                    };
                    let uuid_str = v.get_str("id");
                    let Some(uuid) = uuid_str.and_then(|s| Uuid::parse_str(s).ok()) else {
                        // uuid is required
                        is_fake_sample = true;
                        return None;
                    };
                    if seen_uuids.contains(&uuid) {
                        // no duplicate uuids allowed
                        is_fake_sample = true;
                        return None;
                    }
                    seen_uuids.insert(uuid);

                    // uuidv4
                    match uuid.get_version_num() {
                        4 => is_online_mode = Some(true),
                        3 => {
                            if is_online_mode.is_none() {
                                is_online_mode = Some(false);
                            }
                        }
                        _ if uuid.is_nil() && name == ANONYMOUS_PLAYER_NAME => {
                            // anonymous player doesn't give us any info
                        }
                        _ => is_fake_sample = true,
                    }

                    Some(SamplePlayer { name, uuid })
                })
                .collect()
        })
        .unwrap_or_default();

    let previews_chat = v.get_bool("previewsChat");
    let enforces_secure_chat = v.get_bool("enforcesSecureChat");

    let prevents_chat_reports = v.get_bool("preventsChatReports");
    let forge_data = v.get("forgeData");
    let forgedata_fml_network_version = forge_data.get_i32("fmlNetworkVersion");
    let mod_info = v.get("modinfo");
    let modinfo_type = mod_info.get_str("type").map(sanitize_text);
    let is_modded = v.get_bool("isModded");
    let modpack_data = v.get("modpackData");
    let modpackdata_project_id = modpack_data.get_i32("projectID");
    let modpackdata_name = modpack_data.get_str("name").map(sanitize_text);
    let modpackdata_version = modpack_data.get_str("version").map(sanitize_text);

    Ok(PingResponse {
        description_json,
        description_plaintext,

        version_name,
        version_protocol,
        favicon,
        favicon_hash,

        online_players,
        max_players,
        player_sample,
        is_online_mode,
        is_fake_sample,

        enforces_secure_chat,

        fingerprint,

        previews_chat,
        prevents_chat_reports,
        forgedata_fml_network_version,
        modinfo_type,
        is_modded,
        modpackdata_project_id,
        modpackdata_name,
        modpackdata_version,
    })
}

pub async fn insert_server_to_db(
    db: &Database,
    target: &SocketAddrV4,
    r: &PingResponse,
) -> eyre::Result<()> {
    let mut is_aliased_server = false;
    {
        let mut shared = db.shared.lock();
        let ips_with_same_hash = shared.ip_to_hash_and_ports.get_mut(target.ip());
        if let Some((data, previously_checked_ports)) = ips_with_same_hash {
            if !previously_checked_ports.contains(&target.port())
                && let Some(count) = &mut data.count
            {
                let this_server_hash = make_ping_response_hash(r)?;

                if this_server_hash == data.hash {
                    *count += 1;
                    previously_checked_ports.insert(target.port());

                    if *count >= 100 {
                        // too many servers with the same hash so add to aliased
                        // servers
                        warn!("found a new aliased server: {} :(", target.ip());
                        // we call add_to_ips_with_aliased_servers later
                        is_aliased_server = true;
                    }
                } else {
                    // this server has a different hash than the other servers
                    // with the same IP
                    data.count = None;
                }
            }
        } else {
            let this_server_hash = make_ping_response_hash(r)?;
            shared.ip_to_hash_and_ports.insert(
                *target.ip(),
                (
                    CachedIpHash {
                        count: Some(1),
                        hash: this_server_hash,
                    },
                    HashSet::from_iter(vec![target.port()]),
                ),
            );
        }
    }

    if is_aliased_server {
        let db = db.clone();
        let target = *target;
        tokio::spawn(async move {
            let _ = db
                // for now, assume 25565 is the only allowed port. might change this in the future.
                .add_to_ips_with_aliased_servers(*target.ip(), 25565)
                .await;
        });
        bail!("Aliased server: {target:?}");
    }

    let ip_port = format!("{}:{}", target.ip(), target.port());
    let host = target.ip().to_string();
    let now = chrono::Utc::now().timestamp() as f64;

    // These limits match minecraft-server-scanner so neither program can bloat
    // the shared database with a hostile server response.
    let motd = truncate_chars(&sanitize_text(&r.description_plaintext), 500);
    let version = truncate_chars(
        &sanitize_text(r.version_name.as_deref().unwrap_or_default()),
        100,
    );
    let online_players = r.online_players.unwrap_or(0).max(0) as i64;
    let max_players = r.max_players.unwrap_or(0).max(0) as i64;
    let protocol = r.version_protocol.map(i64::from);

    // Passive offline-mode detection: offline servers hand out v3 uuids.
    let cracked = match r.is_online_mode {
        Some(false) => Some("Yes"),
        Some(true) => Some("No"),
        None => None,
    };

    let sample_names = sorted_unique_names(r.player_sample.iter().map(|p| p.name.as_str()));

    let mut txn = db.write_pool.begin().await?;

    let existing_players_ever = sqlx::query("SELECT players_ever FROM servers WHERE ip_port = ?")
        .bind(&ip_port)
        .fetch_optional(&mut *txn)
        .await?
        .map(|row| row.get::<String, _>(0))
        .unwrap_or_else(|| "[]".to_string());

    let players_ever = merge_player_lists(&existing_players_ever, &sample_names);

    let players_now_json = serde_json::to_string(&sample_names)?;
    let players_ever_json = serde_json::to_string(&players_ever)?;

    sqlx::query(
        r#"
        INSERT INTO servers (
            ip_port, host, port, motd, players_online, max_players, version,
            protocol, cracked, needs_sync, first_seen, last_seen, times_seen,
            last_source, players_now, players_ever
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, ''), 1, ?, ?, 1, 'matscan', ?, ?)
        ON CONFLICT (ip_port) DO UPDATE SET
            host = excluded.host,
            port = excluded.port,
            motd = excluded.motd,
            players_online = excluded.players_online,
            max_players = excluded.max_players,
            version = excluded.version,
            protocol = COALESCE(excluded.protocol, servers.protocol),
            -- preserve a confirmed cracked verdict from minecraft-server-scanner
            cracked = CASE
                WHEN servers.cracked IN ('Yes', 'Yes (cached)') THEN servers.cracked
                ELSE COALESCE(?, servers.cracked)
            END,
            needs_sync = 1,
            last_seen = excluded.last_seen,
            times_seen = servers.times_seen + 1,
            last_source = excluded.last_source,
            players_now = excluded.players_now,
            players_ever = excluded.players_ever
        "#,
    )
    .bind(&ip_port)
    .bind(&host)
    .bind(target.port() as i64)
    .bind(&motd)
    .bind(online_players)
    .bind(max_players)
    .bind(&version)
    .bind(protocol)
    .bind(cracked)
    .bind(now)
    .bind(now)
    .bind(&players_now_json)
    .bind(&players_ever_json)
    .bind(cracked)
    .execute(&mut *txn)
    .await?;

    txn.commit().await?;

    Ok(())
}

/// Clean, deduplicate (case-insensitively), sort, and cap a list of player
/// names. This matches how minecraft-server-scanner stores `players_now`.
fn sorted_unique_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    const MAX_SAMPLE_NAMES: usize = 100;
    const PLAYER_NAME_MAX_LEN: usize = 32;

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for name in names {
        let name = truncate_chars(&sanitize_text(name), PLAYER_NAME_MAX_LEN);
        if name.is_empty() || !seen.insert(name.to_lowercase()) {
            continue;
        }
        out.push(name);
    }
    out.sort_by_key(|n| n.to_lowercase());
    out.truncate(MAX_SAMPLE_NAMES);
    out
}

/// Union of the names already in the database and the latest sample. Names
/// that were already known are kept first so junk names can't evict them.
fn merge_player_lists(existing_json: &str, new_names: &[String]) -> Vec<String> {
    const PLAYERS_EVER_MAX: usize = 500;
    const PLAYER_NAME_MAX_LEN: usize = 32;

    let existing: Vec<String> = serde_json::from_str(existing_json).unwrap_or_default();

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for name in existing.iter().chain(new_names) {
        let name = truncate_chars(&sanitize_text(name), PLAYER_NAME_MAX_LEN);
        if name.is_empty() || !seen.insert(name.to_lowercase()) {
            continue;
        }
        out.push(name);
        if out.len() >= PLAYERS_EVER_MAX {
            break;
        }
    }
    out
}

fn make_ping_response_hash(ping_res: &PingResponse) -> eyre::Result<u64> {
    let description = &ping_res.description_plaintext;
    let version_name = ping_res.version_name.clone().unwrap_or_default();
    let version_protocol = ping_res.version_protocol.unwrap_or_default();
    let max_players = ping_res.max_players.unwrap_or_default();

    let mut hasher = DefaultHasher::new();
    (description, version_name, version_protocol, max_players).hash(&mut hasher);
    Ok(hasher.finish())
}

fn make_favicon_hash(favicon: &str) -> [u8; 16] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(favicon.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0; 16];
    hash.copy_from_slice(&result[..16]);
    hash
}
