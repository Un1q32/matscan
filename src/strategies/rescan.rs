use std::net::Ipv4Addr;

use futures_util::StreamExt;
use rustc_hash::FxHashSet;
use serde::Deserialize;
use sqlx::{QueryBuilder, Row, Sqlite};
use tracing::{debug, warn};

use crate::{config::RescanConfig, database::Database, scanner::targets::ScanRange};

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Sort {
    Random,
    Oldest,
}

pub async fn get_ranges(database: &Database, opts: &RescanConfig) -> eyre::Result<Vec<ScanRange>> {
    let mut ranges = FxHashSet::default();

    let now = chrono::Utc::now().timestamp();

    // `last_seen` is a unix timestamp in the shared sqlite database.
    let mut qb: QueryBuilder<'_, Sqlite> =
        QueryBuilder::new("SELECT host, port FROM servers WHERE last_seen > ");
    qb.push_bind((now - opts.last_ping_ago_max_secs as i64) as f64);
    qb.push(" AND last_seen < ");
    qb.push_bind((now - opts.rescan_every_secs as i64) as f64);

    if !opts.filter_sql.is_empty() {
        // this could result in sql injection, but the config is considered to
        // be trusted
        qb.push(format!(" AND {}", opts.filter_sql));
    }
    if opts.players_online_ago_max_secs.is_some() {
        // The shared servers.db schema only keeps the most recent sighting, so
        // we can't tell when a server last had players online.
        warn!("players_online_ago_max_secs is not supported by the sqlite backend, ignoring it");
    }

    let mut aliased_ips_to_allowed_port = database
        .shared
        .lock()
        .aliased_ips_to_allowed_port
        .to_owned();

    let sort = opts.sort.unwrap_or(Sort::Oldest);

    match sort {
        Sort::Random => {
            qb.push(" ORDER BY random()");
        }
        Sort::Oldest => {
            qb.push(" ORDER BY last_seen");
        }
    }
    if let Some(limit) = opts.limit {
        qb.push(format!(" LIMIT {limit}"));
    }

    let sql = qb.into_sql();
    debug!("Doing rescan query with SQL: {sql}");
    let mut rows = sqlx::query(&sql).fetch(&database.pool);

    let mut servers: usize = 0;

    while let Some(Ok(row)) = rows.next().await {
        let host = row.get::<String, _>(0);
        let Ok(ip) = host.parse::<Ipv4Addr>() else {
            continue;
        };
        let port = row.get::<i64, _>(1) as u16;

        // there shouldn't be any aliased servers since we should've deleted
        // them, but this desync can happen if we're running multiple
        // instances of matscan
        if let Some(&allowed_port) = aliased_ips_to_allowed_port.get(&ip)
            && port != allowed_port
        {
            println!(
                "We encountered an aliased server while getting servers to rescan. Deleting {ip} from database."
            );
            sqlx::query("DELETE FROM servers WHERE host = ? AND port != ?")
                .bind(ip.to_string())
                .bind(allowed_port as i64)
                .execute(&database.write_pool)
                .await?;
            // this doesn't actually remove it from the database, it just makes
            // it so we don't delete twice
            aliased_ips_to_allowed_port.remove(&ip);
            continue;
        }

        if opts.padded && port == 25565 {
            // if padding is enabled, scan some extra addresses that aren't
            // specifically known to have minecraft servers so we're
            // not flooded with responses
            let [a, b, c, _] = ip.octets();
            let c = c & 0b1111_0000;
            ranges.insert(ScanRange {
                ip_start: Ipv4Addr::from([a, b, c, 0]),
                ip_end: Ipv4Addr::from([a, b, c | 0b1111, 255]),
                port_start: port,
                port_end: port,
            });
        } else {
            ranges.insert(ScanRange::single(ip, port));
        }

        if servers.is_multiple_of(1000) {
            println!("{servers} servers");
        }

        servers += 1;
    }

    Ok(ranges.into_iter().collect())
}
