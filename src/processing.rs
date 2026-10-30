pub mod minecraft;
pub mod minecraft_fingerprinting;

use std::{
    collections::{HashMap, VecDeque},
    mem,
    net::SocketAddrV4,
    sync::Arc,
    time::Duration,
};

use chrono::{NaiveDateTime, TimeDelta, Utc};
use parking_lot::Mutex;
use rustc_hash::{FxHashMap, FxHashSet};
use sqlx::{QueryBuilder, Row, Sqlite};
use tokio::time::sleep;

use crate::{
    config::Config, database::Database, processing::minecraft::SamplePlayer, terminal_colors::*,
};

pub struct SharedData {
    pub database: Database,
    /// The queue of servers to process, along with their server list ping
    /// response.
    pub queue: VecDeque<(SocketAddrV4, Vec<u8>)>,
    /// Data from the previous scan, used for identifying players that just
    /// joined or left a server.
    pub cached_players_for_sniping: HashMap<SocketAddrV4, Vec<SamplePlayer>>,

    pub total_new: usize,
    pub total_new_on_default_port: usize,
    pub revived: usize,
    pub results: usize,

    /// Whether the processing task is currently processing something.
    pub is_processing: bool,
}

pub trait ProcessableProtocol: Send + 'static {
    fn handle_response(
        shared: Arc<Mutex<SharedData>>,
        config: Arc<Config>,
        target: SocketAddrV4,
        data: Box<[u8]>,
        database: Database,
    ) -> impl std::future::Future<Output = eyre::Result<()>> + std::marker::Send;
}

/// A task that processes pings from the queue.
pub async fn process_pings<P>(shared: Arc<Mutex<SharedData>>, config: Config)
where
    P: ProcessableProtocol + Send + 'static,
{
    let database = shared.lock().database.clone();
    loop {
        if shared.lock().queue.is_empty() {
            // wait a bit until next loop
            sleep(Duration::from_millis(100)).await;
            continue;
        }

        shared.lock().is_processing = true;

        const CHUNK_SIZE: usize = 100;

        let mut futures = Vec::new();
        let mut updating_servers_in_chunk = FxHashSet::default();

        // Config is already clone, but this makes it cheaper to clone
        let config = Arc::new(config.clone());

        let batch_contents = shared.lock().queue.drain(..).collect::<Vec<_>>();
        for (target, data) in batch_contents {
            // don't handle the server twice in the same chunk of CHUNK_SIZE
            if updating_servers_in_chunk.contains(&target) {
                continue;
            }
            updating_servers_in_chunk.insert(target);

            let shared_clone = shared.clone();
            let config_clone = config.clone();
            let database_clone = database.clone();
            let future = P::handle_response(
                shared_clone,
                config_clone,
                target,
                data.into(),
                database_clone,
            );
            futures.push((target, future));

            if futures.len() >= CHUNK_SIZE {
                if let Err(err) =
                    handle_response_futures(&database, mem::take(&mut futures), &shared).await
                {
                    eprintln!("{err}");
                }

                updating_servers_in_chunk.clear();
            }
        }

        if let Err(err) = handle_response_futures(&database, futures, &shared).await {
            eprintln!("{err}");
        }

        shared.lock().is_processing = false;
        // println!("\x1b[90m\x1b[3mprocessing task is now idle\x1b[m");
    }
}

enum ProcessedServerStatus {
    Added,
    Updated,
    Revived,
    Error,
}

async fn handle_response_futures(
    db: &Database,
    futures: Vec<(SocketAddrV4, impl Future<Output = eyre::Result<()>>)>,
    shared: &Arc<Mutex<SharedData>>,
) -> eyre::Result<()> {
    if futures.is_empty() {
        return Ok(());
    }

    let mut tasks = Vec::with_capacity(futures.len());
    let now = Utc::now();

    let servers = futures.iter().map(|(addr, _)| *addr).collect::<Vec<_>>();

    for (addr, process_fut) in futures {
        tasks.push(async move { (addr, process_fut.await) });
    }

    let last_pinged_map = fetch_last_pinged_for_servers(db, &servers).await?;

    let process_results = futures_util::future::join_all(tasks).await;

    let mut updated_count = 0;
    let mut updated_but_not_revived_count = 0;
    let mut inserted_count = 0;
    let mut inserted_on_default_port_count = 0;
    let mut revived_count = 0;
    for (addr, process_res) in process_results {
        let processed_server_status = if process_res.is_err() {
            ProcessedServerStatus::Error
        } else {
            let last_pinged = last_pinged_map.get(&addr).copied();
            if let Some(last_pinged) = last_pinged {
                // if the last_pinged was more than 2 hours ago, then we
                // consider the server to be Revived instead of
                // Updated
                if now.naive_utc() - last_pinged > TimeDelta::hours(2) {
                    ProcessedServerStatus::Revived
                } else {
                    ProcessedServerStatus::Updated
                }
            } else {
                ProcessedServerStatus::Added
            }
        };

        match processed_server_status {
            ProcessedServerStatus::Added => {
                updated_count += 1;
                inserted_count += 1;
                if addr.port() == 25565 {
                    inserted_on_default_port_count += 1;
                }
            }
            ProcessedServerStatus::Updated => {
                updated_count += 1;
                updated_but_not_revived_count += 1;
            }
            ProcessedServerStatus::Revived => {
                updated_count += 1;
                revived_count += 1;
            }
            ProcessedServerStatus::Error => {}
        }
    }

    let mut shared = shared.lock();
    shared.results += updated_count;
    shared.total_new += inserted_count;
    shared.total_new_on_default_port += inserted_on_default_port_count;
    shared.revived += revived_count;

    let mut changes = Vec::new();
    if updated_but_not_revived_count > 0 {
        changes.push(format!(
            "{YELLOW}updated {BOLD}{updated_but_not_revived_count}{RESET} {GRAY}({}){RESET}",
            shared.results - shared.revived - shared.total_new
        ));
    }
    if inserted_count > 0 {
        changes.push(format!(
            "{BLUE}added {BOLD}{inserted_count}{RESET} {GRAY}({}){RESET}",
            shared.total_new
        ));
    }
    if revived_count > 0 {
        changes.push(format!(
            "{GREEN}revived {BOLD}{revived_count}{RESET} {GRAY}({}){RESET}",
            shared.revived
        ));
    }

    if !changes.is_empty() {
        println!("{}", changes.into_iter().collect::<Vec<_>>().join(", "));
    }

    Ok(())
}

async fn fetch_last_pinged_for_servers(
    db: &Database,
    servers: &[SocketAddrV4],
) -> eyre::Result<FxHashMap<SocketAddrV4, NaiveDateTime>> {
    // fetch the last_seen for all servers in this chunk in one big query
    let mut last_pinged_qb: QueryBuilder<'_, Sqlite> =
        QueryBuilder::new("SELECT host, port, last_seen FROM servers WHERE ip_port IN (");
    let mut separated = last_pinged_qb.separated(", ");
    for addr in servers {
        separated.push_bind(format!("{}:{}", addr.ip(), addr.port()));
    }
    separated.push_unseparated(")");
    let last_pinged_rows = last_pinged_qb.build().fetch_all(&db.pool).await?;
    let mut last_pinged_map = FxHashMap::<SocketAddrV4, NaiveDateTime>::default();
    for row in last_pinged_rows {
        let host = row.get::<String, _>(0);
        let Ok(ip) = host.parse() else {
            continue;
        };
        let port = row.get::<i64, _>(1) as u16;
        let last_seen = row.get::<f64, _>(2);
        let secs = last_seen.trunc() as i64;
        let nanos = ((last_seen.fract() * 1e9) as u32).min(999_999_999);
        let Some(last_pinged) = chrono::DateTime::from_timestamp(secs, nanos) else {
            continue;
        };
        last_pinged_map.insert(SocketAddrV4::new(ip, port), last_pinged.naive_utc());
    }

    Ok(last_pinged_map)
}
