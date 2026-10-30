pub mod collect_servers;
pub mod migrate_mongo_to_postgres;

use std::{collections::HashSet, net::Ipv4Addr, path::Path, sync::Arc, time::Duration};

use lru_cache::LruCache;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use tracing::{error, info};

use crate::database::collect_servers::CollectServersCache;

/// The schema of the `servers` table matches minecraft-server-scanner's
/// `servers.db`, so both programs can write to the same database.
const CREATE_SERVERS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS servers (
        ip_port TEXT PRIMARY KEY,
        host TEXT DEFAULT '',
        port INTEGER DEFAULT 25565,
        motd TEXT DEFAULT '',
        players_online INTEGER DEFAULT 0,
        max_players INTEGER DEFAULT 0,
        version TEXT DEFAULT '',
        protocol INTEGER,
        cracked TEXT DEFAULT '',
        whitelist TEXT DEFAULT '',
        first_seen REAL DEFAULT 0,
        last_seen REAL DEFAULT 0,
        times_seen INTEGER DEFAULT 1,
        last_source TEXT DEFAULT '',
        needs_sync INTEGER DEFAULT 1,
        players_now TEXT DEFAULT '[]',
        players_ever TEXT DEFAULT '[]'
    )
";

#[derive(Clone)]
pub struct Database {
    /// Used for reads. WAL mode lets these run concurrently with writes.
    pub pool: SqlitePool,
    /// Used for writes. Having a single connection serializes our own writers
    /// and avoids most `SQLITE_BUSY` errors. Other processes (like
    /// minecraft-server-scanner) are handled by the busy timeout.
    pub write_pool: SqlitePool,
    pub shared: Arc<Mutex<DatabaseSharedData>>,
}

pub struct DatabaseSharedData {
    /// This is used to detect duplicate servers.
    ///
    /// `CachedIpHash::count` is set to None if we find a server on this IP with
    /// a different hash.
    pub ip_to_hash_and_ports: LruCache<Ipv4Addr, (CachedIpHash, HashSet<u16>)>,

    /// A map of IP addresses with aliased servers to the only port we're
    /// allowed to ping for them.
    pub aliased_ips_to_allowed_port: FxHashMap<Ipv4Addr, u16>,

    collect_servers_cache: CollectServersCache,
}

pub struct CachedIpHash {
    /// The number of IPs found with the same hash. None if we already found an
    /// IP with a different hash.
    pub count: Option<usize>,
    pub hash: u64,
}

impl Database {
    pub async fn connect(db_path: impl AsRef<Path>) -> eyre::Result<Self> {
        let db_path = db_path.as_ref();

        // Create the parent directory if it doesn't exist so a bad path gives a
        // clear error instead of SQLite failing to open the file.
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let options = || {
            SqliteConnectOptions::new()
                .filename(db_path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .busy_timeout(Duration::from_secs(30))
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options())
            .await?;
        let write_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options())
            .await?;

        init_schema(&write_pool).await?;

        let db = Self {
            pool,
            write_pool,
            shared: Arc::new(Mutex::new(DatabaseSharedData {
                // arbitrary capacity (2^20)
                ip_to_hash_and_ports: LruCache::new(1_048_576),

                aliased_ips_to_allowed_port: FxHashMap::default(),
                collect_servers_cache: CollectServersCache::default(),
            })),
        };

        db.update_ips_with_aliased_servers().await?;

        let db_clone = db.clone();
        tokio::spawn(async move {
            loop {
                // every 4 hours
                tokio::time::sleep(Duration::from_secs(60 * 60 * 4)).await;
                if let Err(e) = db_clone.update_ips_with_aliased_servers().await {
                    error!("got error from update_ips_with_aliased_servers: {e}");
                }
            }
        });

        Ok(db)
    }

    async fn update_ips_with_aliased_servers(&self) -> eyre::Result<()> {
        let mut aliased_ips_to_allowed_port = FxHashMap::default();
        let rows = sqlx::query("SELECT ip, allowed_port FROM matscan_aliased_servers")
            .fetch_all(&self.pool)
            .await?;
        for row in rows {
            let Ok(ip) = row.get::<String, _>(0).parse::<Ipv4Addr>() else {
                continue;
            };
            let allowed_port = row.get::<i64, _>(1) as u16;
            aliased_ips_to_allowed_port.insert(ip, allowed_port);
        }
        self.shared.lock().aliased_ips_to_allowed_port = aliased_ips_to_allowed_port;

        Ok(())
    }

    pub async fn add_to_ips_with_aliased_servers(
        &self,
        ip: Ipv4Addr,
        allowed_port: u16,
    ) -> eyre::Result<()> {
        self.shared
            .lock()
            .aliased_ips_to_allowed_port
            .insert(ip, allowed_port);

        let ip_string = ip.to_string();

        let mut txn = self.write_pool.begin().await?;

        sqlx::query(
            "
            INSERT INTO matscan_aliased_servers (ip, allowed_port)
            VALUES (?, ?)
            ON CONFLICT (ip) DO UPDATE SET allowed_port = excluded.allowed_port
            ",
        )
        .bind(&ip_string)
        .bind(allowed_port as i64)
        .execute(&mut *txn)
        .await?;
        // delete all servers with this ip that aren't on the allowed port
        let delete_res = sqlx::query("DELETE FROM servers WHERE host = ? AND port != ?")
            .bind(&ip_string)
            .bind(allowed_port as i64)
            .execute(&mut *txn)
            .await?;
        let deleted_count = delete_res.rows_affected();

        txn.commit().await?;

        info!("Deleted {deleted_count} aliased servers");

        Ok(())
    }
}

async fn init_schema(pool: &SqlitePool) -> eyre::Result<()> {
    sqlx::query(CREATE_SERVERS_TABLE).execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_servers_last_seen ON servers (last_seen DESC)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_servers_version ON servers (version)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_servers_first_seen ON servers (first_seen)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_servers_host_port ON servers (host, port)")
        .execute(pool)
        .await?;

    // matscan-specific bookkeeping. The other programs ignore this table.
    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS matscan_aliased_servers (
            ip TEXT PRIMARY KEY,
            allowed_port INTEGER NOT NULL
        )
        ",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Removes null bytes, which SQLite doesn't like in TEXT values.
pub fn sanitize_text(s: &str) -> String {
    s.replace('\0', "")
}

/// Truncate to at most `max` chars. Server-reported text is untrusted, so we
/// clamp it to the same limits minecraft-server-scanner uses.
pub fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}
