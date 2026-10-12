use std::net::SocketAddrV4;

use crate::database::Database;

pub async fn get_addrs_and_protocol_versions(
    _database: &Database,
) -> eyre::Result<Vec<(SocketAddrV4, i32)>> {
    // Active fingerprinting was removed from matscan; passive fingerprinting
    // still runs as part of normal ping processing. Return no targets instead
    // of panicking so a stale `enabled = true` doesn't crash the scanner.
    Ok(Vec::new())
}
