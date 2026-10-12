use std::process::Command;

use crate::scanner::SourcePort;

/// Ensures the kernel doesn't RST our raw-socket connections.
///
/// matscan crafts SYNs from `source_port` via raw sockets, bypassing the
/// kernel. When the SYN-ACK comes back the kernel sees no matching socket and
/// replies with RST, killing the handshake before we can read the Minecraft
/// ping. A `DROP` rule for that port discards the packet before the kernel TCP
/// stack processes it, while our datalink sniffer (which taps below iptables)
/// still sees its copy.
///
/// The rule is inserted on startup (if missing) and removed on clean shutdown
/// via [`Drop`]. If the process is SIGKILLed or loses power the rule is left
/// behind, which is harmless (nothing legitimate listens on that port) — just
/// delete it manually with `iptables -D ...` / `nft delete rule ...`.
pub struct FirewallGuard {
    backend: Backend,
    /// Port spec for the backend (`61000` or `61000:62000` for iptables,
    /// `61000` or `61000-62000` for nft).
    spec: String,
    /// Whether we inserted the rule (only then do we remove it).
    added: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    Iptables,
    Nft,
}

impl FirewallGuard {
    pub fn setup(source_port: &SourcePort) -> Self {
        let (iptables_spec, nft_spec) = match source_port {
            SourcePort::Number(p) => (p.to_string(), p.to_string()),
            SourcePort::Range { min, max } => (format!("{min}:{max}"), format!("{min}-{max}")),
        };

        let backend = if command_exists("iptables") {
            Backend::Iptables
        } else if command_exists("nft") {
            Backend::Nft
        } else {
            eprintln!(
                "firewall: neither iptables nor nft found, skipping automatic firewall setup. \
                 Firewall source port yourself or scans will see no replies."
            );
            return Self {
                backend: Backend::Iptables,
                spec: iptables_spec,
                added: false,
            };
        };

        let spec = match backend {
            Backend::Iptables => iptables_spec,
            Backend::Nft => nft_spec,
        };

        match ensure_rule(backend, &spec) {
            Ok(added) => {
                if added {
                    println!("firewall: inserted DROP rule for tcp dport {spec} (removed on exit)");
                } else {
                    println!("firewall: DROP rule for tcp dport {spec} already present");
                }
                Self {
                    backend,
                    spec,
                    added,
                }
            }
            Err(err) => {
                eprintln!(
                    "firewall: failed to set up DROP rule for tcp dport {spec}: {err}. \
                     Are you root? Scans will likely see no replies; add the rule manually."
                );
                Self {
                    backend,
                    spec,
                    added: false,
                }
            }
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if !self.added {
            return;
        }
        if let Err(err) = remove_rule(self.backend, &self.spec) {
            eprintln!(
                "firewall: failed to remove DROP rule for tcp dport {}: {err}. \
                 Remove it manually when done.",
                self.spec
            );
        } else {
            println!("firewall: removed DROP rule for tcp dport {}", self.spec);
        }
    }
}

fn command_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns `Ok(true)` if we inserted the rule, `Ok(false)` if it was already
/// there.
fn ensure_rule(backend: Backend, spec: &str) -> eyre::Result<bool> {
    match backend {
        Backend::Iptables => {
            let check = Command::new("iptables")
                .args(["-C", "INPUT", "-p", "tcp", "--dport", spec, "-j", "DROP"])
                .status()?;
            if check.success() {
                return Ok(false);
            }
            let add = Command::new("iptables")
                .args(["-A", "INPUT", "-p", "tcp", "--dport", spec, "-j", "DROP"])
                .status()?;
            if !add.success() {
                eyre::bail!("iptables -A exited with {add}");
            }
            Ok(true)
        }
        Backend::Nft => {
            ensure_nft_chain()?;
            if nft_rule_exists(spec)? {
                return Ok(false);
            }
            let add = Command::new("nft")
                .args([
                    "add", "rule", "ip", "filter", "INPUT", "tcp", "dport", spec, "drop",
                ])
                .output()?;
            if !add.status.success() {
                eyre::bail!(
                    "nft add rule failed: {}",
                    String::from_utf8_lossy(&add.stderr).trim()
                );
            }
            Ok(true)
        }
    }
}

fn remove_rule(backend: Backend, spec: &str) -> eyre::Result<()> {
    match backend {
        Backend::Iptables => {
            // -D deletes one matching rule; only ours should match since we
            // only remove when we added.
            let del = Command::new("iptables")
                .args(["-D", "INPUT", "-p", "tcp", "--dport", spec, "-j", "DROP"])
                .status()?;
            if !del.success() {
                eyre::bail!("iptables -D exited with {del}");
            }
            Ok(())
        }
        Backend::Nft => {
            let handle = nft_rule_handle(spec)?
                .ok_or_else(|| eyre::eyre!("rule for tcp dport {spec} not found"))?;
            let del = Command::new("nft")
                .args(["delete", "rule", "ip", "filter", "INPUT", "handle", &handle])
                .output()?;
            if !del.status.success() {
                eyre::bail!(
                    "nft delete rule failed: {}",
                    String::from_utf8_lossy(&del.stderr).trim()
                );
            }
            Ok(())
        }
    }
}

/// Creates `ip filter INPUT` (accept by default) if it doesn't exist, so we
/// have somewhere to put the DROP rule on systems with no firewall configured.
fn ensure_nft_chain() -> eyre::Result<()> {
    let list = Command::new("nft")
        .args(["list", "chain", "ip", "filter", "INPUT"])
        .output()?;
    if list.status.success() {
        return Ok(());
    }
    for args in [
        ["add", "table", "ip", "filter"].as_slice(),
        [
            "add", "chain", "ip", "filter", "INPUT", "{", "type", "filter", "hook", "input",
            "priority", "0", ";", "policy", "accept", ";", "}",
        ]
        .as_slice(),
    ] {
        let out = Command::new("nft").args(args).output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Race: chain created between our check and now.
            if !stderr.contains("already exists") && !stderr.contains("File exists") {
                eyre::bail!("nft {} failed: {}", args.join(" "), stderr.trim());
            }
        }
    }
    Ok(())
}

fn nft_list_rules() -> eyre::Result<String> {
    let out = Command::new("nft")
        .args(["--terse", "list", "chain", "ip", "filter", "INPUT"])
        .output()?;
    if !out.status.success() {
        eyre::bail!(
            "nft list chain failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn nft_rule_exists(spec: &str) -> eyre::Result<bool> {
    let needle = format!("tcp dport {spec} drop");
    Ok(nft_list_rules()?.contains(&needle))
}

/// Finds the handle of our DROP rule for deletion.
fn nft_rule_handle(spec: &str) -> eyre::Result<Option<String>> {
    let needle = format!("tcp dport {spec} drop");
    let out = Command::new("nft")
        .args([
            "--handle", "--terse", "list", "chain", "ip", "filter", "INPUT",
        ])
        .output()?;
    if !out.status.success() {
        eyre::bail!(
            "nft list chain failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains(&needle) {
            let mut tokens = line.split_whitespace();
            while let Some(tok) = tokens.next() {
                if tok == "handle" {
                    if let Some(handle) = tokens.next() {
                        return Ok(Some(handle.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    /// Fake `iptables` stub: logs argv to $STUB_LOG, exits 1 for `-C` unless
    /// $STUB_RULE_EXISTS=1, else 0.
    const STUB: &str = r#"#!/bin/sh
echo "$@" >> "$STUB_LOG"
if [ "$1" = "-C" ]; then
  [ "$STUB_RULE_EXISTS" = "1" ] && exit 0 || exit 1
fi
exit 0
"#;

    fn setup_stub(test: &str, rule_exists: bool) -> (String, String) {
        let dir = format!("/tmp/opencode/fwtest-{}-{test}", std::process::id());
        let dir = format!("/tmp/opencode/fwtest-{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let stub = format!("{dir}/iptables");
        fs::write(&stub, STUB).unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("PATH", format!("{dir}:{}", std::env::var("PATH").unwrap()));
            std::env::set_var("STUB_LOG", format!("{dir}/calls.log"));
            std::env::set_var("STUB_RULE_EXISTS", if rule_exists { "1" } else { "0" });
        }
        let log = format!("{dir}/calls.log");
        (dir, log)
    }

    fn teardown(dir: &str) {
        unsafe {
            std::env::remove_var("STUB_LOG");
            std::env::remove_var("STUB_RULE_EXISTS");
        }
        let _ = fs::remove_dir_all(dir);
    }

    // Tests below mutate process-global env (PATH), so they must not run in
    // parallel with each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn inserts_and_removes_rule_when_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (dir, log) = setup_stub("missing", false);
        {
            let _guard = FirewallGuard::setup(&SourcePort::Number(61000));
            let calls = fs::read_to_string(&log).unwrap();
            assert!(
                calls.contains("-C INPUT -p tcp --dport 61000 -j DROP"),
                "{calls}"
            );
            assert!(
                calls.contains("-A INPUT -p tcp --dport 61000 -j DROP"),
                "{calls}"
            );
        }
        let calls = fs::read_to_string(&log).unwrap();
        assert!(
            calls.contains("-D INPUT -p tcp --dport 61000 -j DROP"),
            "{calls}"
        );
        teardown(&dir);
    }

    #[test]
    fn leaves_preexisting_rule_alone() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (dir, log) = setup_stub("exists", true);
        {
            let _guard = FirewallGuard::setup(&SourcePort::Range {
                min: 61000,
                max: 62000,
            });
            let calls = fs::read_to_string(&log).unwrap();
            assert!(
                calls.contains("--dport 61000:62000"),
                "range spec must use iptables colon syntax: {calls}"
            );
            assert!(!calls.contains(" -A "), "must not insert: {calls}");
        }
        let calls = fs::read_to_string(&log).unwrap();
        assert!(
            !calls.contains(" -D "),
            "must not delete pre-existing rule: {calls}"
        );
        teardown(&dir);
    }
}
