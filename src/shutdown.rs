use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

use crate::{firewall, scanner::SourcePort};

/// Set by the signal handler. A watcher thread polls it and exits immediately
/// (rule removal + `_exit`), without waiting for the in-flight scan step.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_COUNT: AtomicU8 = AtomicU8::new(0);
static LAST_SIGNAL: AtomicI32 = AtomicI32::new(libc::SIGTERM);

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

pub fn install_handlers() {
    // via a fn pointer: casting the function item directly trips
    // `direct_cast_of_function_item_to_integer`.
    let handler_ptr: extern "C" fn(libc::c_int) = handler;
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        unsafe {
            libc::signal(sig, handler_ptr as libc::sighandler_t);
        }
    }
}

extern "C" fn handler(sig: libc::c_int) {
    // Async-signal-safe: atomics only, no allocation or I/O here.
    LAST_SIGNAL.store(sig, Ordering::SeqCst);
    if SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    } else {
        // Second signal: die immediately with default disposition, skipping
        // even the rule removal (e.g. removal is stuck on a locked table).
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

/// Spawns a thread that exits the process as soon as a deadly signal arrives:
/// removes the firewall DROP rule (best effort) and calls `_exit`, without
/// waiting for the current scan step, sleeps, joins, or destructors.
///
/// Normal (non-signal) exits don't go through here; `FirewallGuard::drop`
/// handles those. Stdout buffers may not flush on this path.
pub fn spawn_exit_watcher(source_port: SourcePort) {
    std::thread::spawn(move || {
        loop {
            if shutdown_requested() {
                // Write directly: stdio may not flush before _exit.
                let msg = b"\nshutting down, removing firewall rule...\n";
                unsafe {
                    libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
                }
                firewall::remove_for_port(&source_port);
                let sig = LAST_SIGNAL.load(Ordering::SeqCst);
                unsafe {
                    libc::_exit(128 + sig);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_sets_shutdown_flag() {
        install_handlers();
        assert!(!shutdown_requested());
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert!(shutdown_requested());
        assert_eq!(LAST_SIGNAL.load(Ordering::SeqCst), libc::SIGTERM);
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        SIGNAL_COUNT.store(0, Ordering::SeqCst);
    }
}
