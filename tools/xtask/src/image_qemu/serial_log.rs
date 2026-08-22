// Where a boot's serial output is kept.
//
// The console log is the primary evidence about a boot, and evidence that only
// exists in a terminal scrollback is evidence nobody can re-read. Every launch
// therefore writes the serial stream to a file as well as to wherever the
// caller is watching it, using QEMU's own chardev `logfile=` — no tee, no
// wrapper process, and it works identically for the interactive stdio chardev
// and the socket one the smoke scripts use.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Directory holding per-boot serial logs, relative to the repo root.
const LOG_DIR: &str = "target/boot-logs";
/// How many logs to keep per arch before the oldest are removed. Enough to
/// compare a run against several earlier ones; bounded so a long session does
/// not fill the disk with boots nobody will read.
const KEEP_PER_ARCH: usize = 20;

/// Suffix marking the stable path to the most recent log for an arch. A
/// reader that wants "the boot that just happened" needs a name it can know in
/// advance, not one containing a timestamp it has to discover.
const LATEST: &str = "latest";

static LINK_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stage a relative symlink beside `latest`, let a test observe the staging
/// boundary, then publish it with one same-directory rename. # C: O(1)
fn republish_latest_with(
    latest: &std::path::Path,
    target: &std::path::Path,
    staged: impl FnOnce(),
) -> std::io::Result<()> {
    let seq = LINK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let Some(link_name) = latest.file_name() else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "latest has no name"));
    };
    let link_name = link_name.to_string_lossy();
    let temporary = latest.with_file_name(format!(
        ".{link_name}.{}.{}",
        std::process::id(),
        seq,
    ));
    std::os::unix::fs::symlink(target, &temporary)?;
    staged();
    if let Err(error) = std::fs::rename(&temporary, latest) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// Atomically point `latest` at the new relative target. # C: O(1)
fn republish_latest(latest: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    republish_latest_with(latest, target, || {})
}

/// UTC `YYYYmmdd-HHMMSS`, via `date` — the same source `xtask` already uses
/// for build stamps, so log names sort the way build namespaces do.
fn stamp() -> String {
    std::process::Command::new("date")
        .args(["-u", "+%Y%m%d-%H%M%S"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unstamped".to_string())
}

/// Drop the oldest logs for `arch`, keeping the newest [`KEEP_PER_ARCH`]. The
/// timestamp format sorts lexicographically, so name order is age order.
fn trim(dir: &std::path::Path, arch: &str) {
    let prefix = format!("{arch}-");
    let mut logs: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.flatten()
            .map(|e| e.path())
            .filter(|p| {
                let Some(n) = p.file_name().and_then(|n| n.to_str()) else { return false };
                n.starts_with(&prefix) && n.ends_with(".log") && !n.contains(LATEST)
            })
            .collect(),
        Err(_) => return,
    };
    if logs.len() <= KEEP_PER_ARCH { return; }
    logs.sort();
    for old in &logs[..logs.len() - KEEP_PER_ARCH] { let _ = std::fs::remove_file(old); }
}

/// Path this boot's serial log should be written to, or `None` when the caller
/// asked for no log (`OXIDE_SERIAL_LOG=` empty or `0`). `OXIDE_SERIAL_LOG=<path>`
/// names one explicitly; otherwise it is `target/boot-logs/<arch>-<stamp>.log`
/// with `<arch>-latest.log` repointed at it.
///
/// Returns `None` rather than failing the launch if the directory cannot be
/// created: not being able to keep a log is a reason to boot without one, not
/// a reason not to boot.
pub(super) fn logfile_for(arch: &str) -> Option<PathBuf> {
    match std::env::var("OXIDE_SERIAL_LOG") {
        Ok(v) if v.is_empty() || v == "0" => return None,
        Ok(v) => return Some(PathBuf::from(v)),
        Err(_) => {}
    }
    let dir = super::common::repo_root().join(LOG_DIR);
    if std::fs::create_dir_all(&dir).is_err() { return None; }
    let path = dir.join(format!("{arch}-{}.log", stamp()));
    let latest = dir.join(format!("{arch}-{LATEST}.log"));
    // A relative target keeps the link valid if the tree is moved or mounted
    // at a different path inside a container.
    if let Some(name) = path.file_name() {
        let _ = republish_latest(&latest, std::path::Path::new(name));
    }
    trim(&dir, arch);
    Some(path)
}

/// Append QEMU's chardev `logfile=` option to `chardev` when a log is wanted.
/// `logappend=off` truncates, so a reused explicit path holds this boot only.
/// # C: O(1)
pub(super) fn with_logfile(chardev: String, arch: &str) -> (String, Option<PathBuf>) {
    match logfile_for(arch) {
        Some(p) => (format!("{chardev},logfile={},logappend=off", p.display()), Some(p)),
        None => (chardev, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The option has to reach QEMU in the form QEMU parses, appended to
    /// whatever backend the caller chose rather than replacing it.
    #[test]
    fn the_option_is_appended_to_the_callers_chardev() {
        // Under the same claim as every other case: resolving a default log
        // path republishes the arch's stable `latest` link, so two cases doing
        // it at once leave one of them reading a link the other has just
        // removed.
        temp_env("OXIDE_SERIAL_LOG", None, || {
            let (out, path) = with_logfile("stdio,id=ser0,signal=off".to_string(), "x86_64");
            let p = path.expect("a log is wanted by default");
            assert!(out.starts_with("stdio,id=ser0,signal=off,"), "backend must survive: {out}");
            assert!(out.contains(&format!("logfile={}", p.display())), "{out}");
            assert!(out.ends_with("logappend=off"), "a reused path holds this boot only: {out}");
        });
    }

    /// An explicit path is honoured verbatim — a caller that already has a
    /// place for the log must not get a second copy somewhere else.
    #[test]
    fn an_explicit_path_is_used_as_given() {
        temp_env("OXIDE_SERIAL_LOG", Some("/tmp/oxide-explicit.log"), || {
            assert_eq!(logfile_for("aarch64"), Some(PathBuf::from("/tmp/oxide-explicit.log")));
        });
    }

    /// Opting out must be possible without editing a script, and must leave
    /// the chardev exactly as the caller built it.
    #[test]
    fn logging_can_be_declined() {
        temp_env("OXIDE_SERIAL_LOG", Some("0"), || {
            assert_eq!(logfile_for("x86_64"), None);
            let (out, path) = with_logfile("socket,id=ser0".to_string(), "x86_64");
            assert_eq!(out, "socket,id=ser0");
            assert!(path.is_none());
        });
    }

    /// The default path names the arch and lands under the log directory, so
    /// two arches booting at once cannot write the same file.
    #[test]
    fn each_arch_gets_its_own_log() {
        temp_env("OXIDE_SERIAL_LOG", None, || {
            let x = logfile_for("x86_64").expect("default log");
            let a = logfile_for("aarch64").expect("default log");
            assert_ne!(x, a);
            for (p, arch) in [(&x, "x86_64"), (&a, "aarch64")] {
                assert!(p.starts_with(super::super::common::repo_root().join(LOG_DIR)), "{p:?}");
                let name = p.file_name().unwrap().to_str().unwrap();
                assert!(name.starts_with(&format!("{arch}-")) && name.ends_with(".log"), "{name}");
            }
        });
    }

    /// `<arch>-latest.log` must resolve to the log this boot writes, or the
    /// stable name points at an older boot and the reader draws a conclusion
    /// from the wrong run.
    #[test]
    fn latest_points_at_the_newest_log() {
        temp_env("OXIDE_SERIAL_LOG", None, || {
            let p = logfile_for("x86_64").expect("default log");
            let latest = p.parent().unwrap().join(format!("x86_64-{LATEST}.log"));
            let target = std::fs::read_link(&latest).expect("latest is a symlink");
            assert_eq!(target, PathBuf::from(p.file_name().unwrap()));
        });
    }

    #[test]
    fn republishing_never_removes_the_previous_latest_link() {
        let seq = LINK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "oxide-serial-link-{}-{seq}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let latest = dir.join("x86_64-latest.log");
        std::os::unix::fs::symlink("old.log", &latest).unwrap();

        let mut observed = false;
        republish_latest_with(&latest, std::path::Path::new("new.log"), || {
            observed = std::fs::read_link(&latest).ok().as_deref()
                == Some(std::path::Path::new("old.log"));
        }).unwrap();
        assert!(observed, "the old stable name remains readable until publication");
        assert_eq!(std::fs::read_link(&latest).unwrap(), std::path::Path::new("new.log"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The composer reads process environment; these tests mutate it.
    fn temp_env(key: &str, val: Option<&str>, f: impl FnOnce()) {
        static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(key).ok();
        match val { Some(v) => std::env::set_var(key, v), None => std::env::remove_var(key) }
        f();
        match prev { Some(v) => std::env::set_var(key, v), None => std::env::remove_var(key) }
    }
}
