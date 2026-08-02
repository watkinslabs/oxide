// Boot proof for the `request_key(2)` upcall.
//
// The helper itself is NOT injected: `/sbin/request-key` and its stock
// configuration come from the keyutils package in the image profile, so what
// this proves is the real distribution helper, not a stand-in we wrote. Only
// the probe and the unit that runs it are added here.
//
// One rule IS injected, in the package's own drop-in directory: the nested
// case. No stock handler asks the kernel for a second key while it is still
// answering the first, and that is precisely the shape the servicing pool has
// to grow a thread for — a single context would be waiting for the outer
// helper to exit and could never start the inner one. The rule routes its own
// description only; the stock rule that answers the plain case is untouched.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The helper the kernel execs. Absent it, the probe can only report the ENOENT
/// that made this proof necessary, so the injection refuses rather than
/// producing a run whose failure would be ambiguous.
const HELPER: &str = "/sbin/request-key";

/// Where the package reads extra rules from, ahead of its own configuration.
const DROPIN: &str = "/etc/request-key.d/oxide-nested.conf";
/// The handler that rule names.
const NESTED_HANDLER: &str = "/usr/local/bin/oxide-nested-handler";

pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    require_helper(root_img)?;
    let bin = build_probe(arch)?;
    let service = write_service()?;
    let handler = write_nested_handler()?;
    let dropin = write_nested_rule()?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, "mkdir /etc/systemd/system/basic.target.wants")?;
    super::dbg_ignore(root_img, "rm /usr/local/bin/request_key_probe");
    super::dbg(root_img, &format!("write {} /usr/local/bin/request_key_probe", bin.display()))?;
    super::dbg(root_img, "sif /usr/local/bin/request_key_probe mode 0100755")?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/request-key-smoke.service");
    super::dbg(root_img, &format!("write {} /etc/systemd/system/request-key-smoke.service", service.display()))?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/basic.target.wants/request-key-smoke.service");
    super::dbg(root_img, "symlink /etc/systemd/system/basic.target.wants/request-key-smoke.service ../request-key-smoke.service")?;
    super::dbg_ignore(root_img, &format!("rm {NESTED_HANDLER}"));
    super::dbg(root_img, &format!("write {} {}", handler.display(), NESTED_HANDLER))?;
    super::dbg(root_img, &format!("sif {NESTED_HANDLER} mode 0100755"))?;
    super::dbg_ignore(root_img, "mkdir /etc/request-key.d");
    super::dbg_ignore(root_img, &format!("rm {DROPIN}"));
    super::dbg(root_img, &format!("write {} {}", dropin.display(), DROPIN))?;
    eprintln!("xtask rootfs: injected request_key upcall proof into {}", root_img.display());
    Ok(())
}

/// Fail loudly when the image carries no helper: a probe that reports ENOENT
/// cannot tell a broken upcall from an image without keyutils, which is the
/// exact ambiguity this proof exists to remove.
fn require_helper(img: &Path) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-R", &format!("stat {HELPER}"), img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    if c.status().map(|s| s.success()).unwrap_or(false) { return Ok(()); }
    eprintln!("xtask rootfs: {HELPER} is not in the image — add keyutils to the images profile and rebuild");
    Err(2)
}

/// Cross-built against the glibc ABI: the probe reaches both syscalls through
/// glibc's `syscall(3)`, which is the entry point under test on both arches.
fn build_probe(arch: &str) -> Result<PathBuf, u8> { super::probe_cargo(arch, "request_key_probe") }

/// The rule that routes the nested description to our handler. Columns are
/// `<op> <type> <description> <callout-info> <prog> <args...>`; the package
/// ranks rules by wildcard length, so a description-specific rule wins over its
/// own `debug:*` line without displacing it.
fn write_nested_rule() -> Result<PathBuf, u8> {
    write_smoke_file("oxide-nested.conf",
        "create\tuser\toxide-nested:*\t*\t/usr/local/bin/oxide-nested-handler %k %d %c %S\n")
}

/// The nested handler: ask the kernel for a SECOND key, then answer the first
/// with the inner key's serial folded into the payload. The probe requires that
/// serial to be there, so the outer construction cannot pass unless the inner
/// one completed while it was still in flight.
fn write_nested_handler() -> Result<PathBuf, u8> {
    write_smoke_file("oxide-nested-handler", NESTED_HANDLER_BODY)
}

/// `$1` key, `$3` callout, `$4` the requester's session keyring. The inner
/// request rides the package's own `debug:*` rule, so the key it builds is
/// answered by the stock handler.
const NESTED_HANDLER_BODY: &str = r#"#!/bin/sh
inner=`keyctl request2 user debug:oxide-inner oxide-inner @s` || exit 1
keyctl instantiate "$1" "Debug $3 inner=$inner" "$4" || exit 1
exit 0
"#;

/// Stage one generated file under `target/smoke`. # C: O(len)
fn write_smoke_file(name: &str, body: &str) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join(name);
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write {name} failed: {e}"); 1u8 })?;
    Ok(path)
}

fn write_service() -> Result<PathBuf, u8> {
    write_smoke_file("request-key-smoke.service", "[Unit]\n\
Description=Oxide request_key upcall proof\n\
After=basic.target\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/sh -c '/usr/local/bin/request_key_probe 2>&1 | /usr/bin/logger -t request-key-probe'\n\
\n\
[Install]\n\
WantedBy=basic.target\n")
}
