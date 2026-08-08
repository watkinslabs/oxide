// printk-family boot parameters: what reaches a console, and in what shape.
//
// Every function is a pure decision over the command line. The caller
// (`kmain`) applies the results to klog exactly once at boot, so there is one
// owner for "where does a log line go" and one owner for "what did the boot
// line ask for".

use crate::token::{bare_flag, present, value};

/// Console loglevel installed by `quiet`. Records at this level or above stop
/// reaching a console.
pub const CONSOLE_LOGLEVEL_QUIET: u32 = 4;
/// Console loglevel installed by `debug`.
pub const CONSOLE_LOGLEVEL_DEBUG: u32 = 10;
/// The level `ignore_loglevel` effectively installs — nothing is suppressed.
pub const CONSOLE_LOGLEVEL_MOTORMOUTH: u32 = 15;

/// `/dev/kmsg` write-side policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DevkmsgMode {
    /// Unrestricted: every write becomes a record.
    On,
    /// Writes are discarded.
    Off,
    /// Writes are accepted under a rate limit.
    Ratelimit,
}

/// Console loglevel the command line asks for, or `None` to keep the build
/// default. Later parameters win, matching a line that ends `quiet debug`
/// meaning debug: the scan is left to right and the last one applies.
/// # C: O(line length)
pub fn console_loglevel(line: &[u8]) -> Option<u32> {
    let mut chosen = None;
    for token in crate::token::tokens(line) {
        let (key, val) = crate::token::split_token(token);
        match (key, val) {
            (b"quiet", None) => chosen = Some(CONSOLE_LOGLEVEL_QUIET),
            (b"debug", None) => chosen = Some(CONSOLE_LOGLEVEL_DEBUG),
            // A malformed level is ignored rather than installed: a blind `0`
            // silences the console, which is the worst possible response to a
            // typo in the parameter that exists to make a boot speak.
            (b"loglevel", Some(v)) => { if let Some(n) = crate::token::full_uint(v) { chosen = Some(n as u32); } }
            _ => {}
        }
    }
    chosen
}

/// Does the line ask for every record to reach the console regardless of its
/// level? # C: O(line length)
pub fn ignore_loglevel(line: &[u8]) -> bool { bare_flag(line, b"ignore_loglevel") }

/// `printk.time=<bool>`: prefix each line with the monotonic timestamp.
/// `None` keeps the build default. # C: O(line length)
pub fn printk_time(line: &[u8]) -> Option<bool> { value(line, b"printk.time").and_then(parse_bool) }

/// `printk.devkmsg=on|off|ratelimit`. An unrecognised value is `None` so the
/// caller keeps the default rather than installing a mode nobody named.
/// # C: O(line length)
pub fn devkmsg_mode(line: &[u8]) -> Option<DevkmsgMode> {
    match value(line, b"printk.devkmsg")? {
        b"on" => Some(DevkmsgMode::On),
        b"off" => Some(DevkmsgMode::Off),
        b"ratelimit" => Some(DevkmsgMode::Ratelimit),
        _ => None,
    }
}

/// `initcall_debug`: trace each boot init step's entry, return value and
/// elapsed time. A boot that never completes then names the step it entered
/// last, which a silent boot cannot.
/// # C: O(line length)
pub fn initcall_debug(line: &[u8]) -> bool {
    match value(line, b"initcall_debug") { Some(v) => parse_bool(v).unwrap_or(true), None => bare_flag(line, b"initcall_debug") }
}

/// Accept the boolean spellings a kernel parameter takes.
fn parse_bool(v: &[u8]) -> Option<bool> {
    match v {
        b"1" | b"y" | b"Y" | b"on" | b"true" | b"" => Some(true),
        b"0" | b"n" | b"N" | b"off" | b"false" => Some(false),
        _ => None,
    }
}

/// Is this parameter name one the boot line may carry that this kernel
/// recognises but cannot yet honour? Naming them at boot is the difference
/// between "the knob did nothing" and "the knob told you it did nothing".
/// # C: O(1)
pub fn unsupported_parameter(name: &[u8]) -> Option<&'static str> {
    match name {
        b"softlockup_panic" => Some("softlockup_panic: lockup detector is report-only"),
        b"nmi_watchdog" => Some("nmi_watchdog: no periodic NMI lockup detector"),
        b"hung_task_panic" => Some("hung_task_panic: no hung-task detector"),
        b"hung_task_timeout_secs" => Some("hung_task_timeout_secs: no hung-task detector"),
        b"log_buf_len" => Some("log_buf_len: record ring is a fixed-size static"),
        b"no_console_suspend" => Some("no_console_suspend: no system-suspend path"),
        b"slub_debug" => Some("slub_debug: allocator debug is build-time only"),
        b"page_poison" => Some("page_poison: page poisoning is build-time only"),
        b"debug_pagealloc" => Some("debug_pagealloc: page-alloc debug is build-time only"),
        b"boot_delay" => Some("boot_delay: no calibrated delay loop"),
        _ => None,
    }
}

/// Walk the line and report each recognised-but-unhonoured parameter, so the
/// boot log says which knob is inert instead of leaving the caller to infer it
/// from missing output.
/// # C: O(line length)
pub fn unsupported_in(line: &[u8]) -> impl Iterator<Item = &'static str> + '_ {
    crate::token::tokens(line).filter_map(|t| unsupported_parameter(crate::token::split_token(t).0))
}

/// Does the line carry `<name>` at all? Re-exported for callers that only
/// need presence. # C: O(line length)
pub fn has(line: &[u8], name: &[u8]) -> bool { present(line, name) }
