use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const CPU: u8 = 1 << 0;
pub const MEMORY: u8 = 1 << 1;
pub const IO: u8 = 1 << 2;
pub const PIDS: u8 = 1 << 3;
pub const CPUSET: u8 = 1 << 4;
pub const ALL: u8 = CPU | MEMORY | IO | PIDS | CPUSET;

/// Controller name ↔ bit. Linux ordering: cpu cpuset io memory pids.
const CTRL_TABLE: &[(&str, u8)] = &[
    ("cpu", CPU),
    ("cpuset", CPUSET),
    ("io", IO),
    ("memory", MEMORY),
    ("pids", PIDS),
];

pub(super) fn ctrl_bit(name: &str) -> Option<u8> {
    CTRL_TABLE.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}

/// Controller a `<ctrl>.<knob>` interface file belongs to (None for
/// the always-present `cgroup.*` core files).
pub(super) fn file_controller(file: &str) -> Option<u8> {
    let pfx = file.split('.').next()?;
    match pfx {
        "cgroup" => None,
        "pids" => Some(PIDS),
        "memory" => Some(MEMORY),
        "cpu" => Some(CPU),
        "io" => Some(IO),
        "cpuset" => Some(CPUSET),
        _ => None,
    }
}

/// Space-separated controller list for a bitset, canonical order.
pub(super) fn ctrl_list(set: u8) -> String {
    let mut out = String::new();
    for (n, b) in CTRL_TABLE {
        if set & b != 0 {
            if !out.is_empty() { out.push(' '); }
            out.push_str(n);
        }
    }
    out
}

/// "max" sentinel ↔ Option<u64>. cgroup v2 uses the literal token
/// `max` for "no limit" across pids.max / memory.max / cpu.max.
pub(super) fn parse_max(tok: &str) -> Option<Option<u64>> {
    let t = tok.trim();
    if t == "max" { return Some(None); }
    t.parse::<u64>().ok().map(Some)
}

pub(super) fn fmt_max(v: Option<u64>) -> String {
    match v { Some(n) => n.to_string(), None => "max".to_string() }
}

/// Files that exist in every cgroup directory (core interface).
pub const CORE_FILES: &[&str] = &[
    "cgroup.procs", "cgroup.threads", "cgroup.controllers",
    "cgroup.subtree_control", "cgroup.events", "cgroup.type",
    "cgroup.stat", "cgroup.max.depth", "cgroup.max.descendants",
];

/// Extra core files present only in non-root cgroups.
pub const NONROOT_FILES: &[&str] = &["cgroup.kill", "cgroup.freeze"];

/// Reserved slot for a name outside the tables below. Never handed out by
/// [`file_slot`], so it cannot alias a real control file.
pub const FILE_SLOT_UNKNOWN: u8 = u8::MAX;

/// A control file's FIXED slot inside its cgroup's inode-number space.
///
/// Order: `CORE_FILES`, `NONROOT_FILES`, then `controller_files(ALL)` — the
/// full set, not the subset a given cgroup has enabled, so a name's slot never
/// moves when a controller is switched on. The inode number is
/// `(cgid << 8) | slot`, so the slot must be unique per name; it replaced an
/// 8-bit multiply-31 hash of the name, under which `pids.events` and
/// `cpuset.cpus` collided and shared one `st_ino`. Linux kernfs gives every
/// node its own ino from an idr (`fs/kernfs/dir.c` `kernfs_new_node`), and
/// anything keyed by inode identity — `stat`, hardlink detection, and inotify's
/// per-inode marks — needs that to hold.
/// # C: O(N_names)
pub fn file_slot(name: &str) -> u8 {
    let mut i: u16 = 0;
    for n in CORE_FILES.iter().chain(NONROOT_FILES.iter()) {
        if *n == name { return i as u8; }
        i += 1;
    }
    for n in controller_files(ALL) {
        if n == name { return i as u8; }
        i += 1;
    }
    FILE_SLOT_UNKNOWN
}

/// Per-controller interface files, gated on the controller being
/// available (enabled in the parent's subtree_control).
/// # C: O(controllers)
pub fn controller_files(avail: u8) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    if avail & PIDS != 0 {
        v.extend(["pids.current", "pids.max", "pids.peak", "pids.events"]);
    }
    if avail & MEMORY != 0 {
        v.extend(["memory.current", "memory.max", "memory.high", "memory.low",
            "memory.min", "memory.swap.max", "memory.swap.current",
            "memory.oom.group", "memory.zswap.max", "memory.pressure_level",
            "memory.events", "memory.events.local", "memory.stat"]);
    }
    if avail & CPU != 0 {
        v.extend(["cpu.weight", "cpu.max", "cpu.stat"]);
    }
    if avail & IO != 0 {
        v.extend(["io.stat", "io.max", "io.weight"]);
    }
    if avail & CPUSET != 0 {
        v.extend(["cpuset.cpus", "cpuset.mems",
            "cpuset.cpus.effective", "cpuset.mems.effective"]);
    }
    v
}
