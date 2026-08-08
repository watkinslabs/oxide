// Landlock denial reporting.
//
// A sandbox that refuses an access and says nothing is undebuggable: the
// program sees an errno with no way to learn which of its own layers refused
// what. Every denial therefore produces a record naming the domain, the layer
// and the exact rights that were missing — unless the policy asked for that
// particular denial to stay silent, which is what the quiet masks and the
// per-execution logging flags are for.
//
// Two record types, matching the two questions an auditor asks: what was
// refused (`landlock_access`), and what the domain that refused it IS
// (`landlock_domain`, written once the first time a domain appears).

extern crate alloc;

use alloc::vec::Vec;

use audit::fmt;
use audit::uapi::{AUDIT_LANDLOCK_ACCESS, AUDIT_LANDLOCK_DOMAIN};

use sync::{Spinlock, TaskList as TaskListClass};

use crate::domain::{Domain, Layer};
use crate::logging::{DomainDetails, LogStatus};
use crate::uapi::*;

/// Which layer levels the CURRENT execution enforced, as a bitmask.
///
/// A function rather than a field because the answer is per-thread and this
/// crate deliberately sits below the task: the kernel glue installs a reader
/// once, and a build with no glue reports "none", which is the same answer a
/// thread that has just been replaced by `execve` gives.
static EXEC_LAYERS: Spinlock<Option<fn() -> u32>, TaskListClass> = Spinlock::new(None);

/// Install the per-thread reader. Idempotent.
/// # C: O(1)
pub fn set_exec_layers_source(f: fn() -> u32) { *EXEC_LAYERS.lock() = Some(f); }

/// Whether `layer` was enforced by the execution that is now being refused.
///
/// The distinction is the whole point of the two per-execution logging flags:
/// a program that sandboxes itself usually expects its OWN denials and does
/// not want them logged, but very much wants the ones a program it later
/// `execve`s runs into.
/// # C: O(1)
pub fn same_execution(layer: usize) -> bool {
    let Some(f) = *EXEC_LAYERS.lock() else { return false };
    if layer >= MAX_NUM_LAYERS { return false; }
    f() & (1u32 << layer) != 0
}

/// What kind of access a denial refused. Selects both which names the rights
/// bits carry and which quiet mask applies.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RequestType {
    FsAccess,
    NetAccess,
    ScopeAbstractUnixSocket,
    ScopeSignal,
}

const FS_BLOCKERS: [&[u8]; 17] = [
    b"fs.execute", b"fs.write_file", b"fs.read_file", b"fs.read_dir", b"fs.remove_dir",
    b"fs.remove_file", b"fs.make_char", b"fs.make_dir", b"fs.make_reg", b"fs.make_sock",
    b"fs.make_fifo", b"fs.make_block", b"fs.make_sym", b"fs.refer", b"fs.truncate",
    b"fs.ioctl_dev", b"fs.resolve_unix",
];

const NET_BLOCKERS: [&[u8]; 4] = [
    b"net.bind_tcp", b"net.connect_tcp", b"net.bind_udp", b"net.connect_send_udp",
];

/// Name of the right at bit `index`, or the placeholder for a bit this
/// implementation has no name for. A record must never omit a blocker it
/// cannot name: an auditor reading a denial with no cause would conclude the
/// wrong thing.
/// # C: O(1)
pub fn blocker_name(ty: RequestType, index: usize) -> &'static [u8] {
    const UNKNOWN: &[u8] = b"unknown";
    match ty {
        RequestType::FsAccess => *FS_BLOCKERS.get(index).unwrap_or(&UNKNOWN),
        RequestType::NetAccess => *NET_BLOCKERS.get(index).unwrap_or(&UNKNOWN),
        RequestType::ScopeAbstractUnixSocket => b"scope.abstract_unix_socket",
        RequestType::ScopeSignal => b"scope.signal",
    }
}

/// Append the comma-separated names of every right in `missing`.
///
/// A scope denial names no rights bit at all, so an empty mask still emits the
/// request's own name rather than an empty field.
/// # C: O(N_bits)
pub fn blockers(out: &mut Vec<u8>, ty: RequestType, missing: AccessMask) {
    let mut first = true;
    for i in 0..AccessMask::BITS as usize {
        if missing & (1 << i) == 0 { continue; }
        if !first { out.push(b','); }
        out.extend_from_slice(blocker_name(ty, i));
        first = false;
    }
    if first { out.extend_from_slice(blocker_name(ty, usize::MAX)); }
}

/// Body of a denial record: which domain refused, and what it refused.
/// # C: O(N_bits)
pub fn access_body(domain_id: u64, ty: RequestType, missing: AccessMask) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"domain=");
    fmt::hex(&mut b, domain_id);
    b.extend_from_slice(b" blockers=");
    blockers(&mut b, ty, missing);
    b
}

/// Body of a domain-description record: who built the domain, and from what.
/// The executable path and the command name come from userspace, so both are
/// encoded as untrusted values.
/// # C: O(path len)
pub fn domain_body(domain_id: u64, d: &DomainDetails) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"domain=");
    fmt::hex(&mut b, domain_id);
    b.extend_from_slice(b" status=allocated mode=enforcing pid=");
    fmt::dec(&mut b, d.pid as u64);
    b.extend_from_slice(b" uid=");
    fmt::dec(&mut b, d.uid as u64);
    b.extend_from_slice(b" exe=");
    fmt::untrusted(&mut b, &d.exe);
    b.extend_from_slice(b" comm=");
    fmt::untrusted(&mut b, &d.comm);
    b
}

/// Body of a domain-teardown record. Only a domain that was described in the
/// log is worth reporting gone: knowing an id will never appear again is the
/// point, and an id that never appeared cannot stop appearing.
/// # C: O(1)
pub fn drop_body(domain_id: u64, denials: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"domain=");
    fmt::hex(&mut b, domain_id);
    b.extend_from_slice(b" status=deallocated denials=");
    fmt::dec(&mut b, denials);
    b
}

/// Whether the layer that refused the request asked for this particular denial
/// to stay unreported.
///
/// A filesystem or network denial is quiet only when the object was marked
/// quiet AND the layer's quiet mask covers EVERY right that was missing:
/// silencing a denial that includes a right the policy never asked to silence
/// would hide the part the author wanted to see. A scope denial has no object
/// to mark, so the layer's scope quiet mask alone decides.
/// # C: O(1)
pub fn quieted(ty: RequestType, object_quiet: bool, missing: AccessMask,
               quiet_fs: AccessMask, quiet_net: AccessMask, quiet_scoped: AccessMask) -> bool
{
    match ty {
        RequestType::FsAccess => object_quiet && (quiet_fs & missing) == missing,
        RequestType::NetAccess => object_quiet && (quiet_net & missing) == missing,
        RequestType::ScopeAbstractUnixSocket =>
            (quiet_scoped & SCOPE_ABSTRACT_UNIX_SOCKET) != 0,
        RequestType::ScopeSignal => (quiet_scoped & SCOPE_SIGNAL) != 0,
    }
}

/// Report one denial, if the layer that produced it reports at all.
///
/// `layer` is the youngest layer still refusing; `same_execution` says whether
/// that layer was enforced by the execution now being refused. The denial
/// counter is bumped whatever the reporting decision is: a policy's author
/// wants to know how often a domain refuses even when the log is quiet.
/// # C: O(N_bits)
pub fn log_denial(dom: &Domain, ty: RequestType, layer: usize, missing: AccessMask,
                  object_quiet: bool, same_execution: bool)
{
    let Some(l) = dom.layers.get(layer) else { return };
    l.count_denial();
    if !l.log.reports(same_execution) { return; }
    if quieted(ty, object_quiet, missing, l.quiet_fs, l.quiet_net, l.quiet_scoped) { return; }
    if !audit::state::enabled() { return; }
    let id = dom.ancestry.get(layer).copied().unwrap_or(0);
    let _ = audit::log(AUDIT_LANDLOCK_ACCESS, &access_body(id, ty, missing));
    // Described once, the first time the domain shows up in the log, so a
    // reader can resolve the bare id every later denial carries.
    if l.claim_description() == LogStatus::Pending {
        let _ = audit::log(AUDIT_LANDLOCK_DOMAIN, &domain_body(id, &l.log.details));
    }
}

/// Report one layer going away.
///
/// Only a layer that was DESCRIBED is reported gone: knowing an id will never
/// appear again is the point, and an id that never appeared cannot stop
/// appearing. The record carries the total denial count, which is how a policy
/// author learns how often a sandbox bit even when the denials were quiet.
/// # C: O(1)
pub fn log_drop_layer(domain_id: u64, l: &Layer) {
    if l.log_status() != LogStatus::Recorded { return; }
    if !audit::state::enabled() { return; }
    let _ = audit::log(AUDIT_LANDLOCK_DOMAIN, &drop_body(domain_id, l.denials()));
}

#[cfg(test)]
#[path = "tests/audit.rs"]
mod tests;
