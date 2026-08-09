// TTY input auditing: the accumulation state machine behind the AUDIT_TTY
// record.
//
// Input read from a terminal by a thread group whose audit-tty mask is set is
// accumulated per thread group rather than logged byte by byte — a shell
// session would otherwise produce one record per keystroke. The buffer is
// flushed ("pushed") as a single record on four events: it filled, the device
// changed, the canonical mode changed, or the thread group died. The last of
// those is why a dying task must reach [`TtyAudit::exit`]: a session's final
// partial line is exactly the part an auditor is most likely to want, and
// nothing else would ever write it.
//
// Everything here is a decision on borrowed state and returns what to log
// rather than logging it, so the whole state machine runs under the hosted
// suite. Emission lives in `producers`; the live wiring in `state`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::AUDIT_OFF;

/// The thread group's terminal input is audited.
pub const AUDIT_TTY_ENABLE: u32 = 1 << 0;
/// Audit input that is being read with echo off under a canonical line
/// discipline — the shape a password prompt has. Off by default: the point of
/// the separate bit is that recording terminal input must not silently mean
/// recording passwords.
pub const AUDIT_TTY_LOG_PASSWD: u32 = 1 << 1;

/// Both defined mask bits. A mask carrying anything else is not a mask this
/// contract produced.
pub const AUDIT_TTY_MASK_ALL: u32 = AUDIT_TTY_ENABLE | AUDIT_TTY_LOG_PASSWD;

/// Accumulated input flushed as one record.
pub const TTY_AUDIT_BUF_SIZE: usize = 4096;

/// A terminal, named the way a record prints it. The device number is carried
/// already split: the packed encoding is the filesystem layer's business, and
/// a second decoder here could disagree with it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Devno { pub major: u32, pub minor: u32 }

/// One flush: the terminal the bytes came from, and the bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Push {
    pub dev: Devno,
    pub data: Vec<u8>,
}

/// Input accumulated for one thread group.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Buf {
    dev: Devno,
    icanon: bool,
    data: Vec<u8>,
}

impl Buf {
    /// Take everything accumulated so far, leaving the buffer empty. `None`
    /// when there was nothing: an empty push would be a record with no
    /// content, which tells an auditor nothing and costs a queue slot.
    /// # C: O(1)
    fn take(&mut self) -> Option<Push> {
        if self.data.is_empty() { return None; }
        Some(Push { dev: self.dev, data: core::mem::take(&mut self.data) })
    }
}

/// One thread group's tty-audit state: the mask an audit daemon set, and the
/// buffer that only exists once audited input has actually arrived.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Group {
    mask: u32,
    buf: Buf,
}

impl Group {
    /// # C: O(1)
    fn idle(&self) -> bool { self.mask == 0 && self.buf.data.is_empty() }
}

/// Every thread group with tty-audit state. A group with neither a mask nor
/// buffered input holds no entry at all, so a system on which no daemon ever
/// enabled tty auditing carries an empty map and the read path costs one
/// failed lookup.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TtyAudit {
    groups: BTreeMap<u32, Group>,
}

impl TtyAudit {
    /// # C: O(1)
    pub const fn new() -> Self { Self { groups: BTreeMap::new() } }

    /// The thread group's mask; zero when it has none.
    /// # C: O(log N_groups)
    pub fn mask(&self, tgid: u32) -> u32 {
        self.groups.get(&tgid).map_or(0, |g| g.mask)
    }

    /// Install a new mask and return the one it replaced.
    /// # C: O(log N_groups)
    pub fn set_mask(&mut self, tgid: u32, mask: u32) -> u32 {
        let g = self.groups.entry(tgid).or_default();
        let old = core::mem::replace(&mut g.mask, mask);
        if g.idle() { self.groups.remove(&tgid); }
        old
    }

    /// A new thread group inherits its parent's mask, and nothing else.
    ///
    /// The mask is inherited because auditing a login shell that does not
    /// survive into the commands it runs would audit almost nothing. The
    /// buffer is not, because it belongs to the parent's terminal session: a
    /// child that inherited half a line would attribute the parent's typing to
    /// itself and push it twice.
    /// # C: O(log N_groups)
    pub fn fork(&mut self, parent_tgid: u32, child_tgid: u32) {
        let mask = self.mask(parent_tgid);
        if mask == 0 { return; }
        self.groups.entry(child_tgid).or_default().mask = mask;
    }

    /// Whether input read from this terminal by this thread group is audited.
    ///
    /// A pty master is refused because its "input" is the slave's output —
    /// auditing it would record the terminal's echo of what the slave side
    /// already recorded, doubling every keystroke.
    /// # C: O(1)
    pub fn audits(mask: u32, size: usize, pty_master: bool, icanon: bool, echo: bool) -> bool {
        if mask & AUDIT_TTY_ENABLE == 0 { return false; }
        if size == 0 { return false; }
        if pty_master { return false; }
        if mask & AUDIT_TTY_LOG_PASSWD == 0 && icanon && !echo { return false; }
        true
    }

    /// Accumulate input a task just read from its terminal, and return every
    /// record that accumulation completed.
    ///
    /// A device or canonical-mode change flushes first: the record carries one
    /// device and one mode, so mixing two of either would misattribute the
    /// bytes. More than one push comes back when the input is larger than the
    /// buffer.
    /// # C: O(len)
    pub fn add_data(&mut self, tgid: u32, dev: Devno, icanon: bool, echo: bool, pty_master: bool,
                    data: &[u8]) -> Vec<Push>
    {
        let mut out = Vec::new();
        let mask = self.mask(tgid);
        if !Self::audits(mask, data.len(), pty_master, icanon, echo) { return out; }
        let g = self.groups.entry(tgid).or_default();
        if g.buf.dev != dev || g.buf.icanon != icanon {
            out.extend(g.buf.take());
            g.buf.dev = dev;
            g.buf.icanon = icanon;
        }
        let mut rest = data;
        while !rest.is_empty() {
            let run = rest.len().min(TTY_AUDIT_BUF_SIZE - g.buf.data.len());
            g.buf.data.extend_from_slice(&rest[..run]);
            rest = &rest[run..];
            if g.buf.data.len() == TTY_AUDIT_BUF_SIZE { out.extend(g.buf.take()); }
        }
        out
    }

    /// Flush whatever this thread group has accumulated, on a boundary the
    /// line discipline knows about — a completed canonical line.
    ///
    /// `EPERM` when the group is not audited at all: the caller uses that to
    /// tell "nothing to write" from "auditing is off here", which is what
    /// decides whether a separate one-off record is written instead.
    /// # C: O(log N_groups)
    pub fn push(&mut self, tgid: u32) -> Result<Option<Push>, Errno> {
        if self.mask(tgid) & AUDIT_TTY_ENABLE == 0 { return Err(Errno::Eperm); }
        Ok(self.flush(tgid))
    }

    /// The last thread of a group died: write out its final partial line and
    /// forget the group.
    ///
    /// Without this the tail of every audited session — the part after the
    /// last completed line — is discarded, and a group id that is later reused
    /// would inherit a dead session's bytes.
    /// # C: O(log N_groups)
    pub fn exit(&mut self, tgid: u32) -> Option<Push> {
        let mut g = self.groups.remove(&tgid)?;
        g.buf.take()
    }

    /// # C: O(log N_groups)
    fn flush(&mut self, tgid: u32) -> Option<Push> {
        let g = self.groups.get_mut(&tgid)?;
        let out = g.buf.take();
        if g.idle() { self.groups.remove(&tgid); }
        out
    }

    /// Thread groups currently holding state. Diagnostics and the hosted
    /// suite's proof that nothing accumulates when nothing is audited.
    /// # C: O(1)
    pub fn tracked(&self) -> usize { self.groups.len() }
}

/// Whether a flush writes a record or is only discarded.
///
/// The buffer is emptied either way. A system with auditing switched off must
/// not accumulate a session's input in the kernel until someone switches it
/// back on, and must not write the pre-existing contents when they do.
/// # C: O(1)
pub fn push_logs(audit_enabled: u32) -> bool { audit_enabled != AUDIT_OFF }

/// `struct audit_tty_status` — `enabled`, `log_passwd`, two `u32`.
pub const AUDIT_TTY_STATUS_LEN: usize = 8;

/// Encode a mask as the two-field status struct a daemon reads.
/// # C: O(1)
pub fn encode_status(mask: u32) -> [u8; AUDIT_TTY_STATUS_LEN] {
    let mut out = [0u8; AUDIT_TTY_STATUS_LEN];
    out[..4].copy_from_slice(&(mask & AUDIT_TTY_ENABLE).to_ne_bytes());
    out[4..].copy_from_slice(&u32::from(mask & AUDIT_TTY_LOG_PASSWD != 0).to_ne_bytes());
    out
}

/// Decode a status struct into a mask.
///
/// A short payload is accepted and zero-filled — the struct has grown before
/// and a daemon built against the shorter one must keep working — but a field
/// holding anything other than zero or one is rejected, because a daemon that
/// meant something by a larger value did not mean this.
/// # C: O(1)
pub fn decode_status(data: &[u8]) -> Result<u32, Errno> {
    let mut buf = [0u8; AUDIT_TTY_STATUS_LEN];
    let n = data.len().min(AUDIT_TTY_STATUS_LEN);
    buf[..n].copy_from_slice(&data[..n]);
    let enabled = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let log_passwd = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if enabled > 1 || log_passwd > 1 { return Err(Errno::Einval); }
    Ok(enabled | if log_passwd != 0 { AUDIT_TTY_LOG_PASSWD } else { 0 })
}

// ---- the live system ------------------------------------------------------

use core::sync::atomic::{AtomicUsize, Ordering};

use sync::Spinlock;

use crate::producers::{self, TtyActor, TTY_DESC_INPUT};
use crate::state;

/// Thread groups whose mask is non-zero, published outside the audit lock.
///
/// The read path consults this before anything else. On a system where no
/// daemon ever enabled tty auditing — every system, almost always — a terminal
/// read costs one relaxed load and returns, instead of taking the audit lock
/// on every keystroke a shell reads.
static ARMED: AtomicUsize = AtomicUsize::new(0);

/// Told when the armed state changes, so the read path's own gate can be a
/// plain flag in the layer that reads it rather than a call into this crate.
static NOTIFIER: Spinlock<Option<fn(bool)>, TtyArmClass> = Spinlock::new(None);

struct TtyArmClass;
impl sync::LockClass for TtyArmClass { fn rank() -> u16 { 35 } fn name() -> &'static str { "TtyArm" } }

/// Install the arm/disarm notifier. Idempotent; installed on first use by the
/// layer that owns the read path. # C: O(1)
pub fn set_arm_notifier(f: fn(bool)) { *NOTIFIER.lock() = Some(f); }

/// # C: O(N_groups)
pub(crate) fn republish(s: &state::AuditState) {
    let n = s.tty.groups.values().filter(|g| g.mask != 0).count();
    let was = ARMED.swap(n, Ordering::Release);
    if (was != 0) == (n != 0) { return; }
    let f = *NOTIFIER.lock();
    if let Some(f) = f { f(n != 0); }
}

/// Whether any thread group at all is marked for tty auditing.
/// # C: O(1)
pub fn armed() -> bool { ARMED.load(Ordering::Acquire) != 0 }

/// Write out one flush.
/// # C: O(len)
fn emit(desc: &[u8], a: TtyActor<'_>, p: Push) {
    let _ = producers::log_tty(desc, a, p.dev, &p.data);
}

/// Accumulate terminal input this task just read, and write out whatever that
/// completed. See [`TtyAudit::add_data`].
/// # C: O(len)
pub fn add_data(tgid: u32, a: TtyActor<'_>, dev: Devno, icanon: bool, echo: bool, pty_master: bool,
                data: &[u8])
{
    if !armed() { return; }
    let (pushes, logs) = state::with(|s| {
        let out = s.tty.add_data(tgid, dev, icanon, echo, pty_master, data);
        (out, push_logs(s.cfg.enabled))
    });
    if !logs { return; }
    for p in pushes { emit(TTY_DESC_INPUT, a, p); }
}

/// Flush at a line-discipline boundary. See [`TtyAudit::push`].
/// # C: O(len)
pub fn push(tgid: u32, a: TtyActor<'_>) -> Result<(), Errno> {
    if !armed() { return Err(Errno::Eperm); }
    let (out, logs) = state::with(|s| (s.tty.push(tgid), push_logs(s.cfg.enabled)));
    let out = out?;
    if let (true, Some(p)) = (logs, out) { emit(TTY_DESC_INPUT, a, p); }
    Ok(())
}

/// The last thread of a group is dying: write out its final partial line.
/// # C: O(len)
pub fn exit(tgid: u32, a: TtyActor<'_>) {
    if !armed() { return; }
    let (out, logs) = state::with(|s| {
        let out = s.tty.exit(tgid);
        republish(s);
        (out, push_logs(s.cfg.enabled))
    });
    if let (true, Some(p)) = (logs, out) { emit(TTY_DESC_INPUT, a, p); }
}

/// A new thread group inherits its parent's mask. See [`TtyAudit::fork`].
/// # C: O(log N_groups)
pub fn fork(parent_tgid: u32, child_tgid: u32) {
    if !armed() { return; }
    state::with(|s| { s.tty.fork(parent_tgid, child_tgid); republish(s); });
}

/// Read a thread group's status, for `AUDIT_TTY_GET`.
/// # C: O(log N_groups)
pub fn status(tgid: u32) -> u32 { state::with(|s| s.tty.mask(tgid)) }

/// Install a thread group's status, for `AUDIT_TTY_SET`; returns the old mask.
/// # C: O(log N_groups)
pub fn set_status(tgid: u32, mask: u32) -> u32 {
    state::with(|s| { let old = s.tty.set_mask(tgid, mask); republish(s); old })
}

#[cfg(test)]
#[path = "tests/tty.rs"]
mod tests;
