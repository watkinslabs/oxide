// An mq descriptor is a
// real file. `read(2)` reports the queue's state line, `poll(2)` reports
// readability/writability, `flush` (every `close(2)`) drops the caller's
// notification registration, and `write(2)` has no method at all — the POSIX
// data path is `mq_timedsend`/`mq_timedreceive`, so a `write` is EINVAL from
// the default.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::file_ops::FileOps;
use vfs::{File, Inode, KResult, POLL_IN, POLL_OUT, POLL_RDNORM};

use crate::mqueue_policy::notify::{NotifyKind, SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD};

use super::model::{queue_of, release_ref, MqQueue};

/// Linux `FILENT_SIZE` — the fixed width of the state line `read(2)` returns.
const FILENT_SIZE: usize = 80;

struct MqFileOps;

/// `i_fop` for every mqueue inode. # C: O(1)
pub fn mq_file_ops() -> Arc<dyn FileOps> { Arc::new(MqFileOps) }

/// Render `value` left-justified in `width` columns into `out`, Linux's
/// `%-Nlu`/`%-Nd`. # C: O(width)
fn pad_dec(out: &mut [u8], at: &mut usize, value: u64, width: usize) {
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    loop { digits[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; if v == 0 { break; } }
    let start = *at;
    for i in 0..n { out[start + i] = digits[n - 1 - i]; }
    *at = start + n;
    while *at < start + width { out[*at] = b' '; *at += 1; }
}

fn put(out: &mut [u8], at: &mut usize, s: &[u8]) {
    for &b in s { out[*at] = b; *at += 1; }
}

/// The state line format is
/// `"QSIZE:%-10lu NOTIFY:%-5d SIGNO:%-5d NOTIFY_PID:%-6d\n"`, where `QSIZE` is
/// the total BYTES queued, `NOTIFY` the registered `sigev_notify` (0 when
/// unregistered), `SIGNO` the signal only for a SIGEV_SIGNAL registration, and
/// `NOTIFY_PID` the owning tgid.
/// # C: O(N_msgs)
fn state_line(q: &MqQueue, out: &mut [u8; FILENT_SIZE]) -> usize {
    let qsize: usize = q.msgs.lock().iter().map(|m| m.bytes.len()).sum();
    let (notify, signo, pid) = match q.notify.lock().as_ref() {
        None => (0u64, 0u64, 0u64),
        Some(r) => {
            let kind = match r.kind {
                NotifyKind::Signal(_) => SIGEV_SIGNAL,
                NotifyKind::None => SIGEV_NONE,
                NotifyKind::Thread => SIGEV_THREAD,
            };
            let sig = match r.kind { NotifyKind::Signal(s) => s as u64, _ => 0 };
            // `pid_vnr(info->notify_owner)` — the NAMESPACE pid, not the
            // opaque internal tgid the registration is keyed by.
            (kind as u64, sig, sched::live::registry::display_vpid(r.owner_tgid))
        }
    };
    let mut at = 0usize;
    put(out, &mut at, b"QSIZE:");
    pad_dec(out, &mut at, qsize as u64, 10);
    put(out, &mut at, b" NOTIFY:");
    pad_dec(out, &mut at, notify, 5);
    put(out, &mut at, b" SIGNO:");
    pad_dec(out, &mut at, signo, 5);
    put(out, &mut at, b" NOTIFY_PID:");
    pad_dec(out, &mut at, pid, 6);
    put(out, &mut at, b"\n");
    at
}

impl FileOps for MqFileOps {
    /// # C: O(N_msgs)
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let Some(q) = queue_of(&file.inode()) else { return Err(vfs::VfsError::Ebadf) };
        let mut line = [0u8; FILENT_SIZE];
        let len = state_line(&q, &mut line) as u64;
        if off >= len { return Ok(0); }
        let n = core::cmp::min(buf.len(), (len - off) as usize);
        buf[..n].copy_from_slice(&line[off as usize..off as usize + n]);
        Ok(n)
    }

    /// Reports readiness without touching the wait queue. # C: O(1)
    /// This description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_file(&self, inode: &Inode, _pos: u64) -> u32 {
        let Some(p) = inode.private::<super::model::MqInodePrivate>() else { return 0 };
        let q = &p.queue;
        let cur = q.curmsgs();
        let mut mask = 0u32;
        if cur != 0 { mask |= POLL_IN | POLL_RDNORM; }
        if cur < q.maxmsg { mask |= POLL_OUT; }
        mask
    }

    /// Every `close(2)` on
    /// a descriptor whose owner registered the notification tears that
    /// registration down, so a process that exits (or execs — mq descriptors
    /// are unconditionally `O_CLOEXEC`) never leaves a notification aimed at a
    /// tgid that may be recycled.
    /// # C: O(1)
    fn on_flush_file(&self, file: &File) -> KResult<()> {
        let Some(q) = queue_of(&file.inode()) else { return Ok(()) };
        let Some(cur) = sched::live::current() else { return Ok(()) };
        let tgid = cur.tgid.load(Ordering::Acquire);
        let detached = {
            let mut g = q.notify.lock();
            let owned = g.as_ref().map(|r| r.owner_tgid == tgid).unwrap_or(false);
            if owned { super::notify::detach_notification(&mut g) } else { None }
        };
        super::notify::finish_removal(detached);
        Ok(())
    }

    /// Last description gone: an unlinked queue dies here (Linux
    /// `mqueue_evict_inode`). # C: O(N_ns)
    fn on_release_file(&self, file: &File) {
        if let Some(q) = queue_of(&file.inode()) { release_ref(&q); }
    }
}
