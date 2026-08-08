// The supervisor side of the protocol: the listener fd's ioctls. Usercopy and
// blocking live here; every transition rule is `state.rs`, every number is
// `uapi.rs`, and the descriptor injection is `addfd.rs`.

extern crate alloc;

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::listener::{self, Listener};
use super::uapi::*;
use super::wait::{self, Woke};

/// Route a listener fd's ioctl. The caller has already established that the
/// descriptor IS a listener.
/// # C: O(N_notifications)
pub fn dispatch(l: &Arc<Listener>, cmd: u32, arg: u64) -> i64 {
    let r = match cmd {
        IOCTL_NOTIF_RECV      => recv(l, arg),
        IOCTL_NOTIF_SEND      => send(l, arg),
        IOCTL_NOTIF_ID_VALID | IOCTL_NOTIF_ID_VALID_WRONG_DIR => id_valid(l, arg),
        // The flags word is the ARGUMENT of this command, not a pointer to it.
        IOCTL_NOTIF_SET_FLAGS => l.inner.lock().set_flags(arg).map(|_| 0),
        // Extensible-argument commands carry their payload size in the command
        // itself, so they are matched with size and direction stripped.
        _ if ea_ioctl(cmd) == ea_ioctl(IOCTL_NOTIF_ADDFD) =>
            super::addfd::addfd(l, arg, ioc_size(cmd)),
        _ => Err(Errno::Einval),
    };
    match r { Ok(v) => v, Err(e) => -(e.as_i32() as i64) }
}

/// `SECCOMP_IOCTL_NOTIF_RECV`: block until a notification is waiting, then
/// hand the oldest one over and mark it sent.
///
/// The supplied buffer must read as all zeroes. That is what keeps the
/// structure extensible: a program built against a larger `struct
/// seccomp_notif` than this kernel fills would otherwise read stale stack
/// contents as kernel-supplied members.
/// # C: O(N_notifications) + wait
fn recv(l: &Arc<Listener>, arg: u64) -> Result<i64, Errno> {
    let mut buf = [0u8; NOTIF_BYTES as usize];
    uaccess::copy_from_user(&mut buf, arg)?;
    if buf.iter().any(|b| *b != 0) { return Err(Errno::Einval); }

    if !ready_to_recv(l) {
        // SAFETY: syscall process context on the running task's own CPU; the listener lock is not held across the park.
        if unsafe { wait::wait_until(&l.wq, false, || ready_to_recv(l)) } == Woke::Interrupted {
            return Ok(syscall::restart::restart_sys());
        }
    }

    let picked = l.inner.lock().recv();
    // The notified task can be killed between the wake and the lock, taking
    // its notification with it; there is then nothing to hand over.
    let Some((id, tid, data)) = picked else { return Err(Errno::Enoent) };
    let out = encode_notif(id, notified_pid(tid), 0, &data);
    // A notification is now waiting for its reply, which is what makes the
    // listener writable.
    l.wake();
    if uaccess::copy_to_user(arg, &out).is_err() {
        // The supervisor never received it, so put it back rather than leaving
        // the notified task waiting for a reply nobody will send.
        l.inner.lock().recv_undo(id);
        l.wake();
        return Err(Errno::Efault);
    }
    Ok(0)
}

/// Either a notification is waiting to be picked up, or nothing can produce
/// one any more because no task still runs the filter that owns this listener.
/// # C: O(N_notifications + N_tasks)
fn ready_to_recv(l: &Arc<Listener>) -> bool {
    if l.inner.lock().has_pending() { return true; }
    !listener::has_users(l.id)
}

/// The notified thread's identity AS THE SUPERVISOR NUMBERS IT — resolved in
/// the reading task's pid namespace, never stored on the notification, so a
/// supervisor in a different namespace is told a number it can act on.
/// # C: O(1)
fn notified_pid(tid: u32) -> u32 {
    #[cfg(target_os = "oxide-kernel")]
    { sched::registry::display_vtid(tid) as u32 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { tid }
}

/// `SECCOMP_IOCTL_NOTIF_SEND`. # C: O(N_notifications)
fn send(l: &Arc<Listener>, arg: u64) -> Result<i64, Errno> {
    let mut buf = [0u8; NOTIF_RESP_BYTES as usize];
    uaccess::copy_from_user(&mut buf, arg)?;
    let resp = NotifResp::decode(&buf);
    l.inner.lock().reply(resp)?;
    l.wake();
    Ok(0)
}

/// `SECCOMP_IOCTL_NOTIF_ID_VALID`. # C: O(N_notifications)
fn id_valid(l: &Arc<Listener>, arg: u64) -> Result<i64, Errno> {
    let mut buf = [0u8; 8];
    uaccess::copy_from_user(&mut buf, arg)?;
    l.inner.lock().id_valid(u64::from_le_bytes(buf)).map(|_| 0)
}
