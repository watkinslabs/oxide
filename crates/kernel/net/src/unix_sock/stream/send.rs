use alloc::{sync::Arc, vec::Vec};

use vfs;

use super::{UnixPair, UnixStreamError, UnixStreamSendError};
use super::super::{GcRights, UnixEnd};
#[cfg(feature = "debug-dbus")]
use super::trace::trace_dbus_stream;

impl UnixPair {
    /// Append `data` from `end` into the ring it writes to.
    /// Returns the number of bytes accepted (full byte count for v1).
    /// # C: O(data.len())
    pub fn write(&self, end: UnixEnd, data: &[u8]) -> Result<usize, UnixStreamError> {
        self.write_bounded(end, data, usize::MAX).map_err(|_| UnixStreamError::PeerClosed)
    }

    /// Append as many bytes as fit under the sender's queue cap. # C: O(data.len())
    pub fn write_bounded(&self, end: UnixEnd, data: &[u8], cap: usize) -> Result<usize, UnixStreamSendError> {
        self.write_inner(end, data, GcRights::from_files(Vec::new()), None, cap)
    }

    /// Append `data` plus a SCM_RIGHTS burst, tagging the fds to the
    /// stream offset of `data`'s first byte so the peer's recvmsg
    /// delivers them exactly with that byte (Linux skb-`fp` semantics)
    /// rather than popping them ahead of their D-Bus message.
    /// # C: O(data.len() + fds)
    pub fn write_with_fds(&self, end: UnixEnd, data: &[u8], fds: Vec<Arc<vfs::File>>) -> Result<usize, UnixStreamError> {
        self.write_with_rights(end, data, GcRights::from_files(fds))
    }

    /// Enqueue a classified canonical SCM_RIGHTS batch. # C: O(data.len() + rights)
    pub fn write_with_rights(&self, end: UnixEnd, data: &[u8], rights: GcRights) -> Result<usize, UnixStreamError> {
        self.write_inner(end, data, rights, None, usize::MAX).map_err(|_| UnixStreamError::PeerClosed)
    }

    /// Enqueue one rights-bearing stream segment under a byte cap. # C: O(data.len() + rights)
    pub fn write_with_rights_bounded(&self, end: UnixEnd, data: &[u8], rights: GcRights,
        cap: usize) -> Result<usize, UnixStreamSendError>
    { self.write_inner(end, data, rights, None, cap) }

    /// Enqueue rights with an explicitly validated SCM_CREDENTIALS record. # C: O(data.len() + rights)
    pub fn write_with_rights_and_creds(&self, end: UnixEnd, data: &[u8], rights: GcRights, creds: (u32, u32, u32)) -> Result<usize, UnixStreamError> {
        self.write_inner(end, data, rights, Some(creds), usize::MAX).map_err(|_| UnixStreamError::PeerClosed)
    }

    /// Enqueue one credential-bearing stream segment under a byte cap. # C: O(data.len() + rights)
    pub fn write_with_rights_and_creds_bounded(&self, end: UnixEnd, data: &[u8], rights: GcRights,
        creds: (u32, u32, u32), cap: usize) -> Result<usize, UnixStreamSendError>
    { self.write_inner(end, data, rights, Some(creds), cap) }

    /// # C: O(data.len() + rights)
    fn write_inner(&self, end: UnixEnd, data: &[u8], rights: GcRights,
        supplied_creds: Option<(u32, u32, u32)>, cap: usize) -> Result<usize, UnixStreamSendError> {
        if data.is_empty() { return Ok(0); }
        // DIAG (debug-dbus): dump AF_UNIX SOCK_STREAM messages that mention the
        // login1 session interface or carry a D-Bus error reply. dbus-broker
        // relays every method call/reply through these streams, so this captures
        // mutter's Properties.GetAll on /org/freedesktop/login1/session/<id> AND
        // logind's reply (method_return or org.freedesktop.DBus.Error.*). D-Bus
        // encodes object paths / interface / error names as inline ASCII, so a
        // substring scan of the wire buffer surfaces the exact failing call -
        // pinning why mutter's get_session_proxy() returns NULL ("no matching
        // session"). Default-off; zero bytes on the hot path.
        #[cfg(feature = "debug-dbus")]
        trace_dbus_stream(data);
        let stable_cred = match end { UnixEnd::A => self.cred_a.get(), UnixEnd::B => self.cred_b.get() };
        #[cfg(target_os = "oxide-kernel")]
        let sender_cred = supplied_creds.unwrap_or_else(|| sched::live::current().map(|c| {
            use core::sync::atomic::Ordering::Relaxed;
            (c.visible_pid(), c.creds.ruid.load(Relaxed), c.creds.rgid.load(Relaxed))
        }).unwrap_or(stable_cred));
        #[cfg(not(target_os = "oxide-kernel"))]
        let sender_cred = supplied_creds.unwrap_or(stable_cred);
        if self.peer_gone(end) { return Err(UnixStreamSendError::PeerClosed); }
        let receiver = self.gc_node(end.other());
        let transition = receiver.pin();
        rights.register(&receiver);
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if self.peer_gone(end) || g.closed_writer || g.reader_shutdown {
            return Err(UnixStreamSendError::PeerClosed);
        }
        let take = core::cmp::min(data.len(), cap.saturating_sub(g.buf.len()));
        if take == 0 { return Err(UnixStreamSendError::WouldBlock); }
        // Tag the burst to the offset of the first byte of THIS write so a
        // reader delivers it with (never before) that byte.
        if !rights.is_empty() {
            // [SCMW] AF_UNIX SOCK_STREAM SCM_RIGHTS send probe: logs the
            // sender vpid + fd count of every fd-carrying write. On the
            // D-Bus system bus the only fd-carrying stream messages are
            // logind's CreateSessionWithPIDFD (leader pidfd) and its reply
            // (session_fd), so this maps every hop of the two-hop broker
            // relay with near-zero noise. Kept permanently behind the
            // `debug-scmfd` cargo feature (default-off).
            #[cfg(feature = "debug-scmfd")]
            {
                let vpid = sched::live::current().map(|c| c.visible_pid()).unwrap_or(0);
                klog::write_raw(b"[SCMW pid=");
                klog::write_dec_u64(vpid as u64);
                klog::write_raw(b" nfds=");
                klog::write_dec_u64(rights.len() as u64);
                klog::write_raw(b"]\n");
            }
        }
        if !data.is_empty() || !rights.is_empty() {
            let off = g.produced;
            g.ancillary.push_back((off, rights, sender_cred));
        }
        g.buf.extend(data[..take].iter().copied());
        let n = take;
        g.produced += n as u64;
        drop(g);
        drop(transition);
        #[cfg(target_os = "oxide-kernel")]
        {
            // debug-syscost DIAG: log dbus-broker's / polkit's connected-socket
            // writes (pair ptr + end + nbytes) to trace the polkit-broker reply
            // path. dbus-broker writing end A to a_to_b IS the reply polkit waits
            // for on its ppoll (fd=6, empty read queue = no reply landed).
            #[cfg(feature = "debug-syscost")]
            {
                let cur = sched::live::current();
                let target = cur.map(|c| {
                    c.creds.euid.load(core::sync::atomic::Ordering::Acquire) == 1000
                        || c.with_exe_path(|p| p.map(|s| s.contains("dbus-broker") || s.contains("polkit")).unwrap_or(false))
                }).unwrap_or(false);
                if target {
                    if let Some(c) = cur {
                        let nm = c.exe_path().unwrap_or_default();
                        klog::write_raw(b"[UXWRITE tid="); klog::write_dec_u64(c.tid as u64);
                        klog::write_raw(b" comm="); klog::write_raw(nm.as_bytes());
                        klog::write_raw(b" pair="); klog::write_hex_u64(self as *const _ as u64);
                        klog::write_raw(if matches!(end, UnixEnd::A) { b" end=A" } else { b" end=B" });
                        klog::write_raw(b" n="); klog::write_dec_u64(n as u64);
                        klog::write_raw(b"]\n");
                    }
                }
            }
            // Writer on `end` feeds the ring the OTHER end reads from.
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            // F181a: targeted epoll wake
            super::super::wake_peer_subs(self, end, vfs::POLL_IN);
        }
        Ok(n)
    }
}
