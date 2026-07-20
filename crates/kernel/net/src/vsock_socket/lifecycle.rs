use super::*;

impl VsockSocket {
    /// Resolve one VSOCK socket option without UAPI memory access. # C: O(1)
    pub fn get_socket_option(&self, level: u64, optname: u64) -> Result<i32, crate::NetError> {
        use crate::uapi::{SOL_SOCKET, SO_ACCEPTCONN, SO_DOMAIN, SO_PROTOCOL, SO_TYPE};
        const SOL_VSOCK: u64 = 287;
        const SO_VM_SOCKETS_BUFFER_SIZE: u64 = 0;
        const SO_VM_SOCKETS_BUFFER_MIN_SIZE: u64 = 1;
        const SO_VM_SOCKETS_BUFFER_MAX_SIZE: u64 = 2;
        if level == SOL_VSOCK {
            if self.is_datagram() { return Err(crate::NetError::Enoprotoopt); }
            return match optname {
                SO_VM_SOCKETS_BUFFER_SIZE => Ok(self.buffer_size.load(core::sync::atomic::Ordering::Acquire) as i32),
                SO_VM_SOCKETS_BUFFER_MIN_SIZE => Ok(self.buffer_min_size.load(core::sync::atomic::Ordering::Acquire) as i32),
                SO_VM_SOCKETS_BUFFER_MAX_SIZE => Ok(self.buffer_max_size.load(core::sync::atomic::Ordering::Acquire) as i32),
                _ => Err(crate::NetError::Enoprotoopt),
            };
        }
        if level != SOL_SOCKET { return Err(crate::NetError::Enoprotoopt); }
        match optname {
            SO_TYPE => Ok(self.so_type.load(core::sync::atomic::Ordering::Acquire) as i32),
            SO_DOMAIN => Ok(crate::socket_args::AF_VSOCK as i32),
            SO_PROTOCOL => Ok(0),
            SO_ACCEPTCONN => Ok(i32::from(matches!(*self.kind.lock(), VsockKind::Listener(_)))),
            _ => Err(crate::NetError::Enoprotoopt),
        }
    }

    /// Reject unsupported VSOCK set options before UAPI parsing. # C: O(1)
    pub fn set_socket_option(&self, level: u64, optname: u64, value: i32) -> Result<(), crate::NetError> {
        const SOL_VSOCK: u64 = 287;
        const SO_VM_SOCKETS_BUFFER_SIZE: u64 = 0;
        const SO_VM_SOCKETS_BUFFER_MIN_SIZE: u64 = 1;
        const SO_VM_SOCKETS_BUFFER_MAX_SIZE: u64 = 2;
        if level != SOL_VSOCK { return Err(crate::NetError::Enoprotoopt); }
        if self.is_datagram() { return Err(crate::NetError::Enoprotoopt); }
        if !matches!(optname, SO_VM_SOCKETS_BUFFER_SIZE
            | SO_VM_SOCKETS_BUFFER_MIN_SIZE | SO_VM_SOCKETS_BUFFER_MAX_SIZE) {
            return Err(crate::NetError::Enoprotoopt);
        }
        if value <= 0 { return Err(crate::NetError::Einval); }
        let value = value as u32;
        match optname {
            SO_VM_SOCKETS_BUFFER_MIN_SIZE => {
                if value > self.buffer_max_size.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Einval); }
                self.buffer_min_size.store(value, core::sync::atomic::Ordering::Release);
            }
            SO_VM_SOCKETS_BUFFER_MAX_SIZE => {
                if value < self.buffer_min_size.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Einval); }
                self.buffer_max_size.store(value, core::sync::atomic::Ordering::Release);
                self.buffer_size.fetch_min(value, core::sync::atomic::Ordering::AcqRel);
            }
            SO_VM_SOCKETS_BUFFER_SIZE => {
                let min = self.buffer_min_size.load(core::sync::atomic::Ordering::Acquire);
                let max = self.buffer_max_size.load(core::sync::atomic::Ordering::Acquire);
                if value < min || value > max { return Err(crate::NetError::Einval); }
                self.buffer_size.store(value, core::sync::atomic::Ordering::Release);
            }
            _ => unreachable!("recognized VSOCK option was not dispatched"),
        }
        Ok(())
    }

    /// Bind an unbound endpoint to one typed sockaddr_vm identity. # C: O(N endpoints)
    pub fn bind(&self, family: u16, port: u32, cid: u64) -> Result<(), crate::NetError> {
        if family != crate::socket_args::AF_VSOCK as u16 {
            return Err(crate::NetError::Eafnosupport);
        }
        // Linux virtio-vsock exposes a DGRAM socket object, but its current
        // transport `dgram_bind` callback returns EOPNOTSUPP.
        if self.is_datagram() { return Err(crate::NetError::Eopnotsupp); }
        let mut kind = self.kind.lock();
        if !matches!(*kind, VsockKind::Init) { return Err(crate::NetError::Einval); }
        let owner = vsock::bind_owner_for_cid(cid)?;
        let reservation = vsock::TABLE.reserve_bind(owner,
            if port == u32::MAX { None } else { Some(port) })?;
        let port = reservation.port;
        *self.binding.lock() = VsockBinding::Explicit(reservation);
        *kind = VsockKind::Bound { port, owner };
        Ok(())
    }

    /// Promote this socket's exact bind reservation into a listener. # C: O(N endpoints)
    pub fn listen(&self) -> Result<(), crate::NetError> {
        self.listen_with_backlog(crate::sysctl::DEFAULT_SOMAXCONN as i32)
    }

    /// Promote a VSOCK bind with Linux-normalized listen backlog capacity. # C: O(N endpoints)
    pub fn listen_with_backlog(&self, backlog: i32) -> Result<(), crate::NetError> {
        if self.is_datagram() { return Err(crate::NetError::Eopnotsupp); }
        let mut kind = self.kind.lock();
        match &*kind {
            VsockKind::Listener(_) => return Ok(()),
            VsockKind::Bound { .. } => {}
            _ => return Err(crate::NetError::Einval),
        }
        let reservation = match &*self.binding.lock() {
            VsockBinding::Explicit(reservation) => reservation.clone(),
            _ => return Err(crate::NetError::Einval),
        };
        let cap = crate::sysctl::normalize_listen_backlog(backlog, crate::sysctl::DEFAULT_SOMAXCONN);
        let listener = vsock::TABLE.promote_bind_with_filter_and_backlog(&reservation, &self.bpf_filter, cap)
            .ok_or(crate::NetError::Eaddrinuse)?;
        *self.binding.lock() = VsockBinding::None;
        *kind = VsockKind::Listener(listener);
        Ok(())
    }

    /// Publish a newly started or connected transport connection. # C: O(1)
    pub fn attach_conn(&self, conn: Arc<VsockConn>) -> Result<(), crate::NetError> {
        let mut kind = self.kind.lock();
        if !matches!(*kind, VsockKind::Init | VsockKind::Bound { .. }) {
            return Err(crate::NetError::Einval);
        }
        *kind = VsockKind::Conn(conn);
        Ok(())
    }

    /// Start a transport connect while retaining its exact local identity. # C: O(RTT)
    pub fn connect_transport(self: &Arc<Self>, peer_cid: u64, peer_port: u32, nonblock: bool)
        -> Result<(), crate::NetError>
    {
        if self.is_datagram() { return Err(crate::NetError::Eopnotsupp); }
        let mut kind = self.kind.lock();
        if let VsockKind::Conn(conn) = &*kind {
            let conn = conn.clone();
            let st = *conn.st.lock();
            drop(kind);
            return match st {
                VsockState::Connecting if nonblock => Err(crate::NetError::Ealready),
                VsockState::Connecting => vsock::connect_wait(&conn),
                VsockState::Connected | VsockState::RcvShutdown => Err(crate::NetError::Eisconn),
                VsockState::Closed => Err(crate::NetError::Enotconn),
            };
        }
        let auto = matches!(*kind, VsockKind::Init);
        let (owner, port) = match &*kind {
            VsockKind::Init => {
                let owner = vsock::driver_owner().ok_or(crate::NetError::Enetunreach)?;
                let reservation = vsock::TABLE.reserve_bind(Some(owner), None)?;
                let port = reservation.port;
                *self.binding.lock() = VsockBinding::Auto(reservation);
                (Some(owner), Some(port))
            }
            VsockKind::Bound { owner, port } => (*owner, Some(*port)),
            _ => return Err(crate::NetError::Einval),
        };
        let conn = match vsock::prepare_connect_owned(owner, port, peer_cid, peer_port,
            Some(Arc::downgrade(self))) {
            Ok(conn) => conn,
            Err(error) => {
                if auto {
                    if let VsockBinding::Auto(binding) = &*self.binding.lock() {
                        *kind = VsockKind::Bound { port: binding.port, owner: binding.owner };
                    }
                }
                return Err(error);
            }
        };
        conn.set_local_buf_alloc(self.buffer_size.load(core::sync::atomic::Ordering::Acquire));
        *kind = VsockKind::Conn(conn.clone());
        drop(kind);
        vsock::start_connect(&conn)?;
        let kind = self.kind.lock();
        let current = matches!(&*kind,
            VsockKind::Conn(published) if Arc::ptr_eq(published, &conn));
        if current { let _ = self.error.take(); }
        if nonblock {
            #[cfg(target_os = "oxide-kernel")]
            let deadline = crate::sock_io::monotonic_ns_safe()
                .saturating_add(vsock::VSOCK_CONNECT_TIMEOUT_NS);
            #[cfg(not(target_os = "oxide-kernel"))]
            let deadline = vsock::VSOCK_CONNECT_TIMEOUT_NS;
            let st = conn.st.lock();
            if current && *st == VsockState::Connecting {
                vsock::arm_connect_timeout(&conn, deadline);
            }
            drop(st);
            drop(kind);
            return Ok(());
        }
        drop(kind);
        #[cfg(test)]
        if let Some(hook) = self.connect_wait_hook.lock().take() { hook(self); }
        match vsock::connect_wait(&conn) {
            Ok(()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Consume completion for only the currently attached outbound connection. # C: O(1)
    pub(crate) fn complete_connect(&self, conn: &Arc<VsockConn>, error: Option<crate::NetError>) {
        let mut kind = self.kind.lock();
        if !matches!(&*kind, VsockKind::Conn(current) if Arc::ptr_eq(current, conn)) { return; }
        let binding = self.binding.lock();
        let next = match &*binding {
            VsockBinding::Explicit(binding) =>
                VsockKind::Bound { port: binding.port, owner: binding.owner },
            VsockBinding::Auto(binding) =>
                VsockKind::Bound { port: binding.port, owner: binding.owner },
            VsockBinding::None => VsockKind::Init,
        };
        *kind = next;
        self.read_shut.store(false, core::sync::atomic::Ordering::Release);
        if let Some(error) = error { self.error.set(connect_errno(error)); }
        drop(binding);
        drop(kind);
        self.poll_subs.notify_mask(if error.is_some() {
            vfs::POLL_ERR | vfs::POLL_OUT
        } else { vfs::POLL_OUT });
    }

    fn detach_conn(&self, conn: &Arc<VsockConn>) {
        let mut kind = self.kind.lock();
        let current = match &*kind {
            VsockKind::Conn(current) if Arc::ptr_eq(current, conn) => current.clone(),
            _ => return,
        };
        let mut binding = self.binding.lock();
        vsock::close(&current);
        let next = match &*binding {
            VsockBinding::Explicit(binding) =>
                VsockKind::Bound { port: binding.port, owner: binding.owner },
            VsockBinding::Auto(_) => {
                let old = core::mem::replace(&mut *binding, VsockBinding::None);
                if let VsockBinding::Auto(binding) = old {
                    let _ = vsock::TABLE.release_bind(&binding);
                }
                VsockKind::Init
            }
            VsockBinding::None => VsockKind::Init,
        };
        *kind = next;
        self.read_shut.store(false, core::sync::atomic::Ordering::Release);
    }

    /// Disconnect while preserving an explicit bind reservation. # C: O(N conns)
    pub fn disconnect(&self) -> Result<(), crate::NetError> {
        let kind = self.kind.lock();
        let conn = match &*kind {
            VsockKind::Conn(conn) => conn.clone(),
            VsockKind::Init | VsockKind::Bound { .. } => return Ok(()),
            _ => return Err(crate::NetError::Einval),
        };
        drop(kind);
        self.detach_conn(&conn);
        Ok(())
    }

    /// Tear down the endpoint at final open-file-description release. # C: O(N pending accepts)
    pub fn release_file(&self) {
        if self.released.swap(true, core::sync::atomic::Ordering::AcqRel) { return; }
        let mut kind = self.kind.lock();
        let mut binding = self.binding.lock();
        match &*kind {
            VsockKind::Listener(listener) => { let _ = vsock::TABLE.remove_listener_exact(listener); }
            VsockKind::Conn(conn) => vsock::close(conn),
            VsockKind::Init | VsockKind::Bound { .. } | VsockKind::Released => {}
        }
        let old = core::mem::replace(&mut *binding, VsockBinding::None);
        if let VsockBinding::Explicit(reservation) | VsockBinding::Auto(reservation) = old {
            let _ = vsock::TABLE.release_bind(&reservation);
        }
        *kind = VsockKind::Released;
    }
}

fn connect_errno(error: crate::NetError) -> i32 {
    use syscall::errno::Errno;
    match error {
        crate::NetError::Econnrefused => Errno::Econnrefused as i32,
        crate::NetError::Econnreset => Errno::Econnreset as i32,
        crate::NetError::Enetunreach => Errno::Enetunreach as i32,
        crate::NetError::Etimedout | crate::NetError::Eio => Errno::Etimedout as i32,
        _ => Errno::Eio as i32,
    }
}
