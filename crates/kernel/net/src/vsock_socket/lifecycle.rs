use super::*;

impl VsockSocket {
    /// Whether `optname` names one of the u64 Linux VSOCK buffer options.
    /// # C: O(1)
    pub const fn is_vsock_buffer_option(optname: u64) -> bool {
        matches!(optname, crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE
            | crate::uapi::SO_VM_SOCKETS_BUFFER_MIN_SIZE
            | crate::uapi::SO_VM_SOCKETS_BUFFER_MAX_SIZE)
    }

    /// Whether `optname` names either Linux VSOCK connect-timeout ABI number.
    /// # C: O(1)
    pub const fn is_vsock_connect_timeout_option(optname: u64) -> bool {
        matches!(optname, crate::uapi::SO_VM_SOCKETS_CONNECT_TIMEOUT_OLD
            | crate::uapi::SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW)
    }

    /// Set the validated Linux VSOCK connect timeout in nanoseconds. A zero
    /// timeval restores the Linux default. # C: O(1)
    pub fn set_vsock_connect_timeout_ns(&self, timeout_ns: u64) {
        let timeout_ns = if timeout_ns == 0 { vsock::VSOCK_CONNECT_TIMEOUT_NS } else { timeout_ns };
        self.connect_timeout_ns.store(timeout_ns, core::sync::atomic::Ordering::Release);
        if let Some(conn) = self.conn() { conn.set_connect_timeout_ns(timeout_ns); }
    }

    /// Snapshot the Linux VSOCK connect timeout in nanoseconds. # C: O(1)
    pub fn vsock_connect_timeout_ns(&self) -> u64 {
        self.connect_timeout_ns.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Resolve one SOL_SOCKET VSOCK value without UAPI memory access. # C: O(1)
    pub fn get_socket_option(&self, level: u64, optname: u64) -> Result<i32, crate::NetError> {
        use crate::uapi::{SOL_SOCKET, SO_ACCEPTCONN, SO_DOMAIN, SO_PROTOCOL, SO_TYPE};
        if level != SOL_SOCKET { return Err(crate::NetError::Enoprotoopt); }
        match optname {
            SO_TYPE => Ok(self.so_type.load(core::sync::atomic::Ordering::Acquire) as i32),
            SO_DOMAIN => Ok(crate::socket_args::AF_VSOCK as i32),
            SO_PROTOCOL => Ok(0),
            SO_ACCEPTCONN => Ok(i32::from(matches!(*self.kind.lock(), VsockKind::Listener(_)))),
            _ => Err(crate::NetError::Enoprotoopt),
        }
    }

    /// Resolve one Linux `SOL_VSOCK` u64 buffer option. # C: O(1)
    pub fn get_vsock_buffer_option(&self, optname: u64) -> Result<u64, crate::NetError> {
        use crate::uapi::{SO_VM_SOCKETS_BUFFER_MAX_SIZE,
            SO_VM_SOCKETS_BUFFER_MIN_SIZE, SO_VM_SOCKETS_BUFFER_SIZE};
        if self.is_datagram() { return Err(crate::NetError::Enoprotoopt); }
        match optname {
            SO_VM_SOCKETS_BUFFER_SIZE => Ok(self.buffer_size.load(core::sync::atomic::Ordering::Acquire)),
            SO_VM_SOCKETS_BUFFER_MIN_SIZE => Ok(self.buffer_min_size.load(core::sync::atomic::Ordering::Acquire)),
            SO_VM_SOCKETS_BUFFER_MAX_SIZE => Ok(self.buffer_max_size.load(core::sync::atomic::Ordering::Acquire)),
            _ => Err(crate::NetError::Enoprotoopt),
        }
    }

    /// Apply Linux's clamped `SOL_VSOCK` u64 buffer policy. # C: O(1) + credit frame
    pub fn set_vsock_buffer_option(&self, optname: u64, value: u64) -> Result<(), crate::NetError> {
        use crate::uapi::{SO_VM_SOCKETS_BUFFER_MAX_SIZE,
            SO_VM_SOCKETS_BUFFER_MIN_SIZE, SO_VM_SOCKETS_BUFFER_SIZE};
        if self.is_datagram() { return Err(crate::NetError::Enoprotoopt); }
        if !Self::is_vsock_buffer_option(optname) {
            return Err(crate::NetError::Enoprotoopt);
        }
        let _policy = self.kind.lock();
        match optname {
            SO_VM_SOCKETS_BUFFER_MIN_SIZE => {
                self.buffer_min_size.store(value, core::sync::atomic::Ordering::Release);
            }
            SO_VM_SOCKETS_BUFFER_MAX_SIZE => {
                self.buffer_max_size.store(value, core::sync::atomic::Ordering::Release);
            }
            SO_VM_SOCKETS_BUFFER_SIZE => {}
            _ => unreachable!("recognized VSOCK option was not dispatched"),
        }
        let min = self.buffer_min_size.load(core::sync::atomic::Ordering::Acquire);
        let max = self.buffer_max_size.load(core::sync::atomic::Ordering::Acquire);
        let value = if value < min { min } else { value };
        let value = if value > max { max } else { value };
        self.buffer_size.store(value, core::sync::atomic::Ordering::Release);
        let conn = match &*_policy { VsockKind::Conn(conn) => Some(conn.clone()), _ => None };
        drop(_policy);
        if let Some(conn) = conn { vsock::publish_local_buf_alloc(&conn, self.advertised_buffer_size()); }
        Ok(())
    }

    /// Bind an unbound endpoint to one typed sockaddr_vm identity. # C: O(N endpoints)
    pub fn bind(&self, family: u16, port: u32, cid: u64) -> Result<(), crate::NetError> {
        crate::security_admission::check(self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Bind)?;
        if family != crate::socket_args::AF_VSOCK as u16 {
            return Err(crate::NetError::Eafnosupport);
        }
        // Linux virtio-vsock exposes a DGRAM socket object, but its current
        // transport `dgram_bind` callback returns EOPNOTSUPP.
        if self.is_datagram() { return Err(crate::NetError::Eopnotsupp); }
        let mut kind = self.kind.lock();
        if !matches!(*kind, VsockKind::Init) { return Err(crate::NetError::Einval); }
        let owner = vsock::bind_owner_for_cid(cid)?;
        if port != vsock::VMADDR_PORT_ANY && port <= vsock::LAST_RESERVED_PORT
            && !sched::live::current().is_some_and(|current|
                nscg::has_net_bind_service_for(current, &self.net_namespace))
        { return Err(crate::NetError::Eacces); }
        let reservation = vsock::TABLE.reserve_bind(owner,
            if port == vsock::VMADDR_PORT_ANY { None } else { Some(port) })?;
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
        crate::security_admission::check(self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Listen)?;
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
        let somaxconn = crate::sysctl::somaxconn_in(self.net_ns()).ok_or(crate::NetError::Enodev)?;
        let cap = crate::sysctl::normalize_listen_backlog(backlog, somaxconn);
        let transport_type = self.socket_type().connection_transport()
            .expect("datagram listen was rejected before transport selection");
        let listener = vsock::TABLE.promote_bind_with_filter_and_backlog(&reservation,
            &self.bpf_filter, transport_type, cap)
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
        crate::security_admission::check(self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Connect)?;
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
        let transport_type = self.socket_type().connection_transport()
            .expect("datagram connect was rejected before transport selection");
        let conn = match vsock::prepare_connect_owned_type(owner, port, peer_cid, peer_port,
            transport_type, Some(Arc::downgrade(self))) {
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
        conn.set_local_buf_alloc(self.advertised_buffer_size());
        conn.set_connect_timeout_ns(self.vsock_connect_timeout_ns());
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
                .saturating_add(conn.connect_timeout_ns());
            #[cfg(not(target_os = "oxide-kernel"))]
            let deadline = conn.connect_timeout_ns();
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
        crate::NetError::Esocktnosupport => Errno::Esocktnosupport as i32,
        crate::NetError::Etimedout | crate::NetError::Eio => Errno::Etimedout as i32,
        _ => Errno::Eio as i32,
    }
}
