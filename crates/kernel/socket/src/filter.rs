use alloc::sync::Arc;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FilterError { PermissionDenied, Locked, NotAttached }

/// Retained common socket-filter target for one open file description.
pub struct FilterFile {
    _file: Arc<vfs::File>,
    filter: Arc<net::bpf_filter::SocketFilter>,
    tcp_namespace: Option<network_namespace::NetworkNamespaceRef>,
}

impl FilterFile {
    /// Classify INET/UNIX/PACKET, NETLINK, or VSOCK without fd-table relookup. # C: O(1)
    pub fn from_file(file: Arc<vfs::File>) -> Option<Self> {
        if let Ok(socket) = file.inode().i_private().clone().downcast::<net::sock::InetSocket>() {
            let family = socket.family.load(core::sync::atomic::Ordering::Acquire);
            let tcp = matches!(family, net::sock::AF_INET | net::sock::AF_INET6)
                && matches!(&*socket.kind.lock(), net::sock::SockKind::TcpInit
                    | net::sock::SockKind::TcpListener(_) | net::sock::SockKind::TcpConn(_));
            return Some(Self {
                _file: file,
                filter: socket.bpf_filter.clone(),
                tcp_namespace: tcp.then(|| socket.net_namespace.clone()),
            });
        }
        if let Ok(socket) = file.inode().i_private().clone()
            .downcast::<net::vsock_socket::VsockSocket>()
        {
            return Some(Self { _file: file, filter: socket.bpf_filter.clone(), tcp_namespace: None });
        }
        if let Ok(socket) = file.inode().i_private().clone().downcast::<netlink::NetlinkSocket>() {
            return Some(Self { _file: file, filter: socket.bpf_filter.clone(), tcp_namespace: None });
        }
        None
    }

    /// Reject mutation before importing mutation-specific program data. # C: O(1)
    pub fn ensure_mutable(&self) -> Result<(), FilterError> {
        self.filter.ensure_mutable().map_err(change_error)
    }

    /// Enforce Linux's CAP_NET_ADMIN restriction for classic TCP filters. # C: O(1)
    pub fn require_classic_admin(&self) -> Result<(), FilterError> {
        let Some(namespace) = self.tcp_namespace.as_ref() else { return Ok(()); };
        #[cfg(target_os = "oxide-kernel")]
        {
            let task = sched::live::current().ok_or(FilterError::PermissionDenied)?;
            if !nscg::has_net_admin_for(task, namespace) {
                return Err(FilterError::PermissionDenied);
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        let _ = namespace;
        Ok(())
    }

    /// Replace the attached filter after caller-complete import. # C: O(program bytes)
    pub fn attach(&self, program: net::bpf_filter::FilterProgram) -> Result<(), FilterError> {
        self.filter.attach(program).map_err(change_error)
    }

    /// Detach the current filter with Linux absent/locked distinction. # C: O(1)
    pub fn detach(&self) -> Result<(), FilterError> {
        self.filter.detach().map_err(change_error)
    }

    /// Apply irreversible SO_LOCK_FILTER state. # C: O(1)
    pub fn set_lock(&self, value: bool) -> Result<(), FilterError> {
        self.filter.set_lock(value).map_err(change_error)
    }

    /// Read common filter lock state. # C: O(1)
    pub fn is_locked(&self) -> bool { self.filter.is_locked() }
}

fn change_error(error: net::bpf_filter::FilterChangeError) -> FilterError {
    match error {
        net::bpf_filter::FilterChangeError::Locked => FilterError::Locked,
        net::bpf_filter::FilterChangeError::NotAttached => FilterError::NotAttached,
    }
}
