//! One durable runtime registry owner.
use super::*;
impl RegistryStore {
    /// Load an existing per-user database or create a new one when absent,
    /// waiting for a contending session to finish. # C: O(file bytes)
    pub fn open(path: &Path) -> Result<Self, Error> { Self::open_with_wait(path, true) }

    /// Open only if no other session owns this database. A held lock answers
    /// `AlreadyServing` rather than parking, which is what lets a service
    /// decide it is a duplicate before it touches any shared endpoint.
    /// # C: O(file bytes)
    pub fn open_exclusive(path: &Path) -> Result<Self, Error> { Self::open_with_wait(path, false) }

    fn open_with_wait(path: &Path, wait: bool) -> Result<Self, Error> {
        let lock_path = path.with_extension("oxide-registry.lock");
        let lock = OpenOptions::new().read(true).write(true).create(true).open(lock_path)?;
        let fd = lock.as_raw_fd();
        let operation = if wait { libc::LOCK_EX } else { libc::LOCK_EX | libc::LOCK_NB };
        // SAFETY: the descriptor belongs to the live sidecar File and remains open for the session.
        if unsafe { libc::flock(fd, operation) } != 0 {
            let error = io::Error::last_os_error();
            let raw = error.raw_os_error();
            if !wait && (raw == Some(libc::EWOULDBLOCK) || raw == Some(libc::EAGAIN)) { return Err(Error::AlreadyServing); }
            return Err(error.into());
        }
        let registry = match fs::symlink_metadata(path) {
            Ok(_) => Registry::load(path)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let registry = Registry::new_with_startup_state()?;
                registry.save(path)?;
                registry
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self { registry, path: path.to_path_buf(), _lock: lock, dirty: false, subscriptions: BTreeMap::new(), next_subscription: 1 })
    }

    /// Borrow the live canonical registry session. # C: O(1)
    pub fn registry(&self) -> &Registry { &self.registry }

    /// Borrow the live registry and mark the session dirty. # C: O(1)
    pub fn registry_mut(&mut self) -> &mut Registry { self.dirty = true; &mut self.registry }

    /// Persist changes atomically; unchanged sessions do no I/O. # C: O(N_values)
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.dirty { self.registry.save(&self.path)?; self.dirty = false; } Ok(())
    }

    /// Return whether the session has unflushed mutations. # C: O(1)
    pub fn is_dirty(&self) -> bool { self.dirty }

    /// Execute one typed registry operation against this session. # C: O(depth log N)
    pub fn execute(&mut self, request: Request) -> Response {
        match request {
            Request::Open { root, subkey } => self.registry.open_handle(root, &subkey).map_or_else(Response::Failure, Response::Handle),
            Request::Create { root, subkey } => self.registry.create_handle(root, &subkey).map_or_else(Response::Failure, |handle| { self.dirty = true; Response::Handle(handle) }),
            Request::OpenRelative { key, subkey } => self.registry.open_relative_handle(key, &subkey).map_or_else(Response::Failure, Response::Handle),
            Request::CreateRelative { key, subkey } => self.registry.create_relative_handle(key, &subkey).map_or_else(Response::Failure, |handle| { self.dirty = true; Response::Handle(handle) }),
            Request::Rename { key, name } => self.registry.rename_key_handle(key, &name).map_or_else(Response::Failure, |_| { self.dirty = true; Response::Success }),
            Request::Set { key, name, value } => self.registry.set_value_handle(key, &name, value).map_or_else(Response::Failure, |_| { self.dirty = true; self.mark_changed(key); Response::Success }),
            Request::DeleteValue { key, name } => self.registry.delete_value_handle(key, &name).map_or_else(Response::Failure, |_| { self.dirty = true; self.mark_changed(key); Response::Success }),
            Request::DeleteKey { key } => self.registry.delete_key_handle(key).map_or_else(Response::Failure, |_| { self.dirty = true; Response::Success }),
            Request::Query { key, name } => self.registry.query_value_handle(key, &name).map_or_else(Response::Failure, Response::Value),
            Request::EnumKeys { key } => self.registry.subkeys_handle(key).map_or_else(Response::Failure, Response::Keys),
            Request::EnumValues { key } => self.registry.values_handle(key).map_or_else(Response::Failure, Response::Values),
            Request::QueryKey { key } => self.registry.query_key_handle(key).map_or_else(Response::Failure, Response::KeyInfo),
            Request::Close { key } => self.registry.close_handle(key).map_or_else(Response::Failure, |_| { self.subscriptions.retain(|_, state| state.key != key); Response::Success }),
            Request::Flush { key } => {
                if !self.registry.handles.contains_key(&key) { return Response::Failure(Error::MissingKey); }
                self.flush().map_or_else(|error| Response::Failure(error), |_| Response::Success)
            }
            Request::SaveHive { key } => self.registry.export_handle(key).map_or_else(Response::Failure, Response::Bytes),
            Request::LoadHive { root, subkey, bytes } => self.load_hive(root, &subkey, &bytes)
                .map_or_else(Response::Failure, |_| Response::Success),
            Request::LoadHiveRelative { key, subkey, bytes } => self.load_hive_relative(key, &subkey, &bytes)
                .map_or_else(Response::Failure, |_| Response::Success),
            Request::QueryPath { key } => self.registry.path_for_handle(key).map_or_else(Response::Failure, Response::Text),
            Request::Subscribe { key, filter, subtree } => {
                if filter != crate::REG_NOTIFY_CHANGE_LAST_SET || self.registry.path_for_handle(key).is_err() { return Response::Failure(Error::InvalidPath); }
                let id = self.next_subscription; self.next_subscription = self.next_subscription.saturating_add(1);
                self.subscriptions.insert(id, Subscription { key, filter, subtree, pending: false }); Response::Subscription(id)
            }
            Request::PollSubscription { subscription } => match self.subscriptions.get(&subscription).map(|state| state.pending) {
                Some(true) => { self.subscriptions.remove(&subscription); Response::Notification }
                Some(false) => Response::Success,
                None => Response::Failure(Error::MissingKey),
            },
            Request::Unsubscribe { subscription } => if self.subscriptions.remove(&subscription).is_some() { Response::Success } else { Response::Failure(Error::MissingKey) },
        }
    }

    fn mark_changed(&mut self, key: KeyHandle) {
        let Some(changed) = self.registry.path_for_handle(key).ok().map(|path| canonical(&path)) else { return };
        for state in self.subscriptions.values_mut() {
            let Some(watched) = self.registry.path_for_handle(state.key).ok().map(|path| canonical(&path)) else { continue };
            let matches = state.key == key || state.subtree && changed.starts_with(&format!("{}\\", watched));
            if matches && state.filter & REG_NOTIFY_CHANGE_LAST_SET != 0 { state.pending = true; }
        }
    }

    fn load_hive(&mut self, root: Root, subkey: &str, bytes: &[u8]) -> Result<(), Error> {
        let target = join_path(root.name(), subkey)?;
        self.commit_hive(target, bytes)
    }

    fn load_hive_relative(&mut self, key: KeyHandle, subkey: &str, bytes: &[u8]) -> Result<(), Error> {
        let parent = self.registry.live_handle_path(key)?;
        let target = join_path(&parent, subkey)?;
        self.commit_hive(target, bytes)
    }

    fn commit_hive(&mut self, target: String, bytes: &[u8]) -> Result<(), Error> {
        let mut candidate = self.registry.clone();
        candidate.import_path(&target, bytes)?;
        self.registry = candidate;
        self.dirty = true;
        Ok(())
    }
}
