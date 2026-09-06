//! Canonical registry database operations and persistence encoding.
use super::*;
impl Registry {
    /// Construct the three predefined roots. # C: O(1)
    pub fn new() -> Self {
        let mut keys = BTreeMap::new(); let mut handles = BTreeMap::new();
        for root in [Root::LocalMachine, Root::CurrentUser, Root::Classes] {
            let path = root.name().to_string();
            let identity = canonical(&path); keys.insert(identity.clone(), Key { path, values: BTreeMap::new() });
            handles.insert(KeyHandle(root_handle(root)), identity);
        }
        Self { keys, handles, deleted: BTreeSet::new(), next_handle: 0x1000 }
    }

    /// Construct a first-run registry with Windows startup state. # C: O(startup key depth)
    pub fn new_with_startup_state() -> Result<Self, Error> {
        let mut registry = Self::new();
        const MACHINE_ENV: &str = r"System\CurrentControlSet\Control\Session Manager\Environment";
        const CURRENT_VERSION: &str = r"Software\Microsoft\Windows NT\CurrentVersion";
        let machine_env = registry.create_key(Root::LocalMachine, MACHINE_ENV)?;
        registry.set_value(&machine_env, "SystemRoot", reg_string(r"C:\Windows"))?;
        registry.set_value(&machine_env, "SystemDrive", reg_string("C:"))?;
        registry.create_key(Root::CurrentUser, "Environment")?;
        registry.create_key(Root::CurrentUser, "Volatile Environment")?;
        let current_version = registry.create_key(Root::LocalMachine, CURRENT_VERSION)?;
        registry.set_value(&current_version, "ProgramFilesDir", reg_string(r"C:\Program Files"))?;
        registry.set_value(&current_version, "CommonFilesDir", reg_string(r"C:\Program Files\Common Files"))?;
        Ok(registry)
    }

    /// Open an existing key relative to a predefined root. # C: O(log N)
    pub fn open_key(&self, root: Root, subkey: &str) -> Result<String, Error> {
        let path = join_path(root.name(), subkey)?;
        let identity = canonical(&path);
        if root == Root::Classes { if self.classes_view_exists(&identity) { Ok(identity) } else { Err(Error::MissingKey) } }
        else if self.keys.contains_key(&identity) { Ok(identity) } else { Err(Error::MissingKey) }
    }

    /// Create all missing path components and return the canonical key handle. # C: O(depth log N)
    pub fn create_key(&mut self, root: Root, subkey: &str) -> Result<String, Error> {
        if root == Root::Classes {
            let path = join_path(root.name(), subkey)?;
            let relative = path.split_once('\\').map_or("", |(_, rest)| rest);
            let backing = classes_backing_path("HKCU", relative);
            self.create_backing_key(&backing)?;
            return Ok(canonical(&path));
        }
        let path = join_path(root.name(), subkey)?;
        let mut current = root.name().to_string();
        for component in path.split('\\').skip(1) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component);
            let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(canonical(&path))
    }

    /// Open an existing key and allocate a process-local 64-bit handle. # C: O(log N)
    pub fn open_handle(&mut self, root: Root, subkey: &str) -> Result<KeyHandle, Error> {
        let key = self.open_key(root, subkey)?; self.allocate_handle(key)
    }

    /// Create a key and allocate a process-local 64-bit handle. # C: O(depth log N)
    pub fn create_handle(&mut self, root: Root, subkey: &str) -> Result<KeyHandle, Error> {
        let key = self.create_key(root, subkey)?; self.allocate_handle(key)
    }

    /// Open a key relative to an existing opaque handle. # C: O(depth log N)
    pub fn open_relative_handle(&mut self, parent: KeyHandle, subkey: &str) -> Result<KeyHandle, Error> {
        let path = self.live_handle_path(parent)?;
        let child = canonical(&join_path(&path, subkey)?);
        if child.starts_with("HKCR\\") && self.classes_view_exists(&child) || self.keys.contains_key(&child) { self.allocate_handle(child) } else { Err(Error::MissingKey) }
    }

    /// Create a key relative to an existing opaque handle. # C: O(depth log N)
    pub fn create_relative_handle(&mut self, parent: KeyHandle, subkey: &str) -> Result<KeyHandle, Error> {
        let path = self.live_handle_path(parent)?;
        if path == "HKCR" || path.starts_with("HKCR\\") {
            let child = join_path(&path, subkey)?;
            let relative = child.split_once('\\').map_or("", |(_, rest)| rest);
            return self.create_handle(Root::Classes, relative);
        }
        let child = self.create_relative_path(&path, subkey)?; self.allocate_handle(child)
    }

    /// Rename one key and every descendant while preserving open-handle identity. # C: O(N_subtree log N)
    pub fn rename_key_handle(&mut self, key: KeyHandle, name: &str) -> Result<(), Error> {
        if name.is_empty() || name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let old = self.live_handle_path(key)?;
        if is_root(&old) { return Err(Error::InvalidPath); }
        let (parent, _) = old.rsplit_once('\\').ok_or(Error::InvalidPath)?;
        let new_path = format!("{}\\{}", parent, name); let new_identity = canonical(&new_path);
        let prefix = format!("{}\\", old);
        if self.keys.keys().any(|path| (*path == new_identity || path.starts_with(&format!("{}\\", new_identity))) && *path != old && !path.starts_with(&prefix)) { return Err(Error::InvalidPath); }
        let affected = self.keys.keys().filter(|path| **path == old || path.starts_with(&prefix)).cloned().collect::<Vec<_>>();
        for path in &affected {
            let mut key_record = self.keys.remove(path).ok_or(Error::MissingKey)?;
            let suffix = &key_record.path[old.len()..]; key_record.path = format!("{}{}", new_path, suffix);
            self.keys.insert(canonical(&key_record.path), key_record);
        }
        for handle_path in self.handles.values_mut() {
            if *handle_path == old || handle_path.starts_with(&prefix) { let suffix = &handle_path[old.len()..]; *handle_path = canonical(&format!("{}{}", new_path, suffix)); }
        }
        Ok(())
    }

    /// Return one predefined root handle without allocating a duplicate. # C: O(1)
    pub fn root_handle(root: Root) -> KeyHandle { KeyHandle(root_handle(root)) }

    /// Set a value through an opaque key handle. # C: O(log N)
    pub fn set_value_handle(&mut self, key: KeyHandle, name: &str, value: Value) -> Result<(), Error> {
        let path = self.live_handle_path(key)?; self.set_value(&path, name, value)
    }

    /// Delete one value through an opaque key handle. # C: O(log N)
    pub fn delete_value_handle(&mut self, key: KeyHandle, name: &str) -> Result<(), Error> {
        let path = self.live_handle_path(key)?; self.delete_value(&path, name)
    }

    /// Delete one leaf key through an opaque handle. # C: O(N_subkeys)
    pub fn delete_key_handle(&mut self, key: KeyHandle) -> Result<(), Error> {
        if self.deleted.contains(&key) { return Ok(()); }
        let path = self.handles.get(&key).cloned().ok_or(Error::MissingKey)?;
        if is_root(&path) || !self.subkeys(&path)?.is_empty() { return Err(Error::InvalidPath); }
        let backing = if path.starts_with("HKCR\\") { classes_backing_path("HKCU", path.strip_prefix("HKCR\\").unwrap_or("")) } else { path.clone() };
        self.keys.remove(&canonical(&backing)).ok_or(Error::MissingKey)?;
        self.deleted.insert(key);
        Ok(())
    }

    /// Query a value through an opaque key handle. # C: O(log N)
    pub fn query_value_handle(&self, key: KeyHandle, name: &str) -> Result<Value, Error> {
        let path = self.live_handle_path(key)?; self.query_value(&path, name)
    }

    /// Enumerate child keys through an opaque key handle. # C: O(N_keys)
    pub fn subkeys_handle(&self, key: KeyHandle) -> Result<Vec<String>, Error> {
        let path = self.live_handle_path(key)?; self.subkeys(&path)
    }

    /// Enumerate values through an opaque key handle in stable display order. # C: O(N_values)
    pub fn values_handle(&self, key: KeyHandle) -> Result<Vec<(String, Value)>, Error> {
        let path = self.handles.get(&key).ok_or(Error::MissingKey)?;
        if path == "HKCR" || path.starts_with("HKCR\\") { return self.classes_values(path); }
        let values = &self.keys.get(path).ok_or(Error::MissingKey)?.values;
        let mut out = values.values().map(|(name, value)| (name.clone(), value.clone())).collect::<Vec<_>>();
        out.sort_by_key(|(name, _)| canonical(name)); Ok(out)
    }

    /// Return key metadata from the canonical registry tree. # C: O(N_values)
    pub fn query_key_handle(&self, key: KeyHandle) -> Result<KeyInfo, Error> {
        let path = self.live_handle_path(key)?;
        let subkeys = self.subkeys(&path)?; let values = self.values_handle(key)?;
        let max_subkey = subkeys.iter().map(|name| name.encode_utf16().count() * 2).max().unwrap_or(0);
        let max_value_name = values.iter().map(|(name, _)| name.encode_utf16().count() * 2).max().unwrap_or(0);
        let max_value_data = values.iter().map(|(_, value)| value.data.len()).max().unwrap_or(0);
        Ok(KeyInfo { name: path.clone(), subkeys: subkeys.len() as u32, max_subkey: max_subkey as u32, values: values.len() as u32, max_value_name: max_value_name as u32, max_value_data: max_value_data as u32 })
    }

    /// Return the canonical display path retained by the registry owner. # C: O(log N)
    pub fn path_for_handle(&self, key: KeyHandle) -> Result<String, Error> {
        let path = self.live_handle_path(key)?;
        if path == "HKCR" || path.starts_with("HKCR\\") { if self.classes_view_exists(&path) { return Ok(path); } return Err(Error::Deleted); }
        Ok(self.keys.get(&path).ok_or(Error::Deleted)?.path.clone())
    }

    /// Close one allocated handle; predefined roots remain valid. # C: O(log N)
    pub fn close_handle(&mut self, key: KeyHandle) -> Result<(), Error> {
        if matches!(key.0, HKEY_LOCAL_MACHINE | HKEY_CURRENT_USER | HKEY_CLASSES_ROOT) { return Err(Error::InvalidPath); }
        if self.deleted.remove(&key) { self.handles.remove(&key); return Ok(()); }
        if self.handles.remove(&key).is_some() { Ok(()) } else { Err(Error::MissingKey) }
    }

    pub(crate) fn live_handle_path(&self, key: KeyHandle) -> Result<String, Error> {
        if self.deleted.contains(&key) { return Err(Error::Deleted); }
        self.handles.get(&key).cloned().ok_or(Error::MissingKey)
    }

    fn allocate_handle(&mut self, path: String) -> Result<KeyHandle, Error> {
        let handle = KeyHandle(self.next_handle); self.next_handle = self.next_handle.checked_add(1).ok_or(Error::InvalidFile)?;
        self.handles.insert(handle, path); Ok(handle)
    }

    fn create_relative_path(&mut self, parent: &str, subkey: &str) -> Result<String, Error> {
        let display_parent = self.keys.get(parent).ok_or(Error::MissingKey)?.path.clone();
        let path = join_path(&display_parent, subkey)?; let mut current = display_parent;
        for component in path.split('\\').skip(parent.split('\\').count()) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component); let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(canonical(&path))
    }

    fn create_backing_key(&mut self, path: &str) -> Result<(), Error> {
        let root = path.split_once('\\').map_or(path, |(root, _)| root);
        let mut current = root.to_string();
        for component in path.split('\\').skip(1) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component); let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(())
    }

    fn classes_view_exists(&self, path: &str) -> bool {
        if path == "HKCR" { return true; }
        let relative = path.strip_prefix("HKCR\\").unwrap_or("");
        ["HKCU", "HKLM"].iter().any(|root| self.keys.contains_key(&canonical(&classes_backing_path(root, relative))))
    }

    fn classes_subkeys(&self, key: &str) -> Result<Vec<String>, Error> {
        if !self.classes_view_exists(key) { return Err(Error::MissingKey); }
        let relative = key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\');
        let mut names = BTreeMap::new();
        for root in ["HKCU", "HKLM"] {
            let backing = classes_backing_path(root, relative);
            if let Ok(children) = self.subkeys(&canonical(&backing)) { for child in children { names.insert(canonical(&child), child); } }
        }
        Ok(names.into_values().collect())
    }

    fn classes_values(&self, key: &str) -> Result<Vec<(String, Value)>, Error> {
        if !self.classes_view_exists(key) { return Err(Error::MissingKey); }
        let relative = key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\');
        let mut values = BTreeMap::new();
        for root in ["HKCU", "HKLM"] {
            let backing = classes_backing_path(root, relative);
            if let Some(key) = self.keys.get(&canonical(&backing)) { for (name, value) in key.values.values() { values.entry(canonical(name)).or_insert_with(|| (name.clone(), value.clone())); } }
        }
        Ok(values.into_values().collect())
    }

    /// Set or replace one typed value. # C: O(log N)
    pub fn set_value(&mut self, key: &str, name: &str, value: Value) -> Result<(), Error> {
        if name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let backing = if key == "HKCR" || key.starts_with("HKCR\\") { classes_backing_path("HKCU", key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\')) } else { key.to_string() };
        let entry = self.keys.get_mut(&canonical(&backing)).ok_or(Error::MissingKey)?;
        entry.values.insert(canonical(name), (name.to_string(), value));
        Ok(())
    }

    /// Query one typed value by case-insensitive name. # C: O(log N)
    pub fn query_value(&self, key: &str, name: &str) -> Result<Value, Error> {
        if key == "HKCR" || key.starts_with("HKCR\\") {
            let relative = key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\');
            let user = classes_backing_path("HKCU", relative); let machine = classes_backing_path("HKLM", relative);
            return self.keys.get(&canonical(&user)).and_then(|key| key.values.get(&canonical(name))).or_else(|| self.keys.get(&canonical(&machine)).and_then(|key| key.values.get(&canonical(name)))).map(|(_, value)| value.clone()).ok_or(Error::MissingValue);
        }
        self.keys.get(key).ok_or(Error::MissingKey)?.values.get(&canonical(name)).map(|(_, value)| value.clone()).ok_or(Error::MissingValue)
    }

    /// Delete one value by its case-insensitive canonical name. # C: O(log N)
    pub fn delete_value(&mut self, key: &str, name: &str) -> Result<(), Error> {
        if name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let backing = if key == "HKCR" || key.starts_with("HKCR\\") { classes_backing_path("HKCU", key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\')) } else { key.to_string() };
        let entry = self.keys.get_mut(&canonical(&backing)).ok_or(Error::MissingKey)?;
        if entry.values.remove(&canonical(name)).is_some() { Ok(()) } else { Err(Error::MissingValue) }
    }

    /// Enumerate child keys in stable display order. # C: O(N_keys)
    pub fn subkeys(&self, key: &str) -> Result<Vec<String>, Error> {
        if key == "HKCR" || key.starts_with("HKCR\\") { return self.classes_subkeys(key); }
        let parent = self.keys.get(key).ok_or(Error::MissingKey)?.path.clone();
        let prefix = format!("{}\\", parent);
        let mut out = Vec::new();
        for child in self.keys.values() {
            if child.path.starts_with(&prefix) && !child.path[prefix.len()..].contains('\\') { out.push(child.path[prefix.len()..].to_string()); }
        }
        out.sort_by_key(|name| canonical(name));
        Ok(out)
    }

    /// Persist one registry database using a bounded, versioned binary format. # C: O(N_values)
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let bytes = self.encode()?;
        let mut selected = None;
        for attempt in 0..1024u32 {
            let temp = path.with_extension(format!("oxide-registry.tmp.{}.{}", std::process::id(), attempt));
            match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => { selected = Some((temp, file)); break; }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let (temp, mut file) = selected.ok_or_else(|| Error::Io("registry temporary-file namespace exhausted".into()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Encode the canonical owner state for a typed hive transaction. # C: O(N_values)
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new(); bytes.extend_from_slice(MAGIC);
        let records = self.keys.values().filter(|key| !is_root(&key.path)).count() as u32;
        put_u32(&mut bytes, records);
        for key in self.keys.values().filter(|key| !is_root(&key.path)) {
            put_bytes(&mut bytes, key.path.as_bytes())?; put_u32(&mut bytes, key.values.len() as u32);
            for (display, value) in key.values.values() { put_bytes(&mut bytes, display.as_bytes())?; put_u32(&mut bytes, value.kind as u32); put_bytes(&mut bytes, &value.data)?; }
        }
        Ok(bytes)
    }

    /// Load a database, retaining predefined roots and rejecting malformed input. # C: O(file bytes)
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::decode(&fs::read(path)?)
    }

    /// Decode a complete owner snapshot before it is committed. # C: O(file bytes)
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut at = 0;
        if bytes.len() > MAX_BYTES as usize { return Err(Error::InvalidFile); }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) { return Err(Error::InvalidFile); } at += MAGIC.len();
        let records = get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?; if records > MAX_RECORDS { return Err(Error::InvalidFile); }
        let mut registry = Self::new();
        for _ in 0..records {
            let path = text(get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?)?;
            let root = persisted_root(&path).ok_or(Error::InvalidFile)?;
            let key = registry.create_key(root, path.split_once('\\').map_or("", |(_, rest)| rest))?;
            let values = get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?; if values > MAX_RECORDS { return Err(Error::InvalidFile); }
            for _ in 0..values {
                let name = text(get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?)?;
                let kind = ValueType::decode(get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?).ok_or(Error::InvalidFile)?;
                let data = get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?.to_vec(); registry.set_value(&key, &name, Value { kind, data })?;
            }
        }
        if at != bytes.len() { return Err(Error::InvalidFile); } Ok(registry)
    }

    pub(crate) fn export_handle(&self, handle: KeyHandle) -> Result<Vec<u8>, Error> {
        let path = self.handles.get(&handle).ok_or(Error::MissingKey)?;
        let mut subset = Self::new();
        for key in self.keys.values().filter(|key| canonical(&key.path) == *path || canonical(&key.path).starts_with(&format!("{}\\", path))) {
            let root = if key.path.starts_with("HKLM") { Root::LocalMachine } else if key.path.starts_with("HKCU") { Root::CurrentUser } else { Root::Classes };
            let relative = key.path.split_once('\\').map_or("", |(_, rest)| rest);
            let target = subset.create_key(root, relative)?;
            for (display, value) in key.values.values() { subset.set_value(&target, display, value.clone())?; }
        }
        subset.keys.retain(|_, key| is_root(&key.path) || canonical(&key.path) == *path || canonical(&key.path).starts_with(&format!("{}\\", path)));
        let payload = subset.encode()?;
        let mut out = Vec::new(); out.extend_from_slice(SUBTREE_MAGIC); put_bytes(&mut out, path.as_bytes())?; out.extend_from_slice(&payload); Ok(out)
    }

    pub(crate) fn import_path(&mut self, target: &str, bytes: &[u8]) -> Result<(), Error> {
        if bytes.get(..SUBTREE_MAGIC.len()) != Some(SUBTREE_MAGIC.as_slice()) { return Err(Error::InvalidFile); }
        let mut at = SUBTREE_MAGIC.len(); let source = text(get_bytes(bytes, &mut at).ok_or(Error::InvalidFile)?)?;
        let incoming = Self::decode(bytes.get(at..).ok_or(Error::InvalidFile)?)?;
        let target_root = target.split_once('\\').map_or(target, |(root, _)| root);
        let root = persisted_root(target).ok_or(Error::InvalidPath)?;
        let target_relative = target.split_once('\\').map_or("", |(_, rest)| rest);
        let target = self.create_key(root, target_relative)?;
        let target = if target_root == "HKCR" { canonical(&target) } else { target };
        for key in incoming.keys.values() {
            let identity = canonical(&key.path);
            if is_root(&key.path) || (identity != canonical(&source) && !identity.starts_with(&format!("{}\\", canonical(&source)))) { continue; }
            let source_identity = canonical(&source);
            let relative = if identity == source_identity { String::new() } else { identity.strip_prefix(&(source_identity + "\\")).ok_or(Error::InvalidPath)?.to_string() };
            let destination = relative_for_target(&target, &relative);
            let created = self.create_key(root, &destination)?;
            for (display, value) in key.values.values() { self.set_value(&created, display, value.clone())?; }
        }
        Ok(())
    }
}

pub(super) fn relative_for_target(target: &str, relative: &str) -> String {
    let target = target.split_once('\\').map_or("", |(_, rest)| rest);
    if target.is_empty() { relative.to_string() } else if relative.is_empty() { target.to_string() } else { format!("{}\\{}", target, relative) }
}

pub(super) fn classes_backing_path(root: &str, relative: &str) -> String {
    if relative.is_empty() { format!("{}\\Software\\Classes", root) } else { format!("{}\\Software\\Classes\\{}", root, relative) }
}

pub(super) fn canonical(text: &str) -> String { text.to_ascii_uppercase() }
pub(super) fn reg_string(value: &str) -> Value { Value { kind: ValueType::String, data: value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() } }
pub(super) fn is_root(path: &str) -> bool { matches!(path, "HKLM" | "HKCU" | "HKCR") }
pub(super) fn persisted_root(path: &str) -> Option<Root> {
    let (root, suffix) = path.split_once('\\').map_or((path, ""), |(root, suffix)| (root, suffix));
    if suffix.is_empty() && !is_root(root) { return None; }
    match root { "HKLM" => Some(Root::LocalMachine), "HKCU" => Some(Root::CurrentUser), "HKCR" => Some(Root::Classes), _ => None }
}
pub(super) fn root_handle(root: Root) -> u64 { match root { Root::LocalMachine => HKEY_LOCAL_MACHINE, Root::CurrentUser => HKEY_CURRENT_USER, Root::Classes => HKEY_CLASSES_ROOT } }
pub(super) fn join_path(root: &str, subkey: &str) -> Result<String, Error> {
    if subkey.contains('\0') || subkey.split('\\').any(str::is_empty) { return if subkey.is_empty() { Ok(root.to_string()) } else { Err(Error::InvalidPath) }; }
    if subkey.is_empty() { Ok(root.to_string()) } else { Ok(format!("{}\\{}", root, subkey)) }
}
pub(super) fn text(bytes: &[u8]) -> Result<String, Error> { String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidFile) }
pub(super) fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
pub(super) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> { if bytes.len() > u32::MAX as usize { return Err(Error::InvalidFile); } put_u32(out, bytes.len() as u32); out.extend_from_slice(bytes); Ok(()) }
pub(super) fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), Error> { put_bytes(out, text.as_bytes()) }
pub(super) fn get_u32(bytes: &[u8], at: &mut usize) -> Option<u32> { let end = at.checked_add(4)?; let value = u32::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
pub(super) fn get_bytes<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> { let len = get_u32(bytes, at)? as usize; let end = at.checked_add(len)?; let value = bytes.get(*at..end)?; *at = end; Some(value) }
