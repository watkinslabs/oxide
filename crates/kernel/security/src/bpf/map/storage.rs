//! Fallible map backing, LPM key identity, and freeze/write arbitration.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::Spinlock;
use syscall::errno::Errno;

use crate::bpf::{BpfMapInode, BpfMapValue, uapi};

const FROZEN: u64 = 1 << 63;
const WRITERS: u64 = FROZEN - 1;
const HASH_MAX_ENTRIES: u32 = 1 << 31;

struct Entry {
    key: Vec<u8>,
    iteration_key: Option<Vec<u8>>,
    value: Arc<BpfMapValue>,
    occupied: bool,
}

struct Table {
    entries: Vec<Entry>,
    preallocated: bool,
    max_entries: usize,
}

type LockedTable = Spinlock<Table, sync::TaskList>;

enum Kind {
    Hash(LockedTable),
    Array(Vec<Arc<BpfMapValue>>),
    LpmTrie(LockedTable),
}

pub(crate) struct MapStorage {
    kind: Kind,
    state: AtomicU64,
}

pub(crate) struct WriteGuard<'a> {
    storage: &'a MapStorage,
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) { self.storage.state.fetch_sub(1, Ordering::SeqCst); }
}

fn zeroed_vec(len: usize) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| Errno::Enomem)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

fn copy_vec(bytes: &[u8]) -> Result<Vec<u8>, Errno> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|_| Errno::Enomem)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn value(len: usize) -> Result<Arc<BpfMapValue>, Errno> {
    Arc::try_new(BpfMapValue {
        bytes: Spinlock::new(zeroed_vec(len)?),
    }).map_err(|_| Errno::Enomem)
}

fn preallocated_table(
    key_size: usize,
    value_size: usize,
    max_entries: usize,
) -> Result<Table, Errno> {
    let stride = key_size.checked_add(value_size)
        .and_then(|bytes| bytes.checked_add(size_of::<Entry>()))
        .ok_or(Errno::E2big)?;
    stride.checked_mul(max_entries).ok_or(Errno::E2big)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(max_entries).map_err(|_| Errno::Enomem)?;
    for _ in 0..max_entries {
        entries.push(Entry {
            key: zeroed_vec(key_size)?,
            iteration_key: None,
            value: value(value_size)?,
            occupied: false,
        });
    }
    Ok(Table { entries, preallocated: true, max_entries })
}

fn dynamic_table(max_entries: usize) -> Table {
    Table { entries: Vec::new(), preallocated: false, max_entries }
}

impl MapStorage {
    /// Allocate map payload storage without invoking an infallible grow path.
    /// # C: O(max_entries × (key_size + value_size)) for preallocated maps
    pub(crate) fn allocate(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> Result<Self, Errno> {
        let max = max_entries as usize;
        let kind = match map_type {
            uapi::map_type::HASH => {
                if max_entries > HASH_MAX_ENTRIES { return Err(Errno::E2big); }
                let table = if map_flags & uapi::map_flags::NO_PREALLOC == 0 {
                    preallocated_table(key_size as usize, value_size as usize, max)?
                } else {
                    dynamic_table(max)
                };
                Kind::Hash(Spinlock::new(table))
            }
            uapi::map_type::LPM_TRIE => {
                Kind::LpmTrie(Spinlock::new(dynamic_table(max)))
            }
            uapi::map_type::ARRAY => {
                (value_size as usize).checked_mul(max).ok_or(Errno::E2big)?;
                let mut values = Vec::new();
                values.try_reserve_exact(max).map_err(|_| Errno::Enomem)?;
                for _ in 0..max { values.push(value(value_size as usize)?); }
                Kind::Array(values)
            }
            _ => return Err(Errno::Einval),
        };
        Ok(Self { kind, state: AtomicU64::new(0) })
    }

    /// Admit a syscall writer unless freeze already won the state transition.
    /// # C: O(CAS retries)
    pub(crate) fn begin_write(&self) -> Result<WriteGuard<'_>, Errno> {
        let mut state = self.state.load(Ordering::SeqCst);
        loop {
            if state & FROZEN != 0 { return Err(Errno::Eperm); }
            if state & WRITERS == WRITERS { return Err(Errno::Ebusy); }
            match self.state.compare_exchange_weak(
                state, state + 1, Ordering::SeqCst, Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(WriteGuard { storage: self }),
                Err(actual) => state = actual,
            }
        }
    }

    /// Publish frozen only when no writer is active; repeat freeze is EBUSY.
    /// # C: O(1)
    pub(crate) fn freeze(&self) -> Result<(), Errno> {
        self.state.compare_exchange(0, FROZEN, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| Errno::Ebusy)
    }

    /// # C: O(1)
    pub(crate) fn frozen(&self) -> bool {
        self.state.load(Ordering::Acquire) & FROZEN != 0
    }

    /// # C: O(entries + key bytes)
    pub(crate) fn lookup(&self, key: &[u8], max_entries: u32)
        -> Option<Arc<BpfMapValue>>
    {
        match &self.kind {
            Kind::Array(values) => {
                array_index(key, max_entries).and_then(|index| values.get(index).cloned())
            }
            Kind::Hash(table) => table.lock().entries.iter()
                .find(|entry| entry.occupied && entry.key == key)
                .map(|entry| Arc::clone(&entry.value)),
            Kind::LpmTrie(table) => table.lock().entries.iter()
                .filter(|entry| entry.occupied && lpm_matches(&entry.key, key))
                .max_by_key(|entry| prefix(&entry.key).unwrap_or(0))
                .map(|entry| Arc::clone(&entry.value)),
        }
    }

    /// # C: O(1)
    pub(crate) fn array_value(&self, index: usize) -> Option<Arc<BpfMapValue>> {
        match &self.kind {
            Kind::Array(values) => values.get(index).cloned(),
            _ => None,
        }
    }

    /// # C: O(entries + key_size + value_size)
    pub(crate) fn update(
        &self,
        map_type: u32,
        mut key: Vec<u8>,
        bytes: Vec<u8>,
        flags: u64,
    ) -> Result<i64, Errno> {
        if let Kind::Array(values) = &self.kind {
            let index = array_index(&key, values.len() as u32).ok_or(Errno::E2big)?;
            let operation = flags & !uapi::elem_flags::F_LOCK;
            if operation > uapi::elem_flags::EXIST { return Err(Errno::Einval); }
            if operation == uapi::elem_flags::NOEXIST { return Err(Errno::Eexist); }
            *values[index].bytes.lock() = bytes;
            return Ok(0);
        }
        let mut iteration_key = None;
        if map_type == uapi::map_type::LPM_TRIE {
            let mut canonical = copy_vec(&key)?;
            canonical_lpm(&mut canonical)?;
            iteration_key = Some(key);
            key = canonical;
        }
        let table = match &self.kind {
            Kind::Hash(table) | Kind::LpmTrie(table) => table,
            Kind::Array(_) => unreachable!(),
        };
        let mut table = table.lock();
        let existing = table.entries.iter().position(|entry| entry.occupied && entry.key == key);
        crate::bpf::attr::update_presence_verdict(flags, existing.is_some())?;
        if let Some(index) = existing {
            *table.entries[index].value.bytes.lock() = bytes;
            if iteration_key.is_some() {
                table.entries[index].iteration_key = iteration_key;
            }
            return Ok(0);
        }
        if table.entries.iter().filter(|entry| entry.occupied).count() >= table.max_entries {
            return Err(if map_type == uapi::map_type::LPM_TRIE {
                Errno::Enospc
            } else {
                Errno::E2big
            });
        }
        if table.preallocated {
            let slot = table.entries.iter_mut()
                .find(|entry| !entry.occupied && Arc::strong_count(&entry.value) == 1)
                .ok_or(Errno::E2big)?;
            slot.key.copy_from_slice(&key);
            *slot.value.bytes.lock() = bytes;
            slot.iteration_key = iteration_key;
            slot.occupied = true;
        } else {
            table.entries.try_reserve(1).map_err(|_| Errno::Enomem)?;
            table.entries.push(Entry {
                key,
                iteration_key,
                value: Arc::try_new(BpfMapValue { bytes: Spinlock::new(bytes) })
                    .map_err(|_| Errno::Enomem)?,
                occupied: true,
            });
        }
        Ok(0)
    }

    /// Remove exact HASH/LPM identity and optionally snapshot its value.
    /// # C: O(entries + value_size)
    pub(crate) fn remove(
        &self,
        map_type: u32,
        key: &[u8],
        snapshot: bool,
    ) -> Result<Option<Vec<u8>>, Errno> {
        let mut canonical = copy_vec(key)?;
        if map_type == uapi::map_type::LPM_TRIE { canonical_lpm(&mut canonical)?; }
        let table = match &self.kind {
            Kind::Hash(table) | Kind::LpmTrie(table) => table,
            Kind::Array(_) => return Ok(None),
        };
        let mut table = table.lock();
        let Some(index) = table.entries.iter()
            .position(|entry| entry.occupied && entry.key == canonical) else {
            return Ok(None);
        };
        let output = if snapshot {
            let locked = table.entries[index].value.bytes.lock();
            let mut copy = Vec::new();
            copy.try_reserve_exact(locked.len()).map_err(|_| Errno::Enomem)?;
            copy.extend_from_slice(&locked);
            Some(copy)
        } else {
            Some(Vec::new())
        };
        if table.preallocated {
            table.entries[index].occupied = false;
        } else {
            table.entries.remove(index);
        }
        Ok(output)
    }

    /// # C: O(entries + key_size)
    pub(crate) fn next_key(
        &self,
        key: Option<&[u8]>,
        max_entries: u32,
    ) -> Result<Option<Vec<u8>>, Errno> {
        if matches!(&self.kind, Kind::Array(_)) {
            let next = match key {
                None => 0,
                Some(raw) => array_index(raw, max_entries)
                    .and_then(|index| index.checked_add(1)).unwrap_or(0),
            };
            if next >= max_entries as usize { return Ok(None); }
            let mut output = zeroed_vec(size_of::<u32>())?;
            output.copy_from_slice(&(next as u32).to_ne_bytes());
            return Ok(Some(output));
        }
        let table = match &self.kind {
            Kind::Hash(table) | Kind::LpmTrie(table) => table,
            Kind::Array(_) => unreachable!(),
        };
        let canonical = match (&self.kind, key) {
            (Kind::LpmTrie(_), Some(raw)) => {
                let mut identity = copy_vec(raw)?;
                canonical_lpm(&mut identity)?;
                Some(identity)
            }
            (_, Some(raw)) => Some(copy_vec(raw)?),
            (_, None) => None,
        };
        let table = table.lock();
        let start = canonical.as_deref().and_then(|raw| {
            table.entries.iter().position(|entry| entry.occupied && entry.key == raw)
                .map(|index| index + 1)
        }).unwrap_or(0);
        let Some(entry) = table.entries.iter().skip(start).find(|entry| entry.occupied) else {
            return Ok(None);
        };
        let source = entry.iteration_key.as_deref().unwrap_or(&entry.key);
        let mut output = zeroed_vec(source.len())?;
        output.copy_from_slice(source);
        Ok(Some(output))
    }
}

fn array_index(key: &[u8], max_entries: u32) -> Option<usize> {
    let raw: [u8; 4] = key.try_into().ok()?;
    let index = u32::from_ne_bytes(raw);
    (index < max_entries).then_some(index as usize)
}

fn prefix(key: &[u8]) -> Option<usize> {
    Some(u32::from_ne_bytes(key.get(..4)?.try_into().ok()?) as usize)
}

fn canonical_lpm(key: &mut [u8]) -> Result<(), Errno> {
    let prefix = prefix(key).ok_or(Errno::Einval)?;
    let bits = key.len().checked_sub(4).and_then(|bytes| bytes.checked_mul(8))
        .ok_or(Errno::Einval)?;
    if prefix > bits { return Err(Errno::Einval); }
    let whole = prefix / 8;
    let partial = prefix % 8;
    if partial != 0 {
        key[4 + whole] &= u8::MAX << (8 - partial);
    }
    let clear = 4 + whole + usize::from(partial != 0);
    key[clear..].fill(0);
    Ok(())
}

fn lpm_matches(stored: &[u8], lookup: &[u8]) -> bool {
    if stored.len() != lookup.len() { return false; }
    let Some(stored_prefix) = prefix(stored) else { return false };
    let Some(lookup_prefix) = prefix(lookup) else { return false };
    let available = stored.len().saturating_sub(4) * 8;
    if stored_prefix > available || lookup_prefix > available || stored_prefix > lookup_prefix {
        return false;
    }
    let whole = stored_prefix / 8;
    let partial = stored_prefix % 8;
    if stored[4..4 + whole] != lookup[4..4 + whole] { return false; }
    partial == 0 || {
        let mask = u8::MAX << (8 - partial);
        stored[4 + whole] & mask == lookup[4 + whole] & mask
    }
}

impl BpfMapInode {
    /// Lookup shared by the element syscall and helper 1.
    /// # C: O(entries + key bytes)
    pub(crate) fn lookup_value(&self, key: &[u8]) -> Option<Arc<BpfMapValue>> {
        self.storage.lookup(key, self.max_entries)
    }

    /// # C: O(1)
    pub(crate) fn array_value(&self, index: usize) -> Option<Arc<BpfMapValue>> {
        self.storage.array_value(index)
    }
}
