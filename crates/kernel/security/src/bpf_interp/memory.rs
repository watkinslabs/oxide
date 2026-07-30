//! Pointer domains and built-in memory helpers for the eBPF interpreter.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use crate::bpf::{BpfMapInode, BpfMapValue};

use super::STACK_BYTES;

const MAP_BASE: u64 = 0x2_0000_0000;
const VALUE_BASE: u64 = 0x3_0000_0000;
const VALUE_STRIDE: u64 = 0x10_0000;

pub(super) enum Context<'a> {
    ReadOnly(&'a [u8]),
    ReadWrite(&'a mut [u8]),
}

impl Context<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Context::ReadOnly(bytes) => bytes,
            Context::ReadWrite(bytes) => bytes,
        }
    }
}

struct ValueRef {
    value: Arc<BpfMapValue>,
    readable: bool,
    writable: bool,
}

pub(super) struct RunMemory<'a> {
    context: Context<'a>,
    packet: &'a [u8],
    maps: &'a [InodeRef],
    values: Vec<ValueRef>,
}

impl<'a> RunMemory<'a> {
    /// Create the pointer-domain state for one interpreter invocation.
    /// # C: O(1)
    pub(super) fn new(
        context: Context<'a>,
        packet: &'a [u8],
        maps: &'a [InodeRef],
    ) -> Self {
        Self { context, packet, maps, values: Vec::new() }
    }

    /// Resolve a relocated map or map-value pseudo instruction.
    /// # C: O(1)
    pub(super) fn pseudo(&mut self, kind: u8, map_index: i32, offset: i32) -> Option<i64> {
        let index = usize::try_from(map_index).ok()?;
        let inode = self.maps.get(index)?;
        match kind {
            crate::bpf::uapi::pseudo::MAP_FD => {
                (offset == 0).then_some((MAP_BASE + index as u64) as i64)
            }
            crate::bpf::uapi::pseudo::MAP_VALUE => {
                let map = inode.private::<BpfMapInode>()?;
                let value = map.array_value(0)?;
                self.pin_value(value, map.map_flags, usize::try_from(offset).ok()?)
            }
            _ => None,
        }
    }

    fn pin_value(&mut self, value: Arc<BpfMapValue>, flags: u32, offset: usize) -> Option<i64> {
        if offset >= value.len() || offset as u64 >= VALUE_STRIDE { return None; }
        let slot = self.values.len();
        self.values.try_reserve(1).ok()?;
        self.values.push(ValueRef {
            value,
            readable: flags & crate::bpf::uapi::map_flags::WRONLY_PROG == 0,
            writable: flags & crate::bpf::uapi::map_flags::RDONLY_PROG == 0,
        });
        Some((VALUE_BASE + slot as u64 * VALUE_STRIDE + offset as u64) as i64)
    }

    fn value_location(&self, addr: u64, size: usize) -> Option<(&ValueRef, usize)> {
        if addr < VALUE_BASE { return None; }
        let relative = addr - VALUE_BASE;
        let slot = usize::try_from(relative / VALUE_STRIDE).ok()?;
        let offset = usize::try_from(relative % VALUE_STRIDE).ok()?;
        let value = self.values.get(slot)?;
        (offset.checked_add(size)? <= value.value.len()).then_some((value, offset))
    }

    fn stack_location(addr: u64, size: usize) -> Option<usize> {
        let base = crate::bpf_layout::STACK_BASE;
        if addr < base || addr >= base + STACK_BYTES as u64 { return None; }
        let offset = usize::try_from(addr - base).ok()?;
        (offset.checked_add(size)? <= STACK_BYTES).then_some(offset)
    }

    /// Read one scalar from a validated stack, context, or map-value address.
    /// # C: O(size)
    pub(super) fn read(&self, addr: i64, size: usize, stack: &[u8]) -> Option<i64> {
        let mut bytes = [0u8; 8];
        self.read_bytes(addr, &mut bytes[..size], stack)?;
        Some(u64::from_le_bytes(bytes) as i64)
    }

    fn read_bytes(&self, addr: i64, out: &mut [u8], stack: &[u8]) -> Option<()> {
        let raw = addr as u64;
        if let Some(offset) = Self::stack_location(raw, out.len()) {
            out.copy_from_slice(&stack[offset..offset + out.len()]);
            return Some(());
        }
        if let Some((value, offset)) = self.value_location(raw, out.len()) {
            if !value.readable { return None; }
            return value.value.read_range(offset, out);
        }
        let offset = usize::try_from(addr).ok()?;
        let context = self.context.bytes();
        if offset.checked_add(out.len())? > context.len() { return None; }
        out.copy_from_slice(&context[offset..offset + out.len()]);
        Some(())
    }

    /// Write one scalar to a validated writable pointer domain.
    /// # C: O(size)
    pub(super) fn write(
        &mut self,
        addr: i64,
        size: usize,
        value: i64,
        stack: &mut [u8],
    ) -> Option<()> {
        let bytes = value.to_le_bytes();
        let raw = addr as u64;
        if let Some(offset) = Self::stack_location(raw, size) {
            stack[offset..offset + size].copy_from_slice(&bytes[..size]);
            return Some(());
        }
        if let Some((entry, offset)) = self.value_location(raw, size) {
            if !entry.writable { return None; }
            return entry.value.write_range(offset, &bytes[..size]);
        }
        let offset = usize::try_from(addr).ok()?;
        let Context::ReadWrite(context) = &mut self.context else { return None; };
        if offset.checked_add(size)? > context.len() { return None; }
        context[offset..offset + size].copy_from_slice(&bytes[..size]);
        Some(())
    }

    /// Atomically read-modify-write within a readable and writable map value.
    /// # C: O(1)
    pub(super) fn atomic_add(&mut self, addr: i64, size: usize, add: i64) -> Option<()> {
        let (entry, offset) = self.value_location(addr as u64, size)?;
        if !entry.readable || !entry.writable { return None; }
        entry.value.atomic_add(offset, size, add)
    }

    /// Implement helper 1 map lookup and return a pinned value pointer.
    /// # C: O(entries + key_size)
    pub(super) fn map_lookup(&mut self, map_addr: i64, key_addr: i64, stack: &[u8]) -> i64 {
        let raw = map_addr as u64;
        let Some(index) = raw.checked_sub(MAP_BASE).and_then(|v| usize::try_from(v).ok())
            else { return 0 };
        let Some(inode) = self.maps.get(index) else { return 0 };
        let Some(map) = inode.private::<BpfMapInode>() else { return 0 };
        let mut key = Vec::new();
        if key.try_reserve_exact(map.key_size as usize).is_err() { return 0; }
        key.resize(map.key_size as usize, 0);
        if self.read_bytes(key_addr, &mut key, stack).is_none() { return 0; }
        let Some(value) = map.lookup_value(&key) else { return 0 };
        self.pin_value(value, map.map_flags, 0).unwrap_or(0)
    }

    /// Implement `bpf_skb_load_bytes`, including destination clearing on fault.
    /// # C: O(length)
    pub(super) fn skb_load_bytes(
        &self,
        offset: i64,
        destination: i64,
        length: i64,
        stack: &mut [u8],
    ) -> i64 {
        let fault = -(Errno::Efault.as_i32() as i64);
        let Ok(length) = usize::try_from(length) else { return fault };
        let Some(stack_offset) = Self::stack_location(destination as u64, length) else {
            return fault;
        };
        stack[stack_offset..stack_offset + length].fill(0);
        let Ok(offset) = usize::try_from(offset) else { return fault };
        let Some(end) = offset.checked_add(length) else { return fault };
        if end > self.packet.len() { return fault; }
        stack[stack_offset..stack_offset + length].copy_from_slice(&self.packet[offset..end]);
        0
    }
}
