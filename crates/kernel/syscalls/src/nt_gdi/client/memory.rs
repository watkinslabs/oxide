//! User mapping and copy helpers for the GDI client binding.

#![cfg(target_os = "oxide-kernel")]

use super::{ClientError, PAGE};
use alloc::sync::Arc;
use vmm::AddressSpace;

pub(crate) fn allocate(mm: &Arc<AddressSpace>, bytes: usize) -> Result<u64, ClientError> {
    elf_load::nt_memory::allocate(mm, None, bytes, vmm::VmaProt::READ | vmm::VmaProt::WRITE, true)
        .map(|allocation| allocation.base.as_u64()).map_err(|_| ClientError::Mapping)
}

pub(crate) fn free(mm: &Arc<AddressSpace>, base: u64, bytes: usize) -> Result<(), ClientError> {
    let base = hal::UserVirtAddr::new(base).ok_or(ClientError::InvalidBinding)?;
    let allocation = elf_load::nt_memory::NtAllocation { base, size: bytes,
        protection: vmm::VmaProt::READ | vmm::VmaProt::WRITE, reserved: false };
    match elf_load::nt_memory::free(mm, allocation) {
        elf_load::nt_memory::NtStatus::Success => Ok(()), _ => Err(ClientError::Mapping),
    }
}

pub(crate) fn zero(address: u64, bytes: usize) -> Result<(), ClientError> {
    let zeros = [0u8; PAGE];
    let mut offset = 0usize;
    while offset < bytes {
        let count = (bytes - offset).min(PAGE);
        let destination = address.checked_add(offset as u64).ok_or(ClientError::InvalidBinding)?;
        uaccess::copy_to_user(destination, &zeros[..count]).map_err(|_| ClientError::UserCopy)?;
        offset += count;
    }
    Ok(())
}

pub(crate) fn write(address: u64, bytes: &[u8]) -> Result<(), ClientError> {
    uaccess::copy_to_user(address, bytes).map_err(|_| ClientError::UserCopy)
}
