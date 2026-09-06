//! Kernel-owned binding for the Windows GDI client projection (`31gf`).
//!
//! This module owns mapping lifetime metadata only.  `GdiManager` remains the
//! sole object/identity owner; the shared syscall crate owns all byte layouts.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::nt_gdi_client as abi;

#[path = "client/memory.rs"]
pub(super) mod memory;
#[path = "client/text.rs"]
mod text;
#[path = "client/lease.rs"]
mod lease;

const PEB_OFFSET: u64 = abi::PEB_TABLE_OFFSET;
const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    NoCurrentProcess,
    NoAddressSpace,
    ForeignTable,
    InvalidBinding,
    Mapping,
    UserCopy,
    Codec,
    ProcessId,
}

/// Retained identity of the two canonical client mappings.
///
/// This is intentionally not an object table.  Main keeps this capability
/// beside its canonical `GdiManager`; all handle admission still goes through
/// that owner before these methods are called.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientBinding {
    pub table_base: u64,
    pub attr_base: u64,
    pub table_bytes: usize,
    pub attr_bytes: usize,
    pub attr_stride: usize,
}

impl ClientBinding {
    pub const fn table_bytes() -> usize { abi::TABLE_BYTES }
    pub const fn attr_bytes() -> usize { abi::DC_ATTR_BYTES }
    pub const fn attr_stride() -> usize { abi::DC_ATTR_SIZE }

    /// Compute the DC_ATTR address from retained mapping identity and the
    /// canonical slot.  Client `UserPointer` is deliberately not consulted.
    pub fn dc_attr_address(&self, handle: u32) -> Result<u64, ClientError> {
        let slot = handle & 0xffff;
        if ((handle & abi::HANDLE_TYPE_MASK) >> 16) as u8 & 0x1f != 1 || slot == 0 {
            return Err(ClientError::Codec);
        }
        abi::dc_attr_address(self.attr_base, slot).map_err(|_| ClientError::InvalidBinding)
    }

    pub fn update_dc_dimensions(&self, handle: u32, width: i32, height: i32) -> Result<(), ClientError> {
        self.update_lease_dimensions(handle, width, height)
    }

    /// Read and validate the complete client DC_ATTR record.  This is the
    /// path used by render/measure consumers, so PE writes are observed rather
    /// than replaced by a cached kernel-side text state.
    pub fn read_dc_attr(&self, handle: u32) -> Result<[u8; abi::DC_ATTR_SIZE], ClientError> {
        self.validate_current()?;
        let address = self.dc_attr_address(handle)?;
        let mut bytes = [0u8; abi::DC_ATTR_SIZE];
        uaccess::copy_from_user(&mut bytes, address).map_err(|_| ClientError::UserCopy)?;
        abi::decode_text(&bytes, handle).map_err(|_| ClientError::Codec)?;
        Ok(bytes)
    }

    /// Commit a complete client DC_ATTR record after validating its identity
    /// and text fields.  Callers must preserve fields they do not own; this
    /// method never merges against a private TextAttributes shadow.
    pub fn write_dc_attr(&self, handle: u32, bytes: &[u8; abi::DC_ATTR_SIZE]) -> Result<(), ClientError> {
        self.validate_current()?;
        abi::decode_text(bytes, handle).map_err(|_| ClientError::Codec)?;
        let address = self.dc_attr_address(handle)?;
        memory::write(address, bytes)
    }

    /// Snapshot shared text fields after validating the complete DC_ATTR.
    pub fn text_snapshot(&self, handle: u32) -> Result<abi::DcText, ClientError> {
        text::snapshot(*self, handle)
    }

    /// Update one owned text field without rewriting unrelated PE-owned bytes.
    pub fn set_text_attribute(&self, handle: u32, attribute: u32, value: u32) -> Result<u32, ClientError> {
        text::set_attribute(*self, handle, attribute, value)
    }

    /// Update current position as one eight-byte shared write.
    pub fn set_text_position(&self, handle: u32, position: (i32, i32)) -> Result<(i32, i32), ClientError> {
        text::set_position(*self, handle, position)
    }

    /// Publish a canonical DC.  Attributes are initialized before the handle
    /// entry becomes visible, matching Wine's lookup ordering.
    pub fn publish_dc(&self, handle: u32, process_id: u16, width: i32, height: i32,
        text: abi::DcText) -> Result<(), ClientError> {
        self.validate_current()?;
        self.publish_dc_unchecked(handle, process_id, width, height, text)
    }

    pub(crate) fn publish_dc_unchecked(&self, handle: u32, process_id: u16, width: i32, height: i32,
        text: abi::DcText) -> Result<(), ClientError> {
        let attr = abi::encode_dc_attr(handle, width, height, text).map_err(|_| ClientError::Codec)?;
        let attr_address = self.dc_attr_address(handle)?;
        let entry = abi::HandleEntry::for_handle(handle, process_id, attr_address)
            .map_err(|_| ClientError::Codec)?.encode().map_err(|_| ClientError::Codec)?;
        memory::write(attr_address, &attr)?;
        let entry_address = abi::entry_address(self.table_base, handle & 0xffff)
            .map_err(|_| ClientError::InvalidBinding)?;
        if let Err(error) = memory::write(entry_address, &entry) {
            let _ = memory::zero(attr_address, abi::DC_ATTR_SIZE);
            return Err(error);
        }
        Ok(())
    }

    /// Publish a canonical owner snapshot when a DC is created or rebound.
    /// Font identity remains in the canonical owner; only shared DC text
    /// attributes cross this projection boundary.
    pub fn publish_dc_state(&self, handle: u32, process_id: u16,
        state: ipc::win32_gdi::TextState) -> Result<(), ClientError> {
        let attrs = state.attributes;
        self.publish_dc(handle, process_id, state.width, state.height, abi::DcText {
            foreground: attrs.foreground, background: attrs.background,
            alignment: attrs.alignment, background_mode: attrs.background_mode,
            current_position: attrs.current_position,
        })
    }

    /// Publish a non-DC canonical handle.  No native/private object pointer
    /// is projected; the owner supplies only the canonical handle identity.
    pub fn publish_handle(&self, handle: u32, process_id: u16) -> Result<(), ClientError> {
        self.validate_current()?;
        self.publish_handle_unchecked(handle, process_id)
    }

    pub(crate) fn publish_handle_unchecked(&self, handle: u32, process_id: u16) -> Result<(), ClientError> {
        let entry = abi::HandleEntry::for_handle(handle, process_id, 0)
            .map_err(|_| ClientError::Codec)?.encode().map_err(|_| ClientError::Codec)?;
        let address = abi::entry_address(self.table_base, handle & 0xffff)
            .map_err(|_| ClientError::InvalidBinding)?;
        memory::write(address, &entry)
    }

    /// Publish an already-existing canonical stock identity.  Stock objects
    /// have no native pointer payload; the shared codec preserves their stock
    /// bit from the canonical handle.
    pub fn publish_stock(&self, handle: u32, process_id: u16) -> Result<(), ClientError> {
        self.publish_handle(handle, process_id)
    }

    pub(crate) fn publish_stock_unchecked(&self, handle: u32, process_id: u16) -> Result<(), ClientError> {
        self.publish_handle_unchecked(handle, process_id)
    }

    pub(crate) fn claim_peb(&self) -> Result<(), ClientError> {
        let peb = sched::live::current().ok_or(ClientError::NoCurrentProcess)?.nt_peb();
        let address = peb.checked_add(PEB_OFFSET).ok_or(ClientError::InvalidBinding)?;
        let current = uaccess::get_user_u64(address).map_err(|_| ClientError::UserCopy)?;
        if current != 0 && current != self.table_base { return Err(ClientError::ForeignTable); }
        uaccess::put_user_u64(address, self.table_base).map_err(|_| ClientError::UserCopy)
    }

    /// Clear a projection after the canonical owner has deleted the object.
    pub fn delete_handle(&self, handle: u32) -> Result<(), ClientError> {
        self.validate_current()?;
        let entry_address = abi::entry_address(self.table_base, handle & 0xffff)
            .map_err(|_| ClientError::InvalidBinding)?;
        memory::zero(entry_address, abi::ENTRY_SIZE)?;
        if ((handle & abi::HANDLE_TYPE_MASK) >> 16) as u8 & 0x1f == 1 {
            let attr_address = self.dc_attr_address(handle)?;
            memory::zero(attr_address, abi::DC_ATTR_SIZE)?;
        }
        Ok(())
    }

    /// Revalidate PEB ownership before every projection mutation.
    fn validate_current(&self) -> Result<(), ClientError> {
        let peb = sched::live::current().ok_or(ClientError::NoCurrentProcess)?.nt_peb();
        if peb == 0 { return Err(ClientError::NoCurrentProcess); }
        let value = uaccess::get_user_u64(peb.checked_add(PEB_OFFSET).ok_or(ClientError::InvalidBinding)?)
            .map_err(|_| ClientError::UserCopy)?;
        if value != self.table_base { return Err(ClientError::ForeignTable); }
        Ok(())
    }
}

/// Process identity used by the shared client entry owner field.
pub fn current_process_id() -> Result<u16, ClientError> {
    let current = sched::live::current().ok_or(ClientError::NoCurrentProcess)?;
    let pid = current.tgid.load(Ordering::Acquire);
    u16::try_from(pid).map_err(|_| ClientError::ProcessId)
}
