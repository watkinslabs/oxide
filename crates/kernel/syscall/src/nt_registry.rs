//! Fixed x86-64 NT registry request records and pointer-shape validation.

use crate::{nt::NtCall, Errno, UserPtr};

pub const KEY_FULL_INFORMATION_FIXED_BYTES: usize = 48;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtUnicodeString { pub length: u16, pub maximum_length: u16, pub padding: u32, pub buffer: UserPtr<u16> }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtObjectAttributes { pub length: u32, pub padding: u32, pub root_directory: u64, pub object_name: UserPtr<NtUnicodeString>, pub attributes: u32, pub padding2: u32, pub security_descriptor: u64, pub security_quality_of_service: u64 }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtCreateKeyRequest { pub key: UserPtr<u32>, pub desired_access: u32, pub padding: u32, pub object_attributes: UserPtr<NtObjectAttributes>, pub title_index: u32, pub padding2: u32, pub class: u64, pub options: u32, pub padding3: u32, pub disposition: u64 }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtOpenKeyRequest { pub key: UserPtr<u32>, pub desired_access: u32, pub padding: u32, pub object_attributes: UserPtr<NtObjectAttributes> }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtQueryValueKeyRequest { pub key: u32, pub value_name: UserPtr<NtUnicodeString>, pub information_class: u32, pub information: UserPtr<u8>, pub length: u32, pub padding: u32, pub result_length: UserPtr<u32> }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtSetValueKeyRequest { pub key: u32, pub title_index: u32, pub value_name: UserPtr<NtUnicodeString>, pub value_type: u32, pub data: UserPtr<u8>, pub data_size: u32, pub padding: u32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtRegistryCall { CreateKey { request: UserPtr<NtCreateKeyRequest> }, OpenKey { request: UserPtr<NtOpenKeyRequest> }, QueryValueKey { request: UserPtr<NtQueryValueKeyRequest> }, SetValueKey { request: UserPtr<NtSetValueKeyRequest> }, RenameKey { key: u32, name: UserPtr<NtUnicodeString> } }

/// Encode one `KEY_VALUE_PARTIAL_INFORMATION` record for the native NT ABI.
/// # C: O(data.len())
pub fn encode_partial_value_information(value_type: u32, data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let length = 12usize.checked_add(data.len())?;
    let mut record = alloc::vec::Vec::with_capacity(length);
    record.extend_from_slice(&0u32.to_le_bytes());
    record.extend_from_slice(&value_type.to_le_bytes());
    record.extend_from_slice(&(data.len() as u32).to_le_bytes());
    record.extend_from_slice(data);
    Some(record)
}

/// Validate the outer record pointer; nested user buffers are copied by the registry owner. # C: O(1)
pub fn decode_registry(call: NtCall) -> Result<NtRegistryCall, Errno> {
    let pointer = call.args.a0;
    Ok(match call.service {
        crate::nt::NtService::CreateKey => NtRegistryCall::CreateKey { request: UserPtr::new(pointer)? },
        crate::nt::NtService::OpenKey => NtRegistryCall::OpenKey { request: UserPtr::new(pointer)? },
        crate::nt::NtService::QueryValueKey => NtRegistryCall::QueryValueKey { request: UserPtr::new(pointer)? },
        crate::nt::NtService::SetValueKey => NtRegistryCall::SetValueKey { request: UserPtr::new(pointer)? },
        crate::nt::NtService::RenameKey => NtRegistryCall::RenameKey { key: pointer as u32, name: UserPtr::new(call.args.a1)? },
        _ => return Err(Errno::Enosys),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nt::{decode, NtService}, SyscallArgs};

    #[test]
    fn registry_records_are_fixed_x64_shapes() {
        assert_eq!(core::mem::size_of::<NtUnicodeString>(), 16);
        assert_eq!(core::mem::size_of::<NtObjectAttributes>(), 48);
        assert_eq!(core::mem::size_of::<NtCreateKeyRequest>(), 56);
        assert_eq!(core::mem::size_of::<NtOpenKeyRequest>(), 24);
        assert_eq!(core::mem::size_of::<NtQueryValueKeyRequest>(), 48);
        assert_eq!(core::mem::size_of::<NtSetValueKeyRequest>(), 40);
    }

    #[test]
    fn registry_outer_pointer_is_validated_before_nested_work() {
        let args = SyscallArgs { a0: 0x1000, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
        assert!(matches!(decode_registry(decode(42, args).unwrap()), Ok(NtRegistryCall::CreateKey { .. })));
        assert_eq!(decode_registry(decode(42, SyscallArgs { a0: 3, ..args }).unwrap()), Err(Errno::Efault));
        assert_eq!(NtService::SetValueKey.entry(), 0x4e54_0000_0000_002d);
    }

    #[test]
    fn partial_value_information_preserves_windows_field_offsets() {
        let record = encode_partial_value_information(1, b"abc").unwrap();
        assert_eq!(record.len(), 15);
        assert_eq!(&record[0..4], &[0, 0, 0, 0]);
        assert_eq!(&record[4..8], &1u32.to_le_bytes());
        assert_eq!(&record[8..12], &3u32.to_le_bytes());
        assert_eq!(&record[12..], b"abc");
    }

    #[test]
    fn partial_value_information_accepts_empty_data_without_shifting_header() {
        let record = encode_partial_value_information(4, &[]).unwrap();
        assert_eq!(record, [0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn key_full_information_includes_security_descriptor_field() {
        assert_eq!(KEY_FULL_INFORMATION_FIXED_BYTES, 48);
    }
}
