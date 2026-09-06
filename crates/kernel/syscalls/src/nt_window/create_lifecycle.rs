//! Canonical synchronous Win32 create-message transaction.

/// x86-64 `CREATESTRUCTW` values supplied to a WndProc callback. Pointer and
/// handle fields stay 64-bit; the five scalar fields retain Windows widths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CreateStructArgs {
    pub lp_create_params: u64,
    pub instance: u64,
    pub menu: u64,
    pub parent: u64,
    pub cy: i32,
    pub cx: i32,
    pub y: i32,
    pub x: i32,
    pub style: i32,
    pub name: u64,
    pub class: u64,
    pub ex_style: u32,
}

/// The caller-specific return ABI is deliberately separate from the borrowed
/// CREATESTRUCT payload. Raw NtUserCreateWindowEx returns HWND/NULL; the
/// native route returns a status while suspended and receives HWND/NTSTATUS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateReturnConvention { RawHandle, NativeStatus }

impl CreateReturnConvention {
    pub(crate) fn failure(self, native_status: u64) -> u64 {
        match self {
            Self::RawHandle => 0,
            Self::NativeStatus => native_status,
        }
    }
}

pub(crate) const CALLBACK_FRAME_BYTES: u64 = 144;
pub(crate) const CREATE_STRUCT_OFFSET: u64 = 48;
pub(crate) const CREATE_STRUCT_BYTES: usize = 80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CreateCallbackLayout { pub callback_rsp: u64, pub create_struct: u64 }

/// Validate and locate the callback-owned user stack storage. The layout keeps
/// the continuation/shadow area, CREATESTRUCTW, and the remaining frame
/// disjoint, while checked arithmetic rejects malformed user stack addresses.
pub(crate) fn callback_layout(callback_rsp: u64) -> Option<CreateCallbackLayout> {
    if callback_rsp == 0 || callback_rsp & 0xf != 8 { return None; }
    let create_struct = callback_rsp.checked_add(CREATE_STRUCT_OFFSET)?;
    let end = create_struct.checked_add(CREATE_STRUCT_BYTES as u64)?;
    let frame_end = callback_rsp.checked_add(CALLBACK_FRAME_BYTES)?;
    (end <= frame_end && callback_rsp.checked_add(40)? <= create_struct).then_some(CreateCallbackLayout { callback_rsp, create_struct })
}

/// Serialize the exact x86-64 CREATESTRUCTW layout used as WM_CREATE's
/// lParam. This is deliberately independent of user-memory access so its ABI
/// can be tested on the host; nt_rtl copies these bytes to the validated stack.
pub(crate) fn serialize_create_struct(params: CreateStructArgs) -> [u8; CREATE_STRUCT_BYTES] {
    let mut bytes = [0u8; CREATE_STRUCT_BYTES];
    let pointer = |bytes: &mut [u8; CREATE_STRUCT_BYTES], offset: usize, value: u64| { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); };
    let scalar = |bytes: &mut [u8; CREATE_STRUCT_BYTES], offset: usize, value: u32| { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); };
    pointer(&mut bytes, 0, params.lp_create_params);
    pointer(&mut bytes, 8, params.instance);
    pointer(&mut bytes, 16, params.menu);
    pointer(&mut bytes, 24, params.parent);
    scalar(&mut bytes, 32, params.cy as u32);
    scalar(&mut bytes, 36, params.cx as u32);
    scalar(&mut bytes, 40, params.y as u32);
    scalar(&mut bytes, 44, params.x as u32);
    scalar(&mut bytes, 48, params.style as u32);
    pointer(&mut bytes, 56, params.name);
    pointer(&mut bytes, 64, params.class);
    scalar(&mut bytes, 72, params.ex_style);
    bytes
}

impl CreateStructArgs {
    /// A zeroed direct native create request remains ABI-shaped and carries no
    /// borrowed caller pointers; the raw Wine adapter supplies real fields.
    #[cfg(target_os = "oxide-kernel")]
    pub(crate) const fn empty(parent: u64) -> Self {
        Self { lp_create_params: 0, instance: 0, menu: 0, parent, cy: 0, cx: 0, y: 0, x: 0, style: 0, name: 0, class: 0, ex_style: 0 }
    }
}

/// The completion owner accepts only the two legal WndProc outcomes during
/// creation: zero rejects `WM_NCCREATE`; signed -1 rejects `WM_CREATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTransition {
    Continue,
    Reject,
    Commit,
}

pub(crate) fn after_nc_create(result: u64) -> CreateTransition {
    if result == 0 { CreateTransition::Reject } else { CreateTransition::Continue }
}

pub(crate) fn after_create(result: u64) -> CreateTransition {
    if result == u64::MAX { CreateTransition::Reject } else { CreateTransition::Commit }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nccreate_zero_rejects_and_nonzero_advances() {
        assert_eq!(after_nc_create(0), CreateTransition::Reject);
        assert_eq!(after_nc_create(1), CreateTransition::Continue);
        assert_eq!(after_nc_create(u64::MAX), CreateTransition::Continue);
    }

    #[test]
    fn create_signed_minus_one_rejects_only_minus_one() {
        assert_eq!(after_create(u64::MAX), CreateTransition::Reject);
        assert_eq!(after_create(0), CreateTransition::Commit);
        assert_eq!(after_create(1), CreateTransition::Commit);
    }

    #[test]
    fn rejection_preserves_caller_return_convention() {
        assert_eq!(CreateReturnConvention::RawHandle.failure(0xc000_000d), 0);
        assert_eq!(CreateReturnConvention::NativeStatus.failure(0xc000_000d), 0xc000_000d);
    }

    #[test]
    fn callback_layout_rejects_bad_alignment_and_overflow() {
        assert_eq!(callback_layout(0), None);
        assert_eq!(callback_layout(0x100), None);
        assert_eq!(callback_layout(u64::MAX - 7), None);
        assert_eq!(callback_layout(0x108), Some(CreateCallbackLayout { callback_rsp: 0x108, create_struct: 0x138 }));
    }

    #[test]
    fn callback_layout_has_no_continuation_shadow_overlap() {
        let layout = callback_layout(0x108).unwrap();
        assert!(layout.callback_rsp + 40 <= layout.create_struct);
        assert!(layout.create_struct + CREATE_STRUCT_BYTES as u64 <= layout.callback_rsp + CALLBACK_FRAME_BYTES);
    }

    #[test]
    fn serialization_matches_create_struct_offsets_and_signed_scalars() {
        let params = CreateStructArgs { lp_create_params: 1, instance: 2, menu: 3, parent: 4, cy: -5, cx: 6, y: -7, x: 8, style: -9, name: 10, class: 11, ex_style: 12 };
        let bytes = serialize_create_struct(params);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 4);
        assert_eq!(i32::from_le_bytes(bytes[32..36].try_into().unwrap()), -5);
        assert_eq!(i32::from_le_bytes(bytes[48..52].try_into().unwrap()), -9);
        assert_eq!(u64::from_le_bytes(bytes[56..64].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 12);
        assert!(bytes[76..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn create_struct_preserves_windows_scalar_and_pointer_shapes() {
        let value = CreateStructArgs { lp_create_params: 0x1234_5678_9abc_def0, instance: 1, menu: 2, parent: 3, cy: -4, cx: 5, y: -6, x: 7, style: -8, name: 9, class: 10, ex_style: 11 };
        assert_eq!(value.cy, -4);
        assert_eq!(value.name, 9);
        assert_eq!(value.ex_style, 11);
    }
}
