//! Callback-table routing, module path contract and full-width event fields.
use super::{hook_event::{begin, Notification}, nt_rtl::CALL};
use ipc::win32_hook::{Hook, WH_WINEVENT, WINEVENT_INCONTEXT};
use sched::nt_callback::Completion;
fn hook(module: Vec<u16>) -> Hook {
    Hook { handle: 0xaabbccdd, id: WH_WINEVENT, process: None, thread: None, owner: 17,
        event_min: 1, event_max: u32::MAX, flags: WINEVENT_INCONTEXT, proc_address: 0x123456789abcdef0,
        unicode: true, module }
}
fn event() -> Notification {
    Notification { event: 0x800a, hwnd: 0xfedcba9876543210, object_id: -4, child_id: -1,
        thread: 0xaabbccdd, time: 0xfffffffe }
}
fn take() -> (u32, Vec<u8>, Completion) { CALL.with(|call| call.borrow_mut().take().expect("client callback was not entered")) }
fn u32_at(bytes: &[u8], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) }
fn u64_at(bytes: &[u8], offset: usize) -> u64 { u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) }

#[test]
fn event_enters_client_callback_with_relative_proc_module_and_continuation() {
    let path: Vec<u16> = "C:\\hooks\\events.dll".encode_utf16().collect();
    let completion = Completion { kind: 0x82, argument: 0x8877665544332211 };
    assert_eq!(begin(&hook(path.clone()), event(), completion), 0x103);
    let (index, bytes, saved) = take();
    assert_eq!(index, 3);
    assert_eq!(saved, completion);
    assert_eq!(u32_at(&bytes, 0), 0x800a);
    assert_eq!(&bytes[4..8], &[0; 4]);
    assert_eq!(u64_at(&bytes, 8), 0xfedcba9876543210);
    assert_eq!(u32_at(&bytes, 16) as i32, -4);
    assert_eq!(u32_at(&bytes, 20) as i32, -1);
    assert_eq!(u64_at(&bytes, 24), 0xaabbccdd);
    assert_eq!(u32_at(&bytes, 32), 0xaabbccdd);
    assert_eq!(u32_at(&bytes, 36), 0xfffffffe);
    assert_eq!(u64_at(&bytes, 40), 0x123456789abcdef0);
    let units: Vec<u16> = bytes[48..].chunks_exact(2).map(|u| u16::from_le_bytes(u.try_into().unwrap())).collect();
    assert_eq!(units, path.into_iter().chain([0]).collect::<Vec<_>>());
}

#[test]
fn absolute_hook_still_uses_client_callback_with_empty_terminated_path() {
    assert_eq!(begin(&hook(Vec::new()), event(), Completion::NONE), 0x103);
    let (index, bytes, completion) = take();
    assert_eq!(index, 3);
    assert_eq!(completion, Completion::NONE);
    assert_eq!(bytes.len(), 50);
    assert_eq!(&bytes[48..], &[0, 0]);
    assert_eq!(u64_at(&bytes, 40), 0x123456789abcdef0);
}

#[test]
fn embedded_terminator_ends_callback_module() {
    begin(&hook(vec![65, 0, 66]), event(), Completion::NONE);
    assert_eq!(&take().1[48..], &[65, 0, 0, 0]);
}

#[test]
fn longest_module_leaves_space_for_terminator() {
    begin(&hook(vec![65; 260]), event(), Completion::NONE);
    let bytes = take().1;
    assert_eq!(bytes.len(), 48 + 260 * 2);
    assert!(bytes[48..566].chunks_exact(2).all(|unit| unit == [65, 0]));
    assert_eq!(&bytes[566..], &[0, 0]);
}
