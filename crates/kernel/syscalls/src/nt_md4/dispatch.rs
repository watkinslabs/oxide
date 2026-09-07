//! User boundary for the MD4 digest services: fetch the context record, run
//! the ungated accumulator, store it back.

use alloc::vec;
use syscall::nt::{NtCall, NtService};

use super::digest::{Context, CONTEXT_BYTES};

/// Bytes one update copies out of user memory at a time.
const UPDATE_CHUNK_BYTES: usize = 4096;

/// Route one MD4 digest service. The exports return no status.
/// # C: O(message bytes) plus the context copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::Md4Init => Some(init(call.args.a0)),
        NtService::Md4Update => Some(update(call.args.a0, call.args.a1, call.args.a2 as u32)),
        NtService::Md4Final => Some(finish(call.args.a0)),
        _ => None,
    }
}

fn init(context: u64) -> u64 {
    if context == 0 { return 0; }
    let _ = uaccess::copy_to_user(context, &Context::new().encode());
    0
}

fn update(context: u64, message: u64, length: u32) -> u64 {
    if context == 0 || (length != 0 && message == 0) { return 0; }
    let mut raw = [0u8; CONTEXT_BYTES];
    if uaccess::copy_from_user(&mut raw, context).is_err() { return 0; }
    let mut state = Context::decode(&raw);
    let mut offset = 0u32;
    while offset < length {
        let span = UPDATE_CHUNK_BYTES.min((length - offset) as usize);
        let mut chunk = vec![0u8; span];
        let Some(slot) = message.checked_add(offset as u64) else { return 0; };
        if uaccess::copy_from_user(&mut chunk, slot).is_err() { return 0; }
        state.update(&chunk);
        offset += span as u32;
    }
    let _ = uaccess::copy_to_user(context, &state.encode());
    0
}

fn finish(context: u64) -> u64 {
    if context == 0 { return 0; }
    let mut raw = [0u8; CONTEXT_BYTES];
    if uaccess::copy_from_user(&mut raw, context).is_err() { return 0; }
    let mut state = Context::decode(&raw);
    state.finish();
    let _ = uaccess::copy_to_user(context, &state.encode());
    0
}
