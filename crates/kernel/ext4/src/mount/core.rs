use crate::superblock::Superblock;

/// Kernel: fn returning a unique id for the current execution CONTEXT (task).
/// The reentrant transaction gate keys ownership on this so a task that sleeps
/// mid-transaction (at I/O) is not mistaken for a different task on the same CPU.
/// 0 ⇒ unset (early single-threaded boot) → `ctx_id` returns 1.
#[cfg(target_os = "oxide-kernel")]
static CTX_ID_HOOK: ::core::sync::atomic::AtomicU64 = ::core::sync::atomic::AtomicU64::new(0);

/// Register the current-context id source. kmain calls this once (before the
/// rootfs mount / SMP bring-up) with a fn returning the current task id.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn set_ctx_id_hook(f: fn() -> u64) {
    CTX_ID_HOOK.store(f as usize as u64, ::core::sync::atomic::Ordering::Release);
}

/// Unique-per-concurrent-context id for the transaction gate.
#[cfg(target_os = "oxide-kernel")]
pub(super) fn ctx_id() -> u64 {
    let raw = CTX_ID_HOOK.load(::core::sync::atomic::Ordering::Acquire);
    if raw == 0 { return 1; } // pre-registration: boot is single-threaded
    // SAFETY: `raw` is a `fn() -> u64` pointer stored only by set_ctx_id_hook.
    let f: fn() -> u64 = unsafe { ::core::mem::transmute(raw as usize) };
    let id = f();
    if id == 0 { 1 } else { id }
}

/// Hosted tests: a unique nonzero id per thread (thread-local, stable) so the
/// concurrent-churn tests exercise real cross-context serialization.
/// Host builds: a unique nonzero id per thread (thread-local, stable) so the
/// concurrent-churn tests exercise real cross-context serialization.
#[cfg(not(target_os = "oxide-kernel"))]
pub(super) fn ctx_id() -> u64 {
    std::thread_local!(static ID: u64 = {
        static NEXT: ::core::sync::atomic::AtomicU64 = ::core::sync::atomic::AtomicU64::new(2);
        NEXT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed)
    });
    ID.with(|&id| id)
}


#[path = "open.rs"]
mod open;
#[path = "metadata.rs"]
mod metadata;
#[path = "transaction.rs"]
mod transaction;

fn gdt_byte_offset_for(sb: &Superblock) -> u64 {
    if sb.block_size == 1024 {
        (sb.block_size as u64) * 2
    } else {
        sb.block_size as u64
    }
}
