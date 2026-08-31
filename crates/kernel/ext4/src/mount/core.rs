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

pub(crate) fn gdt_block_byte_offset_for(sb: &Superblock, desc_block: u32) -> u64 {
    if sb.feature_incompat & crate::superblock::INCOMPAT_META_BG == 0
        || desc_block < sb.first_meta_bg
    { return gdt_byte_offset_for(sb) + u64::from(desc_block) * u64::from(sb.block_size); }
    let desc_per_block = u64::from(sb.block_size) / u64::from(sb.desc_size);
    if desc_per_block == 0 { return u64::MAX; }
    let group = u64::from(desc_block) * desc_per_block;
    let first = u64::from(sb.first_data_block)
        .saturating_add(group.saturating_mul(u64::from(sb.blocks_per_group)));
    let mut has_super = !sb.has_sparse_super()
        || group == 0 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7);
    if sb.block_size == 1024 && desc_block == 0 && sb.first_data_block == 0 { has_super = true; }
    first.saturating_add(if has_super { 1 } else { 0 }) * u64::from(sb.block_size)
}

fn is_power_of(mut n: u64, base: u64) -> bool {
    if n == 0 { return false; }
    while n % base == 0 { n /= base; }
    n == 1
}
