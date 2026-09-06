//! AArch64 synchronous WndProc return leg; tagged service, never an AMD64 relay.
pub const CONTINUATION_BYTES: usize = 44;

/// Spill the 64-bit LRESULT, then NtCallbackReturn(pointer, 8, 0).
/// Does not touch x18, TPIDR_EL0 or nonvolatile registers. # C: O(1)
pub fn encode(selector: u64) -> [u8; CONTINUATION_BYTES] {
    let words = [
        0xd10043ff, // sub sp, sp, #16
        0xf90003e0, // str x0, [sp]
        0x910003e0, // mov x0, sp
        0xd2800101, // mov x1, #8
        0xd2800002, // mov x2, #0
        0xd2800008 | (((selector & 0xffff) as u32) << 5),
        0xf2a00008 | ((((selector >> 16) & 0xffff) as u32) << 5),
        0xf2c00008 | ((((selector >> 32) & 0xffff) as u32) << 5),
        0xf2e00008 | ((((selector >> 48) & 0xffff) as u32) << 5),
        0xd4000001, // svc #0
        0xd4200000, // brk #0: completion must not resume this continuation
    ];
    let mut bytes = [0; CONTINUATION_BYTES];
    for (index, word) in words.into_iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes()); }
    bytes
}

#[cfg(test)]
#[path = "aarch64_wndproc/tests.rs"]
mod tests;
