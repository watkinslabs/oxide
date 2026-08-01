/// Fixed firmware/CPUID ASCII field trimmed at first NUL and trailing spaces.
/// Sole caller is `cpuinfo::trim`, which only the x86_64 block needs. # C: O(N)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) fn ascii_field_trimmed(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    // SAFETY: CPU/vendor firmware fields used here are architected ASCII bytes.
    unsafe { core::str::from_utf8_unchecked(&b[..end]) }.trim()
}
