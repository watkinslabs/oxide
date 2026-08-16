// Constant-time byte comparison. Difference is accumulated over every byte
// with `|=`; there is no early return, so the running time depends only on
// the length and never on where the first mismatch is.

/// True when the two slices are equal. Unequal lengths compare false without
/// inspecting contents (length is not secret).
/// # C: O(n)
pub(crate) fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}
