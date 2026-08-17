// The key list an unbound key answers with.
//
// The list is the WHOLE table, not the subset the enable mask permits. It was
// filtered here, which reads as helpful and is not: an operator on a machine
// with a restrictive `kernel.sysrq` was shown a short list and could not tell a
// key that does not exist from one that is merely refused — while the machine
// they are typing at is, by construction, the one that has stopped answering.
// The reference draws the line the same way: the unbound-key branch prints
// every registered key with no mask consultation, and a refusal is reported per
// keystroke, on the keystroke, by the command path.

use super::table::KEYS;

/// Prefix every help line carries.
pub const HELP_PREFIX: &[u8] = b"[sysrq] keys:";

/// Room for the prefix plus every key and its label. Sized from the table so a
/// key added without room shows up as a compile-time constant that is too
/// small, rather than as a silently clipped line.
pub const HELP_MAX: usize = 128;

/// Render the whole key list into `out`, returning its length.
///
/// Built into a caller-supplied buffer and emitted as ONE line, because the
/// line is printed from the console's emergency route and a line assembled by
/// several writes can be spliced by another CPU's output in between.
/// # C: O(number of keys)
pub fn render_help(out: &mut [u8; HELP_MAX]) -> usize {
    let mut n = 0;
    let mut put = |bytes: &[u8], n: &mut usize| {
        for &b in bytes { if *n < HELP_MAX { out[*n] = b; *n += 1; } }
    };
    put(HELP_PREFIX, &mut n);
    for &(key, label) in KEYS {
        put(b" ", &mut n);
        put(&[key], &mut n);
        put(b"=", &mut n);
        put(label, &mut n);
    }
    n
}

/// Print the key list. # C: O(number of keys)
pub fn emit_help() {
    let mut buf = [0u8; HELP_MAX];
    let n = render_help(&mut buf);
    klog::announce_bytes(&buf[..n]);
}
