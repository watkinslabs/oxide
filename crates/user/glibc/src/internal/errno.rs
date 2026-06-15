// errno — thread-local, exposed to C via `__errno_location` (docs/59§2).
// Real TLS slot lands with G11 (pthread/TLS); G1 stub keeps the type and
// the set/clear helpers so call sites compile. A syscall returning
// -4095..=-1 is `-errno` (Linux ABI); `ret()` splits ok/err.

// # C: thread-local errno cell; one per thread once TLS exists (G11).
#[cfg(any(test, feature = "hosted"))]
pub fn set(_e: i32) {}

// Map a raw syscall return into Result-ish: Err(errno) for the
// [-4095, -1] band, Ok(val) otherwise. docs/15 ABI.
#[inline]
pub fn ret(r: isize) -> Result<isize, i32> {
    if (-4095..=-1).contains(&r) { Err(-r as i32) } else { Ok(r) }
}

// G1 test-harness seed: establishes `cargo test -p glibc` as the
// differential-oracle home (docs/59§7). Area oracles (string/stdio/…)
// land beside their impls at G4+.
#[cfg(test)]
mod tests {
    use super::ret;
    #[test]
    fn errno_band_splits() {
        assert_eq!(ret(-1), Err(1)); // -EPERM
        assert_eq!(ret(-4095), Err(4095)); // band floor
        assert_eq!(ret(0), Ok(0));
        assert_eq!(ret(42), Ok(42));
        assert_eq!(ret(-4096), Ok(-4096)); // below band = valid (e.g. mmap addr)
    }
}
