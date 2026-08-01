use core::mem::size_of;

const U32_BYTES: usize = size_of::<u32>();
const U64_BYTES: usize = size_of::<u64>();

/// Register Linux random helper symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("get_random_bytes",          get_random_bytes          as *const () as usize),
        ("get_random_u32",            get_random_u32            as *const () as usize),
        ("get_random_u64",            get_random_u64            as *const () as usize),
        ("prandom_u32",               prandom_u32               as *const () as usize),
        ("add_device_randomness",     add_device_randomness     as *const () as usize),
        ("add_hwgenerator_randomness", add_hwgenerator_randomness as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn get_random_bytes(buf: *mut u8, nbytes: usize) {
    if buf.is_null() || nbytes == 0 { return; }
    // SAFETY: Linux modules pass a writable kernel buffer of nbytes bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, nbytes) };
    devfs::misc::random_fill(out);
}

extern "C" fn get_random_u32() -> u32 {
    let mut b = [0u8; U32_BYTES];
    get_random_bytes(b.as_mut_ptr(), b.len());
    u32::from_le_bytes(b)
}

extern "C" fn get_random_u64() -> u64 {
    let mut b = [0u8; U64_BYTES];
    get_random_bytes(b.as_mut_ptr(), b.len());
    u64::from_le_bytes(b)
}

extern "C" fn prandom_u32() -> u32 {
    get_random_u32()
}

extern "C" fn add_device_randomness(buf: *const u8, nbytes: usize) {
    if buf.is_null() || nbytes == 0 { return; }
    // SAFETY: Linux modules pass a readable kernel buffer of nbytes bytes.
    let bytes = unsafe { core::slice::from_raw_parts(buf, nbytes) };
    devfs::misc::add_entropy(bytes);
}

extern "C" fn add_hwgenerator_randomness(buf: *const u8, nbytes: usize, entropy: usize) {
    // Linux credits this path and not `add_device_randomness`; aliasing the two
    // meant a hwrng module could never bring a cold pool to ready.
    let _ = entropy;
    if buf.is_null() || nbytes == 0 { return; }
    // SAFETY: Linux modules pass a readable kernel buffer of nbytes bytes to add_hwgenerator_randomness.
    let bytes = unsafe { core::slice::from_raw_parts(buf, nbytes) };
    devfs::misc::add_hw_entropy(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM_LEN: usize = 16;

    #[test]
    fn get_random_bytes_fills_buffer() {
        let _modules = crate::test_serial::claim();
        let mut b = [0u8; RANDOM_LEN];
        get_random_bytes(b.as_mut_ptr(), b.len());
        assert!(b.iter().any(|v| *v != 0));
    }

    #[test]
    fn add_device_randomness_accepts_valid_input() {
        let _modules = crate::test_serial::claim();
        let seed = [1u8, 2, 3, 4];
        add_device_randomness(seed.as_ptr(), seed.len());
        let _ = get_random_u32();
    }
}
