pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("_find_first_bit", _find_first_bit as *const () as usize),
        ("_find_next_bit",  _find_next_bit  as *const () as usize),
        ("__sw_hweight32", __sw_hweight32 as *const () as usize),
        ("__sw_hweight64", __sw_hweight64 as *const () as usize),
        ("__bitmap_weight", __bitmap_weight as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn _find_first_bit(addr: *const usize, size: usize) -> usize {
    _find_next_bit(addr, size, 0)
}

pub(crate) extern "C" fn _find_next_bit(addr: *const usize, size: usize, offset: usize) -> usize {
    if addr.is_null() || offset >= size { return size; }
    let bits = usize::BITS as usize;
    let mut bit = offset;
    while bit < size {
        // SAFETY: bit < size and the KPI contract sizes addr at ceil(size/usize::BITS) words, so bit/bits indexes the caller's own bitmap.
        let word = unsafe { *addr.add(bit / bits) };
        let mask = usize::MAX << (bit % bits);
        let masked = word & mask;
        if masked != 0 {
            let found = bit - (bit % bits) + masked.trailing_zeros() as usize;
            return core::cmp::min(found, size);
        }
        bit = ((bit / bits) + 1) * bits;
    }
    size
}

/// # C: O(1)
pub(crate) extern "C" fn __sw_hweight32(word: u32) -> u32 {
    word.count_ones()
}

/// # C: O(1)
pub(crate) extern "C" fn __sw_hweight64(word: u64) -> usize {
    word.count_ones() as usize
}

/// Count only the bits inside the supplied bitmap width.
/// # C: O(ceil(bits / word_bits))
pub(crate) extern "C" fn __bitmap_weight(bitmap: *const usize, bits: u32) -> u32 {
    if bitmap.is_null() || bits == 0 { return 0; }
    let word_bits = usize::BITS;
    let whole_words = bits / word_bits;
    let trailing_bits = bits % word_bits;
    let mut weight = 0u32;
    for index in 0..whole_words as usize {
        // SAFETY: the Linux bitmap ABI supplies ceil(bits / word_bits) readable words.
        weight += unsafe { (*bitmap.add(index)).count_ones() };
    }
    if trailing_bits != 0 {
        // SAFETY: a non-zero remainder requires one final readable bitmap word by the ABI.
        let tail = unsafe { *bitmap.add(whole_words as usize) };
        weight += (tail & (usize::MAX >> (word_bits - trailing_bits))).count_ones();
    }
    weight
}
