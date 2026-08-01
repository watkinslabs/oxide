pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("_find_first_bit", _find_first_bit as *const () as usize),
        ("_find_next_bit",  _find_next_bit  as *const () as usize),
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
