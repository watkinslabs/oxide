// glibc ctype tables (docs/59§6 G4). <ctype.h>'s is*/to* macros expand to
// `(*__ctype_b_loc())[c] & _ISxxx` etc., indexing a table offset by +128 so
// EOF(-1) and signed-char negatives are valid. C/POSIX locale. The tables are
// pure const data; the *_loc C ABI is freestanding. ABI-checked: the bit
// values match glibc <bits/ctype.h> _ISbit().

// _ISbit(n): n<8 ? (1<<n)<<8 : (1<<n)>>8  (glibc bits/ctype.h).
const ISUPPER: u16 = 0x0100; // _ISbit(0)
const ISLOWER: u16 = 0x0200; // _ISbit(1)
const ISALPHA: u16 = 0x0400; // _ISbit(2)
const ISDIGIT: u16 = 0x0800; // _ISbit(3)
const ISXDIGIT: u16 = 0x1000; // _ISbit(4)
const ISSPACE: u16 = 0x2000; // _ISbit(5)
const ISPRINT: u16 = 0x4000; // _ISbit(6)
const ISGRAPH: u16 = 0x8000; // _ISbit(7)
const ISBLANK: u16 = 0x0001; // _ISbit(8)
const ISCNTRL: u16 = 0x0002; // _ISbit(9)
const ISPUNCT: u16 = 0x0004; // _ISbit(10)
const ISALNUM: u16 = 0x0008; // _ISbit(11)

// C-locale class mask for one ASCII byte (0..=127).
const fn class(c: u8) -> u16 {
    let upper = c >= b'A' && c <= b'Z';
    let lower = c >= b'a' && c <= b'z';
    let digit = c >= b'0' && c <= b'9';
    let xdigit = digit || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F');
    let space = c == b' ' || (c >= 0x09 && c <= 0x0d);
    let blank = c == b' ' || c == b'\t';
    let cntrl = c <= 0x1f || c == 0x7f;
    let print = c >= 0x20 && c <= 0x7e;
    let graph = c >= 0x21 && c <= 0x7e;
    let alpha = upper || lower;
    let alnum = alpha || digit;
    let punct = graph && !alnum;
    let mut m = 0u16;
    if upper { m |= ISUPPER; }
    if lower { m |= ISLOWER; }
    if alpha { m |= ISALPHA; }
    if digit { m |= ISDIGIT; }
    if xdigit { m |= ISXDIGIT; }
    if space { m |= ISSPACE; }
    if blank { m |= ISBLANK; }
    if cntrl { m |= ISCNTRL; }
    if print { m |= ISPRINT; }
    if graph { m |= ISGRAPH; }
    if punct { m |= ISPUNCT; }
    if alnum { m |= ISALNUM; }
    m
}

const fn build_b() -> [u16; 384] {
    let mut t = [0u16; 384];
    let mut c = 0usize;
    while c < 128 { t[c + 128] = class(c as u8); c += 1; } // ASCII only; 128..255 = 0 in C locale
    t
}
const fn build_tolower() -> [i32; 384] {
    let mut t = [0i32; 384];
    let mut i = 0usize;
    while i < 384 { let c = i as i32 - 128; t[i] = if c >= 'A' as i32 && c <= 'Z' as i32 { c + 32 } else { c }; i += 1; }
    t
}
const fn build_toupper() -> [i32; 384] {
    let mut t = [0i32; 384];
    let mut i = 0usize;
    while i < 384 { let c = i as i32 - 128; t[i] = if c >= 'a' as i32 && c <= 'z' as i32 { c - 32 } else { c }; i += 1; }
    t
}
const fn build_b32() -> [u32; 384] {
    let mut t = [0u32; 384];
    let mut c = 0usize;
    while c < 128 { t[c + 128] = class(c as u8) as u32; c += 1; }
    t
}
const fn build_tolower32() -> [u32; 384] {
    let mut t = [0u32; 384];
    let mut i = 0usize;
    while i < 384 {
        let c = i as i32 - 128;
        t[i] = (if c >= 'A' as i32 && c <= 'Z' as i32 { c + 32 } else { c }) as u32;
        i += 1;
    }
    t
}
const fn build_toupper32() -> [u32; 384] {
    let mut t = [0u32; 384];
    let mut i = 0usize;
    while i < 384 {
        let c = i as i32 - 128;
        t[i] = (if c >= 'a' as i32 && c <= 'z' as i32 { c - 32 } else { c }) as u32;
        i += 1;
    }
    t
}

pub(crate) static B_TABLE: [u16; 384] = build_b();
pub(crate) static TOLOWER_TABLE: [i32; 384] = build_tolower();
pub(crate) static TOUPPER_TABLE: [i32; 384] = build_toupper();
static B32_TABLE: [u32; 384] = build_b32();
static TOLOWER32_TABLE: [u32; 384] = build_tolower32();
static TOUPPER32_TABLE: [u32; 384] = build_toupper32();

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::cell::UnsafeCell;

    struct Loc<T>(UnsafeCell<*const T>);
    // SAFETY: each holds a pointer into a 'static const table; *_loc sets it on
    // each call and returns its address (single global; glibc uses TLS).
    unsafe impl<T> Sync for Loc<T> {}
    static B_LOC: Loc<u16> = Loc(UnsafeCell::new(core::ptr::null()));
    static TL_LOC: Loc<i32> = Loc(UnsafeCell::new(core::ptr::null()));
    static TU_LOC: Loc<i32> = Loc(UnsafeCell::new(core::ptr::null()));

    #[repr(transparent)]
    struct Ptr<T>(*const T);
    // SAFETY: these are immutable ABI pointer objects into static tables.
    unsafe impl<T> Sync for Ptr<T> {}

    const CTYPE_B_PTR: *const u16 = {
        // SAFETY: B_TABLE has 384 entries; +128 is the documented base offset.
        unsafe { B_TABLE.as_ptr().add(128) }
    };
    const CTYPE_TOLOWER_PTR: *const i32 = {
        // SAFETY: TOLOWER_TABLE has 384 entries; +128 is the base offset.
        unsafe { TOLOWER_TABLE.as_ptr().add(128) }
    };
    const CTYPE_TOUPPER_PTR: *const i32 = {
        // SAFETY: TOUPPER_TABLE has 384 entries; +128 is the base offset.
        unsafe { TOUPPER_TABLE.as_ptr().add(128) }
    };
    const CTYPE32_B_PTR: *const u32 = {
        // SAFETY: B32_TABLE has 384 entries; +128 is the documented offset.
        unsafe { B32_TABLE.as_ptr().add(128) }
    };
    const CTYPE32_TOLOWER_PTR: *const u32 = {
        // SAFETY: TOLOWER32_TABLE has 384 entries; +128 is the base offset.
        unsafe { TOLOWER32_TABLE.as_ptr().add(128) }
    };
    const CTYPE32_TOUPPER_PTR: *const u32 = {
        // SAFETY: TOUPPER32_TABLE has 384 entries; +128 is the base offset.
        unsafe { TOUPPER32_TABLE.as_ptr().add(128) }
    };

    // # C: const unsigned short *__ctype_b;
    #[no_mangle]
    static __ctype_b: Ptr<u16> = Ptr(CTYPE_B_PTR);
    // # C: const int *__ctype_tolower;
    #[no_mangle]
    static __ctype_tolower: Ptr<i32> = Ptr(CTYPE_TOLOWER_PTR);
    // # C: const int *__ctype_toupper;
    #[no_mangle]
    static __ctype_toupper: Ptr<i32> = Ptr(CTYPE_TOUPPER_PTR);
    // # C: const unsigned int *__ctype32_b;
    #[no_mangle]
    static __ctype32_b: Ptr<u32> = Ptr(CTYPE32_B_PTR);
    // # C: const unsigned int *__ctype32_tolower;
    #[no_mangle]
    static __ctype32_tolower: Ptr<u32> = Ptr(CTYPE32_TOLOWER_PTR);
    // # C: const unsigned int *__ctype32_toupper;
    #[no_mangle]
    static __ctype32_toupper: Ptr<u32> = Ptr(CTYPE32_TOUPPER_PTR);

    // # C: void __ctype_init(void)
    #[no_mangle]
    pub extern "C" fn __ctype_init() {
        __ctype_b_loc();
        __ctype_tolower_loc();
        __ctype_toupper_loc();
    }

    // # C: const unsigned short **__ctype_b_loc(void)
    #[no_mangle]
    pub extern "C" fn __ctype_b_loc() -> *mut *const u16 {
        // SAFETY: B_TABLE is a 'static [u16;384]; offset +128 so callers index
        // [-128..255]. Store the offset pointer, return the cell address.
        unsafe { *B_LOC.0.get() = B_TABLE.as_ptr().add(128); B_LOC.0.get() }
    }
    // # C: const int32_t **__ctype_tolower_loc(void)
    #[no_mangle]
    pub extern "C" fn __ctype_tolower_loc() -> *mut *const i32 {
        // SAFETY: TOLOWER_TABLE is 'static [i32;384]; +128 offset as above.
        unsafe { *TL_LOC.0.get() = TOLOWER_TABLE.as_ptr().add(128); TL_LOC.0.get() }
    }
    // # C: const int32_t **__ctype_toupper_loc(void)
    #[no_mangle]
    pub extern "C" fn __ctype_toupper_loc() -> *mut *const i32 {
        // SAFETY: TOUPPER_TABLE is 'static [i32;384]; +128 offset as above.
        unsafe { *TU_LOC.0.get() = TOUPPER_TABLE.as_ptr().add(128); TU_LOC.0.get() }
    }

    // # C: int isctype(int c, int mask)
    #[no_mangle]
    pub extern "C" fn isctype(c: i32, mask: i32) -> i32 {
        if !(-128..=255).contains(&c) { return 0; }
        (B_TABLE[(c + 128) as usize] as i32) & mask
    }
    // # C: int __isctype(int c, int mask)
    #[no_mangle]
    pub extern "C" fn __isctype(c: i32, mask: i32) -> i32 {
        isctype(c, mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classify_matches_predicates() {
        // spot-check the table vs the C-locale contract.
        assert_ne!(B_TABLE[128 + 'A' as usize] & ISUPPER, 0);
        assert_ne!(B_TABLE[128 + 'A' as usize] & ISALPHA, 0);
        assert_ne!(B_TABLE[128 + 'z' as usize] & ISLOWER, 0);
        assert_ne!(B_TABLE[128 + '5' as usize] & (ISDIGIT | ISXDIGIT | ISALNUM), 0);
        assert_eq!(B_TABLE[128 + '5' as usize] & ISALPHA, 0);
        assert_ne!(B_TABLE[128 + ' ' as usize] & (ISSPACE | ISBLANK | ISPRINT), 0);
        assert_eq!(B_TABLE[128 + ' ' as usize] & ISGRAPH, 0);
        assert_ne!(B_TABLE[128 + '!' as usize] & (ISPUNCT | ISGRAPH | ISPRINT), 0);
        assert_ne!(B_TABLE[128 + 0x0a] & ISCNTRL, 0);
        assert_eq!(B_TABLE[128 + 200] , 0); // high byte unclassified in C locale
        assert_eq!(TOLOWER_TABLE[128 + 'A' as usize], 'a' as i32);
        assert_eq!(TOUPPER_TABLE[128 + 'a' as usize], 'A' as i32);
        assert_eq!(TOLOWER_TABLE[128 + '5' as usize], '5' as i32);
        // EOF(-1) index is valid (identity)
        assert_eq!(TOLOWER_TABLE[128 - 1], -1);
    }
}
