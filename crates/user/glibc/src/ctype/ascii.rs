// ctype is*/to* (docs/59§6 G4), C/POSIX locale. Range-based (the C
// locale needs no table); locale-aware tables arrive with G16. Inputs are
// the [0,255] unsigned-char domain or EOF; outside that we return 0/ident
// like glibc's safe path. Private predicates are tested directly; the
// #[no_mangle] C exports are freestanding-only.

fn byte(c: i32) -> Option<u8> { if (0..=255).contains(&c) { Some(c as u8) } else { None } }

fn is_digit(c: i32) -> bool { matches!(byte(c), Some(b'0'..=b'9')) }
fn is_upper(c: i32) -> bool { matches!(byte(c), Some(b'A'..=b'Z')) }
fn is_lower(c: i32) -> bool { matches!(byte(c), Some(b'a'..=b'z')) }
fn is_alpha(c: i32) -> bool { is_upper(c) || is_lower(c) }
fn is_alnum(c: i32) -> bool { is_alpha(c) || is_digit(c) }
fn is_space(c: i32) -> bool { matches!(byte(c), Some(b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')) }
fn is_blank(c: i32) -> bool { matches!(byte(c), Some(b' ' | b'\t')) }
fn is_xdigit(c: i32) -> bool { is_digit(c) || matches!(byte(c), Some(b'a'..=b'f' | b'A'..=b'F')) }
fn is_cntrl(c: i32) -> bool { matches!(byte(c), Some(0x00..=0x1f | 0x7f)) }
fn is_print(c: i32) -> bool { matches!(byte(c), Some(0x20..=0x7e)) }
fn is_graph(c: i32) -> bool { matches!(byte(c), Some(0x21..=0x7e)) }
fn is_punct(c: i32) -> bool { is_graph(c) && !is_alnum(c) }
fn to_upper(c: i32) -> i32 { if is_lower(c) { c - 0x20 } else { c } }
fn to_lower(c: i32) -> i32 { if is_upper(c) { c + 0x20 } else { c } }

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    macro_rules! pred { ($name:ident, $f:ident, $doc:literal) => {
        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $name(c: i32) -> i32 { $f(c) as i32 }
    }; }
    pred!(isdigit, is_digit, "# C: int isdigit(int)");
    pred!(isupper, is_upper, "# C: int isupper(int)");
    pred!(islower, is_lower, "# C: int islower(int)");
    pred!(isalpha, is_alpha, "# C: int isalpha(int)");
    pred!(isalnum, is_alnum, "# C: int isalnum(int)");
    pred!(isspace, is_space, "# C: int isspace(int)");
    pred!(isblank, is_blank, "# C: int isblank(int)");
    pred!(isxdigit, is_xdigit, "# C: int isxdigit(int)");
    pred!(iscntrl, is_cntrl, "# C: int iscntrl(int)");
    pred!(isprint, is_print, "# C: int isprint(int)");
    pred!(isgraph, is_graph, "# C: int isgraph(int)");
    pred!(ispunct, is_punct, "# C: int ispunct(int)");
    // # C: int toupper(int)
    #[no_mangle]
    pub extern "C" fn toupper(c: i32) -> i32 { to_upper(c) }
    // # C: int tolower(int)
    #[no_mangle]
    pub extern "C" fn tolower(c: i32) -> i32 { to_lower(c) }
    // # C: int isascii(int) — true for the 7-bit ASCII range [0,127] (XSI/SVID)
    #[no_mangle]
    pub extern "C" fn isascii(c: i32) -> i32 { (c & !0x7f == 0) as i32 }
    // # C: int toascii(int) — mask to the low 7 bits (XSI/SVID)
    #[no_mangle]
    pub extern "C" fn toascii(c: i32) -> i32 { c & 0x7f }
    // # C: int _tolower(int) — unchecked lowercase (assumes isupper(c)); SVID
    #[no_mangle]
    pub extern "C" fn _tolower(c: i32) -> i32 { c | 0x20 }
    // # C: int _toupper(int) — unchecked uppercase (assumes islower(c)); SVID
    #[no_mangle]
    pub extern "C" fn _toupper(c: i32) -> i32 { c & !0x20 }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Differential vs host glibc over the full unsigned-char domain.
    #[test]
    fn ctype_matches_host_over_domain() {
        for c in 0..=255i32 {
            // SAFETY: libc ctype fns accept an int in the unsigned-char
            // domain or EOF; c stays within [0,255] here.
            let h = unsafe {
                [libc::isdigit(c), libc::isupper(c), libc::islower(c), libc::isalpha(c),
                 libc::isalnum(c), libc::isspace(c), libc::isblank(c), libc::isxdigit(c),
                 libc::iscntrl(c), libc::isprint(c), libc::isgraph(c), libc::ispunct(c),
                 libc::toupper(c), libc::tolower(c)]
            };
            assert_eq!(is_digit(c), h[0] != 0, "isdigit {c}");
            assert_eq!(is_upper(c), h[1] != 0, "isupper {c}");
            assert_eq!(is_lower(c), h[2] != 0, "islower {c}");
            assert_eq!(is_alpha(c), h[3] != 0, "isalpha {c}");
            assert_eq!(is_alnum(c), h[4] != 0, "isalnum {c}");
            assert_eq!(is_space(c), h[5] != 0, "isspace {c}");
            assert_eq!(is_blank(c), h[6] != 0, "isblank {c}");
            assert_eq!(is_xdigit(c), h[7] != 0, "isxdigit {c}");
            assert_eq!(is_cntrl(c), h[8] != 0, "iscntrl {c}");
            assert_eq!(is_print(c), h[9] != 0, "isprint {c}");
            assert_eq!(is_graph(c), h[10] != 0, "isgraph {c}");
            assert_eq!(is_punct(c), h[11] != 0, "ispunct {c}");
            assert_eq!(to_upper(c), h[12], "toupper {c}");
            assert_eq!(to_lower(c), h[13], "tolower {c}");
        }
    }
}
