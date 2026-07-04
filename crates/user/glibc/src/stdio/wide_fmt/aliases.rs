use super::*;
use super::scan::{wscan_file_va, wscan_str_va};
// __isoc99_*). Same contract; provide both aliases for each entry point.
macro_rules! isoc_swscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *s, const wchar_t *fmt, ...)
        #[no_mangle]
        pub unsafe extern "C" fn $name(s: *const i32, fmt: *const i32, mut ap: ...) -> i32 {
            // SAFETY: s/fmt NUL-terminated wide strings; ap supplies pointer args.
            unsafe { wscan_str_va(s, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_fwscanf {
    ($name:ident) => {
        /// # C: int $name(FILE *f, const wchar_t *fmt, ...)
        #[no_mangle]
        pub unsafe extern "C" fn $name(f: *mut FILE, fmt: *const i32, mut ap: ...) -> i32 {
            // SAFETY: f is a readable stream; ap supplies the pointer args.
            unsafe { wscan_file_va(f, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_wscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *fmt, ...)
        #[no_mangle]
        pub unsafe extern "C" fn $name(fmt: *const i32, mut ap: ...) -> i32 {
            // SAFETY: reads from stdin; ap supplies the pointer args.
            unsafe { wscan_file_va(stdin_ptr(), fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_vswscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *s, const wchar_t *fmt, va_list ap)
        #[no_mangle]
        pub unsafe extern "C" fn $name(s: *const i32, fmt: *const i32, mut ap: VaList) -> i32 {
            // SAFETY: same ABI contract as vswscanf.
            unsafe { wscan_str_va(s, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_vfwscanf {
    ($name:ident) => {
        /// # C: int $name(FILE *f, const wchar_t *fmt, va_list ap)
        #[no_mangle]
        pub unsafe extern "C" fn $name(f: *mut FILE, fmt: *const i32, mut ap: VaList) -> i32 {
            // SAFETY: same ABI contract as vfwscanf.
            unsafe { wscan_file_va(f, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_vwscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *fmt, va_list ap)
        #[no_mangle]
        pub unsafe extern "C" fn $name(fmt: *const i32, mut ap: VaList) -> i32 {
            // SAFETY: same ABI contract and va_list layout as vwscanf.
            unsafe { wscan_file_va(stdin_ptr(), fmt, &mut ap) }
        }
    };
}
isoc_swscanf!(__isoc23_swscanf);
isoc_swscanf!(__isoc99_swscanf);
isoc_fwscanf!(__isoc23_fwscanf);
isoc_fwscanf!(__isoc99_fwscanf);
isoc_wscanf!(__isoc23_wscanf);
isoc_wscanf!(__isoc99_wscanf);
isoc_vswscanf!(__isoc23_vswscanf);
isoc_vswscanf!(__isoc99_vswscanf);
isoc_vfwscanf!(__isoc23_vfwscanf);
isoc_vfwscanf!(__isoc99_vfwscanf);
isoc_vwscanf!(__isoc23_vwscanf);
isoc_vwscanf!(__isoc99_vwscanf);
