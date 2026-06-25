// rt/mqueue — POSIX message queues (docs/59§6 G17b). Thin shims over the mq_*
// syscalls; mq_attr ABI-verified vs the libc crate. mqd_t is an fd (i32).
#[repr(C)]
pub struct mq_attr {
    pub mq_flags: i64,
    pub mq_maxmsg: i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
    __pad: [i64; 4],
}
const _: () = assert!(core::mem::size_of::<mq_attr>() == 64);

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::arch::syscall::{sys1, sys2, sys3, sys4, sys5};
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;
    use crate::rt::Timespec;

    const O_CREAT: i32 = 0o100;

    unsafe extern "C" {
        fn __fortify_fail(msg: *const u8) -> !;
    }

    unsafe fn kernel_mq_name(name: *const u8) -> *const u8 {
        // SAFETY: caller supplies a NUL-terminated POSIX message-queue name.
        if unsafe { *name } == b'/' {
            // SAFETY: the byte after a leading slash is within the same C string.
            unsafe { name.add(1) }
        } else {
            name
        }
    }

    // # C: mqd_t mq_open(const char *name, int oflag, ... [mode_t, struct mq_attr *])
    #[no_mangle]
    pub unsafe extern "C" fn mq_open(name: *const u8, oflag: i32, mode: u32, attr: *const mq_attr) -> i32 {
        // SAFETY: name is a C string; mode/attr are only consumed by the kernel
        // when O_CREAT is set (extra varargs registers, ABI-compatible).
        let name = unsafe { kernel_mq_name(name) };
        // SAFETY: name now follows the mq_open syscall convention; scalar
        // flags/mode and optional attr pointer are kernel-validated.
        ret_isize(unsafe { sys4(nr::MQ_OPEN, name as usize, oflag as usize, mode as usize, attr as usize) }) as i32
    }

    // # C: mqd_t __mq_open_2(const char *name, int oflag)
    #[no_mangle]
    pub unsafe extern "C" fn __mq_open_2(name: *const u8, oflag: i32) -> i32 {
        if oflag & O_CREAT != 0 {
            // SAFETY: __fortify_fail is noreturn and accepts a static C string.
            unsafe { __fortify_fail(b"invalid mq_open call\0".as_ptr()) }
        }
        // SAFETY: checked variant has the same name contract as mq_open.
        unsafe { mq_open(name, oflag, 0, core::ptr::null()) }
    }

    // # C: int mq_close(mqd_t mqdes)
    #[no_mangle]
    pub extern "C" fn mq_close(mqdes: i32) -> i32 {
        // SAFETY: mqdes is a message-queue descriptor (fd); close it.
        ret_isize(unsafe { sys1(nr::CLOSE, mqdes as usize) }) as i32
    }

    // # C: int mq_unlink(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn mq_unlink(name: *const u8) -> i32 {
        // SAFETY: name is a NUL-terminated queue name.
        ret_isize(unsafe { sys1(nr::MQ_UNLINK, name as usize) }) as i32
    }

    // # C: int mq_timedsend(mqd_t, const char *msg, size_t len, unsigned prio, const struct timespec *abs)
    #[no_mangle]
    pub unsafe extern "C" fn mq_timedsend(mqdes: i32, msg: *const u8, len: usize, prio: u32, abs: *const Timespec) -> i32 {
        // SAFETY: msg points to `len` bytes; abs null or a valid deadline.
        ret_isize(unsafe { sys5(nr::MQ_TIMEDSEND, mqdes as usize, msg as usize, len, prio as usize, abs as usize) }) as i32
    }
    // # C: int mq_send(mqd_t, const char *msg, size_t len, unsigned prio)
    #[no_mangle]
    pub unsafe extern "C" fn mq_send(mqdes: i32, msg: *const u8, len: usize, prio: u32) -> i32 {
        // SAFETY: msg points to `len` bytes; blocking send (null timeout).
        unsafe { mq_timedsend(mqdes, msg, len, prio, core::ptr::null()) }
    }

    // # C: ssize_t mq_timedreceive(mqd_t, char *msg, size_t len, unsigned *prio, const struct timespec *abs)
    #[no_mangle]
    pub unsafe extern "C" fn mq_timedreceive(mqdes: i32, msg: *mut u8, len: usize, prio: *mut u32, abs: *const Timespec) -> isize {
        // SAFETY: msg is writable for `len`; prio null or writable; abs null or valid.
        ret_isize(unsafe { sys5(nr::MQ_TIMEDRECEIVE, mqdes as usize, msg as usize, len, prio as usize, abs as usize) })
    }
    // # C: ssize_t mq_receive(mqd_t, char *msg, size_t len, unsigned *prio)
    #[no_mangle]
    pub unsafe extern "C" fn mq_receive(mqdes: i32, msg: *mut u8, len: usize, prio: *mut u32) -> isize {
        // SAFETY: msg writable for `len`; blocking receive (null timeout).
        unsafe { mq_timedreceive(mqdes, msg, len, prio, core::ptr::null()) }
    }

    // # C: int mq_getattr(mqd_t mqdes, struct mq_attr *attr)
    #[no_mangle]
    pub unsafe extern "C" fn mq_getattr(mqdes: i32, attr: *mut mq_attr) -> i32 {
        // SAFETY: attr is writable; mq_getsetattr with a null new-attr reads.
        ret_isize(unsafe { sys3(nr::MQ_GETSETATTR, mqdes as usize, 0, attr as usize) }) as i32
    }
    // # C: int mq_setattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr)
    #[no_mangle]
    pub unsafe extern "C" fn mq_setattr(mqdes: i32, newattr: *const mq_attr, oldattr: *mut mq_attr) -> i32 {
        // SAFETY: newattr valid; oldattr null or writable.
        ret_isize(unsafe { sys3(nr::MQ_GETSETATTR, mqdes as usize, newattr as usize, oldattr as usize) }) as i32
    }

    // # C: int mq_notify(mqd_t mqdes, const struct sigevent *sevp)
    #[no_mangle]
    pub unsafe extern "C" fn mq_notify(mqdes: i32, sevp: *const super::super::timer::sigevent) -> i32 {
        // SAFETY: sevp is null (cancel) or a valid sigevent.
        ret_isize(unsafe { sys2(nr::MQ_NOTIFY, mqdes as usize, sevp as usize) }) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mq_attr_abi() { assert_eq!(core::mem::size_of::<mq_attr>(), core::mem::size_of::<libc::mq_attr>()); }
}
