// SysV IPC semaphores <sys/sem.h> (docs/59§6). semget/semop/semctl/
// semtimedop wrap the per-op Linux syscalls directly — neither x86_64 nor
// aarch64 routes these through the legacy ipc() multiplexer (both have the
// individual slots in nr.rs). semctl is varargs (union semun); glibc passes
// the union value as the raw 4th syscall arg and ORs IPC_64 into the cmd so
// the kernel uses the wide semid64_ds layout. The flag/cmd consts + the
// sembuf layout are always compiled (ABI-checked against the libc crate); only
// the syscall-issuing wrappers are freestanding-only.

// semget/semctl IPC flags + commands (bits/ipc.h, bits/sem.h — same numeric
// values on x86_64 and aarch64).
pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;
pub const SEM_STAT_ANY: i32 = 20;
// semop flag (bits/sem.h).
pub const SEM_UNDO: i32 = 0x1000;
pub const IPC_PRIVATE: i32 = 0;
// Wide-struct selector glibc ORs into the ctl cmd (linux/ipc.h IPC_64).
const IPC_64: i32 = 0x100;

// struct sembuf — argument to semop (sys/sem.h). Layout matches host.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

// union semun — caller-provided ctl argument. The C side defines it; on the
// ABI it is one machine word (int val | pointer). semctl is varargs, so the
// wrapper reads one usize-wide word covering both forms.
#[repr(C)]
#[derive(Clone, Copy)]
pub union semun {
    pub val: i32,
    pub buf: *mut u8,   // struct semid_ds *
    pub array: *mut u16,
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::{IPC_64, sembuf};
    use crate::arch::syscall::{sys3, sys4};
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;
    use crate::time::clock::timespec;

    // # C: int semget(key_t key, int nsems, int semflg)
    #[no_mangle]
    pub unsafe extern "C" fn semget(key: i32, nsems: i32, semflg: i32) -> i32 {
        // SAFETY: semget(2) takes scalar key/nsems/semflg; no memory is
        // dereferenced by libc. Kernel returns a set id or -errno.
        ret_isize(unsafe { sys3(nr::SEMGET, key as usize, nsems as usize, semflg as usize) }) as i32
    }

    // # C: int semop(int semid, struct sembuf *sops, size_t nsops)
    #[no_mangle]
    pub unsafe extern "C" fn semop(semid: i32, sops: *mut sembuf, nsops: usize) -> i32 {
        // SAFETY: semop(2); kernel reads nsops sembuf entries from [sops, ...)
        // in the caller's address space, faulting on a bad pointer rather than
        // corrupting libc state.
        ret_isize(unsafe { sys3(nr::SEMOP, semid as usize, sops as usize, nsops) }) as i32
    }

    // # C: int semtimedop(int semid, struct sembuf *sops, size_t nsops,
    //                      const struct timespec *timeout)
    #[no_mangle]
    pub unsafe extern "C" fn semtimedop(semid: i32, sops: *mut sembuf, nsops: usize, timeout: *const timespec) -> i32 {
        // SAFETY: semtimedop(2); kernel reads nsops sembuf entries and an
        // optional timespec from the caller's address space, faulting on bad
        // pointers rather than corrupting libc.
        ret_isize(unsafe { sys4(nr::SEMTIMEDOP, semid as usize, sops as usize, nsops, timeout as usize) }) as i32
    }

    // Wide-struct commands (semid64_ds / seminfo): glibc ORs IPC_64 only for
    // these so the kernel returns the wide layout. Value/array commands
    // (SETVAL/GETVAL/GETPID/GETNCNT/GETZCNT/GETALL/SETALL/IPC_RMID) pass the
    // bare cmd — the kernel EINVALs IPC_64 on those.
    fn needs_ipc64(cmd: i32) -> bool {
        matches!(cmd, super::IPC_STAT | super::IPC_SET | super::IPC_INFO
            | super::SEM_STAT | super::SEM_INFO | super::SEM_STAT_ANY)
    }

    // # C: int semctl(int semid, int semnum, int cmd, ... /* union semun arg */)
    #[no_mangle]
    pub unsafe extern "C" fn semctl(semid: i32, semnum: i32, cmd: i32, mut args: ...) -> i32 {
        // The kernel takes the union value (int for SETVAL, pointer for the
        // struct/array commands) as one word; value commands ignore it. Read
        // one usize-wide word and forward, ORing IPC_64 only for wide-struct
        // commands (glibc convention).
        // SAFETY: per the SysV C contract the union semun word is the 4th
        // vararg whenever a cmd needs it; reading one usize-wide word matches
        // glibc's __semctl, which forwards that same word (value or pointer)
        // as the raw 4th syscall argument without dereferencing it libc-side.
        ret_isize(unsafe {
            let raw: usize = args.next_arg::<usize>();
            let kcmd = if needs_ipc64(cmd) { cmd | IPC_64 } else { cmd };
            sys4(nr::SEMCTL, semid as usize, semnum as usize, kcmd as usize, raw)
        }) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sembuf_abi() { assert_eq!(core::mem::size_of::<sembuf>(), core::mem::size_of::<libc::sembuf>()); }
    #[test]
    fn ipc_consts() {
        assert_eq!(IPC_CREAT, libc::IPC_CREAT);
        assert_eq!(IPC_RMID, libc::IPC_RMID);
        assert_eq!(GETVAL, libc::GETVAL);
        assert_eq!(SETVAL, libc::SETVAL);
        assert_eq!(SEM_UNDO, libc::SEM_UNDO);
        assert_eq!(IPC_64, 0x100);
    }
}
