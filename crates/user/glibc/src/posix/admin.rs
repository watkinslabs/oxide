// Linux admin / privileged syscall wrappers (docs/59§6 — G19 audit): capabilities,
// kernel-module load/unload, file handles, personality, quota, reboot, fs-uid/gid,
// SysV message queues, sigqueue. Thin wrappers; kernel structs pass as pointers.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys2, sys3, sys4, sys5};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: int capget(cap_user_header_t hdrp, cap_user_data_t datap)
#[no_mangle]
pub unsafe extern "C" fn capget(hdrp: *mut c_void, datap: *mut c_void) -> i32 {
    // SAFETY: hdrp/datap are the caller's cap_user_header/data structs the
    // kernel reads the version+pid from and writes the cap sets into.
    ret_isize(unsafe { sys2(nr::CAPGET, hdrp as usize, datap as usize) }) as i32
}
// # C: int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
#[no_mangle]
pub unsafe extern "C" fn capset(hdrp: *mut c_void, datap: *const c_void) -> i32 {
    // SAFETY: hdrp/datap are valid cap_user structs the kernel reads.
    ret_isize(unsafe { sys2(nr::CAPSET, hdrp as usize, datap as usize) }) as i32
}

// # C: int init_module(void *image, unsigned long len, const char *params)
#[no_mangle]
pub unsafe extern "C" fn init_module(image: *mut c_void, len: u64, params: *const c_char) -> i32 {
    // SAFETY: image points to len bytes of module ELF; params a NUL string.
    ret_isize(unsafe { sys3(nr::INIT_MODULE, image as usize, len as usize, params as usize) }) as i32
}
// # C: int delete_module(const char *name, int flags)
#[no_mangle]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: i32) -> i32 {
    // SAFETY: name is a NUL-terminated module name the kernel reads.
    ret_isize(unsafe { sys2(nr::DELETE_MODULE, name as usize, flags as usize) }) as i32
}

// # C: int name_to_handle_at(int dfd, const char *path, struct file_handle *h,
//                            int *mount_id, int flags)
#[no_mangle]
pub unsafe extern "C" fn name_to_handle_at(dfd: i32, path: *const c_char, handle: *mut c_void, mount_id: *mut i32, flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; handle a file_handle buffer (handle_bytes
    // pre-set) the kernel fills; mount_id an out int. All on the caller's frame.
    ret_isize(unsafe { sys5(nr::NAME_TO_HANDLE_AT, dfd as usize, path as usize, handle as usize, mount_id as usize, flags as usize) }) as i32
}
// # C: int open_by_handle_at(int mount_fd, struct file_handle *h, int flags)
#[no_mangle]
pub unsafe extern "C" fn open_by_handle_at(mount_fd: i32, handle: *mut c_void, flags: i32) -> i32 {
    // SAFETY: handle is a file_handle the kernel reads to resolve the fd.
    ret_isize(unsafe { sys3(nr::OPEN_BY_HANDLE_AT, mount_fd as usize, handle as usize, flags as usize) }) as i32
}

// # C: int personality(unsigned long persona)
#[no_mangle]
pub unsafe extern "C" fn personality(persona: u64) -> i32 {
    // SAFETY: personality(2) takes a scalar; returns the prior persona or -1.
    ret_isize(unsafe { sys2(nr::PERSONALITY, persona as usize, 0) }) as i32
}

// # C: int quotactl(int cmd, const char *special, int id, caddr_t addr)
#[no_mangle]
pub unsafe extern "C" fn quotactl(cmd: i32, special: *const c_char, id: i32, addr: *mut c_void) -> i32 {
    // SAFETY: special is null or a NUL block-device path; addr a cmd-specific
    // struct the kernel reads/writes (dqblk, dqinfo, …).
    ret_isize(unsafe { sys4(nr::QUOTACTL, cmd as usize, special as usize, id as usize, addr as usize) }) as i32
}

// # C: int reboot(int howto)
// glibc's one-arg wrapper over the 4-arg reboot(2): magic1/magic2 + cmd.
#[no_mangle]
pub unsafe extern "C" fn reboot(howto: i32) -> i32 {
    const MAGIC1: usize = 0xfee1dead;
    const MAGIC2: usize = 672274793; // LINUX_REBOOT_MAGIC2
    // SAFETY: reboot(2) with the fixed magics; arg ptr NULL (no cmd needs it here).
    ret_isize(unsafe { sys4(nr::REBOOT, MAGIC1, MAGIC2, howto as usize, 0) }) as i32
}

// # C: uid_t setfsuid(uid_t fsuid) — returns the PRIOR fsuid (never fails).
#[no_mangle]
pub unsafe extern "C" fn setfsuid(fsuid: u32) -> i32 {
    // SAFETY: setfsuid(2) takes a scalar uid and returns the previous value.
    unsafe { sys2(nr::SETFSUID, fsuid as usize, 0) as i32 }
}
// # C: gid_t setfsgid(gid_t fsgid) — returns the PRIOR fsgid.
#[no_mangle]
pub unsafe extern "C" fn setfsgid(fsgid: u32) -> i32 {
    // SAFETY: setfsgid(2) takes a scalar gid and returns the previous value.
    unsafe { sys2(nr::SETFSGID, fsgid as usize, 0) as i32 }
}

// --- SysV message queues ------------------------------------------------
// # C: int msgget(key_t key, int msgflg)
#[no_mangle]
pub unsafe extern "C" fn msgget(key: i32, msgflg: i32) -> i32 {
    // SAFETY: msgget(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys2(nr::MSGGET, key as usize, msgflg as usize) }) as i32
}
// # C: int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
#[no_mangle]
pub unsafe extern "C" fn msgsnd(msqid: i32, msgp: *const c_void, msgsz: usize, msgflg: i32) -> i32 {
    // SAFETY: msgp points to a `struct msgbuf` of mtype+msgsz bytes the kernel reads.
    ret_isize(unsafe { sys4(nr::MSGSND, msqid as usize, msgp as usize, msgsz, msgflg as usize) }) as i32
}
// # C: ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
#[no_mangle]
pub unsafe extern "C" fn msgrcv(msqid: i32, msgp: *mut c_void, msgsz: usize, msgtyp: i64, msgflg: i32) -> isize {
    // SAFETY: msgp is a msgbuf buffer the kernel writes the received message into.
    ret_isize(unsafe { sys5(nr::MSGRCV, msqid as usize, msgp as usize, msgsz, msgtyp as usize, msgflg as usize) })
}
// # C: int msgctl(int msqid, int cmd, struct msqid_ds *buf)
#[no_mangle]
pub unsafe extern "C" fn msgctl(msqid: i32, cmd: i32, buf: *mut c_void) -> i32 {
    // SAFETY: buf is null or a struct msqid_ds the kernel reads/writes.
    ret_isize(unsafe { sys3(nr::MSGCTL, msqid as usize, cmd as usize, buf as usize) }) as i32
}

// # C: int sigqueue(pid_t pid, int sig, const union sigval value)
// glibc builds a SI_QUEUE siginfo and calls rt_sigqueueinfo(pid, sig, &info).
#[no_mangle]
pub unsafe extern "C" fn sigqueue(pid: i32, sig: i32, value: usize) -> i32 {
    const SI_QUEUE: i32 = -1;
    // SAFETY: a 128-byte siginfo_t scratch on this frame; we fill the kernel
    // _rt layout (signo@0, code@8, pid@16, uid@20, sigval@24) then pass it to
    // rt_sigqueueinfo. getpid/getuid identify the sender per POSIX.
    unsafe {
        let mut info = [0u8; 128];
        let p = info.as_mut_ptr();
        *(p.add(0) as *mut i32) = sig;
        *(p.add(8) as *mut i32) = SI_QUEUE;
        *(p.add(16) as *mut i32) = crate::posix::io::getpid();
        *(p.add(20) as *mut u32) = crate::posix::ids::getuid();
        *(p.add(24) as *mut usize) = value;
        ret_isize(sys3(nr::RT_SIGQUEUEINFO, pid as usize, sig as usize, p as usize)) as i32
    }
}
