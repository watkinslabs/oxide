// Hosted tests for syscall dispatch + UserPtr. Numbered to mirror the
// spec sections they cover.

extern crate alloc;
use super::*;
use crate::dispatch::{
    dispatch, handler_for, is_enosys, sys_enosys, SyscallArgs, SyscallFn,
    SYSCALL_TABLE_LEN,
};
use crate::errno::{Errno, KResult};
use crate::userptr::{UserPtr, UserSlice};

use hal::USER_VA_END;

// ---------------------------------------------------------------------------
// Dispatch table (`15§4`)
// ---------------------------------------------------------------------------

#[test]
fn table_size_matches_spec() {
    // `15§4`: 462-entry table.
    assert_eq!(SYSCALL_TABLE_LEN, 462);
}

#[test]
fn unbound_slots_default_to_enosys() {
    // Slots that have a real handler bound — keep this list in sync
    // with `dispatch::build_table()`.
    const BOUND: &[u32] = &[
        1,    // sys_write
        3,    // sys_close
        9,    // sys_mmap (-ENOMEM stub)
        10,   // sys_mprotect (no-op)
        11,   // sys_munmap (no-op)
        12,   // sys_brk (returns 0)
        13,   // sys_rt_sigaction (no-op)
        14,   // sys_rt_sigprocmask (no-op)
        16,   // sys_ioctl (-ENOTTY)
        20,   // sys_writev
        28,   // sys_madvise (no-op)
        39,   // sys_getpid
        60,   // sys_exit
        72,   // sys_fcntl (returns 0)
        89,   // sys_readlink (-EINVAL)
        102,  // sys_getuid
        104,  // sys_getgid
        107,  // sys_geteuid
        108,  // sys_getegid
        186,  // sys_gettid
        218,  // sys_set_tid_address
        273,  // sys_set_robust_list
        302,  // sys_prlimit64
        318,  // sys_getrandom (-ENOSYS — explicit not silent)
    ];
    for nr in 0..(SYSCALL_TABLE_LEN as u32) {
        if BOUND.contains(&nr) { continue; }
        assert!(
            is_enosys(nr),
            "slot {nr} unexpectedly bound — update BOUND list above"
        );
    }
}

#[test]
fn bound_slots_are_not_enosys() {
    // sys_getrandom returns Enosys but the slot is bound (the
    // is_enosys helper compares fn-pointers so a stub returning
    // Err(Enosys) passes !is_enosys; skip 318 here for clarity).
    for nr in [1, 3, 9, 10, 11, 12, 13, 14, 16, 20, 28, 39, 60, 72, 89, 102, 104, 107, 108, 186, 218, 273, 302] {
        assert!(!is_enosys(nr), "slot {nr} must be bound");
    }
}

#[test]
fn trivial_const_syscalls_return_expected_values() {
    let args = SyscallArgs::default();
    assert_eq!(dispatch(39,  &args), 1, "getpid → 1 (single-task v1)");
    assert_eq!(dispatch(186, &args), 1, "gettid → 1 (single-thread v1)");
    assert_eq!(dispatch(102, &args), 0, "getuid  → 0 (root)");
    assert_eq!(dispatch(104, &args), 0, "getgid  → 0");
    assert_eq!(dispatch(107, &args), 0, "geteuid → 0");
    assert_eq!(dispatch(108, &args), 0, "getegid → 0");
}

#[test]
fn dispatch_unknown_number_returns_enosys() {
    let args = SyscallArgs::default();
    let rv = dispatch(7777, &args);
    assert_eq!(rv, -(Errno::Enosys.as_i32() as i64));
}

#[test]
fn dispatch_in_range_unimplemented_returns_enosys() {
    let args = SyscallArgs::default();
    let rv = dispatch(0, &args);
    assert_eq!(rv, -(Errno::Enosys.as_i32() as i64));
}

#[test]
fn error_encoding_matches_spec_negative_errno() {
    // `15§1.3`: error returns are in `-errno` range; libc's
    // `rv > -4096UL` check distinguishes success from error.
    let args = SyscallArgs::default();
    let rv = dispatch(0, &args) as u64;
    let four_kib_mask: u64 = -4096i64 as u64;
    assert!(rv > four_kib_mask, "errno encoding {rv:#x} not in `-errno` range");
}

#[test]
fn dispatch_success_returns_positive_value() {
    fn ok_fn(_: &SyscallArgs) -> KResult<u64> { Ok(42) }
    let f: SyscallFn = ok_fn;
    let v = match f(&SyscallArgs::default()) {
        Ok(v)  => v as i64,
        Err(e) => -(e.as_i32() as i64),
    };
    assert_eq!(v, 42);
}

#[test]
fn handler_for_default_is_sys_enosys() {
    assert_eq!(
        handler_for(123) as usize,
        sys_enosys as SyscallFn as usize,
    );
}

// ---------------------------------------------------------------------------
// UserPtr<T> (`15§1.4`)
// ---------------------------------------------------------------------------

#[test]
fn user_ptr_accepts_valid_user_va() {
    let p = UserPtr::<u64>::new(0x1000).unwrap();
    assert_eq!(p.as_u64(), 0x1000);
}

#[test]
fn user_ptr_rejects_unaligned() {
    assert_eq!(UserPtr::<u64>::new(0x1001), Err(Errno::Efault));
    assert_eq!(UserPtr::<u32>::new(0x1003), Err(Errno::Efault));
    // u8 has align 1 ⇒ any addr accepted.
    UserPtr::<u8>::new(0x1003).unwrap();
}

#[test]
fn user_ptr_rejects_at_or_above_user_va_end() {
    assert_eq!(UserPtr::<u64>::new(USER_VA_END), Err(Errno::Efault));
    // Last 8 bytes straddle the boundary if `addr + size_of` exceeds.
    assert_eq!(UserPtr::<u64>::new(USER_VA_END - 4), Err(Errno::Efault));
}

#[test]
fn user_ptr_accepts_last_aligned_slot() {
    // `addr + size_of::<u64>() == USER_VA_END` is the boundary case.
    // The address itself must be `< USER_VA_END` per `01§1`.
    let last = USER_VA_END - 8;
    UserPtr::<u64>::new(last).unwrap();
}

// ---------------------------------------------------------------------------
// UserSlice<T> (`15§1.4`)
// ---------------------------------------------------------------------------

#[test]
fn user_slice_zero_len_is_always_ok() {
    UserSlice::<u8>::new(0, 0).unwrap();
    UserSlice::<u32>::new(0xdead_beef, 0).unwrap(); // odd alignment OK when len=0
}

#[test]
fn user_slice_rejects_overflow() {
    assert_eq!(
        UserSlice::<u64>::new(USER_VA_END - 16, 1024),
        Err(Errno::Efault),
    );
    assert_eq!(
        UserSlice::<u8>::new(u64::MAX - 8, 16),
        Err(Errno::Efault),
    );
}

#[test]
fn user_slice_accepts_within_bounds() {
    let s = UserSlice::<u64>::new(0x1000, 16).unwrap();
    assert_eq!(s.len(), 16);
    assert_eq!(s.len_bytes(), 128);
    assert!(!s.is_empty());
}

#[test]
fn user_slice_rejects_unaligned_for_aligned_T() {
    assert_eq!(
        UserSlice::<u64>::new(0x1001, 4),
        Err(Errno::Efault),
    );
}

// ---------------------------------------------------------------------------
// Errno
// ---------------------------------------------------------------------------

#[test]
fn errno_values_match_linux_x86_64() {
    assert_eq!(Errno::Eperm.as_i32(),  1);
    assert_eq!(Errno::Enoent.as_i32(), 2);
    assert_eq!(Errno::Eio.as_i32(),    5);
    assert_eq!(Errno::Enomem.as_i32(), 12);
    assert_eq!(Errno::Efault.as_i32(), 14);
    assert_eq!(Errno::Einval.as_i32(), 22);
    assert_eq!(Errno::Enosys.as_i32(), 38);
}
