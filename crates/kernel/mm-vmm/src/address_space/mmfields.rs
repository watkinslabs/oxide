// Linux `mm_struct` argv/env/stack/code/data/brk layout bounds +
// `prctl(PR_SET_MM, ...)` apply/validate logic. Split from
// `address_space.rs` per the 500-line cap.
//
// These bounds are the source `/proc/<pid>/{cmdline,environ,stat}`
// read from and the target `prctl(PR_SET_MM, opt, addr)` rewrites:
// systemd relabels its own argv block then calls PR_SET_MM_ARG_START/
// ARG_END so `/proc/self/cmdline` reflects the new title. The pointer
// setters and PR_SET_MM_MAP path validate exactly like Linux
// `kernel/sys.c` `prctl_set_mm` / `validate_prctl_map_addr`.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;
use hal::USER_VA_END;
use sync::{AddressSpace as AddressSpaceClass, Spinlock};

use super::AddressSpace;

// PR_SET_MM subcommand numbers (`uapi/linux/prctl.h`), passed as
// prctl arg2. 1..=11 are the single-field pointer setters; 12..=15
// are auxv / exe-file / whole-map / map-size.
pub const PR_SET_MM_START_CODE:  u64 = 1;
pub const PR_SET_MM_END_CODE:    u64 = 2;
pub const PR_SET_MM_START_DATA:  u64 = 3;
pub const PR_SET_MM_END_DATA:    u64 = 4;
pub const PR_SET_MM_START_STACK: u64 = 5;
pub const PR_SET_MM_START_BRK:   u64 = 6;
pub const PR_SET_MM_BRK:         u64 = 7;
pub const PR_SET_MM_ARG_START:   u64 = 8;
pub const PR_SET_MM_ARG_END:     u64 = 9;
pub const PR_SET_MM_ENV_START:   u64 = 10;
pub const PR_SET_MM_ENV_END:     u64 = 11;
pub const PR_SET_MM_AUXV:        u64 = 12;
pub const PR_SET_MM_EXE_FILE:    u64 = 13;
pub const PR_SET_MM_MAP:         u64 = 14;
pub const PR_SET_MM_MAP_SIZE:    u64 = 15;

/// Linux `struct prctl_mm_map` (`uapi/linux/prctl.h`). Passed by
/// PR_SET_MM_MAP as a user pointer of size `PR_SET_MM_MAP_SIZE`
/// (== `size_of::<PrctlMmMap>()` == 104). `#[repr(C)]` so the field
/// layout matches the userspace struct byte-for-byte.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct PrctlMmMap {
    pub start_code:  u64,
    pub end_code:    u64,
    pub start_data:  u64,
    pub end_data:    u64,
    pub start_brk:   u64,
    pub brk:         u64,
    pub start_stack: u64,
    pub arg_start:   u64,
    pub arg_end:     u64,
    pub env_start:   u64,
    pub env_end:     u64,
    /// `__u64 *auxv` — user pointer to the auxv blob (not deref'd here).
    pub auxv:        u64,
    pub auxv_size:   u32,
    pub exe_fd:      i32,
}

impl PrctlMmMap {
    /// Decode from the raw user bytes (little-endian). Returns `None`
    /// unless exactly `SIZE` bytes are supplied.
    /// # C: O(1)
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::SIZE { return None; }
        let rd = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().ok().unwrap_or([0; 8]));
        Some(Self {
            start_code:  rd(0),  end_code:  rd(8),
            start_data:  rd(16), end_data:  rd(24),
            start_brk:   rd(32), brk:       rd(40),
            start_stack: rd(48),
            arg_start:   rd(56), arg_end:   rd(64),
            env_start:   rd(72), env_end:   rd(80),
            auxv:        rd(88),
            auxv_size:   u32::from_le_bytes(b[96..100].try_into().ok().unwrap_or([0; 4])),
            exe_fd:      i32::from_le_bytes(b[100..104].try_into().ok().unwrap_or([0; 4])),
        })
    }

    /// Byte size of the userspace struct — the value PR_SET_MM_MAP_SIZE
    /// returns and the mandatory `arg4` for PR_SET_MM_MAP.
    pub const SIZE: usize = core::mem::size_of::<PrctlMmMap>();
}

/// Byte size of `struct prctl_mm_map` (Linux `PR_SET_MM_MAP_SIZE`).
/// # C: O(1)
pub fn prctl_mm_map_size() -> usize { PrctlMmMap::SIZE }

// Ordering helper: an all-zero pair is "unset" (loader didn't record
// it) and skips the check, else apply `<`/`<=` like Linux
// `__prctl_check_order`. Prevents a fresh mm (start_code==end_code==0)
// from EINVALing an unrelated PR_SET_MM_ARG_START.
fn ord_ok(a: u64, b: u64, strict: bool) -> bool {
    if a == 0 && b == 0 { return true; }
    if strict { a < b } else { a <= b }
}

/// Validate a `PrctlMmMap` the way Linux `validate_prctl_map_addr`
/// does: every layout address below the user/kernel split and the
/// ordering invariants (code/data strict, brk/arg/env non-strict).
/// # C: O(1)
pub fn validate_mm_map(m: &PrctlMmMap) -> bool {
    let addrs = [
        m.start_code, m.end_code, m.start_data, m.end_data,
        m.start_brk, m.brk, m.start_stack,
        m.arg_start, m.arg_end, m.env_start, m.env_end,
    ];
    for a in addrs { if a >= USER_VA_END { return false; } }
    ord_ok(m.start_code, m.end_code, true)
        && ord_ok(m.start_data, m.end_data, true)
        && ord_ok(m.start_brk, m.brk, false)
        && ord_ok(m.arg_start, m.arg_end, false)
        && ord_ok(m.env_start, m.env_end, false)
}

/// Owns the eleven `mm_struct` layout bounds + the saved auxv blob.
/// A single AS field so `AddressSpace::{new,fork,*}` construct/copy it
/// in one line each rather than threading eleven atomics. `brk` proper
/// stays on `AddressSpace` (the `sys_brk` cursor); this holds the
/// `start_brk` low-water only.
pub(super) struct MmLayout {
    arg_start:   AtomicU64,
    arg_end:     AtomicU64,
    env_start:   AtomicU64,
    env_end:     AtomicU64,
    start_code:  AtomicU64,
    end_code:    AtomicU64,
    start_data:  AtomicU64,
    end_data:    AtomicU64,
    start_stack: AtomicU64,
    start_brk:   AtomicU64,
    /// Linux `mm_struct::saved_auxv` — the raw auxv blob PR_SET_MM_AUXV
    /// / PR_SET_MM_MAP installed (bounded ≤ one page). None until set.
    auxv:        Spinlock<Option<Vec<u8>>, AddressSpaceClass>,
    /// Set once `prctl(PR_SET_MM)` has explicitly rewritten a layout
    /// field (systemd relabelling its cmdline). Gates the `/proc/<pid>/
    /// {cmdline,environ}` foreign-region read: at exec baseline this is
    /// 0 so those files keep using the correct-order `task.cmdline`
    /// snapshot (our exec stack builder lays argv[0] at the HIGH end of
    /// the block — reverse of Linux — so a baseline raw-region read
    /// would show args reversed). 0 = not user-set, 1 = user-set.
    user_set:    AtomicU64,
    /// Load address of this mm's vDSO ELF header. The signal path uses the
    /// mapped image's `__kernel_rt_sigreturn` symbol when an AArch64 handler
    /// has no SA_RESTORER trampoline, exactly as Linux does.
    vdso_ehdr:   AtomicU64,
}

impl MmLayout {
    pub(super) fn new() -> Self {
        Self {
            arg_start:   AtomicU64::new(0), arg_end:   AtomicU64::new(0),
            env_start:   AtomicU64::new(0), env_end:   AtomicU64::new(0),
            start_code:  AtomicU64::new(0), end_code:  AtomicU64::new(0),
            start_data:  AtomicU64::new(0), end_data:  AtomicU64::new(0),
            start_stack: AtomicU64::new(0), start_brk: AtomicU64::new(0),
            auxv:        Spinlock::new(None),
            user_set:    AtomicU64::new(0),
            vdso_ehdr:   AtomicU64::new(0),
        }
    }

    /// Fork copy: mirror every bound + the auxv blob into the child mm
    /// (Linux `dup_mm` copies the layout wholesale).
    pub(super) fn forked(src: &Self) -> Self {
        let g = |a: &AtomicU64| AtomicU64::new(a.load(Ordering::Acquire));
        Self {
            arg_start:   g(&src.arg_start), arg_end:   g(&src.arg_end),
            env_start:   g(&src.env_start), env_end:   g(&src.env_end),
            start_code:  g(&src.start_code), end_code: g(&src.end_code),
            start_data:  g(&src.start_data), end_data: g(&src.end_data),
            start_stack: g(&src.start_stack), start_brk: g(&src.start_brk),
            auxv:        Spinlock::new(src.auxv.lock().clone()),
            user_set:    g(&src.user_set),
            vdso_ehdr:   g(&src.vdso_ehdr),
        }
    }
}

impl AddressSpace {
    // --- getters (Linux `mm_struct` field reads) ---
    /// # C: O(1)
    pub fn arg_start(&self)   -> u64 { self.mm_layout.arg_start.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn arg_end(&self)     -> u64 { self.mm_layout.arg_end.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn env_start(&self)   -> u64 { self.mm_layout.env_start.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn env_end(&self)     -> u64 { self.mm_layout.env_end.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn start_code(&self)  -> u64 { self.mm_layout.start_code.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn end_code(&self)    -> u64 { self.mm_layout.end_code.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn start_data(&self)  -> u64 { self.mm_layout.start_data.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn end_data(&self)    -> u64 { self.mm_layout.end_data.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn start_stack(&self) -> u64 { self.mm_layout.start_stack.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn start_brk(&self)   -> u64 { self.mm_layout.start_brk.load(Ordering::Acquire) }
    /// Snapshot of the saved auxv blob (None until PR_SET_MM_AUXV/MAP).
    /// # C: O(len) clone
    pub fn auxv(&self) -> Option<Vec<u8>> { self.mm_layout.auxv.lock().clone() }
    /// vDSO ELF header address for this mm, or zero before exec mapping.
    /// # C: O(1)
    pub fn vdso_ehdr(&self) -> u64 { self.mm_layout.vdso_ehdr.load(Ordering::Acquire) }

    /// True once `prctl(PR_SET_MM)` explicitly rewrote a layout field.
    /// `/proc/<pid>/{cmdline,environ}` foreign-read the arg/env region
    /// only then; at exec baseline they use the correct-order snapshot.
    /// # C: O(1)
    pub fn mm_user_set(&self) -> bool { self.mm_layout.user_set.load(Ordering::Acquire) != 0 }

    /// Mark the mm layout as user-rewritten (called by the PR_SET_MM
    /// apply paths on success).
    /// # C: O(1)
    pub fn mark_mm_user_set(&self) { self.mm_layout.user_set.store(1, Ordering::Release); }

    // --- execve-time setters (called once by the loader) ---
    /// Record the argv/env string-block bounds + initial user rsp built
    /// on the exec stack (Linux `setup_arg_pages` / `create_elf_tables`).
    /// # C: O(1)
    pub fn set_arg_env_stack(&self, arg_start: u64, arg_end: u64, env_start: u64, env_end: u64, start_stack: u64) {
        self.mm_layout.arg_start.store(arg_start, Ordering::Release);
        self.mm_layout.arg_end.store(arg_end, Ordering::Release);
        self.mm_layout.env_start.store(env_start, Ordering::Release);
        self.mm_layout.env_end.store(env_end, Ordering::Release);
        self.mm_layout.start_stack.store(start_stack, Ordering::Release);
    }

    /// Record the code/data segment bounds from the ELF PT_LOADs
    /// (Linux `mm->start_code`..`end_data`). `start_code`/`end_code`
    /// = first executable segment; `start_data`/`end_data` = first
    /// writable segment (0 if the image has none of a kind).
    /// # C: O(1)
    pub fn set_code_data(&self, start_code: u64, end_code: u64, start_data: u64, end_data: u64) {
        self.mm_layout.start_code.store(start_code, Ordering::Release);
        self.mm_layout.end_code.store(end_code, Ordering::Release);
        self.mm_layout.start_data.store(start_data, Ordering::Release);
        self.mm_layout.end_data.store(end_data, Ordering::Release);
    }

    /// Record the initial brk low-water (Linux `mm->start_brk`), == the
    /// page-rounded end of the last PT_LOAD.
    /// # C: O(1)
    pub fn set_start_brk(&self, v: u64) { self.mm_layout.start_brk.store(v, Ordering::Release); }

    /// Install a saved auxv blob (PR_SET_MM_AUXV / PR_SET_MM_MAP).
    /// # C: O(len) move
    pub fn set_auxv(&self, blob: Vec<u8>) { *self.mm_layout.auxv.lock() = Some(blob); }

    /// Record the vDSO ELF header address installed during exec.
    /// # C: O(1)
    pub fn set_vdso_ehdr(&self, addr: u64) { self.mm_layout.vdso_ehdr.store(addr, Ordering::Release); }

    // --- prctl(PR_SET_MM) apply paths ---
    /// Snapshot the current layout into a `PrctlMmMap` (auxv ptr /
    /// exe_fd left 0 — those aren't addresses). `brk` reads the live
    /// `sys_brk` cursor.
    /// # C: O(1)
    pub fn snapshot_mm_map(&self) -> PrctlMmMap {
        PrctlMmMap {
            start_code:  self.start_code(), end_code:  self.end_code(),
            start_data:  self.start_data(), end_data:  self.end_data(),
            start_brk:   self.start_brk(),  brk:       self.brk(),
            start_stack: self.start_stack(),
            arg_start:   self.arg_start(),  arg_end:   self.arg_end(),
            env_start:   self.env_start(),  env_end:   self.env_end(),
            auxv: 0, auxv_size: 0, exe_fd: 0,
        }
    }

    /// PR_SET_MM single-field setter (opt 1..=11). Snapshots the map,
    /// applies the one field, validates the whole map like Linux, and
    /// commits atomically on success. `Err(())` == EINVAL.
    /// # C: O(1)
    pub fn prctl_set_field(&self, opt: u64, addr: u64) -> Result<(), ()> {
        if addr >= USER_VA_END { return Err(()); }
        let mut m = self.snapshot_mm_map();
        match opt {
            PR_SET_MM_START_CODE  => m.start_code  = addr,
            PR_SET_MM_END_CODE    => m.end_code    = addr,
            PR_SET_MM_START_DATA  => m.start_data  = addr,
            PR_SET_MM_END_DATA    => m.end_data    = addr,
            PR_SET_MM_START_STACK => m.start_stack = addr,
            PR_SET_MM_START_BRK   => m.start_brk   = addr,
            PR_SET_MM_BRK         => m.brk         = addr,
            PR_SET_MM_ARG_START   => m.arg_start   = addr,
            PR_SET_MM_ARG_END     => m.arg_end     = addr,
            PR_SET_MM_ENV_START   => m.env_start   = addr,
            PR_SET_MM_ENV_END     => m.env_end     = addr,
            _ => return Err(()),
        }
        self.apply_prctl_mm_map(&m)
    }

    /// Validate a full `PrctlMmMap` and, on success, commit all eleven
    /// layout addresses (incl. the `brk` cursor). The auxv blob + exe
    /// file are applied by the caller (they need user-memory / fd
    /// access). `Err(())` == EINVAL, nothing committed.
    /// # C: O(1)
    pub fn apply_prctl_mm_map(&self, m: &PrctlMmMap) -> Result<(), ()> {
        if !validate_mm_map(m) { return Err(()); }
        self.set_code_data(m.start_code, m.end_code, m.start_data, m.end_data);
        self.set_start_brk(m.start_brk);
        self.set_arg_env_stack(m.arg_start, m.arg_end, m.env_start, m.env_end, m.start_stack);
        // Commit the brk cursor itself (child module: private `brk` field
        // of AddressSpace is in scope). PR_SET_MM_BRK moves it wholesale
        // (CAP_SYS_RESOURCE already checked at the syscall boundary), so we
        // bypass the `sys_brk` window clamp deliberately.
        self.brk.store(m.brk, Ordering::Release);
        self.mark_mm_user_set();
        Ok(())
    }
}
