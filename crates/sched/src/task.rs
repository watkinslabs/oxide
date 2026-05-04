// Task / SchedClass / TaskState definitions for the runqueue. Mirrors
// the spec's `13§5` shape. `mm` is now real (P2-13a integrates with
// `vmm::AddressSpace` for per-task address spaces). The other Arc'd
// payloads (`fd_table`, `sig`, `creds`, `ns`, `cgroup`) land with
// their consumer subsystems.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU16, AtomicU64, AtomicU8, Ordering};

use vmm::AddressSpace;

use crate::ARCH_CTX_SIZE;

/// POSIX-style scheduling policy per `13§3`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedPolicy {
    /// `SCHED_OTHER` / `SCHED_BATCH` (Normal / CFS class).
    Normal,
    /// `SCHED_FIFO` (RT class) — runs until block.
    Fifo,
    /// `SCHED_RR` (RT class) — round-robin within priority.
    Rr,
    /// Per-CPU idle task; never user-set.
    Idle,
}

/// Class membership; mirrors the per-class data the runqueue needs to
/// pick. `13§3`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedClass {
    /// RT priority `1..=99` (higher = higher).
    Rt { prio: u8, policy: SchedPolicy },
    /// Normal-class weight from the Linux nice→weight table; vruntime
    /// is held in `Task::vruntime` so the CFS tree can re-key it on
    /// each insert.
    Normal { weight: u32 },
    /// Per-CPU idle.
    Idle,
}

/// Lifecycle state per `13§5`. Stored as `AtomicU8` for lock-free
/// transitions in `wake_up`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaskState {
    Runnable = 0,
    Sleeping = 1,
    Stopped  = 2,
    Zombie   = 3,
}

impl TaskState {
    /// # C: O(1)
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Runnable),
            1 => Some(Self::Sleeping),
            2 => Some(Self::Stopped),
            3 => Some(Self::Zombie),
            _ => None,
        }
    }
}

/// `13§5` task descriptor — runqueue-relevant fields only.
///
/// Allocation: heap-managed via `Arc<Task>` for v1; replaced by
/// slab-backed allocation per `12§3.2` once the integration lands. The
/// runqueue stores `Arc<Task>` clones and re-keys CFS by the current
/// `vruntime` snapshot on each insert.
///
/// `arch_ctx` is an opaque byte buffer sized to fit any per-arch HAL
/// `Context` record (per `14§4`); access goes through
/// `arch_ctx_ptr::<C>()` which compile-time-asserts the size fits.
/// Mutation discipline is the caller's: the kernel scheduler is the
/// only writer, only when this task is the active one on its CPU
/// (Context::switch saves prev's, loads next's). `unsafe impl Sync`
/// is sound under that single-mutator-per-active-CPU invariant.
pub struct Task {
    pub tid:  u32,
    pub name: &'static str,

    pub state:    AtomicU8,
    pub on_rq:    AtomicBool,
    pub cpu:      AtomicU16,
    pub vruntime: AtomicU64,
    pub class:    SchedClass,

    pub exit_status: AtomicI32,

    /// Top of this task's kernel stack (one past the last byte).
    /// Set when the task is constructed alongside its arch ctx.
    /// `null` until set; AtomicPtr so reads are race-free across
    /// concurrent CPU views (read-only on hot paths).
    pub kernel_stack: AtomicPtr<u8>,

    /// Backing storage for the kernel stack — allocated by the
    /// spawn path, freed when the `Arc<Task>` drops. `None` for
    /// tasks that don't own a stack (idle, boot frame, hosted tests
    /// constructing Tasks for runqueue logic only). The pointer
    /// in `kernel_stack` aliases `stack[stack.len()]` (one past
    /// the last byte = top-of-stack on x86_64 / aarch64).
    pub stack: Option<Box<[u8]>>,

    /// Opaque storage for the per-arch HAL `Context` (per `14§5.2`/
    /// `14§6.2`). Sized to `ARCH_CTX_SIZE`. Aligned on a u64 so the
    /// arch-specific Context's first field (an `rsp` / `sp`) sits
    /// at a natural-alignment offset. Caller (kernel) gates access
    /// with the runqueue invariant; see struct doc-comment.
    pub arch_ctx: UnsafeCell<ArchCtxBuf>,

    /// Per-task user address space per `13§5` / `11§3`. `None` for
    /// kernel-only threads (kthreads run in the kernel's static
    /// page tables). Shared via `Arc` per `clone3` semantics so
    /// `CLONE_VM` siblings share the same VMA tree (`13§5` field
    /// list). Schedule per `13§8`: switch_address_space called only
    /// when `next.mm != prev.mm`.
    ///
    /// Wrapped in `UnsafeCell` so `execve` (P2-21) can replace it
    /// in-place: the running task is the sole writer, and reads
    /// from `schedule()`'s AS-swap branch happen with preempt-off
    /// on the same CPU — single-mutator-per-active-CPU per `13§5`
    /// (same invariant the `arch_ctx` field relies on).
    pub mm: UnsafeCell<Option<Arc<AddressSpace>>>,
}

impl Task {
    /// Borrow `mm` (the `Arc<AddressSpace>` if set). Read-only;
    /// callers must observe the single-mutator invariant per the
    /// `mm` field doc.
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent execve runs against
    /// this task on another CPU.
    /// # C: O(1)
    pub unsafe fn mm_ref(&self) -> Option<&Arc<AddressSpace>> {
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern for shared interior mutability under documented external synchronization.
        unsafe { (&*self.mm.get()).as_ref() }
    }

    /// Atomically replace `mm` with `new`, dropping the old Arc.
    /// Used by `execve` per `15§5` and `Task::new_user_with_mm`.
    /// # SAFETY: caller is the running task on its CPU OR holds
    /// the runqueue invariant for this task; preempt-off; single-
    /// CPU UP. Not safe to call on an actively-scheduled task from
    /// another CPU.
    /// # C: O(1) + Arc drop
    pub unsafe fn replace_mm(&self, new: Option<Arc<AddressSpace>>) {
        // SAFETY: see fn-level contract; single-mutator on this CPU.
        unsafe { *self.mm.get() = new; }
    }
}

/// 8-byte-aligned byte buffer holding a per-arch HAL `Context`.
/// Per-arch Context types start with `rsp`/`sp` which are u64;
/// the explicit alignment keeps that field at offset 0 with
/// natural alignment regardless of the buffer placement.
#[repr(C, align(8))]
pub struct ArchCtxBuf(pub [u8; ARCH_CTX_SIZE]);

// SAFETY: `arch_ctx` mutation is gated by the kernel scheduler's
// runqueue invariant (only the CPU running this task writes the
// buffer, and only via `Context::switch` which is a single
// register-dance with no preempt window). Reads are likewise
// single-CPU per active-task invariant. AtomicPtr fields are
// inherently Sync.
unsafe impl Sync for Task {}

impl Task {
    /// Construct a new Runnable kernel-thread task (no `mm`). Tests
    /// use this; production allocation goes through
    /// `spawn_kernel_thread` once HAL `Context` is wired (`13§4`).
    /// # C: O(1)
    pub fn new(tid: u32, name: &'static str, class: SchedClass) -> Self {
        Self::new_with_mm(tid, name, class, None)
    }

    /// Construct a new Runnable user task with the given address
    /// space per `13§5`. Production user-task creation
    /// (clone3 / fork / execve) routes here.
    /// # C: O(1)
    pub fn new_user(
        tid: u32,
        name: &'static str,
        class: SchedClass,
        mm: Arc<AddressSpace>,
    ) -> Self {
        Self::new_with_mm(tid, name, class, Some(mm))
    }

    /// Internal constructor — both kthread and user paths funnel here.
    /// # C: O(1)
    fn new_with_mm(
        tid: u32,
        name: &'static str,
        class: SchedClass,
        mm: Option<Arc<AddressSpace>>,
    ) -> Self {
        Self {
            tid,
            name,
            state:    AtomicU8::new(TaskState::Runnable as u8),
            on_rq:    AtomicBool::new(false),
            cpu:      AtomicU16::new(u16::MAX),
            vruntime: AtomicU64::new(0),
            class,
            exit_status: AtomicI32::new(0),
            kernel_stack: AtomicPtr::new(core::ptr::null_mut()),
            arch_ctx: UnsafeCell::new(ArchCtxBuf([0u8; ARCH_CTX_SIZE])),
            mm: UnsafeCell::new(mm),
            stack: None,
        }
    }

    /// Attach a kernel stack to this task. Stores the top-of-stack
    /// (one past the last byte) in `kernel_stack` and takes
    /// ownership of the backing `Box<[u8]>` so it stays alive for
    /// the task's lifetime.
    /// # SAFETY: caller is the spawn path; this `Task` is not yet
    /// scheduled (no concurrent reader of `kernel_stack`).
    /// # C: O(1)
    pub unsafe fn install_stack(&mut self, stack: Box<[u8]>) {
        let len = stack.len();
        self.stack = Some(stack);
        // Recompute top from the freshly stored Box. Borrowing
        // through `as_mut()` is sound because we just took ownership.
        let s = self.stack.as_mut().expect("just-stored");
        // SAFETY: `s.as_mut_ptr().add(len)` is the one-past-the-last
        // byte ptr — well-defined provenance per std slice semantics.
        let top = unsafe { s.as_mut_ptr().add(len) };
        self.kernel_stack.store(top, Ordering::Release);
    }

    /// Cast the opaque arch-context buffer to `*mut C` for a
    /// per-arch HAL `Context` type. Compile-time-asserts that
    /// `size_of::<C>() <= ARCH_CTX_SIZE`. Caller's responsibility
    /// to honour the single-mutator-per-active-CPU invariant.
    /// # SAFETY: caller is the kernel scheduler holding the
    /// runqueue invariant for this task; the returned pointer
    /// aliases `self.arch_ctx`'s storage and must not outlive a
    /// pending `Context::switch` against this task.
    /// # C: O(1)
    pub unsafe fn arch_ctx_ptr<C: Sized>(&self) -> *mut C {
        const { assert!(core::mem::size_of::<C>() <= ARCH_CTX_SIZE,
            "Context size exceeds ARCH_CTX_SIZE; bump the constant in `crates/sched`"); }
        self.arch_ctx.get() as *mut C
    }

    /// # C: O(1)
    pub fn state(&self) -> TaskState {
        TaskState::from_u8(self.state.load(Ordering::Acquire))
            .expect("Task::state corrupt")
    }

    /// CAS state transition. Returns `Ok(())` on success, `Err(current)`
    /// if the observed state didn't match `from`.
    /// # C: O(1)
    pub fn cas_state(&self, from: TaskState, to: TaskState) -> Result<(), TaskState> {
        match self.state.compare_exchange(
            from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_)  => Ok(()),
            Err(v) => Err(TaskState::from_u8(v).expect("Task::cas_state corrupt")),
        }
    }

    /// # C: O(1)
    pub fn set_state(&self, s: TaskState) { self.state.store(s as u8, Ordering::Release); }

    /// Lift this task's vruntime to `floor` if it's currently below.
    /// Used when waking a long-sleeping CFS task into a moving RQ
    /// `min_vruntime` (`13§5` invariant 5).
    /// # C: O(1)
    pub fn lift_vruntime(&self, floor: u64) {
        let cur = self.vruntime.load(Ordering::Acquire);
        if cur < floor {
            self.vruntime.store(floor, Ordering::Release);
        }
    }
}
