pub trait LockClass: 'static {
    /// Rank in the partial order; lower acquired first. Per `06§3.6`.
    /// # C: O(1)
    fn rank() -> u16;
    /// Class name for lockdep reports. `decl_lock_class!` supplies the real
    /// one; hand-written impls inherit this default rather than being forced to
    /// change, since `rank` alone already identifies the class uniquely.
    /// # C: O(1)
    fn name() -> &'static str { "<unnamed>" }
}

macro_rules! decl_lock_class {
    ($($name:ident = $rank:literal),+ $(,)?) => {
        $(
            pub struct $name;
            impl LockClass for $name {
                fn rank() -> u16 { $rank }
                fn name() -> &'static str { stringify!($name) }
            }
        )+
    };
}

decl_lock_class! {
    Buddy        =  0,
    // Huge-page pool counters and free list (`pmm::hugetlb`). Directly above
    // `Buddy` because a pool grow/shrink calls the buddy allocator, and below
    // everything else because a hugetlbfs inode holds its own lock while
    // charging the pool — the same nesting tmpfs already has over `Buddy`.
    // Never held ACROSS a buddy allocation: a resize computes its plan under
    // the lock, releases it, allocates, then re-takes it to commit.
    HugetlbPool  =  1,
    // Huge-page cgroup owner records (`pmm::hugetlb::charge`): which cgroup a
    // promised or handed-out huge page is charged to. Ranked directly above
    // `HugetlbPool` because a charge is always taken with the pool lock
    // RELEASED — the pool decides, drops its lock, then records the owner — so
    // the two are never held together in the other order.
    HugetlbCharge =  2,
    Timer        =  5,
    Slab         = 10,
    Reclaim      = 15,
    // Page-cache LRU + dirty-inode lists (`block::pagecache`), the reference's
    // per-node `lruvec->lru_lock` plus the flusher's dirty-inode list. Ranked
    // strictly BELOW `Inode` (40) because both reclaim and the flusher walk a
    // list entry and then take the owning mapping's lock to act on it —
    // ascending, and never the other way: a mapping never touches these lists
    // with its own lock held. Ranked above `Reclaim` (15) so PMM reclaim may
    // call the page-cache shrinker while holding its own reclaim state.
    PageCacheLru = 16,
    PageTable    = 20,
    AnonVma      = 25,
    // Per-page migration-token state.  Kept above i_mmap/rmap (25) and
    // below the address-space VMA tree (30); pageout never holds it while
    // taking a page-table lock or while sleeping.
    Migration    = 26,
    AddressSpace = 30,
    Inode        = 40,
    // Global blocked-record-lock graph (Linux `blocked_lock_lock` guarding
    // `blocked_hash`): the "owner X is parked on owner Y" edges
    // `posix_locks_deadlock` walks. Cross-inode by nature, so it cannot live
    // in the per-inode lock context. Taken AFTER an `Inode` (40) file-lock
    // context has been released — never nested inside one — and takes no
    // nested tracked lock itself, so it is a leaf just above `Inode`.
    FileLockBlocked = 45,
    Dentry       = 50,
    // Pseudo-fs (kernfs) directory-structure locks: held during VFS lookup/
    // readdir (under `Dentry`/`Inode`) and call `SuperBlock::iget` (the icache
    // lock at `Superblock`) to materialise child inodes. Ranked strictly
    // between `Dentry` (50) and `Superblock` (60) so a kernfs node lock may be
    // held WHILE acquiring the SB icache lock (ascending) — the rank window
    // that lets kernfs/procfs/sysfs/devfs route inode builds through `iget`.
    Kernfs       = 55,
    // [D28a] Mount-tree writer serialization (`vfs::mount::MOUNT_WRITE`): the
    // coarse outer lock every mount-tree MUTATOR takes around its multi-structure
    // mutation (MOUNTS + MOUNT_HASH + MOUNTPOINTS + NAMESPACES) so two concurrent
    // writers cannot interleave and leave those structures mutually inconsistent.
    // Ranked ABOVE `Dentry` (50) so the `d_invalidate`→`detach_mounts` path can
    // take it while holding a dentry lock, and BELOW `Superblock` (60) /
    // `MountTable` (70) — the mount-structure locks it is held ACROSS (strict
    // outermost-of-the-mount-locks). NEVER held across a sleeping descend
    // (`namei`/`inode.lookup`) or `put_super`; those run outside the region.
    MountWrite   = 58,
    // ext4 block/inode allocator bitmap serialization (Linux `ext4_lock_group`):
    // held across a group bitmap read-modify-write (read → find-free-bit → set →
    // write) so two concurrent allocations cannot pick the SAME free bit and
    // double-allocate one inode/block. Ranked just BELOW `Superblock` (60) — the
    // allocator takes the SB/state lock (60) for the GDT/counter update WHILE
    // holding this, so ascending order is `Ext4Alloc` (59) → `Superblock` (60).
    Ext4Alloc    = 59,
    Superblock   = 60,
    Modules      = 65,
    MountTable   = 70,
    Namespace    = 75,
    FdTable      = 80,
    SignalQueue  = 90,
    // Per-tid registry of open task-scoped perf events (`fs::perf::inherit`),
    // Linux's per-task `perf_event_context::event_list`. Snapshotted (Arcs
    // cloned out, lock dropped) BEFORE any per-event `PerfEvent::state`
    // (`TaskList`, 100) lock is taken, so the two are never held together;
    // ranked below `TaskList` purely to keep that ordering documented.
    PerfTaskEvents = 92,
    // One perf ring buffer's producer state (`fs::perf::ring`) — Linux's
    // `perf_buffer` head/nest/lost fields, which the reference protects with
    // preempt-off + local_cmpxchg rather than a lock. A strict LEAF: the
    // emit path samples the event under `PerfEvent::state` (`TaskList`, 100),
    // releases it, formats the record, and only then takes this. No tracked
    // lock is ever acquired while it is held.
    PerfRing     = 93,
    // Internal gate of a SLEEPING mutex (`sched::live::Mutex`). Held only to
    // decide "take it or enqueue", never across the sleep itself, and the
    // enqueue takes the wait list (`TaskList`, 100) while holding it — so it
    // must rank strictly below that.
    MutexGate    = 95,
    // Per-CPU workqueue ring (`sched::live::workqueue`). Taken irqsave — a
    // hard-IRQ handler queues work here, which is the primitive's purpose.
    Workqueue    = 96,
    // Gate around `kthread::park_if_requested`'s check-then-enqueue and
    // `kthread::unpark`/`stop`'s mutate-then-wake (B1427): same shape as
    // `MutexGate`. Held across the request check AND the `PARK_WAIT` enqueue
    // (which briefly takes `TaskList`, 100, ascending), dropped before
    // `schedule`. Ranked just below `TaskList` for the same reason as
    // `MutexGate`.
    KthreadPark  = 97,
    // Armed wait expiries (`sched::hrtimeout`) — Linux's per-CPU hrtimer base.
    // Taken irqsave: the hard timer IRQ sweeps it while process-context parks
    // insert. `WaitList::park_with_deadline` arms BEFORE pushing the waiter, so
    // it must rank below `TaskList`; it takes no nested tracked lock of its own
    // (the sweep drops it before `ttwu_deferred`), so a rank anywhere under
    // `TaskList` is sound and this one keeps the park path ascending.
    Hrtimeout    = 98,
    // Syscall tracepoint registration. Linux nests tracepoints_mutex outside
    // tasklist_lock while it stamps SYSCALL_WORK_SYSCALL_TRACEPOINT on every
    // live task. Tracefs mirrors that order: this setter-only lock (no hot-path
    // acquisition) may take TaskList while publishing the per-task work bit.
    Tracepoint   = 99,
    TaskList     = 100,
    // Scheduler's secondary task indices (`by_mm` / `by_tgid`). A task mm
    // replacement holds its TaskList pin while publishing membership, so this
    // sits immediately above TaskList; readers release it before pinning a
    // candidate task's mm.
    MmTaskIndex  = 101,
    // Native process scheduler configuration and its stable member set.
    // Process-wide priority changes retain this while walking one member at a
    // time through RtMutexWait -> TaskPi -> Runqueue.
    ThreadGroupSched = 103,
    // PI futex/rtmutex waiter tree. Held while taking the owner's TaskPi then
    // runqueue lock so top-donor selection and publication are one transaction.
    // Wakeups are queued and performed only after this lock is released.
    RtMutexWait  = 104,
    // Linux task_struct::pi_lock equivalent. It serializes a task's wake
    // state and affinity selection before the selected runqueue is acquired,
    // so it must rank below Runqueue (the ttwu lock order is task -> rq).
    TaskPi       = 105,
    Runqueue     = 110,
    // Throttled `SCHED_DEADLINE` entities awaiting replenishment
    // (`sched::deadline::replenish`). Taken irqsave: the hard timer IRQ sweeps
    // it while the throttle path — which runs with the runqueue (110) held —
    // inserts, hence the rank just ABOVE `Runqueue`. A leaf: the sweep collects
    // due entities under it and DROPS it before re-enqueueing them, so it is
    // never held while `Runqueue` is acquired.
    DlReplenish  = 111,
    // Serialises tty TRANSMISSION so two writers cannot interleave bytes now
    // that the emit happens after the port lock is released (`skizm.md` Step
    // 4e). Ranked just BELOW `Tty` because it is acquired first and held across
    // the port lock. Never taken by the RX ISR, so it stays a plain lock and
    // does not mask interrupts during the transmission — which is the point.
    TtyTx        = 119,
    Tty          = 120,
    SocketTable  = 130,
    // Stacked block-device state: the device-mapper type registry, mapped
    // devices and their table slots (`device_mapper`), and MD arrays and their
    // member sets (`md_raid`). Ranked strictly BELOW `Devices` because
    // publishing or withdrawing a stacked device takes the block registry's
    // lock while holding this one — a mapped device becomes a disk, so the
    // nesting only ever runs in that direction. A stacked device's I/O path
    // takes neither: it submits through an `Arc` it already holds.
    StackedBlock = 134,
    Devices      = 135,
    // Bluetooth controller registry: which controller each index names
    // (`bluetooth::hci::registry`). Above `Devices` because registration
    // publishes a device, and below `HciDev` because the registry lock is
    // taken first and dropped BEFORE a controller's own state is touched —
    // the two are never held together.
    HciRegistry  = 136,
    // One Bluetooth controller's own state: its flags, command queue and
    // connection table. Taken by the transport's receive path and by every
    // socket operation on that controller, never while the registry lock is
    // held.
    HciDev       = 137,
    Socket       = 140,
    // The cfg80211 radio list. Ranked ABOVE `Socket` because the network stack
    // enters a wireless interface's transmit path with its own lock held, so
    // every wireless lock is the inner one; the receive path drops its
    // wireless locks BEFORE handing a frame up, so the reverse order never
    // occurs. Strictly below `Wiphy`: registration and a name lookup both hold
    // the list while taking one radio's lock, and no path takes the list with
    // a radio's lock already held.
    WiphyList    = 141,
    // One radio's own state: its name, configuration, virtual interfaces,
    // regulatory domain and scan cache.
    Wiphy        = 142,
    // mac80211 per-station state: the station table and one station's
    // aggregation, key and power-save records. Taken with a `Wiphy` lock held.
    Sta80211     = 143,
    // Heap allocator leaf — independent of PMM/Slab, any subsystem may
    // call `KAlloc` with its own lock held; kalloc never calls back into
    // the kernel, so it's the final acquire in any chain.
    KMalloc      = 200,
    // debug-efence arena leaf (C213): consulted from inside `KAlloc::alloc`/
    // `dealloc` BEFORE the holes lock, so it may be taken while any caller
    // lock (≤200) is held. Its hot path takes NO nested tracked lock — all
    // frames are pre-mapped at init, and the RO/RW flip is a lock-free
    // same-PA permission rewrite on the shared kernel tables — so a leaf
    // rank above KMalloc is sound. Debug-only; never in a shipped build.
    Efence       = 205,
    // Guard-paged kernel-stack allocator slot free-list (C213). Held ONLY to
    // pick/return a slot index; frame alloc + page mapping happen OUTSIDE it
    // (like KMalloc releasing before the grow hook), so it takes no nested
    // tracked lock. Leaf rank above the task-creation locks (Runqueue/TaskList)
    // it is acquired under during spawn.
    KStack       = 206,
    // Connect-time ephemeral-port perturb table (`net::secure_seq::perturb`,
    // Linux `table_perturb`). Taken on the bind/connect path with socket and
    // socket-table locks (130/140) already held, and takes `Crng` (207) inside
    // to seed itself — so it ranks above the socket locks and below the CSPRNG
    // leaf. PROCESS CONTEXT ONLY: the softirq RX path must not take it, which
    // is why `net_secret` itself is lock-free atomics rather than living here.
    NetSecret    = 145,
    // Loaded mandatory-access-control policy, SID table, decision cache and
    // enforcement state (`selinux::SecurityServer`). Ranked above every
    // subsystem lock a check can be taken under — inode, dentry, mount, fd
    // table, task list, socket — because a permission check happens deep
    // inside those paths with their locks already held. Ranked below the
    // allocator leaves because resolving a new context allocates. The engine
    // under it takes no tracked lock of its own, so it is a leaf apart from
    // allocation.
    SecurityPolicy = 150,
    // Security-module framework: the resolved module order, the per-object
    // slot allocation and the hook lists (`lsm::registry`). Set once during
    // early boot and read afterwards. Ranked just below the policy lock
    // because a module is reached through the framework and only then takes
    // its own policy lock inside — never the other way round. Nothing
    // on a hot path takes it: a subsystem owning a hook list owns the lock
    // over that list, and this one covers the framework itself.
    LsmFramework = 149,
    // Kernel CSPRNG state (`crng::pool`). A strict LEAF: the ChaCha20 rekey and
    // output run entirely inside it and take no nested tracked lock, so any
    // consumer (getrandom, /dev/urandom, AT_RANDOM, uuid, socket cookies) may
    // call `crng::fill` with its own lock held.
    Crng         = 207,
}
