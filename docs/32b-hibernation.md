# 32b Hibernation

FROZEN 2026-08-21. Dep:`01`,`02`,`06`,`10`,`13`,`15`,`16`,`17`,`20`,`21`,`23`,`29`,`32`,`32a`,`35`,`36`,`52`,`54`. Provides:suspend-to-disk, `/sys/power/disk`, cold-boot image resume.

## 1 Purpose

Hibernation saves the running kernel's physical-memory image to persistent
storage, powers the machine off, and restores that exact execution from a cold
boot. Unlike `32a`, RAM is not assumed to survive. The successful restore
returns through the original hibernating kernel's saved continuation; it does
not continue in the temporary restore kernel.

## 2 Inputs, outputs, and dependencies

Inputs are the normalized boot memory topology, PMM allocation truth, the
freezer and device/core callbacks from `32a`, a selected swap device or
swapfile, architecture CPU state, and the boot options `resume=`,
`resume_offset=`, `noresume`, and `nohibernate`.

Outputs are a durable image, a terminal shutdown, or a restored kernel. The
public entry points are `disk` in `/sys/power/state`,
`LINUX_REBOOT_CMD_SW_SUSPEND`, and the attributes in `§10`. All public entry
points call the same hibernation transaction.

## 3 Frozen invariants

1. There is one system-transition claim shared by suspend, hibernate, resume,
   reboot, and kexec-preserve-context. Two transitions never overlap.
2. PMM remains the sole truth for free, allocated, reserved, and PCP-held
   frames. Hibernation takes an immutable snapshot from that owner; it keeps no
   parallel live-page registry and does not infer allocation from PageMeta
   reference counts.
3. The normalized boot memory topology is retained once. PMM seeding, image
   saveability, restore compatibility, kexec, and crash-kernel views are
   derived from it; filtered copies are not published as independent truth.
4. One `Snapshot` owns the original-PFN bitmap, copy pages, zero bitmap,
   metadata pages, and collision restore plan. Stream cursors borrow it and
   never own a second page list.
5. Snapshot storage, restore metadata, temporary page tables, stack, and
   relocation code are disjoint from every image destination. Every temporary
   frame remains claimed until the sole restore/snapshot owner drops it.
6. Image payload and map blocks become durable before the valid-image marker.
   The marker is the last durable write. A failed write leaves no valid marker
   and releases every image slot.
7. Resume consumes the marker durably before overwriting any destination. A
   boot never proceeds with both a valid persistent image and a restored live
   copy of it.
8. The restore kernel validates build identity, architecture, page size,
   physical topology, CPU/SMP contract, image counts, map bounds, and checksum
   before quiescing devices or writing a destination.
9. Direct loading into an original PFN is allowed only after PMM atomically
   claims that exact free PFN. A busy target loads into a safe frame and enters
   the collision plan; there is no overwrite-then-repair path.
10. The final architecture restore allocates nothing, takes no lock, uses no
    overwritten stack, and reads no nonlocal object that may itself be a
    destination. It runs from safe executable storage and temporary mappings.
11. Successful restore returns only through the saved continuation, with the
    restored-side discriminator set. Returning from the architecture restore
    entry is failure.
12. A raw block resume target is usable without mounting a filesystem.
    Swapfile resume additionally persists the underlying device identity,
    header offset, and physical extent mapping; logical file offsets are never
    mistaken for raw device offsets.
13. Both x86_64 and aarch64 reach the same public milestone. The kernel does
    not advertise `disk` on an architecture lacking a complete restore path.
14. Hibernation shutdown mode requires no ACPI S4 or PSCI system-suspend
    support. Platform mode is advertised only when platform hibernation ops
    exist.

## 4 Public interface

`power::hibernate()` is the single write-side transaction. It returns an error
before the terminal boundary, or returns success only after a restored image
continues. `power::software_resume()` is the cold-boot reader and either
returns “no usable image”/an error without corrupting the fresh boot, or never
returns because architecture restore transfers control to the saved kernel.

The reboot classifier maps `LINUX_REBOOT_CMD_SW_SUSPEND` to the same
`power::hibernate()` call used by a `disk` write to `/sys/power/state`.
PID-namespace reboot continues to reject it.

## 5 Ownership and data model

`crates/kernel/power` owns the transaction, sequence, snapshot view, image
format, sysfs policy, and unwind. It borrows the existing `32a` freezer,
device-PM, CPU, IRQ, and syscore owners.

`crates/kernel/mm-pmm` owns normalized topology, free-frame snapshotting,
PCP drain, exact-PFN claims, and hibernation copy/safe frames. An exact claim
is reversible and fails when the PFN is not currently free.

The canonical swap area owns image-slot reservation. A hibernation lease pins
one area, makes normal pageout skip its reserved slots, blocks swapoff, and
releases every uncommitted slot on drop. Power stores only opaque persistent
locators returned by that lease.

The block layer owns the resume device lifetime and I/O. A resume token is an
exclusive RAII claim over one canonical device/partition identity.

Each HAL owns its saved continuation, architecture header, temporary mappings,
cache/TLB sequencing, and stackless copy trampoline. Generic power code owns
the destination/collision list passed to it. `hal::pt_walker` remains the one
page-table encoder. Common relocation planning is shared with kexec below the
two consumers; hibernation is not expressed as a `KImage`.

## 6 Snapshot selection

Before device noirq and CPU-offline phases, the transaction drains every PCP
and snapshots buddy truth while holding its owner. It saves every populated,
saveable PFN that is not free, nosave, firmware-reserved, MMIO, ACPI NVS,
offline, a guard page, or hibernation-owned temporary storage. Kernel-image
frames are saveable even though they were never allocated from the buddy.

All copy and metadata storage is preallocated before device noirq. Zero pages
may be represented in the zero bitmap instead of emitted as payload. Each
nonzero saved page has exactly one original PFN and one immutable copy frame.

## 7 Write sequence and unwind

Forward order is:

1. acquire the shared transition claim and hibernation lease;
2. prepare console/notifiers, sync, and freeze every mounted filesystem;
3. freeze userspace tasks and disable/drain usermode helpers;
4. hold device hotplug exclusion and freeze freezable kernel threads;
5. prepare the snapshot and all temporary storage;
6. run device `Freeze` prepare, freeze, late, and noirq phases;
7. offline secondary CPUs, disable interrupts, and suspend syscore;
8. save architecture continuation and copy the physical image;
9. resume syscore/IRQs/CPUs/devices enough to perform storage I/O;
10. serialize header metadata, PFN map, and page stream;
11. flush payload and maps, then commit the valid marker with preflush/FUA;
12. run device `Hibernate` poweroff callbacks and the selected terminal mode.

The original side unwinds every completed reversible step exactly once in
reverse order on failure. The restored side resumes through the saved
continuation, selects device `Hibernate` restore callbacks, thaws filesystems,
helpers, kernel threads, and userspace, releases the transition claim, and
returns to the original caller.

If poweroff fails after marker commit, the kernel either durably unmarks the
image before unwinding or halts. It never resumes normal mutation while the
image remains valid.

## 8 Persistent image format

The resume device's swap header preserves its original ten-byte signature and
uses `S1SUSPEND` as the valid marker. The hibernation overlay contains format
version, flags, checksum, first map-page locator, original signature, build
identity digest, architecture, page size, CPU/SMP identity, normalized-memory
topology digest, image-page count, zero-page count, and an architecture header.

Map pages form a forward-only linked chain of checked physical page locators.
The logical stream is image information, original-PFN metadata, optional zero
metadata, then page data. Readers reject a zero/out-of-range link, cycle,
duplicate payload locator, count overflow, premature end, trailing map entry,
or locator that overlaps the header.

Uncompressed images are mandatory. LZO and LZ4 are accepted and emitted when
selected; each compressed chunk records its encoded length and expands to a
bounded integral number of pages. CRC32 covers the uncompressed logical page
stream. Unknown mandatory flags are rejected.

## 9 Cold-boot resume

Resume detection runs after the selected block device and partitions exist but
before the root filesystem mount and userspace. `noresume` bypasses it.
`resume=` resolves a canonical raw device/partition or a swapfile target whose
physical mapping is available without treating the mounted file as the image
owner.

The reader claims the target, reads and validates the header, consumes the
marker, allocates all restore metadata, loads direct destinations or safe
collision frames, verifies the checksum, then freezes the fresh kernel using
the same filesystem/helper/device/core owners as the write transaction. The
architecture restore copies collisions and transfers to the saved
continuation. A rejected/corrupt image is unmarked when safe and the cold boot
continues with a named error; no destination has been modified before full
admission.

## 10 Sysfs and boot surface

| Path | Mode | Contract |
|---|---|---|
| `/sys/power/state` | rw | includes `disk` only when hibernation is available |
| `/sys/power/disk` | rw | lists `platform`, `shutdown`, `reboot`, `suspend`, `test_resume`; selected mode is bracketed |
| `/sys/power/resume` | rw | selected device path or encoded device number |
| `/sys/power/resume_offset` | rw | raw page offset of a swapfile header |
| `/sys/power/image_size` | rw | preferred maximum image bytes |
| `/sys/power/reserved_size` | rw | bytes reserved from the image for post-resume use |

`platform` is listed only with platform hibernation ops. `suspend` is listed
only when `32a` supplies a suspend state. `test_resume` restores immediately
without powering off. Writes accept one optional trailing newline and reject
unknown/unavailable values with `EINVAL`. A concurrent transition returns
`EBUSY`.

## 11 Architecture restore

On x86_64, the image records the saved continuation, image CR3, CPU state, and
physical-memory compatibility digest. Restore builds safe temporary identity,
direct, and restore-text mappings. Safe stackless code installs the restored
CR3, copies every collision page, restores CPU-global state including syscall,
descriptor, FPU/XSAVE, control, and required platform MSRs, and jumps to the
saved continuation.

On aarch64, the image records the saved continuation/context PFN, TTBR1/load
identity, boot CPU MPIDR, exception level, and CPU state. Restore runs on the
same logical CPU, uses a safe TTBR0 trampoline and safe temporary TTBR1 linear
map, applies break-before-make where required, cleans copied destinations to
PoU, invalidates TLB and instruction cache, installs the restored TTBR1, and
returns through the saved continuation. MTE-tagged memory is either serialized
with its tags or makes hibernation unavailable.

Both paths flush live task FP/SIMD ownership before snapshot and restore it
from the image. Neither path relies on firmware preserving RAM.

## 12 Complexity contract

Snapshot creation, image I/O, checksum, and restore are O(number of populated
saveable pages). PFN and slot membership tests are O(1); map-chain traversal is
linear; exact-PFN claims are O(log free blocks) or better. Metadata is O(number
of populated PFNs), represented by bitmaps and bounded map pages with no
heap object per frame.

## 13 Concurrency

The shared system-transition claim serializes all power transitions. Device
hotplug exclusion stabilizes the PM walk. Filesystem freeze stabilizes
persistent state; freezer and usermode-helper gates stabilize task creation and
userspace mutation. PMM snapshot/claim operations serialize with buddy and PCP
owners. The hibernation lease serializes with pageout, swapon, and swapoff. No
sleeping lock is acquired after interrupts are disabled or inside final restore.

## 14 Debug

`debug-hibernate` logs phase transitions, selected target/mode, page and byte
counts, direct-versus-collision load counts, format admission failures, and the
last completed durability boundary. It never logs page contents.

## 15 Log

Normal operation logs one image-created line before terminal shutdown and one
image-resumed line after the restored continuation. Rejection names the first
failed invariant and whether the marker was consumed. Partial write failures
name the phase and confirm rollback/unmark outcome.

## 16 Performance budget

The uncompressed path performs at most one logical payload write and one read
per saved page plus map/header I/O. Buffers are reused; no whole-image `Vec`
copy exists. Compression may use bounded worker concurrency while preserving
logical stream order. Final marker commit requires an explicit flush/FUA even
when the device otherwise advertises volatile caching.

## 17 Test contract

- Golden format fixtures pin every header/map offset and byte order.
- A memory-backed block device round-trips images across owner destruction,
  including map-page rollover, fragmented slots, zero pages, and both
  compression modes.
- Fault injection at every allocation, read, write, and flush proves complete
  slot rollback and no valid marker. Publishing the marker before payload/map
  durability is a required RED positive control.
- Parser tests reject corrupt signatures, unknown flags, count overflow,
  cycles, duplicates, out-of-range locators, incompatible topology/build/CPU,
  truncated chunks, and bad CRC.
- PMM tests prove PCP drain, exact free-PFN claim, exclusion of every topology
  class, copy/destination disjointness, and collision staging. Removing one
  exclusion must make the snapshot oracle fail.
- Sequence tests inject failure at every phase and compare the exact reverse
  unwind. The restored continuation uses `Hibernate` restore, not ordinary
  suspend resume.
- Architecture hosted tests pin saved/restored field symmetry, temporary-map
  coverage, stackless relocation inputs, and cache/TLB order. A fake memory
  model forces every destination to collide and verifies the exact final PFNs.
- End-to-end QEMU runs on x86_64 and aarch64 use a persistent raw swap disk:
  boot A creates a RAM-only nonce, requests hibernation, and powers off; boot B
  with identical topology resumes and only the restored caller can print the
  nonce and `HIBERNATE-RESUME-PASS` with serial RX. A normal fresh boot cannot
  emit it.
- Negative cold boots cover changed RAM, SMP/CPU identity, build identity, and
  corrupted headers. Each rejects the image without modifying a destination.
- Coverage is at least 85% for generic hibernation decision code.

## 18 Failure modes

No image target or space returns `ENOSPC`; incompatible/corrupt images return
`EINVAL` or `ENODATA`; I/O and flush failures return `EIO`; allocation failure
returns `ENOMEM`; concurrent transition/swapoff returns `EBUSY`; unsupported
architecture/platform state returns `ENOSYS`/`EOPNOTSUPP`. Every pre-marker
failure unwinds. Every post-marker failure either durably unmarks or halts.
Architecture restore failure never returns into partially overwritten fresh
kernel memory.

## 19 Cross-spec

`10` owns physical allocation truth; `13` owns tasks/freezer boundaries; `16`
owns filesystem freeze; `17` owns block durability and swap backing; `20` and
`21` own architecture state; `23` owns time restoration; `32` owns terminal
power transitions; `32a` owns reversible PM sequencing; `35` owns device
callbacks; `36` owns cold-boot handoff; `52` owns crate dependency direction;
`54` governs restore assembly.

## 20 Changelog

(none)
