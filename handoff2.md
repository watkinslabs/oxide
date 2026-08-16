# Handoff — 2026-08-16

`main` = `40bf29711`. 22 PRs merged this session (#5471 – #5492).

The whole session ran one directive: complete `scratch/system-compat.md` in
file order, the Linux way, `../reference` as the authority, no deferrals.

---

## 1. The goal moved

**A boot reaches a login prompt on both arches again**, after two regressions
that had been masking it.

- x86_64: `oxide login:` at 7.3 s, holds — 0 restarts over the following 23 s,
  against 23 restarts per boot before.
- aarch64: 3 of 4 boots, against 0 of 3 before.

**Correction, because the previous hand-off got this wrong and it propagated.**
That file opened "No boot has reached a login prompt. Not this session, not
before it." That is false. This project has booted to `graphical.target` and
`gnome-session`, and to a gdm greeter, in earlier campaigns; before that it
booted to a shell. The measurements above are real regressions found and fixed,
not a first. Do not repeat the "first login prompt" framing — it reached PR
bodies #5477 and #5488 before anyone checked it against the project's history.

Neither cause was what its row said, and that is the session's pattern.

| Blocker | The row said | It actually was |
|---|---|---|
| getty restart-loops every 5.000 s | a timeout in agetty | **agetty never ran.** The pipe computed one readiness mask per *inode* with the two ends' conditions crossed, so a read end could never report hangup and every systemd `Type=idle` unit burned its full 5 s |
| aarch64 never reaches login | a kernel stack overflow | **No signal could reach a poll sleeper.** The whole poll family slept `Uninterruptible`, so `signal_pending_state` refused even SIGKILL. Only aarch64 hit it because glibc compiles `pause()` into `ppoll(NULL,0,NULL,NULL)` there |
| `scheduling while atomic` storm | unknown, held-lock list empty | a bdev mapping copy to a user page held a rank-40 spinlock across a fault. **34,409 reports → 0** |

---

## 2. Tier state

**Tier 0** — gate 1 met both arches. Gate 3 closed. Gate 2 (`every boot reaches
userspace`) still `BLOCKED`, but no longer opaque: two of its recorded facts
were wrong (it is at zram setup ~43 s, not 3.3–3.6 s) and it is two distinct
failures — a livelock that answers SysRq, and a hard wedge that does not.

**Tier 1** — complete. HD-Audio (real codec enumerating under QEMU), suspend/
resume (s2idle + ACPI S3 + PSCI, 20→203 tests, 25 controls, 6 defects found on
the way), power_supply, backlight, thermal/cpuidle/cpufreq, DRM cursor errnos.

**Tier 2** — OverlayFS, FAT (full read/write + create/delete/rename), exFAT +
NTFS, V4L2 (real frames captured both arches), SELinux (parses the
distribution's own 3.7 MB policy), futex2, Bluetooth. Wi-Fi is the one
`NOT FOUND` left and is in flight.

**Tier 3 and Platform — untouched.** 14 Tier-3 rows, 5 platform rows.

Also cleared four red `ext4` test binaries that had been making
`cargo test --workspace` red for every lane. All four were the same fixture
hazard — raw device pokes bypassing the metadata cache — not kernel defects.

---

## 3. In flight

Three lanes were interrupted by an API session limit, resumed, and are running.
Their work is committed on their own branches; nothing is at risk.

| Branch | State |
|---|---|
| `B2245-boot-wedge-gate2` | **Root-caused gate 2.** Idle parked through bare `hlt`/`wfi` without admitting interrupts, so a core could halt with the mask closed and only an NMI would reach it — and the stall scan excused idle CPUs, which is why nothing reported it. Reference is `asm volatile("sti; hlt")`, verified. Fix committed, unpushed; a second wedge is exposed underneath it |
| `F1182-wifi-mac80211-cfg80211` | mid-implementation, WIP commit `71578cb9b` |
| `F1183-conntrack-nat-vlan-bonding` | partly pushed, WIP on top |
| `F1184-9p-and-virtiofs` | **not resumed.** WIP commit `8384f80b3`. Found a real bug: the dirent iterator never terminates after an error |

---

## 4. Do not re-derive these

- **A hand-off's own claims are a proxy, not the thing — check them.** The
  previous hand-off asserted no boot had ever reached a login prompt. The
  project's history says otherwise (gdm greeter, `graphical.target`,
  `gnome-session`, and a shell before that). It was repeated as fact into eight
  PR bodies before the user caught it. `scratch/known_issues.md`,
  `scratch/fixed-issues.md` and the auto-memory index are the cheap checks.
- **`git ls-remote` can serve a stale replica.** It made landed pushes look
  like silent no-ops for most of a session and caused retry storms that then
  failed their own `--force-with-lease` check. Verify with
  `git fetch && git rev-parse origin/<branch>`. The pre-push hook's `exit 141`
  (SIGPIPE) is real but does **not** mean the push failed.
- **Never resolve a code conflict by taking both sides and dropping identical
  lines.** That deleted `let root = fs.root_inode();` from the exFAT mount
  constructor because the overlay constructor beside it has the same statement.
  The pre-push feature gate caught it. Deduping is correct for a ledger row
  list and wrong for code — and it collapsed a section *header* in
  `fixed-issues.md` the same way, which only the multiset count caught.
- **Doc numbers and `docs/52` rule numbers collide constantly.** Four lanes
  claimed doc `62` in one day. Taken: 60 udev, 61 HD-Audio, 62 removable-media
  filesystems, 63 SELinux, 64 V4L2, 65 Bluetooth. `docs/52` §5 runs 1–19 and §7
  runs 1–14, both contiguous as of `40bf29711`. **Append, never renumber**; if
  you must, grep `52§N rule M` and fix the references — two silently pointed at
  the wrong rule today.
- **The open-work summary at the top of `known_issues.md` is hand-maintained
  and was excluding three rows** whose status carries a suffix (`OPEN B2059`,
  `OPEN (PARKED …)`), so two CRITICAL defects were missing from its critical
  column. Recount from the rows when you touch it.
- **`usb-core` is a 97-line packet builder with no class-driver plugin point.**
  Both the V4L2 lane (UVC needs isochronous transfers, which `drv-xhci` lacks
  entirely) and the Bluetooth lane (btusb) hit this independently. It blocks
  the real-hardware path for both and is the highest-leverage unowned item.

---

## 5. Rows a recorded claim got wrong

Roughly a third of what was checked. Worth reading before implementing any row.

- **futex2 `T2-i` demanded work the reference refuses to do.** Upstream's
  `futex_flags_valid` carries `/* Only 32bit futexes are implemented */` and
  rejects every other size class. Implementing `U8`/`U16`/`U64` would have been
  an oxide-invented divergence. The NUMA/MPOL half was real and is done.
- **`T1-a2` was looking at the wrong axis.** Having no cursor plane matches the
  reference; the divergence was refusing with one `EINVAL` where the reference
  returns `ENOENT`, `ENXIO` and `EFAULT`.
- **The FAT allocation row's premise was wrong** — the reference rolls back its
  partial chain too. The real divergences were the side effects.
- **`T2-a`'s VLAN clause** — the 802.1Q frame parser already exists; only the
  VLAN *interface* is missing.
- Row 106 claimed `vfat_ctor` forces `SB_RDONLY`; F1168 had already removed it.

---

## 6. First task next session

Land what is in flight, in this order:

```
cd /home/nd/oxide/kernel-B2245 && git log --oneline -3
```

`B2245` is the valuable one — the idle-park fix is a genuine kernel bug with a
verified reference contract, and it is still unpushed. Get it measured, pushed
and merged, then `F1183`, then `F1182`, then resume `F1184`.

After that the file's remaining work is Tier 3 (14 rows) and Platform (5 rows),
in file order.

