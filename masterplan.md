# Native NT Notepad execution master plan

DRAFT 2026-09-05. Dep:31,52,53,54. Execution plan; does not freeze subsystem specifications.
Baseline: 586e5390e. Coordinator branch for this revision: D1550-notepad-masterplan.
Location: masterplan.md, retained at the user-requested location.
Implementation is active on the coordinator branch; the plan remains the execution ledger and acceptance contract.

Session direction (user clarification, 2026-09-06): one Oxide/Linux system and
the existing GNOME desktop; Windows applications share that presentation and
input environment with Linux applications. NT desktops/window stations are
logical compatibility objects, not another visual shell. A separate logind
broker is not a prerequisite established by the startup reference. Reuse the
existing compositor connection and canonical object/process owners; authenticate
runtime namespace admission through Linux credentials and pinned VFS identity.

Desktop/process requirements (2026-09-06): GNOME is the initial acceptance
environment, not a dependency of NT semantics. Windows applications must also
integrate with KDE and JWM through standard display/window-manager protocols;
test X11 and XWayland explicitly and track native Wayland support separately.
Each Windows process is a canonical OS process: normal PID, procfs identity,
thread enumeration, accounting and lifecycle visible to ordinary Linux task
managers. NT handles reference that same process; no parallel process registry.
Acceptance includes matching the Notepad NT identity to its normal procfs PID,
name, command line, threads and resource accounting while its window is live.

Current execution checkpoint (2026-09-06; supersedes historical status below):

| Status | Work | Evidence / next integration | Branch |
|---|---|---|---|
| WIRED, GUEST UNVERIFIED | Native child process names | Child publication uses canonical Task/MM executable identity and exec comm setter. Real Task fixture6 pass, including generated production-hook removal control. Kernel debug-preempt checks x865.59s/ARM5.74s pass. Procfs command line/accounting and actual desktop task-manager acceptance remain separate checks. | D1550-notepad-masterplan |
| ACTIVE | Normal-user registry launch | KI-0412: wrapper uses root-owned runtime/state paths; native registry client ignores configured endpoint and resolves with root credentials in initial namespace. Repair must carry selected endpoint through canonical admission and preserve one service across multiple applications. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Window extras, long queries, child IDs, instance, rectangle queries | Canonical storage allocated before callbacks; raw creation fixture 54 pass. Geometry and long adapters connected. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Logical fonts, selected lifetime, glyph/font queries | Full LOGFONT records and delayed selected-object deletion; charset, SFNT data, glyph IDs, ABC and outline routes enter native callbacks. Six query boundary tests pass. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Control colors and clipping | Default EDIT background uses protected canonical brush; all raster consumers honor application and paint clips. Actual raw paint boundary test passes. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Paint/session and thread lifetime | Canonical preparation/erase boundary 29 pass; Send boundary 23 pass. Active canceled sends retain callback resources until return or recipient exit. Exact retained backing seeds partial paint before raster. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Messages and HWND properties | MessageCall selector/ANSI layout repaired; owner-thread sends and mixed position waits connected. Property atoms retain stable slots; destruction releases references after GUI unlock. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Scrollbars, caret, synchronous redraw | Redraw boundary313 pass; scroll156 pass after whole-test GUI serialization. Canonical caret settings/raw queries and blink/paint hooks connected, joined boundary3 pass. Resize class-style/WVR preservation and NOREDRAW output policy wired; position boundary25 pass. Isolated production flags-hook removal fails; restored25 pass. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Status-bar services | Nonclient profile and font-normalized metrics enter native callbacks; RectVisible uses canonical clipping; system color and brush routes connected. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | GetDCEx and frame drawing | Both raw routes use canonical visibility/DC leases; raw region-loss control fails and restored suite4 pass, joined raw/context/backing8 pass. Pens, line/rectangle and SetRectRgn wired. Joined raw text-to-glyph raster16 pass. IPC586 pass; actual shared binding5 pass and ABI12 pass/1 ignored after zero-area encoding/geometry-only projection repair. Required canonical DWORD query boundary5 pass. | D1550-notepad-masterplan |
| ACTIVE | NT compatibility identity inside existing GNOME session | Typed objects/default-thread inheritance integrated; object86, desktop12, native prepare2 pass. Normal logical object create/open/select and authenticated namespace admission remain unwired. Current per-process HWND counters collide and hierarchy must become shared canonical state. No separate visual desktop or speculative broker dependency. | D1550-notepad-masterplan |
| WIRED, GUEST UNVERIFIED | Frame flushing and retained paint | Get/Peek idle/busy flush, EndPaint, whole-frame and erase share generation ownership. Production output/message/erase/reservation joined75 and output13 pass. Raw paint20 pass; isolated pending-hook removal fails/restored20 pass. NULL-output preparation fixture19 pass using actual factory/live/callback queue: simulated NC/ERASE writes two nonblack pixels, retained before cleanup; invalid pointer faults after callbacks. Failed transport remains flushable; only Presented emits presentation milestones. | D1550-notepad-masterplan |
| NOT READY | Default image and visible Notepad acceptance | No guest boot or image staging in this wave. Post-staging payload verifier wired; ext4 fixture9 pass, selected native pair byte identity enforced, gate arguments1 pass. Existing images lack compositor and are rejected. Probe target-directory selection fixed: resolver4 pass; actual compositor build gate passes, reintroduced default-cache path fails. Full syscall library2425 pass. Compositor backend28/Xvfb2 pass; prior runtime86 pass/1 ignored plus glyph16. Latest x86 debug-preempt4.96s/ARM4.94s pass. GNOME speed, visible typing and normal close remain unverified. | D1550-notepad-masterplan |

Six-worker assignments cover desktop/thread inheritance, image payload verification, text/DC/BeginPaint, frame publication, resize/session-authority audit, and shared-DC/pending-output controls. Completed bounded assignments are handed back; this is not a claim that six workers remain continuously active. Coordinator owns production hooks and kernel gates. No new image is claimed testable until desktop authority/root integration and visible acceptance pass.

## 1

**Objective:** launch the installed Wine PE32+ AMD64 Notepad on Oxide, show its window, type a unique token into its edit control, observe the rendered token, and close the application normally. Preserve evidence of the NT process, presentation, input delivery, and process exit.

**Scope:** complete the Notepad execution path, including all dependencies it exercises. Keep the broader NT/Wine programme tracked separately below. A successful Notepad run does not establish complete Windows compatibility, Microsoft Notepad compatibility, games support, or ARM Windows execution.

**Estimate:** same-day success is a stretch target. Allocate 1–2 hours for discovery, then re-estimate from measured gaps. A 6–10 hour completion is plausible only if remaining defects are local wiring/ABI issues. Missing ELF runtime initialization, callback execution, or compositor integration can require several additional days. These are planning ranges, not measured durations or a delivery promise.

**First principle:** ask “Is this how Linux does it?” Read the primary reference for each external behavior before selecting the owner or encoding a test. Use the local Windows runtime reference for Wine-private ABI details; Linux alone does not specify them. Record resulting contracts and executable tests; follow CLAUDE.md's restriction on external implementation citations in repository prose.

## 2

Evidence levels: OBSERVED = inspected current code or direct result; REPORTED = prior session result; UNKNOWN = not established. Revalidate after any base change.

| Status | Item | Evidence / limitation | Branch |
|---|---|---|---|
| OBSERVED | Baseline | Local main and origin/main point to 586e5390e; no fresh remote comparison in this revision | — |
| VERIFIED GREEN | Launcher compilation and hosted contracts | Runtime handoff now owns Unixlib buffers/records and the Notepad Unixlib dependency closure; windows-runtime 55 library tests, windows-registry 38, windows-contracts 4 pass on this branch | D1550-notepad-masterplan |
| VERIFIED GREEN | Registry | 38/38 tests pass in the integrated hosted suite | merged registry lane |
| REPORTED GREEN | Notepad shell contract gate | Passed preceding session; script checks declarations/resources, not executed PE instructions | — |
| VERIFIED GREEN | Runtime catalog intake exists | syscalls/src/nt_exec.rs copies Unixlib records and publishes catalog on thread group; staged dependency closure now also admits each dependency's PT_INTERP owner | — |
| VERIFIED GREEN | Runtime catalog consumption | nt_loader_dir/dynamic.rs::load_unixlib now consumes the thread-group UnixlibCatalog through exec::unixlib::load_named; it no longer reopens staged_root through VFS | D1550-notepad-masterplan |
| VERIFIED GREEN | Callable table production publication | Synthetic NTDLL mapping now allocates an in-image eight-slot table, fills bounded executable dispatcher entries, and registers it in the address-space ELF registry; a regression asserts the descriptor and entries | D1550-notepad-masterplan |
| VERIFIED GREEN | Unixlib table identity/lifetime | The address-space registry retains multiple named Unixlib tables, rejects conflicting reuse of one table identity, dispatch accepts per-module table handles, and repeated named loads reuse the canonical table identity; `elf-load` 163 tests and focused Wine syscall tests 20 pass | D1550-notepad-masterplan |
| ACTIVE | Callable entry/return execution | Production dispatch rewrites the live user frame to the validated Unixlib entry. Hosted emitted-instruction tests cover x86 stack alignment, nonvolatile register preservation and return extent. Source-built Wine NTDLL now exposes the explicit Oxide TEB/PEB attachment ABI; guest native entry/return remains unverified. | D1550-notepad-masterplan |
| ACTIVE | Native ELF execution environment | Real `win32u.so` transitively includes interpreter-bearing system objects and TLS-bearing libc; the catalog carries the PT_INTERP image and records the interpreter boundary. PE preparation maps an optional dynamic ELF bootstrap and builds its private initial stack; the admitted bootstrap is now retained on the NT thread group for child process creation; visible execution is still unverified | D1550-notepad-masterplan |
| VERIFIED GREEN | ELF TLS metadata boundary | Shared ELF parsing now retains and validates one PT_TLS template (file/memory sizes, bounds, duplicate rejection); the native Unixlib loader still does not allocate or install the per-thread TLS block | D1550-notepad-masterplan |
| ACTIVE | Native Unixlib table extraction | Loader now carries ELF symbol sizes, extracts relocated `__wine_unix_call_funcs` entries from the staged image, validates executable targets, preserves exact relocation classes, and publishes per-module identities transactionally; a real Notepad `win32u.so` load-by-name/query integration test is still required | D1550-notepad-masterplan |
| VERIFIED GREEN | Wine load-by-name query boundary | Wine-specific `NtQueryVirtualMemory` classes now have a target-only owner that consumes the catalog loader and returns `(module base, table identity)` with nullable ReturnLength support; x86_64/aarch64 target checks pass and 101 shared syscall ABI tests pass | D1550-notepad-masterplan |
| ACTIVE | Userspace native-loader registration boundary | New private query class `1005` accepts a userspace-mapped module/table, validates the catalog name, module bounds, table bounds, and executable callable targets, then publishes the canonical descriptor for Wine's existing load query. The userspace owner has a real `dlopen`/`dlsym`/`dl_iterate_phdr` path; the launch request now carries the current dynamically linked launcher as an ELF bootstrap, which registers `win32u.so` and jumps to the PE continuation. Guest execution remains unverified | D1550-notepad-masterplan |
| ACTIVE | Native relocation coverage | Wine roots require `R_X86_64_64`, now handled by the shared ELF relocator; the shared boundary reports exact relocation classes and a hosted libc probe proves `IRELATIVE` plus `TPOFF64` remain pending userspace resolver/TLS ownership | D1550-notepad-masterplan |
| OBSERVED | Real PE graph test exists | exec/src/tests/pe_loader.rs loads installed graph, checks trampoline/VMAs; skips if fixture absent and does not execute instructions | — |
| OBSERVED | Scatter/gather is not absent | nt_file_scatter.rs contains real VFS reads; gather adapter/policy and dispatch checks exist | unassigned audit |
| OBSERVED | Existing Notepad smoke is headless | boot-smoke.sh sets OXIDE_QEMU_HEADLESS=1; default attempts is three | unassigned |
| ACTIVE — IMPLEMENTATION REQUIRED | Visible Notepad / typing / clean exit | Supersedes earlier all-green claim. Existing rootfs contains Notepad/620 DLLs/36 Unixlibs, but PE text-render ingress, native raster callback, desktop keyboard semantics and SetWindowPlacement still need integration. Creation callbacks, native-thread handshake, bounded compositor transport and GUI/GDI frame hooks now have code and focused tests. Six agents are implementing disjoint remaining pieces. No new guest boot until this production chain and nonboot checks are complete; visible Notepad is NOT verified. Current detailed ownership and evidence appear in the execution section below. | D1550-notepad-masterplan |
| VERIFIED GREEN | Current both-arch gate status | Fresh full-feature `-Dwarnings` checks passed after the environment-layout/test repairs: x86_64 21.57s and aarch64 30.52s. Shared-kernel ARM guest verification remains outstanding. | D1550-notepad-masterplan |
| ACTIVE — REMAINING PERFORMANCE | Boot-latency regression lane | Corrected verification `uart-2875921.log`: session25.202s, shell-started45.380s; inspected captures show GNOME top bar and wallpaper around45–49s. Previous session145.968s. One-vCPU configuration unchanged. Captured IRQ deadlock repaired; old20–21s visible baseline not yet recovered. Frame changes do not prove input responsiveness. | D1550-notepad-masterplan |

Do not convert import resolution, ELF mapping, a function-table address, a readiness struct, a service-entry log, or a merged PR into execution proof.

Current evidence corrections: installed native NTDLL's `NtCurrentTeb` calls `pthread_getspecific`; the null return at the win32u initializer identifies missing native thread-local runtime initialization, not a proven GS-publication defect. Stub tests cover the complete 184-byte preservation frame and 192-byte return extent; guest return remains unverified. PFN contract is now registered in hosted Cargo tests: 5 passed, 2210 filtered, none ignored.

Boot measurement: `python3 tools/perf/boot-timeline.py <serial-log>` distinguishes service targets, display publication, and session running. Unit durations overlap and are not a critical-chain sum. `[BLK-RESUME]` measures completion-to-collection, including delayed async consumption; it does not measure device latency. Existing acceptance config uses one vCPU; host core count is not guest CPU allocation. Do not change CPU count to conceal a regression.

Active fanout: scheduler publication repair owner; independent deadline writer-lock audit; QMP connection-lifecycle harness owner; matching native-runtime source preparation owner; coordinator integration and final acceptance. PFN and trampoline lanes delivered tested patches; native runtime initialization remains open. Heavy builds use separate disk-backed `target/lanes/` paths. Host cleanup moved inactive caches out of tmpfs and reset/re-enabled zram; neither establishes guest performance.

Current prerequisite: stock installed native NTDLL has no standalone attach API for an Oxide-owned TEB. A matching Fedora 10.20 source build now exposes `wine_oxide_attach_thread`, validates the canonical TEB/PEB, and is staged with matching win32u in the default image. Guest proof is still required; child-thread lifecycle remains the separate KI-0377 scope. Do not patch a private fallback key or launch a second object-server authority.

Boot repairs under review: KI-0362 idle block-wait admission; KI-0365 unchanged fsync transaction creation and forced checkpoint waits, related KI-0303. Timer arithmetic audit found no extended-sleep mechanism; 41 offline tests do not establish hardware delivery latency. KI-0363 tracks cross-ABI trampoline preservation; KI-0364 tracks PFN widths/table bounds. No item here closes final guest acceptance.

Confirmed scheduler regression KI-0367: September4 commit78a0164a0 charged each fair group a full4ms request on selection, before execution. A100us task burst incurred40x elapsed time at default shares. Integrated candidate charges actual elapsed runtime through live ancestor accounting. Negative controls fail for old selection charging and removed accounting hook. Combined candidate improved early boot milestones but failed desktop verification on KI-0369; no isolated per-patch wall-clock attribution.

Scheduler follow-up: common-ancestor EEVDF wake comparison replaces cross-group leaf-clock comparison in direct and deferred activation. Order is charge current, place wakee, enqueue, decide preemption. Coordinator independently reran1928tests successfully before candidate build; reinstating old comparison fails direct and deferred activation regressions. Initial KI-0369 publication repair adds4passing tests; cross-CPU writer ownership review remains open.

Acceptance ordering: visible runner waits for GNOME session running and captures `gnome-before-notepad` before launching PE workload. Three hosted ordering/failure tests pass; removing session wait causes two failures. A session marker plus retained frame is evidence to inspect, not automatic proof of desktop responsiveness or Notepad success.

Final verification FAILED: coordinator x86 full-feature gate and ARM lane full-feature-equivalent `-Dwarnings` gate passed before candidate build. `boot-perf-final-20260905` reached systemd startup15.599s but not GNOME. Retained registers show CPU0 in `sched_enc::wakeup::cand_of`, IRQs disabled, spinning on odd deadline generation0xe9; frame chain includes deferred wake processing and IRQ dispatch. Evidence: `target/desktop-boot-verification/stall-qmp.txt` (transcribed captured subset), `live-check.png`, `target/boot-logs/x86_64-20260905-204818.log`. VM no longer live. Diagnose/test publication context offline before rebuilding and final verification; no desktop-speed success claimed.

Ext4 integrity gate resolved: KI-0368 reproduced before fsync changes; concurrent same-parent fixture omitted required parent inode locking. Corrected tests cover distinct-parent parallel allocation and canonical same-parent VFS locking. Full disk-backed suite exit0:933passed,0failed,9ignored,91targets;13fsync tests pass. Candidate root image read-only fsck exit0. Tests/builds require disk-backed TMPDIR and CARGO_TARGET_DIR; recovered tmpfs fixtures remain recoverable outside tmpfs.

Native ABI prerequisite KI-0370: existing build-specific untagged win32u dispatch conflicts with31d§1. Pending raw-argument helper is built, not wired; permanent build-number translation belongs in userspace, consuming the stable tagged Oxide entry. Matching10.20-3.fc42 signed source RPM acquired and signature/digests verified; isolated Fedora source preparation underway. Source acquisition does not establish runtime attachment or backend integration.

KI-0369 offline repair: publication guard masks IRQ/preemption until even generation; timer overrun consumption holds TaskPi/stable rq; DL tick holds rq across snapshot/charge/store. Independent writer audit confirms both identified ownership gaps closed. Coordinator1935scheduler tests and x86 full-feature warnings gate pass; ARM Make gate reported exit0, isolated equivalent rerun pending. Guest remains unverified. Adjacent pre-lock NT class-selection race tracked KI-0372, design audit active.

KI-0371 verification transport integrated: `tools/windows-notepad-acceptance.py::qmp` uses command-scoped connections; serial waits no longer retain exclusive QMP ownership. Six combined transport/order tests pass; production-main wiring test fails with persistent-connection control. Acceptance criteria unchanged; no guest launched for this harness check.

Follow-up gates: isolated ARM full-feature-equivalent KI-0369 check exit0 (17.57s). KI-0372 class revalidation and KI-0373 four futex TaskPi IRQ-save guards are now separate implementation lanes; previous gates do not qualify their new edits. No new guest launched.

Repaired candidate211520: root3.713s, systemd4.063s, basic10.572s, graphical14.157s, system startup14.259s, shell17.499s, display20.126s, GNOME session23.988s. ISO `boot-perf-repaired-20260905` SHA256 `5adc973b01494ad470ea4f3153d0a6ca1eba59c3fc81ff1e04a40e22e88739fc`; build exit0, preboot fsck exit0. Scheduler1938tests and both feature gates passed; futex167tests and target checks passed. Visible verification INCOMPLETE: checker stopped around28s on a two-second unchanged-frame criterion; screenshots still boot text. KI-0374 tracks premature verifier failure. Guest terminated; no proven new kernel stall. Corrected frame-wait harness must pass offline controls before final visible verification;23.988s is session startup, not rendered/input-ready desktop.

Corrected final capture: frame-wait delayed-render and unchanged-deadline tests pass; restoring premature failure makes delayed-render control fail. Restaged candidate build/fsck exit0, ISO SHA256 `5d1f205eae4669fd7a94e1eb9d31855bdf49c4438bf123308f7c887b83f2386a`. GNOME-only verifier exit0; `screen-2875921-overview.png` and `response.png` visually inspected: GNOME panel then wallpaper. Session25.202s; shell-started45.380s; capture interval about45–49s. Runtime `uname -a`: Linux oxide6.19.0-oxide, Oxide version string. QMP quit completed; no live VM. Keyboard-response causality and Notepad remain unverified. Remaining render delay receives offline review, not another exploratory boot.

KI-0375 storage repair is now hosted-green: the canonical main/child arenas are disjoint, catalog publication preserves unrelated PEB/TEB/parameter/environment bytes, and the full `elf-load` library suite passes 172/172. The coordinator also repaired two test consumers that still assumed the pre-arena offsets (empty environment double-NUL and PE module image-size lookup). This closes the environment-layout implementation gate, but not native attachment: libc-pointer/TEB separation and native lifecycle still require explicit contract reconciliation.

Active runtime repairs: KI-0375 owner splitting environment builder/layout/tests and implementing disjoint internal arenas under31b, preserving external field offsets and one process mapping. KI-0376 tracks UTF-16 word/byte confusion in dynamic module-name publication; same owner fixes payload overlap and byte bounds. Existing dynamic loader holds canonical `nt_peb_lock`; catalog updates must not copy stale unrelated TEB/parameter bytes back to userspace.

KI-0377 child-thread lifecycle remains open: libc must create genuine native thread state on the same canonical Task before secondary native NTDLL attachment. The initial launcher now has an explicit attachment ABI and guest proof is pending. Current raw NT child entry still needs the same-task readiness, suspend, handle publication, rollback and termination contracts; x86 libc FS and NT GS coexist; ARM libc TPIDR_EL0 and Windows x18 need a31n revision before register semantics change.

Timing evidence tooling: `screenshot()` now records full hash/path plus command-completion monotonic/Unix nanoseconds in fsynced per-run JSONL; these are capture-completion times, not render-onset timestamps.19offline tools tests pass; unhooked recorder and conflated session/Shell-started milestone controls fail. Existing final captures predate this recorder and retain approximate visible timing only.

Native source preparation complete: matching Fedora 10.20-3.fc42 spec order applied, 244 staging patches/105 enabled sets, generators exit0, no rejects; missing-patch inventory control fails. Source-owned initial-thread attachment is implemented and compiled in NTDLL/win32u; guest execution and broader tagged translation remain open.

Current coordinator result (2026-09-05): the raw Wine x86-64 decoder is wired into production routing with hosted coverage. Runtime evidence identified the post-PFN trap as the intentional `wndproc_continuation` breakpoint; the continuation now marshals its callback-return arguments into Linux syscall-entry registers. Reference comparison then exposed a second concrete defect: `NtUserMessageCall` with `NtUserCallWindowProc` is an initializer, not a kernel-side WndProc invocation. The adapter now writes the Wine `win_proc_params` layout (including `func`, message fields, ANSI flags, mapping, and procA/procW) and returns TRUE, preserving the client-side dispatch boundary and preventing duplicate callback returns. Temporary runtime tracing has been removed. Offline harnesses and all listed host/target gates are green; the build-only image staged PE_DLLS=620 and UNIXLIBS=36 and produced `target/builds/default/oxide-x86_64-grub.iso`. Do not claim Notepad success until window, present, input, and clean exit markers are observed.

Latest controlled run (2026-09-06, build `notepad-parent-read-fix`): the parent-inode reread deadlock fix passed x86_64/aarch64 checks, 2,215 syscall tests, 407 ext4 tests, the Notepad harness, readiness controls, and Python compilation. Real QEMU UART reached GNOME's `Entering running state` at 24.829s with no watchdog/soft-lockup. The acceptance run then failed before Notepad because QMP `screendump` continued returning the boot-console frame despite the GNOME session marker; the rendered-desktop gate correctly refused to launch the PE. Retained evidence: `target/windows-notepad-acceptance/uart-3129442.log`, `target/boot-logs/x86_64-20260906-005619.log`, and `screen-3129442-gnome-probe.ppm`. This is a display/scanout readiness failure, not a Notepad pass. The ext4 fix deliberately removes a parent inode-table reread while VFS `i_rwsem` is held; parent link-count persistence in that canonical locked path remains a correctness follow-up and must be closed before treating the filesystem change as final.

Acceptance correction (2026-09-05): the one authorized visible run reached GNOME and completed PE/Unixlib/PFN initialization, then Notepad exited with status 1 before any `window-create` marker. Wine's Notepad source makes this failure `CreateWindowW` returning NULL. Static comparison found the cause in `encode_x64_wine_dispatcher_stub`: it overwrote register arguments with stack slots, copied only 13 slots into the wrong envelope offsets, and passed the saved-register prefix instead of the argument-array base. The repair now allocates a 17-slot envelope, preserves RCX/RDX/R8/R9 as slots 0–3, copies stack slots 4–16, and passes `RSP+0x20`; PE hosted contracts pass 65/65 after this change, while both target-gated checks are being requalified. No replacement boot has been run.

Acceptance harness correction (2026-09-05): `uart-2984542.log` contains the GNOME session marker, but `screen-2984542-gnome-before-notepad.ppm` is still the boot console. The runner launched from a session marker without proving graphical scanout. `windows-notepad-acceptance.py` now requires two OCR-confirmed GNOME top-bar clock frames before launching Notepad; hosted readiness controls accept `Sep 5 21:22` and reject boot-console timestamps. The repaired ABI candidate still exited status 1 before `window-create`; the retained run is not a Notepad or visible-desktop pass. No further boot is authorized until the CreateWindow failure is classified offline and all new gates are green.

## 3

Coordinator owns scheduling, shared files, integration call sites, git publication, acceptance, and ledger updates. Delegated agents receive one bounded assignment with explicit paths. They must not commit, push, create PRs, merge, alter shared hooks, edit ledger/plan, boot, or remove worktrees.

Start with at most four workers: two implementation-capable lanes plus two read-only audits. Cap heavy builds by available RAM/disk/CPU; increase workers only after measuring useful throughput. Each build lane uses its own absolute CARGO_TARGET_DIR. Unique Cargo caches do not isolate hard-coded target/artifacts, disk images, registry sockets, or QEMU ports; coordinator owns those.

Use the repository's investigative/design model split where available. If named models are unavailable, select suitable capabilities and state the substitution. Cross-ABI design, memory ownership, callback delivery, and security semantics require a capable reviewer before integration.

| Status | Work package | Initial mode / ownership | Depends on | Branch |
|---|---|---|---|---|
| READY | P0 Baseline + acceptance contract | Coordinator; plan, ledger, fixture manifest, git | — | unassigned |
| VERIFIED | P1 Launcher + catalog producer | Runtime-owned PE and Unixlib buffers cross the fixed NT handoff; Notepad closure includes the required Wine root and transitive system ELF dependencies without widening the catalog cap | P0 fixture identity | D1550-notepad-masterplan |
| ACTIVE | P2 ELF/Unixlib consumer and return path | Catalog-backed LoadSoDll, multi-table identity, production NTDLL table publication, and architecture-specific native entry transfer are wired and target-built. System ELF dependencies are admitted as dependencies (including interpreter-bearing objects); dynamic-loader/TLS initialization, native return under real guest execution, and real `win32u.so` mapping remain open | P0; P1 agreed ABI before wiring | D1550-notepad-masterplan |
| READY | P3 PE startup + NT semantics census | Read-only first; PE initialization, NTDLL and exception/APC paths | P0 | unassigned |
| READY | P4 USER/GDI/input + acceptance harness | Read-only first; window/display path, smoke tooling | P0 | unassigned |
| WAITING | P5 Registry/files completion | Audit; canonical registry and NT file/VFS owners | First P3 findings; spare worker | unassigned |
| WAITING | P6 Integrate and pre-boot qualification | Coordinator only | P1–P4; every demonstrated P5 blocker | unassigned |
| WAITING | P7 Final guest acceptance | Coordinator only | P6 all gates + harness ready | unassigned |
| TRACKED | P8 Broader Windows runtime | Dependency-specific lanes | Notepad checkpoint; promote any actual prerequisite earlier | unassigned |

“READY” means schedulable, not claimed or started. Replace Branch before edits.
Allowed states: READY, ACTIVE, WAITING, BLOCKED, REVIEW, VERIFIED, MERGED.
VERIFIED requires the package-specific evidence; MERGED requires verified remote SHA.

~~~mermaid
flowchart TD
    P0[Baseline and acceptance contract] --> P1[Launcher and owned catalog]
    P0 --> P2[Unixlib consumer audit]
    P0 --> P3[Startup and NT semantics audit]
    P0 --> P4[GUI and harness audit]
    P1 --> W[Wire catalog, ELF initialization, callable table and return]
    P2 --> W
    P3 --> F[Implement measured startup or delivery gaps]
    P3 --> P5[Registry and file audit]
    P4 --> G[Wire display, typing and exit proof]
    W --> I[Integrated candidate and all pre-boot gates]
    F --> I
    G --> I
    P5 -->|demonstrated prerequisite| I
    I --> V[Final x86 Notepad acceptance and required ARM regression evidence]
~~~

## 4

P0, first 30–60 minutes:

1. Read CLAUDE.md completely; inspect status, named HEAD, worktrees, branch list and targeted issue queries. Inspect existing remote Notepad/runtime branches before creating duplicates.
2. Fetch remote state using the coordinator; record source SHA. Preserve unrelated changes. Do not detach HEAD or reset a feature branch onto origin/main.
3. Record hashes and package identity of notepad.exe, required PE DLLs, Unixlibs, NLS and rootfs inputs. The host fixture and staged fixture must match.
4. Read the current Windows execution/NT architecture docs and relevant frozen contracts. Reconcile stale prose in the owning change; this plan does not authorize behavior that contradicts a frozen spec.
5. Obtain a current compile baseline and exact first failure. Cargo may update the nested lockfile: inspect the delta and retain legitimate dependency updates in the owning change.
6. Establish the acceptance checks in §10 before assigning implementation.
7. Assign exact file allowlists, target directories, dependencies and handoff deadline. Independent audits begin immediately while P1 repairs the launcher.
8. Use tools/issues.sh --query with targeted grep filters and --show for selected IDs. Coordinator files confirmed gaps promptly; do not scan archived history or create a second issue ledger.

Preflight includes free disk, RAM, running build jobs, image users, and installed toolchain. Missing prerequisites receive concrete ownership and estimates.

## 5

P1: owned runtime catalog.

**Read:** userspace/probes/windows-runtime/src/{lib,main,preflight}.rs; crates/kernel/syscall/src/nt_exec.rs; kernel nt_exec intake and thread-group catalog ownership. Read rootfs staging as a consumer contract. Coordinator reserves shared ABI/Cargo/root module edits.

**Deliver:**

- Define one agreed record/buffer lifetime contract with P2 before coding; current NtExecUnixlib is 48 bytes and request is 96 bytes in the existing ABI tests.
- Build owned source records for the required Unixlib dependency closure, including native DT_NEEDED dependencies obtained through userspace runtime policy. Copying only Wine-directory *.so files may omit system libraries.
- Prove paths, names, lengths, record counts, aggregate memory budget, address stability, duplicates, missing dependencies, and integer bounds. Do not widen limits without a demonstrated fixture requirement.
- Exercise --launch and --preflight through the same request construction contract. A path appearing in configuration or environment is not proof it enters the request.
- Preserve native NTDLL ownership; zero Unixlibs may be valid for an explicitly PE-only request but cannot be used to make the Notepad request compile without its dependencies.
- Split existing oversized implementation files into focused children as required; reserve parent manifest edits with coordinator.

**Tests:** real-fixture request construction, record buffer lifetime after moving the owner, absent/malformed/transitive dependency, ABI offsets and counts, host unsupported-selector classification, preflight/launch agreement. Tests requiring real fixtures fail explicitly when absent.

**Exit:** launcher compiles; valid Notepad request contains the agreed ELF closure; a deliberately omitted required source fails the contract. Deliver exact test counts and the coordinator-owned downstream call site.

## 6

P2: Unixlib load, initialization and call/return.

**Read:** crates/kernel/exec/src/unixlib.rs and unixlib/{context,loader}.rs; exec/src/elf_modules.rs; shared ELF catalog/relocation owners; syscalls/src/nt_loader_dir/dynamic.rs; nt_wine_unix.rs; scheduler catalog state.

**Audit before implementing:**

| Boundary | Required question / experiment |
|---|---|
| Catalog selection | Does the live LoadSoDll path consume the exact catalog copied at exec? Trace both fixed-directory and catalog-based paths |
| Identity and lifetime | What identifies each loaded module/table? Can two Unixlibs coexist without overwriting one descriptor? |
| Dependency closure | Can actual ntdll/win32u sidecars and their native dependencies be admitted? Record first missing object/symbol/relocation |
| Runtime initialization | Who supplies ELF TLS, constructors, symbol versions, weak symbols, cyclic dependency handling and resolver behavior when required? Mapping PT_LOAD is insufficient |
| Callable table | Who locates, relocates, validates and publishes the actual function table, and hands its identity to PE code? |
| Entry/return | Does native ELF code run in user mode with correct ABI, stack, TLS state and continuation? What happens on nested calls and faults? |
| Transactions | Does failed relocation, registration or output copy undo new mappings/state without damaging previously loaded objects? |
| Cleanup | Does process exit retire tables/mappings and prevent stale-handle use? |

**Implementation:** use one canonical source/loaded-module owner; remove the competing lookup route only after proving its consumers are covered. Keep kernel shims within 53§4/53§12. Do not implement a second dynamic linker in syscall handlers or route userspace function pointers through kernel execution.

**Proof:** real-object closure tests, failed dependency rollback, two-module identity, invalid table pointer/slot, unmap cleanup, and an integration test invoking production load-to-publication wiring. A synthetic table-registration unit test alone cannot close this package.

**Decision checkpoint:** if real objects require absent runtime/linker facilities, enumerate them and revise the timeline immediately. Do not label this a three-field initializer fix.

## 7

P3: startup and NT behavior.

**Read:** exec/src/tests/pe_loader.rs; PE loader/initializer/process environment and native stubs; syscalls PE commit and dispatch; corresponding scheduler and x86 context owners. Read 54 before assembly/context edits.

Build a reachable-call census:
module → imported/dynamic symbol → thunk → live dispatch → subsystem operation → required behavior → test → unresolved case.
Distinguish exported, mapped, dispatched, semantically implemented, and guest-observed states.

Audit initializer ordering, DLL process attach, TLS callbacks, PE stack/shadow space/nonvolatile registers, PEB/TEB/process parameters, application entry continuation, and normal exit. Check thread-local assumptions across Linux launcher, NT process and ELF Unixlib calls.

Audit callback dispatch from USER and exception/APC delivery through existing scheduler queues. Verify installed callbacks are executed and return to the right frame; queue insertion and a stored callback address are insufficient. Implement measured required gaps under one owner per area.

Do not enumerate every NTDLL export as a prerequisite merely because it appears in a DLL's import table. Imports must resolve honestly; runtime-required behavior must work fully. Never fabricate success for a reachable unsupported call.

Exit: named live call sites and behavioral evidence for startup/required services/return/exit; precise open cases and dependencies handed to coordinator.

## 8

P4: visible GUI, input, acceptance machinery.

**Read:** syscalls/src/nt_wine_window* and nt_window*/nt_gdi*; canonical IPC window manager, GDI/DRM/input owners; windows-user32 and windows-gdi probes; tools/test-windows-notepad-harness.sh; tools/boot-smoke.sh; Makefile Notepad target and rootfs staging.

Trace:
Wine user32/win32u call → native window object → window procedure delivery → edit-control state → paint/DC/font → presented surface → actual display/compositor → physical input → focused window queue.

Answer whether current native surfaces are composed into the guest desktop. An existing GNOME session and a native GDI surface do not establish that connection. Name the compositor/backend and the real production consumer. Allocate a separate implementation lane if missing.

Keep one owner for window queues, focus, capture, timers, paint invalidation and destruction. Separate GDI/font/display edits from window-manager edits only after assigning files and agreeing the boundary.

Acceptance tooling must:
- enable an inspectable graphical display or capture from the actual guest display;
- identify the Notepad PID/window, match input to that window, capture rendered token, and observe normal process exit;
- preserve logs/images before terminating QEMU;
- disable automatic boot retries for final acceptance;
- correlate evidence to one run and process; reject fabricated/reordered marker logs in host tests;
- distinguish entering a syscall from its successful completion.

Existing boot-smoke.sh forces headless mode and defaults OXIDE_SMOKE_ATTEMPTS to 3. Existing Makefile markers stop at GDI present. Implement and host-test the required acceptance changes before final launch; the existing target alone does not satisfy §10.

P4 begins as an audit concurrently with P1/P2. GUI/display work is mandatory for Notepad even if no optional Vulkan/audio work is needed.

## 9

P5: registry, files and remaining handoff work.

| Status | Assignment | Existing evidence / required proof | Branch |
|---|---|---|---|
| READY | Registry startup | Use canonical registryd; exercise actual launch paths/socket/environment and startup key needs | unassigned |
| READY | Hive persistence follow-up | Review destination truncation with longer prior contents; validate through VFS adapter and durable reopen, not only registry serialization | unassigned |
| READY | Registry service lifetime | Wrapper exec replaces its shell; audit whether EXIT trap can clean registryd after application exit; choose explicit service/supervisor ownership | unassigned |
| READY | Scatter/gather audit | Both adapters exist; verify live dispatch, actual VFS transfer, status/error ordering, short I/O and completion | unassigned |
| READY | File lifecycle | Open/share/delete/section lifetime and ordinary file I/O through the canonical inode/open description | unassigned |
| WAITING | Measured service repairs | Promote only confirmed startup/interaction/exit blockers into Notepad dependency chain | unassigned |

Scatter/gather and hive save/load remain programme work even when Notepad does not call them. Do not serially gate the first launch behind unrelated API completion. File save/reopen can be a separate acceptance checkpoint; the requested first visible Notepad test uses typing and discard-on-close.

## 10

Acceptance contract; coordinator fills concrete artifact paths before launch.

| Status | Checkpoint | Required evidence | Branch |
|---|---|---|---|
| WAITING | A0 Reproducible candidate | Source SHA, clean status, kernel/image/runtime hashes, guest launch command, fixture manifest | integration |
| WAITING | A1 NT process executes | Real fixture identity plus user-mode execution beyond PE frame installation; process/personality correlated | integration |
| WAITING | A2 Window visible | Screenshot/framebuffer capture showing this Notepad window from actual display; successful window/present events correlated | integration |
| WAITING | A3 Input round trip | Inject unique token through guest input; screenshot shows token in edit control after message dispatch and repaint | integration |
| WAITING | A4 Normal close | Close through UI; handle discard dialog if needed; process exit status/reaping and window destruction; no crash substituted for exit | integration |
| WAITING | A5 Runtime cleanup | Registry/service ownership respected; required handles/mappings released; no orphan launch-owned process | integration |
| WAITING | A6 Regression evidence | Both kernel gates; required common Linux smoke on both architectures; Windows workload x86_64 only | integration |

Markers are diagnostics. A fixed total marker order must not reject legitimate asynchronous message/paint interleavings; assert required causal order within the same process/window. No kernel output means execution is unobserved: investigate artifact/launch/serial capture before attributing it to NT admission.

No prior screenshot, alternate smoke process, host Wine window, successful resource preflight, or mocked PE substitute counts.

## 11

Worker brief template, issued by coordinator:

~~~text
Package:
Base SHA:
Branch/worktree:
Absolute CARGO_TARGET_DIR:
Read first:
Exact files allowed:
Shared files reserved to coordinator:
Observed defect and reproducer:
Requested implementation or read-only investigation:
Production entry and downstream consumer:
Required tests / positive control:
Dependencies and sibling interfaces:
Do not commit/push/PR/merge/boot/edit ledger or shared files.
At 45–60 minutes report: finding, changed paths, tests/exits/counts,
next dependency, remaining estimate, and any ownership conflict.
Return early when a decision requires coordinator resolution.
~~~

Coordinator protocol:
1. Claim branch counters with tools/next-branch.sh --claim, not guessed names; claim existing issue rows. Create worker worktrees centrally. Verify no existing lane owns the item.
2. Independent readers may start immediately. Serialize only shared ABI decisions, shared manifests, wiring, and git integration.
3. Use tools/lane-health.sh when progress is uncertain; inspect locks and compilation before interpreting silence.
4. At 60–90 minutes review worktree age and remaining work. The current guard measures administrative gitdir mtime; a fetch alone may not satisfy it. Reconcile through legitimate completion/recreation or supported policy workflow, preserving work. Do not touch timestamps or raise the limit to evade the guard.
5. Stop editing before handoff; coordinator reviews complete delta, applies production call sites, runs boundary tests and positive-controls each new hook.
6. Stage explicit files; commit/push/PR/merge are coordinator-only. Required hooks remain active. Follow CLAUDE.md's narrow documented procedure for independently proven pre-existing gate failures.
7. Every lane's own worktree is removed only after handoff, clean status and verified integration. Preserve unmerged commits; no forced cleanup.
8. Refresh main with git switch main and git pull --ff-only origin main. Never checkout origin/main as the idle primary state. No detached HEAD.
9. Update plan status/branch and canonical issue rows as each package changes state.

Publication follows repository PR policy. Subsystem changes need applicable frozen specs first; plan updates do not grant exceptions. Kernel-visible changes require their final both-arch verification before publication. Plan small coherent PRs around those gates; do not silently accumulate unverified merges to save boots.

## 12

P6: integrate and verify.

Use the pinned toolchain in rust-toolchain.toml. Execute focused tests per lane first. Existing commands below are starting gates; select exact filters after inspecting current test names. Do not equate --check compilation with execution.

~~~sh
./tools/test-windows-notepad-harness.sh
./tools/test-windows-nt-transition-harness.sh
cargo test --manifest-path userspace/probes/Cargo.toml -p windows-runtime -p windows-registry -p windows-user32 -p windows-gdi
cargo test -p pe -p elf-load -p syscall -p syscalls -p sched -p ipc --lib -- --test-threads=1
cargo run --quiet -p xtask -- kernel --arch x86_64 --check
cargo run --quiet -p xtask -- kernel --arch aarch64 --check
python3 -m py_compile tools/windows-notepad-acceptance.py
cargo test -p xtask --quiet
./tools/windows-notepad-acceptance.py  # P7 only; one visible run, never during preparation
git diff --check
~~~

Also run applicable feature-gate, lint-ratchet/spec-lint, stack, hosted and repository Windows compatibility/transition gates required by hooks. Verify test selection exercised production owners. Test absent-fixture and disconnected-hook negative controls in isolated worktrees; restore before collecting final results.

Run independent architecture checks concurrently with unique target directories and capture each PID's exit separately. Bare shell wait is not aggregate pass/fail evidence. Keep image/artifact exports serialized.

Before guest execution:
- all required non-boot gates green on the candidate;
- all required real ELF/PE inputs admitted, resolved and wired;
- actual GUI backend/input/normal-close harness ready;
- no unexplained runtime initialization/callback/return gaps;
- rootfs staging verified offline, including native dependency closure and matching hashes;
- final command, display transport, captures, stop condition and one-attempt setting recorded.

Do not use the previous plan's unverified “make kernel boot” command sequence. Inspect current Makefile/xtask build, image, and launch targets; separate artifact preparation from starting QEMU. Do not accidentally launch a preliminary guest while preparing the final one.

## 13

P7: final verification.

Use `tools/windows-notepad-acceptance.py` for one final visible x86_64 Notepad run after §12. It uses private UART/QMP sockets, QMP `screendump`/`send-key`, OCR, and the wrapper exit marker; it prints `attempts=1` and does not retry. Record the literal invocation before executing. Do not run the unchanged headless smoke and then a second visual boot merely to obtain the missing screenshot.

The Windows workload is x86_64. Shared kernel changes still require the common Linux x86/ARM regression gates under CLAUDE.md. Run those final checks as required, with isolated images and no resource contention. Distinguish these regression boots from the single Notepad acceptance run; ARM compile-only Windows scope does not waive common-kernel smoke policy.

Verify candidate hashes/paths and current git state immediately before launch; mtime alone is insufficient. Check live QEMU/image ownership; never kill sibling processes. Capture §10 evidence, stop after normal application exit, and retain the serial/display artifacts plus exact runner exit.

On failure: preserve the earliest actionable event and its process/module context; diagnose from captures and a focused hosted/target-aware harness. Do not repeat exploratory boots, rename the same failed attempt as a new lane, or reduce acceptance. A repaired candidate receives final verification only after its own gates pass.

If a missing architectural facility is exposed, record scope/owner/estimate and keep independent authorised work progressing. Report the Notepad objective incomplete.

## 14

Schedule from execution start T0; rebase estimates after discovery rather than retaining expired wall-clock slots.

| Status | Window / budget | Work and decision | Branch |
|---|---|---|---|
| VERIFIED | Baseline window | P0 acceptance contract and P1 catalog producer are complete on the coordinator branch; P2/P4 audits identified the native loader/TLS boundary and existing virtio-GPU presentation owner | D1550-notepad-masterplan |
| ACTIVE | Current | P2 production wiring is green through named table publication and architecture-specific entry transfer. Kernel bootstrap now publishes canonical TEB/PEB addresses to the native launcher; source-built Wine NTDLL and win32u compile and stage into the default image, and the launcher calls the explicit attach ABI before loading win32u. The corrected ext4 path reaches GNOME in roughly 25 seconds without the prior `block::submit_wait::wait_done` soft lockup. A controlled run proved atomic KMS and Bochs presentation (`DRM-ATOMIC` and `BOCHS-PRESENT ... ok`), then launched the real staged Notepad PE. The remaining blocker is `NtUserCreateWindowEx` (0x136b): Notepad reaches class registration and `NtUserGetClassInfoEx` (0x13d8), but exits status 1 before `[WINDOWS-USER32] create-window`; raw stack-argument tracing is active for the next ABI fix. | D1550-notepad-masterplan |
| ACTIVE | After runtime-owner design | Registration/bootstrap owner is implemented and target-built; next is integration against the guest image, then resolve the first runtime fault without bypassing the owner | integration |
| WAITING | Next 1–3h, conditional | Full gates, offline image, and one final guest acceptance run after bootstrap/PE execution is observed | integration |
| WAITING | Final 0.5–1.5h allocation | Required final verification and capture/review; actual build and boot durations measured locally | integration |

Current go/no-go (2026-09-06, supersedes the historical ACTIVE row above): NOT READY FOR GUEST ACCEPTANCE. Same-task native child-thread attachment and synchronous creation callback completion are implemented and hooked, not guest-verified. Raw GDI execution, native text callback, keyboard semantics and desktop backend integration remain active. Both architecture gates must be rerun after integration; no reliable completion time is established.

Current parallel implementation ownership:

| Lane | Owner | Deliverable |
|---|---|---|
| Native font measurements | Averroes | Stock-font metadata and real width scaling implemented; text callback ABI/return-policy verification |
| GDI client ABI | Pascal | Canonical handle-table/DC_ATTR publication, shared-field access and serialized object lifetime transactions |
| Desktop backend | Nash | Backend 21 tests and real Xvfb Position positive control passed; auditing actual image Notepad startup callers |
| Window positioning | Curie | Cross-thread inbox/callback cancellation and canonical owned-popup ordering; main integrates retrieval hooks |
| Shared ABI / ARM callbacks | Bernoulli | Client codec 10 tests with pinned C fixture passed; ARM continuation/live callback integration |
| Brushes / object queries | McClintock | Canonical brushes and raw ingress wired; shared brush attributes and PE object queries |
| Integration | Main | raw ABI hooks, launcher, normal image staging, production GUI/GDI hooks and final verification |

Bridge contract: `docs/31gd-windows-compositor-bridge.md` (FROZEN). No new boot until production integration and nonboot gates are ready. Existing root images contain the DLL catalog and Notepad but do not yet contain this newly implemented bridge. Never report source staging changes as an already rebuilt image.

Latest integration: 397 IPC and 2314 hosted syscalls tests passed before the next lifetime/remote-position hooks. x86/ARM debug-preempt checks passed the synchronous position/measurement integration; subsequent checks caught in-progress cross-thread parent hooks, so current tree is not yet final-green. Stock/brush modules, default SYSTEM_FONT selection, raw brush routes, seven-argument position routing and desktop Position stream are now connected. Position validation defect control failed then restored green. ELF staging checks actual image dependency closure before writes (compositor:21 edges verified). Shared GDI publication is not yet connected to PFN initialization; no new image or guest acceptance. KI-0387 records corrected SetTextAlign method107, optional MoveTo output and COLORREF old-value behavior.

Latest integration correction: KI-0386 blocks PE drawing before NtGdi ingress: gdi32 validates typed HDC identity and client DC_ATTR through PEB.GdiSharedHandleTable, but canonical DCs were untyped integers. Canonical typed allocation now reserves fixed slots and fails on exhaustion; client publication/attribute ownership remains under implementation. Raw/descriptor text execution hooks are connected, but do not establish PE GDI compatibility. Actual image source is Wine 10.20; nearby `../windows_reference/wine-source` is 11.16 and cannot alone verify this image's ABI. Native text measurements must match the raster font, not the previous width-zero-to-one-pixel estimate. No guest acceptance or rebuilt-image claim.

Integration evidence during this wave: shared syscall 268 tests, hosted syscalls 2261 tests (serial), native text rendering 7 tests, and xtask Notepad staging 5 tests passed. Both debug-preempt architecture checks need rerunning after final hooks. GDI frame and glyph alpha positive controls failed as expected and production code was restored. Launcher uses an inherited duplex socket, pre-PE capability binding and a bounded desktop handshake. Normal staging now builds windows-compositor; its XCB/XKB libraries are present in the existing image, with final binary dependency closure still to audit. Compositor gap tracked as KI-0384. `/tmp` is a 32GB tmpfs and filled during builds; owned build caches moved to NVMe `target/codex-lanes`, without deleting source or root images. Raw/descriptor ReleaseDC now share canonical lease release and BOOL conversion (KI-0385); raw release previously deleted the DC.

Second integration wave: Pascal now connects PE raw/descriptor GDI calls (including nine-argument NtGdiExtTextOutW) to the canonical owner; Averroes connects the existing userspace RasterFont renderer through same-task callback spec31ge. Main added canonical DC text attributes/snapshots, not another HDC registry. Curie implements SetWindowPlacement; Notepad main.c832 uses it to show the main window. Bernoulli implements backend key translation; McClintock implements keyboard-state queries and single-delivery text semantics; Nash completes actual X11 child/owned-window handling, zero-sized status-bar backing and private-Xvfb tests. Native acceptance now requires a real desktop frame ACK, not an unrelated Wine-server RPC; screenshot/token deletion/close/exit requirements remain. Its UART launch inherits the actual unique GNOME process environment via the verified image-owned nsenter tool.

Latest evidence: `target/windows-notepad-acceptance/uart-3157571.log` and `target/boot-logs/x86_64-20260906-011913.log` prove GNOME/KMS and the real PE handoff; `target/windows-notepad-acceptance/uart-3172254.log` records the 17-argument `NtUserCreateWindowEx` call and status 1 before window creation. The image staging log reports `PE_DLLS=620 UNIXLIBS=36`, with Oxide-owned `ntdll.so`/`win32u.so` replacing the stock Unix pair. The debug-boot variant independently halted in devpts smoke and is not acceptance evidence. Do not claim GUI success until a run reaches window creation, message loop, paint, present, input, and status 0.

Evidence correction, 2026-09-06: `create-reject-trace` again hung during journald mkdir; boot reliability is OPEN. Its exact ELF places watchdog PC `ffffffff8004e8a4` in block completion polling with one preemption-disable credit. Rank 40 is the inode class, not the sleepable GDT mutex. Compiled VFS instantiation and anonymous-security callbacks retain their registry spinlocks across callbacks, including filesystem xattr reads (KI-0379). Fix and regression checks are in progress; the retained log has no caller stack, so causation is not stack-proven. A separate rwsem admission race is repaired with compare-exchange (KI-0378); 407 VFS tests pass and the stale-reader regression fails when the faulty store is restored. Canonical mkdir parent-link persistence and geometry remain under repair. Raw create HWND failures now return NULL; default-placement geometry remains open. No new boot acceptance is claimed.

Read-only image verification: both `target/builds/default/root-x86_64.img` and `target/builds/create-reject-trace/root-x86_64.img` contain 620 DLLs, AMD64 PE32+ Notepad, 36 Unixlibs, 76 NLS files, launcher, registry service/seed, configuration, wrapper, desktop entry and MIME associations. The two custom Unix libraries match source-build hashes. Both conventional Wine catalog symlinks resolve to the staged catalog. Kernel-owned synthetic NTDLL intentionally replaces `ntdll.dll`; empty DXVK/vkd3d-proton/FAudio directories do not establish those runtimes are implemented. Plain `make qemu-x86` stages this boundary unless rootfs staging is explicitly skipped.

Estimates exclude unidentified architectural implementations. Fanout shortens independent work, not serial ABI design, integration, or shared-machine build time.

## 15

Broader programme backlog; each row requires a current-code audit before implementation. Complete Notepad first unless a dependency is reached earlier. These are unfinished programme obligations, not a claim they can all finish today.

| Status | Package | Acceptance direction | Branch |
|---|---|---|---|
| TRACKED | NT exceptions/APCs/remote threads | Real target context delivery, continuation and cleanup beyond the exercised Notepad path | unassigned |
| TRACKED | File/registry breadth | Full scatter/gather, async completion/cancel, sharing/delete and durable hive contracts | unassigned |
| TRACKED | Vulkan/DXVK/vkd3d | Actual loader/device/present path and resource lifetime, not capability flags alone | unassigned |
| TRACKED | Audio | Device discovery, playback/capture buffers, format validation and shutdown through native audio | unassigned |
| TRACKED | Input/XInput | Focus/capture, keyboard/mouse/controller translation, disconnect and feedback through native input | unassigned |
| TRACKED | Winsock/DNS | Actual connect/send/receive, readiness, overlapped completion/cancel and resolver outcomes | unassigned |
| TRACKED | Steam/Proton launch | Runtime record-to-process wiring with actual dependency/catalog consumption | unassigned |
| TRACKED | NT surface completeness | Reachable semantic gaps traced to owning subsystem with full behavior tests | unassigned |

Maintain one source of truth in the canonical ledger; link rows as claimed. Detailed design of uninspected packages requires its own evidence, not speculative function lists.

## 16

Next executor's first action:

~~~sh
git status --short --branch
git worktree list
git branch -a
tools/issues.sh --query 'grep=Notepad|Unixlib|NtExecRequest'
~~~

Then claim P0/P1 centrally and start read-only P2/P3/P4 fanout. Re-read all changed code from the recorded base. Updating this plan is not authorization to report implementation completed.

Final report records: source/merge SHA; package states; actual tests and exit codes; verified production call sites; actual guest observations; artifact paths/hashes; remaining gaps. Only mark Notepad complete when every §10 checkpoint is satisfied.
