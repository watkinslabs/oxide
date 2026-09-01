# Manifest

Authoritative index of every spec. Per `02§6`. Status changes update both file and this index in same commit.

## Charters

| File | Status | Frozen | Depends |
|---|---|---|---|
| `00-master-plan.md` | DRAFT | — | — |
| `01-glossary-and-types.md` | FROZEN | 2026-05-02 | `02`,`08`,`09` |
| `02-spec-discipline.md` | FROZEN | 2026-05-02 | — |
| `03-modernity.md` | FROZEN | 2026-05-02 | `02`,`08` |
| `04-performance.md` | FROZEN | 2026-05-02 | `02`,`08` |
| `05-pre-mortem.md` | DRAFT | — | `00`,`03`,`04` |
| `06-memory-model.md` | FROZEN | 2026-05-02 | `01`,`02`,`08`,`09` |
| `07-toolchain-and-targets.md` | FROZEN | 2026-05-02 | `02`,`08` |
| `08-ai-density.md` | FROZEN | 2026-05-02 | `02` |
| `09-abbreviations.md` | FROZEN | 2026-05-02 | `08` |

## Subsystems

| File | Status | Frozen | Depends |
|---|---|---|---|
| `10-pmm.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`04` |
| `11-vmm.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`10`,`14`,`20`,`21` |
| `12-slab.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`10` |
| `13-sched.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`14` |
| `14-context-switch.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`07`,`08`,`09` |
| `15-syscall-abi.md` | FROZEN | 2026-05-02 | `01`,`03`,`06` |
| `16-vfs.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`12`,`15` |
| `17-block-and-pagecache.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`10`,`11`,`12`,`16` |
| `18-modules.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`08`,`09`,`11`,`15`,`27`,`31` |
| `19-dev-proc-sysfs.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`16`,`18`,`35` |
| `20-hal-x86_64.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`07`,`14`,`22`,`23`,`38` |
| `21-hal-aarch64.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`07`,`14`,`22`,`23`,`38` |
| `22-irq-and-exceptions.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`07`,`14`,`20`,`21` |
| `23-time.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`07`,`14`,`20`,`21`,`22` |
| `24-ipc.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`12`,`13`,`16`,`23` |
| `25-net.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`12`,`13`,`16`,`24`,`33`,`34` |
| `25a-conntrack-nat-vlan-bonding.md` | FROZEN | 2026-08-16 | `01`,`02`,`06`,`25`,`26`,`52` |
| `26-namespaces-cgroups.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`13`,`16`,`19`,`25`,`27` |
| `27-security.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`11`,`13`,`16`,`18`,`26`,`38` |
| `28-tty-pty.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`16`,`19`,`24` |
| `29-init-and-userspace.md` | FROZEN | 2026-05-02 | `01`,`02`,`13`,`15`,`16`,`19`,`28`,`31`,`39` |
| `29a-userspace-platform.md` | FROZEN | 2026-05-02 | `02`,`03`,`07`,`15`,`29`,`31`,`39`,`43` |
| `30-io-uring.md` | FROZEN | 2026-05-02 | `01`,`02`,`06`,`11`,`13`,`15`,`16`,`17`,`23`,`25` |
| `31-elf-loader.md` | FROZEN | 2026-05-02 | `01`,`02`,`11`,`12`,`16`,`18`,`27` |
| `31a-windows-pe-loader.md` | FROZEN | 2026-08-30 | `01`,`02`,`11`,`12`,`16`,`31` |
| `31b-windows-process-environment.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`11`,`14`,`31a`,`52` |
| `31c-nt-memory.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`11`,`31a`,`31b`,`53` |
| `31d-nt-syscall-abi.md` | FROZEN | 2026-08-31 | `01`,`02`,`15`,`31c`,`53` |
| `31e-windows-pe-exec.md` | FROZEN | 2026-08-31 | `01`,`02`,`11`,`13`,`14`,`31a`,`31b`,`31c`,`31d`,`52`,`53` |
| `31f-windows-nt-objects.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`52`,`53` |
| `31g-windows-nt-synchronization.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31f`,`52`,`53` |
| `31h-windows-ntdll-runtime.md` | FROZEN | 2026-08-31 | `01`,`02`,`31a`,`31b`,`31d`,`31e`,`52`,`53` |
| `31i-windows-nt-wait-multiple.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`52`,`53` |
| `31j-windows-nt-sections.md` | FROZEN | 2026-08-31 | `01`,`02`,`11`,`13`,`31c`,`31d`,`31f`,`52`,`53` |
| `31k-windows-nt-process-query.md` | FROZEN | 2026-08-31 | `01`,`02`,`13`,`31b`,`31d`,`31f`,`31h`,`52`,`53` |
| `31l-windows-nt-thread-create.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31b`,`31d`,`31f`,`31g`,`31k`,`52`,`53` |
| `31m-windows-nt-thread-lifecycle.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31b`,`31d`,`31f`,`31l`,`52`,`53` |
| `31n-windows-thread-environment.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31b`,`31l`,`31m`,`52`,`53` |
| `31o-windows-thread-handle-targets.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31f`,`31k`,`31m`,`52`,`53` |
| `31p-windows-runtime-module-catalog.md` | FROZEN | 2026-08-31 | `01`,`02`,`31a`,`31h`,`52`,`53` |
| `31q-windows-pe-forwarders.md` | FROZEN | 2026-08-31 | `01`,`02`,`31a`,`31h`,`31p`,`52`,`53` |
| `31r-windows-nt-heap.md` | FROZEN | 2026-08-31 | `31d`,`31h`,`52`,`53` |
| `31s-windows-pe-initialization.md` | FROZEN | 2026-08-31 | `31a`,`31e`,`31p`,`31q`,`52`,`53` |
| `31t-windows-window-messages.md` | FROZEN | 2026-08-31 | `31g`,`31s`,`46`,`52`,`53` |
| `31u-windows-nt-window-abi.md` | FROZEN | 2026-08-31 | `31d`,`31t`,`46`,`52`,`53` |
| `31v-windows-nt-unwind.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31h`,`52`,`53` |
| `31w-windows-nt-semaphores.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`52`,`53` |
| `31x-windows-nt-paths.md` | FROZEN | 2026-08-31 | `01`,`02`,`16`,`31d`,`31h`,`52`,`53` |
| `31y-windows-runtime-exec-handoff.md` | FROZEN | 2026-08-31 | `01`,`02`,`31a`,`31e`,`31h`,`31p`,`52`,`53` |
| `31z-windows-nt-mutants.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`31h`,`52`,`53` |
| `31aa-windows-nt-completion-ports.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`31h`,`52`,`53` |
| `31ad-windows-nt-tokens.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31f`,`31h`,`52`,`53` |
| `31ae-windows-nt-rtl-strings.md` | FROZEN | 2026-08-31 | `01`,`02`,`31d`,`31h`,`52`,`53` |
| `31af-windows-nt-object-query.md` | FROZEN | 2026-08-31 | `01`,`02`,`31d`,`31f`,`31h`,`52`,`53` |
| `31ag-windows-nt-rtl-ansi-strings.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ah-windows-nt-security-query.md` | FROZEN | 2026-08-31 | `01`,`02`,`31f`,`31h`,`31ad`,`52`,`53` |
| `31ai-windows-nt-performance-counter.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31aj-windows-nt-security-ace.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ak-windows-nt-rtl-acl-read.md` | FROZEN | 2026-08-31 | `01`,`02`,`31aj`,`52`,`53` |
| `31al-windows-nt-rtl-text-detection.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31am-windows-nt-status-errors.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31an-windows-nt-critical-sections.md` | FROZEN | 2026-08-31 | `01`,`02`,`31g`,`31h`,`52`,`53` |
| `31ao-windows-nt-critical-section-enter.md` | FROZEN | 2026-08-31 | `01`,`02`,`31g`,`31h`,`52`,`53` |
| `31ap-windows-nt-vsnprintf.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31aq-windows-nt-rtl-size-heap.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ar-windows-nt-exit-user-thread.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31as-windows-nt-unbiased-interrupt-time.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31at-windows-nt-debug-ui-object.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31au-windows-nt-remote-breakin.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31av-windows-nt-ldr-get-dll-directory.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31aw-windows-nt-ldr-get-procedure-address.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ax-windows-nt-ldr-set-dll-directory.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ay-windows-nt-add-atom.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31az-windows-nt-assign-process-job.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ba-windows-nt-create-job.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bb-windows-nt-create-mailslot.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bc-windows-nt-delete-atom.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bd-windows-nt-device-io-control.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31be-windows-nt-fs-control.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bf-windows-nt-open-job.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bg-windows-nt-power-information.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bh-windows-nt-query-job.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bi-windows-nt-query-section.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bj-windows-nt-query-system.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bk-windows-nt-query-system-time.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bl-windows-nt-set-debug-info.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bm-windows-nt-set-job-info.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bn-windows-nt-set-process-info.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bo-windows-nt-set-thread-info.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bp-windows-nt-thread-execution-state.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bq-windows-nt-terminate-job.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31br-windows-nt-peb-lock.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bs-windows-nt-rtl-atom-table.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bt-windows-nt-ansi-unicode.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bu-windows-nt-capture-context.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bv-windows-nt-char-integer.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bw-windows-nt-atom-table-create.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bx-windows-nt-heap-create.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31by-windows-nt-unicode-create.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31bz-windows-nt-atom-delete.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ca-windows-nt-wait-deregister.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cb-windows-nt-atom-table-destroy.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cc-windows-nt-heap-destroy.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cd-windows-nt-dos-path-type.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ce-windows-nt-dos-path-status.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cf-windows-nt-exit-process.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cg-windows-nt-process-heaps.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ch-windows-nt-heap-user-info.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ci-windows-nt-image-header.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cj-windows-nt-critical-init.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ck-windows-nt-dos83.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cl-windows-nt-atom-lookup.md` | FROZEN | 2026-08-31 | `01`,`02`,`31bs`,`31h`,`52`,`53` |
| `31cm-windows-nt-oem-unicode.md` | FROZEN | 2026-08-31 | `01`,`02`,`31bt`,`31h`,`52`,`53` |
| `31cn-windows-nt-wait-registration.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cp-windows-nt-thread-error.md` | FROZEN | 2026-08-31 | `01`,`02`,`31b`,`31h`,`52`,`53` |
| `31cq-windows-nt-search-path-mode.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cr-windows-nt-unhandled-filter.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31h`,`52`,`53` |
| `31cs-windows-nt-heap-user-value.md` | FROZEN | 2026-08-31 | `01`,`02`,`31d`,`31h`,`52`,`53` |
| `31ct-windows-nt-time-fields.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31cu-windows-nt-unicode-ansi-size.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`52`,`53` |
| `31cv-windows-nt-unicode-ansi.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`31r`,`52`,`53` |
| `31cw-windows-nt-unicode-integer.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ae`,`31h`,`52`,`53` |
| `31cx-windows-nt-unicode-oem-size.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`52`,`53` |
| `31cy-windows-nt-unicode-oem.md` | FROZEN | 2026-08-31 | `01`,`02`,`31cx`,`31h`,`31r`,`52`,`53` |
| `31cz-windows-nt-unicode-multibyte.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`31r`,`52`,`53` |
| `31da-windows-nt-unicode-multibyte-size.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`52`,`53` |
| `31db-windows-nt-unicode-oem.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`31r`,`52`,`53` |
| `31dc-windows-nt-upcase-unicode.md` | FROZEN | 2026-08-31 | `01`,`02`,`31ag`,`31h`,`52`,`53` |
| `31dd-windows-nt-wcsicmp.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31de-windows-nt-ctype-isalpha.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31df-windows-nt-ctype-islower.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dg-windows-nt-ctype-memcpy.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dh-windows-nt-ctype-memmove.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31di-windows-nt-ctype-memset.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dj-windows-nt-ctype-strcat.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dk-windows-nt-ctype-strchr.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dl-windows-nt-ctype-strcpy.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dm-windows-nt-ctype-strlen.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dn-windows-nt-ctype-strpbrk.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31do-windows-nt-ctype-strrchr.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dp-windows-nt-ctype-tolower.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dq-windows-nt-ctype-wcscat.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dr-windows-nt-ctype-wcschr.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31ds-windows-nt-ctype-wcscmp.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dt-windows-nt-ctype-wcscpy.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31du-windows-nt-ctype-wcslen.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dv-windows-nt-ctype-wcsncmp.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dw-windows-nt-ctype-wcsrchr.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dx-windows-nt-ctype-wcstoul.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31co-windows-nt-io-completion-callback.md` | FROZEN | 2026-08-31 | `01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`31h`,`31aa`,`31cn`,`52`,`53` |
| `31ab-windows-runtime-launcher.md` | FROZEN | 2026-08-31 | `01`,`02`,`29a`,`31a`,`31h`,`31p`,`31y`,`52`,`53` |
| `31ac-windows-registry-service.md` | FROZEN | 2026-08-31 | `01`,`03`,`29a`,`31ab`,`52`,`53` |
| `32-power-reset.md` | FROZEN | 2026-08-15 | `01`,`02`,`15`,`20`,`21`,`33` |
| `32a-suspend-resume.md` | FROZEN | 2026-08-15 | `01`,`02`,`06`,`13`,`15`,`20`,`21`,`23`,`32`,`33`,`35`,`54` |
| `32b-hibernation.md` | FROZEN | 2026-08-21 | `01`,`02`,`06`,`10`,`13`,`15`,`16`,`17`,`20`,`21`,`23`,`29`,`32`,`32a`,`35`,`36`,`52`,`54` |
| `33-firmware-tables.md` | FROZEN | 2026-05-02 | `01`,`02`,`19`,`20`,`21`,`34` |
| `34-pci-and-pcie.md` | FROZEN | 2026-05-02 | `01`,`02`,`11`,`19`,`22`,`33`,`35` |
| `35-drivers.md` | FROZEN | 2026-05-02 | `01`,`02`,`16`,`18`,`19`,`22`,`34` |
| `36-bootloader-handoff.md` | FROZEN | 2026-05-02 | `01`,`02`,`07`,`20`,`21`,`33`,`39` |
| `37-observability.md` | FROZEN | 2026-05-02 | `01`,`02`,`04`,`13`,`19`,`23`,`38` |
| `38-error-handling.md` | FROZEN | 2026-05-02 | `01`,`02`,`07`,`08` |
| `39-build-and-image.md` | FROZEN | 2026-05-02 | `02`,`07`,`29`,`36` |
| `40-ci.md` | DRAFT | 2026-05-07 | `02`,`05`,`07`,`39`,`42` |
| `41-debug-flags-catalog.md` | FROZEN | 2026-05-02 | `04`,`07`,`08` |
| `42-test-strategy.md` | DRAFT | 2026-05-07 | `02`,`05`,`06`,`07`,`08`,`40` |
| `43-acceptance.md` | FROZEN | 2026-05-02 | every spec |
| `45-virtio-gpu.md` | FROZEN | 2026-05-09 | `01`,`02`,`07`,`11`,`13`,`15`,`22`,`33`,`34`,`35`,`47` |
| `46-virtio-input.md` | FROZEN | 2026-05-09 | `01`,`02`,`07`,`13`,`15`,`22`,`34`,`35`,`50` |
| `47-drm-kms.md` | FROZEN | 2026-05-09 | `01`,`02`,`07`,`13`,`15`,`16`,`19`,`35`,`45`,`48` |
| `48-fbdev.md` | FROZEN | 2026-05-09 | `01`,`02`,`07`,`13`,`15`,`16`,`19`,`45`,`47` |
| `49-fbcon.md` | FROZEN | 2026-05-09 | `01`,`02`,`07`,`08`,`13`,`15`,`28`,`45`,`47`,`48`,`50` |
| `50-vt.md` | FROZEN | 2026-05-09 | `01`,`02`,`07`,`13`,`15`,`16`,`19`,`28`,`46`,`47`,`49` |
| `51-userspace-handoff.md` | DRAFT | — | `16`,`19`,`28`,`29`,`29a`,`31` |
| `52-repo-structure-and-ownership.md` | DRAFT | — | `02`,`07`,`08`,`39` |
| `52a-stage-a-ownership-classification.md` | DRAFT | — | `52` |
| `53-syscall-layering.md` | DRAFT | — | `02`,`08`,`13`,`15`,`52` |
| `54-asm-correctness.md` | DRAFT | — | `02`,`08`,`13`,`15`,`20`,`21`,`27` |

## Cross-cutting

| File | Status | Frozen | Depends |
|---|---|---|---|
| `boot-flow.md` | FROZEN | 2026-05-02 | `20`,`21`,`33`,`36`,`29` |
| `55-console-color-font.md` | DRAFT | — | `28`,`47`,`48`,`49`,`50` |
| `56-timers-and-registration.md` | DRAFT | — | `02`,`06`,`07`,`08`,`13`,`23`,`52`,`53` |
| `57-vt-emulator.md` | DRAFT | — | `01`,`02`,`07`,`08`,`28`,`49`,`50`,`55` |
| `58-virtio-snd.md` | FROZEN | 2026-06-12 | `01`,`02`,`07`,`15`,`16`,`18`,`19`,`22`,`34`,`35`,`50` |
| `60-udev-kernel-contract.md` | DRAFT | — | `01`,`02`,`03`,`06`,`13`,`15`,`19`,`24`,`27`,`35`,`47` |
| `67-host-share-filesystems.md` | DRAFT | — | `01`,`02`,`07`,`08`,`15`,`16`,`19`,`34`,`35`,`52`,`53` |
| `61-hda-audio.md` | FROZEN | 2026-08-15 | `01`,`02`,`07`,`15`,`16`,`19`,`22`,`34`,`35`,`52`,`58` |
| `62-removable-media-filesystems.md` | DRAFT | — | `01`,`02`,`07`,`08`,`09`,`16`,`17`,`52` |
| `63-selinux-mac.md` | DRAFT | — | `01`,`02`,`06`,`08`,`13`,`15`,`16`,`19`,`24`,`25`,`27`,`29` |
| `64-v4l2-video-capture.md` | DRAFT | — | `01`,`02`,`06`,`07`,`08`,`09`,`13`,`15`,`16`,`19`,`22`,`23`,`34`,`35`,`52`,`53`,`60` |
| `65-bluetooth.md` | DRAFT | — | `01`,`02`,`07`,`08`,`15`,`16`,`19`,`25`,`27`,`28`,`35`,`52`,`53` |
| `66-wireless.md` | DRAFT | — | `01`,`02`,`06`,`07`,`08`,`13`,`15`,`19`,`22`,`25`,`34`,`35`,`52`,`53` |
| `69-image-and-native-filesystems.md` | DRAFT | — | `01`,`02`,`07`,`08`,`09`,`16`,`17`,`52`,`53` |
| `44-phase-quick-reference.md` | DRAFT | — | `00`,`40`,`43` |
| `31dx-windows-nt-debug-header.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dx-windows-nt-debug-output.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dx-windows-nt-debug-strdup.md` | FROZEN | 2026-08-31 | `01`,`02`,`31h`,`52`,`53` |
| `31dy-windows-nt-guid-from-string.md` | FROZEN | 2026-08-31 | `01`,`02`,`31dx`,`52`,`53` |

## Deleted

| File | Deleted | Reason |
|---|---|---|
| `59-glibc.md` | 2026-08-01 (R88) | Specified a glibc-ABI libc + `ld-linux` written in this repo (`crates/user/*`, `xtask glibc`). That code is deleted; userspace is Fedora glibc composed from RPMs by the sibling `../images` repo. No surviving content — kernel-side ABI obligations live in `15`, `31`, `29a`. |

## Freeze order

Charter docs first (no inter-charter cycles): `02` → `08` → `09` → `01` → `06` → `07` → `04` → `03` → `38`. Then subsystem leaves: `14`,`23`,`22`,`33`,`36` (HAL/firmware leaves). Then HAL: `20`,`21`. Then mid: `10`,`12`,`11`,`13`,`15`. Then upper: `16`,`17`,`18`,`19`,`24`,`27`,`26`,`25`,`28`,`30`,`31`,`32`,`34`,`35`,`37`,`29`,`39`. Then `40`,`41`,`42`,`44`,`51`,`52`. Then `43` and `00`,`05` (kept DRAFT-as-living-docs).

Charter docs `00` and `05` deliberately stay DRAFT permanently — they are living docs (master plan and pre-mortem) that should evolve as facts change.

## Open Questions

- Tooling: `xtask doc-check` to verify this index matches filesystem and per-file `Status:` lines. Lean: implement when first spec freezes.
