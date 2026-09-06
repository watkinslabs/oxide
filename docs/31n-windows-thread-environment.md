# Windows thread environment

FROZEN 2026-09-06. Dep:`01`,`02`,`06`,`13`,`31b`,`31l`,`31m`,`52`,`53`. Provides: same-task native libc attachment and per-thread TEB allocation.

## 1 Contract

- The PEB and process parameters remain process-owned by the initial NT environment.
- Every `NtCreateThreadEx` child receives a distinct private TEB page in the shared address space.
- TEB self pointer, PEB pointer, process ID, thread ID, and TLS pointer are initialized before publication.
- x86-64 user GS base identifies TEB; FS remains libc-owned. AArch64 x18 identifies TEB; TPIDR_EL0 remains libc-owned. TEB is never a replacement native thread pointer.
- TEB mapping failure rolls back the user stack and leaves no runnable child.

## 2 Native factory

- Native ELF bootstrap registers factory and return entries in the existing process callback owner after source-built NTDLL attachment; no server or second registry.
- Raw NT create redirects its creator through the existing task callback continuation. The factory uses libc pthread creation; that clone Task is the sole child identity throughout preparation, attachment, publication and exit.
- Linux task publication required by pthread creation precedes NT handle publication. Preparing child executes native initialization only; failure returns through libc cleanup without PE entry. This refines `31l§1` for native ELF processes.
- Child preparation allocates private Windows stack/TEB on its existing mm, records task-owned PEB/TID and preserves libc TLS, robust-list and child-clear-TID ownership.
- Child reports ready only after source-built `wine_oxide_attach_thread` succeeds. Creator publishes NT handle and initial suspend count after readiness; child enters PE only after successful publication. Initial suspension parks at the ENTER return checkpoint before the first PE instruction, never inside preparation or the publication gate; no libc mutex is held across the gate.
- Failed attachment or handle writeback joins the pthread. Successful pthreads release libc resources through normal pthread return. TEB/Windows-stack mappings remain Task-owned until canonical kernel exit after libc TLS teardown; NTDLL's private pthread key cannot outlive its borrowed TEB.
- Enter saves the child's native continuation on its canonical Task. PE return and NT termination restore that continuation and return through libc; terminal kernel exit releases Windows mappings. Forced termination skips Windows callbacks; kernel never fabricates NPTL state or invokes libc from a raw child.
- Forced termination is consumed at return-to-user before suspension when interrupted PC belongs to a registered PE and no native factory continuation is active. Native ELF execution completes before consuming termination, preserving libc lock/cleanup ownership. Explicit PE-return consumes queued termination too. Kernel process destruction remains authoritative for fatal process-wide teardown; native cleanup is not run on a different Task.
- Private `NtQueryVirtualMemory` class `1006`, version `1`, carries factory registration, child prepare/ready, creator publication/completion, child enter/return/release. Its operations validate process ownership and task-owned creation phase before mutation.

## 3 Tests

- two thread environments in one address space have distinct bases;
- all published TEB pointers and IDs match the requested process/thread identity;
- x86-64 and AArch64 kernel checks compile the same publication path;
- the normal Windows compatibility suite includes the environment allocator tests.
- Native factory tests exercise real pthread TLS, same TID at preparation/attachment/entry, failed attachment rollback, suspended publication and native return cleanup.
