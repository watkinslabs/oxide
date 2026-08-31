# Windows NT thread creation

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31b`,`31d`,`31f`,`31g`,`31k`,`52`,`53`. Provides: initial current-process native thread creation for the NT personality.

## 1 Contract

- `NtCreateThreadEx` is appended at NT service ID `22`; earlier selectors remain stable.
- Only the current process target, non-suspended creation, and a user entry point are initially accepted.
- The kernel allocates a page-aligned private user stack in the caller's address space.
- The child is prepared unpublished, joins the caller's canonical `ThreadGroup`, inherits scheduler/security state, receives the caller's NT environment, then becomes visible and runnable.
- The thread handle retains the canonical scheduler task through the NT object table.
- The thread start parameter is placed in the architecture's first user argument register (`RCX` on x86-64, `X0` on aarch64).

## 2 Ownership

| Responsibility | Owner |
|---|---|
| task construction and architectural entry frame | `sched::live::spawn` |
| stack VMA | `mm-vmm` through NT adapter |
| thread identity and lifetime | `sched::Task` + `ThreadGroup` |
| process-local handle | `sched::nt_object` |
| ABI selector and pointer validation | `syscall::nt` |

## 3 Tests

- service ID `22` decodes without renumbering existing NT services;
- the bootstrap NTDLL page resolves `NtCreateThreadEx`;
- invalid process, entry, flags, and stack limits fail before publication;
- thread creation uses the existing unpublished-task publication sequence;
- the start parameter reaches the architecture-specific first argument register;
- Linux task and address-space paths remain unchanged.
