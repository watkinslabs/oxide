# Windows NT activation-context stack

FROZEN 2026-09-03. Dep:`01`,`02`,`13`,`31b`,`31f`,`31ff`,`52`,`53`. Provides: bounded per-thread activation-context nesting and lifetime.

## 1 Contract

- Activation-context identity and semantic references belong to one process's native object table; activation never creates a second context catalog.
- Every NT thread owns a bounded LIFO stack of context object references and nonzero opaque cookies. A normal deactivation may remove only the active frame; forced early deactivation removes the selected frame and every newer frame in top-to-bottom order.
- `RtlActivateActivationContext` targets the current thread. The `Ex` form may target a thread in the same process only when its exact published TEB is supplied.
- Activation acquires the object reference before publishing the frame. A full stack or faulting cookie output rolls the acquisition back without changing the previous active frame.
- `RtlGetActiveActivationContext` returns the active context with a new caller reference. Release, deactivation, explicit stack cleanup, and task teardown retire their references and remove the process-table identity only after the final reference.
- Each x86-64 TEB publishes its inline activation-stack address through `ActivationContextStackPointer`; AArch64 only compiles the shared ownership code and does not execute Windows workloads.
- Manifest section parsing and keyed-section lookup remain separate userspace/runtime work.

## 2 Verification

- scheduler tests cover nested LIFO order, early-deactivation rejection, forced removal, unknown cookies, the 64-frame bound, full-stack cleanup order, and final-reference retirement;
- activation-object tests cover add/release underflow and final-owner transitions;
- process-environment tests verify initial and created-thread TEB stack pointers;
- both kernel architectures compile, and the normal Windows compatibility suite covers the complete native runtime graph.
