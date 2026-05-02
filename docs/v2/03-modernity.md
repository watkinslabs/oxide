# 03 Modernity — v2 deferred entries

Carried from `docs/03-modernity.md` at freeze 2026-05-02 per `02§9.8`.

## 5-level paging

v1 lean = runtime-detect (CR4.LA57 on x86; aarch64 LPA2 symmetry confirmed). v2 may make 5-level the default once hardware ubiquity warrants.

## LSM hook surface

v1 = stubbed-surface (cheap; future-proofs). Landlock is direct-wired through the stub layer. v2 adds full SELinux/AppArmor-equivalent backends if user demand emerges.

## Wall-clock source

v1 = RTC + userspace NTP (chrony). v2 may add TPM-backed monotonic time when measurable trust-anchor demand exists.

## io_uring vs epoll

v1 keeps epoll permanently — level-trigger FD readiness is the correct tool for that workload class. io_uring covers async submission. Listed here because the question of "drop epoll" was raised; permanent-keep is the answer.

## BPF verifier

v1 ships without; v1.x adds a verifier subset. v2 considers a full Linux-equivalent verifier. Scratch-implement vs port not yet decided; revisit at v1.x scope.
