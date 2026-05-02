# oxide2

A Linux-class kernel + minimal userspace, written in Rust.

Targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`. Userspace built for upstream `*-unknown-linux-musl` (per `docs/29a`). Linux-binary-compatible at the modern syscall ABI.

## Status

Pre-code. Spec corpus complete and internally consistent (46 specs, all DRAFT). Phase 0 build infra is next.

## Where to start

- `docs/00-master-plan.md` — top-level plan, phases, exit criteria.
- `docs/MANIFEST.md` — index of every spec.
- `docs/02-spec-discipline.md` — how specs evolve.
- `docs/03-modernity.md` — what's in v1 / what's deferred.
- `CLAUDE.md` — project rules for Claude Code sessions.

## License

TBD (lean toward MIT / Apache-2.0 dual; v1 issue).
