# Hand-off

Notepad runs and its acceptance passes on Wine 10.20. The whole campaign now
turns on one change: stop publishing our synthetic ntdll and ship Wine's own,
which is what unblocks Wine 11.16.

## The decision, settled from the reference

Our kernel publishes all 533 ntdll exports as kernel traps, `memcpy` included.
Only 264 are real system services; the other 373 are user-mode library code
Wine already ships. So we delete ours rather than relocate it.

The syscall edge costs nothing. Every `Nt*` stub tests `KUSER_SHARED_DATA`
offset 0x308 and then either runs a real `syscall` or calls Wine's dispatcher.
Wine's Unix side sets that byte because on Linux it cannot own the instruction.
We map the page in `exec/src/process_env/layout.rs:66` and never write 0x308,
so it is zero and stock stubs trap into us. No shim, no Wine patch.

What stays kernel-side is correct: win32u (`NtUser*`/`NtGdi*`, which is win32k)
and the `Nt*` services.

## In flight

- `B3578` (detached, on `C1573`): flips both ntdll deletion sites, reviews the
  three loader sites that assume the synthetic page is the module, and boots.
  Inventory it works from: `scratch/ntdll-user-mode-split.md`.
- `B3577`: `make feature-gate` red on both arches, the last red gate.
- `C1573-guest-runs-latest-wine` + packages `C1573-oxide-wine`: Wine 11.16
  built from pinned source and packaged as `oxide-wine`. Held unmerged on
  purpose, because with it Notepad stops launching until the ntdll change lands.

## Gate state

`test-build-gate` and the ledger check are green. `feature-gate` (KI-0319),
`stack-gate` (KI-0295) and `lint-ratchet` (KI-0021) are red on main; every
bypass this session cited its row and was verified on an unmodified checkout.

## Traps that cost time here

The surface gate reads the BUILD HOST's Wine catalog, not the image, so it can
report zero unadmitted while the image imports names it cannot see (KI-0701).
Run the acceptance detached or the memory guard kills it. Ledger ids collide
across parallel lanes; refile with `--add` at every rebase.

## First command

    tools/issues.sh --query status=OPEN sev=high
