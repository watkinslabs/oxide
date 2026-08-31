# Windows PE export forwarders

FROZEN 2026-08-31. Dep:`01`,`02`,`31a`,`31h`,`31p`,`52`,`53`. Provides: bounded forwarded-export resolution for mapped PE module graphs.

## 1 Contract

- An export RVA inside the export directory is decoded as a forwarder string rather than a callable image address.
- Forwarders use `module.symbol` or `module.#ordinal`; module matching is case-insensitive and receives a `.dll` suffix when omitted.
- Graph resolution follows at most 16 hops and rejects malformed, cyclic, overflowed, or unresolved chains.
- Direct RVAs still resolve as assigned module base plus validated RVA.
- The legacy RVA-only query continues to reject forwarders, preventing accidental calls through encoded strings.

## 2 Tests

- direct and ordinal exports retain existing behavior;
- named forwarders resolve against the assigned destination module base;
- malformed and over-depth chains fail without producing an address;
- real Wine PE parsing remains in the normal Windows compatibility suite.
