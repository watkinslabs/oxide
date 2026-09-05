# Phase 13 Winsock native DNS

`windows-winsock` now delegates every Windows address lookup to an injected
Linux/native resolver owner. The adapter rejects missing names, invalid hints,
empty answers, oversized result sets, and malformed canonical names without a
fallback resolver or local DNS state; native failures retain their Winsock
mapping and result order is preserved.

Evidence: 27 focused hosted tests pass. The positive control disabled the
missing-name guard and produced 1 failed test / 26 passed, then the guard was
restored and the suite returned to 27 passed. No boot was run; this is an
ungated userspace adapter decision.
