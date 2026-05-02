# 09 Abbreviations — v2 deferred entries

Carried from `docs/09-abbreviations.md` at freeze 2026-05-02 per `02§9.8`.

## Machine-checked `# C:` annotations

v1 lints `# C:` presence only (via `tools/spec-lint/` `code/pub-fn-complexity`). Parsing the body for cost-class match against a measured benchmark is a v2 ratchet. Add when bench-history exists and drift becomes visible.

## TOML/JSON sidecar manifest per spec

A separate machine-readable manifest (status/deps/frozen-date) next to each doc. Doc front-matter (`Status: ...` line) currently serves the same purpose with one fewer file per spec. Revisit if multi-tool pipelines need structured access.
