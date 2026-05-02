# 08 AI-Density — v2 deferred entries

Carried from `docs/08-ai-density.md` at freeze 2026-05-02 per `02§9.8`.

## Density-score auto-summarizer

`tools/density-meter/` script: outputs prose-line-% per spec. Why deferred: `spec-lint` v0 has no density check; add as a `spec-lint` rule when drift is observed. No v1 gate depends on it.

## Pure-data spec format (TOML/JSON for invariants)

Tempting; loses cross-spec readability when prose and tables interleave. Revisit if spec re-reads start failing on JSON-only docs.
