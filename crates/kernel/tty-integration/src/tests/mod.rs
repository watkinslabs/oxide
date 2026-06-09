// T9 hosted integration net (tty-rebuild-plan §3-T9 + §4). Under
// `src/tests/` so spec-lint treats it as test-only (skips the production
// `# C:`/SAFETY checks); the whole module is `#[cfg(test)]`.

mod harness;
mod vt;
mod serial;
mod cross;
