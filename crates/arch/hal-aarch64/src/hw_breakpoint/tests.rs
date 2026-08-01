// Hosted coverage of every ungated layer. These encode the verified aarch64
// hardware-debug ABI contract, so a later change that drifts from it fails
// here rather than inside a debugger.
//
// Module manifest:
//   common — shared fixtures (ID register builder, control words, ESR, a task)
//   idreg  — slot-count decode, the boot cache, `dbg_info`
//   ctrl   — control-word field positions and the whole validation ladder
//   layout — regset byte offsets and buffer round-trip
//   state  — the per-task value type and its write ordering
//   exc    — debug-exception classification and si_code

mod common;

mod ctrl;
mod exc;
mod idreg;
mod layout;
mod state;
