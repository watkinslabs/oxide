//! NTP clock discipline (`adjtimex(2)` / `clock_adjtime(2)` backend).
//! - `uapi`: `ADJ_*` / `STA_*` / `TIME_*` numbers and the discipline scaling constants.
//! - `model`: `NtpState` (Linux `struct ntp_data`), the PLL/FLL math, `second_overflow`, validation.
//! - `state`: the canonical instance, `do_adjtimex`, and the per-tick advance.

pub mod uapi;
pub mod model;
mod state;

pub use model::{AdjError, NtpState, Timex, validate};
pub use state::{do_adjtimex, ntp_advance, ntp_snapshot, AdjOutcome};

#[cfg(test)]
mod tests;
