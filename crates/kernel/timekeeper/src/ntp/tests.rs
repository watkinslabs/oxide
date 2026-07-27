// NTP discipline test manifest (docs/08§7).
// - `fixture`: shared `nominal()` / `query()` builders.
// - `validation`: `timekeeping_validate_timex` ladder — EPERM/EINVAL ordering.
// - `modes`: query semantics and every `ADJ_*` mode, including ADJ_TAI and the
//   legacy `adjtime(3)` single-shot channel.
// - `leap`: `second_overflow` leap-second state machine and dispersion growth.
// - `slew`: the frequency/tick/adjtime applicator that steers the wall clock.

mod fixture;
mod validation;
mod modes;
mod leap;
mod slew;
