// Test manifest.
//   `budgets` — the constants match the Linux Kconfig/header they cite.
//   `math`    — alignment + bounds of every placement fn, on BOTH arches.
//   `modes`   — the three `randomize_va_space` modes and the negative cases.
//   `entropy` — the randomness is real, not merely varying.

mod budgets;
mod entropy;
mod math;
mod modes;
