// Parser contract tests. Module manifest:
// - `token`: tokenisation and scalar-parse edges.
// - `console`: `console=` classes, ordering and line settings.
// - `earlycon`: every accepted `earlycon=` / `earlyprintk=` spelling.
// - `printk`: loglevel, verbosity and `/dev/kmsg` policy decisions.
// - `memory`: `kernelcore=` / `movablecore=` values and replacement rules.
// - hibernation boot options are colocated with their ordered parser.

mod token;
mod console;
mod earlycon;
mod printk;
mod memory;
