// tmpfs mount-option parsing.
//
// `mount("tmpfs", target, "tmpfs", flags, data)` carries a comma-separated
// option string in `data`, and every key in it is either acted on or refused.
// The keys that exist at all are `params.rs`'s answer; what each one MEANS is
// this module's.
//
// Module manifest:
// - limits: the ceilings and separators the option contract is written in.
// - memparse: the numeric and mode spellings a value may be written in.
// - opts: the resolved option set and the credentials it is judged against.
// - mpol: the `mpol=` NUMA policy grammar.
// - parse: the tokeniser and the per-key contract.
//
// UNGATED on purpose: the whole decision surface must be reachable by
// `cargo test` on the host.

mod limits;
mod memparse;
mod mpol;
mod opts;
mod parse;

#[cfg(test)]
mod tests;

pub(super) use limits::ZERO_INO;
pub(super) use opts::{MountCred, QTYPE_MASK_GRP, QTYPE_MASK_USR, QuotaLimits, TmpfsOpts};
pub(super) use parse::parse_opts;


