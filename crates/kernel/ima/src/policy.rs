// Module manifest — the IMA policy language.
//
//   rule      the rule record: action, condition bits, condition values
//   parse     policy text to a rule, with the refusals the language defines
//   validate  which action/hook/condition combinations may be stored
//   matcher   rule against a request, and the ordered policy walk
//   defaults  the built-in policies and their boot-time selection
//   show      a rule back as policy text

pub mod defaults;
pub mod matcher;
pub mod parse;
pub mod rule;
pub mod show;
pub mod validate;

pub use defaults::{init_policy, select_from_cmdline, BuiltinConfig, Selection, TcbPolicy};
pub use matcher::{match_policy, match_rule, Decision, LsmProps, Request};
pub use parse::{parse_rule, ParseError};
pub use rule::{CmpOp, LsmSlot, Rule};
pub use show::show_rule;
pub use validate::validate_rule;

#[cfg(test)]
mod tests;
