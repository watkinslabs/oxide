// Test manifest — policy language.
//
//   parse     rule text to rule, and every refusal the language defines
//   matcher   rule against request, and the ordered walk
//   defaults  the built-in rule sets, pinned as exact sequences
//   show      rendering, and that rendering parses back

mod defaults;
mod matcher;
mod parse;
mod show;
