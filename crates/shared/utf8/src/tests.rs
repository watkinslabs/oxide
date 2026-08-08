// Module manifest:
// - `fixtures`: differential pin against the generator's reference fold.
// - `fold`: case-folded equality and hashing across scripts and spellings.
// - `order`: canonical ordering of combining marks, ignorables, Hangul.
// - `strict`: the validity predicate strict-encoding mounts refuse names on.
// - `load`: charset/version parsing and table-version refusal.

mod fixtures;
mod fold;
mod load;
mod order;
mod strict;
