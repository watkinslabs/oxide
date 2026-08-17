//! Age-threshold cleaning: choosing a victim by how old its data is.
//!
//! The volume's other two victim costs are about SPACE — how few blocks a
//! section would make the cleaner move. This one is about the WRITES that
//! cleaning costs. Data that has already survived a long time will probably
//! survive longer, so copying it out of a section buys space that stays
//! bought; data written moments ago is likely to be invalidated on its own,
//! and copying it spends flash's finite writes on blocks that were about to
//! die for free. A cleaner that ignores this cleans the same young sections
//! over and over.
//!
//! Nothing in this module reads a medium. A candidate arrives as a segment
//! number, an age and a live-block count, so the whole policy — the part that
//! decides which sections a volume rewrites for the rest of its life — is
//! checkable against a table nobody wrote.
//!
//! Module manifest:
//! - `limits`: the ages, shares and scales the policy is defined in.
//! - `state`:  the tunables, the collected candidates, and the age span.
//! - `victim`: costing those candidates, for cleaning and for reuse.
//! - `knobs`:  the four writable controls, and what each will accept.

pub mod limits;
pub mod state;
pub mod victim;
pub mod knobs;

pub use knobs::Knob;
pub use limits::{DEFAULT_ACCURACY_CLASS, DEF_AGE_THRESHOLD, DEF_AGE_WEIGHT,
                 DEF_CANDIDATE_RATIO, DEF_MAX_CANDIDATE_COUNT, INVALID_MTIME};
pub use state::Atgc;
pub use victim::Pick;
