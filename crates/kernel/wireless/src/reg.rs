// Regulatory: which frequencies may be used at what power, where that answer
// came from, and what happens when two sources disagree.
//
// Module manifest:
// - `rule`:      one frequency range and the power rule over it.
// - `domain`:    a whole domain, the built-in world domain, and intersection.
// - `hint`:      how a new request is treated against the one in force.
// - `apply`:     projecting a domain onto a radio's channel list.
// - `country_ie`: reading a domain out of a beacon's country element.

extern crate alloc;

#[path = "reg/rule.rs"]
pub mod rule;
#[path = "reg/domain.rs"]
pub mod domain;
#[path = "reg/hint.rs"]
pub mod hint;
#[path = "reg/apply.rs"]
pub mod apply;
#[path = "reg/country_ie.rs"]
pub mod country_ie;

pub use domain::{RegDomain, ALPHA2_CUSTOM_WORLD, ALPHA2_INTERSECTION, ALPHA2_WORLD};
pub use hint::{treatment, RegRequest, Treatment};
pub use rule::{FreqRange, PowerRule, RegRule};
