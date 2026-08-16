// What happens when a second regulatory request arrives while one is already
// in force.
//
// This is a pure decision over the two requests and is the whole reason the
// answer is testable without a radio. The rule that matters most: a country
// element from an access point never overrides a domain the user set. An AP
// can claim any country it likes, and a station that believed it would
// transmit where its owner may not.

use super::domain::{is_an_alpha2, RegDomain};
use crate::uapi::enums::reg_initiator;

/// One regulatory request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegRequest {
    pub alpha2: [u8; 2],
    /// `reg_initiator` value naming who asked.
    pub initiator: u32,
    /// Radio the request is about, for a driver or country-element request.
    pub wiphy_index: Option<u32>,
    /// Whether the request came from a cellular base station's advice, which
    /// is trusted above an access point's claim and below the user's.
    pub cell_base: bool,
    /// Whether the domain in force was itself produced by an intersection.
    pub intersected: bool,
}

impl RegRequest {
    /// A request from a source with no radio and no cellular provenance.
    /// # C: O(1)
    pub fn new(alpha2: [u8; 2], initiator: u32) -> Self {
        Self { alpha2, initiator, wiphy_index: None, cell_base: false, intersected: false }
    }
}

/// What to do with a new request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Treatment {
    /// Adopt the requested domain.
    Ok,
    /// Adopt the intersection of the requested domain and the one in force.
    Intersect,
    /// Leave the domain alone; the request asks for what is already in force.
    AlreadySet,
    /// Leave the domain alone; the requester may not override this source.
    Ignore,
    /// The request is malformed.
    Invalid,
}

/// Whether a country code differs from the domain actually in force. This is
/// asked about both the new request and the previous one: a previous request
/// whose code does not match the live domain has not been applied yet.
/// # C: O(1)
fn changes(current: [u8; 2], alpha2: [u8; 2]) -> bool { current != alpha2 }

/// How a request is treated against the request currently in force.
///
/// `current` is the country code of the domain actually in force, which is
/// not always the last request's: a request can be accepted and its domain
/// still be pending. `country_ie_ignored` is the radio's own setting: a radio
/// told to disregard country elements does so regardless of what one says.
/// # C: O(1)
pub fn treatment(current: [u8; 2], last: &RegRequest, new: &RegRequest,
                 country_ie_ignored: bool) -> Treatment {
    match new.initiator {
        reg_initiator::CORE =>
            if changes(current, new.alpha2) { Treatment::Ok } else { Treatment::AlreadySet },
        reg_initiator::USER => user(current, last, new),
        reg_initiator::DRIVER => driver(current, last, new),
        reg_initiator::COUNTRY_IE => country_ie(current, last, new, country_ie_ignored),
        _ => Treatment::Invalid,
    }
}

/// A user request. It outranks everything except another user request that
/// has already been intersected, and except advice from a cellular base
/// station, which is a measurement of where the machine actually is.
/// # C: O(1)
fn user(current: [u8; 2], last: &RegRequest, new: &RegRequest) -> Treatment {
    if new.cell_base { return Treatment::Ignore; }
    if last.cell_base { return Treatment::Ignore; }
    if last.initiator == reg_initiator::COUNTRY_IE { return Treatment::Intersect; }
    if last.initiator == reg_initiator::USER && last.intersected { return Treatment::Ignore; }
    // A pending request from the core, a driver or the user is processed
    // before this one; a second request that arrives first is dropped rather
    // than reordered.
    if matches!(last.initiator,
                reg_initiator::CORE | reg_initiator::DRIVER | reg_initiator::USER)
        && changes(current, last.alpha2) { return Treatment::Ignore; }
    if !changes(current, new.alpha2) { return Treatment::AlreadySet; }
    Treatment::Ok
}

/// A driver request. It replaces the core's starting domain outright and
/// intersects with anything a user or an access point put in force, because a
/// driver states what its hardware can do and not where the machine is.
/// # C: O(1)
fn driver(current: [u8; 2], last: &RegRequest, new: &RegRequest) -> Treatment {
    if last.initiator == reg_initiator::CORE {
        return if changes(current, new.alpha2) { Treatment::Ok }
               else { Treatment::AlreadySet };
    }
    if last.initiator == reg_initiator::DRIVER && !changes(current, new.alpha2) {
        return Treatment::AlreadySet;
    }
    Treatment::Intersect
}

/// A country element from a beacon. It may only replace another country
/// element, from the same radio; anything else keeps what is in force.
/// # C: O(1)
fn country_ie(current: [u8; 2], last: &RegRequest, new: &RegRequest,
              ignored: bool) -> Treatment {
    if last.cell_base {
        return if changes(current, new.alpha2) { Treatment::Ignore }
               else { Treatment::AlreadySet };
    }
    if ignored { return Treatment::Ignore; }
    if !is_an_alpha2(new.alpha2) { return Treatment::Invalid; }
    if last.initiator != reg_initiator::COUNTRY_IE { return Treatment::Ok; }
    // Two radios hearing two access points that claim different countries is
    // not something to intersect; the second claim is refused.
    if last.wiphy_index != new.wiphy_index {
        return if changes(current, new.alpha2) { Treatment::Ignore }
               else { Treatment::AlreadySet };
    }
    if changes(current, new.alpha2) { Treatment::Ok } else { Treatment::AlreadySet }
}

/// Apply a treatment, returning the domain that ends up in force. # C: O(rules)
pub fn resolve(treatment: Treatment, current: &RegDomain, requested: &RegDomain)
    -> Option<RegDomain>
{
    match treatment {
        Treatment::Ok => Some(requested.clone()),
        Treatment::Intersect => Some(current.intersect(requested)),
        Treatment::AlreadySet | Treatment::Ignore | Treatment::Invalid => None,
    }
}
