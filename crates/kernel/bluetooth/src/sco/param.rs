//! Synchronous-link parameter tables and the fallback walk.
//!
//! A controller pair that cannot meet one parameter set is asked again with the
//! next, weaker one, so each attempt indexes one row further into a table
//! chosen by the air coding. Exhausting the table is a failure, not a wrap.
//!
//! The packet-type field is a set of types to EXCLUDE for the enhanced-rate
//! packets, which inverts the sense of the capability screen: a row that names
//! the two-megabit three-slot type is the row that does NOT need it, and it is
//! the rows omitting it that a controller without two-megabit eSCO must skip.

use crate::uapi::hci::{EDR_ESCO_MASK, ESCO_2EV3, ESCO_EV3, ESCO_HV1, ESCO_HV3,
                       SCO_AIRMODE_CVSD, SCO_AIRMODE_MASK, SCO_AIRMODE_TRANSP};
use crate::uapi::sco as u;

/// One row of a parameter table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScoParam {
    pub pkt_type: u16,
    pub max_latency: u16,
    pub retrans_effort: u8,
}

/// Continuously variable slope delta modulation over eSCO, strongest first.
pub static ESCO_PARAM_CVSD: [ScoParam; 5] = [
    ScoParam { pkt_type: EDR_ESCO_MASK & !ESCO_2EV3, max_latency: u::SCO_MAX_LATENCY_S3, retrans_effort: u::SCO_RETRANS_POWER },
    ScoParam { pkt_type: EDR_ESCO_MASK & !ESCO_2EV3, max_latency: u::SCO_MAX_LATENCY_S2, retrans_effort: u::SCO_RETRANS_POWER },
    ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_EV3,   max_latency: u::SCO_MAX_LATENCY_S1, retrans_effort: u::SCO_RETRANS_POWER },
    ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV3,   max_latency: u::SCO_MAX_LATENCY_DONT_CARE, retrans_effort: u::SCO_RETRANS_POWER },
    ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV1,   max_latency: u::SCO_MAX_LATENCY_DONT_CARE, retrans_effort: u::SCO_RETRANS_POWER },
];

/// The same coding over a plain synchronous link, which cannot retransmit.
pub static SCO_PARAM_CVSD: [ScoParam; 2] = [
    ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV3, max_latency: u::SCO_MAX_LATENCY_DONT_CARE, retrans_effort: u::SCO_RETRANS_DONT_CARE },
    ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV1, max_latency: u::SCO_MAX_LATENCY_DONT_CARE, retrans_effort: u::SCO_RETRANS_DONT_CARE },
];

/// Transparent air coding, which is what a wideband link carries.
pub static ESCO_PARAM_MSBC: [ScoParam; 2] = [
    ScoParam { pkt_type: EDR_ESCO_MASK & !ESCO_2EV3, max_latency: u::SCO_MAX_LATENCY_T2, retrans_effort: u::SCO_RETRANS_QUALITY },
    ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_EV3,   max_latency: u::SCO_MAX_LATENCY_T1, retrans_effort: u::SCO_RETRANS_QUALITY },
];

/// Why no parameters could be chosen.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParamError {
    /// Every row of the table has been tried.
    Exhausted,
    /// The air coding names no table.
    BadAirMode,
}

/// Advance `attempt` — a one-based row number — to the first row this
/// controller can actually use, skipping rows that need two-megabit eSCO when
/// it has none. Returns the row number reached and its parameters. # C: O(n)
pub fn find_next(table: &[ScoParam], attempt: u16, esco_2m: bool)
    -> Result<(u16, ScoParam), ParamError>
{
    let mut a = attempt;
    while a as usize <= table.len() {
        let row = table[a as usize - 1];
        if esco_2m || row.pkt_type & ESCO_2EV3 != 0 { return Ok((a, row)); }
        a += 1;
    }
    Err(ParamError::Exhausted)
}

/// Whether a controller's own capability, its peer's, and the air coding select
/// the enhanced table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkCaps {
    /// Whether the link can carry an extended synchronous connection at all.
    pub esco: bool,
    /// Whether it can carry the two-megabit eSCO packet types.
    pub esco_2m: bool,
}

/// Choose the parameters for one attempt. Transparent coding always uses the
/// wideband table; the variable-slope coding uses the extended table when the
/// link supports extended connections and the plain one otherwise — and the
/// plain table has no capability screen, because it names no enhanced-rate
/// packet at all. # C: O(n)
pub fn select(setting: u16, attempt: u16, caps: LinkCaps) -> Result<(u16, ScoParam), ParamError> {
    match setting & SCO_AIRMODE_MASK {
        SCO_AIRMODE_TRANSP => find_next(&ESCO_PARAM_MSBC, attempt, caps.esco_2m),
        SCO_AIRMODE_CVSD => {
            if caps.esco { return find_next(&ESCO_PARAM_CVSD, attempt, caps.esco_2m); }
            if attempt as usize > SCO_PARAM_CVSD.len() { return Err(ParamError::Exhausted); }
            Ok((attempt, SCO_PARAM_CVSD[attempt as usize - 1]))
        }
        _ => Err(ParamError::BadAirMode),
    }
}

/// The latency and retransmission effort a deferred accept answers with. The
/// transparent coding tightens the latency when the offered packet types leave
/// the two-megabit three-slot type available; every other coding, and an
/// unrecognised one, falls back to the variable-slope answer. # C: O(1)
pub fn accept_params(setting: u16, pkt_type: u16) -> (u16, u8) {
    match setting & SCO_AIRMODE_MASK {
        SCO_AIRMODE_TRANSP => {
            let lat = if pkt_type & ESCO_2EV3 != 0 { u::SCO_MAX_LATENCY_T1 } else { u::SCO_MAX_LATENCY_T2 };
            (lat, u::SCO_RETRANS_QUALITY)
        }
        _ => (u::SCO_MAX_LATENCY_DONT_CARE, u::SCO_RETRANS_DONT_CARE),
    }
}
