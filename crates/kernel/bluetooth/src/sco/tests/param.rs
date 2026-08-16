//! Parameter-table contract: the documented rows in the documented order, the
//! capability screen, and exhaustion.

use crate::sco::param::{self, LinkCaps, ParamError, ScoParam, ESCO_PARAM_CVSD, ESCO_PARAM_MSBC, SCO_PARAM_CVSD};
use crate::uapi::hci::{EDR_ESCO_MASK, ESCO_2EV3, ESCO_EV3, ESCO_HV1, ESCO_HV3,
                       SCO_AIRMODE_CVSD, SCO_AIRMODE_TRANSP};

const CVSD: u16 = crate::uapi::bt::BT_VOICE_CVSD_16BIT;
const TRANSP: u16 = crate::uapi::bt::BT_VOICE_TRANSPARENT;
const TRANSP16: u16 = crate::uapi::bt::BT_VOICE_TRANSPARENT_16BIT;

const FULL: LinkCaps = LinkCaps { esco: true, esco_2m: true };
const NO_2M: LinkCaps = LinkCaps { esco: true, esco_2m: false };
const NO_ESCO: LinkCaps = LinkCaps { esco: false, esco_2m: false };

#[test]
fn the_variable_slope_table_is_the_documented_one() {
    assert_eq!(ESCO_PARAM_CVSD, [
        ScoParam { pkt_type: EDR_ESCO_MASK & !ESCO_2EV3, max_latency: 0x000a, retrans_effort: 0x01 },
        ScoParam { pkt_type: EDR_ESCO_MASK & !ESCO_2EV3, max_latency: 0x0007, retrans_effort: 0x01 },
        ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_EV3,   max_latency: 0x0007, retrans_effort: 0x01 },
        ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV3,   max_latency: 0xffff, retrans_effort: 0x01 },
        ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV1,   max_latency: 0xffff, retrans_effort: 0x01 },
    ]);
    assert_eq!(SCO_PARAM_CVSD, [
        ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV3, max_latency: 0xffff, retrans_effort: 0xff },
        ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_HV1, max_latency: 0xffff, retrans_effort: 0xff },
    ]);
    assert_eq!(ESCO_PARAM_MSBC, [
        ScoParam { pkt_type: EDR_ESCO_MASK & !ESCO_2EV3, max_latency: 0x000d, retrans_effort: 0x02 },
        ScoParam { pkt_type: EDR_ESCO_MASK | ESCO_EV3,   max_latency: 0x0008, retrans_effort: 0x02 },
    ]);
}

#[test]
fn the_walk_visits_every_row_in_order() {
    let mut seen = alloc::vec::Vec::new();
    for attempt in 1..=ESCO_PARAM_CVSD.len() as u16 {
        let (a, p) = param::select(CVSD, attempt, FULL).unwrap();
        assert_eq!(a, attempt);
        seen.push(p);
    }
    assert_eq!(seen, ESCO_PARAM_CVSD.to_vec());
}

#[test]
fn the_walk_reports_exhaustion_past_the_last_row() {
    assert_eq!(param::select(CVSD, ESCO_PARAM_CVSD.len() as u16 + 1, FULL),
               Err(ParamError::Exhausted));
    assert_eq!(param::select(TRANSP, ESCO_PARAM_MSBC.len() as u16 + 1, FULL),
               Err(ParamError::Exhausted));
    assert_eq!(param::select(CVSD, SCO_PARAM_CVSD.len() as u16 + 1, NO_ESCO),
               Err(ParamError::Exhausted));
}

#[test]
fn rows_that_need_two_megabit_esco_are_skipped_without_it() {
    // The two rows that omit the two-megabit type are the two that need it.
    let (a, p) = param::select(CVSD, 1, NO_2M).unwrap();
    assert_eq!(a, 3, "the first two rows need two-megabit eSCO");
    assert_eq!(p, ESCO_PARAM_CVSD[2]);
    assert_ne!(p.pkt_type & ESCO_2EV3, 0);

    let (a, p) = param::select(TRANSP, 1, NO_2M).unwrap();
    assert_eq!(a, 2);
    assert_eq!(p, ESCO_PARAM_MSBC[1]);

    // With the capability, nothing is skipped.
    assert_eq!(param::select(CVSD, 1, FULL).unwrap().0, 1);
    assert_eq!(param::select(TRANSP, 1, FULL).unwrap().0, 1);
}

#[test]
fn every_row_the_screen_keeps_is_one_the_controller_can_carry() {
    for table in [&ESCO_PARAM_CVSD[..], &ESCO_PARAM_MSBC[..]] {
        let mut attempt = 1u16;
        while let Ok((a, p)) = param::find_next(table, attempt, false) {
            assert_ne!(p.pkt_type & ESCO_2EV3, 0, "row {a} needs two-megabit eSCO");
            attempt = a + 1;
        }
    }
}

#[test]
fn the_plain_table_is_used_without_extended_connections_and_has_no_screen() {
    for attempt in 1..=SCO_PARAM_CVSD.len() as u16 {
        let (a, p) = param::select(CVSD, attempt, NO_ESCO).unwrap();
        assert_eq!(a, attempt, "the plain table skips nothing");
        assert_eq!(p, SCO_PARAM_CVSD[attempt as usize - 1]);
    }
    // Even without the two-megabit capability, which the plain table never asks
    // for.
    let caps = LinkCaps { esco: false, esco_2m: false };
    assert_eq!(param::select(CVSD, 1, caps).unwrap().1, SCO_PARAM_CVSD[0]);
}

#[test]
fn transparent_coding_always_selects_the_wideband_table() {
    let (_, p) = param::select(TRANSP, 1, FULL).unwrap();
    assert_eq!(p, ESCO_PARAM_MSBC[0]);
    let no_esco_but_2m = LinkCaps { esco: false, esco_2m: true };
    let (_, p) = param::select(TRANSP16, 1, no_esco_but_2m).unwrap();
    assert_eq!(p, ESCO_PARAM_MSBC[0], "the wideband table is not gated on extended connections");
}

#[test]
fn an_air_coding_with_no_table_is_refused() {
    for setting in [0x0001u16, 0x0002] {
        assert_eq!(param::select(setting, 1, FULL), Err(ParamError::BadAirMode));
    }
}

#[test]
fn the_deferred_accept_answers_with_the_air_codings_own_parameters() {
    assert_eq!(param::accept_params(TRANSP, EDR_ESCO_MASK), (0x0008, 0x02));
    assert_eq!(param::accept_params(TRANSP, EDR_ESCO_MASK & !ESCO_2EV3), (0x000d, 0x02));
    assert_eq!(param::accept_params(CVSD, EDR_ESCO_MASK), (0xffff, 0xff));
    assert_eq!(param::accept_params(0x0001, EDR_ESCO_MASK), (0xffff, 0xff), "an unknown coding falls back");
}

#[test]
fn the_air_coding_field_names_the_two_codings() {
    assert_eq!(CVSD & crate::uapi::hci::SCO_AIRMODE_MASK, SCO_AIRMODE_CVSD);
    assert_eq!(TRANSP & crate::uapi::hci::SCO_AIRMODE_MASK, SCO_AIRMODE_TRANSP);
    assert_eq!(TRANSP16 & crate::uapi::hci::SCO_AIRMODE_MASK, SCO_AIRMODE_TRANSP);
}
