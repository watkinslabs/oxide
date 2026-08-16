// The regulatory domain: what a query reports and what the two ways of
// changing it accept.

extern crate alloc;

use syscall::errno::Errno;

use crate::nl80211::reg_cmd;
use crate::nl80211::tests_support::{children, find, lock, radio, u32_of, u8_of, Call, Req};
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{dfs_region, reg_type};
use crate::uapi::nested::reg_rule_attr as rra;

/// A rule table naming one 2.4 GHz range. # C: O(1)
fn one_rule(req: &mut Req) {
    req.nest(a::REG_RULES, |out| {
        let at = netlink::genetlink::attr::nest_start(out, 0);
        netlink::genetlink::attr::put_u32(out, rra::FLAGS, 0);
        netlink::genetlink::attr::put_u32(out, rra::FREQ_RANGE_START, 2_402_000);
        netlink::genetlink::attr::put_u32(out, rra::FREQ_RANGE_END, 2_472_000);
        netlink::genetlink::attr::put_u32(out, rra::FREQ_RANGE_MAX_BW, 40_000);
        netlink::genetlink::attr::put_u32(out, rra::POWER_RULE_MAX_EIRP, 2000);
        netlink::genetlink::attr::nest_end(out, at);
    });
}

#[test]
fn a_query_reports_the_world_domain_and_its_rules() {
    let _g = lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(reg_cmd::get);
    assert_eq!(reply.cmd(), Some(cmd::GET_REG));
    let b = reply.body();
    assert_eq!(find(b, a::REG_ALPHA2).map(|p| p[..2].to_vec()), Some(b"00".to_vec()));
    assert_eq!(u32_of(b, a::REG_TYPE), Some(reg_type::WORLD));
    let rules = find(b, a::REG_RULES).expect("rules");
    let listed = children(rules);
    assert_eq!(listed.len(), w.regdom().rules.len());
    let first = listed[0].1;
    assert_eq!(u32_of(first, rra::FREQ_RANGE_START), Some(2_402_000));
    assert!(u32_of(first, rra::FREQ_RANGE_END).is_some());
    assert!(u32_of(first, rra::FREQ_RANGE_MAX_BW).is_some());
    assert!(u32_of(first, rra::POWER_RULE_MAX_EIRP).is_some());
    assert!(u32_of(first, rra::POWER_RULE_MAX_ANT_GAIN).is_some());
    assert!(u32_of(first, rra::DFS_CAC_TIME).is_some());
}

#[test]
fn a_query_naming_a_radio_reports_that_radio() {
    let _g = lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(reg_cmd::get);
    assert_eq!(u32_of(reply.body(), a::WIPHY), Some(w.index));
}

#[test]
fn a_dump_reports_every_radio_and_terminates() {
    let _g = lock();
    let (_a, _oa) = radio();
    let (_b, _ob) = radio();
    let reply = Req::bare().dump().call(reg_cmd::dump);
    assert_eq!(reply.parts().len(), 2);
    assert!(reply.is_done());
}

#[test]
fn a_rule_table_for_a_new_country_is_installed() {
    let _g = lock();
    let (w, ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"GB");
    req.u8(a::DFS_REGION, dfs_region::ETSI);
    one_rule(&mut req);
    assert!(req.call(reg_cmd::set).is_ack());
    let dom = w.regdom();
    assert_eq!(dom.alpha2, *b"GB");
    assert_eq!(dom.dfs_region, dfs_region::ETSI);
    assert_eq!(dom.rules.len(), 1);
    assert!(ops.calls.lock().unwrap().contains(&Call::SetRegdom));
}

#[test]
fn a_rule_table_for_the_country_already_in_force_is_already_set() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"GB");
    one_rule(&mut req);
    assert!(req.call(reg_cmd::set).is_ack());
    // The second request asks for exactly what is now in force, so nothing
    // changes and the caller is told so rather than being left waiting for a
    // change notification that will never come.
    let mut again = Req::bare();
    again.bytes(a::REG_ALPHA2, b"GB");
    one_rule(&mut again);
    assert!(again.call(reg_cmd::set).is_err(Errno::Ealready));
}

#[test]
fn a_country_code_that_is_not_one_is_refused() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"1!");
    one_rule(&mut req);
    assert!(req.call(reg_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_rule_table_with_no_rules_is_refused() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"GB");
    req.nest(a::REG_RULES, |_out| {});
    assert!(req.call(reg_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_rule_whose_range_runs_backwards_is_refused() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"GB");
    req.nest(a::REG_RULES, |out| {
        let at = netlink::genetlink::attr::nest_start(out, 0);
        netlink::genetlink::attr::put_u32(out, rra::FREQ_RANGE_START, 2_472_000);
        netlink::genetlink::attr::put_u32(out, rra::FREQ_RANGE_END, 2_402_000);
        netlink::genetlink::attr::put_u32(out, rra::POWER_RULE_MAX_EIRP, 2000);
        netlink::genetlink::attr::nest_end(out, at);
    });
    assert!(req.call(reg_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_rule_table_with_no_country_code_is_refused() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    one_rule(&mut req);
    assert!(req.call(reg_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_country_hint_is_applied() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"de");
    assert!(req.call(reg_cmd::req_set).is_ack());
    // The code is normalised to upper case whatever the caller sent.
    assert_eq!(w.regdom().alpha2, *b"DE");
}

#[test]
fn a_hint_for_the_country_already_in_force_still_succeeds() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"DE");
    assert!(req.call(reg_cmd::req_set).is_ack());
    // A hint is a request the arbitration may outrank; being outranked is
    // not a caller error, so the second one succeeds too.
    let mut again = Req::bare();
    again.bytes(a::REG_ALPHA2, b"DE");
    assert!(again.call(reg_cmd::req_set).is_ack());
}

#[test]
fn a_hint_with_a_code_that_is_not_a_country_is_refused() {
    let _g = lock();
    let (_w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"98");
    assert!(req.call(reg_cmd::req_set).is_err(Errno::Einval));
}

#[test]
fn a_change_is_visible_to_the_next_query() {
    let _g = lock();
    let (w, _ops) = radio();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"FR");
    one_rule(&mut req);
    assert!(req.call(reg_cmd::set).is_ack());
    let reply = Req::wiphy(&w).call(reg_cmd::get);
    let b = reply.body();
    assert_eq!(find(b, a::REG_ALPHA2).map(|p| p[..2].to_vec()), Some(b"FR".to_vec()));
    assert_eq!(u32_of(b, a::REG_TYPE), Some(reg_type::COUNTRY));
    assert!(u8_of(b, a::DFS_REGION).is_none(),
            "an unset radar region is absent, not reported as zero");
}

#[test]
fn a_change_with_no_radio_registered_reports_no_device() {
    let _g = lock();
    let mut req = Req::bare();
    req.bytes(a::REG_ALPHA2, b"GB");
    one_rule(&mut req);
    assert!(req.call(reg_cmd::set).is_err(Errno::Enodev));
}
