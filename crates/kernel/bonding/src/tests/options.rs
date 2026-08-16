// Option table shape and the dependency check's errno ladder.

use syscall::Errno;

use crate::flags::{BOND_OPTFLAG_IFDOWN, BOND_OPTFLAG_NOSLAVES, BOND_OPTFLAG_RAWVAL};
use crate::options::{
    check_deps, is_rawval, mode_valid, option_by_id, option_by_name, xmit_policy_valid,
    BondStateView, BOND_OPTS, BOND_OPT_ACTIVE_SLAVE, BOND_OPT_AD_SELECT,
    BOND_OPT_ARP_INTERVAL, BOND_OPT_ARP_VALIDATE, BOND_OPT_FAIL_OVER_MAC, BOND_OPT_LACP_RATE,
    BOND_OPT_LAST, BOND_OPT_MIIMON, BOND_OPT_MODE, BOND_OPT_PACKETS_PER_SLAVE,
    BOND_OPT_PRIMARY, BOND_OPT_TLB_DYNAMIC_LB, BOND_OPT_XMIT_HASH,
};
use crate::uapi::{
    bond_mode_from_name, bond_mode_name, xmit_policy_from_name, xmit_policy_name,
    BOND_MODE_8023AD, BOND_MODE_ACTIVEBACKUP, BOND_MODE_ALB, BOND_MODE_BROADCAST,
    BOND_MODE_MAX, BOND_MODE_ROUNDROBIN, BOND_MODE_TLB, BOND_MODE_XOR,
    BOND_XMIT_POLICY_MAX, BOND_XMIT_POLICY_VLAN_SRCMAC,
};

fn state(mode: u8, has_slaves: bool, if_up: bool) -> BondStateView {
    BondStateView { mode, has_slaves, if_up }
}

#[test]
fn the_table_is_dense_and_self_consistent() {
    assert_eq!(BOND_OPTS.len(), BOND_OPT_LAST as usize);
    for (i, o) in BOND_OPTS.iter().enumerate() {
        assert_eq!(o.id as usize, i);
        assert!(!o.name.is_empty());
        assert_eq!(option_by_name(o.name).map(|x| x.id), Some(o.id));
        assert_eq!(option_by_id(o.id).map(|x| x.name), Some(o.name));
    }
}

#[test]
fn an_option_the_mode_does_not_implement_is_a_permission_failure() {
    let ppl = option_by_id(BOND_OPT_PACKETS_PER_SLAVE).unwrap();
    assert_eq!(check_deps(ppl, &state(BOND_MODE_ROUNDROBIN, false, false)), Ok(()));
    for m in [BOND_MODE_ACTIVEBACKUP, BOND_MODE_XOR, BOND_MODE_BROADCAST,
              BOND_MODE_8023AD, BOND_MODE_TLB, BOND_MODE_ALB] {
        assert_eq!(check_deps(ppl, &state(m, false, false)), Err(Errno::Eacces));
    }
}

#[test]
fn the_aggregation_only_options_are_refused_in_every_other_mode() {
    let lacp = option_by_id(BOND_OPT_LACP_RATE).unwrap();
    assert_eq!(check_deps(lacp, &state(BOND_MODE_8023AD, false, false)), Ok(()));
    for m in 0..=BOND_MODE_MAX {
        if m == BOND_MODE_8023AD { continue; }
        assert_eq!(check_deps(lacp, &state(m, false, false)), Err(Errno::Eacces));
    }
}

#[test]
fn the_arp_monitor_options_are_refused_in_the_modes_that_do_not_run_it() {
    for id in [BOND_OPT_ARP_VALIDATE, BOND_OPT_ARP_INTERVAL] {
        let o = option_by_id(id).unwrap();
        for m in [BOND_MODE_8023AD, BOND_MODE_TLB, BOND_MODE_ALB] {
            assert_eq!(check_deps(o, &state(m, false, false)), Err(Errno::Eacces));
        }
        for m in [BOND_MODE_ROUNDROBIN, BOND_MODE_ACTIVEBACKUP, BOND_MODE_XOR,
                  BOND_MODE_BROADCAST] {
            assert_eq!(check_deps(o, &state(m, false, false)), Ok(()));
        }
    }
}

#[test]
fn the_load_balancing_option_is_refused_outside_the_balancing_modes() {
    let o = option_by_id(BOND_OPT_TLB_DYNAMIC_LB).unwrap();
    assert_eq!(check_deps(o, &state(BOND_MODE_TLB, false, false)), Ok(()));
    assert_eq!(check_deps(o, &state(BOND_MODE_ALB, false, false)), Ok(()));
    assert_eq!(check_deps(o, &state(BOND_MODE_XOR, false, false)), Err(Errno::Eacces));
}

#[test]
fn the_primary_options_are_refused_outside_failover_and_balancing_modes() {
    for id in [BOND_OPT_PRIMARY, BOND_OPT_ACTIVE_SLAVE] {
        let o = option_by_id(id).unwrap();
        for m in [BOND_MODE_ACTIVEBACKUP, BOND_MODE_TLB, BOND_MODE_ALB] {
            assert_eq!(check_deps(o, &state(m, false, false)), Ok(()));
        }
        for m in [BOND_MODE_ROUNDROBIN, BOND_MODE_XOR, BOND_MODE_BROADCAST,
                  BOND_MODE_8023AD] {
            assert_eq!(check_deps(o, &state(m, false, false)), Err(Errno::Eacces));
        }
    }
}

#[test]
fn an_option_needing_an_empty_bond_reports_that_the_bond_is_not_empty() {
    let fom = option_by_id(BOND_OPT_FAIL_OVER_MAC).unwrap();
    assert!(fom.flags & BOND_OPTFLAG_NOSLAVES != 0);
    assert_eq!(check_deps(fom, &state(BOND_MODE_ACTIVEBACKUP, false, false)), Ok(()));
    assert_eq!(check_deps(fom, &state(BOND_MODE_ACTIVEBACKUP, true, false)),
               Err(Errno::Enotempty));
}

#[test]
fn an_option_needing_a_down_bond_reports_busy_while_the_bond_is_up() {
    let ad = option_by_id(BOND_OPT_AD_SELECT).unwrap();
    assert!(ad.flags & BOND_OPTFLAG_IFDOWN != 0);
    assert_eq!(check_deps(ad, &state(BOND_MODE_8023AD, true, false)), Ok(()));
    assert_eq!(check_deps(ad, &state(BOND_MODE_8023AD, true, true)), Err(Errno::Ebusy));
}

#[test]
fn the_mode_write_needs_both_an_empty_and_a_down_bond_in_that_order() {
    let m = option_by_id(BOND_OPT_MODE).unwrap();
    assert_eq!(m.flags & (BOND_OPTFLAG_NOSLAVES | BOND_OPTFLAG_IFDOWN),
               BOND_OPTFLAG_NOSLAVES | BOND_OPTFLAG_IFDOWN);
    assert_eq!(check_deps(m, &state(BOND_MODE_ROUNDROBIN, false, false)), Ok(()));
    // A bond that is both non-empty and up reports the emptiness failure first.
    assert_eq!(check_deps(m, &state(BOND_MODE_ROUNDROBIN, true, true)), Err(Errno::Enotempty));
    assert_eq!(check_deps(m, &state(BOND_MODE_ROUNDROBIN, false, true)), Err(Errno::Ebusy));
}

#[test]
fn an_unrestricted_option_is_accepted_in_every_state() {
    let mii = option_by_id(BOND_OPT_MIIMON).unwrap();
    for m in 0..=BOND_MODE_MAX {
        for slaves in [false, true] {
            for up in [false, true] {
                assert_eq!(check_deps(mii, &state(m, slaves, up)), Ok(()));
            }
        }
    }
    let xh = option_by_id(BOND_OPT_XMIT_HASH).unwrap();
    assert_eq!(check_deps(xh, &state(BOND_MODE_BROADCAST, true, true)), Ok(()));
}

#[test]
fn raw_valued_options_are_marked_as_such() {
    assert!(is_rawval(option_by_id(BOND_OPT_PRIMARY).unwrap()));
    assert!(!is_rawval(option_by_id(BOND_OPT_MODE).unwrap()));
    assert_eq!(option_by_id(BOND_OPT_PRIMARY).unwrap().flags & BOND_OPTFLAG_RAWVAL,
               BOND_OPTFLAG_RAWVAL);
}

#[test]
fn mode_and_policy_names_round_trip() {
    for m in 0..=BOND_MODE_MAX {
        let n = bond_mode_name(m).unwrap();
        assert_eq!(bond_mode_from_name(n), Some(m));
    }
    assert_eq!(bond_mode_name(BOND_MODE_MAX + 1), None);
    assert_eq!(bond_mode_from_name("balance-rr"), Some(BOND_MODE_ROUNDROBIN));
    assert_eq!(bond_mode_from_name("nonsense"), None);

    for p in 0..=BOND_XMIT_POLICY_MAX {
        let n = xmit_policy_name(p).unwrap();
        assert_eq!(xmit_policy_from_name(n), Some(p));
    }
    assert_eq!(xmit_policy_from_name("vlan+srcmac"), Some(BOND_XMIT_POLICY_VLAN_SRCMAC));
}

#[test]
fn validity_predicates_bound_the_id_spaces() {
    assert!(mode_valid(BOND_MODE_MAX));
    assert!(!mode_valid(BOND_MODE_MAX + 1));
    assert!(xmit_policy_valid(BOND_XMIT_POLICY_MAX));
    assert!(!xmit_policy_valid(BOND_XMIT_POLICY_MAX + 1));
}
