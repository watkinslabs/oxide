// RTM_NEWLINK operational state follows both administrative and carrier state.

use super::*;

fn operstate(flags: u32) -> u8 {
    let msg = build_newlink_reply(
        1, 2, 3, "eth0", [2, 0, 0, 0, 0, 1], &[u8::MAX; 6], 1500,
        false, flags, LinkStats64::default(), false, None,
    );
    let attrs = &msg[Nlmsghdr::SIZE + Ifinfomsg::SIZE..];
    find_attr(attrs, ifla::IFLA_OPERSTATE).expect("IFLA_OPERSTATE")[0]
}

#[test]
fn carrier_does_not_make_an_administratively_down_link_operationally_up() {
    assert_eq!(operstate(iff::IFF_RUNNING | iff::IFF_LOWER_UP), if_oper::DOWN);
    assert_eq!(operstate(iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_LOWER_UP), if_oper::UP);
}
