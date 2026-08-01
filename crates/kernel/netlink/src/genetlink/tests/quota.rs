// The VFS_DQUOT consumer: a quota warning raised by the VFS must arrive on the
// family's `events` group with every attribute `quota_nld` reads.

extern crate alloc;

use super::harness::*;
use crate::genetlink::quota::{self, quota_nl_attr, quota_nl_cmd, ParsedWarning};
use crate::genetlink::uapi::GENL_ID_VFS_DQUOT;

const TEST_MAJOR: u32 = 253;
const TEST_MINOR: u32 = 7;

fn warning(kind: vfs::QuotaType, id: u32, class: vfs::QuotaWarnType, uid: u32)
    -> vfs::QuotaWarning
{
    vfs::QuotaWarning {
        qid: vfs::Kqid { kind, id },
        dev: vfs::mkdev(TEST_MAJOR, TEST_MINOR),
        warn_type: class,
        caused_by_uid: uid,
    }
}

/// The one socket every quota test broadcasts to, in the initial namespace the
/// family lives in.
fn quota_listener() -> (alloc::sync::Arc<crate::netlink_socket::NetlinkSocket>,
    std::sync::MutexGuard<'static, ()>)
{
    boot();
    let serial = crate::test_serial::quota_events();
    (subscriber(&network_namespace::initial(), GENL_ID_VFS_DQUOT as u32), serial)
}

#[test]
fn a_warning_arrives_with_its_full_attribute_set() {
    let (listener, _serial) = quota_listener();
    let sent = warning(vfs::QuotaType::Group, 4242, vfs::QuotaWarnType::BSoftLongWarn, 1000);
    assert_eq!(quota::multicast_warning(sent), Ok(1));

    let msg = recv(&listener).expect("the warning must reach the events group");
    let got = quota::parse_warning(&msg).expect("a warning must decode");
    assert_eq!(got, ParsedWarning {
        family_id: GENL_ID_VFS_DQUOT,
        cmd:       quota_nl_cmd::QUOTA_NL_C_WARNING,
        version:   quota::QUOTA_FAMILY_VERSION,
        qtype:     vfs::QuotaType::Group.slot() as u32,
        excess_id: 4242,
        warning:   vfs::QuotaWarnType::BSoftLongWarn.as_u32(),
        dev_major: TEST_MAJOR,
        dev_minor: TEST_MINOR,
        caused_id: 1000,
    });
}

#[test]
fn every_quota_class_reports_its_own_qtype() {
    let (listener, _serial) = quota_listener();
    for (kind, id) in [
        (vfs::QuotaType::User, 1u32),
        (vfs::QuotaType::Group, 2),
        (vfs::QuotaType::Project, 3),
    ] {
        assert_eq!(quota::multicast_warning(
            warning(kind, id, vfs::QuotaWarnType::IHardWarn, 0)), Ok(1));
        let got = quota::parse_warning(&recv(&listener).unwrap()).unwrap();
        assert_eq!(got.qtype, kind.slot() as u32);
        assert_eq!(got.excess_id, id as u64);
    }
}

#[test]
fn the_warning_class_travels_as_its_uapi_number() {
    let (listener, _serial) = quota_listener();
    for class in [
        vfs::QuotaWarnType::IHardWarn, vfs::QuotaWarnType::ISoftLongWarn,
        vfs::QuotaWarnType::ISoftWarn, vfs::QuotaWarnType::BHardWarn,
        vfs::QuotaWarnType::BSoftLongWarn, vfs::QuotaWarnType::BSoftWarn,
        vfs::QuotaWarnType::IHardBelow, vfs::QuotaWarnType::ISoftBelow,
        vfs::QuotaWarnType::BHardBelow, vfs::QuotaWarnType::BSoftBelow,
    ] {
        assert_eq!(quota::multicast_warning(
            warning(vfs::QuotaType::User, 9, class, 0)), Ok(1));
        let got = quota::parse_warning(&recv(&listener).unwrap()).unwrap();
        assert_eq!(got.warning, class.as_u32());
    }
}

#[test]
fn the_64_bit_id_attributes_land_8_byte_aligned() {
    boot();
    let body = quota::build_warning(1, GENL_ID_VFS_DQUOT,
        warning(vfs::QuotaType::User, u32::MAX, vfs::QuotaWarnType::BHardWarn, u32::MAX));
    // A 64-bit netlink attribute must have its PAYLOAD 8-byte aligned inside
    // the message, which is what the padding attribute buys.
    let mut off = crate::Nlmsghdr::SIZE + crate::genetlink::uapi::Genlmsghdr::SIZE;
    let mut seen_64bit = 0;
    while off + 4 <= body.len() {
        let len = u16::from_ne_bytes([body[off], body[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([body[off + 2], body[off + 3]]);
        if len < 4 { break; }
        if matches!(ty, quota_nl_attr::QUOTA_NL_A_EXCESS_ID | quota_nl_attr::QUOTA_NL_A_CAUSED_ID) {
            assert_eq!((off + 4) % 8, 0, "64-bit attribute payload must be 8-byte aligned");
            seen_64bit += 1;
        }
        off += crate::nlmsg_align(len);
    }
    assert_eq!(seen_64bit, 2);
}

#[test]
fn a_warning_with_no_listener_is_not_an_error_for_the_filesystem() {
    boot();
    // No subscriber is created here: the hook must swallow ESRCH so quota
    // accounting is never failed by a missing userspace daemon.
    quota::send_warning(warning(vfs::QuotaType::User, 1, vfs::QuotaWarnType::BHardWarn, 0));
}

#[test]
fn the_vfs_hook_is_installed_and_carries_warnings_to_the_group() {
    let (listener, _serial) = quota_listener();
    let _ = vfs::take_logged_warnings();
    // Deliver through the VFS entry point the quota charge path calls, not
    // through the transport directly.
    let sent = warning(vfs::QuotaType::Project, 77, vfs::QuotaWarnType::ISoftWarn, 501);
    vfs::deliver_warning(sent);
    let got = quota::parse_warning(&recv(&listener)
        .expect("a VFS-generated warning must reach the events group")).unwrap();
    assert_eq!(got.qtype, vfs::QuotaType::Project.slot() as u32);
    assert_eq!(got.excess_id, 77);
    assert_eq!(got.warning, vfs::QuotaWarnType::ISoftWarn.as_u32());
    assert_eq!(got.caused_id, 501);
}

#[test]
fn a_batch_flush_delivers_one_message_per_quota_class() {
    let (listener, _serial) = quota_listener();
    let mut warns = vfs::DquotWarns::new();
    let dev = vfs::mkdev(TEST_MAJOR, TEST_MINOR);
    warns.prepare(vfs::Kqid::user(11), vfs::QuotaWarnType::BHardWarn, dev);
    warns.prepare(vfs::Kqid::group(22), vfs::QuotaWarnType::ISoftWarn, dev);
    warns.flush(4000);

    let mut got: alloc::vec::Vec<ParsedWarning> = alloc::vec::Vec::new();
    while let Some(msg) = recv(&listener) { got.push(quota::parse_warning(&msg).unwrap()); }
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].qtype, vfs::QuotaType::User.slot() as u32);
    assert_eq!(got[0].excess_id, 11);
    assert_eq!(got[1].qtype, vfs::QuotaType::Group.slot() as u32);
    assert_eq!(got[1].excess_id, 22);
    for w in &got { assert_eq!(w.caused_id, 4000); }
}
