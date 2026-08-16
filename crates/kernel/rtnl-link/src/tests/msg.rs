// Link-message parsing, including the envelope that names the kind.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::msg::*;
use crate::nla;
use crate::uapi::*;

struct Builder { body: Vec<u8> }

impl Builder {
    fn new(index: i32) -> Self {
        let mut body = alloc::vec![0u8; IFINFOMSG_LEN];
        body[IFI_INDEX_OFF..IFI_INDEX_OFF + 4].copy_from_slice(&index.to_ne_bytes());
        Self { body }
    }
    fn attr(mut self, ty: u16, p: &[u8]) -> Self { nla::put(&mut self.body, ty, p); self }
    fn name(self, n: &str) -> Self {
        let mut s = Vec::from(n.as_bytes()); s.push(0);
        self.attr(IFLA_IFNAME, &s)
    }
    fn linkinfo(mut self, kind: Option<&str>, data: Option<&[u8]>) -> Self {
        let at = nla::nest_start(&mut self.body, IFLA_LINKINFO);
        if let Some(k) = kind {
            let mut s = Vec::from(k.as_bytes()); s.push(0);
            nla::put(&mut self.body, IFLA_INFO_KIND, &s);
        }
        if let Some(d) = data {
            let inner = nla::nest_start(&mut self.body, IFLA_INFO_DATA);
            self.body.extend_from_slice(d);
            nla::nest_end(&mut self.body, inner);
        }
        nla::nest_end(&mut self.body, at);
        self
    }
}

#[test]
fn the_fixed_header_is_read_field_by_field() {
    let mut body = alloc::vec![0u8; IFINFOMSG_LEN];
    body[IFI_FAMILY_OFF] = 7;
    body[IFI_TYPE_OFF..IFI_TYPE_OFF + 2].copy_from_slice(&1u16.to_ne_bytes());
    body[IFI_INDEX_OFF..IFI_INDEX_OFF + 4].copy_from_slice(&42i32.to_ne_bytes());
    body[IFI_FLAGS_OFF..IFI_FLAGS_OFF + 4].copy_from_slice(&0x41u32.to_ne_bytes());
    body[IFI_CHANGE_OFF..IFI_CHANGE_OFF + 4].copy_from_slice(&0xffu32.to_ne_bytes());
    let m = parse(&body).unwrap();
    assert_eq!(m.info, IfInfo { family: 7, dev_type: 1, index: 42,
                                flags: 0x41, change: 0xff });
}

#[test]
fn a_body_shorter_than_the_fixed_header_is_refused() {
    assert_eq!(parse(&[0u8; 4]).err(), Some(Errno::Einval));
    assert_eq!(parse(&[]).err(), Some(Errno::Einval));
}

#[test]
fn a_creation_request_carries_a_name_a_kind_and_kind_data() {
    let inner = { let mut v = Vec::new(); nla::put(&mut v, 1, &100u16.to_ne_bytes()); v };
    let b = Builder::new(0).name("eth0.100")
        .attr(IFLA_LINK, &3u32.to_ne_bytes())
        .linkinfo(Some("vlan"), Some(&inner));
    let m = parse(&b.body).unwrap();
    assert_eq!(m.info.index, 0, "a creation names no device");
    assert_eq!(m.name, Some("eth0.100"));
    assert_eq!(m.link, Some(3));
    assert_eq!(m.kind, Some("vlan"));
    let data = m.data.expect("kind-private attributes");
    assert_eq!(nla::find(data, 1).unwrap().u16(), Some(100));
}

#[test]
fn a_message_with_no_envelope_names_no_kind() {
    let b = Builder::new(0).name("dummy0");
    let m = parse(&b.body).unwrap();
    assert_eq!(m.kind, None);
    assert_eq!(m.data, None);
}

#[test]
fn an_envelope_may_carry_a_kind_with_no_data() {
    let b = Builder::new(0).name("bond0").linkinfo(Some("bond"), None);
    let m = parse(&b.body).unwrap();
    assert_eq!(m.kind, Some("bond"));
    assert_eq!(m.data, None);
}

#[test]
fn a_kind_string_longer_than_the_field_is_refused() {
    // The field is fixed width on the wire; accepting a longer one would let a
    // name match a registered kind by prefix.
    let long = "a".repeat(MODULE_NAME_LEN);
    let b = Builder::new(0).name("x0").linkinfo(Some(&long), None);
    assert_eq!(parse(&b.body).err(), Some(Errno::Einval));
    let ok = "a".repeat(MODULE_NAME_LEN - 1);
    let b = Builder::new(0).name("x0").linkinfo(Some(&ok), None);
    assert_eq!(parse(&b.body).unwrap().kind.map(|s| s.len()), Some(MODULE_NAME_LEN - 1));
}

#[test]
fn an_empty_kind_or_name_is_refused() {
    let b = Builder::new(0).name("x0").linkinfo(Some(""), None);
    assert_eq!(parse(&b.body).err(), Some(Errno::Einval));
    let b = Builder::new(0).name("");
    assert_eq!(parse(&b.body).err(), Some(Errno::Einval));
}

#[test]
fn an_interface_name_at_or_over_the_limit_is_refused() {
    let b = Builder::new(0).name(&"n".repeat(IFNAMSIZ));
    assert_eq!(parse(&b.body).err(), Some(Errno::Einval));
    let b = Builder::new(0).name(&"n".repeat(IFNAMSIZ - 1));
    assert!(parse(&b.body).is_ok());
}

#[test]
fn a_wrongly_sized_scalar_attribute_is_refused() {
    let b = Builder::new(0).name("x0").attr(IFLA_MTU, &[1, 2]);
    assert_eq!(parse(&b.body).err(), Some(Errno::Einval));
    let b = Builder::new(0).name("x0").attr(IFLA_LINK, &[1]);
    assert_eq!(parse(&b.body).err(), Some(Errno::Einval));
}

#[test]
fn the_slave_side_of_the_envelope_is_read_separately() {
    let mut body = alloc::vec![0u8; IFINFOMSG_LEN];
    body[IFI_INDEX_OFF..IFI_INDEX_OFF + 4].copy_from_slice(&5i32.to_ne_bytes());
    nla::put(&mut body, IFLA_MASTER, &9u32.to_ne_bytes());
    let at = nla::nest_start(&mut body, IFLA_LINKINFO);
    nla::put(&mut body, IFLA_INFO_SLAVE_KIND, b"bond\0");
    let inner = nla::nest_start(&mut body, IFLA_INFO_SLAVE_DATA);
    nla::put(&mut body, 1, &7u32.to_ne_bytes());
    nla::nest_end(&mut body, inner);
    nla::nest_end(&mut body, at);

    let m = parse(&body).unwrap();
    assert_eq!(m.master, Some(9));
    assert_eq!(m.slave_kind, Some("bond"));
    assert_eq!(m.kind, None, "a slave kind is not the device's own kind");
    assert!(m.slave_data.is_some());
}

#[test]
fn a_duplicated_attribute_keeps_the_first() {
    let b = Builder::new(0).name("first").name("second");
    assert_eq!(parse(&b.body).unwrap().name, Some("first"));
}

#[test]
fn the_envelope_round_trips_through_the_encoder() {
    let inner = { let mut v = Vec::new(); nla::put(&mut v, 1, &200u16.to_ne_bytes()); v };
    let mut out = Vec::new();
    put_linkinfo(&mut out, "vlan", Some(&inner));
    let mut body = alloc::vec![0u8; IFINFOMSG_LEN];
    body.extend_from_slice(&out);
    let m = parse(&body).unwrap();
    assert_eq!(m.kind, Some("vlan"));
    assert_eq!(nla::find(m.data.unwrap(), 1).unwrap().u16(), Some(200));
}
