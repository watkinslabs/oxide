use alloc::string::String;
use alloc::vec::Vec;

use super::{virt_like, Fdt};
use crate::header::DtbError;
use crate::walk::{find_prop, walk, Event, Flow};

/// Flatten a walk into `"<depth><kind>:<name>"` lines so ordering and depth
/// are both asserted, not just membership.
fn trace(blob: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    walk(blob, |ev| {
        match ev {
            Event::BeginNode { name, depth } =>
                out.push(alloc::format!("{depth}N:{}", String::from_utf8_lossy(name))),
            Event::Prop { name, data, depth } =>
                out.push(alloc::format!("{depth}P:{}={}", String::from_utf8_lossy(name), data.len())),
            Event::EndNode { depth } => out.push(alloc::format!("{depth}E")),
        }
        Flow::Continue
    }).expect("walk");
    out
}

#[test]
fn walk_emits_nodes_props_and_depths_in_wire_order() {
    let blob = Fdt::new().begin("").prop_u32("a", 1).begin("kid").prop_str("b", "x").end().end().finish();
    assert_eq!(trace(&blob), alloc::vec![
        String::from("0N:"), String::from("0P:a=4"),
        String::from("1N:kid"), String::from("1P:b=2"), String::from("1E"),
        String::from("0E"),
    ]);
}

#[test]
fn walk_stops_when_the_callback_says_stop() {
    let blob = virt_like();
    let mut seen = 0usize;
    walk(&blob, |_| { seen += 1; Flow::Stop }).expect("walk");
    assert_eq!(seen, 1, "Stop must end the walk after the first event");
}

#[test]
fn walk_rejects_an_unknown_token() {
    let mut blob = Fdt::new().begin("").end().finish();
    // Overwrite the first token of the struct block, wherever the header says
    // it starts — hardcoding the offset breaks the moment the header grows.
    let st = crate::parse_header(&blob).expect("header").off_dt_struct as usize;
    blob[st..st + 4].copy_from_slice(&7u32.to_be_bytes());
    assert_eq!(walk(&blob, |_| Flow::Continue).err(), Some(DtbError::Inval));
}

#[test]
fn walk_rejects_a_property_length_past_the_struct_block() {
    let mut blob = Fdt::new().begin("").prop_u32("a", 1).end().finish();
    // BEGIN_NODE(4) + name ""(4) = 8, then the PROP token(4), then its length.
    let st = crate::parse_header(&blob).expect("header").off_dt_struct as usize;
    blob[st + 12..st + 16].copy_from_slice(&0xffffu32.to_be_bytes());
    assert_eq!(walk(&blob, |_| Flow::Continue).err(), Some(DtbError::Truncated));
}

#[test]
fn walk_rejects_an_unterminated_node_name() {
    let mut blob = Fdt::new().begin("nodename").end().finish();
    // Fill the struct block with non-NUL after the opening token.
    let st = crate::parse_header(&blob).expect("header").off_dt_struct as usize;
    let n = blob.len();
    for b in blob[st + 4..n - 4].iter_mut() { *b = b'x'; }
    assert!(matches!(walk(&blob, |_| Flow::Continue), Err(DtbError::Truncated) | Err(DtbError::Inval)));
}

#[test]
fn find_prop_reads_the_named_node_only() {
    let blob = virt_like();
    let got = find_prop(&blob, |n, d| d == 1 && n == b"chosen", b"bootargs").expect("bootargs");
    assert_eq!(&got[..got.len() - 1], b"console=ttyAMA0 root=/dev/vda2");
    // `device_type` exists on /memory but not on /chosen — a matcher that
    // leaked across nodes would find it.
    assert!(find_prop(&blob, |n, d| d == 1 && n == b"chosen", b"device_type").is_none());
}
