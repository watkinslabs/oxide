// Hosted tests for the hugetlb controller. Everything here drives the real
// `Tree` — the same code the kernel links — so the accounting is checked
// without a pool that can hand out physical huge pages, which a hosted build
// has none of.

use super::controllers::HUGETLB;
use super::hugetlb_types::{
    HierarchyKind, HugeAttr, HugeCounterKind, HugeGranule, attr_table, file_name, file_names,
    parse_file, parse_limit, unlimited_bytes,
};
use super::types::{ROOT, Tree};
use vfs::VfsError;

const K2M: HugeGranule = HugeGranule::Huge2M;
const K1G: HugeGranule = HugeGranule::Huge1G;
const USE: HugeCounterKind = HugeCounterKind::Usage;
const RSV: HugeCounterKind = HugeCounterKind::Reservation;

/// A mounted tree with the controller delegated one level down, so `child`
/// and `grand` both carry the interface.
fn tree3() -> (Tree, u64, u64) {
    let mut t = Tree::new();
    assert!(t.mount_root());
    t.write_subtree_control(ROOT, "+hugetlb").expect("delegate hugetlb from root");
    let (child, _) = t.create(ROOT, "child").expect("create child");
    t.write_subtree_control(child, "+hugetlb").expect("delegate hugetlb from child");
    let (grand, _) = t.create(child, "grand").expect("create grandchild");
    (t, child, grand)
}

fn read(t: &Tree, id: u64, file: &str) -> alloc::string::String {
    let bytes = t.read_file(id, file).expect("read hugetlb control file");
    alloc::string::String::from_utf8(bytes).expect("utf-8 control file")
}

#[test]
fn usage_and_reservation_are_separate_ledgers_of_the_same_granule() {
    let (mut t, _child, grand) = tree3();
    t.try_charge_hugetlb(grand, K2M, RSV, 4).expect("reserve four 2M pages");
    t.try_charge_hugetlb(grand, K2M, USE, 1).expect("fault one 2M page");
    assert_eq!(t.subtree_hugetlb(grand, K2M, RSV), 4 * K2M.base_pages());
    assert_eq!(t.subtree_hugetlb(grand, K2M, USE), 1 * K2M.base_pages());
    // A charge of one granule never touches the other's counters.
    assert_eq!(t.subtree_hugetlb(grand, K1G, USE), 0);
    assert_eq!(t.subtree_hugetlb(grand, K1G, RSV), 0);
}

#[test]
fn a_charge_rolls_up_to_every_ancestor_and_an_uncharge_removes_it() {
    let (mut t, child, grand) = tree3();
    t.try_charge_hugetlb(grand, K2M, USE, 3).expect("charge three");
    assert_eq!(t.subtree_hugetlb(grand, K2M, USE), 3 * K2M.base_pages());
    assert_eq!(t.subtree_hugetlb(child, K2M, USE), 3 * K2M.base_pages());
    assert_eq!(t.subtree_hugetlb(ROOT, K2M, USE), 3 * K2M.base_pages());
    t.uncharge_hugetlb(grand, K2M, USE, 3);
    assert_eq!(t.subtree_hugetlb(ROOT, K2M, USE), 0);
}

#[test]
fn a_limit_refuses_the_charge_that_would_exceed_it_and_commits_nothing() {
    let (mut t, _child, grand) = tree3();
    t.set_hugetlb_max(grand, K2M, USE, Some(2 * K2M.base_pages())).expect("set limit");
    t.try_charge_hugetlb(grand, K2M, USE, 2).expect("charge up to the limit");
    let refused = t.try_charge_hugetlb(grand, K2M, USE, 1).expect_err("one page over the limit");
    assert_eq!(refused.limit_cgid, grand);
    // Nothing partial was left behind by the refusal.
    assert_eq!(t.subtree_hugetlb(grand, K2M, USE), 2 * K2M.base_pages());
}

#[test]
fn the_failure_lands_on_the_ancestor_that_hit_its_limit_not_the_charger() {
    let (mut t, child, grand) = tree3();
    t.hierarchy = HierarchyKind::V1;
    t.set_hugetlb_max(child, K2M, USE, Some(1 * K2M.base_pages())).expect("limit the parent");
    let refused = t.try_charge_hugetlb(grand, K2M, USE, 2).expect_err("over the parent's limit");
    assert_eq!(refused.limit_cgid, child, "the limiting ancestor is named, not the charger");
    let fail_at_child = t.node(child).unwrap().hugetlb.counter(K2M, USE).failcnt;
    let fail_at_grand = t.node(grand).unwrap().hugetlb.counter(K2M, USE).failcnt;
    assert_eq!(fail_at_child, 1, "the failure count moves on the cgroup that refused");
    assert_eq!(fail_at_grand, 0, "the charging cgroup's failure count does not move");
    // The refusal EVENT, by contrast, is recorded where the charge was made.
    assert_eq!(t.node(grand).unwrap().hugetlb.events(K2M).max, 1);
    assert_eq!(t.node(child).unwrap().hugetlb.events(K2M).max, 0);
}

#[test]
fn only_the_legacy_hierarchy_keeps_a_failure_count() {
    for (kind, want) in [(HierarchyKind::V1, 1u64), (HierarchyKind::V2, 0u64)] {
        let (mut t, _child, grand) = tree3();
        t.hierarchy = kind;
        t.set_hugetlb_max(grand, K2M, USE, Some(0)).expect("refuse everything");
        t.try_charge_hugetlb(grand, K2M, USE, 1).expect_err("refused by a zero limit");
        assert_eq!(t.node(grand).unwrap().hugetlb.counter(K2M, USE).failcnt, want);
        // The event is recorded on BOTH hierarchies; only the count differs.
        assert_eq!(t.node(grand).unwrap().hugetlb.events(K2M).max, 1);
    }
}

#[test]
fn the_watermark_records_the_peak_and_survives_the_uncharge() {
    let (mut t, child, grand) = tree3();
    t.try_charge_hugetlb(grand, K1G, USE, 2).expect("charge two 1G pages");
    t.uncharge_hugetlb(grand, K1G, USE, 2);
    assert_eq!(t.subtree_hugetlb(child, K1G, USE), 0);
    assert_eq!(t.node(child).unwrap().hugetlb.counter(K1G, USE).watermark, 2 * K1G.base_pages());
    assert_eq!(t.node(grand).unwrap().hugetlb.counter(K1G, USE).watermark, 2 * K1G.base_pages());
}

#[test]
fn a_limit_below_the_current_charge_is_refused_and_the_root_has_no_limit() {
    let (mut t, _child, grand) = tree3();
    t.try_charge_hugetlb(grand, K2M, USE, 2).expect("charge two");
    assert_eq!(t.set_hugetlb_max(grand, K2M, USE, Some(K2M.base_pages())), Err(VfsError::Ebusy));
    assert_eq!(t.set_hugetlb_max(ROOT, K2M, USE, Some(0)), Err(VfsError::Einval));
}

#[test]
fn removing_a_cgroup_reparents_its_charges_instead_of_refusing() {
    let (mut t, child, grand) = tree3();
    t.try_charge_hugetlb(grand, K2M, USE, 2).expect("charge usage");
    t.try_charge_hugetlb(grand, K2M, RSV, 3).expect("charge a reservation");
    assert_eq!(t.reparent_hugetlb(grand), Some(child));
    t.remove(grand).expect("a cgroup with hugetlb charges is still removable");
    assert_eq!(t.subtree_hugetlb(child, K2M, USE), 2 * K2M.base_pages());
    assert_eq!(t.subtree_hugetlb(child, K2M, RSV), 3 * K2M.base_pages());
    assert!(!t.hugetlb_has_usage(child) == false);
}

#[test]
fn the_controller_is_available_only_where_it_is_delegated() {
    let mut t = Tree::new();
    assert!(t.mount_root());
    let (undelegated, _) = t.create(ROOT, "plain").expect("create without hugetlb");
    assert_eq!(t.node(undelegated).unwrap().avail & HUGETLB, 0);
    assert!(t.hugetlb_files(undelegated).is_empty());
    assert_eq!(t.read_file(undelegated, "hugetlb.2MB.current"), Err(VfsError::Enoent));
    // The root never publishes the interface even though it has every
    // controller available.
    assert!(t.hugetlb_files(ROOT).is_empty());
    assert_eq!(t.read_file(ROOT, "hugetlb.2MB.current"), Err(VfsError::Enoent));
}

#[test]
fn the_unified_interface_reports_bytes_and_the_unlimited_token() {
    let (mut t, _child, grand) = tree3();
    assert_eq!(read(&t, grand, "hugetlb.2MB.max"), "max\n");
    t.write_file(grand, "hugetlb.2MB.max", "4194304").expect("two 2M pages");
    assert_eq!(read(&t, grand, "hugetlb.2MB.max"), "4194304\n");
    t.try_charge_hugetlb(grand, K2M, USE, 1).expect("charge one");
    assert_eq!(read(&t, grand, "hugetlb.2MB.current"), "2097152\n");
    assert_eq!(read(&t, grand, "hugetlb.2MB.rsvd.current"), "0\n");
    t.try_charge_hugetlb(grand, K2M, RSV, 1).expect("reserve one");
    assert_eq!(read(&t, grand, "hugetlb.2MB.rsvd.current"), "2097152\n");
    t.write_file(grand, "hugetlb.2MB.max", "max").expect("clear the limit");
    assert_eq!(read(&t, grand, "hugetlb.2MB.max"), "max\n");
    // The events file counts refusals, hierarchically and locally.
    t.write_file(grand, "hugetlb.2MB.max", "0").expect_err("a limit under the charge is EBUSY");
    t.uncharge_hugetlb(grand, K2M, USE, 1);
    t.write_file(grand, "hugetlb.2MB.max", "0").expect("now it fits");
    t.try_charge_hugetlb(grand, K2M, USE, 1).expect_err("refused");
    assert_eq!(read(&t, grand, "hugetlb.2MB.events"), "max 1\n");
    assert_eq!(read(&t, grand, "hugetlb.2MB.events.local"), "max 1\n");
    assert_eq!(read(&t, _child, "hugetlb.2MB.events"), "max 1\n");
    assert_eq!(read(&t, _child, "hugetlb.2MB.events.local"), "max 0\n");
}

#[test]
fn a_read_only_unified_file_refuses_a_write() {
    let (mut t, _child, grand) = tree3();
    assert_eq!(t.write_file(grand, "hugetlb.2MB.current", "0"), Err(VfsError::Eacces));
    assert_eq!(t.write_file(grand, "hugetlb.2MB.events", "0"), Err(VfsError::Eacces));
}

#[test]
fn the_legacy_interface_names_and_renders_the_same_counters() {
    let (mut t, _child, grand) = tree3();
    t.hierarchy = HierarchyKind::V1;
    assert_eq!(read(&t, grand, "hugetlb.2MB.limit_in_bytes"),
        alloc::format!("{}\n", unlimited_bytes(K2M)));
    t.write_file(grand, "hugetlb.2MB.limit_in_bytes", "4M").expect("two 2M pages by suffix");
    assert_eq!(read(&t, grand, "hugetlb.2MB.limit_in_bytes"), "4194304\n");
    t.try_charge_hugetlb(grand, K2M, USE, 2).expect("charge to the limit");
    assert_eq!(read(&t, grand, "hugetlb.2MB.usage_in_bytes"), "4194304\n");
    assert_eq!(read(&t, grand, "hugetlb.2MB.max_usage_in_bytes"), "4194304\n");
    t.try_charge_hugetlb(grand, K2M, USE, 1).expect_err("over the limit");
    assert_eq!(read(&t, grand, "hugetlb.2MB.failcnt"), "1\n");
    t.write_file(grand, "hugetlb.2MB.failcnt", "0").expect("reset the failure count");
    assert_eq!(read(&t, grand, "hugetlb.2MB.failcnt"), "0\n");
    t.uncharge_hugetlb(grand, K2M, USE, 2);
    t.write_file(grand, "hugetlb.2MB.max_usage_in_bytes", "0").expect("reset the watermark");
    assert_eq!(read(&t, grand, "hugetlb.2MB.max_usage_in_bytes"), "0\n");
    t.write_file(grand, "hugetlb.2MB.limit_in_bytes", "-1").expect("legacy spells it -1");
    assert_eq!(read(&t, grand, "hugetlb.2MB.limit_in_bytes"),
        alloc::format!("{}\n", unlimited_bytes(K2M)));
    // The unified spellings are not published by the legacy hierarchy.
    assert_eq!(t.read_file(grand, "hugetlb.2MB.current"), Err(VfsError::Enoent));
}

#[test]
fn the_node_breakdown_reports_the_single_memory_node() {
    let (mut t, _child, grand) = tree3();
    t.try_charge_hugetlb(grand, K2M, USE, 1).expect("charge one");
    assert_eq!(read(&t, grand, "hugetlb.2MB.numa_stat"), "total=2097152 N0=2097152\n");
    t.hierarchy = HierarchyKind::V1;
    assert_eq!(read(&t, grand, "hugetlb.2MB.numa_stat"),
        "total=2097152 N0=2097152\nhierarchical_total=2097152 N0=2097152\n");
}

#[test]
fn a_limit_is_rounded_down_to_a_whole_number_of_huge_pages() {
    // Three 2M pages plus a base page is three 2M pages' worth of limit.
    let over = 3 * K2M.bytes() + hal::PAGE_SIZE_BYTES;
    let parsed = parse_limit(&alloc::format!("{}", over), K2M, HierarchyKind::V2)
        .expect("a plain byte count parses");
    assert_eq!(parsed, Some(3 * K2M.base_pages()));
    // A value at or above the counter ceiling IS the unlimited value.
    assert_eq!(parse_limit("max", K2M, HierarchyKind::V2), Some(None));
    assert_eq!(parse_limit("-1", K2M, HierarchyKind::V1), Some(None));
    // Each hierarchy accepts only its own token.
    assert_eq!(parse_limit("-1", K2M, HierarchyKind::V2), None);
    assert_eq!(parse_limit("max", K2M, HierarchyKind::V1), None);
    assert_eq!(parse_limit("nonsense", K2M, HierarchyKind::V2), None);
    // The suffixes a byte count may carry.
    assert_eq!(parse_limit("2M", K2M, HierarchyKind::V2), Some(Some(K2M.base_pages())));
    assert_eq!(parse_limit("2G", K1G, HierarchyKind::V2), Some(Some(2 * K1G.base_pages())));
}

#[test]
fn the_interned_file_names_match_the_attribute_table_they_index() {
    for h in [HierarchyKind::V1, HierarchyKind::V2] {
        let names = file_names(h);
        let attrs = attr_table(h);
        assert_eq!(names.len(), attrs.len() * HugeGranule::ALL.len());
        let mut i = 0;
        for g in HugeGranule::ALL {
            for (suffix, kind, attr) in attrs {
                assert_eq!(names[i], file_name(g, suffix).as_str(),
                    "interned name and its attribute-table entry must spell the same file");
                let parsed = parse_file(names[i], h).expect("every published name parses");
                assert_eq!(parsed.granule, g);
                assert_eq!(parsed.kind, *kind);
                assert_eq!(parsed.attr, *attr);
                i += 1;
            }
        }
    }
}

#[test]
fn a_name_that_is_not_this_hierarchys_file_does_not_parse() {
    assert_eq!(parse_file("hugetlb.2MB.current", HierarchyKind::V1), None);
    assert_eq!(parse_file("hugetlb.2MB.failcnt", HierarchyKind::V2), None);
    assert_eq!(parse_file("hugetlb.512MB.current", HierarchyKind::V2), None);
    assert_eq!(parse_file("memory.current", HierarchyKind::V2), None);
    assert_eq!(parse_file("hugetlb.2MB.nope", HierarchyKind::V2), None);
}

#[test]
fn the_controller_appears_in_the_delegable_set() {
    let mut t = Tree::new();
    assert!(t.mount_root());
    let avail = alloc::string::String::from_utf8(
        t.read_file(ROOT, "cgroup.controllers").expect("read cgroup.controllers")).unwrap();
    assert!(avail.contains("hugetlb"), "hugetlb must be delegable: {avail}");
    assert_eq!(t.write_subtree_control(ROOT, "+hugetlb").map(|s| s & HUGETLB != 0), Ok(true));
    let (child, _) = t.create(ROOT, "c").expect("create");
    assert!(t.hugetlb_files(child).iter().any(|f| *f == "hugetlb.2MB.max"));
    assert_eq!(t.node_files(child).iter().filter(|f| f.starts_with("hugetlb.")).count(),
        attr_table(HierarchyKind::V2).len() * HugeGranule::ALL.len(),
        "every published hugetlb file reaches readdir");
}

#[test]
fn an_attribute_only_the_reservation_ledger_owns_does_not_read_the_usage_one() {
    let (mut t, _child, grand) = tree3();
    t.try_charge_hugetlb(grand, K2M, RSV, 2).expect("reserve two");
    assert_eq!(read(&t, grand, "hugetlb.2MB.current"), "0\n");
    assert_eq!(read(&t, grand, "hugetlb.2MB.rsvd.current"), "4194304\n");
    // A usage limit does not bound reservations, and the reverse.
    t.set_hugetlb_max(grand, K2M, USE, Some(0)).expect("usage limit of zero");
    t.try_charge_hugetlb(grand, K2M, RSV, 1).expect("reservations are a separate limit");
    assert_eq!(t.try_charge_hugetlb(grand, K2M, USE, 1).map_err(|e| e.limit_cgid), Err(grand));
}

#[test]
fn the_attribute_a_file_name_addresses_is_the_one_it_reads() {
    let (mut t, _child, grand) = tree3();
    t.try_charge_hugetlb(grand, K1G, USE, 1).expect("charge a gigantic page");
    // The granule in the name selects the granule in the ledger.
    assert_eq!(read(&t, grand, "hugetlb.1GB.current"), "1073741824\n");
    assert_eq!(read(&t, grand, "hugetlb.2MB.current"), "0\n");
    let f = parse_file("hugetlb.1GB.rsvd.max", HierarchyKind::V2).expect("parses");
    assert_eq!(f.granule, K1G);
    assert_eq!(f.kind, RSV);
    assert_eq!(f.attr, HugeAttr::Limit);
}
