use crate::tree::{MemoryEvent, MemoryKind, ROOT, Tree};

const PAGE_BYTES: u64 = 4096;

fn s(v: &[u8]) -> &str { core::str::from_utf8(v).unwrap() }

fn memory_tree() -> (Tree, u64) {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (cgid, _) = t.create(ROOT, "svc").unwrap();
    (t, cgid)
}

#[test]
fn memory_max_enforced_and_charged() {
    let (mut t, c) = memory_tree();
    t.write_file(c, "memory.max", "4096").unwrap();
    assert!(t.try_charge_memcg(c, PAGE_BYTES));
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "4096\n");
    assert!(!t.try_charge_memcg(c, 1));
    assert_eq!(s(&t.read_file(c, "memory.events").unwrap()), "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\n");
    t.uncharge_memcg(c, PAGE_BYTES);
    assert!(t.try_charge_memcg(c, PAGE_BYTES / 2));
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "2048\n");
}

#[test]
fn memory_high_is_only_a_charge_side_crossing() {
    let (mut t, c) = memory_tree();
    t.write_file(c, "memory.high", "4096").unwrap();
    assert_eq!(t.try_charge_memory_transition(c, MemoryKind::Anon, PAGE_BYTES),
        crate::MemoryCharge::Charged { crossed_high: false });
    assert_eq!(t.try_charge_memory_transition(c, MemoryKind::Anon, 1),
        crate::MemoryCharge::Charged { crossed_high: true });
    assert_eq!(t.try_charge_memory_transition(c, MemoryKind::Anon, 1),
        crate::MemoryCharge::Charged { crossed_high: false });
}

#[test]
fn memory_max_transition_names_the_limiting_ancestor() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (parent, _) = t.create(ROOT, "p").unwrap();
    t.write_subtree_control(parent, "+memory").unwrap();
    t.write_file(parent, "memory.max", "4096").unwrap();
    let (child, _) = t.create(parent, "c").unwrap();
    assert_eq!(t.try_charge_memory_transition(child, MemoryKind::Anon, PAGE_BYTES),
        crate::MemoryCharge::Charged { crossed_high: false });
    assert_eq!(t.try_charge_memory_transition(child, MemoryKind::Anon, 1),
        crate::MemoryCharge::Max { limit_cgid: parent });
}

#[test]
fn memory_unlimited_when_max_unset() {
    let (mut t, c) = memory_tree();
    const GIB_BYTES: u64 = 1024 * 1024 * 1024;
    assert!(t.try_charge_memcg(c, GIB_BYTES));
    assert_eq!(t.subtree_mem(c), GIB_BYTES);
}

#[test]
fn memory_max_enforced_hierarchically() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (parent, _) = t.create(ROOT, "p").unwrap();
    t.write_subtree_control(parent, "+memory").unwrap();
    t.write_file(parent, "memory.max", "8192").unwrap();
    let (child, _) = t.create(parent, "c").unwrap();
    assert!(t.try_charge_memcg(child, PAGE_BYTES * 2));
    assert!(!t.try_charge_memcg(child, 1));
    assert_eq!(s(&t.read_file(parent, "memory.current").unwrap()), "8192\n");
    assert_eq!(s(&t.read_file(child, "memory.current").unwrap()), "8192\n");
    assert_eq!(s(&t.read_file(parent, "memory.events").unwrap()), "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\n");
}

#[test]
fn memory_stat_uses_concrete_owner_ledgers() {
    let (mut t, c) = memory_tree();
    assert!(t.try_charge_memory(c, MemoryKind::Anon, PAGE_BYTES));
    assert!(t.try_charge_memory(c, MemoryKind::File, PAGE_BYTES / 2));
    assert!(t.try_charge_memory(c, MemoryKind::Shmem, PAGE_BYTES / 4));
    assert!(t.try_charge_memory(c, MemoryKind::SlabReclaimable, PAGE_BYTES / 8));
    assert!(t.try_charge_memory(c, MemoryKind::SlabUnreclaimable, PAGE_BYTES / 16));
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "7936\n");
    assert_eq!(s(&t.read_file(c, "memory.stat").unwrap()), "anon 4096\nfile 3072\nkernel 768\nkernel_stack 0\npagetables 0\npercpu 0\nsock 0\nvmalloc 0\nshmem 1024\nslab_reclaimable 512\nslab_unreclaimable 256\nslab 768\n");
    t.uncharge_memory(c, MemoryKind::File, PAGE_BYTES / 2);
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "5888\n");
}

#[test]
fn owner_events_are_hierarchical_but_not_inferred() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (parent, _) = t.create(ROOT, "p").unwrap();
    t.write_subtree_control(parent, "+memory").unwrap();
    let (child, _) = t.create(parent, "c").unwrap();
    t.record_memory_event(child, MemoryEvent::High);
    t.record_memory_event(child, MemoryEvent::Oom);
    t.record_memory_event(child, MemoryEvent::OomKill);
    assert_eq!(s(&t.read_file(child, "memory.events").unwrap()), "low 0\nhigh 1\nmax 0\noom 1\noom_kill 1\n");
    assert_eq!(s(&t.read_file(parent, "memory.events").unwrap()), "low 0\nhigh 1\nmax 0\noom 1\noom_kill 1\n");
}

#[test]
fn exit_preserves_page_owned_memory_charge() {
    let (mut t, c) = memory_tree();
    t.add_proc(c, 100);
    t.write_file(c, "memory.max", "4096").unwrap();
    assert!(t.try_charge_memcg(c, PAGE_BYTES / 4));
    assert!(t.try_charge_memcg(c, PAGE_BYTES / 2));
    t.remove_proc(100);
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "3072\n");
    t.uncharge_memcg(c, PAGE_BYTES - PAGE_BYTES / 4);
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "0\n");
}

#[test]
fn move_preserves_page_owned_memory_charge() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (a, _) = t.create(ROOT, "a").unwrap();
    let (b, _) = t.create(ROOT, "b").unwrap();
    t.add_proc(a, 50);
    assert!(t.try_charge_memcg(a, PAGE_BYTES));
    t.add_proc(b, 50);
    assert_eq!(s(&t.read_file(a, "memory.current").unwrap()), "4096\n");
    assert_eq!(s(&t.read_file(b, "memory.current").unwrap()), "0\n");
    t.uncharge_memcg(a, PAGE_BYTES);
    assert_eq!(s(&t.read_file(a, "memory.current").unwrap()), "0\n");
}

#[test]
fn charged_memcg_cannot_be_removed_before_page_release() {
    let (mut t, c) = memory_tree();
    assert!(t.try_charge_memcg(c, PAGE_BYTES));
    assert!(matches!(t.remove(c), Err(vfs::VfsError::Ebusy)));
    t.uncharge_memcg(c, PAGE_BYTES);
    assert!(t.remove(c).is_ok());
}

#[test]
fn swap_charge_is_hierarchical_and_stays_with_owning_memcg() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (parent, _) = t.create(ROOT, "p").unwrap();
    t.write_subtree_control(parent, "+memory").unwrap();
    let (child, _) = t.create(parent, "c").unwrap();
    t.write_file(parent, "memory.swap.max", "8192").unwrap();
    assert!(t.try_charge_swap(child, PAGE_BYTES));
    assert_eq!(s(&t.read_file(child, "memory.swap.current").unwrap()), "4096\n");
    assert_eq!(s(&t.read_file(parent, "memory.swap.current").unwrap()), "4096\n");
    assert!(!t.try_charge_swap(child, PAGE_BYTES * 2));
    t.uncharge_swap(child, PAGE_BYTES);
    assert_eq!(s(&t.read_file(parent, "memory.swap.current").unwrap()), "0\n");
}

#[test]
fn swap_charge_rejects_unknown_memcg_owner() {
    const UNKNOWN_MEMCG: u64 = u64::MAX;
    let mut t = Tree::new();
    t.mount_root();
    assert!(!t.try_charge_swap(UNKNOWN_MEMCG, PAGE_BYTES));
    assert_eq!(s(&t.read_file(ROOT, "memory.swap.current").unwrap()), "0\n");
}
