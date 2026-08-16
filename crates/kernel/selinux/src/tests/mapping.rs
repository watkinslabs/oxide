// Kernel-to-policy class and permission translation.
//
// The fixture policy numbers every permission differently from the kernel, so
// a translation that quietly returned its input would fail here rather than
// pass by coincidence.

use crate::services::fixture::*;

use crate::mapping::{kernel_perm_bit, Mapping, UNKNOWN_PERM_BITS};
use crate::uapi::classmap::class_by_name;

fn kcls(name: &str) -> u16 { class_by_name(name).expect("kernel class") }

fn kperm(class: u16, name: &str) -> u32 { kernel_perm_bit(class, name).expect("kernel perm") }

#[test]
fn a_class_maps_to_the_policy_value_of_the_same_name() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    assert_eq!(map.policy_class(kcls("process")), Some(CLS_PROCESS));
    assert_eq!(map.policy_class(kcls("file")), Some(CLS_FILE));
    assert_eq!(map.policy_class(kcls("dir")), Some(CLS_DIR));
    assert_eq!(map.kernel_class(CLS_DIR), Some(kcls("dir")));
    assert_eq!(map.kernel_class(999), None);
}

#[test]
fn a_class_the_policy_lacks_is_recorded_and_maps_to_nothing() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let unknown = kcls("filesystem");
    assert_eq!(map.policy_class(unknown), None);
    assert!(map.unknown_classes().contains(&unknown));
    assert!(!map.unknown_classes().contains(&kcls("file")));
    assert_eq!(map.to_policy_av(unknown, u32::MAX), 0);
    assert_eq!(map.to_kernel_av(unknown, u32::MAX), 0);
}

#[test]
fn a_permission_maps_to_the_policy_bit_of_the_same_name() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let process = kcls("process");
    // The fixture reverses the kernel's first two process permissions.
    assert_eq!(map.to_policy_av(process, kperm(process, "fork")), P_FORK);
    assert_eq!(map.to_policy_av(process, kperm(process, "transition")), P_TRANSITION);
    assert_ne!(kperm(process, "fork"), P_FORK);
}

#[test]
fn an_inherited_permission_maps_through_the_common() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let file = kcls("file");
    // `read` is declared by the common, `execute` by the class itself.
    assert_eq!(map.to_policy_av(file, kperm(file, "read")), F_READ);
    assert_eq!(map.to_policy_av(file, kperm(file, "execute")), F_EXECUTE);
    assert_eq!(map.to_policy_av(file, kperm(file, "entrypoint")), F_ENTRYPOINT);
}

#[test]
fn translation_round_trips_on_every_permission_the_policy_defines() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    for (class, names) in [
        (kcls("process"), &["transition", "fork", "sigchld", "dyntransition"][..]),
        (kcls("file"), &["read", "write", "getattr", "open", "ioctl", "execute",
                         "entrypoint", "relabelto"][..]),
        (kcls("dir"), &["search", "read", "write", "add_name", "remove_name", "getattr"][..]),
    ] {
        let mut all = 0u32;
        for name in names {
            let kbit = kperm(class, name);
            all |= kbit;
            let pbit = map.to_policy_av(class, kbit);
            assert_ne!(pbit, UNKNOWN_PERM_BITS, "{name}");
            assert_eq!(map.to_kernel_av(class, pbit), kbit, "{name}");
        }
        assert_eq!(map.to_kernel_av(class, map.to_policy_av(class, all)), all);
    }
}

#[test]
fn a_permission_the_policy_lacks_maps_to_no_bits() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let file = kcls("file");
    // The fixture's `file` class declares neither of these.
    for name in ["unlink", "append", "setattr", "lock", "map"] {
        let kbit = kperm(file, name);
        assert_eq!(map.to_policy_av(file, kbit), UNKNOWN_PERM_BITS, "{name}");
    }
    // An access vector granting everything the policy CAN express still grants
    // no kernel permission the policy never named.
    let granted = map.to_kernel_av(file, u32::MAX);
    assert_eq!(granted & kperm(file, "unlink"), 0);
    assert_eq!(granted & kperm(file, "read"), kperm(file, "read"));
}

#[test]
fn a_shifted_permission_value_would_name_a_different_permission() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let dir = kcls("dir");
    // `search` is policy value 1 and therefore policy bit 0; reading it as
    // bit 1 would answer a search query with the verdict for `read`.
    assert_eq!(map.to_policy_av(dir, kperm(dir, "search")), 1 << 0);
    assert_eq!(map.to_policy_av(dir, kperm(dir, "read")), 1 << 1);
    assert_eq!(map.to_kernel_av(dir, 1 << 0), kperm(dir, "search"));
}

#[test]
fn an_empty_vector_translates_to_nothing_in_both_directions() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let file = kcls("file");
    assert_eq!(map.to_policy_av(file, 0), 0);
    assert_eq!(map.to_kernel_av(file, 0), 0);
}
