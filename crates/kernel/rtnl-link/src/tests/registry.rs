// The kind registry and its dispatch. The registry is process-global, so these
// take one lock and run as a single test rather than racing each other.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use syscall::errno::Errno;

use crate::msg::{LinkMsg, parse};
use crate::nla;
use crate::registry::*;
use crate::uapi::*;

struct Recording {
    kind: &'static str,
    lower: bool,
    created: AtomicU32,
    changed: AtomicU32,
    deleted: AtomicU32,
    reject: Option<Errno>,
}

impl LinkKindOps for Recording {
    fn kind(&self) -> &'static str { self.kind }
    fn needs_lower(&self) -> bool { self.lower }
    fn validate(&self, _m: &LinkMsg<'_>) -> Result<(), Errno> {
        match self.reject { Some(e) => Err(e), None => Ok(()) }
    }
    fn newlink(&self, _m: &LinkMsg<'_>) -> Result<u32, Errno> {
        Ok(self.created.fetch_add(1, Ordering::Relaxed) + 100)
    }
    fn changelink(&self, _i: u32, _m: &LinkMsg<'_>) -> Result<(), Errno> {
        self.changed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn dellink(&self, _i: u32) -> Result<(), Errno> {
        self.deleted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

static PLAIN: Recording = Recording { kind: "testkind", lower: false,
    created: AtomicU32::new(0), changed: AtomicU32::new(0),
    deleted: AtomicU32::new(0), reject: None };
static STACKED: Recording = Recording { kind: "teststack", lower: true,
    created: AtomicU32::new(0), changed: AtomicU32::new(0),
    deleted: AtomicU32::new(0), reject: None };
static REFUSING: Recording = Recording { kind: "testrefuse", lower: false,
    created: AtomicU32::new(0), changed: AtomicU32::new(0),
    deleted: AtomicU32::new(0), reject: Some(Errno::Erange) };

fn body(index: i32, name: Option<&str>, kind: Option<&str>, link: Option<u32>) -> Vec<u8> {
    let mut b = alloc::vec![0u8; IFINFOMSG_LEN];
    b[IFI_INDEX_OFF..IFI_INDEX_OFF + 4].copy_from_slice(&index.to_ne_bytes());
    if let Some(n) = name {
        let mut s = Vec::from(n.as_bytes()); s.push(0);
        nla::put(&mut b, IFLA_IFNAME, &s);
    }
    if let Some(l) = link { nla::put(&mut b, IFLA_LINK, &l.to_ne_bytes()); }
    if let Some(k) = kind {
        let at = nla::nest_start(&mut b, IFLA_LINKINFO);
        let mut s = Vec::from(k.as_bytes()); s.push(0);
        nla::put(&mut b, IFLA_INFO_KIND, &s);
        nla::nest_end(&mut b, at);
    }
    b
}

const EXISTING: u32 = 7;
fn exists(i: u32) -> bool { i == EXISTING }
fn no_kind(_: u32) -> Option<&'static str> { None }
fn plain_kind(_: u32) -> Option<&'static str> { Some("testkind") }

#[test]
fn the_registry_and_its_dispatch() {
    reset();
    assert!(register(&PLAIN).is_ok());
    assert!(register(&STACKED).is_ok());
    assert!(register(&REFUSING).is_ok());

    // A duplicate name would make lookup order decide which kind is built.
    assert_eq!(register(&PLAIN), Err(RegisterError::Exists));

    struct Bad;
    impl LinkKindOps for Bad {
        fn kind(&self) -> &'static str { "" }
        fn validate(&self, _m: &LinkMsg<'_>) -> Result<(), Errno> { Ok(()) }
        fn newlink(&self, _m: &LinkMsg<'_>) -> Result<u32, Errno> { Ok(0) }
        fn changelink(&self, _i: u32, _m: &LinkMsg<'_>) -> Result<(), Errno> { Ok(()) }
        fn dellink(&self, _i: u32) -> Result<(), Errno> { Ok(()) }
    }
    static BAD: Bad = Bad;
    assert_eq!(register(&BAD), Err(RegisterError::BadName));

    let names = kinds();
    for want in ["testkind", "teststack", "testrefuse"] {
        assert!(names.contains(&want), "{want} must be listed");
    }
    assert!(lookup("testkind").is_some());
    assert!(lookup("nosuchkind").is_none());

    // Creating a registered kind.
    let b = body(0, Some("t0"), Some("testkind"), None);
    let m = parse(&b).unwrap();
    assert_eq!(newlink(&m, exists), Ok(100));
    assert_eq!(PLAIN.created.load(Ordering::Relaxed), 1);

    // An unregistered kind must not quietly produce a plain device.
    let b = body(0, Some("t1"), Some("nosuchkind"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Eopnotsupp));

    // A creation with no kind at all is likewise not a plain device.
    let b = body(0, Some("t2"), None, None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Eopnotsupp));

    // A creation must be named; an unnamed one would collide on the next dump.
    let b = body(0, None, Some("testkind"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Einval));

    // A stacked kind must say what it is stacked on.
    let b = body(0, Some("t3"), Some("teststack"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Einval));
    let b = body(0, Some("t3"), Some("teststack"), Some(3));
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Ok(100));

    // Validation runs before anything is built, and its errno is preserved.
    let before = REFUSING.created.load(Ordering::Relaxed);
    let b = body(0, Some("t4"), Some("testrefuse"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Erange));
    assert_eq!(REFUSING.created.load(Ordering::Relaxed), before,
        "a refused request must not have built anything");

    // A message naming an existing device is a change, not a second creation.
    let created_before = PLAIN.created.load(Ordering::Relaxed);
    let b = body(EXISTING as i32, Some("t0"), Some("testkind"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Ok(EXISTING));
    assert_eq!(PLAIN.changed.load(Ordering::Relaxed), 1);
    assert_eq!(PLAIN.created.load(Ordering::Relaxed), created_before,
        "a change must not build a second device with the same name");

    // A change naming a device that is gone.
    let b = body(999, Some("t0"), Some("testkind"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Enodev));

    // Deletion resolves the kind from the device, not from the message.
    let b = body(EXISTING as i32, None, None, None);
    assert_eq!(dellink(&parse(&b).unwrap(), plain_kind), Ok(()));
    assert_eq!(PLAIN.deleted.load(Ordering::Relaxed), 1);

    // A device with no kind is not ours to delete.
    let b = body(EXISTING as i32, None, None, None);
    assert_eq!(dellink(&parse(&b).unwrap(), no_kind), Err(Errno::Eopnotsupp));

    // Index zero names nothing.
    let b = body(0, None, None, None);
    assert_eq!(dellink(&parse(&b).unwrap(), plain_kind), Err(Errno::Einval));

    assert!(unregister("testkind"));
    assert!(!unregister("testkind"));
    assert!(lookup("testkind").is_none());
    let b = body(0, Some("t0"), Some("testkind"), None);
    assert_eq!(newlink(&parse(&b).unwrap(), exists), Err(Errno::Eopnotsupp),
        "a withdrawn kind must stop being creatable");
    reset();
}
