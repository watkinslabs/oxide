// The transaction nodes driven the way userspace drives them: ONE open
// description, a write of the request, then a read of the answer with no seek
// in between.
//
// Every other test in this crate calls `transact` directly, which is where the
// answer is computed but not where it is delivered. That gap hid a live defect
// for the whole of the desktop-boot campaign: the write advanced the
// description's cursor, so the read that followed started past the answer and
// copied out nothing — and a zero-length read is not an error to the caller,
// it is an EMPTY CONTEXT. What the first user process reported was
// `Failed to transition into init label ''`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

use vfs::{Dentry, File, OpenFlags};

use crate::nodes::transaction::{make_transaction, TxKind};

/// Distribution policy this box carries, when it carries one.
const DISTRO_POLICY: &str = "/etc/selinux/targeted/policy/policy.34";

/// Context the first user process runs under before it transitions.
const INIT_SUBJECT: &str = "system_u:system_r:kernel_t:s0";
/// Context of the binary it is about to become.
const INIT_EXEC: &str = "system_u:object_r:init_exec_t:s0";
/// Context the policy says that pairing produces.
const INIT_LABEL: &str = "system_u:system_r:init_t:s0";
/// Context of the display-manager process that opens the PAM session.
const GDM_SUBJECT: &str = "system_u:system_r:xdm_t:s0";
/// Context the distribution assigns to numbered virtual terminals.
const TTY_LABEL: &str = "system_u:object_r:tty_device_t:s0";

/// One open description on a transaction node, as userspace opens it.
fn description(kind: TxKind) -> Arc<File> {
    let inode = make_transaction(kind);
    File::new(inode.clone(), Dentry::new_root(inode), OpenFlags::O_RDWR)
}

/// Write a request and read the answer back, on one description.
fn ask(kind: TxKind, request: &[u8]) -> String {
    let file = description(kind);
    let written = file.write(request).expect("the request is accepted");
    assert_eq!(written, request.len(), "a short write would truncate the request");
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf).expect("the answer is readable");
    String::from_utf8(buf[..n].to_vec()).expect("the answer is text")
}

#[test]
fn an_answer_is_read_back_from_the_description_that_asked() {
    // The compatibility node answers without consulting the policy, so this
    // holds with no security server installed at all — which is what makes it
    // the check that runs everywhere, not only where a policy file exists.
    assert_eq!(ask(TxKind::User, b"anything at all"), "0");
}

#[test]
fn a_request_does_not_move_the_cursor_the_answer_is_read_from() {
    let file = description(TxKind::User);
    file.write(b"a request of some length").expect("write");
    assert_eq!(file.pos(), 0,
               "the answer is read from offset zero of this same description");
}

#[test]
fn reading_past_the_answer_ends_it() {
    // The cursor the READ advances still ends the answer, so a caller looping
    // until zero terminates rather than repeating the answer forever.
    let file = description(TxKind::User);
    file.write(b"q").expect("write");
    let mut buf = vec![0u8; 64];
    assert_eq!(file.read(&mut buf).expect("first read"), 1);
    assert_eq!(file.read(&mut buf).expect("second read"), 0);
}

/// Install the live server with the distribution policy loaded, permissive.
///
/// `false` when the box carries no policy image; the caller skips.
/// Permissive because the subject of a write with no task accessor installed
/// is the kernel's own label, which the policy does not grant the security
/// class to — the question under test is the ANSWER, not the gate, and the
/// gate has its own tests.
fn live_policy() -> bool {
    let Ok(image) = std::fs::read(DISTRO_POLICY) else {
        std::println!("skipping: {DISTRO_POLICY} is not present on this machine");
        return false;
    };
    selinux_runtime::install(selinux::BootConfig::default());
    let ok = selinux_runtime::with(|s| {
        if s.policy().is_none() { s.load_policy(&image).expect("the policy loads"); }
        s.set_enforcing(selinux::Enforcing::Permissive).expect("permissive");
        true
    });
    ok.unwrap_or(false)
}

/// Class value the `class/` tree publishes for a name — what userspace writes
/// back in a request, and the numbering the request is answered in.
fn published_class(name: &str) -> u16 {
    selinux_runtime::with(|s| {
        s.policy().expect("policy").symbols.classes.iter()
            .find(|c| c.name == name).expect("the policy declares the class").value as u16
    }).expect("server")
}

#[test]
fn the_create_node_answers_the_label_the_first_process_transitions_into() {
    if !live_policy() { return }
    let class = published_class("process");
    let request = alloc::format!("{INIT_SUBJECT} {INIT_EXEC} {class}");
    let answer = ask(TxKind::Create, request.as_bytes());
    assert!(!answer.is_empty(),
            "an empty answer is what a caller hands to setcon, which refuses it");
    assert_eq!(answer, INIT_LABEL);
}

#[test]
fn the_create_node_answers_a_pairing_no_rule_names() {
    if !live_policy() { return }
    // No type transition names this pairing, and that is not an error: the
    // class default decides, and for a process class the source's own type is
    // what the object keeps.
    let class = published_class("process");
    let request = alloc::format!("{INIT_SUBJECT} {INIT_SUBJECT} {class}");
    let answer = ask(TxKind::Create, request.as_bytes());
    assert_eq!(answer, INIT_SUBJECT);
}

#[test]
fn the_relabel_node_answers_the_context_pam_selinux_sets_on_a_tty() {
    if !live_policy() { return }
    // pam_selinux gets the tty's current context, writes it with the process
    // context and the chr_file class to `relabel`, then hands this answer to
    // setfilecon. These are the Fedora policy's xdm and `/dev/ttyN` labels.
    let class = published_class("chr_file");
    let request = alloc::format!("{GDM_SUBJECT} {TTY_LABEL} {class}");
    let answer = ask(TxKind::Relabel, request.as_bytes());
    assert!(!answer.is_empty(),
            "an empty relabel answer is what pam_selinux hands to setfilecon");
    assert_eq!(answer, TTY_LABEL);
}

#[test]
fn the_access_node_answers_in_the_numbering_the_class_tree_publishes() {
    if !live_policy() { return }
    let class = published_class("file");
    let request = alloc::format!("{INIT_SUBJECT} {INIT_EXEC} {class}");
    let answer = ask(TxKind::Access, request.as_bytes());
    let fields: alloc::vec::Vec<&str> = answer.split(' ').collect();
    assert_eq!(fields.len(), 6, "allowed, decided, auditallow, auditdeny, seqno, flags");
    let allowed = u32::from_str_radix(fields[0], 16).expect("hex");
    assert_ne!(allowed, 0, "the kernel domain may read its own init binary");
}

#[test]
fn a_class_whose_two_numberings_differ_is_answered_in_the_published_one() {
    if !live_policy() { return }
    // Userspace writes the value the `class/` tree published. Reading that
    // value as the KERNEL's own class number answers about a different class,
    // silently. Find a class where the two readings produce different labels
    // and pin the answer to the published one.
    let subject = INIT_SUBJECT;
    let object = INIT_EXEC;
    let divergent = selinux_runtime::with(|s| {
        let names: alloc::vec::Vec<(String, u32)> = s.policy().expect("policy")
            .symbols.classes.iter().map(|c| (c.name.clone(), c.value)).collect();
        let ssid = s.context_to_sid(subject).expect("subject");
        let tsid = s.context_to_sid(object).expect("object");
        names.into_iter().find_map(|(name, published)| {
            let kernel = selinux::uapi::classmap::class_by_name(&name)?;
            if kernel as u32 == published { return None }
            let as_published = s.transition_sid_user(ssid, tsid, published, None)
                .and_then(|n| s.sid_to_context(n)).ok()?;
            let as_kernel = s.transition_sid(ssid, tsid, kernel, None)
                .and_then(|n| s.sid_to_context(n)).ok()?;
            if as_published == as_kernel { return None }
            Some((name, published, as_published))
        })
    }).expect("server");
    let Some((name, published, expected)) = divergent else {
        std::println!("skipping: no class on this policy distinguishes the two numberings");
        return;
    };
    let request = alloc::format!("{subject} {object} {published}");
    assert_eq!(ask(TxKind::Create, request.as_bytes()), expected,
               "class {name}: the request names the published value {published}");
}
