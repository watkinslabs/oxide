use sched::{Task, SchedClass};
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());
static EVENTS: Mutex<Vec<(u32, Vec<u8>, bool)>> = Mutex::new(Vec::new());
fn notify(tid: u32, _: i32, name: &[u8], exec: bool) {
    EVENTS.lock().unwrap().push((tid, name.to_vec(), exec));
}
fn ignore(_: u32, _: i32, _: &[u8], _: bool) {}
struct Hook;
impl Drop for Hook { fn drop(&mut self) { sched::task::set_comm_hook(ignore); } }

fn check(path: &str, expected: &[u8], with_mm: bool) {
    let _serial = SERIAL.lock().unwrap();
    let child = Task::new(733, "nt-process", SchedClass::Normal { weight: 1024 });
    let mm = with_mm.then(|| vmm::AddressSpace::new(0).unwrap());
    // SAFETY: this fixture exclusively owns the unregistered task and keeps
    // the address-space owner alive throughout publication and observation.
    unsafe { child.replace_mm(mm.clone()); }
    child.set_nt_personality(true);
    EVENTS.lock().unwrap().clear();
    sched::task::set_comm_hook(notify);
    let _hook = Hook;
    super::identity::publish(&child, path);
    assert_eq!(child.exe_path().as_deref(), Some(path));
    if let Some(mm) = mm { assert_eq!(mm.exe_path().as_deref(), Some(path)); }
    let bytes = child.comm_bytes();
    assert_eq!(&bytes[..expected.len()], expected);
    assert!(bytes[expected.len()..].iter().all(|byte| *byte == 0));
    assert_eq!(*EVENTS.lock().unwrap(), vec![(733, expected.to_vec(), true)]);
    assert_eq!(child.tid, 733);
    assert!(child.is_nt_personality());
}

#[test]
fn basename_and_both_executable_owners() { check("/usr/lib/wine/notepad.exe", b"notepad.exe", true); }
#[test]
fn bare_basename_without_mm() { check("notepad.exe", b"notepad.exe", false); }
#[test]
fn long_name_uses_canonical_byte_truncation() { check("/windows/abcdefghijklmnop.exe", b"abcdefghijklmno", true); }
#[test]
fn utf8_boundary_is_byte_truncated_not_reencoded() { check("/windows/abcdefghijklmn\u{e9}.exe", b"abcdefghijklmn\xc3", true); }

#[test]
fn production_hook_precedes_child_publication() {
    let source = include_str!("../../src/nt_process_create.rs");
    let teb = source.find("child.set_nt_teb(").unwrap();
    let hook = source.find("identity::publish(&child, &image_path);").expect("production identity hook");
    let arm = source.find("sched::live::arm_user_entry(&child").unwrap();
    assert!(teb < hook && hook < arm, "identity must be installed on the unpublished image");
}

#[test]
fn executable_parent_slice_rejects_omitted_hook() {
    use std::{io::Write, process::{Command, Stdio}};
    let source = include_str!("../../src/nt_process_create.rs");
    let start = source.find("child.set_nt_teb(").unwrap();
    let start = start + source[start..].find(';').unwrap() + 1;
    let end = source[start..].find("if let Some(catalog)").unwrap() + start;
    let slice = &source[start..end];
    let hook = "identity::publish(&child, &image_path);";
    assert_eq!(slice.matches(hook).count(), 1);
    let deps = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let libraries: Vec<_> = std::fs::read_dir(&deps).unwrap().map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with("libsched-")
            && path.extension().is_some_and(|ext| ext == "rlib")).collect();
    assert_eq!(libraries.len(), 1, "use this lane's private target to resolve canonical sched");
    let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nt_process_create/identity.rs");
    let binary = deps.join(format!("native-identity-control-{}", std::process::id()));
    for omit in [false, true] {
        let body = if omit { slice.replace(hook, "") } else { slice.to_owned() };
        let program = format!(r#"
            #[path = {helper:?}] mod identity;
            fn main() {{
                let child = sched::Task::new(733, "nt-process", sched::SchedClass::Normal {{ weight: 1024 }});
                let image_path = String::from("/usr/lib/wine/notepad.exe");
                {body}
                assert_eq!(child.comm(), "notepad.exe");
                assert_eq!(child.exe_path().as_deref(), Some(image_path.as_str()));
            }}"#);
        let mut compiler = Command::new("rustc").args(["--edition=2021", "--crate-name", "native_identity_control", "-"])
            .arg("--extern").arg(format!("sched={}", libraries[0].display()))
            .arg("-L").arg(format!("dependency={}", deps.display()))
            .arg("-o").arg(&binary).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        compiler.stdin.take().unwrap().write_all(program.as_bytes()).unwrap();
        let compiled = compiler.wait_with_output().unwrap();
        assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
        let result = Command::new(&binary).output().unwrap();
        assert_eq!(result.status.success(), !omit, "generated production hook control: {}", String::from_utf8_lossy(&result.stderr));
        if omit { assert!(String::from_utf8_lossy(&result.stderr).contains("nt-process")); }
    }
    std::fs::remove_file(binary).unwrap();
}
