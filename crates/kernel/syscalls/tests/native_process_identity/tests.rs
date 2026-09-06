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
    // A resolved host path is what permits publishing exe; the command line
    // is the process's own. Both were added when the PE handoff was found to
    // leave procfs describing the launcher rather than the running image.
    super::identity::publish(&child, super::nt_process_naming::comm_of(path), Some(path), "C:\\notepad.exe");
    assert_eq!(child.exe_path().as_deref(), Some(path));
    if let Some(mm) = mm { assert_eq!(mm.exe_path().as_deref(), Some(path)); }
    assert_eq!(child.cmdline().as_deref(), Some("C:\\notepad.exe"));
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
    let hook = source.find("identity::publish(&child, crate::nt_process_naming::comm_of(&image_path), host_path, command.as_str());").expect("production identity hook");
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
    let hook = "identity::publish(&child, crate::nt_process_naming::comm_of(&image_path), host_path, command.as_str());";
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
            // The production line resolves the process name through the crate
            // root, so the control program must provide that path too.
            mod nt_process_naming {{
                pub fn comm_of(path: &str) -> &str {{
                    path.rsplit(['\\', '/']).next().filter(|n| !n.is_empty()).unwrap_or(path)
                }}
            }}
            fn main() {{
                let child = sched::Task::new(733, "nt-process", sched::SchedClass::Normal {{ weight: 1024 }});
                let image_path = String::from("/usr/lib/wine/notepad.exe");
                // The slice derives host_path from the resolved image, so the
                // control supplies a stand-in for that resolution.
                let vp: Option<()> = Some(());
                let command = String::from("C:\\notepad.exe");
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

#[test]
fn an_image_with_no_host_path_publishes_no_executable() {
    // ExecuteWithCatalog can carry an image name that is not a host pathname.
    // Publishing exe from it would report a file that never existed, so a
    // child whose bytes came from elsewhere keeps no exe at all.
    let _serial = SERIAL.lock().unwrap();
    let child = Task::new(734, "nt-process", SchedClass::Normal { weight: 1024 });
    child.set_nt_personality(true);
    sched::task::set_comm_hook(ignore);
    super::identity::publish(&child, super::nt_process_naming::comm_of("C:\\windows\\notepad.exe"), None, "C:\\notepad.exe");
    assert_eq!(child.exe_path(), None, "no host path means no exe");
    assert_eq!(child.cmdline().as_deref(), Some("C:\\notepad.exe"));
    let bytes = child.comm_bytes();
    assert_eq!(&bytes[..11], b"notepad.exe", "comm still comes from the Windows name");
}
