//! One live `HDIO_GET_IDENTITY` transaction against the QEMU AHCI disk.

use support::{fail, line, report, Verdict};

const PROBE: &str = "ata_identity_probe";
const HDIO_GET_IDENTITY: libc::c_ulong = 0x030d;
const IDENTIFY_BYTES: usize = 512;
const SERIAL_OFFSET: usize = 20;
const FIRMWARE_OFFSET: usize = 46;
const MODEL_OFFSET: usize = 54;

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    for suffix in b'a'..=b'z' {
        let path = format!("/dev/sd{}", suffix as char);
        let c_path = std::ffi::CString::new(path.as_str()).expect("node path");
        // SAFETY: `c_path` remains a valid NUL-terminated pathname through the
        // call and the descriptor is closed on every path below.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd < 0 { continue; }
        let mut page = [0u8; IDENTIFY_BYTES];
        // SAFETY: the direct ABI number is Linux's `HDIO_GET_IDENTITY` and
        // `page` is exactly the documented 512-byte output object.
        let result = unsafe { libc::ioctl(fd, HDIO_GET_IDENTITY, page.as_mut_ptr()) };
        let errno = support::errno();
        // SAFETY: `fd` came from `open` and is closed exactly once here.
        unsafe { libc::close(fd); }
        if result == 0 { return validate(&path, &page); }
        if errno == libc::ENOTTY { continue; }
        return fail(&format!("ioctl path={path} errno={errno}"));
    }
    fail("no-sd-node-answered-hdio-get-identity")
}

fn validate(path: &str, page: &[u8; IDENTIFY_BYTES]) -> Verdict {
    let serial = ata_string(page, SERIAL_OFFSET, 20);
    let firmware = ata_string(page, FIRMWARE_OFFSET, 8);
    let model = ata_string(page, MODEL_OFFSET, 40);
    line(&format!("{PROBE}: path={path} serial={serial} firmware={firmware} model={model}"));
    if serial != "oxahci0" { return fail("unexpected-ata-serial"); }
    if firmware != "2.5+" { return fail("firmware-was-not-word-normalized"); }
    if !model.starts_with("QEMU HARDDISK") { return fail("model-was-not-word-normalized"); }
    Verdict::Pass(format!("path={path} serial={serial} model={model}"))
}

fn ata_string(page: &[u8; IDENTIFY_BYTES], offset: usize, bytes: usize) -> String {
    let field = &page[offset..offset + bytes];
    let first = field.iter().position(|byte| !matches!(*byte, b' ' | 0)).unwrap_or(bytes);
    let last = field.iter().rposition(|byte| !matches!(*byte, b' ' | 0)).map_or(first, |index| index + 1);
    String::from_utf8_lossy(&field[first..last]).into_owned()
}
