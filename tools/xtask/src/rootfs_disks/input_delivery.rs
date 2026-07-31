use std::path::{Path, PathBuf};

const PROBE_NAME: &str = "oxide-input-delivery";
const PROBE_DESTINATION: &str = "/usr/local/bin/oxide-input-delivery";
const SERVICE_NAME: &str = "oxide-input-delivery.service";
const SERVICE_DESTINATION: &str = "/etc/systemd/system/oxide-input-delivery.service";
const WANTS_DIRECTORY: &str = "/etc/systemd/system/multi-user.target.wants";
const WANTS_DESTINATION: &str =
    "/etc/systemd/system/multi-user.target.wants/oxide-input-delivery.service";
const PROBE_FILE_MODE: &str = "0100755";
const SERVICE_TIMEOUT_SECONDS: u32 = 300;
const UDEV_SETTLE_TIMEOUT_SECONDS: u32 = 60;
/// Seconds the probe holds each evdev node open waiting for injected events.
const OBSERVE_WINDOW_SECONDS: u32 = 30;
/// Records the probe is willing to collect per node before it stops early.
const OBSERVE_RECORDS: u32 = 64;
/// Bytes of one `struct input_event` on a 64-bit ABI.
const EVENT_BYTES: u32 = 24;
/// 16-bit words per event record, and the index of its type field.
const EVENT_WORDS: u32 = EVENT_BYTES / 2;
const EVENT_TYPE_WORD: u32 = 8;
const EV_SYN: u32 = 0x00;
const EV_KEY: u32 = 0x01;
const EV_REL: u32 = 0x02;
const EXIT_OPERATION_FAILED: u8 = 1;
const EXIT_UNSUPPORTED_ARCH: u8 = 2;

/// Which contract the injected gate asserts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    /// Injected host events must reach the pointer and keyboard evdev nodes.
    Delivery,
    /// Same, then again after the virtio-input children are unbound and rebound.
    Rebind,
}

impl Mode {
    fn token(self) -> &'static str {
        match self {
            Mode::Delivery => "delivery",
            Mode::Rebind => "rebind",
        }
    }
}

/// Inject the input-delivery gate into a disposable root image. The gate
/// announces itself, then fails unless real events arrive on both nodes.
/// # C: O(debugfs writes)
pub(super) fn inject(root_img: &Path, arch: &str, mode: Mode) -> Result<(), u8> {
    validate_arch(arch)?;
    let probe = write_staged(PROBE_NAME, &probe_body(mode))?;
    let service = write_staged(SERVICE_NAME, &service_body())?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, &format!("mkdir {WANTS_DIRECTORY}"))?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", probe.display()))?;
    super::dbg(root_img, &format!("sif {PROBE_DESTINATION} mode {PROBE_FILE_MODE}"))?;
    super::dbg_ignore(root_img, &format!("rm {SERVICE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {SERVICE_DESTINATION}", service.display()))?;
    super::dbg_ignore(root_img, &format!("rm {WANTS_DESTINATION}"));
    super::dbg(root_img, &format!("symlink {WANTS_DESTINATION} ../{SERVICE_NAME}"))?;
    eprintln!(
        "xtask rootfs: injected input {} smoke into {}",
        mode.token(),
        root_img.display(),
    );
    Ok(())
}

fn validate_arch(arch: &str) -> Result<(), u8> {
    match arch {
        "x86_64" | "aarch64" => Ok(()),
        _ => {
            eprintln!("xtask rootfs: unsupported arch `{arch}` for input delivery smoke");
            Err(EXIT_UNSUPPORTED_ARCH)
        }
    }
}

fn write_staged(name: &str, body: &str) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|err| {
        eprintln!("xtask rootfs: mkdir input delivery smoke dir failed: {err}");
        EXIT_OPERATION_FAILED
    })?;
    let path = dir.join(name);
    std::fs::write(&path, body).map_err(|err| {
        eprintln!("xtask rootfs: write {name} failed: {err}");
        EXIT_OPERATION_FAILED
    })?;
    Ok(path)
}

fn service_body() -> String {
    format!(
        "[Unit]\n\
Description=Oxide input delivery smoke\n\
Wants=systemd-udev-settle.service\n\
After=systemd-udev-settle.service systemd-logind.service\n\
\n\
[Service]\n\
Type=oneshot\n\
User=root\n\
TimeoutStartSec={SERVICE_TIMEOUT_SECONDS}\n\
ExecStart={PROBE_DESTINATION}\n\
StandardOutput=journal+console\n\
StandardError=journal+console\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n"
    )
}

/// Serial consoles the harness bridges, in the order the probe tries them:
/// the x86 UART, the arm PL011, then whatever `console=` last selected.
const SERIAL_DEVICES: &str = "/dev/ttyS0 /dev/ttyAMA0 /dev/console";

fn probe_body(mode: Mode) -> String {
    PROBE_TEMPLATE
        .replace("@SERIAL_DEVICES@", SERIAL_DEVICES)
        .replace("@MODE@", mode.token())
        .replace("@SETTLE@", &UDEV_SETTLE_TIMEOUT_SECONDS.to_string())
        .replace("@WINDOW@", &OBSERVE_WINDOW_SECONDS.to_string())
        .replace("@RECORDS@", &OBSERVE_RECORDS.to_string())
        .replace("@EVENT_BYTES@", &EVENT_BYTES.to_string())
        .replace("@EVENT_WORDS@", &EVENT_WORDS.to_string())
        .replace("@EVENT_TYPE_WORD@", &EVENT_TYPE_WORD.to_string())
        .replace("@EV_SYN@", &EV_SYN.to_string())
        .replace("@EV_KEY@", &EV_KEY.to_string())
        .replace("@EV_REL@", &EV_REL.to_string())
}

const PROBE_TEMPLATE: &str = r#"#!/bin/sh
set -u

# The verdict must reach the harness over the SERIAL line: the journal is not
# forwarding, and /dev/console follows the last console= on the command line,
# which is the graphical VT. Claim the UART the harness is bridging instead.
for serial in @SERIAL_DEVICES@
do
    if [ -w "$serial" ]
    then
        exec > "$serial" 2>&1
        break
    fi
done

tag=input_delivery
mode=@MODE@
settle=@SETTLE@
window=@WINDOW@
records=@RECORDS@
work=/run/oxide-input-delivery
driver=/sys/bus/virtio/drivers/virtio-input
pointer=
keyboard=

fail()
{
    printf '%s: FAIL check=%s\n' "$tag" "$*"
    exit 1
}

node_for()
{
    for class in /sys/class/input/event*
    do
        [ -e "$class" ] || continue
        props=$(/usr/bin/udevadm info --query=property --path="$class" 2>/dev/null) ||
            continue
        printf '%s\n' "$props" | /usr/bin/grep -Fqx "$1=1" || continue
        printf '/dev/input/%s\n' "${class##*/}"
        return 0
    done
    return 1
}

resolve()
{
    pointer=$(node_for ID_INPUT_MOUSE) || fail "$1-pointer-node"
    keyboard=$(node_for ID_INPUT_KEYBOARD) || fail "$1-keyboard-node"
    [ -c "$pointer" ] || fail "$1-pointer-char node=$pointer"
    [ -c "$keyboard" ] || fail "$1-keyboard-char node=$keyboard"
}

count_type()
{
    /usr/bin/od -An -v -tu2 "$1" | /usr/bin/awk -v want="$2" '
        { for (i = 1; i <= NF; i++) word[n++] = $i }
        END {
            hits = 0
            for (r = 0; r + @EVENT_WORDS@ <= n; r += @EVENT_WORDS@)
                if (word[r + @EVENT_TYPE_WORD@] == want)
                    hits++
            print hits + 0
        }
    '
}

observe()
{
    phase=$1
    /usr/bin/rm -f "$work/pointer.bin" "$work/keyboard.bin"
    # dd writes each record as it reads it, so the capture files hold whatever
    # arrived even when the window closes on a reader that is still blocked.
    /usr/bin/dd if="$pointer" of="$work/pointer.bin" \
        bs=@EVENT_BYTES@ count="$records" 2>/dev/null &
    pointer_reader=$!
    /usr/bin/dd if="$keyboard" of="$work/keyboard.bin" \
        bs=@EVENT_BYTES@ count="$records" 2>/dev/null &
    keyboard_reader=$!
    printf '%s: READY phase=%s pointer=%s keyboard=%s window=%s\n' \
        "$tag" "$phase" "$pointer" "$keyboard" "$window"
    sleep "$window"
    kill "$pointer_reader" "$keyboard_reader" 2>/dev/null
    sleep 1
    [ -f "$work/pointer.bin" ] || fail "$phase-pointer-capture"
    [ -f "$work/keyboard.bin" ] || fail "$phase-keyboard-capture"
    motion=$(count_type "$work/pointer.bin" @EV_REL@)
    button=$(count_type "$work/pointer.bin" @EV_KEY@)
    sync=$(count_type "$work/pointer.bin" @EV_SYN@)
    keys=$(count_type "$work/keyboard.bin" @EV_KEY@)
    printf '%s: observed phase=%s motion=%s button=%s sync=%s keys=%s\n' \
        "$tag" "$phase" "$motion" "$button" "$sync" "$keys"
    [ "$motion" -gt 0 ] || fail "$phase-pointer-motion"
    [ "$button" -gt 0 ] || fail "$phase-pointer-button"
    [ "$sync" -gt 0 ] || fail "$phase-pointer-sync"
    [ "$keys" -gt 0 ] || fail "$phase-keyboard-key"
}

rebind()
{
    [ -d "$driver" ] || fail rebind-driver-absent
    children=
    for path in "$driver"/*
    do
        [ -L "$path" ] || continue
        children="$children ${path##*/}"
    done
    [ -n "$children" ] || fail rebind-no-children
    for child in $children
    do
        printf '%s\n' "$child" > "$driver/unbind" || fail "rebind-unbind child=$child"
        printf '%s: unbound %s\n' "$tag" "$child"
    done
    for child in $children
    do
        printf '%s\n' "$child" > "$driver/bind" || fail "rebind-bind child=$child"
        printf '%s: rebound %s\n' "$tag" "$child"
    done
    /usr/bin/udevadm settle --timeout="$settle" || fail rebind-settle
}

printf '%s: BEGIN mode=%s\n' "$tag" "$mode"
/usr/bin/mkdir -p "$work" || fail workdir
/usr/bin/udevadm settle --timeout="$settle" || fail udevadm-settle
resolve first
observe first
if [ "$mode" = rebind ]
then
    rebind
    resolve rebound
    observe rebound
fi
printf '%s: PASS mode=%s\n' "$tag" "$mode"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn probe_has_valid_shell_syntax_in_both_modes() {
        for mode in [Mode::Delivery, Mode::Rebind] {
            let mut child = Command::new("/bin/sh")
                .arg("-n")
                .stdin(Stdio::piped())
                .spawn()
                .expect("spawn shell syntax check");
            child.stdin.as_mut().expect("shell stdin")
                .write_all(probe_body(mode).as_bytes())
                .expect("write shell probe");
            assert!(child.wait().expect("wait for syntax check").success(), "{mode:?}");
        }
    }

    #[test]
    fn probe_substitutes_every_placeholder() {
        for mode in [Mode::Delivery, Mode::Rebind] {
            assert!(!probe_body(mode).contains('@'), "unsubstituted placeholder in {mode:?}");
        }
    }

    #[test]
    fn delivery_mode_asserts_every_event_class_and_skips_the_rebind_phase() {
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("mode=delivery"));
        for check in [
            "$phase-pointer-motion",
            "$phase-pointer-button",
            "$phase-pointer-sync",
            "$phase-keyboard-key",
        ] {
            assert!(body.contains(check), "missing assertion: {check}");
        }
        assert!(body.contains("observe first"));
        // The rebind phase is present but gated on the baked-in mode token.
        assert!(body.contains("if [ \"$mode\" = rebind ]"));
        assert!(body.contains("READY phase=%s"));
        assert!(body.contains("PASS mode=%s"));
    }

    #[test]
    fn rebind_mode_reasserts_delivery_after_the_children_come_back() {
        let body = probe_body(Mode::Rebind);
        assert!(body.contains("mode=rebind"));
        assert!(body.contains("/sys/bus/virtio/drivers/virtio-input"));
        assert!(body.contains("$driver/unbind"));
        assert!(body.contains("$driver/bind"));
        assert!(body.contains("resolve rebound"));
        assert!(body.contains("observe rebound"));
    }

    #[test]
    fn probe_claims_a_serial_line_rather_than_the_graphical_console() {
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("for serial in /dev/ttyS0 /dev/ttyAMA0 /dev/console"));
        assert!(body.contains("exec > \"$serial\" 2>&1"));
    }

    #[test]
    fn record_geometry_matches_the_event_abi() {
        assert_eq!(EVENT_BYTES, 24);
        assert_eq!(EVENT_WORDS, 12);
        assert_eq!(EVENT_TYPE_WORD, 8);
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("bs=24"));
        assert!(body.contains("r += 12"));
        assert!(body.contains("word[r + 8]"));
    }

    #[test]
    fn service_runs_after_udev_has_settled_the_input_nodes() {
        let service = service_body();
        assert!(service.contains("After=systemd-udev-settle.service systemd-logind.service\n"));
        assert!(service.contains("ExecStart=/usr/local/bin/oxide-input-delivery\n"));
        assert!(service.contains("StandardOutput=journal+console\n"));
        assert_eq!(validate_arch("x86_64"), Ok(()));
        assert_eq!(validate_arch("aarch64"), Ok(()));
        assert_eq!(validate_arch("riscv64"), Err(EXIT_UNSUPPORTED_ARCH));
    }
}
