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
const EV_ABS: u32 = 0x03;
/// Records the probe transcribes per node when it prints the delivered stream.
const DUMP_RECORDS: u32 = 24;
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
        .replace("@EV_ABS@", &EV_ABS.to_string())
        .replace("@DUMP_RECORDS@", &DUMP_RECORDS.to_string())
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
tablet=

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

# Dumped when a phase cannot classify a node. Distinguishes "udev never ran"
# from "udev ran against a stale sysfs path": the class symlink target, the
# capability attributes udev reads to classify, and the saved property set.
diagnose()
{
    printf '%s: DIAG phase=%s class=%s\n' "$tag" "$1" "$(ls /sys/class/input 2>&1 | tr '\n' ' ')"
    printf '%s: DIAG phase=%s queue=%s\n' "$tag" "$1" "$(cat /run/udev/queue 2>&1 | od -An -tx1 | tr -d '\n')"
    for class in /sys/class/input/event*
    do
        [ -e "$class" ] || continue
        printf '%s: DIAG node=%s link=%s\n' "$tag" "$class" "$(readlink -f "$class" 2>&1)"
        printf '%s: DIAG node=%s ev=%s\n' "$tag" "$class" \
            "$(cat "$class"/device/capabilities/ev 2>&1) rel=$(cat "$class"/device/capabilities/rel 2>&1)"
        printf '%s: DIAG node=%s props<<%s>>\n' "$tag" "$class" \
            "$(/usr/bin/udevadm info --query=property --path="$class" 2>&1 | tr '\n' '|')"
    done
    printf '%s: DIAG data=%s\n' "$tag" "$(ls -l /run/udev/data 2>&1 | tr '\n' ' ')"
}

# An absolute pointer is the node whose ABS capability bitmap is not all
# zeros. udev labels it ID_INPUT_MOUSE too (absolute coordinates plus a mouse
# button), so the property set cannot tell it apart from the relative mouse.
abs_node()
{
    for class in /sys/class/input/event*
    do
        [ -e "$class" ] || continue
        bits=$(cat "$class"/device/capabilities/abs 2>/dev/null) || continue
        printf '%s' "$bits" | /usr/bin/tr -d ' 0' | /usr/bin/grep -q . || continue
        printf '/dev/input/%s\n' "${class##*/}"
        return 0
    done
    return 1
}

# Unconditional evidence: what every input node self-describes as. These are
# the exact attributes udev, libinput, and the compositor classify from.
describe()
{
    for class in /sys/class/input/event*
    do
        [ -e "$class" ] || continue
        printf '%s: caps phase=%s node=%s name="%s" ev=%s rel=%s abs=%s key=%s\n' \
            "$tag" "$1" "${class##*/}" \
            "$(cat "$class"/device/name 2>&1)" \
            "$(cat "$class"/device/capabilities/ev 2>&1)" \
            "$(cat "$class"/device/capabilities/rel 2>&1)" \
            "$(cat "$class"/device/capabilities/abs 2>&1)" \
            "$(cat "$class"/device/capabilities/key 2>&1)"
    done
}

resolve()
{
    describe "$1"
    pointer=$(node_for ID_INPUT_MOUSE) || { diagnose "$1"; fail "$1-pointer-node"; }
    keyboard=$(node_for ID_INPUT_KEYBOARD) || { diagnose "$1"; fail "$1-keyboard-node"; }
    tablet=$(abs_node) || { diagnose "$1"; fail "$1-tablet-node"; }
    [ -c "$pointer" ] || fail "$1-pointer-char node=$pointer"
    [ -c "$keyboard" ] || fail "$1-keyboard-char node=$keyboard"
    [ -c "$tablet" ] || fail "$1-tablet-char node=$tablet"
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

# Transcribe the delivered records as sec.usec:type/code/value. This is the
# primary evidence for event framing: a button press and its release must be
# separate reports with distinct timestamps, each terminated by an EV_SYN.
dump_records()
{
    /usr/bin/od -An -v -tu2 "$2" | /usr/bin/awk -v tag="$tag" -v label="$1" '
        { for (i = 1; i <= NF; i++) word[n++] = $i }
        END {
            out = ""
            shown = 0
            for (r = 0; r + @EVENT_WORDS@ <= n && shown < @DUMP_RECORDS@; r += @EVENT_WORDS@) {
                sec = word[r + 0] + word[r + 1] * 65536
                usec = word[r + 4] + word[r + 5] * 65536
                value = word[r + 10] + word[r + 11] * 65536
                if (value >= 2147483648) value -= 4294967296
                out = out sprintf("%d.%06d:%d/%d/%d ", sec, usec,
                                  word[r + 8], word[r + 9], value)
                shown++
            }
            printf "%s: stream %s <<%s>>\n", tag, label, out
        }
    '
}

observe()
{
    phase=$1
    /usr/bin/rm -f "$work/pointer.bin" "$work/keyboard.bin" "$work/tablet.bin"
    # dd writes each record as it reads it, so the capture files hold whatever
    # arrived even when the window closes on a reader that is still blocked.
    /usr/bin/dd if="$pointer" of="$work/pointer.bin" \
        bs=@EVENT_BYTES@ count="$records" 2>/dev/null &
    pointer_reader=$!
    /usr/bin/dd if="$keyboard" of="$work/keyboard.bin" \
        bs=@EVENT_BYTES@ count="$records" 2>/dev/null &
    keyboard_reader=$!
    /usr/bin/dd if="$tablet" of="$work/tablet.bin" \
        bs=@EVENT_BYTES@ count="$records" 2>/dev/null &
    tablet_reader=$!
    printf '%s: READY phase=%s pointer=%s keyboard=%s tablet=%s window=%s\n' \
        "$tag" "$phase" "$pointer" "$keyboard" "$tablet" "$window"
    sleep "$window"
    kill "$pointer_reader" "$keyboard_reader" "$tablet_reader" 2>/dev/null
    sleep 1
    [ -f "$work/pointer.bin" ] || fail "$phase-pointer-capture"
    [ -f "$work/keyboard.bin" ] || fail "$phase-keyboard-capture"
    [ -f "$work/tablet.bin" ] || fail "$phase-tablet-capture"
    motion=$(count_type "$work/pointer.bin" @EV_REL@)
    button=$(count_type "$work/pointer.bin" @EV_KEY@)
    sync=$(count_type "$work/pointer.bin" @EV_SYN@)
    keys=$(count_type "$work/keyboard.bin" @EV_KEY@)
    absolute=$(count_type "$work/tablet.bin" @EV_ABS@)
    abs_button=$(count_type "$work/tablet.bin" @EV_KEY@)
    abs_sync=$(count_type "$work/tablet.bin" @EV_SYN@)
    # A host injects a button without naming a pointer, and the emulator hands
    # it to whichever pointer is current -- which, once an absolute pointer
    # exists, is the absolute one. So buttons are asserted across both nodes;
    # motion is asserted per node, because only one node carries each kind.
    buttons=$(( button + abs_button ))
    printf '%s: observed phase=%s motion=%s button=%s sync=%s keys=%s absolute=%s abs_button=%s abs_sync=%s\n' \
        "$tag" "$phase" "$motion" "$button" "$sync" "$keys" \
        "$absolute" "$abs_button" "$abs_sync"
    dump_records "$phase-pointer" "$work/pointer.bin"
    dump_records "$phase-tablet" "$work/tablet.bin"
    [ "$motion" -gt 0 ] || fail "$phase-pointer-motion"
    [ "$sync" -gt 0 ] || fail "$phase-pointer-sync"
    [ "$buttons" -gt 0 ] || fail "$phase-pointer-button"
    [ "$keys" -gt 0 ] || fail "$phase-keyboard-key"
    [ "$absolute" -gt 0 ] || fail "$phase-tablet-absolute"
    [ "$abs_sync" -gt 0 ] || fail "$phase-tablet-sync"
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
            "$phase-tablet-absolute",
            "$phase-tablet-sync",
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
    fn an_unclassified_node_dumps_the_sysfs_state_udev_classifies_from() {
        let body = probe_body(Mode::Rebind);
        // A stale class symlink, absent capability attributes, and an empty
        // property set are the three shapes this gate has actually hit.
        assert!(body.contains("diagnose \"$1\"; fail \"$1-pointer-node\""));
        assert!(body.contains("readlink -f \"$class\""));
        assert!(body.contains("/device/capabilities/ev"));
        assert!(body.contains("DIAG data="));
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

    /// An absolute pointer carries the same udev property set as a relative
    /// mouse (absolute coordinates plus a mouse button classify as
    /// ID_INPUT_MOUSE), so the gate must separate them by capability bitmap.
    #[test]
    fn the_absolute_pointer_is_resolved_by_its_abs_capability_bitmap() {
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("abs_node()"));
        assert!(body.contains("/device/capabilities/abs"));
        // All-zero bitmaps ("0" or "0 0 ...") mean no absolute axis at all.
        assert!(body.contains("tr -d ' 0'"));
        assert!(body.contains("tablet=$(abs_node)"));
        assert!(body.contains("$1-tablet-node"));
        assert!(body.contains("$1-tablet-char"));
    }

    /// Both pointers must be captured: the relative mouse carries motion as
    /// EV_REL, the tablet carries it as EV_ABS, and neither substitutes for
    /// the other.
    #[test]
    fn both_pointer_kinds_are_captured_and_asserted_independently() {
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("if=\"$tablet\" of=\"$work/tablet.bin\""));
        assert!(body.contains("absolute=$(count_type \"$work/tablet.bin\" 3)"));
        assert!(body.contains("motion=$(count_type \"$work/pointer.bin\" 2)"));
        assert!(body.contains("kill \"$pointer_reader\" \"$keyboard_reader\" \"$tablet_reader\""));
        assert_eq!(EV_ABS, 3);
        assert_eq!(EV_REL, 2);
    }

    /// Observed on a guest carrying both pointer kinds: injected buttons stop
    /// arriving on the relative mouse and arrive on the absolute pointer
    /// instead, because an unaddressed button goes to the current pointer and
    /// an absolute pointer becomes current. The gate must not read that as
    /// lost button delivery.
    #[test]
    fn buttons_are_asserted_across_both_pointer_nodes() {
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("abs_button=$(count_type \"$work/tablet.bin\" 1)"));
        assert!(body.contains("buttons=$(( button + abs_button ))"));
        assert!(body.contains("[ \"$buttons\" -gt 0 ] || fail \"$phase-pointer-button\""));
        // Motion stays per node: EV_REL only ever reaches the relative mouse,
        // EV_ABS only ever reaches the absolute pointer.
        assert!(body.contains("[ \"$motion\" -gt 0 ] || fail \"$phase-pointer-motion\""));
        assert!(body.contains("[ \"$absolute\" -gt 0 ] || fail \"$phase-tablet-absolute\""));
    }

    /// The record transcript is the evidence a click is a matched pair: a
    /// press report and a release report, each with its own timestamp.
    #[test]
    fn the_delivered_record_stream_is_transcribed_with_timestamps() {
        let body = probe_body(Mode::Delivery);
        assert!(body.contains("dump_records \"$phase-pointer\""));
        assert!(body.contains("dump_records \"$phase-tablet\""));
        // sec/usec live in words 0..1 and 4..5, value in words 10..11.
        assert!(body.contains("sec = word[r + 0] + word[r + 1] * 65536"));
        assert!(body.contains("usec = word[r + 4] + word[r + 5] * 65536"));
        assert!(body.contains("value = word[r + 10] + word[r + 11] * 65536"));
        assert!(body.contains("if (value >= 2147483648) value -= 4294967296"));
        assert!(body.contains("shown < 24"));
    }

    /// The capability dump runs on every phase, pass or fail, so a regression
    /// report always carries what each node self-described as.
    #[test]
    fn capabilities_are_printed_unconditionally_on_every_resolve() {
        let body = probe_body(Mode::Rebind);
        assert!(body.contains("describe \"$1\""));
        assert!(body.contains("caps phase=%s node=%s"));
        for attribute in ["capabilities/ev", "capabilities/rel", "capabilities/abs", "capabilities/key"] {
            assert!(body.contains(attribute), "missing {attribute}");
        }
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
