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
pub(crate) const EVENT_BYTES: u32 = 24;
/// 16-bit words per event record, and the index of its type field.
pub(crate) const EVENT_WORDS: u32 = EVENT_BYTES / 2;
pub(crate) const EVENT_TYPE_WORD: u32 = 8;
const EV_SYN: u32 = 0x00;
const EV_KEY: u32 = 0x01;
pub(crate) const EV_REL: u32 = 0x02;
pub(crate) const EV_ABS: u32 = 0x03;
/// Records the probe transcribes per node when it prints the delivered stream.
const DUMP_RECORDS: u32 = 24;
const EXIT_OPERATION_FAILED: u8 = 1;
pub(crate) const EXIT_UNSUPPORTED_ARCH: u8 = 2;

/// Which contract the injected gate asserts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
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
pub(crate) fn inject(root_img: &Path, arch: &str, mode: Mode) -> Result<(), u8> {
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

pub(crate) fn validate_arch(arch: &str) -> Result<(), u8> {
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

pub(crate) fn service_body() -> String {
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

pub(crate) fn probe_body(mode: Mode) -> String {
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

# libinput is the consumer the desktop actually reads pointers through, and it
# only accepts an absolute device once it has read a usable axis range out of
# the node. Asserting it lists the absolute pointer proves the range reached
# userspace intact -- a range the driver failed to harvest reads back as zeros,
# which libinput refuses, and no other check in this gate would notice.
libinput_nodes_for()
{
    printf '%s\n' "$1" | /usr/bin/awk -v cap="$2" '
        /^Device:/ { node = ""; emitted = 0 }
        /^Kernel:/ { node = $2 }
        /^Capabilities:/ {
            if (node != "" && !emitted)
                for (i = 2; i <= NF; i++)
                    if ($i == cap) { print node; emitted = 1 }
        }
    '
}

require_libinput_pointer()
{
    devices=$(/usr/bin/libinput list-devices 2>&1) || { printf '%s\n' "$devices"; fail "$1-libinput-list"; }
    printf '%s\n' "$devices"
    pointers=$(libinput_nodes_for "$devices" pointer)
    for node in $pointer $tablet
    do
        printf '%s\n' "$pointers" | /usr/bin/grep -Fqx "$node" ||
            fail "$1-libinput-pointer node=$node listed=$(printf '%s' "$pointers" | /usr/bin/tr '\n' ',')"
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
    require_libinput_pointer "$1"
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
