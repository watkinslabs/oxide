use std::path::{Path, PathBuf};

const PROBE_NAME: &str = "oxide-gnome-input-classify";
const PROBE_DESTINATION: &str = "/usr/local/bin/oxide-gnome-input-classify";
const SERVICE_NAME: &str = "oxide-gnome-input-classify.service";
const SERVICE_DESTINATION: &str =
    "/etc/systemd/system/oxide-gnome-input-classify.service";
const WANTS_DIRECTORY: &str = "/etc/systemd/system/graphical.target.wants";
const WANTS_DESTINATION: &str =
    "/etc/systemd/system/graphical.target.wants/oxide-gnome-input-classify.service";
const SERVICE_TIMEOUT_SECONDS: u32 = 90;
const UDEV_SETTLE_TIMEOUT_SECONDS: u32 = 60;
const PROBE_FILE_MODE: &str = "0100755";
const EXIT_OPERATION_FAILED: u8 = 1;
const EXIT_UNSUPPORTED_ARCH: u8 = 2;

/// Inject one disposable-root proof of the Linux input discovery path used by
/// udev, libinput, logind, and GNOME. The packed source image is never changed.
/// # C: O(debugfs writes)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let probe = write_probe()?;
    let service = write_service(arch)?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, &format!("mkdir {WANTS_DIRECTORY}"))?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", probe.display()))?;
    super::dbg(
        root_img,
        &format!("sif {PROBE_DESTINATION} mode {PROBE_FILE_MODE}"),
    )?;
    super::dbg_ignore(root_img, &format!("rm {SERVICE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {SERVICE_DESTINATION}", service.display()))?;
    super::dbg_ignore(root_img, &format!("rm {WANTS_DESTINATION}"));
    super::dbg(root_img, &format!("symlink {WANTS_DESTINATION} ../{SERVICE_NAME}"))?;
    eprintln!(
        "xtask rootfs: injected GNOME input classification smoke into {}",
        root_img.display(),
    );
    Ok(())
}

fn validate_arch(arch: &str) -> Result<(), u8> {
    match arch {
        "x86_64" | "aarch64" => Ok(()),
        _ => {
            eprintln!("xtask rootfs: unsupported arch `{arch}` for GNOME input smoke");
            Err(EXIT_UNSUPPORTED_ARCH)
        }
    }
}

fn write_probe() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|err| {
        eprintln!("xtask rootfs: mkdir GNOME input smoke dir failed: {err}");
        EXIT_OPERATION_FAILED
    })?;
    let path = dir.join(PROBE_NAME);
    std::fs::write(&path, probe_body()).map_err(|err| {
        eprintln!("xtask rootfs: write GNOME input probe failed: {err}");
        EXIT_OPERATION_FAILED
    })?;
    Ok(path)
}

fn write_service(arch: &str) -> Result<PathBuf, u8> {
    validate_arch(arch)?;
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|err| {
        eprintln!("xtask rootfs: mkdir GNOME input smoke dir failed: {err}");
        EXIT_OPERATION_FAILED
    })?;
    let path = dir.join(SERVICE_NAME);
    std::fs::write(&path, service_body()).map_err(|err| {
        eprintln!("xtask rootfs: write GNOME input service failed: {err}");
        EXIT_OPERATION_FAILED
    })?;
    Ok(path)
}

fn service_body() -> String {
    format!(
        "[Unit]\n\
Description=Oxide GNOME input classification smoke\n\
Wants=systemd-udev-settle.service systemd-logind.service\n\
After=systemd-udev-settle.service systemd-logind.service\n\
Before=display-manager.service\n\
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
WantedBy=graphical.target\n"
    )
}

fn probe_body() -> String {
    r#"#!/bin/sh
set -u

tag=gnome_input_classify

fail()
{
    printf '%s: FAIL check=%s\n' "$tag" "$*"
    exit 1
}

require_line()
{
    value=$1
    line=$2
    check=$3
    printf '%s\n' "$value" | /usr/bin/grep -Fqx "$line" ||
        fail "$check missing=$line"
}

has_line()
{
    value=$1
    line=$2
    printf '%s\n' "$value" | /usr/bin/grep -Fqx "$line"
}

require_seat_tag()
{
    value=$1
    check=$2
    printf '%s\n' "$value" |
        /usr/bin/grep -Eq '^(CURRENT_)?TAGS=.*:seat:' ||
        fail "$check missing=seat-tag"
}

libinput_nodes_for()
{
    value=$1
    capability=$2
    printf '%s\n' "$value" | /usr/bin/awk -v cap="$capability" '
        /^Device:/ {
            node = ""
            emitted = 0
        }
        /^Kernel:/ {
            node = $2
        }
        /^Capabilities:/ {
            if (node != "" && !emitted)
                for (i = 2; i <= NF; i++)
                    if ($i == cap) {
                        print node
                        emitted = 1
                    }
        }
    '
}

proc_parent_for()
{
    event=$1
    /usr/bin/awk -v event="$event" '
        /^S: Sysfs=/ {
            parent = substr($0, 10)
        }
        /^H: Handlers=/ {
            handlers = $0
            sub(/^H: Handlers=/, "", handlers)
            handlers = " " handlers " "
            if (index(handlers, " " event " ") != 0) {
                print parent
                exit
            }
        }
    ' /proc/bus/input/devices
}

printf '%s: BEGIN\n' "$tag"
/usr/bin/udevadm settle --timeout=@UDEV_SETTLE_TIMEOUT_SECONDS@ ||
    fail "udevadm-settle"

expected_keyboard_count=1
expected_mouse_count=1
event_count=0
udev_keyboard_count=0
udev_mouse_count=0
udev_keyboard_node=
udev_mouse_node=
input_names=

for event_class in /sys/class/input/event*
do
    [ -L "$event_class" ] || continue
    event_count=$((event_count + 1))
    event=${event_class##*/}
    node=/dev/input/$event

    [ -c "$node" ] || fail "$event-node path=$node"

    event_path=$(/usr/bin/readlink -f "$event_class") ||
        fail "$event-resolve path=$event_class"
    event_parent=$(/usr/bin/readlink -f "$event_class/device") ||
        fail "$event-parent-resolve path=$event_class/device"
    input=${event_parent##*/}
    printf '%s\n' "$input" | /usr/bin/grep -Eq '^input[0-9]+$' ||
        fail "$event-parent-name value=$input"
    parent_class=/sys/class/input/$input
    [ -L "$parent_class" ] || fail "$input-class-link path=$parent_class"
    parent=$(/usr/bin/readlink -f "$parent_class") ||
        fail "$input-parent-resolve path=$parent_class"
    [ "$event_parent" = "$parent" ] ||
        fail "$event-parent expected=$parent actual=$event_parent"
    [ "$event_path" = "$parent/$event" ] ||
        fail "$event-path expected=$parent/$event actual=$event_path"
    case " $input_names " in
        *" $input "*) fail "$event-duplicate-parent input=$input" ;;
    esac
    input_names="$input_names $input"
    printf '%s: topology %s input=%s parent=%s event=%s\n' \
        "$tag" "$event" "$input" "$parent" "$event_path"

    for attr in \
        name phys uniq modalias properties inhibited \
        id/bustype id/vendor id/product id/version \
        capabilities/ev capabilities/key capabilities/rel \
        capabilities/abs capabilities/msc capabilities/led \
        capabilities/snd capabilities/ff capabilities/sw
    do
        value=$(/usr/bin/cat "$parent/$attr") ||
            fail "$event-sysfs-attr path=$parent/$attr"
        printf '%s: sysfs %s %s=%s\n' "$tag" "$event" "$attr" "$value"
    done

    direct=$(/usr/bin/udevadm test-builtin input_id "$event_class" 2>&1) ||
        fail "$event-input-id"
    printf '%s\n' "$direct"
    require_line "$direct" "ID_INPUT=1" "$event-input-id"

    event_db=$(/usr/bin/udevadm info --query=property --path="$event_class" 2>&1) ||
        fail "$event-udev-db"
    printf '%s\n' "$event_db"
    require_line "$event_db" "ID_INPUT=1" "$event-udev-db"

    if has_line "$direct" "ID_INPUT_KEYBOARD=1"; then
        require_line "$event_db" "ID_INPUT_KEYBOARD=1" "$event-udev-db"
        udev_keyboard_count=$((udev_keyboard_count + 1))
        udev_keyboard_node=$node
    elif has_line "$event_db" "ID_INPUT_KEYBOARD=1"; then
        fail "$event-keyboard-db-without-builtin"
    fi
    if has_line "$direct" "ID_INPUT_MOUSE=1"; then
        require_line "$event_db" "ID_INPUT_MOUSE=1" "$event-udev-db"
        udev_mouse_count=$((udev_mouse_count + 1))
        udev_mouse_node=$node
    elif has_line "$event_db" "ID_INPUT_MOUSE=1"; then
        fail "$event-mouse-db-without-builtin"
    fi

    parent_db=$(/usr/bin/udevadm info --query=property --path="$parent_class" 2>&1) ||
        fail "$input-udev-db"
    printf '%s\n' "$parent_db"
    require_seat_tag "$parent_db" "$input-udev-db"

    proc_parent=$(proc_parent_for "$event")
    expected_proc_parent=${parent#/sys}
    [ -n "$proc_parent" ] ||
        fail "$event-proc-record"
    [ "$proc_parent" = "$expected_proc_parent" ] ||
        fail "$event-proc-parent expected=$expected_proc_parent actual=$proc_parent"
    printf '%s: proc %s input=%s parent=%s\n' "$tag" "$event" "$input" "$proc_parent"
done

[ "$event_count" -gt 0 ] ||
    fail "event-count actual=$event_count"
[ "$udev_keyboard_count" -eq "$expected_keyboard_count" ] ||
    fail "udev-keyboard-count actual=$udev_keyboard_count"
[ "$udev_mouse_count" -eq "$expected_mouse_count" ] ||
    fail "udev-mouse-count actual=$udev_mouse_count"

libinput_devices=$(/usr/bin/libinput list-devices 2>&1) ||
    fail "libinput-list-devices"
printf '%s\n' "$libinput_devices"
libinput_keyboard_nodes=$(libinput_nodes_for "$libinput_devices" keyboard)
libinput_pointer_nodes=$(libinput_nodes_for "$libinput_devices" pointer)
libinput_keyboard_count=$(printf '%s\n' "$libinput_keyboard_nodes" |
    /usr/bin/awk 'NF { count++ } END { print count + 0 }')
libinput_pointer_count=$(printf '%s\n' "$libinput_pointer_nodes" |
    /usr/bin/awk 'NF { count++ } END { print count + 0 }')
[ "$libinput_keyboard_count" -eq "$expected_keyboard_count" ] ||
    fail "libinput-keyboard-count actual=$libinput_keyboard_count nodes=$libinput_keyboard_nodes"
[ "$libinput_pointer_count" -eq "$expected_mouse_count" ] ||
    fail "libinput-pointer-count actual=$libinput_pointer_count nodes=$libinput_pointer_nodes"
[ "$libinput_keyboard_nodes" = "$udev_keyboard_node" ] ||
    fail "keyboard-node udev=$udev_keyboard_node libinput=$libinput_keyboard_nodes"
[ "$libinput_pointer_nodes" = "$udev_mouse_node" ] ||
    fail "mouse-node udev=$udev_mouse_node libinput=$libinput_pointer_nodes"

seat_status=$(/usr/bin/loginctl seat-status seat0 2>&1) ||
    fail "logind-seat0"
printf '%s\n' "$seat_status"
for input in $input_names
do
    printf '%s\n' "$seat_status" | /usr/bin/grep -Fq "input:$input" ||
        fail "logind-$input"
done

printf '%s: PASS\n' "$tag"
"#.replace(
        "@UDEV_SETTLE_TIMEOUT_SECONDS@",
        &UDEV_SETTLE_TIMEOUT_SECONDS.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn service_orders_classification_before_the_display_manager() {
        let service = service_body();
        assert!(service.contains("Before=display-manager.service\n"));
        assert!(service.contains("After=systemd-udev-settle.service systemd-logind.service\n"));
        assert!(service.contains("ExecStart=/usr/local/bin/oxide-gnome-input-classify\n"));
        assert!(service.contains("StandardOutput=journal+console\n"));
        assert_eq!(validate_arch("x86_64"), Ok(()));
        assert_eq!(validate_arch("aarch64"), Ok(()));
        assert_eq!(validate_arch("riscv64"), Err(EXIT_UNSUPPORTED_ARCH));
    }

    #[test]
    fn probe_covers_every_linux_input_consumer_view() {
        let body = probe_body();
        for evidence in [
            "$event_class/device",
            "/sys/class/input/$input",
            "inhibited",
            "udevadm test-builtin input_id",
            "udevadm info --query=property",
            "/sys/class/input/event*",
            "event_count",
            "udev_keyboard_count",
            "/proc/bus/input/devices",
            "libinput list-devices",
            "libinput_keyboard_count",
            "loginctl seat-status seat0",
            "gnome_input_classify",
        ] {
            assert!(body.contains(evidence), "missing smoke evidence: {evidence}");
        }
        assert_eq!(body.matches("printf '%s: PASS").count(), 1);
        assert_eq!(body.matches("printf '%s: FAIL").count(), 1);
    }

    #[test]
    fn probe_derives_input_parent_and_roles_from_linux_views() {
        let body = probe_body();
        assert!(body.contains("input=${event_parent##*/}"));
        assert!(body.contains("parent_class=/sys/class/input/$input"));
        assert!(body.contains("for input in $input_names"));
        assert!(!body.contains("input=input$index"));
        assert!(!body.contains("event=event$index"));
        assert!(!body.contains("for index in 0 1"));
        assert!(!body.contains("logind-input0"));
        assert!(!body.contains("libinput-event0-keyboard"));
    }

    #[test]
    fn probe_has_valid_shell_syntax() {
        let mut child = Command::new("/bin/sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn shell syntax check");
        child.stdin.as_mut().expect("shell stdin")
            .write_all(probe_body().as_bytes())
            .expect("write shell probe");
        assert!(child.wait().expect("wait for shell syntax check").success());
    }
}
