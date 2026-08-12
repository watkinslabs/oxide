#!/bin/sh
# Oxide physical-hardware inventory.  It deliberately uses only procfs/sysfs
# and POSIX tools so it remains useful on an early, partially functional boot.
set -u

tag=OXIDE_HARDWARE_AUDIT
root=${OXIDE_HARDWARE_AUDIT_ROOT:-}

usage()
{
    printf '%s\n' "usage: oxide-hardware-audit"
    printf '%s\n' "writes a machine-readable physical-hardware inventory to standard output"
}

clean()
{
    # One record per line and pipe-delimited fields make serial-log collection
    # and a later host-side parser unambiguous.
    printf '%s' "$1" | tr '\n|' '  '
}

emit()
{
    area=$1
    state=$2
    shift 2
    printf '%s|v1|%s|%s' "$tag" "$area" "$state"
    for field in "$@"; do
        printf '|%s' "$(clean "$field")"
    done
    printf '\n'
}

path()
{
    printf '%s%s' "$root" "$1"
}

read_value()
{
    file=$(path "$1")
    if [ -r "$file" ]; then
        # sysfs attributes are a single logical line.  Some attributes reject
        # a streaming read after their value, whereas shell read stops there.
        value=
        IFS= read -r value < "$file" 2>/dev/null || :
        printf '%s' "$value"
    else
        printf '%s' '-'
    fi
}

link_value()
{
    file=$(path "$1")
    if [ -e "$file" ] || [ -L "$file" ]; then
        readlink -f "$file" 2>/dev/null || printf '%s' '-'
    else
        printf '%s' '-'
    fi
}

audit_firmware()
{
    if [ -d "$(path /sys/firmware/efi)" ]; then
        emit firmware PRESENT efi
    else
        emit firmware ABSENT efi
    fi

    tables=$(path /sys/firmware/acpi/tables)
    if [ -d "$tables" ]; then
        count=0
        for table in "$tables"/*; do
            [ -e "$table" ] || continue
            count=$((count + 1))
        done
        emit acpi PRESENT "tables=$count" "fadt=$([ -e "$tables/FACP" ] && printf yes || printf no)" \
            "dmar=$([ -e "$tables/DMAR" ] && printf yes || printf no)" \
            "ivrs=$([ -e "$tables/IVRS" ] && printf yes || printf no)"
    else
        emit acpi UNAVAILABLE tables
    fi
}

audit_cpu()
{
    online=$(read_value /sys/devices/system/cpu/online)
    present=$(read_value /sys/devices/system/cpu/present)
    if [ "$online" = - ]; then
        emit cpu UNAVAILABLE online
    else
        emit cpu PRESENT "online=$online" "present=$present"
    fi
}

audit_pci()
{
    devices=$(path /sys/bus/pci/devices)
    if [ ! -d "$devices" ]; then
        emit pci UNAVAILABLE sysfs
        return
    fi
    count=0
    for device in "$devices"/*; do
        [ -d "$device" ] || continue
        count=$((count + 1))
        bdf=${device##*/}
        vendor=$(tr -d '\n' < "$device/vendor" 2>/dev/null || printf '?')
        product=$(tr -d '\n' < "$device/device" 2>/dev/null || printf '?')
        class=$(tr -d '\n' < "$device/class" 2>/dev/null || printf '?')
        driver=$(link_value "/sys/bus/pci/devices/$bdf/driver")
        driver=${driver##*/}
        emit pci-device PRESENT "bdf=$bdf" "vendor=$vendor" "device=$product" "class=$class" "driver=$driver"
        case "$class" in
            0x010802*) audit_pci_driver "$bdf" "$driver" nvme ;;
            0x010601*) audit_pci_driver "$bdf" "$driver" ahci ;;
            0x0c0330*) audit_pci_driver "$bdf" "$driver" xhci ;;
            0x020000*)
                case "$vendor:$product" in
                    0x8086:0x100e|0x8086:0x100f|0x8086:0x1015|0x8086:0x1016|0x8086:0x1017|0x8086:0x1018|0x8086:0x1075|0x8086:0x1076|0x8086:0x1077|0x8086:0x1078|0x8086:0x1079|0x8086:0x107a|0x8086:0x10b5|0x8086:0x10bc|0x8086:0x10bd|0x8086:0x10d3|0x8086:0x10ea|0x8086:0x10eb|0x8086:0x10ef|0x8086:0x10f0|0x8086:0x10f5|0x8086:0x1502|0x8086:0x1503|0x8086:0x150c|0x8086:0x150e|0x8086:0x150f)
                        audit_pci_driver "$bdf" "$driver" e1000 ;;
                    # Linux's r8169 PCI table binds this RTL8125 PCI ID.
                    # Oxide exposes its matching native driver under the
                    # same name, so the physical-machine audit must grade
                    # the actual successful bind rather than flag it as an
                    # unselected NIC.
                    0x10ec:0x8125)
                        audit_pci_driver "$bdf" "$driver" r8169 ;;
                    *) emit driver-assessment NEEDS-SELECTION "bdf=$bdf" driver=physical-nic \
                        "reason=no-matched-native-driver" ;;
                esac ;;
        esac
    done
    emit pci PRESENT "devices=$count"
}

# Linux publishes a PCI driver's successful probe through the device's
# `driver` symlink. A class or PCI-ID match merely makes a driver eligible;
# it is never proof that its probe completed. Keep this audit on that same
# contract so an unbound controller cannot be mistaken for support.
audit_pci_driver()
{
    bdf=$1
    actual=$2
    expected=$3
    case "$actual" in
        "$expected") emit driver-assessment BOUND "bdf=$bdf" "driver=$expected" ;;
        -) emit driver-assessment UNBOUND "bdf=$bdf" "expected=$expected" ;;
        *) emit driver-assessment WRONG-DRIVER "bdf=$bdf" "expected=$expected" "driver=$actual" ;;
    esac
}

audit_block()
{
    blocks=$(path /sys/block)
    if [ ! -d "$blocks" ]; then
        emit storage UNAVAILABLE sysfs
        return
    fi
    count=0
    for block in "$blocks"/*; do
        [ -e "$block" ] || continue
        count=$((count + 1))
        name=${block##*/}
        size=$(tr -d '\n' < "$block/size" 2>/dev/null || printf '?')
        driver=$(link_value "/sys/block/$name/device/driver")
        driver=${driver##*/}
        emit block-device PRESENT "name=$name" "sectors=$size" "driver=$driver"
    done
    emit storage PRESENT "devices=$count"
}

audit_input()
{
    events=$(path /sys/class/input)
    if [ ! -d "$events" ]; then
        emit input UNAVAILABLE sysfs
        return
    fi
    count=0
    for event in "$events"/event*; do
        [ -e "$event" ] || [ -L "$event" ] || continue
        count=$((count + 1))
        name=${event##*/}
        # name is a regular sysfs attribute, not a driver binding symlink.
        input_name=$(read_value "/sys/class/input/$name/device/name")
        node=$(path "/dev/input/$name")
        if [ -c "$node" ]; then state=PRESENT; else state=MISSING; fi
        emit input-device "$state" "event=$name" "name=$input_name" "node=/dev/input/$name"
    done
    emit input PRESENT "events=$count"
}

audit_network()
{
    nets=$(path /sys/class/net)
    if [ ! -d "$nets" ]; then
        emit network UNAVAILABLE sysfs
        return
    fi
    count=0
    for net in "$nets"/*; do
        [ -e "$net" ] || [ -L "$net" ] || continue
        count=$((count + 1))
        name=${net##*/}
        mac=$(read_value "/sys/class/net/$name/address")
        carrier=$(read_value "/sys/class/net/$name/carrier")
        driver=$(link_value "/sys/class/net/$name/device/driver")
        driver=${driver##*/}
        emit net-device PRESENT "name=$name" "mac=$mac" "carrier=$carrier" "driver=$driver"
    done
    emit network PRESENT "interfaces=$count"
}

audit_iommu()
{
    groups=$(path /sys/kernel/iommu_groups)
    if [ -d "$groups" ]; then
        count=0
        for group in "$groups"/*; do [ -d "$group" ] && count=$((count + 1)); done
        emit iommu PRESENT "groups=$count"
    else
        emit iommu ABSENT groups
    fi
}

main()
{
    case ${1:-} in
        '') ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    emit run BEGIN "root=${root:-/}" "kernel=$(read_value /proc/sys/kernel/ostype)" "release=$(read_value /proc/sys/kernel/osrelease)"
    audit_firmware
    audit_cpu
    audit_pci
    audit_block
    audit_input
    audit_network
    audit_iommu
    emit run COMPLETE
}

main "$@"
