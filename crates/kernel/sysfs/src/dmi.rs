// `/sys/class/dmi/id/*` - SMBIOS system identity (Linux `dmi` class).

use alloc::format;
use alloc::vec::Vec;

use crate::register;
use crate::make_body_inode;

/// Register the DMI identity attributes under both the Linux paths systemd may
/// read: the canonical `/sys/devices/virtual/dmi/id/<attr>` and the class alias
/// `/sys/class/dmi/id/<attr>`. No-op when no SMBIOS tables were found. # C: O(1)
pub fn init() {
    let Some(d) = firmware::smbios::dmi() else { return; };
    if !d.present { return; }
    let fields: [(&str, &[u8]); 13] = [
        ("sys_vendor", d.sys_vendor.as_slice()),
        ("product_name", d.product_name.as_slice()),
        ("product_version", d.product_version.as_slice()),
        ("product_serial", d.product_serial.as_slice()),
        ("product_uuid", d.product_uuid.as_slice()),
        ("bios_vendor", d.bios_vendor.as_slice()),
        ("bios_version", d.bios_version.as_slice()),
        ("bios_date", d.bios_date.as_slice()),
        ("board_vendor", d.board_vendor.as_slice()),
        ("board_name", d.board_name.as_slice()),
        ("board_version", d.board_version.as_slice()),
        ("chassis_vendor", d.chassis_vendor.as_slice()),
        ("chassis_version", d.chassis_version.as_slice()),
    ];
    for (i, (name, val)) in fields.iter().enumerate() {
        // Linux appends a trailing newline to each dmi attribute.
        let body: Vec<u8> = {
            let mut b = Vec::with_capacity(val.len() + 1);
            b.extend_from_slice(val);
            b.push(b'\n');
            b
        };
        register(
            &format!("/sys/devices/virtual/dmi/id/{name}"),
            make_body_inode(body.clone(), crate::ids::DMI_ID_BASE + i as vfs::Ino),
        );
        register(
            &format!("/sys/class/dmi/id/{name}"),
            make_body_inode(body, crate::ids::DMI_ID_BASE + crate::ids::DMI_CLASS_OFFSET + i as vfs::Ino),
        );
    }
}
