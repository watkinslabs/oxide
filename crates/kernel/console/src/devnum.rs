const RDEV_MAJOR_SHIFT: u32 = 8;
const RDEV_MINOR_BITS: u32 = RDEV_MAJOR_SHIFT;
const RDEV_MINOR_MASK: u32 = (1u32 << RDEV_MINOR_BITS) - 1;

const LINUX_VT_MAJOR: u32 = 4;
const LINUX_TTY_MAJOR: u32 = 5;
const LINUX_VCS_MAJOR: u32 = 7;
const LINUX_SERIAL_MINOR: u32 = 64;
const LINUX_TTY_ALIAS_MINOR: u32 = 0;
const LINUX_SYSTEM_CONSOLE_MINOR: u32 = 1;
const LINUX_VCS_MINOR: u32 = 0;
const LINUX_VCSA_MINOR: u32 = 128;

#[cfg(target_arch = "x86_64")]
const LINUX_SERIAL_MAJOR: u32 = LINUX_VT_MAJOR;
#[cfg(target_arch = "aarch64")]
const LINUX_SERIAL_MAJOR: u32 = 204;

pub(crate) const fn rdev(major: u32, minor: u32) -> u32 {
    (major << RDEV_MAJOR_SHIFT) | minor
}

pub(crate) const fn dev_t(rdev: u32) -> (u32, u32) {
    (rdev >> RDEV_MAJOR_SHIFT, rdev & RDEV_MINOR_MASK)
}

pub(crate) const fn tty_alias_rdev() -> u32 {
    rdev(LINUX_TTY_MAJOR, LINUX_TTY_ALIAS_MINOR)
}

pub(crate) const fn system_console_rdev() -> u32 {
    rdev(LINUX_TTY_MAJOR, LINUX_SYSTEM_CONSOLE_MINOR)
}

pub(crate) const fn vt_rdev(vt: u8) -> u32 {
    rdev(LINUX_VT_MAJOR, vt as u32)
}

pub(crate) const fn serial_rdev() -> u32 {
    rdev(LINUX_SERIAL_MAJOR, LINUX_SERIAL_MINOR)
}

pub(crate) const fn vcs_rdev(attr: bool) -> u32 {
    if attr { rdev(LINUX_VCS_MAJOR, LINUX_VCSA_MINOR) } else { rdev(LINUX_VCS_MAJOR, LINUX_VCS_MINOR) }
}
