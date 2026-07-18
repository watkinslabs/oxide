use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::vcs::make_vcs_inode;
use crate::vt_console::{console_rdev, make_console_inode, make_tty_alias_inode};

pub fn try_register_devnodes() -> drv::KResult<()> {
    let mut published = Vec::new();

    push_tty_node(&mut published, "console", crate::devnum::system_console_rdev(), Arc::new(|| crate::system_console_inode()))?;

    let tty: vfs::InodeRef = make_tty_alias_inode();
    let tty0: vfs::InodeRef = make_console_inode(0);
    push_tty_node(&mut published, "tty", crate::devnum::tty_alias_rdev(), Arc::new(move || Arc::clone(&tty)))?;
    push_tty_node(&mut published, "tty0", console_rdev(0), Arc::new(move || Arc::clone(&tty0)))?;

    push_tty_node(&mut published, "ttyS0", crate::serial::serial_rdev(), Arc::new(|| crate::make_serial_inode()))?;

    for vt in 1..=tty::live::N_VT as u8 {
        let mut name = String::with_capacity(6);
        name.push_str("tty");
        if vt >= 10 {
            name.push((b'0' + (vt / 10)) as char);
        }
        name.push((b'0' + (vt % 10)) as char);
        push_tty_node(
            &mut published,
            &name,
            console_rdev(vt),
            Arc::new(move || make_console_inode(vt)),
        )?;
    }

    let vcs: vfs::InodeRef = make_vcs_inode(false);
    let vcs2 = Arc::clone(&vcs);
    push_tty_node(&mut published, "vcs", crate::devnum::vcs_rdev(false), Arc::new(move || Arc::clone(&vcs)))?;
    push_tty_node(&mut published, "vcs0", crate::devnum::vcs_rdev(false), Arc::new(move || Arc::clone(&vcs2)))?;

    let vcsa: vfs::InodeRef = make_vcs_inode(true);
    let vcsa2 = Arc::clone(&vcsa);
    push_tty_node(&mut published, "vcsa", crate::devnum::vcs_rdev(true), Arc::new(move || Arc::clone(&vcsa)))?;
    push_tty_node(&mut published, "vcsa0", crate::devnum::vcs_rdev(true), Arc::new(move || Arc::clone(&vcsa2)))?;
    Ok(())
}

pub fn register_devnodes() {
    if let Err(e) = try_register_devnodes() {
        panic!("console tty device registration failed: {:?}", e);
    }
}

fn push_tty_node(
    published: &mut Vec<Arc<drv::Device>>,
    name: &str,
    rdev: u32,
    factory: drv::NodeFactory,
) -> drv::KResult<()> {
    match add_tty_node(name, rdev, factory) {
        Ok(Some(dev)) => {
            published.push(dev);
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => {
            drv::rollback_devices(published);
            Err(e)
        }
    }
}

fn add_tty_node(
    name: &str,
    rdev: u32,
    factory: drv::NodeFactory,
) -> drv::KResult<Option<Arc<drv::Device>>> {
    let dev_t = crate::devnum::dev_t(rdev);
    match drv::try_device_add(Arc::new(
        drv::Device::new("tty", String::from(name), 0, 0, 0)
            .with_devnode("tty", String::from(name), Some(dev_t))
            .with_node_factory(factory),
    )) {
        Ok(dev) => Ok(Some(dev)),
        Err(drv::Error::Busy) => {
            if drv::devices().iter().any(|d| {
                d.bus == "tty"
                    && d.addr == name
                    && d.dev_class == "tty"
                    && d.devname.as_deref() == Some(name)
                    && d.dev_t == Some(dev_t)
                    && d.node_factory.is_some()
            }) {
                Ok(None)
            } else {
                Err(drv::Error::Busy)
            }
        }
        Err(e) => Err(e),
    }
}
