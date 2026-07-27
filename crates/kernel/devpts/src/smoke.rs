use alloc::format;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::*;

struct DevptsType;
impl vfs::FileSystemType for DevptsType {
    fn name(&self) -> &str { "devpts" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> { Err(vfs::VfsError::Einval) }
}

pub fn smoke_test() {
    use hal::kassert;

    let (master, n) = allocate_pair();
    let ino = master.ino();
    kassert!((ino & 0xFFFF_8000) == 0x6000_0000, "master ino marker");
    kassert!((ino & 0x7FFF) as u32 == n, "master ino encodes pts_num");

    let mut name: alloc::string::String = alloc::string::String::with_capacity(8);
    push_dec(&mut name, n);
    let slave = devpts_fs().root_dir().lookup_path(&name).expect("pts slave registered");
    kassert!(slave.file_type() == FileType::CharDev, "pts slave is chardev");

    let n1 = master.write(0, b"keys\n").expect("master write");
    kassert!(n1 == 5, "master write len (cooked echo accepts all)");
    let mut buf = [0u8; 8];
    let echoed = master.read(0, &mut buf).expect("master read echo");
    kassert!(echoed == 5, "echo len");
    kassert!(&buf[..5] == b"keys\n", "echo bytes");
    let r1 = slave.read(0, &mut buf).expect("slave read");
    kassert!(r1 == 5, "slave read len");
    kassert!(&buf[..5] == b"keys\n", "master→slave bytes");

    let n2 = slave.write(0, b"output").expect("slave write");
    kassert!(n2 == 6, "slave write len");
    let r2 = master.read(0, &mut buf).expect("master read");
    kassert!(r2 == 6, "master read len");
    kassert!(&buf[..6] == b"output", "slave→master bytes");

    sigint_chain_smoke();
    devpts_fs_smoke();

    debug_boot! { klog::write_raw(b"[INFO]  pty-smoke: ok\n"); }
}

fn devpts_fs_smoke() {
    use hal::kassert;
    use vfs::fs::FileSystem;

    let fs = devpts_fs();
    kassert!(fs.name() == "devpts", "devpts name");
    kassert!(fs.magic() == DEVPTS_MAGIC, "devpts magic");
    let root = fs.root().expect("devpts root");
    kassert!(root.file_type() == FileType::Directory, "devpts root is dir");
    let ptmx = root.lookup("ptmx").expect("ptmx in pts root");
    kassert!(ptmx.file_type() == FileType::CharDev, "pts/ptmx is chardev");
    kassert!(ptmx.fsid() == DEVPTS_FSID, "pts/ptmx on devpts fsid");

    let (_m, n) = allocate_pair();
    let name = format!("{}", n);
    let slave = fs.root_dir().lookup_path(&name).expect("slave mirrored in devpts root");
    kassert!(slave.file_type() == FileType::CharDev, "mirrored slave is chardev");
    kassert!(slave.fsid() == DEVPTS_FSID, "slave st_dev == DEVPTS_FSID");

    let s_op: Arc<dyn vfs::SuperOps> =
        Arc::new(vfs::SimpleSuperOps { magic: DEVPTS_MAGIC, block_size: 4096, options: alloc::string::String::new() });
    let sb = SuperBlock::from_ops(Arc::new(DevptsType), s_op, fs.root(), DEVPTS_MAGIC, DEVPTS_FSID, 4096, alloc::string::String::from("devpts"), Arc::new(()));
    fs.set_sb(Arc::downgrade(&sb)).expect("devpts set_sb");
    kassert!(sb.s_magic == DEVPTS_MAGIC, "devpts sb s_magic");
    let rino = sb.s_root_inode().expect("devpts s_root inode");
    kassert!(rino.file_type() == FileType::Directory, "devpts s_root is dir");
    kassert!(rino.fsid() == DEVPTS_FSID, "devpts root st_dev from SB s_dev");

    debug_boot! { klog::write_raw(b"[INFO]  devpts-fs: ok\n"); }
}

fn sigint_chain_smoke() {
    use hal::kassert;
    use sched::{SchedClass, Task};

    let fake_tid = 0xDEAD_C001;
    let fake = alloc::sync::Arc::new(Task::new(
        fake_tid, "pty-smoke-target", SchedClass::Normal { weight: 1024 },
    ));
    fake.set_pgid(fake_tid);
    sched::live::registry::insert(&fake);

    let (master, n) = allocate_pair();
    let pair = pair_for(n).expect("pair_for");
    pair.with_pair(|p| {
        kassert!(p.lflag() != 0, "cooked default");
        p.foreground_pgid = fake_tid;
    });

    let n1 = master.write(
        0,
        &[
            tty::pty::DEFAULT_VINTR,
            tty::pty::DEFAULT_VQUIT,
            tty::pty::DEFAULT_VSUSP,
        ],
    ).expect("master write");
    kassert!(n1 == 3, "all three control chars consumed");

    let pending = fake.sigpending.load(Ordering::Acquire);
    kassert!(pending & (1u64 << 1) != 0, "SIGINT delivered");
    kassert!(pending & (1u64 << 2) != 0, "SIGQUIT delivered");
    kassert!(pending & (1u64 << 19) != 0, "SIGTSTP delivered");

    pair.with_pair(|p| {
        kassert!(!p.pending_sigint, "pending_sigint cleared");
        kassert!(!p.pending_sigquit, "pending_sigquit cleared");
        kassert!(!p.pending_sigtstp, "pending_sigtstp cleared");
    });

    debug_boot! { klog::write_raw(b"[INFO]  pty-sigint-chain: ok\n"); }
    drop(fake);

    termios_winsize_smoke();
}

fn termios_winsize_smoke() {
    use hal::kassert;

    let (_master, n) = allocate_pair();
    let pair = pair_for(n).expect("pair_for");

    pair.with_pair(|p| {
        kassert!(p.lflag() == tty::pty::DEFAULT_LFLAG, "default cooked lflag");
        kassert!(p.iflag() == tty::pty::DEFAULT_IFLAG, "default cooked iflag");
        kassert!(p.oflag() == tty::pty::DEFAULT_OFLAG, "default cooked oflag");
        kassert!(p.vintr() == tty::pty::DEFAULT_VINTR, "default cooked vintr");
        kassert!(p.winsize == tty::pty::Winsize::default_pty(), "default 24x80");
    });

    pair.with_pair(|p| {
        p.set_winsize(tty::pty::Winsize { rows: 50, cols: 132, xpixel: 0, ypixel: 0 });
        kassert!(p.pending_sigwinch, "set_winsize on change → pending");
        kassert!(p.winsize.rows == 50 && p.winsize.cols == 132, "winsize round-trip");
        p.pending_sigwinch = false;
        p.set_winsize(tty::pty::Winsize { rows: 50, cols: 132, xpixel: 0, ypixel: 0 });
        kassert!(!p.pending_sigwinch, "no-op set must NOT fire SIGWINCH");
    });

    debug_boot! { klog::write_raw(b"[INFO]  pty-termios-winsize: ok\n"); }
}

fn push_dec(s: &mut alloc::string::String, mut n: u32) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 11];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        s.push(buf[i] as char);
    }
}
