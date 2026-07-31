// Verified ioctl dispatch split: the generic VFS stage must never shadow a
// file's own handler, and an anon-inode fd is never treated as a filesystem
// file.

use super::*;
use vfs::FileType;

fn reg() -> IoctlFile { IoctlFile { ft: FileType::Regular, anon: false } }
/// epoll / eventfd / signalfd / io_uring: an anon inode wearing a type tag.
fn anon(ft: FileType) -> IoctlFile { IoctlFile { ft, anon: true } }

#[test]
fn fionread_on_a_regular_file_is_answered_by_the_generic_stage() {
    assert_eq!(ioctl_owner(FIONREAD, reg()), IoctlOwner::Vfs);
}

#[test]
fn fionread_on_an_anon_fd_falls_through_to_the_files_own_handler() {
    // The epoll inode is tagged CharDev and the io_uring / userfaultfd inodes
    // are tagged Regular; neither may be answered with `i_size - f_pos`.
    for ft in [FileType::Regular, FileType::CharDev] {
        assert_eq!(ioctl_owner(FIONREAD, anon(ft)), IoctlOwner::FileOps,
                   "an anon inode tagged {ft:?} has no file contents to measure");
    }
}

#[test]
fn fionread_on_sockets_pipes_and_ttys_falls_through() {
    for ft in [FileType::Socket, FileType::Fifo, FileType::CharDev, FileType::Directory] {
        assert_eq!(ioctl_owner(FIONREAD, IoctlFile { ft, anon: false }), IoctlOwner::FileOps,
                   "{ft:?} answers FIONREAD from its own queue accounting");
    }
}

#[test]
fn descriptor_state_commands_are_generic_for_every_file_including_anon_fds() {
    for req in [FIOCLEX, FIONCLEX, FIONBIO, FIOASYNC] {
        assert_eq!(ioctl_owner(req, reg()), IoctlOwner::Vfs);
        assert_eq!(ioctl_owner(req, anon(FileType::CharDev)), IoctlOwner::Vfs,
                   "close-on-exec and O_NONBLOCK are fd/description state, not file content");
    }
}

#[test]
fn fioqsize_is_owned_for_every_type_and_measures_only_some_of_them() {
    // Unlike FIONREAD, this command never reaches the file's own operations:
    // the generic stage answers ENOTTY itself for a shape it cannot measure.
    for f in [reg(), anon(FileType::Regular), IoctlFile { ft: FileType::Socket, anon: false },
              IoctlFile { ft: FileType::Directory, anon: false },
              IoctlFile { ft: FileType::Symlink, anon: false }] {
        assert_eq!(ioctl_owner(FIOQSIZE, f), IoctlOwner::Vfs, "{f:?}");
    }
    assert!(IoctlFile { ft: FileType::Directory, anon: false }.has_allocated_size());
    assert!(IoctlFile { ft: FileType::Symlink, anon: false }.has_allocated_size());
    assert!(reg().has_allocated_size());
    assert!(!anon(FileType::Regular).has_allocated_size(), "an anon inode has no allocation");
    assert!(!IoctlFile { ft: FileType::Socket, anon: false }.has_allocated_size());
    assert!(!IoctlFile { ft: FileType::CharDev, anon: false }.has_allocated_size());
}

#[test]
fn filesystem_attribute_commands_never_run_on_an_anon_fd() {
    for req in [FIGETBSZ, FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_FSGETXATTR,
                FS_IOC_FSSETXATTR, FS_IOC_GETFSUUID, FS_IOC_GETFSSYSFSPATH,
                FICLONE, FICLONERANGE, FIDEDUPERANGE] {
        assert_eq!(ioctl_owner(req, reg()), IoctlOwner::Vfs, "req {req:#x}");
        assert_eq!(ioctl_owner(req, anon(FileType::Regular)), IoctlOwner::FileOps,
                   "req {req:#x}: an anon inode has no superblock to answer for");
    }
}

#[test]
fn block_map_and_preallocate_need_a_real_regular_file() {
    for req in [FIBMAP, FS_IOC_RESVSP, FS_IOC_RESVSP64, FS_IOC_UNRESVSP,
                FS_IOC_UNRESVSP64, FS_IOC_ZERO_RANGE] {
        assert_eq!(ioctl_owner(req, reg()), IoctlOwner::Vfs, "req {req:#x}");
        assert_eq!(ioctl_owner(req, anon(FileType::Regular)), IoctlOwner::FileOps, "req {req:#x}");
        assert_eq!(ioctl_owner(req, IoctlFile { ft: FileType::CharDev, anon: false }),
                   IoctlOwner::FileOps, "req {req:#x}");
    }
}

#[test]
fn an_unlisted_command_always_belongs_to_the_file() {
    // A device/driver/anon-fd command the generic stage knows nothing about —
    // including the epoll busy-poll parameter ioctls.
    for req in [0x8008_8A02u64, 0x4008_8A01, 0x5401 /* TCGETS */, 0x0000_DEAD] {
        for f in [reg(), anon(FileType::CharDev), IoctlFile { ft: FileType::Socket, anon: false }] {
            assert_eq!(ioctl_owner(req, f), IoctlOwner::FileOps, "req {req:#x} {f:?}");
        }
    }
}

#[test]
fn the_filesystem_ioctl_set_is_skipped_for_anon_fds_only() {
    assert!(fs_unlocked_ioctl_applies(reg()));
    assert!(fs_unlocked_ioctl_applies(IoctlFile { ft: FileType::Directory, anon: false }),
            "FITRIM and the label commands are issued on directory fds");
    assert!(fs_unlocked_ioctl_applies(IoctlFile { ft: FileType::BlockDev, anon: false }));
    assert!(!fs_unlocked_ioctl_applies(anon(FileType::CharDev)));
    assert!(!fs_unlocked_ioctl_applies(anon(FileType::Regular)));
}
