use super::*;

impl FileOps for F2fsOps {
    /// Linux f2fs replaces the generic sequential readahead factor with its
    /// live per-mount `seq_file_ra_mul` control.
    /// # C: O(1)
    fn sequential_ra_multiplier(&self, file: &vfs::File) -> u32 {
        F2fsOps::node(file.inode()).map(|node| node.fs.volume.lock().seq_file_ra_mul())
            .unwrap_or(2)
    }

    /// The typed ioctl stage: the version, label and trim commands the
    /// interface carries for every filesystem. This filesystem's OWN commands
    /// do not come through here — they carry their own numbers and reach
    /// `ioctl::vfs::raw` with those untouched.
    /// # C: command-dependent
    fn unlocked_ioctl(&self, file: &vfs::File, _idmap: &Idmap, cred: &vfs::Cred,
                      cmd: vfs::FileIoctlCmd) -> KResult<vfs::FileIoctlReply> {
        crate::ioctl::vfs::unlocked_ioctl(file, cred, cmd)
    }

    /// What this filesystem owes an open, before the handle exists.
    ///
    /// A sealed file's metadata is established HERE: the descriptor is located
    /// and parsed and its signature checked once, against this mount's policy,
    /// and every read of the handle then consumes the result. A rejected
    /// signature is therefore a refused open — which is where a caller can act
    /// on it — rather than a read error at whichever offset first needed a
    /// hash. Nothing else in this filesystem builds that record.
    /// A writable handle also brings this file's quota records in, once, here.
    /// The reference does the same and for the same reason: everything the
    /// handle goes on to do allocates, and an allocation may not go to a quota
    /// file for a record while it is holding the state it is writing. The
    /// per-operation acquisitions stay — the reference keeps both — because an
    /// operation can reach this filesystem without a handle.
    /// # C: O(1) for an ordinary read handle; O(descriptor bytes) on a sealed
    /// file's first open, O(quota file) on an identity's first writable one
    fn on_open_file(&self, file: &vfs::File) -> KResult<()> {
        let inode = file.inode();
        let node = F2fsOps::node(inode)?;
        let live = node.live()?;
        let fl = file.flags();
        let write = fl.contains(vfs::OpenFlags::O_WRONLY) || fl.contains(vfs::OpenFlags::O_RDWR);
        // An encrypted REGULAR file's key is resolved here whichever way the
        // handle was asked for: reading and writing both need the plaintext.
        // Regular only, because the reference gives a directory no open hook at
        // all — a locked directory must still list, and requiring its key here
        // would refuse the one thing it is allowed to do.
        let encrypted = live.encrypted() && mode::file_type(live.mode) == FileType::Regular;
        if !write && !encrypted && !crate::verity::access::is_verity(live.flags) {
            return Ok(());
        }
        let mut v = node.fs.volume.lock();
        if let Some(parent) = file.dentry().parent().and_then(|d| d.inode()) {
            let pnode = F2fsOps::node(&parent)?;
            v.crypt_check_permitted(pnode.ino, node.ino).map_err(errno_to_vfs)?;
        }
        // Verity first: a sealed file refuses a writable handle outright, and
        // there is nothing to acquire for a handle that is not going to exist.
        v.verity_file_open(&live, node.ino, write).map_err(errno_to_vfs)?;
        // Then the key, once, so nothing below this handle resolves one from the
        // medium — and so a file whose key is absent is refused by the open
        // rather than by a read or a write at some later offset.
        if encrypted { v.crypt_file_open(&live, node.ino).map_err(errno_to_vfs)?; }
        if write { v.dquot_initialize(node.ino).map_err(errno_to_vfs)?; }
        Ok(())
    }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = F2fsOps::node(inode)?;
        let live = node.live()?;
        if mode::file_type(live.mode) == FileType::Directory { return Err(VfsError::Eisdir); }
        let v = node.fs.volume.lock();
        v.read_file(&live, node.ino, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = F2fsOps::node(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        if mode::file_type(node.live()?.mode) == FileType::Directory {
            return Err(VfsError::Eisdir);
        }
        // A short write is reported as short, not as a failure and not as a
        // full one: the caller resumes from where it stopped, which is the
        // only way a write that ran out of space part way can be completed.
        let n = node.fs.write(node.ino, off, buf)?;
        node.restat(inode)?;
        Ok(n)
    }

    /// Make one file durable.
    ///
    /// Writes here reach the medium out of place but are not REFERENCED until
    /// something names them, so reporting success without writing would tell a
    /// caller its data is safe when a crash would lose it. What names them is
    /// the volume's decision: a chain of the file's own node blocks where the
    /// state allows a later mount to replay it, and a whole checkpoint where
    /// it does not. Answering every call with a checkpoint is honest but makes
    /// one file's durability cost the whole volume's.
    fn fsync(&self, file: &vfs::File, datasync: bool) -> KResult<()> {
        let inode = file.inode();
        match inode.file_type() {
            FileType::Regular | FileType::Directory => {}
            _ => return Err(VfsError::Einval),
        }
        let node = F2fsOps::node(inode)?;
        if !node.fs.is_writable() { return Ok(()); }
        node.fs.sync_file(node.ino, datasync)
    }

    /// This filesystem STORES `.` and `..` as ordinary entries, so the
    /// listing already carries them. Leaving this at its default would have
    /// the interface synthesise a second pair on top, and every directory
    /// would list both names twice.
    fn iterate_emits_dots(&self) -> bool { true }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let (node, dir) = F2fsOps::dir_of(inode)?;
        let entries = {
            let v = node.fs.volume.lock();
            v.read_dir(&dir, node.ino).map_err(errno_to_vfs)?
        };
        // This filesystem STORES `.` and `..` as ordinary entries, so they are
        // emitted from the listing rather than synthesised: synthesising them
        // on top of the stored pair would report each twice.
        for (i, e) in entries.iter().enumerate() {
            let slot = i as u64;
            if ctx.pos > slot { continue; }
            let name = alloc::string::String::from_utf8_lossy(&e.name);
            if !ctx.emit(&name, u64::from(e.ino), vfs_type(e.file_type), slot + 1) { break; }
        }
        Ok(())
    }
}

