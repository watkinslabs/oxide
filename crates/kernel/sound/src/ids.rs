use vfs::Ino;

/// First number in sound's reserved range ('Snd\0' in the high 32), from the
/// one owner of pseudo-inode number space. The low bits carry `(card, minor)`.
/// Sound-node identity is the inode's own backend state, never this tag.
/// # C: O(1)
pub(crate) const INO_TAG: Ino = vfs::pseudo_ino::SOUND.start();
