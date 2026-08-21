# 69 Image and native filesystems

DRAFT 2026-08-16. Dep:`01`,`02`,`07`,`08`,`09`,`16`,`17`,`52`,`53`. Provides:on-disk contract for `squashfs`,`erofs`,`f2fs`,`xfs`,`btrfs`.

Governs the five filesystem TYPES a Linux system meets that are neither ext4
(`17`), removable media (`62`), a host share (`67`) nor pseudo (`19`):

| Type | Role |
|---|---|
| `squashfs` | compressed read-only image — every live medium, every container base layer |
| `erofs` | compressed read-only image — Android system images, modern container images |
| `f2fs` | log-structured, flash-targeted read-write |
| `xfs` | allocation-group extent filesystem — the default root on enterprise distributions |
| `btrfs` | copy-on-write B-tree filesystem — the default root on several distributions |

## 1 Frozen invariants

1. **A filesystem that misreads is worse than one that refuses.** Every type
   REFUSES a volume whose feature bits, checksums or geometry it does not fully
   understand; it does not mount and return wrong bytes. The refusal is
   part of the contract and is pinned by tests, not left to a reader's care.
2. One crate per FORMAT under `crates/kernel/`, layered exactly as `62§3`: pure
   decision modules over `&[u8]`, a `Volume<S>` over `sectors::SectorSource`, a
   `mount` adapter to `16`. Only `mount` reaches the block layer.
3. Every layer below `mount` is hosted-testable against an in-memory volume the
   test lays out from the format's own rules, not from the reader's.
4. Registration is `syscalls::fsmount_common::registry` only. A second registry
   is a split source of truth (`02` discipline rule 3).
5. A read-only FORMAT mounts read-only whatever the caller asked for; the mount
   succeeds and the superblock says `SB_RDONLY`. A read-WRITE format whose
   volume cannot be written safely mounts read-only, and does not fail.
6. A checksum the format defines is CHECKED, over the range the format defines,
   before the bytes it covers are believed. An unchecked checksum is a defect,
   not an optimisation.
7. A length, count or offset read off the medium is validated against the buffer
   it will index before it is used. A compressed block's declared output length
   is bounded by the destination, never trusted into it.

## 2 Registration

| Type | Crate | Magic | Writability |
|---|---|---|---|
| `squashfs` | `squashfs` | `SQUASHFS_MAGIC` | read-only, always |
| `erofs` | `erofs` | `EROFS_SUPER_MAGIC` | read-only, always |
| `f2fs` | `f2fs` | `F2FS_SUPER_MAGIC` | read-write |
| `xfs` | `xfs` | `XFS_SUPER_MAGIC` | read-write |
| `btrfs` | `btrfs` | `BTRFS_SUPER_MAGIC` | read-write |

Where a read-write format's implementation reads correctly but cannot yet write
correctly, it mounts READ-ONLY and records the gap in `scratch/known_issues.md`.
A guessed writer is the one outcome this spec forbids outright: a wrong write is
unrecoverable, where a refused write is a message.

## 3 Compression

Read-only image formats exist to be compressed, so the codec set decides which
media mount at all.

| Codec | Owner |
|---|---|
| DEFLATE / zlib | `miniz_oxide` |
| Zstandard | `zstd` (`crates/shared/zstd`) |
| LZO | `lzo1x` (`crates/shared/lzo1x`) |
| LZ4 block | per-crate decoder, because the image formats need PARTIAL output-bounded decode |
| XZ / LZMA | none in tree |

A volume whose declared codec has no decoder REFUSES the mount with a log line
naming the codec. This mirrors what a kernel built without that decompressor
does; it is not a deferral, and the row stays open until the decoder lands.

## 4 What each format makes different

### 4.1 squashfs

1. **Two block encodings, not one.** A metadata block carries a 16-bit length
   whose top bit means UNCOMPRESSED; a data block carries a 32-bit length whose
   bit 24 means the same. Decoding one with the other's mask reads the wrong
   number of bytes from the right place, which is the failure that looks like
   success.
2. **Metadata is a byte STREAM across block boundaries.** A structure may
   straddle two compressed metadata blocks, so every read is a loop that
   advances a `(block, offset)` cursor, not a slice of one block.
3. **`.` and `..` are not stored.** They are emitted by the reader; the external
   directory position is therefore offset by three from the on-disk one.
4. **A directory entry's inode number is a SIGNED 16-bit delta** from its
   header's base. Reading it unsigned gives a plausible wrong inode.
5. A file's tail may live in a shared FRAGMENT block. A file with a fragment
   whose size is a whole multiple of the block size is self-inconsistent and is
   refused.

### 4.2 EROFS

1. **A directory entry's name length comes from the NEXT entry's name offset**,
   and the last entry's runs to the end of its block or its first NUL. Taking it
   from the wrong neighbour yields a name that is a prefix or that swallows the
   next.
2. **Two inode layouts**, compact and extended, chosen by the format word's low
   bit; the wrong choice reads every later field at the wrong offset.
3. **Inline data** shares the inode's own block, so a file's tail is addressed
   relative to the inode, not to a block address.
4. The superblock checksum is a compat feature: present, it is checked; absent,
   the volume is still mountable. An unknown INCOMPAT bit refuses regardless.

### 4.3 F2FS

1. **The checkpoint decides which metadata is live.** Two packs, each with its
   own CRC; the valid pack with the higher version wins. Reading the other pack
   reads a consistent, stale filesystem.
2. **A journalled NAT entry OVERRIDES the on-disk table.** Consulting the table
   alone resolves a node identifier to its previous block.
3. **`i_addr[]` starts at an offset that depends on `i_extra_isize` and the
   inline-xattr flag.** A fixed offset reads a real block address for the wrong
   index.
4. Inline data, inline dentries and inline symlinks are the common case on a
   real volume, not an optimisation to add later.

### 4.4 XFS

1. **Geometry is per allocation GROUP.** A block number is either group-relative
   or absolute, and the two differ by a shift the superblock states. Mixing them
   addresses a different group's blocks, which decode plausibly.
2. **Every metadata block carries its own CRC and its own owning-inode/UUID
   back-reference** on a v5 filesystem. Checking the CRC without checking the
   back-reference accepts a block from the wrong tree.
3. The B+tree formats — inode, free-space by block, free-space by size, refcount,
   reverse-map — share a header shape but not a key shape.
4. A log that is not clean cannot be replayed without a writer, so an unclean
   volume mounts read-only, never read-write.

### 4.5 Btrfs

1. **Nothing is at a fixed address.** The CHUNK tree maps logical to physical,
   and the superblock carries a bootstrap copy of enough of it to find the rest.
   Reading a logical address as physical reads another tree's bytes.
2. **Every tree block is checksummed and stamped** with its own logical address,
   fsid and generation; all four are checked before the block is believed.
3. A B-tree descent chooses the child whose key is the greatest not exceeding the
   search key. An off-by-one in that comparison lands in a sibling subtree and
   returns a real item for the wrong object.
4. Unknown `incompat_flags` refuse the mount; unknown `compat_ro_flags` mount
   read-only. The two are different answers and are tested separately.

## 5 Mount options

Each type honours the option set its reference accepts and RENDERS it back in a
form its own parser accepts, so `show_options` round-trips. An option the build
cannot honour is refused (`EINVAL`), never accepted and ignored.

## 6 Test contract (frozen)

1. Every decision module is hosted-tested; no test lives in a target-gated file
   (`53`, phantom-test rule).
2. Each crate carries an image BUILDER that lays out a volume from the format's
   rules, independent of the reader.
3. Every claim of correctness carries a positive control: reinstate the defect,
   the suite goes red, restore, green. Mandatory control classes, because each
   produces plausible-looking wrong data when subtly wrong:
   - an unknown incompat feature bit accepted instead of refused
   - a checksum computed over the wrong range, or not computed
   - a tree descent taking the wrong child
   - an extent or block-index entry decoded with the wrong shift
   - a compressed block whose declared length is trusted past the destination
   - a directory entry's name or inode number taken from the wrong neighbour
4. A control that stays GREEN is a coverage gap and is closed in the same change.
5. A refusal is tested as a behaviour, not assumed: each refusal in `§1` rule 1
   has a test that supplies the malformed volume and asserts the errno.

## 7 Failure modes

| Condition | Answer |
|---|---|
| medium too short for a superblock | `EIO` |
| magic absent | `EINVAL` |
| unknown incompat feature bit | `EINVAL` |
| unknown read-only-compat feature bit | mount, `SB_RDONLY` |
| checksum mismatch on a structure | `EIO` |
| declared codec has no decoder | `EINVAL` |
| length or offset outside the structure it indexes | `EIO` |
| decompressed length disagrees with the expected length | `EIO` |
| write to a read-only mount | `EROFS` |
| volume full | `ENOSPC` |

## 8 Cross-spec

- `16§2` inode/file operation surface.
- `17§2` block device access.
- `52§5` crate ownership boundaries; `52§7` layering.
- `53` shim parses, work-fn decides.
- `62§3` the layer contract these crates share with the removable-media family.

## 9 OQ

1. Where does an XZ/LZMA decoder live once one exists — a `shared` crate beside
   `zstd`, or per-consumer?
2. Does the LZ4 block decoder belong in `shared` once a second consumer needs
   the partial-output form?
3. Btrfs and XFS both need a generic B-tree descent with format-specific key
   comparison. One owner, or two?

## 10 Changelog

- 2026-08-16: Created with `squashfs`, `erofs`, `f2fs`, `xfs`, `btrfs`.
