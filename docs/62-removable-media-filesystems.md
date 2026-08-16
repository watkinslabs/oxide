# 62 Removable-media filesystems

DRAFT 2026-08-16. Dep:`01`,`02`,`07`,`08`,`09`,`16`,`17`,`52`. Provides:on-disk contract for `vfat`,`msdos`,`exfat`,`ntfs3`.

Governs the four filesystem TYPES a medium formatted elsewhere arrives with:
`vfat`, `msdos`, `exfat`, `ntfs3`. Each is read-write; none is a subset
(`02` discipline rule 3). Ext4 is `17`; pseudo-filesystems are `19`.

## 1 Frozen invariants

1. One crate per FORMAT, not per type: `fatfs` serves `vfat` and `msdos`,
   `exfatfs` serves `exfat`, `ntfs3` serves `ntfs3`.
2. Each crate is layered: pure decision modules over `&[u8]`, a `Volume` over
   `sectors::SectorSource`, a `mount` adapter to `16`. Only `mount` reaches the
   block layer.
3. Every layer below `mount` is hosted-testable against an in-memory volume the
   test lays out from the format's rules, not from the reader's.
4. A mechanism two formats genuinely share has ONE owner (`52§5`): the sector
   adapter is `sectors`, the 1980-epoch date/time pair is `dostime`.
5. A medium whose metadata is inconsistent answers `EIO`; a request the format
   cannot express answers `EINVAL`. A volume that cannot be written mounts
   read-only; the mount does not fail.
6. Nothing invents an identity the medium records: an inode number is derived
   only where the format stores none.

## 2 Registration

| Type | Crate | Magic | Dirty volume |
|---|---|---|---|
| `vfat` | `fatfs` | `MSDOS_SUPER_MAGIC` | mount rw + warn |
| `msdos` | `fatfs` | `MSDOS_SUPER_MAGIC` | mount rw + warn |
| `exfat` | `exfatfs` | `EXFAT_SUPER_MAGIC` | mount rw + warn |
| `ntfs3` | `ntfs3` | `NTFS_SUPER_MAGIC` | mount READ-ONLY unless `force` |

`ntfs3` differs because it has a journal: writing to a volume whose journal has
not been replayed loses what the journal was about to redo.

Registration is `syscalls::fsmount_common::registry` only. A second registry is
a split source of truth (`02` discipline rule 3).

## 3 Layer contract

| Layer | Owns | Must not |
|---|---|---|
| `uapi` | on-disk numbers, offsets, flags | policy |
| decision modules | parse/validate/encode over bytes | I/O |
| `Volume<S>` | structures, allocation, name operations | VFS types |
| `mount` | inode/file/superblock operations, block device | work logic |

## 4 What each format makes different

### 4.1 FAT (`fatfs`)

Allocation and chaining are one structure: a cluster is free when its table
entry is zero. A name is one 32-byte record plus long-name slots.

### 4.2 exFAT (`exfatfs`)

1. **Allocation is the BITMAP, not the table.** A run flagged `NoFatChain` has
   no table entries, so its clusters read as free from the table. Allocating
   from the table hands out clusters in use.
2. **A name is a SET** — file entry, stream entry, name entries — carrying a
   16-bit checksum over all of them, with the two bytes holding that checksum
   excluded in the FIRST entry only.
3. **Case folding is the volume's**, from its up-case table, accepted only when
   it expands to the whole 16-bit range and matches its recorded checksum.
4. A timestamp carries its own UTC-offset byte, which wins over `time_offset=`.
5. `valid_size` bounds a read; bytes to `size` were never written by anyone.

### 4.3 NTFS (`ntfs3`)

1. **The update sequence.** The last two bytes of every 512 in a record or
   index block are a repeated value on the medium. Not putting back what they
   displaced decodes a record with two bytes per sector wrong.
2. **Runlists are DELTAS.** A run's cluster is a signed offset from the
   previous run's; a run with no offset is a HOLE, not cluster zero.
3. **A directory is a B-TREE** spanning `$INDEX_ROOT` and `$INDEX_ALLOCATION`.
   A child pointer is an entry's LAST eight bytes, present only when flagged.
4. **`$UpCase` decides ORDER**, not only equality: a descent under a different
   fold walks to the wrong child.
5. Mounting is circular: the MFT is a file whose extents are recorded in its
   own first record.
6. Everything is an attribute, resident or non-resident, and a type may repeat
   under different names — that is an alternate data stream.

## 5 Mount options

Each type honours the option set its reference accepts and RENDERS it back in a
form its own parser accepts: `show_options` output must round-trip, or
`mount -o remount` fails on a working mount. An option the build cannot honour
is refused (`EINVAL`), never accepted and ignored.

## 6 Test contract (frozen)

1. Every decision module is hosted-tested; no test lives in a target-gated file
   (`53`, phantom-test rule).
2. Each crate carries an image BUILDER that lays out a volume from the format's
   rules, independent of the reader.
3. Every write path is verified through a REMOUNT of the resulting image, not
   through the writing mount's own memory.
4. Every claim of correctness carries a positive control: reinstate the defect,
   the suite goes red, restore, green. Checksums, case tables, update sequences
   and runlist deltas are mandatory controls — each produces plausible-looking
   wrong data when subtly wrong.
5. A control that stays GREEN is a coverage gap and is closed in the same
   change.

## 7 Failure modes

| Condition | Answer |
|---|---|
| medium too short for a boot sector | `EIO` |
| boot sector field the format forbids | `EINVAL` |
| metadata inconsistent (bad chain, torn record, bad checksum) | `EIO` |
| name the format cannot spell, on CREATE | `EINVAL` |
| name the format cannot spell, on LOOKUP | resolved |
| volume full | `ENOSPC` |
| write to a read-only mount | `EROFS` |
| encrypted attribute read | `EACCES` |

## 8 Cross-spec

- `16§2` inode/file operation surface.
- `17§2` block device access.
- `52§5` crate ownership boundaries.
- `53` layering: shim parses, work-fn decides.

## 9 OQ

1. Does the shared sector adapter belong in `block` once that crate can depend
   on the errno type?
2. Should `ntfs3` replay `$LogFile` at mount, or keep refusing a dirty volume
   read-write until a checker exists?

## 10 Changelog

- 2026-08-16: Created with `exfat` and `ntfs3`; recorded the shared `sectors`
  and `dostime` owners.
