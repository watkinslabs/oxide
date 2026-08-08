// The four `BPF_MAP_*_BATCH` commands.
//
// A batch is the single-element operation repeated over a user-supplied
// key (and value) array, so it goes through the same map storage the
// element commands use — there is no second element path here, only the
// loop and its write-back protocol.
//
// The protocol is the load-bearing part. `count == 0` returns success and
// writes nothing at all. Otherwise the caller's `batch.count` is zeroed
// first, and the number actually processed is written back on *every*
// exit, including the error and short-batch ones — a caller that gets an
// error still learns how far the batch got. A lookup that produced at
// least one element also writes `out_batch`, the cursor the next call
// resumes from.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::super::attr::{self, Access, Attr};
use super::super::map;
use super::super::uapi;
use super::super::user;
use super::super::BpfMapInode;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(in super::super) enum BatchOp { Lookup, LookupAndDelete, Update, Delete }

impl BatchOp {
    /// A batch that reads elements needs a readable descriptor; every
    /// batch but the plain lookup needs a writable one. # C: O(1)
    fn accesses(self) -> &'static [Access] {
        match self {
            BatchOp::Lookup => &[Access::Read],
            BatchOp::LookupAndDelete => &[Access::Read, Access::Write],
            BatchOp::Update | BatchOp::Delete => &[Access::Write],
        }
    }

    /// The `allowed_flags` mask each batch passes to the element-flag
    /// check. Delete open-codes `elem_flags & ~BPF_F_LOCK`. # C: O(1)
    fn allowed_elem_flags(self) -> u64 {
        use uapi::elem_flags as e;
        match self {
            BatchOp::Lookup | BatchOp::LookupAndDelete => e::F_LOCK | e::F_CPU,
            BatchOp::Update => e::F_LOCK | e::F_CPU | e::F_ALL_CPUS,
            BatchOp::Delete => e::F_LOCK,
        }
    }
}

/// Byte address of element `index` in a user array of `stride`-byte
/// elements. # C: O(1)
fn slot(base: u64, index: u32, stride: u32) -> Result<u64, Errno> {
    base.checked_add(u64::from(index).checked_mul(u64::from(stride)).ok_or(Errno::Efault)?)
        .ok_or(Errno::Efault)
}

/// Write the processed count back into the caller's attr. # C: O(1)
fn write_count(attr_ptr: u64, count: u32) -> Result<(), Errno> {
    let at = attr_ptr
        .checked_add(uapi::off::batch::COUNT as u64)
        .ok_or(Errno::Efault)?;
    user::write_bytes(at, &count.to_ne_bytes())
}

/// `bpf_map_do_batch()`. # C: O(count × (entries + key_size + value_size))
pub(in super::super) fn batch(a: &Attr, attr_ptr: u64, op: BatchOp) -> Result<i64, Errno> {
    use uapi::off::batch as o;
    attr::check_attr(a, o::LAST_END)?;
    let inode = map::map_from_fd(a.u32_at(o::MAP_FD))?;
    let m = inode.private::<BpfMapInode>().ok_or(Errno::Einval)?;
    let _writer = if op.accesses().contains(&Access::Write) {
        Some(m.storage.begin_write()?)
    } else {
        None
    };
    let frozen = m.storage.frozen();
    for want in op.accesses() { attr::map_access_ok(m.map_flags, frozen, *want)?; }
    attr::check_op_flags(a.u64_at(o::ELEM_FLAGS), op.allowed_elem_flags())?;

    let max_count = a.u32_at(o::COUNT);
    if max_count == 0 { return Ok(0); }
    write_count(attr_ptr, 0)?;

    let mut done = 0u32;
    let outcome = match op {
        BatchOp::Update => update_batch(a, m, max_count, &mut done),
        BatchOp::Delete => delete_batch(a, m, max_count, &mut done),
        BatchOp::Lookup | BatchOp::LookupAndDelete =>
            lookup_batch(a, m, op, max_count, &mut done),
    };
    // A fault reaching for the caller's arrays cannot be reported through
    // those same arrays, so the count write-back is skipped for it.
    if outcome == Err(Errno::Efault) { return Err(Errno::Efault); }
    write_count(attr_ptr, done)?;
    outcome
}

fn delete_batch(
    a: &Attr,
    m: &BpfMapInode,
    max_count: u32,
    done: &mut u32,
) -> Result<i64, Errno> {
    use uapi::off::batch as o;
    let keys = a.u64_at(o::KEYS);
    while *done < max_count {
        let key = user::read_vec(slot(keys, *done, m.key_size)?, m.key_size as usize)?;
        if m.map_type == uapi::map_type::ARRAY { return Err(Errno::Einval); }
        if m.storage.remove(m.map_type, &key, false)?.is_none() {
            return Err(Errno::Enoent);
        }
        *done += 1;
    }
    Ok(0)
}

fn update_batch(
    a: &Attr,
    m: &BpfMapInode,
    max_count: u32,
    done: &mut u32,
) -> Result<i64, Errno> {
    use uapi::off::batch as o;
    let keys = a.u64_at(o::KEYS);
    let values = a.u64_at(o::VALUES);
    let flags = a.u64_at(o::ELEM_FLAGS);
    while *done < max_count {
        let key = user::read_vec(slot(keys, *done, m.key_size)?, m.key_size as usize)?;
        let value = user::read_vec(slot(values, *done, m.value_size)?, m.value_size as usize)?;
        attr::check_update_flags(flags)?;
        m.storage.update(m.map_type, key, value, flags)?;
        *done += 1;
    }
    Ok(0)
}

/// The lookup walk. `in_batch` is the resume cursor: absent means start
/// from the first key. A key that vanished between the walk and the value
/// read is skipped rather than failing the batch, because a concurrent
/// delete is not the caller's error. Reaching the end of the map is
/// `-ENOENT` with the short count and cursor written back, which is how a
/// caller learns to stop iterating.
/// # C: O(count × (entries + key_size + value_size))
fn lookup_batch(
    a: &Attr,
    m: &BpfMapInode,
    op: BatchOp,
    max_count: u32,
    done: &mut u32,
) -> Result<i64, Errno> {
    use uapi::off::batch as o;
    let keys = a.u64_at(o::KEYS);
    let values = a.u64_at(o::VALUES);
    let in_batch = a.u64_at(o::IN_BATCH);
    let out_batch = a.u64_at(o::OUT_BATCH);
    let key_size = m.key_size as usize;

    let mut prev: Option<Vec<u8>> = if in_batch == 0 { None }
        else { Some(user::read_vec(in_batch, key_size)?) };

    let mut outcome = Ok(0i64);
    while *done < max_count {
        let Some(key) = m.storage.next_key(prev.as_deref(), m.max_entries)? else {
            outcome = Err(Errno::Enoent);
            break;
        };
        let value = if op == BatchOp::LookupAndDelete {
            m.storage.remove(m.map_type, &key, true)?
        } else {
            match m.lookup_value(&key) { Some(v) => Some(v.copy_out()?), None => None }
        };
        let Some(value) = value else { prev = Some(key); continue };
        user::write_bytes(slot(keys, *done, m.key_size)?, &key)?;
        user::write_bytes(slot(values, *done, m.value_size)?, &value)?;
        *done += 1;
        prev = Some(key);
    }
    if *done != 0 {
        if let Some(cursor) = prev.as_deref() { user::write_bytes(out_batch, cursor)?; }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_attr_boundary_is_offsetofend_batch_flags() {
        use uapi::off::batch as o;
        assert_eq!(o::IN_BATCH, 0);
        assert_eq!(o::OUT_BATCH, 8);
        assert_eq!(o::KEYS, 16);
        assert_eq!(o::VALUES, 24);
        assert_eq!(o::COUNT, 32);
        assert_eq!(o::MAP_FD, 36);
        assert_eq!(o::ELEM_FLAGS, 40);
        assert_eq!(o::FLAGS, 48);
        assert_eq!(o::LAST_END, 56);
    }

    /// The zero-tail check precedes the descriptor resolution, so a
    /// malformed attr naming a closed fd is EINVAL rather than EBADF.
    #[test]
    fn the_attr_tail_is_checked_before_the_map_descriptor() {
        let mut a = Attr::zeroed();
        let fd = uapi::off::batch::MAP_FD;
        a.bytes[fd..fd + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(batch(&a, 0, BatchOp::Lookup), Err(Errno::Ebadf));
        a.bytes[uapi::off::batch::LAST_END] = 1;
        assert_eq!(batch(&a, 0, BatchOp::Lookup), Err(Errno::Einval));
    }

    /// Gating is the descriptor's access mode, exactly as for the
    /// single-element ops: a plain lookup needs read, everything that
    /// mutates needs write, and lookup-and-delete needs both.
    #[test]
    fn each_batch_demands_the_same_access_as_its_element_op() {
        assert_eq!(BatchOp::Lookup.accesses(), &[Access::Read]);
        assert_eq!(BatchOp::LookupAndDelete.accesses(), &[Access::Read, Access::Write]);
        assert_eq!(BatchOp::Update.accesses(), &[Access::Write]);
        assert_eq!(BatchOp::Delete.accesses(), &[Access::Write]);
    }

    /// A frozen map, or one created read-only, refuses the writing
    /// batches with EPERM and still admits the reading one.
    #[test]
    fn a_frozen_or_read_only_map_refuses_the_writing_batches() {
        use uapi::map_flags as f;
        for op in [BatchOp::Update, BatchOp::Delete, BatchOp::LookupAndDelete] {
            let verdict = op.accesses().iter()
                .try_for_each(|want| attr::map_access_ok(0, true, *want));
            assert_eq!(verdict, Err(Errno::Eperm), "{op:?} on a frozen map");
            let verdict = op.accesses().iter()
                .try_for_each(|want| attr::map_access_ok(f::RDONLY, false, *want));
            assert_eq!(verdict, Err(Errno::Eperm), "{op:?} on a read-only map");
        }
        assert_eq!(attr::map_access_ok(0, true, Access::Read), Ok(()));
        assert_eq!(attr::map_access_ok(f::WRONLY, false, Access::Read), Err(Errno::Eperm));
    }

    /// The delete batch's element flags are `~BPF_F_LOCK`-masked, so the
    /// presence flags a single-element update accepts are refused here.
    #[test]
    fn element_flag_masks_differ_per_batch() {
        use uapi::elem_flags as e;
        assert_eq!(BatchOp::Delete.allowed_elem_flags(), e::F_LOCK);
        assert_eq!(BatchOp::Lookup.allowed_elem_flags(), e::F_LOCK | e::F_CPU);
        assert_eq!(BatchOp::LookupAndDelete.allowed_elem_flags(), e::F_LOCK | e::F_CPU);
        assert_eq!(
            BatchOp::Update.allowed_elem_flags(),
            e::F_LOCK | e::F_CPU | e::F_ALL_CPUS,
        );
        for op in [BatchOp::Lookup, BatchOp::Update, BatchOp::Delete] {
            assert_eq!(attr::check_op_flags(0, op.allowed_elem_flags()), Ok(()));
            assert_eq!(
                attr::check_op_flags(e::NOEXIST, op.allowed_elem_flags()),
                Err(Errno::Einval),
            );
            assert_eq!(
                attr::check_op_flags(e::F_LOCK, op.allowed_elem_flags()),
                Err(Errno::Einval),
            );
        }
    }

    /// Element addresses are computed in the full 64-bit range and refuse
    /// to wrap, so a huge count cannot be made to alias low memory.
    #[test]
    fn element_addresses_never_wrap() {
        assert_eq!(slot(0x1000, 0, 8), Ok(0x1000));
        assert_eq!(slot(0x1000, 3, 8), Ok(0x1018));
        assert_eq!(slot(u64::MAX - 4, 1, 8), Err(Errno::Efault));
        assert_eq!(slot(0, u32::MAX, u32::MAX), Ok(0xffff_fffe_0000_0001));
    }

    /// `count == 0` is a success that writes nothing — not even the zero
    /// the non-empty path stores first.
    #[test]
    fn a_zero_count_batch_writes_nothing_at_all() {
        let mut a = Attr::zeroed();
        let fd = uapi::off::batch::MAP_FD;
        a.bytes[fd..fd + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        // The count is still zero here, but the map fd is refused first:
        // the descriptor is resolved before the count is consulted.
        assert_eq!(batch(&a, 0, BatchOp::Delete), Err(Errno::Ebadf));
    }

    #[test]
    fn the_count_write_back_targets_the_batch_count_field() {
        let mut out = [0u8; uapi::ATTR_SIZE];
        let ptr = out.as_mut_ptr() as u64;
        assert_eq!(write_count(ptr, 5), Ok(()));
        let at = uapi::off::batch::COUNT;
        assert_eq!(u32::from_ne_bytes(out[at..at + 4].try_into().unwrap()), 5);
        assert_eq!(write_count(u64::MAX, 1), Err(Errno::Efault));
    }
}
