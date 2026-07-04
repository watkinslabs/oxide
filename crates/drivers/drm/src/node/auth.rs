use alloc::vec::Vec;

use sync::{Spinlock, TaskList as OpsLockClass};
use vfs::File;

pub(super) const DRM_FILE_CAP_ATOMIC: u64 = 1 << crate::DRM_CLIENT_CAP_ATOMIC;

static MASTER_OWNERS: Spinlock<Vec<u64>, OpsLockClass> = Spinlock::new(Vec::new());
static FILE_MAGICS: Spinlock<Vec<(u64, u32)>, OpsLockClass> = Spinlock::new(Vec::new());
static AUTHORIZED_MAGICS: Spinlock<Vec<(u32, u32)>, OpsLockClass> = Spinlock::new(Vec::new());
static NEXT_MAGIC: Spinlock<u32, OpsLockClass> = Spinlock::new(1);

pub(super) fn file_token(file: &File) -> u64 {
    file as *const File as usize as u64
}

pub(super) fn file_magic(file: &File) -> u32 {
    let token = file_token(file);
    let mut magics = FILE_MAGICS.lock();
    if let Some((_, magic)) = magics.iter().find(|(t, _)| *t == token) {
        return *magic;
    }
    let mut next = NEXT_MAGIC.lock();
    let magic = *next;
    *next = next.wrapping_add(1).max(1);
    magics.push((token, magic));
    magic
}

pub(super) fn release_file_magic(token: u64) {
    let magic = {
        let mut magics = FILE_MAGICS.lock();
        magics
            .iter()
            .position(|(t, _)| *t == token)
            .map(|pos| magics.remove(pos).1)
    };
    if let Some(magic) = magic {
        AUTHORIZED_MAGICS.lock().retain(|(_, m)| *m != magic);
    }
}

pub(super) fn authorize_magic(card_id: u32, magic: u32) {
    let mut auth = AUTHORIZED_MAGICS.lock();
    if auth.iter().all(|(card, m)| *card != card_id || *m != magic) {
        auth.push((card_id, magic));
    }
}

pub(super) fn clear_authorized_for_card(card_id: u32) {
    AUTHORIZED_MAGICS.lock().retain(|(card, _)| *card != card_id);
}

#[cfg(test)]
pub(super) fn is_magic_authorized(card_id: u32, magic: u32) -> bool {
    AUTHORIZED_MAGICS.lock().iter().any(|(card, m)| *card == card_id && *m == magic)
}

pub(super) fn master_owner(card_id: u32) -> u64 {
    MASTER_OWNERS.lock().get(card_id as usize).copied().unwrap_or(0)
}

pub(super) fn set_master_owner(card_id: u32, token: u64) -> i64 {
    use syscall::errno::Errno;
    if token == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut owners = MASTER_OWNERS.lock();
    let idx = card_id as usize;
    if owners.len() <= idx {
        owners.resize(idx + 1, 0);
    }
    if owners[idx] == 0 || owners[idx] == token {
        owners[idx] = token;
        0
    } else {
        -(Errno::Ebusy.as_i32() as i64)
    }
}

pub(super) fn drop_master_owner(card_id: u32, token: u64) -> i64 {
    use syscall::errno::Errno;
    let mut owners = MASTER_OWNERS.lock();
    let Some(owner) = owners.get_mut(card_id as usize) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if *owner == token {
        *owner = 0;
        0
    } else {
        -(Errno::Einval.as_i32() as i64)
    }
}

pub(super) fn clear_master_owner(card_id: u32) {
    if let Some(owner) = MASTER_OWNERS.lock().get_mut(card_id as usize) {
        *owner = 0;
    }
}

pub(super) fn release_master_owner(card_id: u32, token: u64) {
    if let Some(owner) = MASTER_OWNERS.lock().get_mut(card_id as usize) {
        if *owner == token {
            *owner = 0;
        }
    }
}

pub(super) fn is_master(card_id: u32, token: u64) -> bool {
    token != 0 && master_owner(card_id) == token
}

pub(super) fn client_cap_atomic(file: &File) -> bool {
    (file.private_data() & DRM_FILE_CAP_ATOMIC) != 0
}

pub(super) fn ioctl_takes_user_ptr(req: u64) -> bool {
    !matches!(req, crate::DRM_IOCTL_SET_MASTER | crate::DRM_IOCTL_DROP_MASTER)
}

pub(super) fn valid_user_range(arg: u64, len: u64) -> bool {
    arg != 0 && arg.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

pub(super) fn copy_bytes_to_user(dst: u64, dst_len: u64, src: &[u8]) -> core::result::Result<(), ()> {
    if dst_len == 0 {
        return Ok(());
    }
    if !valid_user_range(dst, dst_len.min(src.len() as u64)) {
        return Err(());
    }
    let n = core::cmp::min(dst_len, src.len() as u64) as usize;
    // SAFETY: dst..dst+n is validated as a user range above; caller supplied
    // bytes are kernel-owned and immutable for the copy.
    unsafe {
        for (i, b) in src.iter().copied().take(n).enumerate() {
            core::ptr::write_volatile((dst + i as u64) as *mut u8, b);
        }
    }
    Ok(())
}

pub(super) fn atomic_property_count(count_props_ptr: u64, count_objs: u32) -> core::result::Result<u64, ()> {
    let bytes = (count_objs as u64).checked_mul(core::mem::size_of::<u32>() as u64).ok_or(())?;
    if !valid_user_range(count_props_ptr, bytes) {
        return Err(());
    }
    let mut total = 0u64;
    for idx in 0..count_objs {
        let off = idx as u64 * core::mem::size_of::<u32>() as u64;
        // SAFETY: the whole count_props array was validated above.
        let count = unsafe {
            core::ptr::read_volatile((count_props_ptr + off) as *const u32)
        };
        total = total.checked_add(count as u64).ok_or(())?;
    }
    Ok(total)
}

#[cfg(test)]
pub(super) fn reset_test_state() {
    MASTER_OWNERS.lock().clear();
    FILE_MAGICS.lock().clear();
    AUTHORIZED_MAGICS.lock().clear();
    *NEXT_MAGIC.lock() = 1;
}
