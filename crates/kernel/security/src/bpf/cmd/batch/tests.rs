use super::*;

use vfs::InodeRef;

fn put_u32(a: &mut Attr, off: usize, value: u32) {
    a.bytes[off..off + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_u64(a: &mut Attr, off: usize, value: u64) {
    a.bytes[off..off + 8].copy_from_slice(&value.to_ne_bytes());
}

fn hash_map(entries: u32) -> InodeRef {
    map::allocate(uapi::map_type::HASH, 4, 8, entries, 0).unwrap()
}

fn request(
    keys: &mut [u32],
    values: &mut [u64],
    cursor: &mut [u8; 4],
    count: u32,
) -> (Attr, Attr) {
    use uapi::off::batch as o;
    let mut input = Attr::zeroed();
    put_u64(&mut input, o::KEYS, keys.as_mut_ptr() as u64);
    put_u64(&mut input, o::VALUES, values.as_mut_ptr() as u64);
    put_u32(&mut input, o::COUNT, count);
    put_u64(&mut input, o::OUT_BATCH, cursor.as_mut_ptr() as u64);
    (input, Attr::zeroed())
}

fn run(a: &Attr, output: &mut Attr, op: BatchOp, map: &BpfMapInode) -> Result<i64, Errno> {
    batch_map(a, output.bytes.as_mut_ptr() as u64, op, map)
}

#[test]
fn real_hash_map_batches_update_lookup_and_partially_delete() {
    let inode = hash_map(4);
    let map = inode.private::<BpfMapInode>().unwrap();

    let mut no_keys = [0u32; 1];
    let mut no_values = [0u64; 1];
    let mut no_cursor = [0u8; 4];
    let (zero, mut untouched) = request(&mut no_keys, &mut no_values, &mut no_cursor, 0);
    untouched.bytes.fill(0xa5);
    assert_eq!(run(&zero, &mut untouched, BatchOp::Update, map), Ok(0));
    assert!(untouched.bytes.iter().all(|byte| *byte == 0xa5));

    let mut keys = [11u32, 22];
    let mut values = [111u64, 222];
    let mut update_cursor = [0u8; 4];
    let (update, mut update_out) = request(&mut keys, &mut values, &mut update_cursor, 2);
    assert_eq!(run(&update, &mut update_out, BatchOp::Update, map), Ok(0));
    assert_eq!(update_out.u32_at(uapi::off::batch::COUNT), 2);

    let mut found_keys = [0u32; 4];
    let mut found_values = [0u64; 4];
    let mut cursor = [0u8; 4];
    let (lookup, mut lookup_out) = request(&mut found_keys, &mut found_values, &mut cursor, 4);
    assert_eq!(run(&lookup, &mut lookup_out, BatchOp::Lookup, map), Err(Errno::Enoent));
    assert_eq!(lookup_out.u32_at(uapi::off::batch::COUNT), 2);
    let mut pairs = [(found_keys[0], found_values[0]), (found_keys[1], found_values[1])];
    pairs.sort_unstable();
    assert_eq!(pairs, [(11, 111), (22, 222)]);
    assert!(cursor == 11u32.to_ne_bytes() || cursor == 22u32.to_ne_bytes());

    let mut delete_keys = [11u32, 22, 33];
    let mut unused_values = [0u64; 3];
    let mut delete_cursor = [0u8; 4];
    let (delete, mut delete_out) = request(
        &mut delete_keys, &mut unused_values, &mut delete_cursor, 3,
    );
    assert_eq!(run(&delete, &mut delete_out, BatchOp::Delete, map), Err(Errno::Enoent));
    assert_eq!(delete_out.u32_at(uapi::off::batch::COUNT), 2);

    let mut empty_keys = [0u32; 1];
    let mut empty_values = [0u64; 1];
    let mut empty_cursor = [0u8; 4];
    let (empty, mut empty_out) = request(
        &mut empty_keys, &mut empty_values, &mut empty_cursor, 1,
    );
    assert_eq!(run(&empty, &mut empty_out, BatchOp::Lookup, map), Err(Errno::Enoent));
    assert_eq!(empty_out.u32_at(uapi::off::batch::COUNT), 0);
}

#[test]
fn lookup_skips_a_key_deleted_between_iteration_and_value_read() {
    let inode = hash_map(2);
    let map = inode.private::<BpfMapInode>().unwrap();
    map.storage.update(
        map.map_type, 1u32.to_ne_bytes().to_vec(), 10u64.to_ne_bytes().to_vec(), 0,
    ).unwrap();
    map.storage.update(
        map.map_type, 2u32.to_ne_bytes().to_vec(), 20u64.to_ne_bytes().to_vec(), 0,
    ).unwrap();

    let mut keys = [0u32; 2];
    let mut values = [0u64; 2];
    let mut cursor = [0u8; 4];
    let (lookup, mut output) = request(&mut keys, &mut values, &mut cursor, 2);
    let mut done = 0;
    let mut first = true;
    let result = lookup_batch_with(&lookup, map, BatchOp::Lookup, 2, &mut done, |key| {
        if first {
            first = false;
            map.storage.remove(map.map_type, key, false).unwrap();
        }
    });
    write_count(output.bytes.as_mut_ptr() as u64, done).unwrap();

    assert_eq!(result, Err(Errno::Enoent));
    assert_eq!(output.u32_at(uapi::off::batch::COUNT), 1);
    assert_eq!((keys[0], values[0]), (2, 20));
}
