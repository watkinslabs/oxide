//! The descriptor, the tree it describes, and what may be done to the file.

use alloc::vec;

use crate::flags::F2FS_VERITY_FL;
use crate::verity::descriptor;
use crate::verity::uapi::*;
use crate::verity::{access, location, VerityError};

use super::image;

const MAX_FILE: u64 = 1 << 40;
const LOG_4K: u8 = 12;

fn good(size: u64) -> alloc::vec::Vec<u8> {
    image::descriptor(HASH_ALG_SHA256, LOG_4K, 8, size)
}

#[test]
fn a_descriptor_is_read_field_by_field() {
    let d = descriptor::parse(&good(100_000)).expect("well formed");
    assert_eq!(d.version, DESCRIPTOR_VERSION);
    assert_eq!(d.hash_algorithm, HASH_ALG_SHA256);
    assert_eq!(d.log_blocksize, LOG_4K);
    assert_eq!(d.block_size(), 4096);
    assert_eq!(d.salt_size, 8);
    assert_eq!(d.salt_used().len(), 8);
    assert!(d.salt_used().iter().all(|&b| b == 0x5a));
    assert_eq!(d.data_size, 100_000);
    assert_eq!(d.sig_size, 0);
    assert_eq!(d.digest_size().unwrap(), SHA256_DIGEST_SIZE);
    assert_eq!(d.root_used().unwrap().len(), SHA256_DIGEST_SIZE);
    assert_eq!(d.root_used().unwrap()[0], 0xa0);
}

#[test]
fn the_fixed_part_is_the_width_the_format_says() {
    assert_eq!(DESCRIPTOR_SIZE, 256);
    assert_eq!(MAX_ROOT_HASH, 64);
    assert_eq!(MAX_SALT, 32);
    assert_eq!(RESERVED_LEN, 144);
    assert_eq!(D_ROOT_HASH + MAX_ROOT_HASH, D_SALT);
    assert_eq!(D_SALT + MAX_SALT, D_RESERVED);
    assert_eq!(D_RESERVED + RESERVED_LEN, DESCRIPTOR_SIZE);
    // The offsets are written as sums of the widths before them; these are
    // the format's own numbers, so a wrong width cannot shift them unseen.
    assert_eq!((D_VERSION, D_HASH_ALGORITHM, D_LOG_BLOCKSIZE, D_SALT_SIZE), (0, 1, 2, 3));
    assert_eq!((D_SIG_SIZE, D_DATA_SIZE, D_ROOT_HASH), (4, 8, 16));
    assert_eq!((D_SALT, D_RESERVED), (80, 112));
    assert_eq!((LOC_VERSION, LOC_SIZE, LOC_POS, LOCATION_SIZE), (0, 4, 8, 16));
    assert_eq!(METADATA_ALIGN, 64 * 1024);
}

#[test]
fn the_wider_hash_is_read_as_wide_as_it_is() {
    let d = descriptor::parse(&image::descriptor(HASH_ALG_SHA512, LOG_4K, 0, 4096)).unwrap();
    assert_eq!(d.digest_size().unwrap(), SHA512_DIGEST_SIZE);
    assert_eq!(d.root_used().unwrap().len(), SHA512_DIGEST_SIZE);
    assert_eq!(d.salt_used().len(), 0);
}

#[test]
fn a_descriptor_stopping_before_its_fixed_part_ends_is_refused() {
    let d = good(100_000);
    assert_eq!(descriptor::parse(&d[..DESCRIPTOR_SIZE - 1]), Err(VerityError::TruncatedDescriptor));
    assert_eq!(descriptor::parse(&[]), Err(VerityError::TruncatedDescriptor));
    assert_eq!(descriptor::parse(&d[..1]), Err(VerityError::TruncatedDescriptor));
    // Exactly the fixed part is enough.
    assert!(descriptor::parse(&d).is_ok());
}

#[test]
fn a_descriptor_of_another_version_is_refused() {
    let mut d = good(100_000);
    d[D_VERSION] = DESCRIPTOR_VERSION + 1;
    assert_eq!(descriptor::parse(&d), Err(VerityError::UnknownFormat));
}

#[test]
fn a_reserved_byte_that_is_set_is_refused() {
    // A set reserved byte means a field this build would silently ignore.
    let mut d = good(100_000);
    d[D_RESERVED] = 1;
    assert_eq!(descriptor::parse(&d), Err(VerityError::ReservedSet));
    let mut e = good(100_000);
    e[DESCRIPTOR_SIZE - 1] = 1;
    assert_eq!(descriptor::parse(&e), Err(VerityError::ReservedSet));
}

#[test]
fn a_salt_longer_than_its_field_is_refused() {
    let mut d = good(100_000);
    d[D_SALT_SIZE] = MAX_SALT as u8 + 1;
    assert_eq!(descriptor::parse(&d), Err(VerityError::BadSalt));
    d[D_SALT_SIZE] = MAX_SALT as u8;
    assert_eq!(descriptor::parse(&d).unwrap().salt_used().len(), MAX_SALT);
}

#[test]
fn a_signature_longer_than_the_record_holding_it_is_refused() {
    let signed = image::with_signature(good(100_000), &[7u8; 64]);
    let d = descriptor::parse(&signed).unwrap();
    assert_eq!(d.sig_size, 64);
    assert_eq!(descriptor::signature(&signed, &d).unwrap(), vec![7u8; 64]);
    // The same declaration with nothing appended overflows the record.
    let mut lying = good(100_000);
    lying[D_SIG_SIZE..D_SIG_SIZE + 4].copy_from_slice(&64u32.to_le_bytes());
    assert_eq!(descriptor::parse(&lying), Err(VerityError::SignatureOverflow));
}

#[test]
fn a_descriptor_wider_than_will_be_read_is_refused() {
    let huge = image::with_signature(good(100_000), &vec![0u8; MAX_DESCRIPTOR_SIZE]);
    assert_eq!(descriptor::parse(&huge), Err(VerityError::DescriptorTooLarge));
}

#[test]
fn a_descriptor_built_over_another_length_of_file_is_refused() {
    // The declared length is what ties a descriptor to a file.
    let d = descriptor::parse(&good(100_000)).unwrap();
    assert_eq!(descriptor::check(&d, 100_000), Ok(()));
    assert_eq!(descriptor::check(&d, 100_001), Err(VerityError::SizeMismatch));
    assert_eq!(descriptor::check(&d, 0), Err(VerityError::SizeMismatch));
}

#[test]
fn a_hash_or_block_size_the_tree_cannot_be_built_with_is_refused() {
    let mut bad = good(4096);
    bad[D_HASH_ALGORITHM] = 0;
    assert_eq!(descriptor::parse(&bad).unwrap().digest_size(), Err(VerityError::UnsupportedHash));
    assert_eq!(descriptor::check(&descriptor::parse(&bad).unwrap(), 4096), Err(VerityError::UnsupportedHash));
    // Below the narrowest block the format admits.
    let small = descriptor::parse(&image::descriptor(HASH_ALG_SHA256, MIN_LOG_BLOCKSIZE - 1, 0, 4096)).unwrap();
    assert_eq!(descriptor::check(&small, 4096), Err(VerityError::BadBlockSize));
    // A block must hold at least two digests, or the tree never narrows.
    let narrow = descriptor::parse(&image::descriptor(HASH_ALG_SHA512, MIN_LOG_BLOCKSIZE, 0, 4096)).unwrap();
    assert_eq!(narrow.block_size(), 1024);
    assert_eq!(descriptor::check(&narrow, 4096), Ok(()));
}

#[test]
fn a_tree_over_one_block_of_data_has_no_levels_at_all() {
    let d = descriptor::parse(&good(4096)).unwrap();
    assert_eq!(descriptor::tree_levels(&d, 4096).unwrap(), 0);
    assert_eq!(descriptor::tree_size(&d, 4096).unwrap(), 0);
    assert_eq!(descriptor::tree_size(&d, 1).unwrap(), 0);
    assert_eq!(descriptor::tree_size(&d, 0).unwrap(), 0);
}

#[test]
fn the_tree_is_one_block_per_hundred_and_twenty_eight_below_it() {
    // Four-kibibyte blocks of thirty-two-byte digests hold a hundred and
    // twenty-eight hashes each.
    let d = descriptor::parse(&good(0)).unwrap();
    // Two data blocks: one level of one block.
    assert_eq!(descriptor::tree_levels(&d, 2 * 4096).unwrap(), 1);
    assert_eq!(descriptor::tree_size(&d, 2 * 4096).unwrap(), 4096);
    // A hundred and twenty-eight data blocks still fit one level.
    assert_eq!(descriptor::tree_size(&d, 128 * 4096).unwrap(), 4096);
    // One more needs a second level above the two it now takes.
    assert_eq!(descriptor::tree_levels(&d, 129 * 4096).unwrap(), 2);
    assert_eq!(descriptor::tree_size(&d, 129 * 4096).unwrap(), 3 * 4096);
}

#[test]
fn a_tree_deeper_than_will_be_described_is_refused() {
    let d = descriptor::parse(&image::descriptor(HASH_ALG_SHA512, MIN_LOG_BLOCKSIZE, 0, 0)).unwrap();
    // Sixteen hashes per block: the tree grows a level every four bits of
    // block index, so a large enough file exceeds the bound.
    assert_eq!(descriptor::tree_size(&d, u64::MAX), Err(VerityError::TooManyLevels));
    assert_eq!(descriptor::tree_levels(&d, u64::MAX), Err(VerityError::TooManyLevels));
}

#[test]
fn the_two_records_resolve_together_against_the_inode() {
    let size = 200_000;
    let d = descriptor::parse(&good(size)).unwrap();
    let tree = descriptor::tree_size(&d, size).unwrap();
    let at = location::metadata_pos(size);
    let attr = image::location(LOCATION_VERSION, DESCRIPTOR_SIZE as u32, at + tree);
    let v = crate::verity::resolve(&attr, &good(size), size, MAX_FILE).expect("resolves");
    assert_eq!(v.tree_at, at);
    assert_eq!(v.tree_bytes, tree);
    assert_eq!(v.location.pos, at + tree);
    assert_eq!(v.descriptor.data_size, size);
    // The metadata begins past every byte a read may return.
    assert_eq!(location::readable(size, 0, u32::MAX as u64), size);
    assert!(v.tree_at >= size);
}

#[test]
fn a_descriptor_overlapping_its_own_tree_still_resolves() {
    // The pointer is bounded below by where the METADATA starts, not by where
    // the tree ends. A descriptor overlapping the tree is a pointless place to
    // put one and it is not a hole: the descriptor comes off unauthenticated
    // blocks either way, and the bytes it overlaps are hash blocks that then
    // fail to match their parents. Refusing it here would reject a file whose
    // measurement is still computable and whose reads the reference answers.
    let size = 200_000;
    let d = descriptor::parse(&good(size)).unwrap();
    let tree = descriptor::tree_size(&d, size).unwrap();
    assert!(tree > 0);
    let at = location::metadata_pos(size);
    let attr = image::location(LOCATION_VERSION, DESCRIPTOR_SIZE as u32, at + tree - 1);
    let v = crate::verity::resolve(&attr, &good(size), size, MAX_FILE).expect("resolves");
    assert_eq!(v.location.pos, at + tree - 1);
    // The lower bound that IS enforced: one byte below the metadata start.
    let below = image::location(LOCATION_VERSION, DESCRIPTOR_SIZE as u32, at - 1);
    assert_eq!(
        crate::verity::resolve(&below, &good(size), size, MAX_FILE),
        Err(VerityError::Corrupted)
    );
}

#[test]
fn a_descriptor_with_no_signature_resolves_to_an_empty_one() {
    let size = 200_000;
    let d = descriptor::parse(&good(size)).unwrap();
    let at = location::metadata_pos(size) + descriptor::tree_size(&d, size).unwrap();
    let attr = image::location(LOCATION_VERSION, DESCRIPTOR_SIZE as u32, at);
    let v = crate::verity::resolve(&attr, &good(size), size, MAX_FILE).unwrap();
    assert!(v.signature.is_empty());
}

#[test]
fn a_descriptor_carrying_a_signature_resolves_to_those_bytes() {
    let size = 200_000;
    let sig: alloc::vec::Vec<u8> = (0..64u16).map(|i| (i % 251) as u8).collect();
    let bytes = image::with_signature(good(size), &sig);
    let d = descriptor::parse(&bytes).unwrap();
    assert_eq!(d.sig_size, sig.len() as u32);
    let at = location::metadata_pos(size) + descriptor::tree_size(&d, size).unwrap();
    let attr = image::location(LOCATION_VERSION, bytes.len() as u32, at);
    let v = crate::verity::resolve(&attr, &bytes, size, MAX_FILE).unwrap();
    assert_eq!(v.signature, sig);
}

#[test]
fn resolving_stops_when_fewer_bytes_are_there_than_the_pointer_promised() {
    let size = 200_000;
    let d = descriptor::parse(&good(size)).unwrap();
    let tree = descriptor::tree_size(&d, size).unwrap();
    let at = location::metadata_pos(size) + tree;
    let attr = image::location(LOCATION_VERSION, DESCRIPTOR_SIZE as u32 + 64, at);
    // The pointer says there is a signature; the bytes read stop short.
    assert_eq!(
        crate::verity::resolve(&attr, &good(size), size, MAX_FILE),
        Err(VerityError::TruncatedDescriptor)
    );
}

#[test]
fn a_verity_inode_refuses_a_writable_handle() {
    assert!(access::is_verity(F2FS_VERITY_FL));
    assert!(!access::is_verity(0));
    assert_eq!(access::open_write(F2FS_VERITY_FL), Err(VerityError::ReadOnlyFile));
    assert_eq!(access::open_write(0), Ok(()));
    // The refusal is a permission failure, not a read-only medium.
    assert_eq!(VerityError::ReadOnlyFile.errno(), syscall::errno::Errno::Eperm);
}

#[test]
fn a_verity_inode_refuses_to_be_shortened() {
    // Shortening reaches the bytes without a handle, so it is refused too.
    assert_eq!(access::truncate(F2FS_VERITY_FL), Err(VerityError::ReadOnlyFile));
    assert_eq!(access::truncate(0), Ok(()));
}

#[test]
fn verity_may_not_be_turned_on_twice() {
    assert_eq!(access::enable(F2FS_VERITY_FL), Err(VerityError::AlreadyEnabled));
    assert_eq!(access::enable(0), Ok(()));
    assert_eq!(VerityError::AlreadyEnabled.errno(), syscall::errno::Errno::Eexist);
}

#[test]
fn the_flag_read_is_the_one_the_format_defines() {
    // A neighbouring attribute bit must not read as verity.
    assert!(!access::is_verity(crate::flags::F2FS_IMMUTABLE_FL));
    assert!(!access::is_verity(crate::flags::F2FS_ENCRYPT_FL));
    assert!(access::is_verity(F2FS_VERITY_FL | crate::flags::F2FS_IMMUTABLE_FL));
}

#[test]
fn the_attribute_the_pointer_lives_under_is_the_one_the_format_names() {
    assert_eq!(XATTR_NAME, b"v");
    assert_eq!(crate::uapi::XATTR_INDEX_VERITY, 11);
}

#[test]
fn corruption_and_confusion_are_reported_apart() {
    assert_eq!(VerityError::Corrupted.errno(), syscall::errno::Errno::Euclean);
    assert_eq!(VerityError::DescriptorTooLarge.errno(), syscall::errno::Errno::Emsgsize);
    assert_eq!(VerityError::NoDescriptor.errno(), syscall::errno::Errno::Enodata);
    assert_eq!(VerityError::UnknownFormat.errno(), syscall::errno::Errno::Einval);
    assert_eq!(VerityError::SizeMismatch.errno(), syscall::errno::Errno::Einval);
}
