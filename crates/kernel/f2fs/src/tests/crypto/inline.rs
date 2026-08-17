//! Handing file-contents encryption to the block layer.
//!
//! The one claim that matters is that NOTHING about the bytes changes. Two
//! implementations run here — this filesystem's ciphers and the block layer's
//! — and they are separate code over separate mode tables, so agreement
//! between them is real evidence rather than a tautology. If they ever
//! disagreed, a volume written with `inlinecrypt` would be unreadable without
//! it and neither side would report anything.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::crypto::{self as blk, Ctx, Dun, KeyType, Profile};

use crate::crypto::inline::{self, Inline};
use crate::crypto::uapi::*;
use crate::crypto::{FscryptError, Info, MasterKey};
use crate::crypto::policy::{KeyId, Policy};

use super::fixture::*;

/// A device that does no inline encryption of its own — every device in this
/// tree. The software fallback is what serves such a device.
fn no_device() -> Inline<'static> { Inline { enabled: true, profile: None } }

/// A controller that takes hardware-wrapped keys.
struct HwOps;
impl blk::LlOps for HwOps {
    fn keyslot_program(&self, _k: &blk::Key, _s: usize) -> Result<(), block::BlockError> { Ok(()) }
    fn derive_sw_secret(&self, eph: &[u8]) -> Result<[u8; blk::SW_SECRET_SIZE], block::BlockError> {
        // Stands in for an opaque unwrap: a function of the blob, and not the
        // blob, which is all software may assume about it.
        Ok(core::array::from_fn(|i| eph[i % eph.len()] ^ 0x5a))
    }
}

fn hw_profile() -> Profile {
    Profile::new(Arc::new(HwOps) as Arc<dyn blk::LlOps>, 4)
        .with_mode_range(blk::Mode::Aes256Xts, 512, 4096).unwrap()
        .with_max_dun_bytes(16)
        .with_key_types(blk::KeyTypes::RAW | blk::KeyTypes::HW_WRAPPED)
}

/// A v2 policy with one derivation flag set. # C: O(1)
fn p_flags(flags: u8) -> Policy { policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAGS_PAD_4 | flags) }

// ------------------------------------------------------- which mode maps

#[test]
fn only_the_contents_modes_a_controller_performs_have_a_counterpart() {
    assert_eq!(inline::blk_mode(MODE_AES_256_XTS), Some(blk::Mode::Aes256Xts));
    assert_eq!(inline::blk_mode(MODE_AES_128_CBC), Some(blk::Mode::Aes128CbcEssiv));
    assert_eq!(inline::blk_mode(MODE_ADIANTUM), Some(blk::Mode::Adiantum));
    assert_eq!(inline::blk_mode(MODE_SM4_XTS), Some(blk::Mode::Sm4Xts));
    // Names are encrypted whole, as one message, by constructions no device
    // implements over a data unit.
    for n in [MODE_AES_256_CTS, MODE_AES_128_CTS, MODE_SM4_CTS] {
        assert_eq!(inline::blk_mode(n), None, "{n}");
    }
    // The wide-block contents mode likewise has no counterpart.
    assert_eq!(inline::blk_mode(MODE_AES_256_HCTR2), None);
}

#[test]
fn the_widths_of_a_mapped_mode_agree_on_both_sides() {
    for (n, b) in [(MODE_AES_256_XTS, blk::Mode::Aes256Xts),
                   (MODE_AES_128_CBC, blk::Mode::Aes128CbcEssiv),
                   (MODE_ADIANTUM, blk::Mode::Adiantum),
                   (MODE_SM4_XTS, blk::Mode::Sm4Xts)] {
        let fsm = crate::crypto::mode::by_number(n).unwrap();
        let bm = b.params();
        // A disagreement here would derive a key of one width and hand the
        // device a key of another, or address a data unit number the mode
        // cannot carry.
        assert_eq!(fsm.key_size, bm.key_size, "{n} key size");
        assert_eq!(fsm.security_strength, bm.security_strength, "{n} strength");
        assert_eq!(fsm.iv_size, bm.iv_size, "{n} iv size");
    }
}

// -------------------------------------------------------- the four gates

#[test]
fn a_mount_that_did_not_ask_keeps_its_own_crypto() {
    let i = Info::setup(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    assert!(!i.uses_inline_crypto());
}

#[test]
fn a_mount_that_asked_gets_it() {
    let i = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    assert!(i.uses_inline_crypto());
    assert!(i.inline_key().is_some());
}

#[test]
fn a_directory_and_a_symlink_always_do_their_own() {
    for kind in [dir(), folding_dir(), lnk()] {
        let i = Info::setup_inline(&ctx(default_v2()), &kind, &fs(), &master(), &uuid(), 5,
            &no_device()).unwrap();
        assert!(!i.uses_inline_crypto());
    }
}

#[test]
fn every_contents_mode_a_policy_may_name_has_a_counterpart() {
    // The gate exists because inline encryption defines fewer modes than file
    // encryption does — but the modes it lacks are all FILENAME modes, and the
    // pairings a policy may name never put one of those on contents. So on
    // this format the gate never fires, and that is a fact worth pinning: a
    // pairing added later that put a nameless mode on contents would silently
    // fall back to the filesystem's own path rather than being refused.
    for (contents, names, flags) in [(MODE_AES_256_XTS, MODE_AES_256_CTS, 0u8),
                                     (MODE_AES_256_XTS, MODE_AES_256_HCTR2, 0),
                                     (MODE_AES_128_CBC, MODE_AES_128_CTS, 0),
                                     (MODE_SM4_XTS, MODE_SM4_CTS, 0),
                                     (MODE_ADIANTUM, MODE_ADIANTUM, FLAG_DIRECT_KEY)] {
        let p = policy_v2(contents, names, FLAGS_PAD_4 | flags);
        let i = Info::setup_inline(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5,
            &no_device()).unwrap();
        assert!(i.uses_inline_crypto(), "{contents}/{names}");
        assert!(inline::blk_mode(contents).is_some(), "{contents}");
    }
}

#[test]
fn a_device_that_serves_it_natively_is_used_and_still_encrypts() {
    let prof = hw_profile();
    let avail = Inline { enabled: true, profile: Some(&prof) };
    let i = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &avail).unwrap();
    assert!(i.uses_inline_crypto());
    assert_eq!(i.inline_key().unwrap().config().key_type, KeyType::Raw);
}

// ------------------------------------------- the data unit number's width

#[test]
fn each_derivation_rule_asks_for_the_width_it_actually_uses() {
    let fs = fs();
    // Nonce beside the index: the number spans to the end of the nonce field.
    assert_eq!(inline::dun_bytes(&p_flags(FLAG_DIRECT_KEY), &fs, 12), 24);
    // Inode number in the index's high half: the whole word.
    assert_eq!(inline::dun_bytes(&p_flags(FLAG_IV_INO_LBLK_64), &fs, 12), 8);
    // A hashed inode number added and truncated: the narrow form.
    assert_eq!(inline::dun_bytes(&p_flags(FLAG_IV_INO_LBLK_32), &fs, 12), 4);
    // Otherwise only as many bytes as this volume's largest index needs: a
    // 2^42-byte ceiling with 4 KiB units leaves 30 bits, so four bytes.
    assert_eq!(inline::dun_bytes(&default_v2(), &fs, 12), 4);
}

#[test]
fn a_bigger_volume_asks_for_a_wider_number() {
    let big = crate::crypto::policy::FsFacts { max_file_bytes: u64::MAX, blkbits: 12 };
    // 64 bits of offset less 12 of unit leaves 52, which needs seven bytes.
    assert_eq!(inline::dun_bytes(&default_v2(), &big, 12), 7);
}

#[test]
fn a_device_too_narrow_for_the_number_is_not_used() {
    let prof = Profile::new(Arc::new(HwOps) as Arc<dyn blk::LlOps>, 2)
        .with_mode_range(blk::Mode::Aes256Xts, 512, 4096).unwrap()
        .with_max_dun_bytes(2)
        .with_key_types(blk::KeyTypes::HW_WRAPPED);
    // Raw keys are always servable by software, so make the key one only this
    // device could take — and it cannot, because the number is too wide.
    let mk = MasterKey::new_hw_wrapped(&[0x33u8; 40], &[0x44u8; SW_SECRET_SIZE]).unwrap();
    let p = Policy { key: KeyId::Identifier(mk.identifier()),
                     ..p_flags(FLAG_IV_INO_LBLK_64) };
    let avail = Inline { enabled: true, profile: Some(&prof) };
    // Refused rather than downgraded: there is no software form of this key.
    assert_eq!(Info::setup_inline(&ctx(p), &reg(), &fs(), &mk, &uuid(), 5, &avail).err(),
               Some(FscryptError::HwWrappedNoInline));
}

// ------------------------------------- the number is the filesystem's IV

/// The block layer's IV bytes for `index` must be the filesystem's own IV.
/// # C: O(1)
fn assert_same_iv(p: Policy, ino: u32) {
    let i = Info::setup_inline(&ctx(p), &reg(), &fs(), &master(), &uuid(), ino,
        &no_device()).unwrap();
    let mode = crate::crypto::mode::by_number(p.contents_mode).unwrap();
    for index in [0u64, 1, 7, 0xffff, 0x1_0000_0000] {
        let want = crate::crypto::iv::generate(p.flags, &nonce(), ino,
            hashed_ino(&master(), ino), index);
        let got = i.dun(index).to_iv();
        // Only the bytes the mode's IV spans are meaningful; above them both
        // are zero, which the comparison of the whole array also checks.
        assert_eq!(&got[..mode.iv_size], &want[..mode.iv_size], "{:?} index {index}", p.flags);
        assert_eq!(&got[mode.iv_size..], &[0u8; MAX_IV_SIZE][mode.iv_size..]);
    }
}

/// The inode-number hash the narrow rule adds, recomputed here rather than
/// read out of the inode's own state. # C: O(1)
fn hashed_ino(mk: &MasterKey, ino: u32) -> u32 {
    let k = mk.siphash_key(HKDF_INODE_HASH_KEY, &[]).unwrap();
    siphash::siphash_1u64(u64::from(ino), &k) as u32
}

#[test]
fn the_data_unit_number_is_the_filesystems_own_iv() {
    assert_same_iv(default_v2(), 5);
    assert_same_iv(p_flags(FLAG_IV_INO_LBLK_64), 5);
    assert_same_iv(p_flags(FLAG_IV_INO_LBLK_32), 5);
}

#[test]
fn the_wide_tweak_rule_carries_the_nonce_in_the_number_too() {
    // Adiantum's tweak is 32 bytes, so all four limbs are in play and the
    // file's nonce rides in them beside the index.
    let p = policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, FLAGS_PAD_4 | FLAG_DIRECT_KEY);
    assert_same_iv(p, 5);
    let i = Info::setup_inline(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    assert_ne!(i.dun(0).limbs()[1], 0, "the nonce did not reach the number");
}

// --------------------------------------------- the two paths write the same

/// Encrypt one block of contents both ways and require the same bytes.
/// # C: O(BLKSIZE)
fn assert_paths_agree(p: Policy, ino: u32, index: u64) {
    let plain: Vec<u8> = (0..crate::uapi::BLKSIZE).map(|i| (i % 251) as u8).collect();

    // This filesystem's own path.
    let sw = Info::setup(&ctx(p), &reg(), &fs(), &master(), &uuid(), ino).unwrap();
    assert!(!sw.uses_inline_crypto());
    let per = (crate::uapi::BLKSIZE / sw.data_unit_size()) as u64;
    let mut by_fs = plain.clone();
    sw.crypt_contents(index * per, &mut by_fs, true).unwrap();

    // The block layer's, from the context the same policy produces.
    let il = Info::setup_inline(&ctx(p), &reg(), &fs(), &master(), &uuid(), ino,
        &no_device()).unwrap();
    assert!(il.uses_inline_crypto());
    let ctx_ = il.crypt_ctx(index * per).unwrap();
    blk::start_using_key(&NoCrypto as &dyn block::BlockDevice, ctx_.key()).unwrap();
    let mut by_blk = plain.clone();
    blk::fallback::encrypt(&ctx_, &mut by_blk).unwrap();

    assert_ne!(by_fs, plain, "nothing encrypted the block");
    assert_eq!(by_fs, by_blk, "the two implementations disagree for {:?}", p.flags);
}

/// A device with no inline encryption, so `start_using_key` prepares the
/// software fallback — the only thing a device in this tree can offer.
struct NoCrypto;
impl block::BlockDevice for NoCrypto {
    fn block_size(&self) -> u32 { 4096 }
    fn capacity_blocks(&self) -> u64 { 0 }
    fn submit_sync(&self, _r: &mut block::BlockRequest) -> Result<(), block::BlockError> { Ok(()) }
    fn flush(&self) -> Result<(), block::BlockError> { Ok(()) }
}

#[test]
fn both_paths_produce_the_same_ciphertext_under_every_rule() {
    for p in [default_v2(), p_flags(FLAG_IV_INO_LBLK_64), p_flags(FLAG_IV_INO_LBLK_32)] {
        for index in [0u64, 3, 1000] { assert_paths_agree(p, 5, index); }
    }
}

#[test]
fn both_paths_agree_for_every_mapped_mode() {
    let cases = [(MODE_AES_256_XTS, MODE_AES_256_CTS, 0u8),
                 (MODE_AES_128_CBC, MODE_AES_128_CTS, 0),
                 (MODE_SM4_XTS, MODE_SM4_CTS, 0),
                 (MODE_ADIANTUM, MODE_ADIANTUM, FLAG_DIRECT_KEY)];
    for (c, n, f) in cases {
        assert_paths_agree(policy_v2(c, n, FLAGS_PAD_4 | f), 5, 2);
    }
}

#[test]
fn both_paths_agree_with_a_sub_block_data_unit() {
    // A unit smaller than a block: several units per block, and the index the
    // block starts at is not the block number.
    let p = Policy { log2_data_unit_size: 9, ..default_v2() };
    assert_paths_agree(p, 5, 4);
}

// ------------------------------------------- an inline inode does not double

#[test]
fn an_inline_inode_refuses_to_encrypt_here_as_well() {
    let i = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    let mut buf = vec![0u8; 4096];
    // A caller that ran both would produce bytes nothing can recover, and no
    // layer would report it — so the second one refuses.
    assert_eq!(i.encrypt_data_unit(0, &mut buf).err(), Some(FscryptError::InlineOnly));
    assert_eq!(i.decrypt_data_unit(0, &mut buf).err(), Some(FscryptError::InlineOnly));
    assert_eq!(i.crypt_contents(0, &mut buf, true).err(), Some(FscryptError::InlineOnly));
}

// -------------------------------------------------------------- merging

#[test]
fn contiguous_units_of_one_file_share_a_request() {
    let i = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    let first = i.crypt_ctx(0).unwrap();
    assert!(i.mergeable(Some(&first), 4096, 1));
    // One unit short and one unit long are both refused: the second run would
    // be encrypted as the continuation of the first.
    assert!(!i.mergeable(Some(&first), 4096, 2));
    assert!(!i.mergeable(Some(&first), 4096, 0));
}

#[test]
fn two_files_never_share_a_request() {
    let a = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    let b = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 6,
        &no_device()).unwrap();
    // Different keys, so a device asked to serve both would have to encrypt
    // one request under two keys.
    assert!(!b.mergeable(a.crypt_ctx(0).as_ref(), 4096, 1));
}

#[test]
fn encrypted_and_unencrypted_data_never_share_a_request() {
    let enc = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    let plain = Info::setup(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5).unwrap();
    // Unencrypted data joining an encrypted request would be encrypted by a
    // device nobody told to leave it alone.
    assert!(!plain.mergeable(enc.crypt_ctx(0).as_ref(), 4096, 1));
    assert!(!enc.mergeable(None, 4096, 1));
    // Two unencrypted runs merge freely; there is nothing to keep apart.
    assert!(plain.mergeable(None, 4096, 1));
}

#[test]
fn a_run_that_would_wrap_the_number_is_cut_short() {
    let p = p_flags(FLAG_IV_INO_LBLK_32);
    let i = Info::setup_inline(&ctx(p), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    let h = hashed_ino(&master(), 5);
    // The block at which the number is one short of wrapping.
    let lblk = u64::from(u32::MAX.wrapping_sub(h));
    assert_eq!(i.limit_io_blocks(lblk, 8), 1);
    assert_eq!(i.limit_io_blocks(lblk.wrapping_sub(3), 8), 4);
    // Every other rule counts monotonically and never wraps.
    let plain = Info::setup_inline(&ctx(default_v2()), &reg(), &fs(), &master(), &uuid(), 5,
        &no_device()).unwrap();
    assert_eq!(plain.limit_io_blocks(lblk, 8), 8);
}

// ------------------------------------------------- hardware-wrapped keys

/// A wrapped key and the identity a policy names it by. # C: O(1)
fn wrapped() -> MasterKey {
    MasterKey::new_hw_wrapped(&[0x33u8; 40], &[0x44u8; SW_SECRET_SIZE]).unwrap()
}

#[test]
fn a_wrapped_key_and_a_raw_key_can_never_share_a_name() {
    // Someone who learned the secret the controller derived could add it as an
    // ordinary key. Without separate derivation contexts the two would hash to
    // one name, and a policy naming the wrapped key would accept the raw one.
    let hw = wrapped();
    let raw = MasterKey::new(&[0x44u8; SW_SECRET_SIZE]).unwrap();
    assert_ne!(hw.identifier(), raw.identifier());
    assert!(hw.is_hw_wrapped());
    assert!(!raw.is_hw_wrapped());
}

#[test]
fn a_wrapped_key_is_refused_by_the_older_policy_version() {
    let mk = wrapped();
    let p = policy_v1(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAGS_PAD_4);
    let prof = hw_profile();
    let avail = Inline { enabled: true, profile: Some(&prof) };
    assert_eq!(Info::setup_inline(&ctx(p), &reg(), &fs(), &mk, &uuid(), 5, &avail).err(),
               Some(FscryptError::HwWrappedPolicy));
}

#[test]
fn a_wrapped_key_is_refused_by_a_per_file_derivation_rule() {
    let mk = wrapped();
    let prof = hw_profile();
    let avail = Inline { enabled: true, profile: Some(&prof) };
    // Nothing in software can derive a per-file key from a blob it cannot
    // unwrap, so only the rules whose key is per volume are admissible.
    // The default rule derives per file; the direct-key rule derives per mode,
    // which is still a derivation the wrapped key cannot make.
    let per_file = Policy { key: KeyId::Identifier(mk.identifier()), ..default_v2() };
    let per_mode = Policy {
        key: KeyId::Identifier(mk.identifier()),
        ..policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, FLAGS_PAD_4 | FLAG_DIRECT_KEY)
    };
    for p in [per_file, per_mode] {
        assert_eq!(Info::setup_inline(&ctx(p), &reg(), &fs(), &mk, &uuid(), 5, &avail).err(),
                   Some(FscryptError::HwWrappedPolicy), "flags {}", p.flags);
    }
}

#[test]
fn a_wrapped_key_is_refused_when_the_mount_did_not_ask() {
    let mk = wrapped();
    let p = Policy { key: KeyId::Identifier(mk.identifier()), ..p_flags(FLAG_IV_INO_LBLK_64) };
    assert_eq!(Info::setup(&ctx(p), &reg(), &fs(), &mk, &uuid(), 5).err(),
               Some(FscryptError::HwWrappedNoInline));
}

#[test]
fn a_wrapped_key_is_refused_when_no_device_takes_one() {
    let mk = wrapped();
    let p = Policy { key: KeyId::Identifier(mk.identifier()), ..p_flags(FLAG_IV_INO_LBLK_64) };
    // The mount asked and the fallback exists — but the fallback serves raw
    // keys only, and there is no software form of this one.
    assert_eq!(Info::setup_inline(&ctx(p), &reg(), &fs(), &mk, &uuid(), 5, &no_device()).err(),
               Some(FscryptError::HwWrappedNoInline));
}

#[test]
fn a_wrapped_key_reaches_the_block_layer_as_the_blob_itself() {
    let mk = wrapped();
    let p = Policy { key: KeyId::Identifier(mk.identifier()), ..p_flags(FLAG_IV_INO_LBLK_64) };
    let prof = hw_profile();
    let avail = Inline { enabled: true, profile: Some(&prof) };
    let i = Info::setup_inline(&ctx(p), &reg(), &fs(), &mk, &uuid(), 5, &avail).unwrap();
    assert!(i.uses_inline_crypto());
    let k = i.inline_key().unwrap();
    assert_eq!(k.config().key_type, KeyType::HwWrapped);
    // Not derived from and not derived through: the controller is the only
    // thing that can unwrap it, so anything else would hand it the wrong key.
    assert_eq!(k.bytes(), &[0x33u8; 40]);
}

#[test]
fn a_directory_under_a_wrapped_key_still_derives_from_the_secret() {
    let mk = wrapped();
    let p = Policy { key: KeyId::Identifier(mk.identifier()), ..p_flags(FLAG_IV_INO_LBLK_64) };
    let prof = hw_profile();
    let avail = Inline { enabled: true, profile: Some(&prof) };
    // A directory's names are not file contents, so they are encrypted in
    // software under a key derived from the secret — which is exactly what
    // the secret is isolated from the contents key in order to allow.
    let d = Info::setup_inline(&ctx(p), &dir(), &fs(), &mk, &uuid(), 7, &avail).unwrap();
    assert!(!d.uses_inline_crypto());
    let name = d.encrypt_name(b"hello").unwrap();
    assert_eq!(d.decrypt_name(&name).unwrap(), b"hello");
}

#[test]
fn the_secret_is_derived_through_the_device_that_holds_the_key() {
    let prof = hw_profile();
    let secret = prof.derive_sw_secret(&[0x33u8; 40]).unwrap();
    let mk = MasterKey::new_hw_wrapped(&[0x33u8; 40], &secret).unwrap();
    // Two mounts of the same volume on the same hardware name the key the
    // same way, which is what makes a stored policy resolvable at all.
    let again = MasterKey::new_hw_wrapped(&[0x33u8; 40],
        &prof.derive_sw_secret(&[0x33u8; 40]).unwrap()).unwrap();
    assert_eq!(mk.identifier(), again.identifier());
}
