// What actually lands on the medium.
//
// Every other test here can pass while the device receives plaintext, because
// a context attached, a keyslot programmed and a mode declared are all things
// that happen BESIDE the write rather than to it. These read the device back
// with no context at all — the way another machine, or a forensic image,
// would — and assert on the bytes that are really there.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use std::sync::Mutex;

use sync::Inode as InodeClass;

use crate::blockdev::{BlockDevice, BlockRequest, MemDisk};
use crate::crypto::cipher::Cipher;
use crate::crypto::ctx::Ctx;
use crate::crypto::dun::Dun;
use crate::crypto::key::{Key, KeyType, KeyTypes};
use crate::crypto::mode::Mode;
use crate::crypto::profile::{LlOps, Profile};
use crate::crypto::{fallback, submit};
use crate::types::{BlockError, BlockOp, KResult};

use super::raw_key;

type Disk = MemDisk<InodeClass>;

const BS: u32 = 512;
const DUS: u32 = 512;

/// The fallback's declared-mode set and prepared slots are process-global, so
/// a test that clears them must not run beside one that relies on them.
static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A recognisable payload that is the SAME in every data unit, so a data unit
/// number that fails to advance shows up as repeated ciphertext. # C: O(len)
fn payload(units: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(units * DUS as usize);
    for _ in 0..units { v.extend((0..DUS).map(|i| (i % 251) as u8)); }
    v
}

/// The bytes on the disk at `block`, read with no context — what is really
/// there. # C: O(len)
fn on_medium(disk: &Arc<Disk>, block: u64, blocks: u32) -> Vec<u8> {
    let mut req = BlockRequest::new_read(block, blocks, BS);
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

/// Write `data` at `block` under `ctx`, through the one submission path a
/// request with a context may take. # C: O(len)
fn write_encrypted(disk: &Arc<Disk>, block: u64, data: &[u8], ctx: &Ctx)
    -> KResult<BlockRequest> {
    let blocks = (data.len() / BS as usize) as u32;
    let mut req = BlockRequest::new_write(block, blocks, data.to_vec())
        .with_crypt(ctx.clone());
    submit::submit_sync(&**disk as &dyn BlockDevice, &mut req)?;
    Ok(req)
}

fn setup(mode: Mode) -> (Arc<Disk>, Arc<Key>) {
    fallback::reset_for_test();
    let disk = Disk::new(BS, 64);
    let key = raw_key(mode, 3, DUS);
    submit::start_using_key(&*disk as &dyn BlockDevice, &key).unwrap();
    (disk, key)
}

#[test]
fn fallback_write_puts_ciphertext_on_the_medium() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    let plain = payload(4);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key, Dun::from_u64(0))).unwrap();

    // Read the device the way anything without the key would.
    let raw = on_medium(&disk, 0, 4);
    assert_ne!(raw, plain, "the medium holds the plaintext — nothing encrypted it");
    // Not merely different: no data unit of the plaintext appears anywhere.
    let unit = &plain[..DUS as usize];
    assert!(!raw.windows(unit.len()).any(|w| w == unit));
}

#[test]
fn every_data_unit_is_encrypted_under_its_own_number() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    // Four identical plaintext units. If the data unit number did not advance
    // they would encrypt identically, which is both a correctness bug and a
    // disclosure: an observer would learn which blocks of a file are equal.
    let plain = payload(4);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key, Dun::from_u64(0))).unwrap();
    let raw = on_medium(&disk, 0, 4);
    let u = DUS as usize;
    for i in 0..4 {
        for j in i + 1..4 {
            assert_ne!(raw[i * u..(i + 1) * u], raw[j * u..(j + 1) * u], "units {i} and {j}");
        }
    }
}

#[test]
fn the_starting_data_unit_number_changes_the_ciphertext() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    let plain = payload(1);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key.clone(), Dun::from_u64(0))).unwrap();
    let at_zero = on_medium(&disk, 0, 1);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key, Dun::from_u64(9))).unwrap();
    assert_ne!(on_medium(&disk, 0, 1), at_zero);
}

#[test]
fn the_ciphertext_is_the_modes_own_construction() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    let plain = payload(3);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key.clone(), Dun::from_u64(7))).unwrap();

    // Independently: the mode's construction over each unit, at its own number.
    let cipher = Cipher::prepare(Mode::Aes256Xts, key.bytes()).unwrap();
    let mut want = plain.clone();
    let mut dun = Dun::from_u64(7);
    for unit in want.chunks_exact_mut(DUS as usize) {
        cipher.encrypt(&dun.to_iv(), unit).unwrap();
        dun.increment(1);
    }
    assert_eq!(on_medium(&disk, 0, 3), want);
}

#[test]
fn a_read_under_the_context_recovers_the_plaintext() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    let plain = payload(4);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key.clone(), Dun::from_u64(11))).unwrap();

    let mut req = BlockRequest::new_read(0, 4, BS).with_crypt(Ctx::new(key, Dun::from_u64(11)));
    submit::submit_sync(&*disk as &dyn BlockDevice, &mut req).unwrap();
    assert_eq!(req.buffer, plain);
}

#[test]
fn a_read_at_the_wrong_number_does_not_recover_it() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    let plain = payload(2);
    write_encrypted(&disk, 0, &plain, &Ctx::new(key.clone(), Dun::from_u64(11))).unwrap();
    let mut req = BlockRequest::new_read(0, 2, BS).with_crypt(Ctx::new(key, Dun::from_u64(12)));
    submit::submit_sync(&*disk as &dyn BlockDevice, &mut req).unwrap();
    assert_ne!(req.buffer, plain);
}

#[test]
fn every_mode_round_trips_through_the_medium() {
    let _g = guard();
    for m in Mode::ALL {
        let (disk, key) = setup(m);
        let plain = payload(2);
        write_encrypted(&disk, 0, &plain, &Ctx::new(key.clone(), Dun::from_u64(5))).unwrap();
        assert_ne!(on_medium(&disk, 0, 2), plain, "{m:?} left plaintext on the medium");
        let mut req = BlockRequest::new_read(0, 2, BS).with_crypt(Ctx::new(key, Dun::from_u64(5)));
        submit::submit_sync(&*disk as &dyn BlockDevice, &mut req).unwrap();
        assert_eq!(req.buffer, plain, "{m:?}");
    }
}

#[test]
fn the_submitters_buffer_comes_back_holding_plaintext() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    let plain = payload(2);
    let req = write_encrypted(&disk, 0, &plain, &Ctx::new(key, Dun::from_u64(0))).unwrap();
    // A buffer returned enciphered would be encrypted a second time on a
    // retry, and the retry would land bytes nothing can read.
    assert_eq!(req.buffer, plain);
}

#[test]
fn a_request_with_no_context_is_untouched() {
    let _g = guard();
    let (disk, _key) = setup(Mode::Aes256Xts);
    let plain = payload(1);
    let mut req = BlockRequest::new_write(0, 1, plain.clone());
    submit::submit_sync(&*disk as &dyn BlockDevice, &mut req).unwrap();
    assert_eq!(on_medium(&disk, 0, 1), plain);
}

#[test]
fn an_undeclared_mode_is_refused_rather_than_written() {
    let _g = guard();
    fallback::reset_for_test();
    let disk = Disk::new(BS, 64);
    let key = raw_key(Mode::Aes256Xts, 3, DUS);
    // No `start_using_key`. Discovering a missing construction in the middle
    // of a write leaves only wrong bytes or a lost write, so it is refused.
    let plain = payload(1);
    let err = write_encrypted(&disk, 0, &plain, &Ctx::new(key, Dun::from_u64(0))).err();
    assert_eq!(err, Some(BlockError::Eio));
    assert_eq!(on_medium(&disk, 0, 1), vec![0u8; BS as usize], "a refused write still landed");
}

#[test]
fn a_wrapped_key_has_no_software_fallback() {
    let _g = guard();
    fallback::reset_for_test();
    let disk = Disk::new(BS, 64);
    let m = Mode::Aes256Xts;
    let wrapped = Arc::new(
        Key::new(&[0x11u8; 48], KeyType::HwWrapped, m, 8, DUS).unwrap());
    // Nothing in software can encrypt with a blob it cannot unwrap, and this
    // device does not advertise wrapped keys.
    assert_eq!(submit::start_using_key(&*disk as &dyn BlockDevice, &wrapped).err(),
               Some(BlockError::Eopnotsupp));
    assert!(!submit::config_supported(&*disk as &dyn BlockDevice, wrapped.config()));
    // And if a caller ignored that, the submission still refuses.
    let plain = payload(1);
    let err = write_encrypted(&disk, 0, &plain, &Ctx::new(wrapped, Dun::from_u64(0))).err();
    assert!(matches!(err, Some(BlockError::Eio) | Some(BlockError::Eopnotsupp)));
    assert_eq!(on_medium(&disk, 0, 1), vec![0u8; BS as usize]);
}

#[test]
fn a_context_on_an_operation_with_no_payload_is_refused() {
    let _g = guard();
    let (disk, key) = setup(Mode::Aes256Xts);
    for op in [BlockOp::Flush, BlockOp::Discard, BlockOp::WriteZeroes { no_unmap: false }] {
        let mut req = BlockRequest { op, start_block: 0, len_blocks: 1,
            crypt: Some(Ctx::new(key.clone(), Dun::from_u64(0))), ..Default::default() };
        assert_eq!(submit::submit_sync(&*disk as &dyn BlockDevice, &mut req).err(),
                   Some(BlockError::Einval), "{op:?}");
    }
}

#[test]
fn a_payload_that_is_not_whole_data_units_is_refused() {
    let _g = guard();
    fallback::reset_for_test();
    let disk = Disk::new(BS, 64);
    let m = Mode::Aes256Xts;
    // A key whose data unit is larger than the request: the payload is a
    // partial unit, which cannot be encrypted as a whole one nor padded.
    let key = raw_key(m, 3, 4096);
    submit::start_using_key(&*disk as &dyn BlockDevice, &key).unwrap();
    let mut req = BlockRequest::new_write(0, 1, vec![7u8; BS as usize])
        .with_crypt(Ctx::new(key, Dun::from_u64(0)));
    assert_eq!(submit::submit_sync(&*disk as &dyn BlockDevice, &mut req).err(),
               Some(BlockError::Einval));
    assert_eq!(on_medium(&disk, 0, 1), vec![0u8; BS as usize]);
}

// ------------------------------------------------------------ native device

/// A device that says it encrypts in line with the transfer. It does not
/// actually transform the bytes — no such controller exists here — which is
/// what makes it useful: if the fallback ran anyway, the medium would hold
/// ciphertext, and the test would catch the double encryption.
struct Native {
    disk: Arc<Disk>,
    profile: Profile,
    programmed: Mutex<Vec<usize>>,
}

struct NativeOps;
impl LlOps for NativeOps {
    fn keyslot_program(&self, _key: &Key, _slot: usize) -> KResult<()> { Ok(()) }
}

impl Native {
    fn new() -> Arc<Native> {
        Arc::new(Native {
            disk: Disk::new(BS, 64),
            profile: Profile::new(Arc::new(NativeOps) as Arc<dyn LlOps>, 2)
                .with_mode_range(Mode::Aes256Xts, 512, 4096).unwrap()
                .with_max_dun_bytes(16)
                .with_key_types(KeyTypes::RAW | KeyTypes::HW_WRAPPED),
            programmed: Mutex::new(Vec::new()),
        })
    }
}

impl BlockDevice for Native {
    fn block_size(&self) -> u32 { self.disk.block_size() }
    fn capacity_blocks(&self) -> u64 { self.disk.capacity_blocks() }
    fn crypto_profile(&self) -> Option<&Profile> { Some(&self.profile) }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if let Some(c) = req.crypt.as_ref() {
            let slot = self.profile.get_keyslot(c.key()).unwrap().unwrap();
            self.programmed.lock().unwrap().push(slot.index());
        }
        self.disk.submit_sync(req)
    }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

#[test]
fn a_native_device_is_handed_the_request_and_the_fallback_stays_out() {
    let _g = guard();
    fallback::reset_for_test();
    let dev = Native::new();
    let key = raw_key(Mode::Aes256Xts, 3, DUS);
    // Native support means no fallback mode is ever declared, so if the
    // fallback ran it would refuse — and if it were declared and ran, the
    // bytes would be enciphered twice.
    submit::start_using_key(&*dev as &dyn BlockDevice, &key).unwrap();
    assert!(submit::config_supported_natively(&*dev as &dyn BlockDevice, key.config()));

    let plain = payload(2);
    let mut req = BlockRequest::new_write(0, 2, plain.clone())
        .with_crypt(Ctx::new(key, Dun::from_u64(0)));
    submit::submit_sync(&*dev as &dyn BlockDevice, &mut req).unwrap();
    assert_eq!(on_medium(&dev.disk, 0, 2), plain);
    assert!(!dev.programmed.lock().unwrap().is_empty(), "the key never reached a keyslot");
}

#[test]
fn a_native_device_takes_a_wrapped_key_the_fallback_would_refuse() {
    let _g = guard();
    let dev = Native::new();
    let wrapped = Arc::new(
        Key::new(&[0x22u8; 40], KeyType::HwWrapped, Mode::Aes256Xts, 8, DUS).unwrap());
    submit::start_using_key(&*dev as &dyn BlockDevice, &wrapped).unwrap();
    assert!(submit::config_supported(&*dev as &dyn BlockDevice, wrapped.config()));
    let mut req = BlockRequest::new_write(0, 1, payload(1))
        .with_crypt(Ctx::new(wrapped, Dun::from_u64(0)));
    submit::submit_sync(&*dev as &dyn BlockDevice, &mut req).unwrap();
}

#[test]
fn a_native_device_that_cannot_serve_the_config_falls_back() {
    let _g = guard();
    let dev = Native::new();
    // Advertised: AES-256-XTS only. This mode is not, so the software path
    // must serve it — and must actually encrypt.
    let key = raw_key(Mode::Adiantum, 3, DUS);
    assert!(!submit::config_supported_natively(&*dev as &dyn BlockDevice, key.config()));
    submit::start_using_key(&*dev as &dyn BlockDevice, &key).unwrap();
    let plain = payload(2);
    let mut req = BlockRequest::new_write(0, 2, plain.clone())
        .with_crypt(Ctx::new(key, Dun::from_u64(0)));
    submit::submit_sync(&*dev as &dyn BlockDevice, &mut req).unwrap();
    assert_ne!(on_medium(&dev.disk, 0, 2), plain);
}
