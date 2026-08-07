// The `KEYCTL_PKEY_*` family as the keyring sees it: adding an asymmetric key,
// the name it takes when the caller gives none, which keys the operations will
// use, the information string, and the per-command length rules.
//
// The key material is the same 1024-bit RSA pair the `pkey` crate's tests use,
// produced by an outside toolchain.

use super::*;
use super::super::ops::pkey;
use super::super::ops::*;
use ::pkey::Operation;

/// A self-signed certificate for `O=Oxide Test, CN=pkey vector`.
const CERT_DER: &str = concat!(
    "308202323082019ba0030201020214280d0bb06dc810c24687dae3d19387bd2fdea38f300d06092a864886f70d01010b",
    "0500302b31133011060355040a0c0a4f7869646520546573743114301206035504030c0b706b657920766563746f7230",
    "1e170d3236303830313134333932315a170d3336303732393134333932315a302b31133011060355040a0c0a4f786964",
    "6520546573743114301206035504030c0b706b657920766563746f7230819f300d06092a864886f70d01010105000381",
    "8d0030818902818100aa58a4e795793f490436d2c9423c853ff66fa79f1524551ba4ea8c481b282935be33c0b6511171",
    "250bba4a6f254962a03b13818a710d8bdcf70bc9f17e626fb55863e37a6424a0ba1c02d9582079233720c5b92ab39c09",
    "0db99d30e16a380de4bd5df2ac50450d6f6804224d7e8e98d6811bdb748a49338dfe961019c984fbaf0203010001a353",
    "3051301f0603551d23041830168014fb55bbd159ecd01255e7d576480dcb840ddd8ce7300f0603551d130101ff040530",
    "030101ff301d0603551d0e04160414fb55bbd159ecd01255e7d576480dcb840ddd8ce7300d06092a864886f70d01010b",
    "05000381810058c57c5e92aaa83dab4ab7135267ab3e46eae83668e25dd5aea9c20ed4bab7c67b5388dc1d1da58b13ef",
    "380b5e7d74349418d8a08ae2bcf64cad8e92049fc657cab11c1bf76fff9913b7635941f5a46ef2831250bbf21e6f4300",
    "8265bb5a08147a069be57ee610a99eaf6f51bd0a520478d8f1357ac6a795a17d29d246f307ec",
);

/// The matching private key.
const KEY_PKCS8: &str = concat!(
    "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100aa58a4e795793f490436d2",
    "c9423c853ff66fa79f1524551ba4ea8c481b282935be33c0b6511171250bba4a6f254962a03b13818a710d8bdcf70bc9",
    "f17e626fb55863e37a6424a0ba1c02d9582079233720c5b92ab39c090db99d30e16a380de4bd5df2ac50450d6f680422",
    "4d7e8e98d6811bdb748a49338dfe961019c984fbaf02030100010281807ab46fd501aedd0f53a1ca247f39e92231fa2b",
    "dc43f66ff801cb92513e7ea770b719c06f93e5e482b2f7f63629bdbaf58098846f9d100cf7965d3f925d5fbae6d09690",
    "e7d4c4795d7477d68b42333552f5c0019fed234692e8ccfb8580107484677ee293f1e7250f0bc11f2d4e8acbd8884517",
    "551a88b99ab347333e46b58b81024100e13bb2fad85ddd072e9d8bd84803852676203e94a61cb351f0ff092b86d8a155",
    "fa04fc58b440eb2745443ffaa777ef76368606f1a7e3c3ecd6735203ca2e6637024100c19d93074d6996c9a0cc041f72",
    "15c9c2dd797e0e9e8d1127da5184aa6a6ef9387f381c455b0e4a81d47c94fb2d33c22125c4354921d54c098d4b18a38b",
    "39da49024100d2da99a6bdf1b95ee4e3f6ac46568d4b4160d45542e1317aaf9b82512e4f1552b0da040762d03794af02",
    "c2c67c0b0ab1673fb7b6798effb773d7c7dae666e3a702400479cb0b512bceb38c870ad55b42cbae388675768b0dc1c6",
    "c5123b59e129fd92e3c5fd4951288c6a61ea1b5b8f18f234e7f59831bf9979af82d7a8932745c819024100d924e5c888",
    "7fee62ab456fc1ea9879a2bd7b29581aa4a92f2857bc70f5bcd0f346f445525b8fa0be9aa41dc60b470d6c8925703c72",
    "d950f64f09631006569763",
);

/// SHA-256 of `oxide pkey vector`, and the signature over it.
const DIGEST: &str = "266602de73b6e54973d13613f585516562951bc1dd297e08c2a5d8c3f46efd1a";
const SIG: &str = concat!(
    "9b28cfe2ea5f1bb37021fd2032bf5c2506f09359625a1299331570136671096b5284e1c2d8cee6cf1aa48b05c871f316",
    "b49f91b693d892ad45843023d567114b865407fa22fecd20746342beabe418a634ede5f79515edb398444cef61952e29",
    "b934c9ca9403d03c29d6955bc97acaf20b68b10922f3bbc04ed66eac95b5ad8c",
);

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    (0..b.len() / 2).map(|i| nyb(b[i * 2]) << 4 | nyb(b[i * 2 + 1])).collect()
}
fn nyb(c: u8) -> u8 { if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 } }

/// Deterministic padding, so an encryption test is reproducible.
fn fixed_rand(buf: &mut [u8]) { for (i, b) in buf.iter_mut().enumerate() { *b = (i as u8) | 0x41; } }

fn add_cert(t: &Ctx, desc: &str) -> i64 {
    add_key_core(t, "asymmetric", desc, unhex(CERT_DER), true, KEY_SPEC_SESSION_KEYRING)
}
pub(super) fn certificate_payload() -> Vec<u8> { unhex(CERT_DER) }
fn add_private(t: &Ctx, desc: &str) -> i64 {
    add_key_core(t, "asymmetric", desc, unhex(KEY_PKCS8), true, KEY_SPEC_SESSION_KEYRING)
}

// A certificate names itself, so it may be added with no description at all —
// the only registered type that may.
#[test]
fn a_certificate_supplies_its_own_description() {
    let t = ctx(1720, 7720);
    join_session(&t, None);
    let k = add_cert(&t, "") as i32;
    assert!(k >= FIRST_SERIAL, "added: {k}");
    assert_eq!(STORE.lock().keys.get(&k).expect("added key").description,
        "Oxide Test: pkey vector: fb55bbd159ecd01255e7d576480dcb840ddd8ce7");
    // A description the caller DOES supply wins over the proposal.
    let named = add_cert(&t, "my-cert") as i32;
    assert_eq!(STORE.lock().keys.get(&named).expect("added key").description, "my-cert");
}

#[test]
fn asymmetric_search_accepts_partial_and_exact_certificate_ids() {
    let t = ctx(1739, 7739);
    join_session(&t, None);
    let key = add_cert(&t, "id-search") as i32;
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    const SKID: &str = "ex:fb55bbd159ecd01255e7d576480dcb840ddd8ce7";
    const DN: &str = "dn:31133011060355040a0c0a4f7869646520546573743114301206035504030c0b706b657920766563746f72";
    assert_eq!(search_core(&t, ring, "asymmetric", SKID, 0), key as i64);
    assert_eq!(search_core(&t, ring, "asymmetric", "id:0dcb840ddd8ce7", 0), key as i64);
    assert_eq!(search_core(&t, ring, "asymmetric", DN, 0), key as i64);
    assert_eq!(search_core(&t, ring, "asymmetric", "ex:0dcb840ddd8ce7", 0), enokey());
}

// A private-key blob proposes no name, so adding one unnamed is EINVAL rather
// than a key nothing can find.
#[test]
fn a_private_key_blob_must_be_named() {
    let t = ctx(1721, 7721);
    join_session(&t, None);
    assert_eq!(add_private(&t, ""), einval());
    assert!(add_private(&t, "signing-key") >= FIRST_SERIAL as i64);
}

// A payload that is not a key blob is EBADMSG — a decoding failure, not a
// permission or argument problem.
#[test]
fn a_payload_that_is_not_a_key_is_ebadmsg() {
    let t = ctx(1722, 7722);
    join_session(&t, None);
    assert_eq!(add_key_core(&t, "asymmetric", "junk", alloc::vec![1, 2, 3, 4], true,
        KEY_SPEC_SESSION_KEYRING), err(Errno::Ebadmsg));
    // An empty payload never reaches the parser: no blob at all is EINVAL.
    assert_eq!(add_key_core(&t, "asymmetric", "empty", alloc::vec![], false,
        KEY_SPEC_SESSION_KEYRING), einval());
}

// The key material never comes back out: the type has no read method, which is
// the whole point of doing the operations inside the kernel.
#[test]
fn an_asymmetric_key_cannot_be_read_back() {
    let t = ctx(1723, 7723);
    join_session(&t, None);
    let k = add_cert(&t, "readback") as i32;
    force_perm(k, KEY_POS_ALL | KEY_USR_ALL);
    assert_eq!(read_core(&t, k, 0), Err(err(Errno::Eopnotsupp)));
    assert_eq!(update_core(&t, k, unhex(CERT_DER), true), err(Errno::Eopnotsupp));
}

// Only an asymmetric key has these operations; another type is EOPNOTSUPP, and
// a key the caller cannot find is ENOKEY.
#[test]
fn the_operations_apply_only_to_asymmetric_keys() {
    let t = ctx(1724, 7724);
    join_session(&t, None);
    let u = add_key_core(&t, "user", "not-a-pkey", alloc::vec![1, 2], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let info = pkey::parse_info("").expect("an empty string is the default encoding");
    assert_eq!(pkey::query_core(&t, u, &info).err(), Some(err(Errno::Eopnotsupp)));
    assert_eq!(pkey::query_core(&t, 0x7fff_0001, &info).err(), Some(enokey()));

    // The permission needed is SEARCH, not READ: the operation hands back no
    // key material, so a key that can be found can be used.
    let k = add_cert(&t, "search-perm") as i32;
    force_perm(k, KEY_POS_VIEW | KEY_POS_SEARCH);
    assert!(pkey::query_core(&t, k, &info).is_ok(), "search permission is enough");
    force_perm(k, KEY_POS_VIEW);
    assert_eq!(pkey::query_core(&t, k, &info).err(), Some(eacces()));
}

// The information string's grammar. Each rejection stops a request that could
// otherwise be read two ways.
#[test]
fn information_string_grammar() {
    assert_eq!(pkey::parse_info("").expect("empty").encoding, "raw");
    assert_eq!(pkey::parse_info("   \t ").expect("blank").encoding, "raw");
    let i = pkey::parse_info("enc=pkcs1 hash=sha256").expect("both keys");
    assert_eq!((i.encoding.as_str(), i.hash.as_deref()), ("pkcs1", Some("sha256")));
    assert_eq!(pkey::parse_info("enc=pkcs1\thash=sha256").expect("tab separated").hash.as_deref(),
        Some("sha256"));
    assert_eq!(pkey::parse_info("enc=pkcs1 enc=raw"), Err(Errno::Einval), "a repeated key");
    assert_eq!(pkey::parse_info("enc="), Err(Errno::Einval), "an empty value");
    assert_eq!(pkey::parse_info("pkcs1"), Err(Errno::Einval), "a bare word");
    assert_eq!(pkey::parse_info("mgf=mgf1"), Err(Errno::Einval),
        "a parameter this kernel does not implement is refused, not ignored");
}

// What the query reports, and that it tracks the key's private half.
#[test]
fn query_reports_sizes_and_operations() {
    let t = ctx(1725, 7725);
    join_session(&t, None);
    let pubk = add_cert(&t, "q-pub") as i32;
    let privk = add_private(&t, "q-priv") as i32;
    let raw = pkey::parse_info("").expect("default");
    let pkcs1 = pkey::parse_info("enc=pkcs1 hash=sha256").expect("named");

    let q = pkey::query_core(&t, pubk, &raw).expect("queries");
    assert_eq!(q.key_size, 1024, "reported in bits");
    assert_eq!(q.max_enc_size, 128, "reported in bytes");
    assert_eq!((q.can_encrypt, q.can_decrypt, q.can_sign, q.can_verify),
        (true, false, false, false));
    let q = pkey::query_core(&t, privk, &pkcs1).expect("queries");
    assert_eq!((q.can_encrypt, q.can_decrypt, q.can_sign, q.can_verify), (true, true, true, true));
    // An encoding this kernel has no implementation of is refused at query
    // time, so a caller learns before it hands over any data.
    assert_eq!(pkey::query_core(&t, pubk, &pkey::parse_info("enc=oaep").expect("parses")).err(),
        Some(einval()));
}

// The published signature, made and verified through the keyring's own cores.
#[test]
fn sign_then_verify_through_the_keyring() {
    let t = ctx(1726, 7726);
    join_session(&t, None);
    let privk = add_private(&t, "s-priv") as i32;
    let pubk = add_cert(&t, "s-pub") as i32;
    let info = pkey::parse_info("enc=pkcs1 hash=sha256").expect("named");
    let digest = unhex(DIGEST);

    let key = pkey::load_key(&t, privk).expect("loads");
    let sig = pkey::eds_core(&key, Operation::Sign, &info, &digest, fixed_rand).expect("signs");
    assert_eq!(sig, unhex(SIG));

    let pubkey = pkey::load_key(&t, pubk).expect("loads");
    assert_eq!(pkey::verify_core(&pubkey, &info, &digest, &sig), Ok(()));
    // A signature over a different digest is a REJECTED key, which is an
    // authentication answer — not the EBADMSG a malformed block gets.
    let mut other = digest.clone();
    other[0] ^= 1;
    assert_eq!(pkey::verify_core(&pubkey, &info, &other, &sig), Err(err(Errno::Ekeyrejected)));
    let mut mangled = sig.clone();
    mangled[10] ^= 0xff;
    assert_eq!(pkey::verify_core(&pubkey, &info, &digest, &mangled), Err(err(Errno::Ebadmsg)));
    // Signing needs the private half; a certificate cannot.
    assert_eq!(pkey::eds_core(&pubkey, Operation::Sign, &info, &digest, fixed_rand),
        Err(einval()));
}

// Encryption through the keyring round-trips to the private key.
#[test]
fn encrypt_then_decrypt_through_the_keyring() {
    let t = ctx(1727, 7727);
    join_session(&t, None);
    let pubkey = pkey::load_key(&t, add_cert(&t, "e-pub") as i32).expect("loads");
    let privkey = pkey::load_key(&t, add_private(&t, "e-priv") as i32).expect("loads");
    let info = pkey::parse_info("enc=pkcs1").expect("parses");
    let msg = b"keyring pkey round trip".to_vec();
    let ct = pkey::eds_core(&pubkey, Operation::Encrypt, &info, &msg, fixed_rand).expect("encrypts");
    assert_eq!(ct.len(), 128);
    assert_eq!(pkey::eds_core(&privkey, Operation::Decrypt, &info, &ct, fixed_rand), Ok(msg));
}

// The declared lengths are bounded by the widths the query reports, before any
// calculation runs.
#[test]
fn declared_lengths_are_bounded_by_the_query() {
    let t = ctx(1728, 7728);
    join_session(&t, None);
    let k = add_private(&t, "l-priv") as i32;
    let info = pkey::parse_info("enc=pkcs1 hash=sha256").expect("named");
    let q = pkey::query_core(&t, k, &info).expect("queries");

    assert_eq!(pkey::vet_lengths(Operation::Sign, &q, 32, 128), Ok(128));
    assert_eq!(pkey::vet_lengths(Operation::Sign, &q, 129, 128), Err(Errno::Einval),
        "an input past the signature input ceiling");
    assert_eq!(pkey::vet_lengths(Operation::Sign, &q, 32, 129), Err(Errno::Einval),
        "an output buffer wider than the signature");
    assert_eq!(pkey::vet_lengths(Operation::Encrypt, &q, 128, 128), Ok(128));
    assert_eq!(pkey::vet_lengths(Operation::Verify, &q, 32, 128), Ok(128));
    assert_eq!(pkey::vet_lengths(Operation::Verify, &q, 32, 129), Err(Errno::Einval),
        "a signature wider than the key");
}

// The advertised capability bit and the commands must agree.
#[test]
fn capability_bit_tracks_the_implementation() {
    let caps = super::super::keyctl::keyrings_capabilities();
    assert_eq!(caps[0] & KEYCTL_CAPS0_PUBLIC_KEY != 0, pkey::SUPPORTED);
    assert_eq!(caps[1] & KEYCTL_CAPS1_NOTIFICATIONS != 0, super::super::ops::watch::SUPPORTED);
}
