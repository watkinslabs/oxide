// The `.fs-verity` keyring end to end: it exists with the permissions that
// make root its only writer, a certificate reaches the verity verifier only by
// being linked into it, and the link restriction an administrator may install
// decides which certificates may join.
//
// Every certificate here is a real DER blob from an outside toolchain: a 2048-
// bit RSA certificate authority, a signing certificate it issued, and an
// unrelated self-signed certificate that must be REFUSED once the keyring is
// restricted to that authority.

use super::*;
use super::super::ops::*;
use super::super::verity;

/// The certificate authority the restricted keyring is anchored on.
const CA_DER: &str = concat!(
    "3082034930820231a00302010202142fcc0960dca84cbae1a60da60b014512116f6fa1300d06092a864886f70d01010b",
    "0500303431133011060355040a0c0a4f786964652054657374311d301b06035504030c1466732d766572697479206b65",
    "7972696e67204341301e170d3236303831363231343435315a170d3436303831313231343435315a3034311330110603",
    "55040a0c0a4f786964652054657374311d301b06035504030c1466732d766572697479206b657972696e672043413082",
    "0122300d06092a864886f70d01010105000382010f003082010a0282010100dd314e0c7891671ea13fb4cecbcb461f5a",
    "df910a1e30bffaf818f8ea152a89ee678ff3898eec8b2495b5116d2c5671881cac42a9f3ee1855542ddea4fd080a77e8",
    "e0622dd8d6643a75cd548824a2cabd1dd75a26b55652e885f8bd9eb55179e31742fcb1a90699e1862dac810208d46ded",
    "bb47f17f11a883fecd075184a06f3cd1ff3e4a8ae1cbc5525bccb10678109f133f2048c3bd699d0b122e9a96385b90b6",
    "173d55caafe637bebc45d9be6b1d0a7c0624f16624bfbc8fa6e4a2f5ee0840c0eb69c32679fb5f4f98004ef22b08d8f9",
    "16eb5428de941d1978892af109c1f74b6f30ddf1f6e08306a167c6ea113e526da0d88d9d0a7ecfd2621787105e2b1902",
    "03010001a3533051301d0603551d0e041604142be71fcfefdaa086a1cb43f0547bb03df424feb0301f0603551d230418",
    "301680142be71fcfefdaa086a1cb43f0547bb03df424feb0300f0603551d130101ff040530030101ff300d06092a8648",
    "86f70d01010b05000382010100accbbd72bed09cb3b52b850962d72a44f3b0769f14a5622cabe2d1834733b6d6b0f850",
    "2497f1610c5792eba1c87566fea421bcb5fb30d8e7f87972705a38a21b49488bfd30db133bb40c97b62abeb8c1f5d0dd",
    "30a25bd01e5959508d4912e9eba187cf350eb10e257a7583eeb3cf816fd6c564d488ee2e8e8359c68720a2e3363735ba",
    "ccd8c3db8a6856b61fc851a885a6b395518761f9fee5dce6e6f70f853cd31f730f614bec856bd5babd35854cd580cdb7",
    "c9f2fcb3e5fa15f69edfa8b7b3ba4359c456bbd172729e8ea00fe83588271b74574bdad4f50a08e0e0e862eb890a230e",
    "fd86213ed583e3677645d96004e8d0897d65c0f8e1cc5de0dd3da486b1",
);

/// A signing certificate that authority issued.
const LEAF_DER: &str = concat!(
    "3082034030820228a00302010202084f78696465303031300d06092a864886f70d01010b050030343113301106035504",
    "0a0c0a4f786964652054657374311d301b06035504030c1466732d766572697479206b657972696e67204341301e170d",
    "3236303831363231343435315a170d3436303831313231343435315a303031133011060355040a0c0a4f786964652054",
    "6573743119301706035504030c1066732d766572697479207369676e657230820122300d06092a864886f70d01010105",
    "000382010f003082010a0282010100a3e34ec26eac22c5563867e656566e07ef1c81ca2ebb628b0fec0065f47d72f3e6",
    "19c1d8f58e2facb9fd82c3fe5cb65c34f53800119343261f589b156c86537389eba393bc461f3a5cafd7417333aa259e",
    "a372ec839b1d4914859e75139e7ba1c7880ccfe42fc8e44d22257b2c7c8b57cd44c872a1a1306df02a602a4541a2edd8",
    "075c16af45164059527d326bec93b6c1673436461bae172f5b016dbfd6ca6f928e19312336a7c13d46dca586b4c76f8e",
    "438064f53279486b459939e4acc726dc2653278a09ffc81fb589f9419fe52f4d5979ef3be4500cf1c9f06fba41bc0dba",
    "5688d808ef739e232e22ede88d2e407c601d288678415e7d3c9fb7507395970203010001a35a305830090603551d1304",
    "023000300b0603551d0f040403020780301d0603551d0e04160414cfb0b540d046fc4e3d1ab75b36c05b9a3126d94030",
    "1f0603551d230418301680142be71fcfefdaa086a1cb43f0547bb03df424feb0300d06092a864886f70d01010b050003",
    "820101004caa3f0d8f381900a16d2ab183a050b0d875be89d73b3cee80530fc23da1e9798fa34a7d9e3f353540cc51da",
    "ae0e3fc5a588187f4cb8f302797e141128e6af6e3afb78f7dfbf7cffc35ec2ed18444e469411bf0fca35537ac9b3e262",
    "99f10481751e7566849a45836e8b0b1f42b4c81bf1a82b2a90d3536de80d1990a2b556a7f53598e429886b1c69680b31",
    "d4ee867741ceb9d5be5fd0594514b2495b0fe0e99be36832183ac55da507bd79e8fbf69af4cd204971d84354630840ba",
    "8e57c63b79b03789d32d7f8d6f554bbd296745b89f5acce254e52cea39b5ec734563e7c9e38b2784c8345f718c908274",
    "a1a17bc09a313fdcc4241402d289cd9f7590457f",
);

/// A self-signed certificate from an unrelated issuer.
const ROGUE_DER: &str = concat!(
    "308203373082021fa00302010202146d7991970d6881b5cef910b13e7045cab06bdd64300d06092a864886f70d01010b",
    "0500302b310e300c060355040a0c05526f6775653119301706035504030c10756e74727573746564207369676e657230",
    "1e170d3236303831363231343435325a170d3436303831313231343435325a302b310e300c060355040a0c05526f6775",
    "653119301706035504030c10756e74727573746564207369676e657230820122300d06092a864886f70d010101050003",
    "82010f003082010a0282010100a7dff4a4dd07c79aad57ba1c028214a98543ebb3ab35c14fa1037584098d8ef27c7644",
    "aee0528f76c4039a6a2a23ac0c363898dc0b19e6a7dee5a568bffb8c86e8bba4393129c627e351ebd23f468514464e14",
    "156a37d6e00a8d5c58721509dac21aad8121380150cebb1778442a180819169d6be91a0809931c4ad39ceb297913520b",
    "161feda77da1b1d2adc3cfdded6d2bff60e3f8024cfc210714eaa095c9884e28840b39633f5c83b2d4aade988a795301",
    "941d5072a20606c6b24b5deda5df844b6122f291fa78bd11cbbc14bae3296780e886e61f0966800017ddf0eae6a9fd42",
    "b81455e50bba720916942c918f3dcbff1e3085652918a03199bf6035630203010001a3533051301d0603551d0e041604",
    "14551c0599191626afac35229de8fbf7cab8d6d540301f0603551d23041830168014551c0599191626afac35229de8fb",
    "f7cab8d6d540300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010005352f30d3",
    "e08287027edbbb7fa875be6a625a802f314c26bfd1e410ca8c8a53cfd21e0c1f5f19342ff39e2619eadb0351b5af9e2c",
    "215e80cbad63ec1f82b0ea86f9afa460f64d5fda821b08762340237ccb8fdda95bb71c6d82f7d732fb399325534c4382",
    "d3dc7a728524e0ed143ac7168438202e56cb3505a52c06bb382dfaf36fbe25fc203a96e50059508a227da38b7a82f889",
    "5ab42fcd24da9519b730b7f9a2eeb99e98198a084dd666d86ab801406f19ba492a6e9f721b0ee4f05bc05bc39ef95c1c",
    "6651cd9348b17debe441edf9b610da89b1429e34b06fdf3481bdf35e3293f02e889424241fe2177635592883afca8b7c",
    "86a0b9697fa8c8411f6c46",
);

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    (0..b.len() / 2).map(|i| nyb(b[i * 2]) << 4 | nyb(b[i * 2 + 1])).collect()
}
fn nyb(c: u8) -> u8 { if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 } }

/// One keyring for the whole machine means one keyring for the whole test
/// binary: these tests mutate shared state and must not overlap.
static SERIALISE: sync::Spinlock<(), sync::TaskList> = sync::Spinlock::new(());

/// Start every test from a keyring that exists and holds nothing.
fn fresh_ring() -> i32 {
    verity::init();
    let ring = verity::keyring_serial().expect("init minted the keyring");
    let mut g = STORE.lock();
    let members = core::mem::take(&mut g.keys.get_mut(&ring).expect("the keyring exists").members);
    for s in members { g.destroy(s); }
    g.keys.get_mut(&ring).expect("the keyring exists").restriction = None;
    ring
}

/// root: the uid the keyring is owned by, which is what turns its USER
/// permission byte on.
fn root(tid: u32) -> Ctx { ctx(tid, 0) }

fn add(c: &Ctx, der: &str, desc: &str, ring: i32) -> i64 {
    add_key_core(c, "asymmetric", desc, unhex(der), true, ring)
}

// ---------------------------------------------------------------- existence

#[test]
fn the_keyring_exists_with_the_permissions_that_make_root_its_only_writer() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let g = STORE.lock();
    let k = g.keys.get(&ring).expect("the keyring exists");
    assert_eq!(k.description, ".fs-verity");
    assert!(k.is_keyring());
    assert_eq!(k.uid, 0, "the keyring is not owned by root");
    assert_eq!(k.gid, 0);
    assert_eq!(k.perm, FS_VERITY_KEYRING_PERM);
    // Spelled out, because these three are the access policy:
    assert_eq!(k.perm & KEY_OTH_ALL, 0, "an unprivileged task can reach the keyring");
    assert_ne!(k.perm & KEY_USR_WRITE, 0, "root cannot add a certificate");
    assert_eq!(k.perm & (KEY_POS_ALL & !KEY_POS_SEARCH), 0,
        "possession grants more than search on the verity keyring");
    // No restriction out of the box: refusing every certificate at boot would
    // make the feature unusable, and choosing one is the administrator's.
    assert!(k.restriction.is_none(), "a restriction was installed the administrator did not ask for");
}

#[test]
fn a_second_init_does_not_mint_a_second_keyring() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    verity::init();
    assert_eq!(verity::keyring_serial(), Some(ring));
    let g = STORE.lock();
    let n = g.keys.values().filter(|k| k.is_keyring() && k.description == ".fs-verity").count();
    assert_eq!(n, 1, "init minted a duplicate keyring");
}

// -------------------------------------------------------------- the writer

/// The gap this whole module closes: before it, nothing could put a
/// certificate where the verity verifier reads.
#[test]
fn a_certificate_added_by_root_reaches_the_verity_verifier() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    assert!(vfs::verity_keys::is_empty(), "the fresh keyring is not empty");
    vfs::verity_keys::with_store(|s| assert!(s.is_empty()));

    let k = add(&root(1900), CA_DER, "", ring);
    assert!(k >= FIRST_SERIAL as i64, "add_key refused the certificate: {k}");

    assert!(!vfs::verity_keys::is_empty(), "the verifier still sees an empty keyring");
    vfs::verity_keys::with_store(|s| assert_eq!(s.len(), 1,
        "the certificate did not reach the verifier's trust store"));
    assert_eq!(verity::certificates(), alloc::vec![unhex(CA_DER)]);
}

#[test]
fn an_unprivileged_caller_cannot_add_a_certificate() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    // The OTHER byte is empty and this caller neither owns nor possesses the
    // keyring, so the write is refused before the payload is looked at.
    assert_eq!(add(&ctx(1901, 1901), CA_DER, "", ring), eacces());
    assert!(vfs::verity_keys::is_empty(), "an unprivileged caller widened the trust store");
}

/// A key removed from the keyring stops being trusted. This is why the trust
/// set is derived from the keyring on every read rather than accumulated.
#[test]
fn unlinking_a_certificate_withdraws_it_from_the_verifier() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let c = root(1902);
    let k = add(&c, CA_DER, "", ring) as i32;
    assert!(k >= FIRST_SERIAL);
    vfs::verity_keys::with_store(|s| assert_eq!(s.len(), 1));
    assert_eq!(unlink_core(&c, k, ring), 0);
    assert!(vfs::verity_keys::is_empty(), "an unlinked certificate is still trusted");
    vfs::verity_keys::with_store(|s| assert!(s.is_empty()));
}

/// A revoked key is still LINKED, so the machine still counts as using
/// built-in signatures, but it can no longer anchor a chain.
///
/// The certificate is added to the caller's own session keyring and linked
/// from there, which is what gives the caller the possession `KEYCTL_REVOKE`
/// needs — a key sitting only in `.fs-verity` is owned by root but possessed
/// by nobody, and the keyring's own permissions never reach the keys inside
/// it.
#[test]
fn a_revoked_certificate_anchors_nothing_but_still_counts_as_a_link() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let c = root(1903);
    let k = add(&c, CA_DER, "", KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(k >= FIRST_SERIAL, "add_key refused the certificate: {k}");
    assert_eq!(link_core(&c, k, ring), 0, "root could not link the certificate in");
    vfs::verity_keys::with_store(|s| assert_eq!(s.len(), 1));
    assert_eq!(revoke_core(&c, k), 0);
    assert!(!vfs::verity_keys::is_empty(), "a revoked link made the keyring look unused");
    vfs::verity_keys::with_store(|s| assert!(s.is_empty(), "a revoked certificate still anchors a chain"));
}

/// `/proc/keys` is how `keyctl %keyring:.fs-verity` finds the serial, so the
/// keyring has to be visible to root there.
#[test]
fn root_can_find_the_keyring_in_proc_keys() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let text = super::super::report::proc_keys(&root(1904).t, 0);
    let line = text.lines().find(|l| l.contains(".fs-verity")).expect("root cannot see the keyring");
    assert!(line.starts_with(&alloc::format!("{ring:08x}")), "wrong serial rendered: {line}");
    // And an ordinary user cannot: the OTHER byte grants not even VIEW.
    let other = super::super::report::proc_keys(&ctx(1905, 1905).t, 0);
    assert!(!other.contains(".fs-verity"), "an unprivileged task can see the verity keyring");
}

/// Nothing links this keyring and no task owns it, so the collector's ordinary
/// roots do not reach it. A `KEYCTL_CLEAR` on an unrelated keyring runs a
/// collection, and before the kernel held its own reference that collection
/// took the machine's entire verity trust store with it.
#[test]
fn the_collector_does_not_reap_the_keyring_or_its_certificates() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let c = root(1909);
    let k = add(&c, CA_DER, "", ring) as i32;
    assert!(k >= FIRST_SERIAL);
    // An unrelated caller clearing its own keyring is enough to trigger one.
    let other = ctx(1910, 1910);
    join_session(&other, None);
    assert_eq!(clear_core(&other, KEY_SPEC_SESSION_KEYRING), 0);

    assert_eq!(verity::keyring_serial(), Some(ring), "the keyring itself was collected");
    let g = STORE.lock();
    assert!(g.keys.contains_key(&ring), "the keyring was collected");
    assert_eq!(g.keys[&ring].members, alloc::vec![k], "the certificate was collected");
    drop(g);
    vfs::verity_keys::with_store(|s| assert_eq!(s.len(), 1, "the trust store was collected"));
}

// ------------------------------------------------------------- restriction

/// With the keyring restricted to one authority, a certificate that authority
/// issued joins and an unrelated one does not. Getting this wrong is the
/// difference between a trust store and a rubber stamp, so the refusal is
/// asserted as hard as the acceptance.
#[test]
fn a_restricted_keyring_takes_only_certificates_the_anchor_issued() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let c = root(1906);
    let ca = add(&c, CA_DER, "ca", ring) as i32;
    assert!(ca >= FIRST_SERIAL, "the authority itself was refused: {ca}");

    let rule = alloc::format!("key_or_keyring:{ca}");
    assert_eq!(restrict_core(&c, ring, Some("asymmetric"), Some(&rule)), 0);

    // Issued by the anchor: admitted, and now trusted by the verifier.
    let leaf = add(&c, LEAF_DER, "leaf", ring) as i32;
    assert!(leaf >= FIRST_SERIAL, "the authority's own signing certificate was refused: {leaf}");
    vfs::verity_keys::with_store(|s| assert_eq!(s.len(), 2));

    // Issued by nobody the keyring knows: refused, and the trust store is
    // unchanged. The errno is the one for "no key here could have signed it".
    assert_eq!(add(&c, ROGUE_DER, "rogue", ring), enokey());
    vfs::verity_keys::with_store(|s| assert_eq!(s.len(), 2,
        "an untrusted certificate joined the trust store anyway"));
    let g = STORE.lock();
    assert_eq!(g.keys[&ring].members.len(), 2, "the refused key was linked");
}

/// The restriction is one-shot: once an administrator has closed the keyring,
/// a second call cannot quietly replace the rule with a weaker one.
#[test]
fn a_restriction_cannot_be_replaced_once_installed() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    let c = root(1907);
    let ca = add(&c, CA_DER, "ca", ring) as i32;
    let rule = alloc::format!("key_or_keyring:{ca}");
    assert_eq!(restrict_core(&c, ring, Some("asymmetric"), Some(&rule)), 0);
    assert_eq!(restrict_core(&c, ring, Some("asymmetric"), Some(&rule)), err(Errno::Eexist));
    // And a null rule, which would otherwise install the reject-everything
    // restriction, is refused for the same reason.
    assert_eq!(restrict_core(&c, ring, None, None), err(Errno::Eexist));
}

#[test]
fn an_unprivileged_caller_cannot_restrict_the_keyring() {
    let _s = SERIALISE.lock();
    let ring = fresh_ring();
    // SETATTR lives in the USER byte, so only root reaches it.
    assert_eq!(restrict_core(&ctx(1908, 1908), ring, None, None), eacces());
    assert!(STORE.lock().keys[&ring].restriction.is_none());
}
