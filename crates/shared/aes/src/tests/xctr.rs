// XCTR known-answer tests.
//
// Provenance: the published conformance vector set for XCTR over AES,
// transcribed as hex — the 128-bit-key and 256-bit-key cases at 1, 15, 16, 17,
// 31 and 128 bytes. The 192-bit cases are omitted: this crate builds no
// 192-bit key schedule.
//
// XCTR is its own inverse, so a round trip proves nothing at all: a big-endian
// counter, a counter starting at 0, or a counter added to the nonce instead of
// XORed into it all round-trip perfectly. Each of those changes the ciphertext
// here.

use crate::block::AesKey;
use crate::xctr::xctr;
use super::vec_util::{assert_hex, hex};

struct Vector { key: &'static str, iv: &'static str, pt: &'static str, ct: &'static str }

const VECTORS: &[Vector] = &[
    // 128-bit key, 1-byte message
    Vector { key: "9c8dc4bd7136dc827ca1caa3235adba4",
             iv: "8de7a56a958642debaea6e690333860f",
             pt: "bd",
             ct: "b9" },
    // 128-bit key, 16-byte message
    Vector { key: "bc1b120c3f18cc1f5a1dab81a8687c63",
             iv: "22c1dd250b18cba54ada150773d98810",
             pt: "246e64c615269cda2a4b5712ff7cd6b5",
             ct: "d6478d5892b284f9b7ee0d98a1394d8f" },
    // 128-bit key, 31-byte message
    Vector { key: "4403bf4c30f0a7d6bd54bb668ea60e8a",
             iv: "e6f726df8c3caa88cec1bd433b0962ad",
             pt: "3ce346b98f9d3f8deff253ab24e22908f87e1da66d867d60976393297194b4",
             ct: "d4a3c6b8c16f701a520ced4caf5156234845071034c5ba71e5f81ed8cba6e7" },
    // 128-bit key, 128-byte message
    Vector { key: "5b1730941931a1ae248e421e82e6ecb8",
             iv: "d12eb9b8f849eb6806eb653334a2ebf0",
             pt: concat!(
              "1975ec59601b7a3e624687f0deab8136635311a01fce2585496b28fa1c92e51838140079f29eebfc36a76be1e5cf0448446dbd64b3cb78058d7f9aaf3ccf6c45",
              "6c7c464ca8c01ee433a57bbb26d9c0329d8ab3f33d52e6484c9b4c6ea4a3ad665648d5983a93c485e989caa6c1c8e7f8c3e9efbe77e6d13aa699c82ddf400f44"),
             ct: concat!(
              "c61a011a00ba04ff10d17e5dad91de8c085595aed7227740f0331b51effe3d67dfc49f39476793abaa3755fe41e0bacd25027c6151a1cc727a2026b90668bd19",
              "c52e1b754a40b2d2c4eed85ba4557d25fc014d6f0afd375d3e67c03572537be2d6195b926c3a8c2ae2c2a24f2af2b51565c58d97f9bf8c98e4501af276550749") },
    // 256-bit key, 1-byte message
    Vector { key: "05603a7e609046186c60baeb12d7bed1d3f610469df10cb473e39327a82c13aa",
             iv: "f596d1b6cb44d8d03edb92800894cdd3",
             pt: "78",
             ct: "c5" },
    // 256-bit key, 15-byte message
    Vector { key: "35ca38f3d9d634efcdeea32686bafb4501fa5267ffc59daa649a05bb8520a7f2",
             iv: "e3daf5ff42598786ee7bd6b46a2544ff",
             pt: "44671e0453d24bd996330754e48e20",
             ct: "cc554079475c8ba6ca7b9f50e321ea" },
    // 256-bit key, 16-byte message
    Vector { key: "afd91414d5dbc9ce765c5abf43052924c41368cce837bdb94120f55348d0a2d6",
             iv: "a7b400087910aef502bf85b2694cc604",
             pt: "ac6aa80cb084bf4cae9420587e009389",
             ct: "d5aae2e9864c954edeb615cbdc1f1338" },
    // 256-bit key, 17-byte message — the counter advances past the first block
    Vector { key: "ede38be71c17bf4a02e2fc76acf53c005ddcfc83eb45b4cb596260ec699c1645",
             iv: "e40e2b90d2fa942e10e5642b972815c7",
             pt: "e653ff600ec451e4934de555c5d9ad4852",
             ct: "ba2528f5cf319180da2b955f20cbfb9fc6" },
    // 256-bit key, 31-byte message
    Vector { key: "775cc0739a6497912feee020c204592e97d2a770b3b0216b8fbfb851a8ea0f62",
             iv: "318e1fcdfd23eb7f8a1f1b23532744e5",
             pt: "cdff8c9b945a513f409356936639631fbfe6a4fabe799303f5667416fce4ce",
             ct: "8bd3c3ce66f8664cadd6f50fd8995a75a13cab0b213657728829e9ea4a8de9" },
    // 256-bit key, 128-byte message — eight counter values
    Vector { key: "fbf5b73da69542bfd2946c740fbc5a28353c515884fb7d11161e00973708b716",
             iv: "9b535740e6d9a72778d49bd2291d24a9",
             pt: concat!(
              "8b02600a3eb71059c3acd52a7581f2db55ca658644fbfe9126bb45b246223e08a2bf46cb687d457ba16a3c6e25ebed317a8b47f9deec3d8709202efaba8b9bc5",
              "6c259c9d2ae8ab903f86ee611321d4dee10c95fc5c8a6e0a73cf0869444ede25afaa5604c4b360443b8b3deeae424bd29a6ca08e5206b2d15d38306d279b1ad8"),
             ct: concat!(
              "a37833789595970753a3a15b183227f70912537083b56a9f266d100de01ce62b7000dca160ef1beec5a55117aeccf2edc46007dfd57ae9903c9f965d72655def",
              "d09432c4859078a12e64f6ee8e743f202f123b3dd5398e5af98fce945d82186614af4cfee091c34a85cfe7e8f7cbf031887dc95b719d5fd2faeda624dabbb184") },
];

fn iv16(s: &str) -> [u8; 16] { let mut b = [0u8; 16]; b.copy_from_slice(&hex(s)); b }

#[test]
fn encrypt_matches_vectors() {
    for v in VECTORS {
        let key = AesKey::new(&hex(v.key)).unwrap();
        let mut data = hex(v.pt);
        xctr(&key, &iv16(v.iv), &mut data);
        assert_hex(&data, v.ct);
    }
}

#[test]
fn decrypt_matches_vectors() {
    for v in VECTORS {
        let key = AesKey::new(&hex(v.key)).unwrap();
        let mut data = hex(v.ct);
        xctr(&key, &iv16(v.iv), &mut data);
        assert_hex(&data, v.pt);
    }
}

/// A truncated message must produce the leading bytes of the longer one: the
/// keystream depends only on the nonce and the block index, never on how much
/// was asked for.
#[test]
fn prefix_of_longer_message() {
    let v = &VECTORS[9];
    let key = AesKey::new(&hex(v.key)).unwrap();
    let full = hex(v.ct);
    for len in [1usize, 15, 16, 17, 33] {
        let mut data = hex(v.pt);
        data.truncate(len);
        xctr(&key, &iv16(v.iv), &mut data);
        assert_eq!(&data[..], &full[..len]);
    }
}
