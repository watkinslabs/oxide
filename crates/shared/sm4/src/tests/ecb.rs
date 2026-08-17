//! Published multi-block known-answer vectors, applied one block at a time.

use super::hex;
use crate::Sm4;

fn check(key: &str, blocks: &[(&str, &str)]) {
    let c = Sm4::new(&hex::<16>(key));
    for (pt, ct) in blocks {
        let p = hex::<16>(pt);
        let e = hex::<16>(ct);
        assert_eq!(c.encrypt(&p), e, "encrypt {pt}");
        assert_eq!(c.decrypt(&e), p, "decrypt {ct}");
    }
}

#[test]
fn ecb_example_1() {
    check("0123456789abcdeffedcba9876543210", &[
        ("aaaaaaaabbbbbbbbccccccccdddddddd", "5ec8143de509cff7b5179f8f474b8619"),
        ("eeeeeeeeffffffffaaaaaaaabbbbbbbb", "2f1d305a7fb17df985f81c8482192304"),
    ]);
}

#[test]
fn ecb_example_2() {
    check("fedcba98765432100123456789abcdef", &[
        ("aaaaaaaabbbbbbbbccccccccdddddddd", "c5876897e4a59bbba72a10c83872245b"),
        ("eeeeeeeeffffffffaaaaaaaabbbbbbbb", "12dd90bc2d200692b529a4155ac9e600"),
    ]);
}

/// The last ten iterations of the standard's million-iteration example, each
/// step of which is an independent single-block known answer.
#[test]
fn last_ten_iterations_of_million_example() {
    check("0123456789abcdeffedcba9876543210", &[
        ("994ac3e7c357896a81fca80e383eef80", "b198f2de3f4baed1f0f1304c01275a8f"),
        ("b198f2de3f4baed1f0f1304c01275a8f", "45e139b7aeff1f27ad5715ab315d0cef"),
        ("45e139b7aeff1f27ad5715ab315d0cef", "8cc880bd1198f37ba2dd1420f9e8bb82"),
        ("8cc880bd1198f37ba2dd1420f9e8bb82", "f732ca4ba8f7b34d27d1cde6b6655a23"),
        ("f732ca4ba8f7b34d27d1cde6b6655a23", "c2f3548453e3b920a53700bee77b48fb"),
        ("c2f3548453e3b920a53700bee77b48fb", "213d9e481d9ef5bf77d5b44a5371947a"),
        ("213d9e481d9ef5bf77d5b44a5371947a", "88a66e0693ca43a5c4f6cd534b7b8efe"),
        ("88a66e0693ca43a5c4f6cd534b7b8efe", "b4287c4229325d88edce00190e16026e"),
        ("b4287c4229325d88edce00190e16026e", "87ff2cace8e7e9bf3151ec47c35183c1"),
        ("87ff2cace8e7e9bf3151ec47c35183c1", "595298c7c6fd271f0402f804c33d3f66"),
    ]);
}
