//! The published vectors for the almost-universal hash, at four message
//! lengths spanning one unit up to a full segment.

use crate::nh::{nh, NH_KEY_WORDS};
use super::hex;

const NH_KEY: [u8; 1072] = hex::<1072>(
    "0459669281d7e92568fab0ca9fea98cacdbf6da50c22c357dc3505dd5bb0cef6\
    b24c772ed263f01760d8d3d9ed34b6ed6a11c025daba7eef4913f7d9fcb6fd58\
    e95fc5c46989baa62b588d366cb9901e64c7448403703047dd58f48761fd9c6b\
    511b391d6d50ae197103c7a742828fa5636ae28aad4b40a73f8be4aeb28a1478\
    9107ba0208c134b8da6167f698971acb0f8280ff025416571835af161768ccc7\
    52ac313960e4b4cb0ef957e996ff99d6109609ab28921b9f10de3e87b89d2da0\
    3c91858c9ec0979ab4547f4a63c2750f0d2f6256480eb6c7cf0d78cabd319e4c\
    f73f9ec2ea5e446d76f9c5e029ea15bfafd475c889cf4f17fd4a45a54d2d8711\
    2b3e64a26bc5238cfa7113720e7ce12c9f0e29c915de4ed7421f8ee191995038\
    7f15c0f64bfd9d40e94451ca3b83419f8264662212431c4f45113a46b17c620a\
    9d4c9985b01019cfebf965afd8059e61035f1599a90520c8afab319dd5df24ce\
    2b6dd717c304ff82a71839e90d0a5fb9c9861df8022dc38828735cac25c9fecb\
    d2fd6374ace1b8a2c62bb540019bedee7b63660545c26cd858f1a13dc843594b\
    3987246492b0ab75f1b7bf7cdec0af4ac27bd98a99cd8301e6aeeb16e7549c95\
    0a9102af9f794045ce474165ca800d1446585d4d285570497c321f01aa052ff1\
    eba3e61df943e058056122c3eee46f94af82da1818639cfac00427c5395e7aa6\
    8546b776c916f2f8408d4b5e72f33e12a48039b292fe6e5b5badea29bc66e6fe\
    80025d8337fcde6c2554a2ff7db6e1d6cfdb60e3be2f4eb4f5b451f75a25da40\
    845ec00a6bfa0cfb5e3e126c3935c028d61b3a72c3fea54c35a242f63da5bfb5\
    39e3c9d58c1be5ef91d2806fcc77445062c7ac29cb72da6dc5fea7ee8bebfca3\
    46185faac365d08f6798d6ce5f84d4961b67a0cffc94555e4b5168a76d02f953\
    54866b5339e03623871afb531a65d842a885fd2c7f6b7f6770236ce90bf01e0d\
    0bb4d49614957ef39bddd7c42422b99db3a6ac097c00bfd0dcfb9b7c8cbdd41a\
    132b823d7c8c1047496c53eba7c2deede255932c1a5a7de13762dd291a7282c0\
    14735d0e9bcc54683a4d568fc94eaf7bde179c5e838222e328df1bb6db179048\
    b5134ed3975eb39c1608c877b3cd94904f77af67dd80151c59fb3cecf8b367fb\
    a0943c539949942c8526926d8d48f672ddfbb210515bbed5703d2894984f6e20\
    7b7d0f56c9965f602e2f9b387fc73c6b2f2b8f1f071c8557162ec774e5f20dfe\
    ef57b0a44f4c7d81bbaacba0b051cfc2ee902e5e27cad3e8f355025606a5addf\
    a3a90605537455d5d2200a6d4aef16bfc3b27593d86e0fd2ae3bc000226fb50a\
    41fcf941fc164fa61c18416773a879a954184e88440fa15bf068ea3c62598dc7\
    6fd772207439d43a411b5857548560ca494ba10491b6f2cd626367d1ee6b9e5d\
    d6c4586be1e64adbe8b13503158d34694cd254cee86a696faab51f86edac4f16\
    1e4893e86c241cd0bb61c234ddc95cce");
const NH_MSG: [u8; 1024] = hex::<1024>(
    "99576141ad087e17d4ef0b23ff0b960a6c98ac785eb6b2670f48f4a1e51efe83\
    e4562a0364ff7af303fea786dc357913f8e15919044324824482412bc7cff5a4\
    dccaf534c4233c1fa8841f2acdae9d5e05e2fb0c6881901144f6dd5b51d3e0ab\
    293aa99cf67e2de36c0959d7fa7f6a333b237b1bb2795f5cb62db0f8ab3328e0\
    722e2f032216b487f7143f558ab047db422dc00c0a33f8ab44aea3c9fcf6348c\
    60306d3170f33953f12db96ca6489c9cc288b3a998b6c34794029d986e256cf5\
    9bc64dee071e258f01deade5774fd1c062bb3ab9830b29764fb1862c27c73865\
    cb78b702109ede83d1ac058623ce4f8dcc4e3f04f43991811c42474d50e50122\
    98cf9136b37ccf780722a918d2cd7d4da6cbaa52134964b0a53dc7c310872e76\
    a952c55018c05db44cc67f64ae53c34699b7616b0843084c902cee5691b428a8\
    a88b3b1a6771f28148207130dd698ac24c9d4e17fb2ee79b8694a5cef97456ff\
    3bffd95ac898f525a2b96646891739086903591e131268e72f00d3f371d120c5\
    0b3889da623cceea0419476dd86438609671684879f8f47633f6608d21d0ee41\
    c0be33615e66e61614c7fb6cf358ef127c70655d55e8f2923afe3464317c29bb\
    0118bdb6e41ea4f37b4c6a0d01fcc766c3883725cfe9ca82eba13840c9db387b\
    78cf11a31c6b70c8e12f7c172c5828a41340c7690f04e58ef06753ea10f583c9\
    cb6b16ef2e55b3ddedf91a529a7378141421fcef3c40a9feefd76e282fd373ed\
    a373b56241e6d47949312b86745621fe6db2be8180a6811990796fc44e7d6f2f\
    a86fd5c47e233be69b60977be2088aaac77cf6e5013ed2297dd7408495fadfd8\
    81e95edd0d17516b8c0e47f90c921b60ca068ae5e80f06755d76c9322c522c2e\
    d866387516c77d51c4c222c819fc3d691ed964475d218446d7e1f0953a8fbd7a\
    53714c54c13e27deeb0411b0334d570b6b7d6cd5877eb4e2949e9f74e8b7fa05\
    9b8f81433582b85ba85efa7a808dd29058798956902bff923c35be995fd24b15\
    584bbf089b9b9710a455c7ec29c5143e8f56a3929e33cc9e772f33cbc4e919f4\
    322bef6c1c922c4588745fcf56fd875fb69ba251da9b834fec14e8d24203cbe8\
    d0b7f838de6fdf43fa41abec2e3c933976d16f5b6c6e8deb456bc5760029ca3b\
    db78c23209391950a2449209db8b9e16767ff1787bb251bc28bdb07f25637d34\
    fbf63624c7f941b62a06fcf083f2123d602e1070316f37083e9193b5dab84c1b\
    d8b83bd53eb6c0bb380fd2684f7856f6da65b40bb4afa8192f7055e047319f37\
    1a47b90c9779fca976e6fa386725d3898dadc6112d770b35a2e2dfc894d5dfd2\
    692a9993fa4a5fc78a145f2af302f03e218e2e4bc4d2c8a6416e1736e9ad7333\
    6ceac2318f30515c1c20e6051a17155d3e8fd27fa1c547b3b29ce8f06dc1c3a2");

/// The key is consumed as little-endian words.
fn key_words() -> [u32; NH_KEY_WORDS] {
    let mut k = [0u32; NH_KEY_WORDS];
    for i in 0..NH_KEY_WORDS {
        k[i] = u32::from_le_bytes([NH_KEY[4 * i], NH_KEY[4 * i + 1],
                                   NH_KEY[4 * i + 2], NH_KEY[4 * i + 3]]);
    }
    k
}

/// The hash is emitted as four little-endian 64-bit sums.
fn bytes(h: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 { out[8 * i..8 * i + 8].copy_from_slice(&h[i].to_le_bytes()); }
    out
}

const NH_VAL_16: [u8; 32] = hex::<32>(
    "3077557c45d8cef72ab5148c357eaa0050bc507cd3207c9cb4f191268103a568");
const NH_VAL_96: [u8; 32] = hex::<32>(
    "d219caa56c0cdf2f69fa75c163dbfa4d452bb8dbacee61c67a83b60f3282e4d0");
const NH_VAL_256: [u8; 32] = hex::<32>(
    "338fb496f1b6f1b50519bb6bdad99575963f8b42b6cdb7b7e797b5a90bd7dd33");
const NH_VAL_1024: [u8; 32] = hex::<32>(
    "323d51e177b6ac068467b7f224e7ecfd9664ff55c71bf9dca3c7320679cfcab6");

#[test]
fn published_lengths() {
    let k = key_words();
    assert_eq!(bytes(nh(&k, &NH_MSG[..16])), NH_VAL_16);
    assert_eq!(bytes(nh(&k, &NH_MSG[..96])), NH_VAL_96);
    assert_eq!(bytes(nh(&k, &NH_MSG[..256])), NH_VAL_256);
    assert_eq!(bytes(nh(&k, &NH_MSG[..1024])), NH_VAL_1024);
}

/// Misaligned chunking must give the same hash as one contiguous pass. The
/// mode itself only ever hashes contiguously, so no published vector covers
/// this; the partial-unit buffer and the partial-segment carry are only
/// reachable through the streaming form.
#[test]
fn chunked_matches_contiguous() {
    use crate::nhpoly1305::{nhpoly1305, NhPoly1305};
    use crate::poly1305::CoreKey;

    let k = key_words();
    let pk = CoreKey::new(&hex::<16>("851fc40c3467ac0be05cc20404f3f700"));
    // Long enough to cross a segment boundary twice over.
    let mut msg = [0u8; 2600];
    for (i, b) in msg.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(31).wrapping_add(7); }

    let want = nhpoly1305(&k, &pk, &msg);
    for step in [1usize, 7, 16, 17, 64, 333, 1024, 1025] {
        let mut h = NhPoly1305::new();
        let mut off = 0;
        while off < msg.len() {
            let n = core::cmp::min(step, msg.len() - off);
            h.update(&k, &pk, &msg[off..off + n]);
            off += n;
        }
        assert_eq!(h.finish(&k, &pk), want, "step {}", step);
    }
}
