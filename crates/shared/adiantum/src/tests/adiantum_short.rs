//! The published vectors for the mode, at lengths below one hash segment.

use crate::Adiantum;
use super::hex;

/// Encrypt, check against the published ciphertext, then decrypt back.
fn check(key: &[u8; 32], tweak: &[u8; 32], pt: &[u8], ct: &[u8]) {
    let a = Adiantum::new(key).unwrap();
    let mut buf = [0u8; 128];
    let buf = &mut buf[..pt.len()];
    buf.copy_from_slice(pt);
    a.encrypt(tweak, buf).unwrap();
    assert_eq!(buf, ct);
    a.decrypt(tweak, buf).unwrap();
    assert_eq!(buf, pt);
}

const K16: [u8; 32] = hex::<32>(
    "9eebb2493c1cf5f46a99c2c4dfb1f4dd752057ea2c4fcdb2a53d7b491eabfd0f");
const T16: [u8; 32] = hex::<32>(
    "df63d4abd249f3d8338137607dfa7308d8496d80e82f6254eb0ea9395b457f8a");
const P16: [u8; 16] = hex::<16>(
    "67c9f23084418e43fbf3b33e79367fe8");
const C16: [u8; 16] = hex::<16>(
    "6d32861867860f3f967c9d280d53ec9f");

#[test]
fn len_16() { check(&K16, &T16, &P16, &C16); }

const K31: [u8; 32] = hex::<32>(
    "362b5797f85dcd995f1a5a441d920f27cc16d72b856399d3ba96a1dbd26068da");
const T31: [u8; 32] = hex::<32>(
    "ef5869b12c5e9a4724c1b169e112938f433d6d00db5ed8d9129afed9ff2daac4");
const P31: [u8; 31] = hex::<31>(
    "5ea8681985981223260accdb0a04b9df4db3487bb0e3c819435a4606942df2");
const C31: [u8; 31] = hex::<31>(
    "c7c6f1738fc4ff4a39be78be8d28c8894663e70c7d87e84ec9187bbe186050");

#[test]
fn len_31() { check(&K31, &T31, &P31, &C31); }

const K128: [u8; 32] = hex::<32>(
    "a52824341a3cd8f705918fee851f357f803dfc9b94f6fc9e190900a904314f11");
const T128: [u8; 32] = hex::<32>(
    "a1ba4995ff346db8cd875d5efdea85db8a7b5eb25d57dd62aca98c41429475b7");
const P128: [u8; 128] = hex::<128>(
    "69b4e88c37e86782f1ec5d04e5149113dff2871b69811d71709e9c3bde497011\
    a0a3db0d544f6669d7db80a7709268ce81042cc6abaee56015e96fefaa8fa7a7\
    638ff2f077f1a8eae1b71f9eab9e4b3f07875b6fcda8afb9fa700b52b8a8a79e\
    075fa60eb39b791379c33e8d1c2c68c8511d3c7b7d79772a5665c5542328b003");
const C128: [u8; 128] = hex::<128>(
    "9e16abed4ba7425ac6fb4e76ffbe03a00fe3adbae4982b0e2148a0b865482748\
    845454b29a947be64b29e9cf0591801a3af34196851d9f74515663fa7c288549\
    f72ff9f21846f53380a33cceb25793f5aebda9f57b30c49366e0307716e4a031\
    ba70bc6813f5b09ac1fc7efe55805c4874a6aaa3acdcc2f58dde34867860758d");

#[test]
fn len_128() { check(&K128, &T128, &P128, &C128); }

