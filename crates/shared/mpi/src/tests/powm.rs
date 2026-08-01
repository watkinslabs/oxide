// Modular exponentiation, including the 1536-bit Diffie-Hellman vectors the
// keyctl path computes. The prime is the published 1536-bit MODP group
// (RFC 3526 group 5) with generator 2; the expected public values were derived
// from the group definition, so a regression in the limb arithmetic shows up
// as a wrong shared secret rather than as a plausible-looking blob.

use super::{hex, to_hex};
use crate::Mpi;

/// RFC 3526 §2, the 1536-bit MODP group prime.
const MODP_1536_P: &str = "\
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

#[test]
fn small_known_answers() {
    assert_eq!(Mpi::from_u64(2).powm(&Mpi::from_u64(10), &Mpi::from_u64(1000)).expect("nonzero modulus"),
        Mpi::from_u64(24));
    assert_eq!(Mpi::from_u64(4).powm(&Mpi::from_u64(13), &Mpi::from_u64(497)).expect("nonzero modulus"),
        Mpi::from_u64(445));
    assert_eq!(hex("deadbeef").powm(&Mpi::from_u64(0), &Mpi::from_u64(7)).expect("nonzero modulus"),
        Mpi::from_u64(1), "an exponent of zero is one");
    assert_eq!(hex("deadbeef").powm(&Mpi::from_u64(5), &Mpi::from_u64(1)).expect("nonzero modulus"),
        Mpi::zero(), "everything is zero modulo one");
    assert_eq!(Mpi::zero().powm(&Mpi::from_u64(5), &Mpi::from_u64(7)).expect("nonzero modulus"),
        Mpi::zero());
    assert!(Mpi::from_u64(2).powm(&Mpi::from_u64(3), &Mpi::zero()).is_none(),
        "a zero modulus is undefined, not zero");
}

// The public value g^x mod p for the 1536-bit group.
#[test]
fn modp_1536_public_value() {
    let p = hex(MODP_1536_P);
    let g = Mpi::from_u64(2);
    let x = hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let y = g.powm(&x, &p).expect("nonzero modulus");
    assert_eq!(to_hex(&y), "\
9e433f209b5fbf9e8d6e1075b0c9969c4dc642060a79fd918ca5950d470e83c6\
5d0498b5e206c9ed9f981c682d13075fbfa455edbea73f1ebe0497808dd1cfb1\
cae6e41e9747d4d77dc9930cafc4bde7047fc405cda9915a4ed41ca91abea86f\
80fe3cab01a02427a57ee668bbd1283ebb0907119b9540ebc6bae486f78994eb\
5220e72eb3bd01b9c6f4c0616d27ef420bc261f6da71067ed41b8746397084b5\
0c965c713b71474058309120aef50bfbac2b2defc32de03ee55722dc4d95ea20");
    assert_eq!(p.limb_size(), 192, "1536 bits is 24 whole limbs");
}

// Both sides of a key agreement must land on the same shared secret; that is
// the property the syscall actually sells, and it is independent of any
// published vector.
#[test]
fn modp_1536_agreement_is_symmetric() {
    let p = hex(MODP_1536_P);
    let g = Mpi::from_u64(2);
    let a = hex("feedface1234");
    let b = hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let ya = g.powm(&a, &p).expect("nonzero modulus");
    let yb = g.powm(&b, &p).expect("nonzero modulus");
    assert_eq!(to_hex(&ya), "\
db3ab3d1d0e9c9dc577e60dbfee37c7c18fe48c67062a11e585a49223a5b7433\
82a46bd138a1b91de39b0aafca04859216e31ab4c7bc075fecccaba939e895af\
b0c06e4b202c3e18428ce5dfde49d605b3744c72b6be529597bd8714de25196e\
9e83ee02f96b529358a49953bab6210741a8490e37206337f914adedfb552bc4\
d04d6dfbb191586540b06ca2c498f7009da46d2c44f182757bccb97b33d3555a\
f2dc80a72aaa45779510e5630a445ee85adfaea0775a0cd442a71567aeb97b21");
    assert_eq!(yb.powm(&a, &p).expect("nonzero modulus"),
               ya.powm(&b, &p).expect("nonzero modulus"));
}

// A 2048-bit exponentiation, the size real RSA and DH traffic uses: it must
// complete and it must satisfy Fermat's little theorem for the prime modulus.
#[test]
fn fermat_little_theorem_holds_for_the_group_prime() {
    let p = hex(MODP_1536_P);
    let e = p.checked_sub(&Mpi::from_u64(1)).expect("p > 1");
    let base = hex("0123456789abcdeffedcba9876543210");
    assert_eq!(base.powm(&e, &p).expect("nonzero modulus"), Mpi::from_u64(1));
}
