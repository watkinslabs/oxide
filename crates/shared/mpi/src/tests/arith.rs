// Import/export, ordering, and the four arithmetic primitives.

use super::{hex, to_hex};
use crate::Mpi;

// A big-endian import drops leading zero bytes: the value's reported size must
// describe the NUMBER, not the width the sender padded it to. Diffie-Hellman
// reports its output length from exactly this size, so a prime sent with a
// leading zero byte must not inflate the answer by a limb.
#[test]
fn import_strips_leading_zero_bytes() {
    let padded = Mpi::from_be_bytes(&[0, 0, 0, 1]);
    assert_eq!(padded, Mpi::from_u64(1));
    assert_eq!(padded.limbs(), 1);
    assert_eq!(Mpi::from_be_bytes(&[0, 0, 0]), Mpi::zero());
    assert_eq!(Mpi::from_be_bytes(&[]), Mpi::zero());
}

// Export is fixed-width and left-zero-padded, and refuses a width the value
// does not fit in rather than truncating it.
#[test]
fn export_pads_left_and_refuses_truncation() {
    let v = hex("0102030405060708090a");
    assert_eq!(v.byte_len(), 10);
    assert_eq!(v.limb_size(), 16, "two limbs hold ten bytes");
    assert_eq!(v.to_be_bytes(12).expect("fits"),
        alloc::vec![0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a]);
    assert_eq!(v.to_be_bytes(10).expect("exact"),
        alloc::vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a]);
    assert!(v.to_be_bytes(9).is_none(), "narrower than the value is not a truncation");
    assert_eq!(Mpi::zero().to_be_bytes(4).expect("fits"), alloc::vec![0, 0, 0, 0]);
}

#[test]
fn bit_length_and_bit_access() {
    assert_eq!(Mpi::zero().bit_len(), 0);
    assert_eq!(Mpi::from_u64(1).bit_len(), 1);
    assert_eq!(Mpi::from_u64(u64::MAX).bit_len(), 64);
    let v = hex("010000000000000000"); // 2^64
    assert_eq!(v.bit_len(), 65);
    assert!(v.bit(64));
    assert!(!v.bit(63));
    assert!(!v.bit(1000), "a bit past the top is zero, not a panic");
}

#[test]
fn ordering_is_by_magnitude() {
    assert!(hex("ff") < hex("0100"));
    assert!(hex("ffffffffffffffff") < hex("010000000000000000"));
    assert_eq!(hex("00ff"), hex("ff"));
    assert!(Mpi::zero() < Mpi::from_u64(1));
}

#[test]
fn add_and_sub_round_trip_across_a_limb_boundary() {
    let a = hex("ffffffffffffffff");
    let b = Mpi::from_u64(1);
    let s = a.add(&b);
    assert_eq!(to_hex(&s), "10000000000000000");
    assert_eq!(s.checked_sub(&b).expect("no borrow"), a);
    assert!(b.checked_sub(&a).is_none(), "a negative result has no representation");
    assert_eq!(a.checked_sub(&a).expect("zero"), Mpi::zero());
}

#[test]
fn multiplication_known_answers() {
    assert_eq!(to_hex(&hex("ffffffffffffffff").mul(&hex("ffffffffffffffff"))),
        "fffffffffffffffe0000000000000001");
    assert_eq!(hex("deadbeef").mul(&Mpi::zero()), Mpi::zero());
    // 2^128 - 1 squared.
    assert_eq!(to_hex(&hex("ffffffffffffffffffffffffffffffff").mul(&hex("ffffffffffffffffffffffffffffffff"))),
        "fffffffffffffffffffffffffffffffe00000000000000000000000000000001");
}

#[test]
fn shifts_move_whole_and_partial_limbs() {
    let v = Mpi::from_u64(1);
    assert_eq!(to_hex(&v.shl(64)), "10000000000000000");
    assert_eq!(to_hex(&v.shl(65)), "20000000000000000");
    assert_eq!(v.shl(64).shr(64), v);
    assert_eq!(hex("ff").shr(4), Mpi::from_u64(0xf));
    assert_eq!(hex("ff").shr(1000), Mpi::zero());
}

#[test]
fn division_by_zero_is_absent_not_a_trap() {
    assert!(hex("ff").divmod(&Mpi::zero()).is_none());
    assert!(hex("ff").rem(&Mpi::zero()).is_none());
}

#[test]
fn single_limb_division() {
    let (q, r) = hex("0123456789abcdef0123456789abcdef").divmod(&Mpi::from_u64(0x1_0000_0000)).expect("nonzero");
    assert_eq!(to_hex(&q), "123456789abcdef01234567");
    assert_eq!(to_hex(&r), "89abcdef");
    let (q, r) = hex("64").divmod(&Mpi::from_u64(7)).expect("nonzero");
    assert_eq!((to_hex(&q), to_hex(&r)), ("e".into(), "2".into()));
}

// The dividend smaller than the divisor is quotient 0, remainder dividend —
// the case modular reduction hits on nearly every step.
#[test]
fn division_smaller_dividend() {
    let (q, r) = hex("ff").divmod(&hex("0100")).expect("nonzero");
    assert!(q.is_zero());
    assert_eq!(r, hex("ff"));
}

// Multi-limb division, including the shape that drives the trial-digit
// correction: a divisor whose top limb is just above half the base.
#[test]
fn multi_limb_division_known_answers() {
    let a = hex("100000000000000000000000000000000"); // 2^128
    let b = hex("0ffffffffffffffff");                 // 2^64 - 1
    let (q, r) = a.divmod(&b).expect("nonzero");
    assert_eq!(to_hex(&q), "10000000000000001");
    assert_eq!(to_hex(&r), "1");

    let a = hex("fffffffffffffffffffffffffffffffffffffffffffffffe");
    let b = hex("800000000000000000000001");
    let (q, r) = a.divmod(&b).expect("nonzero");
    assert_eq!(to_hex(&q), "1fffffffffffffffffffffffc");
    assert_eq!(to_hex(&r), "2");
}

// Reconstruct the dividend from quotient and remainder over a spread of sizes:
// the identity a == q*b + r with r < b is what every modular reduction relies
// on, and it is the check that catches an add-back the loop got wrong.
#[test]
fn division_identity_holds_over_many_shapes() {
    let seeds: [&str; 6] = [
        "ffffffffffffffffffffffffffffffffffffffff",
        "8000000000000000000000000000000000000000000000000000000000000001",
        "0123456789abcdeffedcba9876543210",
        "ffffffffffffffff0000000000000000ffffffffffffffff",
        "1",
        "10000000000000000000000000000000000000000000000000000000000000000",
    ];
    let divisors: [&str; 5] = [
        "ffffffffffffffff",
        "10000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "8000000000000000000000000000000000000001",
        "3",
    ];
    for s in seeds {
        for d in divisors {
            let (a, b) = (hex(s), hex(d));
            let (q, r) = a.divmod(&b).expect("nonzero divisor");
            assert!(r < b, "remainder below divisor for {s} / {d}");
            assert_eq!(q.mul(&b).add(&r), a, "q*b + r == a for {s} / {d}");
        }
    }
}
