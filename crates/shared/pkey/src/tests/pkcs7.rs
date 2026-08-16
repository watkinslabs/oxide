// Detached SignedData signatures, driven against signatures a real signer
// produced.
//
// Module manifest:
// - fixtures: the certificates, the payload and the three signature shapes.
// - parse:    what the decoder reads out of a message, and what it refuses.
// - verify:   the digest a signature is over, and the tamper cases.
// - trust:    which chains reach a store and which do not.

#[path = "pkcs7/fixtures.rs"] mod fixtures;
#[path = "pkcs7/parse.rs"] mod parse;
#[path = "pkcs7/verify.rs"] mod verify;
#[path = "pkcs7/trust.rs"] mod trust;
