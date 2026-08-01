// Hosted tests for the asymmetric-key material.
//
// Module manifest:
// - fixtures: the key material every test works from.
// - der:      the decoder's well-formedness rules.
// - parse:    certificate / PKCS#8 parsing and the name it proposes.
// - ops:      query, encrypt/decrypt, sign/verify — known answers and the
//             error each malformed request produces.

mod der;
mod fixtures;
mod ops;
mod parse;
