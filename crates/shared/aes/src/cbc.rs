// CBC and CBC with ciphertext stealing, over AES.
//
// The mode is written once, generically, in `blockcipher`: SM4 takes exactly
// the same construction, and the stealing convention is the kind of detail two
// copies drift apart on without any test noticing — each copy decrypts its own
// output perfectly. This module is the AES-named view of it, kept so callers
// spell the pairing as `aes::cbc` rather than naming the cipher twice.
//
// The functions are generic; passing an `&AesKey` is what makes them AES.

pub use blockcipher::cbc::{cts_decrypt, cts_encrypt, decrypt, encrypt, CbcError};
