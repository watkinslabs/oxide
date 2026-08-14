// Module manifest: random owns get_random_bytes/device entropy; crc owns Linux
// CRC helper exports; shash owns crypto_shash allocation and digest operations;
// ffdhe owns named finite-field parameters; kpp owns KPP transform ABI.

mod crc;
mod ffdhe;
mod kpp;
mod random;
mod shash;

/// Register Linux crypto/random/CRC KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    crc::export_symbols();
    kpp::export_symbols();
    random::export_symbols();
    shash::export_symbols();
}
