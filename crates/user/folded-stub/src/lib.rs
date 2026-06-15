//! folded-stub — empty .so body (docs/59§6 G18a). No symbols; the SONAME and
//! the DT_NEEDED(libc.so.6) that make it a working compatibility shim are set
//! at link time by `xtask folded`. Built no_std/panic=abort so the dynsym is
//! essentially empty.
#![no_std]

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
