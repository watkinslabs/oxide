use syscall::nt_native_gdi as abi;

#[test]
fn real_callback_entry_preserves_query_failure_dword_and_pthread_tls() {
    std::thread::spawn(|| {
        std::thread_local! { static TLS: std::cell::Cell<u32> = const { std::cell::Cell::new(91) }; }
        let (entry, _) = super::platform::entries();
        #[cfg(target_arch = "x86_64")]
        type Entry = unsafe extern "win64" fn(*const abi::QueryRequest) -> u64;
        #[cfg(target_arch = "aarch64")]
        type Entry = unsafe extern "C" fn(*const abi::QueryRequest) -> u64;
        // SAFETY: production entry has this architecture's native callback argument/result ABI.
        let callback: Entry = unsafe { std::mem::transmute(entry as usize) };
        let req = abi::QueryRequest { version: 0, size: 80, dc: 1, kind: abi::QUERY_DATA,
            flags: 0, height: 16, width: 0, weight: 400, italic: 0, first: 0, count: 0,
            input: 0, output: 0, table: 0, offset: 0, capacity: 0, reserved: 0 };
        for (kind, expected) in [(abi::QUERY_DATA, u32::MAX as u64), (abi::QUERY_GLYPHS, u32::MAX as u64),
            (abi::QUERY_CHARSET, 1), (abi::QUERY_ABC, 0), (abi::QUERY_OUTLINE, 0)] {
            let req = abi::QueryRequest { kind, ..req };
            // SAFETY: initialized header intentionally fails version validation before usercopy/FFI.
            assert_eq!(unsafe { callback(&req) }, expected);
            TLS.with(|slot| assert_eq!(slot.get(), 91));
        }
    }).join().unwrap();
}
