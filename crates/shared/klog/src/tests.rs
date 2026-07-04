    use super::*;

    struct VecUart(pub alloc::vec::Vec<u8>);
    extern crate alloc;

    impl Uart for VecUart {
        fn write_byte(&mut self, b: u8) { self.0.push(b); }
    }

    #[test]
    fn levels_are_distinct() {
        assert_ne!(Level::Error as u8, Level::Trace as u8);
    }

    #[test]
    fn macro_expands_and_links() {
        kerror!("error path");
        kinfo!("hello");
        kdebug!("dbg");
    }

    #[test]
    fn uart_default_write_bytes_iterates() {
        let mut u = VecUart(alloc::vec::Vec::new());
        u.write_bytes(b"abc");
        assert_eq!(u.0, b"abc");
    }

    // ---------------------------------------------------------------------
    // Byte-sink tests. The sink is process-global; tests serialize on
    // SINK_SERIAL to keep concurrent `cargo test` honest.
    // ---------------------------------------------------------------------

    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static SINK_SERIAL: Mutex<()> = Mutex::new(());

    static SINK_BYTES: Mutex<alloc::vec::Vec<u8>> = Mutex::new(alloc::vec::Vec::new());
    fn test_sink(bytes: &[u8]) {
        SINK_BYTES.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(bytes);
    }

    fn drain_sink() -> alloc::vec::Vec<u8> {
        let mut g = SINK_BYTES.lock().unwrap_or_else(|e| e.into_inner());
        let out = g.clone();
        g.clear();
        out
    }

    fn lock_sink() -> std::sync::MutexGuard<'static, ()> {
        SINK_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn no_sink_emit_is_noop() {
        let _g = lock_sink();
        clear_byte_sink();
        let _ = drain_sink();
        kinfo!("vanishes without sink");
        assert!(drain_sink().is_empty());
    }

    #[test]
    fn kinfo_with_sink_writes_prefix_message_newline() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        kinfo!("init started");
        let out = drain_sink();
        clear_byte_sink();
        assert_eq!(&out[..], b"[INFO]  init started\n");
    }

    #[test]
    fn each_level_uses_its_own_prefix() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        kerror!("e");
        kwarn!("w");
        kinfo!("i");
        kdebug!("d");
        ktrace!("t");
        let out = drain_sink();
        clear_byte_sink();
        let expected = b"[ERROR] e\n[WARN]  w\n[INFO]  i\n[DEBUG] d\n[TRACE] t\n";
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn clear_byte_sink_stops_emit() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        kinfo!("a");
        clear_byte_sink();
        kinfo!("b");
        let out = drain_sink();
        // Only "a" got through; "b" emitted to the cleared sink.
        assert_eq!(&out[..], b"[INFO]  a\n");
    }

    #[test]
    fn sink_invocations_count() {
        let _g = lock_sink();
        let _ = drain_sink();
        // Replace the sink with one that just counts calls.
        static N: AtomicUsize = AtomicUsize::new(0);
        fn counting(_b: &[u8]) { N.fetch_add(1, Ordering::Relaxed); }
        N.store(0, Ordering::Relaxed);
        set_byte_sink(counting);
        kinfo!("hi");
        clear_byte_sink();
        // Three calls per event: prefix, message, newline.
        assert_eq!(N.load(Ordering::Relaxed), 3);
    }
