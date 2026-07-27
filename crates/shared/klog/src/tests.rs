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

    // ---------------------------------------------------------------------
    // Console serialisation (B1433). Without the console lock, concurrent
    // emitters interleave at byte granularity and splice each other's tokens
    // — the defect that corrupted boot captures with impossible timestamps.
    // ---------------------------------------------------------------------

    /// Each thread writes lines built from a single distinct character. Any
    /// line containing two different characters is proof of a spliced write.
    #[test]
    fn concurrent_emitters_do_not_splice_lines() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        // A clock thunk is required: without it `emit_bytes` takes the
        // single-call early-return path, where the sink write is already
        // indivisible and no splicing is possible. The defect lives in the
        // line-assembly loop (shared LINE_START + a separate timestamp emit),
        // which only runs once a clock is installed.
        set_clock_fn(|| 0);

        const THREADS: usize = 8;
        const LINES: usize = 200;
        const WIDTH: usize = 48;
        std::thread::scope(|s| {
            for t in 0..THREADS {
                s.spawn(move || {
                    // Uppercase, and a fixed width: the byte sink is
                    // process-global and other tests emit lowercase prose
                    // concurrently, so the marker space must not overlap.
                    let c = b'A' + t as u8;
                    let mut line = [c; WIDTH + 1];
                    line[WIDTH] = b'\n';
                    for _ in 0..LINES { write_raw(&line); }
                });
            }
        });

        clear_clock_fn();
        clear_byte_sink();
        let out = drain_sink();
        let mut lines = 0usize;
        for line in out.split(|b| *b == b'\n') {
            let payload: alloc::vec::Vec<u8> =
                line.iter().copied().filter(|b| b.is_ascii_uppercase()).collect();
            if payload.len() != WIDTH { continue; }
            lines += 1;
            let first = payload[0];
            assert!(
                payload.iter().all(|b| *b == first),
                "spliced line: two emitters interleaved within one line"
            );
            // The real corruption signature. LINE_START and the timestamp emit
            // are separate steps, so unserialised CPUs produce either a line
            // carrying two stamps (`[0.000][0.000] AAA`) or a line carrying
            // none (a peer consumed the LINE_START token). Exactly one is the
            // only correct outcome, and it is what the boot-log capture was
            // silently getting wrong.
            let stamps = line.iter().filter(|b| **b == b']').count();
            assert_eq!(
                stamps, 1,
                "line has {stamps} timestamps, expected exactly 1 — emitters raced LINE_START"
            );
        }
        assert!(lines >= THREADS, "expected every emitter's output present");
    }

    /// The lock must never deadlock against a nested emit on the same CPU:
    /// a sink that itself logs is a real pattern (fbcon diagnostics), and a
    /// non-reentrant lock would hang the machine instead of the log.
    #[test]
    fn nested_emit_from_sink_does_not_deadlock() {
        let _g = lock_sink();
        let _ = drain_sink();
        static DEPTH: AtomicUsize = AtomicUsize::new(0);
        fn reentrant(_b: &[u8]) {
            if DEPTH.fetch_add(1, Ordering::Relaxed) == 0 { write_raw(b"nested\n"); }
        }
        DEPTH.store(0, Ordering::Relaxed);
        set_cpu_fn(|| 0);
        set_byte_sink(reentrant);
        write_raw(b"outer\n");
        clear_byte_sink();
        clear_cpu_fn();
        assert!(DEPTH.load(Ordering::Relaxed) >= 2, "nested emit did not run");
    }
