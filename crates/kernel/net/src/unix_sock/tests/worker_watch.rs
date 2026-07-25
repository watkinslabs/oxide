use super::*;

// --- udev manager/worker worker_watch repro (SOCK_DGRAM socketpair) ---
//
// systemd-udevd creates ONE SOCK_DGRAM socketpair `worker_watch`: the
// manager epolls the READ end; every forked worker inherits (shares) the
// WRITE end and sends a `struct worker_message` on completion. The manager
// must (a) see POLL_IN and (b) recv EVERY completion. Field symptom: ~11 of
// 14 completions "lost" — manager never registers them. These tests exercise
// the UnixMsgPair (the ring behind worker_watch) directly to see whether the
// ring/poll/recv itself can drop or mis-signal a message.
//
// Mapping to the kernel wiring: manager holds end A (reads b_to_a via
// recv(A)/has_msg(A)); workers hold end B and send(B) (enqueues b_to_a).
// `poll()`'s UnixMsgPair arm is `has_msg(end)`; the blocking read path
// (read_unix_msg_blocking) is `recv(end, max)`.

fn poll_in(p: &UnixMsgPair, end: UnixEnd) -> bool { p.has_msg(end) } // == InetSocket::poll POLL_IN bit

// worker_message is a fixed-size struct in systemd; model it as an 8-byte tag.
fn worker_msg(seqnum: u64) -> [u8; 8] { seqnum.to_le_bytes() }

#[test]
fn worker_watch_single_thread_never_loses_a_completion() {
    // Deterministic single-thread model of manager<-worker completions,
    // including the exact "manager drains to empty, THEN a worker sends
    // again before the manager re-checks" interleaving the report flags.
    let pair = UnixMsgPair::new();
    let mut next_send: u64 = 0;
    let mut next_expect: u64 = 0;

    for round in 0..2000u64 {
        // Each round: a burst of 1..=4 workers finish (send on end B), then
        // the manager drains until has_msg(A) is false. Occasionally a worker
        // sends AFTER the manager saw empty but BEFORE the loop re-checks —
        // modeled by sending again next round without draining in between.
        let burst = 1 + (round % 4);
        for _ in 0..burst {
            let n = pair.send(UnixEnd::B, &worker_msg(next_send));
            assert_eq!(n, Ok(8), "send must enqueue the whole worker_message");
            next_send += 1;
        }

        // The manager only drains on ~3 of every 4 rounds; on the 4th it
        // leaves the queue and lets the next burst pile on top (drain-late).
        if round % 4 != 3 {
            // POLL_IN must be set the instant a message is enqueued.
            assert!(poll_in(&pair, UnixEnd::A),
                "round {round}: manager must see POLL_IN with {} queued", next_send - next_expect);
            while poll_in(&pair, UnixEnd::A) {
                let got = pair.recv(UnixEnd::A, 64)
                    .unwrap_or_else(|| panic!("round {round}: has_msg==true but recv None (lost wake/msg)"));
                assert_eq!(got.len(), 8, "round {round}: truncated completion");
                let seq = u64::from_le_bytes(got[..8].try_into().unwrap());
                assert_eq!(seq, next_expect,
                    "round {round}: completion out of order / dropped — expected {next_expect} got {seq}");
                next_expect += 1;
            }
            // After draining, poll must be false AND recv must be None.
            assert!(!poll_in(&pair, UnixEnd::A), "round {round}: POLL_IN stuck after drain");
            assert!(pair.recv(UnixEnd::A, 64).is_none(), "round {round}: recv non-None after drain");
        }
    }
    // Final flush of any drain-late remainder.
    while let Some(got) = pair.recv(UnixEnd::A, 64) {
        let seq = u64::from_le_bytes(got[..8].try_into().unwrap());
        assert_eq!(seq, next_expect, "final flush: out of order");
        next_expect += 1;
    }
    assert_eq!(next_expect, next_send, "every completion must be received exactly once");
}

#[test]
fn worker_watch_concurrent_workers_no_completion_lost() {
    // N worker threads all share end B (as forked udev workers share the
    // inherited worker_watch WRITE fd) and each sends M completions. A
    // single manager thread drains end A via poll_in()+recv(), exactly like
    // the epoll_wait/recvmsg loop. Assert the manager receives every one of
    // N*M completions — none lost, none duplicated — across the run.
    use std::sync::atomic::AtomicBool;
    use std::thread;

    const WORKERS: u64 = 14; // udev default worker cap in the field trace
    const PER_WORKER: u64 = 5000;
    let total = WORKERS * PER_WORKER;

    for trial in 0..20u64 {
        let pair = UnixMsgPair::new();
        // Move an Arc into each thread.
        let pair = std::sync::Arc::new(pair);
        let done = std::sync::Arc::new(AtomicBool::new(false));

        let mut handles = std::vec::Vec::new();
        for w in 0..WORKERS {
            let p = pair.clone();
            handles.push(thread::spawn(move || {
                for i in 0..PER_WORKER {
                    // payload encodes worker id + seq so we can detect dup/loss
                    let tag = (w << 40) | i;
                    let n = p.send(UnixEnd::B, &tag.to_le_bytes());
                    assert_eq!(n, Ok(8));
                    // yield sometimes to widen the enqueue/drain race window
                    if i % 64 == 0 { thread::yield_now(); }
                }
            }));
        }

        // Manager thread: drain until all workers finished AND queue empty.
        let p = pair.clone();
        let d = done.clone();
        let mgr = thread::spawn(move || {
            let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
            loop {
                let mut drained_any = false;
                // Model the manager: only recv when poll says readable.
                while poll_in(&p, UnixEnd::A) {
                    match p.recv(UnixEnd::A, 64) {
                        Some(got) => {
                            assert_eq!(got.len(), 8);
                            let tag = u64::from_le_bytes(got[..8].try_into().unwrap());
                            assert!(seen.insert(tag), "DUPLICATE completion {tag:#x}");
                            drained_any = true;
                        }
                        None => {
                            // poll said readable but recv empty: the exact
                            // "lost/mis-signaled" failure. Record & fail.
                            panic!("poll_in==true but recv None (phantom readable / lost msg)");
                        }
                    }
                }
                if d.load(std::sync::atomic::Ordering::Acquire) && !poll_in(&p, UnixEnd::A) && !drained_any {
                    break;
                }
                std::thread::yield_now();
            }
            seen.len() as u64
        });

        for h in handles { h.join().unwrap(); }
        done.store(true, std::sync::atomic::Ordering::Release);
        let received = mgr.join().unwrap();
        assert_eq!(received, total,
            "trial {trial}: manager lost completions — received {received} of {total}");
    }
}

