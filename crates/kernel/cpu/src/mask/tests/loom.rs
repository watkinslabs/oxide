use core::sync::atomic::Ordering;

use loom::sync::{Arc, Condvar, Mutex};
use loom::sync::atomic::{fence, AtomicBool, AtomicU64, AtomicUsize};
use loom::thread;

use super::super::latch::{self, Event, NoObserve, Observe, Storage};

const WORDS: usize = 4;
const OLD: [u64; WORDS] = [0xaaaa, 0x1111, 0xcccc, 0x3333];
const NEW: [u64; WORDS] = [0xbbbb, 0x2222, 0xdddd, 0x4444];
const OTHER: [u64; WORDS] = [0xeeee, 0x5555, 0xffff, 0x6666];

fn model(body: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(8);
    builder.max_branches = 100_000;
    builder.check(body);
}

struct ModelMask<const N: usize> {
    seq: AtomicU64,
    words: [[AtomicU64; N]; 2],
    writer: AtomicBool,
}

struct Signal {
    ready: Mutex<bool>,
    changed: Condvar,
}

impl Signal {
    fn new() -> Self { Self { ready: Mutex::new(false), changed: Condvar::new() } }
    fn publish(&self) {
        *self.ready.lock().unwrap() = true;
        self.changed.notify_all();
    }
    fn wait(&self) {
        let mut ready = self.ready.lock().unwrap();
        while !*ready { ready = self.changed.wait(ready).unwrap(); }
    }
}

impl<const N: usize> ModelMask<N> {
    fn new(seq: u64, words: [u64; N]) -> Self {
        Self {
            seq: AtomicU64::new(seq),
            words: core::array::from_fn(|_| core::array::from_fn(|i| AtomicU64::new(words[i]))),
            writer: AtomicBool::new(false),
        }
    }
}

impl<const N: usize> Storage<N> for ModelMask<N> {
    fn seq_load(&self, order: Ordering) -> u64 { self.seq.load(order) }
    fn seq_add(&self, value: u64, order: Ordering) { self.seq.fetch_add(value, order); }
    fn word_load(&self, copy: usize, word: usize, order: Ordering) -> u64 {
        self.words[copy][word].load(order)
    }
    fn word_store(&self, copy: usize, word: usize, value: u64, order: Ordering) {
        self.words[copy][word].store(value, order);
    }
    fn writer_lock(&self, current: bool, new: bool, success: Ordering, failure: Ordering) -> bool {
        self.writer.compare_exchange(current, new, success, failure).is_ok()
    }
    fn writer_store(&self, value: bool, order: Ordering) { self.writer.store(value, order); }
    fn fence(&self, order: Ordering) { fence(order); }
    fn relax(&self) { thread::yield_now(); }
}

struct ReadPause {
    cut: usize,
    reached: Arc<AtomicBool>,
    resume: Arc<AtomicBool>,
    retries: Arc<AtomicUsize>,
}

impl Observe for ReadPause {
    fn event(&self, event: Event) {
        match event {
            Event::ReadWord(word) if word == self.cut => {
                self.reached.store(true, Ordering::Release);
                while !self.resume.load(Ordering::Acquire) { thread::yield_now(); }
            }
            Event::Retry => { self.retries.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }
}

struct RedirectPause {
    target: usize,
    reached: Arc<AtomicBool>,
    resume: Arc<AtomicBool>,
}

struct WriterPause {
    reached: Arc<Signal>,
    resume: Arc<Signal>,
}

impl Observe for WriterPause {
    fn event(&self, event: Event) {
        if event == Event::Redirect(0) {
            self.reached.publish();
            self.resume.wait();
        }
    }
}

struct BusySignal {
    busy: Arc<Signal>,
    first_done: Arc<Signal>,
}

impl Observe for BusySignal {
    fn event(&self, event: Event) {
        if event == Event::WriterBusy {
            self.busy.publish();
            self.first_done.wait();
        }
    }
}

impl Observe for RedirectPause {
    fn event(&self, event: Event) {
        if event == Event::Redirect(self.target) {
            self.reached.store(true, Ordering::Release);
            while !self.resume.load(Ordering::Acquire) { thread::yield_now(); }
        }
    }
}

#[test]
fn unconstrained_reader_writer_memory_order_is_coherent() {
    model(|| {
        const BEFORE: [u64; 2] = [0xaaaa, 0x1111];
        const AFTER: [u64; 2] = [0xbbbb, 0x2222];
        let mask = Arc::new(ModelMask::new(0, BEFORE));
        let writing = Arc::clone(&mask);
        let writer = thread::spawn(move || {
            latch::replace(&*writing, AFTER, Ordering::Release, &NoObserve);
        });
        let reading = Arc::clone(&mask);
        let reader = thread::spawn(move || latch::load(&*reading, Ordering::Acquire, &NoObserve));
        writer.join().unwrap();
        let seen = reader.join().unwrap();
        assert!(seen == BEFORE || seen == AFTER,
            "latch memory ordering admitted a mixed generation");
    });
}

#[test]
fn two_concurrent_writers_serialize_complete_generations() {
    model(|| {
        let mask = Arc::new(ModelMask::new(0, OLD));
        let first_paused = Arc::new(Signal::new());
        let first_resume = Arc::new(Signal::new());
        let first_done = Arc::new(Signal::new());
        let first = Arc::clone(&mask);
        let pause_reached = Arc::clone(&first_paused);
        let pause_resume = Arc::clone(&first_resume);
        let write_done = Arc::clone(&first_done);
        let writer_a = thread::spawn(move || {
            latch::replace(&*first, NEW, Ordering::Release,
                &WriterPause { reached: pause_reached, resume: pause_resume });
            write_done.publish();
        });
        first_paused.wait();
        let second_busy = Arc::new(Signal::new());
        let second = Arc::clone(&mask);
        let busy = Arc::clone(&second_busy);
        let done = Arc::clone(&first_done);
        let writer_b = thread::spawn(move || {
            latch::replace(&*second, OTHER, Ordering::Release,
                &BusySignal { busy, first_done: done });
        });
        second_busy.wait();
        first_resume.publish();
        writer_a.join().unwrap();
        writer_b.join().unwrap();
        let final_words = latch::load(&*mask, Ordering::Acquire, &NoObserve);
        assert_eq!(final_words, OTHER,
            "second colliding writer did not publish one complete generation");
    });
}

#[test]
fn reader_interruption_after_every_word_retries_to_one_generation() {
    for cut in 0..WORDS {
        model(move || {
            let mask = Arc::new(ModelMask::new(0, OLD));
            let reached = Arc::new(AtomicBool::new(false));
            let resume = Arc::new(AtomicBool::new(false));
            let retries = Arc::new(AtomicUsize::new(0));
            let reading = Arc::clone(&mask);
            let read_reached = Arc::clone(&reached);
            let read_resume = Arc::clone(&resume);
            let read_retries = Arc::clone(&retries);
            let reader = thread::spawn(move || latch::load(&*reading, Ordering::Acquire,
                &ReadPause { cut, reached: read_reached, resume: read_resume,
                    retries: read_retries }));
            while !reached.load(Ordering::Acquire) { thread::yield_now(); }
            latch::replace(&*mask, NEW, Ordering::Release, &NoObserve);
            resume.store(true, Ordering::Release);
            assert_eq!(reader.join().unwrap(), NEW);
            assert!(retries.load(Ordering::Relaxed) > 0,
                "reader interruption did not exercise sequence retry");
        });
    }
}

fn redirected_reader(target: usize, expected: [u64; WORDS]) {
    model(move || {
        let mask = Arc::new(ModelMask::new(0, OLD));
        let reached = Arc::new(AtomicBool::new(false));
        let resume = Arc::new(AtomicBool::new(false));
        let writing = Arc::clone(&mask);
        let write_reached = Arc::clone(&reached);
        let write_resume = Arc::clone(&resume);
        let writer = thread::spawn(move || latch::replace(&*writing, NEW, Ordering::Release,
            &RedirectPause { target, reached: write_reached, resume: write_resume }));
        while !reached.load(Ordering::Acquire) { thread::yield_now(); }
        let seen = latch::load(&*mask, Ordering::Acquire, &NoObserve);
        assert_eq!(seen, expected);
        resume.store(true, Ordering::Release);
        writer.join().unwrap();
    });
}

#[test]
fn first_redirect_sends_interrupted_reader_to_old_odd_copy() {
    redirected_reader(0, OLD);
}

#[test]
fn second_redirect_sends_interrupted_reader_to_new_even_copy() {
    redirected_reader(1, NEW);
}

#[test]
fn sequence_wrap_forces_retry_and_preserves_generation() {
    model(|| {
        let mask = Arc::new(ModelMask::new(u64::MAX - 1, OLD));
        let reached = Arc::new(AtomicBool::new(false));
        let resume = Arc::new(AtomicBool::new(false));
        let retries = Arc::new(AtomicUsize::new(0));
        let reading = Arc::clone(&mask);
        let read_reached = Arc::clone(&reached);
        let read_resume = Arc::clone(&resume);
        let read_retries = Arc::clone(&retries);
        let reader = thread::spawn(move || latch::load(&*reading, Ordering::Acquire,
            &ReadPause { cut: 0, reached: read_reached, resume: read_resume,
                retries: read_retries }));
        while !reached.load(Ordering::Acquire) { thread::yield_now(); }
        latch::replace(&*mask, NEW, Ordering::Release, &NoObserve);
        assert_eq!(mask.seq.load(Ordering::Relaxed), 0);
        resume.store(true, Ordering::Release);
        assert_eq!(reader.join().unwrap(), NEW);
        assert!(retries.load(Ordering::Relaxed) > 0,
            "wrapped sequence did not invalidate the interrupted read");
    });
}

#[test]
fn positive_control_unsequenced_writer_returns_a_torn_mask() {
    model(|| {
        let mask = Arc::new(ModelMask::new(0, OLD));
        let low_done = Arc::new(AtomicBool::new(false));
        let read_done = Arc::new(AtomicBool::new(false));
        let writing = Arc::clone(&mask);
        let write_low_done = Arc::clone(&low_done);
        let write_read_done = Arc::clone(&read_done);
        let writer = thread::spawn(move || {
            writing.word_store(0, 0, NEW[0], Ordering::Relaxed);
            write_low_done.store(true, Ordering::Release);
            while !write_read_done.load(Ordering::Acquire) { thread::yield_now(); }
            for word in 1..WORDS {
                writing.word_store(0, word, NEW[word], Ordering::Relaxed);
            }
        });
        while !low_done.load(Ordering::Acquire) { thread::yield_now(); }
        let torn = latch::load(&*mask, Ordering::Acquire, &NoObserve);
        read_done.store(true, Ordering::Release);
        writer.join().unwrap();
        assert_eq!(torn, [NEW[0], OLD[1], OLD[2], OLD[3]],
            "positive control did not expose the unsequenced torn read");
    });
}
