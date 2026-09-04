use core::sync::atomic::Ordering;

pub(super) trait Storage<const N: usize> {
    fn seq_load(&self, order: Ordering) -> u64;
    fn seq_add(&self, value: u64, order: Ordering);
    fn word_load(&self, copy: usize, word: usize, order: Ordering) -> u64;
    fn word_store(&self, copy: usize, word: usize, value: u64, order: Ordering);
    fn writer_lock(&self, current: bool, new: bool, success: Ordering, failure: Ordering) -> bool;
    fn writer_store(&self, value: bool, order: Ordering);
    fn fence(&self, order: Ordering);
    fn relax(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    ReadWord(usize),
    Redirect(usize),
    WriteWord(usize, usize),
    WriterBusy,
    Retry,
}

pub(super) trait Observe {
    fn event(&self, _event: Event) {}
}

pub(super) struct NoObserve;
impl Observe for NoObserve {}

fn read_order(order: Ordering) -> Ordering {
    if matches!(order, Ordering::SeqCst) { Ordering::SeqCst } else { Ordering::Acquire }
}

fn write_order(order: Ordering) -> Ordering {
    if matches!(order, Ordering::SeqCst) { Ordering::SeqCst } else { Ordering::Release }
}

pub(super) fn load<const N: usize, S: Storage<N>, O: Observe>(
    storage: &S, order: Ordering, observe: &O,
) -> [u64; N] {
    loop {
        let before = storage.seq_load(read_order(order));
        let copy = (before & 1) as usize;
        let mut words = [0; N];
        let mut i = 0;
        while i < N {
            words[i] = storage.word_load(copy, i, Ordering::Relaxed);
            observe.event(Event::ReadWord(i));
            i += 1;
        }
        storage.fence(Ordering::Acquire);
        let after = storage.seq_load(Ordering::Relaxed);
        if before == after { return words; }
        observe.event(Event::Retry);
        storage.relax();
    }
}

pub(super) fn lock<const N: usize, S: Storage<N>, O: Observe>(storage: &S, observe: &O) {
    while !storage.writer_lock(false, true, Ordering::Acquire, Ordering::Relaxed) {
        observe.event(Event::WriterBusy);
        storage.relax();
    }
}

pub(super) fn unlock<const N: usize, S: Storage<N>>(storage: &S, order: Ordering) {
    storage.writer_store(false, write_order(order));
}

pub(super) fn active<const N: usize, S: Storage<N>>(storage: &S) -> [u64; N] {
    let copy = (storage.seq_load(Ordering::Relaxed) & 1) as usize;
    let mut words = [0; N];
    let mut i = 0;
    while i < N {
        words[i] = storage.word_load(copy, i, Ordering::Relaxed);
        i += 1;
    }
    words
}

fn redirect<const N: usize, S: Storage<N>, O: Observe>(
    storage: &S, redirect: usize, observe: &O,
) {
    storage.fence(Ordering::Release);
    storage.seq_add(1, Ordering::AcqRel);
    storage.fence(Ordering::Release);
    observe.event(Event::Redirect(redirect));
}

fn write_copy<const N: usize, S: Storage<N>, O: Observe>(
    storage: &S, copy: usize, words: [u64; N], observe: &O,
) {
    let mut i = 0;
    while i < N {
        storage.word_store(copy, i, words[i], Ordering::Relaxed);
        observe.event(Event::WriteWord(copy, i));
        i += 1;
    }
}

pub(super) fn replace_locked<const N: usize, S: Storage<N>, O: Observe>(
    storage: &S, words: [u64; N], observe: &O,
) {
    redirect(storage, 0, observe);
    write_copy(storage, 0, words, observe);
    redirect(storage, 1, observe);
    write_copy(storage, 1, words, observe);
}

pub(super) fn replace<const N: usize, S: Storage<N>, O: Observe>(
    storage: &S, words: [u64; N], order: Ordering, observe: &O,
) {
    lock(storage, observe);
    replace_locked(storage, words, observe);
    unlock(storage, order);
}
