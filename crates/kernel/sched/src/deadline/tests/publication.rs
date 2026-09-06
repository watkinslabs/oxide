use super::*;
use core::cell::Cell;

std::thread_local! {
    static OPEN: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn check_reader(entity: &DlEntity) {
    let address = Arc::as_ptr(&entity.inner) as usize;
    assert!(!OPEN.with(|open| open.get() == address),
        "deadline snapshot reentered its interrupted odd-sequence writer");
}

impl DlEntity {
    pub(crate) fn publication_generation(&self) -> u64 {
        self.inner.seq.load(Ordering::Acquire)
    }
    /// Model a reader interrupting this entity's writer without hanging tests.
    pub(crate) fn with_interrupted_publication<R>(&self, f: impl FnOnce() -> R) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                OPEN.with(|open| open.set(0));
            }
        }
        assert!(OPEN.with(|open| open.get() == 0));
        let _publication = self.inner.write_begin();
        OPEN.with(|open| open.set(Arc::as_ptr(&self.inner) as usize));
        let _reset = Reset;
        f()
    }
}
