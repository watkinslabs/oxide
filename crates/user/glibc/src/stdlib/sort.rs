// qsort / bsearch (docs/59§6 G7). qsort is heapsort: in-place, O(n log n),
// no recursion (no stack-overflow risk), no allocation — a sound default;
// introsort tuning is a later perf refinement. Comparator is the C
// callback. Differentially tested vs a reference sort.
use core::ffi::c_void;

pub(crate) type Cmp = extern "C" fn(*const c_void, *const c_void) -> i32;

#[inline]
unsafe fn elem(base: *mut u8, size: usize, i: usize) -> *mut u8 {
    // SAFETY: i < nmemb and size is the element stride, so this stays in the array.
    unsafe { base.add(i * size) }
}
#[inline]
unsafe fn swap(a: *mut u8, b: *mut u8, size: usize) {
    // SAFETY: a and b are distinct in-array elements of `size` bytes.
    unsafe { let mut k = 0; while k < size { core::ptr::swap(a.add(k), b.add(k)); k += 1; } }
}

// Generic heapsort over a comparison closure (shared by qsort + qsort_r).
pub(crate) unsafe fn heapsort<F: Fn(*const c_void, *const c_void) -> i32>(base: *mut u8, n: usize, size: usize, cmp: &F) {
    // SAFETY: base addresses n elements of `size` bytes; cmp orders them.
    // Heapsort only swaps within the array.
    unsafe {
        if n < 2 || size == 0 { return; }
        let mut start = n / 2;
        while start > 0 { start -= 1; siftdown(base, size, cmp, start, n); }
        let mut end = n;
        while end > 1 { end -= 1; swap(elem(base, size, 0), elem(base, size, end), size); siftdown(base, size, cmp, 0, end); }
    }
}

pub(crate) unsafe fn qsort_impl(base: *mut u8, n: usize, size: usize, cmp: Cmp) {
    // SAFETY: forwards to heapsort with the 2-arg C comparator.
    unsafe { heapsort(base, n, size, &|a, b| cmp(a, b)); }
}

unsafe fn siftdown<F: Fn(*const c_void, *const c_void) -> i32>(base: *mut u8, size: usize, cmp: &F, mut root: usize, count: usize) {
    // SAFETY: root < count <= nmemb; children indices are bounds-checked.
    unsafe {
        loop {
            let mut largest = root;
            let l = 2 * root + 1;
            let r = 2 * root + 2;
            if l < count && cmp(elem(base, size, l) as *const c_void, elem(base, size, largest) as *const c_void) > 0 { largest = l; }
            if r < count && cmp(elem(base, size, r) as *const c_void, elem(base, size, largest) as *const c_void) > 0 { largest = r; }
            if largest == root { break; }
            swap(elem(base, size, root), elem(base, size, largest), size);
            root = largest;
        }
    }
}

pub(crate) unsafe fn bsearch_impl(key: *const u8, base: *const u8, n: usize, size: usize, cmp: Cmp) -> *mut u8 {
    // SAFETY: base addresses n sorted elements of `size` bytes; cmp orders
    // them consistently with the sort; key points at a comparable value.
    unsafe {
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let e = base.add(mid * size);
            let c = cmp(key as *const c_void, e as *const c_void);
            if c < 0 { hi = mid; } else if c > 0 { lo = mid + 1; } else { return e as *mut u8; }
        }
        core::ptr::null_mut()
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: void qsort(void *base, size_t n, size_t size, cmp)
    #[no_mangle]
    pub unsafe extern "C" fn qsort(base: *mut u8, n: usize, size: usize, cmp: Cmp) {
        // SAFETY: forwards the C qsort contract unchanged.
        unsafe { qsort_impl(base, n, size, cmp) }
    }
    // # C: void *bsearch(const void *key, const void *base, size_t n, size_t size, cmp)
    #[no_mangle]
    pub unsafe extern "C" fn bsearch(key: *const u8, base: *const u8, n: usize, size: usize, cmp: Cmp) -> *mut u8 {
        // SAFETY: forwards the C bsearch contract unchanged.
        unsafe { bsearch_impl(key, base, n, size, cmp) }
    }
    type CmpR = extern "C" fn(*const c_void, *const c_void, *mut c_void) -> i32;
    // # C: void qsort_r(void *base, size_t n, size_t size, cmpr, void *ctx)
    #[no_mangle]
    pub unsafe extern "C" fn qsort_r(base: *mut u8, n: usize, size: usize, cmp: CmpR, ctx: *mut c_void) {
        // SAFETY: heapsort over the 3-arg comparator threading `ctx`.
        unsafe { heapsort(base, n, size, &|a, b| cmp(a, b, ctx)); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> i32 {
        // SAFETY: a/b point at i32 elements supplied by the test arrays.
        let (x, y) = unsafe { (*(a as *const i32), *(b as *const i32)) };
        if x < y { -1 } else if x > y { 1 } else { 0 }
    }

    proptest! {
        #[test]
        fn qsort_sorts_like_ref(mut v in proptest::collection::vec(any::<i32>(), 0..256)) {
            let mut expect = v.clone();
            expect.sort_unstable();
            let n = v.len();
            // SAFETY: v holds n i32 elements; cmp_i32 compares them.
            unsafe { qsort_impl(v.as_mut_ptr() as *mut u8, n, 4, cmp_i32); }
            prop_assert_eq!(v, expect);
        }
        #[test]
        fn bsearch_finds(mut v in proptest::collection::vec(any::<i32>(), 1..256), idx in 0usize..256) {
            v.sort_unstable(); v.dedup();
            let n = v.len();
            let key = v[idx % n];
            // SAFETY: v is sorted n i32 elements; key is one of them.
            let p = unsafe { bsearch_impl(&key as *const i32 as *const u8, v.as_ptr() as *const u8, n, 4, cmp_i32) };
            prop_assert!(!p.is_null());
            // SAFETY: p points into v at a matching element.
            prop_assert_eq!(unsafe { *(p as *const i32) }, key);
        }
        #[test]
        fn bsearch_absent(v in proptest::collection::vec(1i32..1000, 0..64), key in -5i32..0) {
            let mut s = v.clone(); s.sort_unstable(); s.dedup();
            let n = s.len();
            // SAFETY: s is sorted n i32 elements; key < all of them.
            let p = unsafe { bsearch_impl(&key as *const i32 as *const u8, s.as_ptr() as *const u8, n, 4, cmp_i32) };
            prop_assert!(p.is_null());
        }
    }
}
