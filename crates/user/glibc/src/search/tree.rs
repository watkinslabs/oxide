// tsearch(3) family (docs/59§6 G8): unbalanced binary search tree keyed by a
// caller comparator. Nodes are malloc'd; the returned void* is the address of
// the node's key slot (opaque to callers, deref'd as void**). twalk VISIT
// codes match glibc: preorder=0 postorder=1 endorder=2 leaf=3. C ABI only.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

type Cmp = extern "C" fn(*const c_void, *const c_void) -> i32;
type Action = extern "C" fn(*const c_void, i32, i32);

#[repr(C)]
struct Node { key: *const c_void, left: *mut Node, right: *mut Node }

extern "C" { fn malloc(n: usize) -> *mut c_void; fn free(p: *mut c_void); }

unsafe fn new_node(key: *const c_void) -> *mut Node {
    // SAFETY: allocate a Node via malloc and initialise all three fields; the
    // caller links it into the tree. Returns null on allocation failure.
    unsafe {
        let p = malloc(core::mem::size_of::<Node>()) as *mut Node;
        if !p.is_null() { (*p).key = key; (*p).left = core::ptr::null_mut(); (*p).right = core::ptr::null_mut(); }
        p
    }
}

// # C: void *tsearch(const void *key, void **rootp, int (*cmp)(const void*, const void*))
#[no_mangle]
pub unsafe extern "C" fn tsearch(key: *const c_void, rootp: *mut *mut c_void, cmp: Cmp) -> *mut c_void {
    // SAFETY: rootp points to the (possibly null) root pointer; cmp is a valid C
    // comparator. Walk to the insertion point, inserting a new node if absent;
    // return the address of the matching node's key slot.
    unsafe {
        if rootp.is_null() { return core::ptr::null_mut(); }
        let mut link = rootp as *mut *mut Node;
        loop {
            let cur = *link;
            if cur.is_null() {
                let n = new_node(key);
                if n.is_null() { return core::ptr::null_mut(); }
                *link = n;
                return core::ptr::addr_of_mut!((*n).key) as *mut c_void;
            }
            let c = cmp(key, (*cur).key);
            if c == 0 { return core::ptr::addr_of_mut!((*cur).key) as *mut c_void; }
            link = if c < 0 { core::ptr::addr_of_mut!((*cur).left) } else { core::ptr::addr_of_mut!((*cur).right) };
        }
    }
}
// # C: void *__tsearch(const void *key, void **rootp, int (*cmp)(...))
#[no_mangle]
pub unsafe extern "C" fn __tsearch(key: *const c_void, rootp: *mut *mut c_void, cmp: Cmp) -> *mut c_void {
    // SAFETY: internal alias has the same tree/comparator contract as tsearch.
    unsafe { tsearch(key, rootp, cmp) }
}

// # C: void *tfind(const void *key, void *const *rootp, int (*cmp)(...))
#[no_mangle]
pub unsafe extern "C" fn tfind(key: *const c_void, rootp: *const *mut c_void, cmp: Cmp) -> *mut c_void {
    // SAFETY: rootp points to the (possibly null) root; cmp is valid. Pure
    // lookup — returns the key-slot address or null without modifying the tree.
    unsafe {
        if rootp.is_null() { return core::ptr::null_mut(); }
        let mut cur = *rootp as *mut Node;
        while !cur.is_null() {
            let c = cmp(key, (*cur).key);
            if c == 0 { return core::ptr::addr_of_mut!((*cur).key) as *mut c_void; }
            cur = if c < 0 { (*cur).left } else { (*cur).right };
        }
        core::ptr::null_mut()
    }
}
// # C: void *__tfind(const void *key, void *const *rootp, int (*cmp)(...))
#[no_mangle]
pub unsafe extern "C" fn __tfind(key: *const c_void, rootp: *const *mut c_void, cmp: Cmp) -> *mut c_void {
    // SAFETY: internal alias has the same tree/comparator contract as tfind.
    unsafe { tfind(key, rootp, cmp) }
}

// # C: void *tdelete(const void *key, void **rootp, int (*cmp)(...))
#[no_mangle]
pub unsafe extern "C" fn tdelete(key: *const c_void, rootp: *mut *mut c_void, cmp: Cmp) -> *mut c_void {
    // SAFETY: rootp points to the root pointer; cmp is valid. Standard BST
    // delete (replace by in-order successor when two children); frees the node
    // and returns the parent's key slot (or root sentinel) per POSIX, null if absent.
    unsafe {
        if rootp.is_null() { return core::ptr::null_mut(); }
        let mut parent: *mut Node = core::ptr::null_mut();
        let mut link = rootp as *mut *mut Node;
        let mut cur = *link;
        loop {
            if cur.is_null() { return core::ptr::null_mut(); }
            let c = cmp(key, (*cur).key);
            if c == 0 { break; }
            parent = cur;
            link = if c < 0 { core::ptr::addr_of_mut!((*cur).left) } else { core::ptr::addr_of_mut!((*cur).right) };
            cur = *link;
        }
        if (*cur).left.is_null() { *link = (*cur).right; }
        else if (*cur).right.is_null() { *link = (*cur).left; }
        else {
            // two children: take in-order successor (leftmost of right subtree)
            let mut sl = core::ptr::addr_of_mut!((*cur).right);
            while !(*(*sl)).left.is_null() { sl = core::ptr::addr_of_mut!((*(*sl)).left); }
            let succ = *sl;
            *sl = (*succ).right;
            (*succ).left = (*cur).left;
            (*succ).right = (*cur).right;
            *link = succ;
        }
        free(cur as *mut c_void);
        if parent.is_null() { rootp as *mut c_void } else { core::ptr::addr_of_mut!((*parent).key) as *mut c_void }
    }
}
// # C: void *__tdelete(const void *key, void **rootp, int (*cmp)(...))
#[no_mangle]
pub unsafe extern "C" fn __tdelete(key: *const c_void, rootp: *mut *mut c_void, cmp: Cmp) -> *mut c_void {
    // SAFETY: internal alias has the same tree/comparator contract as tdelete.
    unsafe { tdelete(key, rootp, cmp) }
}

unsafe fn walk(n: *mut Node, action: Action, level: i32) {
    // SAFETY: n is null or a valid Node; recurse in order invoking action with
    // the glibc VISIT codes (preorder/postorder/endorder for internal nodes,
    // leaf for childless nodes).
    unsafe {
        if n.is_null() { return; }
        if (*n).left.is_null() && (*n).right.is_null() {
            action(n as *const c_void, 3, level); // leaf
        } else {
            action(n as *const c_void, 0, level); // preorder
            walk((*n).left, action, level + 1);
            action(n as *const c_void, 1, level); // postorder
            walk((*n).right, action, level + 1);
            action(n as *const c_void, 2, level); // endorder
        }
    }
}

// # C: void twalk(const void *root, void (*action)(const void*, VISIT, int))
#[no_mangle]
pub unsafe extern "C" fn twalk(root: *const c_void, action: Action) {
    // SAFETY: root is null or a tree node produced by tsearch; action is valid.
    unsafe { walk(root as *mut Node, action, 0); }
}
// # C: void __twalk(const void *root, void (*action)(const void*, VISIT, int))
#[no_mangle]
pub unsafe extern "C" fn __twalk(root: *const c_void, action: Action) {
    // SAFETY: internal alias has the same traversal callback contract as twalk.
    unsafe { twalk(root, action) }
}

type ActionR = extern "C" fn(*const c_void, i32, *mut c_void);

unsafe fn walk_r(n: *mut Node, action: ActionR, closure: *mut c_void) {
    // SAFETY: n is null or a valid Node; recurse in order invoking action with
    // the glibc VISIT codes and the caller's opaque closure (twalk_r variant).
    unsafe {
        if n.is_null() { return; }
        if (*n).left.is_null() && (*n).right.is_null() {
            action(n as *const c_void, 3, closure); // leaf
        } else {
            action(n as *const c_void, 0, closure); // preorder
            walk_r((*n).left, action, closure);
            action(n as *const c_void, 1, closure); // postorder
            walk_r((*n).right, action, closure);
            action(n as *const c_void, 2, closure); // endorder
        }
    }
}

// # C: void twalk_r(const void *root, void (*action)(const void*, VISIT, void*), void *closure)
#[no_mangle]
pub unsafe extern "C" fn twalk_r(root: *const c_void, action: ActionR, closure: *mut c_void) {
    // SAFETY: root is null or a tree node produced by tsearch; action is valid;
    // closure is passed through opaquely to each invocation.
    unsafe { walk_r(root as *mut Node, action, closure); }
}
// # C: void __twalk_r(const void *root, void (*action)(...), void *closure)
#[no_mangle]
pub unsafe extern "C" fn __twalk_r(root: *const c_void, action: ActionR, closure: *mut c_void) {
    // SAFETY: internal alias has the same traversal callback contract as twalk_r.
    unsafe { twalk_r(root, action, closure) }
}

type FreeFn = extern "C" fn(*mut c_void);

unsafe fn destroy(n: *mut Node, freefn: FreeFn) {
    // SAFETY: n is null or a valid Node; recurse children-first, invoke freefn
    // on each node's key, then free the node itself (glibc tdestroy order).
    unsafe {
        if n.is_null() { return; }
        destroy((*n).left, freefn);
        destroy((*n).right, freefn);
        freefn((*n).key as *mut c_void);
        free(n as *mut c_void);
    }
}

// # C: void tdestroy(void *root, void (*free_node)(void *nodep))
#[no_mangle]
pub unsafe extern "C" fn tdestroy(root: *mut c_void, freefn: FreeFn) {
    // SAFETY: root is null or a tree produced by tsearch; freefn is a valid
    // destructor for each key. Free every node post-order; the caller must not
    // reuse the root pointer afterwards (glibc tdestroy contract).
    unsafe { destroy(root as *mut Node, freefn); }
}
