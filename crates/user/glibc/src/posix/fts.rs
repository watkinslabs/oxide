// <fts.h> (docs/59§6 G13) — BSD file-tree traversal: fts_open/read/children/
// set/close. Stateful iterator: a directory is returned pre-order (FTS_D), then
// its entries (recursively), then again post-order (FTS_DP) reusing the same
// FTSENT. Physical walk (lstat) by default; FTS_LOGICAL follows symlinks (stat).
// Cycle detection (FTS_DC) via the ancestor dev/ino chain. No chdir: every node
// carries its full path (fts_path == fts_accpath). All nodes/paths/stats hang
// off one alloc chain in the FTS handle, freed wholesale by fts_close. C ABI.
#![cfg(feature = "freestanding")]
use crate::posix::dirent::dirent;
use crate::posix::stat::stat;
use crate::string::len::strlen_impl;
use core::ffi::c_void;
use alloc::vec::Vec;

extern "C" {
    fn opendir(p: *const u8) -> *mut c_void;
    fn readdir(d: *mut c_void) -> *mut dirent;
    fn closedir(d: *mut c_void) -> i32;
    fn stat(p: *const u8, b: *mut stat) -> i32;
    fn lstat(p: *const u8, b: *mut stat) -> i32;
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

// options
const FTS_COMFOLLOW: i32 = 0x0001;
const FTS_LOGICAL: i32 = 0x0002;
const FTS_NOSTAT: i32 = 0x0008;
const FTS_SEEDOT: i32 = 0x0020;
const FTS_XDEV: i32 = 0x0040;
const FTS_OPTIONMASK: i32 = 0x00ff;
const FTS_STOP: i32 = 0x0200;
// fts_info
const FTS_D: u16 = 1; const FTS_DC: u16 = 2; const FTS_DEFAULT: u16 = 3;
const FTS_DNR: u16 = 4; const FTS_DOT: u16 = 5; const FTS_DP: u16 = 6;
const FTS_ERR: u16 = 7; const FTS_F: u16 = 8; const FTS_INIT: u16 = 9;
const FTS_NS: u16 = 10; const FTS_NSOK: u16 = 11; const FTS_SL: u16 = 12;
const FTS_SLNONE: u16 = 13;
// fts_instr
const FTS_AGAIN: u16 = 1; const FTS_FOLLOW: u16 = 2; const FTS_NOINSTR: u16 = 3;
const FTS_SKIP: u16 = 4;
const FTS_ROOTPARENTLEVEL: i16 = -1;
const FTS_ROOTLEVEL: i16 = 0;
const FTS_NAMEONLY: i32 = 0x0100;

const EINVAL: i32 = 22;

#[cfg(target_arch = "x86_64")] type NlinkT = u64;
#[cfg(target_arch = "aarch64")] type NlinkT = u32;

type Compar = extern "C" fn(*const *const Ftsent, *const *const Ftsent) -> i32;

#[repr(C)]
pub struct Ftsent {
    pub fts_cycle: *mut Ftsent,
    pub fts_parent: *mut Ftsent,
    pub fts_link: *mut Ftsent,
    pub fts_number: i64,
    pub fts_pointer: *mut c_void,
    pub fts_accpath: *mut u8,
    pub fts_path: *mut u8,
    pub fts_errno: i32,
    pub fts_symfd: i32,
    pub fts_pathlen: u16,
    pub fts_namelen: u16,
    pub fts_ino: u64,
    pub fts_dev: u64,
    pub fts_nlink: NlinkT,
    pub fts_level: i16,
    pub fts_info: u16,
    pub fts_flags: u16,
    pub fts_instr: u16,
    pub fts_statp: *mut stat,
    // char fts_name[] follows in the same allocation
}
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Ftsent>() == 112);

#[repr(C)]
pub struct Fts {
    pub fts_cur: *mut Ftsent,
    pub fts_child: *mut Ftsent,
    pub fts_array: *mut *mut Ftsent,
    pub fts_dev: u64,
    pub fts_path: *mut u8,
    pub fts_rfd: i32,
    pub fts_pathlen: i32,
    pub fts_nitems: i32,
    pub fts_compar: Option<Compar>,
    pub fts_options: i32,
}
const _: () = assert!(core::mem::size_of::<Fts>() == 72);

// Private extension living behind the ABI-visible Fts (offset 0 == FTS*).
#[repr(C)]
struct FtsImpl { pub_fts: Fts, chain: *mut Hdr }
#[repr(C)]
struct Hdr { next: *mut Hdr }

// Allocate `size` bytes threaded onto the handle's free chain (8-aligned).
unsafe fn xalloc(im: *mut FtsImpl, size: usize) -> *mut u8 {
    // SAFETY: im is our live handle; malloc gives a >=16-aligned block, payload
    // at +Hdr is 8-aligned (max FTSENT/stat align). Returns null on OOM.
    unsafe {
        let h = crate::malloc::heap::malloc(core::mem::size_of::<Hdr>() + size) as *mut Hdr;
        if h.is_null() { return core::ptr::null_mut(); }
        (*h).next = (*im).chain; (*im).chain = h;
        h.add(1) as *mut u8
    }
}

#[inline] fn name_ptr(p: *mut Ftsent) -> *mut u8 {
    // SAFETY: node was allocated as size_of::<Ftsent>()+namelen+1, so the byte
    // just past the struct is the in-allocation fts_name flexible-array storage.
    unsafe { (p as *mut u8).add(core::mem::size_of::<Ftsent>()) }
}

// Build "parent/name" (or just name when parent is empty) into a chained alloc.
unsafe fn join(im: *mut FtsImpl, parent: *const u8, plen: usize, name: *const u8, nlen: usize) -> (*mut u8, usize) {
    // SAFETY: parent/name are NUL-terminated byte strings of the given lengths;
    // output buffer is sized plen+1+nlen+1 from the chain.
    unsafe {
        let need = if plen == 0 { nlen + 1 } else { plen + 1 + nlen + 1 };
        let b = xalloc(im, need);
        if b.is_null() { return (core::ptr::null_mut(), 0); }
        let mut o = 0;
        if plen > 0 {
            core::ptr::copy_nonoverlapping(parent, b, plen); o += plen;
            *b.add(o) = b'/'; o += 1;
        }
        core::ptr::copy_nonoverlapping(name, b.add(o), nlen); o += nlen;
        *b.add(o) = 0;
        (b, o)
    }
}

// stat a node, fill its statp + ino/dev/nlink, classify fts_info. `follow`
// forces stat(2) (symlink target) regardless of FTS_LOGICAL.
unsafe fn do_stat(im: *mut FtsImpl, p: *mut Ftsent, follow: bool) -> u16 {
    // SAFETY: p is a live node with a zeroed statp and a NUL-terminated accpath.
    unsafe {
        let opts = (*im).pub_fts.fts_options;
        let logical = opts & FTS_LOGICAL != 0;
        let sb = (*p).fts_statp;
        let use_stat = logical || follow;
        let rc = if use_stat { stat((*p).fts_accpath, sb) } else { lstat((*p).fts_accpath, sb) };
        if rc != 0 {
            // dangling symlink under a logical/comfollow walk?
            if use_stat && lstat((*p).fts_accpath, sb) == 0 && ((*sb).st_mode & S_IFMT) == S_IFLNK {
                return FTS_SLNONE;
            }
            (*p).fts_errno = (*crate::internal::errno::__errno_location());
            core::ptr::write_bytes(sb as *mut u8, 0, core::mem::size_of::<stat>());
            return FTS_NS;
        }
        (*p).fts_ino = (*sb).st_ino;
        (*p).fts_dev = (*sb).st_dev;
        (*p).fts_nlink = (*sb).st_nlink as NlinkT;
        let mode = (*sb).st_mode & S_IFMT;
        if mode == S_IFDIR {
            // cycle detection against ancestors
            let mut a = (*p).fts_parent;
            while !a.is_null() && (*a).fts_level >= FTS_ROOTLEVEL {
                if (*a).fts_ino == (*p).fts_ino && (*a).fts_dev == (*p).fts_dev {
                    (*p).fts_cycle = a; return FTS_DC;
                }
                a = (*a).fts_parent;
            }
            if opts & FTS_NOSTAT != 0 { /* still classified as dir */ }
            FTS_D
        } else if mode == S_IFLNK { FTS_SL }
        else if mode == S_IFREG { if opts & FTS_NOSTAT != 0 { FTS_NSOK } else { FTS_F } }
        else { FTS_DEFAULT }
    }
}

// Allocate + initialise a node for `name` under `parent` (null for roots).
unsafe fn alloc_node(im: *mut FtsImpl, parent: *mut Ftsent, name: *const u8, nlen: usize, follow: bool) -> *mut Ftsent {
    // SAFETY: builds one chained FTSENT+name block and a zeroed stat block, sets
    // path/level/parent, then classifies via do_stat.
    unsafe {
        // For roots (no parent), `name` is the full argv path: fts_path is the
        // whole arg but fts_name is only its last component (glibc semantics).
        let (nm, nmlen): (*const u8, usize) = if parent.is_null() {
            let mut bs = 0usize;
            for i in 0..nlen { if *name.add(i) == b'/' { bs = i + 1; } }
            (name.add(bs), nlen - bs)
        } else { (name, nlen) };
        let node = xalloc(im, core::mem::size_of::<Ftsent>() + nmlen + 1) as *mut Ftsent;
        if node.is_null() { return core::ptr::null_mut(); }
        core::ptr::write_bytes(node as *mut u8, 0, core::mem::size_of::<Ftsent>());
        let np = name_ptr(node);
        core::ptr::copy_nonoverlapping(nm, np, nmlen); *np.add(nmlen) = 0;
        (*node).fts_namelen = nmlen as u16;
        (*node).fts_instr = FTS_NOINSTR;
        (*node).fts_parent = parent;
        let sb = xalloc(im, core::mem::size_of::<stat>()) as *mut stat;
        if sb.is_null() { return core::ptr::null_mut(); }
        core::ptr::write_bytes(sb as *mut u8, 0, core::mem::size_of::<stat>());
        (*node).fts_statp = sb;
        // path: full arg for roots; parent/name join for children.
        let (path, plen) = if parent.is_null() {
            join(im, core::ptr::null(), 0, name, nlen)
        } else {
            (*node).fts_level = (*parent).fts_level + 1;
            join(im, (*parent).fts_path, (*parent).fts_pathlen as usize, nm, nmlen)
        };
        if path.is_null() { return core::ptr::null_mut(); }
        (*node).fts_path = path; (*node).fts_accpath = path; (*node).fts_pathlen = plen as u16;
        // skip classification for "." ".." when SEEDOT
        let is_dot = *nm == b'.' && (nmlen == 1 || (nmlen == 2 && *nm.add(1) == b'.'));
        (*node).fts_info = if is_dot { FTS_DOT } else { do_stat(im, node, follow) };
        node
    }
}

// Sort a linked node list (via fts_link) by the user comparator; returns head.
unsafe fn sort_list(head: *mut Ftsent, cmp: Compar) -> *mut Ftsent {
    // SAFETY: head is a fts_link-chained list; we collect to a Vec, sort with the
    // C comparator (which takes &&FTSENT), and relink in the new order.
    unsafe {
        let mut v: Vec<*mut Ftsent> = Vec::new();
        let mut c = head;
        while !c.is_null() { v.push(c); c = (*c).fts_link; }
        // insertion sort (stable-ish; comparator may not be total-order safe)
        for i in 1..v.len() {
            let mut j = i;
            while j > 0 {
                let a = v[j-1] as *const Ftsent; let b = v[j] as *const Ftsent;
                if cmp(&a, &b) > 0 { v.swap(j-1, j); j -= 1; } else { break; }
            }
        }
        for i in 0..v.len() { (*v[i]).fts_link = if i+1 < v.len() { v[i+1] } else { core::ptr::null_mut() }; }
        if v.is_empty() { core::ptr::null_mut() } else { v[0] }
    }
}

// Read `cur`'s directory entries into a fresh child list. Sets cur->fts_info to
// FTS_DNR (unreadable) or FTS_DP (empty) and returns null in those cases.
unsafe fn build(im: *mut FtsImpl, cur: *mut Ftsent) -> *mut Ftsent {
    // SAFETY: cur is the current directory node (FTS_D); opendir/readdir over its
    // accpath; each entry becomes a chained child node.
    unsafe {
        let opts = (*im).pub_fts.fts_options;
        let d = opendir((*cur).fts_accpath);
        if d.is_null() { (*cur).fts_errno = (*crate::internal::errno::__errno_location()); (*cur).fts_info = FTS_DNR; return core::ptr::null_mut(); }
        let follow = opts & FTS_LOGICAL != 0;
        let mut head: *mut Ftsent = core::ptr::null_mut();
        let mut tail: *mut Ftsent = core::ptr::null_mut();
        loop {
            let e = readdir(d);
            if e.is_null() { break; }
            let name = (*e).d_name.as_ptr();
            let is_dot = *name == b'.' && (*name.add(1) == 0 || (*name.add(1) == b'.' && *name.add(2) == 0));
            if is_dot && opts & FTS_SEEDOT == 0 { continue; }
            let nlen = strlen_impl(name);
            let node = alloc_node(im, cur, name, nlen, follow);
            if node.is_null() { break; }
            if head.is_null() { head = node; } else { (*tail).fts_link = node; }
            tail = node;
        }
        closedir(d);
        if head.is_null() { (*cur).fts_info = FTS_DP; return core::ptr::null_mut(); }
        if let Some(cmp) = (*im).pub_fts.fts_compar { head = sort_list(head, cmp); }
        head
    }
}

// # C: FTS *fts_open(char * const *argv, int options, int (*compar)(const FTSENT **, const FTSENT **))
#[no_mangle]
pub unsafe extern "C" fn fts_open(argv: *const *const u8, options: i32, compar: Option<Compar>) -> *mut Fts {
    // SAFETY: argv is a NULL-terminated array of NUL-terminated path strings.
    // Builds the root list + a dummy "before first root" cursor (FTS_INIT).
    unsafe {
        if options & !FTS_OPTIONMASK != 0 { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        if argv.is_null() { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let im = crate::malloc::heap::malloc(core::mem::size_of::<FtsImpl>()) as *mut FtsImpl;
        if im.is_null() { return core::ptr::null_mut(); }
        core::ptr::write_bytes(im as *mut u8, 0, core::mem::size_of::<FtsImpl>());
        (*im).pub_fts.fts_options = options;
        (*im).pub_fts.fts_compar = compar;
        let comfollow = options & FTS_COMFOLLOW != 0;
        // Build root list.
        let mut head: *mut Ftsent = core::ptr::null_mut();
        let mut tail: *mut Ftsent = core::ptr::null_mut();
        let mut i = 0isize;
        while !(*argv.offset(i)).is_null() {
            let s = *argv.offset(i); i += 1;
            let nlen = strlen_impl(s);
            if nlen == 0 { continue; }
            let node = alloc_node(im, core::ptr::null_mut(), s, nlen, comfollow);
            if node.is_null() { fts_close(&mut (*im).pub_fts); return core::ptr::null_mut(); }
            (*node).fts_level = FTS_ROOTLEVEL;
            if head.is_null() { head = node; } else { (*tail).fts_link = node; }
            tail = node;
        }
        if let (false, Some(cmp)) = (head.is_null(), compar) { head = sort_list(head, cmp); }
        // Dummy cursor before the roots.
        let dummy = alloc_node(im, core::ptr::null_mut(), b"\0".as_ptr(), 0, false);
        if dummy.is_null() { fts_close(&mut (*im).pub_fts); return core::ptr::null_mut(); }
        (*dummy).fts_info = FTS_INIT;
        (*dummy).fts_level = FTS_ROOTPARENTLEVEL;
        (*dummy).fts_link = head;
        // roots' parent = dummy (root-parent level) for cycle/ascend termination.
        let mut r = head;
        while !r.is_null() { (*r).fts_parent = dummy; r = (*r).fts_link; }
        (*im).pub_fts.fts_cur = dummy;
        if !head.is_null() { (*im).pub_fts.fts_dev = (*head).fts_dev; }
        &mut (*im).pub_fts
    }
}

// # C: FTSENT *fts_read(FTS *sp)
#[no_mangle]
pub unsafe extern "C" fn fts_read(sp: *mut Fts) -> *mut Ftsent {
    // SAFETY: sp is a live handle from fts_open; drives the BSD pre/post-order
    // state machine over the node tree built lazily by build().
    unsafe {
        let im = sp as *mut FtsImpl;
        let mut p = (*sp).fts_cur;
        if p.is_null() || (*sp).fts_options & FTS_STOP != 0 { return core::ptr::null_mut(); }
        let instr = (*p).fts_instr;
        (*p).fts_instr = FTS_NOINSTR;

        if instr == FTS_AGAIN { return p; }
        if instr == FTS_FOLLOW && ((*p).fts_info == FTS_SL || (*p).fts_info == FTS_SLNONE) {
            (*p).fts_info = do_stat(im, p, true);
            return p;
        }

        // Directory pre-order: descend.
        if (*p).fts_info == FTS_D {
            let xdev = (*sp).fts_options & FTS_XDEV != 0 && (*p).fts_dev != (*sp).fts_dev;
            if instr == FTS_SKIP || xdev {
                (*p).fts_info = FTS_DP;
                return p;
            }
            let child = build(im, p);
            if child.is_null() {
                // empty dir (info=FTS_DP) or unreadable (info=FTS_DNR): re-return.
                return (*sp).fts_cur;
            }
            (*sp).fts_cur = child;
            return child;
        }

        // Non-directory (or DP/DNR/leaf): advance to sibling, else ascend.
        loop {
            let link = (*p).fts_link;
            if !link.is_null() {
                (*sp).fts_cur = link;
                if (*link).fts_instr == FTS_SKIP { p = link; (*p).fts_instr = FTS_NOINSTR; continue; }
                if (*link).fts_instr == FTS_FOLLOW {
                    (*link).fts_info = do_stat(im, link, true);
                    (*link).fts_instr = FTS_NOINSTR;
                }
                return link;
            }
            // ascend to parent → post-order
            let par = (*p).fts_parent;
            (*sp).fts_cur = par;
            if par.is_null() || (*par).fts_level == FTS_ROOTPARENTLEVEL {
                (*sp).fts_cur = core::ptr::null_mut();
                crate::internal::errno::set(0);
                return core::ptr::null_mut();
            }
            (*par).fts_info = if (*par).fts_errno != 0 { FTS_ERR } else { FTS_DP };
            return par;
        }
    }
}

// # C: FTSENT *fts_children(FTS *sp, int instr)
#[no_mangle]
pub unsafe extern "C" fn fts_children(sp: *mut Fts, instr: i32) -> *mut Ftsent {
    // SAFETY: sp live; returns the current directory's child list without
    // advancing. Only meaningful when the current node is a pre-order dir.
    unsafe {
        let im = sp as *mut FtsImpl;
        if instr != 0 && instr != FTS_NAMEONLY { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let p = (*sp).fts_cur;
        if p.is_null() { return core::ptr::null_mut(); }
        // Root-before-first-read (FTS_INIT): children of the first root only if it's a dir.
        if (*p).fts_info != FTS_D && (*p).fts_info != FTS_INIT { return core::ptr::null_mut(); }
        let dir = if (*p).fts_info == FTS_INIT { (*p).fts_link } else { p };
        if dir.is_null() || (*dir).fts_info != FTS_D { return core::ptr::null_mut(); }
        let child = build(im, dir);
        (*sp).fts_child = child;
        child
    }
}

// # C: int fts_set(FTS *sp, FTSENT *p, int instr)
#[no_mangle]
pub unsafe extern "C" fn fts_set(_sp: *mut Fts, p: *mut Ftsent, instr: i32) -> i32 {
    // SAFETY: p is a node returned by fts_read; records the instruction for the
    // next fts_read of that node.
    unsafe {
        let i = instr as u16;
        if i != 0 && i != FTS_AGAIN && i != FTS_FOLLOW && i != FTS_NOINSTR && i != FTS_SKIP {
            crate::internal::errno::set(EINVAL); return -1;
        }
        (*p).fts_instr = i;
        0
    }
}

// # C: int fts_close(FTS *sp)
#[no_mangle]
pub unsafe extern "C" fn fts_close(sp: *mut Fts) -> i32 {
    // SAFETY: sp is a live handle; frees every chained allocation then the handle.
    unsafe {
        if sp.is_null() { return 0; }
        let im = sp as *mut FtsImpl;
        let mut h = (*im).chain;
        while !h.is_null() { let n = (*h).next; crate::malloc::heap::free(h as *mut u8); h = n; }
        crate::malloc::heap::free(im as *mut u8);
        0
    }
}

// LFS variants: stat64 == stat and FTSENT64 == FTSENT on LP64 → thin aliases.
// # C: FTS *fts64_open(char * const *argv, int options, int (*compar)(const FTSENT **, const FTSENT **))
#[no_mangle]
pub unsafe extern "C" fn fts64_open(argv: *const *const u8, options: i32, compar: Option<Compar>) -> *mut Fts {
    // SAFETY: FTSENT64 == FTSENT on LP64; forward.
    unsafe { fts_open(argv, options, compar) }
}
// # C: FTSENT *fts64_read(FTS *sp)
#[no_mangle]
pub unsafe extern "C" fn fts64_read(sp: *mut Fts) -> *mut Ftsent {
    // SAFETY: forward to fts_read (identical ABI on LP64).
    unsafe { fts_read(sp) }
}
// # C: FTSENT *fts64_children(FTS *sp, int instr)
#[no_mangle]
pub unsafe extern "C" fn fts64_children(sp: *mut Fts, instr: i32) -> *mut Ftsent {
    // SAFETY: forward to fts_children (identical ABI on LP64).
    unsafe { fts_children(sp, instr) }
}
// # C: int fts64_set(FTS *sp, FTSENT *p, int instr)
#[no_mangle]
pub unsafe extern "C" fn fts64_set(sp: *mut Fts, p: *mut Ftsent, instr: i32) -> i32 {
    // SAFETY: forward to fts_set (identical ABI on LP64).
    unsafe { fts_set(sp, p, instr) }
}
// # C: int fts64_close(FTS *sp)
#[no_mangle]
pub unsafe extern "C" fn fts64_close(sp: *mut Fts) -> i32 {
    // SAFETY: forward to fts_close (identical ABI on LP64).
    unsafe { fts_close(sp) }
}
