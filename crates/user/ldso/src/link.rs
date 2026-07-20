// Link + run a dynamic executable (docs/59§5, docs/31§4). Builds the global
// link map from the kernel-mapped app + its DT_NEEDED graph (mmap each lib),
// applies every object's RELA + JMPREL + TLS relocations resolving symbols
// across the global scope, runs DT_INIT / DT_INIT_ARRAY dependency-first, and
// returns the app entry. The link map is a process-global the rtld owns so
// dlopen (G12h) can extend it at runtime. Freestanding; verified by the
// dynamic-run harness (xtask ldso --check).
#![cfg(feature = "freestanding")]
use crate::dynamic::Dyn;
use crate::objview::{build_objview, OwnedObj};
use crate::reloc::Rela;
use crate::relocate::RelocCtx;
use crate::{auxv, linkmap, loader, phdr, relocate, search, syscall};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const RELAENT: usize = 24;

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = elf::EM_AARCH64;

// Process-global link map. Accessed single-threaded during startup; the lock
// guards dlopen vs the running program once threads exist.
struct GlobalLink {
    objs: UnsafeCell<Vec<OwnedObj>>,
    sonames: UnsafeCell<Vec<&'static [u8]>>,
    // The rtld's own objview — resolution scope only (it self-relocated and
    // is never relocated/init'd here), so libc's _dl_* refs can bind.
    rtld: UnsafeCell<Option<OwnedObj>>,
    // Saved LD_LIBRARY_PATH (ptr,len) so dlopen can search at runtime.
    llp_ptr: AtomicUsize,
    llp_len: AtomicUsize,
    lock: AtomicBool,
}
// SAFETY: all mutation is serialized by the lock; the objects' backing mmaps
// live for the process.
unsafe impl Sync for GlobalLink {}
static LINK: GlobalLink = GlobalLink {
    objs: UnsafeCell::new(Vec::new()),
    sonames: UnsafeCell::new(Vec::new()),
    rtld: UnsafeCell::new(None),
    llp_ptr: AtomicUsize::new(0),
    llp_len: AtomicUsize::new(0),
    lock: AtomicBool::new(false),
};

unsafe fn saved_llp() -> &'static [u8] {
    // SAFETY: ptr/len were saved from the env at link(); the env lives for the
    // process. Empty if LD_LIBRARY_PATH was unset.
    unsafe {
        let p = LINK.llp_ptr.load(Ordering::Acquire);
        let n = LINK.llp_len.load(Ordering::Acquire);
        if p == 0 { &[] } else { core::slice::from_raw_parts(p as *const u8, n) }
    }
}

// The resolution scope: every loaded object's view plus the rtld's own.
unsafe fn scope_map() -> Vec<linkmap::ObjView<'static>> {
    // SAFETY: caller holds the lock; views reference live mappings.
    unsafe {
        let mut m: Vec<linkmap::ObjView> = objs().iter().map(|o| o.view()).collect();
        if let Some(r) = &*LINK.rtld.get() { m.push(r.view()); }
        m
    }
}

fn lock() {
    while LINK.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire).is_err() {
        core::hint::spin_loop();
    }
}
fn unlock() { LINK.lock.store(false, Ordering::Release); }

#[allow(clippy::mut_from_ref)]
unsafe fn objs() -> &'static mut Vec<OwnedObj> {
    // SAFETY: caller holds the lock; the Vec lives in the global.
    unsafe { &mut *LINK.objs.get() }
}
#[allow(clippy::mut_from_ref)]
unsafe fn sonames() -> &'static mut Vec<&'static [u8]> {
    // SAFETY: caller holds the lock; the Vec lives in the global.
    unsafe { &mut *LINK.sonames.get() }
}

// Value of LD_LIBRARY_PATH from the environment, or empty.
unsafe fn ld_library_path(sp: *const usize) -> &'static [u8] {
    // SAFETY: envp is the kernel env array; each entry is a NUL-terminated
    // "KEY=VALUE" string. We scan for our key and return its value slice.
    unsafe {
        const KEY: &[u8] = b"LD_LIBRARY_PATH=";
        let mut e = auxv::envp(sp);
        while !(*e).is_null() {
            let s = *e;
            let mut n = 0usize;
            while *s.add(n) != 0 { n += 1; }
            let bytes = core::slice::from_raw_parts(s, n);
            if bytes.len() > KEY.len() && &bytes[..KEY.len()] == KEY {
                return &bytes[KEY.len()..];
            }
            e = e.add(1);
        }
        &[]
    }
}

// Resolve `soname` to a NUL-terminated path in `out` via the search path.
unsafe fn find_lib(soname: &[u8], rpath: &[u8], runpath: &[u8], llp: &[u8], out: &mut [u8]) -> bool {
    // SAFETY: probes the filesystem with faccessat over local NUL buffers.
    unsafe {
        let probe = |dirs: &[u8], out: &mut [u8]| {
            for dir in search::Colon::new(dirs) {
                if let Some(n) = search::join_path(dir, soname, out) {
                    if syscall::access(out.as_ptr(), syscall::F_OK) == 0 { return true; }
                    out[n] = 0;
                }
            }
            false
        };
        // DT_RPATH applies before LD_LIBRARY_PATH only when DT_RUNPATH is absent.
        if runpath.is_empty() && probe(rpath, out) { return true; }
        if probe(llp, out) { return true; }
        if probe(runpath, out) { return true; }
        search::resolve(soname, llp, out, |p| {
            let mut c = [0u8; search::PATH_MAX];
            c[..p.len()].copy_from_slice(p);
            syscall::access(c.as_ptr(), syscall::F_OK) == 0
        }).is_some()
    }
}

// open + read + parse + mmap one library by path; append it to the global map.
// Returns the new object's index, or None on any failure.
unsafe fn load_one(path: *const u8) -> Option<usize> {
    // SAFETY: path is NUL-terminated; we open/read/parse/map then push the
    // resulting OwnedObj onto the global objs vec (lock held by caller).
    unsafe {
        let fd = syscall::open(path, syscall::O_RDONLY);
        if fd < 0 { return None; }
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let r = syscall::read(fd as i32, chunk.as_mut_ptr(), chunk.len());
            if r <= 0 { break; }
            buf.extend_from_slice(&chunk[..r as usize]);
        }
        if buf.is_empty() { syscall::close(fd as i32); return None; }
        let parsed = match elf::parse(&buf, MACHINE) { Ok(p) => p, Err(_) => { syscall::close(fd as i32); return None; } };
        let dep_dyn_v = phdr::find_vaddr(&buf[parsed.phoff as usize..], parsed.phnum as usize, phdr::PT_DYNAMIC);
        let mapped = loader::map_object(fd as i32, &parsed);
        syscall::close(fd as i32);
        let (base, end) = mapped.ok()?;
        let dv = dep_dyn_v?;
        objs().push(build_objview(base, end, (base + dv) as *const Dyn));
        Some(objs().len() - 1)
    }
}

// Breadth-first DT_NEEDED load over the global map, starting at index `from`.
unsafe fn load_needed(llp: &[u8], from: usize) {
    // SAFETY: walks each object's DT_NEEDED, loading missing libs into the
    // global map; lock held by caller.
    unsafe {
        let mut i = from;
        while i < objs().len() {
            let needed = objs()[i].info.needed.clone();
            let rpath = objs()[i].info.rpath.map(|o| objs()[i].str_at(o)).unwrap_or(&[]);
            let runpath = objs()[i].info.runpath.map(|o| objs()[i].str_at(o)).unwrap_or(&[]);
            for off in needed {
                let soname = objs()[i].str_at(off);
                if sonames().contains(&soname) { continue; }
                let mut pb = [0u8; search::PATH_MAX];
                if !find_lib(soname, rpath, runpath, llp, &mut pb) { continue; }
                if load_one(pb.as_ptr()).is_some() { sonames().push(soname); }
            }
            i += 1;
        }
    }
}

// Relocate objects [from..] against the full global scope.
unsafe fn relocate_range(from: usize, tls_offs: &[i64]) {
    // SAFETY: applies each object's RELA+JMPREL+TLS in place; resolver reads
    // the global link map's windows.
    unsafe {
        let map = scope_map();
        let resolve = |name: &[u8]| linkmap::lookup_global(&map, name, None).map(|(_, a)| a);
        // COPY relocs (in the exe) must source the symbol from a SHARED LIB,
        // not the exe's own .bss slot — resolve over the map EXCLUDING the exe
        // (object 0). map = [exe, deps…, rtld], so map[1..] is the right scope.
        let copy_scope: &[linkmap::ObjView] = if map.len() > 1 { &map[1..] } else { &map };
        let resolve_copy = |name: &[u8]| linkmap::lookup_global(copy_scope, name, None).map(|(_, a)| a);
        for oi in from..objs().len() {
            let o = &objs()[oi];
            let v = o.view();
            let off = tls_offs.get(oi).copied().unwrap_or(0);
            let modid = (oi + 1) as u64;
            let ctx = RelocCtx { base: o.base, sym: v.sym, tls_offset: off, tls_modid: modid };
            if let Some(ra) = o.info.rela {
                let cnt = (o.info.relasz as usize) / RELAENT;
                let _ = relocate::apply(&ctx, (o.base + ra) as *const Rela, cnt, &resolve, &resolve_copy);
            }
            if let Some(jr) = o.info.jmprel {
                let cnt = (o.info.pltrelsz as usize) / RELAENT;
                let _ = relocate::apply(&ctx, (o.base + jr) as *const Rela, cnt, &resolve, &resolve_copy);
            }
        }
    }
}

// Run DT_INIT then each DT_INIT_ARRAY entry of one object.
unsafe fn run_init(o: &OwnedObj, argc: usize, argv: *const *const u8, envp: *const *const u8) {
    // SAFETY: init pointers are fn() in the object's mapping; called once.
    unsafe {
        if let Some(init) = o.info.init {
            let f: extern "C" fn(usize, *const *const u8, *const *const u8) = core::mem::transmute(o.base + init);
            f(argc, argv, envp);
        }
        if let Some(arr) = o.info.init_array {
            let n = o.info.init_arraysz as usize / 8;
            let p = (o.base + arr) as *const usize;
            for i in 0..n {
                // DT_INIT_ARRAY entries are relocation targets. After the
                // RELATIVE pass each slot already contains its absolute
                // runtime address (B + A); adding o.base again would make
                // the loader branch to 2B + A.
                let f: extern "C" fn(usize, *const *const u8, *const *const u8) = core::mem::transmute(*p.add(i) as u64);
                f(argc, argv, envp);
            }
        }
    }
}

#[derive(Copy, Clone)]
struct TlsImage { base: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64 }

unsafe fn obj_tls(base: u64) -> Option<TlsImage> {
    // SAFETY: every mapped ELF object has its ELF header and program headers
    // in the first PT_LOAD mapping; these reads only inspect that mapped image.
    unsafe {
        let phoff = *((base + 0x20) as *const u64) as usize;
        let phnum = *((base + 0x38) as *const u16) as usize;
        let phdrs = core::slice::from_raw_parts((base as usize + phoff) as *const u8, phnum * phdr::PHDR_SIZE);
        phdr::find_tls(phdrs, phnum).map(|(vaddr, filesz, memsz, align)| TlsImage { base, vaddr, filesz, memsz, align })
    }
}

// Build the initial thread's complete static TLS image and install its TCB.
// Object index + 1 is the ELF TLS module ID, including objects without PT_TLS.
unsafe fn setup_static_tls(page_size: usize, _random: usize) -> Vec<i64> {
    // SAFETY: caller holds LINK.lock; object mappings and AT_RANDOM remain live.
    unsafe {
        let images: Vec<Option<TlsImage>> = objs().iter().map(|o| obj_tls(o.base)).collect();
        let specs: Vec<(u64, u64)> = images.iter().map(|i| i.map(|v| (v.memsz, v.align)).unwrap_or((0, 1))).collect();
        let (offs, total) = crate::tls::layout(&specs, crate::tls::target_variant());
        let page = page_size.max(4096);
        let tcb = 64usize;
        let payload = total as usize + tcb;
        let size = ((payload.max(1) + page - 1) & !(page - 1)).max(page * 2);
        let block = syscall::mmap(0, size, syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS, -1, 0);
        if block < 0 { return alloc::vec![0; objs().len()]; }
        let block = block as usize;
        let tp = match crate::tls::target_variant() {
            crate::tls::Variant::Two => block + total as usize,
            crate::tls::Variant::One => block,
        };
        let dtv_words = objs().len() + 1;
        let dtv = syscall::mmap(0, dtv_words * core::mem::size_of::<usize>(),
            syscall::PROT_READ | syscall::PROT_WRITE, syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS, -1, 0);
        if dtv < 0 { return alloc::vec![0; objs().len()]; }
        let dtv = dtv as *mut usize;
        *dtv = objs().len();
        for (i, image) in images.iter().enumerate() {
            if let Some(image) = image {
                let data = (tp as i64 + offs[i]) as usize;
                core::ptr::copy_nonoverlapping((image.base + image.vaddr) as *const u8, data as *mut u8, image.filesz as usize);
                *dtv.add(i + 1) = data;
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            *(tp as *mut usize).add(0) = tp;
            *(tp as *mut usize).add(1) = dtv as usize;
            *(tp as *mut usize).add(2) = tp;
            if _random != 0 {
                *(tp as *mut usize).add(5) = *(_random as *const usize);
                *(tp as *mut usize).add(6) = *(_random as *const usize).add(1);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            *(tp as *mut usize) = dtv as usize;
        }
        syscall::set_thread_pointer(tp);
        offs
    }
}

// Build the rtld's own objview from its load base + _DYNAMIC, for resolution
// scope only (it self-relocated; never relocated/init'd here).
unsafe fn rtld_objview(rtld_base: u64, rtld_dyn: *const Dyn) -> Option<OwnedObj> {
    // SAFETY: rtld_base is AT_BASE; its ehdr/phdrs are mapped there. Read
    // e_phoff/phnum, find the load span to bound the windows.
    unsafe {
        if rtld_base == 0 { return None; }
        let ph_off = *((rtld_base + 0x20) as *const u64); // e_phoff
        let ph_num = *((rtld_base + 0x38) as *const u16) as usize; // e_phnum
        let phdrs = core::slice::from_raw_parts((rtld_base + ph_off) as *const u8, ph_num * phdr::PHDR_SIZE);
        let (_, hi) = phdr::load_vaddr_span(phdrs, ph_num).unwrap_or((0, 0));
        Some(build_objview(rtld_base, rtld_base + hi, rtld_dyn))
    }
}

/// Link the app + its DT_NEEDED graph and return the app entry point.
/// # C: build the global link map, relocate all, run init, return AT_ENTRY
pub unsafe fn link(sp: *const usize, rtld_base: u64, rtld_dyn: *const Dyn) -> usize {
    // SAFETY: sp is the initial stack; AT_* describe the kernel-mapped app.
    unsafe {
        let at_phdr = auxv::auxval(sp, auxv::AT_PHDR).unwrap_or(0);
        let phnum = auxv::auxval(sp, auxv::AT_PHNUM).unwrap_or(0);
        let page_size = auxv::auxval(sp, auxv::AT_PAGESZ).unwrap_or(4096);
        let entry = auxv::auxval(sp, auxv::AT_ENTRY).unwrap_or(0);
        if at_phdr == 0 || phnum == 0 { return entry; }
        let phdrs = core::slice::from_raw_parts(at_phdr as *const u8, phnum * phdr::PHDR_SIZE);
        let app_base = phdr::load_bias(phdrs, phnum, at_phdr as u64).unwrap_or(0);
        let app_dyn_v = match phdr::find_vaddr(phdrs, phnum, phdr::PT_DYNAMIC) { Some(v) => v, None => return entry };
        let (_, app_hi) = phdr::load_vaddr_span(phdrs, phnum).unwrap_or((0, 0));
        let llp = ld_library_path(sp);

        lock();
        // Save LD_LIBRARY_PATH + the rtld view for dlopen / cross-lib resolution.
        LINK.llp_ptr.store(llp.as_ptr() as usize, Ordering::Release);
        LINK.llp_len.store(llp.len(), Ordering::Release);
        *LINK.rtld.get() = rtld_objview(rtld_base, rtld_dyn);
        objs().push(build_objview(app_base, app_base + app_hi, (app_base + app_dyn_v) as *const Dyn));
        load_needed(llp, 0);
        let random = auxv::auxval(sp, auxv::AT_RANDOM).unwrap_or(0);
        let tls_offs = setup_static_tls(page_size, random);
        relocate_range(0, &tls_offs);
        // Initializers run dependency-first (deps were pushed after the app).
        let n = objs().len();
        let argc = auxv::argc(sp);
        let argv = auxv::argv(sp);
        let envp = auxv::envp(sp);
        for i in (0..n).rev() { run_init(&objs()[i], argc, argv, envp); }
        unlock();
        entry
    }
}

unsafe fn cstr_len(p: *const u8) -> usize {
    // SAFETY: p is a NUL-terminated C string.
    unsafe { let mut n = 0; while *p.add(n) != 0 { n += 1; } n }
}

/// dlopen core: load `path` (+ deps) into the global map, relocate against the
/// full scope, run its init, and return a handle (object index + 1; 0 = fail).
/// # C: void *_dl_open(const char *path, int mode)
#[no_mangle]
pub unsafe extern "C" fn _dl_open(path: *const u8, _mode: i32) -> usize {
    // SAFETY: path is NUL-terminated; we search/open/map under the link lock.
    unsafe {
        if path.is_null() { return 0; }
        lock();
        let from = objs().len();
        let pslice = core::slice::from_raw_parts(path, cstr_len(path));
        let mut pb = [0u8; search::PATH_MAX];
        let resolved: *const u8 = if pslice.contains(&b'/') {
            path
        } else if find_lib(pslice, &[], &[], saved_llp(), &mut pb) {
            pb.as_ptr()
        } else {
            unlock();
            return 0;
        };
        let idx = match load_one(resolved) { Some(i) => i, None => { unlock(); return 0; } };
        load_needed(saved_llp(), from);
        relocate_range(from, &[]);
        let n = objs().len();
        for i in (from..n).rev() { run_init(&objs()[i], 0, core::ptr::null(), core::ptr::null()); }
        unlock();
        idx + 1
    }
}

/// dlsym core: resolve `name` in the handle's object, or the whole scope when
/// `handle` is RTLD_DEFAULT (0). Returns the runtime address (0 = not found).
/// # C: void *_dl_sym(void *handle, const char *name)
#[no_mangle]
pub unsafe extern "C" fn _dl_sym(handle: usize, name: *const u8) -> usize {
    // SAFETY: name is NUL-terminated; lookup reads live link-map windows.
    unsafe {
        if name.is_null() { return 0; }
        let ns = core::slice::from_raw_parts(name, cstr_len(name));
        lock();
        let r = if handle == 0 {
            let map = scope_map();
            linkmap::lookup_global(&map, ns, None).map(|(_, a)| a)
        } else {
            let idx = handle - 1;
            if idx < objs().len() {
                let o = &objs()[idx];
                let v = o.view();
                crate::symbol::resolve(v.gnu_hash, v.sysv_hash, &v.sym, ns)
                    .filter(|&i| v.sym.is_defined(i))
                    .and_then(|i| v.sym.value(i))
                    .map(|val| o.base + val)
            } else {
                None
            }
        };
        unlock();
        r.unwrap_or(0) as usize
    }
}

/// # C: int _dl_close(void *handle) — refcount unmap is a follow-up; returns 0.
#[no_mangle]
pub extern "C" fn _dl_close(_handle: usize) -> i32 { 0 }

// struct dl_phdr_info (LP64, 64 bytes) — fields the unwinder/backtrace read.
#[repr(C)]
struct DlPhdrInfo {
    addr: u64, name: *const u8, phdr: *const u8, phnum: u16, _pad: [u8; 6],
    adds: u64, subs: u64, tls_modid: usize, tls_data: *const u8,
}
static EMPTY_NAME: [u8; 1] = [0];

/// dl_iterate_phdr core: call `cb(info, sizeof, data)` for each loaded object.
/// Each object's phdrs are recovered from its ELF header at `base`
/// (e_phoff@0x20, e_phnum@0x38). Stops + returns the first nonzero `cb` result.
/// dlpi_name is "" for now (the unwinder keys on addr/phdr, not the name).
/// # C: int _dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void *data)
#[no_mangle]
pub unsafe extern "C" fn _dl_iterate_phdr(
    cb: extern "C" fn(*const core::ffi::c_void, usize, *mut core::ffi::c_void) -> i32,
    data: *mut core::ffi::c_void,
) -> i32 {
    // SAFETY: snapshot each object's base under the lock, release it (so the
    // callback may re-enter the loader), then read each ELF header at base to
    // reconstruct dlpi_phdr/dlpi_phnum and invoke the callback.
    unsafe {
        lock();
        let mut bases: Vec<u64> = objs().iter().map(|o| o.base).collect();
        if let Some(r) = &*LINK.rtld.get() { bases.push(r.base); }
        unlock();
        for base in bases {
            if base == 0 { continue; }
            let phoff = *((base + 0x20) as *const u64);
            let phnum = *((base + 0x38) as *const u16);
            let info = DlPhdrInfo {
                addr: base, name: EMPTY_NAME.as_ptr(), phdr: (base + phoff) as *const u8,
                phnum, _pad: [0; 6], adds: 0, subs: 0, tls_modid: 0, tls_data: core::ptr::null(),
            };
            let r = cb(&info as *const _ as *const core::ffi::c_void, core::mem::size_of::<DlPhdrInfo>(), data);
            if r != 0 { return r; }
        }
        0
    }
}

/// dladdr core: find the loaded object containing `addr`; writes its base into
/// `fbase_out`. Returns 1 on a hit, 0 otherwise. (sname/saddr: follow-up.)
/// # C: int _dl_addr(const void *addr, void **fbase_out)
#[no_mangle]
pub unsafe extern "C" fn _dl_addr(addr: usize, fbase_out: *mut usize) -> i32 {
    // SAFETY: walks the global map under the lock; fbase_out is writable.
    unsafe {
        lock();
        let mut hit = 0i32;
        for o in objs().iter() {
            if addr >= o.base as usize && addr < o.image_end as usize {
                if !fbase_out.is_null() { *fbase_out = o.base as usize; }
                hit = 1;
                break;
            }
        }
        unlock();
        hit
    }
}
