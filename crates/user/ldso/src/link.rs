// Link + run a dynamic executable (docs/59§5, docs/31§4). Builds the link
// map from the kernel-mapped app + its DT_NEEDED graph (mmap each lib),
// applies every object's RELA + JMPREL relocations resolving symbols across
// the global scope, runs DT_INIT / DT_INIT_ARRAY dependency-first, and
// returns the app entry for _start to jump to. Freestanding; verified by the
// dynamic-run harness (xtask ldso --check, libc-linked binary).
#![cfg(feature = "freestanding")]
use crate::dynamic::Dyn;
use crate::objview::{build_objview, OwnedObj};
use crate::reloc::Rela;
use crate::relocate::RelocCtx;
use crate::{auxv, linkmap, loader, phdr, relocate, search, syscall};
use alloc::vec::Vec;

const RELAENT: usize = 24;

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = elf::EM_AARCH64;

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

// Apply an object's RELA then JMPREL tables, resolving symbols globally.
unsafe fn relocate_obj(o: &OwnedObj, map: &[linkmap::ObjView]) {
    // SAFETY: o is a mapped object; its rela/jmprel tables live at base+addr
    // within the mapping; resolver reads only the link map's windows.
    unsafe {
        let v = o.view();
        let ctx = RelocCtx { base: o.base, sym: v.sym };
        let resolve = |name: &[u8]| linkmap::lookup_global(map, name, None).map(|(_, a)| a);
        if let Some(ra) = o.info.rela {
            let cnt = (o.info.relasz as usize) / RELAENT;
            let _ = relocate::apply(&ctx, (o.base + ra) as *const Rela, cnt, &resolve);
        }
        if let Some(jr) = o.info.jmprel {
            let cnt = (o.info.pltrelsz as usize) / RELAENT;
            let _ = relocate::apply(&ctx, (o.base + jr) as *const Rela, cnt, &resolve);
        }
    }
}

// Run DT_INIT then each DT_INIT_ARRAY entry of one object.
unsafe fn run_init(o: &OwnedObj) {
    // SAFETY: init pointers are fn() in the object's mapping; called once,
    // dependency-first, before handoff.
    unsafe {
        if let Some(init) = o.info.init {
            let f: extern "C" fn() = core::mem::transmute(o.base + init);
            f();
        }
        if let Some(arr) = o.info.init_array {
            let n = o.info.init_arraysz as usize / 8;
            let p = (o.base + arr) as *const usize;
            for i in 0..n {
                let f: extern "C" fn() = core::mem::transmute(*p.add(i));
                f();
            }
        }
    }
}

// Resolve `soname` to a path (NUL-terminated) in `out` via the search path.
unsafe fn find_lib(soname: &[u8], llp: &[u8], out: &mut [u8]) -> bool {
    // SAFETY: probes the filesystem with faccessat over a local NUL buffer.
    unsafe {
        search::resolve(soname, llp, out, |p| {
            let mut c = [0u8; search::PATH_MAX];
            c[..p.len()].copy_from_slice(p);
            syscall::access(c.as_ptr(), syscall::F_OK) == 0
        }).is_some()
    }
}

/// Link the app + its DT_NEEDED graph and return the app entry point.
/// # C: build link map, relocate all, run init, return AT_ENTRY
pub unsafe fn link(sp: *const usize) -> usize {
    // SAFETY: sp is the initial stack; AT_* describe the kernel-mapped app.
    unsafe {
        let at_phdr = auxv::auxval(sp, auxv::AT_PHDR).unwrap_or(0);
        let phnum = auxv::auxval(sp, auxv::AT_PHNUM).unwrap_or(0);
        let entry = auxv::auxval(sp, auxv::AT_ENTRY).unwrap_or(0);
        if at_phdr == 0 || phnum == 0 { return entry; }
        let phdrs = core::slice::from_raw_parts(at_phdr as *const u8, phnum * phdr::PHDR_SIZE);
        let app_base = phdr::load_bias(phdrs, phnum, at_phdr as u64).unwrap_or(0);
        let app_dyn_v = match phdr::find_vaddr(phdrs, phnum, phdr::PT_DYNAMIC) { Some(v) => v, None => return entry };
        let (_, app_hi) = phdr::load_vaddr_span(phdrs, phnum).unwrap_or((0, 0));
        let app = build_objview(app_base, app_base + app_hi, (app_base + app_dyn_v) as *const Dyn);

        let llp = ld_library_path(sp);
        let mut objs: Vec<OwnedObj> = Vec::new();
        objs.push(app);
        let mut sonames: Vec<&'static [u8]> = Vec::new();

        // Breadth-first DT_NEEDED load.
        let mut i = 0usize;
        while i < objs.len() {
            let needed = objs[i].info.needed.clone();
            for off in needed {
                let soname = objs[i].str_at(off);
                if sonames.contains(&soname) { continue; }
                let mut pb = [0u8; search::PATH_MAX];
                if !find_lib(soname, llp, &mut pb) { continue; }
                let fd = syscall::open(pb.as_ptr(), syscall::O_RDONLY);
                if fd < 0 { continue; }
                // Read the whole file: elf::parse validates PT_LOAD bounds
                // against the buffer, so a partial read rejects large libs.
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    let r = syscall::read(fd as i32, chunk.as_mut_ptr(), chunk.len());
                    if r <= 0 { break; }
                    buf.extend_from_slice(&chunk[..r as usize]);
                }
                if buf.is_empty() { syscall::close(fd as i32); continue; }
                let parsed = match elf::parse(&buf, MACHINE) { Ok(p) => p, Err(_) => { syscall::close(fd as i32); continue; } };
                let dep_dyn_v = phdr::find_vaddr(&buf[parsed.phoff as usize..], parsed.phnum as usize, phdr::PT_DYNAMIC);
                let mapped = loader::map_object(fd as i32, &parsed);
                syscall::close(fd as i32);
                let (base, end) = match mapped { Ok(t) => t, Err(_) => continue };
                if let Some(dv) = dep_dyn_v {
                    objs.push(build_objview(base, end, (base + dv) as *const Dyn));
                    sonames.push(soname);
                }
            }
            i += 1;
        }

        // Relocate every object against the full scope.
        let map: Vec<linkmap::ObjView> = objs.iter().map(|o| o.view()).collect();
        for o in &objs { relocate_obj(o, &map); }
        // Initializers run dependency-first (deps were pushed after the app).
        for o in objs.iter().rev() { run_init(o); }
        entry
    }
}
