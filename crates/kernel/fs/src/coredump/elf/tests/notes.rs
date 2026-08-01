// Note padding, note order, and the byte offsets of the two identity
// structures a debugger decodes without any type information.

use super::fixture;
use super::reader::Image;
use crate::coredump::elf::input::{CoreImageError, CoreImageInput, CoreState};
use crate::coredump::elf::layout::{
    CoreArch, PRPSINFO_BYTES, PR_CSTIME_OFF, PR_CURSIG_OFF, PR_CUTIME_OFF, PR_INFO_CODE_OFF,
    PR_INFO_ERRNO_OFF, PR_INFO_SIGNO_OFF, PR_PGRP_OFF, PR_PID_OFF, PR_PPID_OFF, PR_REG_OFF,
    PR_SID_OFF, PR_SIGHOLD_OFF, PR_SIGPEND_OFF, PR_STIME_OFF, PR_UTIME_OFF, PSINFO_FLAG_OFF,
    PSINFO_FNAME_BYTES, PSINFO_FNAME_OFF, PSINFO_GID_OFF, PSINFO_NICE_OFF, PSINFO_PGRP_OFF,
    PSINFO_PID_OFF, PSINFO_PPID_OFF, PSINFO_PSARGS_BYTES, PSINFO_PSARGS_OFF, PSINFO_SID_OFF,
    PSINFO_SNAME_OFF, PSINFO_STATE_OFF, PSINFO_UID_OFF, PSINFO_ZOMB_OFF,
};
use crate::coredump::elf::notes;
use crate::coredump::elf::uapi::{
    NOTE_ALIGN, NOTE_NAME_CORE, NOTE_NAME_LINUX, NT_AUXV, NT_FILE, NT_PRFPREG, NT_PRPSINFO,
    NT_PRSTATUS, NT_SIGINFO, NT_X86_XSTATE,
};

fn rd32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn rd64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

#[test]
fn order_puts_the_crashing_thread_first() {
    let img = fixture::image(CoreArch::X86_64);
    let types: alloc::vec::Vec<u32> = Image::new(&img).notes().iter().map(|n| n.ty).collect();
    assert_eq!(
        types,
        alloc::vec![
            NT_PRSTATUS, NT_PRPSINFO, NT_SIGINFO, NT_AUXV, NT_FILE, NT_PRFPREG, NT_PRSTATUS,
        ],
        "process-wide notes are interleaved after the first thread's registers",
    );
}

#[test]
fn every_note_carries_its_owner_string() {
    let img = fixture::image(CoreArch::Aarch64);
    for n in Image::new(&img).notes() { assert_eq!(n.name, NOTE_NAME_CORE) }
}

#[test]
fn extended_state_is_owned_by_a_different_string() {
    let arch = CoreArch::X86_64;
    let r = fixture::regs(arch, 1);
    let xs = alloc::vec![0xABu8; 64];
    let threads = [crate::coredump::elf::input::CoreThread {
        tid: fixture::TID_MAIN, regs: &r, fpregs: None, xstate: Some(&xs),
    }];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: &[], auxv: &[],
        siginfo: None,
    };
    let mut mem = fixture::full_reader();
    let img = crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap();
    let n = Image::new(&img).note(NT_X86_XSTATE);
    assert_eq!(n.name, NOTE_NAME_LINUX);
    assert_eq!(n.desc, xs);
}

#[test]
fn note_sizes_match_the_padding_rule() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    let total: usize = i.notes().iter().map(|n| notes::note_bytes(&n.name, n.desc.len())).sum();
    assert_eq!(total as u64, i.phdr(0).filesz, "segment is exactly its notes");
    assert_eq!(i.phdr(0).filesz % NOTE_ALIGN as u64, 0);
}

#[test]
fn an_odd_descriptor_is_padded_not_truncated() {
    let mut buf = alloc::vec::Vec::new();
    notes::push_note(&mut buf, NOTE_NAME_CORE, NT_AUXV, &[1, 2, 3]);
    assert_eq!(rd32(&buf, 0), NOTE_NAME_CORE.len() as u32 + 1, "namesz counts the terminator");
    assert_eq!(rd32(&buf, 4), 3, "descsz is the unpadded length");
    assert_eq!(buf.len(), notes::note_bytes(NOTE_NAME_CORE, 3));
    assert_eq!(buf.len() % NOTE_ALIGN, 0);
    // Header, then the terminated owner string padded from five bytes to eight.
    const DESC_OFF: usize = 20;
    assert_eq!(&buf[12..17], b"CORE\0");
    assert_eq!(&buf[17..DESC_OFF], &[0, 0, 0], "the name's pad is zero");
    assert_eq!(&buf[DESC_OFF..DESC_OFF + 3], &[1, 2, 3]);
    assert_eq!(buf[DESC_OFF + 3], 0, "the descriptor's pad is zero");
}

#[test]
fn prstatus_is_the_arch_length() {
    assert_eq!(CoreArch::X86_64.gregset_bytes(), 27 * 8);
    assert_eq!(CoreArch::Aarch64.gregset_bytes(), 34 * 8);
    assert_eq!(CoreArch::X86_64.prstatus_bytes(), 336);
    assert_eq!(CoreArch::Aarch64.prstatus_bytes(), 392);
    assert_eq!(CoreArch::X86_64.pr_fpvalid_off(), PR_REG_OFF + 27 * 8);
    assert_eq!(CoreArch::Aarch64.pr_fpvalid_off(), PR_REG_OFF + 34 * 8);
    for arch in [CoreArch::X86_64, CoreArch::Aarch64] {
        let img = fixture::image(arch);
        assert_eq!(Image::new(&img).note(NT_PRSTATUS).desc.len(), arch.prstatus_bytes());
    }
}

#[test]
fn prstatus_fields_land_at_their_offsets() {
    for arch in [CoreArch::X86_64, CoreArch::Aarch64] {
        let img = fixture::image(arch);
        let d = Image::new(&img).note(NT_PRSTATUS).desc;
        let id = fixture::identity();
        assert_eq!(rd32(&d, PR_INFO_SIGNO_OFF) as i32, fixture::SIGSEGV);
        assert_eq!(rd32(&d, PR_INFO_CODE_OFF), 0);
        assert_eq!(rd32(&d, PR_INFO_ERRNO_OFF), 0);
        assert_eq!(i16::from_le_bytes([d[PR_CURSIG_OFF], d[PR_CURSIG_OFF + 1]]) as i32,
                   fixture::SIGSEGV);
        assert_eq!(rd64(&d, PR_SIGPEND_OFF), id.sigpend);
        assert_eq!(rd64(&d, PR_SIGHOLD_OFF), id.sighold);
        assert_eq!(rd32(&d, PR_PID_OFF) as i32, fixture::TID_MAIN, "pr_pid is the thread");
        assert_eq!(rd32(&d, PR_PPID_OFF) as i32, fixture::PPID);
        assert_eq!(rd32(&d, PR_PGRP_OFF) as i32, fixture::PGRP);
        assert_eq!(rd32(&d, PR_SID_OFF) as i32, fixture::SID);
        assert_eq!(rd64(&d, PR_UTIME_OFF) as i64, id.times.utime.sec);
        assert_eq!(rd64(&d, PR_UTIME_OFF + 8) as i64, id.times.utime.usec);
        assert_eq!(rd64(&d, PR_STIME_OFF) as i64, id.times.stime.sec);
        assert_eq!(rd64(&d, PR_CUTIME_OFF) as i64, id.times.cutime.sec);
        assert_eq!(rd64(&d, PR_CSTIME_OFF + 8) as i64, id.times.cstime.usec);
        assert_eq!(&d[PR_REG_OFF..arch.pr_fpvalid_off()], &fixture::regs(arch, 0x11)[..]);
        assert_eq!(rd32(&d, arch.pr_fpvalid_off()), 1, "fp state was captured");
    }
}

#[test]
fn a_thread_without_fp_state_says_so() {
    let img = fixture::image(CoreArch::X86_64);
    let ns = Image::new(&img).notes();
    let second = ns.iter().filter(|n| n.ty == NT_PRSTATUS).nth(1).expect("second thread");
    assert_eq!(rd32(&second.desc, CoreArch::X86_64.pr_fpvalid_off()), 0);
    assert_eq!(rd32(&second.desc, PR_PID_OFF) as i32, fixture::TID_WORKER);
}

#[test]
fn fp_note_is_the_arch_length() {
    for arch in [CoreArch::X86_64, CoreArch::Aarch64] {
        let img = fixture::image(arch);
        let n = Image::new(&img).note(NT_PRFPREG);
        assert_eq!(n.desc.len(), arch.fpregset_bytes());
        assert_eq!(n.desc, fixture::fpregs(arch, 0x22));
    }
}

#[test]
fn prpsinfo_fields_land_at_their_offsets() {
    let img = fixture::image(CoreArch::X86_64);
    let d = Image::new(&img).note(NT_PRPSINFO).desc;
    assert_eq!(d.len(), PRPSINFO_BYTES);
    assert_eq!(d[PSINFO_STATE_OFF], CoreState::Running.index());
    assert_eq!(d[PSINFO_SNAME_OFF], b'R');
    assert_eq!(d[PSINFO_ZOMB_OFF], 0);
    assert_eq!(d[PSINFO_NICE_OFF] as i8, -5);
    assert_eq!(rd64(&d, PSINFO_FLAG_OFF), fixture::identity().flag);
    assert_eq!(rd32(&d, PSINFO_UID_OFF), fixture::UID);
    assert_eq!(rd32(&d, PSINFO_GID_OFF), fixture::GID);
    assert_eq!(rd32(&d, PSINFO_PID_OFF) as i32, fixture::PID);
    assert_eq!(rd32(&d, PSINFO_PPID_OFF) as i32, fixture::PPID);
    assert_eq!(rd32(&d, PSINFO_PGRP_OFF) as i32, fixture::PGRP);
    assert_eq!(rd32(&d, PSINFO_SID_OFF) as i32, fixture::SID);
    assert_eq!(&d[PSINFO_FNAME_OFF..PSINFO_FNAME_OFF + fixture::COMM.len()], fixture::COMM);
    assert_eq!(d[PSINFO_FNAME_OFF + fixture::COMM.len()], 0);
    assert_eq!(
        &d[PSINFO_PSARGS_OFF..PSINFO_PSARGS_OFF + fixture::PSARGS.len()],
        b"gnome-shell --mode user ",
        "the argument block's separators render as spaces",
    );
}

#[test]
fn zombie_state_sets_both_derived_fields() {
    let mut id = fixture::identity();
    id.state = CoreState::Zombie;
    let d = notes::prpsinfo(&id);
    assert_eq!(d[PSINFO_STATE_OFF], 4);
    assert_eq!(d[PSINFO_SNAME_OFF], b'Z');
    assert_eq!(d[PSINFO_ZOMB_OFF], 1);
}

#[test]
fn oversized_identity_strings_keep_their_terminator() {
    let long = b"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz\
0123456789abcdefghijklmnopqrstuvwxyz";
    let mut id = fixture::identity();
    id.comm = long;
    id.psargs = long;
    let d = notes::prpsinfo(&id);
    assert_eq!(d[PSINFO_FNAME_OFF + PSINFO_FNAME_BYTES - 1], 0);
    assert_eq!(&d[PSINFO_FNAME_OFF..PSINFO_FNAME_OFF + 15], &long[..15]);
    assert_eq!(d[PSINFO_PSARGS_OFF + PSINFO_PSARGS_BYTES - 1], 0);
    assert_eq!(&d[PSINFO_PSARGS_OFF..PSINFO_PSARGS_OFF + 79], &long[..79]);
}

#[test]
fn auxv_note_is_the_blob_verbatim() {
    let img = fixture::image(CoreArch::Aarch64);
    assert_eq!(Image::new(&img).note(NT_AUXV).desc, fixture::auxv());
}

#[test]
fn siginfo_note_is_omitted_when_absent() {
    let arch = CoreArch::X86_64;
    let r = fixture::regs(arch, 3);
    let threads = [fixture::thread(fixture::TID_MAIN, &r, None)];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: &[], auxv: &[],
        siginfo: None,
    };
    let mut mem = fixture::full_reader();
    let img = crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap();
    let types: alloc::vec::Vec<u32> = Image::new(&img).notes().iter().map(|n| n.ty).collect();
    assert_eq!(types, alloc::vec![NT_PRSTATUS, NT_PRPSINFO, NT_AUXV]);
}

#[test]
fn a_wrong_shaped_register_block_is_refused() {
    let arch = CoreArch::X86_64;
    let short = alloc::vec![0u8; arch.gregset_bytes() - 8];
    let threads = [fixture::thread(fixture::TID_MAIN, &short, None)];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: &[], auxv: &[],
        siginfo: None,
    };
    let mut mem = fixture::full_reader();
    let r = crate::coredump::elf::build::build_core_image(&input, &mut mem);
    assert_eq!(r.unwrap_err(), CoreImageError::RegsLen);
}

#[test]
fn an_aarch64_block_is_not_accepted_for_x86() {
    let regs = fixture::regs(CoreArch::Aarch64, 0);
    let threads = [fixture::thread(fixture::TID_MAIN, &regs, None)];
    let input = CoreImageInput {
        arch: CoreArch::X86_64, identity: fixture::identity(), threads: &threads, segments: &[],
        auxv: &[], siginfo: None,
    };
    let mut mem = fixture::full_reader();
    assert_eq!(
        crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap_err(),
        CoreImageError::RegsLen,
    );
}

#[test]
fn an_image_without_a_thread_is_refused() {
    let input = CoreImageInput {
        arch: CoreArch::X86_64, identity: fixture::identity(), threads: &[], segments: &[],
        auxv: &[], siginfo: None,
    };
    let mut mem = fixture::full_reader();
    assert_eq!(
        crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap_err(),
        CoreImageError::NoThreads,
    );
}

#[test]
fn a_wrong_sized_signal_descriptor_is_refused() {
    let arch = CoreArch::X86_64;
    let r = fixture::regs(arch, 0);
    let threads = [fixture::thread(fixture::TID_MAIN, &r, None)];
    let si = alloc::vec![0u8; 16];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: &[], auxv: &[],
        siginfo: Some(&si),
    };
    let mut mem = fixture::full_reader();
    assert_eq!(
        crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap_err(),
        CoreImageError::SiginfoLen,
    );
}

#[test]
fn a_wrong_sized_fp_block_is_refused() {
    let arch = CoreArch::Aarch64;
    let r = fixture::regs(arch, 0);
    let fp = alloc::vec![0u8; 512];
    let threads = [fixture::thread(fixture::TID_MAIN, &r, Some(&fp))];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: &[], auxv: &[],
        siginfo: None,
    };
    let mut mem = fixture::full_reader();
    assert_eq!(
        crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap_err(),
        CoreImageError::FpregsLen,
    );
}
