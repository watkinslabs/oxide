use alloc::sync::Arc;
use core::cell::RefCell;

use syscall::errno::Errno;

use super::bind_map::{bind_program_map, resolve};
use super::super::attr::{self, Attr, ProgBindMap};
use super::super::map;
use super::super::uapi;
use super::super::{BpfProgInode, make_bpf_prog_inode};

const TEST_PROG_FD: u32 = 3;
const TEST_MAP_FD: u32 = 4;
const TEST_SCALAR_SIZE: u32 = 4;

fn attr_with(prog_fd: u32, map_fd: u32, flags: u32) -> Attr {
    use uapi::off::prog_bind_map as o;
    let mut attr = Attr::zeroed();
    for (offset, value) in [(o::PROG_FD, prog_fd), (o::MAP_FD, map_fd), (o::FLAGS, flags)] {
        attr.bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    attr
}

#[test]
fn attr_tail_and_flags_precede_descriptor_resolution() {
    use uapi::off::prog_bind_map as o;
    const UNKNOWN_BIND_FLAG: u32 = 1;
    let mut tail = attr_with(TEST_PROG_FD, TEST_MAP_FD, 0);
    tail.bytes[o::LAST_END] = 1;
    assert_eq!(attr::prog_bind_map_check(&tail), Err(Errno::Einval));
    assert_eq!(
        attr::prog_bind_map_check(&attr_with(TEST_PROG_FD, TEST_MAP_FD, UNKNOWN_BIND_FLAG)),
        Err(Errno::Einval),
    );
    assert_eq!(
        attr::prog_bind_map_check(&attr_with(TEST_PROG_FD, TEST_MAP_FD, 0)),
        Ok(ProgBindMap { prog_fd: TEST_PROG_FD, map_fd: TEST_MAP_FD }),
    );
}

#[test]
fn program_descriptor_is_resolved_before_map_descriptor() {
    let events = RefCell::new(alloc::vec::Vec::new());
    let request = ProgBindMap { prog_fd: TEST_PROG_FD, map_fd: TEST_MAP_FD };
    let bad_program = resolve(
        request,
        |fd| {
            events.borrow_mut().push(fd);
            Err::<(), _>(Errno::Ebadf)
        },
        |fd| {
            events.borrow_mut().push(fd);
            Ok(())
        },
    );
    assert_eq!(bad_program, Err(Errno::Ebadf));
    assert_eq!(*events.borrow(), alloc::vec![TEST_PROG_FD as i32]);

    events.borrow_mut().clear();
    let bad_map = resolve(
        request,
        |fd| {
            events.borrow_mut().push(fd);
            Ok(())
        },
        |fd| {
            events.borrow_mut().push(fd);
            Err::<(), _>(Errno::Einval)
        },
    );
    assert_eq!(bad_map, Err(Errno::Einval));
    assert_eq!(
        *events.borrow(),
        alloc::vec![TEST_PROG_FD as i32, TEST_MAP_FD as i32],
    );
}

#[test]
fn binding_pins_one_canonical_map_reference_and_is_idempotent() {
    let program = make_bpf_prog_inode(uapi::prog_type::SOCKET_FILTER, alloc::vec::Vec::new());
    let prog = program.private::<BpfProgInode>().unwrap();
    let map = map::allocate(
        uapi::map_type::ARRAY, TEST_SCALAR_SIZE, TEST_SCALAR_SIZE, 1, 0,
    ).unwrap();
    let before = Arc::strong_count(&map);

    bind_program_map(prog, Arc::clone(&map)).unwrap();
    assert_eq!(prog.maps.lock().len(), 1);
    assert_eq!(Arc::strong_count(&map), before + 1);

    bind_program_map(prog, Arc::clone(&map)).unwrap();
    assert_eq!(prog.maps.lock().len(), 1);
    assert_eq!(Arc::strong_count(&map), before + 1);

    drop(program);
    assert_eq!(Arc::strong_count(&map), before);
}
