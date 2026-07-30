use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::super::attr::{self, Attr, ProgBindMap};
use super::super::BpfProgInode;

pub(super) fn bind(a: &Attr) -> Result<i64, Errno> {
    let request = attr::prog_bind_map_check(a)?;
    let (prog_inode, map_inode) = resolve(
        request,
        |fd| super::attach::prog_inode_from_fd(fd),
        |fd| super::super::map::map_from_fd(fd as u32),
    )?;
    let prog = prog_inode.private::<BpfProgInode>().ok_or(Errno::Einval)?;
    bind_program_map(prog, map_inode)?;
    Ok(0)
}

pub(super) fn resolve<P, M>(
    request: ProgBindMap,
    program: impl FnOnce(i32) -> Result<P, Errno>,
    map: impl FnOnce(i32) -> Result<M, Errno>,
) -> Result<(P, M), Errno> {
    let prog = program(request.prog_fd as i32)?;
    let map = map(request.map_fd as i32)?;
    Ok((prog, map))
}

pub(super) fn bind_program_map(prog: &BpfProgInode, map: InodeRef) -> Result<(), Errno> {
    let mut maps = prog.maps.lock();
    if maps.iter().any(|bound| Arc::ptr_eq(bound, &map)) { return Ok(()); }
    maps.try_reserve(1).map_err(|_| Errno::Enomem)?;
    maps.push(map);
    Ok(())
}
