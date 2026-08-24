use syscall::errno::Errno;

use super::super::attr::{self, Attr, Caps};
use super::super::uapi;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct Load {
    pub data: u64,
    pub size: u32,
}

pub(super) fn load(a: &Attr, caps: Caps) -> Result<Load, Errno> {
    use uapi::off::btf_load as o;
    attr::check_attr(a, o::LAST_END)?;
    let flags = a.u32_at(o::FLAGS);
    if flags & !uapi::btf_flags::TOKEN_FD != 0 { return Err(Errno::Einval); }
    let token = if flags & uapi::btf_flags::TOKEN_FD != 0 {
        Some(super::super::token::from_fd(a.u32_at(o::TOKEN_FD))?)
    } else { None };
    let token_capable = token.is_some_and(|t|
        t.allowed_cmds & (1u64 << uapi::cmd::BTF_LOAD) != 0);
    if !caps.bpf_capable() && !token_capable { return Err(Errno::Eperm); }
    Ok(Load { data: a.u64_at(o::DATA), size: a.u32_at(o::DATA_SIZE) })
}

pub(super) fn get_fd_by_id(a: &Attr, caps: Caps) -> Result<u32, Errno> {
    use uapi::off::object_id as o;
    attr::check_attr(a, o::FD_LAST_END)?;
    let flags = a.u32_at(o::FLAGS);
    if flags & !uapi::btf_flags::TOKEN_FD != 0 { return Err(Errno::Einval); }
    if flags & uapi::btf_flags::TOKEN_FD != 0 {
        let _ = super::super::token::from_fd(a.u32_at(o::TOKEN_FD))?;
    }
    if !caps.sys_admin { return Err(Errno::Eperm); }
    Ok(a.u32_at(o::START_ID))
}

pub(super) fn object_info(a: &Attr) -> Result<(i32, u32, u64), Errno> {
    use uapi::off::object_info as o;
    attr::check_attr(a, o::LAST_END)?;
    Ok((a.u32_at(o::FD) as i32, a.u32_at(o::INFO_LEN), a.u64_at(o::INFO)))
}
