/// `25§3` network result error.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NetError {
    Eagain,
    Eio,
    Einval,
    Enobufs,
    Enomem,
    Eaddrnotavail,
    Edestaddrreq,
    Emsgsize,
    Eaddrinuse,
    Enodev,
    Enetdown,
    Enetunreach,
    Ehostunreach,
    Eacces,
    Enonet,
    Enoprotoopt,
    Eopnotsupp,
    Esocktnosupport,
    Eproto,
    Ehostdown,
    Eafnosupport,
    Eisconn,
    Ealready,
    Ebusy,
    Enospc,
    Eperm,
    Einprogress,
    Enotconn,
    Erange,
    Econnrefused,
    Econnaborted,
    Econnreset,
    Etimedout,
    Epipe,
    Enoent,
    Eintr,
    /// Linux `ERESTARTSYS` — `sock_intr_errno(timeo)` (`include/net/sock.h:2759`)
    /// returns this for an interrupted socket wait with no SO_{RCV,SND}TIMEO;
    /// a wait that DID carry a timeout gets `Eintr`, because "with timeout
    /// socket operations are not restartable" (`sock.h:2755-2757`).
    Erestartsys,
}

pub type NetResult<T> = core::result::Result<T, NetError>;
