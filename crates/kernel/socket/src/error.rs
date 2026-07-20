#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Error {
    Eperm = 1, Enoent = 2, Esrch = 3, Eintr = 4, Eio = 5, Enxio = 6,
    Ebadf = 9, Eagain = 11, Enomem = 12, Eacces = 13, Efault = 14,
    Enotblk = 15, Ebusy = 16, Eexist = 17, Exdev = 18, Enodev = 19, Enotdir = 20, Eisdir = 21,
    Einval = 22, Emfile = 24, Enotty = 25, Etxtbsy = 26, Efbig = 27, Enospc = 28,
    Espipe = 29, Erofs = 30, Emlink = 31, Epipe = 32, Enametoolong = 36,
    Enosys = 38, Enotempty = 39, Eloop = 40, Ebade = 52, Enodata = 61,
    Emsgsize = 90, Enoprotoopt = 92, Esocktnosupport = 94,
    Eopnotsupp = 95, Eafnosupport = 97, Eaddrinuse = 98,
    Eaddrnotavail = 99, Enetdown = 100, Enetunreach = 101, Econnreset = 104,
    Enobufs = 105, Eisconn = 106, Enotconn = 107, Etimedout = 110,
    Econnrefused = 111, Ehostdown = 112, Ehostunreach = 113,
    Ealready = 114, Einprogress = 115, Enonet = 64, Eproto = 71,
    Edestaddrreq = 89, Enotsock = 88, Erange = 34, Euclean = 117,
    Edquot = 122, Ecanceled = 125,
}

pub type KResult<T> = core::result::Result<T, Error>;

impl Error {
    /// Positive Linux errno represented by this work error. # C: O(1)
    pub fn errno(self) -> i32 { self as i32 }
}

impl From<vfs::VfsError> for Error {
    fn from(e: vfs::VfsError) -> Self {
        match e {
            vfs::VfsError::Eperm => Self::Eperm, vfs::VfsError::Enoent => Self::Enoent,
            vfs::VfsError::Esrch => Self::Esrch, vfs::VfsError::Eintr => Self::Eintr,
            vfs::VfsError::Eio => Self::Eio, vfs::VfsError::Enxio => Self::Enxio,
            vfs::VfsError::Ebadf => Self::Ebadf, vfs::VfsError::Eagain => Self::Eagain,
            vfs::VfsError::Enomem => Self::Enomem, vfs::VfsError::Eacces => Self::Eacces,
            vfs::VfsError::Efault => Self::Efault, vfs::VfsError::Enotblk => Self::Enotblk,
            vfs::VfsError::Ebusy => Self::Ebusy,
            vfs::VfsError::Eexist => Self::Eexist, vfs::VfsError::Exdev => Self::Exdev,
            vfs::VfsError::Enodev => Self::Enodev, vfs::VfsError::Enotdir => Self::Enotdir,
            vfs::VfsError::Eisdir => Self::Eisdir, vfs::VfsError::Einval => Self::Einval,
            vfs::VfsError::Emfile => Self::Emfile, vfs::VfsError::Enotty => Self::Enotty,
            vfs::VfsError::Etxtbsy => Self::Etxtbsy, vfs::VfsError::Efbig => Self::Efbig,
            vfs::VfsError::Enospc => Self::Enospc, vfs::VfsError::Espipe => Self::Espipe,
            vfs::VfsError::Erofs => Self::Erofs, vfs::VfsError::Emlink => Self::Emlink,
            vfs::VfsError::Epipe => Self::Epipe, vfs::VfsError::Erange => Self::Erange,
            vfs::VfsError::Enametoolong => Self::Enametoolong, vfs::VfsError::Enosys => Self::Enosys,
            vfs::VfsError::Enotempty => Self::Enotempty, vfs::VfsError::Eloop => Self::Eloop,
            vfs::VfsError::Ebade => Self::Ebade, vfs::VfsError::Enodata => Self::Enodata,
            vfs::VfsError::Enonet => Self::Enonet,
            vfs::VfsError::Emsgsize => Self::Emsgsize,
            vfs::VfsError::Eproto => Self::Eproto, vfs::VfsError::Edestaddrreq => Self::Edestaddrreq,
            vfs::VfsError::Enoprotoopt => Self::Enoprotoopt,
            vfs::VfsError::Eopnotsupp => Self::Eopnotsupp,
            vfs::VfsError::Eaddrnotavail => Self::Eaddrnotavail,
            vfs::VfsError::Enetunreach => Self::Enetunreach,
            vfs::VfsError::Econnreset => Self::Econnreset, vfs::VfsError::Enobufs => Self::Enobufs,
            vfs::VfsError::Enotconn => Self::Enotconn, vfs::VfsError::Etimedout => Self::Etimedout,
            vfs::VfsError::Econnrefused => Self::Econnrefused,
            vfs::VfsError::Ehostdown => Self::Ehostdown, vfs::VfsError::Ehostunreach => Self::Ehostunreach,
            vfs::VfsError::Euclean => Self::Euclean, vfs::VfsError::Edquot => Self::Edquot,
            vfs::VfsError::Ecanceled => Self::Ecanceled,
        }
    }
}

impl From<net::NetError> for Error {
    fn from(e: net::NetError) -> Self {
        match e {
            net::NetError::Eagain => Self::Eagain, net::NetError::Eio => Self::Eio,
            net::NetError::Einval => Self::Einval, net::NetError::Enobufs => Self::Enobufs,
            net::NetError::Enomem => Self::Enomem, net::NetError::Eaddrnotavail => Self::Eaddrnotavail,
            net::NetError::Edestaddrreq => Self::Edestaddrreq, net::NetError::Emsgsize => Self::Emsgsize,
            net::NetError::Eaddrinuse => Self::Eaddrinuse, net::NetError::Enodev => Self::Enxio,
            net::NetError::Enetdown => Self::Enetdown,
            net::NetError::Enetunreach => Self::Enetunreach, net::NetError::Ehostunreach => Self::Ehostunreach,
            net::NetError::Eacces => Self::Eacces, net::NetError::Enonet => Self::Enonet,
            net::NetError::Enoprotoopt => Self::Enoprotoopt, net::NetError::Eopnotsupp => Self::Eopnotsupp,
            net::NetError::Esocktnosupport => Self::Esocktnosupport,
            net::NetError::Eproto => Self::Eproto, net::NetError::Ehostdown => Self::Ehostdown,
            net::NetError::Eafnosupport => Self::Eafnosupport, net::NetError::Eisconn => Self::Eisconn,
            net::NetError::Ealready => Self::Ealready, net::NetError::Einprogress => Self::Einprogress,
            net::NetError::Ebusy => Self::Ebusy,
            net::NetError::Enospc => Self::Enospc, net::NetError::Eperm => Self::Eperm,
            net::NetError::Enotconn => Self::Enotconn, net::NetError::Erange => Self::Erange,
            net::NetError::Econnrefused => Self::Econnrefused, net::NetError::Econnreset => Self::Econnreset,
            net::NetError::Etimedout => Self::Etimedout, net::NetError::Epipe => Self::Epipe,
            net::NetError::Enoent => Self::Enoent, net::NetError::Eintr => Self::Eintr,
        }
    }
}

impl From<netlink::SendError> for Error {
    fn from(e: netlink::SendError) -> Self {
        match e {
            netlink::SendError::Emsgsize => Self::Emsgsize,
            netlink::SendError::Backend(error) => Self::from(error),
        }
    }
}
