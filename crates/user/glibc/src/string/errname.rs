// strerrorname_np / strerrordesc_np (docs/59§6 G4) — GNU errno introspection:
// the macro NAME ("EPERM") and the canonical description ("Operation not
// permitted") for an errno, or NULL for an undefined number. Single complete
// Linux asm-generic table (identical numbering on x86_64 + aarch64); strerror's
// message table delegates here so the two never diverge. C ABI exports gated.

/// (name, description) for `e`, or None for undefined. # C: errno → (name, desc)
pub(crate) fn ent(e: i32) -> Option<(&'static [u8], &'static [u8])> {
    Some(match e {
        0 => (b"0\0", b"Success\0"), // glibc names errno 0 literally "0"
        1 => (b"EPERM\0", b"Operation not permitted\0"),
        2 => (b"ENOENT\0", b"No such file or directory\0"),
        3 => (b"ESRCH\0", b"No such process\0"),
        4 => (b"EINTR\0", b"Interrupted system call\0"),
        5 => (b"EIO\0", b"Input/output error\0"),
        6 => (b"ENXIO\0", b"No such device or address\0"),
        7 => (b"E2BIG\0", b"Argument list too long\0"),
        8 => (b"ENOEXEC\0", b"Exec format error\0"),
        9 => (b"EBADF\0", b"Bad file descriptor\0"),
        10 => (b"ECHILD\0", b"No child processes\0"),
        11 => (b"EAGAIN\0", b"Resource temporarily unavailable\0"),
        12 => (b"ENOMEM\0", b"Cannot allocate memory\0"),
        13 => (b"EACCES\0", b"Permission denied\0"),
        14 => (b"EFAULT\0", b"Bad address\0"),
        15 => (b"ENOTBLK\0", b"Block device required\0"),
        16 => (b"EBUSY\0", b"Device or resource busy\0"),
        17 => (b"EEXIST\0", b"File exists\0"),
        18 => (b"EXDEV\0", b"Invalid cross-device link\0"),
        19 => (b"ENODEV\0", b"No such device\0"),
        20 => (b"ENOTDIR\0", b"Not a directory\0"),
        21 => (b"EISDIR\0", b"Is a directory\0"),
        22 => (b"EINVAL\0", b"Invalid argument\0"),
        23 => (b"ENFILE\0", b"Too many open files in system\0"),
        24 => (b"EMFILE\0", b"Too many open files\0"),
        25 => (b"ENOTTY\0", b"Inappropriate ioctl for device\0"),
        26 => (b"ETXTBSY\0", b"Text file busy\0"),
        27 => (b"EFBIG\0", b"File too large\0"),
        28 => (b"ENOSPC\0", b"No space left on device\0"),
        29 => (b"ESPIPE\0", b"Illegal seek\0"),
        30 => (b"EROFS\0", b"Read-only file system\0"),
        31 => (b"EMLINK\0", b"Too many links\0"),
        32 => (b"EPIPE\0", b"Broken pipe\0"),
        33 => (b"EDOM\0", b"Numerical argument out of domain\0"),
        34 => (b"ERANGE\0", b"Numerical result out of range\0"),
        35 => (b"EDEADLK\0", b"Resource deadlock avoided\0"),
        36 => (b"ENAMETOOLONG\0", b"File name too long\0"),
        37 => (b"ENOLCK\0", b"No locks available\0"),
        38 => (b"ENOSYS\0", b"Function not implemented\0"),
        39 => (b"ENOTEMPTY\0", b"Directory not empty\0"),
        40 => (b"ELOOP\0", b"Too many levels of symbolic links\0"),
        42 => (b"ENOMSG\0", b"No message of desired type\0"),
        43 => (b"EIDRM\0", b"Identifier removed\0"),
        44 => (b"ECHRNG\0", b"Channel number out of range\0"),
        45 => (b"EL2NSYNC\0", b"Level 2 not synchronized\0"),
        46 => (b"EL3HLT\0", b"Level 3 halted\0"),
        47 => (b"EL3RST\0", b"Level 3 reset\0"),
        48 => (b"ELNRNG\0", b"Link number out of range\0"),
        49 => (b"EUNATCH\0", b"Protocol driver not attached\0"),
        50 => (b"ENOCSI\0", b"No CSI structure available\0"),
        51 => (b"EL2HLT\0", b"Level 2 halted\0"),
        52 => (b"EBADE\0", b"Invalid exchange\0"),
        53 => (b"EBADR\0", b"Invalid request descriptor\0"),
        54 => (b"EXFULL\0", b"Exchange full\0"),
        55 => (b"ENOANO\0", b"No anode\0"),
        56 => (b"EBADRQC\0", b"Invalid request code\0"),
        57 => (b"EBADSLT\0", b"Invalid slot\0"),
        59 => (b"EBFONT\0", b"Bad font file format\0"),
        60 => (b"ENOSTR\0", b"Device not a stream\0"),
        61 => (b"ENODATA\0", b"No data available\0"),
        62 => (b"ETIME\0", b"Timer expired\0"),
        63 => (b"ENOSR\0", b"Out of streams resources\0"),
        64 => (b"ENONET\0", b"Machine is not on the network\0"),
        65 => (b"ENOPKG\0", b"Package not installed\0"),
        66 => (b"EREMOTE\0", b"Object is remote\0"),
        67 => (b"ENOLINK\0", b"Link has been severed\0"),
        68 => (b"EADV\0", b"Advertise error\0"),
        69 => (b"ESRMNT\0", b"Srmount error\0"),
        70 => (b"ECOMM\0", b"Communication error on send\0"),
        71 => (b"EPROTO\0", b"Protocol error\0"),
        72 => (b"EMULTIHOP\0", b"Multihop attempted\0"),
        73 => (b"EDOTDOT\0", b"RFS specific error\0"),
        74 => (b"EBADMSG\0", b"Bad message\0"),
        75 => (b"EOVERFLOW\0", b"Value too large for defined data type\0"),
        76 => (b"ENOTUNIQ\0", b"Name not unique on network\0"),
        77 => (b"EBADFD\0", b"File descriptor in bad state\0"),
        78 => (b"EREMCHG\0", b"Remote address changed\0"),
        79 => (b"ELIBACC\0", b"Can not access a needed shared library\0"),
        80 => (b"ELIBBAD\0", b"Accessing a corrupted shared library\0"),
        81 => (b"ELIBSCN\0", b".lib section in a.out corrupted\0"),
        82 => (b"ELIBMAX\0", b"Attempting to link in too many shared libraries\0"),
        83 => (b"ELIBEXEC\0", b"Cannot exec a shared library directly\0"),
        84 => (b"EILSEQ\0", b"Invalid or incomplete multibyte or wide character\0"),
        85 => (b"ERESTART\0", b"Interrupted system call should be restarted\0"),
        86 => (b"ESTRPIPE\0", b"Streams pipe error\0"),
        87 => (b"EUSERS\0", b"Too many users\0"),
        88 => (b"ENOTSOCK\0", b"Socket operation on non-socket\0"),
        89 => (b"EDESTADDRREQ\0", b"Destination address required\0"),
        90 => (b"EMSGSIZE\0", b"Message too long\0"),
        91 => (b"EPROTOTYPE\0", b"Protocol wrong type for socket\0"),
        92 => (b"ENOPROTOOPT\0", b"Protocol not available\0"),
        93 => (b"EPROTONOSUPPORT\0", b"Protocol not supported\0"),
        94 => (b"ESOCKTNOSUPPORT\0", b"Socket type not supported\0"),
        95 => (b"EOPNOTSUPP\0", b"Operation not supported\0"),
        96 => (b"EPFNOSUPPORT\0", b"Protocol family not supported\0"),
        97 => (b"EAFNOSUPPORT\0", b"Address family not supported by protocol\0"),
        98 => (b"EADDRINUSE\0", b"Address already in use\0"),
        99 => (b"EADDRNOTAVAIL\0", b"Cannot assign requested address\0"),
        100 => (b"ENETDOWN\0", b"Network is down\0"),
        101 => (b"ENETUNREACH\0", b"Network is unreachable\0"),
        102 => (b"ENETRESET\0", b"Network dropped connection on reset\0"),
        103 => (b"ECONNABORTED\0", b"Software caused connection abort\0"),
        104 => (b"ECONNRESET\0", b"Connection reset by peer\0"),
        105 => (b"ENOBUFS\0", b"No buffer space available\0"),
        106 => (b"EISCONN\0", b"Transport endpoint is already connected\0"),
        107 => (b"ENOTCONN\0", b"Transport endpoint is not connected\0"),
        108 => (b"ESHUTDOWN\0", b"Cannot send after transport endpoint shutdown\0"),
        109 => (b"ETOOMANYREFS\0", b"Too many references: cannot splice\0"),
        110 => (b"ETIMEDOUT\0", b"Connection timed out\0"),
        111 => (b"ECONNREFUSED\0", b"Connection refused\0"),
        112 => (b"EHOSTDOWN\0", b"Host is down\0"),
        113 => (b"EHOSTUNREACH\0", b"No route to host\0"),
        114 => (b"EALREADY\0", b"Operation already in progress\0"),
        115 => (b"EINPROGRESS\0", b"Operation now in progress\0"),
        116 => (b"ESTALE\0", b"Stale file handle\0"),
        117 => (b"EUCLEAN\0", b"Structure needs cleaning\0"),
        118 => (b"ENOTNAM\0", b"Not a XENIX named type file\0"),
        119 => (b"ENAVAIL\0", b"No XENIX semaphores available\0"),
        120 => (b"EISNAM\0", b"Is a named type file\0"),
        121 => (b"EREMOTEIO\0", b"Remote I/O error\0"),
        122 => (b"EDQUOT\0", b"Disk quota exceeded\0"),
        123 => (b"ENOMEDIUM\0", b"No medium found\0"),
        124 => (b"EMEDIUMTYPE\0", b"Wrong medium type\0"),
        125 => (b"ECANCELED\0", b"Operation canceled\0"),
        126 => (b"ENOKEY\0", b"Required key not available\0"),
        127 => (b"EKEYEXPIRED\0", b"Key has expired\0"),
        128 => (b"EKEYREVOKED\0", b"Key has been revoked\0"),
        129 => (b"EKEYREJECTED\0", b"Key was rejected by service\0"),
        130 => (b"EOWNERDEAD\0", b"Owner died\0"),
        131 => (b"ENOTRECOVERABLE\0", b"State not recoverable\0"),
        132 => (b"ERFKILL\0", b"Operation not possible due to RF-kill\0"),
        133 => (b"EHWPOISON\0", b"Memory page has hardware error\0"),
        _ => return None,
    })
}

/// Description for `e` (0 → "Success"). # C: errno → message
pub(crate) fn desc(e: i32) -> Option<&'static [u8]> {
    ent(e).map(|(_, d)| d)
}

#[cfg(feature = "freestanding")]
mod imp {
    // # C: const char *strerrorname_np(int errnum)
    #[no_mangle]
    pub extern "C" fn strerrorname_np(errnum: i32) -> *const u8 {
        match super::ent(errnum) { Some((n, _)) => n.as_ptr(), None => core::ptr::null() }
    }
    // # C: const char *strerrordesc_np(int errnum)
    #[no_mangle]
    pub extern "C" fn strerrordesc_np(errnum: i32) -> *const u8 {
        match super::desc(errnum) { Some(d) => d.as_ptr(), None => core::ptr::null() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spot() {
        assert_eq!(ent(1).unwrap().0, b"EPERM\0");
        assert_eq!(desc(0).unwrap(), b"Success\0");
        assert_eq!(desc(84).unwrap(), b"Invalid or incomplete multibyte or wide character\0");
        assert!(ent(41).is_none());
        assert_eq!(ent(0).unwrap().0, b"0\0");
    }
}
