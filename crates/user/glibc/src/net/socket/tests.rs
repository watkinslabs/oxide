use super::*;
    fn struct_sizes_match_host() {
        assert_eq!(core::mem::size_of::<sockaddr>(), core::mem::size_of::<libc::sockaddr>());
        assert_eq!(core::mem::size_of::<sockaddr_in>(), core::mem::size_of::<libc::sockaddr_in>());
        assert_eq!(core::mem::size_of::<sockaddr_in6>(), core::mem::size_of::<libc::sockaddr_in6>());
        assert_eq!(core::mem::size_of::<sockaddr_storage>(), core::mem::size_of::<libc::sockaddr_storage>());
        assert_eq!(core::mem::size_of::<msghdr>(), core::mem::size_of::<libc::msghdr>());
        assert_eq!(core::mem::size_of::<iovec>(), core::mem::size_of::<libc::iovec>());
    }
