use super::*;
    use crate::malloc::heap;
    use crate::nss::shared::read_file;
    use crate::string::len::strlen_impl;
    use core::ffi::c_char;

    unsafe fn slice_or_empty<'a>(p: *const u8) -> &'a [u8] {
        // SAFETY: p is null or a NUL-terminated C string.
        unsafe { if p.is_null() { &[] } else { core::slice::from_raw_parts(p, strlen_impl(p)) } }
    }

    unsafe fn query_dns_sockaddr(node: *const u8, port: u16, want: i32) -> Result<Option<(i32, [u8; 28], u32)>, i32> {
        // SAFETY: node is a non-null NUL-terminated hostname from getaddrinfo.
        unsafe {
            let qtypes: &[u16] = if want == AF_INET6 as i32 {
                &[T_AAAA]
            } else if want == AF_INET as i32 {
                &[T_A]
            } else {
                &[T_A, T_AAAA]
            };
            for &qtype in qtypes {
                let mut answer = [0u8; 2048];
                let r = crate::net::resolv_query::res_query(
                    node as *const c_char,
                    C_IN as i32,
                    qtype as i32,
                    answer.as_mut_ptr(),
                    answer.len() as i32,
                );
                if r < 0 {
                    return Err(EAI_AGAIN);
                }
                if let Some(t) = fill_sockaddr_from_dns(&answer[..r as usize], port, want) {
                    return Ok(Some(t));
                }
            }
            Ok(None)
        }
    }

    // # C: int getaddrinfo(const char *node, const char *service,
    //                      const struct addrinfo *hints, struct addrinfo **res)
    #[no_mangle]
    pub unsafe extern "C" fn getaddrinfo(node: *const u8, service: *const u8, hints: *const addrinfo, res: *mut *mut addrinfo) -> i32 {
        // SAFETY: node/service null or C strings; hints null or a valid
        // addrinfo; res a writable out-param. We build one numeric result.
        unsafe {
            let want = if hints.is_null() { 0 } else { (*hints).ai_family };
            let flags = if hints.is_null() { 0 } else { (*hints).ai_flags };
            let socktype = if hints.is_null() { 0 } else { (*hints).ai_socktype };
            let service_name = slice_or_empty(service);
            let port = if service_name.is_empty() {
                0
            } else if service_name.iter().all(|b| b.is_ascii_digit()) {
                match parse_numeric_port(service_name) { Some(p) => p, None => return EAI_SERVICE }
            } else {
                if flags & AI_NUMERICSERV != 0 {
                    return EAI_NONAME;
                }
                let services = read_file(b"/etc/services\0").unwrap_or_default();
                match parse_port_with_services(service_name, socktype, &services) {
                    Some(p) => p,
                    None => return EAI_SERVICE,
                }
            };
            let n = slice_or_empty(node);
            let (fam, bytes, len) = match fill_sockaddr(n, port, want) {
                Some(t) => t,
                None => {
                    if flags & AI_NUMERICHOST != 0 {
                        return EAI_NONAME;
                    }
                    match read_file(b"/etc/hosts\0")
                        .and_then(|hosts| fill_sockaddr_from_hosts(&hosts, n, port, want))
                    {
                        Some(t) => t,
                        None => {
                            match query_dns_sockaddr(node, port, want) {
                                Ok(Some(t)) => t,
                                Ok(None) => return EAI_NONAME,
                                Err(e) => return e,
                            }
                        }
                    }
                }
            };
            let _ = flags;
            let sa = heap::malloc(len as usize);
            let ai = heap::malloc(core::mem::size_of::<addrinfo>()) as *mut addrinfo;
            if sa.is_null() || ai.is_null() { return EAI_MEMORY; }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), sa, len as usize);
            (*ai).ai_flags = 0;
            (*ai).ai_family = fam;
            (*ai).ai_socktype = if socktype != 0 { socktype } else { 1 };
            (*ai).ai_protocol = 0;
            (*ai).ai_addrlen = len;
            (*ai).__pad = 0;
            (*ai).ai_addr = sa as *mut core::ffi::c_void;
            (*ai).ai_canonname = core::ptr::null_mut();
            (*ai).ai_next = core::ptr::null_mut();
            *res = ai;
            0
        }
    }

    // # C: void freeaddrinfo(struct addrinfo *res)
    #[no_mangle]
    pub unsafe extern "C" fn freeaddrinfo(mut res: *mut addrinfo) {
        // SAFETY: res is a chain from getaddrinfo; free each node + its addr.
        unsafe {
            while !res.is_null() {
                let next = (*res).ai_next;
                if !(*res).ai_addr.is_null() { heap::free((*res).ai_addr as *mut u8); }
                if !(*res).ai_canonname.is_null() { heap::free((*res).ai_canonname); }
                heap::free(res as *mut u8);
                res = next;
            }
        }
    }

    // # C: const char *gai_strerror(int ecode)
    #[no_mangle]
    pub extern "C" fn gai_strerror(ecode: i32) -> *const u8 {
        let s: &[u8] = match ecode {
            0 => b"Success\0",
            EAI_BADFLAGS => b"Bad value for ai_flags\0",
            EAI_NONAME => b"Name or service not known\0",
            EAI_AGAIN => b"Temporary failure in name resolution\0",
            EAI_FAIL => b"Non-recoverable failure in name resolution\0",
            EAI_NODATA => b"No address associated with hostname\0",
            EAI_FAMILY => b"ai_family not supported\0",
            EAI_SOCKTYPE => b"ai_socktype not supported\0",
            EAI_SERVICE => b"Servname not supported for ai_socktype\0",
            EAI_ADDRFAMILY => b"Address family for hostname not supported\0",
            EAI_MEMORY => b"Memory allocation failure\0",
            EAI_SYSTEM => b"System error\0",
            EAI_OVERFLOW => b"Result too large for supplied buffer\0",
            EAI_INPROGRESS => b"Processing request in progress\0",
            EAI_CANCELED => b"Request canceled\0",
            EAI_NOTCANCELED => b"Request not canceled\0",
            EAI_ALLDONE => b"All requests done\0",
            EAI_INTR => b"Interrupted by a signal\0",
            EAI_IDN_ENCODE => b"Parameter string not correctly encoded\0",
            _ => b"Unknown error\0",
        };
        s.as_ptr()
    }

    // # C: int gai_error(struct gaicb *req)
    #[no_mangle]
    pub unsafe extern "C" fn gai_error(req: *mut gaicb) -> i32 {
        // SAFETY: req is a caller-owned gaicb; read its glibc-compatible status slot.
        unsafe { (*req).__return }
    }

    // # C: int gai_cancel(struct gaicb *gaicbp)
    #[no_mangle]
    pub extern "C" fn gai_cancel(_gaicbp: *mut gaicb) -> i32 {
        EAI_ALLDONE
    }

    // # C: int gai_suspend(const struct gaicb *const list[], int ent,
    //                      const struct timespec *timeout)
    #[no_mangle]
    pub extern "C" fn gai_suspend(_list: *const *const gaicb, _ent: i32, _timeout: *const core::ffi::c_void) -> i32 {
        EAI_ALLDONE
    }

    // # C: int getaddrinfo_a(int mode, struct gaicb *list[], int ent,
    //                        struct sigevent *sig)
    #[no_mangle]
    pub unsafe extern "C" fn getaddrinfo_a(mode: i32, list: *mut *mut gaicb, ent: i32, _sig: *mut core::ffi::c_void) -> i32 {
        // SAFETY: list points to ent gaicb pointers supplied by the caller.
        // This compatibility path completes each non-null request immediately.
        unsafe {
            if mode != GAI_WAIT && mode != GAI_NOWAIT {
                crate::internal::errno::set(EINVAL);
                return EAI_SYSTEM;
            }
            for i in 0..ent {
                let req = *list.add(i as usize);
                if req.is_null() { continue; }
                (*req).ar_result = core::ptr::null_mut();
                let r = getaddrinfo((*req).ar_name, (*req).ar_service, (*req).ar_request, &mut (*req).ar_result);
                (*req).__return = r;
            }
            0
        }
    }

    // # C: int getnameinfo(const struct sockaddr *sa, socklen_t salen,
    //                      char *host, socklen_t hostlen, char *serv,
    //                      socklen_t servlen, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn getnameinfo(sa: *const u8, _salen: u32, host: *mut u8, hostlen: u32, serv: *mut u8, servlen: u32, _flags: i32) -> i32 {
        // SAFETY: sa is a sockaddr (family in the first u16); host/serv are
        // writable for their lengths. Numeric reverse only.
        unsafe {
            if sa.is_null() { return EAI_FAIL; }
            let fam = u16::from_le_bytes([*sa, *sa.add(1)]);
            let port_be = u16::from_be_bytes([*sa.add(2), *sa.add(3)]);
            if !host.is_null() && hostlen > 0 {
                let mut buf = [0u8; super::inet::INET6_ADDRSTRLEN];
                let n = if fam == AF_INET {
                    let mut a = [0u8; 4]; core::ptr::copy_nonoverlapping(sa.add(4), a.as_mut_ptr(), 4);
                    inet::ntop4(&a, &mut buf)
                } else if fam == AF_INET6 {
                    let mut a = [0u8; 16]; core::ptr::copy_nonoverlapping(sa.add(8), a.as_mut_ptr(), 16);
                    inet::ntop6(&a, &mut buf)
                } else { return EAI_FAMILY };
                match n {
                    Some(len) if (len as u32) < hostlen => { core::ptr::copy_nonoverlapping(buf.as_ptr(), host, len); *host.add(len) = 0; }
                    _ => return EAI_SYSTEM,
                }
            }
            if !serv.is_null() && servlen > 0 {
                let mut tmp = [0u8; 8];
                let mut v = port_be as u32;
                let mut k = 0;
                if v == 0 { tmp[0] = b'0'; k = 1; } else { while v > 0 { tmp[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; } }
                if (k as u32) >= servlen { return EAI_SYSTEM; }
                for j in 0..k { *serv.add(j) = tmp[k - 1 - j]; }
                *serv.add(k) = 0;
            }
            0
        }
    }
