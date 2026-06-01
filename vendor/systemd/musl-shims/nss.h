/* Minimal musl shim for glibc's <nss.h>. musl has no NSS; -idirafter
 * /usr/include (needed for kernel UAPI) otherwise leaks glibc's nss.h
 * which doesn't compile under musl. systemd's nss-util.h only needs the
 * nss_status enum + the function-attribute conventions. Track D6. */
#ifndef _OXIDE_MUSL_NSS_H
#define _OXIDE_MUSL_NSS_H
enum nss_status {
    NSS_STATUS_TRYAGAIN = -2,
    NSS_STATUS_UNAVAIL  = -1,
    NSS_STATUS_NOTFOUND = 0,
    NSS_STATUS_SUCCESS  = 1,
    NSS_STATUS_RETURN   = 2,
};
#define NSS_STATUS_TRYAGAIN NSS_STATUS_TRYAGAIN
#endif
