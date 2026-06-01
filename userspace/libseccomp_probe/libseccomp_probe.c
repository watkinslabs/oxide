/* libseccomp_probe — dynamic-link smoke for the cross-built libseccomp.so
 * (L2). Links /usr/lib/libseccomp.so; builds a tiny filter (default
 * ALLOW + a rule) and releases it. Exercises the library API without
 * actually loading the filter into the kernel (seccomp_load), so it
 * works regardless of kernel seccomp support — the point is the .so
 * loaded + resolved. systemd uses libseccomp for sandboxing. */
#include <stdio.h>
#include <seccomp.h>

int main(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { printf("libseccomp_probe: seccomp_init FAIL\n"); return 1; }
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), SCMP_SYS(ptrace), 0);
    seccomp_release(ctx);
    if (rc != 0) { printf("libseccomp_probe: rule_add rc=%d\n", rc); return 1; }
    printf("libseccomp_probe: libseccomp.so OK ver=%s\n", seccomp_version() ? "ok" : "?");
    return 0;
}
