/* pamtest — drive pam_authenticate("login", user, pw) end-to-end via
 * the same libpam.so / pam_unix.so login uses, so we observe the real
 * PAM return codes without patching vendor source.
 *
 * Run from /etc/init.d/oxide-smokes to confirm whether login auth is
 * working in the current build. Useful for B18 diagnostics — currently
 * shows pam_authenticate returning AUTH_ERR (7) because pam_unix's
 * helper fork → libpam.so `pam_modutil_sanitize_helper_fds` SIGSEGVs
 * in the forked child (kernel-side fork+libpam.so interaction bug). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <security/pam_appl.h>

static int conv_fn(int n, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata) {
    const char *pw = appdata;
    struct pam_response *r = calloc(n, sizeof(*r));
    if (!r) return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        printf("[pamtest] conv style=%d msg=[%s]\n",
               msg[i]->msg_style, msg[i]->msg ? msg[i]->msg : "");
        r[i].resp = strdup(pw);
        r[i].resp_retcode = 0;
    }
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "alice";
    const char *pw   = argc > 2 ? argv[2] : "swordfish";
    struct pam_conv conv = { conv_fn, (void *)pw };
    pam_handle_t *pamh = NULL;
    int rc;
    rc = pam_start("login", user, &conv, &pamh);
    printf("[pamtest] pam_start rc=%d (%s)\n", rc, pam_strerror(pamh, rc));
    if (rc != PAM_SUCCESS) return 1;
    rc = pam_authenticate(pamh, 0);
    printf("[pamtest] pam_authenticate rc=%d (%s)\n", rc, pam_strerror(pamh, rc));
    int auth_rc = rc;
    rc = pam_acct_mgmt(pamh, 0);
    printf("[pamtest] pam_acct_mgmt rc=%d (%s)\n", rc, pam_strerror(pamh, rc));
    pam_end(pamh, rc);
    return auth_rc == PAM_SUCCESS ? 0 : 2;
}
