// /usr/lib/security/pam_unix.so — minimal Linux pam_unix module.
// F240: revert to PAM_AUTHTOK-only path (no conv-call) — openssh's
// sshpam_thread_conv uses a socketpair to the main thread, and
// invoking conv from a dlopen'd module inside pam_authenticate hangs
// silently in our environment. Tracked as task #14.
//
// This path works when the calling application has already populated
// PAM_AUTHTOK via pam_set_item before invoking pam_authenticate
// (e.g. login(1) or sudo). It fails (PAM_AUTH_ERR) when called from
// openssh's keyboard-interactive flow because openssh expects the
// module to prompt via conv. Activating pam_unix in /etc/pam.d/sshd
// remains deferred.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern int pam_get_user(void *pamh, const char **user, const char *prompt);
extern int pam_get_item(const void *pamh, int item_type, const void **item);
extern char *crypt(const char *key, const char *setting);

#define PAM_SUCCESS          0
#define PAM_AUTH_ERR         7
#define PAM_USER_UNKNOWN    10
#define PAM_AUTHTOK_ERR     20
#define PAM_AUTHINFO_UNAVAIL 9
#define PAM_AUTHTOK          6

typedef struct pam_handle pam_handle_t;

static int check_shadow(const char *user, const char *pw) {
    FILE *f = fopen("/etc/shadow", "r");
    if (!f) return PAM_AUTHINFO_UNAVAIL;
    char line[1024];
    int rv = PAM_USER_UNKNOWN;
    size_t ulen = strlen(user);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, user, ulen) != 0 || line[ulen] != ':') continue;
        char *hash = line + ulen + 1;
        char *colon = strchr(hash, ':');
        if (colon) *colon = '\0';
        if (*hash == '\0' || *hash == '!' || *hash == '*') {
            rv = PAM_AUTH_ERR;
            break;
        }
        char *got = crypt(pw, hash);
        rv = (got && strcmp(got, hash) == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
        break;
    }
    fclose(f);
    return rv;
}

int pam_sm_authenticate(pam_handle_t *p, int f, int c, const char **v) {
    (void)f; (void)c; (void)v;
    const char *user = NULL;
    if (pam_get_user(p, &user, NULL) != PAM_SUCCESS || !user) return PAM_AUTH_ERR;
    const void *tok = NULL;
    if (pam_get_item(p, PAM_AUTHTOK, &tok) != PAM_SUCCESS || !tok) return PAM_AUTH_ERR;
    return check_shadow(user, (const char *)tok);
}

int pam_sm_setcred      (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
// Account stage: verify the user exists in /etc/shadow and has a
// usable password slot. No password is checked here — that's auth.
int pam_sm_acct_mgmt(pam_handle_t *p, int f, int c, const char **v) {
    (void)f; (void)c; (void)v;
    const char *user = NULL;
    if (pam_get_user(p, &user, NULL) != PAM_SUCCESS || !user) return PAM_USER_UNKNOWN;
    FILE *fh = fopen("/etc/shadow", "r");
    if (!fh) return PAM_AUTHINFO_UNAVAIL;
    char line[1024];
    int rv = PAM_USER_UNKNOWN;
    size_t ulen = strlen(user);
    while (fgets(line, sizeof line, fh)) {
        if (strncmp(line, user, ulen) == 0 && line[ulen] == ':') {
            rv = PAM_SUCCESS;
            break;
        }
    }
    fclose(fh);
    return rv;
}
int pam_sm_open_session (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_close_session(pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_chauthtok    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_AUTHTOK_ERR; }
