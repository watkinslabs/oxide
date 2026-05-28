// /usr/lib/security/pam_unix.so — minimal Linux pam_unix module.
// F239: real /etc/shadow + crypt() check via the PAM conv function.
//
// libpam dlopens us; ld-musl resolves pam_get_item against
// sshd-session's statically-linked libpam (sshd built with
// -Wl,--export-dynamic in F231). PAM_CONV item gives us the
// conv callback openssh's sshpam_thread uses to ping the
// client over keyboard-interactive — we use it to ask for
// the password, then crypt-check against /etc/shadow.
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
#define PAM_CONV_ERR        19

#define PAM_CONV             5
#define PAM_PROMPT_ECHO_OFF  1

typedef struct pam_handle pam_handle_t;

struct pam_message  { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };
struct pam_conv     {
    int (*conv)(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};

static int prompt_password(pam_handle_t *p, char **out) {
    const void *raw = NULL;
    if (pam_get_item(p, PAM_CONV, &raw) != PAM_SUCCESS || !raw) return PAM_CONV_ERR;
    const struct pam_conv *cv = (const struct pam_conv *)raw;
    struct pam_message  msg  = { .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password: " };
    const struct pam_message *msgs[1] = { &msg };
    struct pam_response *resp = NULL;
    int rv = cv->conv(1, msgs, &resp, cv->appdata_ptr);
    if (rv != PAM_SUCCESS || !resp) return PAM_CONV_ERR;
    if (!resp[0].resp) { free(resp); return PAM_CONV_ERR; }
    *out = resp[0].resp;
    free(resp);
    return PAM_SUCCESS;
}

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
    char *pw = NULL;
    int rv = prompt_password(p, &pw);
    if (rv != PAM_SUCCESS) return rv;
    rv = check_shadow(user, pw);
    free(pw);
    return rv;
}

int pam_sm_setcred      (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_acct_mgmt    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_open_session (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_close_session(pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_chauthtok    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_AUTHTOK_ERR; }
