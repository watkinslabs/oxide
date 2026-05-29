// F246 probe: pam_unix_stub.so — built `-nostdlib` like pam_permit
// but distinguishable by name. Same auto-success semantics. Used
// in place of pam_unix.so to test whether the activation hang is
// caused by libc.so DT_NEEDED (this stub has NO DT_NEEDED) vs
// pam_unix.so logic.
#define PAM_SUCCESS 0
typedef struct pam_handle pam_handle_t;

int pam_sm_authenticate (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_setcred      (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_acct_mgmt    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_open_session (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_close_session(pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_chauthtok    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
