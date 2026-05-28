// /lib/security/pam_permit.so — minimal "always allow" PAM module.
// F231: first PAM module shipped as a real shared object dlopen'd by
// libpam. The full Linux-PAM pam_permit.c uses libpam symbols; this
// stripped-down version has no undefined references so it can be
// loaded by libpam-statically-linked-into-sshd without requiring
// the main binary to be relinked with --export-dynamic. Functional
// equivalent: every authentication stage returns PAM_SUCCESS.
#define PAM_SUCCESS 0
typedef struct pam_handle pam_handle_t;

int pam_sm_authenticate (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_setcred      (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_acct_mgmt    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_open_session (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_close_session(pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
int pam_sm_chauthtok    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SUCCESS; }
