// /lib/security/pam_deny.so — minimal "always deny" PAM module.
// F231: companion to pam_permit. Returns PAM_AUTH_ERR for every
// stage. Same no-libpam-refs constraint as pam_permit.
#define PAM_AUTH_ERR    7
#define PAM_CRED_ERR    17
#define PAM_ACCT_EXPIRED 13
#define PAM_SESSION_ERR  14
#define PAM_AUTHTOK_ERR  20
typedef struct pam_handle pam_handle_t;

int pam_sm_authenticate (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_AUTH_ERR; }
int pam_sm_setcred      (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_CRED_ERR; }
int pam_sm_acct_mgmt    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_ACCT_EXPIRED; }
int pam_sm_open_session (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SESSION_ERR; }
int pam_sm_close_session(pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_SESSION_ERR; }
int pam_sm_chauthtok    (pam_handle_t *p, int f, int c, const char **v) { (void)p; (void)f; (void)c; (void)v; return PAM_AUTHTOK_ERR; }
