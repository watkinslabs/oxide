/* Proof that request_key(2) reaches a real userspace construction helper.
 *
 * The kernel half has always been exercised through an injected actor, which
 * proves the bookkeeping but never execs anything: with no helper installed
 * every construction ends ENOENT -> negate, which is indistinguishable from a
 * correct kernel on a box without keyutils. This asks for a key that does not
 * exist, with callout info, and then READS IT BACK. A payload can only be there
 * if the kernel minted an authorisation token, ran the helper, and the helper
 * instantiated the key against that token — the whole upcall, end to end.
 *
 * The description is the one keyutils' stock configuration routes to its own
 * debugging handler, so nothing about this proof depends on configuration we
 * wrote ourselves; the handler answers with "Debug <callout>".
 *
 * glibc has no request_key/keyctl wrapper, so both go through syscall(3) —
 * still a glibc entry point, and identical on both architectures.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>

/* Routed to the stock debugging handler by the shipped configuration. */
#define KEY_DESC    "debug:oxide-upcall"
/* Echoed back inside the payload, so the answer cannot be a coincidence. */
#define KEY_CALLOUT "oxide-proof"
/* The requester's own default keyring is chosen by the kernel. */
#define DEST_KEYRING 0

#define PAYLOAD_MAX 256

int main(void)
{
    long key = syscall(SYS_request_key, "user", KEY_DESC, KEY_CALLOUT, DEST_KEYRING);
    if (key < 0) {
        printf("REQUEST-KEY-PROBE: FAIL request_key errno=%d\n", errno);
        return 1;
    }

    char payload[PAYLOAD_MAX];
    memset(payload, 0, sizeof payload);
    long n = syscall(SYS_keyctl, KEYCTL_READ, key, payload, (long)sizeof payload - 1, 0L);
    if (n < 0) {
        printf("REQUEST-KEY-PROBE: FAIL read serial=%ld errno=%d\n", key, errno);
        return 1;
    }

    /* The handler answers "Debug <callout>", so the callout we sent must come
     * back inside the payload. Anything else means the key was answered by
     * something other than the helper we asked for. */
    if (strstr(payload, KEY_CALLOUT) == NULL) {
        printf("REQUEST-KEY-PROBE: FAIL payload serial=%ld len=%ld body=%s\n", key, n, payload);
        return 1;
    }

    printf("REQUEST-KEY-PROBE: OK serial=%ld len=%ld payload=%s\n", key, n, payload);
    return 0;
}
