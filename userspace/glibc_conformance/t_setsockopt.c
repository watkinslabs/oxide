/* Linux row-54 setsockopt(2) error-precedence corpus; compared verbatim by N17. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static void t(const char *label, int rc) {
    printf("%s rc=%d errno=%d\n", label, rc, rc < 0 ? errno : 0);
}

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;

    /* A known int option with a NULL optval but a short optlen: Linux checks
       the minimum length before dereferencing optval, so this is EINVAL. */
    errno = 0; t("null_short_optlen", setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, NULL, 2));
    /* NULL optval with a sufficient optlen faults on the copy: EFAULT. */
    errno = 0; t("null_ok_optlen", setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, NULL, 4));
    /* A short optlen with a valid optval is EINVAL. */
    errno = 0; t("short_valid", setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 2));

    /* An unknown level is dispatched to the protocol handler, which returns
       ENOPROTOOPT without ever reading optval — even a NULL optval. */
    errno = 0; t("unknown_level_null", setsockopt(fd, 999, 1, NULL, 4));
    errno = 0; t("unknown_level_valid", setsockopt(fd, 999, 1, &one, 4));
    /* An unknown option at a known level is ENOPROTOOPT. */
    errno = 0; t("unknown_opt", setsockopt(fd, SOL_SOCKET, 99999, &one, 4));

    /* A valid option succeeds. */
    errno = 0; t("valid_reuseaddr", setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 4));

    close(fd);
    return 0;
}
