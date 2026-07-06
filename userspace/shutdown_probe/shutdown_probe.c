#include <errno.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <unistd.h>

int main(void) {
    puts("shutdown_probe: RB_AUTOBOOT");
    fflush(stdout);
    int rv = reboot(RB_AUTOBOOT);
    printf("shutdown_probe: FAIL reboot returned rv=%d errno=%d\n", rv, errno);
    return 1;
}
