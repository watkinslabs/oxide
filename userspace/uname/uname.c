// /bin/uname — print system info via uname(2).
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>

static void write_field(const char *p) {
    write(1, p, strlen(p));
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    struct utsname u;
    if (uname(&u) < 0) return 1;
    int all = 0;
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "-a") == 0) all = 1;
    write_field(u.sysname);
    if (all) {
        write(1, " ", 1); write_field(u.nodename);
        write(1, " ", 1); write_field(u.release);
        write(1, " ", 1); write_field(u.version);
        write(1, " ", 1); write_field(u.machine);
    }
    write(1, "\n", 1);
    return 0;
}
