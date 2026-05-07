// /bin/ls — minimal POSIX ls. Lists names one per line.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    const char *path = (argc > 1) ? argv[1] : ".";
    DIR *d = opendir(path);
    if (!d) { write(2, "ls: open failed\n", 16); return 1; }
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        if (e->d_name[0] == '.' && (e->d_name[1] == 0 ||
            (e->d_name[1] == '.' && e->d_name[2] == 0))) continue;
        write(1, e->d_name, strlen(e->d_name));
        write(1, "\n", 1);
    }
    closedir(d);
    return 0;
}
