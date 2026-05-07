// /bin/find — POSIX find(1) subset. Walks paths recursively.
// v1: -name PAT (literal match) and -type f|d filter.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

static char path_buf[1024];

static void walk(int depth_left, long path_len, char filter_type, const char *name_pat) {
    if (depth_left <= 0) return;
    DIR *d = opendir(path_buf);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        const char *name = e->d_name;
        if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) continue;
        long nlen = strlen(name);
        if (path_len + 1 + nlen + 1 >= (long)sizeof(path_buf)) continue;
        path_buf[path_len] = '/';
        memcpy(path_buf + path_len + 1, name, nlen);
        path_buf[path_len + 1 + nlen] = 0;
        int matches = 1;
        if (filter_type == 'f' && e->d_type != DT_REG) matches = 0;
        if (filter_type == 'd' && e->d_type != DT_DIR) matches = 0;
        if (name_pat && strcmp(name, name_pat) != 0) matches = 0;
        if (matches) { write(1, path_buf, strlen(path_buf)); write(1, "\n", 1); }
        if (e->d_type == DT_DIR) walk(depth_left - 1, path_len + 1 + nlen, filter_type, name_pat);
    }
    closedir(d);
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    const char *root = (argc > 1 && argv[1][0] != '-') ? argv[1] : ".";
    char filter_type = 0;
    const char *name_pat = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-type") == 0 && i+1 < argc) { filter_type = argv[i+1][0]; i++; }
        else if (strcmp(argv[i], "-name") == 0 && i+1 < argc) { name_pat = argv[i+1]; i++; }
    }
    long n = strlen(root);
    if (n + 1 >= (long)sizeof(path_buf)) return 1;
    memcpy(path_buf, root, n);
    path_buf[n] = 0;
    write(1, path_buf, n); write(1, "\n", 1);
    walk(8, n, filter_type, name_pat);
    return 0;
}
