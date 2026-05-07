// /bin/pwd — print working directory.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    char buf[1024];
    if (getcwd(buf, sizeof(buf)) == 0) return 1;
    size_t n = strlen(buf);
    write(1, buf, n);
    write(1, "\n", 1);
    return 0;
}
