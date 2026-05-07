// /bin/whoami — print "root" (v1 shortcut, always uid 0).
#include "../shared/oxide_start.h"
#include <unistd.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    write(1, "root\n", 5);
    return 0;
}
