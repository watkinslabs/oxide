// Minimal exec-path test binary. No argv touch, no musl init beyond
// what oxide_start.h does, no PT_INTERP. write(1, "BARE-OK\n", 8)
// then _exit(0). If this prints, the kernel exec/argv path is fine
// and the issue is downstream in C-stdlib / strlen / argv parsing.

#include "../shared/oxide_start.h"
#include <unistd.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    write(1, "BARE-OK\n", 8);
    return 0;
}
