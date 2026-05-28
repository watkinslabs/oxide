// /bin/vim_smoke — F253 (T17 step 4): fork+exec /usr/bin/vim in
// ex-silent mode with an immediate :qa! and assert it exits 0.
// Proves vim (static-musl + vendored ncurses) loads its terminfo
// entry, parses the script, and returns cleanly on the oxide
// kernel.
//
// TERM=xterm matches the entry shipped at /usr/share/terminfo/x/xterm
// by F252; stdin redirected to /dev/null so vim never blocks on
// console input (ex-mode normally reads commands from stdin).

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define PASS_MSG "vim_smoke: PASS\n"
#define FAIL_MSG "vim_smoke: FAIL\n"

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    write(1, "vim_smoke: start\n", 17);

    pid_t pid = fork();
    if (pid < 0) {
        write(2, "vim_smoke: fork fail\n", 21);
        return 1;
    }
    if (pid == 0) {
        int n = open("/dev/null", O_RDONLY);
        if (n >= 0) {
            dup2(n, 0);
            if (n != 0) close(n);
        }
        char* const args[] = {
            (char*)"/usr/bin/vim",
            (char*)"-e", (char*)"-s",
            (char*)"-u", (char*)"NONE",
            (char*)"-c", (char*)"qa!",
            (char*)"/etc/passwd",
            (char*)0,
        };
        char* const env[] = {
            (char*)"TERM=xterm",
            (char*)"PATH=/usr/bin:/bin",
            (char*)"HOME=/root",
            (char*)0,
        };
        execve("/usr/bin/vim", args, env);
        write(2, "vim_smoke: execve fail\n", 23);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if ((status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0) {
        write(1, PASS_MSG, sizeof(PASS_MSG) - 1);
        return 0;
    }
    write(1, FAIL_MSG, sizeof(FAIL_MSG) - 1);
    return 1;
}
