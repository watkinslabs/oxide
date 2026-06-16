/* Admin syscall wrappers: capget, personality (query), setfsuid/setfsgid
 * (query form), SysV msg roundtrip, sigqueue->sigtimedwait, name_to_handle_at.
 * Non-destructive subset (no reboot/init_module/quotactl). Diff vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/personality.h>
#include <sys/fsuid.h>
#include <sys/msg.h>
#include <sys/ipc.h>

/* raw cap syscall wrappers (header lives in libcap, not glibc) */
struct cap_hdr { unsigned version; int pid; };
struct cap_data { unsigned effective, permitted, inheritable; };
extern int capget(struct cap_hdr *, struct cap_data *);

struct mbuf { long mtype; char text[16]; };

int main(void) {
    struct cap_hdr h = { 0x20080522u, 0 }; /* _LINUX_CAPABILITY_VERSION_3 */
    struct cap_data d[2]; memset(d, 0, sizeof d);
    printf("capget=%d\n", capget(&h, d) == 0);

    printf("personality_query_ok=%d\n", personality(0xffffffffu) >= 0);

    printf("setfsuid_query=%d setfsgid_query=%d\n",
           setfsuid(-1) >= 0, setfsgid(-1) >= 0);

    int q = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
    int snd = -1, rcvok = 0;
    if (q >= 0) {
        struct mbuf m = { 1, "hello" };
        snd = msgsnd(q, &m, 6, 0);
        struct mbuf r; memset(&r, 0, sizeof r);
        ssize_t n = msgrcv(q, &r, sizeof r.text, 1, 0);
        rcvok = (n == 6) && (strcmp(r.text, "hello") == 0);
        msgctl(q, IPC_RMID, NULL);
    }
    printf("msg_created=%d msgsnd=%d msg_roundtrip=%d\n", q >= 0, snd, rcvok);

    /* sigqueue SIGRTMIN with a value, receive via sigtimedwait */
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &set, NULL);
    union sigval v; v.sival_int = 4242;
    int sq = sigqueue(getpid(), SIGRTMIN, v);
    siginfo_t si; struct timespec ts = { 1, 0 };
    int got = sigtimedwait(&set, &si, &ts);
    printf("sigqueue=%d got_signo=%d got_val=%d\n",
           sq, got == SIGRTMIN, si.si_value.sival_int);

    struct file_handle { unsigned handle_bytes; int handle_type; unsigned char f[128]; } fh;
    fh.handle_bytes = 128; int mid;
    printf("name_to_handle_at=%d\n", name_to_handle_at(AT_FDCWD, "/", (void*)&fh, &mid, 0) == 0);
    return 0;
}
