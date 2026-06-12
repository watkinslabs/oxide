// /bin/bpf_filter_probe — §2.11 guard: SO_ATTACH_BPF must run a loaded eBPF
// program over each inbound UDP datagram and honor its verdict (r0==0 drops).
//
//   1. bpf(BPF_PROG_LOAD) a "drop" prog (MOV R0,0; EXIT) and an "accept" prog
//      (MOV R0,0xffff; EXIT).
//   2. bind a UDP socket; attach the drop prog; send to it → recv is EAGAIN
//      (the datagram was filtered out).
//   3. attach the accept prog; send again → recv returns the bytes.
//
// SIGALRM watchdog turns any hang into FAIL.

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif
#ifndef SO_DETACH_BPF
#define SO_DETACH_BPF 27
#endif
#define BPF_PROG_LOAD 5
#define PORT 12345

#define PASS "bpf_filter_probe: PASS\n"
static void fail(const char *why) {
    write(2, "bpf_filter_probe: FAIL ", 23);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}
static void on_alrm(int s) { (void)s; fail("watchdog"); }

// One 8-byte eBPF insn.
static void insn(uint8_t *p, uint8_t opc, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
    p[0]=opc; p[1]=(uint8_t)((src<<4)|(dst&0xf));
    memcpy(p+2,&off,2); memcpy(p+4,&imm,4);
}
struct bpf_attr_load { uint32_t prog_type, insn_cnt; uint64_t insns, license; uint8_t pad[16]; };

static int load_prog(int32_t r0_imm) {
    uint8_t prog[16];
    insn(prog,      0xb7, 0, 0, 0, r0_imm); // MOV64 R0, imm
    insn(prog + 8,  0x95, 0, 0, 0, 0);      // EXIT
    struct bpf_attr_load a; memset(&a, 0, sizeof a);
    a.prog_type = 1; // SOCKET_FILTER
    a.insn_cnt = 2;
    a.insns = (uint64_t)(uintptr_t)prog;
    return (int)syscall(SYS_bpf, BPF_PROG_LOAD, &a, sizeof a);
}

int main(void) {
    struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=on_alrm; sigaction(SIGALRM,&sa,0);
    alarm(6);

    int drop = load_prog(0);
    if (drop < 0) fail("load drop prog");
    int accept = load_prog(0xffff);
    if (accept < 0) fail("load accept prog");

    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    if (rx < 0) fail("rx socket");
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(rx, (struct sockaddr*)&a, sizeof a) != 0) fail("bind");

    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    if (tx < 0) fail("tx socket");

    // (2) drop filter → datagram filtered out.
    if (setsockopt(rx, SOL_SOCKET, SO_ATTACH_BPF, &drop, sizeof drop) != 0) fail("attach drop");
    if (sendto(tx, "hi", 2, 0, (struct sockaddr*)&a, sizeof a) != 2) fail("sendto drop");
    usleep(50000);
    char buf[16];
    errno = 0;
    ssize_t n = recv(rx, buf, sizeof buf, MSG_DONTWAIT);
    if (n > 0) fail("drop filter did not drop");
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) fail("recv error after drop");

    // (3) accept filter → datagram delivered.
    if (setsockopt(rx, SOL_SOCKET, SO_ATTACH_BPF, &accept, sizeof accept) != 0) fail("attach accept");
    if (sendto(tx, "ok", 2, 0, (struct sockaddr*)&a, sizeof a) != 2) fail("sendto accept");
    usleep(50000);
    n = recv(rx, buf, sizeof buf, MSG_DONTWAIT);
    if (n != 2 || buf[0] != 'o' || buf[1] != 'k') fail("accept filter did not deliver");

    alarm(0);
    write(1, PASS, sizeof PASS - 1);
    return 0;
}
