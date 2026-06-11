// /bin/vsock_probe — D3.3 virtio-vsock / AF_VSOCK round-trip regression.
//
// Proves the kernel's virtio-vsock driver + AF_VSOCK socket family carry
// a real STREAM through to a host peer: socket(AF_VSOCK, SOCK_STREAM),
// connect to {cid=2 (VMADDR_CID_HOST), port=1234}, write a known ping,
// read the echo back, assert echo == sent. The host side runs an echo
// server (socat VSOCK-LISTEN / python AF_VSOCK) started by the smoke
// harness before QEMU. Real OP_REQUEST/OP_RESPONSE handshake + OP_RW
// data over the virtio-vsock TX/RX queues, not a loopback fake.

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

// musl ships no <linux/vm_sockets.h>; define the AF_VSOCK ABI inline.
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int   svm_port;
    unsigned int   svm_cid;
    unsigned char  svm_zero[sizeof(struct sockaddr) -
                            sizeof(unsigned short) - sizeof(unsigned short) -
                            sizeof(unsigned int) - sizeof(unsigned int)];
};

static void emit(const char *m) { write(1, m, strlen(m)); }

#define HOST_CID  2u      /* VMADDR_CID_HOST */
#define HOST_PORT 1234u

int main(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { emit("vsock_probe: FAIL socket(AF_VSOCK)\n"); return 1; }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof addr);
    addr.svm_family = AF_VSOCK;
    addr.svm_cid    = HOST_CID;
    addr.svm_port   = HOST_PORT;

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        emit("vsock_probe: FAIL connect cid=2 port=1234\n");
        close(fd);
        return 1;
    }

    static const char ping[] = "oxide-vsock-ping";
    size_t plen = sizeof(ping) - 1;
    if (write(fd, ping, plen) != (ssize_t)plen) {
        emit("vsock_probe: FAIL write\n");
        close(fd);
        return 1;
    }

    char buf[64];
    size_t got = 0;
    while (got < plen) {
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);

    if (got != plen || memcmp(buf, ping, plen) != 0) {
        emit("vsock_probe: FAIL echo mismatch\n");
        return 1;
    }

    emit("vsock_probe: PASS\n");
    return 0;
}
