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
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

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

static void emit(const char *m) {
    write(1, m, strlen(m));
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, m, strlen(m));
        close(fd);
    }
}

#define HOST_CID  2u      /* VMADDR_CID_HOST */
#define HOST_PORT 1234u
#define SOL_VSOCK 287
#define SO_VM_SOCKETS_BUFFER_SIZE 0
#define SO_VM_SOCKETS_BUFFER_MIN_SIZE 1
#define SO_VM_SOCKETS_BUFFER_MAX_SIZE 2

static int check_vsock_options(int fd) {
    int value = 0;
    socklen_t len = sizeof(value);
    if (getsockopt(fd, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &value, &len) < 0
        || len != sizeof(value) || value != 256 * 1024) return -1;
    if (getsockopt(fd, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MIN_SIZE, &value, &len) < 0
        || value != 128) return -1;
    if (getsockopt(fd, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE, &value, &len) < 0
        || value != 256 * 1024) return -1;
    value = 512 * 1024;
    if (setsockopt(fd, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE, &value, sizeof(value)) < 0) return -1;
    if (setsockopt(fd, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &value, sizeof(value)) < 0) return -1;
    if (getsockopt(fd, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &value, &len) < 0
        || value != 512 * 1024) return -1;
    emit("vsock_probe: options PASS\n");
    return 0;
}

int main(void) {
    emit("vsock_probe: START\n");
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { emit("vsock_probe: FAIL socket(AF_VSOCK)\n"); return 1; }
    emit("vsock_probe: socket OK\n");
    if (check_vsock_options(fd) < 0) {
        emit("vsock_probe: FAIL SOL_VSOCK options\n");
        close(fd);
        return 1;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof addr);
    addr.svm_family = AF_VSOCK;
    addr.svm_cid    = HOST_CID;
    addr.svm_port   = HOST_PORT;

    emit("vsock_probe: connect START\n");
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        emit("vsock_probe: FAIL connect cid=2 port=1234\n");
        close(fd);
        return 1;
    }
    emit("vsock_probe: connect OK\n");

    static const char ping[] = "oxide-vsock-ping";
    size_t plen = sizeof(ping) - 1;
    emit("vsock_probe: write START\n");
    if (write(fd, ping, plen) != (ssize_t)plen) {
        emit("vsock_probe: FAIL write\n");
        close(fd);
        return 1;
    }
    emit("vsock_probe: read START\n");

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
