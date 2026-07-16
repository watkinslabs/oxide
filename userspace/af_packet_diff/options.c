#include "probe.h"

struct scalar_case {
    const char *name;
    int option;
    int value;
};

static void scalar(const struct scalar_case *c) {
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    int value = c->value;
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, c->option, &value, sizeof(value));
    int se = errno;
    int got = 0x5a5a5a5a;
    socklen_t len = sizeof(got);
    errno = 0;
    int grc = getsockopt(fd, SOL_PACKET, c->option, &got, &len);
    int ge = errno;
    out("option", c->name,
        "set_rc=%d|set_errno=%s(%d)|get_rc=%d|get_errno=%s(%d)|len=%u|value=%d",
        rc, errno_name(se), se, grc, errno_name(ge), ge, (unsigned int)len, got);
    close(fd);
}

static void version_hdrlen(int version) {
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int se = errno;
    int hdrlen = version;
    socklen_t len = sizeof(hdrlen);
    errno = 0;
    int grc = getsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &hdrlen, &len);
    int ge = errno;
    char name[32];
    snprintf(name, sizeof(name), "version_%d_hdrlen", version);
    out("option", name,
        "set_rc=%d|set_errno=%s(%d)|get_rc=%d|get_errno=%s(%d)|len=%u|value=%d",
        rc, errno_name(se), se, grc, errno_name(ge), ge, (unsigned int)len, hdrlen);
    close(fd);
}

static void malformed_optlen(void) {
    static const socklen_t lens[] = {0, 1, 2, 3, 5, 8};
    int value = 1;
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
        errno = 0;
        int rc = setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &value, lens[i]);
        int err = errno;
        char name[32];
        snprintf(name, sizeof(name), "auxdata_optlen_%u", (unsigned int)lens[i]);
        result("option_malformed", name, rc, err);
        close(fd);
    }
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    unsigned char bytes[8];
    memset(bytes, 0xa5, sizeof(bytes));
    socklen_t len = 1;
    errno = 0;
    int rc = getsockopt(fd, SOL_PACKET, PACKET_VERSION, bytes, &len);
    int err = errno;
    out("option_malformed", "get_version_len_1", "rc=%d|errno=%s(%d)|len=%u|byte0=%u",
        rc, errno_name(err), err, (unsigned int)len, (unsigned int)bytes[0]);
    close(fd);

    size_t page_size = 0;
    void *fault = fault_page(&page_size);
    if (fault != MAP_FAILED) {
        fd = packet_socket(SOCK_RAW, ETH_P_ALL);
        errno = 0;
        rc = setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, fault, sizeof(value));
        result("option_malformed", "set_auxdata_fault", rc, errno);
        len = sizeof(value);
        errno = 0;
        rc = getsockopt(fd, SOL_PACKET, PACKET_VERSION, fault, &len);
        result("option_malformed", "get_version_value_fault", rc, errno);
        errno = 0;
        rc = getsockopt(fd, SOL_PACKET, PACKET_VERSION, &value, fault);
        result("option_malformed", "get_version_length_fault", rc, errno);
        close(fd);
        munmap(fault, page_size);
    }
}

static void unsupported_options(void) {
    int value = 1;
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_RECV_OUTPUT, &value, sizeof(value));
    result("option_unsupported", "recv_output", rc, errno);
    errno = 0;
    rc = setsockopt(fd, SOL_PACKET, PACKET_TX_TIMESTAMP, &value, sizeof(value));
    result("option_unsupported", "tx_timestamp", rc, errno);
    errno = 0;
    rc = setsockopt(fd, SOL_PACKET, 0x7fffffff, &value, sizeof(value));
    result("option_unsupported", "unknown", rc, errno);
    close(fd);
}

static void get_copy_order(void) {
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    socklen_t *len = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (len == MAP_FAILED) return;
    *len = sizeof(int);
    mprotect(len, page_size, PROT_READ);
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    int value = 0x5a5a5a5a;
    errno = 0;
    int rc = getsockopt(fd, SOL_PACKET, PACKET_VERSION, &value, len);
    int err = errno;
    out("option_malformed", "get_readonly_length_order",
        "rc=%d|errno=%s(%d)|value_unchanged=%d",
        rc, errno_name(err), err, value == 0x5a5a5a5a);
    value = 0x5a5a5a5a;
    errno = 0;
    rc = getsockopt(fd, SOL_PACKET, 0x7fffffff, &value, len);
    err = errno;
    out("option_malformed", "get_unknown_readonly_length",
        "rc=%d|errno=%s(%d)|value_unchanged=%d",
        rc, errno_name(err), err, value == 0x5a5a5a5a);
    close(fd);
    mprotect(len, page_size, PROT_READ | PROT_WRITE);
    munmap(len, page_size);
}

static void membership(const struct probe_env *env) {
    struct packet_mreq req;
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    memset(&req, 0, sizeof(req));
    req.mr_ifindex = env->ifindex;
    req.mr_type = PACKET_MR_PROMISC;
    errno = 0;
    int add = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &req, sizeof(req));
    int ae = errno;
    errno = 0;
    int drop = setsockopt(fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &req, sizeof(req));
    int de = errno;
    out("option", "membership_promisc", "add_rc=%d|add_errno=%s(%d)|drop_rc=%d|drop_errno=%s(%d)",
        add, errno_name(ae), ae, drop, errno_name(de), de);
    close(fd);
}

void probe_options(const struct probe_env *env) {
    static const struct scalar_case cases[] = {
        {"copy_thresh", PACKET_COPY_THRESH, 4096},
        {"auxdata", PACKET_AUXDATA, 1},
        {"origdev", PACKET_ORIGDEV, 1},
        {"version", PACKET_VERSION, TPACKET_V2},
        {"reserve", PACKET_RESERVE, 32},
        {"loss", PACKET_LOSS, 1},
        {"vnet_hdr", PACKET_VNET_HDR, 1},
        {"timestamp", PACKET_TIMESTAMP, 2},
        {"tx_has_off", PACKET_TX_HAS_OFF, 1},
        {"qdisc_bypass", PACKET_QDISC_BYPASS, 1},
        {"ignore_outgoing", PACKET_IGNORE_OUTGOING, 1},
        {"vnet_hdr_sz", PACKET_VNET_HDR_SZ, 12},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) scalar(&cases[i]);
    version_hdrlen(TPACKET_V1);
    version_hdrlen(TPACKET_V2);
    version_hdrlen(TPACKET_V3);
    malformed_optlen();
    unsupported_options();
    get_copy_order();
    membership(env);
}
