#include "probe.h"

static int set_effective_rcvbuf(int fd, int target) {
    int requested = target / 2;
    socklen_t len = sizeof(requested);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested));
    int effective = 0;
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &effective, &len);
    if (effective != target) {
        requested = target;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested));
        len = sizeof(effective);
        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &effective, &len);
    }
    return effective;
}

static void queue_first_drop(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int effective = set_effective_rcvbuf(fd, 4096);
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    unsigned int packets = 0, drops = 0;
    int sent = 0;
    for (unsigned int sequence = 0; sequence < 64 && drops == 0; sequence++) {
        if (send_frame(env->ifindex, PROBE_PROTOCOL, sequence) < 0) break;
        sent++;
        struct tpacket_stats stats;
        memset(&stats, 0, sizeof(stats));
        socklen_t len = sizeof(stats);
        if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) != 0) break;
        packets += stats.tp_packets;
        drops += stats.tp_drops;
    }
    out("runtime", "queue_first_drop",
        "bind_rc=%d|effective_rcvbuf=%d|sent_nonzero=%d|drop_seen=%d|accepted_before_drop=%u",
        br, effective, sent > 0, drops > 0, packets - drops);
    close(fd);
}

static void statistics_pressure(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    int rcvbuf = 4096;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int br = bind_packet(fd, env->ifindex, ETH_P_ALL);
    int sent = send_udp_burst(512);
    poll_mask(fd, POLLIN, POLL_MS);
    struct tpacket_stats stats;
    memset(&stats, 0, sizeof(stats));
    socklen_t len = sizeof(stats);
    errno = 0;
    int rc = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
    int err = errno;
    struct tpacket_stats reset;
    memset(&reset, 0xff, sizeof(reset));
    socklen_t reset_len = sizeof(reset);
    errno = 0;
    int reset_rc = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &reset, &reset_len);
    int reset_err = errno;
    out("runtime", "queue_pressure_stats",
        "bind_rc=%d|sent_all=%d|get_rc=%d|get_errno=%s(%d)|len=%u|packets_nonzero=%d|drops_nonzero=%d|drops_le_packets=%d|reset_rc=%d|reset_errno=%s(%d)|reset_len=%u|reset_zero=%d",
        br, sent == 512, rc, errno_name(err), err, (unsigned int)len,
        stats.tp_packets > 0, stats.tp_drops > 0, stats.tp_drops <= stats.tp_packets,
        reset_rc, errno_name(reset_err), reset_err, (unsigned int)reset_len,
        reset.tp_packets == 0 && reset.tp_drops == 0);
    close(fd);
}

static void statistics_v3(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V3;
    int vr = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    send_frame(env->ifindex, PROBE_PROTOCOL, 0x33);
    struct tpacket_stats_v3 stats;
    memset(&stats, 0, sizeof(stats));
    socklen_t len = sizeof(stats);
    errno = 0;
    int rc = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
    int err = errno;
    out("runtime", "statistics_v3",
        "version_rc=%d|bind_rc=%d|get_rc=%d|get_errno=%s(%d)|len=%u|packets_nonzero=%d|drops=%u|freeze=%u",
        vr, br, rc, errno_name(err), err, (unsigned int)len,
        stats.tp_packets > 0, stats.tp_drops, stats.tp_freeze_q_cnt);
    close(fd);
}

static void statistics_length_fault(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 0x34);
    poll_mask(fd, POLLIN, POLL_MS);
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    socklen_t *fault_len = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fault_len == MAP_FAILED) { close(fd); return; }
    *fault_len = sizeof(struct tpacket_stats);
    mprotect(fault_len, page_size, PROT_READ);
    struct tpacket_stats fault_stats;
    memset(&fault_stats, 0x5a, sizeof(fault_stats));
    errno = 0;
    int fault_rc = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS,
                              &fault_stats, fault_len);
    int fault_err = errno;
    struct tpacket_stats after;
    memset(&after, 0, sizeof(after));
    socklen_t len = sizeof(after);
    errno = 0;
    int after_rc = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &after, &len);
    int after_err = errno;
    out("runtime", "statistics_length_fault_order",
        "bind_rc=%d|send_ok=%d|fault_rc=%d|fault_errno=%s(%d)|value_unchanged=%d|after_rc=%d|after_errno=%s(%d)|after_packets_nonzero=%d",
        br, sent >= 0, fault_rc, errno_name(fault_err), fault_err,
        fault_stats.tp_packets == 0x5a5a5a5aU && fault_stats.tp_drops == 0x5a5a5a5aU,
        after_rc, errno_name(after_err), after_err, after.tp_packets > 0);
    mprotect(fault_len, page_size, PROT_READ | PROT_WRITE);
    munmap(fault_len, page_size);
    close(fd);
}

static void queue_poll(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    drain_packets(fd);
    int initial = poll_mask(fd, POLLIN | POLLOUT, 0);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 0x44);
    int ready = poll_mask(fd, POLLIN | POLLOUT, POLL_MS);
    int drained = drain_packets(fd);
    int after = poll_mask(fd, POLLIN | POLLOUT, 0);
    out("poll", "queue_transitions",
        "bind_rc=%d|initial_in=%d|initial_out=%d|send_ok=%d|ready_in=%d|ready_out=%d|drained_nonzero=%d|after_in=%d|after_out=%d",
        br, !!(initial & POLLIN), !!(initial & POLLOUT), sent >= 0,
        !!(ready & POLLIN), !!(ready & POLLOUT), drained > 0,
        !!(after & POLLIN), !!(after & POLLOUT));
    close(fd);
}

static void descriptor_lifetime(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int duplicate = dup(fd);
    bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    close(fd);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 0x55);
    int ready = poll_mask(duplicate, POLLIN, POLL_MS);
    int received = drain_packets(duplicate);
    close(duplicate);
    errno = 0;
    int bad = (int)recv(duplicate, &sent, sizeof(sent), MSG_DONTWAIT);
    int err = errno;
    out("lifetime", "dup_last_close",
        "dup_ok=%d|send_ok=%d|ready_in=%d|received_nonzero=%d|after_close_rc=%d|after_close_errno=%s(%d)",
        duplicate >= 0, sent >= 0, !!(ready & POLLIN), received > 0,
        bad, errno_name(err), err);
}

static void mapping_lifetime(void) {
    struct tpacket_req req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr = 1,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr = BLOCK_SIZE / FRAME_SIZE,
    };
    size_t size = req.tp_block_size;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    int parent_access = 0, child_access = 0, child_status = -1;
    if (map != MAP_FAILED) {
        volatile unsigned char *bytes = map;
        bytes[size - 1] = 0x6d;
        parent_access = bytes[size - 1] == 0x6d;
        pid_t pid = fork();
        if (pid == 0) _exit(bytes[size - 1] == 0x6d ? 0 : 1);
        if (pid > 0 && waitpid(pid, &child_status, 0) == pid)
            child_access = WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
        munmap(map, size);
    }
    out("lifetime", "mapping_after_close_fork",
        "ring_rc=%d|mapped=%d|parent_access=%d|child_access=%d|unmapped=1",
        rr, map != MAP_FAILED, parent_access, child_access);
}

static void mapped_ring_busy(void) {
    struct tpacket_req req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr = 1,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr = BLOCK_SIZE / FRAME_SIZE,
    };
    struct tpacket_req disable;
    memset(&disable, 0, sizeof(disable));
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    void *map = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    errno = 0;
    int disable_mapped = setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                                    &disable, sizeof(disable));
    int me = errno;
    if (map != MAP_FAILED) munmap(map, BLOCK_SIZE);
    errno = 0;
    int disable_unmapped = setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                                      &disable, sizeof(disable));
    int ue = errno;
    out("lifetime", "mapped_ring_busy",
        "ring_rc=%d|mapped=%d|mapped_disable_rc=%d|mapped_errno=%s(%d)|unmapped_disable_rc=%d|unmapped_errno=%s(%d)",
        rr, map != MAP_FAILED, disable_mapped, errno_name(me), me,
        disable_unmapped, errno_name(ue), ue);
    close(fd);
}

void probe_runtime(const struct probe_env *env) {
    queue_first_drop(env);
    statistics_pressure(env);
    statistics_v3(env);
    statistics_length_fault(env);
    queue_poll(env);
    descriptor_lifetime(env);
    mapping_lifetime();
    mapped_ring_busy();
}
