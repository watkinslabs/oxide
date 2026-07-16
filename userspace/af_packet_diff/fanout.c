#include "probe.h"

static uint32_t legacy_value(uint16_t id, uint16_t type_flags) {
    return (uint32_t)id | ((uint32_t)type_flags << 16);
}

static int send_from(int fd, int ifindex, unsigned int sequence) {
    unsigned char frame[64];
    struct sockaddr_ll addr;
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xff, ETH_ALEN);
    frame[12] = (unsigned char)(PROBE_PROTOCOL >> 8);
    frame[13] = (unsigned char)PROBE_PROTOCOL;
    memcpy(frame + 14, "AF_PACKET_FANOUT", 16);
    memcpy(frame + 32, &sequence, sizeof(sequence));
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(PROBE_PROTOCOL);
    addr.sll_ifindex = ifindex;
    return (int)sendto(fd, frame, sizeof(frame), 0,
                       (struct sockaddr *)&addr, sizeof(addr));
}

static int join_lb(int fd, uint16_t id, uint16_t flags) {
    uint32_t value = legacy_value(id, (uint16_t)(PACKET_FANOUT_LB | flags));
    return setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
}

static int drain_outgoing(int fd, unsigned int sequence) {
    unsigned char buf[4096];
    int outgoing = 0;
    for (;;) {
        struct sockaddr_ll addr;
        socklen_t len = sizeof(addr);
        ssize_t received = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT,
                                    (struct sockaddr *)&addr, &len);
        if (received < 0) break;
        unsigned int seen = 0;
        if (received >= 36) memcpy(&seen, buf + 32, sizeof(seen));
        if (len >= sizeof(addr) && addr.sll_pkttype == PACKET_OUTGOING
            && received >= 36 && buf[12] == (unsigned char)(PROBE_PROTOCOL >> 8)
            && buf[13] == (unsigned char)PROBE_PROTOCOL && seen == sequence)
        { outgoing++; }
    }
    return outgoing;
}

static void mode_one(const struct probe_env *env, unsigned int mode) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    uint32_t value = legacy_value((uint16_t)(0x5100U + mode), (uint16_t)mode);
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    int se = errno;
    uint32_t got = 0xdeadbeefU;
    socklen_t len = sizeof(got);
    errno = 0;
    int grc = getsockopt(fd, SOL_PACKET, PACKET_FANOUT, &got, &len);
    int ge = errno;
    int data_rc = 0, data_err = 0;
    if (rc == 0 && mode == PACKET_FANOUT_CBPF) {
        struct sock_filter insn = BPF_STMT(BPF_RET | BPF_K, 0);
        struct sock_fprog prog = {.len = 1, .filter = &insn};
        errno = 0;
        data_rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT_DATA, &prog, sizeof(prog));
        data_err = errno;
    } else if (rc == 0 && mode == PACKET_FANOUT_EBPF) {
        int invalid_bpf_fd = -1;
        errno = 0;
        data_rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT_DATA,
                             &invalid_bpf_fd, sizeof(invalid_bpf_fd));
        data_err = errno;
    }
    char name[24];
    snprintf(name, sizeof(name), "mode_%u", mode);
    out("fanout", name,
        "bind_rc=%d|set_rc=%d|set_errno=%s(%d)|get_rc=%d|get_errno=%s(%d)|len=%u|value_match=%d|data_rc=%d|data_errno=%s(%d)",
        br, rc, errno_name(se), se, grc, errno_name(ge), ge, (unsigned int)len,
        got == value, data_rc, errno_name(data_err), data_err);
    close(fd);
}

static void fanout_args_case(const struct probe_env *env) {
    struct fanout_args args;
    memset(&args, 0, sizeof(args));
    args.id = 0x5200;
    args.type_flags = PACKET_FANOUT_LB;
    args.max_num_members = 2;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &args, sizeof(args));
    result("fanout", "args_max_2", rc, errno);
    close(fd);
}

static void fanout_errors(const struct probe_env *env) {
    uint32_t value = legacy_value(0x5300, PACKET_FANOUT_LB);
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    result("fanout_error", "unbound", rc, errno);
    close(fd);

    fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    value = legacy_value(0x5301, 0x00ff);
    errno = 0;
    rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    result("fanout_error", "invalid_mode", rc, errno);
    close(fd);

    int a = packet_socket(SOCK_RAW, ETH_P_ALL);
    int b = packet_socket(SOCK_RAW, ETH_P_ALL);
    bind_packet(a, env->ifindex, ETH_P_ALL);
    bind_packet(b, env->ifindex, ETH_P_ALL);
    value = legacy_value(0x5302, PACKET_FANOUT_LB);
    int first = setsockopt(a, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    errno = 0;
    int again = setsockopt(a, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    int ae = errno;
    uint32_t incompatible = legacy_value(0x5302, PACKET_FANOUT_HASH);
    errno = 0;
    int mismatch = setsockopt(b, SOL_PACKET, PACKET_FANOUT,
                              &incompatible, sizeof(incompatible));
    int me = errno;
    out("fanout_error", "membership_conflicts",
        "first_rc=%d|repeat_rc=%d|repeat_errno=%s(%d)|mismatch_rc=%d|mismatch_errno=%s(%d)",
        first, again, errno_name(ae), ae, mismatch, errno_name(me), me);
    close(a);
    close(b);

    fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    unsigned char short_value[3] = {0};
    errno = 0;
    rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, short_value, sizeof(short_value));
    result("fanout_error", "short_optlen", rc, errno);
    close(fd);
}

static void distribution(const struct probe_env *env) {
    int a = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int b = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(a, env->ifindex, PROBE_PROTOCOL);
    bind_packet(b, env->ifindex, PROBE_PROTOCOL);
    uint32_t value = legacy_value(0x5400, PACKET_FANOUT_LB);
    int ar = setsockopt(a, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    int br = setsockopt(b, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    int sent = 0;
    for (unsigned int i = 0; i < 4; i++) {
        if (send_frame(env->ifindex, PROBE_PROTOCOL, i) >= 0) sent++;
    }
    poll_mask(a, POLLIN, POLL_MS);
    poll_mask(b, POLLIN, POLL_MS);
    int ac = drain_packets(a);
    int bc = drain_packets(b);
    out("fanout", "lb_distribution",
        "join_a=%d|join_b=%d|sent=%d|a_nonzero=%d|b_nonzero=%d|total_nonzero=%d|both_used=%d",
        ar, br, sent, ac > 0, bc > 0, ac + bc > 0, ac > 0 && bc > 0);
    close(a);
    close(b);
}

static void close_releases_group(const struct probe_env *env) {
    uint32_t lb = legacy_value(0x5500, PACKET_FANOUT_LB);
    uint32_t hash = legacy_value(0x5500, PACKET_FANOUT_HASH);
    int first = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(first, env->ifindex, PROBE_PROTOCOL);
    int join = setsockopt(first, SOL_PACKET, PACKET_FANOUT, &lb, sizeof(lb));
    close(first);
    int replacement = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(replacement, env->ifindex, PROBE_PROTOCOL);
    errno = 0;
    int rejoin = setsockopt(replacement, SOL_PACKET, PACKET_FANOUT, &hash, sizeof(hash));
    int err = errno;
    out("fanout", "close_releases_group", "join_rc=%d|rejoin_rc=%d|rejoin_errno=%s(%d)",
        join, rejoin, errno_name(err), err);
    close(replacement);
}

static void origin_suppresses_group(const struct probe_env *env) {
    int a = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int b = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int observer = packet_socket(SOCK_RAW, ETH_P_ALL);
    bind_packet(a, env->ifindex, PROBE_PROTOCOL);
    bind_packet(b, env->ifindex, PROBE_PROTOCOL);
    bind_packet(observer, env->ifindex, ETH_P_ALL);
    int ar = join_lb(a, 0x5700, 0);
    int br = join_lb(b, 0x5700, 0);
    int sent = send_from(a, env->ifindex, 1);
    poll_mask(a, POLLIN, POLL_MS);
    poll_mask(b, POLLIN, POLL_MS);
    poll_mask(observer, POLLIN, POLL_MS);
    int ac = drain_outgoing(a, 1), bc = drain_outgoing(b, 1);
    int observed = drain_outgoing(observer, 1);
    out("fanout", "origin_suppresses_group",
        "join_a=%d|join_b=%d|sent=%d|outgoing_a=%d|outgoing_b=%d|outgoing_total=%d|observer=%d",
        ar, br, sent, ac, bc, ac + bc, observed);
    close(a);
    close(b);
    close(observer);
}

static void member_ignore_is_not_group_flag(const struct probe_env *env) {
    int a = packet_socket(SOCK_RAW, ETH_P_ALL);
    int b = packet_socket(SOCK_RAW, ETH_P_ALL);
    bind_packet(a, env->ifindex, ETH_P_ALL);
    bind_packet(b, env->ifindex, ETH_P_ALL);
    int ar = join_lb(a, 0x5701, 0);
    int br = join_lb(b, 0x5701, 0);
    int enabled = 1;
    int ir = setsockopt(b, SOL_PACKET, PACKET_IGNORE_OUTGOING,
                        &enabled, sizeof(enabled));
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 2);
    poll_mask(a, POLLIN, POLL_MS);
    poll_mask(b, POLLIN, POLL_MS);
    int ac = drain_outgoing(a, 2), bc = drain_outgoing(b, 2);
    out("fanout", "member_ignore_not_group_flag",
        "join_a=%d|join_b=%d|ignore_b=%d|sent=%d|outgoing_a=%d|outgoing_b=%d|outgoing_total=%d",
        ar, br, ir, sent, ac, bc, ac + bc);
    close(a);
    close(b);
}

static void group_ignore_suppresses_outgoing(const struct probe_env *env) {
    int a = packet_socket(SOCK_RAW, ETH_P_ALL);
    int b = packet_socket(SOCK_RAW, ETH_P_ALL);
    int observer = packet_socket(SOCK_RAW, ETH_P_ALL);
    bind_packet(a, env->ifindex, ETH_P_ALL);
    bind_packet(b, env->ifindex, ETH_P_ALL);
    bind_packet(observer, env->ifindex, ETH_P_ALL);
    uint16_t flag = PACKET_FANOUT_FLAG_IGNORE_OUTGOING;
    int ar = join_lb(a, 0x5702, flag);
    int br = join_lb(b, 0x5702, flag);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 3);
    poll_mask(a, POLLIN, POLL_MS);
    poll_mask(b, POLLIN, POLL_MS);
    poll_mask(observer, POLLIN, POLL_MS);
    int ac = drain_outgoing(a, 3), bc = drain_outgoing(b, 3);
    int observed = drain_outgoing(observer, 3);
    out("fanout", "group_ignore_outgoing",
        "join_a=%d|join_b=%d|sent=%d|outgoing_a=%d|outgoing_b=%d|outgoing_total=%d|observer=%d",
        ar, br, sent, ac, bc, ac + bc, observed);
    close(a);
    close(b);
    close(observer);
}

static void close_uses_swap_delete(const struct probe_env *env) {
    int a = packet_socket(SOCK_RAW, ETH_P_ALL);
    int b = packet_socket(SOCK_RAW, ETH_P_ALL);
    int c = packet_socket(SOCK_RAW, ETH_P_ALL);
    bind_packet(a, env->ifindex, ETH_P_ALL);
    bind_packet(b, env->ifindex, ETH_P_ALL);
    bind_packet(c, env->ifindex, ETH_P_ALL);
    int ar = join_lb(a, 0x5703, 0);
    int br = join_lb(b, 0x5703, 0);
    int cr = join_lb(c, 0x5703, 0);
    close(a);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 4);
    poll_mask(b, POLLIN, POLL_MS);
    poll_mask(c, POLLIN, POLL_MS);
    int bc = drain_outgoing(b, 4), cc = drain_outgoing(c, 4);
    out("fanout", "close_swap_delete",
        "join_a=%d|join_b=%d|join_c=%d|sent=%d|outgoing_b=%d|outgoing_c=%d|outgoing_total=%d",
        ar, br, cr, sent, bc, cc, bc + cc);
    close(b);
    close(c);
}

static void rollover_statistics(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    uint32_t value = legacy_value(0x5600, PACKET_FANOUT_ROLLOVER);
    int join = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    struct tpacket_rollover_stats stats;
    memset(&stats, 0xff, sizeof(stats));
    socklen_t len = sizeof(stats);
    errno = 0;
    int rc = getsockopt(fd, SOL_PACKET, PACKET_ROLLOVER_STATS, &stats, &len);
    int err = errno;
    out("fanout", "rollover_statistics",
        "bind_rc=%d|join_rc=%d|get_rc=%d|get_errno=%s(%d)|len=%u|all_zero=%d",
        br, join, rc, errno_name(err), err, (unsigned int)len,
        stats.tp_all == 0 && stats.tp_huge == 0 && stats.tp_failed == 0);
    close(fd);
}

void probe_fanout(const struct probe_env *env) {
    for (unsigned int mode = PACKET_FANOUT_HASH; mode <= PACKET_FANOUT_EBPF; mode++)
        mode_one(env, mode);
    fanout_args_case(env);
    fanout_errors(env);
    distribution(env);
    close_releases_group(env);
    origin_suppresses_group(env);
    member_ignore_is_not_group_flag(env);
    group_ignore_suppresses_outgoing(env);
    close_uses_swap_delete(env);
    rollover_statistics(env);
}
