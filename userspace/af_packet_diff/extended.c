#include "probe.h"

static struct tpacket_req one_ring(unsigned int blocks) {
    struct tpacket_req req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr = blocks,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr = blocks * (BLOCK_SIZE / FRAME_SIZE),
    };
    return req;
}

static int epoll_mask(int epfd) {
    struct epoll_event event;
    int rc = epoll_wait(epfd, &event, 1, 0);
    return rc == 1 ? (int)event.events : rc;
}

static void tx_epoll_states(const struct probe_env *env) {
    struct tpacket_req req = one_ring(1);
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int tr = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    void *map = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLOUT, .data.fd = fd};
    int er = epfd < 0 ? -1 : epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
    int available = -1, requested = -1, sending = -1, wrong = -1;
    if (map != MAP_FAILED && er == 0) {
        struct tpacket2_hdr *a = map;
        struct tpacket2_hdr *b = (void *)((unsigned char *)map + FRAME_SIZE);
        a->tp_status = b->tp_status = TP_STATUS_AVAILABLE;
        available = epoll_mask(epfd);
        a->tp_status = b->tp_status = TP_STATUS_SEND_REQUEST;
        requested = epoll_mask(epfd);
        a->tp_status = b->tp_status = TP_STATUS_SENDING;
        sending = epoll_mask(epfd);
        a->tp_status = b->tp_status = TP_STATUS_WRONG_FORMAT;
        wrong = epoll_mask(epfd);
    }
    out("epoll", "tx_ring_states",
        "ring_rc=%d|bind_rc=%d|mapped=%d|epoll_rc=%d|available_out=%d|request_out=%d|sending_out=%d|wrong_out=%d",
        tr, br, map != MAP_FAILED, er, !!(available & EPOLLOUT),
        !!(requested & EPOLLOUT), !!(sending & EPOLLOUT), !!(wrong & EPOLLOUT));
    if (epfd >= 0) close(epfd);
    if (map != MAP_FAILED) munmap(map, BLOCK_SIZE);
    close(fd);
}

static void v3_retire_timeout(const struct probe_env *env) {
    struct tpacket_req3 req = {
        .tp_block_size = BLOCK_SIZE, .tp_block_nr = 1,
        .tp_frame_size = FRAME_SIZE, .tp_frame_nr = BLOCK_SIZE / FRAME_SIZE,
        .tp_retire_blk_tov = 20,
    };
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V3;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    void *map = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 0x9651);
    poll_mask(fd, POLLIN, 0);
    int retired = poll_mask(fd, POLLIN, POLL_MS);
    unsigned int packets = 0;
    if (map != MAP_FAILED && (retired & POLLIN)) {
        struct tpacket_block_desc *block = map;
        packets = block->hdr.bh1.num_pkts;
        block->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }
    out("poll", "v3_retire_timeout",
        "ring_rc=%d|bind_rc=%d|mapped=%d|send_ok=%d|retired_in=%d|packets_nonzero=%d",
        rr, br, map != MAP_FAILED, sent >= 0, !!(retired & POLLIN), packets > 0);
    if (map != MAP_FAILED) munmap(map, BLOCK_SIZE);
    close(fd);
}

static size_t tcp4_frame(unsigned char *frame, size_t payload) {
    size_t len = ETH_HLEN + 20 + 20 + payload;
    memset(frame, 0, len);
    memset(frame, 0xff, ETH_ALEN);
    frame[12] = 0x08; frame[13] = 0x00;
    frame[14] = 0x45; frame[23] = IPPROTO_TCP;
    uint16_t iplen = htons((uint16_t)(20 + 20 + payload));
    memcpy(frame + 16, &iplen, sizeof(iplen));
    frame[26] = 10; frame[29] = 1; frame[30] = 10; frame[33] = 2;
    frame[46] = 0x50; frame[47] = 0x19;
    return len;
}

static size_t tcp6_frame(unsigned char *frame, size_t payload) {
    size_t len = ETH_HLEN + 40 + 20 + payload;
    memset(frame, 0, len);
    memset(frame, 0xff, ETH_ALEN);
    frame[12] = 0x86; frame[13] = 0xdd; frame[14] = 0x60;
    uint16_t plen = htons((uint16_t)(20 + payload));
    memcpy(frame + 18, &plen, sizeof(plen));
    frame[20] = IPPROTO_TCP; frame[22] = 1; frame[38] = 2;
    frame[66] = 0x50; frame[67] = 0x19;
    return len;
}

static size_t udp4_frame(unsigned char *frame, size_t payload) {
    size_t len = ETH_HLEN + 20 + 8 + payload;
    memset(frame, 0, len);
    memset(frame, 0xff, ETH_ALEN);
    frame[12] = 0x08; frame[13] = 0x00;
    frame[14] = 0x45; frame[23] = IPPROTO_UDP;
    uint16_t iplen = htons((uint16_t)(20 + 8 + payload));
    uint16_t udplen = htons((uint16_t)(8 + payload));
    memcpy(frame + 16, &iplen, sizeof(iplen));
    memcpy(frame + 38, &udplen, sizeof(udplen));
    frame[26] = 10; frame[29] = 1; frame[30] = 10; frame[33] = 2;
    return len;
}

static int vnet_send(int fd, int ifindex, unsigned char gso, unsigned short size,
                     unsigned char flags, unsigned short hdr_len,
                     unsigned short csum_start, unsigned short csum_offset,
                     const unsigned char *frame, size_t frame_len, int *saved_errno) {
    unsigned char input[sizeof(struct virtio_net_hdr) + 14 + 40 + 20 + 64];
    struct virtio_net_hdr header;
    struct sockaddr_ll addr;
    memset(&header, 0, sizeof(header));
    header.flags = flags;
    header.gso_type = gso;
    header.hdr_len = hdr_len;
    header.gso_size = size;
    header.csum_start = csum_start;
    header.csum_offset = csum_offset;
    memcpy(input, &header, sizeof(header));
    memcpy(input + sizeof(header), frame, frame_len);
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    memcpy(&addr.sll_protocol, frame + 12, sizeof(addr.sll_protocol));
    addr.sll_ifindex = ifindex;
    errno = 0;
    int rc = (int)sendto(fd, input, sizeof(header) + frame_len, MSG_DONTWAIT,
                         (struct sockaddr *)&addr, sizeof(addr));
    *saved_errno = errno;
    return rc;
}

static void gso_matrix(const struct probe_env *env) {
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    int one = 1;
    int vr = setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one));
    int br = bind_packet(fd, env->ifindex, ETH_P_ALL);
    unsigned char tcp4[14 + 20 + 20 + 64], tcp6[14 + 40 + 20 + 64];
    unsigned char udp4[14 + 20 + 8 + 64];
    size_t tcp4_len = tcp4_frame(tcp4, 64), tcp6_len = tcp6_frame(tcp6, 64);
    size_t udp4_len = udp4_frame(udp4, 64);
    int pe, t4e, t4ee, t6e, ufoe, usoe, ee, ze;
    int plain = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_NONE, 0,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 54, 34, 16, tcp4, tcp4_len, &pe);
    int tcp4_rc = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_TCPV4, 32,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 54, 34, 16, tcp4, tcp4_len, &t4e);
    int tcp4_ecn = vnet_send(fd, env->ifindex,
        VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN, 32,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 54, 34, 16, tcp4, tcp4_len, &t4ee);
    int tcp6_rc = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_TCPV6, 32,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 74, 54, 16, tcp6, tcp6_len, &t6e);
    int ufo = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_UDP, 32,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 42, 34, 6, udp4, udp4_len, &ufoe);
    int uso = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_UDP_L4, 32,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 42, 34, 6, udp4, udp4_len, &usoe);
    int ecn = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_ECN, 32,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 54, 34, 16, tcp4, tcp4_len, &ee);
    int zero = vnet_send(fd, env->ifindex, VIRTIO_NET_HDR_GSO_TCPV4, 0,
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 54, 34, 16, tcp4, tcp4_len, &ze);
    out("gso", "vnet_combinations",
        "vnet_rc=%d|bind_rc=%d|plain_ok=%d:%s(%d)|tcp4_ok=%d:%s(%d)|tcp4_ecn_ok=%d:%s(%d)|tcp6_ok=%d:%s(%d)|ufo_ok=%d:%s(%d)|uso_ok=%d:%s(%d)|ecn_rc=%d:%s(%d)|zero_rc=%d:%s(%d)",
        vr, br, plain >= 0, errno_name(pe), pe,
        tcp4_rc >= 0, errno_name(t4e), t4e, tcp4_ecn >= 0, errno_name(t4ee), t4ee,
        tcp6_rc >= 0, errno_name(t6e), t6e, ufo >= 0, errno_name(ufoe), ufoe,
        uso >= 0, errno_name(usoe), usoe, ecn, errno_name(ee), ee,
        zero, errno_name(ze), ze);
    close(fd);
}

struct fanout_race {
    int ifindex;
    pthread_barrier_t barrier;
    int sent;
};

static void *fanout_sender(void *opaque) {
    struct fanout_race *race = opaque;
    pthread_barrier_wait(&race->barrier);
    for (unsigned int i = 0; i < 128; i++)
        if (send_frame(race->ifindex, PROBE_PROTOCOL, 0x9700 + i) >= 0) race->sent++;
    return NULL;
}

static void fanout_close_race(const struct probe_env *env) {
    int a = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int b = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    bind_packet(a, env->ifindex, PROBE_PROTOCOL);
    bind_packet(b, env->ifindex, PROBE_PROTOCOL);
    uint32_t value = 0x5965U | ((uint32_t)PACKET_FANOUT_LB << 16);
    int ar = setsockopt(a, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    int br = setsockopt(b, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value));
    struct fanout_race race = {.ifindex = env->ifindex, .sent = 0};
    pthread_barrier_init(&race.barrier, NULL, 2);
    pthread_t thread;
    int created = pthread_create(&thread, NULL, fanout_sender, &race);
    pthread_barrier_wait(&race.barrier);
    close(a);
    if (created == 0) pthread_join(thread, NULL);
    int post = send_frame(env->ifindex, PROBE_PROTOCOL, 0x9765);
    poll_mask(b, POLLIN, POLL_MS);
    int received = drain_packets(b);
    out("fanout", "concurrent_close",
        "join_a=%d|join_b=%d|thread_rc=%d|sent_all=%d|post_send_ok=%d|survivor_nonzero=%d",
        ar, br, created, race.sent == 128, post >= 0, received > 0);
    pthread_barrier_destroy(&race.barrier);
    close(b);
}

static int disable_rx_ring(int fd, int *saved_errno) {
    struct tpacket_req disable;
    memset(&disable, 0, sizeof(disable));
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &disable, sizeof(disable));
    *saved_errno = errno;
    return rc;
}

static void mapping_split_fork(void) {
    struct tpacket_req req = one_ring(2);
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    unsigned char *map = mmap(NULL, BLOCK_SIZE * 2, PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
    int release_pipe[2] = {-1, -1};
    int pr = pipe(release_pipe);
    pid_t child = -1;
    if (map != MAP_FAILED && pr == 0) {
        child = fork();
        if (child == 0) {
            close(release_pipe[1]);
            char byte;
            int ok = map[0] == 0 && read(release_pipe[0], &byte, 1) == 1;
            _exit(ok ? 0 : 1);
        }
    }
    if (release_pipe[0] >= 0) close(release_pipe[0]);
    int first_unmap = map == MAP_FAILED ? -1 : munmap(map, BLOCK_SIZE);
    int be, ce, ae;
    int busy_split = disable_rx_ring(fd, &be);
    int second_unmap = map == MAP_FAILED ? -1 : munmap(map + BLOCK_SIZE, BLOCK_SIZE);
    int busy_child = disable_rx_ring(fd, &ce);
    if (release_pipe[1] >= 0) { char byte = 1; write(release_pipe[1], &byte, 1); close(release_pipe[1]); }
    int child_ok = 0, status = 0;
    if (child > 0 && waitpid(child, &status, 0) == child)
        child_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    int after = disable_rx_ring(fd, &ae);
    out("lifetime", "mapping_split_fork",
        "ring_rc=%d|mapped=%d|fork_ok=%d|first_unmap=%d|split_disable=%d:%s(%d)|second_unmap=%d|child_disable=%d:%s(%d)|child_access=%d|after_disable=%d:%s(%d)",
        rr, map != MAP_FAILED, child > 0, first_unmap, busy_split, errno_name(be), be,
        second_unmap, busy_child, errno_name(ce), ce, child_ok, after, errno_name(ae), ae);
    close(fd);
}

static void mapping_remap(void) {
    struct tpacket_req req = one_ring(2);
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    unsigned char *map = mmap(NULL, BLOCK_SIZE * 2, PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
    void *moved = map == MAP_FAILED ? MAP_FAILED :
        mremap(map, BLOCK_SIZE * 2, BLOCK_SIZE * 2, MREMAP_MAYMOVE);
    int access = 0;
    if (moved != MAP_FAILED) {
        volatile unsigned char *bytes = moved;
        bytes[BLOCK_SIZE * 2 - 1] = 0x65;
        access = bytes[BLOCK_SIZE * 2 - 1] == 0x65;
    }
    int be, ae;
    int busy = disable_rx_ring(fd, &be);
    int unmap = moved == MAP_FAILED ? -1 : munmap(moved, BLOCK_SIZE * 2);
    int after = disable_rx_ring(fd, &ae);
    out("lifetime", "mapping_remap",
        "ring_rc=%d|mapped=%d|remapped=%d|access=%d|busy_disable=%d:%s(%d)|unmap=%d|after_disable=%d:%s(%d)",
        rr, map != MAP_FAILED, moved != MAP_FAILED, access, busy, errno_name(be), be,
        unmap, after, errno_name(ae), ae);
    if (moved == MAP_FAILED && map != MAP_FAILED) munmap(map, BLOCK_SIZE * 2);
    close(fd);
}

struct blocked_recv {
    int fd;
    pthread_barrier_t barrier;
    ssize_t rc;
    int err;
};

static void *blocked_receiver(void *opaque) {
    struct blocked_recv *state = opaque;
    unsigned char frame[128];
    pthread_barrier_wait(&state->barrier);
    errno = 0;
    state->rc = recv(state->fd, frame, sizeof(frame), 0);
    state->err = errno;
    return NULL;
}

static int send_preopened(int fd, int ifindex, unsigned int sequence) {
    unsigned char frame[64];
    struct sockaddr_ll addr;
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xff, ETH_ALEN);
    frame[12] = (unsigned char)(PROBE_PROTOCOL >> 8);
    frame[13] = (unsigned char)PROBE_PROTOCOL;
    memcpy(frame + 14, "AF_PACKET_BLOCK", 15);
    memcpy(frame + 32, &sequence, sizeof(sequence));
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(PROBE_PROTOCOL);
    addr.sll_ifindex = ifindex;
    return (int)sendto(fd, frame, sizeof(frame), 0,
                       (struct sockaddr *)&addr, sizeof(addr));
}

static void close_while_blocked(const struct probe_env *env) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(PROBE_PROTOCOL));
    int sender = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    struct blocked_recv state = {.fd = fd, .rc = -1, .err = 0};
    pthread_barrier_init(&state.barrier, NULL, 2);
    pthread_t thread;
    int created = pthread_create(&thread, NULL, blocked_receiver, &state);
    pthread_barrier_wait(&state.barrier);
    struct timespec pause = {.tv_nsec = 20000000};
    nanosleep(&pause, NULL);
    int cr = close(fd);
    int sent = send_preopened(sender, env->ifindex, 0x9865);
    if (created == 0) pthread_join(thread, NULL);
    out("lifetime", "close_while_recv_blocked",
        "bind_rc=%d|thread_rc=%d|close_rc=%d|send_ok=%d|recv_positive=%d|recv_errno=%s(%d)",
        br, created, cr, sent >= 0, state.rc > 0, errno_name(state.err), state.err);
    pthread_barrier_destroy(&state.barrier);
    close(sender);
}

void probe_extended(const struct probe_env *env) {
    gso_matrix(env);
    tx_epoll_states(env);
    v3_retire_timeout(env);
    fanout_close_race(env);
    mapping_split_fork();
    mapping_remap();
    close_while_blocked(env);
}
