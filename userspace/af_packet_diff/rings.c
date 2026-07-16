#include "probe.h"

static struct tpacket_req request_v12(void) {
    struct tpacket_req req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr = BLOCK_NR,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr = BLOCK_NR * (BLOCK_SIZE / FRAME_SIZE),
    };
    return req;
}

static struct tpacket_req3 request_v3(void) {
    struct tpacket_req3 req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr = BLOCK_NR,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr = BLOCK_NR * (BLOCK_SIZE / FRAME_SIZE),
        .tp_retire_blk_tov = 50,
        .tp_sizeof_priv = 32,
        .tp_feature_req_word = TP_FT_REQ_FILL_RXHASH,
    };
    return req;
}

static void malformed_one(const char *name, int version, const void *req, socklen_t len) {
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int vrc = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    errno = 0;
    int rc = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, len);
    int err = errno;
    out("ring_malformed", name, "version_rc=%d|rc=%d|errno=%s(%d)",
        vrc, rc, errno_name(err), err);
    close(fd);
}

static void malformed_layouts(void) {
    struct tpacket_req req = request_v12();
    malformed_one("v1_valid", TPACKET_V1, &req, sizeof(req));
    malformed_one("v2_valid", TPACKET_V2, &req, sizeof(req));

    req = request_v12(); req.tp_block_size = 0;
    malformed_one("block_size_zero", TPACKET_V2, &req, sizeof(req));
    req = request_v12(); req.tp_block_size = BLOCK_SIZE + 1;
    malformed_one("block_not_page_multiple", TPACKET_V2, &req, sizeof(req));
    req = request_v12(); req.tp_block_nr = 0;
    malformed_one("block_nr_zero", TPACKET_V2, &req, sizeof(req));
    req = request_v12(); req.tp_frame_size = 0;
    malformed_one("frame_size_zero", TPACKET_V2, &req, sizeof(req));
    req = request_v12(); req.tp_frame_size = FRAME_SIZE - 1;
    malformed_one("frame_unaligned", TPACKET_V2, &req, sizeof(req));
    req = request_v12(); req.tp_frame_nr--;
    malformed_one("frame_count_mismatch", TPACKET_V2, &req, sizeof(req));
    req = request_v12(); req.tp_block_nr = UINT32_MAX;
    malformed_one("block_count_overflow", TPACKET_V2, &req, sizeof(req));
    req = request_v12();
    malformed_one("req_short", TPACKET_V2, &req, sizeof(req) - 1);

    struct tpacket_req3 req3 = request_v3();
    malformed_one("v3_valid", TPACKET_V3, &req3, sizeof(req3));
    req3 = request_v3(); req3.tp_sizeof_priv = BLOCK_SIZE;
    malformed_one("v3_priv_too_large", TPACKET_V3, &req3, sizeof(req3));
    req3 = request_v3(); req3.tp_feature_req_word = 0x80000000U;
    malformed_one("v3_unknown_feature", TPACKET_V3, &req3, sizeof(req3));
    req3 = request_v3();
    malformed_one("v3_req_v1_size", TPACKET_V3, &req3, sizeof(struct tpacket_req));

    size_t page_size = 0;
    void *fault = fault_page(&page_size);
    if (fault != MAP_FAILED) {
        malformed_one("request_fault", TPACKET_V2, fault, sizeof(struct tpacket_req));
        munmap(fault, page_size);
    }
}

static void mmap_shape(void) {
    struct tpacket_req req = request_v12();
    size_t ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int ring_rc = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    errno = 0;
    void *exact = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, fd, 0);
    int ee = errno;
    errno = 0;
    void *short_map = mmap(NULL, ring_size - BLOCK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED, fd, 0);
    int se = errno;
    errno = 0;
    void *offset = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, (off_t)BLOCK_SIZE);
    int oe = errno;
    errno = 0;
    void *private_map = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE, fd, 0);
    int pe = errno;
    out("mmap", "rx_shapes",
        "ring_rc=%d|exact=%d:%s(%d)|short=%d:%s(%d)|offset=%d:%s(%d)|private=%d:%s(%d)",
        ring_rc, exact != MAP_FAILED, errno_name(ee), ee,
        short_map != MAP_FAILED, errno_name(se), se,
        offset != MAP_FAILED, errno_name(oe), oe,
        private_map != MAP_FAILED, errno_name(pe), pe);
    if (exact != MAP_FAILED) munmap(exact, ring_size);
    if (short_map != MAP_FAILED) munmap(short_map, ring_size - BLOCK_SIZE);
    if (offset != MAP_FAILED) munmap(offset, ring_size);
    if (private_map != MAP_FAILED) munmap(private_map, ring_size);
    close(fd);
}

static void combined_mmap(void) {
    struct tpacket_req req = request_v12();
    size_t one = (size_t)req.tp_block_size * req.tp_block_nr;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rx = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    int tx = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    errno = 0;
    void *both = mmap(NULL, one * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int be = errno;
    errno = 0;
    void *rx_only = mmap(NULL, one, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int re = errno;
    out("mmap", "combined_rx_tx", "rx_rc=%d|tx_rc=%d|combined=%d:%s(%d)|rx_only=%d:%s(%d)",
        rx, tx, both != MAP_FAILED, errno_name(be), be,
        rx_only != MAP_FAILED, errno_name(re), re);
    if (both != MAP_FAILED) munmap(both, one * 2);
    if (rx_only != MAP_FAILED) munmap(rx_only, one);
    close(fd);
}

static void v3_large_private_width(void) {
    enum { large_block = 131072, large_frame = 2048, large_private = 65536 };
    struct tpacket_req3 req = {
        .tp_block_size = large_block,
        .tp_block_nr = 1,
        .tp_frame_size = large_frame,
        .tp_frame_nr = large_block / large_frame,
        .tp_retire_blk_tov = 50,
        .tp_sizeof_priv = large_private,
    };
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V3;
    int vr = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    errno = 0;
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    int re = errno;
    void *map = MAP_FAILED;
    int me = 0;
    if (rr == 0) {
        errno = 0;
        map = mmap(NULL, large_block, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        me = errno;
    }
    unsigned int priv_off = UINT32_MAX, first_off = UINT32_MAX;
    if (map != MAP_FAILED) {
        struct tpacket_block_desc *bd = map;
        priv_off = bd->offset_to_priv;
        first_off = bd->hdr.bh1.offset_to_first_pkt;
    }
    out("mmap", "v3_large_private_width",
        "version_rc=%d|ring_rc=%d|ring_errno=%s(%d)|mapped=%d|map_errno=%s(%d)|priv_off=%u|first_off=%u",
        vr, rr, errno_name(re), re, map != MAP_FAILED, errno_name(me), me,
        priv_off, first_off);
    if (map != MAP_FAILED) munmap(map, large_block);
    close(fd);
}

static void rx_v12(const struct probe_env *env, int version) {
    struct tpacket_req req = request_v12();
    size_t size = (size_t)req.tp_block_size * req.tp_block_nr;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int initial = poll_mask(fd, POLLIN, 0);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, (unsigned int)version);
    int ready = poll_mask(fd, POLLIN, POLL_MS);
    char name[16];
    snprintf(name, sizeof(name), "v%d_rx", version + 1);
    if (map == MAP_FAILED || !(ready & POLLIN)) {
        out("ring", name, "ring_rc=%d|bind_rc=%d|mapped=%d|initial=%d|send=%d|ready=%d|visible=0",
            rr, br, map != MAP_FAILED, initial, sent, ready);
    } else if (version == TPACKET_V1) {
        struct tpacket_hdr *h = map;
        struct sockaddr_ll *sll = (void *)((unsigned char *)map + TPACKET_ALIGN(sizeof(*h)));
        out("ring", name,
            "ring_rc=%d|bind_rc=%d|initial=%d|send=%d|ready=%d|visible=1|status_user=%d|len=%u|snap=%u|mac=%u|net=%u|sll_off=%zu|ifindex_match=%d|pkttype=%u",
            rr, br, initial, sent, ready, !!(h->tp_status & TP_STATUS_USER), h->tp_len,
            h->tp_snaplen, h->tp_mac, h->tp_net, TPACKET_ALIGN(sizeof(*h)),
            sll->sll_ifindex == env->ifindex, sll->sll_pkttype);
        h->tp_status = TP_STATUS_KERNEL;
    } else {
        struct tpacket2_hdr *h = map;
        struct sockaddr_ll *sll = (void *)((unsigned char *)map + TPACKET_ALIGN(sizeof(*h)));
        out("ring", name,
            "ring_rc=%d|bind_rc=%d|initial=%d|send=%d|ready=%d|visible=1|status_user=%d|len=%u|snap=%u|mac=%u|net=%u|sll_off=%zu|ifindex_match=%d|pkttype=%u",
            rr, br, initial, sent, ready, !!(h->tp_status & TP_STATUS_USER), h->tp_len,
            h->tp_snaplen, h->tp_mac, h->tp_net, TPACKET_ALIGN(sizeof(*h)),
            sll->sll_ifindex == env->ifindex, sll->sll_pkttype);
        h->tp_status = TP_STATUS_KERNEL;
    }
    if (map != MAP_FAILED) munmap(map, size);
    close(fd);
}

static void rx_v3(const struct probe_env *env) {
    struct tpacket_req3 req = request_v3();
    size_t size = (size_t)req.tp_block_size * req.tp_block_nr;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V3;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int rr = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int initial = poll_mask(fd, POLLIN, 0);
    int sent = send_frame(env->ifindex, PROBE_PROTOCOL, 3);
    int ready = poll_mask(fd, POLLIN, POLL_MS);
    if (map == MAP_FAILED || !(ready & POLLIN)) {
        out("ring", "v3_rx", "ring_rc=%d|bind_rc=%d|mapped=%d|initial=%d|send=%d|ready=%d|visible=0",
            rr, br, map != MAP_FAILED, initial, sent, ready);
    } else {
        struct tpacket_block_desc *bd = map;
        struct tpacket_hdr_v1 *bh = &bd->hdr.bh1;
        struct tpacket3_hdr *h = (void *)((unsigned char *)map + bh->offset_to_first_pkt);
        struct sockaddr_ll *sll = (void *)((unsigned char *)h + TPACKET_ALIGN(sizeof(*h)));
        out("ring", "v3_rx",
            "ring_rc=%d|bind_rc=%d|initial=%d|send=%d|ready=%d|visible=1|block_user=%d|version=%u|priv_off=%u|packets=%u|first_off=%u|next=%u|len=%u|snap=%u|mac=%u|net=%u|ifindex_match=%d|pkttype=%u",
            rr, br, initial, sent, ready, !!(bh->block_status & TP_STATUS_USER), bd->version,
            bd->offset_to_priv, bh->num_pkts, bh->offset_to_first_pkt, h->tp_next_offset,
            h->tp_len, h->tp_snaplen, h->tp_mac, h->tp_net,
            sll->sll_ifindex == env->ifindex, sll->sll_pkttype);
        bh->block_status = TP_STATUS_KERNEL;
    }
    if (map != MAP_FAILED) munmap(map, size);
    close(fd);
}

static void tx_v2(const struct probe_env *env) {
    struct tpacket_req req = request_v12();
    size_t size = (size_t)req.tp_block_size * req.tp_block_nr;
    int fd = packet_socket(SOCK_RAW, PROBE_PROTOCOL);
    int version = TPACKET_V2;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    int tr = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    int br = bind_packet(fd, env->ifindex, PROBE_PROTOCOL);
    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int before = poll_mask(fd, POLLOUT, 0);
    int kick = -1, ke = 0;
    unsigned int status = UINT32_MAX;
    if (map != MAP_FAILED) {
        struct tpacket2_hdr *h = map;
        unsigned char *frame = (unsigned char *)map + TPACKET2_HDRLEN;
        memset(frame, 0, 64);
        memset(frame, 0xff, ETH_ALEN);
        frame[12] = (unsigned char)(PROBE_PROTOCOL >> 8);
        frame[13] = (unsigned char)PROBE_PROTOCOL;
        memcpy(frame + 14, "AF_PACKET_TX", 12);
        h->tp_len = 64;
        h->tp_snaplen = 64;
        h->tp_mac = TPACKET2_HDRLEN;
        h->tp_net = TPACKET2_HDRLEN + ETH_HLEN;
        __atomic_store_n(&h->tp_status, TP_STATUS_SEND_REQUEST, __ATOMIC_RELEASE);
        errno = 0;
        kick = (int)send(fd, NULL, 0, MSG_DONTWAIT);
        ke = errno;
        for (int i = 0; i < 100; i++) {
            status = __atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE);
            if (status != TP_STATUS_SEND_REQUEST && status != TP_STATUS_SENDING) break;
            struct timespec ts = {.tv_nsec = 1000000};
            nanosleep(&ts, NULL);
        }
    }
    int after = poll_mask(fd, POLLOUT, POLL_MS);
    out("ring", "v2_tx", "ring_rc=%d|bind_rc=%d|mapped=%d|poll_before=%d|kick=%d|kick_errno=%s(%d)|status=%u|available=%d|poll_after=%d|mac=%u|net=%u",
        tr, br, map != MAP_FAILED, before, kick, errno_name(ke), ke, status,
        status == TP_STATUS_AVAILABLE, after, (unsigned int)TPACKET2_HDRLEN,
        (unsigned int)(TPACKET2_HDRLEN + ETH_HLEN));
    if (map != MAP_FAILED) munmap(map, size);
    close(fd);
}

void probe_rings(const struct probe_env *env) {
    malformed_layouts();
    mmap_shape();
    combined_mmap();
    v3_large_private_width();
    rx_v12(env, TPACKET_V1);
    rx_v12(env, TPACKET_V2);
    rx_v3(env);
    tx_v2(env);
}
