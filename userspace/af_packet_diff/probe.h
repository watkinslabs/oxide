#ifndef AF_PACKET_DIFF_PROBE_H
#define AF_PACKET_DIFF_PROBE_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

#define PROBE_PROTOCOL 0x88b5
#define FRAME_SIZE 2048U
#define BLOCK_SIZE 4096U
#define BLOCK_NR 2U
#define POLL_MS 250

struct probe_env {
    int ifindex;
    int packet_errno;
};

void out(const char *area, const char *test, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void result(const char *area, const char *test, int rc, int err);
int packet_socket(int type, int protocol);
int bind_packet(int fd, int ifindex, int protocol);
int send_frame(int ifindex, int protocol, unsigned int sequence);
int send_udp_burst(unsigned int count);
int poll_mask(int fd, short events, int timeout_ms);
int drain_packets(int fd);
void *fault_page(size_t *size);
const char *errno_name(int err);

void probe_options(const struct probe_env *env);
void probe_rings(const struct probe_env *env);
void probe_fanout(const struct probe_env *env);
void probe_runtime(const struct probe_env *env);
void probe_extended(const struct probe_env *env);

#endif
