#include "probe.h"

int main(void) {
    struct probe_env env;
    int fd;

    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(&env, 0, sizeof(env));
    env.ifindex = (int)if_nametoindex("lo");
    fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    if (fd < 0) env.packet_errno = errno;
    else close(fd);

    out("meta", "format", "af_packet_diff=1");
    out("env", "af_packet", "available=%d|errno=%s(%d)",
        env.packet_errno == 0, errno_name(env.packet_errno), env.packet_errno);
    out("env", "loopback", "available=%d", env.ifindex > 0);
    probe_recvfrom();
    if (env.packet_errno != 0) {
        out("env", "unsupported", "reason=AF_PACKET_SOCKET|errno=%s(%d)",
            errno_name(env.packet_errno), env.packet_errno);
        out("meta", "complete", "status=UNSUPPORTED");
        return 0;
    }
    if (env.ifindex <= 0) {
        out("env", "unsupported", "reason=LOOPBACK_INTERFACE");
        out("meta", "complete", "status=UNSUPPORTED");
        return 0;
    }

    probe_options(&env);
    probe_rings(&env);
    probe_fanout(&env);
    probe_runtime(&env);
    probe_extended(&env);
    out("meta", "complete", "status=DONE");
    return 0;
}
