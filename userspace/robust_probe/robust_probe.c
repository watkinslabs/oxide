// /bin/robust_probe — verifies robust-futex list recovery on thread exit
// (Linux do_exit -> exit_robust_list). A child pthread registers a robust
// list holding ONE mutex word `w` (low 30 bits = its gettid, FUTEX_WAITERS
// set), then exits. The kernel's exit walk must OR FUTEX_OWNER_DIED into `w`
// and wake a waiter. Main joins the child and asserts the bit was set.
//
// RAW approach (no dependence on musl's internal robust wiring): build the
// struct robust_list_head by hand and register via syscall(SYS_set_robust_list).
//
// Expected on a working kernel:
//   robust_probe: child tid=NNN registered, w=0x8000....
//   robust_probe: PASS
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>

#define FUTEX_WAITERS    0x80000000u
#define FUTEX_OWNER_DIED 0x40000000u
#define FUTEX_TID_MASK   0x3fffffffu
#define ROBUST_LIST_HEAD_SIZE 24  // sizeof(struct robust_list_head) on 64-bit

// Layout must match the kernel walker (linux/futex.h):
//   robust_list_head { list.next @0; futex_offset @8; list_op_pending @16 }
struct robust_list { struct robust_list *next; };
struct robust_list_head {
    struct robust_list list;
    long futex_offset;
    struct robust_list *list_op_pending;
};

// The futex word + list nodes are STATIC so they outlive the child thread —
// the kernel walks them during the child's exit, after it has returned.
static volatile unsigned int w;
static struct robust_list node;
static struct robust_list_head head;

static void *child(void *arg) {
    (void)arg;
    long tid = syscall(SYS_gettid);
    // One-entry robust list: head.next -> node -> head (terminates the walk).
    head.list.next = &node;
    node.next = (struct robust_list *)&head;
    // futex_offset chosen so (node + futex_offset) == &w, i.e. the walker
    // computes the mutex word address as &w for this entry.
    head.futex_offset = (long)((char *)&w - (char *)&node);
    head.list_op_pending = 0;
    // Owner TID in low 30 bits == gettid; FUTEX_WAITERS set so the walk wakes.
    w = FUTEX_WAITERS | ((unsigned int)tid & FUTEX_TID_MASK);
    if (syscall(SYS_set_robust_list, &head, ROBUST_LIST_HEAD_SIZE) != 0) {
        write(2, "robust_probe: set_robust_list FAIL\n", 35);
        return NULL;
    }
    printf("robust_probe: child tid=%ld registered, w=0x%08x\n",
           tid, (unsigned int)w);
    fflush(stdout);
    return NULL;  // thread exit -> kernel exit_robust_list walks the list
}

int main(void) {
    // Reject a wrong len up front (Linux + our GAP 3 check return EINVAL).
    if (syscall(SYS_set_robust_list, &head, 16) == 0) {
        write(2, "robust_probe: len!=24 accepted (should EINVAL) FAIL\n", 51);
        return 1;
    }
    pthread_t t;
    if (pthread_create(&t, NULL, child, NULL) != 0) {
        write(2, "robust_probe: pthread_create FAIL\n", 34);
        return 1;
    }
    pthread_join(t, NULL);
    usleep(50 * 1000);
    unsigned int fin = w;
    if (fin & FUTEX_OWNER_DIED) {
        printf("robust_probe: w=0x%08x OWNER_DIED set\n", fin);
        write(1, "robust_probe: PASS\n", 19);
        return 0;
    }
    printf("robust_probe: w=0x%08x OWNER_DIED NOT set\n", fin);
    write(1, "robust_probe: FAIL\n", 19);
    return 1;
}
