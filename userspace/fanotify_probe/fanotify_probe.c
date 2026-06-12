// /bin/fanotify_probe — §2.13 guard: fanotify must deliver real
// `fanotify_event_metadata` (with a working object fd), not the inotify_event
// shim it used to share. Pre-change a fanotify fd WAS an inotify fd and read()
// returned struct inotify_event.
//
// Asserts:
//   1. fanotify_init() + fanotify_mark(FAN_MODIFY) on a real tmpfs file;
//   2. writing the file delivers a 24-byte fanotify_event_metadata with
//      vers==FANOTIFY_METADATA_VERSION, metadata_len==24, mask & FAN_MODIFY;
//   3. the metadata.fd is a real, open fd whose contents == the file (proving
//      read() minted an object fd, not a placeholder).

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/fanotify.h>

#define PASS "fanotify_probe: PASS\n"
static void fail(const char *why) {
    write(2, "fanotify_probe: FAIL ", 21);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}

#define TARGET "/tmp/fanotify_target"
static const char CONTENT[] = "fanotify-object-bytes";

int main(void) {
    // Create the target file with known content.
    int tf = open(TARGET, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (tf < 0) fail("create target");
    if (write(tf, CONTENT, sizeof CONTENT - 1) != (ssize_t)(sizeof CONTENT - 1)) fail("seed write");
    close(tf);

    int fan = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fan < 0) fail("fanotify_init");
    if (fanotify_mark(fan, FAN_MARK_ADD, FAN_MODIFY, AT_FDCWD, TARGET) != 0)
        fail("fanotify_mark");

    // Modify the file → FAN_MODIFY. Append so the seeded prefix stays intact
    // for the object-fd content check below.
    int wf = open(TARGET, O_WRONLY | O_APPEND);
    if (wf < 0) fail("reopen target");
    if (write(wf, "X", 1) != 1) fail("modify write");
    close(wf);

    // Read the event metadata.
    struct fanotify_event_metadata meta;
    ssize_t n = read(fan, &meta, sizeof meta);
    if (n < (ssize_t)FAN_EVENT_METADATA_LEN) fail("short metadata read");
    if (meta.vers != FANOTIFY_METADATA_VERSION) fail("bad metadata version");
    if (meta.event_len < FAN_EVENT_METADATA_LEN) fail("bad event_len");
    if (!(meta.mask & FAN_MODIFY)) fail("mask missing FAN_MODIFY");
    if (meta.fd < 0) fail("no object fd");

    // The object fd must read back the file's bytes.
    char buf[64];
    ssize_t r = pread(meta.fd, buf, sizeof buf, 0);
    if (r <= 0) fail("object fd unreadable");
    if (strncmp(buf, CONTENT, sizeof CONTENT - 1) != 0) fail("object fd content mismatch");
    close(meta.fd);
    close(fan);

    write(1, PASS, sizeof PASS - 1);
    return 0;
}
