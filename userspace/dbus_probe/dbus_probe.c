/* dbus_probe — dynamic-link smoke for the cross-built libdbus-1.so (L2,
 * mandatory systemd bus stack). Links /usr/lib/libdbus-1.so; builds a
 * D-Bus method-call message, round-trips a string argument through the
 * append/iter API, and frees it. No bus daemon needed — this proves the
 * .so loaded + resolved and the core message machinery works. */
#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>
int main(void) {
    DBusMessage *m = dbus_message_new_method_call(
        "org.oxide.Probe", "/org/oxide/Probe", "org.oxide.Probe", "Ping");
    if (!m) { printf("dbus_probe: new_method_call FAIL\n"); return 1; }
    const char *in = "oxide";
    if (!dbus_message_append_args(m, DBUS_TYPE_STRING, &in, DBUS_TYPE_INVALID)) {
        printf("dbus_probe: append FAIL\n"); return 1;
    }
    DBusMessageIter it;
    char *out = NULL;
    if (!dbus_message_iter_init(m, &it) ||
        dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_STRING) {
        printf("dbus_probe: iter FAIL\n"); return 1;
    }
    dbus_message_iter_get_basic(&it, &out);
    if (!out || strcmp(out, in) != 0) { printf("dbus_probe: roundtrip FAIL\n"); return 1; }
    dbus_message_unref(m);
    int maj = 0, min = 0, mic = 0;
    dbus_get_version(&maj, &min, &mic);
    printf("dbus_probe: libdbus-1.so OK ver=%d.%d.%d arg=%s\n", maj, min, mic, out);
    return 0;
}
