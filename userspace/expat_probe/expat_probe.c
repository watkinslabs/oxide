/* expat_probe — dynamic-link smoke for the cross-built libexpat.so (L2,
 * dbus's XML parser). Links /usr/lib/libexpat.so; parses a tiny XML doc
 * and counts a start element via the callback. Proves the .so loaded. */
#include <stdio.h>
#include <string.h>
#include <expat.h>
static int starts = 0;
static void on_start(void *u, const XML_Char *n, const XML_Char **a) {
    (void)u; (void)a; if (!strcmp(n, "oxide")) starts++;
}
int main(void) {
    XML_Parser p = XML_ParserCreate(NULL);
    if (!p) { printf("expat_probe: create FAIL\n"); return 1; }
    XML_SetStartElementHandler(p, on_start);
    const char *doc = "<oxide><x/></oxide>";
    int rc = XML_Parse(p, doc, (int)strlen(doc), 1);
    XML_ParserFree(p);
    if (rc != XML_STATUS_OK || starts != 1) { printf("expat_probe: parse FAIL\n"); return 1; }
    printf("expat_probe: libexpat.so OK v=%s\n", XML_ExpatVersion());
    return 0;
}
