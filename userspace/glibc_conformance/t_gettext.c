/* gettext passthrough vs host glibc (no catalog loaded → msgid returned). */
#include <stdio.h>
#include <libintl.h>
#include <locale.h>
int main(void){
    setlocale(LC_ALL, "C");
    printf("g=%s\n", gettext("Hello, world"));
    printf("dg=%s\n", dgettext("myapp", "untranslated"));
    printf("n1=%s n2=%s n0=%s\n",
           ngettext("%d file", "%d files", 1),
           ngettext("%d file", "%d files", 2),
           ngettext("%d file", "%d files", 0));
    printf("td=%s\n", textdomain("myapp"));
    printf("td_q=%s\n", textdomain(NULL));   /* query current */
    printf("bind=%s\n", bindtextdomain("myapp", "/usr/share/locale"));
    printf("codeset=%s\n", bind_textdomain_codeset("myapp", "UTF-8"));
    return 0;
}
