/* res_hnok/res_ownok/res_mailok/res_dnok domain validators vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <resolv.h>

#define STRING60 "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
#define STRING63 STRING60 "zzz"

static void run(const char *s) {
    printf("[%s] h=%d o=%d m=%d d=%d\n",
        s, res_hnok(s), res_ownok(s), res_mailok(s), res_dnok(s));
}

int main(void) {
    const char *cases[] = {
        "", ".", "..", "www", "www.", "example.com", "www.example.com.",
        "www-.example.com.", "www.-example.com.", "*.example.com",
        "-v", "-v.example.com", "**.example.com", "www.example.com\\",
        STRING63, STRING63 ".", STRING63 "\\.", STRING63 "z",
        STRING63 ".example.com",
        STRING63 "." STRING63 "." STRING63 "." STRING60 "z",
        STRING63 "." STRING63 "." STRING63 "." STRING60 "z.",
        STRING63 "." STRING63 "." STRING63 "." STRING60 "zz",
        "hostmaster@mail.example.com", "hostmaster\\@mail.example.com",
        "user.name@example.com", "with whitespace", "with\twhitespace",
        "with.whitespace ", "with\\ whitespace", "bad_underscore.com",
        "a\\.b.example", "mail@example.com", "@example.com", "user@",
    };
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) run(cases[i]);
    return 0;
}
