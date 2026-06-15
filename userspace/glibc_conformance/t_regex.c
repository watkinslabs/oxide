/* POSIX regex audit vs host glibc: ERE patterns, classes, anchors, quantifiers,
   alternation, capture groups, REG_ICASE/NEWLINE/NOTBOL/NOTEOL, regerror. */
#include <stdio.h>
#include <regex.h>

static void t(const char *pat, const char *s, int cflags, int eflags){
    regex_t re; regmatch_t m[10];
    int rc = regcomp(&re, pat, cflags | REG_EXTENDED);
    if (rc){ printf("C|%s comp=%d\n", pat, rc); return; }
    rc = regexec(&re, s, 10, m, eflags);
    printf("M|%s|%s rc=%d ns=%zu", pat, s, rc, re.re_nsub);
    if (rc == 0) for (size_t i = 0; i <= re.re_nsub; i++) printf(" [%d,%d]", m[i].rm_so, m[i].rm_eo);
    printf("\n");
    regfree(&re);
}

/* BRE mode: compile without REG_EXTENDED. */
static void tb(const char *pat, const char *s){
    regex_t re; regmatch_t m[10];
    int rc = regcomp(&re, pat, 0);
    if (rc){ printf("CB|%s comp=%d\n", pat, rc); return; }
    rc = regexec(&re, s, 10, m, 0);
    printf("B|%s|%s rc=%d ns=%zu", pat, s, rc, re.re_nsub);
    if (rc == 0) for (size_t i = 0; i <= re.re_nsub; i++) printf(" [%d,%d]", m[i].rm_so, m[i].rm_eo);
    printf("\n");
    regfree(&re);
}

int main(void){
    t("a.c", "xabcx", 0, 0);
    t("a*", "aaab", 0, 0);
    t("a+", "baaa", 0, 0);
    t("colou?r", "color", 0, 0);
    t("colou?r", "colour", 0, 0);
    t("[0-9]+", "id=4096!", 0, 0);
    t("[^0-9]+", "abc123", 0, 0);
    t("[[:alpha:]]+", "  Hello42", 0, 0);
    t("[[:space:]]+", "a   b", 0, 0);
    t("^foo$", "foo", 0, 0);
    t("^foo$", "foox", 0, 0);
    t("a{2,3}", "aaaaa", 0, 0);
    t("a{3}", "aa", 0, 0);
    t("(ab)+", "ababab", 0, 0);
    t("(a)(b)(c)", "abc", 0, 0);
    t("(foo|bar|baz)+", "foobarbaz", 0, 0);
    t("https?://[a-z.]+", "see http://oxide.dev now", 0, 0);
    t("[-+]?[0-9]+", "x-42y", 0, 0);
    t("(a+)(b+)", "aaabb", 0, 0);
    t("x*", "", 0, 0);
    t("WORD", "a word here", REG_ICASE, 0);
    t("[a-z]+", "ABCdef", REG_ICASE, 0);
    t("z+", "no zees? zzz", 0, 0);
    t("^", "abc", 0, REG_NOTBOL);
    t("$", "abc", 0, REG_NOTEOL);
    /* BRE mode (no REG_EXTENDED): \(\) groups, \{\} bounds, +?(){}| literal */
    tb("a\\(b\\)c", "abc");
    tb("\\(ab\\)*", "ababab");
    tb("a\\{2,3\\}", "aaaa");
    tb("a+", "aaa+b");          /* '+' literal in BRE → matches "a+" */
    tb("(x)", "(x)");           /* parens literal in BRE */
    tb("^foo", "foo");
    tb("bar$", "foobar");
    tb("a.c", "xabcx");
    tb("[0-9]\\{3\\}", "id4096");

    /* error path + regerror */
    regex_t bad; int rc = regcomp(&bad, "a(b", REG_EXTENDED);
    char buf[64]; regerror(rc, &bad, buf, sizeof buf);
    printf("E|rc=%d msg=%s\n", rc, buf);
    return 0;
}
