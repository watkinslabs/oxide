/* POSIX regex audit vs host glibc: ERE patterns, classes, anchors, quantifiers,
   alternation, capture groups, REG_ICASE/NEWLINE/NOTBOL/NOTEOL, regerror. */
#include <stdio.h>
#include <regex.h>
#include <string.h>

extern char *re_comp(const char *);
extern int re_exec(const char *);
struct re_registers {
    unsigned num_regs;
    int *start;
    int *end;
};
extern const char *re_compile_pattern(const char *, size_t, struct re_pattern_buffer *);
extern int re_compile_fastmap(struct re_pattern_buffer *);
extern int re_match(struct re_pattern_buffer *, const char *, int, int, struct re_registers *);
extern int re_search(struct re_pattern_buffer *, const char *, int, int, int, struct re_registers *);
extern reg_syntax_t re_syntax_options;
extern reg_syntax_t re_set_syntax(reg_syntax_t);
#ifndef RE_SYNTAX_POSIX_EXTENDED
#define RE_SYNTAX_POSIX_EXTENDED 242428UL
#endif
#ifndef RE_SYNTAX_POSIX_BASIC
#define RE_SYNTAX_POSIX_BASIC 16843462UL
#endif

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

    printf("RE|comp=%s\n", re_comp("a*b") ? "err" : "ok");
    printf("RE|match=%d nomatch=%d\n", re_exec("aaab"), re_exec("ccc"));

    struct re_pattern_buffer rb;
    memset(&rb, 0, sizeof rb);
    printf("GNURE|compile=%s\n", re_compile_pattern("a*b", 3, &rb) ? "err" : "ok");
    char fast[256];
    memset(fast, 0, sizeof fast);
    rb.__fastmap = fast;
    printf("GNURE|fastmap=%d\n", re_compile_fastmap(&rb));
    struct re_registers regs;
    memset(&regs, 0, sizeof regs);
    printf("GNURE|match=%d\n", re_match(&rb, "aaab", 4, 0, &regs));
    printf("GNURE|regs=%u %d %d\n", regs.num_regs, regs.start ? regs.start[0] : -9, regs.end ? regs.end[0] : -9);
    printf("GNURE|search=%d\n", re_search(&rb, "xxaaab", 6, 0, 6, &regs));
    printf("GNURE|regs2=%u %d %d\n", regs.num_regs, regs.start ? regs.start[0] : -9, regs.end ? regs.end[0] : -9);
    printf("GNURE|syntax0=%lu\n", (unsigned long)re_syntax_options);
    reg_syntax_t old_syntax = re_set_syntax(RE_SYNTAX_POSIX_BASIC);
    printf("GNURE|setbasic_old=%lu now=%lu\n", (unsigned long)old_syntax, (unsigned long)re_syntax_options);
    memset(&rb, 0, sizeof rb);
    printf("GNURE|basic_plus=%s ", re_compile_pattern("a+b", 3, &rb) ? "err" : "ok");
    printf("match=%d\n", re_match(&rb, "aaab", 4, 0, 0));
    old_syntax = re_set_syntax(RE_SYNTAX_POSIX_EXTENDED);
    printf("GNURE|setext_old=%lu now=%lu\n", (unsigned long)old_syntax, (unsigned long)re_syntax_options);
    memset(&rb, 0, sizeof rb);
    printf("GNURE|ext_plus=%s ", re_compile_pattern("a+b", 3, &rb) ? "err" : "ok");
    printf("match=%d\n", re_match(&rb, "aaab", 4, 0, 0));
    return 0;
}
