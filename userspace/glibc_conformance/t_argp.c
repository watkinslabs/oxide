/* argp + argz extras + envz + wordexp audit vs host glibc.
   All sub-tests are deterministic: argp parses a fixed argv; the error path is
   captured by redirecting stderr to a pipe and echoing it back to stdout;
   wordexp runs over a fixed environment with WRDE_NOCMD and a pattern that
   cannot match anything in the cwd. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <argp.h>
#include <argz.h>
#include <envz.h>
#include <wordexp.h>

/* ---- argp ---- */
struct args { int verbose; char *output; int count; int nargs; char arg0[64]; };

static const struct argp_option opts[] = {
    {"verbose", 'v', 0,      0, "Be verbose", 0},
    {"output",  'o', "FILE", 0, "Output to FILE", 0},
    {"count",   'c', "N",    0, "Repeat N times", 0},
    {0,0,0,0,0,0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct args *a = state->input;
    switch (key) {
    case 'v': a->verbose = 1; break;
    case 'o': a->output = arg; break;
    case 'c': a->count = atoi(arg); break;
    case ARGP_KEY_ARG:
        if (a->nargs == 0) snprintf(a->arg0, sizeof a->arg0, "%s", arg);
        a->nargs++;
        break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { opts, parse_opt, "ARG", "test argp", 0, 0, 0 };

static void test_argp(void) {
    char *av[] = {"prog", "-v", "-o", "out.txt", "-c", "3", "thefile", NULL};
    int ac = 7;
    struct args a; memset(&a, 0, sizeof a);
    int idx = 0;
    argp_parse(&argp, ac, av, ARGP_NO_EXIT, &idx, &a);
    printf("argp: verbose=%d output=%s count=%d nargs=%d arg0=%s idx=%d\n",
           a.verbose, a.output, a.count, a.nargs, a.arg0, idx);

    /* forced argp_error captured via stderr->pipe (no exit: ARGP_NO_EXIT) */
    int p[2]; if (pipe(p) != 0) return;
    int saved = dup(2); dup2(p[1], 2); close(p[1]);

    char *bv[] = {"prog", "-z", NULL};  /* -z unknown → error + see-help */
    struct args b; memset(&b, 0, sizeof b);
    argp_parse(&argp, 2, bv, ARGP_NO_EXIT, NULL, &b);

    fflush(stderr); dup2(saved, 2); close(saved);
    char buf[512]; ssize_t n = read(p[0], buf, sizeof buf - 1);
    if (n < 0) n = 0; buf[n] = 0; close(p[0]);
    printf("argp_err: %s", buf);
}

static void version_hook(FILE *stream, struct argp_state *state) {
    fprintf(stream, "hook name=%s next=%d flags=%u\n",
            state && state->name ? state->name : "(null)",
            state ? state->next : -1, state ? state->flags : 0);
}

static void test_argp_version_hook(void) {
    fflush(stdout);
    int p[2]; if (pipe(p) != 0) return;
    int saved = dup(1); dup2(p[1], 1); close(p[1]);

    argp_program_version = "plain-version";
    argp_program_version_hook = version_hook;
    char *av[] = {"progname", "--version", NULL};
    int idx = 99;
    int r = argp_parse(&argp, 2, av, ARGP_NO_EXIT, &idx, NULL);

    fflush(stdout); dup2(saved, 1); close(saved);
    char buf[256]; ssize_t n = read(p[0], buf, sizeof buf - 1);
    if (n < 0) n = 0; buf[n] = 0; close(p[0]);
    printf("argp_version_hook: r=%d idx=%d out=%s", r, idx, buf);
    argp_program_version_hook = NULL;
    argp_program_version = NULL;
}

/* ---- argz extras ---- */
static void test_argz(void) {
    char *az = NULL; size_t len = 0;
    argz_add(&az, &len, "a");
    argz_add(&az, &len, "b");
    argz_add(&az, &len, "c");
    /* insert "X" before "b" */
    char *before = argz_next(az, len, NULL);
    before = argz_next(az, len, before);  /* points at "b" */
    argz_insert(&az, &len, before, "X");
    printf("argz_insert:"); for (char *e=argz_next(az,len,NULL);e;e=argz_next(az,len,e)) printf(" %s",e); printf("\n");
    /* delete "X" */
    char *x = argz_next(az, len, NULL); x = argz_next(az, len, x); /* "X" */
    argz_delete(&az, &len, x);
    printf("argz_delete:"); for (char *e=argz_next(az,len,NULL);e;e=argz_next(az,len,e)) printf(" %s",e); printf("\n");
    /* replace "b" with "BB" */
    unsigned rc = 0;
    argz_replace(&az, &len, "b", "BB", &rc);
    printf("argz_replace(rc=%u):", rc); for (char *e=argz_next(az,len,NULL);e;e=argz_next(az,len,e)) printf(" %s",e); printf("\n");
    free(az);
}

/* ---- envz ---- */
static void test_envz(void) {
    char *ez = NULL; size_t len = 0;
    envz_add(&ez, &len, "A", "1");
    envz_add(&ez, &len, "B", "2");
    envz_add(&ez, &len, "C", NULL);  /* null entry */
    printf("envz_get A=%s B=%s C=%s\n", envz_get(ez,len,"A"), envz_get(ez,len,"B"),
           envz_get(ez,len,"C") ? envz_get(ez,len,"C") : "(null)");
    /* merge: D=4, B=overridden */
    char *m = NULL; size_t ml = 0;
    envz_add(&m, &ml, "D", "4");
    envz_add(&m, &ml, "B", "99");
    envz_merge(&ez, &len, m, ml, 1);
    printf("envz_merge B=%s D=%s\n", envz_get(ez,len,"B"), envz_get(ez,len,"D"));
    free(m);
    /* strip null entries */
    envz_strip(&ez, &len);
    printf("envz_strip C-entry=%p count=%zu\n", (void*)envz_entry(ez,len,"C"), argz_count(ez,len));
    free(ez);
}

/* ---- wordexp ---- */
static void test_wordexp(void) {
    setenv("WX", "hello world", 1);
    unsetenv("WXUNSET");
    wordexp_t we;
    /* fixed pattern: literal a b, $WX (splits into 2), ${WXUNSET:-def}, a
       glob that won't match. WRDE_NOCMD rejects command substitution. */
    int r = wordexp("a b $WX ${WXUNSET:-def} zzz_nomatch_*.qzx", &we, WRDE_NOCMD);
    printf("wordexp r=%d wordc=%zu:", r, we.we_wordc);
    if (r == 0) for (size_t i=0;i<we.we_wordc;i++) printf(" [%s]", we.we_wordv[i]);
    printf("\n");
    if (r == 0) wordfree(&we);
}

int main(void) {
    test_argp();
    test_argp_version_hook();
    test_argz();
    test_envz();
    test_wordexp();
    return 0;
}
