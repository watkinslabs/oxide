/* getopt / getopt_long audit vs host glibc: combined options, attached/
   separated/missing args, ':' mode, unknown opts, '--', '+' POSIX mode,
   GNU permutation, long options + abbreviation + optional args. */
#define _GNU_SOURCE
#include <stdio.h>
#include <getopt.h>

static void run(int argc, char **argv, const char *os){
    optind = 0; opterr = 0; optopt = 0; optarg = 0; /* 0 = full GNU reset */
    int o;
    while ((o = getopt(argc, argv, os)) != -1){
        if (o == '?' || o == ':') printf("[%c:%c]", o, optopt ? optopt : '_');
        else if (optarg) printf("[%c=%s]", o, optarg);
        else printf("[%c]", o);
    }
    printf(" oi=%d rest=", optind);
    for (int i = optind; i < argc; i++) printf("%s,", argv[i]);
    printf("\n");
}

int main(void){
    char *a1[] = {"p","-a","-b","val","-c","arg",0};         run(6, a1, "ab:c");
    char *a2[] = {"p","-abc",0};                              run(2, a2, "abc");
    char *a3[] = {"p","-bval","-a",0};                        run(3, a3, "ab:c");
    char *a4[] = {"p","-x","-a",0};                           run(3, a4, "ab:c"); /* unknown x */
    char *a5[] = {"p","-b",0};                                run(2, a5, "ab:c"); /* missing arg -> ? */
    char *a6[] = {"p","-b",0};                                run(2, a6, ":ab:c"); /* missing -> : */
    char *a7[] = {"p","file1","-a","file2",0};               run(4, a7, "a");   /* permutation */
    char *a8[] = {"p","-a","--","-b",0};                      run(4, a8, "ab:"); /* -- terminator */
    char *a9[] = {"p","file","-a",0};                         run(3, a9, "+a");  /* POSIX: stop at file */

    /* getopt_long */
    static struct option lo[] = {
        {"verbose", no_argument, 0, 'v'},
        {"file", required_argument, 0, 'f'},
        {"level", optional_argument, 0, 'l'},
        {0,0,0,0}
    };
    char *l1[] = {"p","--verbose","--file=x","--file","y","-v",0};
    optind=0; opterr=0; int o, idx;
    while ((o = getopt_long(6, l1, "vf:l::", lo, &idx)) != -1){
        if (optarg) printf("<%c=%s>", o, optarg); else printf("<%c>", o);
    }
    printf(" oi=%d\n", optind);

    char *l2[] = {"p","--lev","--lev=3","--verb",0}; /* abbreviation + optional arg */
    optind=0; opterr=0;
    while ((o = getopt_long(4, l2, "vf:l::", lo, &idx)) != -1){
        if (optarg) printf("<%c=%s>", o, optarg); else printf("<%c>", o);
    }
    printf(" oi=%d\n", optind);
    return 0;
}
