/* Non-PIE COPY-reloc coverage for libc data aliases.  The harness links this
   one test with -fno-pie/-no-pie; most conformance tests stay PIE. */
#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

extern char **environ;
extern char **__environ;
extern char **_environ;
extern char *program_invocation_name;
extern char *__progname_full;
extern char *program_invocation_short_name;
extern char *__progname;
extern int signgam;
extern int __signgam;
extern char *tzname[2];
extern char *__tzname[2];
extern long timezone;
extern long __timezone;
extern int daylight;
extern int __daylight;

static int streq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

int main(void) {
    tzset();
    (void)lgamma(0.5);

    printf("env_alias=%d\n", environ && __environ && _environ &&
                               environ[0] && __environ[0] && _environ[0] &&
                               environ == __environ && environ == _environ);
    printf("prog_full_alias=%d\n", streq(program_invocation_name, __progname_full));
    printf("prog_short_alias=%d\n", streq(program_invocation_short_name, __progname));
    printf("signgam_alias=%d\n", signgam == __signgam);
    printf("tzname_alias=%d\n", tzname[0] && __tzname[0] && strcmp(tzname[0], __tzname[0]) == 0);
    printf("timezone_alias=%d\n", timezone == __timezone);
    printf("daylight_alias=%d\n", daylight == __daylight);
    return 0;
}
