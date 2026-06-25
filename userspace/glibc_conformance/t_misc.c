/* addmntent/getmntent round-trip, adjtimex/ntp_gettime sanity (booleans),
 * fmtmsg+addseverity return codes, getdate_r template parse — vs host glibc.
 * Output must be byte-identical between host glibc and oxide libc, so the
 * timex/ntp checks are reduced to environment-independent boolean ranges. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <mntent.h>
#include <fmtmsg.h>
#include <sys/timex.h>

extern FILE *__setmntent(const char *, const char *);

int main(void){
    /* 1. addmntent escaping round-trip through getmntent. */
    char mtmpl[] = "/tmp/t_misc_mtab.XXXXXX";
    int mfd = mkstemp(mtmpl);
    FILE *mf = fdopen(mfd, "w+");
    struct mntent me = {
        .mnt_fsname = "/dev/sda1",
        .mnt_dir    = "/mnt/with space",   /* space must escape to \040 */
        .mnt_type   = "ext4",
        .mnt_opts   = "rw,relatime",
        .mnt_freq   = 1,
        .mnt_passno = 2,
    };
    addmntent(mf, &me);
    rewind(mf);
    struct mntent *r = getmntent(mf);
    printf("mnt fsname=%s dir=%s type=%s opts=%s freq=%d passno=%d\n",
           r->mnt_fsname, r->mnt_dir, r->mnt_type, r->mnt_opts, r->mnt_freq, r->mnt_passno);
    printf("hasmntopt rw=%d nope=%d\n",
           hasmntopt(r, "rw") != NULL, hasmntopt(r, "nope") != NULL);
    fclose(mf);

    FILE *amf = __setmntent(mtmpl, "r");
    struct mntent *mr = getmntent(amf);
    printf("setmntent_alias=%d dir=%s\n", amf != NULL, mr ? mr->mnt_dir : "NULL");
    endmntent(amf);
    unlink(mtmpl);

    /* 2. adjtimex read-only (modes=0): success + tick in a sane fixed band.
     *    Print booleans only (absolute tick/state are environment-specific). */
    struct timex tx; memset(&tx, 0, sizeof tx); tx.modes = 0;
    int ar = adjtimex(&tx);
    printf("adjtimex ok=%d tick_sane=%d\n",
           ar >= 0, (tx.tick >= 9000 && tx.tick <= 11000));
    struct ntptimeval ntv; memset(&ntv, 0, sizeof ntv);
    int nr = ntp_gettime(&ntv);
    printf("ntp_gettime ok=%d time_pos=%d\n", nr >= 0, ntv.time.tv_sec > 0);

    /* 3. fmtmsg return code + addseverity round-trip. Output goes to stderr
     *    (not captured); assert the documented return values only. */
    int fr = fmtmsg(MM_PRINT, "OXIDE:t_misc", MM_INFO,
                    "test message", "no action needed", "OX-1");
    printf("fmtmsg ret_ok=%d\n", fr == MM_OK);
    /* Sequence the addseverity calls (printf arg order is unspecified). */
    int sv_add = addseverity(10, "CUSTOM") == MM_OK;
    int sv_rej = addseverity(MM_ERROR, "X") == MM_NOTOK;
    int sv_rm  = addseverity(10, NULL) == MM_OK;
    printf("addseverity add=%d builtin_rej=%d remove=%d\n", sv_add, sv_rej, sv_rm);

    /* 4. getdate_r against a "%Y-%m-%d" template via DATEMSK. */
    char dtmpl[] = "/tmp/t_misc_datemsk.XXXXXX";
    int dfd = mkstemp(dtmpl);
    FILE *df = fdopen(dfd, "w");
    fputs("%Y-%m-%d\n", df);
    fclose(df);
    setenv("DATEMSK", dtmpl, 1);
    struct tm gtm; memset(&gtm, 0, sizeof gtm);
    int gr = getdate_r("2026-06-15", &gtm);
    printf("getdate_r rc=%d year=%d mon=%d mday=%d\n",
           gr, gtm.tm_year + 1900, gtm.tm_mon + 1, gtm.tm_mday);
    unlink(dtmpl);

    return 0;
}
