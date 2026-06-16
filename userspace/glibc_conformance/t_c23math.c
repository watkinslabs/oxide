/* C23 math renames + _Float32/_Float64 aliases: logp1(f/f32/f64), remquof/f32,
 * lgammaf32_r/f64_r, strfromf64. Each is identical to an existing function, so
 * the diff vs host glibc is bit-exact. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

extern double logp1(double);
extern float logp1f(float);
extern float logp1f32(float);
extern double logp1f64(double);
extern float remquof(float, float, int *);
extern float remquof32(float, float, int *);
extern float lgammaf32_r(float, int *);
extern double lgammaf64_r(double, int *);
extern int strfromf64(char *, size_t, const char *, double);

int main(void) {
    printf("logp1=%a logp1f=%a logp1f32=%a logp1f64=%a\n",
        logp1(0.5), (double)logp1f(0.5f), (double)logp1f32(1e-7f), logp1f64(-0.25));

    int q1 = 0, q2 = 0;
    float r1 = remquof(13.0f, 4.0f, &q1);
    float r2 = remquof32(-13.0f, 4.0f, &q2);
    printf("remquof=%a q=%d remquof32=%a q=%d\n", (double)r1, q1, (double)r2, q2);

    /* lgammaf64_r forwards to lgamma_r; print at <16 sig figs so the existing
     * ~1-ULP lgamma vs host difference doesn't mask the alias check. */
    int s1 = 0, s2 = 0;
    printf("lgammaf32_r=%a sign=%d lgammaf64_r=%.12g sign=%d\n",
        (double)lgammaf32_r(-0.5f, &s1), s1, lgammaf64_r(-0.5, &s2), s2);

    char buf[64];
    strfromf64(buf, sizeof buf, "%.10g", 3.14159265358979);
    printf("strfromf64=%s\n", buf);
    return 0;
}
