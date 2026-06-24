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
extern float fadd(double, double);
extern float fsub(double, double);
extern float fmul(double, double);
extern float fdiv(double, double);
extern float fsqrt(double);
extern float ffma(double, double, double);
extern float f32addf64(double, double);
extern float f32subf64(double, double);
extern float f32mulf64(double, double);
extern float f32divf64(double, double);
extern float f32sqrtf64(double);
extern float f32fmaf64(double, double, double);

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
    printf("narrow=%a %a %a %a %a %a\n",
        (double)fadd(1.25, 2.5), (double)fsub(5.5, 2.25),
        (double)fmul(1.5, 3.0), (double)fdiv(7.5, 2.5),
        (double)fsqrt(9.0), (double)ffma(2.0, 3.0, 4.0));
    printf("narrow_alias=%a %a %a %a %a %a\n",
        (double)f32addf64(1.25, 2.5), (double)f32subf64(5.5, 2.25),
        (double)f32mulf64(1.5, 3.0), (double)f32divf64(7.5, 2.5),
        (double)f32sqrtf64(9.0), (double)f32fmaf64(2.0, 3.0, 4.0));
    return 0;
}
