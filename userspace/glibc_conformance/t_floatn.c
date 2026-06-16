/* _FloatN math aliases: *f32 == float fn, *f64 == double fn (same format,
 * distinct C23 type). Header declares them under _GNU_SOURCE. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
int main(void) {
    printf("sinf32=%d sqrtf32=%d expf32=%d cosf32=%d\n",
           sinf32(1.0f) == sinf(1.0f), sqrtf32(2.0f) == sqrtf(2.0f),
           expf32(1.0f) == expf(1.0f), cosf32(0.5f) == cosf(0.5f));
    printf("sinf64=%d sqrtf64=%d powf64=%d logf64=%d\n",
           sinf64(1.0) == sin(1.0), sqrtf64(2.0) == sqrt(2.0),
           powf64(2.0, 10.0) == pow(2.0, 10.0), logf64(3.0) == log(3.0));
    return 0;
}
