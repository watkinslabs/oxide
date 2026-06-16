/* C23 <stdbit.h> bit utilities. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbit.h>
int main(void) {
    printf("lz=%u %u tz=%u\n", stdc_leading_zeros_ui(1), stdc_leading_zeros_uc(1), stdc_trailing_zeros_ui(8));
    printf("lo=%u to=%u\n", stdc_leading_ones_ui(0xFF000000u), stdc_trailing_ones_us(0x000Fu));
    printf("flz=%u flo=%u ftz=%u fto=%u\n",
           stdc_first_leading_zero_ui(0xFFFFFFFFu), stdc_first_leading_one_ui(1),
           stdc_first_trailing_zero_ui(0u), stdc_first_trailing_one_ui(8));
    printf("co=%u cz=%u\n", stdc_count_ones_ui(0xFFu), stdc_count_zeros_uc(0xF0));
    printf("hsb=%d %d w=%u\n", stdc_has_single_bit_ui(64), stdc_has_single_bit_ui(65), stdc_bit_width_ui(255));
    printf("floor=%u ceil=%u\n", stdc_bit_floor_ui(100), stdc_bit_ceil_ui(100));
    printf("us=%u uc=%u\n", stdc_bit_ceil_us(300), stdc_bit_floor_uc(100));
    return 0;
}
