#ifndef OXIDE_LINUX_STRING_H
#define OXIDE_LINUX_STRING_H

#include <linux/stddef.h>
#include <linux/types.h>

extern const unsigned char _ctype[];

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *memcpy_and_pad(void *dst, size_t dst_len, const void *src, size_t count, int pad);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t max);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
int strncasecmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
char *strsep(char **s, const char *delim);
char *strim(char *s);
ssize_t sized_strscpy(char *dst, const char *src, size_t count);
int hex_to_bin(int ch);
int hex2bin(unsigned char *dst, const char *src, size_t count);
char *bin2hex(char *dst, const void *src, size_t count);
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base);
int kstrtobool(const char *s, bool *res);
int kstrtoint(const char *s, unsigned int base, int *res);
int kstrtou8(const char *s, unsigned int base, u8 *res);
int kstrtou16(const char *s, unsigned int base, u16 *res);
int kstrtouint(const char *s, unsigned int base, unsigned int *res);
int kstrtoull(const char *s, unsigned int base, unsigned long long *res);

#endif
