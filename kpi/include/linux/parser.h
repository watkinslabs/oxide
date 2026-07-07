#ifndef OXIDE_LINUX_PARSER_H
#define OXIDE_LINUX_PARSER_H

#include <linux/types.h>

typedef struct {
    const char *from;
    const char *to;
} substring_t;

struct match_token {
    int token;
    const char *pattern;
};

typedef const struct match_token match_table_t[];

int match_token(const char *s, match_table_t table, substring_t args[]);
char *match_strdup(const substring_t *s);
int match_int(substring_t *s, int *result);
int match_u64(substring_t *s, u64 *result);

#endif
