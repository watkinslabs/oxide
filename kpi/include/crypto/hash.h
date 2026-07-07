#ifndef OXIDE_CRYPTO_HASH_H
#define OXIDE_CRYPTO_HASH_H

#include <linux/types.h>
#include <linux/stddef.h>

#define CRYPTO_ALG_TYPE_SHASH 0x0000000e

struct crypto_shash;
struct shash_desc {
    struct crypto_shash *tfm;
    u32 flags;
};

struct crypto_shash *crypto_alloc_shash(const char *alg_name, u32 type, u32 mask);
void crypto_free_shash(struct crypto_shash *tfm);
unsigned int crypto_shash_digestsize(struct crypto_shash *tfm);
unsigned int crypto_shash_descsize(struct crypto_shash *tfm);
int crypto_shash_init(struct shash_desc *desc);
int crypto_shash_update(struct shash_desc *desc, const u8 *data, unsigned int len);
int crypto_shash_final(struct shash_desc *desc, u8 *out);
int crypto_shash_digest(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out);

#endif
