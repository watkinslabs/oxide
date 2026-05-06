// Drepper-2007 sha512crypt (glibc-parity). Header-only C reference
// shared between /bin/login and /bin/su. Bit-identical output to
// the Rust crypt::sha512::sha512crypt path.
//
// Usage:
//   char hash[128];
//   long n = sha512crypt(password, salt, 5000, hash);  // hash[0..n] = digest
//
// All buffers are caller-owned. Streaming SHA-512 is required
// because DS = SHA512(salt × (16 + A[0])) can grow past 4 KB.

#ifndef OXIDE_SHA512CRYPT_H
#define OXIDE_SHA512CRYPT_H

#include <stdint.h>

static const uint64_t SC_K[80] = {
  0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
  0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
  0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
  0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL };

typedef struct {
    uint64_t h[8];
    uint8_t  buf[128];
    int      buf_len;
    uint64_t total;
} sc_sha512_t;

static inline uint64_t sc_rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sc_compress(sc_sha512_t* s) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | s->buf[i*8 + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = sc_rotr(w[i-15],1)^sc_rotr(w[i-15],8)^(w[i-15]>>7);
        uint64_t s1 = sc_rotr(w[i-2],19)^sc_rotr(w[i-2],61)^(w[i-2]>>6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint64_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = sc_rotr(e,14)^sc_rotr(e,18)^sc_rotr(e,41);
        uint64_t ch = (e&f)^(~e&g);
        uint64_t t1 = h + S1 + ch + SC_K[i] + w[i];
        uint64_t S0 = sc_rotr(a,28)^sc_rotr(a,34)^sc_rotr(a,39);
        uint64_t mj = (a&b)^(a&c)^(b&c);
        uint64_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sc_init(sc_sha512_t* s) {
    s->h[0]=0x6a09e667f3bcc908ULL; s->h[1]=0xbb67ae8584caa73bULL;
    s->h[2]=0x3c6ef372fe94f82bULL; s->h[3]=0xa54ff53a5f1d36f1ULL;
    s->h[4]=0x510e527fade682d1ULL; s->h[5]=0x9b05688c2b3e6c1fULL;
    s->h[6]=0x1f83d9abfb41bd6bULL; s->h[7]=0x5be0cd19137e2179ULL;
    s->buf_len = 0; s->total = 0;
}

static void sc_update(sc_sha512_t* s, const uint8_t* data, long len) {
    s->total += (uint64_t)len;
    long i = 0;
    while (i < len) {
        long take = 128 - s->buf_len;
        long rem  = len - i;
        if (take > rem) take = rem;
        for (long k = 0; k < take; k++) s->buf[s->buf_len + k] = data[i + k];
        s->buf_len += (int)take;
        i += take;
        if (s->buf_len == 128) { sc_compress(s); s->buf_len = 0; }
    }
}

static void sc_final(sc_sha512_t* s, uint8_t out[64]) {
    uint64_t bl = s->total * 8;
    s->buf[s->buf_len++] = 0x80;
    if (s->buf_len > 112) {
        while (s->buf_len < 128) s->buf[s->buf_len++] = 0;
        sc_compress(s); s->buf_len = 0;
    }
    while (s->buf_len < 112) s->buf[s->buf_len++] = 0;
    // upper 8 bytes of length = 0; lower 8 bytes = bl
    for (int i = 0; i < 8; i++) s->buf[112 + i] = 0;
    for (int i = 0; i < 8; i++) s->buf[120 + i] = (uint8_t)(bl >> (56 - 8*i));
    s->buf_len = 128;
    sc_compress(s);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            out[i*8 + j] = (uint8_t)(s->h[i] >> (56 - 8*j));
}

static const char SC_ALPH[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Permutation triples for sha512 variant of crypt-base64.
static const uint8_t SC_TRIPLES[21][3] = {
    {0,21,42},{22,43,1},{44,2,23},{3,24,45},{25,46,4},
    {47,5,26},{6,27,48},{28,49,7},{50,8,29},{9,30,51},
    {31,52,10},{53,11,32},{12,33,54},{34,55,13},{56,14,35},
    {15,36,57},{37,58,16},{59,17,38},{18,39,60},{40,61,19},
    {62,20,41} };

static long sc_b64_encode(const uint8_t c[64], char* out) {
    long o = 0;
    for (int t = 0; t < 21; t++) {
        uint32_t v = ((uint32_t)c[SC_TRIPLES[t][0]] << 16)
                   | ((uint32_t)c[SC_TRIPLES[t][1]] << 8)
                   |  (uint32_t)c[SC_TRIPLES[t][2]];
        for (int k = 0; k < 4; k++) { out[o++] = SC_ALPH[v & 63]; v >>= 6; }
    }
    uint32_t v = c[63];
    out[o++] = SC_ALPH[v & 63]; v >>= 6;
    out[o++] = SC_ALPH[v & 63];
    return o;
}

// Drepper sha512crypt. Returns chars written (always 86).
// `password` and `salt` are NUL-terminated strings.
static long sha512crypt(const char* password, const char* salt, uint32_t rounds, char* out) {
    if (rounds < 1000) rounds = 1000;
    if (rounds > 999999999u) rounds = 999999999u;
    long pl = 0; while (password[pl]) pl++;
    long sl = 0; while (salt[sl]) sl++;

    // B = SHA512(pw | s | pw)
    sc_sha512_t hb; sc_init(&hb);
    sc_update(&hb, (const uint8_t*)password, pl);
    sc_update(&hb, (const uint8_t*)salt,     sl);
    sc_update(&hb, (const uint8_t*)password, pl);
    uint8_t b[64]; sc_final(&hb, b);

    // A_input.
    sc_sha512_t ha; sc_init(&ha);
    sc_update(&ha, (const uint8_t*)password, pl);
    sc_update(&ha, (const uint8_t*)salt,     sl);
    long k = pl;
    while (k >= 64) { sc_update(&ha, b, 64); k -= 64; }
    if (k > 0) sc_update(&ha, b, k);
    long bits = pl;
    while (bits > 0) {
        if (bits & 1) sc_update(&ha, b, 64);
        else          sc_update(&ha, (const uint8_t*)password, pl);
        bits >>= 1;
    }
    uint8_t a[64]; sc_final(&ha, a);

    // DP -> P (first pl bytes).
    sc_sha512_t hp; sc_init(&hp);
    for (long i = 0; i < pl; i++) sc_update(&hp, (const uint8_t*)password, pl);
    uint8_t dp[64]; sc_final(&hp, dp);
    uint8_t p_buf[256];
    if (pl > (long)sizeof(p_buf)) return 0;
    long pidx = 0;
    while (pidx + 64 <= pl) { for (int i = 0; i < 64; i++) p_buf[pidx + i] = dp[i]; pidx += 64; }
    for (long i = 0; i < pl - pidx; i++) p_buf[pidx + i] = dp[i];

    // DS -> S (first sl bytes).
    sc_sha512_t hs; sc_init(&hs);
    long reps = 16 + a[0];
    for (long i = 0; i < reps; i++) sc_update(&hs, (const uint8_t*)salt, sl);
    uint8_t ds[64]; sc_final(&hs, ds);
    uint8_t s_buf[64];
    if (sl > (long)sizeof(s_buf)) return 0;
    for (long i = 0; i < sl; i++) s_buf[i] = ds[i % 64];

    // Main loop.
    uint8_t c[64]; for (int i = 0; i < 64; i++) c[i] = a[i];
    for (uint32_t i = 0; i < rounds; i++) {
        sc_sha512_t hc; sc_init(&hc);
        if (i & 1) sc_update(&hc, p_buf, pl); else sc_update(&hc, c, 64);
        if (i % 3) sc_update(&hc, s_buf, sl);
        if (i % 7) sc_update(&hc, p_buf, pl);
        if (i & 1) sc_update(&hc, c, 64); else sc_update(&hc, p_buf, pl);
        sc_final(&hc, c);
    }

    return sc_b64_encode(c, out);
}

#endif // OXIDE_SHA512CRYPT_H
