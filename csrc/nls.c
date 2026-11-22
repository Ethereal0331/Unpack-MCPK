/* The NLS cipher: a per-byte substitution driven by a 6-round key schedule.
 *
 * The key schedule uses a Wichmann-Hill PRNG seeded from six bytes. That PRNG
 * is defined in terms of double arithmetic, and the Python original leans on
 * Python's `int(x / y)` (truncate toward zero) and on the exact result of
 * `(a + b + c) - int(a + b + c)`. Both are reproduced literally below; using
 * integer arithmetic here would silently produce a different keystream.
 */
#include "mcp.h"

#include <math.h>
#include <string.h>

static const uint8_t DEFAULT_SEED[6] = { 0x98, 0x84, 0x5D, 0x9A, 0x9E, 0x8B };

/* signed 32-bit wraparound, matching Python's _int32() */
static int32_t i32(int64_t v)
{
    return (int32_t)(uint32_t)(uint64_t)v;
}

typedef struct {
    int32_t s1, s2, s3;
    uint8_t mask[6];
    uint8_t step[6];
    uint8_t sbox[6 * 256];
    uint8_t rsbox[6 * 256];
} nls_t;

/* Python: int(a / b) truncates toward zero. */
static int32_t py_idiv(int32_t a, int32_t b)
{
    return (int32_t)((double)a / (double)b);
}

static int nls_prng_step(nls_t *c, int limit)
{
    int32_t v5 = i32((int64_t)171 * c->s1 - (int64_t)30269 * py_idiv(c->s1, 177));
    c->s1 = v5 >= 0 ? v5 : (int32_t)(v5 + 30269);

    int32_t v7 = i32((int64_t)172 * c->s2 - (int64_t)30307 * py_idiv(c->s2, 176));
    c->s2 = v7 >= 0 ? v7 : (int32_t)(v7 + 30307);

    int32_t v8 = i32((int64_t)170 * c->s3 - (int64_t)30323 * py_idiv(c->s3, 178));
    c->s3 = v8 >= 0 ? v8 : (int32_t)(v8 + 30323);

    double t1 = (double)c->s1 / 30269.0;
    double t2 = (double)c->s2 / 30307.0;
    double t3 = (double)c->s3 / 30323.0;
    double sum = (t1 + t2) + t3;
    double fraction = sum - (double)(int64_t)sum;   /* int() truncates toward 0 */

    return (int)(fraction * (double)limit);
}

static void nls_generate_keys(nls_t *c)
{
    for (int r = 0; r < 6; r++) {
        c->mask[r] = (uint8_t)(nls_prng_step(c, 256) & 0xFF);

        int s = nls_prng_step(c, 128);
        c->step[r] = (uint8_t)((s * 2 + 1) & 0xFF);

        uint8_t perm[256];
        for (int i = 0; i < 256; i++)
            perm[i] = (uint8_t)i;

        uint8_t *sbox = c->sbox + r * 256;
        uint8_t *rsbox = c->rsbox + r * 256;

        int n = 256;
        while (n >= 2) {
            int idx = nls_prng_step(c, n);
            uint8_t sel = perm[idx];
            uint8_t last = perm[n - 1];
            perm[idx] = last;
            perm[n - 1] = sel;
            sbox[sel] = (uint8_t)(n - 1);
            rsbox[n - 1] = sel;
            n--;
        }
        sbox[perm[0]] = 0;
        rsbox[0] = perm[0];
    }
}

void nls_dump(void);
static void nls_init(nls_t *c, const uint8_t seed[6])
{
    memcpy(c->mask, seed, 6);
    /* little-endian int16 triple */
    c->s1 = (int16_t)(uint16_t)(seed[0] | (seed[1] << 8));
    c->s2 = (int16_t)(uint16_t)(seed[2] | (seed[3] << 8));
    c->s3 = (int16_t)(uint16_t)(seed[4] | (seed[5] << 8));
    nls_generate_keys(c);
}

/* Decryption runs the six boxes in reverse with the sbox (not rsbox):
 *   val = sb[1280 + val] ^ m5 ... val = sb[val] ^ m0
 * i.e. look up first, then xor -- the mirror of encrypt. */
static void nls_apply(nls_t *c, uint8_t *data, size_t len)
{
    const uint8_t *sb = c->sbox;
    int m0 = c->mask[0], m1 = c->mask[1], m2 = c->mask[2];
    int m3 = c->mask[3], m4 = c->mask[4], m5 = c->mask[5];
    int t0 = c->step[0], t1 = c->step[1], t2 = c->step[2];
    int t3 = c->step[3], t4 = c->step[4], t5 = c->step[5];

    for (size_t k = 0; k < len; k++) {
        unsigned v = data[k];
        v = sb[1280 + v] ^ m5;
        v = sb[1024 + (v & 255)] ^ m4;
        v = sb[768 + (v & 255)] ^ m3;
        v = sb[512 + (v & 255)] ^ m2;
        v = sb[256 + (v & 255)] ^ m1;
        v = sb[v & 255] ^ m0;
        data[k] = (uint8_t)v;

        int s;
        s = m0 + t0; m0 = s & 255;
        if (s >= 256) m1 = (m1 + 1) & 255;
        s = m1 + t1; m1 = s & 255;
        if (s >= 256) m2 = (m2 + 1) & 255;
        s = m2 + t2; m2 = s & 255;
        if (s >= 256) m3 = (m3 + 1) & 255;
        s = m3 + t3; m3 = s & 255;
        if (s >= 256) m4 = (m4 + 1) & 255;
        s = m4 + t4; m4 = s & 255;
        if (s >= 256) m5 = (m5 + 1) & 255;
        s = m5 + t5; m5 = s & 255;
    }
}

void nls_decrypt(uint8_t *data, size_t len)
{
    nls_t c;
    nls_init(&c, DEFAULT_SEED);
    nls_apply(&c, data, len);
}

/* test hook */
void nls_dump(void)
{
    nls_t c;
    nls_init(&c, DEFAULT_SEED);
    printf("mask:");
    for (int i = 0; i < 6; i++) printf(" %d", c.mask[i]);
    printf("\nstep:");
    for (int i = 0; i < 6; i++) printf(" %d", c.step[i]);
    printf("\nrsbox[0:16]:");
    for (int i = 0; i < 16; i++) printf(" %d", c.rsbox[i]);
    printf("\nrsbox[256:272]:");
    for (int i = 256; i < 272; i++) printf(" %d", c.rsbox[i]);
    printf("\n");
}
