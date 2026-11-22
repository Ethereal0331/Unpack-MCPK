/* The container's own directory/file hashes. These decide which files a
 * .mcp entry refers to, so they must match the original bit for bit; the
 * arithmetic below mirrors the Python expression by expression (multiplications
 * are 64-bit unsigned, then folded into 32 bits). */
#include "mcp.h"

#include <string.h>

#define M1 645597969u
#define M2 3186325470u
#define M3 33818625u
#define M4 2105457630u
#define M5 8405025u
#define H1_INIT 933775118u
#define H2_INIT 2002301995u
#define ROT_INIT 4110059816u

static uint32_t u32(uint64_t v) { return (uint32_t)v; }

static void update(uint32_t *ph1, uint32_t *ph2, uint32_t rot, uint32_t chunk)
{
    uint32_t h1 = *ph1, h2 = *ph2;
    uint32_t x1 = h1 ^ chunk;
    uint32_t x2 = h2 ^ chunk;

    /* Every sum stays in 64 bits: Python has unbounded ints, and `s1 >> 32`
     * is genuinely non-zero sometimes. Truncating early loses the carry. */
    uint64_t k1 = (uint64_t)u32((u32(u32(rot ^ M1) + x2) & M2) | M3);
    uint64_t p1 = (uint64_t)x1 * k1;
    uint64_t hi1 = p1 >> 32;
    uint64_t s1 = hi1 + (hi1 != 0 ? 1u : 0u) + (p1 & 0xFFFFFFFFu);
    uint64_t nh1 = u32(s1 + (s1 >> 32));

    uint64_t k2 = (uint64_t)u32((u32(u32(rot ^ M1) + x1) & M4) | M5);
    uint64_t p2 = (uint64_t)x2 * k2;
    uint64_t hi2 = p2 >> 32;
    uint64_t s2 = (p2 & 0xFFFFFFFFu) + 2u * hi2;
    uint64_t nh2 = u32(s2 + 2u * (s2 >> 32));

    *ph1 = (uint32_t)nh1;
    *ph2 = (uint32_t)nh2;
}

static uint32_t finalize(uint32_t h1, uint32_t h2, uint32_t rot)
{
    uint32_t f2 = h2 ^ 2615624776u;
    uint32_t f1 = h1 ^ 2615624776u;

    uint32_t rot_f1 = u32((u32(rot << 1) | (rot >> 31)));
    uint32_t k1 = u32(rot_f1 ^ M1);
    uint64_t t1 = (uint64_t)u32((u32(u32(k1 + f2) & M2)) | M3);
    uint64_t p1 = (uint64_t)f1 * t1;
    uint64_t hi1 = p1 >> 32;
    uint64_t s1 = hi1 + (hi1 != 0 ? 1u : 0u) + (p1 & 0xFFFFFFFFu);
    uint32_t y1 = u32((s1 + (s1 >> 32)) ^ 1727278152u);

    uint64_t t2 = (uint64_t)u32((u32(u32(k1 + f1) & M4)) | M5);
    uint64_t p2 = (uint64_t)f2 * t2;
    uint64_t hi2 = p2 >> 32;
    uint64_t s2 = (p2 & 0xFFFFFFFFu) + 2u * hi2;
    uint32_t y2 = u32((s2 + 2u * (s2 >> 32)) ^ 1727278152u);

    uint32_t rot_f2 = u32(u32(rot << 2) | (rot >> 30));
    uint32_t k2 = u32(rot_f2 ^ M1);

    uint64_t t3 = (uint64_t)u32((u32(u32(k2 + y2) & M2)) | M3);
    uint64_t p3 = (uint64_t)y1 * t3;
    uint64_t hi3 = p3 >> 32;
    uint64_t s3 = hi3 + (hi3 != 0 ? 1u : 0u) + (p3 & 0xFFFFFFFFu);
    uint32_t part1 = u32(s3 + (s3 >> 32));

    uint64_t t4 = (uint64_t)u32((u32(u32(k2 + y1) & M4)) | M5);
    uint64_t p4 = (uint64_t)y2 * t4;
    uint64_t s4 = (p4 & 0xFFFFFFFFu) + 2u * (p4 >> 32) + (p4 >> 63);
    uint32_t part2 = u32(s4 + 2u * (s4 >> 32));

    return u32(part1 ^ part2);
}

uint32_t mcpk_hash_name(const char *s)
{
    const uint8_t *d = (const uint8_t *)s;
    size_t len = strlen(s);
    uint32_t h1 = H1_INIT, h2 = H2_INIT, rot = ROT_INIT;
    size_t idx = 0;

    if (idx >= len || d[idx] == 0)
        return finalize(h1, h2, rot);

    while (idx < len) {
        rot = u32((u32(rot << 1) | (rot >> 31)));
        uint32_t chunk = 0;
        int complete = 1;
        for (int j = 0; j < 4; j++) {
            if (idx < len && d[idx] != 0) {
                chunk |= (uint32_t)d[idx] << (j * 8);
                idx++;
            } else {
                complete = 0;
                break;
            }
        }
        update(&h1, &h2, rot, chunk);
        if (!complete)
            return finalize(h1, h2, rot);
    }
    return finalize(h1, h2, rot);
}

/* Directory hash: the containing path (everything before the last '/'), run
 * through the same mixer. Short trailing chunks are zero-padded rather than
 * treated as terminators, which is how it differs from the file hash. */
uint32_t mcpk_hash_dir(const char *s)
{
    const uint8_t *d = (const uint8_t *)s;
    size_t len = strlen(s);
    size_t last = (size_t)-1;
    for (size_t i = len; i > 0; i--) {
        if (d[i - 1] == '/') {
            last = i - 1;
            break;
        }
    }
    if (last == (size_t)-1 || last == 0)
        return 0;
    len = last;

    uint32_t h1 = H1_INIT, h2 = H2_INIT, rot = ROT_INIT;
    size_t i = 0;
    while (i + 4 <= len) {
        rot = u32(u32(rot << 1) | (rot >> 31));
        uint32_t chunk = (uint32_t)d[i] | ((uint32_t)d[i + 1] << 8)
                       | ((uint32_t)d[i + 2] << 16) | ((uint32_t)d[i + 3] << 24);
        update(&h1, &h2, rot, chunk);
        i += 4;
    }
    if (i < len) {
        rot = u32(u32(rot << 1) | (rot >> 31));
        uint32_t chunk = 0;
        for (size_t j = 0; j < len - i; j++)
            chunk |= (uint32_t)d[i + j] << (j * 8);
        update(&h1, &h2, rot, chunk);
    }
    return finalize(h1, h2, rot);
}
