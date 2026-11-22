/* Outer layer of an .mcs: either a zlib blob with an MCPK-xored 4-byte magic
 * (redirect.mcs), or NLS-encrypted zlib with the payload reversed and its
 * first 130 bytes xored (everything else). */
#include "mcp.h"

#include <string.h>
#include <zlib.h>

void nls_decrypt(uint8_t *data, size_t len);

static void xor_head(uint8_t *p, size_t n, uint8_t key, size_t limit)
{
    if (n < limit)
        limit = n;
    for (size_t i = 0; i < limit; i++)
        p[i] ^= key;
}

int zlib_inflate_raw(const uint8_t *in, size_t n, buf_t *out)
{
    z_stream z;
    memset(&z, 0, sizeof z);
    if (inflateInit(&z) != Z_OK)
        return -1;
    z.next_in = (Bytef *)in;
    z.avail_in = (uInt)n;
    buf_init(out);
    uint8_t chunk[65536];
    int rc;
    do {
        z.next_out = chunk;
        z.avail_out = sizeof chunk;
        rc = inflate(&z, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&z);
            buf_free(out);
            return -1;
        }
        buf_append(out, chunk, sizeof chunk - z.avail_out);
    } while (rc != Z_STREAM_END);
    inflateEnd(&z);
    return 0;
}

/* Returns 1 when the payload looked encrypted and was decoded, 0 when it was
 * passed through untouched, -1 on error. */
int crypto_decrypt(const uint8_t *in, size_t n, buf_t *out)
{
    buf_init(out);
    if (n == 0) {
        buf_append(out, in, n);
        return 0;
    }

    int is_redirect = (in[0] == 0x35);
    int is_nls = (n >= 2 && in[0] == 0xE5 && in[1] == 0x1F);
    if (!is_redirect && !is_nls) {
        buf_append(out, in, n);
        return 0;                       /* already plain */
    }

    buf_t zc;
    buf_init(&zc);
    if (is_redirect) {
        static const uint8_t magic[4] = { 'M', 'C', 'P', 'K' };
        uint8_t head[4];
        size_t hn = n < 4 ? n : 4;
        for (size_t i = 0; i < hn; i++)
            head[i] = in[i] ^ magic[i];
        buf_append(&zc, head, hn);
        buf_append(&zc, in + hn, n - hn);
    } else {
        buf_append(&zc, in, n);
        nls_decrypt(zc.data, zc.len);
    }

    if (zc.len <= 2 || zc.data[0] != 0x78
        || (zc.data[1] != 0x01 && zc.data[1] != 0x9C && zc.data[1] != 0xDA)) {
        /* not zlib after decryption: hand back the raw bytes */
        buf_append(out, zc.data, zc.len);
        buf_free(&zc);
        return 0;
    }

    buf_t plain;
    if (zlib_inflate_raw(zc.data, zc.len, &plain) != 0) {
        buf_append(out, zc.data, zc.len);
        buf_free(&zc);
        return 0;
    }
    buf_free(&zc);

    if (is_nls) {
        xor_head(plain.data, plain.len, 0x9C, 130);
        /* the payload was reversed before encryption */
        for (size_t i = 0, j = plain.len ? plain.len - 1 : 0; i < j; i++, j--) {
            uint8_t t = plain.data[i];
            plain.data[i] = plain.data[j];
            plain.data[j] = t;
        }
    }
    buf_append(out, plain.data, plain.len);
    buf_free(&plain);
    return 1;
}
