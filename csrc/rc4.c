#include "mcp.h"

#include <string.h>

void rc4_init(rc4_t *c, const uint8_t *key, size_t klen)
{
    for (int i = 0; i < 256; i++)
        c->s[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + c->s[i] + key[i % (int)klen]) & 255;
        uint8_t t = c->s[i];
        c->s[i] = c->s[j];
        c->s[j] = t;
    }
    c->i = c->j = 0;
}

void rc4_crypt(rc4_t *c, uint8_t *data, size_t len)
{
    for (size_t k = 0; k < len; k++) {
        c->i = (c->i + 1) & 255;
        c->j = (c->j + c->s[c->i]) & 255;
        uint8_t t = c->s[c->i];
        c->s[c->i] = c->s[c->j];
        c->s[c->j] = t;
        data[k] ^= c->s[(c->s[c->i] + c->s[c->j]) & 255];
    }
}
