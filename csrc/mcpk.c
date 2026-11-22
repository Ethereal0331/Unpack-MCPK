/* MCPK container: a 57-byte header, a directory table, a per-directory index
 * of (file hash, offset, compressed size, size), then the payload.
 *
 * Two flavours exist. A script pack keeps a redirect.mcs at the root and is
 * self-describing: each entry's own MCS header names its source file, so no
 * listing is needed. A resource pack lists its paths in contents.json. Both
 * are handled; entries that are not zlib and not MCS are stored verbatim. */
#include "mcp.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t d_hash, index_off, count;
    uint32_t *f_hash, *f_off, *c_size, *u_size;
    size_t nfiles, cap;
} dir_t;

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void push_file(mcpk_t *m, const char *rel, const uint8_t *p, size_t n)
{
    m->files = xrealloc(m->files, (m->count + 1) * sizeof(mcpk_file_t));
    m->files[m->count].rel_path = xstrdup(rel);
    m->files[m->count].data = xmalloc(n ? n : 1);
    if (n)
        memcpy(m->files[m->count].data, p, n);
    m->files[m->count].len = n;
    m->count++;
}

void mcpk_free(mcpk_t *m)
{
    for (size_t i = 0; i < m->count; i++) {
        free(m->files[i].rel_path);
        free(m->files[i].data);
    }
    free(m->files);
    m->files = NULL;
    m->count = 0;
}

/* Pull the .py name out of an MCS payload's code object; empty when the entry
 * is not an MCS at all. */
static void mcs_filename(const uint8_t *p, size_t n, char *out, size_t outsz)
{
    out[0] = '\0';
    buf_t plain;
    if (crypto_decrypt(p, n, &plain) != 1 && plain.len == 0) {
        buf_free(&plain);
        return;
    }
    if (plain.len && plain.data[0] != 'o' && plain.data[0] != 'c'
        && plain.data[0] != 'M' && plain.data[0] != 'a') {
        buf_free(&plain);
        return;
    }
    mv_t *root = mcs_parse(plain.data, plain.len);
    buf_free(&plain);
    if (!root)
        return;
    if (root->type == MV_CODE && root->u.code.filename
        && (root->u.code.filename->type == MV_TEXT
            || root->u.code.filename->type == MV_BYTES)) {
        size_t k = root->u.code.filename->u.bytes.n;
        /* the field is a length-prefixed byte string, not a C string: stop at
         * the first NUL and never copy the length prefix itself */
        const uint8_t *src = root->u.code.filename->u.bytes.p;
        size_t m = 0;
        while (m < k && src[m] != 0)
            m++;
        if (m >= outsz)
            m = outsz - 1;
        memcpy(out, src, m);
        out[m] = '\0';
    }
    mv_free(root);
}

static void store_entry(mcpk_t *m, const char *rel, const uint8_t *p, size_t n)
{
    /* zlib payload -> plain bytes under the given name */
    if (n >= 2 && p[0] == 0x78 && (p[1] == 0x9C || p[1] == 0xDA || p[1] == 0x01)) {
        buf_t out;
        if (zlib_inflate_raw(p, n, &out) == 0) {
            push_file(m, rel, out.data, out.len);
            buf_free(&out);
            return;
        }
        buf_free(&out);
    }
    push_file(m, rel, p, n);
}

int mcpk_unpack(const char *path, mcpk_t *out)
{
    buf_t f;
    if (read_file(path, &f) != 0)
        return -1;
    if (f.len < 57 || memcmp(f.data, "MCPK", 4) != 0) {
        buf_free(&f);
        return -1;
    }

    uint32_t dir_table_off = rd32(f.data + 12);
    uint32_t index_base = rd32(f.data + 16);
    if (dir_table_off + 12 > f.len || index_base > f.len) {
        buf_free(&f);
        return -1;
    }

    size_t dir_count = (index_base - dir_table_off) / 12;
    dir_t *dirs = xmalloc(dir_count * sizeof(dir_t));
    memset(dirs, 0, dir_count * sizeof(dir_t));

    uint32_t max_rel = 0, last_files = 0;
    for (size_t i = 0; i < dir_count; i++) {
        const uint8_t *e = f.data + dir_table_off + i * 12;
        dirs[i].d_hash = rd32(e);
        dirs[i].index_off = rd32(e + 4);
        dirs[i].count = rd32(e + 8);
        if (dirs[i].index_off >= max_rel) {
            max_rel = dirs[i].index_off;
            last_files = dirs[i].count;
        }
    }
    uint32_t data_base = index_base + max_rel + last_files * 16;

    for (size_t i = 0; i < dir_count; i++) {
        dir_t *d = &dirs[i];
        size_t at = (size_t)index_base + d->index_off;
        if (at + (size_t)d->count * 16 > f.len)
            continue;
        d->f_hash = xmalloc(d->count * sizeof(uint32_t));
        d->f_off = xmalloc(d->count * sizeof(uint32_t));
        d->c_size = xmalloc(d->count * sizeof(uint32_t));
        d->u_size = xmalloc(d->count * sizeof(uint32_t));
        d->nfiles = d->cap = d->count;
        for (uint32_t k = 0; k < d->count; k++) {
            const uint8_t *e = f.data + at + (size_t)k * 16;
            d->f_hash[k] = rd32(e);
            d->f_off[k] = rd32(e + 4);
            d->c_size[k] = rd32(e + 8);
            d->u_size[k] = rd32(e + 12);
        }
    }

    /* Script pack: the name comes from each MCS payload's own filename field. */
    for (size_t i = 0; i < dir_count; i++) {
        dir_t *d = &dirs[i];
        for (size_t k = 0; k < d->nfiles; k++) {
            size_t at = (size_t)data_base + d->f_off[k];
            if (at + d->c_size[k] > f.len)
                continue;
            const uint8_t *p = f.data + at;
            size_t n = d->c_size[k];

            char name[512];
            mcs_filename(p, n, name, sizeof name);
            if (name[0]) {
                /* ".py" -> ".mcs" makes the name one byte longer, so it needs
                 * a fresh buffer rather than an in-place overwrite. */
                size_t rl = strlen(name);
                char *rel = xmalloc(rl + 3);
                memcpy(rel, name, rl + 1);
                if (rl > 3 && strcmp(rel + rl - 3, ".py") == 0) {
                    /* ".mcs" is one byte longer than ".py": the terminator
                     * moves with it. */
                    memcpy(rel + rl - 3, ".mcs", 4);
                    rel[rl + 1] = '\0';
                }
                store_entry(out, rel, p, n);
                free(rel);
                continue;
            }
            /* not an MCS: keep it under <dhash>/<fhash> like the original */
            char rel[64];
            snprintf(rel, sizeof rel, "%08X/%08X", d->d_hash, d->f_hash[k]);
            store_entry(out, rel, p, n);
        }
    }

    for (size_t i = 0; i < dir_count; i++) {
        free(dirs[i].f_hash); free(dirs[i].f_off);
        free(dirs[i].c_size); free(dirs[i].u_size);
    }
    free(dirs);
    buf_free(&f);
    return 0;
}
