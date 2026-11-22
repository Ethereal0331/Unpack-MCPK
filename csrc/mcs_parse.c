/* Parser for the MCS payload: a marshal-like stream whose tags are mostly the
 * same as CPython's, with a few extra ones for RC4- and xor-encrypted strings
 * and for the reordered code-object layouts of MCS v2-v4. */
#include "mcp.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *d;
    size_t n, pos;
    mv_t **refs;
    size_t nrefs, caprefs;
} rd_t;

static mv_t *r_object(rd_t *r);
static mv_t *r_code_object(rd_t *r, int tag);

static mv_t *mv_new(mv_type t)
{
    mv_t *v = xmalloc(sizeof *v);
    memset(v, 0, sizeof *v);
    v->type = t;
    v->refs = 1;
    return v;
}

static void mv_release(mv_t *v);

void mv_free(mv_t *v)
{
    if (!v)
        return;
    if (--v->refs > 0)
        return;
    mv_release(v);
}

static void mv_release(mv_t *v)
{
    switch (v->type) {
    case MV_BYTES:
    case MV_TEXT:
        free(v->u.bytes.p);
        break;
    case MV_TUPLE:
    case MV_LIST:
    case MV_SET:
        for (size_t i = 0; i < v->u.seq.n; i++)
            mv_free(v->u.seq.items[i]);
        free(v->u.seq.items);
        break;
    case MV_DICT:
        for (size_t i = 0; i < v->u.dict.n; i++) {
            mv_free(v->u.dict.k[i]);
            mv_free(v->u.dict.v[i]);
        }
        free(v->u.dict.k);
        free(v->u.dict.v);
        break;
    case MV_CODE:
        mv_free(v->u.code.code);
        mv_free(v->u.code.consts);
        mv_free(v->u.code.names);
        mv_free(v->u.code.varnames);
        mv_free(v->u.code.freevars);
        mv_free(v->u.code.cellvars);
        mv_free(v->u.code.filename);
        mv_free(v->u.code.name);
        mv_free(v->u.code.lnotab);
        break;
    default:
        break;
    }
    free(v);
}

static int r_byte(rd_t *r)
{
    if (r->pos >= r->n)
        return 0;
    return r->d[r->pos++];
}

static int32_t r_int(rd_t *r)
{
    if (r->pos + 4 > r->n) {
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) {
            if (r->pos < r->n)
                v |= (uint32_t)r->d[r->pos++] << (i * 8);
            else
                v |= (uint32_t)255 << (i * 8);
        }
        return (int32_t)v;
    }
    uint32_t v = (uint32_t)r->d[r->pos]
               | ((uint32_t)r->d[r->pos + 1] << 8)
               | ((uint32_t)r->d[r->pos + 2] << 16)
               | ((uint32_t)r->d[r->pos + 3] << 24);
    r->pos += 4;
    return (int32_t)v;
}

static uint16_t r_short(rd_t *r)
{
    if (r->pos + 2 > r->n)
        return 0;
    uint16_t v = (uint16_t)(r->d[r->pos] | (r->d[r->pos + 1] << 8));
    r->pos += 2;
    return v;
}

static int64_t r_long(rd_t *r)
{
    int32_t size = r_int(r);
    if (size == 0)
        return 0;
    int64_t n = size < 0 ? -(int64_t)size : size;
    int64_t res = 0;
    for (int64_t i = 0; i < n; i++) {
        uint16_t digit = r_short(r);
        res |= (int64_t)(digit & 32767) << (i * 15);
    }
    return size > 0 ? res : -res;
}

static void r_bytes(rd_t *r, const uint8_t **p, size_t *len, int32_t size)
{
    if (size < 0)
        size = 0;
    if (r->pos + (size_t)size > r->n)
        size = (int32_t)(r->n - r->pos);
    *p = r->d + r->pos;
    *len = (size_t)size;
    r->pos += (size_t)size;
}

static mv_t *mv_bytes(const uint8_t *p, size_t n, mv_type t)
{
    mv_t *v = mv_new(t);
    v->u.bytes.p = xmalloc(n ? n : 1);
    memcpy(v->u.bytes.p, p, n);
    v->u.bytes.n = n;
    return v;
}

/* The table only remembers where a shared value lives; it does not own it.
 * Ownership passes to whoever the value ends up attached to, so `R` takes a
 * new reference while push_ref takes none. Doing both (or neither) makes the
 * count drift and the tree gets freed twice or not at all. */
static void push_ref(rd_t *r, mv_t *v)
{
    v->refs++;              /* the table owns one share */
    GROW(r->refs, r->nrefs, r->caprefs);
    r->refs[r->nrefs++] = v;
}

static mv_t *r_seq(rd_t *r, int tag)
{
    int32_t n = r_int(r);
    if (n < 0)
        n = 0;
    mv_t *v = mv_new(tag == '[' ? MV_LIST : (tag == '(' ? MV_TUPLE : MV_SET));
    v->u.seq.items = xmalloc((size_t)n * sizeof(mv_t *));
    v->u.seq.n = 0;
    for (int32_t i = 0; i < n; i++)
        v->u.seq.items[v->u.seq.n++] = r_object(r);
    return v;
}

static mv_t *r_dict(rd_t *r)
{
    mv_t *v = mv_new(MV_DICT);
    size_t cap = 0;
    for (;;) {
        mv_t *k = r_object(r);
        if (k->type == MV_NULL && k->u.i == 0) {
            /* the terminator is the _NULL sentinel, encoded as tag '0' */
            mv_free(k);
            break;
        }
        mv_t *val = r_object(r);
        if (v->u.dict.n >= cap) {
            cap = cap ? cap * 2 : 16;
            /* both arrays must grow together: they are indexed by the same n */
            v->u.dict.k = xrealloc(v->u.dict.k, cap * sizeof(mv_t *));
            v->u.dict.v = xrealloc(v->u.dict.v, cap * sizeof(mv_t *));
        }
        v->u.dict.k[v->u.dict.n] = k;
        v->u.dict.v[v->u.dict.n] = val;
        v->u.dict.n++;
    }
    return v;
}

static mv_t *r_object(rd_t *r)
{
    int tag = r_byte(r);
    const uint8_t *p;
    size_t plen;

    switch (tag) {
    case '0':
        /* _NULL sentinel */
        {
            mv_t *v = mv_new(MV_NULL);
            v->u.i = 0;
            return v;
        }
    case 'N': case 'n': return mv_new(MV_NULL);
    case 'T': case 'F': {
        mv_t *v = mv_new(MV_BOOL);
        v->u.b = (tag == 'T');
        return v;
    }
    case '.': { mv_t *v = mv_new(MV_NULL); v->u.i = 1; return v; }
    case 'S': { mv_t *v = mv_new(MV_NULL); v->u.i = 2; return v; }
    case 'i': { mv_t *v = mv_new(MV_INT); v->u.i = r_int(r); return v; }
    case 'I': {
        mv_t *v = mv_new(MV_LONG);
        int64_t got = 0;
        if (r->pos + 8 <= r->n) {
            for (int i = 0; i < 8; i++)
                got |= (int64_t)r->d[r->pos + i] << (i * 8);
            r->pos += 8;
        }
        v->u.l = got;
        return v;
    }
    case 'l': case 'L': {
        mv_t *v = mv_new(MV_LONG);
        v->u.l = r_long(r);
        return v;
    }
    case 'f': {
        int sz = r_byte(r);
        r_bytes(r, &p, &plen, sz);
        char tmp[64];
        size_t k = plen < sizeof tmp - 1 ? plen : sizeof tmp - 1;
        memcpy(tmp, p, k);
        tmp[k] = '\0';
        mv_t *v = mv_new(MV_FLOAT);
        v->u.d = strtod(tmp, NULL);
        return v;
    }
    case 'g': {
        mv_t *v = mv_new(MV_FLOAT);
        if (r->pos + 8 <= r->n) {
            uint64_t bits = 0;
            for (int i = 0; i < 8; i++)
                bits |= (uint64_t)r->d[r->pos + i] << (i * 8);
            r->pos += 8;
            memcpy(&v->u.d, &bits, 8);
        }
        return v;
    }
    case 's':
        r_bytes(r, &p, &plen, r_int(r));
        return mv_bytes(p, plen, MV_BYTES);
    case 't': {
        r_bytes(r, &p, &plen, r_int(r));
        mv_t *v = mv_bytes(p, plen, MV_BYTES);
        push_ref(r, v);
        return v;
    }
    case 'u':
        r_bytes(r, &p, &plen, r_int(r));
        return mv_bytes(p, plen, MV_TEXT);
    case 'R': {
        int32_t idx = r_int(r);
        if (idx >= 0 && (size_t)idx < r->nrefs) {
            r->refs[idx]->refs++;   /* handing out another owner */
            return r->refs[idx];
        }
        return mv_new(MV_NULL);
    }
    case '(': case '[': case '<': case '>':
        return r_seq(r, tag);
    case '{':
        return r_dict(r);
    case 'm': case '1': case 23: case 26: case 29: {
        int use_v2 = (tag == 23 || tag == 26 || tag == 29);
        static const uint8_t K2[4] = { 0xa7, 0x0d, 0x37, 0x7a };
        static const uint8_t K3[13] = { 0x8d, 0x06, 0xe8, 0xc8, 0xb7, 0xd7,
                                        0xb7, 0x28, 0x46, 0x51, 0xae, 0x04, 0x00 };
        r_bytes(r, &p, &plen, r_int(r));
        mv_t *v = mv_bytes(p, plen, MV_BYTES);
        rc4_t rc;
        if (use_v2)
            rc4_init(&rc, K2, sizeof K2);
        else
            rc4_init(&rc, K3, 12);
        rc4_crypt(&rc, v->u.bytes.p, v->u.bytes.n);
        if (tag == 26)
            push_ref(r, v);
        if (tag == 29) {
            v->type = MV_TEXT;
        }
        return v;
    }
    case 'b': {
        static const uint8_t K3[13] = { 0x8d, 0x06, 0xe8, 0xc8, 0xb7, 0xd7,
                                        0xb7, 0x28, 0x46, 0x51, 0xae, 0x04, 0x00 };
        r_bytes(r, &p, &plen, r_int(r));
        mv_t *v = mv_bytes(p, plen, MV_BYTES);
        rc4_t rc;
        rc4_init(&rc, K3, 12);
        rc4_crypt(&rc, v->u.bytes.p, v->u.bytes.n);
        push_ref(r, v);
        return v;
    }
    case 8: case 14: case 15: {
        r_bytes(r, &p, &plen, r_int(r));
        mv_t *v = mv_bytes(p, plen, MV_BYTES);
        for (size_t i = 0; i < v->u.bytes.n; i++)
            v->u.bytes.p[i] ^= 141;
        if (tag == 15)
            push_ref(r, v);
        return v;
    }
    case 'c': case 'M': case 'o': case 'a':
        return r_code_object(r, tag);
    default:
        fprintf(stderr, "mcp: unknown marshal tag 0x%02x at %zu\n", tag, r->pos - 1);
        return mv_new(MV_NULL);
    }
}

static mv_t *r_code_object(rd_t *r, int tag)
{
    mv_t *v = mv_new(MV_CODE);
    switch (tag) {
    case 'c':
        v->u.code.version = 1;
        v->u.code.argcount = r_int(r);
        v->u.code.nlocals = r_int(r);
        v->u.code.stacksize = r_int(r);
        v->u.code.flags = r_int(r);
        v->u.code.code = r_object(r);
        v->u.code.consts = r_object(r);
        v->u.code.names = r_object(r);
        v->u.code.varnames = r_object(r);
        v->u.code.freevars = r_object(r);
        v->u.code.cellvars = r_object(r);
        v->u.code.filename = r_object(r);
        v->u.code.name = r_object(r);
        v->u.code.firstlineno = r_int(r);
        v->u.code.lnotab = r_object(r);
        v->u.code.magic = 0;
        break;
    case 'M':
        v->u.code.version = 4;
        v->u.code.argcount = r_int(r);
        v->u.code.lnotab = r_object(r);
        v->u.code.cellvars = r_object(r);
        v->u.code.firstlineno = r_int(r);
        v->u.code.varnames = r_object(r);
        v->u.code.consts = r_object(r);
        v->u.code.name = r_object(r);
        v->u.code.stacksize = r_int(r);
        v->u.code.freevars = r_object(r);
        v->u.code.names = r_object(r);
        v->u.code.code = r_object(r);
        v->u.code.flags = r_int(r);
        v->u.code.filename = r_object(r);
        v->u.code.nlocals = r_int(r);
        v->u.code.magic = r_int(r);
        break;
    case 'o':
        v->u.code.version = 2;
        v->u.code.nlocals = r_int(r);
        v->u.code.flags = r_int(r);
        v->u.code.consts = r_object(r);
        v->u.code.stacksize = r_int(r);
        v->u.code.varnames = r_object(r);
        v->u.code.argcount = r_int(r);
        v->u.code.cellvars = r_object(r);
        v->u.code.names = r_object(r);
        v->u.code.freevars = r_object(r);
        v->u.code.name = r_object(r);
        v->u.code.code = r_object(r);
        v->u.code.firstlineno = r_int(r);
        v->u.code.lnotab = r_object(r);
        v->u.code.magic = r_int(r);
        v->u.code.filename = r_object(r);
        break;
    case 'a':
        v->u.code.version = 3;
        v->u.code.lnotab = r_object(r);
        v->u.code.varnames = r_object(r);
        v->u.code.flags = r_int(r);
        v->u.code.freevars = r_object(r);
        v->u.code.cellvars = r_object(r);
        v->u.code.filename = r_object(r);
        v->u.code.stacksize = r_int(r);
        v->u.code.firstlineno = r_int(r);
        v->u.code.consts = r_object(r);
        v->u.code.argcount = r_int(r);
        v->u.code.code = r_object(r);
        v->u.code.nlocals = r_int(r);
        v->u.code.name = r_object(r);
        v->u.code.names = r_object(r);
        v->u.code.magic = r_int(r);
        break;
    }
    return v;
}

mv_t *mcs_parse(const uint8_t *data, size_t len)
{
    rd_t r;
    memset(&r, 0, sizeof r);
    r.d = data;
    r.n = len;
    mv_t *root = r_object(&r);
    /* entries that nothing referenced still need releasing */
    for (size_t i = 0; i < r.nrefs; i++)
        mv_free(r.refs[i]);
    free(r.refs);
    return root;
}
