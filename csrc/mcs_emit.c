/* MCS tree -> CPython 2.7 .pyc
 *
 * Two steps mirror the Python implementation exactly:
 *   1. transform_code: rewrite each MCS opcode to its CPython 2.7 equivalent.
 *      Whether an instruction carries an argument is decided by the *standard*
 *      opcode (>= 90), not the MCS one -- getting that wrong desynchronises
 *      the whole instruction stream.
 *   2. fix unmapped opcodes: MAP_ADD / SET_ADD are missing from the MCS map,
 *      so 0xBB / 0xBC survive step 1 and are rewritten here, at instruction
 *      boundaries only.
 */
#include "mcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#define HAVE_ARGUMENT 90
#define PY27_MAGIC "\x03\xf3\r\n"

/* ---- writer ------------------------------------------------------------ */
typedef struct {
    buf_t *b;
} wr_t;

static void w_byte(wr_t *w, unsigned v)
{
    buf_push(w->b, (uint8_t)v);
}

static void w_int(wr_t *w, int32_t v)
{
    uint32_t u = (uint32_t)v;
    uint8_t t[4] = { (uint8_t)u, (uint8_t)(u >> 8), (uint8_t)(u >> 16), (uint8_t)(u >> 24) };
    buf_append(w->b, t, 4);
}

static void w_long(wr_t *w, int64_t v)
{
    if (v == 0) {
        w_int(w, 0);
        return;
    }
    int sign = v >= 0 ? 1 : -1;
    uint64_t n = (uint64_t)(v >= 0 ? v : -v);
    uint16_t digits[16];
    int count = 0;
    while (n && count < 16) {
        digits[count++] = (uint16_t)(n & 0x7FFF);
        n >>= 15;
    }
    w_int(w, sign * count);
    for (int i = 0; i < count; i++) {
        w_byte(w, digits[i] & 0xFF);
        w_byte(w, (digits[i] >> 8) & 0xFF);
    }
}

static void w_string(wr_t *w, const uint8_t *p, size_t n)
{
    w_byte(w, 's');
    w_int(w, (int32_t)n);
    buf_append(w->b, p, n);
}

/* ---- step 1: opcode translation --------------------------------------- */
static int std_code(const mv_t *code, int version, buf_t *out)
{
    const uint16_t *map = mcs_opcode_map(version);
    const uint8_t *src;
    size_t n;

    if (!code || code->type != MV_BYTES) {
        buf_init(out);
        return 0;
    }
    src = code->u.bytes.p;
    n = code->u.bytes.n;
    buf_init(out);

    size_t i = 0;
    while (i < n) {
        uint8_t mcs_op = src[i];
        unsigned std_op = map[mcs_op];
        int has_arg = (std_op >= HAVE_ARGUMENT);
        unsigned arg = 0;
        size_t step;

        if (has_arg) {
            if (i + 2 < n) {
                arg = (unsigned)src[i + 1] | ((unsigned)src[i + 2] << 8);
                step = 3;
            } else {
                arg = 0;
                step = n - i;
            }
        } else {
            step = 1;
        }
        buf_push(out, (uint8_t)std_op);
        if (has_arg) {
            buf_push(out, (uint8_t)(arg & 255));
            buf_push(out, (uint8_t)((arg >> 8) & 255));
        }
        i += step;
    }
    return 0;
}

/* ---- float repr --------------------------------------------------------
 *
 * Python's repr(float) shows the shortest string that round-trips, and picks
 * between fixed and exponential notation with its own rule: fixed when the
 * decimal exponent falls in [-4, 16), exponential otherwise. C's %g uses a
 * different threshold, which is why 30.0 must come out as "30.0" and not
 * "3e+01" -- the text goes straight into the marshalled constant.
 */
static void py_float_repr(double d, char *out)
{
    char sci[64] = { 0 };
    int prec;
    for (prec = 1; prec <= 17; prec++) {
        char tmp[64];
        int n = snprintf(tmp, sizeof tmp, "%.*e", prec - 1, d);
        if (n <= 0 || n >= (int)sizeof tmp)
            continue;
        if (strtod(tmp, NULL) == d) {
            memcpy(sci, tmp, (size_t)n + 1);
            break;
        }
    }
    if (!sci[0])
        snprintf(sci, sizeof sci, "%.16e", d);

    /* sci looks like  d.dddddde+XX */
    const char *ep = strchr(sci, 'e');
    int exp10 = ep ? atoi(ep + 1) : 0;

    if (exp10 >= -4 && exp10 < 16) {
        /* rebuild as fixed notation with the same digits */
        char digits[32];
        int nd = 0;
        for (const char *p = sci; *p && *p != 'e'; p++)
            if (*p >= '0' && *p <= '9')
                digits[nd++] = *p;
        while (nd > 1 && digits[nd - 1] == '0')
            nd--;                       /* strip trailing zeros of the mantissa */

        char *o = out;
        if (sci[0] == '-')
            *o++ = '-';
        int intlen = exp10 + 1;         /* digits before the point */
        if (intlen <= 0) {
            *o++ = '0';
            *o++ = '.';
            for (int i = 0; i < -intlen; i++)
                *o++ = '0';
            for (int i = 0; i < nd; i++)
                *o++ = digits[i];
        } else {
            for (int i = 0; i < intlen; i++)
                *o++ = (i < nd) ? digits[i] : '0';
            *o++ = '.';
            if (nd > intlen) {
                for (int i = intlen; i < nd; i++)
                    *o++ = digits[i];
            } else {
                *o++ = '0';
            }
        }
        *o = '\0';
        return;
    }

    /* exponential: Python keeps the shortest mantissa and writes e+NN */
    char mant[40];
    int md = 0;
    for (const char *p = sci; *p && *p != 'e'; p++)
        if (*p >= '0' && *p <= '9')
            mant[md++] = *p;
    while (md > 1 && mant[md - 1] == '0')
        md--;
    char *o = out;
    if (sci[0] == '-')
        *o++ = '-';
    *o++ = mant[0];
    if (md > 1) {
        *o++ = '.';
        for (int i = 1; i < md; i++)
            *o++ = mant[i];
    }
    o += sprintf(o, "e%c%02d", exp10 < 0 ? '-' : '+', exp10 < 0 ? -exp10 : exp10);
    *o = '\0';
}

/* ---- step 2: fill in MAP_ADD / SET_ADD ---------------------------------
 *
 * The MCS opcode table has no entry for 0xBB / 0xBC, so step 1 passes them
 * through unchanged. Inside a dict/set comprehension they mean MAP_ADD and
 * SET_ADD; anywhere else those byte values are ordinary data.
 *
 * Only bytes that sit on an instruction boundary of a real co_code may be
 * rewritten. Getting this wrong corrupts string constants -- the UTF-8 for a
 * full-width paren is EF BC 88, so a stray 0xBC rewrite eats a character.
 */
static void fix_in_blob(buf_t *blob)
{
    size_t i = 0;
    while (i < blob->len) {
        uint8_t op = blob->data[i];
        if (op == 0xBB)
            blob->data[i] = 0x93;
        else if (op == 0xBC)
            blob->data[i] = 0x92;
        i += (op >= HAVE_ARGUMENT) ? 3 : 1;
    }
}

/* ---- recursive emit ---------------------------------------------------- */
static int emit_object(wr_t *w, const mv_t *v);

static int emit_code(wr_t *w, const mv_t *v)
{
    const mv_t *c = v->u.code.code;
    buf_t std;
    std_code(c, v->u.code.version, &std);

    fix_in_blob(&std);

    w_byte(w, 'c');
    w_int(w, v->u.code.argcount);
    w_int(w, v->u.code.nlocals);
    w_int(w, v->u.code.stacksize);
    w_int(w, v->u.code.flags);
    if (std.len) {
        w_string(w, std.data, std.len);
    } else {
        w_string(w, (const uint8_t *)"", 0);
    }
    buf_free(&std);

    emit_object(w, v->u.code.consts);
    emit_object(w, v->u.code.names);
    emit_object(w, v->u.code.varnames);
    emit_object(w, v->u.code.freevars);
    emit_object(w, v->u.code.cellvars);
    emit_object(w, v->u.code.filename);
    emit_object(w, v->u.code.name);
    w_int(w, v->u.code.firstlineno);
    emit_object(w, v->u.code.lnotab);
    return 0;
}

static int emit_seq(wr_t *w, const mv_t *v)
{
    char tag = v->type == MV_TUPLE ? '(' : (v->type == MV_LIST ? '[' : '<');
    w_byte(w, tag);
    w_int(w, (int32_t)v->u.seq.n);
    for (size_t i = 0; i < v->u.seq.n; i++)
        emit_object(w, v->u.seq.items[i]);
    return 0;
}

static int emit_object(wr_t *w, const mv_t *v)
{
    if (!v) {
        w_byte(w, 'N');
        return 0;
    }
    switch (v->type) {
    case MV_NULL:  w_byte(w, 'N'); break;
    case MV_BOOL:  w_byte(w, v->u.b ? 'T' : 'F'); break;
    case MV_INT:   w_byte(w, 'i'); w_int(w, v->u.i); break;
    case MV_LONG:
        if (v->u.l >= -2147483648LL && v->u.l <= 2147483647LL) {
            w_byte(w, 'i');
            w_int(w, (int32_t)v->u.l);
        } else {
            w_byte(w, 'l');
            w_long(w, v->u.l);
        }
        break;
    case MV_FLOAT: {
        char repr[64];
        py_float_repr(v->u.d, repr);
        int n = (int)strlen(repr);
        w_byte(w, 'f');
        w_byte(w, (unsigned)n);
        buf_append(w->b, repr, (size_t)n);
        break;
    }
    case MV_BYTES:
        w_string(w, v->u.bytes.p, v->u.bytes.n);
        break;
    case MV_TEXT:
        w_byte(w, 'u');
        w_int(w, (int32_t)v->u.bytes.n);
        buf_append(w->b, v->u.bytes.p, v->u.bytes.n);
        break;
    case MV_TUPLE:
    case MV_LIST:
    case MV_SET:
        emit_seq(w, v);
        break;
    case MV_DICT:
        w_byte(w, '{');
        for (size_t i = 0; i < v->u.dict.n; i++) {
            emit_object(w, v->u.dict.k[i]);
            emit_object(w, v->u.dict.v[i]);
        }
        w_byte(w, '0');
        break;
    case MV_CODE:
        emit_code(w, v);
        break;
    }
    return 0;
}

int mcs_emit_root(mv_t *root, buf_t *out);
int mcs_emit_root(mv_t *root, buf_t *out)
{
    wr_t w;
    w.b = out;
    emit_object(&w, root);
    return 0;
}

int mcs_decode(const uint8_t *in, size_t n, buf_t *out)
{
    extern int crypto_decrypt(const uint8_t *in, size_t n, buf_t *out);
    buf_t plain;
    buf_init(out);
    if (crypto_decrypt(in, n, &plain) < 0)
        return -1;
    if (plain.len == 0) {
        buf_free(&plain);
        return -1;
    }
    mv_t *root = mcs_parse(plain.data, plain.len);
    buf_free(&plain);
    if (!root)
        return -1;

    wr_t w;
    w.b = out;
    buf_append(out, PY27_MAGIC, 4);
    buf_append(out, "\x00\x00\x00\x00", 4);
    emit_object(&w, root);
    mv_free(root);
    return 0;
}
