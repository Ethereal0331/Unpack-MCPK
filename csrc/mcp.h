/* mcp - MCPK unpacker + decompiler, pure C.
 *
 * Pipeline: MCPK container -> .mcs  ->  decrypt + deobfuscate -> .pyc
 *           -> pycdc -> .py source.
 *
 * Everything before pycdc used to run in an embedded Python interpreter; it is
 * plain byte manipulation, so it lives here instead and the executable carries
 * no interpreter at all.
 */
#ifndef MCP_H
#define MCP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ---- growable byte buffer ---------------------------------------------- */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
int  buf_reserve(buf_t *b, size_t extra);
int  buf_append(buf_t *b, const void *p, size_t n);
int  buf_push(buf_t *b, uint8_t c);

/* ---- misc helpers ------------------------------------------------------ */
char *xstrdup(const char *s);
void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
int   mkdir_p(const char *path);
int   read_file(const char *path, buf_t *out);
int   write_file(const char *path, const void *data, size_t len);
const char *path_ext(const char *p);
char *path_join(const char *a, const char *b);
/* number of bytes to grow a dynamic array from n to n+1 */
#define GROW(arr, n, cap) do { \
    if ((n) >= (cap)) { (cap) = (cap) ? (cap) * 2 : 16; \
        (arr) = xrealloc((arr), (size_t)(cap) * sizeof(*(arr))); } \
} while (0)

/* ---- MCS --------------------------------------------------------------- */
/* Decrypt an .mcs into the pyc bytes the game would marshal.loads(). */
int mcs_decode(const uint8_t *in, size_t n, buf_t *out);

/* ---- MCPK -------------------------------------------------------------- */
typedef struct {
    char  *rel_path;      /* path inside the container */
    uint8_t *data;        /* extracted bytes (decompressed when applicable) */
    size_t   len;
} mcpk_file_t;

typedef struct {
    mcpk_file_t *files;
    size_t       count;
} mcpk_t;

int  mcpk_unpack(const char *path, mcpk_t *out);

uint32_t mcpk_hash_name(const char *s);
uint32_t mcpk_hash_dir(const char *s);

/* Rewrite pycdc's \\xNN-escaped byte strings as UTF-8 (unescape.c).
 * Returns 1 when the text changed. */
int unescape_utf8_literals(buf_t *text);

/* Replace obfuscation decoy bodies (malformed bytecode, never called) with a
 * one-line comment. Returns 1 when the text changed. */
int strip_obfuscation_decoys(buf_t *text);

/* Prepend a UTF-8 coding declaration when the file needs one. */
int ensure_coding_decl(buf_t *text);

/* zlib helpers (crypto.c) */
int zlib_inflate_raw(const uint8_t *in, size_t n, buf_t *out);
int crypto_decrypt(const uint8_t *in, size_t n, buf_t *out);
void mcpk_free(mcpk_t *m);

#endif /* MCP_H */

/* ---- RC4 --------------------------------------------------------------- */
typedef struct {
    uint8_t s[256];
    int i, j;
} rc4_t;

void rc4_init(rc4_t *c, const uint8_t *key, size_t klen);
void rc4_crypt(rc4_t *c, uint8_t *data, size_t len);

/* ---- MCS value tree ---------------------------------------------------- */
/* A parsed .mcs is a tree of these; a code object is a dict-like node. */
typedef enum {
    MV_NULL, MV_BOOL, MV_INT, MV_LONG, MV_FLOAT, MV_BYTES, MV_TEXT,
    MV_TUPLE, MV_LIST, MV_SET, MV_DICT, MV_CODE
} mv_type;

typedef struct mv mv_t;

struct mv {
    mv_type type;
    /* Shared nodes (R references) are owned by more than one place; the count
     * keeps mv_free from releasing them twice. */
    int refs;
    union {
        int      b;
        int32_t  i;
        int64_t  l;
        double   d;
        struct { uint8_t *p; size_t n; } bytes;   /* also MV_TEXT (utf-8) */
        struct { mv_t **items; size_t n; } seq;   /* tuple/list/set */
        struct { mv_t **k, **v; size_t n; } dict;
        struct {                                   /* MV_CODE */
            int32_t argcount, nlocals, stacksize, flags, firstlineno;
            int32_t magic, version;
            mv_t *code, *consts, *names, *varnames;
            mv_t *freevars, *cellvars, *filename, *name, *lnotab;
        } code;
    } u;
};

/* Parse a decrypted MCS payload into a value tree. */
mv_t *mcs_parse(const uint8_t *data, size_t len);
void  mv_free(mv_t *v);

/* ---- MCS -> pyc -------------------------------------------------------- */
/* Full .mcs -> pyc conversion (decrypt, parse, opcode fixup, marshal). */
int mcs_decode(const uint8_t *in, size_t n, buf_t *out);

const uint16_t *mcs_opcode_map(int version);
