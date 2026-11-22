#include "mcp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>

static void warn(const char *fmt, ...)
{
    va_list ap;
    fputs("[!] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fputs("mcp: out of memory\n", stderr);
        exit(1);
    }
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fputs("mcp: out of memory\n", stderr);
        exit(1);
    }
    return q;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->len = b->cap = 0;
}

void buf_free(buf_t *b)
{
    free(b->data);
    buf_init(b);
}

int buf_reserve(buf_t *b, size_t extra)
{
    size_t need = b->len + extra;
    if (need <= b->cap)
        return 0;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < need)
        cap *= 2;
    b->data = xrealloc(b->data, cap);
    b->cap = cap;
    return 0;
}

int buf_append(buf_t *b, const void *p, size_t n)
{
    if (n == 0)
        return 0;
    buf_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

int buf_push(buf_t *b, uint8_t c)
{
    buf_reserve(b, 1);
    b->data[b->len++] = c;
    return 0;
}

const char *path_ext(const char *p)
{
    const char *dot = strrchr(p, '.');
    const char *slash = strrchr(p, '/');
    if (!dot || (slash && dot < slash))
        return "";
    return dot;
}

char *path_join(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    int need = (la > 0 && a[la - 1] != '/');
    char *p = xmalloc(la + (size_t)need + lb + 1);
    memcpy(p, a, la);
    if (need)
        p[la++] = '/';
    memcpy(p + la, b, lb + 1);
    return p;
}

/* A path is only trustworthy if it is printable text. Anything else means a
 * pointer or a length went wrong upstream, and creating a directory named
 * after that garbage litters the user's tree with something they cannot even
 * type in a shell. Refuse it here instead. */
static int path_is_sane(const char *p)
{
    if (!p || !*p)
        return 0;
    /* Printable ASCII, or bytes that form valid UTF-8 (so non-English
     * directory names still work). A lone high byte -- which is what a
     * truncated pointer looks like -- is rejected. */
    const unsigned char *c = (const unsigned char *)p;
    while (*c) {
        if (*c < 0x20 || *c == 0x7F)
            return 0;
        if (*c < 0x80) { c++; continue; }
        int extra;
        if ((*c & 0xE0) == 0xC0) extra = 1;
        else if ((*c & 0xF0) == 0xE0) extra = 2;
        else if ((*c & 0xF8) == 0xF0) extra = 3;
        else return 0;
        for (int i = 1; i <= extra; i++)
            if ((c[i] & 0xC0) != 0x80)
                return 0;
        c += extra + 1;
    }
    return 1;
}

int mkdir_p(const char *path)
{
    if (!path || !*path)
        return 0;
    if (!path_is_sane(path)) {
        warn("refusing to create a directory with a corrupt name");
        return -1;
    }
    char *tmp = xstrdup(path);
    size_t n = strlen(tmp);

    /* strip trailing slashes */
    while (n > 1 && tmp[n - 1] == '/')
        tmp[--n] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            free(tmp);
            return -1;
        }
        *p = '/';
    }
    int rc = 0;
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        rc = -1;
    free(tmp);
    return rc;
}

int read_file(const char *path, buf_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    buf_init(out);
    uint8_t chunk[65536];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0)
        buf_append(out, chunk, n);
    int bad = ferror(f);
    fclose(f);
    return bad ? -1 : 0;
}

int write_file(const char *path, const void *data, size_t len)
{
    if (!path_is_sane(path)) {
        warn("refusing to write a file with a corrupt name");
        return -1;
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (len && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    return fclose(f) == 0 ? 0 : -1;
}
