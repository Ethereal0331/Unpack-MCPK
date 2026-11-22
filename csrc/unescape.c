/* Turn pycdc's escaped byte strings back into readable UTF-8.
 *
 * pycdc prints a Python 2 `str` containing non-ASCII bytes as its repr:
 *     '\xc2\xa77[\xc2\xa7d\xe6\x9d\x90\xe8\xb4\xa8...'
 * Docstrings come out as text, but ordinary string literals get escaped. The
 * bytes are identical either way -- under a UTF-8 coding declaration the escape
 * sequence and the corresponding character literal compile to the same three
 * bytes -- so rewriting the literal to UTF-8 changes nothing at runtime while
 * making the source readable.
 *
 * The rewrite is deliberately conservative:
 *   - only inside string literals; comments and code are copied verbatim;
 *   - never for u'' / b'' / r'' prefixed literals, where the meaning differs;
 *   - only when the escape run is valid UTF-8; anything else stays as it was,
 *     so a byte string that really is binary is left alone.
 */
#include "mcp.h"

#include <stdlib.h>
#include <string.h>

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode `\xNN` runs starting at p (after the opening quote). Returns the number
 * of source bytes consumed and fills buf with the raw bytes for one maximal
 * run; returns 0 when there is no valid run. */
static size_t read_escape_run(const char *p, buf_t *raw)
{
    buf_init(raw);
    size_t used = 0;
    while (p[used] == '\\' && (p[used + 1] == 'x' || p[used + 1] == 'X')) {
        int hi = hexval((unsigned char)p[used + 2]);
        int lo = hexval((unsigned char)p[used + 3]);
        if (hi < 0 || lo < 0)
            break;
        buf_push(raw, (uint8_t)((hi << 4) | lo));
        used += 4;
    }
    return used;
}

/* Validate that `n` bytes form non-empty, well-formed UTF-8 with at least one
 * multi-byte sequence (otherwise there is nothing to make readable). */
static int utf8_ok(const uint8_t *p, size_t n)
{
    size_t i = 0;
    int multibyte = 0;
    if (n == 0)
        return 0;
    while (i < n) {
        uint8_t c = p[i];
        int extra;
        if (c < 0x80) { i++; continue; }
        if ((c & 0xE0) == 0xC0) extra = 1;
        else if ((c & 0xF0) == 0xE0) extra = 2;
        else if ((c & 0xF8) == 0xF0) extra = 3;
        else return 0;
        if (i + (size_t)extra >= n + 0 && i + (size_t)extra > n - 1)
            return 0;
        for (int k = 1; k <= extra; k++)
            if ((p[i + k] & 0xC0) != 0x80)
                return 0;
        multibyte = 1;
        i += (size_t)extra + 1;
    }
    return multibyte;
}

/* Rewrite one literal's body. `body`/`len` is the text between the quotes;
 * returns 1 when something changed. */
static int rewrite_body(const char *body, size_t len, buf_t *out)
{
    int changed = 0;
    size_t i = 0;
    buf_init(out);
    while (i < len) {
        if (body[i] != '\\' || (body[i + 1] != 'x' && body[i + 1] != 'X')) {
            buf_push(out, (uint8_t)body[i]);
            i++;
            continue;
        }
        buf_t raw;
        size_t used = read_escape_run(body + i, &raw);
        if (used == 0) {
            buf_push(out, (uint8_t)body[i]);
            i++;
            continue;
        }
        if (utf8_ok(raw.data, raw.len)) {
            buf_append(out, raw.data, raw.len);
            changed = 1;
        } else {
            buf_append(out, body + i, used);
        }
        buf_free(&raw);
        i += used;
    }
    return changed;
}

/* Process a whole source file. Returns 1 when the text was modified. */
int unescape_utf8_literals(buf_t *text)
{
    buf_t out;
    buf_init(&out);

    const char *s = (const char *)text->data;
    size_t n = text->len;
    size_t i = 0;
    int changed = 0;

    while (i < n) {
        char c = s[i];

        /* comment: copy to end of line */
        if (c == '#') {
            size_t j = i;
            while (j < n && s[j] != '\n')
                j++;
            buf_append(&out, s + i, j - i);
            i = j;
            continue;
        }

        /* string literal, possibly prefixed */
        size_t start = i;
        int is_unicode = 0, is_bytes_or_raw = 0;
        if ((c == 'u' || c == 'U' || c == 'b' || c == 'B' || c == 'r' || c == 'R')
            && i + 1 < n && (s[i + 1] == '\'' || s[i + 1] == '"')) {
            if (c == 'u' || c == 'U')
                is_unicode = 1;
            else
                is_bytes_or_raw = 1;
            i++;
            c = s[i];
        }
        if (c != '\'' && c != '"') {
            buf_append(&out, s + start, i - start + 1);
            i++;
            continue;
        }

        char quote = c;
        int triple = 0;
        if (i + 2 < n && s[i + 1] == quote && s[i + 2] == quote)
            triple = 1;
        size_t qlen = triple ? 3 : 1;

        /* find the closing quote */
        size_t body_start = i + qlen;
        size_t j = body_start;
        while (j < n) {
            if (s[j] == '\\') { j += 2; continue; }
            if (triple) {
                if (s[j] == quote && j + 2 < n && s[j + 1] == quote && s[j + 2] == quote)
                    break;
                j++;
            } else {
                if (s[j] == quote)
                    break;
                if (s[j] == '\n')   /* unterminated; leave the rest alone */
                    break;
                j++;
            }
        }
        if (j >= n) {
            buf_append(&out, s + start, n - start);
            i = n;
            break;
        }

        size_t body_len = j - body_start;
        buf_append(&out, s + start, (body_start - start));
        if (!is_unicode && !is_bytes_or_raw && !triple) {
            buf_t body;
            if (rewrite_body(s + body_start, body_len, &body)) {
                changed = 1;
                buf_append(&out, body.data, body.len);
            } else {
                buf_append(&out, s + body_start, body_len);
            }
            buf_free(&body);
        } else {
            buf_append(&out, s + body_start, body_len);
        }
        buf_append(&out, s + j, qlen);
        i = j + qlen;
    }

    if (changed) {
        buf_free(text);
        *text = out;
        return 1;
    }
    buf_free(&out);
    return 0;
}

/* A source file with literal non-ASCII bytes needs a coding declaration, or
 * the Python 2 importer refuses to compile it. Only added when the first two
 * lines do not already declare one. */
int ensure_coding_decl(buf_t *text)
{
    const char *s = (const char *)text->data;
    size_t n = text->len;
    int has_nonascii = 0;
    for (size_t i = 0; i < n; i++)
        if ((uint8_t)s[i] >= 0x80) { has_nonascii = 1; break; }
    if (!has_nonascii)
        return 0;

    /* look for "coding" in a comment on the first two lines */
    size_t line = 0, i = 0;
    while (i < n && line < 2) {
        size_t j = i;
        while (j < n && s[j] != '\n')
            j++;
        const char *hash = memchr(s + i, '#', j - i);
        if (hash && (size_t)(j - (hash - s)) > 6) {
            if (memmem(hash, (size_t)(j - (hash - s)), "coding", 6))
                return 0;
        }
        i = j + 1;
        line++;
    }

    static const char decl[] = "# -*- coding: utf-8 -*-\n";
    buf_t out;
    buf_init(&out);
    buf_append(&out, decl, sizeof decl - 1);
    buf_append(&out, text->data, text->len);
    buf_free(text);
    *text = out;
    return 1;
}
