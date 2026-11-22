/* Collapse the game's obfuscation decoys into a single comment.
 *
 * vanilla.mcp carries thousands of functions named `foo_01dVersi0n`,
 * `foo_newVersi0n`, `foo_exceptV` and so on. Their bodies are not real
 * bytecode: variable indices point past `nlocals` (LOAD_FAST 58368 in a
 * function with three locals), jumps land beyond the end of the code, and
 * opcodes appear in sequences no compiler emits. They exist to make
 * decompilers emit nonsense or fall over, and nothing calls them -- the
 * reference count across the whole package is zero.
 *
 * pycdc already degrades gracefully: it prints bad-local-N and bad-const-N
 * placeholder comments instead of guessing. That output is honest but
 * unreadable, so a whole decoy body becomes:
 *
 *     def my_release_01dVersi0n():
 *         # obfuscation decoy: malformed bytecode, never called
 *         pass
 *
 * Only functions that satisfy BOTH conditions are touched:
 *   - the body contains a bad-local / bad-const placeholder, and
 *   - the name carries one of the decoy suffixes.
 * A real function that merely failed to decompile keeps every line, as does the
 * `import x as <bad-name>` case, which is a naming gap rather than a
 * broken body.
 */
#include "mcp.h"

#include <stdlib.h>
#include <string.h>

static int has_decoy_suffix(const char *name, size_t len)
{
    static const char *suffixes[] = {
        "_01dVersi0n", "_oldVersi0n", "_newVersi0n", "_new_Version",
        "_furtureVersion", "_futureVersion", "Versi0n", "_exceptV",
    };
    /* Some decoys append a counter (`encrypt_function_new_Version2`), so the
     * suffix is allowed to be followed by digits only. */
    size_t ndig = 0;
    while (ndig < len && name[len - 1 - ndig] >= '0' && name[len - 1 - ndig] <= '9')
        ndig++;
    size_t trim = len;
    if (ndig > 0 && ndig < len)
        trim = len - ndig;

    for (size_t i = 0; i < sizeof suffixes / sizeof suffixes[0]; i++) {
        size_t sl = strlen(suffixes[i]);
        if (trim >= sl) {
            const char *tail = name + trim - sl;
            size_t k = 0;
            for (; k < sl; k++) {
                char a = tail[k], b = suffixes[i][k];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b) break;
            }
            if (k == sl)
                return 1;
        }
    }
    return 0;
}

/* index just past a bad-local / bad-const placeholder, or 0 */
static size_t bad_placeholder_at(const char *s, size_t len, size_t i)
{
    static const char local[] = "/*bad-local-";
    static const char konst[] = "/*bad-const-";
    const char *pat = NULL;
    size_t pl = 0;
    if (i + 12 < len && memcmp(s + i, local, 12) == 0) { pat = local; pl = 12; }
    else if (i + 12 < len && memcmp(s + i, konst, 12) == 0) { pat = konst; pl = 12; }
    if (!pat)
        return 0;
    size_t j = i + pl;
    size_t digits = 0;
    while (j < len && s[j] >= '0' && s[j] <= '9') { j++; digits++; }
    if (!digits || j + 1 >= len || s[j] != '*' || s[j + 1] != '/')
        return 0;
    return j + 2;
}

static int has_bad_placeholder(const char *s, size_t len)
{
    for (size_t i = 0; i + 12 < len; i++)
        if (s[i] == '/' && bad_placeholder_at(s, len, i))
            return 1;
    return 0;
}

/* True when a line is one of the shapes a broken body produces: a placeholder,
 * a chain of `None` operators, or a bare statement. */
static int line_is_junk(const char *l, size_t n)
{
    /* trim */
    while (n && (l[0] == ' ' || l[0] == '\t')) { l++; n--; }
    while (n && (l[n - 1] == ' ' || l[n - 1] == '\t' || l[n - 1] == '\r')) n--;
    if (n == 0)
        return 1;

    if (n >= 4 && memcmp(l, "pass", 4) == 0) return 1;
    if (n >= 5 && memcmp(l, "break", 5) == 0) return 1;
    if (n >= 8 && memcmp(l, "continue", 8) == 0) return 1;
    if (n >= 7 && memcmp(l, "return ", 7) == 0) {
        /* `return None(...)`, `return None >> None` -- junk either way */
        for (size_t i = 7; i + 4 <= n; i++)
            if (memcmp(l + i, "None", 4) == 0) return 1;
    }
    /* a lone comment carries no code */
    if (n >= 1 && l[0] == '#') return 1;
    /* statements a broken body falls back to: `print`, `while 1:`, a bare
     * number, or an import whose module name was lost */
    if (n >= 5 && memcmp(l, "print", 5) == 0) return 1;
    if (n >= 6 && memcmp(l, "while ", 6) == 0) return 1;
    /* block headers whose body is also junk (the body lines are checked
     * separately) */
    if (n >= 4 && memcmp(l, "for ", 4) == 0) return 1;
    if (n >= 4 && memcmp(l, "if ", 3) == 0) return 1;
    if (n >= 6 && memcmp(l, "else:", 5) == 0) return 1;
    if (n >= 7 && memcmp(l, "import ", 7) == 0) return 1;
    if (n >= 5 && memcmp(l, "from ", 5) == 0) return 1;
    {
        int numeric = 1;
        for (size_t i = 0; i < n; i++)
            if (!(l[i] >= '0' && l[i] <= '9') && l[i] != '.' && l[i] != ':') { numeric = 0; break; }
        if (numeric) return 1;
    }
    for (size_t i = 0; i + 5 <= n; i++)
        if (l[i] == '/' && l[i + 1] == '*' && l[i + 2] == 'b'
            && l[i + 3] == 'a' && l[i + 4] == 'd')
            return 1;
    /* a bare identifier or dotted name on its own line: `range`, `obj.attr` */
    {
        int ident_only = 1;
        for (size_t i = 0; i < n; i++) {
            char c = l[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '_' || c == '.')
                continue;
            ident_only = 0; break;
        }
        /* ident_only already guarantees the first char is a letter, a digit
         * or '_'; a leading digit would not start a statement, so require a
         * letter */
        if (ident_only && ((l[0] >= 'a' && l[0] <= 'z') || (l[0] >= 'A' && l[0] <= 'Z')))
            return 1;
    }

    /* Mostly `None` plus operators, optionally behind a `name = ` target:
     *   num = None(**None, **None, ...)
     *   [None, None, ...]
     * Plain identifiers are allowed as long as `None` appears -- a line with no
     * None at all is ordinary code and must be kept. */
    int seen_none = 0;
    for (size_t i = 0; i < n; i++) {
        char c = l[i];
        if (c == 'N' && i + 4 <= n && memcmp(l + i, "None", 4) == 0) {
            seen_none = 1; i += 3; continue;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') continue;
        if (strchr(" .()[]>+-~,%*|&:=0123456789", c)) continue;
        return 0;
    }
    return seen_none;
}

/* Find the end of a def block: the next line at the same or lower indent that
 * is not blank and not a continuation. */
static size_t block_end(const char *s, size_t len, size_t body_start, int indent)
{
    size_t i = body_start;
    size_t end = body_start;
    while (i < len) {
        size_t ls = i;
        while (i < len && s[i] != '\n')
            i++;
        size_t le = i;
        if (i < len)
            i++;

        /* measure indentation */
        size_t k = ls, ind = 0;
        while (k < le && (s[k] == ' ' || s[k] == '\t')) {
            ind += (s[k] == '\t') ? 8 : 1;
            k++;
        }
        int blank = (k >= le);
        if (blank) {
            end = i;
            continue;
        }
        if ((int)ind <= indent) {
            end = ls;
            break;
        }
        end = i;
    }
    return end;
}

int strip_obfuscation_decoys(buf_t *text)
{
    const char *s = (const char *)text->data;
    size_t n = text->len;
    buf_t out;
    buf_init(&out);

    int changed = 0;
    size_t i = 0;
    size_t copied = 0;

    while (i < n) {
        /* line start? */
        if (i != 0 && s[i - 1] != '\n') { i++; continue; }

        size_t ls = i;
        size_t ind = 0;
        size_t k = ls;
        while (k < n && (s[k] == ' ' || s[k] == '\t')) {
            ind += (s[k] == '\t') ? 8 : 1;
            k++;
        }
        if (k + 4 > n || memcmp(s + k, "def ", 4) != 0) {
            i = ls + 1;
            while (i < n && s[i - 1] != '\n')
                i++;
            continue;
        }

        /* parse the name */
        size_t ns = k + 4;
        size_t ne = ns;
        while (ne < n && (s[ne] == '_' || (s[ne] >= 'a' && s[ne] <= 'z')
                          || (s[ne] >= 'A' && s[ne] <= 'Z')
                          || (s[ne] >= '0' && s[ne] <= '9')))
            ne++;
        if (ne == ns || ne >= n || s[ne] != '(') {
            i = ls + 1;
            while (i < n && s[i - 1] != '\n')
                i++;
            continue;
        }

        /* find the end of the signature (the colon that closes the header) */
        size_t hdr = ne;
        int depth = 0;
        while (hdr < n) {
            char c = s[hdr];
            if (c == '(') depth++;
            else if (c == ')') depth--;
            else if (c == ':' && depth == 0) break;
            else if (c == '\n') break;
            hdr++;
        }
        if (hdr >= n || s[hdr] != ':') {
            i = ls + 1;
            while (i < n && s[i - 1] != '\n')
                i++;
            continue;
        }

        size_t body_start = hdr + 1;
        while (body_start < n && s[body_start] != '\n')
            body_start++;
        if (body_start < n)
            body_start++;

        size_t bend = block_end(s, n, body_start, (int)ind);
        const char *body = s + body_start;
        size_t blen = bend > body_start ? bend - body_start : 0;

        int decoy_body = has_bad_placeholder(body, blen);
        if (!decoy_body && blen) {
            /* an empty body (comment-only) is a crashed decoy too: leaving it
             * as-is produces `def f():` with no statement, which Python
             * rejects outright */
            size_t q = 0, real = 0;
            while (q < blen) {
                size_t le = q;
                while (le < blen && body[le] != '\n') le++;
                size_t t = q;
                while (t < le && (body[t] == ' ' || body[t] == '\t')) t++;
                if (t < le && body[t] != '#') real++;
                q = le + 1;
            }
            if (real == 0) decoy_body = 2;   /* empty: strip regardless of name */
        }
        if (!decoy_body && blen) {
            /* a body made entirely of junk counts too: it is the same decoy in
             * a form that happens to decode without local/const placeholders */
            decoy_body = 1;
            size_t q = 0;
            while (q < blen) {
                size_t le = q;
                while (le < blen && body[le] != '\n')
                    le++;
                if (!line_is_junk(body + q, le - q)) { decoy_body = 0; break; }
                q = le + 1;
            }
        }
        if (decoy_body && (decoy_body == 2 || has_decoy_suffix(s + ns, ne - ns))) {
            /* emit everything up to the def, then a stub */
            buf_append(&out, s + copied, ls - copied);
            buf_append(&out, s + ls, hdr - ls + 1);      /* def ... : */
            buf_push(&out, '\n');
            for (size_t t = 0; t < ind + 4; t++)
                buf_push(&out, ' ');
            const char *note = "# obfuscation decoy: malformed bytecode, never called\n";
            buf_append(&out, note, strlen(note));
            for (size_t t = 0; t < ind + 4; t++)
                buf_push(&out, ' ');
            buf_append(&out, "pass\n", 5);
            /* keep the blank lines that separated the decoy from its
             * neighbours, so the remaining code keeps its shape */
            size_t tail = bend;
            while (tail > body_start && s[tail - 1] == '\n'
                   && tail >= 2 && s[tail - 2] == '\n')
                tail--;
            if (tail < bend)
                buf_push(&out, '\n');
            copied = bend;
            changed = 1;
        }
        i = bend > ls ? bend : ls + 1;
    }

    if (changed) {
        buf_append(&out, s + copied, n - copied);
        buf_free(text);
        *text = out;
        return 1;
    }
    buf_free(&out);
    return 0;
}
