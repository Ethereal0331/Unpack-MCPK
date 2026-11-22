/* mcp - unpack an MCPK container and decompile its scripts.
 *
 *   mcp unpack <input.mcp> [output_dir]
 *   mcp info   <input.mcp>
 *
 * No interpreter is involved: the container parsing, MCS decryption and pyc
 * writing are C, and decompilation is a single pycdc subprocess.
 */
#include "mcp.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include <dirent.h>
#include <sys/wait.h>

/* embedded pycdc (mkres.py) */
extern const unsigned long mcp_pycdc_raw_len;
extern const unsigned long mcp_pycdc_comp_len;
extern const unsigned char mcp_pycdc_image[];

static int verbose = 0;

static void step(const char *fmt, ...)
{
    va_list ap;
    fputs("[*] ", stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static void warn(const char *fmt, ...)
{
    va_list ap;
    fputs("[!] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ---- phase timing ------------------------------------------------------ */
#define MAX_PHASES 32
static struct { const char *name; double secs; } phases[MAX_PHASES];
static int nphases = 0;
static double t_start;

static double now_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void phase(const char *name, double secs)
{
    if (nphases < MAX_PHASES) {
        phases[nphases].name = name;
        phases[nphases].secs = secs;
        nphases++;
    }
}

static void report_timings(void)
{
    double total = now_secs() - t_start;
    size_t w = strlen("total");
    for (int i = 0; i < nphases; i++)
        if (strlen(phases[i].name) > w)
            w = strlen(phases[i].name);

    step("timings");
    for (int i = 0; i < nphases; i++)
        printf("    %-*s %7.3f s  %5.1f%%\n", (int)w, phases[i].name,
               phases[i].secs, total > 0 ? 100.0 * phases[i].secs / total : 0.0);
    printf("    %-*s %7.3f s\n", (int)w, "total", total);
    fflush(stdout);
}

/* ---- embedded pycdc ---------------------------------------------------- */
static char *pycdc_path = NULL;

static const char *pycdc_binary(void)
{
    if (pycdc_path)
        return pycdc_path[0] ? pycdc_path : NULL;

    double t0 = now_secs();
    uLongf raw_len = (uLongf)mcp_pycdc_raw_len;
    uint8_t *raw = xmalloc(raw_len ? raw_len : 1);
    if (uncompress(raw, &raw_len, mcp_pycdc_image,
                   (uLong)mcp_pycdc_comp_len) != Z_OK
        || raw_len != (uLongf)mcp_pycdc_raw_len) {
        free(raw);
        pycdc_path = xstrdup("");
        phase("pycdc unpack", now_secs() - t0);
        return NULL;
    }

    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir)
        tmpdir = "/tmp";
    char *tpl = path_join(tmpdir, "mcp-pycdc-XXXXXX");
    int fd = mkstemp(tpl);
    if (fd < 0) {
        free(tpl);
        free(raw);
        pycdc_path = xstrdup("");
        phase("pycdc unpack", now_secs() - t0);
        return NULL;
    }
    size_t off = 0;
    while (off < raw_len) {
        ssize_t w = write(fd, raw + off, raw_len - off);
        if (w <= 0) {
            close(fd);
            unlink(tpl);
            free(tpl);
            free(raw);
            pycdc_path = xstrdup("");
            phase("pycdc unpack", now_secs() - t0);
            return NULL;
        }
        off += (size_t)w;
    }
    close(fd);
    chmod(tpl, 0755);
    free(raw);
    pycdc_path = tpl;
    phase("pycdc unpack", now_secs() - t0);
    return pycdc_path;
}

/* ---- filesystem helpers ------------------------------------------------ */
static int rmtree(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISDIR(st.st_mode))
        return unlink(path);
    DIR *d = opendir(path);
    if (!d)
        return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char *p = path_join(path, e->d_name);
        rmtree(p);
        free(p);
    }
    closedir(d);
    return rmdir(path);
}

static int write_at(const char *root, const char *rel, const void *data, size_t n)
{
    char *p = path_join(root, rel);
    char *slash = strrchr(p, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(p);
        *slash = '/';
    }
    int rc = write_file(p, data, n);
    free(p);
    return rc;
}


/* ---- project stubs ----------------------------------------------------- */
/* The editor expects a manifest; the original wrote it with json.dump(indent=2),
 * so the layout below follows that exactly. */
static const char *package_name(const mcpk_t *m)
{
    for (size_t i = 0; i < m->count; i++) {
        const char *rel = m->files[i].rel_path;
        const char *slash = strchr(rel, '/');
        if (!slash)
            continue;
        size_t n = (size_t)(slash - rel);
        static char name[256];
        if (n < sizeof name) {
            memcpy(name, rel, n);
            name[n] = '\0';
            return name;
        }
    }
    return NULL;
}

static void write_manifest(const char *path, const char *pkg)
{
    const char *name = pkg ? pkg : "recovered";
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    fprintf(f,
        "{\n"
        "  \"format_version\": 1,\n"
        "  \"header\": {\n"
        "    \"name\": \"%s_behavior_pack\",\n"
        "    \"description\": \"Recovered by mcp\",\n"
        "    \"version\": [\n      0,\n      1,\n      0\n    ],\n"
        "    \"min_engine_version\": [\n      1,\n      18,\n      0\n    ]\n"
        "  },\n"
        "  \"modules\": [\n"
        "    {\n"
        "      \"type\": \"data\",\n"
        "      \"description\": \"Recovered scripts\",\n"
        "      \"version\": [\n        0,\n        1,\n        0\n      ]\n"
        "    }\n"
        "  ],\n"
        "  \"dependencies\": []\n"
        "}\n", name);
    fclose(f);
}


static void random_hex(char *out, int nbytes)
{
    static const char *hx = "0123456789abcdef";
    unsigned char raw[64];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(raw, 1, (size_t)nbytes, f) != (size_t)nbytes)
            memset(raw, 0, (size_t)nbytes);
        fclose(f);
    } else {
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        for (int i = 0; i < nbytes; i++)
            raw[i] = (unsigned char)(rand() & 0xFF);
    }
    for (int i = 0; i < nbytes; i++) {
        out[i * 2] = hx[raw[i] >> 4];
        out[i * 2 + 1] = hx[raw[i] & 15];
    }
    out[nbytes * 2] = '\0';
}

static void write_editor_stubs(const char *out, const char *pkg)
{
    const char *name = pkg ? pkg : "recovered";

    char *studio = path_join(out, "studio.json");
    if (access(studio, F_OK) != 0) {
        char id[65];
        random_hex(id, 32);
        FILE *f = fopen(studio, "wb");
        if (f) {
            fprintf(f,
                "{\n"
                "  \"Source\": \"import\",\n"
                "  \"CreateVersion\": \"\",\n"
                "  \"EditVersion\": \"\",\n"
                "  \"Id\": \"%s\",\n"
                "  \"EditType\": 0,\n"
                "  \"IsMap\": false,\n"
                "  \"CodeEnable\": true,\n"
                "  \"GameType\": 0\n"
                "}\n", id);
            fclose(f);
        }
    }
    free(studio);

    char *work = path_join(out, "work.mcscfg");
    if (access(work, F_OK) != 0) {
        char uid[65];
        random_hex(uid, 32);
        FILE *f = fopen(work, "wb");
        if (f) {
            fprintf(f,
                "{\n"
                "  \"UID\": \"%s\",\n"
                "  \"Language\": 0,\n"
                "  \"Type\": 7,\n"
                "  \"Name\": \"%s\",\n"
                "  \"HasEncrypt\": true,\n"
                "  \"TemplateType\": 0,\n"
                "  \"IsPc\": false\n"
                "}\n", uid, name);
            fclose(f);
        }
    }
    free(work);
}

/* ---- commands ---------------------------------------------------------- */
static int cmd_info(const char *path)
{
    buf_t f;
    if (read_file(path, &f) != 0) {
        warn("cannot read %s", path);
        return 1;
    }
    if (f.len < 57 || memcmp(f.data, "MCPK", 4) != 0) {
        warn("not an MCPK file");
        buf_free(&f);
        return 1;
    }
    uint32_t dt = f.data[12] | (f.data[13] << 8) | (f.data[14] << 16) | ((uint32_t)f.data[15] << 24);
    uint32_t ib = f.data[16] | (f.data[17] << 8) | (f.data[18] << 16) | ((uint32_t)f.data[19] << 24);
    uint32_t db = f.data[20] | (f.data[21] << 8) | (f.data[22] << 16) | ((uint32_t)f.data[23] << 24);
    printf("magic      : %.4s\n", f.data);
    printf("dir table  : %u\n", dt);
    printf("index base : %u\n", ib);
    printf("data base  : %u\n", db);
    buf_free(&f);
    return 0;
}

static int run_pycdc(const char *pyc_root, const char *out_root)
{
    const char *pycdc = pycdc_binary();
    if (!pycdc) {
        warn("embedded pycdc is missing from this build");
        return -1;
    }
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1)
        ncpu = 1;
    char jobs[16];
    snprintf(jobs, sizeof jobs, "%ld", ncpu);

    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execl(pycdc, pycdc, "-q", "-j", jobs, "-o", out_root, pyc_root, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int cmd_unpack(const char *src, const char *out)
{
    double t0;

    t0 = now_secs();
    step("unpacking %s", src);
    mcpk_t m;
    memset(&m, 0, sizeof m);
    if (mcpk_unpack(src, &m) != 0) {
        warn("failed");
        return 1;
    }
    phase("mcpk extract", now_secs() - t0);

    /* Stage: write the .pyc files pycdc will read. */
    t0 = now_secs();
    char *stage = path_join(out, ".mcp_pyc");
    rmtree(stage);
    mkdir_p(stage);

    char *pyc_root = path_join(stage, "in");
    size_t npyc = 0, nfail = 0;
    char **names = xmalloc(sizeof(char *) * (m.count ? m.count : 1));
    size_t nnames = 0;

    for (size_t i = 0; i < m.count; i++) {
        const char *rel = m.files[i].rel_path;
        size_t rl = strlen(rel);
        if (rl < 4 || strcmp(rel + rl - 4, ".mcs") != 0)
            continue;
        buf_t pyc;
        if (mcs_decode(m.files[i].data, m.files[i].len, &pyc) != 0) {
            warn("cannot decode %s", rel);
            nfail++;
            buf_free(&pyc);
            continue;
        }
        char *pyrel = xmalloc(rl + 1);
        memcpy(pyrel, rel, rl + 1);
        memcpy(pyrel + rl - 3, "pyc", 3);      /* .mcs -> .pyc */
        write_at(pyc_root, pyrel, pyc.data, pyc.len);
        names[nnames++] = pyrel;
        npyc++;
        buf_free(&pyc);
    }
    phase("mcs decrypt", now_secs() - t0);

    if (npyc == 0) {
        warn("nothing to decompile");
        mcpk_free(&m);
        rmtree(stage);
        return 1;
    }

    t0 = now_secs();
    char *pyc_out = path_join(stage, "out");
    int prc = run_pycdc(pyc_root, pyc_out);
    phase("pycdc", now_secs() - t0);
    if (prc != 0) {
        /* pycdc died or refused the batch; reporting one line per file would
         * bury the actual cause under a hundred "no output" warnings. */
        warn("pycdc failed; nothing decompiled");
        mcpk_free(&m);
        rmtree(stage);
        free(pyc_root);
        free(pyc_out);
        free(stage);
        for (size_t i = 0; i < nnames; i++)
            free(names[i]);
        free(names);
        return 1;
    }

    t0 = now_secs();
    size_t ndone = 0;
    for (size_t i = 0; i < nnames; i++) {
        char *srcp = path_join(pyc_out, names[i]);
        size_t sl = strlen(srcp);
        memcpy(srcp + sl - 3, "py", 2);        /* .pyc -> .py */
        srcp[sl - 1] = '\0';
        buf_t src_buf;
        if (read_file(srcp, &src_buf) != 0) {
            warn("pycdc produced no output for %s", names[i]);
            free(srcp);
            nfail++;
            continue;
        }
        /* everything goes under BP/, except the loader bootstrap at the root */
        /* Always a fresh string: names[] is owned by the caller and freed at
         * the end, so aliasing it here would double free. */
        /* pycdc escapes non-ASCII inside string literals; make them readable.
         * Same bytes, so the compiled result is unchanged. */
        /* decoy bodies are malformed on purpose; collapse them before the
         * readability pass so the placeholders never reach the user */
        strip_obfuscation_decoys(&src_buf);
        if (unescape_utf8_literals(&src_buf))
            ensure_coding_decl(&src_buf);

        char *dst_rel;
        if (strchr(names[i], '/')) {
            dst_rel = xstrdup(names[i]);
        } else {
            dst_rel = xmalloc(strlen(".mcp_loader/") + strlen(names[i]) + 1);
            sprintf(dst_rel, ".mcp_loader/%s", names[i]);
        }
        size_t dl = strlen(dst_rel);
        dst_rel[dl - 3] = 'p'; dst_rel[dl - 2] = 'y'; dst_rel[dl - 1] = '\0';
        /* root-level files are the MCS loader bootstrap, not project sources */
        const char *root = (strchr(names[i], '/') != NULL) ? "BP" : "";
        char *base = *root ? path_join(out, root) : xstrdup(out);
        write_at(base, dst_rel, src_buf.data, src_buf.len);
        free(base);
        free(dst_rel);
        buf_free(&src_buf);
        free(srcp);
        ndone++;
    }
    phase("collect", now_secs() - t0);

    t0 = now_secs();
    char *bp = path_join(out, "BP");
    mkdir_p(bp);
    /* Project stub files the editor expects to find. */
    char *manifest = path_join(bp, "pack_manifest.json");
    if (access(manifest, F_OK) != 0)
        write_manifest(manifest, package_name(&m));
    free(manifest);
    write_editor_stubs(out, package_name(&m));
    free(bp);

    rmtree(stage);
    phase("layout", now_secs() - t0);

    step("unpacked %zu file(s) -> %s/BP", ndone, out);
    report_timings();

    for (size_t i = 0; i < nnames; i++)
        free(names[i]);
    free(names);
    free(pyc_root);
    free(pyc_out);
    free(stage);
    mcpk_free(&m);
    return nfail ? 1 : 0;
}

#ifndef MCP_VERSION
#define MCP_VERSION "dev"
#endif

static int usage(void)
{
    printf("mcp - MCPK unpacker / decompiler.\n\n"
           "Usage:\n"
           "    mcp unpack <input.mcp> [output_dir]     (writes decompiled .py sources)\n"
           "    mcp info   <input.mcp>\n\n"
           "Options:\n"
           "    -v, --verbose   show per-file details (default: only step summaries)\n"
           "    -V, --version   print the version and exit\n");
    return 0;
}

int main(int argc, char **argv)
{
    t_start = now_secs();

    /* Zero-filled: reading args[k] past the last real argument has to yield
     * NULL, not whatever happened to be on the stack. */
    char *args[8] = { 0 };
    int n = 0;
    for (int i = 1; i < argc && n < 8; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            verbose = 1;
            continue;
        }
        args[n++] = argv[i];
    }
    (void)verbose;

    if (n >= 1 && (!strcmp(args[0], "-V") || !strcmp(args[0], "--version")
                   || !strcmp(args[0], "version"))) {
        printf("mcp %s\n", MCP_VERSION);
        return 0;
    }

    if (n == 0 || !strcmp(args[0], "-h") || !strcmp(args[0], "--help")
        || !strcmp(args[0], "help"))
        return usage();

    if (!strcmp(args[0], "info")) {
        if (n < 2) {
            fprintf(stderr, "usage: mcp info <input.mcp>\n");
            return 1;
        }
        return cmd_info(args[1]);
    }
    if (!strcmp(args[0], "unpack")) {
        if (n < 2) {
            fprintf(stderr, "usage: mcp unpack <input.mcp> [output_dir]\n");
            return 1;
        }
        const char *out = (n > 2) ? args[2] : NULL;
        char *derived = NULL;
        if (!out) {
            const char *base = strrchr(args[1], '/');
            base = base ? base + 1 : args[1];
            derived = xstrdup(base);
            char *dot = strrchr(derived, '.');
            if (dot)
                *dot = '\0';
            out = derived;
        }
        int rc = cmd_unpack(args[1], out);
        free(derived);
        return rc;
    }
    fprintf(stderr, "[!] unknown command: %s\n", args[0]);
    usage();
    return 1;
}
