/*
 * fma_hook.cpp — CUDA module interceptor for the CMP 170HX FMA bypass.
 *
 * Injected into libcuda.so via patchelf --add-needed.  Overrides
 * cuModuleLoad*, rewrites FFMA → FMUL+FADD via rewriter_daemon.py on a
 * Unix socket.  Results are SHA-256 cached on disk.
 *
 * Protocol over SOCKET_PATH (one connection per call):
 *   Request:  [uint32_t length, network byte order][cubin bytes]
 *   Response: [uint32_t length, network byte order][rewritten cubin bytes]
 *             response length == 0 → no change, use original
 *
 * Build: src/fma/build_fma.sh
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <mutex>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#include <string>
#include "sha256.h"

extern "C" {
#include <cuda.h>
}

#define SOCKET_PATH "/var/run/cmppatcher-rewriter.sock"
#define CACHE_DIR   "/etc/cmppatcher/cache"
#define LOG_PATH    "/var/log/cmppatcher-fma.log"

// nvcc wrapper magic (__fatBinC_Wrapper_t)
#define FATBIN_WRAPPER_MAGIC 0x466243B1U
// Inner fatbin payload magic (CUDA 7+): bytes 50 ED 55 BA
#define FATBIN_PAYLOAD_MAGIC 0xBA55ED50U

static std::mutex g_mutex;
static void *g_libcuda_handle = nullptr;

// Real dlsym — obtained via dlvsym to avoid bootstrap recursion.
typedef void *(*real_dlsym_t)(void *, const char *);
static real_dlsym_t _real_dlsym = nullptr;

static void *resolve_real_symbol(const char *name) {
    if (!_real_dlsym)
        _real_dlsym = (real_dlsym_t)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    if (!_real_dlsym || !name) return nullptr;

    void *p = nullptr;
    if (g_libcuda_handle) p = _real_dlsym(g_libcuda_handle, name);
    if (!p) p = _real_dlsym(RTLD_NEXT, name);
    if (!p) p = _real_dlsym(RTLD_DEFAULT, name);
    if (!p) {
        void *h = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
        if (h) {
            if (!g_libcuda_handle) g_libcuda_handle = h;
            p = _real_dlsym(h, name);
        }
    }
    return p;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

static void log_msg(const char *fmt, ...) {
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
    close(fd);
}

// ---------------------------------------------------------------------------
// SHA-256 cache key
// ---------------------------------------------------------------------------

static std::string cache_key(const void *data, size_t size) {
    uint8_t digest[32];
    sha256((const uint8_t *)data, size, digest);
    char hex[65] = {};
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", (unsigned)digest[i]);
    return std::string(CACHE_DIR "/") + hex + ".cubin";
}

static std::vector<uint8_t> cache_get(const std::string &path) {
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return {}; }
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf((size_t)sz);
    size_t n = fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    buf.resize(n);
    return buf;
}

static void cache_put(const std::string &path,
                      const uint8_t *data, size_t size) {
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) return;
    fwrite(data, 1, size, f);
    fclose(f);
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

static bool write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

static bool read_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

// ---------------------------------------------------------------------------
// IPC: send cubin to daemon, receive rewritten cubin
// ---------------------------------------------------------------------------

static std::vector<uint8_t> ipc_rewrite(const void *cubin, size_t size) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return {};

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return {};  // Daemon not running — graceful degradation
    }

    uint32_t req_len = htonl((uint32_t)size);
    bool ok = write_all(sock, &req_len, 4) && write_all(sock, cubin, size);
    if (!ok) { close(sock); return {}; }

    uint32_t resp_len_be = 0;
    if (!read_all(sock, &resp_len_be, 4)) { close(sock); return {}; }

    uint32_t resp_len = ntohl(resp_len_be);
    if (resp_len == 0) { close(sock); return {}; }

    std::vector<uint8_t> out((size_t)resp_len);
    ok = read_all(sock, out.data(), resp_len);
    close(sock);
    return ok ? out : std::vector<uint8_t>{};
}

// ---------------------------------------------------------------------------
// ELF helpers
// ---------------------------------------------------------------------------

static bool is_cuda_elf(const void *data, size_t available) {
    if (!data || available < 16) return false;
    const uint8_t *m = (const uint8_t *)data;
    return m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F';
}

static size_t elf_size_hint(const void *data) {
    const Elf64_Ehdr *h = (const Elf64_Ehdr *)data;
    size_t sh_end = (size_t)h->e_shoff + (size_t)h->e_shentsize * h->e_shnum;
    size_t ph_end = (size_t)h->e_phoff + (size_t)h->e_phentsize * h->e_phnum;
    return (sh_end > ph_end ? sh_end : ph_end) + 512;
}

// ---------------------------------------------------------------------------
// Main rewrite logic
// ---------------------------------------------------------------------------

static std::vector<uint8_t> rewrite_if_needed(const void *image) {
    if (!image) return {};

    const uint8_t *scan_ptr = (const uint8_t *)image;
    const uint32_t first_word = *(const uint32_t *)scan_ptr;
    if (first_word == FATBIN_WRAPPER_MAGIC) {
        const uint8_t *wrapped = (const uint8_t *)*(const uint64_t *)(scan_ptr + 8);
        if (!wrapped) return {};
        scan_ptr = wrapped;
    }

    const void  *cubin      = scan_ptr;
    size_t       cubin_size = 0;

    // Detect inner fatbinary payload
    const uint32_t payload_magic = *(const uint32_t *)scan_ptr;
    if (payload_magic == FATBIN_PAYLOAD_MAGIC) {
        // fatbinary header: magic(4) + version(2) + headerSize(2) + fatSize(8)
        uint64_t fat_size = *(const uint64_t *)(scan_ptr + 8);
        if (fat_size < 32 || fat_size > (1ULL << 30)) return {};

        const uint8_t *p   = scan_ptr;
        const uint8_t *end = p + fat_size;
        cubin = nullptr;
        for (const uint8_t *q = p; q + 16 < end; q++) {
            if (q[0]==0x7f && q[1]=='E' && q[2]=='L' && q[3]=='F') {
                const Elf64_Ehdr *eh = (const Elf64_Ehdr *)q;
                // e_machine 0xBE = EM_CUDA
                if (eh->e_machine == 0xBE || eh->e_machine == 190) {
                    cubin      = q;
                    cubin_size = elf_size_hint(eh);
                    break;
                }
            }
        }
        if (!cubin) return {};
    }

    if (!is_cuda_elf(cubin, 64)) return {};
    if (cubin_size == 0) cubin_size = elf_size_hint(cubin);

    std::string cpath = cache_key(cubin, cubin_size);
    auto cached = cache_get(cpath);
    if (!cached.empty()) {
        log_msg("[fma_hook] cache hit pid=%d size=%zu\n", getpid(), cubin_size);
        return cached;
    }

    auto rewritten = ipc_rewrite(cubin, cubin_size);
    if (rewritten.empty()) return {};

    cache_put(cpath, rewritten.data(), rewritten.size());
    log_msg("[fma_hook] rewritten %zu->%zu bytes pid=%d\n",
            cubin_size, rewritten.size(), getpid());
    return rewritten;
}

// ---------------------------------------------------------------------------
// cuModuleLoad* overrides (exported symbols override libcuda.so's PLT)
// ---------------------------------------------------------------------------

typedef CUresult (*cuModuleLoadDataEx_t)(CUmodule *, const void *,
                                         unsigned int, CUjit_option *, void **);
typedef CUresult (*cuModuleLoad_t)(CUmodule *, const char *);
typedef CUresult (*cuModuleLoadFatBinary_t)(CUmodule *, const void *);

// CUDA 12+ library loading API
typedef CUresult (*cuLibraryLoadData_t)(
    CUlibrary *, const void *,
    CUjit_option *, void **, unsigned int,
    CUlibraryOption *, void **, unsigned int);
typedef CUresult (*cuLibraryLoadFromFile_t)(
    CUlibrary *, const char *,
    CUjit_option *, void **, unsigned int,
    CUlibraryOption *, void **, unsigned int);

static CUresult dispatch(const void *image,
                          CUmodule *mod,
                          unsigned int n_opts,
                          CUjit_option *opts,
                          void **vals) {
    std::lock_guard<std::mutex> lk(g_mutex);

    auto rewritten = rewrite_if_needed(image);
    const void *use = rewritten.empty() ? image : (const void *)rewritten.data();

    static cuModuleLoadDataEx_t real_ex = nullptr;
    if (!real_ex)
        real_ex = (cuModuleLoadDataEx_t)resolve_real_symbol("cuModuleLoadDataEx");
    if (!real_ex) {
        log_msg("[fma_hook] dispatch: real cuModuleLoadDataEx not found\n");
        return CUDA_ERROR_NOT_SUPPORTED;
    }
    CUresult r = real_ex(mod, use, n_opts, opts, vals);
    log_msg("[fma_hook] dispatch: cuModuleLoadDataEx returned %d rewritten=%d\n",
            (int)r, rewritten.empty() ? 0 : 1);
    return r;
}

extern "C" {

__attribute__((visibility("default")))
CUresult cuModuleLoadData(CUmodule *mod, const void *image) {
    return dispatch(image, mod, 0, nullptr, nullptr);
}

__attribute__((visibility("default")))
CUresult cuModuleLoadDataEx(CUmodule *mod, const void *image,
                             unsigned int n, CUjit_option *opts, void **vals) {
    return dispatch(image, mod, n, opts, vals);
}

__attribute__((visibility("default")))
CUresult cuModuleLoad(CUmodule *mod, const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) {
        static cuModuleLoad_t real = nullptr;
        if (!real) real = (cuModuleLoad_t)resolve_real_symbol("cuModuleLoad");
        return real(mod, fname);
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf((size_t)sz);
    size_t n = fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    buf.resize(n);
    return dispatch(buf.data(), mod, 0, nullptr, nullptr);
}

__attribute__((visibility("default")))
CUresult cuModuleLoadFatBinary(CUmodule *mod, const void *fatCubin) {
    std::lock_guard<std::mutex> lk(g_mutex);
    auto rewritten = rewrite_if_needed(fatCubin);
    if (!rewritten.empty()) {
        static cuModuleLoadDataEx_t real_ex = nullptr;
        if (!real_ex)
            real_ex = (cuModuleLoadDataEx_t)resolve_real_symbol("cuModuleLoadDataEx");
        if (!real_ex) return CUDA_ERROR_NOT_SUPPORTED;
        return real_ex(mod, rewritten.data(), 0, nullptr, nullptr);
    }

    static cuModuleLoadFatBinary_t real_fat = nullptr;
    if (!real_fat)
        real_fat = (cuModuleLoadFatBinary_t)resolve_real_symbol("cuModuleLoadFatBinary");
    if (!real_fat) {
        log_msg("[fma_hook] cuModuleLoadFatBinary: real not found\n");
        return CUDA_ERROR_NOT_SUPPORTED;
    }
    CUresult r = real_fat(mod, fatCubin);
    log_msg("[fma_hook] cuModuleLoadFatBinary returned %d rewritten=%d\n",
            (int)r, rewritten.empty() ? 0 : 1);
    return r;
}

// CUDA 12+ cuLibraryLoadData
__attribute__((visibility("default")))
CUresult cuLibraryLoadData(
    CUlibrary *lib, const void *code,
    CUjit_option *jit_opts, void **jit_vals, unsigned int n_jit,
    CUlibraryOption *lib_opts, void **lib_vals, unsigned int n_lib)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    auto rewritten = rewrite_if_needed(code);
    const void *use = rewritten.empty() ? code : (const void *)rewritten.data();

    static cuLibraryLoadData_t real = nullptr;
    if (!real)
        real = (cuLibraryLoadData_t)resolve_real_symbol("cuLibraryLoadData");
    if (!real) {
        log_msg("[fma_hook] cuLibraryLoadData: real not found\n");
        return CUDA_ERROR_NOT_SUPPORTED;
    }
    CUresult r = real(lib, use, jit_opts, jit_vals, n_jit, lib_opts, lib_vals, n_lib);
    log_msg("[fma_hook] cuLibraryLoadData returned %d rewritten=%d\n",
            (int)r, rewritten.empty() ? 0 : 1);
    return r;
}

// CUDA 12+ cuLibraryLoadFromFile
__attribute__((visibility("default")))
CUresult cuLibraryLoadFromFile(
    CUlibrary *lib, const char *fname,
    CUjit_option *jit_opts, void **jit_vals, unsigned int n_jit,
    CUlibraryOption *lib_opts, void **lib_vals, unsigned int n_lib)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    FILE *f = fopen(fname, "rb");
    if (!f) {
        static cuLibraryLoadFromFile_t real = nullptr;
        if (!real)
            real = (cuLibraryLoadFromFile_t)resolve_real_symbol("cuLibraryLoadFromFile");
        if (!real) return CUDA_ERROR_NOT_SUPPORTED;
        return real(lib, fname, jit_opts, jit_vals, n_jit, lib_opts, lib_vals, n_lib);
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf((size_t)sz);
    size_t n = fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    buf.resize(n);

    auto rewritten = rewrite_if_needed(buf.data());
    const void *use = rewritten.empty() ? (const void *)buf.data()
                                        : (const void *)rewritten.data();

    static cuLibraryLoadData_t real_data = nullptr;
    if (!real_data)
        real_data = (cuLibraryLoadData_t)resolve_real_symbol("cuLibraryLoadData");
    if (!real_data) return CUDA_ERROR_NOT_SUPPORTED;

    return real_data(lib, use, jit_opts, jit_vals, n_jit, lib_opts, lib_vals, n_lib);
}

// ---------------------------------------------------------------------------
// cuGetProcAddress hook — CUDA 12+ runtimes call this to fetch all function
// pointers at startup, bypassing the dynamic linker entirely.  We intercept
// it and substitute our hooks for the module/library loading symbols.
// ---------------------------------------------------------------------------

extern "C" CUresult cuGetProcAddress_shim(const char *sym, void **pfn, int ver, cuuint64_t flags, ...);

static void *_hook_for(const char *sym) {
    if (!sym) return nullptr;
#define H(n) if (strcmp(sym, #n) == 0) return (void *)(n);
    H(cuModuleLoadData)
    H(cuModuleLoadDataEx)
    H(cuModuleLoad)
    H(cuModuleLoadFatBinary)
    H(cuLibraryLoadData)
    H(cuLibraryLoadFromFile)
    if (strcmp(sym, "cuGetProcAddress") == 0) return (void *)cuGetProcAddress_shim;
    H(cuGetProcAddress_v2)
#undef H
    return nullptr;
}

// 5-param version (CUDA 12.3+, underlying symbol for the cuGetProcAddress macro)
typedef CUresult (*cuGetProcAddress_v2_t)(const char *, void **, int,
                                          cuuint64_t,
                                          CUdriverProcAddressQueryResult *);
static cuGetProcAddress_v2_t g_real_cuGetProcAddress_v2 = nullptr;
extern "C" CUresult cuGetProcAddress_shim(const char *sym, void **pfn, int ver, cuuint64_t flags, ...);

static cuGetProcAddress_v2_t resolve_real_cuGetProcAddress_v2() {
    if (g_real_cuGetProcAddress_v2) return g_real_cuGetProcAddress_v2;
    if (!_real_dlsym)
        _real_dlsym = (real_dlsym_t)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    if (!_real_dlsym) return nullptr;

    void *p = nullptr;
    if (g_libcuda_handle)
        p = _real_dlsym(g_libcuda_handle, "cuGetProcAddress_v2");
    if (!p) p = _real_dlsym(RTLD_NEXT, "cuGetProcAddress_v2");
    if (!p) p = _real_dlsym(RTLD_DEFAULT, "cuGetProcAddress_v2");
    if (!p) {
        void *h = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
        if (h) {
            if (!g_libcuda_handle) g_libcuda_handle = h;
            p = _real_dlsym(h, "cuGetProcAddress_v2");
        }
    }
    if (p == (void *)cuGetProcAddress_v2) return nullptr;
    g_real_cuGetProcAddress_v2 = (cuGetProcAddress_v2_t)p;
    return g_real_cuGetProcAddress_v2;
}

__attribute__((visibility("default")))
CUresult cuGetProcAddress_v2(const char *sym, void **pfn, int ver,
                              cuuint64_t flags,
                              CUdriverProcAddressQueryResult *status)
{
    if (sym && pfn && strcmp(sym, "cuGetProcAddress") == 0) {
        *pfn = (void *)cuGetProcAddress_shim;
        if (status) *status = CU_GET_PROC_ADDRESS_SUCCESS;
        return CUDA_SUCCESS;
    }
    static cuGetProcAddress_v2_t real = nullptr;
    if (!real)
        real = resolve_real_cuGetProcAddress_v2();
    if (!real) return CUDA_ERROR_NOT_SUPPORTED;
    CUresult r = real(sym, pfn, ver, flags, status);
    if (r == CUDA_SUCCESS && pfn) {
        void *h = _hook_for(sym);
        if (h) *pfn = h;
    }
    return r;
}

__attribute__((visibility("default")))
CUresult cuGetProcAddress_shim(const char *sym, void **pfn, int ver, cuuint64_t flags, ...) {
    return cuGetProcAddress_v2(sym, pfn, ver, flags, nullptr);
}


__attribute__((visibility("default")))
void *dlsym(void *handle, const char *symbol) {
    if (!_real_dlsym)
        _real_dlsym = (real_dlsym_t)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    if (!_real_dlsym) return nullptr;
    // Don't intercept our own RTLD_NEXT lookups — that would recurse forever.
    if (handle == RTLD_NEXT || handle == RTLD_DEFAULT)
        return _real_dlsym(handle, symbol);
    void *result = _real_dlsym(handle, symbol);
    if (result && symbol && strcmp(symbol, "cuGetProcAddress_v2") == 0) {
        g_libcuda_handle = handle;
        g_real_cuGetProcAddress_v2 = (cuGetProcAddress_v2_t)result;
    }
    if (result && symbol) {
        void *hook = _hook_for(symbol);
        if (hook) return hook;
    }
    return result;
}

__attribute__((constructor))
void fma_hook_init() {
    _real_dlsym = (real_dlsym_t)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    log_msg("[fma_hook] loaded into pid=%d\n", getpid());
    mkdir(CACHE_DIR, 0755);
}

} // extern "C"
