/* gta6_tag.dll - compute the GTA VI save tag without the 120 MB game exe.
 *
 * Loads gta6_tag_blob.bin (the extracted code + lookup tables, ~0.9 MB) next to
 * this DLL, maps it at the original virtual addresses, and calls the game's own
 * init/update/final to produce the 32-byte tag.
 *
 * Export:  int compute_tag(const unsigned char* data, unsigned long long len,
 *                          unsigned char out[32]);
 *          returns 0 on success, nonzero on error.
 *
 * Build (x64):  see build_helper.bat   (cl /LD gta6_tag.c)
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define IMAGE_BASE 0x140000000ULL
#define INIT_RVA   (0x145603F60ULL - IMAGE_BASE)
#define UPDATE_RVA (0x145604100ULL - IMAGE_BASE)
#define FINAL_RVA  (0x145604180ULL - IMAGE_BASE)
#define BLOB_RVA   (0x1466FD190ULL - IMAGE_BASE)
#define GUARD_VA   0x146F11530ULL
#define IAT_MEMCPY 0x146794358ULL
#define IAT_MEMSET 0x146794368ULL
#define IAT_MALLOC 0x1467948F0ULL
#define IAT_FREE   0x1467948E8ULL
#define TAG_OK     564457155u

typedef unsigned int (*init_fn)(void* blob, void** ctx);
typedef unsigned int (*update_fn)(void* ctx, const void* data, unsigned long long len);
typedef unsigned int (*final_fn)(void* ctx, void* out);

static unsigned char* g_base = NULL;

static int page_commit(unsigned char* base, uint64_t va, uint64_t len) {
    uint64_t p = (va / 0x1000) * 0x1000;
    uint64_t end = ((va + len + 0xFFF) / 0x1000) * 0x1000;
    void* r = VirtualAlloc(base + (p - IMAGE_BASE), (SIZE_T)(end - p), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return r != NULL;
}

static int load_helper(void) {
    char path[MAX_PATH];
    HMODULE hm = NULL;
    FILE* f;
    long sz;
    unsigned char* data;
    uint32_t n, i;
    size_t off;
    uint64_t hi = 0, span, base;
    char* s;

    if (g_base) return 0;

    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&load_helper, &hm);
    GetModuleFileNameA(hm, path, MAX_PATH);
    s = strrchr(path, '\\');
    if (s) strcpy(s + 1, "gta6_tag_blob.bin"); else strcpy(path, "gta6_tag_blob.bin");

    f = fopen(path, "rb");
    if (!f) return 10;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    data = (unsigned char*)malloc(sz);
    if (!data) { fclose(f); return 11; }
    if (fread(data, 1, sz, f) != (size_t)sz) { fclose(f); free(data); return 12; }
    fclose(f);

    n = *(uint32_t*)data; off = 4;
    for (i = 0; i < n; i++) {
        uint64_t va = *(uint64_t*)(data + off); off += 8;
        uint32_t ln = *(uint32_t*)(data + off); off += 4;
        if (va + ln - IMAGE_BASE > hi) hi = va + ln - IMAGE_BASE;
        off += ln;
    }
    if ((GUARD_VA - IMAGE_BASE) + 16 > hi) hi = (GUARD_VA - IMAGE_BASE) + 16;
    span = (hi + 0xFFFF) & ~0xFFFFULL;

    base = (uint64_t)VirtualAlloc((void*)IMAGE_BASE, (SIZE_T)span, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) base = (uint64_t)VirtualAlloc(NULL, (SIZE_T)span, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) { free(data); return 13; }
    g_base = (unsigned char*)base;

    off = 4;
    for (i = 0; i < n; i++) {
        uint64_t va = *(uint64_t*)(data + off); off += 8;
        uint32_t ln = *(uint32_t*)(data + off); off += 4;
        if (!page_commit(g_base, va, ln)) { free(data); return 14; }
        memcpy(g_base + (va - IMAGE_BASE), data + off, ln);
        off += ln;
    }
    free(data);

    page_commit(g_base, GUARD_VA, 1);
    *(g_base + (GUARD_VA - IMAGE_BASE)) = 1;

    *(void**)(g_base + (IAT_MEMCPY - IMAGE_BASE)) = (void*)&memcpy;
    *(void**)(g_base + (IAT_MEMSET - IMAGE_BASE)) = (void*)&memset;
    *(void**)(g_base + (IAT_MALLOC - IMAGE_BASE)) = (void*)&malloc;
    *(void**)(g_base + (IAT_FREE - IMAGE_BASE))   = (void*)&free;
    return 0;
}

__declspec(dllexport) int compute_tag(const unsigned char* data, unsigned long long len, unsigned char out[32]) {
    int rc;
    init_fn init; update_fn update; final_fn final;
    void* ctx = NULL;
    unsigned char dummy = 0;

    rc = load_helper();
    if (rc) return rc;

    init   = (init_fn)(g_base + INIT_RVA);
    update = (update_fn)(g_base + UPDATE_RVA);
    final  = (final_fn)(g_base + FINAL_RVA);

    if (init((void*)(g_base + BLOB_RVA), &ctx) != TAG_OK) return 20;
    if (update(ctx, len ? data : &dummy, len) != TAG_OK) return 21;
    if (final(ctx, out) != TAG_OK) return 22;
    return 0;
}

/* Optional CLI: gta6_tag.exe <hex-payload>  (built only if compiled as an exe) */
#ifdef BUILD_EXE
int main(int argc, char** argv) {
    unsigned char out[32], *buf; unsigned long long len = 0; int i;
    if (argc < 2) { fprintf(stderr, "usage: gta6_tag <hex>\n"); return 2; }
    len = strlen(argv[1]) / 2;
    buf = (unsigned char*)malloc(len ? len : 1);
    for (i = 0; i < (int)len; i++) sscanf(argv[1] + 2 * i, "%2hhx", &buf[i]);
    if (compute_tag(buf, len, out)) { fprintf(stderr, "error\n"); return 1; }
    for (i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
#endif
