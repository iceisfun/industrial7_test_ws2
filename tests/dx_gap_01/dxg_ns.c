/* Name-space provider install with a provider-specific blob, boundary string lengths and read-back:
 * WSCInstallNameSpace / WSCInstallNameSpaceEx (+32 forms) with WSCUnInstallNameSpace(32) and
 * WSCEnableNSProvider(32), plus a refused chained install whose library has no provider entry point.
 *
 * An Ex install stores the blob verbatim next to the record; the extended enumeration returns it (size and
 * bytes), the plain install stores none. A path may be up to 259 characters, an identifier somewhat shorter. A second install
 * under the same id is refused and the first record keeps its blob. New records are appended after the stock
 * ones. The native name-space list is cached per process, so it is read back in a fresh process; the 32-bit
 * list is read directly. All ids are throwaway (marker plus index); every test uninstalls what it added and
 * the catalogs are compared with the starting state at the end. Skipped unless elevated. */
#include "dxg.h"

typedef int (WSAAPI *ns_inst_t)(const WCHAR *, const WCHAR *, DWORD, DWORD, const GUID *);
typedef int (WSAAPI *ns_instex_t)(const WCHAR *, const WCHAR *, DWORD, DWORD, const GUID *, const BLOB *);
typedef int (WSAAPI *ns_un_t)(const GUID *);
typedef int (WSAAPI *ns_en_t)(const GUID *, BOOL);
typedef INT (WSAAPI *nsx_enum_t)(LPDWORD, LPWSANAMESPACE_INFOEXW);

#define NS_NUM 0x7e57u
static const WCHAR PATH[] = L"%SystemRoot%\\system32\\dxg1_no_such_nsp.dll";
static const WCHAR NAME[] = L"dxg1 namespace";
#define N_IDS 6

static GUID id_of(unsigned idx)
{
    GUID g = { 0x77733274, 0xD0C1, 0x7A01, { 0x6e, 0x73, 0x78, 0x67, 0x00, 0x00, 0x00, 0x00 } };
    g.Data4[6] = (BYTE)(idx >> 8); g.Data4[7] = (BYTE)idx;
    return g;
}
static void fill_blob(BYTE *b, int n, unsigned idx) { for (int i = 0; i < n; i++) b[i] = (BYTE)(i * 7 + idx); }

static int install(int wow, const WCHAR *name, const WCHAR *path, DWORD ns, DWORD ver, const GUID *g, const BLOB *b, int ex)
{
    const char *fn = ex ? (wow ? "WSCInstallNameSpaceEx32" : "WSCInstallNameSpaceEx") : (wow ? "WSCInstallNameSpace32" : "WSCInstallNameSpace");
    void *f = dxg_fn(fn);
    if (!f) return -2;
    SetLastError(0x1234);
    return ex ? ((ns_instex_t)f)(name, path, ns, ver, g, b) : ((ns_inst_t)f)(name, path, ns, ver, g);
}
static int uninstall(int wow, const GUID *g)
{
    ns_un_t f = (ns_un_t)dxg_fn(wow ? "WSCUnInstallNameSpace32" : "WSCUnInstallNameSpace");
    return f ? f(g) : -2;
}
static int enable(int wow, const GUID *g, BOOL on)
{
    ns_en_t f = (ns_en_t)dxg_fn(wow ? "WSCEnableNSProvider32" : "WSCEnableNSProvider");
    return f ? f(g, on) : -2;
}

/* ---- read-back through the extended enumeration ---- */
static int ex_enum(int wow, WSANAMESPACE_INFOEXW **out, int *count)
{
    nsx_enum_t f = (nsx_enum_t)dxg_fn(wow ? "WSCEnumNameSpaceProvidersEx32" : "WSAEnumNameSpaceProvidersExW");
    WSANAMESPACE_INFOEXW *buf = NULL; DWORD len = 0; INT n = -1;
    *out = NULL; *count = 0;
    if (!f) return -1;
    if (!wow && dxg_up()) return -1;
    for (int tries = 0; tries < 4; tries++) {
        n = f(&len, buf);
        if (n >= 0 && n != SOCKET_ERROR) break;
        n = -1;
        if (!len) break;
        free(buf); buf = (WSANAMESPACE_INFOEXW *)calloc(1, len);
        if (!buf) return -1;
    }
    if (n < 0) { free(buf); return -1; }
    *out = buf; *count = n;
    return 0;
}

/* 0 present and matching, 1 absent, 2 present with a different field, 3 enumeration failed, 4 not last. */
static int check_entry(int wow, unsigned idx, long ver, int active, long blobsz, long ident_len, int must_be_last)
{
    WSANAMESPACE_INFOEXW *e; int n, rc = 1; GUID g = id_of(idx);
    if (ex_enum(wow, &e, &n)) return 3;
    for (int i = 0; i < n; i++) {
        if (memcmp(&e[i].NSProviderId, &g, sizeof g)) continue;
        rc = 0;
        if (e[i].dwNameSpace != NS_NUM) rc = 2;
        if (ver >= 0 && e[i].dwVersion != (DWORD)ver) rc = 2;
        if (active >= 0 && (e[i].fActive != 0) != (active != 0)) rc = 2;
        if (blobsz >= 0) {
            if (e[i].ProviderSpecific.cbSize != (ULONG)blobsz) rc = 2;
            else if (blobsz > 0) {
                BYTE want[8192]; fill_blob(want, (int)blobsz, idx);
                if (!e[i].ProviderSpecific.pBlobData || memcmp(e[i].ProviderSpecific.pBlobData, want, (size_t)blobsz)) rc = 2;
            }
        }
        if (ident_len >= 0 && (!e[i].lpszIdentifier || lstrlenW(e[i].lpszIdentifier) != ident_len)) rc = 2;
        if (rc == 0 && must_be_last && i != n - 1) rc = 4;
    }
    free(e);
    return rc;
}

CHILD(dxg_nscheck)
{
    /* args: idx ver active blobsz ident_len last */
    if (argc < 7) return 99;
    return check_entry(0, (unsigned)atoi(argv[1]), atol(argv[2]), atoi(argv[3]), atol(argv[4]), atol(argv[5]), atoi(argv[6]));
}
static int check(int wow, unsigned idx, long ver, int active, long blobsz, long ident_len, int last)
{
    char a[128]; DWORD rc;
    if (wow) return check_entry(1, idx, ver, active, blobsz, ident_len, last);
    snprintf(a, sizeof a, "%u %ld %d %ld %ld %d", idx, ver, active, blobsz, ident_len, last);
    rc = t_run_child("dxg_nscheck", a, 30000);
    return rc > 99 ? 3 : (int)rc;
}

/* ---- guard and sweep ---- */
static int g_state;      /* 0 untried, 1 ready, -1 refused */
static dxg_snapshot g_base;
static int g_atexit;

static void sweep(void)
{
    for (unsigned i = 1; i <= N_IDS; i++) {
        GUID g = id_of(i);
        uninstall(0, &g); uninstall(1, &g);
    }
}
static int begin(int wow)
{
    if (g_state == 0) {
        if (!dxg_elevated()) g_state = -1;
        else if (dxg_up()) g_state = -1;
        else { sweep(); dxg_snap(&g_base); g_state = 1; if (!g_atexit) { g_atexit = 1; atexit(sweep); } }
    }
    if (g_state < 0) { t_skip("needs an elevated process and a started stack"); return 0; }
    if (wow) { dxg_sig s; if (dxg_ns32_sig(&s)) { t_skip("32-bit name-space catalog not available"); return 0; } }
    return 1;
}
#define BEGIN(w) do { if (!begin(w)) return; } while (0)
static void end(void)
{
    sweep();
    CHECKF(dxg_snap_same(&g_base), "catalogs differ from the starting state");
}

/* ---- round trips with a blob ---- */
static void blob_roundtrip(int wow, int size, int use_null_data)
{
    GUID g = id_of(1); BYTE data[8192]; BLOB b;
    BEGIN(wow);
    fill_blob(data, size, 1);
    b.cbSize = size; b.pBlobData = (use_null_data || size == 0) ? NULL : data;
    if (use_null_data && size) { t_skip("row needs data"); return; }
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 3, &g, &b, 1), 0);
    if (size == 0) EXPECT_EQ(check(wow, 1, 3, -1, 0, -1, 0), 0);
    else EXPECT_EQ(check(wow, 1, 3, -1, size, -1, 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    EXPECT_EQ(check(wow, 1, -1, -1, -1, -1, 0), 1);
    end();
}
#define BLOB_TESTS(w, tag) \
    TEST(dxg1_nsex_##tag##_blob_1_byte) { blob_roundtrip(w, 1, 0); } \
    TEST(dxg1_nsex_##tag##_blob_5_bytes) { blob_roundtrip(w, 5, 0); } \
    TEST(dxg1_nsex_##tag##_blob_255_bytes) { blob_roundtrip(w, 255, 0); } \
    TEST(dxg1_nsex_##tag##_blob_256_bytes) { blob_roundtrip(w, 256, 0); } \
    TEST(dxg1_nsex_##tag##_blob_4096_bytes) { blob_roundtrip(w, 4096, 0); } \
    TEST(dxg1_nsex_##tag##_blob_zero_size_null_data) { blob_roundtrip(w, 0, 1); }
BLOB_TESTS(0, native)
BLOB_TESTS(1, wow)

static void null_blob_has_size_zero(int wow, int ex)
{
    GUID g = id_of(2);
    BEGIN(wow);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 1, &g, NULL, ex), 0);
    EXPECT_EQ(check(wow, 2, 1, -1, 0, -1, 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_null_blob_size_zero) { null_blob_has_size_zero(0, 1); }
TEST(dxg1_nsex_wow_null_blob_size_zero) { null_blob_has_size_zero(1, 1); }
TEST(dxg1_ns_native_plain_install_has_no_blob) { null_blob_has_size_zero(0, 0); }
TEST(dxg1_ns_wow_plain_install_has_no_blob) { null_blob_has_size_zero(1, 0); }

/* ---- the second install under the same id is refused and the first keeps its blob ---- */
static void dup_keeps_first(int wow)
{
    GUID g = id_of(3); BYTE d1[16], d2[32]; BLOB b1 = { 16, d1 }, b2 = { 32, d2 };
    BEGIN(wow);
    fill_blob(d1, 16, 3); memset(d2, 0xee, sizeof d2);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 4, &g, &b1, 1), 0);
    EXPECT_EQ(install(wow, L"dxg1 other", PATH, NS_NUM + 1, 9, &g, &b2, 1), -1);
    EXPECT_EQ(GetLastError(), DXGE_INVAL);
    EXPECT_EQ(check(wow, 3, 4, -1, 16, (long)lstrlenW(NAME), 0), 0);
    EXPECT_EQ(install(wow, L"dxg1 other", PATH, NS_NUM, 9, &g, NULL, 0), -1);
    EXPECT_EQ(GetLastError(), DXGE_INVAL);
    EXPECT_EQ(check(wow, 3, 4, -1, 16, (long)lstrlenW(NAME), 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_second_install_keeps_first_record) { dup_keeps_first(0); }
TEST(dxg1_nsex_wow_second_install_keeps_first_record) { dup_keeps_first(1); }

/* ---- the two catalogs are independent ---- */
static void independent(int wow)
{
    GUID g = id_of(4);
    BEGIN(1);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 1, &g, NULL, 1), 0);
    EXPECT_EQ(check(wow, 4, -1, -1, -1, -1, 0), 0);
    EXPECT_EQ(check(!wow, 4, -1, -1, -1, -1, 0), 1);
    EXPECT_EQ(uninstall(!wow, &g), -1);
    EXPECT_EQ(check(wow, 4, -1, -1, -1, -1, 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_install_not_in_wow_catalog) { independent(0); }
TEST(dxg1_nsex_wow_install_not_in_native_catalog) { independent(1); }

/* ---- version, activation, ordering ---- */
static void version_row(int wow, DWORD ver)
{
    GUID g = id_of(5);
    BEGIN(wow);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, ver, &g, NULL, 1), 0);
    EXPECT_EQ(check(wow, 5, (long)ver, -1, 0, -1, 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_version_zero) { version_row(0, 0); }
TEST(dxg1_nsex_native_version_one) { version_row(0, 1); }
TEST(dxg1_nsex_native_version_large) { version_row(0, 0x7fffffffu); }
TEST(dxg1_nsex_wow_version_zero) { version_row(1, 0); }
TEST(dxg1_nsex_wow_version_one) { version_row(1, 1); }
TEST(dxg1_nsex_wow_version_large) { version_row(1, 0x7fffffffu); }

static void appended_last(int wow)
{
    GUID g = id_of(1), h = id_of(2);
    BEGIN(wow);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 1, &g, NULL, 1), 0);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 1, &h, NULL, 1), 0);
    EXPECT_EQ(check(wow, 2, -1, -1, -1, -1, 1), 0);
    EXPECT_EQ(check(wow, 1, -1, -1, -1, -1, 0), 0);
    EXPECT_EQ(uninstall(wow, &h), 0);
    EXPECT_EQ(check(wow, 1, -1, -1, -1, -1, 1), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_records_are_appended) { appended_last(0); }
TEST(dxg1_nsex_wow_records_are_appended) { appended_last(1); }

static void enable_keeps_blob(int wow)
{
    GUID g = id_of(1); BYTE d[24]; BLOB b = { 24, d };
    BEGIN(wow);
    fill_blob(d, 24, 1);
    EXPECT_EQ(install(wow, NAME, PATH, NS_NUM, 2, &g, &b, 1), 0);
    EXPECT_EQ(enable(wow, &g, FALSE), 0);
    EXPECT_EQ(check(wow, 1, 2, 0, 24, -1, 0), 0);
    EXPECT_EQ(enable(wow, &g, TRUE), 0);
    EXPECT_EQ(check(wow, 1, 2, 1, 24, -1, 0), 0);
    EXPECT_EQ(enable(wow, &g, FALSE), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_enable_toggle_keeps_blob) { enable_keeps_blob(0); }
TEST(dxg1_nsex_wow_enable_toggle_keeps_blob) { enable_keeps_blob(1); }

/* ---- long strings (a 259 character path is kept; a 259 character identifier is accepted by the install but leaves the catalog unreadable, so identifiers stop at 100) and a non-ASCII identifier ---- */
static WCHAR g_long[600];
static void boundary_row(int wow, int ex, int ident_len, int path_len)
{
    GUID g = id_of(6); static WCHAR path[600];
    BEGIN(wow);
    dxg_fill_w(g_long, ident_len, L'i'); dxg_fill_w(path, path_len, L'p');
    EXPECT_EQ(install(wow, g_long, path, NS_NUM, 1, &g, NULL, ex), 0);
    EXPECT_EQ(check(wow, 6, 1, -1, 0, ident_len, 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_ns_native_identifier_100_chars) { boundary_row(0, 0, 100, 20); }
TEST(dxg1_ns_native_path_259_chars) { boundary_row(0, 0, 10, 259); }
TEST(dxg1_ns_wow_identifier_100_chars) { boundary_row(1, 0, 100, 20); }
TEST(dxg1_ns_wow_path_259_chars) { boundary_row(1, 0, 10, 259); }
TEST(dxg1_ns_native_identifier_1_char) { boundary_row(0, 0, 1, 1); }

static void unicode_identifier(int wow)
{
    GUID g = id_of(6); static const WCHAR ident[] = { 0x00e9, 0x4e2d, 0x6587, ' ', 'x', 0 };
    BEGIN(wow);
    EXPECT_EQ(install(wow, ident, PATH, NS_NUM, 1, &g, NULL, 1), 0);
    EXPECT_EQ(check(wow, 6, 1, -1, 0, 5, 0), 0);
    EXPECT_EQ(uninstall(wow, &g), 0);
    end();
}
TEST(dxg1_nsex_native_unicode_identifier) { unicode_identifier(0); }
TEST(dxg1_nsex_wow_unicode_identifier) { unicode_identifier(1); }

/* The boundary one past the limit is refused even when the other string is fine (also checked in the
 * non-destructive area against a clean catalog; here the catalog additionally holds our own records). */
TEST(dxg1_ns_native_260_char_identifier_refused_with_our_records_present)
{
    GUID g = id_of(1), h = id_of(2);
    BEGIN(0);
    EXPECT_EQ(install(0, NAME, PATH, NS_NUM, 1, &g, NULL, 1), 0);
    dxg_fill_w(g_long, 260, L'i');
    EXPECT_EQ(install(0, g_long, PATH, NS_NUM, 1, &h, NULL, 1), -1);
    EXPECT_EQ(GetLastError(), DXGE_INVAL);
    EXPECT_EQ(check(0, 2, -1, -1, -1, -1, 0), 1);
    EXPECT_EQ(uninstall(0, &g), 0);
    end();
}
/* A failed install does not consume the id: it can be installed afterwards. */
TEST(dxg1_ns_native_refused_install_does_not_reserve_id)
{
    GUID g = id_of(1);
    BEGIN(0);
    dxg_fill_w(g_long, 260, L'i');
    EXPECT_EQ(install(0, g_long, PATH, NS_NUM, 1, &g, NULL, 1), -1);
    EXPECT_EQ(install(0, NAME, PATH, NS_NUM, 1, &g, NULL, 1), 0);
    EXPECT_EQ(check(0, 1, 1, -1, 0, (long)lstrlenW(NAME), 0), 0);
    EXPECT_EQ(uninstall(0, &g), 0);
    end();
}

/* ---- chained install of a library without a provider entry point ---- */
TEST(dxg1_chains_library_without_provider_entry_is_refused)
{
    typedef int (WSAAPI *chains_t)(const GUID *, const WCHAR *, const WCHAR *, const WCHAR *, DWORD, WSAPROTOCOL_INFOW *, DWORD, DWORD *, INT *);
    typedef int (WSAAPI *deinst_t)(const GUID *, INT *);
    chains_t f = (chains_t)dxg_fn("WSCInstallProviderAndChains64_32");
    deinst_t d = (deinst_t)dxg_fn("WSCDeinstallProvider");
    GUID g = id_of(1); WSAPROTOCOL_INFOW p; DWORD out[8] = { 0 }; INT err = DXG_NOERR; int rc;
    DXG_NEED(f);
    BEGIN(0);
    dxg_base_info(&p, 0x7e01);
    rc = f(&g, L"%SystemRoot%\\system32\\kernel32.dll", NULL, L"dxg1 chain", 0, &p, 1, out, &err);
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(err, DXGE_INVPROCTBL);
    if (rc == 0 && d) { INT e; d(&g, &e); }     /* never leave a provider behind */
    end();
}
