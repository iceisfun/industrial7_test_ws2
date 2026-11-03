/* WSCGetProviderPath / WSCGetProviderPath32, WPUGetProviderPathEx, WSCGetProviderInfo / WSCGetProviderInfo32,
 * WSCGetApplicationCategory(+Ex) and the argument checks of WSCSetApplicationCategory.
 * Measures: provider DLL path lookup by provider id (the stored, unexpanded path, the length protocol with
 * its asymmetric success/failure meaning, the error for ids no catalog holds), provider info queries on a base
 * provider (size handshake, supported info types, error codes per type), and the application category lookup
 * for applications that have no entry. Everything is read-only; the Set function is only called with
 * arguments it rejects before touching the registry. */
#include "pc.h"
#include <stdlib.h>

typedef int (WSPAPI *path_fn)(LPGUID, WCHAR *, LPINT, LPINT);
typedef int (WSPAPI *info_fn)(LPGUID, int, PBYTE, size_t *, DWORD, LPINT);

static path_fn pathfn(int which) { return (path_fn)t_proc_in("ws2_32.dll", which == 1 ? "WSCGetProviderPath" : "WSCGetProviderPath32"); }
static info_fn infofn(int which) { return (info_fn)t_proc_in("ws2_32.dll", which == 1 ? "WSCGetProviderInfo" : "WSCGetProviderInfo32"); }

#define STOCK_PATH L"%SystemRoot%\\system32\\mswsock.dll"

#define PTEST(nm, ...) \
    static void nm##_impl(int which); \
    TEST(provpath_native_##nm) { PC_NEED_WSA(); REQUIRE(pathfn(1)); nm##_impl(1); } \
    TEST(provpath_wow_##nm) { PC_NEED_WSA(); REQUIRE(pathfn(2)); nm##_impl(2); } \
    static void nm##_impl(int which) __VA_ARGS__

PTEST(v4_success, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0, r;
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, 0);
    CHECK(len > 0);
    EXPECT_EQ(len, lstrlenW(buf));
})

PTEST(v4_path_is_stored_unexpanded_mswsock, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0;
    CHECK(f(&g, buf, &len, &err) == 0);
    CHECKF(pc_wieq(buf, STOCK_PATH), "path is %ls", buf);
})

PTEST(v6_path_is_stored_unexpanded_mswsock, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip6; WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0;
    CHECK(f(&g, buf, &len, &err) == 0);
    CHECKF(pc_wieq(buf, STOCK_PATH), "path is %ls", buf);
})

PTEST(v4_expanded_path_names_an_existing_file, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH], full[MAX_PATH]; INT len = MAX_PATH, err = 0;
    CHECK(f(&g, buf, &len, &err) == 0);
    CHECK(ExpandEnvironmentStringsW(buf, full, MAX_PATH) > 0);
    CHECK(GetFileAttributesW(full) != INVALID_FILE_ATTRIBUTES);
})

PTEST(exact_fit_includes_terminator, {
    /* Success needs room for the terminator: strlen+1 fits, and the reported length is strlen. */
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = (INT)lstrlenW(STOCK_PATH) + 1, err = 0;
    int r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(len, lstrlenW(STOCK_PATH));
})

PTEST(one_char_short_fails_with_efault, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = (INT)lstrlenW(STOCK_PATH), err = 0, r;
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEFAULT);
    EXPECT_EQ(len, lstrlenW(STOCK_PATH) + 1);
})

PTEST(short_buffer_not_written, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = 4, err = 0, r;
    int i;
    for (i = 0; i < MAX_PATH; i++) buf[i] = 0x5a5a;
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(buf[0], 0x5a5a);
})

PTEST(zero_length_null_buffer_is_size_query, {
    path_fn f = pathfn(which); GUID g = pc_guid_tcpip4; INT len = 0, err = 0, r;
    r = f(&g, NULL, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEFAULT);
    EXPECT_EQ(len, lstrlenW(STOCK_PATH) + 1);
})

PTEST(unknown_id_is_einval_and_untouched, {
    path_fn f = pathfn(which); GUID g = pc_guid_unknown_a; WCHAR buf[MAX_PATH]; INT len = 77, err = 0, r;
    int i;
    for (i = 0; i < MAX_PATH; i++) buf[i] = 0x5a5a;
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(len, 77);
    EXPECT_EQ(buf[0], 0x5a5a);
})

PTEST(unknown_id_with_null_buffer_is_einval, {
    path_fn f = pathfn(which); GUID g = pc_guid_unknown_b; INT len = 0, err = 0, r;
    r = f(&g, NULL, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
})

PTEST(every_catalog_provider_has_a_path, {
    pc_list l; path_fn f = pathfn(which); int i;
    CHECK(pc_enum_w(which, NULL, &l) > 0);
    for (i = 0; i < l.n; i++) {
        WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0; GUID g = l.e[i].ProviderId;
        CHECKF(f(&g, buf, &len, &err) == 0, "entry %lu: provider path lookup failed (%d)", l.e[i].dwCatalogEntryId, err);
        CHECKF(len > 0 && len < MAX_PATH && len == lstrlenW(buf), "entry %lu: bad length %d", l.e[i].dwCatalogEntryId, len);
    }
    pc_free(&l);
})

PTEST(tcp_and_udp_share_a_provider_path, {
    path_fn f = pathfn(which); pc_list l; const WSAPROTOCOL_INFOW *t, *u; WCHAR a[MAX_PATH], b[MAX_PATH]; INT la = MAX_PATH, lb = MAX_PATH, err = 0;
    CHECK(pc_enum_w(which, NULL, &l) > 0);
    t = pc_find(&l, AF_INET, SOCK_STREAM, 6, 1); u = pc_find(&l, AF_INET, SOCK_DGRAM, 17, 1);
    if (t && u) {
        GUID gt = t->ProviderId, gu = u->ProviderId;
        CHECK(f(&gt, a, &la, &err) == 0 && f(&gu, b, &lb, &err) == 0);
        CHECK(lstrcmpW(a, b) == 0);
    } else CHECK(0);
    pc_free(&l);
})

/* No WSAStartup is needed for the SPI path lookup. */
CHILD(path_no_startup)
{
    path_fn f = pathfn(1); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0;
    if (!f) return 90;
    if (f(&g, buf, &len, &err) != 0) return 10;
    if (len != lstrlenW(buf) || len == 0) return 11;
    return 0;
}
TEST(provpath_works_without_wsastartup) { EXPECT_EQ(t_run_child("path_no_startup", "", 30000), 0); }

/* The extended path lookup rejects a missing target description. */
typedef int (WSPAPI *path_ex_fn)(LPGUID, WCHAR *, LPINT, LPINT, void *);
TEST(provpath_ex_without_target_is_einval)
{
    path_ex_fn f = (path_ex_fn)t_proc_in("ws2_32.dll", "WPUGetProviderPathEx"); GUID g = pc_guid_tcpip4; WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0, r;
    REQUIRE(f);
    r = f(&g, buf, &len, &err, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
}

/* ---- WSCGetProviderInfo ------------------------------------------------------------------------ */
#define ITEST(nm, ...) \
    static void nm##_impl(int which); \
    TEST(provinfo_native_##nm) { PC_NEED_WSA(); REQUIRE(infofn(1)); nm##_impl(1); } \
    TEST(provinfo_wow_##nm) { PC_NEED_WSA(); REQUIRE(infofn(2)); nm##_impl(2); } \
    static void nm##_impl(int which) __VA_ARGS__

/* Unknown provider ids lose before the info type is even looked at. */
static const int info_types[] = { 0, 1, 2, 3, 100, -1, 0x7fffffff };

ITEST(unknown_id_is_norecovery_for_every_type, {
    info_fn f = infofn(which); GUID g = pc_guid_unknown_a; int i;
    for (i = 0; i < PC_N(info_types); i++) {
        DWORD v = 0; size_t sz = 4; INT err = 0, r;
        r = f(&g, info_types[i], (PBYTE)&v, &sz, 0, &err);
        CHECKF(r == SOCKET_ERROR && err == WSANO_RECOVERY, "type %d: r=%d err=%d", info_types[i], r, err);
    }
})

ITEST(base_provider_lsp_categories_not_applicable, {
    /* LSP categories belong to layered providers; a base provider id with the right-sized buffer is refused as invalid provider. */
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; DWORD v = 0x1234; size_t sz = 4; INT err = 0, r;
    r = f(&g, 0, (PBYTE)&v, &sz, 0, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVALIDPROVIDER);
    EXPECT_EQ(v, 0x1234);
})

ITEST(base_provider_wrong_size_is_einval_and_size_reported, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; BYTE buf[16] = {0}; static const size_t sizes[] = { 0, 1, 2, 3, 5, 8, 16 }; int i;
    for (i = 0; i < PC_N(sizes); i++) {
        size_t sz = sizes[i]; INT err = 0, r;
        r = f(&g, 0, buf, &sz, 0, &err);
        CHECKF(r == SOCKET_ERROR && err == WSAEINVAL && sz == 4, "size %u: r=%d err=%d size=%u", (unsigned)sizes[i], r, err, (unsigned)sz);
    }
})

ITEST(base_provider_null_info_reports_size, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; size_t sz = 0; INT err = 0, r;
    r = f(&g, 0, NULL, &sz, 0, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(sz, 4);
})

ITEST(base_provider_null_info_correct_size_still_einval, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; size_t sz = 4; INT err = 0, r;
    r = f(&g, 0, NULL, &sz, 0, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(sz, 4);
})

ITEST(base_provider_audit_info_not_implemented, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; BYTE buf[64] = {0}; size_t sz = sizeof buf; INT err = 0, r;
    r = f(&g, 1, buf, &sz, 0, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(sz, sizeof buf);
})

ITEST(base_provider_unknown_types_are_norecovery, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; int i;
    for (i = 2; i < PC_N(info_types); i++) {
        BYTE buf[16] = {0}; size_t sz = 4; INT err = 0, r;
        r = f(&g, info_types[i], buf, &sz, 0, &err);
        CHECKF(r == SOCKET_ERROR && err == WSANO_RECOVERY, "type %d: r=%d err=%d", info_types[i], r, err);
    }
})

ITEST(flags_are_ignored, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip4; static const DWORD fl[] = { 0, 1, 0x80000000, 0xffffffff }; int i;
    for (i = 0; i < PC_N(fl); i++) {
        DWORD v = 0; size_t sz = 4; INT err = 0, r;
        r = f(&g, 0, (PBYTE)&v, &sz, fl[i], &err);
        CHECKF(r == SOCKET_ERROR && err == WSAEINVALIDPROVIDER, "flags %lx: r=%d err=%d", fl[i], r, err);
    }
})

ITEST(v6_base_provider_behaves_like_v4, {
    info_fn f = infofn(which); GUID g = pc_guid_tcpip6; DWORD v = 0; size_t sz = 4; INT err = 0, r;
    r = f(&g, 0, (PBYTE)&v, &sz, 0, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVALIDPROVIDER);
})

ITEST(layered_provider_returns_categories, {
    /* Only exercised when the catalog holds a layered entry (chain length 0). */
    info_fn f = infofn(which); pc_list l; int i, tried = 0;
    CHECK(pc_enum_w(which, NULL, &l) > 0);
    for (i = 0; i < l.n; i++) {
        DWORD v = 0xdeadbeef; size_t sz = 4; INT err = 0; GUID g = l.e[i].ProviderId;
        if (l.e[i].ProtocolChain.ChainLen != LAYERED_PROTOCOL) continue;
        tried++;
        CHECKF(f(&g, 0, (PBYTE)&v, &sz, 0, &err) == 0, "layered entry %lu: err %d", l.e[i].dwCatalogEntryId, err);
        CHECK(v != 0xdeadbeef);
        break;
    }
    if (!tried) t_note("no layered provider in this catalog");
    pc_free(&l);
})

/* The info functions run without WSAStartup as well. */
CHILD(info_no_startup)
{
    info_fn f = infofn(1); GUID g = pc_guid_tcpip4; DWORD v = 0; size_t sz = 4; INT err = 0;
    if (!f) return 90;
    if (f(&g, 0, (PBYTE)&v, &sz, 0, &err) != SOCKET_ERROR) return 10;
    if (err != WSAEINVALIDPROVIDER) return 11;
    return 0;
}
TEST(provinfo_works_without_wsastartup) { EXPECT_EQ(t_run_child("info_no_startup", "", 30000), 0); }

/* ---- application categories --------------------------------------------------------------------- */
typedef int (WSPAPI *appcat_get_fn)(LPCWSTR, DWORD, LPCWSTR, DWORD, DWORD *, LPINT);
typedef int (WSPAPI *appcat_ex_fn)(LPCWSTR, DWORD, LPCWSTR, DWORD, DWORD *, LPINT, void *);
typedef int (WSPAPI *appcat_set_fn)(LPCWSTR, DWORD, LPCWSTR, DWORD, DWORD, DWORD *, LPINT);

static const WCHAR APP[] = L"C:\\ws2t_no_such_dir\\no_such_app.exe";

TEST(appcat_get_null_output_is_einval)
{
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0, r;
    REQUIRE(f);
    r = f(APP, (DWORD)lstrlenW(APP), NULL, 0, NULL, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
}

TEST(appcat_get_null_path_with_length_is_einval)
{
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0, r; DWORD cat = 0x77;
    REQUIRE(f);
    r = f(NULL, 10, NULL, 0, &cat, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(cat, 0x77);
}

TEST(appcat_get_zero_path_length_with_path_is_einval)
{
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0, r; DWORD cat = 0x77;
    REQUIRE(f);
    r = f(APP, 0, NULL, 0, &cat, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(cat, 0x77);
}

TEST(appcat_get_unlisted_application_fails_cleanly)
{
    /* No category entry exists for an application nobody registered: either the catalog key is absent
     * (file not found) or no entry matches (service not found). The output is not written. */
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0, r; DWORD cat = 0x77;
    REQUIRE(f);
    r = f(APP, (DWORD)lstrlenW(APP), NULL, 0, &cat, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECKF(err == WSASERVICE_NOT_FOUND || err == ERROR_FILE_NOT_FOUND, "error %d", err);
    EXPECT_EQ(cat, 0x77);
    t_note("unlisted application error class: %s", err == WSASERVICE_NOT_FOUND ? "entry not found" : "catalog key absent");
}

TEST(appcat_get_unlisted_application_with_extra_fails_cleanly)
{
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0, r; DWORD cat = 0x77;
    static const WCHAR extra[] = L"-ws2t one";
    REQUIRE(f);
    r = f(APP, (DWORD)lstrlenW(APP), extra, (DWORD)lstrlenW(extra), &cat, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECKF(err == WSASERVICE_NOT_FOUND || err == ERROR_FILE_NOT_FOUND, "error %d", err);
    EXPECT_EQ(cat, 0x77);
}

TEST(appcat_get_environment_path_unlisted_fails_cleanly)
{
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0, r; DWORD cat = 0x77;
    static const WCHAR p[] = L"%SystemRoot%\\ws2t_no_such_app.exe";
    REQUIRE(f);
    r = f(p, (DWORD)lstrlenW(p), NULL, 0, &cat, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECKF(err == WSASERVICE_NOT_FOUND || err == ERROR_FILE_NOT_FOUND, "error %d", err);
}

TEST(appcat_get_ex_without_target_is_einval)
{
    appcat_ex_fn f = (appcat_ex_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategoryEx"); INT err = 0, r; DWORD cat = 0x77;
    REQUIRE(f);
    r = f(APP, (DWORD)lstrlenW(APP), NULL, 0, &cat, &err, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(cat, 0x77);
}

TEST(appcat_get_works_without_wsastartup_child)
{
    EXPECT_EQ(t_run_child("appcat_no_startup", "", 30000), 0);
}
CHILD(appcat_no_startup)
{
    appcat_get_fn f = (appcat_get_fn)t_proc_in("ws2_32.dll", "WSCGetApplicationCategory"); INT err = 0; DWORD cat = 0;
    if (!f) return 90;
    if (f(APP, (DWORD)lstrlenW(APP), NULL, 0, &cat, &err) != SOCKET_ERROR) return 10;
    if (err != WSASERVICE_NOT_FOUND && err != ERROR_FILE_NOT_FOUND) return 11;
    return 0;
}

/* Set: only the argument rejections that happen before any registry access. */
TEST(appcat_set_zero_path_length_is_einval)
{
    appcat_set_fn f = (appcat_set_fn)t_proc_in("ws2_32.dll", "WSCSetApplicationCategory"); INT err = 0, r; DWORD prev = 0x77;
    REQUIRE(f);
    r = f(APP, 0, NULL, 0, 0, &prev, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(prev, 0x77);
}

TEST(appcat_set_null_path_is_einval)
{
    appcat_set_fn f = (appcat_set_fn)t_proc_in("ws2_32.dll", "WSCSetApplicationCategory"); INT err = 0, r; DWORD prev = 0x77;
    REQUIRE(f);
    r = f(NULL, 12, NULL, 0, 0, &prev, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(prev, 0x77);
}
