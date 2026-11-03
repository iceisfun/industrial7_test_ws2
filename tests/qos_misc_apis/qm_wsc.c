/* The WSC* catalog writers: failure paths that must not change the catalog.
 *
 * Every test here drives a writer with arguments that cannot match anything installed (a throwaway provider
 * id, an order list that omits or invents entries, a type the call does not support). The calls all fail
 * before anything is written, so the catalogs are identical afterwards; tests that can compare the protocol
 * catalog before and after do so. Positive installs / removals live in the guarded destructive area.
 *
 * Observed contract:
 *   - the WSC* family does not need WSAStartup (no WSANOTINITIALISED);
 *   - these writers open the catalog root for writing: with an elevated token the codes below are returned,
 *     with a plain token the root cannot be opened and the family reports a catalog-unavailable code instead,
 *     so the exact code is only asserted when elevated (otherwise recorded as a note);
 *   - WSCDeinstallProvider(unknown id)         : -1, *lpErrno = WSAEFAULT;
 *   - WSCWriteProviderOrder(incomplete list)   : the WSAEINVAL code is the RETURN value (no -1 convention);
 *   - WSCWriteProviderOrder(list with unknown) : same;
 *   - WSCUpdateProvider(unknown id)            : -1, *lpErrno = 11003 (provider not found in the catalog);
 *   - WSCInstallProvider(id already present)   : -1, *lpErrno = 11003, catalog untouched;
 *   - WSCUnInstallNameSpace / WSCEnableNSProvider(unknown id): -1 and GetLastError() = WSAEINVAL;
 *   - WSCSetProviderInfo: type 0 needs a 4-byte value (else WSAEINVAL), type 1 is ERROR_CALL_NOT_IMPLEMENTED,
 *     any other type reports 11003. */
#include "qm.h"

UDECL(int, WSCDeinstallProvider, (LPGUID, LPINT));
UDECL(int, WSCWriteProviderOrder, (LPDWORD, DWORD));
UDECL(int, WSCUpdateProvider, (LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT));
UDECL(int, WSCInstallProvider, (LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT));
UDECL(int, WSCEnumProtocols, (LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT));
UDECL(int, WSCUnInstallNameSpace, (LPGUID));
UDECL(int, WSCEnableNSProvider, (LPGUID, BOOL));
UDECL(int, WSCWriteNameSpaceOrder, (LPGUID, DWORD));
UDECL(int, WSCSetProviderInfo, (LPGUID, int, PBYTE, size_t, DWORD, LPINT));
UDECL(int, WSCGetProviderInfo, (LPGUID, int, PBYTE, size_t *, DWORD, LPINT));

#define NO_ERRNO 0x5A5A5A5A
/* The catalog writers are stubs that abort the process in the emulated stack; only real Winsock runs them. */
#define REQ(p) do { if (t_is_wine()) { t_skip("catalog writers are not provided by the emulated stack"); return; } if (!(p)) { t_skip("missing export: " #p); return; } } while (0)

/* Hard assertion when elevated, note otherwise (a plain token cannot open the catalog root for writing). */
#define ELEV_EQ(got, want) do { long long g_ = (long long)(got), w_ = (long long)(want); \
    if (qm_elevated()) t_check(g_ == w_, __FILE__, __LINE__, #got " == " #want, "got %lld want %lld", g_, w_); \
    else if (g_ != w_) t_note("not elevated: " #got " is %lld (elevated: %lld)", g_, w_); } while (0)

/* The protocol catalog ids in catalog order (through the public enumeration). Returns the count. */
static int cat_ids(DWORD *ids, int cap, WSAPROTOCOL_INFOW *first_tcp4)
{
    /* The writers see every catalog row, including the ones the public enumeration hides. */
    DWORD len = 0; int n, e = 0;
    n = UN(WSCEnumProtocols)(NULL, NULL, &len, &e);
    if (n != SOCKET_ERROR || len == 0) return -1;
    WSAPROTOCOL_INFOW *b = malloc(len);
    n = UN(WSCEnumProtocols)(NULL, b, &len, &e);
    if (n <= 0) { free(b); return -1; }
    int out = n < cap ? n : cap;
    for (int i = 0; i < out; i++) ids[i] = b[i].dwCatalogEntryId;
    if (first_tcp4) {
        memset(first_tcp4, 0, sizeof *first_tcp4);
        for (int i = 0; i < n; i++)
            if (b[i].iAddressFamily == AF_INET && b[i].iSocketType == SOCK_STREAM && b[i].ProtocolChain.ChainLen == 1) { *first_tcp4 = b[i]; break; }
    }
    free(b);
    return out;
}
static int same_catalog(const DWORD *a, int na, const DWORD *b, int nb)
{
    return na == nb && memcmp(a, b, na * sizeof(DWORD)) == 0;
}

/* ---- WSCDeinstallProvider ---------------------------------------------------------------------------- */

TEST(wsc_deinstall_unknown_id_fails_with_efault)
{
    REQ(UN(WSCDeinstallProvider));
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), -1);
    ELEV_EQ(err, WSAEFAULT);
    CHECK(err != NO_ERRNO && err != 0);
}
TEST(wsc_deinstall_unknown_id_twice_is_stable)
{
    REQ(UN(WSCDeinstallProvider));
    GUID g = qm_guid_b; int e1 = NO_ERRNO, e2 = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &e1), -1);
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &e2), -1);
    EXPECT_EQ(e1, e2);
}
TEST(wsc_deinstall_all_zero_id_fails)
{
    REQ(UN(WSCDeinstallProvider));
    GUID g; memset(&g, 0, sizeof g); int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), -1);
    ELEV_EQ(err, WSAEFAULT);
}
TEST(wsc_deinstall_all_ones_id_fails)
{
    REQ(UN(WSCDeinstallProvider));
    GUID g; memset(&g, 0xFF, sizeof g); int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), -1);
    ELEV_EQ(err, WSAEFAULT);
}
TEST(wsc_deinstall_unknown_id_leaves_catalog_alone)
{
    REQ(UN(WSCDeinstallProvider)); QM_NEED_WSA();
    DWORD a[256], b[256];
    int na = cat_ids(a, 256, NULL);
    GUID g = qm_guid_a; int err = 0;
    UN(WSCDeinstallProvider)(&g, &err);
    int nb = cat_ids(b, 256, NULL);
    CHECK(na > 0);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_deinstall_32_unknown_id_fails_with_efault)
{
    REQ(UN(WSCDeinstallProvider));
    int (WINAPI *f)(LPGUID, LPINT) = (int (WINAPI *)(LPGUID, LPINT))t_proc_in("ws2_32.dll", "WSCDeinstallProvider32");
    REQ(f);
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(f(&g, &err), -1);
    ELEV_EQ(err, WSAEFAULT);
}
CHILD(wsc_no_startup_deinstall)
{
    GUID g = qm_guid_a; int err = NO_ERRNO;
    STEP(1, UN(WSCDeinstallProvider) != NULL);
    STEP(2, UN(WSCDeinstallProvider)(&g, &err) == -1);
    STEP(3, err != WSANOTINITIALISED);               /* no stack required */
    STEP(4, err != NO_ERRNO);
    return 0;
}
TEST(wsc_deinstall_needs_no_startup)
{
    REQ(UN(WSCDeinstallProvider));
    RUN_CHILD("wsc_no_startup_deinstall", "", 20000);
}

/* ---- WSCWriteProviderOrder --------------------------------------------------------------------------- */

TEST(wsc_order_empty_list_is_einval_return)
{
    REQ(UN(WSCWriteProviderOrder));
    int r = UN(WSCWriteProviderOrder)(NULL, 0);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);                                   /* a catalog with entries cannot be ordered by an empty list */
}
TEST(wsc_order_single_unknown_id_is_einval_return)
{
    REQ(UN(WSCWriteProviderOrder));
    DWORD ids[1] = { 0xFFFFFFF0u };
    int r = UN(WSCWriteProviderOrder)(ids, 1);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
}
TEST(wsc_order_incomplete_list_is_einval_and_catalog_unchanged)
{
    REQ(UN(WSCWriteProviderOrder)); QM_NEED_WSA();
    DWORD a[256], b[256];
    int na = cat_ids(a, 256, NULL);
    if (na < 2) { t_skip("catalog too small"); return; }
    DWORD part[1] = { a[0] };
    int r = UN(WSCWriteProviderOrder)(part, 1);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_order_all_but_last_is_einval_and_catalog_unchanged)
{
    REQ(UN(WSCWriteProviderOrder)); QM_NEED_WSA();
    DWORD a[256], b[256];
    int na = cat_ids(a, 256, NULL);
    if (na < 2) { t_skip("catalog too small"); return; }
    int r = UN(WSCWriteProviderOrder)(a, na - 1);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_order_duplicate_instead_of_last_is_einval_and_catalog_unchanged)
{
    REQ(UN(WSCWriteProviderOrder)); QM_NEED_WSA();
    DWORD a[256], l[256], b[256];
    int na = cat_ids(a, 256, NULL);
    if (na < 2) { t_skip("catalog too small"); return; }
    memcpy(l, a, na * sizeof(DWORD));
    l[na - 1] = l[0];
    int r = UN(WSCWriteProviderOrder)(l, na);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_order_complete_list_plus_unknown_is_einval_and_catalog_unchanged)
{
    REQ(UN(WSCWriteProviderOrder)); QM_NEED_WSA();
    DWORD a[256], l[257], b[256];
    int na = cat_ids(a, 255, NULL);
    if (na < 1) { t_skip("catalog empty"); return; }
    memcpy(l, a, na * sizeof(DWORD));
    l[na] = 0xFFFFFFF1u;
    int r = UN(WSCWriteProviderOrder)(l, na + 1);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_order_32_empty_list_is_einval_return)
{
    int (WINAPI *f)(LPDWORD, DWORD) = (int (WINAPI *)(LPDWORD, DWORD))t_proc_in("ws2_32.dll", "WSCWriteProviderOrder32");
    REQ(f);
    int r = f(NULL, 0);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
}
TEST(wsc_order_32_unknown_id_is_einval_return)
{
    int (WINAPI *f)(LPDWORD, DWORD) = (int (WINAPI *)(LPDWORD, DWORD))t_proc_in("ws2_32.dll", "WSCWriteProviderOrder32");
    REQ(f);
    DWORD ids[1] = { 0xFFFFFFF2u };
    int r = f(ids, 1);
    ELEV_EQ(r, WSAEINVAL);
    CHECK(r != 0);
}
TEST(wsc_order_needs_no_startup_child)
{
    REQ(UN(WSCWriteProviderOrder));
    RUN_CHILD("wsc_no_startup_order", "", 20000);
}
CHILD(wsc_no_startup_order)
{
    STEP(1, UN(WSCWriteProviderOrder) != NULL);
    int r = UN(WSCWriteProviderOrder)(NULL, 0);
    STEP(2, r != 0);
    STEP(3, r != WSANOTINITIALISED);
    return 0;
}

/* ---- WSCUpdateProvider ------------------------------------------------------------------------------- */

static void make_entry(WSAPROTOCOL_INFOW *e, const GUID *id)
{
    WSAPROTOCOL_INFOW t;
    if (cat_ids((DWORD[256]){0}, 256, &t) > 0 && t.iAddressFamily == AF_INET) *e = t;
    else { memset(e, 0, sizeof *e); e->iAddressFamily = AF_INET; e->iSocketType = SOCK_STREAM; e->iProtocol = IPPROTO_TCP; e->ProtocolChain.ChainLen = 1; }
    e->ProviderId = *id;
}
TEST(wsc_update_unknown_id_reports_not_found)
{
    REQ(UN(WSCUpdateProvider)); QM_NEED_WSA();
    WSAPROTOCOL_INFOW e; make_entry(&e, &qm_guid_a);
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCUpdateProvider)(&g, L"%SystemRoot%\\system32\\mswsock.dll", &e, 1, &err), -1);
    ELEV_EQ(err, 11003);
    CHECK(err != NO_ERRNO && err != 0);
}
TEST(wsc_update_unknown_id_leaves_catalog_alone)
{
    REQ(UN(WSCUpdateProvider)); QM_NEED_WSA();
    DWORD a[256], b[256];
    int na = cat_ids(a, 256, NULL);
    WSAPROTOCOL_INFOW e; make_entry(&e, &qm_guid_b);
    GUID g = qm_guid_b; int err = 0;
    UN(WSCUpdateProvider)(&g, L"%SystemRoot%\\system32\\mswsock.dll", &e, 1, &err);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_update_32_unknown_id_reports_not_found)
{
    int (WINAPI *f)(LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT) =
        (int (WINAPI *)(LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT))t_proc_in("ws2_32.dll", "WSCUpdateProvider32");
    REQ(f); QM_NEED_WSA();
    WSAPROTOCOL_INFOW e; make_entry(&e, &qm_guid_a);
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(f(&g, L"%SystemRoot%\\system32\\mswsock.dll", &e, 1, &err), -1);
    ELEV_EQ(err, 11003);
}
TEST(wsc_update_count_mismatch_with_unknown_id_is_not_found)
{
    /* Two entries supplied, none matches: still "not found", nothing written. */
    REQ(UN(WSCUpdateProvider)); QM_NEED_WSA();
    WSAPROTOCOL_INFOW e[2]; make_entry(&e[0], &qm_guid_a); make_entry(&e[1], &qm_guid_a);
    e[1].dwCatalogEntryId = e[0].dwCatalogEntryId + 1;
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCUpdateProvider)(&g, L"%SystemRoot%\\system32\\mswsock.dll", e, 2, &err), -1);
    ELEV_EQ(err, 11003);
}

/* ---- WSCInstallProvider with an id that is already installed ------------------------------------------ */

TEST(wsc_install_existing_id_is_refused_and_catalog_unchanged)
{
    REQ(UN(WSCInstallProvider)); QM_NEED_WSA();
    DWORD a[256], b[256]; WSAPROTOCOL_INFOW tcp;
    int na = cat_ids(a, 256, &tcp);
    if (na < 1 || tcp.iAddressFamily != AF_INET) { t_skip("no base TCP entry"); return; }
    GUID g = tcp.ProviderId; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCInstallProvider)(&g, L"%SystemRoot%\\system32\\mswsock.dll", &tcp, 1, &err), -1);
    ELEV_EQ(err, 11003);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_install_existing_id_32_is_refused)
{
    int (WINAPI *f)(LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT) =
        (int (WINAPI *)(LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT))t_proc_in("ws2_32.dll", "WSCInstallProvider64_32");
    REQ(f); QM_NEED_WSA();
    DWORD a[256], b[256]; WSAPROTOCOL_INFOW tcp;
    int na = cat_ids(a, 256, &tcp);
    if (na < 1 || tcp.iAddressFamily != AF_INET) { t_skip("no base TCP entry"); return; }
    GUID g = tcp.ProviderId; int err = NO_ERRNO;
    int r = f(&g, L"%SystemRoot%\\system32\\mswsock.dll", &tcp, 1, &err);
    EXPECT_EQ(r, -1);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}

/* ---- namespace catalog writers ------------------------------------------------------------------------ */

TEST(wsc_uninstall_namespace_unknown_id_fails_with_einval)
{
    REQ(UN(WSCUnInstallNameSpace));
    GUID g = qm_guid_a;
    SET_ERR(0);
    EXPECT_EQ(UN(WSCUnInstallNameSpace)(&g), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
    CHECK(e != 0);
}
TEST(wsc_uninstall_namespace_32_unknown_id_fails_with_einval)
{
    int (WINAPI *f)(LPGUID) = (int (WINAPI *)(LPGUID))t_proc_in("ws2_32.dll", "WSCUnInstallNameSpace32");
    REQ(f);
    GUID g = qm_guid_b;
    SET_ERR(0);
    EXPECT_EQ(f(&g), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
}
TEST(wsc_enable_ns_provider_unknown_id_fails_with_einval)
{
    REQ(UN(WSCEnableNSProvider));
    GUID g = qm_guid_a;
    SET_ERR(0);
    EXPECT_EQ(UN(WSCEnableNSProvider)(&g, TRUE), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
    CHECK(e != 0);
}
TEST(wsc_enable_ns_provider_disable_unknown_id_fails_the_same)
{
    REQ(UN(WSCEnableNSProvider));
    GUID g = qm_guid_b;
    SET_ERR(0);
    EXPECT_EQ(UN(WSCEnableNSProvider)(&g, FALSE), -1);
    CHECK(GetLastError() != 0);
}
TEST(wsc_enable_ns_provider_32_unknown_id_fails_with_einval)
{
    int (WINAPI *f)(LPGUID, BOOL) = (int (WINAPI *)(LPGUID, BOOL))t_proc_in("ws2_32.dll", "WSCEnableNSProvider32");
    REQ(f);
    GUID g = qm_guid_a;
    SET_ERR(0);
    EXPECT_EQ(f(&g, TRUE), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
}
/* ---- WSCSetProviderInfo / WSCGetProviderInfo type handling -------------------------------------------- */

TEST(wsc_setinfo_type1_audit_is_not_implemented)
{
    REQ(UN(WSCSetProviderInfo));
    GUID g = qm_guid_a; DWORD v = 0; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCSetProviderInfo)(&g, 1, (PBYTE)&v, sizeof v, 0, &err), -1);
    ELEV_EQ(err, ERROR_CALL_NOT_IMPLEMENTED);
}
TEST(wsc_setinfo_unknown_type_reports_not_found_code)
{
    REQ(UN(WSCSetProviderInfo));
    static const int types[] = { 2, 3, 77, -1 };
    for (int i = 0; i < QM_N(types); i++) {
        GUID g = qm_guid_a; DWORD v = 0; int err = NO_ERRNO;
        int r = UN(WSCSetProviderInfo)(&g, types[i], (PBYTE)&v, sizeof v, 0, &err);
        t_check(r == -1, __FILE__, __LINE__, "setinfo(bad type)", "type %d ret %d", types[i], r);
        if (qm_elevated()) t_check(err == 11003, __FILE__, __LINE__, "setinfo(bad type) errno", "type %d err %d", types[i], err);
    }
}
TEST(wsc_setinfo_type0_wrong_size_is_einval)
{
    REQ(UN(WSCSetProviderInfo));
    static const size_t sizes[] = { 0, 1, 3, 5, 8 };
    for (int i = 0; i < QM_N(sizes); i++) {
        GUID g = qm_guid_a; DWORD v[2] = { 0, 0 }; int err = NO_ERRNO;
        int r = UN(WSCSetProviderInfo)(&g, 0, (PBYTE)v, sizes[i], 0, &err);
        t_check(r == -1, __FILE__, __LINE__, "setinfo(size)", "size %zu ret %d", sizes[i], r);
        if (qm_elevated()) t_check(err == WSAEINVAL, __FILE__, __LINE__, "setinfo(size) errno", "size %zu err %d", sizes[i], err);
    }
}
TEST(wsc_setinfo_type0_unknown_id_reports_not_found_code)
{
    REQ(UN(WSCSetProviderInfo));
    GUID g = qm_guid_a; DWORD v = 0; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCSetProviderInfo)(&g, 0, (PBYTE)&v, sizeof v, 0, &err), -1);
    ELEV_EQ(err, 11003);
}
/* The lookup of the provider id comes first for a read: an unknown id reports 11003 whatever the type. */
TEST(wsc_getinfo_unknown_id_reports_not_found_for_every_type)
{
    REQ(UN(WSCGetProviderInfo));
    static const int types[] = { 0, 1, 2, 5, -1 };
    for (int i = 0; i < QM_N(types); i++) {
        GUID g = qm_guid_a; DWORD v = 0; size_t sz = sizeof v; int err = NO_ERRNO;
        int r = UN(WSCGetProviderInfo)(&g, types[i], (PBYTE)&v, &sz, 0, &err);
        t_check(r == -1, __FILE__, __LINE__, "getinfo(unknown id)", "type %d ret %d", types[i], r);
        if (qm_elevated()) t_check(err == 11003, __FILE__, __LINE__, "getinfo(unknown id) errno", "type %d err %d", types[i], err);
    }
}
TEST(wsc_getinfo_type1_audit_on_a_known_provider_is_not_implemented)
{
    REQ(UN(WSCGetProviderInfo)); QM_NEED_WSA();
    DWORD ids[8]; WSAPROTOCOL_INFOW tcp;
    if (cat_ids(ids, 8, &tcp) < 1 || tcp.iAddressFamily != AF_INET) { t_skip("no base TCP entry"); return; }
    GUID g = tcp.ProviderId; DWORD v = 0; size_t sz = sizeof v; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCGetProviderInfo)(&g, 1, (PBYTE)&v, &sz, 0, &err), -1);
    ELEV_EQ(err, ERROR_CALL_NOT_IMPLEMENTED);
}
TEST(wsc_getinfo_other_type_on_a_known_provider_reports_not_found_code)
{
    REQ(UN(WSCGetProviderInfo)); QM_NEED_WSA();
    DWORD ids[8]; WSAPROTOCOL_INFOW tcp;
    if (cat_ids(ids, 8, &tcp) < 1 || tcp.iAddressFamily != AF_INET) { t_skip("no base TCP entry"); return; }
    static const int types[] = { 2, 3, 99 };
    for (int i = 0; i < QM_N(types); i++) {
        GUID g = tcp.ProviderId; DWORD v = 0; size_t sz = sizeof v; int err = NO_ERRNO;
        int r = UN(WSCGetProviderInfo)(&g, types[i], (PBYTE)&v, &sz, 0, &err);
        t_check(r == -1, __FILE__, __LINE__, "getinfo(type)", "type %d ret %d", types[i], r);
        if (qm_elevated()) t_check(err == 11003, __FILE__, __LINE__, "getinfo(type) errno", "type %d err %d", types[i], err);
    }
}

/* ---- export table facts ------------------------------------------------------------------------------- */

TEST(wsc_writer_exports_present)
{
    static const char *names[] = {
        "WSCDeinstallProvider", "WSCDeinstallProvider32", "WSCDeinstallProviderEx", "WSCEnableNSProvider",
        "WSCEnableNSProvider32", "WSCInstallNameSpace", "WSCInstallNameSpace32", "WSCInstallNameSpaceEx",
        "WSCInstallNameSpaceEx2", "WSCInstallNameSpaceEx32", "WSCInstallProvider", "WSCInstallProvider64_32",
        "WSCInstallProviderAndChains64_32", "WSCInstallProviderEx", "WSCSetProviderInfo", "WSCSetProviderInfo32",
        "WSCUnInstallNameSpace", "WSCUnInstallNameSpace32", "WSCUnInstallNameSpaceEx2", "WSCUpdateProvider",
        "WSCUpdateProvider32", "WSCUpdateProviderEx", "WSCWriteNameSpaceOrder", "WSCWriteNameSpaceOrder32",
        "WSCWriteProviderOrder", "WSCWriteProviderOrder32", "WSCWriteProviderOrderEx", "WSCSetApplicationCategoryEx" };
    int missing = 0;
    for (int i = 0; i < QM_N(names); i++) if (!t_proc_in("ws2_32.dll", names[i])) { missing++; t_note("not exported: %s", names[i]); }
    if (t_is_wine()) { t_skip("writer family incomplete in the emulated stack"); return; }
    EXPECT_EQ(missing, 0);
}

/* ---- extended entry points with a missing target description ------------------------------------------ */

UDECL(int, WSCDeinstallProviderEx, (LPGUID, LPINT, void *, DWORD));
UDECL(int, WSCInstallProviderEx, (LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT, void *, void *));
UDECL(int, WSCWriteProviderOrderEx, (LPDWORD, DWORD, void *, DWORD));
UDECL(int, WSCUnInstallNameSpaceEx2, (LPGUID, void *, DWORD, DWORD));
UDECL(int, WSCInstallNameSpace, (LPWSTR, LPWSTR, DWORD, DWORD, LPGUID));
UDECL(int, WSCInstallNameSpaceEx2, (LPWSTR, LPWSTR, DWORD, DWORD, LPGUID, LPBLOB, void *));

TEST(wsc_ex_deinstall_without_target_is_einval_in_errno)
{
    REQ(UN(WSCDeinstallProviderEx));
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProviderEx)(&g, &err, NULL, 0), -1);
    EXPECT_EQ(err, WSAEINVAL);
}
TEST(wsc_ex_install_without_target_is_einval_in_errno)
{
    REQ(UN(WSCInstallProviderEx));
    GUID g = qm_guid_a; WSAPROTOCOL_INFOW e; memset(&e, 0, sizeof e); int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCInstallProviderEx)(&g, L"%SystemRoot%\\system32\\mswsock.dll", &e, 1, &err, NULL, NULL), -1);
    EXPECT_EQ(err, WSAEINVAL);
}
TEST(wsc_ex_write_order_without_target_is_minus_one)
{
    REQ(UN(WSCWriteProviderOrderEx));
    DWORD ids[1] = { 0xFFFFFFF3u };
    EXPECT_EQ(UN(WSCWriteProviderOrderEx)(ids, 1, NULL, 0), -1);
}
TEST(wsc_ex_uninstall_namespace_without_target_is_minus_one_and_silent)
{
    REQ(UN(WSCUnInstallNameSpaceEx2));
    GUID g = qm_guid_a;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(WSCUnInstallNameSpaceEx2)(&g, NULL, 0, 0), -1);
    EXPECT_EQ(GetLastError(), 0x4242);                  /* the missing-target path records nothing */
}
TEST(wsc_ex_install_namespace_without_target_is_minus_one_and_silent)
{
    REQ(UN(WSCInstallNameSpaceEx2));
    GUID g = qm_guid_a;
    SET_ERR(0x4243);
    EXPECT_EQ(UN(WSCInstallNameSpaceEx2)((LPWSTR)L"ws2t", (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", NS_DNS, 0, &g, NULL, NULL), -1);
    EXPECT_EQ(GetLastError(), 0x4243);
}
TEST(wsc_install_namespace_existing_id_is_einval_and_catalog_unchanged)
{
    REQ(UN(WSCInstallNameSpace)); QM_NEED_WSA();
    DWORD len = 0;
    int n = U(WSAEnumNameSpaceProvidersW)(&len, NULL);
    if (n != SOCKET_ERROR || len == 0) { t_skip("no namespace enumeration"); return; }
    WSANAMESPACE_INFOW *b = malloc(len);
    n = U(WSAEnumNameSpaceProvidersW)(&len, b);
    if (n <= 0) { free(b); t_skip("no namespace providers"); return; }
    GUID g = b[0].NSProviderId; DWORD ns = b[0].dwNameSpace;
    SET_ERR(0);
    EXPECT_EQ(UN(WSCInstallNameSpace)((LPWSTR)L"ws2t duplicate", (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", ns, 0, &g), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
    CHECK(e != 0);
    DWORD len2 = 0;
    EXPECT_EQ(U(WSAEnumNameSpaceProvidersW)(&len2, NULL), SOCKET_ERROR);
    EXPECT_EQ(len2, len);                               /* same catalog size */
    free(b);
}

/* ---- application category, chained install, 32-bit twins ---------------------------------------------- */

UDECL(int, WSCSetApplicationCategoryEx, (LPCWSTR, DWORD, LPCWSTR, DWORD, DWORD, DWORD *, LPINT, void *));
UDECL(int, WSCInstallProviderAndChains64_32, (LPGUID, LPWSTR, LPWSTR, LPWSTR, DWORD, LPWSAPROTOCOL_INFOW, DWORD, LPDWORD, LPINT));
UDECL(int, WSCEnumNameSpaceProviders32, (LPDWORD, LPWSANAMESPACE_INFOW));

TEST(wsc_setappcategory_ex_empty_path_is_einval)
{
    REQ(UN(WSCSetApplicationCategoryEx));
    DWORD prev = 0x77; int err = NO_ERRNO; char ctx[64] = { 0 };
    EXPECT_EQ(UN(WSCSetApplicationCategoryEx)(L"C:\\ws2t\\none.exe", 0, NULL, 0, 1, &prev, &err, ctx), -1);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(prev, 0x77);
}
TEST(wsc_setappcategory_ex_null_path_is_einval)
{
    REQ(UN(WSCSetApplicationCategoryEx));
    DWORD prev = 0x77; int err = NO_ERRNO; char ctx[64] = { 0 };
    EXPECT_EQ(UN(WSCSetApplicationCategoryEx)(NULL, 20, NULL, 0, 1, &prev, &err, ctx), -1);
    EXPECT_EQ(err, WSAEINVAL);
}
TEST(wsc_setappcategory_ex_null_target_is_einval)
{
    REQ(UN(WSCSetApplicationCategoryEx));
    DWORD prev = 0x77; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCSetApplicationCategoryEx)(L"C:\\ws2t\\none.exe", 17, NULL, 0, 1, &prev, &err, NULL), -1);
    EXPECT_EQ(err, WSAEINVAL);
}
TEST(wsc_chains_install_zero_entries_is_einval)
{
    REQ(UN(WSCInstallProviderAndChains64_32)); QM_NEED_WSA();
    DWORD ids[4]; WSAPROTOCOL_INFOW tcp;
    if (cat_ids(ids, 4, &tcp) < 1 || tcp.iAddressFamily != AF_INET) { t_skip("no base TCP entry"); return; }
    GUID g = qm_guid_a; DWORD out[4] = { 0 }; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCInstallProviderAndChains64_32)(&g, (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", (LPWSTR)L"%SystemRoot%\\syswow64\\mswsock.dll",
                                                  (LPWSTR)L"ws2t chain", 0, &tcp, 0, out, &err), -1);
    EXPECT_EQ(err, WSAEINVAL);
}
TEST(wsc_chains_install_leaves_catalog_alone_on_failure)
{
    REQ(UN(WSCInstallProviderAndChains64_32)); QM_NEED_WSA();
    DWORD a[256], b[256]; WSAPROTOCOL_INFOW tcp;
    int na = cat_ids(a, 256, &tcp);
    if (na < 1 || tcp.iAddressFamily != AF_INET) { t_skip("no base TCP entry"); return; }
    GUID g = qm_guid_a; DWORD out[4] = { 0 }; int err = NO_ERRNO;
    UN(WSCInstallProviderAndChains64_32)(&g, (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", (LPWSTR)L"%SystemRoot%\\syswow64\\mswsock.dll",
                                        (LPWSTR)L"ws2t chain", 0, &tcp, 0, out, &err);
    int nb = cat_ids(b, 256, NULL);
    CHECK(same_catalog(a, na, b, nb));
}
TEST(wsc_setproviderinfo32_unknown_id_rows)
{
    int (WINAPI *f)(LPGUID, int, PBYTE, size_t, DWORD, LPINT) = (int (WINAPI *)(LPGUID, int, PBYTE, size_t, DWORD, LPINT))t_proc_in("ws2_32.dll", "WSCSetProviderInfo32");
    REQ(f);
    GUID g = qm_guid_a; DWORD v = 0; int err = NO_ERRNO;
    EXPECT_EQ(f(&g, 1, (PBYTE)&v, sizeof v, 0, &err), -1);
    ELEV_EQ(err, ERROR_CALL_NOT_IMPLEMENTED);
    err = NO_ERRNO;
    EXPECT_EQ(f(&g, 0, (PBYTE)&v, 2, 0, &err), -1);
    ELEV_EQ(err, WSAEINVAL);
    err = NO_ERRNO;
    EXPECT_EQ(f(&g, 0, (PBYTE)&v, sizeof v, 0, &err), -1);
    ELEV_EQ(err, 11003);
}
TEST(wsc_updateproviderex_is_not_called_without_a_target)
{
    /* The extended form reads its target description before any argument check; a NULL one is a fault. */
    REQ(t_proc_in("ws2_32.dll", "WSCUpdateProviderEx"));
    t_skip("no safe argument-error path (the target description is dereferenced first)");
}
static int ns_existing(GUID *g, DWORD *ns, int use32)
{
    DWORD len = 0; int n;
    n = use32 ? UN(WSCEnumNameSpaceProviders32)(&len, NULL) : U(WSAEnumNameSpaceProvidersW)(&len, NULL);
    if (n != SOCKET_ERROR || len == 0) return 0;
    WSANAMESPACE_INFOW *b = malloc(len);
    n = use32 ? UN(WSCEnumNameSpaceProviders32)(&len, b) : U(WSAEnumNameSpaceProvidersW)(&len, b);
    int ok = n > 0;
    if (ok) { *g = b[0].NSProviderId; *ns = b[0].dwNameSpace; }
    free(b);
    return ok;
}
TEST(wsc_install_namespace32_existing_id_is_einval)
{
    int (WINAPI *f)(LPWSTR, LPWSTR, DWORD, DWORD, LPGUID) = (int (WINAPI *)(LPWSTR, LPWSTR, DWORD, DWORD, LPGUID))t_proc_in("ws2_32.dll", "WSCInstallNameSpace32");
    REQ(f); REQ(UN(WSCEnumNameSpaceProviders32)); QM_NEED_WSA();
    GUID g; DWORD ns;
    if (!ns_existing(&g, &ns, 1)) { t_skip("32-bit namespace catalog empty or unreadable"); return; }
    SET_ERR(0);
    EXPECT_EQ(f((LPWSTR)L"ws2t duplicate", (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", ns, 0, &g), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
}
TEST(wsc_install_namespace_ex_existing_id_is_einval)
{
    int (WINAPI *f)(LPWSTR, LPWSTR, DWORD, DWORD, LPGUID, LPBLOB) = (int (WINAPI *)(LPWSTR, LPWSTR, DWORD, DWORD, LPGUID, LPBLOB))t_proc_in("ws2_32.dll", "WSCInstallNameSpaceEx");
    REQ(f); QM_NEED_WSA();
    GUID g; DWORD ns;
    if (!ns_existing(&g, &ns, 0)) { t_skip("namespace catalog unreadable"); return; }
    SET_ERR(0);
    EXPECT_EQ(f((LPWSTR)L"ws2t duplicate", (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", ns, 0, &g, NULL), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
}
TEST(wsc_install_namespace_ex32_existing_id_is_einval)
{
    int (WINAPI *f)(LPWSTR, LPWSTR, DWORD, DWORD, LPGUID, LPBLOB) = (int (WINAPI *)(LPWSTR, LPWSTR, DWORD, DWORD, LPGUID, LPBLOB))t_proc_in("ws2_32.dll", "WSCInstallNameSpaceEx32");
    REQ(f); REQ(UN(WSCEnumNameSpaceProviders32)); QM_NEED_WSA();
    GUID g; DWORD ns;
    if (!ns_existing(&g, &ns, 1)) { t_skip("32-bit namespace catalog empty or unreadable"); return; }
    SET_ERR(0);
    EXPECT_EQ(f((LPWSTR)L"ws2t duplicate", (LPWSTR)L"%SystemRoot%\\system32\\mswsock.dll", ns, 0, &g, NULL), -1);
    DWORD e = GetLastError();
    if (qm_elevated()) EXPECT_EQ(e, WSAEINVAL); else t_note("not elevated: last error %lu", e);
}
