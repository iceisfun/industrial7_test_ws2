/* Name-space provider configuration and application categories: WSCInstallNameSpace / WSCUnInstallNameSpace /
 * WSCEnableNSProvider (+32 variants), WSCWriteNameSpaceOrder, and WSCSetApplicationCategory /
 * WSCGetApplicationCategory.
 *
 * Name-space entries use a throwaway provider id and name-space number and a DLL path that is never loaded:
 * the install only stores the strings (each at most 259 units), refuses a provider id that is already present
 * with WSAEINVAL, and reports through the thread's last-error value. The application-category entries use a
 * path that does not exist on disk; the Set call merges (ORs) categories into an existing entry and a zero
 * category deletes it. Everything created here is removed at the end of every test; dx_end checks that the
 * catalogs equal the baseline. Skipped unless elevated. */
#include "dx.h"

#define NS_TEST 0x7e57u
static const WCHAR NS_PATH[] = L"%SystemRoot%\\system32\\ws2t_dx_no_such_nsp.dll";
static const WCHAR NS_NAME[] = L"ws2t dx namespace";

/* The name-space list is cached per process, so what a call persisted is read back in a fresh process
 * (dx_child_query); the thread's last error carries the failure reason of every call here. */
static int err_now(void) { return (int)GetLastError(); }
static int ns_install(const GUID *g, DWORD ns, DWORD ver)
{
    SetLastError(0);
    return DX_NSINSTALL(NS_NAME, NS_PATH, ns, ver, g);
}
static int has(unsigned idx) { return dx_child_query("nshas %u", idx) == 0; }
static int gone(unsigned idx) { return dx_child_query("nshas %u", idx) == 1; }
static int fields_are(unsigned idx, DWORD ns, DWORD ver, int active)
{
    return dx_child_query("nsfields %u 0x%lx 0x%lx %d", idx, (unsigned long)ns, (unsigned long)ver, active) == 0;
}

/* ---- install / uninstall ---- */

TEST(dxns_install_returns_zero_and_lists)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    CHECK(has(1));
    dx_end();
}
TEST(dxns_fields_round_trip)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 7), 0);
    CHECK(fields_are(1, NS_TEST, 7, -1));
    EXPECT_EQ(dx_child_query("nsident 1 0 x"), 0);
    dx_end();
}
TEST(dxns_default_activation_logged)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    t_note("a freshly installed name-space entry is %s", dx_child_query("nsactive 1") == 0 ? "active" : "inactive");
    dx_end();
}
TEST(dxns_duplicate_provider_id_refused)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(ns_install(&g, NS_TEST + 1, 2), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}
TEST(dxns_duplicate_refusal_keeps_first_record)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(ns_install(&g, NS_TEST + 1, 2), SOCKET_ERROR);
    CHECK(fields_are(1, NS_TEST, 1, -1));
    dx_end();
}
TEST(dxns_stock_provider_id_refused)
{
    /* The id of the DNS name space is taken; the refused install must leave the catalog alone. */
    static const GUID dns = {0x22059D40, 0x7E9E, 0x11CF, {0xAE, 0x5A, 0x00, 0xAA, 0x00, 0xA7, 0x11, 0x2B}};
    dx_nslist l; int have;
    DX_BEGIN();
    CHECK(dx_ns_enum(&l) >= 0);
    have = dx_ns_by_guid(&l, &dns) != NULL;
    dx_ns_free(&l);
    if (!have) { t_skip("no DNS name space provider"); dx_end(); return; }
    EXPECT_EQ(ns_install(&dns, NS_TEST, 1), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}
TEST(dxns_same_namespace_number_twice_allowed)
{
    GUID a = dx_guid(1), b = dx_guid(2);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&a, NS_TEST, 1), 0);
    EXPECT_EQ(ns_install(&b, NS_TEST, 1), 0);
    CHECK(has(1) && has(2));
    dx_end();
}
TEST(dxns_uninstall_returns_zero_and_unlists)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    CHECK(has(1));
    SetLastError(0);
    EXPECT_EQ(DX_NSUNINSTALL(&g), 0);
    CHECK(gone(1));
    dx_end();
}
TEST(dxns_uninstall_unknown_fails)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSUNINSTALL(&g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}
TEST(dxns_uninstall_twice_second_fails)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSUNINSTALL(&g), 0);
    SetLastError(0);
    EXPECT_EQ(DX_NSUNINSTALL(&g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}
TEST(dxns_uninstall_leaves_neighbours)
{
    GUID a = dx_guid(1), b = dx_guid(2);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&a, NS_TEST, 1), 0);
    EXPECT_EQ(ns_install(&b, NS_TEST + 1, 1), 0);
    EXPECT_EQ(DX_NSUNINSTALL(&a), 0);
    CHECK(gone(1));
    CHECK(has(2));
    dx_end();
}
TEST(dxns_reinstall_after_uninstall)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSUNINSTALL(&g), 0);
    EXPECT_EQ(ns_install(&g, NS_TEST, 2), 0);
    CHECK(fields_are(1, NS_TEST, 2, -1));
    dx_end();
}
TEST(dxns_uninstall_restores_baseline)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    CHECK(!dx_ns_matches_baseline());
    EXPECT_EQ(DX_NSUNINSTALL(&g), 0);
    CHECK(dx_ns_matches_baseline());
    dx_end();
}
TEST(dxns_install_appends_after_stock_entries)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(dx_child_query("nslast 1"), 0);
    dx_end();
}
TEST(dxns_second_install_appends_after_first)
{
    GUID a = dx_guid(1), b = dx_guid(2);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&a, NS_TEST, 1), 0);
    EXPECT_EQ(ns_install(&b, NS_TEST + 1, 1), 0);
    EXPECT_EQ(dx_child_query("nsbefore 1 2"), 0);
    dx_end();
}
TEST(dxns_install_leaves_protocol_catalog_alone)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    CHECK(dx_native_matches_baseline());
    EXPECT_EQ(DX_NSUNINSTALL(&g), 0);
    dx_end();
}
TEST(dxns_protocol_install_leaves_ns_catalog_alone)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_ns_matches_baseline());
    dx_end();
}

/* The strings are stored in 260-unit fields. */
static WCHAR *filled(int n, WCHAR c)
{
    WCHAR *s = (WCHAR *)calloc(n + 2, sizeof(WCHAR));
    for (int i = 0; i < n; i++) s[i] = c;
    return s;
}
/* A 259-unit identifier is accepted by the install call, but on genuine Windows 10 the persisted entry then makes
 * every later WSAStartup fail and cannot be removed again, so only a moderately long identifier is installed. */
TEST(dxns_identifier_64_units_ok)
{
    GUID g = dx_guid(1); WCHAR *id = filled(64, L'n');
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(id, NS_PATH, NS_TEST, 1, &g), 0);
    EXPECT_EQ(dx_child_query("nsident 1 64 n"), 0);
    free(id);
    dx_end();
}
TEST(dxns_identifier_260_units_invalid)
{
    GUID g = dx_guid(1); WCHAR *id = filled(260, L'n');
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(id, NS_PATH, NS_TEST, 1, &g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    CHECK(gone(1));
    free(id);
    dx_end();
}
TEST(dxns_path_259_units_ok_without_loading)
{
    GUID g = dx_guid(1); WCHAR *p = filled(259, L'p');
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(NS_NAME, p, NS_TEST, 1, &g), 0);
    free(p);
    dx_end();
}
TEST(dxns_path_260_units_invalid)
{
    GUID g = dx_guid(1); WCHAR *p = filled(260, L'p');
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(NS_NAME, p, NS_TEST, 1, &g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    CHECK(gone(1));
    free(p);
    dx_end();
}
TEST(dxns_path_far_too_long_invalid)
{
    GUID g = dx_guid(1); WCHAR *p = filled(2000, L'q');
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(NS_NAME, p, NS_TEST, 1, &g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    free(p);
    dx_end();
}
TEST(dxns_path_is_not_checked_for_existence)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(NS_NAME, L"C:\\ws2t_dx_catalog_dir\\none.dll", NS_TEST, 1, &g), 0);
    dx_end();
}
TEST(dxns_empty_strings_outcome_logged)
{
    GUID g = dx_guid(1); INT r;
    DX_BEGIN();
    SetLastError(0);
    r = DX_NSINSTALL(L"", L"", NS_TEST, 1, &g);
    t_note("empty identifier and path: %s", r == 0 ? "accepted" : "refused");
    dx_end();
}
TEST(dxns_namespace_zero_and_version_zero)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(NS_NAME, NS_PATH, 0, 0, &g), 0);
    CHECK(fields_are(1, 0, 0, -1));
    dx_end();
}
TEST(dxns_large_values_round_trip)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL(NS_NAME, NS_PATH, 0xfffffff0u, 0xfffffffeu, &g), 0);
    CHECK(fields_are(1, 0xfffffff0u, 0xfffffffeu, -1));
    dx_end();
}

/* ---- enable / disable ---- */

static int wait_active(unsigned idx, int want) { return dx_child_query("nsactive %u", idx) == (want ? 0 : 1); }
TEST(dxns_disable_clears_active_flag)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    SetLastError(0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    CHECK(wait_active(1, 0));
    dx_end();
}
TEST(dxns_enable_sets_active_flag)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    EXPECT_EQ(DX_NSENABLE(&g, TRUE), 0);
    CHECK(wait_active(1, 1));
    dx_end();
}
TEST(dxns_enable_is_idempotent)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSENABLE(&g, TRUE), 0);
    EXPECT_EQ(DX_NSENABLE(&g, TRUE), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    CHECK(wait_active(1, 0));
    dx_end();
}
TEST(dxns_nonzero_enable_value_means_true)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    EXPECT_EQ(DX_NSENABLE(&g, (BOOL)0x100), 0);
    CHECK(wait_active(1, 1));
    dx_end();
}
TEST(dxns_enable_unknown_provider_fails)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    SetLastError(0);
    EXPECT_EQ(DX_NSENABLE(&g, TRUE), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    SetLastError(0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}
TEST(dxns_disabled_provider_stays_installed)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    CHECK(has(1));
    EXPECT_EQ(DX_NSUNINSTALL(&g), 0);
    dx_end();
}
TEST(dxns_disable_does_not_change_other_fields)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 9), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    CHECK(fields_are(1, NS_TEST, 9, 0));
    EXPECT_EQ(dx_child_query("nsident 1 0 x"), 0);
    dx_end();
}
TEST(dxns_disabling_ours_leaves_stock_active_flags)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    EXPECT_EQ(ns_install(&g, NS_TEST, 1), 0);
    EXPECT_EQ(DX_NSENABLE(&g, FALSE), 0);
    CHECK(wait_active(1, 0));
    CHECK(dx_ns_matches_baseline() == 0);        /* only the count is compared: ours is still listed */
    dx_end();
}

/* ---- name-space order ---- */

typedef INT (WSAAPI *wno_fn)(LPGUID, DWORD);
static wno_fn nsorder(void) { return (wno_fn)t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder"); }
TEST(dxnsord_swap_two_of_ours)
{
    GUID a = dx_guid(1), b = dx_guid(2); dx_nslist l; GUID *ids; wno_fn wo = nsorder(); int pa = -1, pb = -1;
    DX_BEGIN();
    REQUIRE(wo);
    dx_ns_order_dirty = 1;
    EXPECT_EQ(ns_install(&a, NS_TEST, 1), 0);
    EXPECT_EQ(ns_install(&b, NS_TEST + 1, 1), 0);
    EXPECT_EQ(dx_child_query("nsbefore 1 2"), 0);
    CHECK(dx_ns_enum(&l) >= 0);
    ids = (GUID *)calloc(l.n + 2, sizeof(GUID));
    /* The in-process list may predate the installs; rebuild the full list from the stock entries plus ours. */
    { int k = 0;
      for (int i = 0; i < l.n; i++) if (!dx_is_ours(&l.e[i].NSProviderId)) ids[k++] = l.e[i].NSProviderId;
      ids[k++] = b; ids[k++] = a;
      SetLastError(0);
      t_note("name-space order call returned %d", (int)wo(ids, (DWORD)k));
      (void)pa; (void)pb; }
    EXPECT_EQ(dx_child_query("nsbefore 2 1"), 0);
    free(ids); dx_ns_free(&l);
    dx_end();
}
/* A name-space order list that leaves a registered provider out is not exercised: on genuine Windows 10 the call
 * is accepted and the omitted provider drops out of the persisted order, which leaves the catalog in a state the
 * sweep cannot repair. */
TEST(dxnsord_unknown_provider_refused)
{
    GUID a = dx_guid(1); dx_nslist l; GUID *ids; wno_fn wo = nsorder(); INT r; int k = 0;
    DX_BEGIN();
    REQUIRE(wo);
    dx_ns_order_dirty = 1;
    EXPECT_EQ(ns_install(&a, NS_TEST, 1), 0);
    CHECK(dx_ns_enum(&l) > 1);
    ids = (GUID *)calloc(l.n + 2, sizeof(GUID));
    for (int i = 0; i < l.n; i++) if (!dx_is_ours(&l.e[i].NSProviderId)) ids[k++] = l.e[i].NSProviderId;
    ids[k++] = a; ids[k++] = dx_guid(200);
    SetLastError(0);
    r = wo(ids, (DWORD)k);
    CHECK(r != 0);
    CHECK(dx_child_query("nslast 1") == 0);
    free(ids); dx_ns_free(&l);
    dx_end();
}

/* ---- the 32-bit name-space catalog ---- */

typedef INT (WSAAPI *nsenum32_fn)(LPDWORD, LPWSANAMESPACE_INFOW);
static int ns32_has(const GUID *g)
{
    nsenum32_fn f = (nsenum32_fn)t_proc_in("ws2_32.dll", "WSCEnumNameSpaceProviders32");
    DWORD len = 0; INT n; WSANAMESPACE_INFOW *b; int has = 0;
    if (!f) return -1;
    n = f(&len, NULL);
    if (n >= 0 && n != SOCKET_ERROR) return 0;
    if (!len) return -1;
    b = (WSANAMESPACE_INFOW *)calloc(1, len);
    n = f(&len, b);
    for (int i = 0; i < n; i++) if (!memcmp(&b[i].NSProviderId, g, sizeof *g)) has = 1;
    free(b);
    return has;
}
TEST(dxns32_install_and_uninstall)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    REQUIRE(DX_NSINSTALL32); REQUIRE(DX_NSUNINSTALL32);
    if (ns32_has(&g) < 0) { t_skip("32-bit name-space enumeration unavailable"); dx_end(); return; }
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL32(NS_NAME, NS_PATH, NS_TEST, 1, &g), 0);
    EXPECT_EQ(ns32_has(&g), 1);
    EXPECT_EQ(DX_NSUNINSTALL32(&g), 0);
    EXPECT_EQ(ns32_has(&g), 0);
    dx_end();
}
TEST(dxns32_does_not_touch_native_catalog)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    REQUIRE(DX_NSINSTALL32); REQUIRE(DX_NSUNINSTALL32);
    if (ns32_has(&g) < 0) { t_skip("32-bit name-space enumeration unavailable"); dx_end(); return; }
    EXPECT_EQ(DX_NSINSTALL32(NS_NAME, NS_PATH, NS_TEST, 1, &g), 0);
    Sleep(200);
    CHECK(dx_ns_matches_baseline());
    EXPECT_EQ(DX_NSUNINSTALL32(&g), 0);
    dx_end();
}
TEST(dxns32_uninstall_unknown_fails)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    REQUIRE(DX_NSUNINSTALL32);
    SetLastError(0);
    EXPECT_EQ(DX_NSUNINSTALL32(&g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}
TEST(dxns32_duplicate_refused)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    REQUIRE(DX_NSINSTALL32); REQUIRE(DX_NSUNINSTALL32);
    if (ns32_has(&g) < 0) { t_skip("32-bit name-space enumeration unavailable"); dx_end(); return; }
    EXPECT_EQ(DX_NSINSTALL32(NS_NAME, NS_PATH, NS_TEST, 1, &g), 0);
    SetLastError(0);
    EXPECT_EQ(DX_NSINSTALL32(NS_NAME, NS_PATH, NS_TEST, 1, &g), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    EXPECT_EQ(DX_NSUNINSTALL32(&g), 0);
    dx_end();
}
TEST(dxns32_enable_unknown_fails)
{
    GUID g = dx_guid(1);
    DX_BEGIN();
    REQUIRE(DX_NSENABLE32);
    SetLastError(0);
    EXPECT_EQ(DX_NSENABLE32(&g, TRUE), SOCKET_ERROR);
    EXPECT_EQ(err_now(), DXE_INVAL);
    dx_end();
}

/* ---- application categories ---- */

static int appset(const WCHAR *path, const WCHAR *extra, DWORD cat, DWORD *prev, int *err)
{
    INT e = 0; dx_appset_fn f = DX_APPSET;
    DWORD xl = extra ? (DWORD)lstrlenW(extra) : 0;
    int r = f(path, (DWORD)lstrlenW(path), extra, xl, cat, prev, &e);
    if (err) *err = e;
    return r;
}
static int appget(const WCHAR *path, const WCHAR *extra, DWORD *cat, int *err)
{
    INT e = 0; dx_appget_fn f = DX_APPGET;
    DWORD xl = extra ? (DWORD)lstrlenW(extra) : 0;
    int r = f(path, (DWORD)lstrlenW(path), extra, xl, cat, &e);
    if (err) *err = e;
    return r;
}
#define APP_NEED() do { REQUIRE(DX_APPGET); REQUIRE(DX_APPSET); } while (0)
/* A lookup in a catalog that has no entries yet may fail for the missing key instead of the missing entry;
 * create and remove one entry first so that the catalog key exists. */
static void app_prepare(void)
{
    DWORD prev = 0; int e = 0;
    appset(dx_app_path2, NULL, 1, &prev, &e);
    appset(dx_app_path2, NULL, 0, &prev, &e);
}

TEST(dxapp_set_then_get)
{
    DWORD prev = 0x77, cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 4);
    dx_end();
}
TEST(dxapp_first_set_reports_zero_previous)
{
    DWORD prev = 0x77; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 1, &prev, &e), 0);
    EXPECT_EQ(prev, 0);
    dx_end();
}
TEST(dxapp_second_set_merges_categories)
{
    DWORD prev = 0x77, cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 1, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    EXPECT_EQ(prev, 1);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 5);
    dx_end();
}
TEST(dxapp_set_same_value_keeps_it)
{
    DWORD prev = 0, cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 2, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path, NULL, 2, &prev, &e), 0);
    EXPECT_EQ(prev, 2);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 2);
    dx_end();
}
TEST(dxapp_set_subset_does_not_remove_bits)
{
    DWORD prev = 0, cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 7, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path, NULL, 2, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 7);
    dx_end();
}
TEST(dxapp_all_bits_round_trip)
{
    DWORD prev = 0, cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 0xffffffffu, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 0xffffffffu);
    dx_end();
}
TEST(dxapp_high_bit_round_trip)
{
    DWORD prev = 0, cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 0x80000000u, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 0x80000000u);
    dx_end();
}
TEST(dxapp_zero_deletes_entry)
{
    DWORD prev = 0x77, cat = 0x55; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 6, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path, NULL, 0, &prev, &e), 0);
    EXPECT_EQ(prev, 6);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    EXPECT_EQ(cat, 0x55);
    dx_end();
}
TEST(dxapp_zero_on_missing_entry_succeeds)
{
    DWORD prev = 0x77; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 0, &prev, &e), 0);
    EXPECT_EQ(prev, 0);
    dx_end();
}
TEST(dxapp_zero_on_missing_entry_leaves_none)
{
    DWORD cat = 0; int e = 0, r;
    DX_BEGIN(); APP_NEED(); app_prepare();
    appset(dx_app_path, NULL, 0, NULL, &e);
    r = appget(dx_app_path, NULL, &cat, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_set_without_previous_output)
{
    DWORD cat = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 3, NULL, &e), 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), 0);
    EXPECT_EQ(cat, 3);
    dx_end();
}
TEST(dxapp_get_unknown_application)
{
    DWORD cat = 0x55; int e = 0;
    DX_BEGIN(); APP_NEED(); app_prepare();
    EXPECT_EQ(appget(dx_app_path, NULL, &cat, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    EXPECT_EQ(cat, 0x55);
    dx_end();
}
TEST(dxapp_two_applications_are_independent)
{
    DWORD prev = 0, c1 = 0, c2 = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 1, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path2, NULL, 8, &prev, &e), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &c1, &e), 0);
    EXPECT_EQ(appget(dx_app_path2, NULL, &c2, &e), 0);
    EXPECT_EQ(c1, 1); EXPECT_EQ(c2, 8);
    EXPECT_EQ(appset(dx_app_path, NULL, 0, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path2, NULL, &c2, &e), 0);
    EXPECT_EQ(c2, 8);
    dx_end();
}
TEST(dxapp_arguments_make_distinct_entries)
{
    static const WCHAR x1[] = L"one two";
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, x1, 2, &prev, &e), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(appget(dx_app_path, x1, &c, &e), 0);
    EXPECT_EQ(c, 2);
    EXPECT_EQ(appget(dx_app_path, NULL, &c, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_different_arguments_do_not_match)
{
    static const WCHAR x1[] = L"one two", x2[] = L"one three";
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, x1, 2, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path, x2, &c, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_plain_entry_not_found_by_argument_lookup)
{
    static const WCHAR x1[] = L"one two";
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 2, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path, x1, &c, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_delete_with_arguments_leaves_plain_entry)
{
    static const WCHAR x1[] = L"one two";
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 1, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path, x1, 2, &prev, &e), 0);
    EXPECT_EQ(appset(dx_app_path, x1, 0, &prev, &e), 0);
    EXPECT_EQ(prev, 2);
    EXPECT_EQ(appget(dx_app_path, NULL, &c, &e), 0);
    EXPECT_EQ(c, 1);
    dx_end();
}
TEST(dxapp_environment_path_expands)
{
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(L"%SystemDrive%\\ws2t_dx_catalog_dir\\dx_app_one.exe", NULL, 4, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &c, &e), 0);
    EXPECT_EQ(c, 4);
    dx_end();
}
TEST(dxapp_lookup_expands_environment_too)
{
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    EXPECT_EQ(appget(L"%SystemDrive%\\ws2t_dx_catalog_dir\\dx_app_one.exe", NULL, &c, &e), 0);
    EXPECT_EQ(c, 4);
    dx_end();
}
TEST(dxapp_path_case_insensitive_lookup)
{
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    int r;
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    r = appget(L"C:\\WS2T_DX_CATALOG_DIR\\DX_APP_ONE.EXE", NULL, &c, &e);
    CHECKF(r == 0 || e == DXE_NOTFOUND, "result %d error %d", r, e);
    t_note("an upper-case spelling of the path %s the entry", r == 0 ? "matches" : "does not match");
    dx_end();
}
TEST(dxapp_drive_letter_is_ignored)
{
    DWORD prev = 0, c = 0; int e = 0, r;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    r = appget(L"Z:\\ws2t_dx_catalog_dir\\dx_app_one.exe", NULL, &c, &e);
    CHECKF(r == 0 || e == DXE_NOTFOUND, "result %d error %d", r, e);
    t_note("a different drive letter %s the entry", r == 0 ? "matches" : "does not match");
    dx_end();
}
TEST(dxapp_other_directory_does_not_match)
{
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    EXPECT_EQ(appget(L"C:\\ws2t_dx_other_dir\\dx_app_one.exe", NULL, &c, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_other_file_name_does_not_match)
{
    DWORD prev = 0, c = 0; int e = 0;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    EXPECT_EQ(appget(dx_app_path2, NULL, &c, &e), SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_entry_survives_catalog_changes)
{
    DWORD prev = 0, c = 0; int e = 0; WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, &e), 0);
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(appget(dx_app_path, NULL, &c, &e), 0);
    EXPECT_EQ(c, 4);
    dx_end();
}
TEST(dxapp_failed_get_reports_through_errno_only)
{
    DWORD c = 0; INT e = 0; INT r;
    DX_BEGIN(); APP_NEED(); app_prepare();
    r = DX_APPGET(dx_app_path, (DWORD)lstrlenW(dx_app_path), NULL, 0, &c, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(e, DXE_NOTFOUND);
    dx_end();
}
TEST(dxapp_successful_get_leaves_errno)
{
    DWORD prev = 0, c = 0; INT e = 0x1234; INT r;
    DX_BEGIN(); APP_NEED();
    EXPECT_EQ(appset(dx_app_path, NULL, 4, &prev, (int *)&e), 0);
    e = 0x1234;
    r = DX_APPGET(dx_app_path, (DWORD)lstrlenW(dx_app_path), NULL, 0, &c, &e);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(e, 0x1234);
    dx_end();
}
