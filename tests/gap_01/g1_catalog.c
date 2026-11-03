/* Provider-catalog writers that must fail without changing anything:
 * WSCInstallProviderAndChains64_32, WSCInstallProvider, WSCInstallProvider64_32, WSCSetProviderInfo(32),
 * WSCUpdateProvider(32), WSCDeinstallProvider(32) and WSCWriteProviderOrder(32).
 *
 * The chained-install call checks its arguments in a fixed order before it reads or writes any catalog:
 * the error out-parameter (NULL: silent -1), the provider id, the library path (at most 259 characters; with
 * no 32-bit path given it must lie under the system directory), the layered-provider name (at most 254
 * characters), the record list (a non-NULL list needs a non-zero count and no two records with the same
 * address family, socket type and protocol). All of those refusals are WSAEINVAL in the out-parameter.
 * The plain install refuses a provider id that already exists (WSANO_RECOVERY) and a library path of 260
 * or more characters (WSAEINVAL). Updates are matched by catalog id and count the rewritten records, so a
 * list that matches nothing fails with WSANO_RECOVERY. Deinstall of an unknown id is WSAEFAULT; a provider
 * order naming unknown catalog ids is WSAEINVAL. Provider-info type 0 wants a 4-byte value, type 1 is not
 * implemented, other types are WSANO_RECOVERY. Hard expectations need an elevated process (the catalog root
 * must be writable to reach the checks); otherwise the observed values are only logged. */
#include "g1.h"

typedef int (WSAAPI *chains_t)(const GUID *, const WCHAR *, const WCHAR *, const WCHAR *, DWORD, WSAPROTOCOL_INFOW *, DWORD, DWORD *, INT *);
typedef int (WSAAPI *inst_t)(const GUID *, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, INT *);
typedef int (WSAAPI *deinst_t)(const GUID *, INT *);
typedef int (WSAAPI *order_t)(DWORD *, DWORD);
typedef int (WSAAPI *upd_t)(const GUID *, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, INT *);
typedef int (WSAAPI *pinfo_t)(const GUID *, int, BYTE *, size_t, DWORD, INT *);

static const WCHAR SYS_PATH[] = L"%SystemRoot%\\system32\\mswsock.dll";
static WCHAR g_buf[5000];

/* After a refused call: catalogs equal the snapshot; an error is hard only when elevated. */
static void check_err(const char *what, INT err, INT want)
{
    if (g1_elevated()) t_check(err == want, __FILE__, __LINE__, what, "error %d want %d", (int)err, (int)want);
    else t_note("not elevated: %s error %d", what, (int)err);
}

/* ---- WSCInstallProviderAndChains64_32 ---- */
static int chains(const GUID *g, const WCHAR *p64, const WCHAR *p32, const WCHAR *name, DWORD flags,
                  WSAPROTOCOL_INFOW *list, DWORD n, INT *err)
{
    chains_t f = (chains_t)g1_fn("WSCInstallProviderAndChains64_32");
    DWORD out[8] = { 0 };
    *err = G1_NOERR;
    return f(g, p64, p32, name, flags, list, n, out, err);
}

static void chains_row(const char *what, const GUID *g, const WCHAR *p64, const WCHAR *p32, const WCHAR *name,
                       WSAPROTOCOL_INFOW *list, DWORD n, INT want)
{
    g1_snapshot before; INT err; int rc;
    G1_NEED(g1_fn("WSCInstallProviderAndChains64_32"));
    g1_snap(&before);
    rc = chains(g, p64, p32, name, 0, list, n, &err);
    t_check(rc == -1, __FILE__, __LINE__, what, "return %d want -1", rc);
    check_err(what, err, want);
    CHECKF(g1_snap_same(&before), "catalog changed (%s)", what);
}

TEST(gap1_chains_null_errno_is_silent_failure)
{
    WSAPROTOCOL_INFOW p; g1_snapshot before; int rc;
    chains_t f = (chains_t)g1_fn("WSCInstallProviderAndChains64_32");
    G1_NEED(f);
    g1_base_info(&p, 0x7e01);
    g1_snap(&before);
    rc = f(&g1_guid_a, SYS_PATH, NULL, L"gap1 chain", 0, &p, 1, NULL, NULL);
    EXPECT_EQ(rc, G1E_INVAL);   /* no error-out pointer: the code comes back as the return value */
    CHECK(g1_snap_same(&before));
}
TEST(gap1_chains_null_provider_id)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("null provider id", NULL, SYS_PATH, NULL, L"gap1 chain", &p, 1, G1E_INVAL);
}
TEST(gap1_chains_null_path)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("null library path", &g1_guid_a, NULL, NULL, L"gap1 chain", &p, 1, G1E_INVAL);
}
#define CHAINS_PATH_LEN(n) \
    TEST(gap1_chains_path_##n##_chars) { \
        WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01); g1_fill_w(g_buf, n, L'p'); \
        chains_row("library path too long", &g1_guid_a, g_buf, L"x.dll", L"gap1 chain", &p, 1, G1E_INVAL); }
CHAINS_PATH_LEN(260) CHAINS_PATH_LEN(261) CHAINS_PATH_LEN(500) CHAINS_PATH_LEN(4000)

/* With no 32-bit path the 64-bit path must start with the system directory. */
TEST(gap1_chains_path_outside_system_dir_without_32bit_path)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("path outside system dir", &g1_guid_a, L"C:\\gap1_no_such_dir\\gap1_lsp.dll", NULL, L"gap1 chain", &p, 1, G1E_INVAL);
}
TEST(gap1_chains_path_shorter_than_system_dir_without_32bit_path)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("path shorter than system dir", &g1_guid_a, L"C:\\a.dll", NULL, L"gap1 chain", &p, 1, G1E_INVAL);
}
TEST(gap1_chains_relative_path_without_32bit_path)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("relative path", &g1_guid_a, L"gap1_lsp_relative_path_that_is_long_enough.dll", NULL, L"gap1 chain", &p, 1, G1E_INVAL);
}
TEST(gap1_chains_null_name)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("null name", &g1_guid_a, SYS_PATH, NULL, NULL, &p, 1, G1E_INVAL);
}
#define CHAINS_NAME_LEN(n) \
    TEST(gap1_chains_name_##n##_chars) { \
        WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01); g1_fill_w(g_buf, n, L'n'); \
        chains_row("name too long", &g1_guid_a, SYS_PATH, NULL, g_buf, &p, 1, G1E_INVAL); }
CHAINS_NAME_LEN(255) CHAINS_NAME_LEN(256) CHAINS_NAME_LEN(1000)

TEST(gap1_chains_record_list_with_zero_count)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    chains_row("list with zero count", &g1_guid_a, SYS_PATH, NULL, L"gap1 chain", &p, 0, G1E_INVAL);
}
TEST(gap1_chains_duplicate_records)
{
    WSAPROTOCOL_INFOW p[2]; g1_base_info(&p[0], 0x7e01); g1_base_info(&p[1], 0x7e01);
    chains_row("two identical records", &g1_guid_a, SYS_PATH, NULL, L"gap1 chain", p, 2, G1E_INVAL);
}
/* Only family, socket type and protocol decide what is a duplicate; flags and names do not matter. */
TEST(gap1_chains_duplicate_records_other_fields_differ)
{
    WSAPROTOCOL_INFOW p[2]; g1_base_info(&p[0], 0x7e01); g1_base_info(&p[1], 0x7e01);
    p[1].dwServiceFlags1 = 0; p[1].dwProviderFlags = 7; p[1].iVersion = 9; p[1].iMaxSockAddr = 64;
    lstrcpyW(p[1].szProtocol, L"gap1 other name"); p[1].dwCatalogEntryId = 99;
    chains_row("duplicate by family/type/protocol", &g1_guid_a, SYS_PATH, NULL, L"gap1 chain", p, 2, G1E_INVAL);
}
TEST(gap1_chains_duplicate_first_and_third)
{
    WSAPROTOCOL_INFOW p[3]; g1_base_info(&p[0], 0x7e01); g1_base_info(&p[1], 0x7e02); g1_base_info(&p[2], 0x7e01);
    chains_row("first and third identical", &g1_guid_a, SYS_PATH, NULL, L"gap1 chain", p, 3, G1E_INVAL);
}
TEST(gap1_chains_duplicate_last_two_of_four)
{
    WSAPROTOCOL_INFOW p[4]; g1_base_info(&p[0], 0x7e01); g1_base_info(&p[1], 0x7e02);
    g1_base_info(&p[2], 0x7e03); g1_base_info(&p[3], 0x7e03);
    chains_row("last two identical", &g1_guid_a, SYS_PATH, NULL, L"gap1 chain", p, 4, G1E_INVAL);
}
/* A refused call leaves the busy marker clear: a second call is judged on its arguments again. */
TEST(gap1_chains_repeat_refusal_is_stable)
{
    WSAPROTOCOL_INFOW p; g1_base_info(&p, 0x7e01);
    for (int i = 0; i < 3; i++) chains_row("repeat", NULL, SYS_PATH, NULL, L"gap1 chain", &p, 1, G1E_INVAL);
}

/* ---- WSCInstallProvider / WSCInstallProvider64_32 ---- */
static void install_dup_row(const char *fn)
{
    inst_t f = (inst_t)g1_fn(fn);
    GUID ids[64]; int n; g1_snapshot before; WSAPROTOCOL_INFOW p;
    G1_NEED(f);
    n = g1_proto_ids(0, ids, 64);
    if (n == 0) { t_skip("no stock providers listed"); return; }
    g1_base_info(&p, 0x7e01);
    g1_snap(&before);
    for (int i = 0; i < n; i++) {
        INT err = G1_NOERR;
        int rc = f(&ids[i], SYS_PATH, &p, 1, &err);
        t_check(rc == -1, __FILE__, __LINE__, "install existing provider id", "return %d want -1", rc);
        check_err("install existing provider id", err, G1E_NORECOVERY);
        if (rc == 0) { deinst_t d = (deinst_t)g1_fn("WSCDeinstallProvider"); (void)d; /* never remove a stock provider here */ }
    }
    CHECK(g1_snap_same(&before));
}
TEST(gap1_install_existing_provider_id_is_refused) { install_dup_row("WSCInstallProvider"); }
TEST(gap1_install64_32_existing_provider_id_is_refused) { install_dup_row("WSCInstallProvider64_32"); }

static void install_long_row(const char *fn, int len)
{
    inst_t f = (inst_t)g1_fn(fn);
    WSAPROTOCOL_INFOW p; g1_snapshot before; INT err = G1_NOERR; int rc;
    G1_NEED(f);
    g1_base_info(&p, 0x7e01);
    g1_fill_w(g_buf, len, L'q');
    g1_snap(&before);
    rc = f(&g1_guid_b, g_buf, &p, 1, &err);
    t_check(rc == -1, __FILE__, __LINE__, "install with long library path", "return %d want -1", rc);
    check_err("install with long library path", err, G1E_INVAL);
    if (rc == 0) { deinst_t d = (deinst_t)g1_fn("WSCDeinstallProvider"); INT e; if (d) d(&g1_guid_b, &e); }
    CHECK(g1_snap_same(&before));
}
#define INSTALL_LONG(tag, fn, n) TEST(gap1_##tag##_path_##n##_chars) { install_long_row(fn, n); }
INSTALL_LONG(install, "WSCInstallProvider", 260)
INSTALL_LONG(install, "WSCInstallProvider", 261)
INSTALL_LONG(install, "WSCInstallProvider", 1000)
INSTALL_LONG(install, "WSCInstallProvider", 4000)
INSTALL_LONG(install64_32, "WSCInstallProvider64_32", 260)
INSTALL_LONG(install64_32, "WSCInstallProvider64_32", 261)
INSTALL_LONG(install64_32, "WSCInstallProvider64_32", 1000)
INSTALL_LONG(install64_32, "WSCInstallProvider64_32", 4000)

/* ---- WSCSetProviderInfo / WSCSetProviderInfo32 ---- */
static void pinfo_type_row(const char *fn, int type)
{
    static const size_t sizes[] = { 0, 1, 3, 4, 5, 8 };
    pinfo_t f = (pinfo_t)g1_fn(fn);
    g1_snapshot before; BYTE val[16] = { 1, 0, 0, 0 };
    G1_NEED(f);
    g1_snap(&before);
    for (int i = 0; i < G1_N(sizes); i++) {
        INT err = G1_NOERR; int rc = f(&g1_guid_a, type, val, sizes[i], 0, &err);
        INT want;
        if (type == 0) want = sizes[i] == 4 ? G1E_NORECOVERY : G1E_INVAL;
        else if (type == 1) want = G1E_CALLNOTIMPL;
        else want = G1E_NORECOVERY;
        t_check(rc == -1, __FILE__, __LINE__, "set provider info", "type %d size %zu return %d want -1", type, sizes[i], rc);
        if (g1_elevated()) t_check(err == want, __FILE__, __LINE__, "set provider info error", "type %d size %zu error %d want %d", type, sizes[i], (int)err, (int)want);
        else t_note("not elevated: type %d size %zu error %d", type, sizes[i], (int)err);
    }
    CHECK(g1_snap_same(&before));
}
#define PINFO_TYPE(tag, fn, ty, nm) TEST(gap1_##tag##_type_##nm) { pinfo_type_row(fn, ty); }
PINFO_TYPE(setinfo, "WSCSetProviderInfo", 0, 0)
PINFO_TYPE(setinfo, "WSCSetProviderInfo", 1, 1)
PINFO_TYPE(setinfo, "WSCSetProviderInfo", 2, 2)
PINFO_TYPE(setinfo, "WSCSetProviderInfo", 3, 3)
PINFO_TYPE(setinfo, "WSCSetProviderInfo", -1, minus1)
PINFO_TYPE(setinfo, "WSCSetProviderInfo", 0x7fffffff, max)
PINFO_TYPE(setinfo32, "WSCSetProviderInfo32", 0, 0)
PINFO_TYPE(setinfo32, "WSCSetProviderInfo32", 1, 1)
PINFO_TYPE(setinfo32, "WSCSetProviderInfo32", 2, 2)
PINFO_TYPE(setinfo32, "WSCSetProviderInfo32", 3, 3)
PINFO_TYPE(setinfo32, "WSCSetProviderInfo32", -1, minus1)
PINFO_TYPE(setinfo32, "WSCSetProviderInfo32", 0x7fffffff, max)

/* The flags argument is not looked at; the zero id behaves like any unknown id. */
static void pinfo_flags_row(const char *fn, DWORD flags, const GUID *g)
{
    pinfo_t f = (pinfo_t)g1_fn(fn);
    BYTE val[4] = { 0, 0, 0, 0 }; INT err = G1_NOERR; int rc;
    G1_NEED(f);
    rc = f(g, 0, val, 4, flags, &err);
    EXPECT_EQ(rc, -1);
    check_err("set provider info flags", err, G1E_NORECOVERY);
}
TEST(gap1_setinfo_flags_ignored) { pinfo_flags_row("WSCSetProviderInfo", 0xffffffffu, &g1_guid_a); }
TEST(gap1_setinfo_zero_id) { pinfo_flags_row("WSCSetProviderInfo", 0, &g1_guid_zero); }
TEST(gap1_setinfo32_flags_ignored) { pinfo_flags_row("WSCSetProviderInfo32", 0xffffffffu, &g1_guid_a); }
TEST(gap1_setinfo32_zero_id) { pinfo_flags_row("WSCSetProviderInfo32", 0, &g1_guid_zero); }

/* ---- WSCUpdateProvider / WSCUpdateProvider32 ---- */
static void update_unknown_row(const char *fn, int n)
{
    upd_t f = (upd_t)g1_fn(fn);
    WSAPROTOCOL_INFOW p[5]; g1_snapshot before; INT err = G1_NOERR; int rc;
    G1_NEED(f);
    for (int i = 0; i < 5; i++) { g1_base_info(&p[i], 0x7e01 + i); p[i].dwCatalogEntryId = 0xFFFF0000u + i; }
    g1_snap(&before);
    rc = f(&g1_guid_a, SYS_PATH, p, n, &err);
    t_check(rc == -1, __FILE__, __LINE__, "update unknown provider", "return %d want -1", rc);
    check_err("update unknown provider", err, G1E_NORECOVERY);
    CHECK(g1_snap_same(&before));
}
TEST(gap1_update_unknown_provider_1) { update_unknown_row("WSCUpdateProvider", 1); }
TEST(gap1_update_unknown_provider_2) { update_unknown_row("WSCUpdateProvider", 2); }
TEST(gap1_update_unknown_provider_5) { update_unknown_row("WSCUpdateProvider", 5); }
TEST(gap1_update32_unknown_provider_1) { update_unknown_row("WSCUpdateProvider32", 1); }
TEST(gap1_update32_unknown_provider_2) { update_unknown_row("WSCUpdateProvider32", 2); }
TEST(gap1_update32_unknown_provider_5) { update_unknown_row("WSCUpdateProvider32", 5); }

/* A stock provider with records whose catalog ids match nothing rewrites zero records, which is not the
 * requested count: refused, and the catalog is untouched. */
static void update_stock_row(int wow)
{
    upd_t f = (upd_t)g1_fn(wow ? "WSCUpdateProvider32" : "WSCUpdateProvider");
    GUID ids[64]; int n; WSAPROTOCOL_INFOW p; g1_snapshot before;
    G1_NEED(f);
    n = g1_proto_ids(wow, ids, 64);
    if (n == 0) { t_skip("no providers listed"); return; }
    g1_base_info(&p, 0x7e01); p.dwCatalogEntryId = 0xFFFF0001u;
    g1_snap(&before);
    for (int i = 0; i < n; i++) {
        INT err = G1_NOERR; int rc = f(&ids[i], SYS_PATH, &p, 1, &err);
        t_check(rc == -1, __FILE__, __LINE__, "update stock provider with unmatched record", "return %d want -1", rc);
        check_err("update stock provider with unmatched record", err, G1E_NORECOVERY);
    }
    CHECK(g1_snap_same(&before));
}
TEST(gap1_update_stock_providers_unmatched_record) { update_stock_row(0); }
TEST(gap1_update32_stock_providers_unmatched_record) { update_stock_row(1); }

/* ---- WSCDeinstallProvider / WSCDeinstallProvider32 of ids that do not exist ---- */
static void deinstall_row(const char *fn, const GUID *g)
{
    deinst_t f = (deinst_t)g1_fn(fn);
    g1_snapshot before; INT err = G1_NOERR; int rc;
    G1_NEED(f);
    g1_snap(&before);
    rc = f(g, &err);
    t_check(rc == -1, __FILE__, __LINE__, "deinstall unknown provider", "return %d want -1", rc);
    check_err("deinstall unknown provider", err, G1E_FAULT);
    CHECK(g1_snap_same(&before));
}
TEST(gap1_deinstall_unknown_throwaway) { deinstall_row("WSCDeinstallProvider", &g1_guid_a); }
TEST(gap1_deinstall_unknown_zero_guid) { deinstall_row("WSCDeinstallProvider", &g1_guid_zero); }
TEST(gap1_deinstall_unknown_all_ones_guid) { deinstall_row("WSCDeinstallProvider", &g1_guid_ones); }
TEST(gap1_deinstall32_unknown_throwaway) { deinstall_row("WSCDeinstallProvider32", &g1_guid_a); }
TEST(gap1_deinstall32_unknown_zero_guid) { deinstall_row("WSCDeinstallProvider32", &g1_guid_zero); }
TEST(gap1_deinstall32_unknown_all_ones_guid) { deinstall_row("WSCDeinstallProvider32", &g1_guid_ones); }

/* ---- WSCWriteProviderOrder / WSCWriteProviderOrder32 with unknown catalog ids ---- */
static void order_row(const char *fn, const DWORD *ids, DWORD n)
{
    order_t f = (order_t)g1_fn(fn);
    DWORD tmp[8]; g1_snapshot before; int rc;
    G1_NEED(f);
    memcpy(tmp, ids, n * sizeof(DWORD));
    g1_snap(&before);
    rc = f(tmp, n);
    t_check(rc != 0, __FILE__, __LINE__, "order naming unknown ids", "returned success");
    if (g1_elevated()) t_check(rc == G1E_INVAL, __FILE__, __LINE__, "order naming unknown ids", "return %d want %d", rc, G1E_INVAL);
    else t_note("not elevated: order returned %d", rc);
    CHECK(g1_snap_same(&before));
}
static const DWORD ord_one[] = { 0xFFFF7e57u };
static const DWORD ord_two[] = { 0xFFFF7e57u, 0xFFFF7e58u };
static const DWORD ord_same[] = { 0xFFFF7e57u, 0xFFFF7e57u, 0xFFFF7e57u };
static const DWORD ord_zero[] = { 0 };
TEST(gap1_order_one_unknown_id) { order_row("WSCWriteProviderOrder", ord_one, 1); }
TEST(gap1_order_two_unknown_ids) { order_row("WSCWriteProviderOrder", ord_two, 2); }
TEST(gap1_order_repeated_unknown_id) { order_row("WSCWriteProviderOrder", ord_same, 3); }
TEST(gap1_order_zero_id) { order_row("WSCWriteProviderOrder", ord_zero, 1); }
TEST(gap1_order32_one_unknown_id) { order_row("WSCWriteProviderOrder32", ord_one, 1); }
TEST(gap1_order32_two_unknown_ids) { order_row("WSCWriteProviderOrder32", ord_two, 2); }
TEST(gap1_order32_repeated_unknown_id) { order_row("WSCWriteProviderOrder32", ord_same, 3); }
TEST(gap1_order32_zero_id) { order_row("WSCWriteProviderOrder32", ord_zero, 1); }
