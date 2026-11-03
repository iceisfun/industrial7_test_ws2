/* Name-space provider configuration calls that must fail without changing anything:
 * WSCInstallNameSpace / WSCInstallNameSpaceEx (+32 forms), WSCUnInstallNameSpace(32), WSCEnableNSProvider(32).
 *
 * What the DLL does, as observed from its behaviour: it opens the configuration root, loads the relevant
 * catalog (native, or the 32-bit one for the *32 forms), copies and length-checks the strings (at most 259
 * characters each; 260 is refused), refuses a provider id that is already present, and only then persists.
 * Every refusal here is therefore reported as WSAEINVAL through the thread's last error with a -1 result and
 * leaves the catalog byte-for-byte as it was. Unknown ids are refused by uninstall and enable the same way.
 * Nothing in this file removes or toggles a stock provider: only ids that do not exist are used for those.
 * Expectations that depend on reaching the catalog are hard only when the process is elevated. */
#include "g1.h"

typedef int (WSAAPI *ns_inst_t)(const WCHAR *, const WCHAR *, DWORD, DWORD, const GUID *);
typedef int (WSAAPI *ns_instex_t)(const WCHAR *, const WCHAR *, DWORD, DWORD, const GUID *, const BLOB *);
typedef int (WSAAPI *ns_un_t)(const GUID *);
typedef int (WSAAPI *ns_en_t)(const GUID *, BOOL);

/* Variants: 0 plain, 1 plain 32-bit, 2 Ex, 3 Ex 32-bit. */
static const char *const k_inst_name[4] = { "WSCInstallNameSpace", "WSCInstallNameSpace32", "WSCInstallNameSpaceEx", "WSCInstallNameSpaceEx32" };
#define V_WOW(v) ((v) & 1)
#define V_EX(v)  ((v) >= 2)

static const WCHAR GOOD_PATH[] = L"%SystemRoot%\\system32\\gap1_no_such_nsp.dll";
static const WCHAR GOOD_NAME[] = L"gap1 namespace";

static int ns_install(int v, const WCHAR *name, const WCHAR *path, DWORD ns, DWORD ver, const GUID *g, const BLOB *b)
{
    void *f = g1_fn(k_inst_name[v]);
    SetLastError(0x1234);
    if (V_EX(v)) return ((ns_instex_t)f)(name, path, ns, ver, g, b);
    return ((ns_inst_t)f)(name, path, ns, ver, g);
}

/* True when the variant can be exercised here; otherwise it has called t_skip. */
static int ns_ready(int v)
{
    if (!g1_fn(k_inst_name[v])) { t_skip("missing export: %s", k_inst_name[v]); return 0; }
    if (g1_up()) { t_skip("WSAStartup failed"); return 0; }
    if (V_WOW(v)) {
        g1_sig s;
        if (g1_ns32_sig(&s)) { t_skip("32-bit name-space catalog not available"); return 0; }
    }
    return 1;
}

/* A refused call: -1 and WSAEINVAL (elevated), catalogs unchanged. Cleans up if it unexpectedly succeeded. */
static void expect_refused(int v, int rc, const GUID *g, const g1_snapshot *before, const char *what)
{
    DWORD e = GetLastError();
    t_check(rc == -1, __FILE__, __LINE__, what, "return %d want -1", rc);
    if (g1_elevated()) t_check(e == G1E_INVAL, __FILE__, __LINE__, what, "last error %lu want %d", e, G1E_INVAL);
    else t_note("not elevated: %s last error %lu", what, e);
    if (rc == 0 && (!memcmp(g, &g1_guid_a, sizeof *g) || !memcmp(g, &g1_guid_b, sizeof *g))) {   /* defensive: never leave our own entry behind */
        ns_un_t un = (ns_un_t)g1_fn(V_WOW(v) ? "WSCUnInstallNameSpace32" : "WSCUnInstallNameSpace");
        if (un) un(g);
    }
    CHECKF(g1_snap_same(before), "catalog changed by a refused call (%s)", what);
}

/* ---- string length limits: 259 accepted (not tried here, it would install), 260 and more refused ---- */
static WCHAR g_long[5000];

static void len_row(int v, int field /* 0 identifier, 1 path */, int len)
{
    g1_snapshot before; int rc;
    if (!ns_ready(v)) return;
    g1_snap(&before);
    g1_fill_w(g_long, len, L'a');
    rc = field == 0 ? ns_install(v, g_long, GOOD_PATH, 0x7e57, 1, &g1_guid_a, NULL)
                    : ns_install(v, GOOD_NAME, g_long, 0x7e57, 1, &g1_guid_a, NULL);
    expect_refused(v, rc, &g1_guid_a, &before, field == 0 ? "identifier too long" : "path too long");
}

#define LEN_TESTS(v, tag) \
    TEST(gap1_ns_##tag##_identifier_260) { len_row(v, 0, 260); } \
    TEST(gap1_ns_##tag##_identifier_261) { len_row(v, 0, 261); } \
    TEST(gap1_ns_##tag##_identifier_1000) { len_row(v, 0, 1000); } \
    TEST(gap1_ns_##tag##_identifier_4500) { len_row(v, 0, 4500); } \
    TEST(gap1_ns_##tag##_path_260) { len_row(v, 1, 260); } \
    TEST(gap1_ns_##tag##_path_261) { len_row(v, 1, 261); } \
    TEST(gap1_ns_##tag##_path_1000) { len_row(v, 1, 1000); } \
    TEST(gap1_ns_##tag##_path_4500) { len_row(v, 1, 4500); }
LEN_TESTS(0, plain)
LEN_TESTS(1, plain32)
LEN_TESTS(2, ex)
LEN_TESTS(3, ex32)

/* Both strings too long at once, with a blob and an odd name-space number: still just WSAEINVAL. */
static void both_long(int v)
{
    g1_snapshot before; static WCHAR other[400]; BLOB b; BYTE data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    if (!ns_ready(v)) return;
    g1_snap(&before);
    g1_fill_w(g_long, 300, L'x'); g1_fill_w(other, 300, L'y');
    b.cbSize = sizeof data; b.pBlobData = data;
    expect_refused(v, ns_install(v, g_long, other, 0xffffffffu, 0xffffffffu, &g1_guid_b, V_EX(v) ? &b : NULL), &g1_guid_b, &before, "both too long");
}
TEST(gap1_ns_plain_both_strings_too_long) { both_long(0); }
TEST(gap1_ns_plain32_both_strings_too_long) { both_long(1); }
TEST(gap1_ns_ex_both_strings_too_long) { both_long(2); }
TEST(gap1_ns_ex32_both_strings_too_long) { both_long(3); }

/* ---- an id that is already present is refused, whatever else is passed ---- */
enum { DUP_PLAIN, DUP_NS_ZERO, DUP_NS_OTHER, DUP_BLOB_EMPTY, DUP_BLOB_DATA, DUP_VERSION_BIG };

static void dup_rows(int v, int mode)
{
    GUID ids[16]; DWORD nss[16]; int n; g1_snapshot before;
    BYTE data[16] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6 };
    BLOB empty = { 0, NULL }, full = { sizeof data, data };
    if (!ns_ready(v)) return;
    if ((mode == DUP_BLOB_EMPTY || mode == DUP_BLOB_DATA) && !V_EX(v)) { t_skip("blob only exists on the Ex forms"); return; }
    n = g1_ns_ids(V_WOW(v), ids, nss, 16);
    if (n == 0) { t_skip("catalog lists no providers"); return; }
    g1_snap(&before);
    for (int i = 0; i < n; i++) {
        DWORD ns = nss[i], ver = 1; const BLOB *b = NULL; int rc;
        if (mode == DUP_NS_ZERO) ns = 0;
        if (mode == DUP_NS_OTHER) ns = 0x7e57;
        if (mode == DUP_BLOB_EMPTY) b = &empty;
        if (mode == DUP_BLOB_DATA) b = &full;
        if (mode == DUP_VERSION_BIG) ver = 0x7fffffff;
        rc = ns_install(v, GOOD_NAME, GOOD_PATH, ns, ver, &ids[i], b);
        expect_refused(v, rc, &ids[i], &before, "duplicate provider id");
    }
}

#define DUP_TESTS(v, tag) \
    TEST(gap1_ns_##tag##_duplicate_stock_id) { dup_rows(v, DUP_PLAIN); } \
    TEST(gap1_ns_##tag##_duplicate_stock_id_ns_zero) { dup_rows(v, DUP_NS_ZERO); } \
    TEST(gap1_ns_##tag##_duplicate_stock_id_ns_other) { dup_rows(v, DUP_NS_OTHER); } \
    TEST(gap1_ns_##tag##_duplicate_stock_id_big_version) { dup_rows(v, DUP_VERSION_BIG); } \
    TEST(gap1_ns_##tag##_duplicate_stock_id_empty_blob) { dup_rows(v, DUP_BLOB_EMPTY); } \
    TEST(gap1_ns_##tag##_duplicate_stock_id_data_blob) { dup_rows(v, DUP_BLOB_DATA); }
DUP_TESTS(0, plain)
DUP_TESTS(1, plain32)
DUP_TESTS(2, ex)
DUP_TESTS(3, ex32)

/* The refusal does not depend on the string check order: valid strings, existing id, and an invalid string,
 * existing id, give the same answer. */
static void dup_and_long(int v)
{
    GUID ids[16]; int n; g1_snapshot before;
    if (!ns_ready(v)) return;
    n = g1_ns_ids(V_WOW(v), ids, NULL, 16);
    if (n == 0) { t_skip("catalog lists no providers"); return; }
    g1_snap(&before);
    g1_fill_w(g_long, 400, L'z');
    expect_refused(v, ns_install(v, g_long, GOOD_PATH, 0x7e57, 1, &ids[0], NULL), &ids[0], &before, "long identifier + existing id");
    expect_refused(v, ns_install(v, GOOD_NAME, g_long, 0x7e57, 1, &ids[0], NULL), &ids[0], &before, "long path + existing id");
}
TEST(gap1_ns_plain_existing_id_and_long_string) { dup_and_long(0); }
TEST(gap1_ns_plain32_existing_id_and_long_string) { dup_and_long(1); }
TEST(gap1_ns_ex_existing_id_and_long_string) { dup_and_long(2); }
TEST(gap1_ns_ex32_existing_id_and_long_string) { dup_and_long(3); }

/* A refusal replaces whatever was in the thread's last error (it is set unconditionally at the end). */
TEST(gap1_ns_refusal_overwrites_last_error)
{
    GUID ids[4]; int n;
    if (!ns_ready(0)) return;
    n = g1_ns_ids(0, ids, NULL, 4);
    if (n == 0) { t_skip("catalog lists no providers"); return; }
    if (!g1_elevated()) { t_skip("needs elevation to reach the catalog"); return; }
    SetLastError(0);
    EXPECT_EQ(ns_install(0, GOOD_NAME, GOOD_PATH, 0x7e57, 1, &ids[0], NULL), -1);
    EXPECT_EQ(GetLastError(), G1E_INVAL);
    EXPECT_EQ(ns_install(0, GOOD_NAME, GOOD_PATH, 0x7e57, 1, &ids[0], NULL), -1);
    EXPECT_EQ(GetLastError(), G1E_INVAL);
}

/* ---- uninstall / enable of ids that do not exist ---- */
static void un_row(int wow, const GUID *g, const char *what)
{
    ns_un_t f = (ns_un_t)g1_fn(wow ? "WSCUnInstallNameSpace32" : "WSCUnInstallNameSpace");
    g1_snapshot before; int rc;
    G1_NEED(f);
    if (!ns_ready(wow ? 1 : 0)) return;
    g1_snap(&before);
    SetLastError(0x1234);
    rc = f(g);
    expect_refused(wow ? 1 : 0, rc, g, &before, what);
}
TEST(gap1_ns_uninstall_unknown_throwaway) { un_row(0, &g1_guid_a, "uninstall unknown"); }
TEST(gap1_ns_uninstall_unknown_zero_guid) { un_row(0, &g1_guid_zero, "uninstall zero guid"); }
TEST(gap1_ns_uninstall_unknown_all_ones_guid) { un_row(0, &g1_guid_ones, "uninstall all-ones guid"); }
TEST(gap1_ns_uninstall32_unknown_throwaway) { un_row(1, &g1_guid_a, "uninstall32 unknown"); }
TEST(gap1_ns_uninstall32_unknown_zero_guid) { un_row(1, &g1_guid_zero, "uninstall32 zero guid"); }
TEST(gap1_ns_uninstall32_unknown_all_ones_guid) { un_row(1, &g1_guid_ones, "uninstall32 all-ones guid"); }

static void en_row(int wow, const GUID *g, BOOL on, const char *what)
{
    ns_en_t f = (ns_en_t)g1_fn(wow ? "WSCEnableNSProvider32" : "WSCEnableNSProvider");
    g1_snapshot before; int rc;
    G1_NEED(f);
    if (!ns_ready(wow ? 1 : 0)) return;
    g1_snap(&before);
    SetLastError(0x1234);
    rc = f(g, on);
    expect_refused(wow ? 1 : 0, rc, g, &before, what);
}
TEST(gap1_ns_enable_unknown_throwaway_on) { en_row(0, &g1_guid_a, TRUE, "enable unknown"); }
TEST(gap1_ns_enable_unknown_throwaway_off) { en_row(0, &g1_guid_a, FALSE, "disable unknown"); }
TEST(gap1_ns_enable_unknown_zero_guid_on) { en_row(0, &g1_guid_zero, TRUE, "enable zero guid"); }
TEST(gap1_ns_enable_unknown_zero_guid_off) { en_row(0, &g1_guid_zero, FALSE, "disable zero guid"); }
TEST(gap1_ns_enable_unknown_ones_guid_on) { en_row(0, &g1_guid_ones, TRUE, "enable all-ones guid"); }
TEST(gap1_ns_enable_unknown_nonzero_value) { en_row(0, &g1_guid_b, (BOOL)0x7fff0000, "enable with odd boolean"); }
TEST(gap1_ns_enable32_unknown_throwaway_on) { en_row(1, &g1_guid_a, TRUE, "enable32 unknown"); }
TEST(gap1_ns_enable32_unknown_throwaway_off) { en_row(1, &g1_guid_a, FALSE, "disable32 unknown"); }
TEST(gap1_ns_enable32_unknown_zero_guid_on) { en_row(1, &g1_guid_zero, TRUE, "enable32 zero guid"); }
TEST(gap1_ns_enable32_unknown_zero_guid_off) { en_row(1, &g1_guid_zero, FALSE, "disable32 zero guid"); }
TEST(gap1_ns_enable32_unknown_ones_guid_on) { en_row(1, &g1_guid_ones, TRUE, "enable32 all-ones guid"); }
TEST(gap1_ns_enable32_unknown_nonzero_value) { en_row(1, &g1_guid_b, (BOOL)0x7fff0000, "enable32 with odd boolean"); }

/* The two catalogs are separate: an id that exists natively is judged against the 32-bit list for the *32 forms.
 * Uninstall/enable of an id missing from the 32-bit list are refused even if the native list has it, so only
 * ids absent from the targeted list are used. */
TEST(gap1_ns_32_forms_do_not_consult_native_list)
{
    GUID nat[16], w[16]; int nn, nw; g1_snapshot before;
    ns_un_t un = (ns_un_t)g1_fn("WSCUnInstallNameSpace32");
    G1_NEED(un);
    if (!ns_ready(1)) return;
    nn = g1_ns_ids(0, nat, NULL, 16); nw = g1_ns_ids(1, w, NULL, 16);
    for (int i = 0; i < nn; i++) {
        int in32 = 0;
        for (int j = 0; j < nw; j++) if (!memcmp(&nat[i], &w[j], sizeof(GUID))) in32 = 1;
        if (in32) continue;
        g1_snap(&before);
        SetLastError(0);
        EXPECT_EQ(un(&nat[i]), -1);
        if (g1_elevated()) EXPECT_EQ(GetLastError(), G1E_INVAL);
        CHECK(g1_snap_same(&before));
        return;
    }
    t_skip("every native provider id also exists in the 32-bit list");
}
