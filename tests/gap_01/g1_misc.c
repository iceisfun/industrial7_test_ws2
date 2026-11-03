/* Export shape of the gap_01 surface, service-class installation argument checks and application-category
 * argument checks.
 *
 * Exports: every name resolves in ws2_32.dll to code that lives in ws2_32.dll itself (none is a forwarder),
 * the ordinal and the name give the same address, and the A/W and native/32-bit twins are distinct functions.
 * WSAInstallServiceClassA/W: the ANSI form rejects a NULL structure before anything else; the wide form needs a
 * started stack first. A structure that names real classes is never passed here: the call is offered to every
 * active name-space provider, so only the destructive area does that.
 * WSCSetApplicationCategory refuses an empty or NULL path with WSAEINVAL before it touches any configuration,
 * and leaves its "previous categories" output alone. */
#include "g1.h"

static const struct { const char *name; unsigned ord; } k_exports[] = {
    {"WSCInstallNameSpaceEx", 143}, {"WSCInstallNameSpaceEx32", 145}, {"WSCSetProviderInfo32", 154},
    {"WSCUnInstallNameSpace32", 156}, {"WSCUpdateProvider32", 159}, {"WSCWriteProviderOrder32", 164},
    {"WSCDeinstallProvider32", 126}, {"WSCEnableNSProvider32", 129}, {"WSCInstallNameSpace32", 142},
    {"WSCInstallProvider64_32", 147}, {"WSCInstallProviderAndChains64_32", 148}, {"WSCInstallProvider", 146},
    {"WSCEnableNSProvider", 128}, {"WSCInstallNameSpace", 141}, {"WSCUnInstallNameSpace", 155},
    {"WSCWriteNameSpaceOrder", 161}, {"WSCSetProviderInfo", 153}, {"WSCUpdateProvider", 158},
    {"WSCSetApplicationCategory", 150}, {"WSAProviderCompleteAsyncCall", 89}, {"WSAProviderConfigChange", 90},
    {"WSAUnadvertiseProvider", 123}, {"WPUCompleteOverlappedRequest", 39}, {"WSAInstallServiceClassA", 76},
    {"WSAInstallServiceClassW", 77},
};

static void export_row(int i)
{
    FARPROC byname = t_proc_in("ws2_32.dll", k_exports[i].name);
    FARPROC byord = t_proc_ord("ws2_32.dll", k_exports[i].ord);
    HMODULE owner = NULL;
    if (!byname) { t_check(0, __FILE__, __LINE__, "export present", "%s missing", k_exports[i].name); return; }
    CHECKF(byord == byname, "ordinal %u does not resolve to %s", k_exports[i].ord, k_exports[i].name);
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)byname, &owner))
        CHECKF(owner == t_module("ws2_32.dll"), "%s is a forwarder, not code in ws2_32.dll", k_exports[i].name);
    else t_check(0, __FILE__, __LINE__, "module of export", "%s", k_exports[i].name);
}
#define EXPORT_TEST(i, nm) TEST(gap1_export_##nm) { export_row(i); }
EXPORT_TEST(0, WSCInstallNameSpaceEx) EXPORT_TEST(1, WSCInstallNameSpaceEx32) EXPORT_TEST(2, WSCSetProviderInfo32)
EXPORT_TEST(3, WSCUnInstallNameSpace32) EXPORT_TEST(4, WSCUpdateProvider32) EXPORT_TEST(5, WSCWriteProviderOrder32)
EXPORT_TEST(6, WSCDeinstallProvider32) EXPORT_TEST(7, WSCEnableNSProvider32) EXPORT_TEST(8, WSCInstallNameSpace32)
EXPORT_TEST(9, WSCInstallProvider64_32) EXPORT_TEST(10, WSCInstallProviderAndChains64_32) EXPORT_TEST(11, WSCInstallProvider)
EXPORT_TEST(12, WSCEnableNSProvider) EXPORT_TEST(13, WSCInstallNameSpace) EXPORT_TEST(14, WSCUnInstallNameSpace)
EXPORT_TEST(15, WSCWriteNameSpaceOrder) EXPORT_TEST(16, WSCSetProviderInfo) EXPORT_TEST(17, WSCUpdateProvider)
EXPORT_TEST(18, WSCSetApplicationCategory) EXPORT_TEST(19, WSAProviderCompleteAsyncCall) EXPORT_TEST(20, WSAProviderConfigChange)
EXPORT_TEST(21, WSAUnadvertiseProvider) EXPORT_TEST(22, WPUCompleteOverlappedRequest) EXPORT_TEST(23, WSAInstallServiceClassA)
EXPORT_TEST(24, WSAInstallServiceClassW)

static void distinct(const char *a, const char *b)
{
    FARPROC pa = t_proc_in("ws2_32.dll", a), pb = t_proc_in("ws2_32.dll", b);
    G1_NEED(pa); G1_NEED(pb);
    CHECKF(pa != pb, "%s and %s share an address", a, b);
}
TEST(gap1_twins_install_namespace) { distinct("WSCInstallNameSpace", "WSCInstallNameSpace32"); }
TEST(gap1_twins_install_namespace_ex) { distinct("WSCInstallNameSpaceEx", "WSCInstallNameSpaceEx32"); }
TEST(gap1_twins_install_namespace_plain_ex) { distinct("WSCInstallNameSpace", "WSCInstallNameSpaceEx"); }
TEST(gap1_twins_uninstall_namespace) { distinct("WSCUnInstallNameSpace", "WSCUnInstallNameSpace32"); }
TEST(gap1_twins_enable_provider) { distinct("WSCEnableNSProvider", "WSCEnableNSProvider32"); }
TEST(gap1_twins_set_provider_info) { distinct("WSCSetProviderInfo", "WSCSetProviderInfo32"); }
TEST(gap1_twins_update_provider) { distinct("WSCUpdateProvider", "WSCUpdateProvider32"); }
TEST(gap1_twins_write_order) { distinct("WSCWriteNameSpaceOrder", "WSCWriteProviderOrder32"); }
TEST(gap1_twins_deinstall) { distinct("WSCDeinstallProvider", "WSCDeinstallProvider32"); }
TEST(gap1_twins_write_provider_order) { distinct("WSCWriteProviderOrder", "WSCWriteProviderOrder32"); }
TEST(gap1_twins_install_provider_64_32) { distinct("WSCInstallProvider", "WSCInstallProvider64_32"); }
TEST(gap1_twins_install_service_class) { distinct("WSAInstallServiceClassA", "WSAInstallServiceClassW"); }

/* ---- WSAInstallServiceClassA / W ---- */
typedef int (WSAAPI *isc_t)(const void *);

CHILD(g1_isc_before_startup)
{
    isc_t a = (isc_t)g1_fn("WSAInstallServiceClassA"), w = (isc_t)g1_fn("WSAInstallServiceClassW");
    int rc;
    G1_STEP(1, a && w);
    /* The ANSI form checks its argument before anything needs the per-process state. */
    SetLastError(0); rc = a(NULL);
    G1_STEP(2, rc == -1); G1_STEP(3, GetLastError() == G1E_INVAL);
    /* The wide form initialises the per-process state first. */
    SetLastError(0); rc = w(NULL);
    G1_STEP(4, rc == -1); G1_STEP(5, GetLastError() == G1E_NOTINIT);
    return 0;
}
TEST(gap1_isc_null_before_startup)
{
    G1_NEED(g1_fn("WSAInstallServiceClassA")); G1_NEED(g1_fn("WSAInstallServiceClassW"));
    EXPECT_EQ(t_run_child("g1_isc_before_startup", "", 20000), 0);
}
TEST(gap1_isc_ansi_null_after_startup)
{
    isc_t a = (isc_t)g1_fn("WSAInstallServiceClassA");
    G1_NEED(a); G1_UP();
    SetLastError(0);
    EXPECT_EQ(a(NULL), -1);
    EXPECT_EQ(GetLastError(), G1E_INVAL);
}
TEST(gap1_isc_wide_null_after_startup)
{
    isc_t w = (isc_t)g1_fn("WSAInstallServiceClassW");
    G1_NEED(w); G1_UP();
    SetLastError(0);
    EXPECT_EQ(w(NULL), -1);
    EXPECT_EQ(GetLastError(), G1E_INVAL);
}
TEST(gap1_isc_null_replaces_previous_last_error)
{
    isc_t a = (isc_t)g1_fn("WSAInstallServiceClassA"), w = (isc_t)g1_fn("WSAInstallServiceClassW");
    G1_NEED(a); G1_NEED(w); G1_UP();
    SetLastError(0x4242); EXPECT_EQ(a(NULL), -1); EXPECT_EQ(GetLastError(), G1E_INVAL);
    SetLastError(0x4242); EXPECT_EQ(w(NULL), -1); EXPECT_EQ(GetLastError(), G1E_INVAL);
}
TEST(gap1_isc_null_repeated_is_stable)
{
    isc_t a = (isc_t)g1_fn("WSAInstallServiceClassA"), w = (isc_t)g1_fn("WSAInstallServiceClassW");
    G1_NEED(a); G1_NEED(w); G1_UP();
    for (int i = 0; i < 4; i++) {
        SetLastError(0); EXPECT_EQ(a(NULL), -1); EXPECT_EQ(GetLastError(), G1E_INVAL);
        SetLastError(0); EXPECT_EQ(w(NULL), -1); EXPECT_EQ(GetLastError(), G1E_INVAL);
    }
}

/* ---- WSCSetApplicationCategory: arguments checked before any configuration is read ---- */
typedef int (WSAAPI *appset_t)(const WCHAR *, DWORD, const WCHAR *, DWORD, DWORD, DWORD *, INT *);

static void app_row(const WCHAR *path, DWORD pathlen, const WCHAR *extra, DWORD extralen, DWORD cat, const char *what)
{
    appset_t f = (appset_t)g1_fn("WSCSetApplicationCategory");
    DWORD prev = 0x77; INT err = G1_NOERR; int rc;
    G1_NEED(f);
    rc = f(path, pathlen, extra, extralen, cat, &prev, &err);
    t_check(rc == -1, __FILE__, __LINE__, what, "return %d want -1", rc);
    t_check(err == G1E_INVAL, __FILE__, __LINE__, what, "error %d want %d", (int)err, G1E_INVAL);
    t_check(prev == 0x77, __FILE__, __LINE__, what, "previous categories written: 0x%lx", prev);
}
TEST(gap1_appcat_null_path_category_1) { app_row(NULL, 20, NULL, 0, 1, "null path"); }
TEST(gap1_appcat_null_path_category_0) { app_row(NULL, 20, NULL, 0, 0, "null path, category 0"); }
TEST(gap1_appcat_null_path_all_bits) { app_row(NULL, 20, NULL, 0, 0xffffffffu, "null path, all bits"); }
TEST(gap1_appcat_null_path_zero_length) { app_row(NULL, 0, NULL, 0, 1, "null path, zero length"); }
TEST(gap1_appcat_empty_length_category_1) { app_row(L"C:\\gap1\\none.exe", 0, NULL, 0, 1, "zero path length"); }
TEST(gap1_appcat_empty_length_category_0) { app_row(L"C:\\gap1\\none.exe", 0, NULL, 0, 0, "zero path length, category 0"); }
TEST(gap1_appcat_empty_length_all_bits) { app_row(L"C:\\gap1\\none.exe", 0, NULL, 0, 0xffffffffu, "zero path length, all bits"); }
TEST(gap1_appcat_zero_length_with_arguments) { app_row(L"C:\\gap1\\none.exe", 0, L"-x", 2, 1, "zero path length with arguments"); }
TEST(gap1_appcat_null_path_with_arguments) { app_row(NULL, 17, L"-x", 2, 1, "null path with arguments"); }
TEST(gap1_appcat_empty_string_zero_length) { app_row(L"", 0, NULL, 0, 1, "empty path"); }
TEST(gap1_appcat_failure_replaces_previous_error_out)
{
    appset_t f = (appset_t)g1_fn("WSCSetApplicationCategory");
    DWORD prev = 0; INT err = 0; int rc;
    G1_NEED(f);
    rc = f(NULL, 3, NULL, 0, 1, &prev, &err);
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(err, G1E_INVAL);
}
