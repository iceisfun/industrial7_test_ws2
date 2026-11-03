/* WSCGetProviderPath / WSCGetProviderPath32 against a throwaway catalog entry: the buffer-size protocol
 * (too small buffer, exact buffer, oversized buffer) and the unknown-provider answer. The entry is installed
 * by the test and removed again; stock entries are never read through this path here. Skipped unless
 * elevated. */
#include "dx.h"

typedef INT (WSAAPI *dx_getpath_fn)(const GUID *, WCHAR *, LPINT, LPINT);

static dx_getpath_fn getpath(int which)
{
    return (dx_getpath_fn)t_proc_in("ws2_32.dll", which == DX_WOW ? "WSCGetProviderPath32" : "WSCGetProviderPath");
}

static int install_ours(int which, const GUID *g)
{
    WSAPROTOCOL_INFOW p;
    dx_base_entry(&p, dx_guid_index(g));
    return which == DX_WOW ? dx_install64_32_one(g, &p) : dx_install_one(g, &p);
}

static void path_too_small(int which)
{
    GUID g = dx_guid(1); WCHAR buf[MAX_PATH]; INT len, err = 0, r; INT want;
    dx_getpath_fn f = getpath(which);
    DX_BEGIN();
    if (!f || (which == DX_WOW && !dx_wow_available())) { t_skip("entry point unavailable"); dx_end(); return; }
    EXPECT_EQ(install_ours(which, &g), 0);
    want = (INT)lstrlenW(dx_dll_path());
    len = 4;
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, DXE_FAULT);
    CHECK(len > 4);
    t_note("required length %s the string length", len >= want ? "covers" : "is below");
    dx_end();
}
static void path_exact(int which)
{
    GUID g = dx_guid(1); WCHAR buf[MAX_PATH]; INT len, err = 0, r;
    dx_getpath_fn f = getpath(which);
    DX_BEGIN();
    if (!f || (which == DX_WOW && !dx_wow_available())) { t_skip("entry point unavailable"); dx_end(); return; }
    EXPECT_EQ(install_ours(which, &g), 0);
    len = (INT)lstrlenW(dx_dll_path()) + 1;
    r = f(&g, buf, &len, &err);
    if (r == 0) EXPECT_WSTR(buf, dx_dll_path());
    else t_note("a buffer of exactly the string length plus one unit was refused (error %d)", err);
    dx_end();
}
static void path_big(int which)
{
    GUID g = dx_guid(1); WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0, r;
    dx_getpath_fn f = getpath(which);
    DX_BEGIN();
    if (!f || (which == DX_WOW && !dx_wow_available())) { t_skip("entry point unavailable"); dx_end(); return; }
    EXPECT_EQ(install_ours(which, &g), 0);
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, 0);
    if (r == 0) EXPECT_WSTR(buf, dx_dll_path());
    dx_end();
}
static void path_unknown(int which)
{
    GUID g = dx_guid(1); WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0, r;
    dx_getpath_fn f = getpath(which);
    DX_BEGIN();
    if (!f || (which == DX_WOW && !dx_wow_available())) { t_skip("entry point unavailable"); dx_end(); return; }
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECKF(err != 0, "no error reported");
    t_note("path of an unknown provider id: error class %s", err == DXE_INVAL ? "invalid-argument" : "other");
    dx_end();
}
static void path_after_deinstall(int which)
{
    GUID g = dx_guid(1); WCHAR buf[MAX_PATH]; INT len = MAX_PATH, err = 0, r;
    dx_getpath_fn f = getpath(which);
    dx_deinstall_fn de = which == DX_WOW ? DX_DEINSTALL32 : DX_DEINSTALL;
    DX_BEGIN();
    if (!f || !de || (which == DX_WOW && !dx_wow_available())) { t_skip("entry point unavailable"); dx_end(); return; }
    EXPECT_EQ(install_ours(which, &g), 0);
    EXPECT_EQ(de(&g, &err), 0);
    r = f(&g, buf, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    dx_end();
}

TEST(dxpath_native_buffer_too_small) { path_too_small(DX_NATIVE); }
TEST(dxpath_native_buffer_exact) { path_exact(DX_NATIVE); }
TEST(dxpath_native_buffer_large) { path_big(DX_NATIVE); }
TEST(dxpath_native_unknown_provider_fails) { path_unknown(DX_NATIVE); }
TEST(dxpath_native_after_deinstall_fails) { path_after_deinstall(DX_NATIVE); }
TEST(dxpath_wow_buffer_too_small) { path_too_small(DX_WOW); }
TEST(dxpath_wow_buffer_exact) { path_exact(DX_WOW); }
TEST(dxpath_wow_buffer_large) { path_big(DX_WOW); }
TEST(dxpath_wow_unknown_provider_fails) { path_unknown(DX_WOW); }
TEST(dxpath_wow_after_deinstall_fails) { path_after_deinstall(DX_WOW); }
