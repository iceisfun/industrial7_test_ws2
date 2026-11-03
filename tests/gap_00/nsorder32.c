/* gap_00: WSCWriteNameSpaceOrder32, the name-space order writer of the 32-bit catalog.
 *
 * This file holds the cases that never change the catalog: export presence, the refusal of an order naming a
 * provider that is not registered (refused before anything is persisted), parity with the native-catalog
 * writer, and the unchanged-catalog check after a refusal. The cases that rewrite the persisted order live in
 * the dx_gap_00 area.
 *
 * The call returns the error number itself (0 on success) rather than a sentinel with a separate last-error
 * query; the refusal for an unregistered provider is 10022 (invalid argument). */
#include "t.h"
#include <winsock2.h>
#include <ws2spi.h>
#include <stdlib.h>

typedef INT (WSAAPI *g0_order_fn)(LPGUID, DWORD);
typedef INT (WSAAPI *g0_nsenum_fn)(LPDWORD, LPWSANAMESPACE_INFOW);

#define G0_INVAL 10022

static g0_order_fn g0_wr32(void) { return (g0_order_fn)t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder32"); }
static g0_order_fn g0_wr64(void) { return (g0_order_fn)t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder"); }

static int g0_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD got = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

static int g0_up(void)
{
    static int st;
    if (!st) {
        WSADATA d; typedef int (WSAAPI *su_fn)(WORD, LPWSADATA);
        su_fn f = (su_fn)t_proc_in("ws2_32.dll", "WSAStartup");
        st = (f && f(0x202, &d) == 0) ? 1 : -1;
    }
    return st > 0;
}

/* Reads the 32-bit name-space catalog; returns the entry count or -1. The GUIDs come back in catalog order. */
static int g0_ns32(GUID **out)
{
    g0_nsenum_fn f = (g0_nsenum_fn)t_proc_in("ws2_32.dll", "WSCEnumNameSpaceProviders32");
    DWORD len = 0; INT n; WSANAMESPACE_INFOW *b; GUID *g;
    *out = NULL;
    if (!f) return -1;
    n = f(&len, NULL);
    if (n >= 0 && n != SOCKET_ERROR) return 0;
    if (!len) return -1;
    b = (WSANAMESPACE_INFOW *)calloc(1, len);
    n = f(&len, b);
    if (n == SOCKET_ERROR || n < 0) { free(b); return -1; }
    g = (GUID *)calloc(n ? n : 1, sizeof(GUID));
    for (int i = 0; i < n; i++) g[i] = b[i].NSProviderId;
    free(b);
    *out = g;
    return n;
}

/* A GUID no machine registers: fixed pattern, unrelated to any shipped provider. */
static GUID g0_unknown(unsigned k)
{
    GUID g = { 0x6a0b5c01u, 0x7e11, 0x4c3d, { 0x9a, 0x42, 0x0d, 0x1f, 0x5e, 0x77, 0x00, 0x00 } };
    g.Data4[6] = (BYTE)(k >> 8); g.Data4[7] = (BYTE)k;
    return g;
}

static int g0_same(const GUID *a, const GUID *b, int n) { return n == 0 || !memcmp(a, b, n * sizeof(GUID)); }

TEST(gap0_nsorder32_export_present)
{
    if (t_is_wine()) { t_skip("the 32-bit catalog exports are not provided by an emulated stack"); return; }
    CHECK(t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder32") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "WSCEnumNameSpaceProviders32") != NULL);
}

TEST(gap0_nsorder32_distinct_from_native_writer)
{
    REQUIRE(g0_wr32()); REQUIRE(g0_wr64());
    CHECK((void *)g0_wr32() != (void *)g0_wr64());
}

TEST(gap0_nsorder32_catalog_is_readable)
{
    GUID *g; int n;
    REQUIRE(t_proc_in("ws2_32.dll", "WSCEnumNameSpaceProviders32"));
    n = g0_ns32(&g);
    if (n < 0) { t_skip("32-bit name-space catalog unavailable"); return; }
    CHECK(n >= 0);
    free(g);
}

TEST(gap0_nsorder32_unknown_guid_refused)
{
    GUID u = g0_unknown(1), *before, *after; int nb, na; INT r;
    REQUIRE(g0_wr32());
    if (t_is_wine()) { t_skip("catalog writers are not available on an emulated stack"); return; }
    if (!g0_elevated()) { t_skip("needs an elevated token"); return; }
    if (!g0_up()) { t_skip("WSAStartup failed"); return; }
    nb = g0_ns32(&before);
    if (nb < 0) { t_skip("32-bit name-space catalog unavailable"); return; }
    r = g0_wr32()(&u, 1);
    EXPECT_EQ(r, G0_INVAL);
    na = g0_ns32(&after);
    EXPECT_EQ(na, nb);
    if (na == nb) CHECK(g0_same(before, after, nb));
    free(before); free(after);
}

TEST(gap0_nsorder32_unknown_guid_refused_repeatable)
{
    GUID u = g0_unknown(2);
    REQUIRE(g0_wr32());
    if (t_is_wine()) { t_skip("catalog writers are not available on an emulated stack"); return; }
    if (!g0_elevated()) { t_skip("needs an elevated token"); return; }
    if (!g0_up()) { t_skip("WSAStartup failed"); return; }
    for (int i = 0; i < 3; i++) EXPECT_EQ(g0_wr32()(&u, 1), G0_INVAL);
}

TEST(gap0_nsorder32_several_unknown_guids_refused)
{
    GUID u[3]; GUID *before, *after; int nb, na;
    REQUIRE(g0_wr32());
    if (t_is_wine()) { t_skip("catalog writers are not available on an emulated stack"); return; }
    if (!g0_elevated()) { t_skip("needs an elevated token"); return; }
    if (!g0_up()) { t_skip("WSAStartup failed"); return; }
    for (int i = 0; i < 3; i++) u[i] = g0_unknown(10 + i);
    nb = g0_ns32(&before);
    if (nb < 0) { t_skip("32-bit name-space catalog unavailable"); return; }
    EXPECT_EQ(g0_wr32()(u, 3), G0_INVAL);
    na = g0_ns32(&after);
    EXPECT_EQ(na, nb);
    if (na == nb) CHECK(g0_same(before, after, nb));
    free(before); free(after);
}

TEST(gap0_nsorder32_known_then_unknown_refused_unchanged)
{
    GUID *before, *after, *list; int nb, na;
    REQUIRE(g0_wr32());
    if (t_is_wine()) { t_skip("catalog writers are not available on an emulated stack"); return; }
    if (!g0_elevated()) { t_skip("needs an elevated token"); return; }
    if (!g0_up()) { t_skip("WSAStartup failed"); return; }
    nb = g0_ns32(&before);
    if (nb < 1) { if (nb == 0) free(before); t_skip("32-bit name-space catalog empty or unavailable"); return; }
    list = (GUID *)calloc(nb + 1, sizeof(GUID));
    memcpy(list, before, nb * sizeof(GUID));
    list[nb] = g0_unknown(20);
    /* every registered provider plus one that is not: refused as a whole, nothing persisted */
    EXPECT_EQ(g0_wr32()(list, (DWORD)nb + 1), G0_INVAL);
    na = g0_ns32(&after);
    EXPECT_EQ(na, nb);
    if (na == nb) CHECK(g0_same(before, after, nb));
    free(list); free(before); free(after);
}

TEST(gap0_nsorder32_unknown_first_then_known_refused_unchanged)
{
    GUID *before, *after, *list; int nb, na;
    REQUIRE(g0_wr32());
    if (t_is_wine()) { t_skip("catalog writers are not available on an emulated stack"); return; }
    if (!g0_elevated()) { t_skip("needs an elevated token"); return; }
    if (!g0_up()) { t_skip("WSAStartup failed"); return; }
    nb = g0_ns32(&before);
    if (nb < 1) { if (nb == 0) free(before); t_skip("32-bit name-space catalog empty or unavailable"); return; }
    list = (GUID *)calloc(nb + 1, sizeof(GUID));
    list[0] = g0_unknown(21);
    memcpy(list + 1, before, nb * sizeof(GUID));
    EXPECT_EQ(g0_wr32()(list, (DWORD)nb + 1), G0_INVAL);
    na = g0_ns32(&after);
    EXPECT_EQ(na, nb);
    if (na == nb) CHECK(g0_same(before, after, nb));
    free(list); free(before); free(after);
}

TEST(gap0_nsorder32_native_writer_refuses_the_same_way)
{
    GUID u = g0_unknown(3);
    REQUIRE(g0_wr32()); REQUIRE(g0_wr64());
    if (t_is_wine()) { t_skip("catalog writers are not available on an emulated stack"); return; }
    if (!g0_elevated()) { t_skip("needs an elevated token"); return; }
    if (!g0_up()) { t_skip("WSAStartup failed"); return; }
    EXPECT_EQ(g0_wr64()(&u, 1), G0_INVAL);
    EXPECT_EQ(g0_wr32()(&u, 1), g0_wr64()(&u, 1));
}
