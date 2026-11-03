/* dx_gap_00: WSCWriteNameSpaceOrder32 cases that rewrite the persisted 32-bit name-space order.
 *
 * Every test records the 32-bit name-space order before it starts and writes it back when it ends (and at
 * process exit), so the catalog is left as found. No provider is installed or removed: only the order of the
 * already registered providers is permuted. Skipped unless elevated and not on an emulated stack.
 * Never calls the writer with a duplicated provider id. */
#include "t.h"
#include <winsock2.h>
#include <ws2spi.h>
#include <stdlib.h>

/* The harness macros evaluate their operands more than once; calls here have side effects, so each is made once. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)

typedef INT (WSAAPI *x_order_fn)(LPGUID, DWORD);
typedef INT (WSAAPI *x_nsenum_fn)(LPDWORD, LPWSANAMESPACE_INFOW);
typedef INT (WSAAPI *x_nsenumw_fn)(LPDWORD, LPWSANAMESPACE_INFOW);

static x_order_fn x_wr32(void) { return (x_order_fn)t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder32"); }

static int x_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD got = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}
static int x_up(void)
{
    static int st;
    if (!st) {
        WSADATA d; typedef int (WSAAPI *su_fn)(WORD, LPWSADATA);
        su_fn f = (su_fn)t_proc_in("ws2_32.dll", "WSAStartup");
        st = (f && f(0x202, &d) == 0) ? 1 : -1;
    }
    return st > 0;
}

static int x_enum_generic(const char *name, GUID **out)
{
    x_nsenum_fn f = (x_nsenum_fn)t_proc_in("ws2_32.dll", name);
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
static int x_ns32(GUID **o) { return x_enum_generic("WSCEnumNameSpaceProviders32", o); }
static int x_ns64(GUID **o) { return x_enum_generic("WSAEnumNameSpaceProvidersW", o); }

static GUID *g_base; static int g_basen = -1, g_state;

static void x_restore(void)
{
    GUID *cur; int n;
    if (g_state != 1 || !x_wr32()) return;
    n = x_ns32(&cur);
    if (n == g_basen && n > 0 && memcmp(cur, g_base, n * sizeof(GUID)) != 0) x_wr32()(g_base, (DWORD)n);
    free(cur);
}

/* Returns 1 when the test may proceed. */
static int x_begin(void)
{
    if (g_state == 0) {
        if (t_is_wine() || !x_wr32()) g_state = -1;
        else if (!x_elevated() || !x_up()) g_state = -2;
        else {
            g_basen = x_ns32(&g_base);
            if (g_basen < 0) g_state = -1;
            else { g_state = 1; atexit(x_restore); }
        }
    }
    if (g_state == -1) { t_skip("32-bit name-space catalog writer unavailable"); return 0; }
    if (g_state == -2) { t_skip("needs an elevated token"); return 0; }
    if (g_basen < 2) { t_skip("fewer than two 32-bit name-space providers"); return 0; }
    return 1;
}
static void x_end(void)
{
    GUID *cur; int n;
    x_restore();
    n = x_ns32(&cur);
    CHECK(n == g_basen);
    if (n == g_basen) CHECK(!memcmp(cur, g_base, n * sizeof(GUID)));
    free(cur);
}
#define X_BEGIN() do { if (!x_begin()) return; } while (0)

static int x_order_is(const GUID *want, int n)
{
    GUID *cur; int m = x_ns32(&cur), ok = (m == n) && !memcmp(cur, want, n * sizeof(GUID));
    free(cur);
    return ok;
}

TEST(dxgap0_nsorder32_empty_list_is_noop)
{
    X_BEGIN();
    EXPECT_EQ(x_wr32()(NULL, 0), 0);
    CHECK(x_order_is(g_base, g_basen));
    x_end();
}

TEST(dxgap0_nsorder32_same_order_accepted)
{
    X_BEGIN();
    EXPECT_EQ(x_wr32()(g_base, (DWORD)g_basen), 0);
    CHECK(x_order_is(g_base, g_basen));
    x_end();
}

TEST(dxgap0_nsorder32_reverse_full_list)
{
    GUID *rev; int ok;
    X_BEGIN();
    rev = (GUID *)calloc(g_basen, sizeof(GUID));
    for (int i = 0; i < g_basen; i++) rev[i] = g_base[g_basen - 1 - i];
    EXPECT_EQ(x_wr32()(rev, (DWORD)g_basen), 0);
    ok = x_order_is(rev, g_basen);
    CHECK(ok);
    free(rev);
    x_end();
}

TEST(dxgap0_nsorder32_listed_entry_moves_behind_unlisted)
{
    GUID first; GUID *want; int ok;
    X_BEGIN();
    first = g_base[0];
    want = (GUID *)calloc(g_basen, sizeof(GUID));
    for (int i = 1; i < g_basen; i++) want[i - 1] = g_base[i];
    want[g_basen - 1] = first;
    EXPECT_EQ(x_wr32()(&first, 1), 0);
    ok = x_order_is(want, g_basen);
    CHECK(ok);
    free(want);
    x_end();
}

TEST(dxgap0_nsorder32_rotate_by_one)
{
    GUID *rot; int ok;
    X_BEGIN();
    rot = (GUID *)calloc(g_basen, sizeof(GUID));
    for (int i = 0; i < g_basen; i++) rot[i] = g_base[(i + 1) % g_basen];
    EXPECT_EQ(x_wr32()(rot, (DWORD)g_basen), 0);
    ok = x_order_is(rot, g_basen);
    CHECK(ok);
    free(rot);
    x_end();
}

TEST(dxgap0_nsorder32_repeated_writes_stable)
{
    GUID *rev;
    X_BEGIN();
    rev = (GUID *)calloc(g_basen, sizeof(GUID));
    for (int i = 0; i < g_basen; i++) rev[i] = g_base[g_basen - 1 - i];
    for (int k = 0; k < 3; k++) {
        EXPECT_EQ(x_wr32()(rev, (DWORD)g_basen), 0);
        CHECK(x_order_is(rev, g_basen));
    }
    free(rev);
    x_end();
}

TEST(dxgap0_nsorder32_leaves_native_catalog_alone)
{
    GUID *n0, *n1, *rev; int a, b;
    X_BEGIN();
    a = x_ns64(&n0);
    rev = (GUID *)calloc(g_basen, sizeof(GUID));
    for (int i = 0; i < g_basen; i++) rev[i] = g_base[g_basen - 1 - i];
    EXPECT_EQ(x_wr32()(rev, (DWORD)g_basen), 0);
    b = x_ns64(&n1);
    EXPECT_EQ(a, b);
    if (a == b && a > 0) CHECK(!memcmp(n0, n1, a * sizeof(GUID)));
    free(n0); free(n1); free(rev);
    x_end();
}

TEST(dxgap0_nsorder32_refusal_after_valid_write_changes_nothing_further)
{
    GUID *rev, bogus = { 0x6a0b5c01u, 0x7e11, 0x4c3d, { 0x9a, 0x42, 0x0d, 0x1f, 0x5e, 0x77, 0x00, 0x30 } };
    GUID *list; int n;
    X_BEGIN();
    rev = (GUID *)calloc(g_basen, sizeof(GUID));
    for (int i = 0; i < g_basen; i++) rev[i] = g_base[g_basen - 1 - i];
    EXPECT_EQ(x_wr32()(rev, (DWORD)g_basen), 0);
    list = (GUID *)calloc(g_basen + 1, sizeof(GUID));
    memcpy(list, g_base, g_basen * sizeof(GUID));
    list[g_basen] = bogus;
    EXPECT_EQ(x_wr32()(list, (DWORD)g_basen + 1), 10022);
    n = g_basen;
    CHECK(x_order_is(rev, n));         /* the earlier valid order stands */
    free(list); free(rev);
    x_end();
}
