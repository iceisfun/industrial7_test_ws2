/* Namespace provider catalog: WSAEnumNameSpaceProvidersA/W, WSAEnumNameSpaceProvidersExA/W and the 32-bit
 * catalog forms WSCEnumNameSpaceProviders32 / WSCEnumNameSpaceProvidersEx32.
 * Measures: the buffer-size protocol (WSAEFAULT with the required length; a NULL buffer ignores the stated
 * length; success leaves the length alone and returns the entry count), the exact size formula (per entry the
 * structure plus 16 bytes of slack plus the identifier string at wide width, plus the provider blob for the
 * Ex forms), the buffer layout (all structures first, then each identifier followed by its blob, packed with no
 * gaps), parity of the A/W/Ex/32-bit views, and the stock DNS namespace entry. The 32-bit forms run without
 * WSAStartup. */
#include "pc.h"
#include <stdlib.h>

typedef INT (WSAAPI *ns_fn)(LPDWORD, void *);

typedef struct { const char *name; DWORD stride; int ansi, ex; } nsv;
enum { V_W, V_A, V_EXW, V_EXA, V_W32, V_EX32, NV };
static const nsv V[NV] = {
    { "WSAEnumNameSpaceProvidersW", 40, 0, 0 },   { "WSAEnumNameSpaceProvidersA", 40, 1, 0 },
    { "WSAEnumNameSpaceProvidersExW", 56, 0, 1 }, { "WSAEnumNameSpaceProvidersExA", 56, 1, 1 },
    { "WSCEnumNameSpaceProviders32", 40, 0, 0 },  { "WSCEnumNameSpaceProvidersEx32", 56, 0, 1 },
};
static ns_fn fnof(int v) { return (ns_fn)t_proc_in("ws2_32.dll", V[v].name); }

/* Field access on a returned buffer (layout is ABI: id 0, namespace 16, active 20, version 24, identifier 32,
 * blob size 40, blob pointer 48). */
#define ID(b, v, i)     ((const GUID *)((b) + (size_t)(i) * V[v].stride))
#define NSP(b, v, i)    (*(const DWORD *)((b) + (size_t)(i) * V[v].stride + 16))
#define ACT(b, v, i)    (*(const DWORD *)((b) + (size_t)(i) * V[v].stride + 20))
#define VER(b, v, i)    (*(const DWORD *)((b) + (size_t)(i) * V[v].stride + 24))
#define IDENT(b, v, i)  (*(void *const *)((b) + (size_t)(i) * V[v].stride + 32))
#define BCB(b, v, i)    (*(const DWORD *)((b) + (size_t)(i) * V[v].stride + 40))
#define BPTR(b, v, i)   (*(void *const *)((b) + (size_t)(i) * V[v].stride + 48))

typedef struct { unsigned char *b; DWORD len; int n; } nsbuf;

static DWORD ns_need(int v)
{
    DWORD len = 0;
    SET_ERR(0);
    fnof(v)(&len, NULL);
    return len;
}
static int ns_fetch(int v, nsbuf *o)
{
    DWORD len = ns_need(v);
    o->b = NULL; o->n = -1; o->len = len;
    if (!len) return -1;
    o->b = (unsigned char *)calloc(1, len);
    if (!o->b) return -1;
    o->n = fnof(v)(&len, o->b);
    return o->n;
}
static void ns_free(nsbuf *o) { free(o->b); o->b = NULL; }
static size_t ident_bytes(int v, const void *p) { return V[v].ansi ? strlen((const char *)p) + 1 : (lstrlenW((const WCHAR *)p) + 1) * sizeof(WCHAR); }

#define NTEST(nm, ...) \
    static void nm##_impl(int v); \
    TEST(nsenum_w_##nm) { PC_NEED_WSA(); REQUIRE(fnof(V_W)); nm##_impl(V_W); } \
    TEST(nsenum_a_##nm) { PC_NEED_WSA(); REQUIRE(fnof(V_A)); nm##_impl(V_A); } \
    TEST(nsenum_exw_##nm) { PC_NEED_WSA(); REQUIRE(fnof(V_EXW)); nm##_impl(V_EXW); } \
    TEST(nsenum_exa_##nm) { PC_NEED_WSA(); REQUIRE(fnof(V_EXA)); nm##_impl(V_EXA); } \
    TEST(nsenum_w32_##nm) { PC_NEED_WSA(); REQUIRE(fnof(V_W32)); nm##_impl(V_W32); } \
    TEST(nsenum_ex32_##nm) { PC_NEED_WSA(); REQUIRE(fnof(V_EX32)); nm##_impl(V_EX32); } \
    static void nm##_impl(int v) __VA_ARGS__

NTEST(null_buffer_is_size_query, {
    DWORD len = 0; int r;
    SET_ERR(0);
    r = fnof(v)(&len, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    CHECK(len >= V[v].stride);
})

NTEST(null_buffer_big_length_replaced, {
    DWORD len = 900000, want = ns_need(v); int r;
    SET_ERR(0);
    r = fnof(v)(&len, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(len, want);
})

NTEST(zero_length_with_buffer_is_size_query, {
    DWORD len = 0, want = ns_need(v); int r; unsigned char dummy[64] = {0};
    SET_ERR(0);
    r = fnof(v)(&len, dummy);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    EXPECT_EQ(len, want);
})

NTEST(one_byte_short_fails, {
    DWORD want = ns_need(v), len; int r; unsigned char *b = calloc(1, want);
    REQUIRE(b);
    len = want - 1;
    SET_ERR(0);
    r = fnof(v)(&len, b);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    EXPECT_EQ(len, want);
    free(b);
})

NTEST(exact_length_succeeds_and_keeps_length, {
    DWORD want = ns_need(v), len; int r; unsigned char *b = calloc(1, want);
    REQUIRE(b);
    len = want;
    r = fnof(v)(&len, b);
    CHECK(r >= 1);
    EXPECT_EQ(len, want);
    free(b);
})

NTEST(oversize_length_untouched, {
    DWORD want = ns_need(v), len; int r; unsigned char *b = calloc(1, want + 500);
    REQUIRE(b);
    len = want + 500;
    r = fnof(v)(&len, b);
    CHECK(r >= 1);
    EXPECT_EQ(len, want + 500);
    free(b);
})

NTEST(required_size_is_deterministic, {
    EXPECT_EQ(ns_need(v), ns_need(v));
})

NTEST(count_agrees_with_wide_catalog, {
    nsbuf a, w; int wv = (v == V_W32 || v == V_EX32) ? V_W32 : V_W;
    if (ns_fetch(v, &a) < 0 || ns_fetch(wv, &w) < 0) { CHECK(0); ns_free(&a); ns_free(&w); return; }
    EXPECT_EQ(a.n, w.n);
    ns_free(&a); ns_free(&w);
})

NTEST(provider_ids_nonzero_and_unique, {
    nsbuf o; int i, j; GUID zero = {0};
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    for (i = 0; i < o.n; i++) {
        CHECKF(!pc_guid_eq(ID(o.b, v, i), &zero), "entry %d has a null provider id", i);
        for (j = i + 1; j < o.n; j++) CHECKF(!pc_guid_eq(ID(o.b, v, i), ID(o.b, v, j)), "entries %d and %d share an id", i, j);
    }
    ns_free(&o);
})

NTEST(active_flag_is_boolean, {
    nsbuf o; int i;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    for (i = 0; i < o.n; i++) CHECKF(ACT(o.b, v, i) <= 1, "entry %d active flag %lu", i, ACT(o.b, v, i));
    ns_free(&o);
})

NTEST(identifiers_are_inside_the_buffer_and_nonempty, {
    nsbuf o; int i;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    for (i = 0; i < o.n; i++) {
        const unsigned char *p = (const unsigned char *)IDENT(o.b, v, i);
        CHECKF(p >= o.b && p < o.b + o.len, "entry %d identifier outside the buffer", i);
        if (p >= o.b && p < o.b + o.len) CHECKF(V[v].ansi ? ((const char *)p)[0] != 0 : ((const WCHAR *)p)[0] != 0, "entry %d identifier empty", i);
    }
    ns_free(&o);
})

NTEST(structures_first_then_identifiers_packed, {
    nsbuf o; int i; const unsigned char *cur;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    cur = o.b + (size_t)o.n * V[v].stride;
    for (i = 0; i < o.n; i++) {
        const unsigned char *p = (const unsigned char *)IDENT(o.b, v, i);
        CHECKF(p == cur, "entry %d identifier at +%d, expected +%d", i, (int)(p - o.b), (int)(cur - o.b));
        cur = p + ident_bytes(v, p);
        if (V[v].ex) {
            DWORD cb = BCB(o.b, v, i);
            if (cb) { CHECKF((const unsigned char *)BPTR(o.b, v, i) == cur, "entry %d blob not packed after identifier", i); cur += cb; }
            else CHECKF(BPTR(o.b, v, i) == NULL, "entry %d empty blob has a pointer", i);
        }
    }
    ns_free(&o);
})

NTEST(used_bytes_do_not_exceed_required, {
    nsbuf o; int i; size_t used;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    used = (size_t)o.n * V[v].stride;
    for (i = 0; i < o.n; i++) { used += ident_bytes(v, IDENT(o.b, v, i)); if (V[v].ex) used += BCB(o.b, v, i); }
    CHECKF(used <= o.len, "used %u of %u", (unsigned)used, (unsigned)o.len);
    ns_free(&o);
})

NTEST(required_size_formula, {
    /* Each entry reserves its structure, 16 bytes of slack and the identifier at wide width (plus its blob for
     * the Ex forms), whatever the string conversion later needs. */
    nsbuf o; int i; size_t want = 0; const nsv *s = &V[v]; int wv = (v == V_W32 || v == V_EX32) ? v : (s->ex ? V_EXW : V_W);
    nsbuf w;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    if (ns_fetch(wv, &w) < 1) { CHECK(0); ns_free(&o); ns_free(&w); return; }
    for (i = 0; i < w.n; i++) {
        want += s->stride + 16 + ident_bytes(wv, IDENT(w.b, wv, i));
        if (s->ex) want += BCB(w.b, wv, i);
    }
    EXPECT_EQ(o.len, want);
    ns_free(&o); ns_free(&w);
})

NTEST(dns_namespace_is_present_and_active, {
    nsbuf o; int i, found = 0;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    for (i = 0; i < o.n; i++)
        if (NSP(o.b, v, i) == NS_DNS) {
            found++;
            CHECK(pc_guid_eq(ID(o.b, v, i), &pc_guid_ns_dns));
            CHECK(ACT(o.b, v, i) == 1);
        }
    EXPECT_EQ(found, 1);
    ns_free(&o);
})

NTEST(namespaces_recorded, {
    nsbuf o; int i;
    if (ns_fetch(v, &o) < 1) { CHECK(0); ns_free(&o); return; }
    for (i = 0; i < o.n; i++) t_note("%s entry: namespace %lu active %lu version %lu", V[v].name, NSP(o.b, v, i), ACT(o.b, v, i), VER(o.b, v, i));
    ns_free(&o);
})

NTEST(listing_is_stable, {
    nsbuf a, b; int i;
    if (ns_fetch(v, &a) < 1 || ns_fetch(v, &b) < 1) { CHECK(0); ns_free(&a); ns_free(&b); return; }
    EXPECT_EQ(a.n, b.n);
    for (i = 0; i < a.n && i < b.n; i++) {
        CHECK(pc_guid_eq(ID(a.b, v, i), ID(b.b, v, i)));
        CHECK(NSP(a.b, v, i) == NSP(b.b, v, i) && ACT(a.b, v, i) == ACT(b.b, v, i) && VER(a.b, v, i) == VER(b.b, v, i));
    }
    ns_free(&a); ns_free(&b);
})

/* ---- parity between the views ---------------------------------------------------------------- */
static void parity(int x, int y)
{
    nsbuf a, b; int i;
    if (ns_fetch(x, &a) < 1 || ns_fetch(y, &b) < 1) { CHECK(0); ns_free(&a); ns_free(&b); return; }
    EXPECT_EQ(a.n, b.n);
    for (i = 0; i < a.n && i < b.n; i++) {
        CHECKF(pc_guid_eq(ID(a.b, x, i), ID(b.b, y, i)), "entry %d id differs", i);
        CHECKF(NSP(a.b, x, i) == NSP(b.b, y, i), "entry %d namespace differs", i);
        CHECKF(ACT(a.b, x, i) == ACT(b.b, y, i), "entry %d active differs", i);
        CHECKF(VER(a.b, x, i) == VER(b.b, y, i), "entry %d version differs", i);
    }
    ns_free(&a); ns_free(&b);
}
TEST(nsenum_parity_w_a) { PC_NEED_WSA(); REQUIRE(fnof(V_W)); REQUIRE(fnof(V_A)); parity(V_W, V_A); }
TEST(nsenum_parity_w_exw) { PC_NEED_WSA(); REQUIRE(fnof(V_W)); REQUIRE(fnof(V_EXW)); parity(V_W, V_EXW); }
TEST(nsenum_parity_exw_exa) { PC_NEED_WSA(); REQUIRE(fnof(V_EXW)); REQUIRE(fnof(V_EXA)); parity(V_EXW, V_EXA); }
TEST(nsenum_parity_w32_ex32) { PC_NEED_WSA(); REQUIRE(fnof(V_W32)); REQUIRE(fnof(V_EX32)); parity(V_W32, V_EX32); }

static void names_equal(int w, int a)
{
    nsbuf x, y; int i;
    if (ns_fetch(w, &x) < 1 || ns_fetch(a, &y) < 1) { CHECK(0); ns_free(&x); ns_free(&y); return; }
    for (i = 0; i < x.n && i < y.n; i++) {
        char want[512];
        int k = WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)IDENT(x.b, w, i), -1, want, sizeof want, NULL, NULL);
        CHECKF(k > 0 && strcmp(want, (const char *)IDENT(y.b, a, i)) == 0, "entry %d identifier differs", i);
    }
    ns_free(&x); ns_free(&y);
}
TEST(nsenum_ansi_identifiers_are_narrowed_wide) { PC_NEED_WSA(); REQUIRE(fnof(V_W)); REQUIRE(fnof(V_A)); names_equal(V_W, V_A); }
TEST(nsenum_ex_ansi_identifiers_are_narrowed_wide) { PC_NEED_WSA(); REQUIRE(fnof(V_EXW)); REQUIRE(fnof(V_EXA)); names_equal(V_EXW, V_EXA); }

TEST(nsenum_ex_blob_sizes_match_between_widths)
{
    nsbuf x, y; int i;
    PC_NEED_WSA(); REQUIRE(fnof(V_EXW)); REQUIRE(fnof(V_EXA));
    if (ns_fetch(V_EXW, &x) < 1 || ns_fetch(V_EXA, &y) < 1) { CHECK(0); ns_free(&x); ns_free(&y); return; }
    for (i = 0; i < x.n && i < y.n; i++) {
        CHECKF(BCB(x.b, V_EXW, i) == BCB(y.b, V_EXA, i), "entry %d blob size differs", i);
        if (BCB(x.b, V_EXW, i) && BCB(y.b, V_EXA, i)) CHECKF(memcmp(BPTR(x.b, V_EXW, i), BPTR(y.b, V_EXA, i), BCB(x.b, V_EXW, i)) == 0, "entry %d blob differs", i);
    }
    ns_free(&x); ns_free(&y);
}

TEST(nsenum_native_and_wow_have_dns)
{
    nsbuf a, b; int i, da = 0, db = 0;
    PC_NEED_WSA(); REQUIRE(fnof(V_W)); REQUIRE(fnof(V_W32));
    if (ns_fetch(V_W, &a) < 1 || ns_fetch(V_W32, &b) < 1) { CHECK(0); ns_free(&a); ns_free(&b); return; }
    for (i = 0; i < a.n; i++) da += NSP(a.b, V_W, i) == NS_DNS;
    for (i = 0; i < b.n; i++) db += NSP(b.b, V_W32, i) == NS_DNS;
    EXPECT_EQ(da, 1); EXPECT_EQ(db, 1);
    t_note("namespace entries: native %d, 32-bit %d", a.n, b.n);
    ns_free(&a); ns_free(&b);
}

/* ---- second thread ---------------------------------------------------------------------------- */
typedef struct { int v; DWORD need; } targ;
static DWORD WINAPI thr(LPVOID p) { targ *a = (targ *)p; a->need = ns_need(a->v); return 0; }
TEST(nsenum_works_from_another_thread)
{
    targ a = { V_W, 0 }; HANDLE h; DWORD want;
    PC_NEED_WSA(); REQUIRE(fnof(V_W));
    want = ns_need(V_W);
    h = CreateThread(NULL, 0, thr, &a, 0, NULL);
    REQUIRE(h);
    EXPECT_EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0);
    CloseHandle(h);
    EXPECT_EQ(a.need, want);
}

/* ---- WSAStartup requirements ----------------------------------------------------------------- */
CHILD(ns32_no_startup)
{
    DWORD len = 0, len2 = 0;
    ns_fn f = fnof(V_W32), g = fnof(V_EX32);
    if (!f || !g) return 90;
    if (f(&len, NULL) != SOCKET_ERROR || U(WSAGetLastError)() != WSAEFAULT || !len) return 10;
    if (g(&len2, NULL) != SOCKET_ERROR || U(WSAGetLastError)() != WSAEFAULT || len2 <= len) return 11;
    return 0;
}
TEST(nsenum_32bit_forms_work_without_wsastartup) { EXPECT_EQ(t_run_child("ns32_no_startup", "", 30000), 0); }

CHILD(ns_native_no_startup)
{
    DWORD len = 0;
    ns_fn f = fnof(V_W);
    if (!f) return 90;
    if (f(&len, NULL) != SOCKET_ERROR) return 10;
    if (U(WSAGetLastError)() != WSANOTINITIALISED) return 11;
    return 0;
}
TEST(nsenum_native_form_before_startup_is_notinitialised) { EXPECT_EQ(t_run_child("ns_native_no_startup", "", 30000), 0); }

TEST(nsenum_ex_is_larger_than_plain)
{
    PC_NEED_WSA(); REQUIRE(fnof(V_W)); REQUIRE(fnof(V_EXW));
    CHECK(ns_need(V_EXW) > ns_need(V_W));
}
