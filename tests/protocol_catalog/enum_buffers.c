/* WSAEnumProtocolsA / WSAEnumProtocolsW: the buffer-size protocol in depth.
 * Measures: the required size is an exact multiple of the structure size, the size query is identical whether
 * the buffer is NULL or the length is zero, an undersized length (one byte short, one entry short) fails with
 * WSAENOBUFS and rewrites the length, an exact length succeeds, an oversized length is left alone by the wide
 * form but rounded down to a whole number of entries by the ANSI form, repeated queries are stable, and
 * the enumeration works from a second thread. Variants are driven through one table so both forms get the
 * same cases. */
#include "pc.h"
#include <stdlib.h>

typedef INT (WSAAPI *fn_any)(LPINT, void *, LPDWORD);

typedef struct { const char *name; DWORD esz; } variant;
static const variant V[2] = { { "WSAEnumProtocolsW", PC_INFOW_SIZE }, { "WSAEnumProtocolsA", PC_INFOA_SIZE } };

static fn_any getfn(int v) { return (fn_any)t_proc_in("ws2_32.dll", V[v].name); }

/* Entry count and required length via the size query. */
static int need(int v, INT *filter, DWORD *len)
{
    fn_any f = getfn(v);
    *len = 0;
    SET_ERR(0);
    return f(filter, NULL, len);
}

#define VTEST(nm, ...) \
    static void nm##_impl(int v); \
    TEST(enumbuf_w_##nm) { PC_NEED_WSA(); REQUIRE(getfn(0)); nm##_impl(0); } \
    TEST(enumbuf_a_##nm) { PC_NEED_WSA(); REQUIRE(getfn(1)); nm##_impl(1); } \
    static void nm##_impl(int v) __VA_ARGS__

VTEST(size_is_entry_multiple, {
    DWORD len; int r = need(v, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECK(len > 0);
    EXPECT_EQ(len % V[v].esz, 0);
})

VTEST(size_query_sets_enobufs, {
    DWORD len; int r = need(v, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
})

VTEST(null_buffer_big_length_is_still_query, {
    /* A NULL buffer makes the stated length irrelevant: the call fails and the length is replaced by the need. */
    fn_any f = getfn(v); DWORD want, len = 1000000; int r;
    need(v, NULL, &want);
    SET_ERR(0);
    r = f(NULL, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
    EXPECT_EQ(len, want);
})

VTEST(zero_length_with_buffer_is_query, {
    fn_any f = getfn(v); DWORD want, len = 0; int r; char dummy[8] = {0};
    need(v, NULL, &want);
    SET_ERR(0);
    r = f(NULL, dummy, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
    EXPECT_EQ(len, want);
})

VTEST(one_byte_short_fails, {
    fn_any f = getfn(v); DWORD want, len; int r; char *buf;
    need(v, NULL, &want);
    buf = calloc(1, want);
    REQUIRE(buf);
    len = want - 1;
    SET_ERR(0);
    r = f(NULL, buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
    EXPECT_EQ(len, want);
    free(buf);
})

VTEST(one_entry_short_fails, {
    fn_any f = getfn(v); DWORD want, len; int r; char *buf;
    need(v, NULL, &want);
    if (want <= V[v].esz) { t_skip("catalog has a single visible entry"); return; }
    buf = calloc(1, want);
    REQUIRE(buf);
    len = want - V[v].esz;
    SET_ERR(0);
    r = f(NULL, buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
    EXPECT_EQ(len, want);
    free(buf);
})

VTEST(exact_length_succeeds, {
    fn_any f = getfn(v); DWORD want, len; int r, n; char *buf;
    need(v, NULL, &want);
    n = (int)(want / V[v].esz);
    buf = calloc(1, want);
    REQUIRE(buf);
    len = want;
    r = f(NULL, buf, &len);
    EXPECT_EQ(r, n);
    EXPECT_EQ(len, want);
    free(buf);
})

VTEST(count_matches_size_over_entry, {
    fn_any f = getfn(v); DWORD want, len; int r; char *buf;
    need(v, NULL, &want);
    buf = calloc(1, want + 4 * V[v].esz);
    REQUIRE(buf);
    len = want + 4 * V[v].esz;
    r = f(NULL, buf, &len);
    EXPECT_EQ((DWORD)r, want / V[v].esz);
    free(buf);
})

VTEST(oversize_length_by_partial_entry, {
    /* 100 spare bytes are less than one entry. Wide form leaves the length alone; the ANSI form reports the
     * length rounded down to whole entries, which is exactly the need. */
    fn_any f = getfn(v); DWORD want, len, given; int r; char *buf;
    need(v, NULL, &want);
    given = want + 100;
    buf = calloc(1, given);
    REQUIRE(buf);
    len = given;
    r = f(NULL, buf, &len);
    CHECK(r > 0);
    EXPECT_EQ(len, v == 0 ? given : want);
    free(buf);
})

VTEST(oversize_length_by_whole_entries, {
    fn_any f = getfn(v); DWORD want, len, given; int r; char *buf;
    need(v, NULL, &want);
    given = want + 3 * V[v].esz;
    buf = calloc(1, given);
    REQUIRE(buf);
    len = given;
    r = f(NULL, buf, &len);
    CHECK(r > 0);
    EXPECT_EQ(len, given);
    free(buf);
})

VTEST(failure_is_repeatable, {
    fn_any f = getfn(v); DWORD want, a, b; int r1, r2;
    need(v, NULL, &want);
    a = b = 0;
    r1 = f(NULL, NULL, &a);
    r2 = f(NULL, NULL, &b);
    EXPECT_EQ(r1, r2);
    EXPECT_EQ(a, b);
    EXPECT_EQ(a, want);
})

VTEST(entries_have_distinct_nonzero_ids, {
    fn_any f = getfn(v); DWORD want, len; int n, i, j; unsigned char *buf;
    need(v, NULL, &want);
    buf = calloc(1, want);
    REQUIRE(buf);
    len = want;
    n = f(NULL, buf, &len);
    for (i = 0; i < n; i++) {
        DWORD idi = v == 0 ? ((WSAPROTOCOL_INFOW *)buf)[i].dwCatalogEntryId : ((WSAPROTOCOL_INFOA *)buf)[i].dwCatalogEntryId;
        CHECKF(idi != 0, "entry %d has id 0", i);
        for (j = i + 1; j < n; j++) {
            DWORD idj = v == 0 ? ((WSAPROTOCOL_INFOW *)buf)[j].dwCatalogEntryId : ((WSAPROTOCOL_INFOA *)buf)[j].dwCatalogEntryId;
            CHECKF(idi != idj, "entries %d and %d share id %lu", i, j, idi);
        }
    }
    free(buf);
})

VTEST(listing_is_stable_across_calls, {
    fn_any f = getfn(v); DWORD want, l1, l2; int n1, n2; unsigned char *b1, *b2;
    need(v, NULL, &want);
    b1 = calloc(1, want); b2 = calloc(1, want);
    REQUIRE(b1 && b2);
    l1 = l2 = want;
    n1 = f(NULL, b1, &l1);
    n2 = f(NULL, b2, &l2);
    EXPECT_EQ(n1, n2);
    CHECK(memcmp(b1, b2, want) == 0);
    free(b1); free(b2);
})

/* ---- filter lists ---------------------------------------------------------------------------- */
VTEST(filter_size_query_matches_filtered_count, {
    INT filt[] = { IPPROTO_TCP, 0 };
    DWORD len; int r = need(v, filt, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
    CHECK(len >= V[v].esz);
    EXPECT_EQ(len % V[v].esz, 0);
})

VTEST(filter_smaller_than_full, {
    INT filt[] = { IPPROTO_TCP, 0 };
    DWORD all, one;
    need(v, NULL, &all); need(v, filt, &one);
    CHECK(one <= all);
    CHECK(one >= V[v].esz);
})

VTEST(filter_only_terminator_is_empty_success, {
    /* A list holding just the terminator selects nothing: success with zero entries, no error, no length. */
    fn_any f = getfn(v); INT filt[] = { 0 }; DWORD len = 0; int r;
    SET_ERR(0);
    r = f(filt, NULL, &len);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(len, 0);
})

VTEST(filter_no_match_is_empty_success, {
    fn_any f = getfn(v); INT filt[] = { 0xdead, 0xbeef, 0 }; DWORD len = 0; int r;
    r = f(filt, NULL, &len);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(len, 0);
})

VTEST(filter_negative_value_matches_nothing, {
    fn_any f = getfn(v); INT filt[] = { -1, -6, 0 }; DWORD len = 0; int r;
    r = f(filt, NULL, &len);
    EXPECT_EQ(r, 0);
})

VTEST(filter_entries_after_terminator_are_ignored, {
    INT a[] = { IPPROTO_TCP, 0 }, b[] = { IPPROTO_TCP, 0, IPPROTO_UDP, 0 };
    DWORD la, lb;
    need(v, a, &la); need(v, b, &lb);
    EXPECT_EQ(la, lb);
})

VTEST(filter_duplicates_do_not_duplicate_entries, {
    INT a[] = { IPPROTO_TCP, 0 }, b[] = { IPPROTO_TCP, IPPROTO_TCP, IPPROTO_TCP, 0 };
    DWORD la, lb;
    need(v, a, &la); need(v, b, &lb);
    EXPECT_EQ(la, lb);
})

VTEST(filter_order_of_list_is_irrelevant, {
    INT a[] = { IPPROTO_TCP, IPPROTO_UDP, 0 }, b[] = { IPPROTO_UDP, IPPROTO_TCP, 0 };
    DWORD la, lb;
    need(v, a, &la); need(v, b, &lb);
    EXPECT_EQ(la, lb);
})

VTEST(filter_union_covers_each_member, {
    INT t[] = { IPPROTO_TCP, 0 }, u[] = { IPPROTO_UDP, 0 }, tu[] = { IPPROTO_TCP, IPPROTO_UDP, 0 };
    DWORD lt, lu, ltu;
    need(v, t, &lt); need(v, u, &lu); need(v, tu, &ltu);
    CHECK(ltu >= lt && ltu >= lu);
    CHECK(ltu <= lt + lu);
})

VTEST(filter_undersized_buffer_fails, {
    fn_any f = getfn(v); INT filt[] = { IPPROTO_TCP, 0 }; DWORD want, len; char *buf; int r;
    need(v, filt, &want);
    buf = calloc(1, want);
    REQUIRE(buf);
    len = want - 1;
    SET_ERR(0);
    r = f(filt, buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS);
    EXPECT_EQ(len, want);
    free(buf);
})

VTEST(filter_exact_buffer_succeeds, {
    fn_any f = getfn(v); INT filt[] = { IPPROTO_UDP, 0 }; DWORD want, len; char *buf; int r;
    need(v, filt, &want);
    buf = calloc(1, want);
    REQUIRE(buf);
    len = want;
    r = f(filt, buf, &len);
    EXPECT_EQ((DWORD)r, want / V[v].esz);
    free(buf);
})

/* ---- second thread -------------------------------------------------------------------------- */
typedef struct { int v; int count; DWORD len; } thr_arg;
static DWORD WINAPI thr_enum(LPVOID p)
{
    thr_arg *a = (thr_arg *)p;
    DWORD len = 0;
    fn_any f = getfn(a->v);
    SET_ERR(0);
    if (f(NULL, NULL, &len) == SOCKET_ERROR && U(WSAGetLastError)() == WSAENOBUFS) { a->count = (int)(len / V[a->v].esz); a->len = len; }
    else a->count = -1;
    return 0;
}

VTEST(works_from_another_thread, {
    thr_arg a = { v, -2, 0 }; DWORD want; HANDLE h;
    need(v, NULL, &want);
    h = CreateThread(NULL, 0, thr_enum, &a, 0, NULL);
    REQUIRE(h);
    EXPECT_EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0);
    CloseHandle(h);
    EXPECT_EQ(a.len, want);
})

/* ---- ANSI conversion of the wide listing ------------------------------------------------------ */
TEST(enumbuf_a_matches_w_numeric_fields)
{
    pc_list w; WSAPROTOCOL_INFOA *a; int nw, na, i;
    PC_NEED_WSA();
    REQUIRE(getfn(0)); REQUIRE(getfn(1));
    nw = pc_enum_w(0, NULL, &w);
    na = pc_enum_a(NULL, &a);
    EXPECT_EQ(na, nw);
    for (i = 0; i < nw && i < na; i++) {
        CHECKF(memcmp(&w.e[i], &a[i], offsetof(WSAPROTOCOL_INFOW, szProtocol)) == 0, "entry %d differs before the name", i);
    }
    pc_free(&w); free(a);
}

TEST(enumbuf_a_name_is_narrowed_w_name)
{
    pc_list w; WSAPROTOCOL_INFOA *a; int nw, na, i;
    PC_NEED_WSA();
    REQUIRE(getfn(0)); REQUIRE(getfn(1));
    nw = pc_enum_w(0, NULL, &w);
    na = pc_enum_a(NULL, &a);
    for (i = 0; i < nw && i < na; i++) {
        char want[WSAPROTOCOL_LEN + 1];
        int k = WideCharToMultiByte(CP_ACP, 0, w.e[i].szProtocol, -1, want, sizeof want, NULL, NULL);
        CHECKF(k > 0, "entry %d name not convertible", i);
        CHECKF(k > 0 && strcmp(want, a[i].szProtocol) == 0, "entry %d name differs", i);
    }
    pc_free(&w); free(a);
}

TEST(enumbuf_a_filter_matches_w_filter)
{
    INT filt[] = { IPPROTO_UDP, IPPROTO_TCP, 0 };
    pc_list w; WSAPROTOCOL_INFOA *a; int nw, na, i;
    PC_NEED_WSA();
    REQUIRE(getfn(0)); REQUIRE(getfn(1));
    nw = pc_enum_w(0, filt, &w);
    na = pc_enum_a(filt, &a);
    EXPECT_EQ(na, nw);
    for (i = 0; i < nw && i < na; i++) EXPECT_EQ(w.e[i].dwCatalogEntryId, a[i].dwCatalogEntryId);
    pc_free(&w); free(a);
}

TEST(enumbuf_a_size_query_is_a_struct_multiple_of_w_count)
{
    DWORD lw, la;
    PC_NEED_WSA();
    REQUIRE(getfn(0)); REQUIRE(getfn(1));
    need(0, NULL, &lw); need(1, NULL, &la);
    EXPECT_EQ(lw / PC_INFOW_SIZE, la / PC_INFOA_SIZE);
}

TEST(enumbuf_struct_sizes_are_abi)
{
    EXPECT_EQ(sizeof(WSAPROTOCOL_INFOW), PC_INFOW_SIZE);
    EXPECT_EQ(sizeof(WSAPROTOCOL_INFOA), PC_INFOA_SIZE);
    EXPECT_EQ(offsetof(WSAPROTOCOL_INFOW, szProtocol), 0x74);
    EXPECT_EQ(offsetof(WSAPROTOCOL_INFOW, iProtocol), 0x5c);
    EXPECT_EQ(offsetof(WSAPROTOCOL_INFOW, iProtocolMaxOffset), 0x60);
}

/* ---- additional cases ------------------------------------------------------------------------ */
CHILD(wsaenum_a_no_startup)
{
    DWORD len = 0; INT r;
    INT (WSAAPI *f)(LPINT, void *, LPDWORD) = (void *)t_proc_in("ws2_32.dll", "WSAEnumProtocolsA");
    if (!f) return 90;
    SetLastError(0);
    r = f(NULL, NULL, &len);
    if (r != SOCKET_ERROR) return 10;
    if (U(WSAGetLastError)() != WSANOTINITIALISED) return 11;
    return 0;
}
TEST(enumbuf_a_before_startup_is_notinitialised) { EXPECT_EQ(t_run_child("wsaenum_a_no_startup", "", 30000), 0); }

TEST(enumbuf_filtered_entries_are_subset_with_matching_range)
{
    INT filt[] = { IPPROTO_UDP, 0 };
    pc_list all, sub; int i;
    PC_NEED_WSA(); REQUIRE(getfn(0));
    CHECK(pc_enum_w(0, NULL, &all) > 0);
    CHECK(pc_enum_w(0, filt, &sub) > 0);
    for (i = 0; i < sub.n; i++) {
        const WSAPROTOCOL_INFOW *m = pc_by_id(&all, sub.e[i].dwCatalogEntryId);
        CHECKF(m != NULL, "filtered entry %d is not in the full listing", i);
        CHECKF(pc_in_range(&sub.e[i], IPPROTO_UDP), "filtered entry %d does not cover UDP", i);
        if (m) CHECKF(memcmp(m, &sub.e[i], sizeof *m) == 0, "filtered entry %d differs from the full listing", i);
    }
    pc_free(&all); pc_free(&sub);
}

TEST(enumbuf_filter_keeps_catalog_order)
{
    INT filt[] = { IPPROTO_TCP, IPPROTO_UDP, 0 };
    pc_list all, sub; int i, last = -1;
    PC_NEED_WSA(); REQUIRE(getfn(0));
    CHECK(pc_enum_w(0, NULL, &all) > 0);
    CHECK(pc_enum_w(0, filt, &sub) > 0);
    for (i = 0; i < sub.n; i++) {
        int k;
        for (k = 0; k < all.n && all.e[k].dwCatalogEntryId != sub.e[i].dwCatalogEntryId; k++) ;
        CHECKF(k < all.n && k > last, "filtered entry %d is out of catalog order", i);
        last = k;
    }
    pc_free(&all); pc_free(&sub);
}

#define CONC_THREADS 4
typedef struct { int bad; } conc_arg;
static DWORD WINAPI conc_thr(LPVOID p)
{
    conc_arg *a = (conc_arg *)p; DWORD first = 0; int i;
    for (i = 0; i < 30; i++) {
        DWORD len = 0;
        if (getfn(0)(NULL, NULL, &len) != SOCKET_ERROR || U(WSAGetLastError)() != WSAENOBUFS) { a->bad++; continue; }
        if (i == 0) first = len; else if (len != first) a->bad++;
    }
    return 0;
}
TEST(enumbuf_concurrent_size_queries_agree)
{
    HANDLE h[CONC_THREADS]; conc_arg a[CONC_THREADS]; int i, bad = 0;
    PC_NEED_WSA(); REQUIRE(getfn(0));
    for (i = 0; i < CONC_THREADS; i++) {
        a[i].bad = 0;
        h[i] = CreateThread(NULL, 0, conc_thr, &a[i], 0, NULL);
        REQUIRE(h[i]);
    }
    for (i = 0; i < CONC_THREADS; i++) {
        CHECK(WaitForSingleObject(h[i], 20000) == WAIT_OBJECT_0);
        CloseHandle(h[i]);
        bad += a[i].bad;
    }
    EXPECT_EQ(bad, 0);
}
