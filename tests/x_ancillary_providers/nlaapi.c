/* The location-awareness client library (nlaapi.dll): the in-process object constructors that never reach the
 * service (type sets, filter trees, plugin-request lists), the net-signature helpers' argument validation, and the
 * handle-based entry points called with handles that do not exist. Measures: the exact Win32 error for each rejected
 * argument, the accepted range of data-type codes, the way the filter builders report a child that belongs to another
 * filter, and the behaviour of the void-returning disposal routines on NULL. No query is opened and the location
 * service is never contacted. */
#include "anc.h"

#define ERR_INVALID_PARAM 87

static HMODULE nla(void) { return t_module("nlaapi.dll"); }
#define NLA_FN(ret, name, args) typedef ret (WINAPI *name##_fn) args
NLA_FN(DWORD, NlaCreate, (void **));
NLA_FN(void, NlaDelete, (void *));
NLA_FN(DWORD, NlaAddTypes, (void *, DWORD, ...));
NLA_FN(void *, NlaCombine, (void *, DWORD, ...));
NLA_FN(void *, NlaLeaf, (void *, void *));
NLA_FN(DWORD, NlaSigCall, (void *, void *, void *, void *));
NLA_FN(DWORD, NlaSigEq, (void *, void *, DWORD, BYTE *));

static void *nfn(const char *name) { HMODULE m = nla(); return m ? (void *)GetProcAddress(m, name) : NULL; }

/* ---- type sets ---- */
TEST(typeset_create_and_delete) {
    NlaCreate_fn cts = nfn("NlaCreateTypeSet"); NlaDelete_fn dts = nfn("NlaDeleteTypeSet");
    if (!cts || !dts) { t_skip("nlaapi.dll type-set exports missing"); return; }
    void *ts = (void *)1;
    EXPECT_EQ(cts(&ts), 0); CHECK(ts != NULL && ts != (void *)1);
    dts(ts);
    EXPECT_EQ(cts(NULL), ERR_INVALID_PARAM);
    dts(NULL);   /* disposal of NULL is a no-op */
    void *a = NULL, *b = NULL;
    EXPECT_EQ(cts(&a), 0); EXPECT_EQ(cts(&b), 0); CHECK(a != b); dts(a); dts(b);
}

TEST(typeset_add_type_code_range) {
    NlaCreate_fn cts = nfn("NlaCreateTypeSet"); NlaDelete_fn dts = nfn("NlaDeleteTypeSet"); NlaAddTypes_fn ats = nfn("NlaAddToTypeSet");
    if (!cts || !dts || !ats) { t_skip("nlaapi.dll type-set exports missing"); return; }
    void *ts = NULL; cts(&ts);
    for (DWORD t = 0; t <= 0x22; t++) { char w[24]; sprintf(w, "type %lu", t); CHECKF(ats(ts, 1, t) == 0, "%s rejected", w); }
    static const DWORD bad[] = { 0x23, 0x24, 0x40, 100, 255, 256, 0x1000, 0x7fffffff, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < ANC_N(bad); i++) CHECKF(ats(ts, 1, bad[i]) == ERR_INVALID_PARAM, "type %lx accepted", bad[i]);
    dts(ts);
}

TEST(typeset_add_argument_validation) {
    NlaCreate_fn cts = nfn("NlaCreateTypeSet"); NlaDelete_fn dts = nfn("NlaDeleteTypeSet"); NlaAddTypes_fn ats = nfn("NlaAddToTypeSet");
    if (!cts || !dts || !ats) { t_skip("nlaapi.dll type-set exports missing"); return; }
    void *ts = NULL; cts(&ts);
    EXPECT_EQ(ats(NULL, 1, 1), ERR_INVALID_PARAM);      /* no set */
    EXPECT_EQ(ats(ts, 0, 1), ERR_INVALID_PARAM);        /* zero entries */
    EXPECT_EQ(ats(ts, 2, 1, 2), 0);                     /* several at once */
    EXPECT_EQ(ats(ts, 3, 1, 2, 3), 0);
    EXPECT_EQ(ats(ts, 2, 1, 0x40), ERR_INVALID_PARAM);  /* one bad entry fails the call */
    EXPECT_EQ(ats(ts, 2, 1, 99), ERR_INVALID_PARAM);
    EXPECT_EQ(ats(ts, 1, 7), 0);                        /* the set stays usable after a failure */
    dts(ts);
}

/* ---- filters ---- */
TEST(filter_create_and_delete) {
    NlaCreate_fn cf = nfn("NlaCreateFilter"); NlaDelete_fn df = nfn("NlaDeleteFilter");
    if (!cf || !df) { t_skip("nlaapi.dll filter exports missing"); return; }
    void *f = (void *)1; EXPECT_EQ(cf(&f), 0); CHECK(f != NULL && f != (void *)1); df(f);
    EXPECT_EQ(cf(NULL), ERR_INVALID_PARAM);
    df(NULL);
}

static void *mk_leaf(NlaLeaf_fn fn, void *f, DWORD type, DWORD size, DWORD *gle) {
    DWORD d[600]; memset(d, 0, sizeof d); d[0] = type; d[2] = size;
    SetLastError(99); void *r = fn(f, d); *gle = GetLastError(); return r;
}

static void leaf_table(const char *name) {
    NlaCreate_fn cf = nfn("NlaCreateFilter"); NlaDelete_fn df = nfn("NlaDeleteFilter"); NlaLeaf_fn leaf = nfn(name);
    if (!cf || !df || !leaf) { t_skip("nlaapi.dll filter exports missing"); return; }
    void *f = NULL; cf(&f); DWORD gle;
    for (DWORD ty = 0; ty < 48; ty++) {
        void *r = mk_leaf(leaf, f, ty, 0, &gle);
        if (ty >= 1 && ty <= 0x22) { CHECKF(r != NULL && gle == 0, "%s type %lu: result %p error %lu", name, ty, r, gle); }
        else { CHECKF(r == NULL && gle == ERR_INVALID_PARAM, "%s type %lu: result %p error %lu", name, ty, r, gle); }
    }
    /* declared payload size */
    CHECK(mk_leaf(leaf, f, 1, 1, &gle) != NULL); EXPECT_EQ(gle, 0);
    CHECK(mk_leaf(leaf, f, 1, 0x30, &gle) != NULL); EXPECT_EQ(gle, 0);
    CHECK(mk_leaf(leaf, f, 1, 0x1000, &gle) == NULL); EXPECT_EQ(gle, ERR_INVALID_PARAM);
    /* missing pieces */
    SetLastError(99); CHECK(leaf(f, NULL) == NULL); EXPECT_ERR(ERR_INVALID_PARAM);
    DWORD d[8] = { 1, 0, 0 };
    SetLastError(99); CHECK(leaf(NULL, d) == NULL); EXPECT_ERR(ERR_INVALID_PARAM);
    SetLastError(99); CHECK(leaf(NULL, NULL) == NULL); EXPECT_ERR(ERR_INVALID_PARAM);
    df(f);
}
TEST(filter_equal_validates_the_data_block) { leaf_table("NlaEqual"); }
TEST(filter_not_equal_validates_the_data_block) { leaf_table("NlaNotEqual"); }

static void combine_rules(const char *name) {
    NlaCreate_fn cf = nfn("NlaCreateFilter"); NlaDelete_fn df = nfn("NlaDeleteFilter"); NlaCombine_fn comb = nfn(name); NlaLeaf_fn eq = nfn("NlaEqual");
    if (!cf || !df || !comb || !eq) { t_skip("nlaapi.dll filter exports missing"); return; }
    void *f = NULL, *g = NULL; cf(&f); cf(&g); DWORD gle;
    void *a = mk_leaf(eq, f, 1, 0, &gle), *b = mk_leaf(eq, f, 2, 0, &gle), *x = mk_leaf(eq, g, 1, 0, &gle);
    CHECK(a != NULL && b != NULL && x != NULL);
    SetLastError(99); void *r = comb(f, 0, NULL, NULL); CHECK(r != NULL); EXPECT_ERR(0);               /* an empty combination is accepted */
    SetLastError(99); r = comb(f, 1, a); CHECK(r != NULL); EXPECT_ERR(0);
    SetLastError(99); r = comb(f, 2, a, b); CHECK(r != NULL); EXPECT_ERR(0);
    SetLastError(99); r = comb(NULL, 1, a); CHECK(r == NULL); EXPECT_ERR(ERR_INVALID_PARAM);          /* no filter */
    SetLastError(99); r = comb(f, 1, NULL); CHECK(r == NULL); EXPECT_ERR(ERR_INVALID_PARAM);          /* NULL child */
    SetLastError(99); r = comb(f, 2, a, NULL); CHECK(r == NULL); EXPECT_ERR(ERR_INVALID_PARAM);
    SetLastError(99); r = comb(f, 1, x); CHECK(r == x); EXPECT_ERR(ERR_INVALID_PARAM);                /* a child of another filter: the offending child is returned with the error set */
    SetLastError(99); r = comb(f, 2, a, x); CHECK(r == x); EXPECT_ERR(ERR_INVALID_PARAM);
    df(f); df(g);
}
TEST(filter_and_builder_rules) { combine_rules("NlaAnd"); }
TEST(filter_or_builder_rules) { combine_rules("NlaOr"); }

TEST(filter_single_level_tree_disposal) {
    NlaCreate_fn cf = nfn("NlaCreateFilter"); NlaDelete_fn df = nfn("NlaDeleteFilter"); NlaCombine_fn an = nfn("NlaAnd"), orr = nfn("NlaOr"); NlaLeaf_fn eq = nfn("NlaEqual");
    if (!cf || !df || !an || !orr || !eq) { t_skip("nlaapi.dll filter exports missing"); return; }
    /* Deleting a filter releases the tree under its last root. A tree with one combining node over equality leaves is
     * released cleanly; deeper nesting is not exercised because the release walk does not handle it. */
    for (int round = 0; round < 20; round++) {
        void *f = NULL; DWORD gle; cf(&f);
        void *a = mk_leaf(eq, f, 3, 0, &gle), *b = mk_leaf(eq, f, 4, 0, &gle);
        void *c = (round & 1) ? an(f, 2, a, b) : orr(f, 2, a, b);
        CHECK(a && b && c); CHECK(a != b && b != c && a != c);
        df(f);
    }
}

/* ---- plugin-request lists ---- */
TEST(plugin_requests_create_and_delete) {
    NlaCreate_fn cpr = nfn("NlaCreatePluginRequests"); NlaDelete_fn dpr = nfn("NlaDeletePluginRequests");
    if (!cpr || !dpr) { t_skip("nlaapi.dll plugin-request exports missing"); return; }
    void *p = (void *)1; EXPECT_EQ(cpr(&p), 0); CHECK(p != NULL && p != (void *)1);
    dpr(p); dpr(NULL);
    NlaAddTypes_fn apr = nfn("NlaAddToPluginRequests");
    if (apr) { void *q = NULL; cpr(&q); EXPECT_EQ(apr(q, 0, NULL), ERR_INVALID_PARAM); dpr(q); }
}

/* ---- disposal routines tolerate NULL ---- */
TEST(disposal_routines_accept_null) {
    NlaDelete_fn dds = nfn("NlaDeleteDataSet"); NlaDelete_fn lan = nfn("LANIdFreeCollection");
    if (!dds || !lan) { t_skip("nlaapi.dll disposal exports missing"); return; }
    dds(NULL); lan(NULL);
    CHECK(1);
}

/* ---- net signatures: argument validation ---- */
static DWORD sigblk[16];
static void sig_init(void) { memset(sigblk, 0, sizeof sigblk); sigblk[0] = 1; sigblk[2] = 0x30; }

TEST(netsignature_compose_validation) {
    NlaSigCall_fn comp = nfn("NlaComposeNetSignature");
    if (!comp) { t_skip("NlaComposeNetSignature missing"); return; }
    BYTE g[16] = { 1, 2, 3, 4 }; DWORD mask;
    sig_init();
    EXPECT_EQ(comp(NULL, &mask, g, NULL), ERR_INVALID_PARAM);
    mask = 1; EXPECT_EQ(comp(NULL, &mask, g, NULL), ERR_INVALID_PARAM);
    EXPECT_EQ(comp(sigblk, NULL, g, NULL), ERR_INVALID_PARAM);
    mask = 0; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);       /* no component selected */
    mask = 8; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);       /* unknown component bit */
    mask = 0x10; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
    mask = 0xffffffffu; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
    mask = 1; sigblk[0] = 2; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);   /* wrong block type */
    sig_init(); sigblk[2] = 0x2f; mask = 1; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);   /* wrong block size */
    sigblk[2] = 0x31; EXPECT_EQ(comp(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
}

TEST(netsignature_decompose_validation) {
    NlaSigCall_fn dec = nfn("NlaDecomposeNetSignature");
    if (!dec) { t_skip("NlaDecomposeNetSignature missing"); return; }
    BYTE g[16]; DWORD mask;
    sig_init();
    mask = 1; EXPECT_EQ(dec(NULL, &mask, g, NULL), ERR_INVALID_PARAM);
    EXPECT_EQ(dec(sigblk, NULL, g, NULL), ERR_INVALID_PARAM);
    mask = 0; EXPECT_EQ(dec(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
    mask = 8; EXPECT_EQ(dec(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
    mask = 1; sigblk[0] = 3; EXPECT_EQ(dec(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
    sig_init(); sigblk[2] = 0x20; EXPECT_EQ(dec(sigblk, &mask, g, NULL), ERR_INVALID_PARAM);
    /* a well-formed but empty signature has nothing to decompose */
    sig_init(); mask = 1; memset(g, 0xAA, sizeof g);
    EXPECT_EQ(dec(sigblk, &mask, g, NULL), 777); CHECK(g[0] == 0xAA);
}

TEST(netsignature_equal_validation) {
    NlaSigEq_fn eqs = nfn("NlaEqualNetSignatures");
    if (!eqs) { t_skip("NlaEqualNetSignatures missing"); return; }
    DWORD b2[16]; BYTE eq = 0x55; sig_init(); memcpy(b2, sigblk, sizeof b2);
    EXPECT_EQ(eqs(NULL, b2, 1, &eq), ERR_INVALID_PARAM);
    EXPECT_EQ(eqs(sigblk, NULL, 1, &eq), ERR_INVALID_PARAM);
    EXPECT_EQ(eqs(sigblk, b2, 1, NULL), ERR_INVALID_PARAM);
    EXPECT_EQ(eqs(sigblk, b2, 0, &eq), ERR_INVALID_PARAM);
    EXPECT_EQ(eqs(sigblk, b2, 8, &eq), ERR_INVALID_PARAM);
    EXPECT_EQ(eqs(sigblk, b2, 0xffffffffu, &eq), ERR_INVALID_PARAM);
    b2[0] = 2; EXPECT_EQ(eqs(sigblk, b2, 1, &eq), ERR_INVALID_PARAM);
    CHECK(eq == 0x55);
    b2[0] = 1; sigblk[0] = 0; EXPECT_EQ(eqs(sigblk, b2, 1, &eq), ERR_INVALID_PARAM);
    sig_init(); EXPECT_EQ(eqs(sigblk, b2, 1, &eq), 777);
}

/* ---- capability queries: argument check before the handle lookup ---- */
TEST(capability_queries_check_pointers_first) {
    typedef DWORD (WINAPI *inet_fn)(HANDLE, int *, BYTE *);
    typedef DWORD (WINAPI *intra_fn)(HANDLE, int *, BYTE *, BYTE *);
    inet_fn gi = nfn("NlaGetInternetCapability"); intra_fn gt = nfn("NlaGetIntranetCapability");
    if (!gi || !gt) { t_skip("capability exports missing"); return; }
    int x = 0; BYTE b = 0;
    EXPECT_EQ(gi(NULL, &x, NULL), ERR_INVALID_PARAM);
    EXPECT_EQ(gi((HANDLE)0x1234, &x, NULL), ERR_INVALID_PARAM);
    EXPECT_EQ(gt(NULL, &x, NULL, NULL), ERR_INVALID_PARAM);
    EXPECT_EQ(gt((HANDLE)0x1234, &x, NULL, NULL), ERR_INVALID_PARAM);
    (void)b;
}

/* ---- handle-based entry points with handles that were never issued ---- */
TEST(query_handles_that_do_not_exist_are_rejected) {
    typedef DWORD (WINAPI *h1_fn)(HANDLE);
    typedef DWORD (WINAPI *hq_fn)(HANDLE, void *);
    typedef DWORD (WINAPI *inet_fn)(HANDLE, int *, BYTE *);
    typedef DWORD (WINAPI *intra_fn)(HANDLE, int *, BYTE *, BYTE *);
    h1_fn refresh = nfn("NlaRefreshQuery"); hq_fn sigs = nfn("NlaQueryNetSignatures");
    inet_fn gi = nfn("NlaGetInternetCapability"); intra_fn gt = nfn("NlaGetIntranetCapability");
    if (!refresh || !sigs || !gi || !gt) { t_skip("handle-based exports missing"); return; }
    HANDLE hs[] = { NULL, (HANDLE)0x1234, (HANDLE)(ULONG_PTR)-1 };
    for (size_t i = 0; i < ANC_N(hs); i++) {
        DWORD r = refresh(hs[i]); CHECKF(r == ERROR_INVALID_HANDLE, "NlaRefreshQuery handle %zu: %lu", i, r);
        BYTE buf[256]; memset(buf, 0, sizeof buf);
        r = sigs(hs[i], buf); t_note("net-signature query on unissued handle %zu -> %lu", i, r); CHECKF(r == ERROR_INVALID_HANDLE, "NlaQueryNetSignatures handle %zu: %lu", i, r);
        int x = 0; BYTE b = 0;
        r = gi(hs[i], &x, &b); t_note("internet capability on unissued handle %zu -> %lu", i, r); CHECKF(r == ERROR_INVALID_HANDLE, "NlaGetInternetCapability handle %zu: %lu", i, r);
        r = gt(hs[i], &x, &b, &b); t_note("intranet capability on unissued handle %zu -> %lu", i, r); CHECKF(r == ERROR_INVALID_HANDLE, "NlaGetIntranetCapability handle %zu: %lu", i, r);
    }
}
