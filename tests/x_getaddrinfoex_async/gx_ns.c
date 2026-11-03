/* GetAddrInfoExW name-space selector and name-shape matrix, loopback and literal data only.
 * Measures: which dwNameSpace values are accepted, the exact error for the others, how literal names
 * (v4/v6/bracketed/scoped/mapped) and "localhost" are answered, and the shape of the answer entries.
 * The last two checks of each row are relations (same answer for NS_ALL and NS_DNS). */
#include "gx.h"

#define NSALL 0
#define NSDNS 12
#define NSNLA 15

/* ---- literals ---------------------------------------------------------------------------------- */
static const struct { const char *name; int fam; const char *addr; } lits[] = {
    {"127.0.0.1", AF_INET, "127.0.0.1"},
    {"1.2.3.4", AF_INET, "1.2.3.4"},
    {"0.0.0.0", AF_INET, "0.0.0.0"},
    {"::1", AF_INET6, "v6:0:0:0:0:0:0:0:1"},
    {"[::1]", AF_INET6, "v6:0:0:0:0:0:0:0:1"},
    {"0:0:0:0:0:0:0:1", AF_INET6, "v6:0:0:0:0:0:0:0:1"},
    {"::", AF_INET6, "v6:0:0:0:0:0:0:0:0"},
    {"fe80::1%1", AF_INET6, "v6:fe80:0:0:0:0:0:0:1"},
    {"::ffff:1.2.3.4", AF_INET6, "v6:0:0:0:0:0:ffff:102:304"},
};
TEST(xns_literals_answer_single_numeric_entry)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(lits); i++) {
        gx_res r = gx_call(lits[i].name, NULL, ns ? NSDNS : NSALL, NULL);
        CHECKF(r.ret == 0 && r.wsa == 0, "%s ns=%d ret=%d wsa=%d", lits[i].name, ns, r.ret, r.wsa);
        if (r.ret == 0 && r.res) {
            CHECKF(gx_count(r.res) == 1, "%s count %d", lits[i].name, gx_count(r.res));
            CHECKF(r.res->ai_family == lits[i].fam, "%s family %d", lits[i].name, r.res->ai_family);
            CHECKF(!strcmp(gx_addr(r.res->ai_addr, r.res->ai_addrlen), lits[i].addr), "%s addr %s", lits[i].name,
                   gx_addr(r.res->ai_addr, r.res->ai_addrlen));
            /* a numeric answer is marked AI_NUMERICHOST in every entry */
            GX_EQ(r.res->ai_flags & AI_NUMERICHOST, AI_NUMERICHOST);
            CHECK(r.res->ai_canonname == NULL);
            CHECK(r.res->ai_blob == NULL && r.res->ai_bloblen == 0 && r.res->ai_provider == NULL);
            GX_EQ(r.res->ai_addrlen, r.res->ai_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            GX_EQ(gx_port(r.res->ai_addr), 0);
        }
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_scoped_literal_keeps_scope_zero_out_of_loopback)
{
    GX_BEGIN();
    gx_res r = gx_call("fe80::1%1", NULL, NSDNS, NULL);
    GX_EQ(r.ret, 0);
    if (r.res && r.res != &gx_sentinel_ex && r.res->ai_family == AF_INET6)
        GX_EQ(((struct sockaddr_in6 *)r.res->ai_addr)->sin6_scope_id, 1);
    gx_release(&r);
    GX_END();
}

/* ---- localhost spellings ----------------------------------------------------------------------- */
static const char *const lhnames[] = {"localhost", "LOCALHOST", "LocalHost", "localhost."};
TEST(xns_localhost_returns_v6_then_v4)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(lhnames); i++) {
        gx_res r = gx_call(lhnames[i], NULL, ns ? NSDNS : NSALL, NULL);
        CHECKF(r.ret == 0 && r.wsa == 0, "%s ret=%d wsa=%d", lhnames[i], r.ret, r.wsa);
        CHECKF(!strcmp(gx_fams(r.res == &gx_sentinel_ex ? NULL : r.res), "23,2"), "%s order %s", lhnames[i], gx_fams(r.res));
        if (r.ret == 0 && gx_count(r.res) == 2) {
            CHECK(GX_IS_V6LOOP(r.res));
            CHECK(GX_IS_V4(r.res->ai_next, "127.0.0.1"));
            /* a name (not a literal) is not marked numeric */
            GX_EQ(r.res->ai_flags & AI_NUMERICHOST, 0);
            GX_EQ(r.res->ai_next->ai_flags & AI_NUMERICHOST, 0);
            CHECK(r.res->ai_canonname == NULL && r.res->ai_next->ai_canonname == NULL);
        }
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_all_and_dns_agree_for_loopback_names)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(lhnames) + NARR(lits); i++) {
        const char *n = i < NARR(lhnames) ? lhnames[i] : lits[i - NARR(lhnames)].name;
        gx_res a = gx_call(n, NULL, NSALL, NULL), d = gx_call(n, NULL, NSDNS, NULL);
        GX_EQ(a.ret, d.ret);
        if (a.ret == 0 && d.ret == 0) {
            GXEX *x = a.res, *y = d.res;
            GX_EQ(gx_count(a.res), gx_count(d.res));
            for (; x && y; x = x->ai_next, y = y->ai_next) {
                GX_EQ(x->ai_family, y->ai_family);
                GX_EQ(x->ai_addrlen, y->ai_addrlen);
                CHECK(!memcmp(x->ai_addr, y->ai_addr, x->ai_addrlen));
                GX_EQ(x->ai_flags, y->ai_flags);
            }
        }
        gx_release(&a); gx_release(&d);
    }
    GX_END();
}

/* ---- names that must not resolve --------------------------------------------------------------- */
/* Non-dotted-quad numerics are not literals, are not in the hosts file, and the guest has no resolver:
 * the answer is "host not found" under both selectors, and the result slot is cleared. */
static const char *const nonames[] = {"0x7f.1", "127.1", "1.1.1.1.1", "256.1.1.1", "a_b.invalid", "1.2.3.4.in-addr.arpa",
                                      "xn--4ca.test", "nosuch.invalid", "127.0.0.1.", "1.2.3", "01.02.03.04.05"};
TEST(xns_unresolvable_names_host_not_found)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(nonames); i++) {
        gx_res r = gx_call(nonames[i], NULL, ns ? NSDNS : NSALL, NULL);
        CHECKF(r.ret == WSAHOST_NOT_FOUND && r.wsa == WSAHOST_NOT_FOUND, "%s ns=%d ret=%d wsa=%d", nonames[i], ns, r.ret, r.wsa);
        CHECKF(r.res == NULL, "%s result slot not cleared", nonames[i]);
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_non_ascii_names_host_not_found)
{
    static const WCHAR n1[] = {0xe4, 0xf6, 0xfc, '.', 't', 'e', 's', 't', 0};
    static const WCHAR n2[] = {0x4f8b, 0x3048, '.', 'j', 'p', 0};
    static const WCHAR n3[] = {0xff11, 0xff12, 0xff17, '.', '0', '.', '0', '.', '1', 0}; /* fullwidth digits */
    static const WCHAR n4[] = {'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x3002, 0};   /* ideographic full stop */
    const WCHAR *names[] = {n1, n2, n3, n4};
    unsigned i; int ns, flagsel;
    GX_BEGIN();
    for (flagsel = 0; flagsel < 2; flagsel++) for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(names); i++) {
        GXEX h = gx_hint(flagsel ? AI_DISABLE_IDN_ENCODING : 0, 0, 0, 0), *res = &gx_sentinel_ex;
        SETWSERR(0x7777);
        int r = GXW()(names[i], NULL, ns ? NSDNS : NSALL, NULL, &h, (void **)&res, NULL, NULL, NULL, NULL);
        CHECKF(r == WSAHOST_NOT_FOUND && WSERR() == WSAHOST_NOT_FOUND, "name %u ns=%d flag=%d ret=%d", i, ns, flagsel, r);
        CHECK(res == NULL);
    }
    GX_END();
}

/* A name written with fullwidth dots is mapped to the dotted-quad literal during name normalisation, so it
 * resolves to the same address, but the entry is NOT flagged numeric (it was resolved as a name) and the
 * canonical name keeps the original spelling. AI_DISABLE_IDN_ENCODING does not change that. */
TEST(xns_fullwidth_dots_map_to_literal_address)
{
    static const WCHAR fw[] = {'1', '2', '7', 0xff0e, '0', 0xff0e, '0', 0xff0e, '1', 0};
    int flagsel;
    GX_BEGIN();
    for (flagsel = 0; flagsel < 3; flagsel++) {
        GXEX h = gx_hint(flagsel == 0 ? 0 : flagsel == 1 ? AI_DISABLE_IDN_ENCODING : AI_CANONNAME, 0, 0, 0), *res = &gx_sentinel_ex;
        SETWSERR(0x7777);
        int r = GXW()(fw, NULL, NSDNS, NULL, &h, (void **)&res, NULL, NULL, NULL, NULL);
        GX_EQ(r, 0);
        if (r == 0 && res) {
            GX_EQ(gx_count(res), 1);
            CHECK(GX_IS_V4(res, "127.0.0.1"));
            GX_EQ(res->ai_flags & AI_NUMERICHOST, 0);
            if (flagsel == 2) { CHECK(res->ai_canonname != NULL); if (res->ai_canonname) EXPECT_WSTR(res->ai_canonname, fw); }
            else CHECK(res->ai_canonname == NULL);
            U(FreeAddrInfoExW)((PADDRINFOEXW)res);
        }
    }
    GX_END();
}

/* ---- name spaces ------------------------------------------------------------------------------- */
/* Selectors without a provider for host names: "service not found" whatever the name is; the two PNRP
 * selectors are rejected as invalid arguments; none of this depends on the name. */
static const struct { DWORD ns; int err; } nsrows[] = {
    {1, WSASERVICE_NOT_FOUND}, {10, WSASERVICE_NOT_FOUND}, {11, WSASERVICE_NOT_FOUND}, {13, WSASERVICE_NOT_FOUND},
    {14, WSASERVICE_NOT_FOUND}, {15, WSASERVICE_NOT_FOUND}, {16, WSASERVICE_NOT_FOUND}, {37, WSASERVICE_NOT_FOUND},
    {38, WSAEINVAL}, {39, WSAEINVAL}, {99, WSASERVICE_NOT_FOUND}, {0xffffffffu, WSASERVICE_NOT_FOUND},
};
static const char *const nsnames[] = {"127.0.0.1", "::1", "localhost", "1.2.3.4", "nosuch.invalid", "0x7f.1", ""};
TEST(xns_unsupported_selector_error_table)
{
    unsigned i, j;
    GX_BEGIN();
    for (i = 0; i < NARR(nsrows); i++) for (j = 0; j < NARR(nsnames); j++) {
        gx_res r = gx_call(nsnames[j], NULL, nsrows[i].ns, NULL);
        CHECKF(r.ret == nsrows[i].err && r.wsa == nsrows[i].err, "ns=%lu name='%s' ret=%d wsa=%d", (unsigned long)nsrows[i].ns, nsnames[j], r.ret, r.wsa);
        CHECK(r.res == NULL);
        gx_release(&r);
    }
    GX_END();
}

/* The NULL-name/NULL-service check runs before the selector is looked at. */
TEST(xns_null_name_null_service_precedes_selector)
{
    static const DWORD all[] = {0, 1, 10, 11, 12, 13, 14, 15, 16, 37, 38, 39, 99, 0xffffffffu};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(all); i++) {
        gx_res r = gx_call(NULL, NULL, all[i], NULL);
        CHECKF(r.ret == WSAHOST_NOT_FOUND && r.wsa == WSAHOST_NOT_FOUND, "ns=%lu ret=%d wsa=%d", (unsigned long)all[i], r.ret, r.wsa);
        CHECK(r.res == NULL);
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_empty_name_returns_local_addresses)
{
    int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) {
        gx_res r = gx_call("", NULL, ns ? NSDNS : NSALL, NULL);
        GXEX *e;
        GX_EQ(r.ret, 0);
        GX_EQ(r.wsa, 0);
        CHECK(r.res != NULL && r.res != &gx_sentinel_ex);
        for (e = r.res == &gx_sentinel_ex ? NULL : r.res; e; e = e->ai_next) {
            CHECK(e->ai_family == AF_INET || e->ai_family == AF_INET6);
            GX_EQ(e->ai_flags & AI_NUMERICHOST, 0);
        }
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_family_filter_on_localhost)
{
    GX_BEGIN();
    GXEX h4 = gx_hint(0, AF_INET, 0, 0), h6 = gx_hint(0, AF_INET6, 0, 0), h0 = gx_hint(0, AF_UNSPEC, 0, 0);
    gx_res a = gx_call("localhost", NULL, NSDNS, &h4), b = gx_call("localhost", NULL, NSDNS, &h6), c = gx_call("localhost", NULL, NSDNS, &h0);
    GX_EQ(a.ret, 0); GX_EQ(b.ret, 0); GX_EQ(c.ret, 0);
    CHECKF(!strcmp(gx_fams(a.res), "2"), "v4 only: %s", gx_fams(a.res));
    CHECKF(!strcmp(gx_fams(b.res), "23"), "v6 only: %s", gx_fams(b.res));
    CHECKF(!strcmp(gx_fams(c.res), "23,2"), "unspec: %s", gx_fams(c.res));
    gx_release(&a); gx_release(&b); gx_release(&c);
    GX_END();
}

TEST(xns_literal_vs_wrong_family_hint)
{
    GX_BEGIN();
    GXEX h6 = gx_hint(0, AF_INET6, 0, 0), h4 = gx_hint(0, AF_INET, 0, 0);
    gx_res a = gx_call("127.0.0.1", NULL, NSDNS, &h6), b = gx_call("::1", NULL, NSDNS, &h4);
    GX_EQ(a.ret, WSAHOST_NOT_FOUND); GX_EQ(a.wsa, WSAHOST_NOT_FOUND); CHECK(a.res == NULL);
    GX_EQ(b.ret, WSAHOST_NOT_FOUND); GX_EQ(b.wsa, WSAHOST_NOT_FOUND); CHECK(b.res == NULL);
    gx_release(&a); gx_release(&b);
    GX_END();
}

TEST(xns_unsupported_family_hint_error_table)
{
    static const int fams[] = {1, 6, 17, 99, -1};
    unsigned i, j;
    static const char *const names[] = {"localhost", "127.0.0.1", "::1"};
    GX_BEGIN();
    for (i = 0; i < NARR(fams); i++) for (j = 0; j < NARR(names); j++) {
        GXEX h = gx_hint(0, fams[i], 0, 0);
        gx_res r = gx_call(names[j], NULL, NSDNS, &h);
        CHECKF(r.ret == WSAEAFNOSUPPORT && r.wsa == WSAEAFNOSUPPORT, "fam %d %s ret=%d", fams[i], names[j], r.ret);
        CHECK(r.res == NULL);
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_success_clears_thread_error_slot)
{
    GX_BEGIN();
    static const char *const names[] = {"localhost", "127.0.0.1", "::1", ""};
    unsigned i;
    for (i = 0; i < NARR(names); i++) {
        gx_res r = gx_call(names[i], NULL, NSDNS, NULL);
        CHECKF(r.ret == 0 && r.wsa == 0, "%s: marker 0x7777 must be cleared, wsa=%d", names[i], r.wsa);
        gx_release(&r);
    }
    GX_END();
}

TEST(xns_failure_sets_thread_error_slot_to_return_value)
{
    GX_BEGIN();
    gx_res a = gx_call("0x7f.1", NULL, NSDNS, NULL), b = gx_call("127.0.0.1", NULL, 99, NULL), c = gx_call("127.0.0.1", NULL, 38, NULL);
    GX_EQ(a.wsa, a.ret); GX_EQ(b.wsa, b.ret); GX_EQ(c.wsa, c.ret);
    GX_END();
}

TEST(xns_result_chain_is_freeable_repeatedly)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 50; i++) {
        gx_res r = gx_call("localhost", NULL, NSDNS, NULL);
        GX_EQ(r.ret, 0);
        gx_release(&r);
    }
    GX_END();
}
