/* Versioned address-info results. The hint's ai_version field is only honoured when the hint also sets
 * AI_EXTENDED; and only entries whose ai_flags carry AI_EXTENDED may be read past the base structure.
 * Observed rule: AI_EXTENDED with both AI_CANONNAME and AI_FQDN yields version-2 entries (ai_version 2,
 * ai_fqdn on the first entry only); AI_RESOLUTION_HANDLE yields version-4 entries; every other request
 * yields plain entries whatever version the hint declares. */
#include "gx.h"

#define NSDNS 12
#define AI_EXTENDED_F 0x80000000u
#define AI_RESHANDLE_F 0x40000000u

static const char *const vnames[] = {"localhost", "127.0.0.1", "::1"};

static void check_v2_chain(const char *name, GXEX *res)
{
    GXEX *e;
    int first = 1;
    for (e = res; e; e = e->ai_next, first = 0) {
        CHECKF(((unsigned)e->ai_flags & AI_EXTENDED_F) != 0, "%s entry lacks AI_EXTENDED", name);
        if (!((unsigned)e->ai_flags & AI_EXTENDED_F)) return;
        CHECKF(e->ai_version == 2, "%s ai_version %d", name, e->ai_version);
        if (first) {
            CHECK(e->ai_fqdn != NULL && e->ai_canonname != NULL);
            if (e->ai_fqdn && e->ai_canonname) EXPECT_WSTR(e->ai_fqdn, e->ai_canonname);
        } else {
            CHECK(e->ai_fqdn == NULL);
            CHECK(e->ai_canonname == NULL);
        }
    }
}
TEST(xver_extended_canon_and_fqdn_gives_version2_entries)
{
    unsigned i; int v, idx;
    GX_BEGIN();
    for (i = 0; i < NARR(vnames); i++) for (v = 2; v <= 4; v++) for (idx = 0; idx < 2; idx++) {
        GXEX h = gx_hint((int)(AI_EXTENDED_F | AI_CANONNAME | AI_FQDN), 0, 0, 0);
        gx_res r;
        h.ai_version = v; h.ai_interfaceindex = idx;
        r = gx_call(vnames[i], NULL, NSDNS, &h);
        CHECKF(r.ret == 0 && r.wsa == 0, "%s v%d ret=%d", vnames[i], v, r.ret);
        if (r.ret == 0) {
            GX_EQ(gx_count(r.res), i == 0 ? 2 : 1);
            check_v2_chain(vnames[i], r.res);
            if (i > 0 && r.res->ai_fqdn) EXPECT_WSTR(r.res->ai_fqdn, gx_w(vnames[i]));   /* a literal's fqdn is its own text */
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xver_extended_fqdn_of_localhost_is_machine_name)
{
    GX_BEGIN();
    GXEX h = gx_hint((int)(AI_EXTENDED_F | AI_CANONNAME | AI_FQDN), 0, 0, 0);
    gx_res r;
    WCHAR a[300], b[300]; DWORD la = 300, lb = 300;
    h.ai_version = 2;
    r = gx_call("localhost", NULL, NSDNS, &h);
    GX_EQ(r.ret, 0);
    if (r.ret == 0 && r.res->ai_fqdn) {
        if (!GetComputerNameExW(ComputerNameDnsHostname, a, &la)) a[0] = 0;
        if (!GetComputerNameExW(ComputerNameDnsFullyQualified, b, &lb)) b[0] = 0;
        CHECKF(!lstrcmpiW(r.res->ai_fqdn, a) || !lstrcmpiW(r.res->ai_fqdn, b), "fqdn '%s'", gx_s(r.res->ai_fqdn));
    }
    gx_release(&r);
    GX_END();
}
TEST(xver_extended_with_one_name_flag_gives_plain_entries)
{
    static const int fl[] = {0, AI_CANONNAME, AI_FQDN, AI_RETURN_PREFERRED_NAMES};
    unsigned i, f; int v;
    GX_BEGIN();
    for (i = 0; i < NARR(vnames); i++) for (f = 0; f < NARR(fl); f++) for (v = 2; v <= 4; v++) {
        GXEX h = gx_hint((int)(AI_EXTENDED_F | fl[f]), 0, 0, 0), *e;
        gx_res r;
        h.ai_version = v;
        r = gx_call(vnames[i], NULL, NSDNS, &h);
        CHECKF(r.ret == 0, "%s fl=%x v%d ret=%d", vnames[i], fl[f], v, r.ret);
        if (r.ret == 0) for (e = r.res; e; e = e->ai_next) CHECKF(((unsigned)e->ai_flags & AI_EXTENDED_F) == 0, "%s fl=%x v%d entry flags %x", vnames[i], fl[f], v, e->ai_flags);
        gx_release(&r);
    }
    GX_END();
}
/* AI_CANONNAME and AI_FQDN together produce version-2 entries even when the hint neither sets AI_EXTENDED nor
 * declares a version (any declared value, valid or not, is ignored without AI_EXTENDED). */
TEST(xver_canon_and_fqdn_together_always_give_version2_entries)
{
    unsigned i; int v;
    GX_BEGIN();
    for (i = 0; i < NARR(vnames); i++) for (v = -1; v <= 8; v++) {
        GXEX h = gx_hint(AI_CANONNAME | AI_FQDN, 0, 0, 0);
        gx_res r;
        h.ai_version = v; h.ai_interfaceindex = 1;
        r = gx_call(vnames[i], NULL, NSDNS, &h);
        CHECKF(r.ret == 0 && gx_count(r.res) == (i == 0 ? 2 : 1), "%s v%d ret=%d", vnames[i], v, r.ret);
        if (r.ret == 0) check_v2_chain(vnames[i], r.res);
        gx_release(&r);
    }
    GX_END();
}
TEST(xver_single_name_flag_gives_plain_entries_whatever_the_version)
{
    static const int fl[] = {0, AI_CANONNAME, AI_FQDN};
    unsigned i, f; int v;
    GX_BEGIN();
    for (i = 0; i < NARR(vnames); i++) for (f = 0; f < NARR(fl); f++) for (v = -1; v <= 8; v++) {
        GXEX h = gx_hint(fl[f], 0, 0, 0), *e;
        gx_res r;
        h.ai_version = v;
        r = gx_call(vnames[i], NULL, NSDNS, &h);
        CHECKF(r.ret == 0, "%s fl=%x v%d ret=%d", vnames[i], fl[f], v, r.ret);
        if (r.ret == 0) for (e = r.res; e; e = e->ai_next) CHECKF(((unsigned)e->ai_flags & AI_EXTENDED_F) == 0, "%s fl=%x v%d entry flags %x", vnames[i], fl[f], v, e->ai_flags);
        gx_release(&r);
    }
    GX_END();
}
TEST(xver_extended_with_unknown_versions_still_resolves_literals)
{
    static const int vs[] = {-1, 0, 1, 6, 99};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(vs); i++) {
        GXEX h = gx_hint((int)AI_EXTENDED_F, 0, 0, 0);
        gx_res r;
        h.ai_version = vs[i];
        r = gx_call("127.0.0.1", NULL, NSDNS, &h);
        CHECKF(r.ret == 0 && gx_count(r.res) == 1 && GX_IS_V4(r.res, "127.0.0.1"), "v%d ret=%d", vs[i], r.ret);
        gx_release(&r);
    }
    GX_END();
}
TEST(xver_resolution_handle_flag_gives_version4_entries)
{
    int hv;
    GX_BEGIN();
    for (hv = 0; hv <= 2; hv++) {
        GXEX h = gx_hint((int)AI_RESHANDLE_F, 0, 0, 0), *e;
        gx_res r;
        h.ai_version = hv;
        r = gx_call("localhost", NULL, NSDNS, &h);
        GX_EQ(r.ret, 0);
        if (r.ret == 0) {
            GX_EQ(gx_count(r.res), 2);
            for (e = r.res; e; e = e->ai_next) {
                CHECKF((unsigned)e->ai_flags == AI_EXTENDED_F, "entry flags %x", e->ai_flags);
                if ((unsigned)e->ai_flags == AI_EXTENDED_F) { GX_EQ(e->ai_version, 4); CHECK(e->ai_fqdn == NULL); }
            }
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xver_extended_chain_frees_cleanly_and_repeatedly)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 20; i++) {
        GXEX h = gx_hint((int)(AI_EXTENDED_F | AI_CANONNAME | AI_FQDN), 0, 0, 0);
        gx_res r;
        h.ai_version = 2 + (i % 3);
        r = gx_call("localhost", NULL, NSDNS, &h);
        GX_EQ(r.ret, 0);
        gx_release(&r);
    }
    GX_END();
}
TEST(xver_extended_overlapped_localhost)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = NULL; GXEX h = gx_hint((int)(AI_EXTENDED_F | AI_CANONNAME | AI_FQDN), 0, 0, 0);
    h.ai_version = 2;
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, &h, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    CHECK(res != NULL);
    if (res) { GX_EQ(gx_count(res), 2); check_v2_chain("localhost", res); GXFREE(res); }
    CloseHandle(ev);
    GX_END();
}
