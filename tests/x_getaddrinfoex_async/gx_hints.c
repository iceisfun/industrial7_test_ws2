/* GetAddrInfoExW hint-structure rules: fields that must be zero, fields that are passed through, flag bits
 * one at a time, canonical-name flags, passive addresses. All names are loopback or literals. */
#include "gx.h"

#define NSALL 0
#define NSDNS 12

/* ---- fields that must be zero in the hint -------------------------------------------------------- */
/* ai_addrlen, ai_canonname, ai_addr and ai_next must be zero/NULL in the hint: "no recovery" otherwise,
 * checked before the name is looked at (so it applies to any name). ai_blob, ai_bloblen and ai_provider
 * are ignored. The pointers used are valid, never garbage. */
static const char *const hnames[] = {"localhost", "127.0.0.1", "", "nosuch.invalid"};
static void dirty_row(int field, int expect_ok)
{
    unsigned i; int ns;
    static char dummy[64];
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(hnames); i++) {
        if (expect_ok == 0 && i == 3 && field == 0) continue;
        GXEX h = gx_hint(0, 0, 0, 0);
        switch (field) {
        case 0: h.ai_addrlen = 4; break;
        case 1: h.ai_canonname = (PWSTR)gx_w("x"); break;
        case 2: h.ai_addr = (struct sockaddr *)dummy; break;
        case 3: h.ai_next = &h; break;
        case 4: h.ai_blob = dummy; break;
        case 5: h.ai_bloblen = 4; break;
        case 6: h.ai_provider = (LPGUID)dummy; break;
        }
        gx_res r = gx_call(hnames[i], NULL, ns ? NSDNS : NSALL, &h);
        if (expect_ok) {
            if (i == 3) { CHECKF(r.ret == WSAHOST_NOT_FOUND, "field %d '%s' ret=%d", field, hnames[i], r.ret); }
            else CHECKF(r.ret == 0 && r.wsa == 0, "field %d '%s' ret=%d wsa=%d", field, hnames[i], r.ret, r.wsa);
        } else {
            CHECKF(r.ret == WSANO_RECOVERY && r.wsa == WSANO_RECOVERY, "field %d '%s' ns=%d ret=%d wsa=%d", field, hnames[i], ns, r.ret, r.wsa);
            CHECK(r.res == NULL);
        }
        gx_release(&r);
    }
}
TEST(xhint_nonzero_addrlen_refused)    { GX_BEGIN(); dirty_row(0, 0); GX_END(); }
TEST(xhint_nonnull_canonname_refused)  { GX_BEGIN(); dirty_row(1, 0); GX_END(); }
TEST(xhint_nonnull_addr_refused)       { GX_BEGIN(); dirty_row(2, 0); GX_END(); }
TEST(xhint_nonnull_next_refused)       { GX_BEGIN(); dirty_row(3, 0); GX_END(); }
TEST(xhint_blob_ignored)               { GX_BEGIN(); dirty_row(4, 1); GX_END(); }
TEST(xhint_bloblen_ignored)            { GX_BEGIN(); dirty_row(5, 1); GX_END(); }
TEST(xhint_provider_ignored)           { GX_BEGIN(); dirty_row(6, 1); GX_END(); }

/* ---- pass-through of socktype and protocol ------------------------------------------------------- */
TEST(xhint_socktype_echoed_on_every_entry)
{
    int st;
    GX_BEGIN();
    for (st = 0; st <= 6; st++) {
        GXEX h = gx_hint(0, 0, st, 0);
        gx_res a = gx_call("localhost", NULL, NSDNS, &h), b = gx_call("127.0.0.1", "80", NSDNS, &h);
        GXEX *e;
        GX_EQ(a.ret, 0); GX_EQ(b.ret, 0);
        for (e = a.res == &gx_sentinel_ex ? NULL : a.res; e; e = e->ai_next) GX_EQ(e->ai_socktype, st);
        for (e = b.res == &gx_sentinel_ex ? NULL : b.res; e; e = e->ai_next) { GX_EQ(e->ai_socktype, st); GX_EQ(gx_port(e->ai_addr), 80); }
        GX_EQ(gx_count(a.res), 2);
        gx_release(&a); gx_release(&b);
    }
    GX_END();
}
TEST(xhint_protocol_echoed_on_every_entry)
{
    static const int prot[] = {0, 1, 6, 17, 58, 255, 300};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(prot); i++) {
        GXEX h = gx_hint(0, 0, 0, prot[i]);
        gx_res a = gx_call("localhost", NULL, NSDNS, &h), b = gx_call("127.0.0.1", "80", NSDNS, &h);
        GXEX *e;
        GX_EQ(a.ret, 0); GX_EQ(b.ret, 0);
        for (e = a.res == &gx_sentinel_ex ? NULL : a.res; e; e = e->ai_next) GX_EQ(e->ai_protocol, prot[i]);
        for (e = b.res == &gx_sentinel_ex ? NULL : b.res; e; e = e->ai_next) GX_EQ(e->ai_protocol, prot[i]);
        gx_release(&a); gx_release(&b);
    }
    GX_END();
}
TEST(xhint_hint_not_modified)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_CANONNAME, AF_INET, SOCK_STREAM, IPPROTO_TCP), copy = h;
    gx_res r = gx_call("localhost", "80", NSDNS, &h);
    GX_EQ(r.ret, 0);
    CHECK(!memcmp(&h, &copy, sizeof h));
    gx_release(&r);
    GX_END();
}
TEST(xhint_entry_flags_do_not_echo_request_flags)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_PASSIVE | AI_NUMERICSERV | AI_ADDRCONFIG, 0, 0, 0);
    gx_res r = gx_call("localhost", "80", NSDNS, &h);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) { GXEX *e; for (e = r.res; e; e = e->ai_next) GX_EQ(e->ai_flags, 0); }
    gx_release(&r);
    GX_END();
}

/* ---- single flag bits on a loopback name ---------------------------------------------------------- */
/* AI_CANONNAME (0x2) and AI_FQDN (0x20000) fill the canonical name of the first entry only; AI_NUMERICHOST
 * (0x4) makes a non-literal fail with host-not-found; the other documented and undocumented bits below bit
 * 30 leave the answer unchanged. Run for a version-0 hint and for a hint that says version 2 (no extended
 * flag), which must behave identically. */
static void flag_table(int version)
{
    int bit;
    for (bit = 0; bit < 30; bit++) {
        GXEX h = gx_hint(1 << bit, 0, 0, 0), *e;
        gx_res r;
        h.ai_version = version;
        r = gx_call("localhost", NULL, NSDNS, &h);
        if (bit == 2) {
            CHECKF(r.ret == WSAHOST_NOT_FOUND && r.res == NULL, "NUMERICHOST bit ret=%d", r.ret);
        } else {
            CHECKF(r.ret == 0 && gx_count(r.res) == 2 && !strcmp(gx_fams(r.res), "23,2"), "bit %d ret=%d fams %s", bit, r.ret, gx_fams(r.res == &gx_sentinel_ex ? NULL : r.res));
            if (r.ret == 0) {
                if (bit == 1 || bit == 17) {
                    CHECKF(r.res->ai_canonname != NULL, "bit %d wants canonical name", bit);
                    CHECK(r.res->ai_next->ai_canonname == NULL);
                } else {
                    for (e = r.res; e; e = e->ai_next) CHECKF(e->ai_canonname == NULL, "bit %d must not set canonical name", bit);
                }
            }
        }
        gx_release(&r);
    }
}
TEST(xhint_flag_bits_one_at_a_time)          { GX_BEGIN(); flag_table(0); GX_END(); }
TEST(xhint_flag_bits_with_declared_version2) { GX_BEGIN(); flag_table(2); GX_END(); }

TEST(xhint_flag_bits_on_literal)
{
    int bit;
    GX_BEGIN();
    for (bit = 0; bit < 30; bit++) {
        GXEX h = gx_hint(1 << bit, 0, 0, 0);
        gx_res r = gx_call("127.0.0.1", NULL, NSDNS, &h);
        CHECKF(r.ret == 0 && gx_count(r.res) == 1 && GX_IS_V4(r.res, "127.0.0.1"), "bit %d ret=%d", bit, r.ret);
        if (r.ret == 0) {
            /* AI_V4MAPPED (bit 11) is the one flag after which the literal is not marked numeric */
            GX_EQ(r.res->ai_flags & AI_NUMERICHOST, bit == 11 ? 0 : AI_NUMERICHOST);
            /* for a literal, CANONNAME and FQDN return the literal text itself */
            if (bit == 1 || bit == 17) { CHECK(r.res->ai_canonname != NULL); if (r.res->ai_canonname) EXPECT_WSTR(r.res->ai_canonname, gx_w("127.0.0.1")); }
            else CHECK(r.res->ai_canonname == NULL);
        }
        gx_release(&r);
    }
    GX_END();
}

/* ---- canonical names ------------------------------------------------------------------------------ */
static const struct { const char *name; int fam; } canon_lits[] = {{"127.0.0.1", 2}, {"::1", 23}, {"1.2.3.4", 2}};
TEST(xhint_canon_of_literal_is_literal_text)
{
    unsigned i; int fl;
    static const int flags[] = {AI_CANONNAME, AI_FQDN, AI_CANONNAME | AI_FQDN};
    GX_BEGIN();
    for (i = 0; i < NARR(canon_lits); i++) for (fl = 0; fl < 3; fl++) {
        GXEX h = gx_hint(flags[fl], 0, 0, 0);
        gx_res r = gx_call(canon_lits[i].name, NULL, NSDNS, &h);
        CHECKF(r.ret == 0, "%s fl=%x ret=%d", canon_lits[i].name, flags[fl], r.ret);
        if (r.ret == 0 && r.res->ai_canonname) EXPECT_WSTR(r.res->ai_canonname, gx_w(canon_lits[i].name));
        else CHECK(0);
        gx_release(&r);
    }
    GX_END();
}
static int host_name_matches(const WCHAR *canon)
{
    WCHAR a[300], b[300];
    DWORD la = 300, lb = 300;
    if (!canon) return 0;
    if (!GetComputerNameExW(ComputerNameDnsHostname, a, &la)) a[0] = 0;
    if (!GetComputerNameExW(ComputerNameDnsFullyQualified, b, &lb)) b[0] = 0;
    return !lstrcmpiW(canon, a) || !lstrcmpiW(canon, b);
}
TEST(xhint_canon_of_localhost_is_machine_name)
{
    static const int flags[] = {AI_CANONNAME, AI_FQDN, AI_CANONNAME | AI_FQDN};
    int fl;
    GX_BEGIN();
    for (fl = 0; fl < 3; fl++) {
        GXEX h = gx_hint(flags[fl], 0, 0, 0);
        gx_res r = gx_call("localhost", NULL, NSDNS, &h);
        GX_EQ(r.ret, 0);
        if (r.ret == 0) {
            /* relation, not a literal: the name is the machine's own DNS host name or FQDN */
            CHECKF(host_name_matches(r.res->ai_canonname), "flags %x canonical name '%s'", flags[fl], gx_s(r.res->ai_canonname));
            CHECK(r.res->ai_next->ai_canonname == NULL);
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xhint_return_preferred_names_does_not_set_canon)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_RETURN_PREFERRED_NAMES, 0, 0, 0);
    gx_res a = gx_call("localhost", NULL, NSDNS, &h), b = gx_call("127.0.0.1", NULL, NSDNS, &h);
    GX_EQ(a.ret, 0); GX_EQ(b.ret, 0);
    if (a.ret == 0) CHECK(a.res->ai_canonname == NULL);
    if (b.ret == 0) CHECK(b.res->ai_canonname == NULL);
    gx_release(&a); gx_release(&b);
    GX_END();
}
TEST(xhint_canon_with_family_filter_still_first_entry)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_CANONNAME, AF_INET, 0, 0);
    gx_res r = gx_call("localhost", NULL, NSDNS, &h);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) { GX_EQ(gx_count(r.res), 1); CHECK(host_name_matches(r.res->ai_canonname)); }
    gx_release(&r);
    GX_END();
}
/* The ANSI front end: AI_CANONNAME gives the same name for localhost; AI_FQDN alone yields no canonical name
 * for a host name (but does for a literal), unlike the wide front end. */
TEST(xhint_ansi_canonname_rules)
{
    GX_BEGIN();
    if (!GXA() || !U(FreeAddrInfoEx)) { t_skip("no GetAddrInfoExA"); return; }
    {
        static const struct { const char *name; int flags; int want; } rows[] = {
            {"localhost", AI_CANONNAME, 1}, {"localhost", AI_CANONNAME | AI_FQDN, 1}, {"localhost", AI_FQDN, 0},
            {"localhost", AI_RETURN_PREFERRED_NAMES, 0}, {"localhost", 0, 0},
            {"127.0.0.1", AI_CANONNAME, 2}, {"127.0.0.1", AI_FQDN, 2}, {"127.0.0.1", AI_CANONNAME | AI_FQDN, 2},
            {"127.0.0.1", 0, 0}, {"127.0.0.1", AI_RETURN_PREFERRED_NAMES, 0},
            {"::1", AI_CANONNAME, 3}, {"::1", AI_FQDN, 3}, {"::1", 0, 0},
        };
        unsigned i;
        for (i = 0; i < NARR(rows); i++) {
            GXEXA h, *res = NULL;
            memset(&h, 0, sizeof h);
            h.ai_flags = rows[i].flags;
            SETWSERR(0x7777);
            int r = GXA()(rows[i].name, NULL, NSDNS, NULL, &h, (void **)&res, NULL, NULL, NULL, NULL);
            CHECKF(r == 0 && res, "%s fl=%x ret=%d", rows[i].name, rows[i].flags, r);
            if (r == 0 && res) {
                if (rows[i].want == 0) CHECK(res->ai_canonname == NULL);
                else if (rows[i].want == 1) { CHECK(res->ai_canonname != NULL); if (res->ai_canonname) { WCHAR w[300]; MultiByteToWideChar(CP_ACP, 0, res->ai_canonname, -1, w, 300); CHECK(host_name_matches(w)); } }
                else { CHECK(res->ai_canonname != NULL); if (res->ai_canonname) EXPECT_STR(res->ai_canonname, rows[i].name); }
                if (res->ai_next) CHECK(res->ai_next->ai_canonname == NULL);
            }
            if (res) U(FreeAddrInfoEx)((PADDRINFOEXA)res);
        }
    }
    GX_END();
}

/* ---- AI_PASSIVE and absent names ----------------------------------------------------------------- */
TEST(xhint_passive_null_name_gives_wildcards_v6_first)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_PASSIVE, 0, 0, 0);
    gx_res r = gx_call(NULL, "80", NSDNS, &h);
    GX_EQ(r.ret, 0);
    if (r.ret == 0 && gx_count(r.res) == 2) {
        CHECKF(!strcmp(gx_fams(r.res), "23,2"), "order %s", gx_fams(r.res));
        CHECK(!strcmp(gx_addr(r.res->ai_addr, r.res->ai_addrlen), "v6:0:0:0:0:0:0:0:0"));
        CHECK(GX_IS_V4(r.res->ai_next, "0.0.0.0"));
        GX_EQ(gx_port(r.res->ai_addr), 80);
        GX_EQ(gx_port(r.res->ai_next->ai_addr), 80);
    } else CHECKF(0, "count %d", gx_count(r.res));
    gx_release(&r);
    GX_END();
}
TEST(xhint_null_name_without_passive_gives_loopback_v6_first)
{
    GX_BEGIN();
    gx_res r = gx_call(NULL, "80", NSDNS, NULL);
    GX_EQ(r.ret, 0);
    if (r.ret == 0 && gx_count(r.res) == 2) {
        CHECKF(!strcmp(gx_fams(r.res), "23,2"), "order %s", gx_fams(r.res));
        CHECK(GX_IS_V6LOOP(r.res));
        CHECK(GX_IS_V4(r.res->ai_next, "127.0.0.1"));
        GX_EQ(gx_port(r.res->ai_addr), 80);
    } else CHECKF(0, "count %d", gx_count(r.res));
    gx_release(&r);
    GX_END();
}
TEST(xhint_passive_null_name_null_service_host_not_found)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_PASSIVE, 0, 0, 0);
    gx_res r = gx_call(NULL, NULL, NSDNS, &h);
    GX_EQ(r.ret, WSAHOST_NOT_FOUND); CHECK(r.res == NULL);
    gx_release(&r);
    GX_END();
}
TEST(xhint_passive_with_name_is_ignored)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_PASSIVE, 0, 0, 0);
    gx_res r = gx_call("127.0.0.1", "80", NSDNS, &h);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) { CHECK(GX_IS_V4(r.res, "127.0.0.1")); GX_EQ(gx_count(r.res), 1); }
    gx_release(&r);
    GX_END();
}
