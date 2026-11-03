/* Table-driven shape rules for GetAddrInfoExW on literal and loopback names: which spellings of an
 * address are accepted, which are refused with host-not-found, how socket type / protocol hints interact
 * with the services file, and what the family hint does to literal answers (v4-mapped forms, passive
 * wildcards). Every row was measured on Windows 10 with an elevated and a standard token; both selectors
 * (NS_ALL and NS_DNS) answer identically for all of them. */
#include "gx.h"

#define NSALL 0
#define NSDNS 12

/* ---- accepted literal spellings --------------------------------------------------------------------- */
static const struct { const char *name; int fam; const char *addr; unsigned long scope; } okl[] = {
    {"::ffff:127.0.0.1", 23, "v6:0:0:0:0:0:ffff:7f00:1", 0},
    {"::ffff:0:0", 23, "v6:0:0:0:0:0:ffff:0:0", 0},
    {"1::", 23, "v6:1:0:0:0:0:0:0:0", 0},
    {"::1%5", 23, "v6:0:0:0:0:0:0:0:1", 5},
    {"::1%0", 23, "v6:0:0:0:0:0:0:0:1", 0},
    {"fe80::1%4294967295", 23, "v6:fe80:0:0:0:0:0:0:1", 4294967295ul},
    {"1:2:3:4:5:6:7:8", 23, "v6:1:2:3:4:5:6:7:8", 0},
    {"[::1]:80", 23, "v6:0:0:0:0:0:0:0:1", 0},               /* a bracketed form may carry a port; the port is dropped */
    {"[fe80::1%1]", 23, "v6:fe80:0:0:0:0:0:0:1", 1},
    {"::127.0.0.1", 23, "v6:0:0:0:0:0:0:7f00:1", 0},
    {"FE80::1", 23, "v6:fe80:0:0:0:0:0:0:1", 0},
    {"0:0:0:0:0:0:127.0.0.1", 23, "v6:0:0:0:0:0:0:7f00:1", 0},
    {"1:2:3:4:5:6:1.2.3.4", 23, "v6:1:2:3:4:5:6:102:304", 0},
    {"255.255.255.255", 2, "255.255.255.255", 0},
};
TEST(xtab_accepted_literal_spellings)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(okl); i++) {
        gx_res r = gx_call(okl[i].name, NULL, ns ? NSDNS : NSALL, NULL);
        CHECKF(r.ret == 0 && r.wsa == 0 && r.res && gx_count(r.res) == 1, "'%s' ns=%d ret=%d", okl[i].name, ns, r.ret);
        if (r.ret == 0 && r.res && r.res != &gx_sentinel_ex) {
            CHECKF(r.res->ai_family == okl[i].fam, "'%s' family %d", okl[i].name, r.res->ai_family);
            CHECKF(!strcmp(gx_addr(r.res->ai_addr, r.res->ai_addrlen), okl[i].addr), "'%s' addr %s", okl[i].name, gx_addr(r.res->ai_addr, r.res->ai_addrlen));
            GX_EQ(r.res->ai_flags, AI_NUMERICHOST);
            GX_EQ(gx_port(r.res->ai_addr), 0);
            if (okl[i].fam == 23) CHECKF(((struct sockaddr_in6 *)r.res->ai_addr)->sin6_scope_id == okl[i].scope, "'%s' scope", okl[i].name);
        }
        gx_release(&r);
    }
    GX_END();
}

/* ---- refused literal spellings ----------------------------------------------------------------------- */
static const char *const badl[] = {
    "127.000.000.001", "127.0.0.01", "0177.0.0.1", "fe80::1%eth0", "fe80::1%99999999999", "1:2:3:4:5:6:7:8:9", "::g", ":::",
    "1::2::3", "[::1", "::1]", "127.0.0.1:80", " 127.0.0.1", "127.0.0.1 ", "::1 ", "[127.0.0.1]", "1.2.3.4%1", "::1%", "::1%%1",
    "1:2:3:4:5:6:7:1.2.3.4", "255.255.255.256", "0.0.0.0.0", "1.2.3.4.", ".1.2.3.4", "1..2.3", "localhost%1",
};
TEST(xtab_refused_literal_spellings)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(badl); i++) {
        gx_res r = gx_call(badl[i], NULL, ns ? NSDNS : NSALL, NULL);
        CHECKF(r.ret == WSAHOST_NOT_FOUND && r.wsa == WSAHOST_NOT_FOUND && r.res == NULL, "'%s' ns=%d ret=%d wsa=%d", badl[i], ns, r.ret, r.wsa);
        gx_release(&r);
    }
    GX_END();
}
TEST(xtab_overlong_names_host_not_found)
{
    static const int lens[] = {63, 64, 253, 254, 255, 256, 257, 300, 1000};
    static WCHAR big[1100];
    unsigned i; int dotted, j;
    GX_BEGIN();
    for (dotted = 0; dotted < 2; dotted++) for (i = 0; i < NARR(lens); i++) {
        GXEX *res = &gx_sentinel_ex; int r;
        for (j = 0; j < lens[i]; j++) big[j] = (dotted && j % 20 == 19) ? '.' : 'a';
        big[lens[i]] = 0;
        SETWSERR(0x7777);
        r = GXW()(big, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, NULL, NULL, NULL);
        CHECKF(r == WSAHOST_NOT_FOUND && WSERR() == WSAHOST_NOT_FOUND && res == NULL, "len %d dotted %d ret=%d", lens[i], dotted, r);
    }
    GX_END();
}

/* ---- socket type and protocol hints ------------------------------------------------------------------ */
/* ai_socktype is not validated: any value is echoed on every entry, and a numeric port is applied for all of them. */
TEST(xtab_socktype_values_outside_the_defined_range_are_echoed)
{
    static const int st[] = {-2, -1, 7, 8, 9, 10, 11, 100};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(st); i++) {
        GXEX h = gx_hint(0, 0, st[i], 0);
        gx_res a = gx_call("localhost", "80", NSDNS, &h), b = gx_call("localhost", NULL, NSDNS, &h);
        GXEX *e;
        CHECKF(a.ret == 0 && b.ret == 0, "st %d ret %d/%d", st[i], a.ret, b.ret);
        for (e = a.ret ? NULL : a.res; e; e = e->ai_next) { GX_EQ(e->ai_socktype, st[i]); GX_EQ(gx_port(e->ai_addr), 80); }
        for (e = b.ret ? NULL : b.res; e; e = e->ai_next) { GX_EQ(e->ai_socktype, st[i]); GX_EQ(gx_port(e->ai_addr), 0); }
        gx_release(&a); gx_release(&b);
    }
    GX_END();
}
/* A named service is looked up with the socket type: a stream-only service refuses SOCK_DGRAM whatever the
 * protocol says; the protocol is never matched against the socket type. */
static const struct { int st, pr; int err; } http_rows[] = {
    {SOCK_STREAM, IPPROTO_TCP, 0}, {SOCK_STREAM, IPPROTO_UDP, 0}, {SOCK_STREAM, IPPROTO_ICMP, 0},
    {SOCK_RAW, IPPROTO_TCP, 0},
    {SOCK_DGRAM, IPPROTO_TCP, WSATYPE_NOT_FOUND}, {SOCK_DGRAM, IPPROTO_UDP, WSATYPE_NOT_FOUND}, {SOCK_DGRAM, IPPROTO_ICMP, WSATYPE_NOT_FOUND},
};
TEST(xtab_named_service_socktype_and_protocol_matrix)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(http_rows); i++) {
        GXEX h = gx_hint(0, 0, http_rows[i].st, http_rows[i].pr);
        gx_res r = gx_call("localhost", "http", NSDNS, &h);
        if (http_rows[i].err) CHECKF(r.ret == http_rows[i].err && r.wsa == r.ret && r.res == NULL, "st %d pr %d ret=%d", http_rows[i].st, http_rows[i].pr, r.ret);
        else {
            GXEX *e;
            CHECKF(r.ret == 0 && gx_count(r.res) == 2, "st %d pr %d ret=%d", http_rows[i].st, http_rows[i].pr, r.ret);
            for (e = r.ret ? NULL : r.res; e; e = e->ai_next) {
                GX_EQ(e->ai_socktype, http_rows[i].st); GX_EQ(e->ai_protocol, http_rows[i].pr); GX_EQ(gx_port(e->ai_addr), 80);
            }
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xtab_negative_protocol_is_echoed)
{
    GX_BEGIN();
    GXEX h = gx_hint(0, 0, 0, -1);
    gx_res r = gx_call("localhost", "domain", NSDNS, &h);
    GXEX *e;
    GX_EQ(r.ret, 0);
    for (e = r.ret ? NULL : r.res; e; e = e->ai_next) { GX_EQ(e->ai_protocol, -1); GX_EQ(e->ai_socktype, 0); GX_EQ(gx_port(e->ai_addr), 53); }
    gx_release(&r);
    GX_END();
}

/* ---- family hint against literals ---------------------------------------------------------------------- */
typedef struct { const char *name; DWORD flags; int fam; int err; int n; const char *fams; const char *first; } fam_row;
static const fam_row famrows[] = {
    /* a literal of the other family is refused unless AI_V4MAPPED turns a v4 literal into a mapped v6 one */
    {"127.0.0.1", 0, AF_INET6, WSAHOST_NOT_FOUND, 0, NULL, NULL},
    {"::1", 0, AF_INET, WSAHOST_NOT_FOUND, 0, NULL, NULL},
    {"127.0.0.1", AI_V4MAPPED, AF_INET6, 0, 1, "23", "v6:0:0:0:0:0:ffff:7f00:1"},
    {"127.0.0.1", AI_V4MAPPED | AI_ALL, AF_INET6, 0, 1, "23", "v6:0:0:0:0:0:ffff:7f00:1"},
    {"127.0.0.1", AI_V4MAPPED, AF_INET, 0, 1, "2", "127.0.0.1"},
    {"::1", AI_V4MAPPED, AF_INET6, 0, 1, "23", "v6:0:0:0:0:0:0:0:1"},
    {"localhost", AI_V4MAPPED, AF_INET6, 0, 1, "23", "v6:0:0:0:0:0:0:0:1"},   /* v6 exists, so no mapped v4 is added */
    {"localhost", AI_ADDRCONFIG, 0, 0, 2, "23,2", "v6:0:0:0:0:0:0:0:1"},      /* loopback is exempt from the config filter */
    {"::1", AI_ADDRCONFIG, 0, 0, 1, "23", "v6:0:0:0:0:0:0:0:1"},
    {"127.0.0.1", AI_ADDRCONFIG, 0, 0, 1, "2", "127.0.0.1"},
};
TEST(xtab_family_hint_against_literals)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(famrows); i++) {
        GXEX h = gx_hint((int)famrows[i].flags, famrows[i].fam, 0, 0);
        gx_res r = gx_call(famrows[i].name, NULL, NSDNS, &h);
        if (famrows[i].err) CHECKF(r.ret == famrows[i].err && r.wsa == r.ret && r.res == NULL, "row %u '%s' ret=%d", i, famrows[i].name, r.ret);
        else {
            CHECKF(r.ret == 0 && gx_count(r.res) == famrows[i].n && !strcmp(gx_fams(r.res), famrows[i].fams), "row %u '%s' ret=%d fams %s", i, famrows[i].name, r.ret, r.ret ? "-" : gx_fams(r.res));
            if (r.ret == 0) CHECKF(!strcmp(gx_addr(r.res->ai_addr, r.res->ai_addrlen), famrows[i].first), "row %u first %s", i, gx_addr(r.res->ai_addr, r.res->ai_addrlen));
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xtab_v4mapped_answer_is_not_marked_numeric)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_V4MAPPED, AF_INET6, 0, 0);
    gx_res r = gx_call("127.0.0.1", NULL, NSDNS, &h);
    GX_EQ(r.ret, 0);
    if (r.ret == 0) GX_EQ(r.res->ai_flags, 0);
    gx_release(&r);
    GX_END();
}
TEST(xtab_passive_wildcard_per_family)
{
    GX_BEGIN();
    GXEX h4 = gx_hint(AI_PASSIVE, AF_INET, 0, 0), h6 = gx_hint(AI_PASSIVE, AF_INET6, 0, 0);
    gx_res a = gx_call(NULL, "80", NSDNS, &h4), b = gx_call(NULL, "80", NSDNS, &h6);
    GX_EQ(a.ret, 0); GX_EQ(b.ret, 0);
    if (a.ret == 0) { GX_EQ(gx_count(a.res), 1); CHECK(GX_IS_V4(a.res, "0.0.0.0")); GX_EQ(gx_port(a.res->ai_addr), 80); GX_EQ(a.res->ai_flags, 0); }
    if (b.ret == 0) { GX_EQ(gx_count(b.res), 1); CHECK(!strcmp(gx_addr(b.res->ai_addr, b.res->ai_addrlen), "v6:0:0:0:0:0:0:0:0")); GX_EQ(gx_port(b.res->ai_addr), 80); }
    gx_release(&a); gx_release(&b);
    GX_END();
}

/* ---- AI_NUMERICHOST / AI_NUMERICSERV with absent names ------------------------------------------------- */
TEST(xtab_numerichost_and_null_empty_names)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_NUMERICHOST, 0, 0, 0), hp = gx_hint(AI_NUMERICHOST | AI_PASSIVE, 0, 0, 0);
    gx_res a = gx_call("", "80", NSDNS, &h);
    gx_res b = gx_call(NULL, "80", NSDNS, &h);
    gx_res c = gx_call(NULL, "80", NSDNS, &hp);
    GX_EQ(a.ret, WSAHOST_NOT_FOUND); CHECK(a.res == NULL);               /* an empty name is not numeric */
    GX_EQ(b.ret, 0);                                                      /* no name at all is still the loopback pair */
    if (b.ret == 0) { CHECK(!strcmp(gx_fams(b.res), "23,2")); CHECK(GX_IS_V6LOOP(b.res)); GX_EQ(b.res->ai_flags, 0); }
    GX_EQ(c.ret, 0);
    if (c.ret == 0) { CHECK(!strcmp(gx_fams(c.res), "23,2")); CHECK(!strcmp(gx_addr(c.res->ai_addr, c.res->ai_addrlen), "v6:0:0:0:0:0:0:0:0")); CHECK(GX_IS_V4(c.res->ai_next, "0.0.0.0")); }
    gx_release(&a); gx_release(&b); gx_release(&c);
    GX_END();
}
TEST(xtab_numericserv_with_service_name_and_null_name)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_NUMERICSERV, 0, 0, 0);
    gx_res r = gx_call(NULL, "http", NSDNS, &h);
    GX_EQ(r.ret, WSAHOST_NOT_FOUND); CHECK(r.res == NULL);
    gx_release(&r);
    GX_END();
}

/* ---- canonical-name hint with absent / odd names -------------------------------------------------------- */
/* A canonical-name request without a name is invalid arguments, not "not found" - unless the service is absent
 * too, in which case the missing-everything rule wins first. */
TEST(xtab_canonname_with_null_name_is_einval)
{
    static const struct { int flags; const char *svc; DWORD ns; int err; } rows[] = {
        {AI_CANONNAME, "80", NSDNS, WSAEINVAL}, {AI_CANONNAME, "80", NSALL, WSAEINVAL}, {AI_FQDN, "80", NSDNS, WSAEINVAL},
        {AI_CANONNAME | AI_PASSIVE, "80", NSDNS, WSAEINVAL}, {AI_CANONNAME | AI_FQDN, "80", NSDNS, WSAEINVAL},
        {AI_CANONNAME, NULL, NSDNS, WSAHOST_NOT_FOUND},
    };
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(rows); i++) {
        GXEX h = gx_hint(rows[i].flags, 0, 0, 0);
        gx_res r = gx_call(NULL, rows[i].svc, rows[i].ns, &h);
        CHECKF(r.ret == rows[i].err && r.wsa == rows[i].err && r.res == NULL, "row %u ret=%d wsa=%d", i, r.ret, r.wsa);
        gx_release(&r);
    }
    {
        GXEX *res; gx_res r = gx_call(NULL, "80", NSDNS, NULL);        /* without a hint the same call is fine */
        res = r.res;
        GX_EQ(r.ret, 0);
        if (r.ret == 0) { CHECK(!strcmp(gx_fams(res), "23,2")); CHECK(res->ai_canonname == NULL); }
        gx_release(&r);
    }
    GX_END();
}
/* AI_RETURN_PREFERRED_NAMES combined with a name flag behaves like that name flag alone. */
TEST(xtab_preferred_names_adds_nothing)
{
    GX_BEGIN();
    GXEX hc = gx_hint(AI_RETURN_PREFERRED_NAMES | AI_CANONNAME, 0, 0, 0), hf = gx_hint(AI_RETURN_PREFERRED_NAMES | AI_FQDN, 0, 0, 0);
    gx_res a = gx_call("localhost", NULL, NSDNS, &hc), b = gx_call("localhost", NULL, NSDNS, &hf), c = gx_call("127.0.0.1", NULL, NSDNS, &hf);
    GX_EQ(a.ret, 0); GX_EQ(b.ret, 0); GX_EQ(c.ret, 0);
    if (a.ret == 0 && b.ret == 0) {
        CHECK(a.res->ai_canonname && b.res->ai_canonname && !lstrcmpiW(a.res->ai_canonname, b.res->ai_canonname));
        CHECK(!a.res->ai_next->ai_canonname && !b.res->ai_next->ai_canonname);
    }
    if (c.ret == 0) { CHECK(c.res->ai_canonname != NULL); if (c.res->ai_canonname) EXPECT_WSTR(c.res->ai_canonname, gx_w("127.0.0.1")); GX_EQ(c.res->ai_flags, AI_NUMERICHOST); }
    gx_release(&a); gx_release(&b); gx_release(&c);
    GX_END();
}
TEST(xtab_canonname_trailing_dot_and_case_variants)
{
    static const char *const nm[] = {"localhost.", "LOCALHOST", "LocalHost"};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(nm); i++) {
        WCHAR a[300], b[300]; DWORD la = 300, lb = 300;
        GXEX h = gx_hint(AI_CANONNAME, 0, 0, 0);
        gx_res r = gx_call(nm[i], "80", NSDNS, &h);
        GX_EQ(r.ret, 0);
        if (r.ret == 0) {
            if (!GetComputerNameExW(ComputerNameDnsHostname, a, &la)) a[0] = 0;
            if (!GetComputerNameExW(ComputerNameDnsFullyQualified, b, &lb)) b[0] = 0;
            CHECKF(r.res->ai_canonname && (!lstrcmpiW(r.res->ai_canonname, a) || !lstrcmpiW(r.res->ai_canonname, b)), "'%s' canon '%s'", nm[i], gx_s(r.res->ai_canonname));
        }
        gx_release(&r);
    }
    {
        GXEX h = gx_hint(AI_CANONNAME, 0, 0, 0);
        gx_res r = gx_call("127.0.0.1.", "80", NSDNS, &h);
        GX_EQ(r.ret, WSAHOST_NOT_FOUND);                                /* a literal with a trailing dot is not a literal */
        gx_release(&r);
    }
    GX_END();
}

/* ---- name spellings of the loopback host ---------------------------------------------------------------- */
/* Only "localhost" (any case, optional single trailing dot) and "loopback" are special; every other spelling
 * goes to the absent resolver and is not found. */
TEST(xtab_loopback_name_spellings)
{
    static const struct { const char *name; int ok; } rows[] = {
        {"localhost", 1}, {"lOcAlHoSt", 1}, {"LocalHost.", 1}, {"loopback", 1},
        {"localhost..", 0}, {".localhost", 0}, {"localhost.localdomain", 0}, {"localdomain", 0}, {"ip6-localhost", 0}, {"ip6-loopback", 0},
        {"localhost6", 0}, {"foo.localhost", 0}, {"local host", 0}, {"localhost ", 0}, {" localhost", 0}, {"localhost:80", 0},
        {"localhost/", 0}, {"localhost@", 0}, {"*", 0},
    };
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(rows); i++) {
        gx_res r = gx_call(rows[i].name, NULL, ns ? NSDNS : NSALL, NULL);
        if (rows[i].ok) {
            CHECKF(r.ret == 0 && !strcmp(gx_fams(r.res == &gx_sentinel_ex ? NULL : r.res), "23,2"), "'%s' ns=%d ret=%d", rows[i].name, ns, r.ret);
            if (r.ret == 0) { CHECK(GX_IS_V6LOOP(r.res)); CHECK(GX_IS_V4(r.res->ai_next, "127.0.0.1")); }
        } else CHECKF(r.ret == WSAHOST_NOT_FOUND && r.res == NULL, "'%s' ns=%d ret=%d", rows[i].name, ns, r.ret);
        gx_release(&r);
    }
    GX_END();
}
/* Numeric spellings that are not dotted quads or v6 text never reach the numeric parser. */
TEST(xtab_numeric_looking_names_not_found)
{
    static const char *const nm[] = {"0", "00", "1", "4294967295", "2130706433", "0x7f000001", "[::1]%1"};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(nm); i++) {
        gx_res r = gx_call(nm[i], NULL, NSDNS, NULL);
        CHECKF(r.ret == WSAHOST_NOT_FOUND && r.res == NULL, "'%s' ret=%d", nm[i], r.ret);
        gx_release(&r);
    }
    {
        gx_res a = gx_call("::ffff:7f00:1", NULL, NSDNS, NULL), b = gx_call("::FFFF:127.0.0.1", NULL, NSDNS, NULL), c = gx_call("[::1%1]", NULL, NSDNS, NULL), d = gx_call("::1%1", NULL, NSDNS, NULL);
        GX_EQ(a.ret, 0); GX_EQ(b.ret, 0); GX_EQ(c.ret, 0); GX_EQ(d.ret, 0);
        if (a.ret == 0 && b.ret == 0) CHECK(!memcmp(a.res->ai_addr, b.res->ai_addr, sizeof(struct sockaddr_in6)));
        if (c.ret == 0) GX_EQ(((struct sockaddr_in6 *)c.res->ai_addr)->sin6_scope_id, 1);
        if (d.ret == 0) GX_EQ(((struct sockaddr_in6 *)d.res->ai_addr)->sin6_scope_id, 1);
        gx_release(&a); gx_release(&b); gx_release(&c); gx_release(&d);
    }
    GX_END();
}

/* ---- services file: socket type interplay ---------------------------------------------------------------- */
/* kind: 'S' service listed for stream only, 'D' datagram only, 'B' both. For a service listed for both, the
 * hinted type is echoed unchanged (any value); for a one-protocol service an out-of-range hint is replaced by
 * the service's own type, SOCK_RAW is kept, and the other defined type is "type not found". */
static const struct { const char *svc; char kind; int port; } svctab[] = {
    {"http", 'S', 80}, {"ftp", 'S', 21}, {"telnet", 'S', 23}, {"HTTP", 'S', 80}, {"Http", 'S', 80},
    {"ntp", 'D', 123}, {"snmp", 'D', 161},
    {"domain", 'B', 53}, {"https", 'B', 443}, {"echo", 'B', 7}, {"kerberos", 'B', 88}, {"epmap", 'B', 135},
};
TEST(xtab_service_type_resolution_matrix)
{
    static const int sts[] = {-1, 0, 1, 2, 3, 4, 5, 6};
    unsigned i, k;
    GX_BEGIN();
    for (i = 0; i < NARR(svctab); i++) for (k = 0; k < NARR(sts); k++) {
        GXEX h = gx_hint(0, AF_INET, sts[k], 0);
        gx_res r = gx_call("127.0.0.1", svctab[i].svc, NSDNS, &h);
        int own = svctab[i].kind == 'S' ? SOCK_STREAM : SOCK_DGRAM, other = svctab[i].kind == 'S' ? SOCK_DGRAM : SOCK_STREAM;
        if (svctab[i].kind != 'B' && sts[k] == other) {
            CHECKF(r.ret == WSATYPE_NOT_FOUND && r.wsa == WSATYPE_NOT_FOUND && r.res == NULL, "%s st %d ret=%d", svctab[i].svc, sts[k], r.ret);
        } else {
            int want = svctab[i].kind == 'B' || sts[k] == own || sts[k] == SOCK_RAW ? sts[k] : (sts[k] == 0 ? own : own);
            CHECKF(r.ret == 0 && gx_count(r.res) == 1, "%s st %d ret=%d", svctab[i].svc, sts[k], r.ret);
            if (r.ret == 0) {
                CHECKF(r.res->ai_socktype == want, "%s st %d -> %d want %d", svctab[i].svc, sts[k], r.res->ai_socktype, want);
                GX_EQ(gx_port(r.res->ai_addr), svctab[i].port);
            }
        }
        gx_release(&r);
    }
    GX_END();
}
TEST(xtab_service_with_protocol_suffix_not_found)
{
    static const char *const sv[] = {"http/tcp", "80/tcp", "nosuchsvc"};
    unsigned i; int st;
    GX_BEGIN();
    for (i = 0; i < NARR(sv); i++) for (st = -1; st <= 6; st++) {
        GXEX h = gx_hint(0, AF_INET, st, 0);
        gx_res r = gx_call("127.0.0.1", sv[i], NSDNS, &h);
        CHECKF(r.ret == WSATYPE_NOT_FOUND && r.res == NULL, "%s st %d ret=%d", sv[i], st, r.ret);
        gx_release(&r);
    }
    GX_END();
}

/* ---- AI_V4MAPPED / AI_ALL on a name that has both families ---------------------------------------------- */
TEST(xtab_v4mapped_all_on_localhost)
{
    GX_BEGIN();
    GXEX h1 = gx_hint(AI_V4MAPPED | AI_ALL, AF_INET6, 0, 0), h2 = gx_hint(AI_ALL, AF_INET6, 0, 0), h3 = gx_hint(AI_ALL, 0, 0, 0), h4 = gx_hint(AI_V4MAPPED, 0, 0, 0);
    gx_res a = gx_call("localhost", NULL, NSDNS, &h1), b = gx_call("localhost", NULL, NSDNS, &h2), c = gx_call("localhost", NULL, NSDNS, &h3), d = gx_call("localhost", NULL, NSDNS, &h4);
    GX_EQ(a.ret, 0); GX_EQ(b.ret, 0); GX_EQ(c.ret, 0); GX_EQ(d.ret, 0);
    if (a.ret == 0) {                                      /* the real ::1 plus the mapped form of 127.0.0.1 */
        CHECKF(gx_count(a.res) == 2 && !strcmp(gx_fams(a.res), "23,23"), "fams %s", gx_fams(a.res));
        if (gx_count(a.res) == 2) {
            CHECK(GX_IS_V6LOOP(a.res));
            CHECK(!strcmp(gx_addr(a.res->ai_next->ai_addr, a.res->ai_next->ai_addrlen), "v6:0:0:0:0:0:ffff:7f00:1"));
        }
    }
    if (b.ret == 0) { GX_EQ(gx_count(b.res), 1); CHECK(GX_IS_V6LOOP(b.res)); }
    if (c.ret == 0) CHECK(!strcmp(gx_fams(c.res), "23,2"));
    if (d.ret == 0) CHECK(!strcmp(gx_fams(d.res), "23,2"));
    gx_release(&a); gx_release(&b); gx_release(&c); gx_release(&d);
    {
        GXEX h = gx_hint(AI_V4MAPPED, AF_INET6, 0, 0);
        gx_res r = gx_call("0.0.0.0", NULL, NSDNS, &h);            /* the unspecified v4 address is not mapped */
        GX_EQ(r.ret, WSAHOST_NOT_FOUND);
        gx_release(&r);
    }
    GX_END();
}
TEST(xtab_numericserv_selector_difference)
{
    GX_BEGIN();
    GXEX h = gx_hint(AI_NUMERICSERV, 0, 0, 0);
    gx_res a = gx_call("127.0.0.1", "http", NSDNS, &h), b = gx_call("127.0.0.1", "http", NSALL, &h), c = gx_call("127.0.0.1", "80", NSDNS, &h);
    GX_EQ(a.ret, WSAHOST_NOT_FOUND); CHECK(a.res == NULL);          /* NS_DNS: a non-numeric service under NUMERICSERV */
    GX_EQ(b.ret, 0);                                                /* NS_ALL: lenient, port 0 */
    if (b.ret == 0) GX_EQ(gx_port(b.res->ai_addr), 0);
    GX_EQ(c.ret, 0);
    if (c.ret == 0) GX_EQ(gx_port(c.res->ai_addr), 80);
    gx_release(&a); gx_release(&b); gx_release(&c);
    GX_END();
}
