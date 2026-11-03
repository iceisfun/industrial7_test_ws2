/* getprotobyname / getprotobynumber: the protocol database record and its result block.
 * Measures: per protocol the canonical lower-case name, the single upper-case alias, the number; that a
 * lookup by alias returns the canonical record; the error numbers (NULL name WSAEINVAL, unknown name or number
 * WSANO_DATA, WSANOTINITIALISED before startup); numbers outside the 8-bit protocol range and the strict
 * whole-string name match; the layout of the result block and its per-thread reuse. */
#include "lns.h"

#define ROW(id, nm, al, num) \
TEST(protorow_##id##_by_name) { \
    struct protoent *p; \
    LNS_NEED(getprotobyname); \
    p = U(getprotobyname)(nm); \
    CHECK(p != NULL); \
    if (p) { \
        CHECK(p->p_name && !strcmp(p->p_name, nm)); \
        EXPECT_EQ(p->p_proto, num); \
        EXPECT_EQ(lns_list_len(p->p_aliases), 1); \
        CHECK(p->p_aliases && p->p_aliases[0] && !strcmp(p->p_aliases[0], al)); \
        CHECK(p->p_aliases && p->p_aliases[1] == NULL); \
    } \
    LNS_DONE(); \
} \
TEST(protorow_##id##_by_alias_gives_canonical_record) { \
    struct protoent *p; \
    LNS_NEED(getprotobyname); \
    p = U(getprotobyname)(al); \
    CHECK(p != NULL); \
    if (p) { CHECK(p->p_name && !strcmp(p->p_name, nm)); EXPECT_EQ(p->p_proto, num); } \
    LNS_DONE(); \
} \
TEST(protorow_##id##_by_number) { \
    struct protoent *p; \
    LNS_NEED(getprotobynumber); \
    p = U(getprotobynumber)(num); \
    CHECK(p != NULL); \
    if (p) { \
        CHECK(p->p_name && !strcmp(p->p_name, nm)); \
        EXPECT_EQ(p->p_proto, num); \
        CHECK(p->p_aliases && p->p_aliases[0] && !strcmp(p->p_aliases[0], al)); \
    } \
    LNS_DONE(); \
}
ROW(ip, "ip", "IP", 0)
ROW(icmp, "icmp", "ICMP", 1)
ROW(ggp, "ggp", "GGP", 3)
ROW(tcp, "tcp", "TCP", 6)
ROW(egp, "egp", "EGP", 8)
ROW(pup, "pup", "PUP", 12)
ROW(udp, "udp", "UDP", 17)
ROW(hmp, "hmp", "HMP", 20)
ROW(xns_idp, "xns-idp", "XNS-IDP", 22)
ROW(rdp, "rdp", "RDP", 27)
ROW(ipv6, "ipv6", "IPv6", 41)
ROW(ipv6_route, "ipv6-route", "IPv6-Route", 43)
ROW(ipv6_frag, "ipv6-frag", "IPv6-Frag", 44)
ROW(esp, "esp", "ESP", 50)
ROW(ah, "ah", "AH", 51)
ROW(ipv6_icmp, "ipv6-icmp", "IPv6-ICMP", 58)
ROW(ipv6_nonxt, "ipv6-nonxt", "IPv6-NoNxt", 59)
ROW(ipv6_opts, "ipv6-opts", "IPv6-Opts", 60)
ROW(rvd, "rvd", "RVD", 66)

/* ---- name matching ------------------------------------------------------------------------------------- */

#define SPELL(id, text, num) \
TEST(protoname_spelling_##id) { \
    struct protoent *p; \
    LNS_NEED(getprotobyname); \
    p = U(getprotobyname)(text); \
    CHECKF(p != NULL, "%s", text); \
    if (p) EXPECT_EQ(p->p_proto, num); \
    LNS_DONE(); \
}
SPELL(tcp_mixed1, "Tcp", 6)
SPELL(tcp_mixed2, "tCP", 6)
SPELL(tcp_mixed3, "tcP", 6)
SPELL(udp_mixed, "UdP", 17)
SPELL(icmp_mixed, "IcMp", 1)
SPELL(ipv6_lower, "ipv6", 41)
SPELL(ipv6_upper, "IPV6", 41)
SPELL(ipv6_icmp_upper, "IPV6-ICMP", 58)
SPELL(ipv6_nonxt_lower, "ipv6-nonxt", 59)
SPELL(xns_idp_mixed, "Xns-Idp", 22)

#define NOTAPROTO(id, text) \
TEST(protoname_not_matched_##id) { \
    LNS_NEED(getprotobyname); \
    LNS_SETERR(0); \
    CHECK(U(getprotobyname)(text) == NULL); \
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA); \
    LNS_DONE(); \
}
NOTAPROTO(empty, "")
NOTAPROTO(trailing_space, "tcp ")
NOTAPROTO(leading_space, " tcp")
NOTAPROTO(prefix, "tc")
NOTAPROTO(extended, "tcpp")
NOTAPROTO(digits, "6")
NOTAPROTO(igmp, "igmp")
NOTAPROTO(gre, "gre")
NOTAPROTO(ospf, "ospf")
NOTAPROTO(sctp, "sctp")
NOTAPROTO(unknown, "no-such-protocol")
NOTAPROTO(ipv6_prefix, "ipv")

TEST(protoname_very_long_is_no_data)
{
    char big[2000];
    LNS_NEED(getprotobyname);
    memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
    LNS_SETERR(0);
    CHECK(U(getprotobyname)(big) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(protoname_null_is_invalid)
{
    LNS_NEED(getprotobyname);
    LNS_SETERR(0);
    CHECK(U(getprotobyname)(NULL) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_INVAL);
    LNS_DONE();
}

/* ---- numbers ------------------------------------------------------------------------------------------- */

#define NOTANUM(id, n) \
TEST(protonum_not_matched_##id) { \
    LNS_NEED(getprotobynumber); \
    LNS_SETERR(0); \
    CHECK(U(getprotobynumber)(n) == NULL); \
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA); \
    LNS_DONE(); \
}
NOTANUM(two, 2)
NOTANUM(four, 4)
NOTANUM(ninety_nine, 99)
NOTANUM(one_twenty_eight, 128)
NOTANUM(two_fifty_five, 255)
NOTANUM(two_fifty_six, 256)
NOTANUM(negative, -1)
NOTANUM(tcp_plus_256, 262)
NOTANUM(tcp_plus_65536, 65542)
NOTANUM(tcp_minus_256, -250)
NOTANUM(big_positive, 0x7fffffff)
NOTANUM(big_negative, (-0x7fffffff - 1))
NOTANUM(ip_plus_2_pow_32_wrap, 0x40000000)

TEST(protonum_every_defined_number_has_a_name)
{
    static const int defined[] = { 0, 1, 3, 6, 8, 12, 17, 20, 22, 27, 41, 43, 44, 50, 51, 58, 59, 60, 66 };
    int i, found = 0, n;
    LNS_NEED(getprotobynumber);
    for (n = 0; n < 256; n++) {
        struct protoent *p = U(getprotobynumber)(n);
        if (p) found++;
    }
    EXPECT_EQ(found, LNS_COUNT(defined));
    for (i = 0; i < LNS_COUNT(defined); i++) CHECK(U(getprotobynumber)(defined[i]) != NULL);
    LNS_DONE();
}
TEST(protonum_name_roundtrip)
{
    int n, bad = 0;
    LNS_NEED(getprotobynumber);
    REQUIRE(U(getprotobyname));
    for (n = 0; n < 256; n++) {
        struct protoent *p = U(getprotobynumber)(n);
        char nm[64];
        if (!p) continue;
        lstrcpynA(nm, p->p_name, sizeof nm);
        p = U(getprotobyname)(nm);
        if (!p || p->p_proto != n) bad++;
    }
    EXPECT_EQ(bad, 0);
    LNS_DONE();
}
TEST(protonum_canonical_names_are_lower_case_aliases_are_not)
{
    int n, lower = 0, upper_alias = 0;
    LNS_NEED(getprotobynumber);
    for (n = 0; n < 256; n++) {
        struct protoent *p = U(getprotobynumber)(n);
        const char *c;
        int ok;
        if (!p) continue;
        ok = 1;
        for (c = p->p_name; *c; c++) if (*c >= 'A' && *c <= 'Z') ok = 0;
        lower += ok;
        if (p->p_aliases[0] && !strcmp(p->p_aliases[0], p->p_name)) { /* an alias equal to the name would not be upper case */ }
        else upper_alias++;
    }
    EXPECT_EQ(lower, 19);
    EXPECT_EQ(upper_alias, 19);
    LNS_DONE();
}

/* ---- before WSAStartup --------------------------------------------------------------------------------- */

TEST(protoname_before_startup_not_initialised)
{
    REQUIRE(U(getprotobyname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getprotobyname)("tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(protoname_null_before_startup_not_initialised)
{
    REQUIRE(U(getprotobyname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getprotobyname)(NULL) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(protonum_before_startup_not_initialised)
{
    REQUIRE(U(getprotobynumber)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getprotobynumber)(6) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(protonum_unknown_before_startup_not_initialised)
{
    REQUIRE(U(getprotobynumber)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getprotobynumber)(99) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

/* ---- the result block ---------------------------------------------------------------------------------- */

TEST(protoblock_alias_array_directly_follows_struct)
{
    struct protoent *p;
    LNS_NEED(getprotobyname);
    p = U(getprotobyname)("tcp");
    CHECK(p != NULL);
    if (p) CHECK((char *)p->p_aliases == (char *)(p + 1));
    LNS_DONE();
}
TEST(protoblock_strings_live_in_the_block)
{
    struct protoent *p;
    LNS_NEED(getprotobyname);
    p = U(getprotobyname)("udp");
    CHECK(p != NULL);
    if (p) {
        CHECK(lns_inside(p, 1024, p->p_name, strlen(p->p_name) + 1));
        CHECK(lns_inside(p, 1024, p->p_aliases[0], strlen(p->p_aliases[0]) + 1));
        CHECK((char *)p->p_name != (char *)p->p_aliases[0]);
    }
    LNS_DONE();
}
TEST(protoblock_name_and_number_lookups_share_a_block)
{
    struct protoent *a, *b;
    LNS_NEED(getprotobyname);
    REQUIRE(U(getprotobynumber));
    a = U(getprotobyname)("tcp");
    b = U(getprotobynumber)(17);
    CHECK(a != NULL && b != NULL);
    CHECK(a == b);
    LNS_DONE();
}
TEST(protoblock_second_lookup_overwrites_first)
{
    struct protoent *a, *b;
    LNS_NEED(getprotobyname);
    a = U(getprotobyname)("tcp");
    CHECK(a != NULL && a->p_proto == 6);
    b = U(getprotobyname)("icmp");
    CHECK(b == a);
    if (a) { CHECK(!strcmp(a->p_name, "icmp")); EXPECT_EQ(a->p_proto, 1); CHECK(!strcmp(a->p_aliases[0], "ICMP")); }
    LNS_DONE();
}
/* An invalid-argument failure returns before the database is touched: the previous record survives. */
TEST(protoblock_invalid_argument_keeps_previous_result)
{
    struct protoent *a;
    LNS_NEED(getprotobyname);
    a = U(getprotobyname)("udp");
    CHECK(a != NULL);
    CHECK(U(getprotobyname)(NULL) == NULL);
    if (a) { CHECK(!strcmp(a->p_name, "udp")); EXPECT_EQ(a->p_proto, 17); }
    LNS_DONE();
}
/* A lookup that scans the whole database and finds nothing leaves the block holding the record it read last. */
TEST(protoblock_not_found_scan_leaves_last_record)
{
    struct protoent *a, *b;
    LNS_NEED(getprotobyname);
    REQUIRE(U(getprotobynumber));
    a = U(getprotobyname)("udp");
    CHECK(a != NULL);
    b = U(getprotobynumber)(99);
    CHECK(b == NULL);
    if (a) {
        EXPECT_EQ(a->p_proto, 66);
        CHECK(!strcmp(a->p_name, "rvd"));
    }
    LNS_DONE();
}

TEST(protoblock_repeated_lookups_reuse_one_block)
{
    struct protoent *a, *b; int i;
    LNS_NEED(getprotobynumber);
    a = U(getprotobynumber)(6);
    CHECK(a != NULL);
    for (i = 0; i < 60; i++) {
        b = U(getprotobynumber)(i % 2 ? 17 : 41);
        CHECK(b == a);
    }
    LNS_DONE();
}
TEST(protoblock_every_number_lookup_uses_the_same_block)
{
    struct protoent *first = NULL; int n, bad = 0;
    LNS_NEED(getprotobynumber);
    for (n = 0; n < 70; n++) {
        struct protoent *p = U(getprotobynumber)(n);
        if (!p) continue;
        if (!first) first = p; else if (p != first) bad++;
    }
    EXPECT_EQ(bad, 0);
    LNS_DONE();
}

struct pr_ctx { HANDLE ready, go; struct protoent *blk; volatile LONG ok; };
static DWORD WINAPI proto_thread(void *p)
{
    struct pr_ctx *c = p; WSADATA d; struct protoent *e;
    if (U(WSAStartup)(0x202, &d)) return 1;
    e = U(getprotobyname)("esp");
    c->blk = e;
    SetEvent(c->ready);
    WaitForSingleObject(c->go, 10000);
    c->ok = e && !strcmp(e->p_name, "esp") && e->p_proto == 50;
    U(WSACleanup)();
    return 0;
}
TEST(protoblock_each_thread_has_its_own_block)
{
    struct pr_ctx c; HANDLE th; struct protoent *mine;
    LNS_NEED(getprotobyname);
    memset(&c, 0, sizeof c);
    c.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    c.go = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, proto_thread, &c, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        EXPECT_EQ(WaitForSingleObject(c.ready, 10000), WAIT_OBJECT_0);
        mine = U(getprotobyname)("ah");
        CHECK(mine != NULL);
        CHECK(mine != c.blk);
        SetEvent(c.go);
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
        CloseHandle(th);
        EXPECT_EQ(c.ok, 1);
        if (mine) CHECK(!strcmp(mine->p_name, "ah"));
    }
    CloseHandle(c.ready); CloseHandle(c.go);
    LNS_DONE();
}

#define NT 3
#define NR 150
static volatile LONG g_bad;
static DWORD WINAPI proto_hammer(void *p)
{
    static const struct { const char *n; int num; } t[3] = { { "tcp", 6 }, { "udp", 17 }, { "icmp", 1 } };
    int me = (int)(INT_PTR)p, i; WSADATA d; struct protoent *first = NULL;
    if (U(WSAStartup)(0x202, &d)) { InterlockedIncrement(&g_bad); return 1; }
    for (i = 0; i < NR; i++) {
        struct protoent *e = (i & 1) ? U(getprotobyname)(t[me].n) : U(getprotobynumber)(t[me].num);
        if (!e || e->p_proto != t[me].num || strcmp(e->p_name, t[me].n)) InterlockedIncrement(&g_bad);
        else if (!first) first = e;
        else if (e != first) InterlockedIncrement(&g_bad);
    }
    U(WSACleanup)();
    return 0;
}
TEST(protoblock_concurrent_threads_do_not_interfere)
{
    HANDLE th[NT]; int i;
    LNS_NEED(getprotobyname);
    g_bad = 0;
    for (i = 0; i < NT; i++) th[i] = CreateThread(NULL, 0, proto_hammer, (void *)(INT_PTR)i, 0, NULL);
    for (i = 0; i < NT; i++) {
        if (!th[i]) { CHECK(0); continue; }
        EXPECT_EQ(WaitForSingleObject(th[i], 20000), WAIT_OBJECT_0);
        CloseHandle(th[i]);
    }
    EXPECT_EQ(g_bad, 0);
    LNS_DONE();
}

/* ---- consistency with the numbers used by socket() ------------------------------------------------------ */

TEST(protoconst_numbers_match_ipproto_constants)
{
    struct { const char *n; int v; } t[] = { { "ip", IPPROTO_IP }, { "icmp", IPPROTO_ICMP }, { "tcp", IPPROTO_TCP }, { "udp", IPPROTO_UDP },
                                             { "ipv6", IPPROTO_IPV6 }, { "esp", IPPROTO_ESP }, { "ah", IPPROTO_AH }, { "ipv6-icmp", IPPROTO_ICMPV6 },
                                             { "ipv6-route", IPPROTO_ROUTING }, { "ipv6-frag", IPPROTO_FRAGMENT }, { "ipv6-opts", IPPROTO_DSTOPTS },
                                             { "ipv6-nonxt", IPPROTO_NONE }, { "pup", IPPROTO_PUP }, { "egp", IPPROTO_EGP }, { "rdp", IPPROTO_RDP }, { "ggp", IPPROTO_GGP } };
    int i;
    LNS_NEED(getprotobyname);
    for (i = 0; i < LNS_COUNT(t); i++) {
        struct protoent *p = U(getprotobyname)(t[i].n);
        CHECKF(p && p->p_proto == t[i].v, "%s", t[i].n);
    }
    LNS_DONE();
}

/* ---- wsock32 ------------------------------------------------------------------------------------------ */

TEST(protoname_wsock32_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "getprotobyname"), b = t_proc_in("wsock32.dll", "getprotobyname");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
TEST(protonum_wsock32_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "getprotobynumber"), b = t_proc_in("wsock32.dll", "getprotobynumber");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
TEST(protoname_wsock32_form_is_callable)
{
    struct protoent *(WINAPI *p)(const char *);
    struct protoent *e;
    LNS_NEED(getprotobyname);
    p = (struct protoent *(WINAPI *)(const char *))t_proc_in("wsock32.dll", "getprotobyname");
    REQUIRE(p);
    e = p("udp");
    CHECK(e != NULL);
    if (e) EXPECT_EQ(e->p_proto, 17);
    LNS_DONE();
}
