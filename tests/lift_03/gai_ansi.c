/* getaddrinfo / freeaddrinfo: argument combinations, numeric-literal parsing (IPv4, bracketed and plain IPv6,
 * ports in the node string), AI_NUMERICHOST, service lookup failure and the shared hint matrix. Only names that
 * need no DNS server are used; the literals below are parsed, never contacted. */
#include "lift03.h"

static ADDRINFOA g_sentinel_a;

#define NEED_A() do { REQUIRE(U(getaddrinfo)); REQUIRE(U(freeaddrinfo)); if (l3_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define DONE_A() l3_down()

static void fr(ADDRINFOA *p) { if (p) U(freeaddrinfo)(p); }

/* Check that an entry is an IPv6 address with port 0 and the given textual form. */
static void check_v6(const ADDRINFOA *ai, const char *text)
{
    CHECK(ai != NULL);
    if (!ai) return;
    EXPECT_EQ(ai->ai_family, AF_INET6);
    CHECK(ai->ai_addrlen >= sizeof(struct sockaddr_in6));
    CHECK(ai->ai_addr != NULL);
    if (!ai->ai_addr || ai->ai_addrlen < sizeof(struct sockaddr_in6)) return;
    const SOCKADDR_IN6 *s6 = (const SOCKADDR_IN6 *)ai->ai_addr;
    EXPECT_EQ(s6->sin6_family, AF_INET6);
    EXPECT_EQ(s6->sin6_port, 0);
    if (UN(inet_ntop)) {
        char buf[64] = "";
        const char *r = UN(inet_ntop)(AF_INET6, &s6->sin6_addr, buf, sizeof buf);
        CHECK(r != NULL);
        EXPECT_STR(buf, text);
    }
}

TEST(gaia_null_node_null_service_fails)
{
    NEED_A();
    ADDRINFOA *res = &g_sentinel_a;
    SETWSERR(0x1234);
    EXPECT_EQ(U(getaddrinfo)(NULL, NULL, NULL, &res), WSAHOST_NOT_FOUND);
    EXPECT_EQ(WSERR(), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    DONE_A();
}

TEST(gaia_empty_node_succeeds_and_clears_error)
{
    NEED_A();
    ADDRINFOA *res = NULL;
    SETWSERR(0x1234);
    EXPECT_EQ(U(getaddrinfo)("", NULL, NULL, &res), 0);
    CHECK(res != NULL);
    EXPECT_EQ(WSERR(), 0);
    fr(res);
    DONE_A();
}

TEST(gaia_null_node_zero_service_equals_empty_service)
{
    NEED_A();
    ADDRINFOA *a = NULL, *b = NULL;
    EXPECT_EQ(U(getaddrinfo)(NULL, "0", NULL, &a), 0);
    EXPECT_EQ(U(getaddrinfo)(NULL, "", NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_a(a, b), 0);
    fr(a); fr(b);
    DONE_A();
}

TEST(gaia_empty_node_zero_service_equals_empty_service)
{
    NEED_A();
    ADDRINFOA *a = NULL, *b = NULL;
    SETWSERR(0x1234);
    EXPECT_EQ(U(getaddrinfo)("", "0", NULL, &a), 0);
    EXPECT_EQ(WSERR(), 0);
    EXPECT_EQ(U(getaddrinfo)("", "", NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_a(a, b), 0);
    fr(a); fr(b);
    DONE_A();
}

TEST(gaia_localhost_service_variants)
{
    NEED_A();
    const char *services[] = {NULL, "", "0", "80"};
    ADDRINFOA hint;
    memset(&hint, 0, sizeof hint);
    for (int withhint = 0; withhint < 2; withhint++)
        for (size_t i = 0; i < ARRSZ(services); i++) {
            ADDRINFOA *res = NULL;
            int r = U(getaddrinfo)("localhost", services[i], withhint ? &hint : NULL, &res);
            CHECKF(r == 0, "hint=%d service#%u -> %d", withhint, (unsigned)i, r);
            CHECK(res != NULL);
            fr(res);
        }
    DONE_A();
}

TEST(gaia_localhost_with_hint_leaves_error_zero)
{
    NEED_A();
    ADDRINFOA hint, *res = NULL;
    memset(&hint, 0, sizeof hint);
    SETWSERR(0x1234);
    EXPECT_EQ(U(getaddrinfo)("localhost", "80", &hint, &res), 0);
    EXPECT_EQ(WSERR(), 0);
    fr(res);
    DONE_A();
}

/* A host name that is not a numeric literal is refused when AI_NUMERICHOST is set; result is cleared. */
TEST(gaia_numerichost_rejects_name)
{
    NEED_A();
    ADDRINFOA hint, *res = &g_sentinel_a;
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICHOST;
    SETWSERR(0x1234);
    EXPECT_EQ(U(getaddrinfo)("localhost", "80", &hint, &res), WSAHOST_NOT_FOUND);
    EXPECT_EQ(WSERR(), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    DONE_A();
}

TEST(gaia_own_hostname_equals_empty_node)
{
    NEED_A();
    char name[256];
    DWORD size = sizeof name;
    name[0] = 0;
    if (!GetComputerNameExA(ComputerNamePhysicalDnsHostname, name, &size) || !name[0]) { t_skip("no host name"); DONE_A(); return; }
    ADDRINFOA *a = NULL, *b = NULL;
    EXPECT_EQ(U(getaddrinfo)(name, NULL, NULL, &a), 0);
    EXPECT_EQ(U(getaddrinfo)("", NULL, NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_a(a, b), 0);
    fr(a); fr(b);
    DONE_A();
}

TEST(gaia_own_hostname_with_empty_service_equals_empty_node)
{
    NEED_A();
    char name[256];
    DWORD size = sizeof name;
    name[0] = 0;
    if (!GetComputerNameExA(ComputerNamePhysicalDnsHostname, name, &size) || !name[0]) { t_skip("no host name"); DONE_A(); return; }
    ADDRINFOA *a = NULL, *b = NULL;
    EXPECT_EQ(U(getaddrinfo)(name, "", NULL, &a), 0);
    EXPECT_EQ(U(getaddrinfo)("", "", NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_a(a, b), 0);
    fr(a); fr(b);
    DONE_A();
}

TEST(gaia_ipv4_literal_converts)
{
    NEED_A();
    ADDRINFOA *res = NULL;
    EXPECT_EQ(U(getaddrinfo)("192.168.1.253", NULL, NULL, &res), 0);
    CHECK(res != NULL);
    if (res) {
        EXPECT_EQ(res->ai_family, AF_INET);
        CHECK(res->ai_addrlen >= sizeof(struct sockaddr_in));
        CHECK(res->ai_addr != NULL);
        if (res->ai_addr && res->ai_addrlen >= sizeof(struct sockaddr_in)) {
            const SOCKADDR_IN *s4 = (const SOCKADDR_IN *)res->ai_addr;
            EXPECT_EQ(s4->sin_family, AF_INET);
            EXPECT_EQ(s4->sin_port, 0);
            EXPECT_EQ(s4->sin_addr.s_addr, 0xfd01a8c0u); /* c0.a8.01.fd in memory order */
        }
    }
    fr(res);
    DONE_A();
}

/* A trailing ":port" is not accepted on an IPv4 literal. */
TEST(gaia_ipv4_literal_with_port_rejected)
{
    NEED_A();
    ADDRINFOA hint, *res = &g_sentinel_a;
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICHOST;
    EXPECT_EQ(U(getaddrinfo)("192.168.1.253:1024", NULL, &hint, &res), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    DONE_A();
}

TEST(gaia_ipv6_literal_plain)
{
    NEED_A();
    ADDRINFOA *res = NULL;
    EXPECT_EQ(U(getaddrinfo)("2a00:2039:dead:beef:cafe::6666", NULL, NULL, &res), 0);
    check_v6(res, "2a00:2039:dead:beef:cafe::6666");
    fr(res);
    DONE_A();
}

TEST(gaia_ipv6_literal_bracketed)
{
    NEED_A();
    ADDRINFOA *res = NULL;
    EXPECT_EQ(U(getaddrinfo)("[beef::cafe]", NULL, NULL, &res), 0);
    check_v6(res, "beef::cafe");
    fr(res);
    DONE_A();
}

TEST(gaia_ipv6_literal_bracketed_with_hint)
{
    NEED_A();
    ADDRINFOA hint, *res = NULL;
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = AF_INET6;
    EXPECT_EQ(U(getaddrinfo)("[beef::cafe]", NULL, &hint, &res), 0);
    check_v6(res, "beef::cafe");
    fr(res);
    DONE_A();
}

/* An IPv4-only hint cannot produce an IPv6 literal. */
TEST(gaia_ipv6_literal_with_inet_hint_rejected)
{
    NEED_A();
    ADDRINFOA hint, *res = &g_sentinel_a;
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = AF_INET;
    EXPECT_EQ(U(getaddrinfo)("[beef::cafe]", NULL, &hint, &res), WSAHOST_NOT_FOUND);
    DONE_A();
}

/* A port after the closing bracket is accepted and discarded: the returned port stays 0. */
TEST(gaia_ipv6_literal_bracketed_with_port)
{
    NEED_A();
    ADDRINFOA *res = NULL;
    EXPECT_EQ(U(getaddrinfo)("[beef::cafe]:10239", NULL, NULL, &res), 0);
    check_v6(res, "beef::cafe");
    fr(res);
    DONE_A();
}

TEST(gaia_ipv6_literal_unmatched_brackets_rejected)
{
    NEED_A();
    ADDRINFOA hint, *res = NULL;
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = AF_INET;
    EXPECT_EQ(U(getaddrinfo)("[beef::cafe", NULL, &hint, &res), WSAHOST_NOT_FOUND);
    EXPECT_EQ(U(getaddrinfo)("beef::cafe]", NULL, &hint, &res), WSAHOST_NOT_FOUND);
    hint.ai_family = AF_UNSPEC;
    int r1 = U(getaddrinfo)("[beef::cafe", NULL, &hint, &res);
    int r2 = U(getaddrinfo)("beef::cafe]", NULL, &hint, &res);
    if (r1 != WSAHOST_NOT_FOUND || r2 != WSAHOST_NOT_FOUND)
        t_note("unmatched bracket with AF_UNSPEC: unexpected result codes");
    DONE_A();
}

static void hint_rows_a(int family, DWORD err)
{
    for (size_t i = 0; i < ARRSZ(l3_hints); i++) {
        const struct l3_hint *h = &l3_hints[i];
        if ((family >= 0 && h->family != family) || h->error != err) continue;
        ADDRINFOA hint, *res = NULL, *p;
        memset(&hint, 0, sizeof hint);
        hint.ai_family = h->family;
        hint.ai_socktype = h->socktype;
        hint.ai_protocol = h->protocol;
        SETWSERR(0x1234);
        int r = U(getaddrinfo)("localhost", NULL, &hint, &res);
        CHECKF(r == (int)h->error, "row %u: ret %d want %lu", (unsigned)i, r, h->error);
        if (!r) {
            CHECK(res != NULL);
            for (p = res; p; p = p->ai_next) {
                if (h->family == AF_UNSPEC) CHECKF(p->ai_family == AF_INET || p->ai_family == AF_INET6, "row %u family %d", (unsigned)i, p->ai_family);
                else CHECKF(p->ai_family == h->family, "row %u family %d", (unsigned)i, p->ai_family);
                CHECKF(p->ai_socktype == h->socktype, "row %u socktype %d", (unsigned)i, p->ai_socktype);
                CHECKF(p->ai_protocol == h->protocol, "row %u protocol %d", (unsigned)i, p->ai_protocol);
            }
            fr(res);
        } else {
            CHECKF(WSERR() == (int)h->error, "row %u: wsa error %d", (unsigned)i, WSERR());
        }
    }
}

TEST(gaia_hint_matrix_unspec_family)  { NEED_A(); hint_rows_a(AF_UNSPEC, 0); DONE_A(); }
TEST(gaia_hint_matrix_inet_family)    { NEED_A(); hint_rows_a(AF_INET, 0); DONE_A(); }
TEST(gaia_hint_matrix_unknown_socktype) { NEED_A(); hint_rows_a(-1, WSAESOCKTNOSUPPORT); DONE_A(); }

/* A service name that is not in the services database is WSATYPE_NOT_FOUND. */
TEST(gaia_unknown_service_name)
{
    NEED_A();
    ADDRINFOA hint, *res = &g_sentinel_a;
    memset(&hint, 0, sizeof hint);
    EXPECT_EQ(U(getaddrinfo)(NULL, "nonexistentservice", &hint, &res), WSATYPE_NOT_FOUND);
    DONE_A();
}
