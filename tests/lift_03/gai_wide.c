/* GetAddrInfoW / FreeAddrInfoW: argument combinations on empty, NULL and loopback names, the "empty node means
 * local host" equivalences, the shared hint matrix and how the last-error state is left. Only names resolvable
 * without a DNS server are used. */
#include "lift03.h"

static const WCHAR kEmpty[] = {0};
static const WCHAR kZero[] = {'0', 0};
static const WCHAR kEighty[] = {'8', '0', 0};
static const WCHAR kLocalhost[] = {'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0};
static ADDRINFOW g_sentinel;

#define NEED_W() do { REQUIRE(U(GetAddrInfoW)); REQUIRE(U(FreeAddrInfoW)); if (l3_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define DONE_W() l3_down()

TEST(gaiw_null_node_null_service_fails)
{
    NEED_W();
    ADDRINFOW *res = &g_sentinel;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoW)(NULL, NULL, NULL, &res);
    EXPECT_EQ(r, WSAHOST_NOT_FOUND);
    EXPECT_EQ(WSERR(), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    DONE_W();
}

TEST(gaiw_empty_node_succeeds_and_clears_error)
{
    NEED_W();
    ADDRINFOW *res = NULL;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoW)(kEmpty, NULL, NULL, &res);
    EXPECT_EQ(r, 0);
    CHECK(res != NULL);
    EXPECT_EQ(WSERR(), 0);
    if (res) U(FreeAddrInfoW)(res);
    DONE_W();
}

TEST(gaiw_null_node_zero_service_equals_empty_service)
{
    NEED_W();
    ADDRINFOW *a = NULL, *b = NULL;
    EXPECT_EQ(U(GetAddrInfoW)(NULL, kZero, NULL, &a), 0);
    EXPECT_EQ(U(GetAddrInfoW)(NULL, kEmpty, NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_w(a, b), 0);
    if (a) U(FreeAddrInfoW)(a);
    if (b) U(FreeAddrInfoW)(b);
    DONE_W();
}

TEST(gaiw_empty_node_zero_service_equals_empty_service)
{
    NEED_W();
    ADDRINFOW *a = NULL, *b = NULL;
    SETWSERR(0x1234);
    EXPECT_EQ(U(GetAddrInfoW)(kEmpty, kZero, NULL, &a), 0);
    EXPECT_EQ(WSERR(), 0);
    EXPECT_EQ(U(GetAddrInfoW)(kEmpty, kEmpty, NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_w(a, b), 0);
    if (a) U(FreeAddrInfoW)(a);
    if (b) U(FreeAddrInfoW)(b);
    DONE_W();
}

/* localhost resolves with every service spelling, with and without a zeroed hint. */
TEST(gaiw_localhost_service_variants)
{
    NEED_W();
    const WCHAR *services[] = {NULL, kEmpty, kZero, kEighty};
    ADDRINFOW hint;
    memset(&hint, 0, sizeof hint);
    for (int withhint = 0; withhint < 2; withhint++)
        for (size_t i = 0; i < ARRSZ(services); i++) {
            ADDRINFOW *res = NULL;
            int r = U(GetAddrInfoW)(kLocalhost, services[i], withhint ? &hint : NULL, &res);
            CHECKF(r == 0, "hint=%d service#%u -> %d", withhint, (unsigned)i, r);
            CHECK(res != NULL);
            if (res) U(FreeAddrInfoW)(res);
        }
    DONE_W();
}

TEST(gaiw_localhost_with_hint_leaves_error_zero)
{
    NEED_W();
    ADDRINFOW hint, *res = NULL;
    memset(&hint, 0, sizeof hint);
    SetLastError(0x1234);
    SETWSERR(0x1234);
    EXPECT_EQ(U(GetAddrInfoW)(kLocalhost, kEighty, &hint, &res), 0);
    EXPECT_EQ(WSERR(), 0);
    if (res) U(FreeAddrInfoW)(res);
    DONE_W();
}

/* The computer's own DNS host name behaves like an empty node name. */
TEST(gaiw_own_hostname_equals_empty_node)
{
    NEED_W();
    WCHAR name[256];
    DWORD size = ARRSZ(name);
    name[0] = 0;
    if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, name, &size) || !name[0]) { t_skip("no host name"); DONE_W(); return; }
    ADDRINFOW *a = NULL, *b = NULL;
    EXPECT_EQ(U(GetAddrInfoW)(name, NULL, NULL, &a), 0);
    EXPECT_EQ(U(GetAddrInfoW)(kEmpty, NULL, NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_w(a, b), 0);
    if (a) U(FreeAddrInfoW)(a);
    if (b) U(FreeAddrInfoW)(b);
    DONE_W();
}

TEST(gaiw_own_hostname_with_empty_service_equals_empty_node)
{
    NEED_W();
    WCHAR name[256];
    DWORD size = ARRSZ(name);
    name[0] = 0;
    if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, name, &size) || !name[0]) { t_skip("no host name"); DONE_W(); return; }
    ADDRINFOW *a = NULL, *b = NULL;
    EXPECT_EQ(U(GetAddrInfoW)(name, kEmpty, NULL, &a), 0);
    EXPECT_EQ(U(GetAddrInfoW)(kEmpty, kEmpty, NULL, &b), 0);
    CHECK(a && b);
    EXPECT_EQ(l3_cmp_ai_w(a, b), 0);
    if (a) U(FreeAddrInfoW)(a);
    if (b) U(FreeAddrInfoW)(b);
    DONE_W();
}

/* Run the shared hint matrix for rows whose family is `family` (-1: all) and whose expected result is `err`. */
static void hint_rows(int family, DWORD err)
{
    for (size_t i = 0; i < ARRSZ(l3_hints); i++) {
        const struct l3_hint *h = &l3_hints[i];
        if ((family >= 0 && h->family != family) || h->error != err) continue;
        ADDRINFOW hint, *res = NULL, *p;
        memset(&hint, 0, sizeof hint);
        hint.ai_family = h->family;
        hint.ai_socktype = h->socktype;
        hint.ai_protocol = h->protocol;
        SetLastError(0x1234);
        int r = U(GetAddrInfoW)(kLocalhost, NULL, &hint, &res);
        CHECKF(r == (int)h->error, "row %u: ret %d want %lu", (unsigned)i, r, h->error);
        if (!r) {
            CHECK(res != NULL);
            for (p = res; p; p = p->ai_next) {
                if (h->family == AF_UNSPEC) CHECKF(p->ai_family == AF_INET || p->ai_family == AF_INET6, "row %u family %d", (unsigned)i, p->ai_family);
                else CHECKF(p->ai_family == h->family, "row %u family %d", (unsigned)i, p->ai_family);
                CHECKF(p->ai_socktype == h->socktype, "row %u socktype %d", (unsigned)i, p->ai_socktype);
                CHECKF(p->ai_protocol == h->protocol, "row %u protocol %d", (unsigned)i, p->ai_protocol);
            }
            if (res) U(FreeAddrInfoW)(res);
        } else {
            CHECKF(WSERR() == (int)h->error, "row %u: wsa error %d", (unsigned)i, WSERR());
        }
    }
}

TEST(gaiw_hint_matrix_unspec_family)  { NEED_W(); hint_rows(AF_UNSPEC, 0); DONE_W(); }
TEST(gaiw_hint_matrix_inet_family)    { NEED_W(); hint_rows(AF_INET, 0); DONE_W(); }
/* An unknown socket type is rejected up front with WSAESOCKTNOSUPPORT (return value and last error). */
TEST(gaiw_hint_matrix_unknown_socktype) { NEED_W(); hint_rows(-1, WSAESOCKTNOSUPPORT); DONE_W(); }
