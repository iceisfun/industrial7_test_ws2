/* gethostbyname / gethostbyaddr: result shape, name forms, error codes and the per-thread result block.
 * Measures: that "localhost", numeric dotted strings, the empty string and NULL resolve without any
 * network, which numeric spellings are rejected (WSAHOST_NOT_FOUND), the layout of the single block that
 * holds the hostent, its lists, the address bytes and the name, how gethostbyaddr treats its length and
 * type arguments (type is only compared with AF_INET6, length only for IPv6), the error numbers of the
 * failure paths and that every thread owns exactly one result block that each lookup overwrites. */
#include "lns.h"

static const unsigned char LO4[4] = { 127, 0, 0, 1 };
static const unsigned char LO6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

static int addr_is(struct hostent *h, int idx, const void *bytes, int n)
{
    return h && h->h_length == n && h->h_addr_list && h->h_addr_list[idx] && !memcmp(h->h_addr_list[idx], bytes, n);
}

/* ---- numeric names ------------------------------------------------------------------------------- */

/* A dotted-quad string is converted, not looked up: the "name" of the result is the string itself. */
#define NUMERIC_CASE(tag, text, b0, b1, b2, b3) \
TEST(hostbyname_numeric_##tag) { \
    static const unsigned char want[4] = { b0, b1, b2, b3 }; struct hostent *h; \
    LNS_NEED(gethostbyname); \
    h = U(gethostbyname)(text); \
    CHECK(h != NULL); \
    if (h) { \
        EXPECT_EQ(h->h_addrtype, AF_INET); EXPECT_EQ(h->h_length, 4); \
        CHECK(addr_is(h, 0, want, 4)); \
        EXPECT_EQ(lns_list_len(h->h_addr_list), 1); \
        EXPECT_EQ(lns_list_len(h->h_aliases), 0); \
        CHECK(h->h_name && !strcmp(h->h_name, text)); \
    } \
    LNS_DONE(); \
}
NUMERIC_CASE(loopback, "127.0.0.1", 127, 0, 0, 1)
NUMERIC_CASE(documentation_net, "1.2.3.4", 1, 2, 3, 4)
NUMERIC_CASE(all_ones, "255.255.255.255", 255, 255, 255, 255)
NUMERIC_CASE(all_zero, "0.0.0.0", 0, 0, 0, 0)
NUMERIC_CASE(class_a, "10.200.30.40", 10, 200, 30, 40)
NUMERIC_CASE(max_octets, "255.254.253.252", 255, 254, 253, 252)
NUMERIC_CASE(loopback_range, "127.255.255.254", 127, 255, 255, 254)

/* Spellings that inet_addr accepts but this lookup does not resolve: it falls through to the name path. */
#define BADNUM_CASE(tag, text) \
TEST(hostbyname_numeric_rejected_##tag) { \
    struct hostent *h; \
    LNS_NEED(gethostbyname); \
    LNS_SETERR(0); \
    h = U(gethostbyname)(text); \
    CHECKF(h == NULL, "unexpectedly resolved %s", text); \
    if (!h) EXPECT_EQ(LNS_ERR(), LNS_E_HOSTNF); \
    LNS_DONE(); \
}
BADNUM_CASE(two_parts, "127.1")
BADNUM_CASE(three_parts, "1.2.3")
BADNUM_CASE(hex_part, "0x7f.1")
BADNUM_CASE(single_integer, "2130706433")
BADNUM_CASE(octal_part, "0177.0.0.1")
BADNUM_CASE(octet_256, "256.1.1.1")
BADNUM_CASE(five_parts, "1.2.3.4.5")
BADNUM_CASE(ipv6_literal, "::1")
BADNUM_CASE(leading_space, " 127.0.0.1")
BADNUM_CASE(trailing_space, "127.0.0.1 ")
BADNUM_CASE(only_dot, ".")
BADNUM_CASE(embedded_space, "a b")
BADNUM_CASE(single_dash, "-")

/* ---- localhost and the machine name ------------------------------------------------------------------ */

static int own_addr_count(struct hostent *h) { return lns_list_len(h->h_addr_list); }

TEST(hostbyname_localhost_shape)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("localhost");
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(h->h_addrtype, AF_INET);
        EXPECT_EQ(h->h_length, 4);
        EXPECT_EQ(own_addr_count(h), 1);
        CHECK(addr_is(h, 0, LO4, 4));
        EXPECT_EQ(lns_list_len(h->h_aliases), 0);
        CHECK(h->h_name && h->h_name[0]);
    }
    LNS_DONE();
}

#define LH_CASE(tag, text) \
TEST(hostbyname_localhost_spelling_##tag) { \
    struct hostent *h; \
    LNS_NEED(gethostbyname); \
    h = U(gethostbyname)(text); \
    CHECKF(h != NULL, "%s", text); \
    if (h) CHECK(addr_is(h, 0, LO4, 4)); \
    LNS_DONE(); \
}
LH_CASE(upper, "LOCALHOST")
LH_CASE(mixed, "LocalHost")
LH_CASE(trailing_dot, "localhost.")
LH_CASE(upper_trailing_dot, "LOCALHOST.")

TEST(hostbyname_localhost_spellings_share_canonical_name)
{
    struct hostent *h; char a[260], b[260];
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("localhost"); CHECK(h != NULL);
    if (!h) { LNS_DONE(); return; }
    lstrcpynA(a, h->h_name, sizeof a);
    h = U(gethostbyname)("LOCALHOST"); CHECK(h != NULL);
    if (!h) { LNS_DONE(); return; }
    lstrcpynA(b, h->h_name, sizeof b);
    CHECK(!strcmp(a, b));
    LNS_DONE();
}

/* The canonical name reported for localhost is the machine's own name (observation, configurable by a hosts entry). */
TEST(hostbyname_localhost_canonical_name_vs_machine_name)
{
    struct hostent *h; char me[300];
    LNS_NEED(gethostbyname);
    REQUIRE(U(gethostname));
    CHECK(U(gethostname)(me, sizeof me) == 0);
    h = U(gethostbyname)("localhost");
    CHECK(h != NULL);
    if (h && h->h_name && _stricmp(h->h_name, me)) t_note("localhost canonical name is not the machine name");
    LNS_DONE();
}

TEST(hostbyname_localhost_with_domain_not_resolved)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    LNS_SETERR(0);
    h = U(gethostbyname)("localhost.localdomain");
    CHECK(h == NULL);
    if (!h) EXPECT_EQ(LNS_ERR(), LNS_E_HOSTNF);
    LNS_DONE();
}

TEST(hostbyname_ipv6_loopback_name_not_resolved)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    LNS_SETERR(0);
    h = U(gethostbyname)("ip6-localhost");
    CHECK(h == NULL);
    if (!h) EXPECT_EQ(LNS_ERR(), LNS_E_HOSTNF);
    LNS_DONE();
}

/* NULL and "" both mean "this machine": same machine name as gethostname, at least one IPv4 address. */
static void check_self(struct hostent *h)
{
    char me[300];
    CHECK(h != NULL);
    if (!h) return;
    EXPECT_EQ(h->h_addrtype, AF_INET);
    EXPECT_EQ(h->h_length, 4);
    CHECK(own_addr_count(h) >= 1);
    CHECK(h->h_name != NULL);
    if (U(gethostname)(me, sizeof me) == 0 && h->h_name) CHECK(!_stricmp(h->h_name, me));
}
TEST(hostbyname_null_name_means_this_machine)  { LNS_NEED(gethostbyname); REQUIRE(U(gethostname)); check_self(U(gethostbyname)(NULL)); LNS_DONE(); }
TEST(hostbyname_empty_name_means_this_machine) { LNS_NEED(gethostbyname); REQUIRE(U(gethostname)); check_self(U(gethostbyname)("")); LNS_DONE(); }
TEST(hostbyname_machine_name_means_this_machine)
{
    char me[300];
    LNS_NEED(gethostbyname);
    REQUIRE(U(gethostname));
    CHECK(U(gethostname)(me, sizeof me) == 0);
    check_self(U(gethostbyname)(me));
    LNS_DONE();
}
TEST(hostbyname_machine_name_case_insensitive)
{
    char me[300], up[300]; struct hostent *h; int i;
    LNS_NEED(gethostbyname);
    REQUIRE(U(gethostname));
    CHECK(U(gethostname)(me, sizeof me) == 0);
    for (i = 0; me[i]; i++) up[i] = (char)((me[i] >= 'a' && me[i] <= 'z') ? me[i] - 32 : me[i]);
    up[i] = 0;
    h = U(gethostbyname)(up);
    check_self(h);
    for (i = 0; me[i]; i++) up[i] = (char)((me[i] >= 'A' && me[i] <= 'Z') ? me[i] + 32 : me[i]);
    h = U(gethostbyname)(up);
    check_self(h);
    LNS_DONE();
}
TEST(hostbyname_null_and_empty_agree)
{
    struct hostent *h; char a[260]; int n1, n2;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)(NULL); CHECK(h != NULL);
    if (!h) { LNS_DONE(); return; }
    lstrcpynA(a, h->h_name, sizeof a); n1 = own_addr_count(h);
    h = U(gethostbyname)(""); CHECK(h != NULL);
    if (!h) { LNS_DONE(); return; }
    CHECK(!strcmp(a, h->h_name)); n2 = own_addr_count(h);
    EXPECT_EQ(n1, n2);
    LNS_DONE();
}
/* The loopback address is never what "this machine" resolves to once a real address exists: observation only. */
TEST(hostbyname_this_machine_address_kind)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("");
    CHECK(h != NULL);
    if (h && h->h_addr_list && h->h_addr_list[0]) t_note("first address of this machine is %s", h->h_addr_list[0][0] == 127 ? "loopback" : "not loopback");
    LNS_DONE();
}

/* ---- unknown names ------------------------------------------------------------------------------------ */

#define UNKNOWN_CASE(tag, text) \
TEST(hostbyname_unknown_##tag) { \
    struct hostent *h; \
    LNS_NEED(gethostbyname); \
    LNS_SETERR(0); \
    h = U(gethostbyname)(text); \
    CHECK(h == NULL); \
    if (!h) EXPECT_EQ(LNS_ERR(), LNS_E_HOSTNF); \
    LNS_DONE(); \
}
/* The reserved "invalid" top-level domain can never exist; it is rejected without waiting for a resolver. */
UNKNOWN_CASE(reserved_domain, "nosuch.invalid")
UNKNOWN_CASE(reserved_deep, "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.invalid")
UNKNOWN_CASE(reserved_upper, "NOSUCH.INVALID")

TEST(hostbyname_unknown_very_long_name)
{
    char big[2000]; struct hostent *h;
    LNS_NEED(gethostbyname);
    memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
    LNS_SETERR(0);
    h = U(gethostbyname)(big);
    CHECK(h == NULL);
    if (!h) EXPECT_EQ(LNS_ERR(), LNS_E_HOSTNF);
    LNS_DONE();
}

/* A failed lookup must not disturb the result of the previous successful one on this thread. */
TEST(hostbyname_failed_lookup_keeps_previous_result)
{
    struct hostent *a, *b; char name[64];
    LNS_NEED(gethostbyname);
    a = U(gethostbyname)("1.2.3.4");
    CHECK(a != NULL);
    if (!a) { LNS_DONE(); return; }
    lstrcpynA(name, a->h_name, sizeof name);
    b = U(gethostbyname)("nosuch.invalid");
    CHECK(b == NULL);
    CHECK(!strcmp(a->h_name, name));
    CHECK(a->h_addr_list[0] && a->h_addr_list[0][0] == 1 && a->h_addr_list[0][3] == 4);
    LNS_DONE();
}

/* ---- block layout ------------------------------------------------------------------------------------- */

/* hostent, aliases, address list, address bytes and name sit in one block in that order (single address, no alias). */
static void check_block(struct hostent *h, const char *tag)
{
    int n, na;
    char *p;
    CHECKF(h != NULL, "%s: no result", tag);
    if (!h) return;
    p = (char *)(h + 1);
    CHECKF((char *)h->h_aliases == p, "%s: aliases not right after the struct", tag);
    na = lns_list_len(h->h_aliases);
    p += sizeof(char *) * (na + 1);
    CHECKF((char *)h->h_addr_list == p, "%s: address list not after the aliases", tag);
    n = lns_list_len(h->h_addr_list);
    p += sizeof(char *) * (n + 1);
    CHECKF(h->h_addr_list[0] == p, "%s: first address not after the address list", tag);
    if (n >= 1) {
        int i;
        for (i = 1; i < n; i++) CHECKF(h->h_addr_list[i] == h->h_addr_list[i - 1] + h->h_length, "%s: addresses not packed", tag);
        CHECKF(h->h_name == h->h_addr_list[n - 1] + h->h_length || (char *)h->h_name > h->h_addr_list[n - 1],
               "%s: name before the address bytes", tag);
    }
}
TEST(hostblock_layout_numeric) { LNS_NEED(gethostbyname); check_block(U(gethostbyname)("9.8.7.6"), "numeric"); LNS_DONE(); }
TEST(hostblock_layout_localhost) { LNS_NEED(gethostbyname); check_block(U(gethostbyname)("localhost"), "localhost"); LNS_DONE(); }
TEST(hostblock_layout_this_machine) { LNS_NEED(gethostbyname); check_block(U(gethostbyname)(""), "self"); LNS_DONE(); }
TEST(hostblock_layout_by_address)
{
    LNS_NEED(gethostbyaddr);
    check_block(U(gethostbyaddr)((const char *)LO4, 4, AF_INET), "byaddr4");
    check_block(U(gethostbyaddr)((const char *)LO6, 16, AF_INET6), "byaddr6");
    LNS_DONE();
}
/* For a single-address, alias-free result the name directly follows the address bytes. */
TEST(hostblock_name_follows_single_address)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("5.6.7.8");
    CHECK(h != NULL);
    if (h && lns_list_len(h->h_addr_list) == 1) CHECK(h->h_name == h->h_addr_list[0] + 4);
    LNS_DONE();
}
TEST(hostblock_name_is_inside_a_modest_block)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("5.6.7.8");
    CHECK(h != NULL);
    /* The block is a few hundred bytes at most for a result of this size. */
    if (h) CHECK(lns_inside(h, 512, h->h_name, strlen(h->h_name) + 1));
    LNS_DONE();
}
TEST(hostblock_h_addr_is_first_list_entry)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("5.6.7.8");
    CHECK(h != NULL);
    if (h) { CHECK(h->h_addr == h->h_addr_list[0]); CHECK(h->h_addr_list[1] == NULL); }
    LNS_DONE();
}
TEST(hostblock_address_bytes_are_unaligned_packed_ok)
{
    struct hostent *h;
    LNS_NEED(gethostbyname);
    h = U(gethostbyname)("11.22.33.44");
    CHECK(h != NULL);
    if (h) { unsigned char *a = (unsigned char *)h->h_addr_list[0]; CHECK(a[0] == 11 && a[1] == 22 && a[2] == 33 && a[3] == 44); }
    LNS_DONE();
}

/* ---- gethostbyaddr ----------------------------------------------------------------------------------- */

TEST(hostbyaddr_loopback_v4)
{
    struct hostent *h;
    LNS_NEED(gethostbyaddr);
    h = U(gethostbyaddr)((const char *)LO4, 4, AF_INET);
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(h->h_addrtype, AF_INET);
        EXPECT_EQ(h->h_length, 4);
        CHECK(addr_is(h, 0, LO4, 4));
        EXPECT_EQ(lns_list_len(h->h_addr_list), 1);
        EXPECT_EQ(lns_list_len(h->h_aliases), 0);
        CHECK(h->h_name && h->h_name[0]);
    }
    LNS_DONE();
}
TEST(hostbyaddr_loopback_v6)
{
    struct hostent *h;
    LNS_NEED(gethostbyaddr);
    h = U(gethostbyaddr)((const char *)LO6, 16, AF_INET6);
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(h->h_addrtype, AF_INET6);
        EXPECT_EQ(h->h_length, 16);
        CHECK(addr_is(h, 0, LO6, 16));
        EXPECT_EQ(lns_list_len(h->h_addr_list), 1);
        CHECK(h->h_name && h->h_name[0]);
    }
    LNS_DONE();
}
TEST(hostbyaddr_loopback_names_agree_between_families)
{
    struct hostent *h; char a[260];
    LNS_NEED(gethostbyaddr);
    h = U(gethostbyaddr)((const char *)LO4, 4, AF_INET); CHECK(h != NULL);
    if (!h) { LNS_DONE(); return; }
    lstrcpynA(a, h->h_name, sizeof a);
    h = U(gethostbyaddr)((const char *)LO6, 16, AF_INET6); CHECK(h != NULL);
    if (h) CHECK(!_stricmp(a, h->h_name));
    LNS_DONE();
}
TEST(hostbyaddr_loopback_name_vs_localhost_lookup)
{
    struct hostent *h; char a[260];
    LNS_NEED(gethostbyaddr);
    REQUIRE(U(gethostbyname));
    h = U(gethostbyname)("localhost"); CHECK(h != NULL);
    if (!h) { LNS_DONE(); return; }
    lstrcpynA(a, h->h_name, sizeof a);
    h = U(gethostbyaddr)((const char *)LO4, 4, AF_INET); CHECK(h != NULL);
    if (h) CHECK(!_stricmp(a, h->h_name));
    LNS_DONE();
}

/* NULL address is invalid argument for every type (the argument test follows the initialisation test). */
#define BYADDR_NULL_CASE(tag, len, type) \
TEST(hostbyaddr_null_address_##tag) { \
    LNS_NEED(gethostbyaddr); \
    LNS_SETERR(0); \
    CHECK(U(gethostbyaddr)(NULL, (len), (type)) == NULL); \
    EXPECT_EQ(LNS_ERR(), LNS_E_INVAL); \
    LNS_DONE(); \
}
BYADDR_NULL_CASE(v4, 4, AF_INET)
BYADDR_NULL_CASE(v6, 16, AF_INET6)
BYADDR_NULL_CASE(len_zero, 0, AF_INET)
BYADDR_NULL_CASE(unspec, 4, AF_UNSPEC)
BYADDR_NULL_CASE(odd_type, 4, 99)

/* An IPv6 request must say 16 bytes. */
#define BYADDR_V6LEN_CASE(tag, len) \
TEST(hostbyaddr_v6_wrong_length_##tag) { \
    LNS_NEED(gethostbyaddr); \
    LNS_SETERR(0); \
    CHECK(U(gethostbyaddr)((const char *)LO6, (len), AF_INET6) == NULL); \
    EXPECT_EQ(LNS_ERR(), LNS_E_INVAL); \
    LNS_DONE(); \
}
BYADDR_V6LEN_CASE(zero, 0)
BYADDR_V6LEN_CASE(four, 4)
BYADDR_V6LEN_CASE(eight, 8)
BYADDR_V6LEN_CASE(fifteen, 15)
BYADDR_V6LEN_CASE(seventeen, 17)
BYADDR_V6LEN_CASE(negative, -1)

/* Any type other than AF_INET6 is read as a 4-byte IPv4 address and the length is not looked at. */
#define BYADDR_V4LOOSE_CASE(tag, len, type) \
TEST(hostbyaddr_v4_reading_##tag) { \
    struct hostent *h; \
    LNS_NEED(gethostbyaddr); \
    h = U(gethostbyaddr)((const char *)LO4, (len), (type)); \
    CHECK(h != NULL); \
    if (h) { EXPECT_EQ(h->h_addrtype, AF_INET); EXPECT_EQ(h->h_length, 4); CHECK(addr_is(h, 0, LO4, 4)); } \
    LNS_DONE(); \
}
BYADDR_V4LOOSE_CASE(len_zero, 0, AF_INET)
BYADDR_V4LOOSE_CASE(len_three, 3, AF_INET)
BYADDR_V4LOOSE_CASE(len_sixteen_v4, 16, AF_INET)
BYADDR_V4LOOSE_CASE(type_unspec, 4, AF_UNSPEC)
BYADDR_V4LOOSE_CASE(type_odd, 4, 99)
BYADDR_V4LOOSE_CASE(type_netbios, 4, AF_NETBIOS)

TEST(hostbyaddr_unmapped_v4_not_found)
{
    static const unsigned char a[4] = { 1, 2, 3, 4 };
    LNS_NEED(gethostbyaddr);
    LNS_SETERR(0);
    CHECK(U(gethostbyaddr)((const char *)a, 4, AF_INET) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(hostbyaddr_broadcast_not_found)
{
    static const unsigned char a[4] = { 255, 255, 255, 255 };
    LNS_NEED(gethostbyaddr);
    LNS_SETERR(0);
    CHECK(U(gethostbyaddr)((const char *)a, 4, AF_INET) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(hostbyaddr_unmapped_v6_not_found)
{
    static const unsigned char a[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    LNS_NEED(gethostbyaddr);
    LNS_SETERR(0);
    CHECK(U(gethostbyaddr)((const char *)a, 16, AF_INET6) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(hostbyaddr_v4_bytes_labelled_v6_not_found)
{
    unsigned char a[16]; /* 127.0.0.1 followed by zeros is not ::1 */
    LNS_NEED(gethostbyaddr);
    memset(a, 0, sizeof a); memcpy(a, LO4, 4);
    LNS_SETERR(0);
    CHECK(U(gethostbyaddr)((const char *)a, 16, AF_INET6) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(hostbyaddr_this_machine_address_round_trip)
{
    struct hostent *h; unsigned char a[4]; char name[300];
    LNS_NEED(gethostbyaddr);
    REQUIRE(U(gethostbyname));
    h = U(gethostbyname)("");
    CHECK(h != NULL && h->h_addr_list && h->h_addr_list[0]);
    if (!h || !h->h_addr_list || !h->h_addr_list[0]) { LNS_DONE(); return; }
    memcpy(a, h->h_addr_list[0], 4);
    lstrcpynA(name, h->h_name, sizeof name);
    h = U(gethostbyaddr)((const char *)a, 4, AF_INET);
    CHECK(h != NULL);
    if (h) CHECK(!_stricmp(name, h->h_name));
    LNS_DONE();
}

/* ---- before WSAStartup -------------------------------------------------------------------------------- */

TEST(hostbyname_before_startup_not_initialised)
{
    REQUIRE(U(gethostbyname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(gethostbyname)("localhost") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(hostbyname_null_before_startup_not_initialised)
{
    REQUIRE(U(gethostbyname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(gethostbyname)(NULL) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(hostbyaddr_before_startup_not_initialised)
{
    REQUIRE(U(gethostbyaddr)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(gethostbyaddr)((const char *)LO4, 4, AF_INET) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(hostbyaddr_null_before_startup_not_initialised)
{
    REQUIRE(U(gethostbyaddr)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(gethostbyaddr)(NULL, 4, AF_INET) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

/* ---- the per-thread result block --------------------------------------------------------------------- */

TEST(hostbuf_repeated_lookups_reuse_one_block)
{
    struct hostent *a, *b; int i;
    LNS_NEED(gethostbyname);
    a = U(gethostbyname)("1.1.1.1");
    CHECK(a != NULL);
    for (i = 0; i < 50; i++) {
        b = U(gethostbyname)(i & 1 ? "2.2.2.2" : "localhost");
        CHECK(b == a);
    }
    LNS_DONE();
}
TEST(hostbuf_name_and_addr_lookups_share_a_block)
{
    struct hostent *a, *b;
    LNS_NEED(gethostbyaddr);
    REQUIRE(U(gethostbyname));
    a = U(gethostbyname)("localhost");
    b = U(gethostbyaddr)((const char *)LO4, 4, AF_INET);
    CHECK(a != NULL && b != NULL);
    CHECK(a == b);
    LNS_DONE();
}
TEST(hostbuf_v4_and_v6_lookups_share_a_block)
{
    struct hostent *a, *b;
    LNS_NEED(gethostbyaddr);
    a = U(gethostbyaddr)((const char *)LO4, 4, AF_INET);
    b = U(gethostbyaddr)((const char *)LO6, 16, AF_INET6);
    CHECK(a != NULL && b != NULL);
    CHECK(a == b);
    LNS_DONE();
}
/* The newer lookup overwrites the older result: the older pointer now describes the newer answer. */
TEST(hostbuf_second_lookup_overwrites_first)
{
    struct hostent *a, *b;
    LNS_NEED(gethostbyname);
    a = U(gethostbyname)("1.2.3.4");
    CHECK(a != NULL && a->h_name && !strcmp(a->h_name, "1.2.3.4"));
    b = U(gethostbyname)("5.6.7.8");
    CHECK(b == a);
    if (a && a->h_name) CHECK(!strcmp(a->h_name, "5.6.7.8"));
    if (a && a->h_addr_list && a->h_addr_list[0]) CHECK((unsigned char)a->h_addr_list[0][0] == 5);
    LNS_DONE();
}
TEST(hostbuf_v6_result_overwrites_v4_shape)
{
    struct hostent *a;
    LNS_NEED(gethostbyaddr);
    a = U(gethostbyaddr)((const char *)LO4, 4, AF_INET);
    CHECK(a != NULL);
    if (a) EXPECT_EQ(a->h_length, 4);
    a = U(gethostbyaddr)((const char *)LO6, 16, AF_INET6);
    CHECK(a != NULL);
    if (a) { EXPECT_EQ(a->h_length, 16); EXPECT_EQ(a->h_addrtype, AF_INET6); }
    a = U(gethostbyname)("9.9.9.9");
    CHECK(a != NULL);
    if (a) { EXPECT_EQ(a->h_length, 4); EXPECT_EQ(a->h_addrtype, AF_INET); }
    LNS_DONE();
}
TEST(hostbuf_block_not_shared_with_other_result_types)
{
    struct hostent *h; struct servent *s; struct protoent *p;
    LNS_NEED(gethostbyname);
    REQUIRE(U(getservbyname)); REQUIRE(U(getprotobyname));
    h = U(gethostbyname)("localhost");
    s = U(getservbyname)("http", "tcp");
    p = U(getprotobyname)("tcp");
    CHECK(h && s && p);
    CHECK((void *)h != (void *)s);
    CHECK((void *)h != (void *)p);
    CHECK((void *)s != (void *)p);
    /* Each result is still intact after the other two lookups. */
    if (h && s && p) { CHECK(h->h_addr_list[0] && h->h_addr_list[0][0] == 127); CHECK(s->s_name && !strcmp(s->s_name, "http")); CHECK(p->p_name && !strcmp(p->p_name, "tcp")); }
    LNS_DONE();
}

struct thr_ctx { HANDLE ready, go; struct hostent *blk; char name[64]; volatile LONG ok; };
static DWORD WINAPI host_thread(void *p)
{
    struct thr_ctx *c = p;
    WSADATA d;
    struct hostent *h;
    if (U(WSAStartup)(0x202, &d)) return 1;
    h = U(gethostbyname)("7.7.7.7");
    c->blk = h;
    if (h) lstrcpynA(c->name, h->h_name, sizeof c->name);
    SetEvent(c->ready);
    WaitForSingleObject(c->go, 10000);
    /* After the main thread did its own lookups this block must still say what this thread asked for. */
    c->ok = h && h->h_name && !strcmp(h->h_name, "7.7.7.7");
    U(WSACleanup)();
    return 0;
}
TEST(hostbuf_each_thread_has_its_own_block)
{
    struct thr_ctx c; HANDLE th; struct hostent *mine, *again;
    LNS_NEED(gethostbyname);
    memset(&c, 0, sizeof c);
    c.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    c.go = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, host_thread, &c, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        EXPECT_EQ(WaitForSingleObject(c.ready, 10000), WAIT_OBJECT_0);
        mine = U(gethostbyname)("8.8.8.8");
        CHECK(mine != NULL);
        CHECK(mine != c.blk);
        again = U(gethostbyname)("8.8.4.4");
        CHECK(again == mine);
        SetEvent(c.go);
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
        CloseHandle(th);
        EXPECT_EQ(c.ok, 1);
        CHECK(!strcmp(c.name, "7.7.7.7"));
        if (mine && mine->h_name) CHECK(!strcmp(mine->h_name, "8.8.4.4"));
    }
    CloseHandle(c.ready); CloseHandle(c.go);
    LNS_DONE();
}

#define NT 3
#define NR 100
static volatile LONG g_bad;
static DWORD WINAPI hammer(void *p)
{
    static const char *names[] = { "1.1.1.1", "2.2.2.2", "3.3.3.3" };
    int me = (int)(INT_PTR)p, i;
    WSADATA d;
    struct hostent *first = NULL;
    if (U(WSAStartup)(0x202, &d)) { InterlockedIncrement(&g_bad); return 1; }
    for (i = 0; i < NR; i++) {
        struct hostent *h = U(gethostbyname)(names[me]);
        if (!h || !h->h_name || strcmp(h->h_name, names[me])) InterlockedIncrement(&g_bad);
        else if (!first) first = h;
        else if (h != first) InterlockedIncrement(&g_bad);
        if (h && (!h->h_addr_list[0] || (unsigned char)h->h_addr_list[0][0] != me + 1)) InterlockedIncrement(&g_bad);
    }
    U(WSACleanup)();
    return 0;
}
TEST(hostbuf_concurrent_threads_do_not_interfere)
{
    HANDLE th[NT]; int i;
    LNS_NEED(gethostbyname);
    g_bad = 0;
    for (i = 0; i < NT; i++) th[i] = CreateThread(NULL, 0, hammer, (void *)(INT_PTR)i, 0, NULL);
    for (i = 0; i < NT; i++) {
        if (!th[i]) { CHECK(0); continue; }
        EXPECT_EQ(WaitForSingleObject(th[i], 20000), WAIT_OBJECT_0);
        CloseHandle(th[i]);
    }
    EXPECT_EQ(g_bad, 0);
    LNS_DONE();
}

/* WSAGetLastError is per thread too: a failure on a worker does not appear on the caller. */
static DWORD WINAPI fail_thread(void *p)
{
    WSADATA d;
    struct hostent *h;
    if (U(WSAStartup)(0x202, &d)) return 1;
    /* An argument failure is answered locally, without any resolver round trip. */
    h = U(gethostbyaddr)(NULL, 4, AF_INET);
    *(int *)p = h ? -1 : U(WSAGetLastError)();
    U(WSACleanup)();
    return 0;
}
TEST(hosterr_last_error_is_per_thread)
{
    int theirs = 0; HANDLE th;
    LNS_NEED(gethostbyaddr);
    LNS_SETERR(0x4321);
    th = CreateThread(NULL, 0, fail_thread, &theirs, 0, NULL);
    CHECK(th != NULL);
    if (th) { EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0); CloseHandle(th); }
    EXPECT_EQ(theirs, LNS_E_INVAL);
    EXPECT_EQ(LNS_ERR(), 0x4321);
    LNS_DONE();
}

/* ---- forwarders ------------------------------------------------------------------------------------- */

TEST(hostbyname_wsock32_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "gethostbyname"), b = t_proc_in("wsock32.dll", "gethostbyname");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
TEST(hostbyaddr_wsock32_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "gethostbyaddr"), b = t_proc_in("wsock32.dll", "gethostbyaddr");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
TEST(hostbyname_wsock32_form_is_callable)
{
    struct hostent *(WINAPI *p)(const char *);
    struct hostent *h;
    LNS_NEED(gethostbyname);
    p = (struct hostent *(WINAPI *)(const char *))t_proc_in("wsock32.dll", "gethostbyname");
    REQUIRE(p);
    h = p("127.0.0.1");
    CHECK(h != NULL);
    if (h) CHECK(addr_is(h, 0, LO4, 4));
    LNS_DONE();
}
