/* The bind request beyond input validation: the share word, address collisions, repeat binds and what the
 * Winsock layer can see afterwards.
 *
 * The first word of the bind input says how the endpoint wants to share its address: 0 default, 1 allow
 * reuse by others that also asked for it, 2 and 3 other modes (3 is the "exclusive" request). On this
 * stack the word is not validated (every value binds); the effect shows when a second endpoint asks for an
 * address and port that are already taken: the second bind fails with a sharing violation, except that a
 * second bind which asks for reuse against a first that did not is an access-denied failure and two
 * binds that both asked for reuse succeed.
 */
#include "abl.h"

#define ST_ACCESS_DENIED 0xC0000022UL

static ULONG expect_collision(ULONG first_share, ULONG second_share) {
    if (first_share == 1 && second_share == 1) return NS_SUCCESS;
    if (second_share == 1) return ST_ACCESS_DENIED;
    return NS_SHARING_VIOLATION;
}

static void collide_table(int type) {
    for (ULONG i = 0; i < 4; i++) for (ULONG j = 0; j < 4; j++) {
        SOCKET s1 = abl_sock(AF_INET, type), s2 = abl_sock(AF_INET, type);
        struct sockaddr_in o, n;
        LONG st1 = abl_raw_bind4(s1, i, LO4, 0, &o);
        CHECK_NS(st1, NS_SUCCESS);
        LONG st2 = abl_raw_bind4(s2, j, LO4, o.sin_port, &n);
        ULONG want = expect_collision(i, j);
        t_check((ULONG)st2 == want, __FILE__, __LINE__, "share collision", "%s first %lu second %lu: got 0x%08lx want 0x%08lx",
                type == SOCK_STREAM ? "tcp" : "udp", (unsigned long)i, (unsigned long)j, (unsigned long)st2, (unsigned long)want);
        if (want == NS_SUCCESS) CHECK(n.sin_port == o.sin_port);
        abl_close(s1); abl_close(s2);
    }
}
TEST(ablb_share_collision_table_tcp) { ABL_BEGIN(); collide_table(SOCK_STREAM); }
TEST(ablb_share_collision_table_udp) { ABL_BEGIN(); collide_table(SOCK_DGRAM); }

TEST(ablb_share_values_not_validated) {
    ABL_BEGIN();
    static const ULONG v[] = { 0, 1, 2, 3, 4, 5, 0x10, 0x100, 0x7fffffff, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        SOCKET s = abl_tcp(); struct sockaddr_in o;
        LONG st = abl_raw_bind4(s, v[i], LO4, 0, &o);
        t_check((ULONG)st == NS_SUCCESS, __FILE__, __LINE__, "share word accepted", "share 0x%lx: 0x%08lx", (unsigned long)v[i], (unsigned long)st);
        abl_close(s);
    }
}
TEST(ablb_collision_failure_leaves_endpoint_unbound) {
    ABL_BEGIN();
    struct sockaddr_in a, o; SOCKET s1 = abl_bound(SOCK_STREAM, &a), s2 = abl_tcp();
    CHECK_NS(abl_raw_bind4(s2, 0, LO4, a.sin_port, &o), NS_SHARING_VIOLATION);
    CHECK_NS(abl_raw_bind4(s2, 0, LO4, 0, &o), NS_SUCCESS);               /* a retry on a free port works */
    CHECK(o.sin_port != a.sin_port);
    abl_close(s1); abl_close(s2);
}
TEST(ablb_collision_matches_winsock_error) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET s1 = abl_bound(SOCK_STREAM, &a), s2 = abl_tcp();
    struct sockaddr_in w = abl_lo4(a.sin_port);
    SET_ERR(0);
    CHECK(W.bind(s2, (struct sockaddr *)&w, sizeof w) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEADDRINUSE);
    abl_close(s1); abl_close(s2);
}
TEST(ablb_port_free_again_after_close) {
    ABL_BEGIN();
    for (int type = 0; type < 2; type++) {
        struct sockaddr_in a, o; SOCKET s1 = abl_bound(type ? SOCK_DGRAM : SOCK_STREAM, &a);
        abl_close(s1);
        SOCKET s2 = abl_sock(AF_INET, type ? SOCK_DGRAM : SOCK_STREAM);
        CHECK_NS(abl_raw_bind4(s2, 0, LO4, a.sin_port, &o), NS_SUCCESS);
        CHECK(o.sin_port == a.sin_port);
        abl_close(s2);
    }
}
TEST(ablb_wildcard_and_specific_coexist_on_one_port) {
    /* without reuse a wildcard bind and a specific-address bind of the same port both succeed, in either order */
    ABL_BEGIN();
    for (int order = 0; order < 2; order++) {
        SOCKET s1 = abl_tcp(), s2 = abl_tcp(); struct sockaddr_in w = abl_lo4(0), o, n; IO_STATUS_BLOCK io;
        w.sin_addr.s_addr = order ? BE32(LO4) : 0;
        CHECK_NS(abl_raw_bind(s1, 0, &w, sizeof w, &o, sizeof o, &io), NS_SUCCESS);
        w = abl_lo4(o.sin_port); w.sin_addr.s_addr = order ? 0 : BE32(LO4);
        CHECK_NS(abl_raw_bind(s2, 0, &w, sizeof w, &n, sizeof n, &io), NS_SUCCESS);
        CHECK(n.sin_port == o.sin_port);
        abl_close(s1); abl_close(s2);
    }
}
TEST(ablb_distinct_loopback_addresses_do_not_conflict) {
    ABL_BEGIN();
    SOCKET s1 = abl_tcp(), s2 = abl_tcp(); struct sockaddr_in o, n;
    CHECK_NS(abl_raw_bind4(s1, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(abl_raw_bind4(s2, 0, 0x7f000002UL, o.sin_port, &n), NS_SUCCESS);
    CHECK(n.sin_port == o.sin_port && n.sin_addr.s_addr == BE32(0x7f000002UL));
    abl_close(s1); abl_close(s2);
}
TEST(ablb_tcp_and_udp_ports_are_independent) {
    ABL_BEGIN();
    SOCKET t = abl_tcp(), u = abl_udp(); struct sockaddr_in o, n;
    CHECK_NS(abl_raw_bind4(t, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(abl_raw_bind4(u, 0, LO4, o.sin_port, &n), NS_SUCCESS);
    CHECK(n.sin_port == o.sin_port);
    abl_close(t); abl_close(u);
}

/* ---- repeated binds -------------------------------------------------------------------------------- */
static void rebind_refused(SOCKET s) {
    struct sockaddr_in o;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_ADDRESS_ALREADY_ASSOCIATED);
}
TEST(ablb_second_raw_bind_refused) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    rebind_refused(s);
    abl_close(s);
}
TEST(ablb_second_bind_does_not_move_the_name) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o, o2, n; IO_STATUS_BLOCK io;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o2), NS_ADDRESS_ALREADY_ASSOCIATED);
    CHECK_NS(abl_raw_name(s, &n, sizeof n, &io), NS_SUCCESS);
    CHECK(!memcmp(&o, &n, sizeof o));
    abl_close(s);
}
TEST(ablb_rebind_after_winsock_bind_refused) { ABL_BEGIN(); SOCKET s = abl_bound(SOCK_STREAM, NULL); rebind_refused(s); abl_close(s); }
TEST(ablb_rebind_on_datagram_refused) { ABL_BEGIN(); SOCKET s = abl_bound(SOCK_DGRAM, NULL); rebind_refused(s); abl_close(s); }
TEST(ablb_rebind_on_listener_refused) { ABL_BEGIN(); SOCKET s = abl_listener(NULL); rebind_refused(s); abl_close(s); }
TEST(ablb_rebind_on_connected_refused) {
    ABL_BEGIN();
    SOCKET c, s; abl_pair(&c, &s);
    rebind_refused(c); rebind_refused(s);
    abl_close(c); abl_close(s);
}
TEST(ablb_rebind_on_udp_after_connect_refused) {
    ABL_BEGIN();
    struct sockaddr_in ua; SOCKET u1 = abl_bound(SOCK_DGRAM, &ua), u2 = abl_udp();
    CHECK(W.connect(u2, (struct sockaddr *)&ua, sizeof ua) == 0);      /* connect binds implicitly */
    rebind_refused(u2);
    abl_close(u1); abl_close(u2);
}

/* ---- output block ------------------------------------------------------------------------------------ */
TEST(ablb_output_larger_than_address_reports_address_size) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0); IO_STATUS_BLOCK io; BYTE out[64];
    memset(out, 0xcc, sizeof out);
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, out, sizeof out, &io), NS_SUCCESS);
    CHECK_INFO(io, sizeof(struct sockaddr_in));
    CHECK(out[16] == 0xcc);
    abl_close(s);
}
TEST(ablb_exact_size_output) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK(o.sin_family == AF_INET && o.sin_port != 0 && o.sin_addr.s_addr == BE32(LO4));
    for (int i = 0; i < 8; i++) CHECK(o.sin_zero[i] == 0);
    abl_close(s);
}
TEST(ablb_missing_output_or_input_is_parameter_error) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0); BYTE buf[20] = {0}; BYTE out[32]; IO_STATUS_BLOCK io; LONG first;
    memcpy(buf + 4, &a, sizeof a);
    CHECK_NS(abl_ctl(s, IO_BIND, buf, 20, NULL, 0, &io, &first), NS_INVALID_PARAMETER);
    CHECK_NS(first, NS_INVALID_PARAMETER);
    CHECK_NS(abl_ctl(s, IO_BIND, NULL, 0, out, 16, &io, &first), NS_INVALID_PARAMETER);
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &a), NS_SUCCESS);               /* the failures left it unbound */
    abl_close(s);
}
TEST(ablb_output_size_table) {
    ABL_BEGIN();
    static const struct { ULONG n; ULONG st; } t[] = {
        { 0, NS_INVALID_PARAMETER }, { 1, NS_INVALID_PARAMETER }, { 2, NS_INVALID_PARAMETER }, { 8, NS_INVALID_PARAMETER }, { 16, NS_SUCCESS },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0); BYTE out[32]; IO_STATUS_BLOCK io;
        LONG st = abl_raw_bind(s, 0, &a, sizeof a, t[i].n ? out : NULL, t[i].n, &io);
        t_check((ULONG)st == t[i].st, __FILE__, __LINE__, "bind output size", "out %lu: 0x%08lx", (unsigned long)t[i].n, (unsigned long)st);
        abl_close(s);
    }
}

/* ---- address forms ---------------------------------------------------------------------------------- */
TEST(ablb_sin_zero_garbage_ignored) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0), o; IO_STATUS_BLOCK io;
    memset(a.sin_zero, 0xff, sizeof a.sin_zero);
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &o, sizeof o, &io), NS_SUCCESS);
    abl_close(s);
}
TEST(ablb_v4_socket_wildcard_reports_zero_address) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0), o; IO_STATUS_BLOCK io;
    a.sin_addr.s_addr = 0;
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &o, sizeof o, &io), NS_SUCCESS);
    CHECK(o.sin_addr.s_addr == 0);
    CHECK(o.sin_port != 0);
    abl_close(s);
}
TEST(ablb_explicit_port_is_kept) {
    ABL_BEGIN();
    /* ask for a free port found by binding and releasing one */
    struct sockaddr_in a; SOCKET p = abl_bound(SOCK_STREAM, &a); abl_close(p);
    SOCKET s = abl_tcp(); struct sockaddr_in o;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, a.sin_port, &o), NS_SUCCESS);
    CHECK(o.sin_port == a.sin_port);
    abl_close(s);
}
TEST(ablb_v6_loopback_roundtrip) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), o; IO_STATUS_BLOCK io;
    memset(&o, 0xcc, sizeof o);
    CHECK_NS(abl_raw_bind(s, 0, &a, sizeof a, &o, sizeof o, &io), NS_SUCCESS);
    CHECK_INFO(io, sizeof o);
    CHECK(o.sin6_family == AF_INET6 && o.sin6_port != 0);
    CHECK(!memcmp(&o.sin6_addr, &a.sin6_addr, 16));
    rebind_refused(s);
    abl_close(s);
}

/* ---- what the Winsock layer sees --------------------------------------------------------------------- */
TEST(ablb_raw_bind_invisible_to_getsockname) {
    /* the Winsock layer keeps its own idea of "bound"; a raw bind does not update it */
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o, n; int len = sizeof n;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    SET_ERR(0);
    CHECK(W.getsockname(s, (struct sockaddr *)&n, &len) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(s);
}
TEST(ablb_raw_bound_socket_holds_the_port) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(), o2 = abl_tcp(); struct sockaddr_in o;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    struct sockaddr_in w = abl_lo4(o.sin_port);
    CHECK(W.bind(o2, (struct sockaddr *)&w, sizeof w) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEADDRINUSE);
    abl_close(s); abl_close(o2);
}
TEST(ablb_winsock_bind_then_raw_name) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in a = abl_lo4(0), n, q; int len = sizeof q; IO_STATUS_BLOCK io;
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&q, &len) == 0);
    CHECK_NS(abl_raw_name(s, &n, sizeof n, &io), NS_SUCCESS);
    CHECK(!memcmp(&n, &q, sizeof n));
    abl_close(s);
}
TEST(ablb_setsockopt_reuseaddr_does_not_change_raw_share_word) {
    /* the share word of a raw bind decides, not the socket option set before it */
    ABL_BEGIN();
    SOCKET s1 = abl_tcp(), s2 = abl_tcp(); int one = 1; struct sockaddr_in o, n;
    CHECK(W.setsockopt(s1, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof one) == 0);
    CHECK(W.setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof one) == 0);
    CHECK_NS(abl_raw_bind4(s1, 0, LO4, 0, &o), NS_SUCCESS);
    CHECK_NS(abl_raw_bind4(s2, 0, LO4, o.sin_port, &n), NS_SHARING_VIOLATION);
    abl_close(s1); abl_close(s2);
}
