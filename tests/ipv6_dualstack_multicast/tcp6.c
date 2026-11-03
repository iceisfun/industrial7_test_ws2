/* IPv6 loopback TCP and dual-stack behaviour.
 * Measures: address family / length / scope reported by getsockname, getpeername and accept for IPv6
 * sockets; how a dual-stack listener (IPV6_V6ONLY off) presents IPv4 clients as v4-mapped addresses;
 * that a V6ONLY listener refuses IPv4 clients; v4-mapped destinations from an IPv6 socket; connect
 * argument rules (unspecified address, port zero, closed port); short name buffers; data transfer over
 * both families.  Loopback only, ephemeral ports, every socket closed. */
#include "d6.h"

static const char PROBE_TXT[] = "ds6-probe";

/* connect with a bounded wait using a non-blocking socket; returns 0 on success else the WSA error */
static int connect_bounded(SOCKET c, const void *a, int len, int ms) {
    unsigned long on = 1, off = 0;
    int rc, failed = 0;
    U(ioctlsocket)(c, FIONBIO, &on);
    rc = d_connect(c, a, len);
    if (rc == 0) { U(ioctlsocket)(c, FIONBIO, &off); return 0; }
    if (d_err() != WSAEWOULDBLOCK) { int e = d_err(); U(ioctlsocket)(c, FIONBIO, &off); return e; }
    if (!d_writable_or_failed(c, ms, &failed)) { U(ioctlsocket)(c, FIONBIO, &off); return -1; }
    U(ioctlsocket)(c, FIONBIO, &off);
    if (failed) { int e = 0; d_gso(c, SOL_SOCKET, SO_ERROR, &e, &(int){sizeof e}); return e ? e : -2; }
    return 0;
}

/* Exchange PROBE_TXT client->server over an accepted pair and verify; returns 1 when intact. */
static int echo_once(SOCKET cli, SOCKET srv) {
    char b[32] = {0};
    int n;
    if (d_send(cli, PROBE_TXT, sizeof PROBE_TXT) != (int)sizeof PROBE_TXT) return 0;
    n = d_recv_to(srv, b, sizeof b, 3000);
    return n == (int)sizeof PROBE_TXT && !memcmp(b, PROBE_TXT, sizeof PROBE_TXT);
}

TEST(ds6_tcp_v6_loopback_connect_accept_exchange) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, &sa, &n);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_v6_loop(&sa));
    if (a != INVALID_SOCKET) CHECK(echo_once(c, a));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_getsockname_loopback_fields) {
    lsn l; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    memset(&sa, 0xcc, sizeof sa);
    CHECK(d_name(l.s, &sa, &n) == 0);
    EXPECT_EQ(n, SZ_SA6);
    EXPECT_EQ(sa.sin6_family, AF_INET6);
    CHECK(is_v6_loop(&sa));
    EXPECT_EQ(sa.sin6_port, l.port);
    CHECK(sa.sin6_port != 0);
    EXPECT_EQ(sa.sin6_flowinfo, 0);
    EXPECT_EQ(sa.sin6_scope_id, 0);
    d_close(l.s);
}

TEST(ds6_tcp_getsockname_wildcard_is_unspecified) {
    lsn l; struct sockaddr_in6 sa; int n = sizeof sa; static const unsigned char z[16];
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, -1));
    CHECK(d_name(l.s, &sa, &n) == 0);
    EXPECT_EQ(sa.sin6_family, AF_INET6);
    CHECK(!memcmp(sa.sin6_addr.u.Byte, z, 16));
    EXPECT_EQ(sa.sin6_scope_id, 0);
    d_close(l.s);
}

TEST(ds6_tcp_getpeername_matches_listener_and_accept_pair) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa, la, pn, cn; int n = sizeof sa, nn = sizeof pn;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, &la, &n);
    CHECK(a != INVALID_SOCKET);
    memset(&pn, 0, sizeof pn);
    CHECK(d_peer(c, &pn, &nn) == 0);
    EXPECT_EQ(nn, SZ_SA6);
    CHECK(is_v6_loop(&pn));
    EXPECT_EQ(pn.sin6_port, l.port);
    /* the accepted socket's peer is the client's own local name */
    nn = sizeof cn; CHECK(d_name(c, &cn, &nn) == 0);
    nn = sizeof pn; CHECK(d_peer(a, &pn, &nn) == 0);
    EXPECT_EQ(pn.sin6_port, cn.sin6_port);
    EXPECT_EQ(la.sin6_port, cn.sin6_port);
    /* the accepted socket reports the listener's port as its own */
    nn = sizeof pn; CHECK(d_name(a, &pn, &nn) == 0);
    EXPECT_EQ(pn.sin6_port, l.port);
    CHECK(is_v6_loop(&pn));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_getpeername_unconnected_is_enotconn) {
    SOCKET s; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    d_seterr(0);
    CHECK(d_peer(s, &sa, &n) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENOTCONN);
    d_close(s);
}

TEST(ds6_tcp_getsockname_unbound_v6_is_einval) {
    SOCKET s; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    d_seterr(0);
    CHECK(d_name(s, &sa, &n) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(s);
}

TEST(ds6_tcp_getsockname_short_buffer_is_efault) {
    lsn l; struct sockaddr_in6 sa; int n;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    for (n = 0; n < SZ_SA6; n += 9) {   /* 0, 9, 18, 27 */
        d_seterr(0);
        CHECK(d_name(l.s, &sa, &n) == SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEFAULT);
    }
    d_close(l.s);
}

TEST(ds6_tcp_getpeername_short_buffer_is_efault) {
    lsn l; SOCKET c; struct sockaddr_in6 sa; int n = 4;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    d_seterr(0);
    CHECK(d_peer(c, &sa, &n) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEFAULT);
    d_close(c); d_close(l.s);
}

TEST(ds6_tcp_large_name_buffer_returns_actual_length) {
    lsn l; struct sockaddr_storage ss; int n = sizeof ss;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    memset(&ss, 0, sizeof ss);
    CHECK(d_name(l.s, &ss, &n) == 0);
    EXPECT_EQ(n, SZ_SA6);
    EXPECT_EQ(ss.ss_family, AF_INET6);
    d_close(l.s);
}

TEST(ds6_tcp_v6only_default_listener_refuses_v4_client) {
    lsn l; SOCKET c; struct sockaddr_in sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, -1));          /* default: V6ONLY on */
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&sa, 1, l.port);
    d_seterr(0);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAECONNREFUSED);
    d_close(c); d_close(l.s);
}

TEST(ds6_tcp_v6only_explicit_on_listener_refuses_v4_client) {
    lsn l; SOCKET c; struct sockaddr_in sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 1));
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&sa, 1, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAECONNREFUSED);
    d_close(c); d_close(l.s);
}

TEST(ds6_tcp_dualstack_listener_accepts_v4_client_as_mapped) {
    lsn l; SOCKET c, a; struct sockaddr_in ca; struct sockaddr_in6 pa; int n = sizeof pa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&ca, 1, l.port);
    CHECK(d_connect(c, &ca, sizeof ca) == 0);
    memset(&pa, 0, sizeof pa);
    a = d_accept_to(l.s, 3000, &pa, &n);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(n, SZ_SA6);
    EXPECT_EQ(pa.sin6_family, AF_INET6);
    CHECK(is_mapped_loop(&pa));
    EXPECT_EQ(pa.sin6_scope_id, 0);
    if (a != INVALID_SOCKET) CHECK(echo_once(c, a));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_dualstack_accepted_names_are_mapped) {
    lsn l; SOCKET c, a; struct sockaddr_in ca; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&ca, 1, l.port);
    CHECK(d_connect(c, &ca, sizeof ca) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    n = sizeof sa; memset(&sa, 0, sizeof sa);
    CHECK(d_peer(a, &sa, &n) == 0);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_mapped_loop(&sa));
    n = sizeof sa; memset(&sa, 0, sizeof sa);
    CHECK(d_name(a, &sa, &n) == 0);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_mapped_loop(&sa));
    EXPECT_EQ(sa.sin6_port, l.port);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_dualstack_client_sees_v4_names) {
    lsn l; SOCKET c, a; struct sockaddr_in ca, pn; int n = sizeof pn;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&ca, 1, l.port);
    CHECK(d_connect(c, &ca, sizeof ca) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    memset(&pn, 0, sizeof pn);
    CHECK(d_peer(c, &pn, &n) == 0);
    EXPECT_EQ(n, SZ_SA4);
    EXPECT_EQ(pn.sin_family, AF_INET);
    EXPECT_EQ(pn.sin_port, l.port);
    EXPECT_EQ(pn.sin_addr.s_addr, d_h32(0x7f000001u));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_dualstack_listener_accepts_both_families_in_order) {
    lsn l; SOCKET c4, c6, a1, a2; struct sockaddr_in ca; struct sockaddr_in6 c6a, p1, p2; int n1 = sizeof p1, n2 = sizeof p2;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c4 = d_sock(AF_INET, SOCK_STREAM);
    mk4(&ca, 1, l.port);
    CHECK(d_connect(c4, &ca, sizeof ca) == 0);
    c6 = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&c6a, K_LOOP, l.port);
    CHECK(d_connect(c6, &c6a, sizeof c6a) == 0);
    a1 = d_accept_to(l.s, 3000, &p1, &n1);
    a2 = d_accept_to(l.s, 3000, &p2, &n2);
    CHECK(a1 != INVALID_SOCKET && a2 != INVALID_SOCKET);
    /* connection order is preserved: the IPv4 client first */
    CHECK(is_mapped_loop(&p1));
    CHECK(is_v6_loop(&p2));
    d_close(a1); d_close(a2); d_close(c4); d_close(c6); d_close(l.s);
}

TEST(ds6_tcp_v6_client_reaches_dualstack_listener) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, &sa, &n);
    CHECK(a != INVALID_SOCKET);
    CHECK(is_v6_loop(&sa));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_mapped_destination_from_dualstack_client_reaches_v4_listener) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa, pn; struct sockaddr_in la; int n = sizeof la;
    NEED_V6();
    CHECK(lsn_open4(&l));
    c = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(d_setint(c, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    mk6(&sa, K_MAP_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, &la, &n);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(n, SZ_SA4);
    EXPECT_EQ(la.sin_addr.s_addr, d_h32(0x7f000001u));
    n = sizeof pn; memset(&pn, 0, sizeof pn);
    CHECK(d_peer(c, &pn, &n) == 0);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_mapped_loop(&pn));
    EXPECT_EQ(pn.sin6_port, l.port);
    if (a != INVALID_SOCKET) CHECK(echo_once(c, a));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_mapped_destination_with_v6only_is_not_reachable) {
    lsn l; SOCKET c; struct sockaddr_in6 sa; int e;
    NEED_V6();
    CHECK(lsn_open4(&l));
    c = d_sock(AF_INET6, SOCK_STREAM);        /* V6ONLY on by default */
    mk6(&sa, K_MAP_LOOP, l.port);
    e = connect_bounded(c, &sa, sizeof sa, 3000);
    CHECK(e != 0);                            /* a V6ONLY socket cannot reach an IPv4 listener */
    t_note("v6only connect to mapped destination: error class %s", e == WSAEADDRNOTAVAIL ? "EADDRNOTAVAIL" : e == WSAEAFNOSUPPORT ? "EAFNOSUPPORT" : e == WSAEINVAL ? "EINVAL" : "other");
    d_close(c); d_close(l.s);
}

TEST(ds6_tcp_v4_socket_with_v6_destination_fails) {
    lsn l; SOCKET c; struct sockaddr_in6 sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    d_seterr(0);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    t_note("v4 socket connect(AF_INET6 name) error %d", d_err());
    d_close(c); d_close(l.s);
}

TEST(ds6_tcp_connect_unspecified_address_is_eaddrnotavail) {
    SOCKET c; struct sockaddr_in6 sa;
    NEED_V6();
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_ANY, d_h16(9));
    d_seterr(0);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(c);
}

TEST(ds6_tcp_connect_port_zero_is_eaddrnotavail) {
    SOCKET c; struct sockaddr_in6 sa;
    NEED_V6();
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, 0);
    d_seterr(0);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(c);
}

TEST(ds6_tcp_connect_closed_port_is_refused) {
    lsn l; SOCKET c; struct sockaddr_in6 sa; unsigned short p;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    p = l.port; d_close(l.s);                 /* nothing listens here any more */
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, p);
    d_seterr(0);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAECONNREFUSED);
    d_close(c);
}

TEST(ds6_tcp_connect_short_name_fails) {
    lsn l; SOCKET c; struct sockaddr_in6 sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    d_seterr(0);
    CHECK(d_connect(c, &sa, SZ_SA6 - 1) == SOCKET_ERROR);
    t_note("connect with a 27-byte IPv6 name: error %d", d_err());
    d_close(c); d_close(l.s);
}

TEST(ds6_tcp_connect_twice_on_connected_socket_is_eisconn) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    d_seterr(0);
    CHECK(d_connect(c, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEISCONN);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_bind_same_v6_endpoint_twice_is_addrinuse) {
    lsn l; SOCKET s; struct sockaddr_in6 sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    s = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    d_seterr(0);
    CHECK(d_bind(s, &sa, sizeof sa) == SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRINUSE);
    d_close(s); d_close(l.s);
}

TEST(ds6_tcp_v6only_wildcard_leaves_v4_port_free) {
    lsn l; SOCKET s; struct sockaddr_in sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 1));
    s = d_sock(AF_INET, SOCK_STREAM);
    mk4(&sa, 0, l.port);
    CHECK(d_bind(s, &sa, sizeof sa) == 0);
    d_close(s); d_close(l.s);
}

TEST(ds6_tcp_bind_mapped_loopback_on_dualstack_socket) {
    lsn l; SOCKET c; struct sockaddr_in6 a6, pn; struct sockaddr_in ca; int n = sizeof a6, r;
    NEED_V6();
    l.s = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(d_setint(l.s, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    mk6(&a6, K_MAP_LOOP, 0);
    r = d_bind(l.s, &a6, sizeof a6);
    if (r) { t_note("bind(mapped loopback) on dual-stack socket failed %d", d_err()); d_close(l.s); t_skip("mapped bind refused"); return; }
    CHECK(d_listen(l.s, 2) == 0);
    CHECK(d_name(l.s, &a6, &n) == 0);
    CHECK(is_mapped_loop(&a6));
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&ca, 1, a6.sin6_port);
    CHECK(d_connect(c, &ca, sizeof ca) == 0);
    n = sizeof pn;
    SOCKET a = d_accept_to(l.s, 3000, &pn, &n);
    CHECK(a != INVALID_SOCKET);
    CHECK(is_mapped_loop(&pn));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_bind_mapped_loopback_with_v6only_note) {
    SOCKET s; struct sockaddr_in6 a6; int r;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&a6, K_MAP_LOOP, 0);
    d_seterr(0);
    r = d_bind(s, &a6, sizeof a6);
    t_note("bind(mapped loopback) with V6ONLY on: rc %d err %d", r, r ? d_err() : 0);
    d_close(s);
}

TEST(ds6_tcp_v6only_reads_back_after_dualstack_switch) {
    SOCKET s; int v;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0); EXPECT_EQ(v, 1);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0); EXPECT_EQ(v, 0);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 1) == 0);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0); EXPECT_EQ(v, 1);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 5) == 0);   /* any non-zero is "on" */
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0); EXPECT_EQ(v, 1);
    d_close(s);
}

TEST(ds6_tcp_v6only_toggle_after_bind_note) {
    SOCKET s; struct sockaddr_in6 a6; int r, v = -1;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&a6, K_ANY, 0);
    CHECK(d_bind(s, &a6, sizeof a6) == 0);
    d_seterr(0);
    r = d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 0);
    d_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v);
    t_note("V6ONLY toggled after bind: rc %d err %d now %d", r, r ? d_err() : 0, v);
    d_close(s);
}

TEST(ds6_tcp_accepted_socket_inherits_v6only) {
    lsn l; SOCKET c, a; int v;
    struct sockaddr_in6 sa;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    CHECK(d_getint(a, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0);
    EXPECT_EQ(v, 0);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_bulk_transfer_over_v6_is_intact) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa; static char out[65536], in[65536]; int sent = 0, got = 0, i;
    NEED_V6();
    for (i = 0; i < (int)sizeof out; i++) out[i] = (char)(i * 31 + 7);
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    if (a != INVALID_SOCKET) {
        int r = d_send(c, out, sizeof out);
        CHECK(r == (int)sizeof out);          /* fits the loopback buffers */
        sent = r > 0 ? r : 0;
        while (got < sent) {
            r = d_recv_to(a, in + got, sent - got, 3000);
            if (r <= 0) break;
            got += r;
        }
        EXPECT_EQ(got, sent);
        CHECK(!memcmp(in, out, got));
    }
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_graceful_close_reads_zero_over_v6) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa; char b[4];
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    CHECK(U(shutdown)(c, SD_SEND) == 0);
    EQC(d_recv_to(a, b, sizeof b, 3000), 0);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_tcp_accept_name_buffer_too_small_is_efault) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa; int n = 16;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    CHECK(d_readable(l.s, 3000));
    d_seterr(0);
    a = d_accept(l.s, &sa, &n);
    CHECK(a == INVALID_SOCKET);
    EXPECT_EQ(d_err(), WSAEFAULT);
    d_close(a); d_close(c); d_close(l.s);
}
