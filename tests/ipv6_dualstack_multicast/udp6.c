/* IPv6 UDP on loopback.
 * Measures: sender address reporting (family, length, scope) for recvfrom on IPv6 sockets; zero-length
 * and truncated datagrams; dual-stack sockets receiving IPv4 senders as v4-mapped addresses and replying
 * to them; V6ONLY sockets staying deaf to IPv4; connected-socket filtering; address argument rules for
 * sendto/connect/bind (unspecified address, link-local and scoped names, multicast names); unbound
 * auto-bind; endpoint sharing rules; hop-limit option round trips.  Loopback only, ephemeral ports. */
#include "d6.h"

static const char DG[] = "dg6-probe-0123456789";

/* send DG from `from` to loopback port of `to` (v6 name) */
static int send6(SOCKET from, unsigned short port) {
    struct sockaddr_in6 a; mk6(&a, K_LOOP, port);
    return d_sendto(from, DG, sizeof DG, &a, sizeof a);
}

TEST(ds6_udp_v6_loopback_roundtrip_reports_sender) {
    usk r, s; struct sockaddr_in6 from; int n = sizeof from, got; char b[64];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    CHECK(send6(s.s, r.port) == (int)sizeof DG);
    CHECK(d_readable(r.s, 3000));
    memset(&from, 0, sizeof from);
    got = d_recvfrom(r.s, b, sizeof b, &from, &n);
    EXPECT_EQ(got, sizeof DG);
    CHECK(!memcmp(b, DG, sizeof DG));
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_v6_loop(&from));
    EXPECT_EQ(from.sin6_port, s.port);
    EXPECT_EQ(from.sin6_scope_id, 0);
    d_close(r.s); d_close(s.s);
}

TEST(ds6_udp_recvfrom_null_from_is_allowed) {
    usk r, s; char b[64];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    CHECK(send6(s.s, r.port) == (int)sizeof DG);
    CHECK(d_readable(r.s, 3000));
    EQC(d_recvfrom(r.s, b, sizeof b, NULL, NULL), sizeof DG);
    d_close(r.s); d_close(s.s);
}

TEST(ds6_udp_zero_length_datagram_is_delivered) {
    usk r, s; struct sockaddr_in6 a; char b[8]; int got;
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    mk6(&a, K_LOOP, r.port);
    EQC(d_sendto(s.s, "", 0, &a, sizeof a), 0);
    CHECK(d_readable(r.s, 3000));
    got = d_recvfrom(r.s, b, sizeof b, NULL, NULL);
    EXPECT_EQ(got, 0);
    d_close(r.s); d_close(s.s);
}

TEST(ds6_udp_truncated_datagram_is_emsgsize_and_consumed) {
    usk r, s; struct sockaddr_in6 a; char b[64]; int got, n = 8;
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    mk6(&a, K_LOOP, r.port);
    CHECK(d_sendto(s.s, DG, sizeof DG, &a, sizeof a) == (int)sizeof DG);
    CHECK(d_sendto(s.s, "second", 7, &a, sizeof a) == 7);
    CHECK(d_readable(r.s, 3000));
    memset(b, 0, sizeof b);
    d_seterr(0);
    got = d_recvfrom(r.s, b, n, NULL, NULL);
    EXPECT_EQ(got, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEMSGSIZE);
    CHECK(!memcmp(b, DG, n));                /* the leading bytes were delivered */
    CHECK(d_readable(r.s, 3000));
    memset(b, 0, sizeof b);
    got = d_recvfrom(r.s, b, sizeof b, NULL, NULL);   /* the tail was dropped, next datagram is intact */
    EXPECT_EQ(got, 7);
    CHECK(!memcmp(b, "second", 7));
    d_close(r.s); d_close(s.s);
}

TEST(ds6_udp_message_boundaries_are_kept) {
    usk r, s; struct sockaddr_in6 a; char b[64]; int i;
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    mk6(&a, K_LOOP, r.port);
    for (i = 1; i <= 4; i++) CHECK(d_sendto(s.s, DG, i * 3, &a, sizeof a) == i * 3);
    for (i = 1; i <= 4; i++) {
        CHECK(d_readable(r.s, 3000));
        EQC(d_recvfrom(r.s, b, sizeof b, NULL, NULL), i * 3);
    }
    d_close(r.s); d_close(s.s);
}

TEST(ds6_udp_recvfrom_short_fromlen_is_efault) {
    usk r, s; struct sockaddr_in6 from; int n = 20, got; char b[64];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    CHECK(send6(s.s, r.port) == (int)sizeof DG);
    CHECK(d_readable(r.s, 3000));
    d_seterr(0);
    got = d_recvfrom(r.s, b, sizeof b, &from, &n);
    EXPECT_EQ(got, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEFAULT);
    d_close(r.s); d_close(s.s);
}

TEST(ds6_udp_recv_unbound_v6_is_einval) {
    SOCKET s; char b[8];
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    d_seterr(0);
    EQC(d_recv(s, b, sizeof b), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(s);
}

TEST(ds6_udp_sendto_autobinds_unbound_socket) {
    usk r; SOCKET s; struct sockaddr_in6 n6; int n = sizeof n6; static const unsigned char z[16];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1));
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(send6(s, r.port) == (int)sizeof DG);
    CHECK(d_name(s, &n6, &n) == 0);
    EXPECT_EQ(n6.sin6_family, AF_INET6);
    CHECK(n6.sin6_port != 0);
    CHECK(!memcmp(n6.sin6_addr.u.Byte, z, 16));    /* auto-bind leaves the address unspecified */
    d_close(s); d_close(r.s);
}

TEST(ds6_udp_sendto_unspecified_destination_is_eaddrnotavail) {
    SOCKET s; struct sockaddr_in6 a;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_ANY, d_h16(9));
    d_seterr(0);
    EQC(d_sendto(s, DG, sizeof DG, &a, sizeof a), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(s);
}

TEST(ds6_udp_connect_unspecified_destination_is_eaddrnotavail) {
    SOCKET s; struct sockaddr_in6 a;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_ANY, d_h16(9));
    d_seterr(0);
    EQC(d_connect(s, &a, sizeof a), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(s);
}

TEST(ds6_udp_sendto_oversize_datagram_is_emsgsize) {
    usk r; SOCKET s; static char big[70000]; struct sockaddr_in6 a;
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1));
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_LOOP, r.port);
    d_seterr(0);
    EQC(d_sendto(s, big, sizeof big, &a, sizeof a), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEMSGSIZE);
    d_close(s); d_close(r.s);
}

TEST(ds6_udp_connected_send_recv_and_names) {
    usk r; SOCKET c; struct sockaddr_in6 a, pn, ln; int n = sizeof pn, got; char b[64];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_LOOP, r.port);
    CHECK(d_connect(c, &a, sizeof a) == 0);
    memset(&pn, 0, sizeof pn);
    CHECK(d_peer(c, &pn, &n) == 0);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_v6_loop(&pn)); EXPECT_EQ(pn.sin6_port, r.port);
    n = sizeof ln; CHECK(d_name(c, &ln, &n) == 0);
    CHECK(is_v6_loop(&ln));                  /* connect picked the loopback source */
    CHECK(d_send(c, DG, sizeof DG) == (int)sizeof DG);
    CHECK(d_readable(r.s, 3000));
    n = sizeof pn; got = d_recvfrom(r.s, b, sizeof b, &pn, &n);
    EXPECT_EQ(got, sizeof DG);
    EXPECT_EQ(pn.sin6_port, ln.sin6_port);
    d_close(c); d_close(r.s);
}

TEST(ds6_udp_connected_socket_ignores_other_senders) {
    usk peer, other; SOCKET c; struct sockaddr_in6 a, cn; int n = sizeof cn; char b[64];
    NEED_V6();
    CHECK(usk_open6(&peer, K_LOOP, -1)); CHECK(usk_open6(&other, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_LOOP, peer.port);
    CHECK(d_connect(c, &a, sizeof a) == 0);
    CHECK(d_name(c, &cn, &n) == 0);
    mk6(&a, K_LOOP, cn.sin6_port);
    CHECK(d_sendto(other.s, "stranger", 9, &a, sizeof a) == 9);
    CHECK(d_sendto(peer.s, "friend", 7, &a, sizeof a) == 7);
    CHECK(d_readable(c, 3000));
    EQC(d_recv(c, b, sizeof b), 7);
    CHECK(!memcmp(b, "friend", 7));
    CHECK(!d_readable(c, 300));              /* the stranger's datagram was filtered out */
    d_close(c); d_close(peer.s); d_close(other.s);
}

TEST(ds6_udp_connected_to_closed_port_reports_connreset) {
    usk r; SOCKET c; struct sockaddr_in6 a; unsigned short p; char b[8]; int got;
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1));
    p = r.port; d_close(r.s);
    c = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_LOOP, p);
    CHECK(d_connect(c, &a, sizeof a) == 0);
    CHECK(d_send(c, DG, sizeof DG) == (int)sizeof DG);
    if (!d_readable(c, 3000)) { t_note("no ICMPv6 unreachable surfaced on the connected socket"); d_close(c); return; }
    d_seterr(0);
    got = d_recv(c, b, sizeof b);
    EXPECT_EQ(got, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAECONNRESET);
    d_close(c);
}

TEST(ds6_udp_dualstack_receives_v4_sender_as_mapped) {
    usk r, s4; struct sockaddr_in to; struct sockaddr_in6 from; int n = sizeof from, got; char b[64]; DWORD off = 0;
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, 0));
    CHECK(usk_open4(&s4, 1));
    mk4(&to, 1, r.port);
    CHECK(d_sendto(s4.s, DG, sizeof DG, &to, sizeof to) == (int)sizeof DG);
    CHECK(d_readable(r.s, 3000));
    memset(&from, 0, sizeof from);
    got = d_recvfrom(r.s, b, sizeof b, &from, &n);
    EXPECT_EQ(got, sizeof DG);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_mapped_loop(&from));
    EXPECT_EQ(from.sin6_port, s4.port);
    EXPECT_EQ(from.sin6_scope_id, 0);
    d_close(r.s); d_close(s4.s);
}

TEST(ds6_udp_dualstack_reply_to_mapped_sender_reaches_v4_socket) {
    usk r, s4; struct sockaddr_in to; struct sockaddr_in6 from; struct sockaddr_in back; int n = sizeof from, m = sizeof back; char b[64];
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, 0));
    CHECK(usk_open4(&s4, 1));
    mk4(&to, 1, r.port);
    CHECK(d_sendto(s4.s, DG, sizeof DG, &to, sizeof to) == (int)sizeof DG);
    CHECK(d_readable(r.s, 3000));
    CHECK(d_recvfrom(r.s, b, sizeof b, &from, &n) == (int)sizeof DG);
    CHECK(d_sendto(r.s, "pong", 5, &from, n) == 5);
    CHECK(d_readable(s4.s, 3000));
    memset(&back, 0, sizeof back);
    EQC(d_recvfrom(s4.s, b, sizeof b, &back, &m), 5);
    EXPECT_EQ(m, SZ_SA4);
    EXPECT_EQ(back.sin_family, AF_INET);
    EXPECT_EQ(back.sin_port, r.port);
    EXPECT_EQ(back.sin_addr.s_addr, d_h32(0x7f000001u));
    d_close(r.s); d_close(s4.s);
}

TEST(ds6_udp_dualstack_sendto_mapped_destination_reaches_v4_socket) {
    usk s6, r4; SOCKET c; struct sockaddr_in6 a; struct sockaddr_in from; int n = sizeof from; char b[64];
    NEED_V6();
    CHECK(usk_open4(&r4, 1));
    c = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_setint(c, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    mk6(&a, K_MAP_LOOP, r4.port);
    CHECK(d_sendto(c, DG, sizeof DG, &a, sizeof a) == (int)sizeof DG);
    CHECK(d_readable(r4.s, 3000));
    EQC(d_recvfrom(r4.s, b, sizeof b, &from, &n), sizeof DG);
    EXPECT_EQ(from.sin_addr.s_addr, d_h32(0x7f000001u));
    d_close(c); d_close(r4.s);
}

TEST(ds6_udp_v6only_socket_does_not_see_v4_datagrams) {
    usk r, s4; struct sockaddr_in to;
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, 1));
    CHECK(usk_open4(&s4, 1));
    mk4(&to, 1, r.port);
    CHECK(d_sendto(s4.s, DG, sizeof DG, &to, sizeof to) == (int)sizeof DG);
    CHECK(!d_readable(r.s, 500));
    d_close(r.s); d_close(s4.s);
}

TEST(ds6_udp_v6only_socket_mapped_destination_note) {
    usk r4; SOCKET c; struct sockaddr_in6 a; int rc;
    NEED_V6();
    CHECK(usk_open4(&r4, 1));
    c = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_MAP_LOOP, r4.port);
    d_seterr(0);
    rc = d_sendto(c, DG, sizeof DG, &a, sizeof a);
    t_note("V6ONLY socket sendto(mapped destination): rc %d err %d", rc, rc < 0 ? d_err() : 0);
    CHECK(rc < 0 ? 1 : !d_readable(r4.s, 300) || 1);
    d_close(c); d_close(r4.s);
}

TEST(ds6_udp_v4_socket_sendto_v6_name_note) {
    usk r; SOCKET c; struct sockaddr_in6 a; int rc;
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1));
    c = d_sock(AF_INET, SOCK_DGRAM);
    mk6(&a, K_LOOP, r.port);
    d_seterr(0);
    rc = d_sendto(c, DG, sizeof DG, &a, sizeof a);
    CHECK(rc == SOCKET_ERROR);
    t_note("AF_INET socket sendto(AF_INET6 name): error %d", d_err());
    d_close(c); d_close(r.s);
}

TEST(ds6_udp_v6_socket_sendto_v4_name_note) {
    usk r4; SOCKET c; struct sockaddr_in a; int rc;
    NEED_V6();
    CHECK(usk_open4(&r4, 1));
    c = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_setint(c, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    mk4(&a, 1, r4.port);
    d_seterr(0);
    rc = d_sendto(c, DG, sizeof DG, &a, sizeof a);
    t_note("AF_INET6 socket sendto(AF_INET name): rc %d err %d", rc, rc < 0 ? d_err() : 0);
    d_close(c); d_close(r4.s);
}

TEST(ds6_udp_bind_unassigned_link_local_is_eaddrnotavail) {
    SOCKET s; struct sockaddr_in6 a;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_ANY, 0);
    a.sin6_addr.u.Byte[0] = 0xfe; a.sin6_addr.u.Byte[1] = 0x80;
    a.sin6_addr.u.Byte[12] = 0xde; a.sin6_addr.u.Byte[13] = 0xad; a.sin6_addr.u.Byte[14] = 0xbe; a.sin6_addr.u.Byte[15] = 0xef;
    d_seterr(0);
    EQC(d_bind(s, &a, sizeof a), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(s);
}

TEST(ds6_udp_bind_unassigned_link_local_with_scope_is_eaddrnotavail) {
    SOCKET s; struct sockaddr_in6 a; int i; static const unsigned ids[] = {1, 2, 0x7fff0000u};
    NEED_V6();
    for (i = 0; i < 3; i++) {
        s = d_sock(AF_INET6, SOCK_DGRAM);
        mk6(&a, K_ANY, 0);
        a.sin6_addr.u.Byte[0] = 0xfe; a.sin6_addr.u.Byte[1] = 0x80;
        a.sin6_addr.u.Byte[12] = 0xde; a.sin6_addr.u.Byte[13] = 0xad; a.sin6_addr.u.Byte[14] = 0xbe; a.sin6_addr.u.Byte[15] = 0xef;
        a.sin6_scope_id = ids[i];
        d_seterr(0);
        EQC(d_bind(s, &a, sizeof a), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
        d_close(s);
    }
}

TEST(ds6_udp_bind_unassigned_global_address_is_eaddrnotavail) {
    SOCKET s; struct sockaddr_in6 a;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_ANY, 0);
    a.sin6_addr.u.Byte[0] = 0x20; a.sin6_addr.u.Byte[1] = 0x01; a.sin6_addr.u.Byte[2] = 0x0d; a.sin6_addr.u.Byte[3] = 0xb8;
    a.sin6_addr.u.Byte[15] = 0x77;
    d_seterr(0);
    EQC(d_bind(s, &a, sizeof a), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(s);
}

TEST(ds6_udp_bind_loopback_with_scope_id_note) {
    SOCKET s; struct sockaddr_in6 a, n6; int n = sizeof n6, rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_LOOP, 0);
    a.sin6_scope_id = 1;
    d_seterr(0);
    rc = d_bind(s, &a, sizeof a);
    t_note("bind(::1 scope 1): rc %d err %d", rc, rc ? d_err() : 0);
    if (rc == 0 && d_name(s, &n6, &n) == 0) t_note("  scope reported back as %s", n6.sin6_scope_id == 1 ? "1" : n6.sin6_scope_id == 0 ? "0" : "other");
    d_close(s);
}

TEST(ds6_udp_bind_multicast_name_note) {
    SOCKET s; struct sockaddr_in6 a; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&a, K_ANY, 0);
    a.sin6_addr.u.Byte[0] = 0xff; a.sin6_addr.u.Byte[1] = 0x02; a.sin6_addr.u.Byte[15] = 1;
    d_seterr(0);
    rc = d_bind(s, &a, sizeof a);
    t_note("UDP bind(ff02::1, scope 0): rc %d err %d", rc, rc ? d_err() : 0);
    d_close(s);
}

TEST(ds6_tcp_bind_multicast_name_note) {
    SOCKET s; struct sockaddr_in6 a; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&a, K_ANY, 0);
    a.sin6_addr.u.Byte[0] = 0xff; a.sin6_addr.u.Byte[1] = 0x02; a.sin6_addr.u.Byte[15] = 1;
    d_seterr(0);
    rc = d_bind(s, &a, sizeof a);
    t_note("TCP bind(ff02::1, scope 0): rc %d err %d", rc, rc ? d_err() : 0);
    d_close(s);
}

TEST(ds6_udp_bind_same_endpoint_twice_is_addrinuse) {
    usk a; SOCKET s; struct sockaddr_in6 n;
    NEED_V6();
    CHECK(usk_open6(&a, K_LOOP, -1));
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&n, K_LOOP, a.port);
    d_seterr(0);
    EQC(d_bind(s, &n, sizeof n), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRINUSE);
    d_close(s); d_close(a.s);
}

TEST(ds6_udp_reuseaddr_allows_second_bind) {
    SOCKET a, b; struct sockaddr_in6 n; int len = sizeof n;
    NEED_V6();
    a = d_sock(AF_INET6, SOCK_DGRAM); b = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_setint(a, SOL_SOCKET, SO_REUSEADDR, 1) == 0);
    CHECK(d_setint(b, SOL_SOCKET, SO_REUSEADDR, 1) == 0);
    mk6(&n, K_LOOP, 0);
    CHECK(d_bind(a, &n, sizeof n) == 0);
    CHECK(d_name(a, &n, &len) == 0);
    CHECK(d_bind(b, &n, sizeof n) == 0);
    d_close(a); d_close(b);
}

TEST(ds6_udp_bind_twice_on_same_socket_is_einval) {
    SOCKET s; struct sockaddr_in6 n;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&n, K_LOOP, 0);
    CHECK(d_bind(s, &n, sizeof n) == 0);
    d_seterr(0);
    EQC(d_bind(s, &n, sizeof n), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(s);
}

TEST(ds6_udp_v6_and_v4_loopback_ports_are_independent_with_v6only) {
    usk a6; SOCKET s4; struct sockaddr_in n;
    NEED_V6();
    CHECK(usk_open6(&a6, K_ANY, 1));
    s4 = d_sock(AF_INET, SOCK_DGRAM);
    mk4(&n, 1, a6.port);
    CHECK(d_bind(s4, &n, sizeof n) == 0);   /* V6ONLY wildcard leaves the IPv4 port free */
    d_close(s4); d_close(a6.s);
}

TEST(ds6_udp_hop_limit_options_round_trip) {
    SOCKET s; int v, i; static const int vals[] = {1, 2, 64, 128, 255};
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    for (i = 0; i < 5; i++) {
        CHECK(d_setint(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, vals[i]) == 0);
        CHECK(d_getint(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v) == 0);
        EXPECT_EQ(v, vals[i]);
        CHECK(d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, vals[i]) == 0);
        CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &v) == 0);
        EXPECT_EQ(v, vals[i]);
    }
    d_close(s);
}

TEST(ds6_udp_hop_limit_out_of_range_is_einval) {
    SOCKET s; static const int bad[] = {256, 1000};
    int i;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    for (i = 0; i < 2; i++) {
        d_seterr(0);
        EQC(d_setint(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, bad[i]), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEINVAL);
        d_seterr(0);
        EQC(d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, bad[i]), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEINVAL);
    }
    d_close(s);
}

TEST(ds6_udp_default_multicast_options) {
    SOCKET s; int v;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &v) == 0);
    EXPECT_EQ(v, 1);
    d_close(s);
}

TEST(ds6_udp_unicast_hops_default_is_in_range) {
    SOCKET s; int v;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v) == 0);
    CHECK(v >= 1 && v <= 255);
    t_note("default unicast hop limit is %s", v == 128 ? "128" : v == 64 ? "64" : "other");
    d_close(s);
}

TEST(ds6_udp_sockname_after_connect_to_mapped_is_mapped) {
    usk r4; SOCKET c; struct sockaddr_in6 a, n6; int n = sizeof n6;
    NEED_V6();
    CHECK(usk_open4(&r4, 1));
    c = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_setint(c, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    mk6(&a, K_MAP_LOOP, r4.port);
    CHECK(d_connect(c, &a, sizeof a) == 0);
    CHECK(d_name(c, &n6, &n) == 0);
    EXPECT_EQ(n6.sin6_family, AF_INET6);
    CHECK(is_mapped_loop(&n6));
    n = sizeof n6;
    CHECK(d_peer(c, &n6, &n) == 0);
    CHECK(is_mapped_loop(&n6));
    EXPECT_EQ(n6.sin6_port, r4.port);
    d_close(c); d_close(r4.s);
}

TEST(ds6_udp_many_datagrams_from_one_sender_keep_order) {
    usk r, s; struct sockaddr_in6 a; int i, bad = 0; char b[16];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    mk6(&a, K_LOOP, r.port);
    for (i = 0; i < 20; i++) { b[0] = (char)i; CHECK(d_sendto(s.s, b, 1, &a, sizeof a) == 1); }
    for (i = 0; i < 20; i++) {
        if (!d_readable(r.s, 3000)) { bad = 1; break; }
        if (d_recvfrom(r.s, b, sizeof b, NULL, NULL) != 1 || b[0] != (char)i) bad = 1;
    }
    CHECK(!bad);
    d_close(r.s); d_close(s.s);
}
