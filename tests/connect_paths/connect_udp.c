/* connect() on datagram sockets: an association with one peer, not a handshake.
 *
 * Measures: connect to a bound or unbound destination always succeeds; the peer filter on receive;
 * send() needs an association (WSAENOTCONN otherwise); re-connecting to another peer is allowed;
 * disconnecting by connecting to an all-zero address body (and the exact rules for what counts as
 * "all zero"); the ICMP-port-unreachable reset and its SIO_UDP_CONNRESET switch.  Loopback only.
 */
#include "cp.h"

#define WAIT_MS 3000

/* A zero sockaddr body of the given family, as many bytes as asked for. */
static void zero_addr(unsigned char *buf, int family)
{
    memset(buf, 0, 128);
    buf[0] = (unsigned char)(family & 0xFF);
    buf[1] = (unsigned char)((family >> 8) & 0xFF);
}

static SOCKET udp_unbound(void) { return cp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }

static int recv_ready(SOCKET s, char *b, int n, DWORD ms)
{
    if (!(cp_wait(s, CP_R, ms) & CP_R)) return -1000;
    return cp_recv(s, b, n, 0);
}

/* ---- establishing the association ------------------------------------------------------------ */

TEST(cpu_connect_to_bound_peer_succeeds_and_names_it)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CHECK(cp_peer_is(c, &pa));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_connect_binds_an_unbound_socket_implicitly)
{
    struct sockaddr_in pa, n;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    int nl = sizeof n;
    REQUIRE(U(connect)); NEED();
    CP_FAILS(cp_getsockname(c, (struct sockaddr *)&n, &nl), WSAEINVAL);
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(n.sin_family, AF_INET);
    CP_NE(n.sin_port, 0);
    CP_EQ(n.sin_addr.s_addr, cp_htonl(INADDR_LOOPBACK));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_connect_keeps_an_explicit_binding)
{
    struct sockaddr_in pa, b = cp_lo4(0), n;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    int nl = sizeof n;
    u_short port;
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_bind(c, (struct sockaddr *)&b, sizeof b), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    port = n.sin_port;
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    nl = sizeof n;
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(n.sin_port, port);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_connect_does_not_connect_the_other_side)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_peer_err(peer), WSAENOTCONN);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_connect_to_dead_port_succeeds)
{
    /* No handshake takes place, so a port nobody listens on is still a valid association. */
    struct sockaddr_in d;
    SOCKET c = udp_unbound();
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    CP_EQ(cp_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    CHECK(cp_peer_is(c, &d));
    cp_closesocket(c);
}

TEST(cpu_wsaconnect_matches_connect)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    REQUIRE(U(WSAConnect)); NEED();
    CP_EQ(cp_WSAConnect(c, (struct sockaddr *)&pa, sizeof pa, NULL, NULL, NULL, NULL), 0);
    CHECK(cp_peer_is(c, &pa));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_connect_to_own_address_succeeds)
{
    struct sockaddr_in a;
    SOCKET s = cp_udp_bound(&a);
    char b[4] = {0};
    int r;
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(s, (struct sockaddr *)&a, sizeof a), 0);
    CHECK(cp_peer_is(s, &a));
    CP_EQ(cp_send(s, "self", 4, 0), 4);
    r = recv_ready(s, b, 4, WAIT_MS);
    t_note("datagram sent to the socket's own address -> recv %d", r);
    cp_closesocket(s);
}

TEST(cpu_two_sockets_connected_to_each_other_exchange_datagrams)
{
    struct sockaddr_in aa, ba;
    SOCKET a = cp_udp_bound(&aa), b = cp_udp_bound(&ba);
    char buf[8] = {0};
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(a, (struct sockaddr *)&ba, sizeof ba), 0);
    CP_EQ(cp_connect(b, (struct sockaddr *)&aa, sizeof aa), 0);
    CP_EQ(cp_send(a, "ab", 2, 0), 2);
    CP_EQ(recv_ready(b, buf, sizeof buf, WAIT_MS), 2);
    CHECK(!memcmp(buf, "ab", 2));
    CP_EQ(cp_send(b, "cde", 3, 0), 3);
    CP_EQ(recv_ready(a, buf, sizeof buf, WAIT_MS), 3);
    CHECK(!memcmp(buf, "cde", 3));
    cp_closesocket(a); cp_closesocket(b);
}

/* ---- send / receive semantics of the association ---------------------------------------------- */

TEST(cpu_send_without_association_is_enotconn)
{
    SOCKET c = udp_unbound();
    REQUIRE(U(send)); NEED();
    CP_FAILS(cp_send(c, "data", 4, 0), WSAENOTCONN);
    cp_closesocket(c);
}

TEST(cpu_send_reaches_the_peer_from_the_local_name)
{
    struct sockaddr_in pa, n, from;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    char b[8] = {0};
    int nl = sizeof n, fl = sizeof from, r;
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(cp_send(c, "data", 4, 0), 4);
    CHECK(cp_wait(peer, CP_R, WAIT_MS) & CP_R);
    r = cp_recvfrom(peer, b, sizeof b, 0, (struct sockaddr *)&from, &fl);
    CP_EQ(r, 4);
    CHECK(!memcmp(b, "data", 4));
    CHECK(cp_same_addr(&from, &n));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_connected_socket_ignores_datagrams_from_strangers)
{
    struct sockaddr_in pa, ca;
    SOCKET peer = cp_udp_bound(&pa), stranger = cp_udp_bound(&ca), c = udp_unbound(), t;
    struct sockaddr_in n;
    int nl = sizeof n;
    char b[8] = {0};
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    /* the stranger writes first, then the real peer */
    CP_EQ(cp_sendto(stranger, "bad", 3, 0, (struct sockaddr *)&n, sizeof n), 3);
    CP_EQ(cp_sendto(peer, "good", 4, 0, (struct sockaddr *)&n, sizeof n), 4);
    CP_EQ(recv_ready(c, b, sizeof b, WAIT_MS), 4);
    CHECK(!memcmp(b, "good", 4));
    t = c;
    CP_EQ(cp_wait(t, CP_R, 300), 0);   /* the stranger's datagram was dropped, not queued */
    cp_closesocket(c); cp_closesocket(peer); cp_closesocket(stranger);
}

TEST(cpu_unconnected_socket_accepts_datagrams_from_anyone)
{
    struct sockaddr_in ra, pa, ca;
    SOCKET r = cp_udp_bound(&ra), p1 = cp_udp_bound(&pa), p2 = cp_udp_bound(&ca);
    char b[8];
    REQUIRE(U(sendto)); NEED();
    CP_EQ(cp_sendto(p1, "one", 3, 0, (struct sockaddr *)&ra, sizeof ra), 3);
    CP_EQ(cp_sendto(p2, "two", 3, 0, (struct sockaddr *)&ra, sizeof ra), 3);
    memset(b, 0, sizeof b);
    CP_EQ(recv_ready(r, b, sizeof b, WAIT_MS), 3);
    CP_EQ(recv_ready(r, b, sizeof b, WAIT_MS), 3);
    cp_closesocket(r); cp_closesocket(p1); cp_closesocket(p2);
}

TEST(cpu_sendto_on_connected_socket_note)
{
    struct sockaddr_in pa, oa;
    SOCKET peer = cp_udp_bound(&pa), other = cp_udp_bound(&oa), c = udp_unbound();
    int r;
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    cp_WSASetLastError(0);
    r = cp_sendto(c, "x", 1, 0, (struct sockaddr *)&oa, sizeof oa);
    t_note("sendto to a different address on a connected datagram socket -> %d (err %d)", r, r < 0 ? cp_WSAGetLastError() : 0);
    if (r == 1) {
        char b[2];
        t_note("the other socket received it: %d", recv_ready(other, b, sizeof b, 500) == 1);
    }
    cp_closesocket(c); cp_closesocket(peer); cp_closesocket(other);
}

TEST(cpu_peername_on_connected_datagram_socket_has_exact_size)
{
    struct sockaddr_in pa, p;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    int pl = sizeof p;
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_getpeername(c, (struct sockaddr *)&p, &pl), 0);
    CP_EQ(pl, sizeof p);
    CP_EQ(p.sin_family, AF_INET);
    cp_closesocket(c); cp_closesocket(peer);
}

/* ---- re-connecting ---------------------------------------------------------------------------- */

TEST(cpu_connect_twice_to_the_same_peer_is_allowed)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = udp_unbound();
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_WSAConnect(c, (struct sockaddr *)&pa, sizeof pa, NULL, NULL, NULL, NULL), 0);
    CHECK(cp_peer_is(c, &pa));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_reconnect_to_another_peer_replaces_the_association)
{
    struct sockaddr_in pa, qa, n;
    SOCKET p = cp_udp_bound(&pa), q = cp_udp_bound(&qa), c = udp_unbound();
    int nl = sizeof n;
    char b[8] = {0};
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&qa, sizeof qa), 0);
    CHECK(cp_peer_is(c, &qa));
    CP_EQ(cp_send(c, "to-q", 4, 0), 4);
    CP_EQ(recv_ready(q, b, sizeof b, WAIT_MS), 4);
    CP_EQ(cp_wait(p, CP_R, 300), 0);
    /* The old peer is now a stranger. */
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(cp_sendto(p, "old", 3, 0, (struct sockaddr *)&n, sizeof n), 3);
    CP_EQ(cp_wait(c, CP_R, 300), 0);
    cp_closesocket(c); cp_closesocket(p); cp_closesocket(q);
}

TEST(cpu_reconnect_keeps_the_local_port)
{
    struct sockaddr_in pa, qa, n1, n2;
    SOCKET p = cp_udp_bound(&pa), q = cp_udp_bound(&qa), c = udp_unbound();
    int l1 = sizeof n1, l2 = sizeof n2;
    REQUIRE(U(connect)); NEED();
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n1, &l1), 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&qa, sizeof qa), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n2, &l2), 0);
    CP_EQ(n1.sin_port, n2.sin_port);
    cp_closesocket(c); cp_closesocket(p); cp_closesocket(q);
}

/* ---- disconnecting ----------------------------------------------------------------------------- */

static SOCKET connected_udp(struct sockaddr_in *pa, SOCKET *peer)
{
    SOCKET c = udp_unbound();
    *peer = cp_udp_bound(pa);
    if (cp_connect(c, (struct sockaddr *)pa, sizeof *pa)) { cp_closesocket(c); return INVALID_SOCKET; }
    return c;
}

TEST(cpu_disconnect_with_unspec_zero_address)
{
    struct sockaddr_in pa;
    SOCKET peer, c;
    unsigned char z[128];
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    CHECK(c != INVALID_SOCKET);
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, sizeof(struct sockaddr_in)), 0);
    CP_EQ(cp_peer_err(c), WSAENOTCONN);
    CP_FAILS(cp_send(c, "x", 1, 0), WSAENOTCONN);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_disconnect_with_wsaconnect)
{
    struct sockaddr_in pa;
    SOCKET peer, c;
    unsigned char z[128];
    REQUIRE(U(WSAConnect)); NEED();
    c = connected_udp(&pa, &peer);
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_WSAConnect(c, (struct sockaddr *)z, 16, NULL, NULL, NULL, NULL), 0);
    CP_EQ(cp_peer_err(c), WSAENOTCONN);
    cp_closesocket(c); cp_closesocket(peer);
}

/* The provider only inspects the bytes after the family field: whatever family is claimed, a zero body
 * on a connected datagram socket is a disconnect. */
static const int g_zero_fams[] = { AF_UNSPEC, AF_INET, AF_INET6, AF_UNIX, 0x1234 };

TEST(cpu_disconnect_accepts_any_family_with_zero_body)
{
    size_t i;
    REQUIRE(U(connect)); NEED();
    for (i = 0; i < sizeof g_zero_fams / sizeof g_zero_fams[0]; i++) {
        struct sockaddr_in pa;
        SOCKET peer, c = connected_udp(&pa, &peer);
        unsigned char z[128];
        zero_addr(z, g_zero_fams[i]);
        cp_WSASetLastError(0);
        int r = cp_connect(c, (struct sockaddr *)z, 16);
        int e = cp_WSAGetLastError();
        t_check(r == 0, __FILE__, __LINE__, "zero body disconnects", "family 0x%x: ret %d err %d", g_zero_fams[i], r, e);
        t_check(cp_peer_err(c) == WSAENOTCONN, __FILE__, __LINE__, "disconnected", "family 0x%x", g_zero_fams[i]);
        cp_closesocket(c); cp_closesocket(peer);
    }
}

TEST(cpu_disconnect_ignores_bytes_beyond_the_address_length)
{
    /* Only the first 16 bytes (the AF_INET address size) are examined, however long the buffer claim is. */
    struct sockaddr_in pa;
    SOCKET peer, c;
    unsigned char z[128];
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    zero_addr(z, AF_UNSPEC);
    memset(z + 16, 0x5A, 112);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, 128), 0);
    CP_EQ(cp_peer_err(c), WSAENOTCONN);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_disconnect_needs_a_full_length_address)
{
    /* The length rule is applied first: 2..15 bytes is WSAEFAULT and the association survives. */
    static const int lens[] = { 2, 4, 8, 15 };
    struct sockaddr_in pa;
    SOCKET peer, c;
    unsigned char z[128];
    size_t i;
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    zero_addr(z, AF_UNSPEC);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++)
        CP_FAILS(cp_connect(c, (struct sockaddr *)z, lens[i]), WSAEFAULT);
    CHECK(cp_peer_is(c, &pa));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_disconnect_twice_second_one_is_wrong_family)
{
    struct sockaddr_in pa;
    SOCKET peer, c;
    unsigned char z[128];
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, 16), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)z, 16), WSAEAFNOSUPPORT);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_disconnect_local_name_note)
{
    struct sockaddr_in pa, n1, n2;
    SOCKET peer, c;
    unsigned char z[128];
    int l1 = sizeof n1, l2 = sizeof n2;
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n1, &l1), 0);
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, 16), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n2, &l2), 0);
    t_note("local port kept across the disconnect: %d", n1.sin_port == n2.sin_port);
    t_note("local address after disconnect: %s", n2.sin_addr.s_addr == 0 ? "wildcard" : "unchanged/other");
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_disconnected_socket_receives_from_anyone_again)
{
    struct sockaddr_in pa, sa, n;
    SOCKET peer, c, stranger;
    unsigned char z[128];
    int nl = sizeof n;
    char b[8] = {0};
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    stranger = cp_udp_bound(&sa);
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, 16), 0);
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&n, &nl), 0);
    n.sin_addr.s_addr = cp_htonl(INADDR_LOOPBACK);
    CP_EQ(cp_sendto(stranger, "hi", 2, 0, (struct sockaddr *)&n, sizeof n), 2);
    CP_EQ(recv_ready(c, b, sizeof b, WAIT_MS), 2);
    cp_closesocket(c); cp_closesocket(peer); cp_closesocket(stranger);
}

TEST(cpu_disconnected_socket_can_connect_again)
{
    struct sockaddr_in pa, qa;
    SOCKET peer, c, q = cp_udp_bound(&qa);
    unsigned char z[128];
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, 16), 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&qa, sizeof qa), 0);
    CHECK(cp_peer_is(c, &qa));
    cp_closesocket(c); cp_closesocket(peer); cp_closesocket(q);
}

TEST(cpu_nonzero_pad_byte_does_not_disconnect_note)
{
    /* A body that is zero except for sin_zero is not a disconnect request; record what happens. */
    struct sockaddr_in pa;
    SOCKET peer, c;
    unsigned char z[128];
    int r;
    REQUIRE(U(connect)); NEED();
    c = connected_udp(&pa, &peer);
    zero_addr(z, AF_INET);
    z[12] = 1;
    cp_WSASetLastError(0);
    r = cp_connect(c, (struct sockaddr *)z, 16);
    t_note("AF_INET 0.0.0.0:0 with a nonzero pad byte on a connected datagram socket -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpu_tcp_connected_socket_zero_address_is_eisconn)
{
    SOCKET c, s;
    unsigned char z[128];
    REQUIRE(U(connect)); NEED();
    CHECK(cp_pair(&c, &s));
    zero_addr(z, AF_UNSPEC);
    CP_FAILS(cp_connect(c, (struct sockaddr *)z, 16), WSAEISCONN);
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpu_tcp_unconnected_zero_address_is_wrong_family)
{
    SOCKET s;
    unsigned char z[128];
    REQUIRE(U(connect)); NEED();
    zero_addr(z, AF_UNSPEC);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)z, 16), WSAEAFNOSUPPORT);
    cp_closesocket(s);
}

/* ---- ICMP port unreachable and the reset switch -------------------------------------------------- */

TEST(cpu_connected_send_to_dead_port_resets_next_receive)
{
    struct sockaddr_in d;
    SOCKET c = udp_unbound();
    char b[8];
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    CP_EQ(cp_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    CP_EQ(cp_send(c, "ping", 4, 0), 4);
    if (!(cp_wait(c, CP_R, WAIT_MS) & CP_R)) {
        cp_closesocket(c);
        t_skip("no port-unreachable indication arrived on loopback");
        return;
    }
    CP_FAILS(cp_recv(c, b, sizeof b, 0), WSAECONNRESET);
    cp_closesocket(c);
}

TEST(cpu_connreset_is_reported_once)
{
    struct sockaddr_in d;
    SOCKET c = udp_unbound();
    char b[8];
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    CP_EQ(cp_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    CP_EQ(cp_send(c, "ping", 4, 0), 4);
    if (!(cp_wait(c, CP_R, WAIT_MS) & CP_R)) { cp_closesocket(c); t_skip("no port-unreachable indication"); return; }
    CP_FAILS(cp_recv(c, b, sizeof b, 0), WSAECONNRESET);
    CP_EQ(cp_wait(c, CP_R, 300), 0);   /* the condition was consumed */
    cp_closesocket(c);
}

TEST(cpu_connreset_switch_off_suppresses_the_indication)
{
    struct sockaddr_in d;
    SOCKET c = udp_unbound();
    BOOL off = FALSE;
    DWORD got = 0;
    REQUIRE(U(connect)); REQUIRE(U(WSAIoctl)); NEED();
    CHECK(cp_dead_port(&d));
    if (cp_WSAIoctl(c, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &got, NULL, NULL)) {
        cp_closesocket(c);
        t_skip("SIO_UDP_CONNRESET not accepted (err %d)", cp_WSAGetLastError());
        return;
    }
    CP_EQ(cp_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    CP_EQ(cp_send(c, "ping", 4, 0), 4);
    CP_EQ(cp_wait(c, CP_R, 800), 0);   /* nothing becomes readable */
    {
        char b[8];
        cp_nb(c, 1);
        CP_FAILS(cp_recv(c, b, sizeof b, 0), WSAEWOULDBLOCK);
    }
    cp_closesocket(c);
}

TEST(cpu_unconnected_send_to_dead_port_does_not_reset)
{
    /* The ICMP indication is only delivered to a socket with an association; with sendto() it is not. */
    struct sockaddr_in d;
    SOCKET c = udp_unbound();
    REQUIRE(U(sendto)); NEED();
    CHECK(cp_dead_port(&d));
    CP_EQ(cp_sendto(c, "ping", 4, 0, (struct sockaddr *)&d, sizeof d), 4);
    t_note("readable after sendto to a dead port: %d", (cp_wait(c, CP_R, 800) & CP_R) != 0);
    cp_closesocket(c);
}

/* ---- destinations needing care ------------------------------------------------------------------- */

TEST(cpu_connect_to_limited_broadcast_without_so_broadcast_note)
{
    struct sockaddr_in b = cp_lo4(cp_ns(9));
    SOCKET c = udp_unbound();
    int r;
    REQUIRE(U(connect)); NEED();
    b.sin_addr.s_addr = 0xFFFFFFFF;
    cp_WSASetLastError(0);
    r = cp_connect(c, (struct sockaddr *)&b, sizeof b);
    t_note("UDP connect to 255.255.255.255 without SO_BROADCAST -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    cp_closesocket(c);
}

/* ---- IPv6 datagram association -------------------------------------------------------------------- */

TEST(cpu_v6_connect_and_disconnect)
{
    struct sockaddr_in6 pa = cp_lo6(0), n;
    SOCKET peer = cp_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), c;
    int nl = sizeof pa, pl;
    unsigned char z[128];
    struct sockaddr_in6 p;
    REQUIRE(U(connect)); NEED();
    if (peer == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; }
    if (cp_bind(peer, (struct sockaddr *)&pa, sizeof pa) || cp_getsockname(peer, (struct sockaddr *)&pa, &nl)) {
        cp_closesocket(peer);
        t_skip("IPv6 loopback unavailable");
        return;
    }
    c = cp_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    CP_EQ(cp_connect(c, (struct sockaddr *)&pa, sizeof pa), 0);
    pl = sizeof p;
    CP_EQ(cp_getpeername(c, (struct sockaddr *)&p, &pl), 0);
    CP_EQ(p.sin6_port, pa.sin6_port);
    /* The zero-body rule uses the family's own address size (28 here). */
    zero_addr(z, AF_UNSPEC);
    CP_EQ(cp_connect(c, (struct sockaddr *)z, 28), 0);
    pl = sizeof p;
    CP_FAILS(cp_getpeername(c, (struct sockaddr *)&p, &pl), WSAENOTCONN);
    (void)n;
    cp_closesocket(c); cp_closesocket(peer);
}
