/* listen(): which socket states and types can listen, backlog values, repeated calls, and the effect on the
 * socket's other operations.
 *
 * Measures: a closed handle is WSAENOTSOCK; a datagram socket is WSAEOPNOTSUPP whether unbound, bound or
 * connected; a stream socket that is not bound is WSAEINVAL; a connected stream socket is WSAEISCONN; a
 * bound stream socket listens for any non-negative backlog, for SOMAXCONN and for the SOMAXCONN_HINT form,
 * and listening twice is not an error; listening is observable through SO_ACCEPTCONN, still accepts
 * connections afterwards and closes the door on bind().
 */
#include "bla.h"

TEST(bla_listen_closed_socket_is_notsock)
{
    SOCKET s;
    NEED();
    s = tcp();
    EQ(cls(s), 0);
    FAILS(lsn(s, 1), WSAENOTSOCK);
    FAILS(lsn(s, 0), WSAENOTSOCK);
    FAILS(lsn(s, -1), WSAENOTSOCK);
}

TEST(bla_listen_invalid_handle_ignores_backlog)
{
    static const int backs[] = { 0, 1, SOMAXCONN, -1, 0x7fffffff, (int)0x80000000 };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof backs / sizeof backs[0]; i++) {
        FAILS(lsn(INVALID_SOCKET, backs[i]), WSAENOTSOCK);
        FAILS(lsn((SOCKET)0x1234, backs[i]), WSAENOTSOCK);
    }
}

/* ---- socket type ---- */

TEST(bla_listen_udp_unbound_is_opnotsupp)
{
    SOCKET s;
    NEED();
    s = udp();
    FAILS(lsn(s, 1), WSAEOPNOTSUPP);
    cls(s);
}

TEST(bla_listen_udp_bound_is_opnotsupp)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = udp();
    EQ(bind_lo(s, &a), 0);
    FAILS(lsn(s, 1), WSAEOPNOTSUPP);
    FAILS(lsn(s, SOMAXCONN), WSAEOPNOTSUPP);
    cls(s);
}

TEST(bla_listen_udp_connected_is_opnotsupp)
{
    struct sockaddr_in t;
    SOCKET s, u;
    NEED();
    u = udp();
    EQ(bind_lo(u, &t), 0);
    s = udp();
    EQ(con(s, &t, sizeof t), 0);
    FAILS(lsn(s, 1), WSAEOPNOTSUPP);
    cls(s); cls(u);
}

TEST(bla_listen_udp_type_check_precedes_backlog)
{
    SOCKET s;
    NEED();
    s = udp();
    FAILS(lsn(s, -1), WSAEOPNOTSUPP);
    FAILS(lsn(s, 0), WSAEOPNOTSUPP);
    cls(s);
}

TEST(bla_listen_udp_v6_is_opnotsupp)
{
    SOCKET s;
    NEED(); NEED6();
    s = udp6();
    FAILS(lsn(s, 1), WSAEOPNOTSUPP);
    cls(s);
}

/* ---- state ---- */

TEST(bla_listen_unbound_tcp_is_einval_for_every_backlog)
{
    static const int backs[] = { 0, 1, 2, 5, 200, SOMAXCONN, -1, -2, SOMAXCONN_HINT(100) };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof backs / sizeof backs[0]; i++) {
        SOCKET s = tcp();
        FAILS(lsn(s, backs[i]), WSAEINVAL);
        cls(s);
    }
}

TEST(bla_listen_unbound_v6_is_einval)
{
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    FAILS(lsn(s, 1), WSAEINVAL);
    cls(s);
}

TEST(bla_listen_failed_bind_leaves_socket_unlistenable)
{
    struct sockaddr_in a;
    SOCKET s1, s2;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(bind_lo(s1, &a), 0);
    FAILS(bnd(s2, &a, sizeof a), WSAEADDRINUSE);
    FAILS(lsn(s2, 1), WSAEINVAL);
    cls(s1); cls(s2);
}

TEST(bla_listen_connected_client_is_eisconn)
{
    struct sockaddr_in a;
    SOCKET l, c;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    CHECK(c != INVALID_SOCKET);
    FAILS(lsn(c, 1), WSAEISCONN);
    cls(c); cls(l);
}

TEST(bla_listen_accepted_socket_is_eisconn)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        FAILS(lsn(s, 1), WSAEISCONN);
        cls(s);
    }
    cls(c); cls(l);
}

TEST(bla_listen_connected_state_precedes_backlog_value)
{
    struct sockaddr_in a;
    SOCKET l, c;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    FAILS(lsn(c, 0), WSAEISCONN);
    FAILS(lsn(c, SOMAXCONN), WSAEISCONN);
    cls(c); cls(l);
}

TEST(bla_listen_after_refused_connect_is_not_eisconn)
{
    struct sockaddr_in dst = dead_port();
    SOCKET s;
    NEED();
    s = tcp();
    CHECK(con(s, &dst, sizeof dst) == SOCKET_ERROR);
    wset(0x5a5a);
    if (lsn(s, 1) == 0) t_note("listen after a refused connect succeeded");
    else t_note("listen after a refused connect -> %s", werr_class(werr()));
    cls(s);
}

TEST(bla_listen_after_shutdown_of_unconnected_socket)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    wset(0x5a5a);
    if (U(shutdown)(s, SD_BOTH) == 0) {
        wset(0x5a5a);
        if (lsn(s, 1) == 0) t_note("listen after shutdown of a bound socket succeeded");
        else t_note("listen after shutdown of a bound socket -> %s", werr_class(werr()));
    } else {
        t_note("shutdown of a bound unconnected socket -> %s", werr() == WSAENOTCONN ? "NOTCONN" : werr_class(werr()));
    }
    cls(s);
}

/* ---- backlog values ---- */

static void listen_and_serve(int backlog)
{
    struct sockaddr_in a;
    SOCKET s = tcp(), c, d;
    EQ(bind_lo(s, &a), 0);
    wset(0x5a5a);
    EQ(lsn(s, backlog), 0);
    c = dial(&a);
    CHECK(c != INVALID_SOCKET);
    d = acc_wait(s, NULL, NULL, 3000);
    CHECK(d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) cls(d);
    if (c != INVALID_SOCKET) cls(c);
    cls(s);
}
#define BACKLOG(nm, v) TEST(bla_listen_backlog_##nm) { NEED(); listen_and_serve(v); }
BACKLOG(0, 0)
BACKLOG(1, 1)
BACKLOG(2, 2)
BACKLOG(5, 5)
BACKLOG(128, 128)
BACKLOG(somaxconn, SOMAXCONN)
BACKLOG(int_max, 0x7fffffff)
BACKLOG(hint_1, SOMAXCONN_HINT(1))
BACKLOG(hint_100, SOMAXCONN_HINT(100))
BACKLOG(hint_200, SOMAXCONN_HINT(200))
BACKLOG(hint_65535, SOMAXCONN_HINT(65535))

static void listen_negative(int backlog, const char *what)
{
    struct sockaddr_in a;
    SOCKET s = tcp(), c, d;
    EQ(bind_lo(s, &a), 0);
    wset(0x5a5a);
    if (lsn(s, backlog) != 0) {
        t_note("%s -> %s", what, werr_class(werr()));
    } else {
        t_note("%s accepted", what);
        c = dial(&a);
        d = acc_wait(s, NULL, NULL, 3000);
        CHECK(c != INVALID_SOCKET && d != INVALID_SOCKET);
        if (d != INVALID_SOCKET) cls(d);
        if (c != INVALID_SOCKET) cls(c);
    }
    cls(s);
}
TEST(bla_listen_backlog_minus_one_recorded)  { NEED(); listen_negative(-1, "backlog -1"); }
TEST(bla_listen_backlog_minus_two_recorded)  { NEED(); listen_negative(-2, "backlog -2"); }
TEST(bla_listen_backlog_int_min_recorded)    { NEED(); listen_negative((int)0x80000000, "backlog INT_MIN"); }

TEST(bla_listen_twice_same_backlog)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    EQ(lsn(s, 5), 0);
    EQ(lsn(s, 5), 0);
    cls(s);
}

TEST(bla_listen_twice_different_backlog_keeps_serving)
{
    struct sockaddr_in a;
    SOCKET s, c, d;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    EQ(lsn(s, 1), 0);
    EQ(lsn(s, SOMAXCONN), 0);
    EQ(lsn(s, 0), 0);
    c = dial(&a);
    d = acc_wait(s, NULL, NULL, 3000);
    CHECK(c != INVALID_SOCKET && d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) cls(d);
    if (c != INVALID_SOCKET) cls(c);
    cls(s);
}

TEST(bla_listen_again_with_connection_pending_keeps_the_connection)
{
    struct sockaddr_in a;
    SOCKET s, c, d;
    NEED();
    s = listener(&a, 5);
    c = dial(&a);
    EQ(lsn(s, 5), 0);
    d = acc_wait(s, NULL, NULL, 3000);
    CHECK(d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) cls(d);
    cls(c); cls(s);
}

TEST(bla_listen_v6_loopback_serves)
{
    struct sockaddr_in6 a = lo6(0), got;
    int n = sizeof got;
    SOCKET s, c, d;
    NEED(); NEED6();
    s = tcp6();
    EQ(bnd(s, &a, sizeof a), 0);
    EQ(gsn(s, &got, &n), 0);
    EQ(lsn(s, 1), 0);
    c = tcp6();
    EQ(con(c, &got, sizeof got), 0);
    d = acc_wait(s, NULL, NULL, 3000);
    CHECK(d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) cls(d);
    cls(c); cls(s);
}

/* ---- listening is visible and sticky ---- */

static int acceptconn(SOCKET s)
{
    DWORD v = 0xdead;
    int n = sizeof v;
    if (gso(s, SOL_SOCKET, SO_ACCEPTCONN, &v, &n) != 0) return -1;
    return (int)v;
}

TEST(bla_listen_acceptconn_zero_until_listening)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(acceptconn(s), 0);
    EQ(bind_lo(s, &a), 0);
    EQ(acceptconn(s), 0);
    EQ(lsn(s, 1), 0);
    EQ(acceptconn(s), 1);
    cls(s);
}

TEST(bla_listen_acceptconn_zero_on_udp_and_connected)
{
    struct sockaddr_in a, t;
    SOCKET u, l, c, s;
    NEED();
    u = udp();
    EQ(bind_lo(u, &t), 0);
    { int v = -5, n = sizeof v;                        /* a datagram socket has no listening state to report */
      CHECK(U(getsockopt)(u, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &n) == SOCKET_ERROR);
      EQ(werr(), WSAENOPROTOOPT); }
    l = listener(&a, 1);
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    EQ(acceptconn(c), 0);
    if (s != INVALID_SOCKET) { EQ(acceptconn(s), 0); cls(s); }
    EQ(acceptconn(l), 1);
    cls(c); cls(l); cls(u);
}

TEST(bla_listen_acceptconn_still_zero_after_failed_listen)
{
    SOCKET s;
    NEED();
    s = tcp();
    FAILS(lsn(s, 1), WSAEINVAL);
    EQ(acceptconn(s), 0);
    cls(s);
}

TEST(bla_listen_bind_after_listen_is_einval)
{
    struct sockaddr_in a, other = lo4(0);
    SOCKET s;
    NEED();
    s = listener(&a, 1);
    FAILS(bnd(s, &other, sizeof other), WSAEINVAL);
    cls(s);
}

TEST(bla_listen_name_and_peer_after_listen)
{
    struct sockaddr_in a, got, p;
    int n = sizeof got, m = sizeof p;
    SOCKET s;
    NEED();
    s = listener(&a, 1);
    EQ(gsn(s, &got, &n), 0);
    CHECK(!memcmp(&a, &got, sizeof a));
    FAILS(gpn(s, &p, &m), WSAENOTCONN);
    cls(s);
}

TEST(bla_listen_connect_on_listening_socket_fails)
{
    struct sockaddr_in a, b;
    SOCKET s, other;
    NEED();
    s = listener(&a, 1);
    other = listener(&b, 1);
    wset(0x5a5a);
    CHECK(con(s, &b, sizeof b) == SOCKET_ERROR);
    t_note("connect on a listening socket -> %s", werr() == WSAEISCONN ? "ISCONN" : werr() == WSAEINVAL ? "INVAL" :
           werr() == WSAEOPNOTSUPP ? "OPNOTSUPP" : "other");
    cls(s); cls(other);
}

TEST(bla_listen_shutdown_on_listening_socket_fails)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = listener(&a, 1);
    wset(0x5a5a);
    CHECK(U(shutdown)(s, SD_SEND) == SOCKET_ERROR);
    t_note("shutdown on a listening socket -> %s", werr() == WSAENOTCONN ? "NOTCONN" : werr_class(werr()));
    cls(s);
}

TEST(bla_listen_readable_only_with_pending_connection)
{
    struct sockaddr_in a;
    SOCKET s, c, d;
    NEED();
    s = listener(&a, 5);
    CHECK(!readable(s, 100));
    c = dial(&a);
    CHECK(readable(s, 3000));
    d = acc(s, NULL, NULL);
    CHECK(d != INVALID_SOCKET);
    CHECK(!readable(s, 100));                           /* the queue is drained */
    if (d != INVALID_SOCKET) cls(d);
    cls(c); cls(s);
}

TEST(bla_listen_queue_holds_several_connections_in_order)
{
    struct sockaddr_in a, n1, n2, n3, p;
    int l1 = sizeof n1, l2 = sizeof n2, l3 = sizeof n3, m = sizeof p;
    SOCKET s, c1, c2, c3, d1, d2, d3;
    NEED();
    s = listener(&a, 5);
    c1 = dial(&a); c2 = dial(&a); c3 = dial(&a);
    CHECK(c1 != INVALID_SOCKET && c2 != INVALID_SOCKET && c3 != INVALID_SOCKET);
    EQ(gsn(c1, &n1, &l1), 0); EQ(gsn(c2, &n2, &l2), 0); EQ(gsn(c3, &n3, &l3), 0);
    m = sizeof p; d1 = acc_wait(s, &p, &m, 3000);
    CHECK(d1 != INVALID_SOCKET); CHECK(p.sin_port == n1.sin_port);
    m = sizeof p; d2 = acc_wait(s, &p, &m, 3000);
    CHECK(d2 != INVALID_SOCKET); CHECK(p.sin_port == n2.sin_port);
    m = sizeof p; d3 = acc_wait(s, &p, &m, 3000);
    CHECK(d3 != INVALID_SOCKET); CHECK(p.sin_port == n3.sin_port);
    if (d1 != INVALID_SOCKET) cls(d1);
    if (d2 != INVALID_SOCKET) cls(d2);
    if (d3 != INVALID_SOCKET) cls(d3);
    cls(c1); cls(c2); cls(c3); cls(s);
}

TEST(bla_listen_closed_listener_resets_queued_client)
{
    struct sockaddr_in a;
    SOCKET s, c;
    char b;
    int r;
    NEED();
    s = listener(&a, 5);
    c = dial(&a);
    CHECK(c != INVALID_SOCKET);
    cls(s);                                             /* a connection never accepted is torn down */
    rcvto(c, 3000);
    r = rcv(c, &b, 1);
    CHECK(r == SOCKET_ERROR || r == 0);
    if (r == SOCKET_ERROR) t_note("client of a closed listener sees %s", werr() == WSAECONNRESET ? "reset" : werr_class(werr()));
    cls(c);
}

TEST(bla_listen_port_free_after_listener_close)
{
    struct sockaddr_in a, again;
    SOCKET s, s2;
    NEED();
    s = listener(&a, 1);
    cls(s);
    again = a;
    s2 = tcp();
    EQ(bnd(s2, &again, sizeof again), 0);
    EQ(lsn(s2, 1), 0);
    cls(s2);
}

TEST(bla_listen_two_listeners_distinct_ports)
{
    struct sockaddr_in a, b;
    SOCKET s1, s2;
    NEED();
    s1 = listener(&a, 1);
    s2 = listener(&b, 1);
    CHECK(s1 != INVALID_SOCKET && s2 != INVALID_SOCKET);
    CHECK(a.sin_port != b.sin_port);
    cls(s1); cls(s2);
}
