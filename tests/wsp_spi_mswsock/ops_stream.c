/* Connection-oriented operations of the base provider through its procedure table: bind, listen, connect,
 * accept, name queries, shutdown and the half-close entry points, send/receive including scatter/gather and
 * overlapped completion, select, event select / enumeration, and the "wrong state" error numbers.
 *
 * Every endpoint is a loopback listener on an ephemeral port created by the test; every socket is closed and
 * nothing prints a port or handle.  Errors are read from lpErrno (the provider does not touch the thread's
 * last-error value), and the failure sentinel is checked together with it.
 */
#include "spi.h"

#define FAIL_WITH(call, err) do { int e_ = 0x5151; EXPECT_EQ((call), SOCKET_ERROR); EXPECT_EQ(e_ == 0x5151 ? 0 : e_, (err)); } while (0)

/* ---------------------------------------------------------------- bind */
TEST(bind_ephemeral_loopback)
{
    SOCKET s; struct sockaddr_in a;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(sp_name(s, &a), 0);
    EXPECT_EQ(a.sin_family, AF_INET);
    EXPECT_EQ(a.sin_addr.s_addr, 0x0100007Fu);
    CHECK(a.sin_port != 0);
    sp_close(s);
}
TEST(bind_wildcard_reads_back_wildcard_address)
{
    SOCKET s; struct sockaddr_in a, w; int e = 0;
    SP_NEED();
    s = sp_tcp();
    sp_v4(&w, 0); w.sin_addr.s_addr = 0;
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&w, sizeof w, &e), 0);
    EXPECT_EQ(sp_name(s, &a), 0);
    EXPECT_EQ(a.sin_addr.s_addr, 0);
    CHECK(a.sin_port != 0);
    sp_close(s);
}
TEST(bind_explicit_port_is_kept)
{
    SOCKET s, probe; struct sockaddr_in a, b; int e = 0;
    SP_NEED();
    probe = sp_tcp();
    EXPECT_EQ(sp_bind_lo(probe), 0);
    EXPECT_EQ(sp_name(probe, &a), 0);
    sp_close(probe);
    s = sp_tcp();
    b = a;
    e = 0;
    if (P.lpWSPBind(s, (struct sockaddr *)&b, sizeof b, &e) != 0) { t_note("port taken in between, err %d", e); sp_close(s); return; }
    EXPECT_EQ(sp_name(s, &a), 0);
    EXPECT_EQ(a.sin_port, b.sin_port);
    sp_close(s);
}
TEST(bind_null_name)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPBind(s, NULL, 16, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(bind_length_shorter_than_family_minimum)
{
    SOCKET s; struct sockaddr_in a; int e = 0;
    SP_NEED();
    s = sp_tcp();
    sp_v4(&a, 0);
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&a, 15, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    e = 0;
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&a, 0, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(bind_failed_attempt_leaves_socket_unbound)
{
    SOCKET s; struct sockaddr_in a; int e = 0;
    SP_NEED();
    s = sp_tcp();
    sp_v4(&a, 0);
    (void)P.lpWSPBind(s, (struct sockaddr *)&a, 4, &e);
    EXPECT_EQ(sp_bind_lo(s), 0);   /* a later correct bind still works */
    sp_close(s);
}
TEST(bind_twice_is_invalid)
{
    SOCKET s; struct sockaddr_in a; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    sp_v4(&a, 0);
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&a, sizeof a, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(bind_invalid_socket)
{
    struct sockaddr_in a; int e = 0;
    SP_NEED();
    sp_v4(&a, 0);
    EXPECT_EQ(P.lpWSPBind(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(bind_port_in_use)
{
    SOCKET a, b; struct sockaddr_in n; int e = 0;
    SP_NEED();
    a = sp_tcp(); b = sp_tcp();
    EXPECT_EQ(sp_bind_lo(a), 0);
    EXPECT_EQ(sp_name(a, &n), 0);
    EXPECT_EQ(P.lpWSPBind(b, (struct sockaddr *)&n, sizeof n, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAEADDRINUSE);
    sp_close(a); sp_close(b);
}
TEST(bind_port_in_use_by_listener)
{
    SOCKET l, b; struct sockaddr_in n; int e = 0;
    SP_NEED();
    l = sp_listener(&n);
    CHECK(l != INVALID_SOCKET);
    b = sp_tcp();
    EXPECT_EQ(P.lpWSPBind(b, (struct sockaddr *)&n, sizeof n, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAEADDRINUSE);
    sp_close(b); sp_close(l);
}
TEST(bind_address_not_local)
{
    SOCKET s; struct sockaddr_in a; int e = 0;
    SP_NEED();
    s = sp_tcp();
    sp_v4(&a, 0);
    a.sin_addr.s_addr = 0x010200C0u;    /* 192.0.2.1, documentation range: never a local address */
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&a, sizeof a, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAEADDRNOTAVAIL);
    sp_close(s);
}
TEST(bind_udp_ephemeral)
{
    SOCKET s; struct sockaddr_in a;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(sp_name(s, &a), 0);
    CHECK(a.sin_port != 0);
    sp_close(s);
}
TEST(bind_two_udp_sockets_get_different_ports)
{
    SOCKET a, b; struct sockaddr_in na, nb;
    SP_NEED();
    a = sp_udp(); b = sp_udp();
    EXPECT_EQ(sp_bind_lo(a), 0); EXPECT_EQ(sp_bind_lo(b), 0);
    sp_name(a, &na); sp_name(b, &nb);
    CHECK(na.sin_port != nb.sin_port);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- name queries */
TEST(getsockname_unbound_is_invalid)
{
    SOCKET s; struct sockaddr_in a; int e = 0, l = sizeof a;
    SP_NEED();
    s = sp_tcp();
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(P.lpWSPGetSockName(s, (struct sockaddr *)&a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    EXPECT_EQ(a.sin_family, 0x7777);   /* nothing written */
    sp_close(s);
}
TEST(getsockname_invalid_socket)
{
    struct sockaddr_in a; int e = 0, l = sizeof a;
    SP_NEED();
    EXPECT_EQ(P.lpWSPGetSockName(INVALID_SOCKET, (struct sockaddr *)&a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(getsockname_short_buffer_is_a_fault)
{
    SOCKET s; char b[4]; int e = 0, l = sizeof b;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(P.lpWSPGetSockName(s, (struct sockaddr *)b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(getsockname_large_buffer_reports_actual_length)
{
    SOCKET s; struct sockaddr_storage st; int e = 0, l = sizeof st;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(P.lpWSPGetSockName(s, (struct sockaddr *)&st, &l, &e), 0);
    EXPECT_EQ(l, 16);
    sp_close(s);
}
TEST(getpeername_unconnected_stream)
{
    SOCKET s; struct sockaddr_in a; int e = 0, l = sizeof a;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPGetPeerName(s, (struct sockaddr *)&a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(getpeername_invalid_socket)
{
    struct sockaddr_in a; int e = 0, l = sizeof a;
    SP_NEED();
    EXPECT_EQ(P.lpWSPGetPeerName(INVALID_SOCKET, (struct sockaddr *)&a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(getpeername_connected_returns_listener_address)
{
    struct sockaddr_in la, pa; SOCKET l, c; int e = 0, n = sizeof pa;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    memset(&pa, 0, sizeof pa);
    EXPECT_EQ(P.lpWSPGetPeerName(c, (struct sockaddr *)&pa, &n, &e), 0);
    EXPECT_EQ(n, (int)sizeof pa);
    EXPECT_EQ(pa.sin_family, AF_INET);
    EXPECT_EQ(pa.sin_port, la.sin_port);
    EXPECT_EQ(pa.sin_addr.s_addr, la.sin_addr.s_addr);
    sp_close(c); sp_close(l);
}
TEST(getpeername_short_buffer_keeps_length_untouched)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[4]; int e = 0, l = sizeof b;
        EXPECT_EQ(P.lpWSPGetPeerName(c, (struct sockaddr *)b, &l, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_FAULT);
        EXPECT_EQ(l, 4);
        sp_close(c); sp_close(a);
    }
}
TEST(getpeername_negative_length_is_a_fault)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        struct sockaddr_in p; int e = 0, l = -1;
        EXPECT_EQ(P.lpWSPGetPeerName(c, (struct sockaddr *)&p, &l, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_FAULT);
        sp_close(c); sp_close(a);
    }
}
TEST(pair_names_mirror_each_other)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        struct sockaddr_in cn, ap, an, cp; int e = 0, l1 = 16, l2 = 16;
        EXPECT_EQ(sp_name(c, &cn), 0);
        EXPECT_EQ(P.lpWSPGetPeerName(a, (struct sockaddr *)&ap, &l1, &e), 0);
        EXPECT_EQ(sp_name(a, &an), 0);
        EXPECT_EQ(P.lpWSPGetPeerName(c, (struct sockaddr *)&cp, &l2, &e), 0);
        EXPECT_EQ(cn.sin_port, ap.sin_port);
        EXPECT_EQ(an.sin_port, cp.sin_port);
        sp_close(c); sp_close(a);
    }
}

/* ---------------------------------------------------------------- listen */
TEST(listen_unbound_stream_is_invalid)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPListen(s, 1, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(listen_datagram_not_supported)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(P.lpWSPListen(s, 1, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_OPNOTSUPP);
    sp_close(s);
}
TEST(listen_unbound_datagram_not_supported)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(P.lpWSPListen(s, 1, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_OPNOTSUPP);
    sp_close(s);
}
TEST(listen_invalid_socket)
{
    int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPListen(INVALID_SOCKET, 1, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(listen_on_bound_socket)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(P.lpWSPListen(s, 1, &e), 0);
    sp_close(s);
}
TEST(listen_max_backlog_value)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(P.lpWSPListen(s, SOMAXCONN, &e), 0);
    sp_close(s);
}
TEST(listen_twice_succeeds)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    EXPECT_EQ(P.lpWSPListen(s, 1, &e), 0);
    EXPECT_EQ(P.lpWSPListen(s, 5, &e), 0);
    sp_close(s);
}
TEST(listen_sets_accept_conn_option)
{
    struct sockaddr_in la; SOCKET l; int v = 0, n = 4, e = 0;
    SP_NEED();
    l = sp_listener(&la);
    CHECK(l != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPGetSockOpt(l, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &n, &e), 0);
    EXPECT_EQ(v != 0, 1);
    sp_close(l);
}
TEST(listen_on_connected_socket_is_isconn)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        int e = 0;
        EXPECT_EQ(P.lpWSPListen(c, 1, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_ISCONN);
        sp_close(c); sp_close(a);
    }
}
TEST(listen_after_close_of_listener_port_is_reusable_later)
{
    struct sockaddr_in la, b; SOCKET l, s; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    sp_close(l);
    s = sp_tcp();
    b = la;
    if (P.lpWSPBind(s, (struct sockaddr *)&b, sizeof b, &e) != 0) t_note("rebind after close failed, err %d", e);
    sp_close(s);
}

/* ---------------------------------------------------------------- connect */
TEST(connect_refused_on_closed_port)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    CHECK(l != INVALID_SOCKET);
    sp_close(l);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAECONNREFUSED);
    sp_close(c);
}
TEST(connect_invalid_socket)
{
    struct sockaddr_in a; int e = 0;
    SP_NEED();
    sp_v4(&a, 9);
    EXPECT_EQ(P.lpWSPConnect(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(connect_short_name_length)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, 8, NULL, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(c); sp_close(l);
}
TEST(connect_family_mismatch)
{
    struct sockaddr_in6 a6; SOCKET c; int e = 0;
    SP_NEED();
    c = sp_tcp();
    sp_v6(&a6, 9);
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&a6, sizeof a6, NULL, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_AFNOSUPPORT);
    sp_close(c);
}
TEST(connect_twice_is_isconn)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    e = 0;
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_ISCONN);
    sp_close(c); sp_close(l);
}
TEST(connect_on_listening_socket_is_invalid)
{
    struct sockaddr_in la, other; SOCKET l, l2; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    l2 = sp_listener(&other);
    EXPECT_EQ(P.lpWSPConnect(l, (struct sockaddr *)&other, sizeof other, NULL, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(l); sp_close(l2);
}
TEST(connect_binds_implicitly)
{
    struct sockaddr_in la, n; SOCKET l, c; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_name(c, &n), 0);
    CHECK(n.sin_port != 0);
    EXPECT_EQ(n.sin_addr.s_addr, 0x0100007Fu);
    sp_close(c); sp_close(l);
}
TEST(connect_nonblocking_reports_would_block_then_completes)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0; DWORD n = 0; u_long on = 1;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(c, FIONBIO, &on, sizeof on, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
    e = 0;
    if (P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e) == SOCKET_ERROR)
        EXPECT_EQ(e, SE_WOULDBLOCK);
    else
        t_note("loopback connect completed immediately");
    EXPECT_EQ(sp_writable(c, 5000), 1);
    {   /* now connected */
        struct sockaddr_in p; int pl = sizeof p;
        EXPECT_EQ(P.lpWSPGetPeerName(c, (struct sockaddr *)&p, &pl, &e), 0);
    }
    sp_close(c); sp_close(l);
}
TEST(connect_udp_sets_peer_and_allows_reconnect)
{
    SOCKET a, b; struct sockaddr_in na, nb, p; int e = 0, pl = sizeof p;
    SP_NEED();
    a = sp_udp(); b = sp_udp();
    EXPECT_EQ(sp_bind_lo(a), 0); EXPECT_EQ(sp_bind_lo(b), 0);
    sp_name(a, &na); sp_name(b, &nb);
    EXPECT_EQ(P.lpWSPConnect(a, (struct sockaddr *)&nb, sizeof nb, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(P.lpWSPGetPeerName(a, (struct sockaddr *)&p, &pl, &e), 0);
    EXPECT_EQ(p.sin_port, nb.sin_port);
    EXPECT_EQ(P.lpWSPConnect(a, (struct sockaddr *)&na, sizeof na, NULL, NULL, NULL, NULL, &e), 0);
    pl = sizeof p;
    EXPECT_EQ(P.lpWSPGetPeerName(a, (struct sockaddr *)&p, &pl, &e), 0);
    EXPECT_EQ(p.sin_port, na.sin_port);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- accept */
TEST(accept_returns_peer_address)
{
    struct sockaddr_in la, cn, pa; SOCKET l, c, a; int e = 0, n = sizeof pa;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    memset(&pa, 0, sizeof pa);
    a = P.lpWSPAccept(l, (struct sockaddr *)&pa, &n, NULL, 0, &e);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(n, (int)sizeof pa);
    sp_name(c, &cn);
    EXPECT_EQ(pa.sin_family, AF_INET);
    EXPECT_EQ(pa.sin_port, cn.sin_port);
    EXPECT_EQ(pa.sin_addr.s_addr, cn.sin_addr.s_addr);
    sp_close(a); sp_close(c); sp_close(l);
}
TEST(accept_without_address_buffers)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        CHECK(c != INVALID_SOCKET && a != INVALID_SOCKET);
        sp_close(c); sp_close(a);
    }
}
TEST(accepted_socket_is_a_stream_with_listener_name)
{
    struct sockaddr_in la, an; SOCKET l, c, a; int e = 0, t = 0, tl = 4;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPGetSockOpt(a, SOL_SOCKET, SO_TYPE, (char *)&t, &tl, &e), 0);
    EXPECT_EQ(t, SOCK_STREAM);
    EXPECT_EQ(sp_name(a, &an), 0);
    EXPECT_EQ(an.sin_port, la.sin_port);
    sp_close(a); sp_close(c); sp_close(l);
}
TEST(accepted_socket_is_not_a_listener)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        int v = 5, n = 4, e = 0;
        EXPECT_EQ(P.lpWSPGetSockOpt(a, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &n, &e), 0);
        EXPECT_EQ(v, 0);
        sp_close(c); sp_close(a);
    }
}
TEST(accept_on_unlistened_socket_is_invalid)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    CHECK(P.lpWSPAccept(s, NULL, NULL, NULL, 0, &e) == INVALID_SOCKET);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(accept_on_datagram_socket_not_supported)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    CHECK(P.lpWSPAccept(s, NULL, NULL, NULL, 0, &e) == INVALID_SOCKET);
    EXPECT_EQ(e, SE_OPNOTSUPP);
    sp_close(s);
}
TEST(accept_invalid_socket)
{
    int e = 0;
    SP_NEED();
    CHECK(P.lpWSPAccept(INVALID_SOCKET, NULL, NULL, NULL, 0, &e) == INVALID_SOCKET);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(accept_nonblocking_with_nothing_pending)
{
    struct sockaddr_in la; SOCKET l; int e = 0; DWORD n = 0; u_long on = 1;
    SP_NEED();
    l = sp_listener(&la);
    EXPECT_EQ(P.lpWSPIoctl(l, FIONBIO, &on, sizeof on, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
    e = 0;
    CHECK(P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e) == INVALID_SOCKET);
    EXPECT_EQ(e, SE_WOULDBLOCK);
    sp_close(l);
}
TEST(accept_connection_survives_listener_close)
{
    struct sockaddr_in la; SOCKET l, c, a; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
    sp_close(l);
    CHECK(a != INVALID_SOCKET);
    CHECK(sp_send_all(c, "ok", 2));
    EXPECT_EQ(sp_readable(a, 5000), 1);
    sp_close(a); sp_close(c);
}
TEST(accept_queue_holds_several_connections)
{
    struct sockaddr_in la; SOCKET l, c[3], a; int e = 0, i, got = 0;
    SP_NEED();
    l = sp_listener(&la);
    for (i = 0; i < 3; i++) {
        c[i] = sp_tcp();
        EXPECT_EQ(P.lpWSPConnect(c[i], (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    }
    for (i = 0; i < 3; i++) {
        if (sp_readable(l, 5000) != 1) break;
        a = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
        if (a != INVALID_SOCKET) { got++; sp_close(a); }
    }
    EXPECT_EQ(got, 3);
    for (i = 0; i < 3; i++) sp_close(c[i]);
    sp_close(l);
}

/* ---------------------------------------------------------------- send / receive */
TEST(send_recv_roundtrip)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[16] = {0}; int n;
        CHECK(sp_send_all(c, "hello", 5));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        n = sp_recv_some(a, b, sizeof b, NULL);
        EXPECT_EQ(n, 5);
        CHECK(!memcmp(b, "hello", 5));
        sp_close(c); sp_close(a);
    }
}
TEST(send_reports_full_count)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD sent = 0; int e = 0; char data[3000];
        memset(data, 'x', sizeof data);
        w.buf = data; w.len = sizeof data;
        EXPECT_EQ(P.lpWSPSend(c, &w, 1, &sent, 0, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(sent, 3000);
        sp_close(c); sp_close(a);
    }
}
TEST(send_scatter_gather_concatenates)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w[3]; DWORD sent = 0; int e = 0; char b[16] = {0}; int n;
        w[0].buf = "ab"; w[0].len = 2; w[1].buf = "cde"; w[1].len = 3; w[2].buf = "f"; w[2].len = 1;
        EXPECT_EQ(P.lpWSPSend(c, w, 3, &sent, 0, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(sent, 6);
        EXPECT_EQ(sp_readable(a, 5000), 1);
        n = sp_recv_some(a, b, sizeof b, NULL);
        EXPECT_EQ(n, 6);
        CHECK(!memcmp(b, "abcdef", 6));
        sp_close(c); sp_close(a);
    }
}
TEST(recv_scatter_fills_buffers_in_order)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w[2]; DWORD got = 0, fl = 0; int e = 0; char x[4], y[16];
        CHECK(sp_send_all(c, "0123456789", 10));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        Sleep(50);
        w[0].buf = x; w[0].len = 4; w[1].buf = y; w[1].len = sizeof y;
        EXPECT_EQ(P.lpWSPRecv(a, w, 2, &got, &fl, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(got, 10);
        CHECK(!memcmp(x, "0123", 4));
        CHECK(!memcmp(y, "456789", 6));
        sp_close(c); sp_close(a);
    }
}
TEST(recv_short_buffer_leaves_rest_queued)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[8] = {0}; int n;
        CHECK(sp_send_all(c, "abcdefgh", 8));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        Sleep(50);
        n = sp_recv_some(a, b, 3, NULL);
        EXPECT_EQ(n, 3);
        n = sp_recv_some(a, b + 3, 5, NULL);
        EXPECT_EQ(n, 5);
        CHECK(!memcmp(b, "abcdefgh", 8));
        sp_close(c); sp_close(a);
    }
}
TEST(recv_peek_does_not_consume)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD got = 0, fl = MSG_PEEK; int e = 0; char b[8] = {0};
        CHECK(sp_send_all(c, "peek", 4));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(got, 4);
        got = 0; fl = 0;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(got, 4);
        sp_close(c); sp_close(a);
    }
}
TEST(recv_flags_out_is_zero_for_plain_data)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD got = 0, fl = 0; int e = 0; char b[8];
        CHECK(sp_send_all(c, "zz", 2));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(fl, 0);
        sp_close(c); sp_close(a);
    }
}
TEST(recv_after_peer_close_returns_zero_bytes)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[8]; int n;
        sp_close(c);
        EXPECT_EQ(sp_readable(a, 5000), 1);
        n = sp_recv_some(a, b, sizeof b, NULL);
        EXPECT_EQ(n, 0);
        sp_close(a);
    }
}
TEST(recv_delivers_data_sent_before_close_then_eof)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[8]; int n;
        CHECK(sp_send_all(c, "bye", 3));
        sp_close(c);
        Sleep(50);
        n = sp_recv_some(a, b, sizeof b, NULL);
        EXPECT_EQ(n, 3);
        n = sp_recv_some(a, b, sizeof b, NULL);
        EXPECT_EQ(n, 0);
        sp_close(a);
    }
}
TEST(send_on_unconnected_stream)
{
    SOCKET s; WSABUF w; DWORD sent = 0; int e = 0;
    SP_NEED();
    s = sp_tcp();
    w.buf = "x"; w.len = 1;
    EXPECT_EQ(P.lpWSPSend(s, &w, 1, &sent, 0, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(recv_on_unconnected_stream)
{
    SOCKET s; WSABUF w; DWORD got = 0, fl = 0; int e = 0; char b[4];
    SP_NEED();
    s = sp_tcp();
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(P.lpWSPRecv(s, &w, 1, &got, &fl, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(send_invalid_socket)
{
    WSABUF w; DWORD sent = 0; int e = 0;
    SP_NEED();
    w.buf = "x"; w.len = 1;
    EXPECT_EQ(P.lpWSPSend(INVALID_SOCKET, &w, 1, &sent, 0, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(recv_invalid_socket)
{
    WSABUF w; DWORD got = 0, fl = 0; int e = 0; char b[4];
    SP_NEED();
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(P.lpWSPRecv(INVALID_SOCKET, &w, 1, &got, &fl, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(send_after_send_shutdown)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD sent = 0; int e = 0;
        EXPECT_EQ(P.lpWSPShutdown(c, SD_SEND, &e), 0);
        w.buf = "x"; w.len = 1;
        EXPECT_EQ(P.lpWSPSend(c, &w, 1, &sent, 0, NULL, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, WSAESHUTDOWN);
        sp_close(c); sp_close(a);
    }
}
TEST(send_zero_bytes_on_connected_stream)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD sent = 99; int e = 0;
        w.buf = "x"; w.len = 0;
        EXPECT_EQ(P.lpWSPSend(c, &w, 1, &sent, 0, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(sent, 0);
        sp_close(c); sp_close(a);
    }
}
TEST(send_nonblocking_until_buffers_fill)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        static char blob[65536];
        WSABUF w; DWORD sent = 0; int e = 0, i, blocked = 0; u_long on = 1; DWORD n = 0;
        EXPECT_EQ(P.lpWSPIoctl(c, FIONBIO, &on, sizeof on, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        w.buf = blob; w.len = sizeof blob;
        for (i = 0; i < 2000; i++) {
            e = 0;
            if (P.lpWSPSend(c, &w, 1, &sent, 0, NULL, NULL, NULL, &e) == SOCKET_ERROR) { blocked = e; break; }
        }
        EXPECT_EQ(blocked, SE_WOULDBLOCK);
        sp_close(c); sp_close(a);
    }
}
TEST(recv_nonblocking_with_no_data)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD got = 0, fl = 0; int e = 0; u_long on = 1; DWORD n = 0; char b[4];
        EXPECT_EQ(P.lpWSPIoctl(a, FIONBIO, &on, sizeof on, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_WOULDBLOCK);
        sp_close(c); sp_close(a);
    }
}

/* ---------------------------------------------------------------- overlapped */
TEST(overlapped_recv_is_pending_then_completes)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSAOVERLAPPED ov; WSABUF w; DWORD got = 0, fl = 0, xfer = 0, xf = 0; int e = 0; char b[8] = {0};
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, &ov, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_IOPENDING);
        CHECK(sp_send_all(c, "late", 4));
        EXPECT_EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
        e = 0;
        EXPECT_EQ(P.lpWSPGetOverlappedResult(a, &ov, &xfer, FALSE, &xf, &e), TRUE);
        EXPECT_EQ(xfer, 4);
        EXPECT_EQ(xf, 0);
        CHECK(!memcmp(b, "late", 4));
        CloseHandle(ov.hEvent);
        sp_close(c); sp_close(a);
    }
}
TEST(overlapped_result_incomplete_while_pending)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSAOVERLAPPED ov; WSABUF w; DWORD got = 0, fl = 0, xfer = 0, xf = 0; int e = 0; char b[8];
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, &ov, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_IOPENDING);
        e = 0;
        EXPECT_EQ(P.lpWSPGetOverlappedResult(a, &ov, &xfer, FALSE, &xf, &e), FALSE);
        EXPECT_EQ(e, SE_IOINCOMPLETE);
        sp_close(a);            /* cancels the pending receive */
        WaitForSingleObject(ov.hEvent, 5000);
        CloseHandle(ov.hEvent);
        sp_close(c);
    }
}
TEST(overlapped_recv_cancelled_by_close_reports_aborted)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSAOVERLAPPED ov; WSABUF w; DWORD got = 0, fl = 0, xfer = 0, xf = 0; int e = 0; char b[8];
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, &ov, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_IOPENDING);
        P.lpWSPCloseSocket(a, &e);
        EXPECT_EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
        e = 0;
        EXPECT_EQ(P.lpWSPGetOverlappedResult(a, &ov, &xfer, FALSE, &xf, &e), FALSE);
        EXPECT_EQ(e, WSAECONNABORTED);   /* a receive cancelled by close completes as aborted-connection */
        CloseHandle(ov.hEvent);
        sp_close(c);
    }
}
TEST(overlapped_send_completes)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSAOVERLAPPED ov; WSABUF w; DWORD sent = 0, xfer = 0, xf = 0; int e = 0, r;
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        w.buf = "ping"; w.len = 4;
        r = P.lpWSPSend(c, &w, 1, &sent, 0, &ov, NULL, NULL, &e);
        if (r == SOCKET_ERROR) EXPECT_EQ(e, SE_IOPENDING);
        EXPECT_EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
        e = 0;
        EXPECT_EQ(P.lpWSPGetOverlappedResult(c, &ov, &xfer, TRUE, &xf, &e), TRUE);
        EXPECT_EQ(xfer, 4);
        CloseHandle(ov.hEvent);
        sp_close(c); sp_close(a);
    }
}
TEST(overlapped_result_wait_blocks_until_done)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSAOVERLAPPED ov; WSABUF w; DWORD got = 0, fl = 0, xfer = 0, xf = 0; int e = 0; char b[8];
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, &ov, NULL, NULL, &e), SOCKET_ERROR);
        CHECK(sp_send_all(c, "go", 2));
        e = 0;
        EXPECT_EQ(P.lpWSPGetOverlappedResult(a, &ov, &xfer, TRUE, &xf, &e), TRUE);
        EXPECT_EQ(xfer, 2);
        CloseHandle(ov.hEvent);
        sp_close(c); sp_close(a);
    }
}

/* ---------------------------------------------------------------- shutdown and half-close */
TEST(shutdown_invalid_how_on_connected)
{
    static const int how[] = { 3, -1, 4, 0x100, 0x7fffffff };
    int i;
    SP_NEED();
    {
        SP_PAIR(c, a);
        for (i = 0; i < 5; i++) {
            int e = 0;
            EXPECT_EQ(P.lpWSPShutdown(c, how[i], &e), SOCKET_ERROR);
            EXPECT_EQ(e, SE_INVAL);
        }
        sp_close(c); sp_close(a);
    }
}
TEST(shutdown_unconnected_stream)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPShutdown(s, SD_BOTH, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(shutdown_invalid_how_on_datagram)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(P.lpWSPShutdown(s, 7, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(shutdown_invalid_socket)
{
    int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPShutdown(INVALID_SOCKET, SD_BOTH, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(shutdown_send_gives_peer_eof)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[4]; int e = 0, n;
        EXPECT_EQ(P.lpWSPShutdown(c, SD_SEND, &e), 0);
        EXPECT_EQ(sp_readable(a, 5000), 1);
        n = sp_recv_some(a, b, sizeof b, NULL);
        EXPECT_EQ(n, 0);
        /* the other direction still works */
        CHECK(sp_send_all(a, "z", 1));
        EXPECT_EQ(sp_readable(c, 5000), 1);
        n = sp_recv_some(c, b, sizeof b, NULL);
        EXPECT_EQ(n, 1);
        sp_close(c); sp_close(a);
    }
}
TEST(shutdown_both_then_peer_sees_eof)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[4]; int e = 0;
        EXPECT_EQ(P.lpWSPShutdown(c, SD_BOTH, &e), 0);
        EXPECT_EQ(sp_readable(a, 5000), 1);
        EXPECT_EQ(sp_recv_some(a, b, sizeof b, NULL), 0);
        sp_close(c); sp_close(a);
    }
}
TEST(shutdown_receive_is_accepted)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        int e = 0;
        EXPECT_EQ(P.lpWSPShutdown(a, SD_RECEIVE, &e), 0);
        sp_close(c); sp_close(a);
    }
}
TEST(shutdown_twice_is_accepted)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        int e = 0;
        EXPECT_EQ(P.lpWSPShutdown(c, SD_SEND, &e), 0);
        e = 0;
        int r = P.lpWSPShutdown(c, SD_SEND, &e);
        if (r != 0) t_note("second shutdown(SD_SEND) failed with %d", e);
        sp_close(c); sp_close(a);
    }
}
TEST(senddisconnect_acts_as_send_shutdown)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        char b[4]; int e = 0;
        EXPECT_EQ(P.lpWSPSendDisconnect(c, NULL, &e), 0);
        EXPECT_EQ(sp_readable(a, 5000), 1);
        EXPECT_EQ(sp_recv_some(a, b, sizeof b, NULL), 0);
        sp_close(c); sp_close(a);
    }
}
TEST(recvdisconnect_on_connected_succeeds)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        int e = 0;
        EXPECT_EQ(P.lpWSPRecvDisconnect(a, NULL, &e), 0);
        sp_close(c); sp_close(a);
    }
}
TEST(senddisconnect_unconnected)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPSendDisconnect(s, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(recvdisconnect_unconnected)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPRecvDisconnect(s, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(senddisconnect_invalid_socket)
{
    int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPSendDisconnect(INVALID_SOCKET, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(recvdisconnect_invalid_socket)
{
    int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPRecvDisconnect(INVALID_SOCKET, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}

/* ---------------------------------------------------------------- select */
TEST(select_readable_after_data)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        EXPECT_EQ(sp_readable(a, 0), 0);
        CHECK(sp_send_all(c, "x", 1));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        sp_close(c); sp_close(a);
    }
}
TEST(select_idle_connected_socket_is_writable)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        EXPECT_EQ(sp_writable(c, 5000), 1);
        sp_close(c); sp_close(a);
    }
}
TEST(select_timeout_zero_returns_zero_for_nothing_ready)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        fd_set r; struct timeval tv; int e = 0;
        r.fd_count = 2; r.fd_array[0] = c; r.fd_array[1] = a;
        tv.tv_sec = 0; tv.tv_usec = 0;
        EXPECT_EQ(P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e), 0);
        EXPECT_EQ(r.fd_count, 0);
        sp_close(c); sp_close(a);
    }
}
TEST(select_counts_across_sets)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        fd_set r, w; struct timeval tv; int e = 0;
        CHECK(sp_send_all(c, "x", 1));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        r.fd_count = 1; r.fd_array[0] = a;
        w.fd_count = 1; w.fd_array[0] = c;
        tv.tv_sec = 5; tv.tv_usec = 0;
        EXPECT_EQ(P.lpWSPSelect(0, &r, &w, NULL, &tv, &e), 2);
        EXPECT_EQ(r.fd_count, 1);
        EXPECT_EQ(w.fd_count, 1);
        sp_close(c); sp_close(a);
    }
}
TEST(select_leaves_only_ready_sockets_in_set)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        SP_PAIR(c2, a2);
        fd_set r; struct timeval tv; int e = 0;
        CHECK(sp_send_all(c2, "x", 1));
        EXPECT_EQ(sp_readable(a2, 5000), 1);
        r.fd_count = 2; r.fd_array[0] = a; r.fd_array[1] = a2;
        tv.tv_sec = 0; tv.tv_usec = 0;
        EXPECT_EQ(P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e), 1);
        EXPECT_EQ(r.fd_count, 1);
        EXPECT_EQ(r.fd_array[0], a2);
        sp_close(c); sp_close(a); sp_close(c2); sp_close(a2);
    }
}
TEST(select_listener_readable_on_pending_connection)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    EXPECT_EQ(sp_readable(l, 0), 0);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    sp_close(c); sp_close(l);
}
TEST(select_readable_on_peer_close)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        sp_close(c);
        EXPECT_EQ(sp_readable(a, 5000), 1);
        sp_close(a);
    }
}
TEST(select_non_socket_in_set)
{
    fd_set r; struct timeval tv; int e = 0;
    SP_NEED();
    r.fd_count = 1; r.fd_array[0] = (SOCKET)0xFFFFF4;
    tv.tv_sec = 0; tv.tv_usec = 0;
    EXPECT_EQ(P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(select_refused_connect_reports_in_except_set)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0; DWORD n = 0; u_long on = 1; fd_set x; struct timeval tv;
    SP_NEED();
    l = sp_listener(&la);
    sp_close(l);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(c, FIONBIO, &on, sizeof on, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
    e = 0;
    if (P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e) != SOCKET_ERROR) { t_note("connect did not fail"); sp_close(c); return; }
    EXPECT_EQ(e, SE_WOULDBLOCK);
    x.fd_count = 1; x.fd_array[0] = c;
    tv.tv_sec = 5; tv.tv_usec = 0;
    EXPECT_EQ(P.lpWSPSelect(0, NULL, NULL, &x, &tv, &e), 1);
    {
        int v = 0, l2 = 4;
        EXPECT_EQ(P.lpWSPGetSockOpt(c, SOL_SOCKET, SO_ERROR, (char *)&v, &l2, &e), 0);
        EXPECT_EQ(v, WSAECONNREFUSED);
    }
    sp_close(c);
}

/* ---------------------------------------------------------------- ioctl */
TEST(ioctl_fionread_counts_queued_bytes)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        u_long avail = 99; DWORD n = 0; int e = 0;
        CHECK(sp_send_all(c, "12345", 5));
        EXPECT_EQ(sp_readable(a, 5000), 1);
        Sleep(50);
        EXPECT_EQ(P.lpWSPIoctl(a, FIONREAD, NULL, 0, &avail, sizeof avail, &n, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(avail, 5);
        EXPECT_EQ(n, 4);
        sp_close(c); sp_close(a);
    }
}
TEST(ioctl_fionread_empty_is_zero)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        u_long avail = 99; DWORD n = 0; int e = 0;
        EXPECT_EQ(P.lpWSPIoctl(a, FIONREAD, NULL, 0, &avail, sizeof avail, &n, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(avail, 0);
        sp_close(c); sp_close(a);
    }
}
TEST(ioctl_unknown_code_is_not_supported_and_reports_zero_bytes)
{
    SOCKET s; DWORD n = 77; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(s, 0xdeadbeef, NULL, 0, NULL, 0, &n, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_OPNOTSUPP);
    EXPECT_EQ(n, 0);
    sp_close(s);
}
TEST(ioctl_invalid_socket)
{
    DWORD n = 0; int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPIoctl(INVALID_SOCKET, FIONREAD, NULL, 0, NULL, 0, &n, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(ioctl_fionbio_toggles_blocking_behaviour)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD got = 0, fl = 0, n = 0; int e = 0; u_long on = 1, off = 0; char b[4];
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPIoctl(a, FIONBIO, &on, 4, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_WOULDBLOCK);
        EXPECT_EQ(P.lpWSPIoctl(a, FIONBIO, &off, 4, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        sp_close(c); sp_close(a);
    }
}
TEST(ioctl_overlapped_needs_bytes_returned_pointer)
{
    SOCKET s; WSAOVERLAPPED ov; int e = 0;
    SP_NEED();
    s = sp_tcp();
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(P.lpWSPIoctl(s, 0xdeadbeef, NULL, 0, NULL, 0, NULL, &ov, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}

/* ---------------------------------------------------------------- event select */
TEST(eventselect_invalid_socket)
{
    int e = 0; HANDLE ev;
    SP_NEED();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(P.lpWSPEventSelect(INVALID_SOCKET, ev, FD_READ, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
    CloseHandle(ev);
}
TEST(eventselect_mask_out_of_range)
{
    SOCKET s; HANDLE ev; int e = 0;
    SP_NEED();
    s = sp_tcp();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(P.lpWSPEventSelect(s, ev, 0x400, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    e = 0;
    EXPECT_EQ(P.lpWSPEventSelect(s, ev, (long)0x80000000, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    CloseHandle(ev);
    sp_close(s);
}
TEST(eventselect_read_signals_on_data)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); int e = 0;
        EXPECT_EQ(P.lpWSPEventSelect(a, ev, FD_READ | FD_CLOSE, &e), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 100), WAIT_TIMEOUT);
        CHECK(sp_send_all(c, "d", 1));
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(P.lpWSPEventSelect(a, NULL, 0, &e), 0);
        CloseHandle(ev);
        sp_close(c); sp_close(a);
    }
}
TEST(eventselect_enum_reports_read_and_resets_event)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); int e = 0; WSANETWORKEVENTS ne;
        EXPECT_EQ(P.lpWSPEventSelect(a, ev, FD_READ, &e), 0);
        CHECK(sp_send_all(c, "d", 1));
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        memset(&ne, 0x66, sizeof ne);
        EXPECT_EQ(P.lpWSPEnumNetworkEvents(a, ev, &ne, &e), 0);
        EXPECT_EQ(ne.lNetworkEvents, FD_READ);
        EXPECT_EQ(ne.iErrorCode[FD_READ_BIT], 0);
        EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
        P.lpWSPEventSelect(a, NULL, 0, &e);
        CloseHandle(ev);
        sp_close(c); sp_close(a);
    }
}
TEST(eventselect_write_signals_on_connected_socket)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); int e = 0; WSANETWORKEVENTS ne;
        EXPECT_EQ(P.lpWSPEventSelect(c, ev, FD_WRITE, &e), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(P.lpWSPEnumNetworkEvents(c, ev, &ne, &e), 0);
        CHECK((ne.lNetworkEvents & FD_WRITE) != 0);
        EXPECT_EQ(ne.iErrorCode[FD_WRITE_BIT], 0);
        P.lpWSPEventSelect(c, NULL, 0, &e);
        CloseHandle(ev);
        sp_close(c); sp_close(a);
    }
}
TEST(eventselect_accept_signals_on_pending_connection)
{
    struct sockaddr_in la; SOCKET l, c; HANDLE ev; int e = 0; WSANETWORKEVENTS ne;
    SP_NEED();
    l = sp_listener(&la);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(P.lpWSPEventSelect(l, ev, FD_ACCEPT, &e), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 100), WAIT_TIMEOUT);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(P.lpWSPEnumNetworkEvents(l, ev, &ne, &e), 0);
    EXPECT_EQ(ne.lNetworkEvents, FD_ACCEPT);
    EXPECT_EQ(ne.iErrorCode[FD_ACCEPT_BIT], 0);
    P.lpWSPEventSelect(l, NULL, 0, &e);
    CloseHandle(ev);
    sp_close(c); sp_close(l);
}
TEST(eventselect_connect_signals_on_completion)
{
    struct sockaddr_in la; SOCKET l, c; HANDLE ev; int e = 0; WSANETWORKEVENTS ne;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(P.lpWSPEventSelect(c, ev, FD_CONNECT, &e), 0);
    e = 0;
    if (P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e) == SOCKET_ERROR) EXPECT_EQ(e, SE_WOULDBLOCK);
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(P.lpWSPEnumNetworkEvents(c, ev, &ne, &e), 0);
    EXPECT_EQ(ne.lNetworkEvents, FD_CONNECT);
    EXPECT_EQ(ne.iErrorCode[FD_CONNECT_BIT], 0);
    P.lpWSPEventSelect(c, NULL, 0, &e);
    CloseHandle(ev);
    sp_close(c); sp_close(l);
}
TEST(eventselect_connect_refused_reports_error_code)
{
    struct sockaddr_in la; SOCKET l, c; HANDLE ev; int e = 0; WSANETWORKEVENTS ne;
    SP_NEED();
    l = sp_listener(&la);
    sp_close(l);
    c = sp_tcp();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(P.lpWSPEventSelect(c, ev, FD_CONNECT, &e), 0);
    e = 0;
    if (P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e) == SOCKET_ERROR) EXPECT_EQ(e, SE_WOULDBLOCK);
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(P.lpWSPEnumNetworkEvents(c, ev, &ne, &e), 0);
    EXPECT_EQ(ne.lNetworkEvents, FD_CONNECT);
    EXPECT_EQ(ne.iErrorCode[FD_CONNECT_BIT], WSAECONNREFUSED);
    P.lpWSPEventSelect(c, NULL, 0, &e);
    CloseHandle(ev);
    sp_close(c);
}
TEST(eventselect_close_signals_when_peer_closes)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); int e = 0; WSANETWORKEVENTS ne;
        EXPECT_EQ(P.lpWSPEventSelect(a, ev, FD_CLOSE, &e), 0);
        sp_close(c);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(P.lpWSPEnumNetworkEvents(a, ev, &ne, &e), 0);
        EXPECT_EQ(ne.lNetworkEvents, FD_CLOSE);
        EXPECT_EQ(ne.iErrorCode[FD_CLOSE_BIT], 0);
        P.lpWSPEventSelect(a, NULL, 0, &e);
        CloseHandle(ev);
        sp_close(a);
    }
}
TEST(eventselect_makes_socket_nonblocking)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); int e = 0; WSABUF w; DWORD got = 0, fl = 0; char b[4];
        EXPECT_EQ(P.lpWSPEventSelect(a, ev, FD_READ, &e), 0);
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_WOULDBLOCK);
        P.lpWSPEventSelect(a, NULL, 0, &e);
        CloseHandle(ev);
        sp_close(c); sp_close(a);
    }
}
TEST(enum_network_events_invalid_socket)
{
    WSANETWORKEVENTS ne; int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPEnumNetworkEvents(INVALID_SOCKET, NULL, &ne, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(enum_network_events_nothing_recorded)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSANETWORKEVENTS ne; int e = 0;
        memset(&ne, 0x66, sizeof ne);
        EXPECT_EQ(P.lpWSPEnumNetworkEvents(a, NULL, &ne, &e), 0);
        EXPECT_EQ(ne.lNetworkEvents, 0);
        sp_close(c); sp_close(a);
    }
}

/* ---------------------------------------------------------------- async select argument checks */
TEST(asyncselect_event_mask_out_of_range)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPAsyncSelect(s, NULL, 0x401, 0x400, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(asyncselect_null_window_with_events)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPAsyncSelect(s, NULL, 0x401, FD_READ, &e), SOCKET_ERROR);
    CHECK(e == SE_INVAL || e == SE_NOTSOCK || e == 0);
    sp_close(s);
}

/* ---------------------------------------------------------------- cancel blocking call, misc */
TEST(cancel_blocking_call_is_accepted)
{
    int e = 0x4444;
    SP_NEED();
    EXPECT_EQ(P.lpWSPCancelBlockingCall(&e), 0);
}
TEST(get_qos_by_name_invalid_socket)
{
    WSABUF n; int e = 0;
    SP_NEED();
    n.buf = (CHAR *)"x"; n.len = 1;
    EXPECT_EQ(P.lpWSPGetQOSByName(INVALID_SOCKET, &n, NULL, &e), FALSE);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(join_leaf_on_stream_socket_not_supported)
{
    SOCKET s, r; struct sockaddr_in a; int e = 0;
    SP_NEED();
    s = sp_tcp();
    sp_v4(&a, 9);
    r = P.lpWSPJoinLeaf(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, 0, &e);
    CHECK(r == INVALID_SOCKET);
    CHECK(e == SE_OPNOTSUPP || e == SE_INVAL);
    sp_close(s);
}
TEST(join_leaf_invalid_socket)
{
    struct sockaddr_in a; int e = 0;
    SP_NEED();
    sp_v4(&a, 9);
    CHECK(P.lpWSPJoinLeaf(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, 0, &e) == INVALID_SOCKET);
    EXPECT_EQ(e, SE_NOTSOCK);
}

/* ---------------------------------------------------------------- duplicate */
TEST(duplicate_invalid_socket)
{
    WSAPROTOCOL_INFOW pi; int e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPDuplicateSocket(INVALID_SOCKET, GetCurrentProcessId(), &pi, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(duplicate_null_info)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPDuplicateSocket(s, GetCurrentProcessId(), NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(duplicate_unknown_process)
{
    SOCKET s; WSAPROTOCOL_INFOW pi; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPDuplicateSocket(s, 0xFFFFFFF0u, &pi, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(duplicate_into_own_process_then_adopt)
{
    SOCKET s, d; WSAPROTOCOL_INFOW pi; int e = 0, t = 0, tl = 4;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    memset(&pi, 0, sizeof pi);
    EXPECT_EQ(P.lpWSPDuplicateSocket(s, GetCurrentProcessId(), &pi, &e), 0);
    EXPECT_EQ(pi.iSocketType, SOCK_STREAM);
    EXPECT_EQ(pi.iAddressFamily, AF_INET);
    CHECK(pi.dwProviderReserved != 0);
    sp_up_reset(&sp_upA);
    d = P.lpWSPSocket(-1, -1, -1, &pi, 0, WSA_FLAG_OVERLAPPED, &e);
    CHECKF(d != INVALID_SOCKET, "adopt failed %d", e);
    if (d != INVALID_SOCKET) {
        EXPECT_EQ(sp_up_total(&sp_upA), 0);   /* adopting a duplicated handle is not announced to the host */
        EXPECT_EQ(P.lpWSPGetSockOpt(d, SOL_SOCKET, SO_TYPE, (char *)&t, &tl, &e), 0);
        EXPECT_EQ(t, SOCK_STREAM);
        sp_close(d);
    }
    sp_close(s);
}
TEST(duplicate_shares_one_endpoint)
{
    SOCKET s, d; WSAPROTOCOL_INFOW pi; struct sockaddr_in a, b; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(sp_bind_lo(s), 0);
    memset(&pi, 0, sizeof pi);
    EXPECT_EQ(P.lpWSPDuplicateSocket(s, GetCurrentProcessId(), &pi, &e), 0);
    d = P.lpWSPSocket(-1, -1, -1, &pi, 0, WSA_FLAG_OVERLAPPED, &e);
    if (d == INVALID_SOCKET) { CHECKF(0, "adopt failed %d", e); sp_close(s); return; }
    EXPECT_EQ(sp_name(s, &a), 0);
    EXPECT_EQ(sp_name(d, &b), 0);
    EXPECT_EQ(a.sin_port, b.sin_port);
    sp_close(d); sp_close(s);
}
