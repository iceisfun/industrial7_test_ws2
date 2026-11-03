/* TCP connection establishment over loopback: blocking and non-blocking connect(), the completion
 * signals (writability, exception set, SO_ERROR, FD_CONNECT), refused destinations, queued
 * connections that are accepted later, and the SO_CONNECT_TIME option.
 *
 * Every listener is created by the test on an ephemeral port; refused destinations are ports that
 * were bound and released.  Waits are bounded to a few seconds.
 */
#include "cp.h"

#define WAIT_MS 5000

/* ---- blocking connect --------------------------------------------------------------------- */

TEST(cpf_blocking_connect_succeeds_and_peers_agree)
{
    struct sockaddr_in la, cn, sn, p;
    SOCKET l, c, a = INVALID_SOCKET;
    int n1 = sizeof cn, n2 = sizeof sn, n3 = sizeof p;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    CP_EQ(cp_getsockname(c, (struct sockaddr *)&cn, &n1), 0);
    CP_EQ(cp_getpeername(a, (struct sockaddr *)&p, &n3), 0);
    CHECK(cp_same_addr(&cn, &p));
    CP_EQ(cp_getsockname(a, (struct sockaddr *)&sn, &n2), 0);
    CHECK(cp_peer_is(c, &sn));
    CHECK(cp_same_addr(&sn, &la));
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_blocking_connect_leaves_no_pending_socket_error)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CP_EQ(cp_so_error(c), 0);
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_blocking_connect_completes_before_accept)
{
    /* The handshake is finished by the stack; the application does not need to call accept first. */
    struct sockaddr_in la;
    SOCKET l, c[3], a[3];
    int i;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 5);
    for (i = 0; i < 3; i++) {
        c[i] = cp_socket(AF_INET, SOCK_STREAM, 0);
        CP_EQ(cp_connect(c[i], (struct sockaddr *)&la, sizeof la), 0);
    }
    for (i = 0; i < 3; i++) {
        a[i] = INVALID_SOCKET;
        CHECK(cp_accept_one(l, &a[i], WAIT_MS));
    }
    /* Each accepted socket's peer is one of the connectors' local names, all different. */
    for (i = 0; i < 3; i++) {
        struct sockaddr_in cn; int n = sizeof cn;
        CP_EQ(cp_getsockname(c[i], (struct sockaddr *)&cn, &n), 0);
        int found = 0, j;
        for (j = 0; j < 3; j++) if (a[j] != INVALID_SOCKET && cp_peer_is(a[j], &cn)) found++;
        CP_EQ(found, 1);
    }
    for (i = 0; i < 3; i++) { cp_closesocket(a[i]); cp_closesocket(c[i]); }
    cp_closesocket(l);
}

TEST(cpf_data_sent_right_after_connect_is_readable_after_late_accept)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    char b[8] = {0};
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CP_EQ(cp_send(c, "early", 5, 0), 5);
    Sleep(100);
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    CHECK(cp_wait(a, CP_R, WAIT_MS) & CP_R);
    CP_EQ(cp_recv(a, b, sizeof b, 0), 5);
    CHECK(!memcmp(b, "early", 5));
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_blocking_connect_to_dead_port_is_refused)
{
    struct sockaddr_in d;
    SOCKET s;
    DWORD t0, el;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    t0 = GetTickCount();
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    el = GetTickCount() - t0;
    CHECK(el < 10000);   /* generous bound: a refusal may be retried by the stack, this only guards against a hang */
    cp_closesocket(s);
}

TEST(cpf_wsaconnect_to_dead_port_is_refused)
{
    struct sockaddr_in d;
    SOCKET s;
    REQUIRE(U(WSAConnect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&d, sizeof d, NULL, NULL, NULL, NULL), WSAECONNREFUSED);
    cp_closesocket(s);
}

TEST(cpf_refused_connect_leaves_socket_unconnected)
{
    struct sockaddr_in d;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    {
        char b[2];
        int r;
        cp_WSASetLastError(0);
        r = cp_send(s, "x", 1, 0);
        t_note("send after a refused connect -> %d (err %d)", r, r < 0 ? cp_WSAGetLastError() : 0);
        cp_WSASetLastError(0);
        r = cp_recv(s, b, sizeof b, 0);
        t_note("recv after a refused connect -> %d (err %d)", r, r < 0 ? cp_WSAGetLastError() : 0);
    }
    cp_closesocket(s);
}

TEST(cpf_refused_connect_twice_gives_the_same_answer)
{
    struct sockaddr_in d;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    cp_closesocket(s);
}

TEST(cpf_connect_after_listener_closed_is_refused)
{
    struct sockaddr_in la;
    SOCKET l, c;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_closesocket(l);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAECONNREFUSED);
    cp_closesocket(c);
}

TEST(cpf_bound_but_not_listening_destination_is_refused)
{
    struct sockaddr_in b;
    SOCKET l = cp_listener(&b, 0), c;   /* bound only */
    REQUIRE(U(connect)); NEED();
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&b, sizeof b), WSAECONNREFUSED);
    cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_udp_listener_port_is_not_a_tcp_destination)
{
    struct sockaddr_in u;
    SOCKET us = cp_udp_bound(&u), c;
    REQUIRE(U(connect)); NEED();
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&u, sizeof u), WSAECONNREFUSED);
    cp_closesocket(c); cp_closesocket(us);
}

/* ---- non-blocking connect ----------------------------------------------------------------- */

TEST(cpf_nb_connect_reports_wouldblock_then_becomes_writable)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    int m;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_nb(c, 1), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    m = cp_wait(c, CP_W | CP_X, WAIT_MS);
    CHECK(m & CP_W);
    CHECK(!(m & CP_X));
    CP_EQ(cp_so_error(c), 0);
    CHECK(cp_peer_is(c, &la));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_nb_wsaconnect_reports_wouldblock_too)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    REQUIRE(U(WSAConnect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_WSAConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL), WSAEWOULDBLOCK);
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_nb_connect_again_after_completion_is_eisconn)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEISCONN);
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_nb_connected_socket_can_exchange_data)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    char b[4] = {0};
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    CP_EQ(cp_send(c, "abcd", 4, 0), 4);
    CHECK(cp_wait(a, CP_R, WAIT_MS) & CP_R);
    CP_EQ(cp_recv(a, b, 4, 0), 4);
    CHECK(!memcmp(b, "abcd", 4));
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_nb_refused_connect_signals_exception_set_not_writable)
{
    struct sockaddr_in d;
    SOCKET s;
    int m;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(s, 1);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAEWOULDBLOCK);
    m = cp_wait(s, CP_W | CP_X, WAIT_MS);
    CHECK(m & CP_X);
    CHECK(!(m & CP_W));
    cp_closesocket(s);
}

TEST(cpf_nb_refused_connect_is_invisible_to_a_write_only_wait)
{
    /* A failed connect never makes the socket writable: waiting on the write set alone times out,
     * while the exception set reports it. */
    struct sockaddr_in d;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(s, 1);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAEWOULDBLOCK);
    CP_EQ(cp_wait(s, CP_W, 600), 0);
    CHECK(cp_wait(s, CP_X, WAIT_MS) & CP_X);
    cp_closesocket(s);
}

TEST(cpf_nb_refused_connect_so_error_is_connrefused)
{
    struct sockaddr_in d;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(s, 1);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAEWOULDBLOCK);
    CHECK(cp_wait(s, CP_X, WAIT_MS) & CP_X);
    CP_EQ(cp_so_error(s), WSAECONNREFUSED);
    t_note("second SO_ERROR read after a refused connect = %d", cp_so_error(s));
    cp_closesocket(s);
}

TEST(cpf_nb_refused_connect_leaves_socket_unconnected)
{
    struct sockaddr_in d;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(s, 1);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAEWOULDBLOCK);
    CHECK(cp_wait(s, CP_X, WAIT_MS) & CP_X);
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    cp_closesocket(s);
}

TEST(cpf_nb_connect_to_live_listener_after_a_refusal)
{
    struct sockaddr_in d, la;
    SOCKET l, s, a = INVALID_SOCKET;
    int r;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    l = cp_listener(&la, 1);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(s, 1);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAEWOULDBLOCK);
    CHECK(cp_wait(s, CP_X, WAIT_MS) & CP_X);
    cp_WSASetLastError(0);
    r = cp_connect(s, (struct sockaddr *)&la, sizeof la);
    if (r != 0) {
        CP_EQ(cp_WSAGetLastError(), WSAEWOULDBLOCK);
        CHECK(cp_wait(s, CP_W, WAIT_MS) & CP_W);
    }
    CHECK(cp_peer_is(s, &la));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpf_blocking_socket_made_nonblocking_after_failed_connect_connects_later)
{
    struct sockaddr_in d, la;
    SOCKET l, s, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_dead_port(&d));
    l = cp_listener(&la, 1);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    cp_nb(s, 1);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CHECK(cp_wait(s, CP_W, WAIT_MS) & CP_W);
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

/* ---- event notification --------------------------------------------------------------------- */

TEST(cpf_event_select_makes_blocking_socket_nonblocking_for_connect)
{
    /* WSAEventSelect switches the socket to non-blocking mode, so connect() returns WSAEWOULDBLOCK. */
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    WSAEVENT ev;
    REQUIRE(U(connect)); REQUIRE(U(WSAEventSelect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    ev = cp_WSACreateEvent();
    CP_EQ(cp_WSAEventSelect(c, ev, FD_CONNECT), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, WAIT_MS, FALSE), WSA_WAIT_EVENT_0);
    cp_accept_one(l, &a, WAIT_MS);
    cp_WSAEventSelect(c, NULL, 0);
    cp_WSACloseEvent(ev);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_event_select_connect_success_has_zero_error)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    WSAEVENT ev;
    WSANETWORKEVENTS ne;
    REQUIRE(U(connect)); REQUIRE(U(WSAEventSelect)); REQUIRE(U(WSAEnumNetworkEvents)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    ev = cp_WSACreateEvent();
    CP_EQ(cp_WSAEventSelect(c, ev, FD_CONNECT | FD_WRITE), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, WAIT_MS, FALSE), WSA_WAIT_EVENT_0);
    memset(&ne, 0xCC, sizeof ne);
    CP_EQ(cp_WSAEnumNetworkEvents(c, ev, &ne), 0);
    CHECK(ne.lNetworkEvents & FD_CONNECT);
    CP_EQ(ne.iErrorCode[FD_CONNECT_BIT], 0);
    CHECK(ne.lNetworkEvents & FD_WRITE);
    CP_EQ(ne.iErrorCode[FD_WRITE_BIT], 0);
    CHECK(!(ne.lNetworkEvents & FD_READ));
    cp_accept_one(l, &a, WAIT_MS);
    cp_WSAEventSelect(c, NULL, 0);
    cp_WSACloseEvent(ev);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_event_select_connect_refused_carries_error_and_no_write)
{
    struct sockaddr_in d;
    SOCKET c;
    WSAEVENT ev;
    WSANETWORKEVENTS ne;
    REQUIRE(U(connect)); REQUIRE(U(WSAEventSelect)); REQUIRE(U(WSAEnumNetworkEvents)); NEED();
    CHECK(cp_dead_port(&d));
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    ev = cp_WSACreateEvent();
    CP_EQ(cp_WSAEventSelect(c, ev, FD_CONNECT | FD_WRITE), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&d, sizeof d), WSAEWOULDBLOCK);
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, WAIT_MS, FALSE), WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne);
    CP_EQ(cp_WSAEnumNetworkEvents(c, ev, &ne), 0);
    CHECK(ne.lNetworkEvents & FD_CONNECT);
    CP_EQ(ne.iErrorCode[FD_CONNECT_BIT], WSAECONNREFUSED);
    CHECK(!(ne.lNetworkEvents & FD_WRITE));
    cp_WSAEventSelect(c, NULL, 0);
    cp_WSACloseEvent(ev);
    cp_closesocket(c);
}

TEST(cpf_event_select_connect_event_is_consumed_by_enum)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    WSAEVENT ev;
    WSANETWORKEVENTS ne;
    REQUIRE(U(connect)); REQUIRE(U(WSAEventSelect)); REQUIRE(U(WSAEnumNetworkEvents)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    ev = cp_WSACreateEvent();
    CP_EQ(cp_WSAEventSelect(c, ev, FD_CONNECT), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, WAIT_MS, FALSE), WSA_WAIT_EVENT_0);
    CP_EQ(cp_WSAEnumNetworkEvents(c, ev, &ne), 0);
    CHECK(ne.lNetworkEvents & FD_CONNECT);
    /* The event was reset by the enumeration and FD_CONNECT is reported once. */
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, 150, FALSE), WSA_WAIT_TIMEOUT);
    CP_EQ(cp_WSAEnumNetworkEvents(c, ev, &ne), 0);
    CP_EQ(ne.lNetworkEvents & FD_CONNECT, 0);
    cp_accept_one(l, &a, WAIT_MS);
    cp_WSAEventSelect(c, NULL, 0);
    cp_WSACloseEvent(ev);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

TEST(cpf_event_select_accept_event_fires_on_connect)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    WSAEVENT ev;
    WSANETWORKEVENTS ne;
    REQUIRE(U(connect)); REQUIRE(U(WSAEventSelect)); REQUIRE(U(WSAEnumNetworkEvents)); NEED();
    l = cp_listener(&la, 1);
    ev = cp_WSACreateEvent();
    CP_EQ(cp_WSAEventSelect(l, ev, FD_ACCEPT), 0);
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, 150, FALSE), WSA_WAIT_TIMEOUT);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CP_EQ(cp_WSAWaitForMultipleEvents(1, &ev, FALSE, WAIT_MS, FALSE), WSA_WAIT_EVENT_0);
    CP_EQ(cp_WSAEnumNetworkEvents(l, ev, &ne), 0);
    CHECK(ne.lNetworkEvents & FD_ACCEPT);
    CP_EQ(ne.iErrorCode[FD_ACCEPT_BIT], 0);
    cp_accept_one(l, &a, WAIT_MS);
    cp_WSAEventSelect(l, NULL, 0);
    cp_WSACloseEvent(ev);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}

/* ---- address reuse -------------------------------------------------------------------------- */

TEST(cpf_duplicate_four_tuple_with_reuseaddr_note)
{
    /* Two clients with the same local port connecting to the same listener: record the outcome. */
    struct sockaddr_in la, b = cp_lo4(0), n;
    SOCKET l, s1, s2, a1 = INVALID_SOCKET;
    BOOL on = TRUE;
    int nl = sizeof n, r;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 2);
    s1 = cp_socket(AF_INET, SOCK_STREAM, 0);
    s2 = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_setsockopt(s1, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
    cp_setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
    CP_EQ(cp_bind(s1, (struct sockaddr *)&b, sizeof b), 0);
    CP_EQ(cp_getsockname(s1, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(cp_connect(s1, (struct sockaddr *)&la, sizeof la), 0);
    r = cp_bind(s2, (struct sockaddr *)&n, sizeof n);
    t_note("second bind to the in-use local port with SO_REUSEADDR -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    if (r == 0) {
        r = cp_connect(s2, (struct sockaddr *)&la, sizeof la);
        t_note("connect with a duplicate four-tuple -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    }
    cp_accept_one(l, &a1, WAIT_MS);
    cp_closesocket(a1); cp_closesocket(s1); cp_closesocket(s2); cp_closesocket(l);
}

TEST(cpf_bind_in_use_by_listener_is_addrinuse_not_connect_problem)
{
    /* A connecting socket may not bind a local port that has an exclusive listener on it. */
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_bind(s, (struct sockaddr *)&la, sizeof la), WSAEADDRINUSE);
    cp_closesocket(s); cp_closesocket(l);
}

/* ---- SO_CONNECT_TIME ------------------------------------------------------------------------- */

static unsigned connect_time(SOCKET s, int *rc, int *outlen)
{
    unsigned v = 0x12345678;
    int n = sizeof v;
    *rc = cp_getsockopt(s, SOL_SOCKET, SO_CONNECT_TIME, (char *)&v, &n);
    if (outlen) *outlen = n;
    return v;
}

TEST(cpf_connect_time_unconnected_tcp_is_all_ones)
{
    SOCKET s;
    int rc, n;
    unsigned v;
    REQUIRE(U(getsockopt)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    v = connect_time(s, &rc, &n);
    CP_EQ(rc, 0);
    CP_EQ(n, 4);
    CP_EQ(v, 0xFFFFFFFFu);
    cp_closesocket(s);
}

TEST(cpf_connect_time_listener_is_all_ones)
{
    struct sockaddr_in la;
    SOCKET l;
    int rc;
    REQUIRE(U(getsockopt)); NEED();
    l = cp_listener(&la, 1);
    CP_EQ(connect_time(l, &rc, NULL), 0xFFFFFFFFu);
    CP_EQ(rc, 0);
    cp_closesocket(l);
}

TEST(cpf_connect_time_connected_pair_is_small_on_both_sides)
{
    SOCKET c, s;
    int rc, n;
    unsigned v;
    REQUIRE(U(getsockopt)); NEED();
    CHECK(cp_pair(&c, &s));
    v = connect_time(c, &rc, &n);
    CP_EQ(rc, 0); CP_EQ(n, 4);
    CHECK(v < 30);
    v = connect_time(s, &rc, &n);
    CP_EQ(rc, 0); CP_EQ(n, 4);
    CHECK(v < 30);
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpf_connect_time_counts_seconds_since_connection)
{
    SOCKET c, s;
    int rc;
    unsigned v0, v1;
    REQUIRE(U(getsockopt)); NEED();
    CHECK(cp_pair(&c, &s));
    v0 = connect_time(c, &rc, NULL);
    Sleep(2100);
    v1 = connect_time(c, &rc, NULL);
    CHECK(v1 >= v0 + 2);   /* only a lower bound: at least two whole seconds have passed */
    CHECK(v1 < 60);
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpf_connect_time_refused_attempt_stays_all_ones)
{
    struct sockaddr_in d;
    SOCKET s;
    int rc;
    REQUIRE(U(getsockopt)); NEED();
    CHECK(cp_dead_port(&d));
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    CP_EQ(connect_time(s, &rc, NULL), 0xFFFFFFFFu);
    CP_EQ(rc, 0);
    cp_closesocket(s);
}

TEST(cpf_connect_time_survives_peer_close)
{
    SOCKET c, s;
    int rc;
    unsigned v;
    REQUIRE(U(getsockopt)); NEED();
    CHECK(cp_pair(&c, &s));
    cp_closesocket(s);
    CHECK(cp_wait(c, CP_R, WAIT_MS) & CP_R);   /* FIN delivered */
    v = connect_time(c, &rc, NULL);
    CP_EQ(rc, 0);
    t_note("SO_CONNECT_TIME after the peer closed = %u", v);
    cp_closesocket(c);
}

TEST(cpf_connect_time_datagram_socket_is_all_ones_even_when_connected)
{
    struct sockaddr_in ua;
    SOCKET us = cp_udp_bound(&ua), c;
    int rc;
    REQUIRE(U(getsockopt)); NEED();
    c = cp_socket(AF_INET, SOCK_DGRAM, 0);
    CP_EQ(connect_time(c, &rc, NULL), 0xFFFFFFFFu);
    CP_EQ(cp_connect(c, (struct sockaddr *)&ua, sizeof ua), 0);
    CP_EQ(connect_time(c, &rc, NULL), 0xFFFFFFFFu);
    CP_EQ(rc, 0);
    CP_EQ(connect_time(us, &rc, NULL), 0xFFFFFFFFu);
    cp_closesocket(c); cp_closesocket(us);
}

TEST(cpf_connect_time_short_option_buffer_note)
{
    SOCKET s;
    unsigned char b[2];
    int n = 2, r;
    REQUIRE(U(getsockopt)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    r = cp_getsockopt(s, SOL_SOCKET, SO_CONNECT_TIME, (char *)b, &n);
    t_note("SO_CONNECT_TIME with a 2-byte buffer -> %d (err %d, len %d)", r, r ? cp_WSAGetLastError() : 0, n);
    cp_closesocket(s);
}

TEST(cpf_update_connect_context_after_plain_connect_note)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    int one = 1, r;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    cp_WSASetLastError(0);
    r = cp_setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, (char *)&one, 0);
    t_note("SO_UPDATE_CONNECT_CONTEXT after connect() -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l);
}
