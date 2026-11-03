/* SO_LINGER on TCP: value coding, and the observable difference between an abortive close (linger on, zero
 * timeout: the peer sees a reset) and a graceful one (peer reads the data then end-of-stream). All peers are
 * loopback sockets of this process; waits are bounded. */
#include "xt.h"

static xt_res set_linger(SOCKET s, u_short on, u_short secs)
{
    struct linger l; l.l_onoff = on; l.l_linger = secs;
    return xt_so(s, SOL_SOCKET, SO_LINGER, &l, sizeof l);
}
static int get_linger(SOCKET s, struct linger *l)
{
    int n = sizeof *l; xt_res r = xt_go(s, SOL_SOCKET, SO_LINGER, l, &n);
    return r.rc ? r.err : 0;
}
static int recv_err(SOCKET s, char *b, int n, int *e)
{
    int r = U(recv)(s, b, n, 0);
    *e = r < 0 ? U(WSAGetLastError)() : 0;
    return r;
}

/* ---- value coding ------------------------------------------------------------------------------------------ */
TEST(linger_default_is_off_with_zero_timeout)
{
    SOCKET s; struct linger l; int n = sizeof l; xt_res r;
    NEED();
    s = xt_tcp(); l.l_onoff = 7; l.l_linger = 7;
    r = xt_go(s, SOL_SOCKET, SO_LINGER, &l, &n);
    EQ(r.rc, 0); EQ(n, 4); EQ(l.l_onoff, 0); EQ(l.l_linger, 0);
    xt_close(s);
}
TEST(linger_values_roundtrip_in_a_table)
{
    static const struct { u_short on, secs; } rows[] = {{1, 0}, {1, 1}, {1, 30}, {1, 65535}, {0, 0}, {0, 5}, {5, 65535}, {65535, 1}, {2, 2}};
    SOCKET s; unsigned i;
    NEED();
    s = xt_tcp();
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        struct linger g; xt_res r = set_linger(s, rows[i].on, rows[i].secs);
        EQ(r.rc, 0);
        EQ(get_linger(s, &g), 0);
        CHECKF(g.l_onoff == rows[i].on && g.l_linger == rows[i].secs, "row %u: got %u/%u want %u/%u", i, g.l_onoff, g.l_linger, rows[i].on, rows[i].secs);
    }
    xt_close(s);
}
TEST(linger_option_length_rules)
{
    SOCKET s; struct linger l = {1, 3}; char big[16] = {1, 0, 3, 0}; xt_res r;
    NEED();
    s = xt_tcp();
    r = xt_so(s, SOL_SOCKET, SO_LINGER, &l, 3); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT);
    r = xt_so(s, SOL_SOCKET, SO_LINGER, &l, 4); EQ(r.rc, 0);
    r = xt_so(s, SOL_SOCKET, SO_LINGER, big, 8); EQ(r.rc, 0);
    r = xt_so(s, SOL_SOCKET, SO_LINGER, big, 16); EQ(r.rc, 0);
    xt_close(s);
}
TEST(linger_failed_set_keeps_previous_value)
{
    SOCKET s; struct linger g; struct linger l = {1, 9};
    NEED();
    s = xt_tcp();
    EQ(set_linger(s, 1, 4).rc, 0);
    EQ(xt_so(s, SOL_SOCKET, SO_LINGER, &l, 3).rc, SOCKET_ERROR);
    EQ(get_linger(s, &g), 0); EQ(g.l_onoff, 1); EQ(g.l_linger, 4);
    xt_close(s);
}
TEST(linger_dontlinger_accepts_a_boolean)
{
    SOCKET s; int one = 1;
    NEED();
    s = xt_tcp();
    EQ(xt_so(s, SOL_SOCKET, SO_DONTLINGER, &one, 4).rc, 0);
    xt_close(s);
}
TEST(linger_set_while_connected_is_accepted)
{
    SOCKET c, a, l; struct linger g;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(set_linger(c, 1, 0).rc, 0); EQ(get_linger(c, &g), 0); EQ(g.l_onoff, 1); EQ(g.l_linger, 0);
    EQ(set_linger(a, 1, 7).rc, 0); EQ(get_linger(a, &g), 0); EQ(g.l_onoff, 1); EQ(g.l_linger, 7);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(linger_setting_on_a_listener_is_inherited_by_accepted_sockets)
{
    SOCKET l, c, a; u_short p; struct linger g;
    NEED();
    EQ(xt_listen_lo(&l, &p, 2), 1);
    EQ(set_linger(l, 1, 11).rc, 0);
    c = xt_tcp(); EQ(xt_connect_lo(c, p), 0);
    CHECK(xt_readable(l, 3000));
    a = xt_accept(l);
    EQ(get_linger(a, &g), 0);
    EQ(g.l_onoff, 1); EQ(g.l_linger, 11);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- abortive close: the peer sees a reset ----------------------------------------------------------------- */
/* side 0: the connecting socket closes abortively; side 1: the accepted socket does. */
static void abortive_case(int side)
{
    SOCKET c, a, l, x, y; char b[16]; int e, r; xt_info0 inf; DWORD v = 0; xt_res ri;
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    x = side ? a : c; y = side ? c : a;
    EQ(set_linger(x, 1, 0).rc, 0);
    EQ(xt_send(x, "ab", 2), 2);
    xt_close(x);
    CHECK(xt_readable(y, 3000));
    r = recv_err(y, b, 16, &e); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    r = recv_err(y, b, 16, &e); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    r = xt_send(y, "z", 1); e = U(WSAGetLastError)(); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    ri = xt_io(y, XT_SIO_TCP_INFO, &v, 4, &inf, sizeof inf);
    EQ(ri.rc, 0); EQ(inf.State, 0);
    xt_close(y); xt_close(l);
}
TEST(linger_abortive_close_by_client_resets_the_accepted_socket) { NEED(); abortive_case(0); }
TEST(linger_abortive_close_by_accepted_socket_resets_the_client) { NEED(); abortive_case(1); }
TEST(linger_abortive_close_discards_data_already_sent)
{
    SOCKET c, a, l; char b[16]; int e, r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(c, "abcdef", 6), 6);
    CHECK(xt_wait_state(a, 4, 1000));
    { xt_info1 i; DWORD v = 1; int k; for (k = 0; k < 100; k++) { xt_io(a, XT_SIO_TCP_INFO, &v, 4, &i, sizeof i); if (i.b.BytesIn == 6) break; Sleep(20); } EQ(i.b.BytesIn, 6); }
    EQ(set_linger(c, 1, 0).rc, 0);
    xt_close(c);
    CHECK(xt_readable(a, 3000));
    r = recv_err(a, b, 16, &e);
    EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    xt_close(a); xt_close(l);
}
TEST(linger_abortive_close_of_idle_pair_is_also_a_reset)
{
    SOCKET c, a, l; char b[16]; int e, r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(set_linger(c, 1, 0).rc, 0);
    xt_close(c);
    CHECK(xt_readable(a, 3000));
    r = recv_err(a, b, 16, &e); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    xt_close(a); xt_close(l);
}

/* ---- graceful close: data, then end-of-stream --------------------------------------------------------------- */
static void graceful_case(int side, u_short on, u_short secs)
{
    SOCKET c, a, l, x, y; char b[16]; int e, r;
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    x = side ? a : c; y = side ? c : a;
    EQ(set_linger(x, on, secs).rc, 0);
    EQ(xt_send(x, "ab", 2), 2);
    xt_close(x);
    CHECK(xt_readable(y, 3000));
    r = recv_err(y, b, 16, &e); EQ(r, 2); EQ(e, 0);
    r = recv_err(y, b, 16, &e); EQ(r, 0); EQ(e, 0);
    r = recv_err(y, b, 16, &e); EQ(r, 0); EQ(e, 0);
    xt_close(y); xt_close(l);
}
TEST(linger_off_zero_close_is_graceful_from_client) { NEED(); graceful_case(0, 0, 0); }
TEST(linger_off_zero_close_is_graceful_from_accepted) { NEED(); graceful_case(1, 0, 0); }
TEST(linger_off_with_timeout_is_graceful) { NEED(); graceful_case(0, 0, 5); }
TEST(linger_on_with_timeout_is_graceful_from_client) { NEED(); graceful_case(0, 1, 5); }
TEST(linger_on_with_timeout_is_graceful_from_accepted) { NEED(); graceful_case(1, 1, 5); }
TEST(linger_plain_close_with_unread_incoming_data_resets_the_peer)
{
    SOCKET c, a, l; char b[16]; int e, r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(a, "q", 1), 1);
    { xt_info1 i; DWORD v = 1; int k; for (k = 0; k < 100; k++) { xt_io(c, XT_SIO_TCP_INFO, &v, 4, &i, sizeof i); if (i.b.BytesIn == 1) break; Sleep(20); } EQ(i.b.BytesIn, 1); }
    xt_close(c);                         /* closes with a byte nobody read */
    CHECK(xt_readable(a, 3000));
    r = recv_err(a, b, 16, &e); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    xt_close(a); xt_close(l);
}
TEST(linger_graceful_shutdown_then_close_has_no_reset)
{
    SOCKET c, a, l; char b[16]; int e, r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(c, "xyz", 3), 3);
    EQ(U(shutdown)(c, SD_SEND), 0);
    xt_close(c);
    r = recv_err(a, b, 16, &e); EQ(r, 3);
    r = recv_err(a, b, 16, &e); EQ(r, 0);
    xt_close(a); xt_close(l);
}

TEST(linger_abortive_close_after_send_shutdown_still_ends_as_plain_end_of_stream)
{
    SOCKET c, a, l; char b[16]; int e, r;
    struct linger z = {1, 0};
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    xt_so(c, SOL_SOCKET, SO_LINGER, &z, sizeof z);
    EQ(U(shutdown)(c, SD_SEND), 0);
    CHECK(xt_wait_state(a, 7, 3000));
    xt_close(c);
    Sleep(100);
    r = recv_err(a, b, 16, &e); EQ(r, 0); EQ(e, 0);
    r = recv_err(a, b, 16, &e); EQ(r, 0); EQ(e, 0);
    xt_close(a); xt_close(l);
}
TEST(linger_abortive_close_from_close_wait_resets_the_half_closed_peer)
{
    SOCKET c, a, l; char b[16]; int e, r;
    struct linger z = {1, 0};
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    xt_so(a, SOL_SOCKET, SO_LINGER, &z, sizeof z);
    EQ(U(shutdown)(c, SD_SEND), 0);
    CHECK(xt_wait_state(a, 7, 3000));
    r = recv_err(a, b, 16, &e); EQ(r, 0);
    xt_close(a);
    CHECK(xt_readable(c, 3000));
    r = recv_err(c, b, 16, &e); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    r = xt_send(c, "x", 1); e = U(WSAGetLastError)(); EQ(r, SOCKET_ERROR); EQ(e, WSAESHUTDOWN);
    xt_close(c); xt_close(l);
}
TEST(linger_after_reset_so_error_stays_clear_and_name_queries_still_work)
{
    SOCKET c, a, l; char b[16]; int e; long long v1 = -1, v2 = -1; struct sockaddr_in pa; int pl = sizeof pa; fd_set ex; struct timeval tv = {0, 0};
    struct linger z = {1, 0};
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    xt_so(c, SOL_SOCKET, SO_LINGER, &z, sizeof z); xt_close(c);
    CHECK(xt_readable(a, 3000));
    EQ(xt_geti(a, SOL_SOCKET, SO_ERROR, &v1), 0); EQ(v1, 0);
    EQ(xt_geti(a, SOL_SOCKET, SO_ERROR, &v2), 0); EQ(v2, 0);
    ex.fd_count = 1; ex.fd_array[0] = a;
    EQ(U(select)(0, NULL, NULL, &ex, &tv), 0);
    EQ(U(getpeername)(a, (struct sockaddr *)&pa, &pl), 0);
    EQ(U(shutdown)(a, SD_SEND), 0);
    EQ(recv_err(a, b, 16, &e), SOCKET_ERROR); EQ(e, WSAECONNRESET);
    xt_close(a); xt_close(l);
}
TEST(linger_pending_incoming_data_is_discarded_by_the_reset)
{
    SOCKET c, a, l; char b[16]; int e, r; u_long n = 99;
    struct linger z = {1, 0};
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(c, "abc", 3), 3);
    { xt_info1 i; DWORD v = 1; int k; for (k = 0; k < 100; k++) { xt_io(a, XT_SIO_TCP_INFO, &v, 4, &i, sizeof i); if (i.b.BytesIn == 3) break; Sleep(20); } EQ(i.b.BytesIn, 3); }
    xt_so(c, SOL_SOCKET, SO_LINGER, &z, sizeof z); xt_close(c);
    CHECK(xt_readable(a, 3000));        /* a reset makes the socket readable */
    EQ(U(ioctlsocket)(a, FIONREAD, &n), 0); EQ(n, 0);
    r = U(recv)(a, b, 16, MSG_PEEK); e = r < 0 ? U(WSAGetLastError)() : 0;
    EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    xt_close(a); xt_close(l);
}
TEST(linger_closing_a_listener_resets_queued_connections)
{
    SOCKET l, c; u_short p; char b[16]; int e, r;
    NEED();
    EQ(xt_listen_lo(&l, &p, 4), 1);
    c = xt_tcp(); EQ(xt_connect_lo(c, p), 0);
    xt_close(l);
    CHECK(xt_readable(c, 3000));
    r = recv_err(c, b, 16, &e); EQ(r, SOCKET_ERROR); EQ(e, WSAECONNRESET);
    xt_close(c);
}
TEST(linger_nonblocking_close_with_timeout_returns_zero_and_delivers_data)
{
    SOCKET c, a, l; char b[4]; struct linger g = {1, 2}; u_long nb = 1;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_so(c, SOL_SOCKET, SO_LINGER, &g, sizeof g).rc, 0);
    EQ(U(ioctlsocket)(c, FIONBIO, &nb), 0);
    EQ(xt_send(c, "xy", 2), 2);
    EQ(U(closesocket)(c), 0);
    EQ(xt_recv_all(a, b, 2, 3000), 2);
    xt_close(a); xt_close(l);
}
