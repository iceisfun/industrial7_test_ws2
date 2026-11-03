/* AF_UNIX stream sockets: readiness and asynchronous I/O. select, WSAPoll and WSAEventSelect on
 * listeners, connecting, connected and closed sockets; overlapped WSARecv/WSASend with events,
 * completion routines and completion ports; cancellation by CancelIoEx and by closing the socket.
 * Every wait is bounded by a few seconds. */
#include "au.h"

/* ---- select ----------------------------------------------------------------------------------- */
TEST(afu_sel_listener_readable_on_pending_connect)
{
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "sel_lis.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    AU_EQ(au_readable(lis, 100), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(au_readable(lis, 3000), 1);
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("sel_lis.sock");
}

TEST(afu_sel_listener_not_readable_after_accept)
{
    TRIO(t, "sel_lis2.sock");
    AU_EQ(au_readable(t.lis, 100), 0);
    au_trio_close(&t);
}

TEST(afu_sel_connected_is_writable)
{
    TRIO(t, "sel_w.sock");
    AU_EQ(au_writable(t.cli, 1000), 1);
    AU_EQ(au_writable(t.srv, 1000), 1);
    au_trio_close(&t);
}

TEST(afu_sel_connected_idle_not_readable)
{
    TRIO(t, "sel_idle.sock");
    AU_EQ(au_readable(t.cli, 100), 0);
    AU_EQ(au_readable(t.srv, 100), 0);
    au_trio_close(&t);
}

TEST(afu_sel_readable_after_send)
{
    TRIO(t, "sel_data.sock");
    AU_EQ(U(send)(t.cli, "d", 1, 0), 1);
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(au_readable(t.cli, 50), 0);
    au_trio_close(&t);
}

TEST(afu_sel_readable_stays_until_drained)
{
    char b[8];
    TRIO(t, "sel_drain.sock");
    AU_EQ(U(send)(t.cli, "abcd", 4, 0), 4);
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(U(recv)(t.srv, b, 2, 0), 2);
    AU_EQ(au_readable(t.srv, 1000), 1);
    AU_EQ(U(recv)(t.srv, b, 2, 0), 2);
    AU_EQ(au_readable(t.srv, 100), 0);
    au_trio_close(&t);
}

TEST(afu_sel_unconnected_socket_flags)
{
    fd_set r, w, e;
    struct timeval tv = { 0, 100000 };
    int n;
    UP();
    SOCK_OR_RETURN(s);
    FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
    FD_SET(s, &r); FD_SET(s, &w); FD_SET(s, &e);
    n = U(select)(0, &r, &w, &e, &tv);
    AU_EQ(n, 0);
    U(closesocket)(s);
}

TEST(afu_sel_nonblocking_connect_becomes_writable)
{
    SOCKADDR_UN a;
    SOCKET c, s;
    TRIO(t, "sel_conn.sock");
    a = t.addr;
    c = au_sock();
    au_blocking(c, FALSE);
    int r = U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    CHECKF(r == 0 || au_err() == WSAEWOULDBLOCK, "connect %d err %d", r, au_err());
    AU_EQ(au_writable(c, 3000), 1);
    s = au_accept_bounded(t.lis);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_sel_failed_connect_fails_synchronously)
{
    /* The path is opened during connect itself, so a non-blocking connect to a missing file fails at once. */
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_blocking(c, FALSE);
    au_addr_leaf(&a, "sel_missing.sock");
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c);
}

TEST(afu_sel_eof_makes_readable)
{
    TRIO(t, "sel_eof.sock");
    U(shutdown)(t.cli, SD_SEND);
    AU_EQ(au_readable(t.srv, 3000), 1);
    au_trio_close(&t);
}

TEST(afu_sel_closed_listener_handle_notsock)
{
    fd_set r;
    struct timeval tv = { 0, 10000 };
    SOCKET s;
    UP();
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    U(closesocket)(s);
    FD_ZERO(&r); FD_SET(s, &r);
    au_seterr(0);
    AU_EQ(U(select)(0, &r, NULL, NULL, &tv), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTSOCK);
}

TEST(afu_sel_mixed_with_tcp_socket)
{
    /* One call can watch a UNIX socket and a TCP socket together. */
    SOCKET tcp;
    fd_set r;
    struct timeval tv = { 0, 100000 };
    int n;
    TRIO(t, "sel_mix.sock");
    tcp = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (tcp == INVALID_SOCKET) { au_trio_close(&t); t_skip("no tcp"); return; }
    U(send)(t.cli, "m", 1, 0);
    Sleep(50);
    FD_ZERO(&r); FD_SET(t.srv, &r); FD_SET(tcp, &r);
    n = U(select)(0, &r, NULL, NULL, &tv);
    AU_EQ(n, 1);
    CHECK(au_isset(t.srv, &r) && !au_isset(tcp, &r));
    U(closesocket)(tcp);
    au_trio_close(&t);
}

/* ---- WSAPoll ------------------------------------------------------------------------------------ */
TEST(afu_poll_listener_pending_is_rdnorm)
{
    SOCKADDR_UN a;
    SOCKET c;
    short ev;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "poll_lis.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    AU_EQ(au_poll1(lis, POLLRDNORM, 50), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    ev = au_poll1(lis, POLLRDNORM, 3000);
    CHECK(ev & POLLRDNORM);
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("poll_lis.sock");
}

TEST(afu_poll_connected_wrnorm)
{
    TRIO(t, "poll_w.sock");
    CHECK(au_poll1(t.cli, POLLWRNORM, 1000) & POLLWRNORM);
    au_trio_close(&t);
}

TEST(afu_poll_connected_idle_no_rdnorm)
{
    TRIO(t, "poll_idle.sock");
    AU_EQ(au_poll1(t.srv, POLLRDNORM, 50), 0);
    au_trio_close(&t);
}

TEST(afu_poll_data_gives_rdnorm)
{
    TRIO(t, "poll_data.sock");
    U(send)(t.cli, "p", 1, 0);
    CHECK(au_poll1(t.srv, POLLRDNORM, 3000) & POLLRDNORM);
    au_trio_close(&t);
}

TEST(afu_poll_peer_close_reports_hup_or_read)
{
    short ev;
    TRIO(t, "poll_hup.sock");
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    ev = au_poll1(t.srv, POLLRDNORM, 3000);
    CHECK(ev & POLLHUP);
    CHECK(!(ev & POLLERR));
    au_trio_close(&t);
}

TEST(afu_poll_abortive_close_reports_error_or_hup)
{
    struct linger lg = { 1, 0 };
    short ev;
    TRIO(t, "poll_rst.sock");
    U(setsockopt)(t.cli, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    ev = au_poll1(t.srv, POLLRDNORM, 3000);
    CHECK(ev & POLLHUP);
    CHECK(ev & POLLERR);
    au_trio_close(&t);
}

TEST(afu_poll_closed_socket_value)
{
    WSAPOLLFD p;
    SOCKET s;
    UP();
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    U(closesocket)(s);
    p.fd = s; p.events = POLLRDNORM; p.revents = 0;
    int r = U(WSAPoll)(&p, 1, 0);
    AU_OBS("WSAPoll on a closed socket", "ret %d err %d revents 0x%x", r, r < 0 ? au_err() : 0, (unsigned)p.revents);
    CHECK(r == SOCKET_ERROR || (r == 1 && (p.revents & POLLNVAL)));
}

TEST(afu_poll_unconnected_has_no_readiness_for_read)
{
    UP();
    SOCK_OR_RETURN(s);
    short ev = au_poll1(s, POLLRDNORM | POLLWRNORM, 50);
    AU_EQ(ev, 0);
    U(closesocket)(s);
}

TEST(afu_poll_array_of_unix_sockets)
{
    WSAPOLLFD p[2];
    int n;
    TRIO(t, "poll_arr.sock");
    U(send)(t.cli, "a", 1, 0);
    p[0].fd = t.srv; p[0].events = POLLRDNORM; p[0].revents = 0;
    p[1].fd = t.cli; p[1].events = POLLRDNORM; p[1].revents = 0;
    Sleep(50);
    n = U(WSAPoll)(p, 2, 3000);
    AU_EQ(n, 1);
    CHECK(p[0].revents & POLLRDNORM);
    AU_EQ(p[1].revents, 0);
    au_trio_close(&t);
}

/* ---- WSAEventSelect ---------------------------------------------------------------------------- */
static long events_now(SOCKET s, WSAEVENT ev, long *errs_nonzero)
{
    WSANETWORKEVENTS ne;
    int i;
    memset(&ne, 0, sizeof(ne));
    if (U(WSAEnumNetworkEvents)(s, ev, &ne) != 0) return -1;
    if (errs_nonzero) { *errs_nonzero = 0; for (i = 0; i < FD_MAX_EVENTS; i++) if (ne.iErrorCode[i]) *errs_nonzero |= 1L << i; }
    return ne.lNetworkEvents;
}

TEST(afu_ev_accept_on_pending_connect)
{
    SOCKADDR_UN a;
    SOCKET c;
    WSAEVENT ev;
    long ne, errs;
    UP();
    SOCK_OR_RETURN(lis);
    ev = U(WSACreateEvent)();
    AU_EQ(au_bind_leaf(lis, "ev_acc.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    AU_EQ(U(WSAEventSelect)(lis, ev, FD_ACCEPT), 0);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 100, FALSE), WSA_WAIT_TIMEOUT);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(lis, ev, &errs);
    AU_EQ(ne, FD_ACCEPT);
    AU_EQ(errs, 0);
    U(closesocket)(c); U(closesocket)(lis);
    U(WSACloseEvent)(ev);
    au_unlink_leaf("ev_acc.sock");
}

TEST(afu_ev_connect_and_write_on_nonblocking_connect)
{
    SOCKADDR_UN a;
    SOCKET c, s;
    WSAEVENT ev;
    long ne, errs;
    TRIO(t, "ev_conn.sock");
    a = t.addr;
    c = au_sock();
    ev = U(WSACreateEvent)();
    AU_EQ(U(WSAEventSelect)(c, ev, FD_CONNECT | FD_WRITE), 0);
    int r = U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    CHECKF(r == 0 || au_err() == WSAEWOULDBLOCK, "err %d", au_err());
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(c, ev, &errs);
    CHECK(ne & FD_CONNECT);
    AU_EQ(errs, 0);
    s = au_accept_bounded(t.lis);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c);
    U(WSACloseEvent)(ev);
    au_trio_close(&t);
}

TEST(afu_ev_connect_failure_is_synchronous)
{
    SOCKADDR_UN a;
    SOCKET c;
    WSAEVENT ev;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    ev = U(WSACreateEvent)();
    AU_EQ(U(WSAEventSelect)(c, ev, FD_CONNECT), 0);
    au_addr_leaf(&a, "ev_missing.sock");
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c);
    U(WSACloseEvent)(ev);
}

TEST(afu_ev_read_and_close)
{
    WSAEVENT ev;
    long ne, errs;
    TRIO(t, "ev_rc.sock");
    ev = U(WSACreateEvent)();
    AU_EQ(U(WSAEventSelect)(t.srv, ev, FD_READ | FD_CLOSE), 0);
    U(WSAResetEvent)(ev);
    AU_EQ(U(send)(t.cli, "r", 1, 0), 1);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(t.srv, ev, &errs);
    CHECK(ne & FD_READ);
    CHECK(!(ne & FD_CLOSE));
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(t.srv, ev, &errs);
    CHECK(ne & FD_CLOSE);
    AU_EQ(errs & (1L << FD_CLOSE_BIT), 0);
    U(WSACloseEvent)(ev);
    au_trio_close(&t);
}

TEST(afu_ev_close_after_abortive_has_error)
{
    struct linger lg = { 1, 0 };
    WSAEVENT ev;
    long ne, errs;
    TRIO(t, "ev_rstc.sock");
    ev = U(WSACreateEvent)();
    AU_EQ(U(WSAEventSelect)(t.srv, ev, FD_CLOSE), 0);
    U(setsockopt)(t.cli, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(t.srv, ev, &errs);
    CHECK(ne & FD_CLOSE);
    CHECK(errs & (1L << FD_CLOSE_BIT));
    U(WSACloseEvent)(ev);
    au_trio_close(&t);
}

TEST(afu_ev_write_after_drain)
{
    static char chunk[16384], sink[65536];
    WSAEVENT ev;
    long ne, errs;
    int r, guard = 0;
    TRIO(t, "ev_wr.sock");
    memset(chunk, 'w', sizeof(chunk));
    ev = U(WSACreateEvent)();
    au_blocking(t.cli, FALSE); au_blocking(t.srv, FALSE);
    AU_EQ(U(WSAEventSelect)(t.cli, ev, FD_WRITE), 0);
    events_now(t.cli, ev, &errs);
    for (guard = 0; guard < 8192; guard++) { r = U(send)(t.cli, chunk, sizeof(chunk), 0); if (r == SOCKET_ERROR) break; }
    AU_EQ(au_err(), WSAEWOULDBLOCK);
    events_now(t.cli, ev, &errs);
    U(WSAResetEvent)(ev);
    while ((r = U(recv)(t.srv, sink, sizeof(sink), 0)) > 0) {}
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(t.cli, ev, &errs);
    CHECK(ne & FD_WRITE);
    U(WSACloseEvent)(ev);
    au_trio_close(&t);
}

TEST(afu_ev_select_makes_socket_nonblocking)
{
    WSAEVENT ev;
    char b[4];
    TRIO(t, "ev_nb.sock");
    ev = U(WSACreateEvent)();
    AU_EQ(U(WSAEventSelect)(t.srv, ev, FD_READ), 0);
    au_seterr(0);
    AU_EQ(U(recv)(t.srv, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEWOULDBLOCK);
    AU_EQ(U(WSAEventSelect)(t.srv, NULL, 0), 0);
    U(WSACloseEvent)(ev);
    au_trio_close(&t);
}

TEST(afu_ev_enum_clears_event_and_pending)
{
    WSAEVENT ev;
    long ne, errs;
    TRIO(t, "ev_enum.sock");
    ev = U(WSACreateEvent)();
    AU_EQ(U(WSAEventSelect)(t.srv, ev, FD_READ), 0);
    U(WSAResetEvent)(ev);
    U(send)(t.cli, "e", 1, 0);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ne = events_now(t.srv, ev, &errs);
    CHECK(ne & FD_READ);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    ne = events_now(t.srv, ev, &errs);
    AU_EQ(ne, 0);
    U(WSACloseEvent)(ev);
    au_trio_close(&t);
}

/* ---- overlapped I/O ---------------------------------------------------------------------------- */
TEST(afu_ov_recv_pending_then_data)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8] = {0};
    DWORD got = 0, fl = 0;
    BOOL ok;
    int r;
    TRIO(t, "ov_recv.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSA_IO_PENDING);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 100, FALSE), WSA_WAIT_TIMEOUT);
    au_seterr(0);
    ok = U(WSAGetOverlappedResult)(t.srv, &ov, &got, FALSE, &fl);
    CHECK(!ok);
    AU_EQ(au_err(), WSA_IO_INCOMPLETE);
    U(send)(t.cli, "ovl", 3, 0);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ok = U(WSAGetOverlappedResult)(t.srv, &ov, &got, FALSE, &fl);
    CHECK(ok);
    AU_EQ(got, 3);
    CHECK(!memcmp(buf, "ovl", 3));
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

TEST(afu_ov_recv_immediate_when_data_waiting)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8] = {0};
    DWORD got = 0, fl = 0;
    int r;
    TRIO(t, "ov_imm.sock");
    U(send)(t.cli, "now", 3, 0);
    AU_EQ(au_readable(t.srv, 3000), 1);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    if (r == 0) AU_EQ(got, 3);
    else { AU_EQ(au_err(), WSA_IO_PENDING); AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0); }
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

TEST(afu_ov_recv_eof_completes_with_zero)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8];
    DWORD got = 9, fl = 0;
    BOOL ok;
    int r;
    TRIO(t, "ov_eof.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    CHECK(r == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    U(shutdown)(t.cli, SD_SEND);
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ok = U(WSAGetOverlappedResult)(t.srv, &ov, &got, FALSE, &fl);
    CHECK(ok);
    AU_EQ(got, 0);
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

TEST(afu_ov_send_completes)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8] = {0};
    DWORD sent = 0, fl = 0;
    int r;
    TRIO(t, "ov_send.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = (CHAR *)"sent!"; b.len = 5;
    r = U(WSASend)(t.cli, &b, 1, &sent, 0, &ov, NULL);
    if (r != 0) { AU_EQ(au_err(), WSA_IO_PENDING); AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0); }
    CHECK(U(WSAGetOverlappedResult)(t.cli, &ov, &sent, FALSE, &fl));
    AU_EQ(sent, 5);
    AU_EQ(au_recv_n(t.srv, buf, 5), 5);
    CHECK(!memcmp(buf, "sent!", 5));
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

static volatile LONG g_cr_calls;
static volatile DWORD g_cr_bytes, g_cr_err;
static void CALLBACK cr_routine(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD flags)
{
    g_cr_err = err; g_cr_bytes = bytes; InterlockedIncrement(&g_cr_calls);
}
TEST(afu_ov_completion_routine_runs_when_alertable)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8] = {0};
    DWORD got = 0, fl = 0, w;
    int r;
    TRIO(t, "ov_cr.sock");
    g_cr_calls = 0; g_cr_bytes = 0; g_cr_err = 99;
    memset(&ov, 0, sizeof(ov));
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, cr_routine);
    CHECK(r == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    U(send)(t.cli, "cr", 2, 0);
    w = SleepEx(3000, TRUE);
    AU_EQ(w, WAIT_IO_COMPLETION);
    AU_EQ(g_cr_calls, 1);
    AU_EQ(g_cr_bytes, 2);
    AU_EQ(g_cr_err, 0);
    au_trio_close(&t);
}

TEST(afu_ov_cancelioex_aborts_pending_recv)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8];
    DWORD got = 0, fl = 0;
    BOOL ok;
    int r;
    TRIO(t, "ov_cancel.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    CHECK(r == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    CHECK(CancelIoEx((HANDLE)t.srv, &ov));
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    au_seterr(0);
    ok = U(WSAGetOverlappedResult)(t.srv, &ov, &got, FALSE, &fl);
    CHECK(!ok);
    AU_EQ(au_err(), WSA_OPERATION_ABORTED);
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

TEST(afu_ov_cancelio_nothing_pending)
{
    BOOL ok;
    TRIO(t, "ov_cancel0.sock");
    SetLastError(0);
    ok = CancelIo((HANDLE)t.srv);
    CHECK(ok);
    au_trio_close(&t);
}

TEST(afu_ov_close_aborts_pending_recv)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8];
    DWORD got = 0, fl = 0;
    BOOL ok;
    int r;
    TRIO(t, "ov_close.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    CHECK(r == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    SOCKET srv = t.srv;
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    au_seterr(0);
    ok = U(WSAGetOverlappedResult)(srv, &ov, &got, FALSE, &fl);
    AU_EQ(ok, 0);
    AU_EQ(au_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

TEST(afu_ov_many_pending_recvs_complete_in_order)
{
    WSAOVERLAPPED ov[3];
    WSABUF b[3];
    char buf[3][4];
    DWORD got, fl;
    int i;
    TRIO(t, "ov_many.sock");
    for (i = 0; i < 3; i++) {
        memset(&ov[i], 0, sizeof(ov[i]));
        ov[i].hEvent = U(WSACreateEvent)();
        memset(buf[i], 0, 4);
        b[i].buf = buf[i]; b[i].len = 1;
        fl = 0;
        CHECK(U(WSARecv)(t.srv, &b[i], 1, &got, &fl, &ov[i], NULL) == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    }
    U(send)(t.cli, "xyz", 3, 0);
    for (i = 0; i < 3; i++) {
        AU_EQ(U(WSAWaitForMultipleEvents)(1, &ov[i].hEvent, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
        fl = 0;
        CHECK(U(WSAGetOverlappedResult)(t.srv, &ov[i], &got, FALSE, &fl));
        AU_EQ(got, 1);
        AU_EQ(buf[i][0], "xyz"[i]);
        U(WSACloseEvent)(ov[i].hEvent);
    }
    au_trio_close(&t);
}

TEST(afu_ov_iocp_receives_recv_completion)
{
    HANDLE port, p2;
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8] = {0};
    DWORD got = 0, fl = 0, bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED pov = NULL;
    TRIO(t, "ov_iocp.sock");
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    p2 = CreateIoCompletionPort((HANDLE)t.srv, port, 0x77, 0);
    CHECK(p2 == port);
    memset(&ov, 0, sizeof(ov));
    b.buf = buf; b.len = sizeof(buf);
    CHECK(U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL) == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    U(send)(t.cli, "port", 4, 0);
    CHECK(GetQueuedCompletionStatus(port, &bytes, &key, &pov, 3000));
    AU_EQ(bytes, 4);
    AU_EQ(key, 0x77);
    CHECK(pov == (LPOVERLAPPED)&ov);
    CHECK(!memcmp(buf, "port", 4));
    CloseHandle(port);
    au_trio_close(&t);
}

TEST(afu_ov_iocp_close_delivers_abort)
{
    HANDLE port;
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8];
    DWORD got = 0, fl = 0, bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED pov = NULL;
    BOOL ok;
    TRIO(t, "ov_iocp2.sock");
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CreateIoCompletionPort((HANDLE)t.srv, port, 5, 0);
    memset(&ov, 0, sizeof(ov));
    b.buf = buf; b.len = sizeof(buf);
    CHECK(U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL) == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    SetLastError(0);
    ok = GetQueuedCompletionStatus(port, &bytes, &key, &pov, 3000);
    AU_EQ(ok, 0);
    AU_EQ(GetLastError(), ERROR_CONNECTION_ABORTED);
    CHECK(pov == (LPOVERLAPPED)&ov);
    CloseHandle(port);
    au_trio_close(&t);
}

TEST(afu_ov_skip_completion_on_success)
{
    /* With SKIP_COMPLETION_PORT_ON_SUCCESS set, an immediately completed operation queues no packet. */
    HANDLE port;
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8];
    DWORD got = 0, fl = 0, bytes = 0;
    ULONG_PTR key;
    LPOVERLAPPED pov;
    int r;
    TRIO(t, "ov_skip.sock");
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CreateIoCompletionPort((HANDLE)t.srv, port, 1, 0);
    if (!SetFileCompletionNotificationModes((HANDLE)t.srv, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS)) {
        AU_OBS("SetFileCompletionNotificationModes", "error %lu", GetLastError()); CloseHandle(port); au_trio_close(&t); return;
    }
    U(send)(t.cli, "s", 1, 0);
    AU_EQ(au_readable(t.srv, 3000), 1);
    memset(&ov, 0, sizeof(ov));
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    AU_OBS("recv with skip flag", "ret %d", r);
    if (r == 0) CHECK(!GetQueuedCompletionStatus(port, &bytes, &key, &pov, 200));
    CloseHandle(port);
    au_trio_close(&t);
}

TEST(afu_ov_overlapped_result_wait_true)
{
    WSAOVERLAPPED ov;
    WSABUF b;
    char buf[8];
    DWORD got = 0, fl = 0;
    int r;
    TRIO(t, "ov_wait.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    b.buf = buf; b.len = sizeof(buf);
    r = U(WSARecv)(t.srv, &b, 1, &got, &fl, &ov, NULL);
    CHECK(r == SOCKET_ERROR && au_err() == WSA_IO_PENDING);
    U(shutdown)(t.cli, SD_SEND);
    CHECK(U(WSAGetOverlappedResult)(t.srv, &ov, &got, TRUE, &fl));
    AU_EQ(got, 0);
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

TEST(afu_ov_wsarecv_nonoverlapped_socket_blocks_then_completes)
{
    /* A socket created without the overlapped flag still serves a plain blocking WSARecv. */
    SOCKADDR_UN a;
    SOCKET c, s;
    WSABUF b;
    char buf[8] = {0};
    DWORD got = 0, fl = 0;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "ov_plain.sock", &a), 0);
    AU_EQ(U(listen)(lis, 1), 0);
    c = au_sock_flags(0);
    s = au_connect_accept(lis, c, &a);
    if (s != INVALID_SOCKET) {
        au_rcvtimeo(c, 3000);
        U(send)(s, "plain", 5, 0);
        b.buf = buf; b.len = sizeof(buf);
        AU_EQ(U(WSARecv)(c, &b, 1, &got, &fl, NULL, NULL), 0);
        AU_EQ(got, 5);
        U(closesocket)(s);
    }
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("ov_plain.sock");
}

TEST(afu_ov_listener_accept_by_event_select_then_accept)
{
    SOCKADDR_UN a;
    SOCKET c, s;
    WSAEVENT ev;
    UP();
    SOCK_OR_RETURN(lis);
    ev = U(WSACreateEvent)();
    AU_EQ(au_bind_leaf(lis, "ov_accev.sock", &a), 0);
    AU_EQ(U(listen)(lis, 1), 0);
    AU_EQ(U(WSAEventSelect)(lis, ev, FD_ACCEPT), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    s = U(accept)(lis, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        int v = 0, l = sizeof(v);
        /* The accepted socket inherits the event registration. */
        u_long n = 0;
        AU_OBS("accepted socket blocking after listener event select", "%s", U(ioctlsocket)(s, FIONREAD, &n) == 0 ? "ioctl ok" : "ioctl failed");
        (void)v; (void)l;
        U(closesocket)(s);
    }
    U(closesocket)(c); U(closesocket)(lis);
    U(WSACloseEvent)(ev);
    au_unlink_leaf("ov_accev.sock");
}
