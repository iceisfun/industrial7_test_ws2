/* Measures the edge-triggered behaviour of event-based selection on loopback TCP: which events a
 * selection reports at once for a socket that is already connected, whether re-selecting the same mask
 * re-raises anything, how FD_READ / FD_WRITE / FD_OOB / FD_ACCEPT are re-armed, the FD_CLOSE rules
 * (graceful close, half close, data still unread, close before select), and the optional second event
 * that accompanies FD_CONNECT.  Expectations follow a Windows 10 stack. */
#include "ese.h"

/* Wait (bounded) for the event, enumerate with it, compare the reported mask with `want`; bits in `opt`
 * may or may not be present.  When nothing is expected only a short absence window is observed. */
static void es_expect(int line, SOCKET s, HANDLE ev, LONG want, LONG opt)
{
    LONG m;
    if (want) es_wait(ev, 2000); else es_wait(ev, 150);
    m = es_mask(s, ev);
    t_check(m >= 0 && (m & ~opt) == want, __FILE__, line, "event mask", "got %ld want %ld (optional %ld)", m, want, opt);
}
#define EXPECT_EV(s, ev, want)        es_expect(__LINE__, (s), (ev), (want), 0)
#define EXPECT_EV_OPT(s, ev, want, o) es_expect(__LINE__, (s), (ev), (want), (o))
#define EXPECT_NONE(s, ev)            es_expect(__LINE__, (s), (ev), 0, 0)
#define ES_ALLTCP (FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE)

static void es_rst_close(SOCKET s)
{
    struct linger l; l.l_onoff = 1; l.l_linger = 0;
    U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
    U(closesocket)(s);
}
static void es_reselect(SOCKET s, HANDLE ev, LONG mask)
{
    CHECK(U(WSAEventSelect)(s, ev, mask) == 0);
}

/* ---- connect ------------------------------------------------------------------------------------------ */
ESTEST(ese_sem_connect_reports_connect_then_nothing)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 2), c = es_sock(SOCK_STREAM), v; HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    es_reselect(c, ev, ES_ALLTCP);
    EXPECT_NONE(c, ev);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    EXPECT_EV_OPT(c, ev, FD_CONNECT, FD_WRITE);
    es_wait(ev, 100); es_mask(c, ev);                    /* a separate late FD_WRITE is tolerated */
    EXPECT_NONE(c, ev);
    v = U(accept)(l, NULL, NULL);
    es_close(v); es_close(c); es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_reselect_same_mask_does_not_rerun_connect_or_write)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(c, ev, ES_ALLTCP);
    EXPECT_EV_OPT(c, ev, FD_CONNECT, FD_WRITE);
    es_wait(ev, 100); es_mask(c, ev);
    es_reselect(c, ev, ES_ALLTCP);
    EXPECT_NONE(c, ev);
    es_reselect(c, ev, 0);
    es_reselect(c, ev, ES_ALLTCP);
    EXPECT_NONE(c, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_select_after_connect_reports_connect_and_write)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(es_send_all(c, "data", 5) == 5);
    es_reselect(c, ev, ES_ALLTCP);
    EXPECT_EV_OPT(c, ev, FD_CONNECT, FD_WRITE);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_accepted_socket_select_without_connect_reports_write)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    EXPECT_EV(v, ev, FD_WRITE);
    EXPECT_NONE(v, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_connect_event_selected_late_reports_only_connect)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 2), c = es_sock(SOCK_STREAM), v; HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    es_reselect(c, ev, FD_ACCEPT | FD_CLOSE | FD_OOB | FD_READ | FD_WRITE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    v = U(accept)(l, NULL, NULL);
    EXPECT_EV(c, ev, FD_WRITE);
    es_reselect(c, ev, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    EXPECT_EV(c, ev, FD_CONNECT);
    es_close(v); es_close(c); es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_write_selected_late_reports_write_only)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(es_send_all(c, "data", 5) == 5);
    es_reselect(c, ev, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_EV(c, ev, FD_CONNECT);
    EXPECT_NONE(c, ev);
    es_reselect(c, ev, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    EXPECT_EV(c, ev, FD_WRITE);
    EXPECT_NONE(c, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}

/* ---- write -------------------------------------------------------------------------------------------- */
ESTEST(ese_sem_send_does_not_clear_pending_write)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    CHECK(es_send_all(v, "data", 5) == 5);
    EXPECT_EV(v, ev, FD_WRITE);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_write_rearmed_after_send_buffer_drains)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); static char blk[8192]; int i, r = 0, blocked = 0;
    REQUIRE(ev);
    es_reselect(c, ev, FD_WRITE);
    EXPECT_EV(c, ev, FD_WRITE);
    for (i = 0; i < 8192 && !blocked; ++i) {
        r = U(send)(c, blk, sizeof(blk), 0);
        if (r == SOCKET_ERROR) blocked = (es_err() == WSAEWOULDBLOCK);
        if (r == SOCKET_ERROR) break;
    }
    if (!blocked) { t_skip("send buffer did not fill"); es_close(c); es_close(v); U(WSACloseEvent)(ev); return; }
    es_wait(ev, 100); es_mask(c, ev);                    /* discard anything recorded while filling */
    es_drain(v);
    EXPECT_EV(c, ev, FD_WRITE);
    EXPECT_NONE(c, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}

/* ---- read --------------------------------------------------------------------------------------------- */
ESTEST(ese_sem_read_once_per_arrival_not_per_poll)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    CHECK(es_send_all(c, "data", 5) == 5);
    EXPECT_EV(v, ev, FD_READ);
    EXPECT_NONE(v, ev);                                  /* data is still unread but nothing new arrived */
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    es_reselect(v, ev, 0);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_read_raised_again_by_second_arrival)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_READ);
    CHECK(es_send_all(c, "data", 5) == 5);
    EXPECT_EV(v, ev, FD_READ);
    CHECK(es_send_all(c, "more", 5) == 5);               /* first block still unread */
    EXPECT_EV(v, ev, FD_READ);
    EXPECT_NONE(v, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_partial_recv_rearms_read_until_empty)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); char b[8]; int i;
    REQUIRE(ev);
    es_reselect(v, ev, FD_READ);
    CHECK(es_send_all(c, "abcdefgh", 8) == 8);
    EXPECT_EV(v, ev, FD_READ);
    for (i = 0; i < 8; ++i) {
        CHECK(U(recv)(v, b, 1, 0) == 1);
        if (i < 7) EXPECT_EV(v, ev, FD_READ);            /* bytes remain: re-armed */
        else EXPECT_NONE(v, ev);                         /* drained: quiet */
    }
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_read_data_arrived_while_unselected_reported_at_select)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); char b[8];
    REQUIRE(ev);
    es_reselect(v, ev, 0);
    CHECK(es_send_all(c, "data", 5) == 5);
    Sleep(50);
    es_reselect(v, ev, FD_READ);
    EXPECT_EV(v, ev, FD_READ);
    CHECK(U(recv)(v, b, 8, 0) == 5);
    es_reselect(v, ev, 0);
    CHECK(es_send_all(c, "data", 5) == 5);
    Sleep(50);
    es_drain(v);
    es_reselect(v, ev, FD_READ);
    EXPECT_NONE(v, ev);                                  /* consumed while unselected: nothing left to report */
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_pending_overlapped_recv_takes_the_data_without_read_event)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); WSAOVERLAPPED ov; WSABUF wb; char b[4]; DWORD fl = 0, got = 0;
    REQUIRE(ev);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    REQUIRE(ov.hEvent);
    es_reselect(v, ev, FD_READ);
    wb.buf = b; wb.len = 1;
    CHECK(U(WSARecv)(v, &wb, 1, NULL, &fl, &ov, NULL) == SOCKET_ERROR);
    ES_EQ(es_err(), WSA_IO_PENDING);
    CHECK(es_send_all(c, "a", 1) == 1);
    CHECK(es_wait(ov.hEvent, 2000));
    CHECK(U(WSAGetOverlappedResult)(v, &ov, &got, FALSE, &fl));
    ES_EQ(got, 1);
    EXPECT_NONE(v, ev);                                  /* delivered straight to the receive request */
    CHECK(es_send_all(c, "a", 1) == 1);
    EXPECT_EV(v, ev, FD_READ);
    U(WSACloseEvent)(ov.hEvent);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}

/* ---- out of band -------------------------------------------------------------------------------------- */
ESTEST(ese_sem_oob_event_and_rearm)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); char b;
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    CHECK(U(send)(c, "a", 1, MSG_OOB) == 1);
    EXPECT_EV(v, ev, FD_OOB);
    EXPECT_NONE(v, ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    CHECK(U(send)(c, "b", 1, MSG_OOB) == 1);
    EXPECT_EV(v, ev, FD_OOB);                            /* a second urgent byte raises it again */
    CHECK(U(recv)(v, &b, 1, MSG_OOB) == 1);
    es_mask(v, ev);                                      /* whatever the read made visible */
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}

/* ---- accept ------------------------------------------------------------------------------------------- */
ESTEST(ese_sem_accept_event_rules)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 4), c1 = es_sock(SOCK_STREAM), c2 = es_sock(SOCK_STREAM), s;
    HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && c1 != INVALID_SOCKET && c2 != INVALID_SOCKET && ev);
    es_reselect(l, ev, FD_CONNECT | FD_READ | FD_OOB);
    EXPECT_NONE(l, ev);
    CHECK(U(connect)(c1, (struct sockaddr *)&a, sizeof(a)) == 0);
    es_reselect(l, ev, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    EXPECT_EV(l, ev, FD_ACCEPT);                         /* pending connection seen at selection time */
    EXPECT_NONE(l, ev);
    es_reselect(l, ev, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    EXPECT_NONE(l, ev);
    CHECK(U(connect)(c2, (struct sockaddr *)&a, sizeof(a)) == 0);
    { LONG m2; es_wait(ev, 500); m2 = es_mask(l, ev);    /* a second arrival while one is queued: observed only */
      CHECKF(m2 == 0 || m2 == FD_ACCEPT, "mask %ld", m2);
      t_note("second queued connection raises FD_ACCEPT again: %d", m2 == FD_ACCEPT); }
    s = U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    es_close(s);
    EXPECT_EV(l, ev, FD_ACCEPT);                         /* one connection still queued: re-armed by accept */
    s = U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    es_close(s);
    EXPECT_NONE(l, ev);
    es_close(c1); es_close(c2); es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_accept_before_select_leaves_nothing)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 2), c = es_sock(SOCK_STREAM), s; HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof(a)) == 0);
    Sleep(100);
    s = U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    es_reselect(l, ev, FD_ACCEPT);
    EXPECT_NONE(l, ev);
    es_close(s); es_close(c); es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_accepted_socket_reports_write_when_selected)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 2), c = es_sock(SOCK_STREAM), s; HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof(a)) == 0);
    s = U(accept)(l, NULL, NULL);
    REQUIRE(s != INVALID_SOCKET);
    es_reselect(s, ev, FD_READ | FD_WRITE | FD_CLOSE);
    EXPECT_EV(s, ev, FD_WRITE);
    es_close(s); es_close(c); es_close(l); U(WSACloseEvent)(ev);
}

/* ---- close -------------------------------------------------------------------------------------------- */
ESTEST(ese_sem_graceful_close_raises_close_once)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); char b[4];
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    es_close(c);
    EXPECT_EV(v, ev, FD_CLOSE);
    EXPECT_NONE(v, ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    es_reselect(v, ev, 0);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    CHECK(U(recv)(v, b, sizeof(b), 0) == 0);
    EXPECT_NONE(v, ev);
    es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_peer_send_shutdown_raises_close)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    CHECK(U(shutdown)(c, SD_SEND) == 0);
    EXPECT_EV(v, ev, FD_CLOSE);
    EXPECT_NONE(v, ev);
    es_close(c);
    EXPECT_NONE(v, ev);                                  /* the later full close adds nothing */
    es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_receive_shutdown_and_local_shutdown_raise_nothing)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    CHECK(U(shutdown)(c, SD_RECEIVE) == 0);
    CHECK(U(shutdown)(v, SD_BOTH) == 0);
    EXPECT_NONE(v, ev);
    CHECK(U(shutdown)(c, SD_SEND) == 0);
    EXPECT_EV(v, ev, FD_CLOSE);
    EXPECT_NONE(v, ev);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_close_follows_read_with_data_still_unread)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); char b[8];
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    CHECK(es_send_all(c, "data", 5) == 5);
    EXPECT_EV(v, ev, FD_READ);
    es_close(c);
    EXPECT_EV(v, ev, FD_CLOSE);                          /* recorded while the 5 bytes are unread */
    CHECK(U(recv)(v, b, 3, 0) == 3);
    EXPECT_EV(v, ev, FD_READ);
    CHECK(U(recv)(v, b, 8, 0) == 2);
    EXPECT_NONE(v, ev);
    es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_close_before_select_reported_at_select)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_close(c);
    Sleep(100);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_EV(v, ev, FD_CLOSE);
    es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_close_while_close_unselected_then_select)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);
    es_close(c);
    EXPECT_NONE(v, ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_EV(v, ev, FD_CLOSE);
    es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_sem_reset_close_reports_connaborted_once)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); WSANETWORKEVENTS ne;
    REQUIRE(ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    es_rst_close(c);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_enum(v, ev, &ne), 0);
    CHECK((ne.lNetworkEvents & FD_CLOSE) != 0);
    ES_EQ(ne.iErrorCode[FD_CLOSE_BIT], WSAECONNABORTED);
    EXPECT_NONE(v, ev);
    es_reselect(v, ev, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    EXPECT_NONE(v, ev);
    es_close(v); U(WSACloseEvent)(ev);
}
