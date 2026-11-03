/* A thread is blocked inside a Winsock call and another thread closes the socket out from under it.
 *
 * Measures: which blocking entry points are released by closesocket from a different thread, with what
 * return value and WSAGetLastError, that closesocket itself succeeds while the call is in flight, that the
 * released call leaves the socket handle invalid (WSAENOTSOCK afterwards), that closing an unrelated socket
 * releases nobody, and that every blocked caller on the same socket is released together.
 * Blocked calls: accept, WSAAccept, recv (plain, MSG_PEEK, MSG_WAITALL), recvfrom, WSARecv, WSARecvFrom,
 * select (read / except sets), WSAPoll, and send / WSASend on a full send path.
 */
#include "thr.h"

/* Result of a blocking call that was released by a local closesocket. */
static void report(const char *what, const struct blk *b)
{
    t_note("%s released: ret=%d err=%d", what, b->ret, b->err);
}

/* Errors a released blocking call may carry; which one is a property of the call, pinned per test below. */
static int in_set(int e, const int *set, int n)
{
    int i;
    for (i = 0; i < n; i++) if (set[i] == e) return 1;
    return 0;
}

/* Generic scenario: blocker on `s`, close `s` from this thread, expect the call to fail with `want`. */
static void close_releases(int kind, SOCKET s, SOCKET keep, int want, const char *what)
{
    struct blk b;
    blk_start(&b, kind, s, 64);
    CHECKF(!finished(b.th), "%s returned before the socket was touched", what);
    wset(0);
    EQV(cls(s), 0);
    CHECK(blk_join(&b));
    report(what, &b);
    EQV(b.ret, SOCKET_ERROR);
    CHECKF(b.err == want, "%s released with error %d, want %d", what, b.err, want);
    if (keep != INVALID_SOCKET) cls(keep);
}

TEST(thr_close_accept)
{
    struct sockaddr_in a; SOCKET l;
    NEED();
    l = listener(&a, 4);
    close_releases(B_ACCEPT, l, INVALID_SOCKET, WSAEINTR, "accept");
}
TEST(thr_close_wsaaccept)
{
    struct sockaddr_in a; SOCKET l;
    NEED();
    l = listener(&a, 4);
    close_releases(B_WSAACCEPT, l, INVALID_SOCKET, WSAEINTR, "WSAAccept");
}
TEST(thr_close_recv_accepted_side)
{
    SOCKET c, s;
    NEED();
    CHECK(pair(&c, &s));
    close_releases(B_RECV, s, c, WSAECONNABORTED, "recv(accepted)");
}
TEST(thr_close_recv_connecting_side)
{
    SOCKET c, s;
    NEED();
    CHECK(pair(&c, &s));
    close_releases(B_RECV, c, s, WSAECONNABORTED, "recv(connecting)");
}
TEST(thr_close_recv_peek)
{
    SOCKET c, s;
    NEED();
    CHECK(pair(&c, &s));
    close_releases(B_RECV_PEEK, s, c, WSAECONNABORTED, "recv(MSG_PEEK)");
}
TEST(thr_close_recvfrom_stream)
{
    SOCKET c, s;
    NEED();
    CHECK(pair(&c, &s));
    close_releases(B_RECVFROM, s, c, WSAECONNABORTED, "recvfrom(stream)");
}
TEST(thr_close_recvfrom_dgram)
{
    struct sockaddr_in a; SOCKET u;
    NEED();
    u = udp_bound(&a);
    close_releases(B_RECVFROM, u, INVALID_SOCKET, WSAEINTR, "recvfrom(dgram)");
}
TEST(thr_close_wsarecv_blocking)
{
    SOCKET c, s;
    NEED();
    CHECK(pair(&c, &s));
    close_releases(B_WSARECV, s, c, WSAECONNABORTED, "WSARecv(no overlapped)");
}
TEST(thr_close_wsarecvfrom_dgram)
{
    struct sockaddr_in a; SOCKET u;
    NEED();
    u = udp_bound(&a);
    close_releases(B_WSARECVFROM, u, INVALID_SOCKET, WSAEINTR, "WSARecvFrom(dgram)");
}
TEST(thr_close_wsarecv_dgram)
{
    struct sockaddr_in a; SOCKET u;
    NEED();
    u = udp_bound(&a);
    close_releases(B_WSARECV, u, INVALID_SOCKET, WSAEINTR, "WSARecv(dgram)");
}
TEST(thr_close_recv_waitall_partial)
{
    /* MSG_WAITALL with part of the data already delivered: the caller is released by the close. */
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV_WAITALL, s, 64);
    snd(c, "abc", 3);
    SETTLE();
    CHECK(!finished(b.th));
    cls(s);
    CHECK(blk_join(&b));
    report("recv(MSG_WAITALL partial)", &b);
    EQV(b.ret, 3);                       /* the bytes already received are returned, not an error */
    cls(c);
}

/* select(): the closed socket is in the set the caller is waiting on. */
TEST(thr_close_select_read)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_R, s, 0);
    CHECK(!finished(b.th));
    cls(s);
    CHECK(blk_join(&b));
    report("select(read)", &b);
    EQV(b.ret, 1);                       /* the closed handle counts as readable; the next call reports why */
    cls(c);
}
TEST(thr_close_select_except)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_X, s, 0);
    CHECK(!finished(b.th));
    cls(s);
    CHECK(blk_join(&b));
    report("select(except)", &b);
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAENOTSOCK);
    cls(c);
}
TEST(thr_close_poll)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_POLL_IN, s, 0);
    CHECK(!finished(b.th));
    cls(s);
    CHECK(blk_join(&b));
    report("WSAPoll", &b);
    EQV(b.ret, 1);
    EQV(b.flags, POLLNVAL);
    cls(c);
}

/* Blocking send on a full path. */
static void send_full_case(int kind, const char *what)
{
    SOCKET c, s;
    struct blk b;
    long long q;
    NEED();
    CHECK(pair(&c, &s));
    small_bufs(c);
    q = fill_send(c);
    if (q < 0) { cls(c); cls(s); t_skip("send path never filled"); return; }
    blk_start(&b, kind, c, 1 << 18);     /* far more than the send path can take: the call has to block */
    CHECK(!finished(b.th));
    cls(c);
    CHECK(blk_join(&b));
    report(what, &b);
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAECONNABORTED);
    cls(s);
}
TEST(thr_close_send_full)    { send_full_case(B_SEND, "send(full)"); }
TEST(thr_close_wsasend_full) { send_full_case(B_WSASEND, "WSASend(full)"); }

/* ---- aftermath --------------------------------------------------------------------------------------------- */
TEST(thr_close_then_use_is_notsock)
{
    SOCKET c, s;
    struct blk b;
    char x;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(s);
    CHECK(blk_join(&b));
    wset(0);
    EQV(rcv(s, &x, 1), SOCKET_ERROR);
    EQV(werr(), WSAENOTSOCK);
    wset(0);
    EQV(cls(s), SOCKET_ERROR);
    EQV(werr(), WSAENOTSOCK);
    cls(c);
}
TEST(thr_close_then_select_is_notsock)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(s);
    CHECK(blk_join(&b));
    memset(&b, 0, sizeof b);
    b.kind = B_SELECT_R; b.s = s; b.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    blk_main(&b);
    CloseHandle(b.ready);
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAENOTSOCK);
    cls(c);
}
TEST(thr_close_peer_gets_reset_after_release)
{
    SOCKET c, s;
    struct blk b;
    char x;
    int r;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(s);
    CHECK(blk_join(&b));
    r = rcv(c, &x, 1);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSAECONNRESET);          /* closing under a pending receive aborts the connection: the peer sees a reset */
    cls(c);
}
TEST(thr_close_blocker_gets_no_data)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(s);
    CHECK(blk_join(&b));
    CHECK(b.ret != 0);               /* a released call is a failure, not an end-of-stream */
    cls(c);
}

/* ---- several blockers, one socket ---------------------------------------------------------------------------- */
TEST(thr_close_releases_two_receivers)
{
    SOCKET c, s;
    struct blk a, b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&a, B_RECV, s, 8);
    blk_start(&b, B_WSARECV, s, 8);
    cls(s);
    CHECK(blk_join(&a));
    CHECK(blk_join(&b));
    EQV(a.ret, SOCKET_ERROR);
    EQV(b.ret, SOCKET_ERROR);
    EQV(a.err, WSAECONNABORTED);
    EQV(b.err, WSAECONNABORTED);
    cls(c);
}
TEST(thr_close_releases_receiver_and_selector)
{
    SOCKET c, s;
    struct blk a, b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&a, B_RECV, s, 8);
    blk_start(&b, B_SELECT_R, s, 0);
    cls(s);
    CHECK(blk_join(&a));
    CHECK(blk_join(&b));
    EQV(a.ret, SOCKET_ERROR);
    cls(c);
}
TEST(thr_close_releases_four_acceptors)
{
    struct sockaddr_in a; SOCKET l;
    struct blk b[4];
    int i;
    NEED();
    l = listener(&a, 4);
    for (i = 0; i < 4; i++) blk_start(&b[i], i & 1 ? B_WSAACCEPT : B_ACCEPT, l, 0);
    cls(l);
    for (i = 0; i < 4; i++) {
        CHECK(blk_join(&b[i]));
        EQV(b[i].ret, SOCKET_ERROR);
        EQV(b[i].err, WSAEINTR);
    }
}
TEST(thr_close_releases_four_receivers)
{
    SOCKET c, s;
    struct blk b[4];
    int i;
    NEED();
    CHECK(pair(&c, &s));
    for (i = 0; i < 4; i++) blk_start(&b[i], B_RECV, s, 8);
    cls(s);
    for (i = 0; i < 4; i++) {
        CHECK(blk_join(&b[i]));
        EQV(b[i].ret, SOCKET_ERROR);
        EQV(b[i].err, WSAECONNABORTED);
    }
    cls(c);
}

/* ---- isolation: another socket closes, nobody else moves ----------------------------------------------------------- */
TEST(thr_close_other_socket_does_not_release_recv)
{
    SOCKET c, s, c2, s2;
    struct blk b;
    char x = 'q';
    NEED();
    CHECK(pair(&c, &s));
    CHECK(pair(&c2, &s2));
    blk_start(&b, B_RECV, s, 8);
    cls(c2); cls(s2);
    SETTLE();
    CHECK(!finished(b.th));
    snd(c, &x, 1);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    EQV(b.buf[0], 'q');
    cls(c); cls(s);
}
TEST(thr_close_other_socket_does_not_release_accept)
{
    struct sockaddr_in a, a2; SOCKET l, l2, d;
    struct blk b;
    NEED();
    l = listener(&a, 4);
    l2 = listener(&a2, 4);
    blk_start(&b, B_ACCEPT, l, 0);
    cls(l2);
    SETTLE();
    CHECK(!finished(b.th));
    d = dial(&a);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);            /* accept returned a socket (closed by the worker) */
    cls(d); cls(l);
}
TEST(thr_close_other_socket_does_not_release_select)
{
    SOCKET c, s, c2, s2;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    CHECK(pair(&c2, &s2));
    blk_start(&b, B_SELECT_R, s, 0);
    cls(c2); cls(s2);
    SETTLE();
    CHECK(!finished(b.th));
    snd(c, "z", 1);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(c); cls(s);
}
TEST(thr_close_peer_not_the_blocked_socket_release_with_eof)
{
    /* closing the peer (not the blocked socket) is a different wake-up: recv returns 0 */
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(c);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    cls(s);
}

/* ---- WSAWaitForMultipleEvents --------------------------------------------------------------------------------------- */
struct waiter { WSAEVENT *ev; DWORD n; BOOL all; DWORD ms; BOOL alert; DWORD ret; int err; HANDLE th, ready; };
static DWORD WINAPI wait_main(void *p)
{
    struct waiter *w = (struct waiter *)p;
    SetEvent(w->ready);
    w->ret = U(WSAWaitForMultipleEvents)(w->n, w->ev, w->all, w->ms, w->alert);
    w->err = werr();
    return 0;
}
static void waiter_start(struct waiter *w, WSAEVENT *ev, DWORD n, BOOL all, DWORD ms, BOOL alert)
{
    memset(w, 0, sizeof *w);
    w->ev = ev; w->n = n; w->all = all; w->ms = ms; w->alert = alert; w->ret = 0xdeadbeef;
    w->ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    w->th = CreateThread(NULL, 0, wait_main, w, 0, NULL);
    WaitForSingleObject(w->ready, 3000);
    SETTLE();
}
static int waiter_join(struct waiter *w)
{
    int ok = join(w->th, 10000);
    w->th = NULL;
    CloseHandle(w->ready);
    return ok;
}

TEST(thr_close_event_selected_socket_does_not_signal_event)
{
    /* closesocket cancels the event association without signalling the event: the wait times out */
    SOCKET c, s;
    WSAEVENT ev;
    struct waiter w;
    NEED();
    CHECK(pair(&c, &s));
    ev = U(WSACreateEvent)();
    CHECK(U(WSAEventSelect)(s, ev, FD_READ | FD_CLOSE) == 0);
    waiter_start(&w, &ev, 1, FALSE, 800, FALSE);
    cls(s);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_TIMEOUT);        /* closesocket does not post FD_CLOSE to the closing side */
    U(WSACloseEvent)(ev);
    cls(c);
}
TEST(thr_wait_events_set_event_from_other_thread)
{
    WSAEVENT ev = U(WSACreateEvent)();
    struct waiter w;
    NEED();
    waiter_start(&w, &ev, 1, FALSE, 8000, FALSE);
    CHECK(!finished(w.th));
    CHECK(U(WSASetEvent)(ev));
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0);
    U(WSACloseEvent)(ev);
}
TEST(thr_wait_events_wait_all_needs_every_event)
{
    WSAEVENT ev[2];
    struct waiter w;
    NEED();
    ev[0] = U(WSACreateEvent)(); ev[1] = U(WSACreateEvent)();
    waiter_start(&w, ev, 2, TRUE, 8000, FALSE);
    U(WSASetEvent)(ev[0]);
    SETTLE();
    CHECK(!finished(w.th));
    U(WSASetEvent)(ev[1]);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0);
    U(WSACloseEvent)(ev[0]); U(WSACloseEvent)(ev[1]);
}
TEST(thr_wait_events_wait_any_reports_second_index)
{
    WSAEVENT ev[3];
    struct waiter w;
    int i;
    NEED();
    for (i = 0; i < 3; i++) ev[i] = U(WSACreateEvent)();
    waiter_start(&w, ev, 3, FALSE, 8000, FALSE);
    U(WSASetEvent)(ev[2]);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0 + 2);
    for (i = 0; i < 3; i++) U(WSACloseEvent)(ev[i]);
}
TEST(thr_wait_events_wait_any_lowest_index_wins)
{
    WSAEVENT ev[3];
    struct waiter w;
    int i;
    NEED();
    for (i = 0; i < 3; i++) ev[i] = U(WSACreateEvent)();
    U(WSASetEvent)(ev[1]); U(WSASetEvent)(ev[2]);
    waiter_start(&w, ev, 3, FALSE, 8000, FALSE);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0 + 1);
    for (i = 0; i < 3; i++) U(WSACloseEvent)(ev[i]);
}
TEST(thr_wait_events_timeout_value)
{
    WSAEVENT ev = U(WSACreateEvent)();
    struct waiter w;
    NEED();
    waiter_start(&w, &ev, 1, FALSE, 200, FALSE);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_TIMEOUT);
    U(WSACloseEvent)(ev);
}
TEST(thr_wait_events_zero_timeout_is_poll)
{
    WSAEVENT ev = U(WSACreateEvent)();
    struct waiter w;
    NEED();
    waiter_start(&w, &ev, 1, FALSE, 0, FALSE);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_TIMEOUT);
    U(WSACloseEvent)(ev);
}

static void CALLBACK noop_apc(ULONG_PTR p) { InterlockedIncrement((volatile LONG *)p); }
TEST(thr_wait_events_alertable_wakes_on_apc)
{
    WSAEVENT ev = U(WSACreateEvent)();
    struct waiter w;
    volatile LONG hits = 0;
    NEED();
    waiter_start(&w, &ev, 1, FALSE, 8000, TRUE);
    CHECK(!finished(w.th));
    CHECK(QueueUserAPC(noop_apc, w.th, (ULONG_PTR)&hits));
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_IO_COMPLETION);
    EQV(hits, 1);
    U(WSACloseEvent)(ev);
}
TEST(thr_wait_events_not_alertable_ignores_apc_until_event)
{
    WSAEVENT ev = U(WSACreateEvent)();
    struct waiter w;
    volatile LONG hits = 0;
    NEED();
    waiter_start(&w, &ev, 1, FALSE, 8000, FALSE);
    QueueUserAPC(noop_apc, w.th, (ULONG_PTR)&hits);
    SETTLE();
    CHECK(!finished(w.th));
    EQV(hits, 0);
    U(WSASetEvent)(ev);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0);
    U(WSACloseEvent)(ev);
}
TEST(thr_wait_events_event_select_data_from_other_thread)
{
    SOCKET c, s;
    WSAEVENT ev;
    struct waiter w;
    WSANETWORKEVENTS ne;
    NEED();
    CHECK(pair(&c, &s));
    ev = U(WSACreateEvent)();
    CHECK(U(WSAEventSelect)(s, ev, FD_READ | FD_CLOSE) == 0);
    waiter_start(&w, &ev, 1, FALSE, 8000, FALSE);
    CHECK(!finished(w.th));
    snd(c, "x", 1);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne);
    EQV(U(WSAEnumNetworkEvents)(s, ev, &ne), 0);
    EQV(ne.lNetworkEvents, FD_READ);
    EQV(ne.iErrorCode[FD_READ_BIT], 0);
    U(WSACloseEvent)(ev);
    cls(c); cls(s);
}
TEST(thr_wait_events_peer_close_signals_fd_close)
{
    SOCKET c, s;
    WSAEVENT ev;
    struct waiter w;
    WSANETWORKEVENTS ne;
    NEED();
    CHECK(pair(&c, &s));
    ev = U(WSACreateEvent)();
    CHECK(U(WSAEventSelect)(s, ev, FD_CLOSE) == 0);
    waiter_start(&w, &ev, 1, FALSE, 8000, FALSE);
    cls(c);
    CHECK(waiter_join(&w));
    EQV(w.ret, WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne);
    EQV(U(WSAEnumNetworkEvents)(s, ev, &ne), 0);
    EQV(ne.lNetworkEvents, FD_CLOSE);
    EQV(ne.iErrorCode[FD_CLOSE_BIT], 0);
    U(WSACloseEvent)(ev);
    cls(s);
}
TEST(thr_wait_events_enum_after_close_is_notsock)
{
    SOCKET c, s;
    WSAEVENT ev;
    WSANETWORKEVENTS ne;
    NEED();
    CHECK(pair(&c, &s));
    ev = U(WSACreateEvent)();
    CHECK(U(WSAEventSelect)(s, ev, FD_READ) == 0);
    cls(s);
    wset(0);
    EQV(U(WSAEnumNetworkEvents)(s, ev, &ne), SOCKET_ERROR);
    EQV(werr(), WSAENOTSOCK);
    U(WSACloseEvent)(ev);
    cls(c);
}

/* ---- IPv6 and abortive-close variants ---------------------------------------------------------------------------------------- */
TEST(thr_close_recv_ipv6)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    if (!pair6(&c, &s)) { t_skip("IPv6 loopback unavailable"); return; }
    blk_start(&b, B_RECV, s, 8);
    CHECK(!finished(b.th));
    cls(s);
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAECONNABORTED);          /* same mapping as the IPv4 stream */
    cls(c);
}
TEST(thr_close_select_ipv6)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    if (!pair6(&c, &s)) { t_skip("IPv6 loopback unavailable"); return; }
    blk_start(&b, B_SELECT_R, s, 0);
    cls(s);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(c);
}
TEST(thr_close_with_zero_linger_releases_reader_and_resets_peer)
{
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    char x;
    int r;
    NEED();
    CHECK(pair(&c, &s));
    lg.l_onoff = 1; lg.l_linger = 0;
    EQV(sso(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg), 0);
    blk_start(&b, B_RECV, s, 8);
    cls(s);
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAECONNABORTED);
    SETTLE();
    r = rcv(c, &x, 1);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSAECONNRESET);          /* the abortive close reaches the peer as a reset */
    cls(c);
}
TEST(thr_close_listener_pending_connection_is_reset_for_client)
{
    /* a connection completed by the stack but never accepted is dropped when the listener closes */
    struct sockaddr_in a; SOCKET l, d;
    char x;
    int r;
    NEED();
    l = listener(&a, 4);
    d = dial(&a);                         /* queued in the backlog, nobody accepts it */
    CHECK(d != INVALID_SOCKET);
    cls(l);
    SETTLE();
    r = rcv(d, &x, 1);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSAECONNRESET);
    cls(d);
}
