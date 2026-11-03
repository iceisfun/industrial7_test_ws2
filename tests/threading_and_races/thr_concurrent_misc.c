/* Concurrency scenarios that do not fit the other files: per-thread error slots under load, several waiters
 * on one socket, event re-association while a thread waits, ordered datagrams across threads, WSACleanup
 * pulling the stack out from under a blocked thread (in a child process so the reference count is private),
 * and an overlapped send on a full path being aborted by closesocket.
 */
#include "thr.h"

/* ---- per-thread error slot under load ------------------------------------------------------------------------------- */
struct errthr { int want; int mode; int bad; int iters; HANDLE th, go; };
static DWORD WINAPI errthr_main(void *x)
{
    struct errthr *p = (struct errthr *)x;
    int i;
    WaitForSingleObject(p->go, 5000);
    for (i = 0; i < p->iters; i++) {
        wset(p->want);
        if (p->mode & 1) Sleep(0);
        if (werr() != p->want) p->bad++;
    }
    return 0;
}
static void run_err_threads(int mode)
{
    struct errthr t[4];
    HANDLE go = CreateEventA(NULL, TRUE, FALSE, NULL);
    int i;
    for (i = 0; i < 4; i++) {
        memset(&t[i], 0, sizeof t[i]);
        t[i].want = 10000 + i * 111; t[i].mode = mode; t[i].iters = 2000; t[i].go = go;
        t[i].th = CreateThread(NULL, 0, errthr_main, &t[i], 0, NULL);
    }
    SetEvent(go);
    wset(7777);
    for (i = 0; i < 4; i++) { CHECK(join(t[i].th, 15000)); EQV(t[i].bad, 0); }
    EQV(werr(), 7777);                    /* the starting thread's slot is untouched by four busy threads */
    CloseHandle(go);
}
TEST(thr_err_four_threads_keep_own_value)          { NEED(); run_err_threads(0); }
TEST(thr_err_four_threads_keep_own_value_yielding) { NEED(); run_err_threads(1); }

struct failer { int kind; int want; int bad; HANDLE th, go; };
static DWORD WINAPI failer_main(void *x)
{
    struct failer *p = (struct failer *)x;
    int i;
    char b[4];
    SOCKET s = tcp();
    WaitForSingleObject(p->go, 5000);
    for (i = 0; i < 200; i++) {
        int r;
        wset(0);
        switch (p->kind) {
        case 0: r = (int)U(accept)(s, NULL, NULL); r = r == (int)INVALID_SOCKET ? -1 : 0; break;    /* not listening */
        case 1: r = U(recv)(s, b, 4, 0); break;                                                      /* not connected */
        case 2: r = U(closesocket)((SOCKET)0x6FFF4); break;                                          /* not a socket */
        default: r = U(send)(s, b, 4, 0); break;                                                     /* not connected */
        }
        if (r != -1 || werr() != p->want) { if (!p->bad) t_note("failer kind %d: ret=%d err=%d", p->kind, r, werr()); p->bad++; }
    }
    cls(s);
    return 0;
}
TEST(thr_err_four_threads_distinct_failures)
{
    struct failer f[4];
    HANDLE go;
    int i;
    int want[4] = { WSAEINVAL, WSAENOTCONN, WSAENOTSOCK, WSAENOTCONN };
    NEED();
    go = CreateEventA(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < 4; i++) {
        memset(&f[i], 0, sizeof f[i]);
        f[i].kind = i; f[i].want = want[i]; f[i].go = go;
        f[i].th = CreateThread(NULL, 0, failer_main, &f[i], 0, NULL);
    }
    SetEvent(go);
    for (i = 0; i < 4; i++) { CHECK(join(f[i].th, 15000)); EQV(f[i].bad, 0); }
    CloseHandle(go);
}
TEST(thr_err_blocker_failure_does_not_touch_waiter_slot)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(s);                               /* the blocked thread fails with some error meanwhile */
    wset(4321);
    CHECK(blk_join(&b));
    EQV(werr(), 4321);
    CHECK(b.err != 4321);
    cls(c);
}
/* ---- several waiters on one socket ------------------------------------------------------------------------------------- */
TEST(thr_multi_two_selectors_both_released_by_data)
{
    SOCKET c, s;
    struct blk a, b;
    char x;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&a, B_SELECT_R, s, 0);
    blk_start(&b, B_SELECT_R, s, 0);
    snd(c, "d", 1);
    CHECK(blk_join(&a));
    CHECK(blk_join(&b));
    EQV(a.ret, 1); EQV(b.ret, 1);         /* select reports readiness without consuming the byte */
    EQV(rcv(s, &x, 1), 1);
    EQV(x, 'd');
    cls(c); cls(s);
}
TEST(thr_multi_three_pollers_all_released)
{
    SOCKET c, s;
    struct blk b[3];
    int i;
    NEED();
    CHECK(pair(&c, &s));
    for (i = 0; i < 3; i++) blk_start(&b[i], B_POLL_IN, s, 0);
    snd(c, "d", 1);
    for (i = 0; i < 3; i++) { CHECK(blk_join(&b[i])); EQV(b[i].ret, 1); CHECK(b[i].flags & POLLRDNORM); }
    cls(c); cls(s);
}
TEST(thr_multi_selector_and_reader_one_byte)
{
    /* the byte is consumed by the reader; the selector may or may not have been released first */
    SOCKET c, s;
    struct blk a, b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&a, B_RECV, s, 8);
    blk_start(&b, B_SELECT_R, s, 0);
    snd(c, "d", 1);
    CHECK(blk_join(&a));
    EQV(a.ret, 1);
    cls(c);                               /* closing the peer releases the selector if it is still waiting */
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(s);
}
TEST(thr_multi_two_readers_one_byte_one_stays_blocked)
{
    SOCKET c, s;
    struct blk a, b;
    int done;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&a, B_RECV, s, 8);
    blk_start(&b, B_RECV, s, 8);
    snd(c, "1", 1);
    SETTLE();
    SETTLE();
    done = finished(a.th) + finished(b.th);
    EQV(done, 1);
    snd(c, "2", 1);
    CHECK(blk_join(&a));
    CHECK(blk_join(&b));
    CHECK(a.buf[0] != b.buf[0]);
    cls(c); cls(s);
}
TEST(thr_multi_readers_released_by_single_fin)
{
    SOCKET c, s;
    struct blk b[3];
    int i;
    NEED();
    CHECK(pair(&c, &s));
    for (i = 0; i < 3; i++) blk_start(&b[i], B_RECV, s, 8);
    U(shutdown)(c, SD_SEND);
    for (i = 0; i < 3; i++) { CHECK(blk_join(&b[i])); EQV(b[i].ret, 0); }
    cls(c); cls(s);
}
TEST(thr_multi_readers_released_by_single_reset)
{
    SOCKET c, s;
    struct blk b[3];
    struct linger lg;
    int i;
    NEED();
    CHECK(pair(&c, &s));
    for (i = 0; i < 3; i++) blk_start(&b[i], B_RECV, s, 8);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    for (i = 0; i < 3; i++) { CHECK(blk_join(&b[i])); EQV(b[i].ret, SOCKET_ERROR); EQV(b[i].err, WSAECONNRESET); }
    cls(s);
}

/* ---- event re-association from another thread ------------------------------------------------------------------------------ */
struct waiter1 { WSAEVENT ev; DWORD ms, ret; HANDLE th; };
static DWORD WINAPI waiter1_main(void *x)
{
    struct waiter1 *w = (struct waiter1 *)x;
    w->ret = U(WSAWaitForMultipleEvents)(1, &w->ev, FALSE, w->ms, FALSE);
    return 0;
}
TEST(thr_evsel_reassociation_moves_signal_to_new_event)
{
    SOCKET c, s;
    WSAEVENT e1, e2;
    struct waiter1 w1, w2;
    NEED();
    CHECK(pair(&c, &s));
    e1 = U(WSACreateEvent)(); e2 = U(WSACreateEvent)();
    EQV(U(WSAEventSelect)(s, e1, FD_READ), 0);
    EQV(U(WSAEventSelect)(s, e2, FD_READ), 0);        /* another association replaces the first */
    w1.ev = e1; w1.ms = 800; w1.ret = 0xdead;
    w2.ev = e2; w2.ms = 8000; w2.ret = 0xdead;
    w1.th = CreateThread(NULL, 0, waiter1_main, &w1, 0, NULL);
    w2.th = CreateThread(NULL, 0, waiter1_main, &w2, 0, NULL);
    SETTLE();
    snd(c, "d", 1);
    CHECK(join(w2.th, 10000));
    CHECK(join(w1.th, 10000));
    EQV(w2.ret, WSA_WAIT_EVENT_0);
    EQV(w1.ret, WSA_WAIT_TIMEOUT);
    U(WSACloseEvent)(e1); U(WSACloseEvent)(e2);
    cls(c); cls(s);
}
TEST(thr_evsel_cancel_from_other_thread_stops_signalling)
{
    SOCKET c, s;
    WSAEVENT e;
    struct waiter1 w;
    NEED();
    CHECK(pair(&c, &s));
    e = U(WSACreateEvent)();
    EQV(U(WSAEventSelect)(s, e, FD_READ), 0);
    w.ev = e; w.ms = 800; w.ret = 0xdead;
    w.th = CreateThread(NULL, 0, waiter1_main, &w, 0, NULL);
    SETTLE();
    EQV(U(WSAEventSelect)(s, e, 0), 0);               /* cancel the association */
    snd(c, "d", 1);
    CHECK(join(w.th, 10000));
    EQV(w.ret, WSA_WAIT_TIMEOUT);
    U(WSACloseEvent)(e);
    cls(c); cls(s);
}
TEST(thr_evsel_connect_signalled_from_other_thread)
{
    struct sockaddr_in a; SOCKET l, c;
    WSAEVENT e;
    struct waiter1 w;
    WSANETWORKEVENTS ne;
    NEED();
    l = listener(&a, 4);
    c = tcp();
    e = U(WSACreateEvent)();
    EQV(U(WSAEventSelect)(c, e, FD_CONNECT), 0);
    w.ev = e; w.ms = 8000; w.ret = 0xdead;
    w.th = CreateThread(NULL, 0, waiter1_main, &w, 0, NULL);
    SETTLE();
    wset(0);
    EQV(U(connect)(c, (struct sockaddr *)&a, sizeof a), SOCKET_ERROR);   /* event-select puts the socket in non-blocking mode */
    EQV(werr(), WSAEWOULDBLOCK);
    CHECK(join(w.th, 10000));
    EQV(w.ret, WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne);
    EQV(U(WSAEnumNetworkEvents)(c, e, &ne), 0);
    EQV(ne.lNetworkEvents, FD_CONNECT);
    EQV(ne.iErrorCode[FD_CONNECT_BIT], 0);
    U(WSACloseEvent)(e);
    cls(c); cls(l);
}

/* ---- ordered datagrams across threads ------------------------------------------------------------------------------------- */
struct seqsend { SOCKET s; struct sockaddr_in to; HANDLE th; };
static DWORD WINAPI seqsend_main(void *x)
{
    struct seqsend *p = (struct seqsend *)x;
    int i;
    Sleep(100);
    for (i = 0; i < 50; i++) {
        unsigned char m[16];
        memset(m, 0, sizeof m);
        m[0] = (unsigned char)i;
        U(sendto)(p->s, (char *)m, sizeof m, 0, (struct sockaddr *)&p->to, sizeof p->to);
    }
    return 0;
}
TEST(thr_dgram_single_sender_preserves_order)
{
    struct sockaddr_in a;
    SOCKET r, t;
    struct seqsend p;
    int got = 0, last = -1, bad = 0, n;
    unsigned char m[16];
    fd_set fds;
    struct timeval tv;
    NEED();
    r = udp_bound(&a);
    t = udp();
    p.s = t; p.to = a;
    p.th = CreateThread(NULL, 0, seqsend_main, &p, 0, NULL);
    for (;;) {
        FD_ZERO(&fds); FD_SET(r, &fds);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (U(select)(0, &fds, NULL, NULL, &tv) != 1) break;
        n = U(recvfrom)(r, (char *)m, sizeof m, 0, NULL, NULL);
        if (n != 16) { bad++; break; }
        if (m[0] <= last) bad++;
        last = m[0];
        got++;
        if (got == 50) break;
    }
    CHECK(join(p.th, 10000));
    EQV(bad, 0);
    t_note("ordered datagrams received: %d of 50", got);
    CHECK(got > 0);
    cls(t); cls(r);
}

/* ---- WSACleanup under a blocked thread (private process, private reference count) ------------------------------------------------ */
static SOCKET g_c, g_s;
static DWORD WINAPI blocked_in_child(void *x)
{
    struct blk *b = (struct blk *)x;
    return blk_main(b);
}
/* argv[1]: accept | recv | select ; exit code 0 when the blocked thread was released with a failure */
CHILD(thr_cleanup_blocked)
{
    WSADATA d;
    struct blk b;
    struct sockaddr_in a;
    int kind, rc = 0;
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    if (argc < 2) return 90;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 91;
    if (!strcmp(argv[1], "accept")) { s = listener(&a, 4); kind = B_ACCEPT; }
    else if (!strcmp(argv[1], "recv")) { if (!pair(&c, &s)) return 92; kind = B_RECV; }
    else { if (!pair(&c, &s)) return 92; kind = B_SELECT_R; }
    if (s == INVALID_SOCKET) return 93;
    blk_start(&b, kind, s, 8);
    if (finished(b.th)) return 94;
    if (U(WSACleanup)() != 0) return 95;              /* last reference: the stack goes away */
    if (!blk_join(&b)) return 96;
    printf("cleanup released %s: ret=%d err=%d\n", argv[1], b.ret, b.err);
    return rc;
}
static void cleanup_case(const char *kind)
{
    DWORD rc = t_run_child("thr_cleanup_blocked", kind, 40000);
    CHECKF(rc == 0, "child step %lu", rc);
}
TEST(thr_cleanup_releases_blocked_accept) { REQUIRE(U(WSAStartup)); cleanup_case("accept"); }
TEST(thr_cleanup_releases_blocked_recv)   { REQUIRE(U(WSAStartup)); cleanup_case("recv"); }
TEST(thr_cleanup_releases_blocked_select) { REQUIRE(U(WSAStartup)); cleanup_case("select"); }

/* ---- overlapped send aborted by close ------------------------------------------------------------------------------------------- */
TEST(thr_ovl_pending_send_on_full_path_aborted_by_close)
{
    SOCKET c, s;
    WSAOVERLAPPED ov;
    WSABUF wb;
    static char big[65536];
    DWORD n = 0, f = 0;
    long long q;
    int r;
    struct delayed d;
    NEED();
    CHECK(pair(&c, &s));
    small_bufs(c); small_bufs(s);
    q = fill_send(c);
    if (q < 0) { cls(c); cls(s); t_skip("send path never filled"); return; }
    memset(&ov, 0, sizeof ov);
    ov.hEvent = U(WSACreateEvent)();
    wb.buf = big; wb.len = sizeof big;
    r = U(WSASend)(c, &wb, 1, &n, 0, &ov, NULL);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSA_IO_PENDING);
    delayed_start(&d, c, -1, 100);
    CHECK(WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
    CHECK(join(d.th, 5000));
    wset(0);
    n = 99; f = 99;
    r = U(WSAGetOverlappedResult)(c, &ov, &n, FALSE, &f);
    EQV(r, FALSE);
    EQV(werr(), WSAENOTSOCK);
    U(WSACloseEvent)(ov.hEvent);
    cls(s);
}
TEST(thr_ovl_pending_recvfrom_dgram_aborted_by_close)
{
    struct sockaddr_in a, from;
    SOCKET u;
    WSAOVERLAPPED ov;
    WSABUF wb;
    char buf[32];
    DWORD n = 0, f = 0;
    int fl = sizeof from, r;
    struct delayed d;
    NEED();
    u = udp_bound(&a);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = U(WSACreateEvent)();
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecvFrom)(u, &wb, 1, &n, &f, (struct sockaddr *)&from, &fl, &ov, NULL);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSA_IO_PENDING);
    delayed_start(&d, u, -1, 100);
    CHECK(WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
    CHECK(join(d.th, 5000));
    wset(0);
    r = U(WSAGetOverlappedResult)(u, &ov, &n, FALSE, &f);
    EQV(r, FALSE);
    EQV(werr(), WSAENOTSOCK);
    U(WSACloseEvent)(ov.hEvent);
}
TEST(thr_ovl_delayed_shutdown_receive_completes_overlapped_recv)
{
    SOCKET c, s;
    WSAOVERLAPPED ov;
    WSABUF wb;
    char buf[8];
    DWORD n = 77, f = 0;
    int r;
    struct delayed d;
    NEED();
    CHECK(pair(&c, &s));
    memset(&ov, 0, sizeof ov);
    ov.hEvent = U(WSACreateEvent)();
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(s, &wb, 1, &n, &f, &ov, NULL);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSA_IO_PENDING);
    delayed_start(&d, c, SD_SEND, 100);               /* peer FIN from another thread */
    CHECK(WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
    CHECK(join(d.th, 5000));
    n = 77;
    r = U(WSAGetOverlappedResult)(s, &ov, &n, FALSE, &f);
    EQV(r, TRUE);
    EQV(n, 0);                                        /* completes successfully with zero bytes: end of stream */
    U(WSACloseEvent)(ov.hEvent);
    cls(c); cls(s);
}
TEST(thr_ovl_delayed_reset_fails_overlapped_recv)
{
    SOCKET c, s;
    WSAOVERLAPPED ov;
    WSABUF wb;
    char buf[8];
    DWORD n = 77, f = 0;
    int r;
    struct linger lg;
    NEED();
    CHECK(pair(&c, &s));
    memset(&ov, 0, sizeof ov);
    ov.hEvent = U(WSACreateEvent)();
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(s, &wb, 1, &n, &f, &ov, NULL);
    EQV(werr(), WSA_IO_PENDING);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    CHECK(WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
    wset(0);
    r = U(WSAGetOverlappedResult)(s, &ov, &n, FALSE, &f);
    EQV(r, FALSE);
    EQV(werr(), WSAECONNRESET);
    U(WSACloseEvent)(ov.hEvent);
    cls(s);
}
