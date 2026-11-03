/* Closing an endpoint underneath blocked callers and completion routines, and the peer-side effect on requests
 * that are in flight: blocking calls in another thread are released by closesocket from the main thread, APC-style
 * completion routines of a cancelled request run once at the next alertable wait, and a request outstanding when
 * the peer closes or resets finishes with the matching status.
 */
#include "acc.h"

typedef struct {
    int op; SOCKET s; volatile LONG started; volatile LONG done; int ret; int err; char buf[64]; DWORD revents;
} blk_t;
enum { B_RECV, B_RECVFROM, B_ACCEPT, B_SEND, B_SELECT, B_POLL };

static DWORD WINAPI blk_thread(void *arg)
{
    blk_t *b = (blk_t *)arg;
    struct sockaddr_in from; int fl = sizeof from;
    InterlockedExchange(&b->started, 1);
    switch (b->op) {
    case B_RECV: b->ret = U(recv)(b->s, b->buf, sizeof b->buf, 0); break;
    case B_RECVFROM: b->ret = U(recvfrom)(b->s, b->buf, sizeof b->buf, 0, (struct sockaddr *)&from, &fl); break;
    case B_ACCEPT: b->ret = (int)U(accept)(b->s, NULL, NULL); break;
    case B_SEND: { static char blk[65536]; b->ret = U(send)(b->s, blk, sizeof blk, 0); break; }
    case B_SELECT: { fd_set r; struct timeval tv = { 4, 0 }; FD_ZERO(&r); FD_SET(b->s, &r); b->ret = U(select)(0, &r, NULL, NULL, &tv); break; }
    case B_POLL: { WSAPOLLFD pf; pf.fd = b->s; pf.events = POLLRDNORM; pf.revents = 0; b->ret = U(WSAPoll)(&pf, 1, 4000); b->revents = (DWORD)pf.revents; break; }
    }
    b->err = WERR();
    InterlockedExchange(&b->done, 1);
    return 0;
}
/* run `op` blocked on `target`, then close `target` from this thread; wait for the thread to finish */
static int blocked_case(blk_t *b, int op, SOCKET target, SOCKET fill_peer_unused)
{
    HANDLE th; int i;
    memset(b, 0, sizeof *b);
    b->op = op; b->s = target;
    th = CreateThread(NULL, 0, blk_thread, b, 0, NULL);
    if (!th) return 0;
    for (i = 0; i < 200 && !b->started; i++) Sleep(5);
    Sleep(300);                                   /* let the call block */
    CHECK(!b->done);                              /* still blocked before the close */
    CLOSES(target);
    if (WaitForSingleObject(th, ACC_WAIT) != WAIT_OBJECT_0) { t_note("blocked thread not released by close"); CloseHandle(th); return 0; }
    CloseHandle(th);
    return 1;
}

TEST(cc_wait_blocking_recv_released_by_close)
{
    blk_t b;
    UP();
    PAIR(c, s);
    acc_timeo(c, 0);
    if (!blocked_case(&b, B_RECV, c, 0)) { CLOSES(s); return; }
    CHECK(b.ret == SOCKET_ERROR);
    EXPECT_EQ(b.err, WSAECONNABORTED);       /* a connected stream is aborted, like its overlapped receive */
    CLOSES(s);
}
TEST(cc_wait_blocking_recvfrom_released_by_close)
{
    blk_t b; SOCKET u;
    UP();
    u = acc_udp(NULL); acc_timeo(u, 0);
    REQUIRE(u != INVALID_SOCKET);
    if (!blocked_case(&b, B_RECVFROM, u, 0)) return;
    CHECK(b.ret == SOCKET_ERROR);
    EXPECT_EQ(b.err, WSAEINTR);
}
TEST(cc_wait_blocking_accept_released_by_close)
{
    blk_t b; SOCKET l;
    UP();
    l = acc_listener(NULL);
    REQUIRE(l != INVALID_SOCKET);
    acc_timeo(l, 0);
    if (!blocked_case(&b, B_ACCEPT, l, 0)) return;
    CHECK(b.ret == (int)INVALID_SOCKET);
    EXPECT_EQ(b.err, WSAEINTR);
}
TEST(cc_wait_blocking_send_released_by_close)
{
    blk_t b;
    UP();
    PAIR(c, s);
    acc_timeo(c, 0);
    if (acc_fill_send(c, 32u << 20) == 0) { t_skip("could not fill"); CLOSES(c); CLOSES(s); return; }
    if (!blocked_case(&b, B_SEND, c, 0)) { CLOSES(s); return; }
    CHECK(b.ret == SOCKET_ERROR);
    EXPECT_EQ(b.err, WSAECONNABORTED);
    CLOSES(s);
}
TEST(cc_wait_select_released_by_close)
{
    blk_t b;
    UP();
    PAIR(c, s);
    if (!blocked_case(&b, B_SELECT, c, 0)) { CLOSES(s); return; }
    EXPECT_EQ(b.ret, 1);                      /* the closed socket is reported as ready, not as an error */
    CLOSES(s);
}
TEST(cc_wait_wsapoll_released_by_close)
{
    blk_t b;
    UP();
    PAIR(c, s);
    if (!blocked_case(&b, B_POLL, c, 0)) { CLOSES(s); return; }
    EXPECT_EQ(b.ret, 1);
    EXPECT_EQ(b.revents, POLLNVAL);
    CLOSES(s);
}

/* ---- completion routines of a request cancelled by close --------------------------------------------------- */
static volatile LONG g_calls; static volatile DWORD g_err, g_bytes; static volatile ULONG_PTR g_ov;
static void CALLBACK routine(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD flags)
{
    InterlockedIncrement(&g_calls); g_err = err; g_bytes = bytes; g_ov = (ULONG_PTR)ov;
}
static void routine_case(int udp, DWORD *err_out)
{
    SOCKET t, o = INVALID_SOCKET; OVERLAPPED ov; WSABUF wb; char buf[8]; DWORD fl = 0; int r;
    UP();
    g_calls = 0; g_err = 77; g_bytes = 77; g_ov = 0;
    if (udp) t = acc_udp(NULL); else { if (!acc_pair(&t, &o)) { t_skip("no pair"); return; } }
    REQUIRE(t != INVALID_SOCKET);
    acc_ov_init(&ov, NULL);
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(t, &wb, 1, NULL, &fl, &ov, routine);
    CHECK(r == SOCKET_ERROR && WERR() == WSA_IO_PENDING);
    CLOSES(t);
    EXPECT_EQ(g_calls, 0);                         /* needs an alertable wait */
    CHECK(SleepEx(ACC_WAIT, TRUE) == WAIT_IO_COMPLETION);
    EXPECT_EQ(g_calls, 1);
    EXPECT_EQ(g_bytes, 0);
    EXPECT_EQ(g_ov, (ULONG_PTR)&ov);
    *err_out = g_err;
    CHECK(SleepEx(50, TRUE) == 0);                 /* exactly once */
    EXPECT_EQ(g_calls, 1);
    if (o != INVALID_SOCKET) CLOSES(o);
}
TEST(cc_wait_completion_routine_runs_once_after_close_udp)
{
    DWORD e = 0;
    routine_case(1, &e);
    EXPECT_EQ(e, ERROR_OPERATION_ABORTED);
}
TEST(cc_wait_completion_routine_runs_once_after_close_tcp)
{
    DWORD e = 0;
    routine_case(0, &e);
    EXPECT_EQ(e, WSAECONNABORTED);          /* completion routines get the Winsock number */
}

/* ---- requests outstanding when the peer goes away ---------------------------------------------------------- */
TEST(cc_wait_pending_send_fails_when_peer_resets)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_SEND_FULL, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    acc_rst_close(p.other); p.other = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(acc_pend_status(&p), ST_REMOTE_DISCONNECT);
    acc_pend_done(&p);
}
TEST(cc_wait_pending_send_fails_when_peer_closes_with_unread_data)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_SEND_FULL, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CLOSES(p.other); p.other = INVALID_SOCKET;        /* the peer has unread data: its close is a reset */
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(acc_pend_status(&p), ST_REMOTE_DISCONNECT);
    acc_pend_done(&p);
}
TEST(cc_wait_pending_poll_completes_on_peer_close)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_POLL, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CLOSES(p.other); p.other = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(p.io.Status, ST_SUCCESS);
    CHECK(((unsigned char *)p.poll)[24] & AFD_POLL_DISC);   /* the disconnect event of the polled endpoint */
    acc_pend_done(&p);
}

/* ---- event objects and message selection outlive the endpoint --------------------------------------------- */
TEST(cc_wait_event_select_event_object_survives_close)
{
    SOCKET s; HANDLE ev; WSANETWORKEVENTS ne; DWORD f;
    UP();
    s = acc_sock(SOCK_STREAM); ev = acc_event();
    CHECK(U(WSAEventSelect)(s, ev, FD_READ | FD_CLOSE) == 0);
    CLOSES(s);
    CHECK(GetHandleInformation(ev, &f));             /* the event is the caller's, still valid */
    CHECK(SetEvent(ev));
    WSETERR(0);
    CHECK(U(WSAEnumNetworkEvents)(s, ev, &ne) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAENOTSOCK);
    CloseHandle(ev);
}
TEST(cc_wait_event_select_after_close_is_notsock)
{
    SOCKET s; HANDLE ev;
    UP();
    s = acc_sock(SOCK_STREAM); ev = acc_event();
    CLOSES(s);
    WSETERR(0);
    CHECK(U(WSAEventSelect)(s, ev, FD_READ) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAENOTSOCK);
    CloseHandle(ev);
}
TEST(cc_wait_event_select_unsignalled_by_own_close)
{
    SOCKET s; HANDLE ev;
    UP();
    s = acc_sock(SOCK_STREAM); ev = acc_event();
    CHECK(U(WSAEventSelect)(s, ev, FD_CLOSE | FD_READ) == 0);
    CLOSES(s);
    EXPECT_EQ(WaitForSingleObject(ev, 100), WAIT_TIMEOUT);   /* closing your own socket raises no event */
    CloseHandle(ev);
}
