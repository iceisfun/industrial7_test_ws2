/* Requests in flight when an endpoint goes away or is cancelled.
 *
 * For every kind of request an AFD endpoint can have outstanding (stream receive, datagram receive, accept, address
 * list change, blocked send, plain NtReadFile, the poll control code) this measures: the completion status and
 * information count when the last handle is closed by each of the three routes (closesocket, CloseHandle, NtClose),
 * the same when a completion port is associated (packet key, apc context, status block), and the effect of the three
 * cancellation routes (NtCancelIoFile, NtCancelIoFileEx, CancelIoEx) on each kind, including that the endpoint stays
 * usable afterwards.
 */
#include "acc.h"

/* What closing the last handle does to each kind of request on a Windows 10 stack:
 * a connected stream's receive is aborted (CONNECTION_ABORTED), a blocked send is failed with LOCAL_DISCONNECT, a
 * poll succeeds and returns its parameter block (32 bytes, one entry), everything else is plainly cancelled. */
static LONG close_status(int op)
{
    switch (op) {
    case OP_RECV_TCP: case OP_NTREAD: return ST_CONN_ABORTED;
    case OP_SEND_FULL: return ST_LOCAL_DISCONNECT;
    case OP_POLL: return ST_SUCCESS;
    default: return ST_CANCELLED;
    }
}
static ULONG_PTR close_info(int op) { return op == OP_POLL ? 0x20 : 0; }
/* explicit cancel: a cancelled poll reports the 16-byte header in Information, everything else zero */
static ULONG_PTR cancel_info(int op) { return op == OP_POLL ? 0x10 : 0; }

/* Close the endpoint the request is queued on by `how`; the request must then finish as cancelled. */
static void pend_close_case(int op, int how, int use_port)
{
    pend_t p;
    HANDLE port = NULL;
    UP();
    if (use_port) { port = acc_port(); REQUIRE(port); }
    if (!acc_pend_start(&p, op, port, 0x5150)) { t_skip("could not queue %s", acc_op_name[op]); if (port) CloseHandle(port); acc_pend_done(&p); return; }
    EXPECT_EQ(acc_pend_status(&p), ST_PENDING);
    acc_close(p.target, how);
    p.target = INVALID_SOCKET;
    CHECKF(acc_pend_wait(&p, ACC_WAIT), "%s not completed after %s", acc_op_name[op], acc_how_name[how]);
    EXPECT_ST(acc_pend_status(&p), close_status(op));
    EXPECT_EQ(p.is_nt ? p.io.Information : p.ov.InternalHigh, close_info(op));
    if (port) {
        ULONG_PTR key = 0, apc = 0; IO_STATUS_BLOCK io;
        LONG st = acc_remove(port, &key, &apc, &io, ACC_WAIT);
        EXPECT_EQ(st, ST_SUCCESS);
        EXPECT_EQ(key, 0x5150);
        EXPECT_EQ(io.Status, close_status(op));
        EXPECT_EQ(io.Information, close_info(op));
        if (!p.is_nt) EXPECT_EQ(apc, (ULONG_PTR)&p.ov);
        st = acc_remove(port, &key, &apc, &io, 50);
        EXPECT_EQ(st, ST_TIMEOUT);          /* exactly one packet per request */
        CloseHandle(port);
    }
    acc_pend_done(&p);
}

#define PEND_TESTS(op, nm) \
    TEST(cc_pend_##nm##_closesocket)        { pend_close_case(op, CL_SOCKET, 0); } \
    TEST(cc_pend_##nm##_closehandle)        { pend_close_case(op, CL_HANDLE, 0); } \
    TEST(cc_pend_##nm##_ntclose)            { pend_close_case(op, CL_NT, 0); } \
    TEST(cc_pend_##nm##_port_closesocket)   { pend_close_case(op, CL_SOCKET, 1); } \
    TEST(cc_pend_##nm##_port_ntclose)       { pend_close_case(op, CL_NT, 1); }

PEND_TESTS(OP_RECV_TCP, recv_tcp)
PEND_TESTS(OP_RECV_UDP, recv_udp)
PEND_TESTS(OP_ACCEPT, acceptex)
PEND_TESTS(OP_ADDRCHANGE, addrchange)
PEND_TESTS(OP_SEND_FULL, send_full)
PEND_TESTS(OP_NTREAD, ntread)
PEND_TESTS(OP_POLL, poll)

/* The cancelling thread issued the request, so the completion is delivered before the close call returns. */
static void pend_done_before_return(int op, int how)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, op, NULL, 0)) { t_skip("could not queue %s", acc_op_name[op]); acc_pend_done(&p); return; }
    acc_close(p.target, how);
    p.target = INVALID_SOCKET;
    CHECK(acc_pend_status(&p) != ST_PENDING);
    EXPECT_ST(acc_pend_status(&p), close_status(op));
    CHECK(WaitForSingleObject(p.ev, 0) == WAIT_OBJECT_0);
    acc_pend_done(&p);
}
#define DONE_TESTS(op, nm) \
    TEST(cc_pend_##nm##_complete_before_closesocket_returns) { pend_done_before_return(op, CL_SOCKET); } \
    TEST(cc_pend_##nm##_complete_before_ntclose_returns)     { pend_done_before_return(op, CL_NT); }
DONE_TESTS(OP_RECV_TCP, recv_tcp)
DONE_TESTS(OP_ACCEPT, acceptex)
DONE_TESTS(OP_NTREAD, ntread)
DONE_TESTS(OP_POLL, poll)

/* ---- cancellation routes ---------------------------------------------------------------------------------- */
enum { CX_NTCANCEL, CX_NTCANCELEX, CX_CANCELIOEX_ALL, CX_CANCELIOEX_ONE, CX_CANCELIO };
static LONG do_cancel(pend_t *p, int how)
{
    IO_STATUS_BLOCK io;
    memset(&io, 0xAB, sizeof io);
    switch (how) {
    case CX_NTCANCEL:    return UN(NtCancelIoFile)((HANDLE)p->target, &io);
    case CX_NTCANCELEX:  return UN(NtCancelIoFileEx)((HANDLE)p->target, p->is_nt ? &p->io : (IO_STATUS_BLOCK *)&p->ov, &io);
    case CX_CANCELIOEX_ALL: return CancelIoEx((HANDLE)p->target, NULL) ? 0 : (LONG)GetLastError();
    case CX_CANCELIOEX_ONE: return CancelIoEx((HANDLE)p->target, p->is_nt ? NULL : &p->ov) ? 0 : (LONG)GetLastError();
    default: return CancelIo((HANDLE)p->target) ? 0 : (LONG)GetLastError();
    }
}

/* Cancel by `how`; the request finishes cancelled and the endpoint is still an open, working socket. */
static void pend_cancel_case(int op, int how)
{
    pend_t p;
    int type = -1, len = sizeof type;
    UP();
    if (!acc_pend_start(&p, op, NULL, 0)) { t_skip("could not queue %s", acc_op_name[op]); acc_pend_done(&p); return; }
    if (how == CX_CANCELIOEX_ONE && p.is_nt) { /* NULL overlapped: not a per-request cancel, same as ALL */ }
    EXPECT_ST(do_cancel(&p, how), 0);
    CHECKF(acc_pend_wait(&p, ACC_WAIT), "%s not completed after cancel", acc_op_name[op]);
    EXPECT_EQ(acc_pend_status(&p), ST_CANCELLED);
    EXPECT_EQ(p.is_nt ? p.io.Information : p.ov.InternalHigh, cancel_info(op));
    /* the endpoint survives: a socket-level query still works */
    CHECK(U(getsockopt)(p.target, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0);
    CHECK(type == (op == OP_RECV_UDP ? SOCK_DGRAM : SOCK_STREAM));
    acc_pend_done(&p);
}
#define CANCEL_TESTS(op, nm) \
    TEST(cc_cancel_##nm##_ntcancelio)      { pend_cancel_case(op, CX_NTCANCEL); } \
    TEST(cc_cancel_##nm##_ntcancelioex)    { pend_cancel_case(op, CX_NTCANCELEX); } \
    TEST(cc_cancel_##nm##_cancelioex_all)  { pend_cancel_case(op, CX_CANCELIOEX_ALL); } \
    TEST(cc_cancel_##nm##_cancelioex_one)  { pend_cancel_case(op, CX_CANCELIOEX_ONE); } \
    TEST(cc_cancel_##nm##_cancelio)        { pend_cancel_case(op, CX_CANCELIO); }
CANCEL_TESTS(OP_RECV_TCP, recv_tcp)
CANCEL_TESTS(OP_RECV_UDP, recv_udp)
CANCEL_TESTS(OP_ACCEPT, acceptex)
CANCEL_TESTS(OP_ADDRCHANGE, addrchange)
CANCEL_TESTS(OP_SEND_FULL, send_full)
CANCEL_TESTS(OP_NTREAD, ntread)
CANCEL_TESTS(OP_POLL, poll)

/* ---- specific scenarios ------------------------------------------------------------------------------------ */

/* Three receives stacked on one stream: closing completes all three as cancelled, one packet each. */
TEST(cc_pend_three_recvs_all_aborted)
{
    OVERLAPPED ov[3]; HANDLE ev[3]; char buf[3][8]; WSABUF wb[3]; DWORD fl, i;
    HANDLE port;
    UP();
    PAIR(c, s);
    port = acc_port();
    REQUIRE(port);
    CreateIoCompletionPort((HANDLE)c, port, 77, 0);
    for (i = 0; i < 3; i++) {
        ev[i] = acc_event(); acc_ov_init(&ov[i], ev[i]);
        wb[i].buf = buf[i]; wb[i].len = 8; fl = 0;
        CHECK(U(WSARecv)(c, &wb[i], 1, NULL, &fl, &ov[i], NULL) == SOCKET_ERROR && WERR() == WSA_IO_PENDING);
    }
    CLOSES(c);
    for (i = 0; i < 3; i++) {
        CHECK(WaitForSingleObject(ev[i], ACC_WAIT) == WAIT_OBJECT_0);
        EXPECT_ST(OV_STATUS(&ov[i]), ST_CONN_ABORTED);
        EXPECT_EQ(ov[i].InternalHigh, 0);
    }
    for (i = 0; i < 3; i++) {
        ULONG_PTR key = 0, apc = 0; IO_STATUS_BLOCK io;
        EXPECT_ST(acc_remove(port, &key, &apc, &io, ACC_WAIT), ST_SUCCESS);
        EXPECT_EQ(key, 77);
        EXPECT_EQ(io.Status, ST_CONN_ABORTED);
    }
    EXPECT_ST(acc_remove(port, (ULONG_PTR[1]){0}, (ULONG_PTR[1]){0}, &(IO_STATUS_BLOCK){0}, 50), ST_TIMEOUT);
    for (i = 0; i < 3; i++) CloseHandle(ev[i]);
    CloseHandle(port); CLOSES(s);
}

/* A receive and a send both outstanding: one close cancels both. */
TEST(cc_pend_recv_and_send_both_failed)
{
    OVERLAPPED orv, osd; HANDLE e1, e2; char rb[8], sb[1024]; WSABUF wr, ws; DWORD fl = 0;
    UP();
    PAIR(c, s);
    if (acc_fill_send(c, 32u << 20) == 0) { t_skip("send queue could not be filled"); CLOSES(c); CLOSES(s); return; }
    e1 = acc_event(); e2 = acc_event();
    acc_ov_init(&orv, e1); acc_ov_init(&osd, e2);
    wr.buf = rb; wr.len = 8; ws.buf = sb; ws.len = sizeof sb;
    /* the peer sent nothing, so the receive is outstanding too */
    CHECK(U(WSARecv)(c, &wr, 1, NULL, &fl, &orv, NULL) == SOCKET_ERROR && WERR() == WSA_IO_PENDING);
    CHECK(U(WSASend)(c, &ws, 1, NULL, 0, &osd, NULL) == SOCKET_ERROR && WERR() == WSA_IO_PENDING);
    CLOSES(c);
    CHECK(WaitForSingleObject(e1, ACC_WAIT) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(e2, ACC_WAIT) == WAIT_OBJECT_0);
    EXPECT_ST(OV_STATUS(&orv), ST_CONN_ABORTED);
    EXPECT_ST(OV_STATUS(&osd), ST_LOCAL_DISCONNECT);
    CloseHandle(e1); CloseHandle(e2); CLOSES(s);
}

/* The Win32 error for a receive aborted by close is ERROR_CONNECTION_ABORTED (WSAECONNABORTED on the Winsock side). */
TEST(cc_pend_getoverlappedresult_after_close_is_connaborted)
{
    pend_t p; DWORD n = 77, fl = 77; BOOL r;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CLOSES(p.target); p.target = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    WSETERR(0);
    r = U(WSAGetOverlappedResult)(p.other, &p.ov, &n, FALSE, &fl);
    CHECK(!r); EXPECT_EQ(WERR(), WSAECONNABORTED);
    EXPECT_EQ(n, 0);
    SetLastError(0); n = 77;
    r = GetOverlappedResult(INVALID_HANDLE_VALUE, &p.ov, &n, FALSE);
    CHECK(!r); EXPECT_ERR(ERROR_CONNECTION_ABORTED);
    acc_pend_done(&p);
}

/* A datagram receive cancelled by close is plainly cancelled: ERROR_OPERATION_ABORTED / WSA_OPERATION_ABORTED. */
TEST(cc_pend_getoverlappedresult_udp_close_is_aborted)
{
    pend_t p; DWORD n = 77, fl = 77; BOOL r;
    UP();
    if (!acc_pend_start(&p, OP_RECV_UDP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CLOSES(p.target); p.target = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    SetLastError(0);
    r = GetOverlappedResult(INVALID_HANDLE_VALUE, &p.ov, &n, FALSE);
    CHECK(!r); EXPECT_ERR(ERROR_OPERATION_ABORTED);
    EXPECT_EQ(n, 0);
    acc_pend_done(&p);
}

/* The receive buffer is not touched by a request that is cancelled. */
TEST(cc_pend_cancelled_recv_leaves_buffer_untouched)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    memset(p.buf, 0x5A, 16);
    CLOSES(p.target); p.target = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    { int i, ok = 1; for (i = 0; i < 16; i++) if ((unsigned char)p.buf[i] != 0x5A) ok = 0; CHECK(ok); }
    acc_pend_done(&p);
}

/* After the endpoint is gone the same value is not a socket for any call. */
TEST(cc_pend_use_after_close_notsock)
{
    pend_t p; char b[4]; DWORD fl = 0; OVERLAPPED ov; WSABUF wb;
    SOCKET dead;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    dead = p.target;
    CLOSES(dead); p.target = INVALID_SOCKET;
    acc_pend_wait(&p, ACC_WAIT);
    acc_ov_init(&ov, NULL); wb.buf = b; wb.len = 4;
    WSETERR(0);
    CHECK(U(WSARecv)(dead, &wb, 1, NULL, &fl, &ov, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAENOTSOCK);
    WSETERR(0);
    CHECK(U(recv)(dead, b, 4, 0) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAENOTSOCK);
    WSETERR(0);
    CHECK(CLOSES(dead) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAENOTSOCK);
    acc_pend_done(&p);
}

/* A cancelled AcceptEx leaves the accept socket open and unconnected, and the listener still accepts. */
TEST(cc_pend_cancelled_acceptex_keeps_listener_working)
{
    pend_t p; struct sockaddr_in a; int n = sizeof a; SOCKET cl, ac; OVERLAPPED ov2; HANDLE e2; char buf[64]; DWORD got = 0;
    UP();
    if (!acc_pend_start(&p, OP_ACCEPT, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CHECK(CancelIoEx((HANDLE)p.target, &p.ov));
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_EQ(OV_STATUS(&p.ov), ST_CANCELLED);
    CHECK(U(getsockname)(p.target, (struct sockaddr *)&a, &n) == 0);
    /* second AcceptEx on the same listener with the same accept socket is accepted and completes on connect */
    e2 = acc_event(); acc_ov_init(&ov2, e2);
    ac = p.extra;
    CHECK(U(AcceptEx)(p.target, ac, buf, 0, 32, 32, &got, &ov2) == FALSE && WERR() == WSA_IO_PENDING);
    cl = acc_sock(SOCK_STREAM);
    CHECK(U(connect)(cl, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(WaitForSingleObject(e2, ACC_WAIT) == WAIT_OBJECT_0);
    EXPECT_EQ(OV_STATUS(&ov2), ST_SUCCESS);
    CLOSES(cl); CloseHandle(e2);
    acc_pend_done(&p);
}

/* A pending receive finishes normally (not cancelled) when the peer closes first, then the close is quiet. */
TEST(cc_pend_peer_close_completes_recv_with_eof)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CLOSES(p.other); p.other = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_EQ(OV_STATUS(&p.ov), ST_SUCCESS);
    EXPECT_EQ(p.ov.InternalHigh, 0);
    acc_pend_done(&p);
}

/* Abortive close by the peer fails the pending receive with a reset status. */
TEST(cc_pend_peer_rst_fails_recv_with_reset)
{
    pend_t p; DWORD n = 0, fl = 0;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    acc_rst_close(p.other); p.other = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_EQ(OV_STATUS(&p.ov), ST_CONN_RESET);
    WSETERR(0);
    CHECK(!U(WSAGetOverlappedResult)(p.target, &p.ov, &n, FALSE, &fl));
    EXPECT_EQ(WERR(), WSAECONNRESET);
    acc_pend_done(&p);
}

/* shutdown(SD_RECEIVE) does not complete a pending receive on this stack... record what happens. */
TEST(cc_pend_shutdown_receive_leaves_recv_pending)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CHECK(U(shutdown)(p.target, SD_RECEIVE) == 0);
    Sleep(100);
    t_note("pending recv after SD_RECEIVE: status %s", OV_PENDING(&p.ov) ? "pending" : "completed");
    CHECK(U(shutdown)(p.target, SD_BOTH) == 0);
    CLOSES(p.target); p.target = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    acc_pend_done(&p);
}

/* Reusing the OVERLAPPED and event of a cancelled request for a new one is allowed once it has completed. */
TEST(cc_pend_reuse_overlapped_after_cancel)
{
    pend_t p; DWORD fl = 0;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CHECK(CancelIoEx((HANDLE)p.target, &p.ov));
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    ResetEvent(p.ev);
    p.ov.Internal = 0; p.ov.InternalHigh = 0;
    CHECK(U(WSARecv)(p.target, &p.wb, 1, NULL, &fl, &p.ov, NULL) == SOCKET_ERROR && WERR() == WSA_IO_PENDING);
    EXPECT_EQ(OV_STATUS(&p.ov), ST_PENDING);
    CHECK(U(send)(p.other, "x", 1, 0) == 1);
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_EQ(OV_STATUS(&p.ov), ST_SUCCESS);
    EXPECT_EQ(p.ov.InternalHigh, 1);
    acc_pend_done(&p);
}

/* ---- raw NtReadFile on an overlapped endpoint --------------------------------------------------------------- */
/* Without a byte offset the read is refused: the endpoint is not a synchronous file, so there is no implicit position. */
TEST(cc_ntread_without_byteoffset_invalid_parameter)
{
    SOCKET c, s; IO_STATUS_BLOCK io; char b[8]; LONG st;
    UP();
    if (!acc_pair(&c, &s)) { t_skip("no pair"); return; }
    memset(&io, 0xEE, sizeof io);
    st = UN(NtReadFile)((HANDLE)c, NULL, NULL, NULL, &io, b, 8, NULL, NULL);
    EXPECT_ST(st, ST_INVALID_PARAMETER);
    CLOSES(c); CLOSES(s);
}

/* ---- poll: what closing reports ------------------------------------------------------------------------------ */
typedef struct { LONGLONG timeout; ULONG count; ULONG exclusive; struct { ULONG_PTR h; ULONG flags; LONG status; } e[1]; } pp_t;

/* Closing the endpoint that is both carrier and polled socket completes the poll normally with the close event
 * for that very socket and a success status inside the entry. */
TEST(cc_pend_poll_close_reports_close_event)
{
    pend_t p; pp_t *o;
    UP();
    if (!acc_pend_start(&p, OP_POLL, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    CLOSES(p.target); 
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    o = (pp_t *)p.poll;
    EXPECT_EQ(o->count, 1);
    EXPECT_EQ(o->e[0].h, (ULONG_PTR)p.target);
    EXPECT_EQ(o->e[0].flags, AFD_POLL_CLOSE);
    EXPECT_ST(o->e[0].status, 0);
    p.target = INVALID_SOCKET;
    acc_pend_done(&p);
}

/* A poll carried by one endpoint for another: closing the polled endpoint reports the close event and the carrier
 * lives on; closing the carrier instead leaves the request outstanding until the polled socket has an event. */
static void poll_other_case(int close_carrier)
{
    SOCKET carrier, polled, peer; HANDLE ev; IO_STATUS_BLOCK io; pp_t pi; LONG st;
    UP();
    carrier = acc_sock(SOCK_DGRAM);
    { PAIR(c, s); polled = c; peer = s; }
    ev = acc_event();
    memset(&pi, 0, sizeof pi);
    pi.timeout = -(LONGLONG)20000 * 10000; pi.count = 1;
    pi.e[0].h = (ULONG_PTR)polled; pi.e[0].flags = AFD_POLL_RECEIVE;
    st = UN(NtDeviceIoControlFile)((HANDLE)carrier, ev, NULL, NULL, &io, AFD_IOCTL_POLL, &pi, sizeof pi, &pi, sizeof pi);
    EXPECT_ST(st, ST_PENDING);
    if (close_carrier) {
        /* the poll belongs to the polled socket's events, not to the carrier handle: it stays outstanding */
        CLOSES(carrier);
        EXPECT_EQ(WaitForSingleObject(ev, 300), WAIT_TIMEOUT);
        CLOSES(polled);                      /* now its close event arrives */
        CHECK(WaitForSingleObject(ev, ACC_WAIT) == WAIT_OBJECT_0);
        EXPECT_ST(io.Status, ST_SUCCESS);
        EXPECT_EQ(pi.e[0].flags, AFD_POLL_CLOSE);
    } else {
        CLOSES(polled);
        CHECK(WaitForSingleObject(ev, ACC_WAIT) == WAIT_OBJECT_0);
        EXPECT_ST(io.Status, ST_SUCCESS);
        EXPECT_EQ(pi.e[0].flags, AFD_POLL_CLOSE);
        { int type = 0, len = sizeof type; CHECK(U(getsockopt)(carrier, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0); }
        CLOSES(carrier);
    }
    CloseHandle(ev); CLOSES(peer);
}
TEST(cc_pend_poll_other_socket_closed_reports_close)  { poll_other_case(0); }
TEST(cc_pend_poll_carrier_closed_request_stays_outstanding)             { poll_other_case(1); }
