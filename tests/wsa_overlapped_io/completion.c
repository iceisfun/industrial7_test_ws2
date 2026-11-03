/* wsa_overlapped_io / completion: completion routines (APCs) and event-array waits.
 * Measures: routine arguments (error, bytes, OVERLAPPED, flags), that routines run only when the issuing
 * thread is in an alertable wait, that hEvent is ignored when a routine is supplied, WSA_IO_PENDING for
 * routine requests, routines scheduled for immediately-completed requests, error codes passed to the
 * routine on cancel and close, chaining, ordering, and WSAWaitForMultipleEvents' parameter rules and
 * alertable/fWaitAll semantics. */
#include "oio.h"

/* Queue a routine-based receive. */
static int cr_recv(SOCKET s, char *buf, ULONG len, WSAOVERLAPPED *o)
{
    WSABUF b = {len, buf}; DWORD fl = 0;
    return U(WSARecv)(s, &b, 1, NULL, &fl, o, oio_cr);
}

TEST(oio_cr_recv_pends_and_runs_when_alertable)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8];
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    OEQ(cr_recv(c, buf, sizeof buf, &o), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    OEQ(o.Internal, OIO_STATUS_PENDING);
    oio_send(s, "cr!", 3);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.err, 0); OEQ(g_cr.bytes, 3); OEQ(g_cr.flags, 0);
    OEQ(g_cr.ov, &o); OEQ(g_cr.tid, GetCurrentThreadId());
    CHECK(!memcmp(buf, "cr!", 3));
    oio_close2(c, s);
}

TEST(oio_cr_not_run_by_nonalertable_wait)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; HANDLE never = oio_event();
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    oio_send(s, "x", 1);
    Sleep(150);
    OEQ(WaitForSingleObject(never, 100), WAIT_TIMEOUT);   /* not alertable */
    OEQ(g_cr.calls, 0);
    OEQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s); CloseHandle(never);
}

TEST(oio_cr_event_is_ignored_when_routine_given)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, ev);
    OEQ(cr_recv(c, buf, sizeof buf, &o), SOCKET_ERROR);
    oio_send(s, "e", 1);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(oio_wait(ev, 0), WAIT_TIMEOUT);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cr_sleepex_alertable_with_nothing_queued_times_out)
{
    UP();
    oio_cr_reset();
    OEQ(SleepEx(20, TRUE), 0);
    OEQ(g_cr.calls, 0);
}

TEST(oio_cr_send_routine_reports_bytes)
{
    SOCKET c, s; WSAOVERLAPPED o; char got[8];
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    WSABUF b = {4, (CHAR *)"send"};
    int rc = U(WSASend)(c, &b, 1, NULL, 0, &o, oio_cr);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.err, 0); OEQ(g_cr.bytes, 4); OEQ(g_cr.ov, &o);
    OEQ(U(recv)(s, got, 4, 0), 4);
    oio_close2(c, s);
}

/* A routine is scheduled even when the call itself completed at once (return value 0). */
TEST(oio_cr_scheduled_for_immediate_completion)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD nb = 0, fl = 0;
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    oio_send(s, "now", 3); Sleep(50);
    WSABUF b = {sizeof buf, buf};
    int rc = U(WSARecv)(c, &b, 1, &nb, &fl, &o, oio_cr);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    if (rc == 0) { OEQ(nb, 3); OEQ(g_cr.calls, 0); }
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.bytes, 3);
    oio_close2(c, s);
}

TEST(oio_cr_cancel_delivers_operation_aborted)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8];
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    CHECK(CancelIoEx((HANDLE)c, &o));
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.err, WSA_OPERATION_ABORTED); OEQ(g_cr.bytes, 0);
    OEQ(o.Internal, OIO_STATUS_CANCELLED);
    oio_close2(c, s);
}

TEST(oio_cr_closesocket_delivers_operation_aborted)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8];
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    U(closesocket)(c);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.err, WSAECONNABORTED); OEQ(g_cr.bytes, 0);
    U(closesocket)(s);
}

TEST(oio_cr_peer_close_delivers_zero_bytes_success)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8];
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    U(closesocket)(s);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.err, 0); OEQ(g_cr.bytes, 0);
    U(closesocket)(c);
}

TEST(oio_cr_two_requests_run_in_submission_order)
{
    SOCKET c, s; WSAOVERLAPPED o1, o2; char b1[2], b2[2];
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o1, NULL); oio_ovl(&o2, NULL);
    o1.hEvent = (HANDLE)(ULONG_PTR)0x100; o2.hEvent = (HANDLE)(ULONG_PTR)0x200; /* tags only: ignored with a routine */
    cr_recv(c, b1, 2, &o1); cr_recv(c, b2, 2, &o2);
    oio_send(s, "1122", 4);
    Sleep(100);
    SleepEx(OIO_WAIT, TRUE);
    if (g_cr.calls < 2) SleepEx(OIO_WAIT, TRUE);
    OEQ(g_cr.calls, 2);
    OEQ(g_cr.order[0], 0x100); OEQ(g_cr.order[1], 0x200);
    oio_close2(c, s);
}

/* All queued routines are run by one alertable wait that returns WAIT_IO_COMPLETION. */
TEST(oio_cr_multiple_ready_before_wait)
{
    SOCKET c, s; WSAOVERLAPPED o[3]; char b[3][1];
    UP(); PAIR(c, s);
    oio_cr_reset();
    for (int i = 0; i < 3; i++) { oio_ovl(&o[i], NULL); cr_recv(c, b[i], 1, &o[i]); }
    oio_send(s, "abc", 3);
    Sleep(150);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 3);
    CHECK(b[0][0] == 'a' && b[1][0] == 'b' && b[2][0] == 'c');
    oio_close2(c, s);
}

/* A routine may issue the next request from inside its own invocation. */
static SOCKET g_chain_sock; static WSAOVERLAPPED g_chain_ov[3]; static char g_chain_buf[3]; static volatile LONG g_chain_n;
static void CALLBACK chain_cr(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD fl)
{
    LONG i = InterlockedIncrement(&g_chain_n);
    if (i < 3) {
        WSABUF b = {1, &g_chain_buf[i]}; DWORD f = 0;
        memset(&g_chain_ov[i], 0, sizeof g_chain_ov[i]);
        U(WSARecv)(g_chain_sock, &b, 1, NULL, &f, &g_chain_ov[i], chain_cr);
    }
}
TEST(oio_cr_chained_requests)
{
    SOCKET c, s; WSABUF b = {1, g_chain_buf}; DWORD fl = 0;
    UP(); PAIR(c, s);
    g_chain_sock = c; g_chain_n = 0; memset(g_chain_ov, 0, sizeof g_chain_ov);
    U(WSARecv)(c, &b, 1, NULL, &fl, &g_chain_ov[0], chain_cr);
    oio_send(s, "xyz", 3);
    for (int i = 0; i < 6 && g_chain_n < 3; i++) SleepEx(1000, TRUE);
    OEQ(g_chain_n, 3);
    CHECK(!memcmp(g_chain_buf, "xyz", 3));
    oio_close2(c, s);
}

static volatile DWORD g_other_tid_result;
static void thr_alertable_nothing(void *p) { g_other_tid_result = SleepEx(400, TRUE); }
/* A routine runs on the thread that issued the request, not on another alertable thread. */
TEST(oio_cr_runs_on_issuing_thread_only)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; oio_thr t;
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL); g_other_tid_result = 0xFFFF;
    cr_recv(c, buf, sizeof buf, &o);
    HANDLE th = oio_spawn(&t, thr_alertable_nothing, NULL);
    oio_send(s, "t", 1);
    oio_join(th);
    OEQ(g_other_tid_result, 0);       /* other thread timed out, no APC for it */
    OEQ(g_cr.calls, 0);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.tid, GetCurrentThreadId());
    oio_close2(c, s);
}

TEST(oio_cr_waitforsingleobjectex_alertable)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; HANDLE never = oio_event();
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    oio_send(s, "w", 1);
    OEQ(WaitForSingleObjectEx(never, OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s); CloseHandle(never);
}

TEST(oio_cr_wsawait_alertable_returns_io_completion)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; HANDLE never = oio_event();
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    oio_send(s, "w", 1);
    DWORD r = U(WSAWaitForMultipleEvents)(1, &never, FALSE, OIO_WAIT, TRUE);
    OEQ(r, WSA_WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s); CloseHandle(never);
}

TEST(oio_cr_wsawait_not_alertable_leaves_routine_queued)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; HANDLE never = oio_event();
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    oio_send(s, "w", 1);
    Sleep(100);
    OEQ(U(WSAWaitForMultipleEvents)(1, &never, FALSE, 100, FALSE), WSA_WAIT_TIMEOUT);
    OEQ(g_cr.calls, 0);
    SleepEx(0, TRUE);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s); CloseHandle(never);
}

/* WSAGetOverlappedResult with fWait on a routine-based request does not run the routine. */
TEST(oio_cr_getresult_wait_true_does_not_run_routine)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD bytes = 0, fl = 0;
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    oio_send(s, "g", 1);
    Sleep(100);
    BOOL r = U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &fl);
    t_note("getresult(no wait) on routine request: %d bytes %lu err %d", r, bytes, r ? 0 : WERR());
    OEQ(g_cr.calls, 0);
    SleepEx(OIO_WAIT, TRUE);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s);
}

/* ---- WSAWaitForMultipleEvents rules ------------------------------------------------- */
TEST(oio_wait_zero_events_invalid_parameter)
{
    HANDLE e = oio_event();
    UP();
    SET_ERR(0);
    OEQ(U(WSAWaitForMultipleEvents)(0, &e, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    OEQ(WERR(), WSA_INVALID_PARAMETER);
    CloseHandle(e);
}

TEST(oio_wait_over_max_events_invalid_parameter)
{
    HANDLE e[65]; UP();
    for (int i = 0; i < 65; i++) e[i] = oio_event();
    OEQ(U(WSAWaitForMultipleEvents)(65, e, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    OEQ(WERR(), WSA_INVALID_PARAMETER);
    OEQ(U(WSAWaitForMultipleEvents)(64, e, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    for (int i = 0; i < 65; i++) CloseHandle(e[i]);
}

TEST(oio_wait_invalid_handle_in_array)
{
    HANDLE e[2]; UP();
    e[0] = oio_event(); e[1] = INVALID_HANDLE_VALUE;
    DWORD r = U(WSAWaitForMultipleEvents)(2, e, FALSE, 0, FALSE);
    t_note("wait with bad handle: ret 0x%lx err %d", r, r == WSA_WAIT_FAILED ? WERR() : 0);
    CloseHandle(e[0]);
}

TEST(oio_wait_any_returns_signalled_index)
{
    HANDLE e[3]; UP();
    for (int i = 0; i < 3; i++) e[i] = oio_event();
    SetEvent(e[1]);
    OEQ(U(WSAWaitForMultipleEvents)(3, e, FALSE, 1000, FALSE), WSA_WAIT_EVENT_0 + 1);
    SetEvent(e[0]);
    OEQ(U(WSAWaitForMultipleEvents)(3, e, FALSE, 1000, FALSE), WSA_WAIT_EVENT_0);   /* lowest index wins */
    for (int i = 0; i < 3; i++) CloseHandle(e[i]);
}

TEST(oio_wait_all_needs_every_event)
{
    HANDLE e[2]; UP();
    e[0] = oio_event(); e[1] = oio_event();
    SetEvent(e[0]);
    OEQ(U(WSAWaitForMultipleEvents)(2, e, TRUE, 50, FALSE), WSA_WAIT_TIMEOUT);
    SetEvent(e[1]);
    OEQ(U(WSAWaitForMultipleEvents)(2, e, TRUE, 1000, FALSE), WSA_WAIT_EVENT_0);
    CloseHandle(e[0]); CloseHandle(e[1]);
}

TEST(oio_wait_zero_timeout_polls)
{
    HANDLE e = oio_event(); UP();
    OEQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    SetEvent(e);
    OEQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    CloseHandle(e);
}

/* Two overlapped receives on two sockets, waited as a set. */
TEST(oio_wait_two_sockets_events_any_and_all)
{
    SOCKET c1, s1, c2, s2; WSAOVERLAPPED o[2]; char b[2][4]; DWORD fl; HANDLE e[2];
    UP(); PAIR(c1, s1); PAIR(c2, s2);
    e[0] = oio_event(); e[1] = oio_event();
    oio_ovl(&o[0], e[0]); oio_ovl(&o[1], e[1]);
    oio_post_recv(c1, b[0], 4, &o[0], &fl); oio_post_recv(c2, b[1], 4, &o[1], &fl);
    oio_send(s2, "2", 1);
    OEQ(U(WSAWaitForMultipleEvents)(2, e, FALSE, OIO_WAIT, FALSE), WSA_WAIT_EVENT_0 + 1);
    OEQ(U(WSAWaitForMultipleEvents)(2, e, TRUE, 100, FALSE), WSA_WAIT_TIMEOUT);
    oio_send(s1, "1", 1);
    OEQ(U(WSAWaitForMultipleEvents)(2, e, TRUE, OIO_WAIT, FALSE), WSA_WAIT_EVENT_0);
    oio_close2(c1, s1); oio_close2(c2, s2); CloseHandle(e[0]); CloseHandle(e[1]);
}

TEST(oio_wait_event_signalled_beats_alertable_apc_order)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    cr_recv(c, buf, sizeof buf, &o);
    oio_send(s, "a", 1); Sleep(100);
    SetEvent(ev);
    DWORD r = U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 1000, TRUE);
    t_note("signalled event + queued APC: ret 0x%lx calls %ld", r, (long)g_cr.calls);
    CHECK(r == WSA_WAIT_EVENT_0 || r == WSA_WAIT_IO_COMPLETION);
    SleepEx(0, TRUE);
    OEQ(g_cr.calls, 1);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_wsacreateevent_is_manual_reset_unsignalled)
{
    UP();
    WSAEVENT e = U(WSACreateEvent)();
    REQUIRE(e != WSA_INVALID_EVENT);
    OEQ(oio_wait(e, 0), WAIT_TIMEOUT);
    OEQ(U(WSASetEvent)(e), TRUE);
    OEQ(oio_wait(e, 0), WAIT_OBJECT_0);
    OEQ(oio_wait(e, 0), WAIT_OBJECT_0);       /* manual reset: stays signalled */
    OEQ(U(WSAResetEvent)(e), TRUE);
    OEQ(oio_wait(e, 0), WAIT_TIMEOUT);
    OEQ(U(WSACloseEvent)(e), TRUE);
}

TEST(oio_wsacloseevent_invalid_handle)
{
    UP();
    SET_ERR(0);
    OEQ(U(WSACloseEvent)(NULL), FALSE);
    OEQ(WERR(), WSA_INVALID_HANDLE);
    OEQ(U(WSASetEvent)(NULL), FALSE);
    OEQ(WERR(), WSA_INVALID_HANDLE);
    OEQ(U(WSAResetEvent)(NULL), FALSE);
    OEQ(WERR(), WSA_INVALID_HANDLE);
}

/* Using a WSAEVENT as the OVERLAPPED event is the same as any event. */
TEST(oio_wait_wsaevent_as_overlapped_event)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err;
    UP(); PAIR(c, s);
    WSAEVENT ev = U(WSACreateEvent)();
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, 4, &o, &fl);
    oio_send(s, "v", 1);
    OEQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, OIO_WAIT, FALSE), WSA_WAIT_EVENT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 1);
    U(WSACloseEvent)(ev); oio_close2(c, s);
}
