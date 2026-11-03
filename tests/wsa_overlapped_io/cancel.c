/* wsa_overlapped_io / cancel: cancellation and closing with outstanding overlapped I/O, plus overlapped
 * calls on sockets created without WSA_FLAG_OVERLAPPED.
 * Measures: CancelIo / CancelIoEx return values and their ERROR_NOT_FOUND cases, the completion state of a
 * cancelled request (Internal == STATUS_CANCELLED, InternalHigh == 0, WSAGetOverlappedResult failing with
 * WSA_OPERATION_ABORTED), selective cancel, data not lost to a cancelled receive, closesocket with a
 * request pending, and the export surface around cancellation. */
#include "oio.h"

TEST(oio_cancel_ex_specific_request)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 77, f2 = 77; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    CHECK(CancelIoEx((HANDLE)c, &o));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_CANCELLED); OEQ(o.InternalHigh, 0);
    OEQ(U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSA_OPERATION_ABORTED);
    OEQ(bytes, 0);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cancel_kernel32_getoverlappedresult_reports_aborted)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 77; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    CancelIoEx((HANDLE)c, &o);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    SetLastError(0);
    OEQ(GetOverlappedResult((HANDLE)c, (LPOVERLAPPED)&o, &bytes, FALSE), FALSE);
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    OEQ(bytes, 0);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cancel_ex_all_requests_with_null_overlapped)
{
    SOCKET c, s; WSAOVERLAPPED o[3]; char b[3][4]; DWORD fl; HANDLE e[3];
    UP(); PAIR(c, s);
    for (int i = 0; i < 3; i++) { e[i] = oio_event(); oio_ovl(&o[i], e[i]); oio_post_recv(c, b[i], 4, &o[i], &fl); }
    CHECK(CancelIoEx((HANDLE)c, NULL));
    for (int i = 0; i < 3; i++) {
        OEQ(oio_wait(e[i], OIO_WAIT), WAIT_OBJECT_0);
        OEQ(o[i].Internal, OIO_STATUS_CANCELLED);
        CloseHandle(e[i]);
    }
    oio_close2(c, s);
}

TEST(oio_cancel_ex_nothing_pending_not_found)
{
    SOCKET c, s; UP(); PAIR(c, s);
    SetLastError(0);
    OEQ(CancelIoEx((HANDLE)c, NULL), FALSE);
    EXPECT_ERR(ERROR_NOT_FOUND);
    oio_close2(c, s);
}

TEST(oio_cancel_ex_completed_request_not_found)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "d", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    SetLastError(0);
    OEQ(CancelIoEx((HANDLE)c, &o), FALSE);
    EXPECT_ERR(ERROR_NOT_FOUND);
    OEQ(o.Internal, OIO_STATUS_SUCCESS);     /* completed state is not disturbed */
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cancel_ex_twice_second_not_found)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    CHECK(CancelIoEx((HANDLE)c, &o));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    SetLastError(0);
    OEQ(CancelIoEx((HANDLE)c, &o), FALSE);
    EXPECT_ERR(ERROR_NOT_FOUND);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cancel_ex_foreign_overlapped_not_found)
{
    SOCKET c1, s1, c2, s2; WSAOVERLAPPED o1, o2; char b1[4], b2[4]; DWORD fl; HANDLE e1 = oio_event(), e2 = oio_event();
    UP(); PAIR(c1, s1); PAIR(c2, s2);
    oio_ovl(&o1, e1); oio_ovl(&o2, e2);
    oio_post_recv(c1, b1, 4, &o1, &fl); oio_post_recv(c2, b2, 4, &o2, &fl);
    SetLastError(0);
    OEQ(CancelIoEx((HANDLE)c1, &o2), FALSE);        /* o2 belongs to c2 */
    EXPECT_ERR(ERROR_NOT_FOUND);
    OEQ(oio_wait(e2, 100), WAIT_TIMEOUT);
    CHECK(CancelIoEx((HANDLE)c1, &o1)); CHECK(CancelIoEx((HANDLE)c2, &o2));
    oio_close2(c1, s1); oio_close2(c2, s2); CloseHandle(e1); CloseHandle(e2);
}

TEST(oio_cancel_ex_invalid_handle)
{
    UP();
    SetLastError(0);
    BOOL r = CancelIoEx(INVALID_HANDLE_VALUE, NULL);
    t_note("CancelIoEx(INVALID_HANDLE_VALUE): ret %d err %lu", r, r ? 0 : GetLastError());
}

/* Selective cancel leaves the other request pending, and it still completes with data. */
TEST(oio_cancel_ex_one_of_two_other_still_completes)
{
    SOCKET c, s; WSAOVERLAPPED o1, o2; char b1[4], b2[4]; DWORD fl, bytes, f2; int err; HANDLE e1 = oio_event(), e2 = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o1, e1); oio_ovl(&o2, e2);
    oio_post_recv(c, b1, 4, &o1, &fl); oio_post_recv(c, b2, 4, &o2, &fl);
    CHECK(CancelIoEx((HANDLE)c, &o1));
    OEQ(oio_wait(e1, OIO_WAIT), WAIT_OBJECT_0);
    /* Windows cancels the whole receive queue of the socket here: the second request completes too. */
    OEQ(oio_wait(e2, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o2.Internal, OIO_STATUS_CANCELLED); OEQ(o2.InternalHigh, 0);
    OEQ(o1.Internal, OIO_STATUS_CANCELLED);
    oio_close2(c, s); CloseHandle(e1); CloseHandle(e2);
}

/* Cancelling the older of two requests: the newer one takes the next data, nothing is lost. */
TEST(oio_cancel_does_not_consume_data)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8], b2[8]; DWORD fl; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    CancelIoEx((HANDLE)c, &o);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    oio_send(s, "kept", 4); Sleep(50);
    OEQ(U(recv)(c, b2, sizeof b2, 0), 4);
    CHECK(!memcmp(b2, "kept", 4));
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cancel_io_same_thread_cancels)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    CHECK(CancelIo((HANDLE)c));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_CANCELLED);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_cancel_io_with_nothing_pending_succeeds)
{
    SOCKET c, s; UP(); PAIR(c, s);
    CHECK(CancelIo((HANDLE)c));
    oio_close2(c, s);
}

static void thr_cancel_io(void *p) { *(volatile BOOL *)((void **)p)[1] = CancelIo((HANDLE)(ULONG_PTR)*(SOCKET *)((void **)p)[0]); }
TEST(oio_cancel_io_other_thread_scope_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; HANDLE ev = oio_event(); oio_thr t; volatile BOOL r = 2;
    void *args[2];
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    args[0] = &c; args[1] = (void *)&r;
    oio_join(oio_spawn(&t, thr_cancel_io, args));
    DWORD w = oio_wait(ev, 200);
    t_note("CancelIo from another thread: ret %d, request %s", (int)r, w == WAIT_OBJECT_0 ? "cancelled" : "still pending");
    CancelIoEx((HANDLE)c, NULL);
    oio_close2(c, s); CloseHandle(ev);
}

/* closesocket with a request outstanding: the request completes as cancelled; Internal says so. */
TEST(oio_close_pending_recv_completes_cancelled)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 5, f2; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    OEQ(U(closesocket)(c), 0);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_CONN_ABORTED); OEQ(o.InternalHigh, 0);
    /* the socket is gone: the result query refuses it */
    OEQ(U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSAENOTSOCK);
    U(closesocket)(s); CloseHandle(ev);
}

TEST(oio_close_two_pending_recvs_both_cancelled)
{
    SOCKET c, s; WSAOVERLAPPED o1, o2; char b1[4], b2[4]; DWORD fl; HANDLE e1 = oio_event(), e2 = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o1, e1); oio_ovl(&o2, e2);
    oio_post_recv(c, b1, 4, &o1, &fl); oio_post_recv(c, b2, 4, &o2, &fl);
    U(closesocket)(c);
    OEQ(oio_wait(e1, OIO_WAIT), WAIT_OBJECT_0); OEQ(oio_wait(e2, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o1.Internal, OIO_STATUS_CONN_ABORTED); OEQ(o2.Internal, OIO_STATUS_CONN_ABORTED);
    U(closesocket)(s); CloseHandle(e1); CloseHandle(e2);
}

TEST(oio_close_after_completion_is_quiet)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "z", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    U(closesocket)(c);
    OEQ(o.Internal, OIO_STATUS_SUCCESS);     /* a finished request keeps its result across close */
    OEQ(o.InternalHigh, 1);
    U(closesocket)(s); CloseHandle(ev);
}

/* Fill the send path with unread data until a send pends, then cancel it. */
TEST(oio_cancel_pending_send)
{
    enum { N = 65536, MAXI = 200 };
    SOCKET c, s; static char blk[N]; static WSAOVERLAPPED o[MAXI]; HANDLE ev = oio_event();
    int pend = -1;
    UP(); PAIR(c, s);
    for (int i = 0; i < MAXI && pend < 0; i++) {
        WSABUF b = {N, blk}; DWORD nb = 0;
        oio_ovl(&o[i], ev);
        int rc = U(WSASend)(c, &b, 1, &nb, 0, &o[i], NULL);
        if (rc == SOCKET_ERROR) { OEQ(WERR(), WSA_IO_PENDING); pend = i; }
    }
    if (pend < 0) { t_skip("send path never filled"); U(closesocket)(c); U(closesocket)(s); CloseHandle(ev); return; }
    OEQ(o[pend].Internal, OIO_STATUS_PENDING);
    CHECK(CancelIoEx((HANDLE)c, &o[pend]));
    ResetEvent(ev);
    for (int i = 0; i < 100 && o[pend].Internal == OIO_STATUS_PENDING; i++) Sleep(10);
    OEQ(o[pend].Internal, OIO_STATUS_CANCELLED);
    DWORD bytes = 0, f2;
    OEQ(U(WSAGetOverlappedResult)(c, &o[pend], &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSA_OPERATION_ABORTED);
    CancelIoEx((HANDLE)c, NULL);
    U(closesocket)(c); U(closesocket)(s); CloseHandle(ev);
    Sleep(100);
}

TEST(oio_close_pending_send_completes_cancelled)
{
    enum { N = 65536, MAXI = 200 };
    SOCKET c, s; static char blk[N]; static WSAOVERLAPPED o[MAXI]; HANDLE ev = oio_event();
    int pend = -1;
    UP(); PAIR(c, s);
    for (int i = 0; i < MAXI && pend < 0; i++) {
        WSABUF b = {N, blk}; DWORD nb = 0;
        oio_ovl(&o[i], ev);
        if (U(WSASend)(c, &b, 1, &nb, 0, &o[i], NULL) == SOCKET_ERROR) pend = i;
    }
    if (pend < 0) { t_skip("send path never filled"); U(closesocket)(c); U(closesocket)(s); CloseHandle(ev); return; }
    U(closesocket)(c);
    for (int i = 0; i < 300 && o[pend].Internal == OIO_STATUS_PENDING; i++) Sleep(10);
    OEQ(o[pend].Internal, OIO_STATUS_LOCAL_DISCONNECT);
    U(closesocket)(s); CloseHandle(ev);
    Sleep(100);
}

/* ---- sockets created without WSA_FLAG_OVERLAPPED ----------------------------------------- */

/* An OVERLAPPED passed to WSASend on a non-overlapped socket does not pend: the call completes
 * synchronously with the byte count. */
TEST(oio_plain_send_with_overlapped_completes_inline)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 99; char got[4];
    UP(); PAIR_PLAIN(c, s);
    oio_ovl(&o, NULL);
    WSABUF b = {3, (CHAR *)"abc"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    OEQ(rc, 0); OEQ(nb, 3);
    OEQ(U(recv)(s, got, 3, 0), 3);
    oio_close2(c, s);
}

TEST(oio_plain_send_overlapped_fields_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0, bytes = 0, f2 = 0; HANDLE ev = oio_event();
    UP(); PAIR_PLAIN(c, s);
    oio_ovl_sentinel(&o, ev);
    WSABUF b = {2, (CHAR *)"hi"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    OEQ(rc, 0);
    t_note("non-overlapped send: Internal 0x%llx InternalHigh %llu event %s", (unsigned long long)o.Internal,
           (unsigned long long)o.InternalHigh, oio_wait(ev, 0) == WAIT_OBJECT_0 ? "signalled" : "clear");
    BOOL r = U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2);
    t_note("  WSAGetOverlappedResult: %d bytes %lu err %d", r, bytes, r ? 0 : WERR());
    oio_close2(c, s); CloseHandle(ev);
}

/* A completion routine on a non-overlapped socket: the call is synchronous; whether the routine is
 * queued is recorded. */
TEST(oio_plain_send_with_routine_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0;
    UP(); PAIR_PLAIN(c, s);
    oio_cr_reset(); oio_ovl(&o, NULL);
    WSABUF b = {2, (CHAR *)"hi"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, oio_cr);
    t_note("non-overlapped send with routine: rc %d err %d", rc, rc ? WERR() : 0);
    SleepEx(100, TRUE);
    t_note("  routine calls: %ld", (long)g_cr.calls);
    oio_close2(c, s);
}

TEST(oio_plain_recv_data_ready_with_overlapped_returns_data_inline)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0, fl = 0; char buf[8];
    UP(); PAIR_PLAIN(c, s);
    oio_send(s, "inl", 3); Sleep(50);
    oio_ovl(&o, NULL);
    WSABUF b = {sizeof buf, buf};
    int rc = U(WSARecv)(c, &b, 1, &nb, &fl, &o, NULL);
    OEQ(rc, 0); OEQ(nb, 3); OEQ(fl, 0);
    CHECK(!memcmp(buf, "inl", 3));
    oio_close2(c, s);
}

/* Cancel on a socket that is not overlapped: nothing to cancel. */
TEST(oio_plain_cancelioex_nothing_pending)
{
    SOCKET c, s; UP(); PAIR_PLAIN(c, s);
    SetLastError(0);
    OEQ(CancelIoEx((HANDLE)c, NULL), FALSE);
    EXPECT_ERR(ERROR_NOT_FOUND);
    oio_close2(c, s);
}

/* ---- export surface ---------------------------------------------------------------------- */
TEST(oio_export_wsacanceloverlappedio_absent)
{
    HMODULE m = t_module("ws2_32.dll"); REQUIRE(m);
    SetLastError(0);
    FARPROC p = GetProcAddress(m, "WSACancelOverlappedIO");
    CHECK(p == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

TEST(oio_export_wsarecvmsg_absent_wsasendmsg_present)
{
    HMODULE m = t_module("ws2_32.dll"); REQUIRE(m);
    CHECK(GetProcAddress(m, "WSARecvMsg") == NULL);
    CHECK(GetProcAddress(m, "WSASendMsg") != NULL);
    CHECK(GetProcAddress(m, "WSASendDisconnect") != NULL);
    CHECK(GetProcAddress(m, "WSARecvDisconnect") != NULL);
    CHECK(GetProcAddress(m, "WSARecvFrom") != NULL);
    CHECK(GetProcAddress(m, "WSASendTo") != NULL);
    CHECK(GetProcAddress(m, "WSAGetOverlappedResult") != NULL);
}

TEST(oio_export_wsock32_forwards_overlapped_free_calls)
{
    UP();
    CHECK(t_proc_in("wsock32.dll", "recv") != NULL);
    CHECK(t_proc_in("wsock32.dll", "send") != NULL);
    CHECK(t_proc_in("wsock32.dll", "WSASend") == NULL);
}
