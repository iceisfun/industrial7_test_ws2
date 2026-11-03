/* Edge cases around overlapped socket requests that the grid in matrix.c does not reach: cancelling when nothing
 * (or the wrong thing) is pending, cancelling every request on a handle at once, argument-shape errors of the
 * WSA calls with and without an OVERLAPPED, peeking and waiting receives, gather/scatter buffer lists, the way a
 * pending receive ends when the peer closes, resets or the local side shuts down, reusing an OVERLAPPED, and
 * thread exit with a request pending. Observations use the token mechanism of the grid and are compared with
 * the table in tbl.c. */
#include "xom.h"

#define EO(key_) char eo_obs[768]; const char *eo_key = key_; xom_out = eo_obs; xom_cap = sizeof eo_obs; eo_obs[0] = 0
#define EO_DONE() xom_compare(eo_key, eo_obs)
#define EO_NEXT(key_) do { xom_compare(eo_key, eo_obs); eo_key = key_; eo_obs[0] = 0; } while (0)
#define TRE(fmt_, call) do { int r_ = (int)(call); T(fmt_, r_, U(WSAGetLastError)()); } while (0)

static SOCKET eo_tcp(DWORD fl) { return xom_sock(SOCK_STREAM, fl); }
static void eo_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static int eo_pair(SOCKET *c, SOCKET *s, DWORD fl)
{
    memset(&g, 0, sizeof g);
    g.s = g.p = g.l = g.a = INVALID_SOCKET;
    if (!xom_tcp_pair(fl)) { xom_free(); return 0; }
    *c = g.s; *s = g.p; g.s = g.p = INVALID_SOCKET;
    xom_free();
    return 1;
}
static void eo_wait_done(OVERLAPPED *o, DWORD ms)
{
    DWORD t0 = GetTickCount();
    while (!HasOverlappedIoCompleted(o) && GetTickCount() - t0 < ms) SleepEx(2, TRUE);
}
/* Start one pending receive of up to len bytes on c, on an event-style OVERLAPPED. */
static int eo_recv(SOCKET c, OVERLAPPED *ov, HANDLE ev, char *buf, ULONG len, DWORD fl_in, WSABUF *wb)
{
    DWORD n = 0, fl = fl_in; int r;
    memset(ov, 0, sizeof *ov); ov->hEvent = ev; wb->buf = buf; wb->len = len;
    r = U(WSARecv)(c, wb, 1, &n, &fl, (LPWSAOVERLAPPED)ov, NULL);
    return r == 0 ? 0 : U(WSAGetLastError)();
}

/* --- CancelIoEx / CancelIo ---------------------------------------------------- */
TEST(cancel_when_nothing_is_pending)
{
    EO("cancel/idle_null"); SOCKET c, s; OVERLAPPED ov; BOOL ok;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov);
    SetLastError(0); ok = CancelIoEx((HANDLE)c, NULL); T("ret=%d e=%lu", ok, ok ? 0 : GetLastError());
    EO_NEXT("cancel/idle_specific");
    SetLastError(0); ok = CancelIoEx((HANDLE)c, &ov); T("ret=%d e=%lu", ok, ok ? 0 : GetLastError());
    EO_NEXT("cancel/idle_cancelio");
    SetLastError(0); ok = CancelIo((HANDLE)c); T("ret=%d e=%lu", ok, ok ? 0 : GetLastError());
    EO_DONE();
    eo_close(c); eo_close(s);
}
TEST(cancel_after_request_completed)
{
    EO("cancel/after_done"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[16]; WSABUF wb; BOOL ok; int e;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    e = eo_recv(c, &ov, ev, b, sizeof b, 0, &wb);
    T("issue=%d", e);
    U(send)(s, "abc", 3, 0);
    T("signalled=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    SetLastError(0); ok = CancelIoEx((HANDLE)c, &ov); T("ret=%d e=%lu", ok, ok ? 0 : GetLastError());
    T("status=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(cancel_all_with_null_overlapped)
{
    EO("cancelall/two_recvs"); SOCKET c, s; OVERLAPPED ov[2]; HANDLE ev[2], p; char b[2][8]; WSABUF wb[2]; BOOL ok; int i;
    DWORD by; ULONG_PTR key; LPOVERLAPPED po;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    CreateIoCompletionPort((HANDLE)c, p, XOM_KEY, 0);
    for (i = 0; i < 2; i++) { ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL); T("issue%d=%d", i, eo_recv(c, &ov[i], ev[i], b[i], 8, 0, &wb[i])); }
    SetLastError(0); ok = CancelIoEx((HANDLE)c, NULL); T("cancel=%d", ok);
    for (i = 0; i < 2; i++) { eo_wait_done(&ov[i], 2000); T("st%d=%lx", i, (DWORD)ov[i].Internal); }
    for (i = 0; i < 2; i++) {
        SetLastError(0); ok = GetQueuedCompletionStatus(p, &by, &key, &po, 2000);
        T("pkt%d=%d,e%lu,b%lu", i, ok, ok ? 0 : GetLastError(), by);
    }
    EO_DONE();
    for (i = 0; i < 2; i++) CloseHandle(ev[i]);
    CloseHandle(p); eo_close(c); eo_close(s);
}
TEST(cancel_targets_only_the_named_request)
{
    EO("cancelone/two_recvs"); SOCKET c, s; OVERLAPPED ov[2]; HANDLE ev[2]; char b[2][8]; WSABUF wb[2]; BOOL ok; int i;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    for (i = 0; i < 2; i++) { ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL); T("issue%d=%d", i, eo_recv(c, &ov[i], ev[i], b[i], 8, 0, &wb[i])); }
    memset(b, 0, sizeof b);
    ok = CancelIoEx((HANDLE)c, &ov[1]); T("cancel=%d", ok);
    eo_wait_done(&ov[1], 2000);
    eo_wait_done(&ov[0], 1000);
    T("done0=%d done1=%d st0=%lx st1=%lx", HasOverlappedIoCompleted(&ov[0]) != 0, HasOverlappedIoCompleted(&ov[1]) != 0, (DWORD)ov[0].Internal, (DWORD)ov[1].Internal);
    U(send)(s, "xy", 2, 0);
    T("sig0=%d", WaitForSingleObject(ev[0], 3000) == WAIT_OBJECT_0);
    T("bytes0=%lu", (DWORD)ov[0].InternalHigh);
    EO_DONE();
    for (i = 0; i < 2; i++) CloseHandle(ev[i]);
    eo_close(c); eo_close(s);
}
TEST(cancelio_cancels_pending_receive_of_this_thread)
{
    EO("cancelio/recv"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[8]; WSABUF wb; BOOL ok;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T("issue=%d", eo_recv(c, &ov, ev, b, 8, 0, &wb));
    ok = CancelIo((HANDLE)c); T("cancel=%d", ok);
    eo_wait_done(&ov, 2000);
    T("st=%lx bytes=%lu sig=%d", (DWORD)ov.Internal, (DWORD)ov.InternalHigh, WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}

/* --- argument shape --------------------------------------------------------- */
TEST(send_recv_buffer_list_shape_errors)
{
    EO("shape/send_nobuf_ovl"); SOCKET c, s; OVERLAPPED ov; WSABUF wb; char b[8] = "abc"; DWORD n = 0, fl = 0;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    wb.buf = b; wb.len = 3;
    TRE("r=%d e=%d", U(WSASend)(c, NULL, 0, &n, 0, (LPWSAOVERLAPPED)&ov, NULL));
    EO_NEXT("shape/send_count0_ovl");
    TRE("r=%d e=%d", U(WSASend)(c, &wb, 0, &n, 0, (LPWSAOVERLAPPED)&ov, NULL));
    EO_NEXT("shape/recv_nobuf_ovl");
    TRE("r=%d e=%d", U(WSARecv)(c, NULL, 0, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL));
    EO_NEXT("shape/recv_count0_ovl");
    TRE("r=%d e=%d", U(WSARecv)(c, &wb, 0, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL));
    EO_NEXT("shape/routine_without_overlapped");
    TRE("r=%d e=%d", U(WSASend)(c, &wb, 1, &n, 0, NULL, xom_rt));
    EO_DONE();
    CloseHandle(ov.hEvent); eo_close(c); eo_close(s);
}
TEST(extension_ioctl_bytes_returned_rules)
{
    EO("extptr/nobytes_noov"); SOCKET s; GUID id = WSAID_ACCEPTEX; void *fp = NULL; DWORD n = 0; OVERLAPPED ov;
    XOM_UP();
    s = eo_tcp(WSA_FLAG_OVERLAPPED);
    memset(&ov, 0, sizeof ov);
    TRE("r=%d e=%d", U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &fp, sizeof fp, NULL, NULL, NULL));
    EO_NEXT("extptr/nobytes_ov");
    TRE("r=%d e=%d", U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &fp, sizeof fp, NULL, (LPWSAOVERLAPPED)&ov, NULL));
    T("fp=%d", fp != NULL);
    EO_NEXT("extptr/small_out");
    fp = NULL; n = 0;
    TRE("r=%d e=%d", U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &fp, 4, &n, NULL, NULL));
    T("n=%lu", n);
    EO_NEXT("extptr/no_out");
    TRE("r=%d e=%d", U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, NULL, 0, &n, NULL, NULL));
    EO_NEXT("extptr/no_in");
    TRE("r=%d e=%d", U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, NULL, 0, &fp, sizeof fp, &n, NULL, NULL));
    EO_NEXT("extptr/zero_guid");
    { GUID z; memset(&z, 0, sizeof z);
      TRE("r=%d e=%d", U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &z, sizeof z, &fp, sizeof fp, &n, NULL, NULL)); }
    EO_DONE();
    eo_close(s);
}

/* --- receive flavours ----------------------------------------------------------- */
TEST(peeking_receive_keeps_the_data)
{
    EO("peek/pending"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[16], t[16]; WSABUF wb; int e, got;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    e = eo_recv(c, &ov, ev, b, sizeof b, MSG_PEEK, &wb); T("issue=%d", e);
    U(send)(s, "peekme", 6, 0);
    T("sig=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    got = U(recv)(c, t, sizeof t, 0); T("left=%d", got);
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(waitall_receive_completes_only_when_full)
{
    EO("waitall/pending"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[16]; WSABUF wb; int e;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    e = eo_recv(c, &ov, ev, b, 8, MSG_WAITALL, &wb); T("issue=%d", e);
    U(send)(s, "abc", 3, 0);
    T("sig_after3=%d", WaitForSingleObject(ev, 300) == WAIT_OBJECT_0);
    U(send)(s, "defgh", 5, 0);
    T("sig_after8=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(scatter_gather_with_empty_middle_buffer)
{
    EO("sg/recv"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b1[2], b2[4], b3[8]; WSABUF wb[3]; DWORD n = 0, fl = 0; int r;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    wb[0].buf = b1; wb[0].len = 2; wb[1].buf = b2; wb[1].len = 0; wb[2].buf = b3; wb[2].len = 8;
    memset(b1, '.', 2); memset(b3, '.', 8);
    r = U(WSARecv)(c, wb, 3, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL); T("r=%d e=%d", r, U(WSAGetLastError)());
    U(send)(s, "ABCDE", 5, 0);
    T("sig=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("bytes=%lu data=%c%c_%c%c%c", (DWORD)ov.InternalHigh, b1[0], b1[1], b3[0], b3[1], b3[2]);
    EO_NEXT("sg/send");
    { char t[16]; int got; WSABUF sb[3]; sb[0].buf = "12"; sb[0].len = 2; sb[1].buf = "x"; sb[1].len = 0; sb[2].buf = "345"; sb[2].len = 3;
      memset(&ov, 0, sizeof ov); n = 0;
      r = U(WSASend)(c, sb, 3, &n, 0, (LPWSAOVERLAPPED)&ov, NULL); T("r=%d e=%d", r, U(WSAGetLastError)());
      if (r) eo_wait_done(&ov, 2000);
      T("bytes=%lu", r ? (DWORD)ov.InternalHigh : n);
      xom_readable(s, 3000); got = U(recv)(s, t, sizeof t, 0); T("peer=%d", got); if (got > 0) T("data=%.5s", t); }
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}

/* --- how a pending receive ends --------------------------------------------------- */
TEST(pending_receive_ends_on_graceful_close)
{
    EO("peerfin/recv"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[8]; WSABUF wb;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T("issue=%d", eo_recv(c, &ov, ev, b, 8, 0, &wb));
    U(shutdown)(s, SD_SEND);
    T("sig=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    { DWORD got = 9, f = 9; BOOL ok = U(WSAGetOverlappedResult)(c, (LPWSAOVERLAPPED)&ov, &got, FALSE, &f); T("wgor=%d,%lu,%lx", ok, got, f); }
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(pending_receive_ends_on_peer_reset)
{
    EO("peerrst/recv"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[8]; WSABUF wb; struct linger lg;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T("issue=%d", eo_recv(c, &ov, ev, b, 8, 0, &wb));
    lg.l_onoff = 1; lg.l_linger = 0; U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg);
    U(closesocket)(s); s = INVALID_SOCKET;
    T("sig=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    { DWORD got = 9, f = 9; BOOL ok = U(WSAGetOverlappedResult)(c, (LPWSAOVERLAPPED)&ov, &got, FALSE, &f); T("wgor=%d,%lu,%lx e=%d", ok, got, f, U(WSAGetLastError)()); }
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(pending_receive_and_local_shutdown_receive)
{
    EO("localshut/recv"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[8]; WSABUF wb;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T("issue=%d", eo_recv(c, &ov, ev, b, 8, 0, &wb));
    TRE("shut=%d,%d", U(shutdown)(c, SD_RECEIVE));
    T("sig=%d", WaitForSingleObject(ev, 1500) == WAIT_OBJECT_0);
    T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    CancelIoEx((HANDLE)c, &ov); eo_wait_done(&ov, 2000);
    T("st_after_cancel=%lx", (DWORD)ov.Internal);
    EO_NEXT("localshut/after");
    { DWORD n = 0, fl = 0; OVERLAPPED o2; memset(&o2, 0, sizeof o2); o2.hEvent = ev; ResetEvent(ev);
      TRE("recv=%d,%d", U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&o2, NULL)); T("n=%lu", n); }
    EO_NEXT("localshut/send_after_shutdown_send");
    { DWORD n = 0; OVERLAPPED o2; memset(&o2, 0, sizeof o2); o2.hEvent = ev;
      U(shutdown)(c, SD_SEND);
      TRE("send=%d,%d", U(WSASend)(c, &wb, 1, &n, 0, (LPWSAOVERLAPPED)&o2, NULL)); }
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(unconnected_stream_requests_fail_at_once)
{
    EO("unconn/send"); SOCKET c; OVERLAPPED ov; HANDLE ev; char b[8] = "abc"; WSABUF wb; DWORD n = 0, fl = 0; HANDLE p; DWORD by; ULONG_PTR key; LPOVERLAPPED po = NULL;
    XOM_UP();
    c = eo_tcp(WSA_FLAG_OVERLAPPED);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1); CreateIoCompletionPort((HANDLE)c, p, XOM_KEY, 0);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov); ov.hEvent = ev; wb.buf = b; wb.len = 3;
    TRE("r=%d e=%d", U(WSASend)(c, &wb, 1, &n, 0, (LPWSAOVERLAPPED)&ov, NULL));
    T("sig=%d pkt=%d", WaitForSingleObject(ev, 0) == WAIT_OBJECT_0, GetQueuedCompletionStatus(p, &by, &key, &po, 100) || po != NULL);
    EO_NEXT("unconn/recv");
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    TRE("r=%d e=%d", U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL));
    T("sig=%d pkt=%d", WaitForSingleObject(ev, 0) == WAIT_OBJECT_0, GetQueuedCompletionStatus(p, &by, &key, &po, 100) || po != NULL);
    EO_DONE();
    CloseHandle(ev); CloseHandle(p); eo_close(c);
}

/* --- OVERLAPPED reuse and untouched structures ---------------------------------------- */
TEST(overlapped_fields_are_rewritten_on_reuse)
{
    EO("reuse/second_recv"); SOCKET c, s; OVERLAPPED ov; HANDLE ev; char b[8]; WSABUF wb; DWORD n = 0, fl = 0; int r;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    T("issue=%d", eo_recv(c, &ov, ev, b, 8, 0, &wb));
    U(send)(s, "one", 3, 0); WaitForSingleObject(ev, 3000);
    /* poison the status fields, then reuse the structure without clearing it */
    ov.Internal = 0x1234; ov.InternalHigh = 0x4321; ResetEvent(ev);
    r = U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL); T("r=%d e=%d", r, U(WSAGetLastError)());
    T("pending_st=%lx high_is_poison=%d", (DWORD)ov.Internal, ov.InternalHigh == 0x4321);
    U(send)(s, "twotwo", 6, 0); WaitForSingleObject(ev, 3000);
    T("done_st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}
TEST(result_query_for_a_zeroed_structure)
{
    EO("zeroed/gor"); SOCKET c, s; OVERLAPPED ov; DWORD got = 9, f = 9; BOOL ok;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov);
    SetLastError(0); ok = GetOverlappedResult((HANDLE)c, &ov, &got, FALSE); T("ret=%d got=%lu e=%lu", ok, got, ok ? 0 : GetLastError());
    EO_NEXT("zeroed/wgor");
    U(WSASetLastError)(0); ok = U(WSAGetOverlappedResult)(c, (LPWSAOVERLAPPED)&ov, &got, FALSE, &f);
    T("ret=%d got=%lu f=%lx e=%d", ok, got, f, ok ? 0 : U(WSAGetLastError)());
    EO_NEXT("zeroed/wgor_badsock");
    got = 9; f = 9; U(WSASetLastError)(0);
    ok = U(WSAGetOverlappedResult)(INVALID_SOCKET, (LPWSAOVERLAPPED)&ov, &got, FALSE, &f);
    T("ret=%d got=%lu f=%lx e=%d", ok, got, f, ok ? 0 : U(WSAGetLastError)());
    EO_DONE();
    eo_close(c); eo_close(s);
}

/* --- thread exit ------------------------------------------------------------------------- */
static SOCKET eo_t_sock; static OVERLAPPED eo_t_ov; static char eo_t_buf[8]; static int eo_t_err;
static DWORD WINAPI eo_t_issue(void *a)
{
    WSABUF wb; DWORD n = 0, fl = 0; int r;
    (void)a;
    wb.buf = eo_t_buf; wb.len = sizeof eo_t_buf;
    r = U(WSARecv)(eo_t_sock, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&eo_t_ov, NULL);
    eo_t_err = r ? U(WSAGetLastError)() : 0;
    return 0;
}
TEST(receive_pending_when_issuing_thread_exits)
{
    EO("threadexit/event"); SOCKET c, s; HANDLE th, ev;
    XOM_UP();
    if (!eo_pair(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&eo_t_ov, 0, sizeof eo_t_ov); eo_t_ov.hEvent = ev; eo_t_sock = c;
    th = CreateThread(NULL, 0, eo_t_issue, NULL, 0, NULL);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    T("issue=%d", eo_t_err);
    eo_wait_done(&eo_t_ov, 3000);
    T("done=%d st=%lx bytes=%lu", HasOverlappedIoCompleted(&eo_t_ov) != 0, (DWORD)eo_t_ov.Internal, (DWORD)eo_t_ov.InternalHigh);
    EO_DONE();
    CloseHandle(ev); eo_close(c); eo_close(s);
}

/* --- inheritance of the overlapped attribute by accepted sockets ------------------------------ */
static void eo_accept_case(DWORD listen_flags, DWORD client_flags, int predata)
{
    SOCKET l, c, a; struct sockaddr_in la; int len = sizeof la; OVERLAPPED ov; HANDLE ev, p; WSABUF wb; char b[8]; DWORD n = 0, fl = 0; int r;
    DWORD by; ULONG_PTR key; LPOVERLAPPED po = NULL; BOOL k;
    l = eo_tcp(listen_flags); c = eo_tcp(client_flags);
    if (l == INVALID_SOCKET || c == INVALID_SOCKET || !xom_bind_lo(l, &la) || U(listen)(l, 2) || U(connect)(c, (struct sockaddr *)&la, sizeof la)) {
        T("setup=fail"); eo_close(l); eo_close(c); return;
    }
    xom_readable(l, 3000);
    a = U(accept)(l, (struct sockaddr *)&la, &len);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    SetLastError(0); k = (CreateIoCompletionPort((HANDLE)a, p, XOM_KEY, 0) != NULL);
    T("assoc=%d e=%lu", k, k ? 0 : GetLastError());
    memset(&ov, 0, sizeof ov); ov.hEvent = ev; wb.buf = b; wb.len = sizeof b;
    /* data is queued first when the accepted socket might be synchronous, so the call cannot block */
    if (predata) { U(send)(c, "hi", 2, 0); xom_readable(a, 3000); }
    r = U(WSARecv)(a, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, r ? U(WSAGetLastError)() : 0);
    if (predata) T("n=%lu ev=%d", n, WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
    if (!predata && r && U(WSAGetLastError)() == WSA_IO_PENDING) {
        U(send)(c, "hi", 2, 0);
        T("sig=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
        T("bytes=%lu", (DWORD)ov.InternalHigh);
        T("pkt=%d", GetQueuedCompletionStatus(p, &by, &key, &po, 500) && po == &ov);
    }
    CloseHandle(ev); CloseHandle(p); eo_close(a); eo_close(c); eo_close(l);
}
TEST(accepted_socket_inherits_overlapped_attribute)
{
    EO("accept/ovl_listener"); XOM_UP();
    eo_accept_case(WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED, 0);
    EO_NEXT("accept/plain_listener");
    eo_accept_case(0, WSA_FLAG_OVERLAPPED, 1);
    EO_DONE();
}

/* --- datagram truncation and empty datagrams -------------------------------------------------- */
TEST(overlapped_datagram_receive_truncation)
{
    EO("dgram/wsarecv_trunc"); SOCKET a, b; struct sockaddr_in sa, pa; OVERLAPPED ov; HANDLE ev, p; WSABUF wb; char buf[4]; DWORD n = 0, fl = 0; int r;
    DWORD by; ULONG_PTR key; LPOVERLAPPED po = NULL; BOOL k;
    XOM_UP();
    a = xom_sock(SOCK_DGRAM, WSA_FLAG_OVERLAPPED); b = xom_sock(SOCK_DGRAM, WSA_FLAG_OVERLAPPED);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET || !xom_bind_lo(a, &sa) || !xom_bind_lo(b, &pa)) { t_skip("no sockets"); eo_close(a); eo_close(b); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1); CreateIoCompletionPort((HANDLE)a, p, XOM_KEY, 0);
    memset(&ov, 0, sizeof ov); ov.hEvent = ev; wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(a, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL); T("r=%d e=%d", r, U(WSAGetLastError)());
    U(sendto)(b, "0123456789", 10, 0, (struct sockaddr *)&sa, sizeof sa);
    T("sig=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh);
    { DWORD got = 9, f = 9; k = U(WSAGetOverlappedResult)(a, (LPWSAOVERLAPPED)&ov, &got, FALSE, &f); T("wgor=%d,%lu,%lx e=%d", k, got, f, k ? 0 : U(WSAGetLastError)()); }
    SetLastError(0); k = GetQueuedCompletionStatus(p, &by, &key, &po, 1000);
    T("pkt=%d e=%lu b=%lu ov=%d", k, k ? 0 : GetLastError(), by, po == &ov);
    EO_NEXT("dgram/recvfrom_trunc_ready");
    {   struct sockaddr_in from; int fromlen = sizeof from; DWORD f2 = 0; DWORD n2 = 0;
        U(sendto)(b, "0123456789", 10, 0, (struct sockaddr *)&sa, sizeof sa);
        xom_readable(a, 3000);
        memset(&ov, 0, sizeof ov); ov.hEvent = ev; ResetEvent(ev);
        r = U(WSARecvFrom)(a, &wb, 1, &n2, &f2, (struct sockaddr *)&from, &fromlen, (LPWSAOVERLAPPED)&ov, NULL);
        T("r=%d e=%d n=%lu", r, r ? U(WSAGetLastError)() : 0, n2);
        if (r) { eo_wait_done(&ov, 2000); T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh); }
        T("fromlen=%d", fromlen);
        GetQueuedCompletionStatus(p, &by, &key, &po, 200);
    }
    EO_NEXT("dgram/empty_datagram");
    {   DWORD f2 = 0; DWORD n2 = 0;
        U(sendto)(b, "", 0, 0, (struct sockaddr *)&sa, sizeof sa);
        xom_readable(a, 3000);
        memset(&ov, 0, sizeof ov); ov.hEvent = ev; ResetEvent(ev);
        r = U(WSARecv)(a, &wb, 1, &n2, &f2, (LPWSAOVERLAPPED)&ov, NULL);
        T("r=%d e=%d n=%lu", r, r ? U(WSAGetLastError)() : 0, n2);
        if (r) { eo_wait_done(&ov, 2000); T("st=%lx bytes=%lu", (DWORD)ov.Internal, (DWORD)ov.InternalHigh); }
        GetQueuedCompletionStatus(p, &by, &key, &po, 200);
    }
    EO_NEXT("dgram/skipmodes_udp");
    { BOOL ok; SetLastError(0); ok = SetFileCompletionNotificationModes((HANDLE)a, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);
      T("ret=%d e=%lu", ok, ok ? 0 : GetLastError()); }
    EO_DONE();
    CloseHandle(ev); CloseHandle(p); eo_close(a); eo_close(b);
}
