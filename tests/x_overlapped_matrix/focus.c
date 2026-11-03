/* Focused overlapped-I/O behaviours that do not fit the grid in matrix.c: association with a completion
 * port, FILE_SKIP_* mode setting, event reset on issue, optional byte-count pointers, ordering of packets,
 * batch dequeue, mixed pending requests at close, zero-length transfers and invalid handles. Each test renders
 * observations through the same token mechanism as the grid and compares them with expect.inc. */
#include "xom.h"

#define FO(key_) char fo_obs[768]; const char *fo_key = key_; xom_out = fo_obs; xom_cap = sizeof fo_obs; fo_obs[0] = 0
#define FO_DONE() xom_compare(fo_key, fo_obs)
#define FO_NEXT(key_) do { xom_compare(fo_key, fo_obs); fo_key = key_; fo_obs[0] = 0; } while (0)

/* Evaluate the call first, then read the error slot (argument evaluation order is unspecified). */
#define TRE(fmt_, call) do { int r_ = (int)(call); T(fmt_, r_, U(WSAGetLastError)()); } while (0)
static SOCKET fo_tcp(DWORD fl) { return xom_sock(SOCK_STREAM, fl); }
static HANDLE fo_port(void) { return CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1); }
static void fo_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static int fo_connected(SOCKET *c, SOCKET *s, DWORD fl)
{
    memset(&g, 0, sizeof g);
    g.s = g.p = g.l = g.a = INVALID_SOCKET;
    if (!xom_tcp_pair(fl)) { xom_free(); return 0; }
    *c = g.s; *s = g.p; g.s = g.p = INVALID_SOCKET;
    xom_free();
    return 1;
}
static void fo_wait_done(OVERLAPPED *o, DWORD ms)
{
    DWORD t0 = GetTickCount();
    while (!HasOverlappedIoCompleted(o) && GetTickCount() - t0 < ms) SleepEx(2, TRUE);
}

/* --- association --------------------------------------------------------- */
TEST(assoc_plain_socket_refused)
{
    FO("assoc/plain"); HANDLE p, r; SOCKET s;
    XOM_UP();
    s = fo_tcp(0); p = fo_port();
    SetLastError(0); r = CreateIoCompletionPort((HANDLE)s, p, XOM_KEY, 0);
    if (r) T("ret=handle"); else T("ret=null e=%lu", GetLastError());
    FO_DONE();
    CloseHandle(p); fo_close(s);
}
TEST(assoc_repeat_rules)
{
    FO("assoc/first"); HANDLE p, p2, r; SOCKET s;
    XOM_UP();
    s = fo_tcp(WSA_FLAG_OVERLAPPED); p = fo_port(); p2 = fo_port();
    SetLastError(0); r = CreateIoCompletionPort((HANDLE)s, p, XOM_KEY, 0);
    T("ret=%s", r == p ? "port" : "other");
    FO_NEXT("assoc/same_port_again");
    SetLastError(0); r = CreateIoCompletionPort((HANDLE)s, p, XOM_KEY, 0);
    if (r) T("ret=%s", r == p ? "port" : "other"); else T("ret=null e=%lu", GetLastError());
    FO_NEXT("assoc/other_port");
    SetLastError(0); r = CreateIoCompletionPort((HANDLE)s, p2, XOM_KEY, 0);
    if (r) T("ret=%s", r == p2 ? "port" : "other"); else T("ret=null e=%lu", GetLastError());
    FO_DONE();
    CloseHandle(p); CloseHandle(p2); fo_close(s);
}
TEST(skip_modes_setting_rules)
{
    static const UCHAR flags[] = { 0, 1, 2, 3, 4, 8, 0x80 };
    unsigned i, k;
    XOM_UP();
    for (k = 0; k < 3; k++) {
        static const char *const nm[3] = { "assoc", "unassoc", "plain" };
        for (i = 0; i < sizeof flags; i++) {
            char key[64]; FO("x"); HANDLE p = NULL; SOCKET s = fo_tcp(k == 2 ? 0 : WSA_FLAG_OVERLAPPED); BOOL ok;
            if (k == 0) { p = fo_port(); CreateIoCompletionPort((HANDLE)s, p, XOM_KEY, 0); }
            snprintf(key, sizeof key, "skipmodes/%s/%02x", nm[k], flags[i]);
            SetLastError(0); ok = SetFileCompletionNotificationModes((HANDLE)s, flags[i]);
            if (ok) T("ret=ok"); else T("ret=fail e=%lu", GetLastError());
            fo_key = key; FO_DONE();
            if (p) CloseHandle(p);
            fo_close(s);
        }
    }
}

/* --- event handling --------------------------------------------------------- */
TEST(event_is_reset_when_request_starts_pending)
{
    FO("evreset/recv_pending"); SOCKET c, s; WSABUF wb; char b[16]; DWORD n = 0, fl = 0; OVERLAPPED ov; int r;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    wb.buf = b; wb.len = sizeof b;
    r = U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)());
    T("ev=%d", WaitForSingleObject(ov.hEvent, 0) == WAIT_OBJECT_0);
    CancelIoEx((HANDLE)c, &ov); fo_wait_done(&ov, 2000);
    FO_DONE();
    CloseHandle(ov.hEvent); fo_close(c); fo_close(s);
}
TEST(event_lowbit_without_port)
{
    FO("lowbit/noport_pending"); SOCKET c, s; WSABUF wb; char b[16]; DWORD n = 0, fl = 0; OVERLAPPED ov; int r; HANDLE ev;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov); ov.hEvent = (HANDLE)((ULONG_PTR)ev | 1);
    wb.buf = b; wb.len = sizeof b;
    r = U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)());
    U(send)(s, "hello", 5, 0);
    T("signalled=%d", WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    T("bytes=%lu", (DWORD)ov.InternalHigh);
    FO_DONE();
    CloseHandle(ev); fo_close(c); fo_close(s);
}
TEST(wait_for_completion_with_fwait_true)
{
    FO("gorwait/event"); SOCKET c, s; WSABUF wb; char b[16]; DWORD n = 0, fl = 0, got = 0, f2 = 0; OVERLAPPED ov; int r; BOOL ok;
    HANDLE ev;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov); ov.hEvent = ev; wb.buf = b; wb.len = sizeof b;
    r = U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)());
    U(send)(s, "hello", 5, 0);
    ok = U(WSAGetOverlappedResult)(c, (LPWSAOVERLAPPED)&ov, &got, TRUE, &f2);
    T("wgor=%d,%lu,%lx", ok, got, f2);
    got = 99; ok = GetOverlappedResult((HANDLE)c, &ov, &got, TRUE);
    T("gor=%d,%lu", ok, got);
    FO_NEXT("gorwait/noevent");
    memset(&ov, 0, sizeof ov); fl = 0; n = 0;
    r = U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)());
    U(send)(s, "world", 5, 0);
    got = 99; ok = GetOverlappedResult((HANDLE)c, &ov, &got, TRUE);
    T("gor=%d,%lu", ok, got);
    FO_DONE();
    CloseHandle(ev); fo_close(c); fo_close(s);
}
TEST(wait_false_on_pending_reports_incomplete)
{
    FO("gorpending/event"); SOCKET c, s; WSABUF wb; char b[16]; DWORD n = 0, fl = 0, got = 7, f2 = 7; OVERLAPPED ov; BOOL ok;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); wb.buf = b; wb.len = sizeof b;
    U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    SetLastError(0); ok = GetOverlappedResult((HANDLE)c, &ov, &got, FALSE);
    T("gor=%d e=%lu bytes=%lu", ok, GetLastError(), got);
    U(WSASetLastError)(0); ok = U(WSAGetOverlappedResult)(c, (LPWSAOVERLAPPED)&ov, &got, FALSE, &f2);
    T("wgor=%d e=%d", ok, U(WSAGetLastError)());
    T("completed=%d", HasOverlappedIoCompleted(&ov) != 0);
    CancelIoEx((HANDLE)c, &ov); fo_wait_done(&ov, 2000);
    T("completed_after_cancel=%d", HasOverlappedIoCompleted(&ov) != 0);
    FO_DONE();
    CloseHandle(ov.hEvent); fo_close(c); fo_close(s);
}

/* --- optional byte-count pointer ------------------------------------------- */
TEST(null_byte_count_is_allowed_with_overlapped)
{
    FO("nullcount/wsasend"); SOCKET c, s; WSABUF wb; char b[16] = "abcdefgh"; OVERLAPPED ov; int r; DWORD fl = 0; BOOL okb;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    wb.buf = b; wb.len = 8;
    r = U(WSASend)(c, &wb, 1, NULL, 0, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)()); fo_wait_done(&ov, 2000); T("bytes=%lu", (DWORD)ov.InternalHigh);
    FO_NEXT("nullcount/wsarecv");
    memset(&ov, 0, sizeof ov); ov.hEvent = ov.hEvent; wb.len = 16; wb.buf = b; memset(b, 0, 16);
    xom_readable(s, 2000); { char t[16]; U(recv)(s, t, 16, 0); }
    U(send)(s, "12345", 5, 0); xom_readable(c, 2000);
    r = U(WSARecv)(c, &wb, 1, NULL, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)()); fo_wait_done(&ov, 2000); T("bytes=%lu", (DWORD)ov.InternalHigh);
    FO_NEXT("nullcount/writefile");
    memset(&ov, 0, sizeof ov); ov.hEvent = ov.hEvent;
    SetLastError(0); okb = WriteFile((HANDLE)c, b, 8, NULL, &ov);
    T("ret=%d e=%lu", okb, okb ? 0 : GetLastError()); fo_wait_done(&ov, 2000); T("bytes=%lu", (DWORD)ov.InternalHigh);
    FO_NEXT("nullcount/readfile");
    xom_readable(s, 2000); { char t[64]; U(recv)(s, t, 64, 0); }
    U(send)(s, "abc", 3, 0); xom_readable(c, 2000);
    memset(&ov, 0, sizeof ov); ov.hEvent = ov.hEvent;
    SetLastError(0); okb = ReadFile((HANDLE)c, b, 16, NULL, &ov);
    T("ret=%d e=%lu", okb, okb ? 0 : GetLastError()); fo_wait_done(&ov, 2000); T("bytes=%lu", (DWORD)ov.InternalHigh);
    FO_DONE();
    CloseHandle(ov.hEvent); fo_close(c); fo_close(s);
}

/* --- plain file I/O calls on a socket handle ---------------------------------- */
TEST(synchronous_readfile_writefile_on_overlapped_socket)
{
    FO("syncfile/write"); SOCKET c, s; DWORD n = 0; BOOL ok; char b[32];
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    ok = WriteFile((HANDLE)c, "0123456789", 10, &n, NULL);
    T("ret=%d n=%lu e=%lu", ok, n, ok ? 0 : GetLastError());
    FO_NEXT("syncfile/read");
    xom_readable(s, 3000);
    n = 0; ok = ReadFile((HANDLE)s, b, sizeof b, &n, NULL);
    T("ret=%d n=%lu e=%lu", ok, n, ok ? 0 : GetLastError());
    FO_NEXT("syncfile/read_after_shutdown");
    U(shutdown)(c, SD_SEND);
    xom_readable(s, 3000);
    n = 77; SetLastError(0); ok = ReadFile((HANDLE)s, b, sizeof b, &n, NULL);
    T("ret=%d n=%lu e=%lu", ok, n, ok ? 0 : GetLastError());
    FO_DONE();
    fo_close(c); fo_close(s);
}

/* --- ordering and batching ---------------------------------------------------- */
TEST(packets_follow_completion_order_of_ordered_receives)
{
    FO("order/three_recvs"); SOCKET c, s; WSABUF wb[3]; char b[3][8]; OVERLAPPED ov[3]; HANDLE p; DWORD n, fl; int i;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    p = fo_port(); CreateIoCompletionPort((HANDLE)c, p, XOM_KEY, 0);
    for (i = 0; i < 3; i++) {
        memset(&ov[i], 0, sizeof ov[i]); wb[i].buf = b[i]; wb[i].len = 2; n = 0; fl = 0;
        { char f_[16]; snprintf(f_, sizeof f_, "r%d=%%d,%%d", i); TRE(f_, U(WSARecv)(c, &wb[i], 1, &n, &fl, (LPWSAOVERLAPPED)&ov[i], NULL)); }
    }
    U(send)(s, "aabbcc", 6, 0);
    for (i = 0; i < 3; i++) {
        DWORD by = 0; ULONG_PTR key = 0; LPOVERLAPPED po = NULL;
        BOOL ok = GetQueuedCompletionStatus(p, &by, &key, &po, 3000);
        T("p%d=%d,%lu,%d", i, ok, by, po == &ov[i]);
    }
    T("data=%c%c%c%c%c%c", b[0][0], b[0][1], b[1][0], b[1][1], b[2][0], b[2][1]);
    FO_DONE();
    CloseHandle(p); fo_close(c); fo_close(s);
}
TEST(batch_dequeue_reports_status_and_bytes)
{
    FO("batch/entries"); SOCKET c, s; WSABUF wb[3]; char b[3][8]; OVERLAPPED ov[3]; HANDLE p; DWORD n, fl; int i;
    OVERLAPPED_ENTRY e[8]; ULONG got = 0; BOOL ok;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    p = fo_port(); CreateIoCompletionPort((HANDLE)c, p, XOM_KEY, 0);
    for (i = 0; i < 3; i++) { memset(&ov[i], 0, sizeof ov[i]); wb[i].buf = b[i]; wb[i].len = 4; n = 0; fl = 0; U(WSARecv)(c, &wb[i], 1, &n, &fl, (LPWSAOVERLAPPED)&ov[i], NULL); }
    U(send)(s, "xxxxyyyy", 8, 0);
    Sleep(200);
    memset(e, 0, sizeof e);
    ok = GetQueuedCompletionStatusEx(p, e, 8, &got, 3000, FALSE);
    T("ret=%d count=%lu", ok, got);
    for (i = 0; i < (int)got && i < 3; i++)
        T("e%d=key%d,ov%d,st%lx,b%lu", i, e[i].lpCompletionKey == XOM_KEY, e[i].lpOverlapped == &ov[i], (DWORD)e[i].Internal, e[i].dwNumberOfBytesTransferred);
    /* third receive is still pending: cancel and collect its entry */
    CancelIoEx((HANDLE)c, &ov[2]);
    memset(e, 0, sizeof e); got = 0;
    ok = GetQueuedCompletionStatusEx(p, e, 8, &got, 3000, FALSE);
    T("cancel_ret=%d count=%lu", ok, got);
    if (got) T("ce=ov2:%d,st%lx,b%lu", e[0].lpOverlapped == &ov[2], (DWORD)e[0].Internal, e[0].dwNumberOfBytesTransferred);
    FO_DONE();
    CloseHandle(p); fo_close(c); fo_close(s);
}
TEST(close_with_mixed_pending_requests)
{
    FO("mixed/close"); SOCKET c, s; WSABUF wb; char b[8]; OVERLAPPED ov[2]; HANDLE p; DWORD n = 0, fl = 0, got; int i; ULONG_PTR key;
    LPOVERLAPPED po;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    p = fo_port(); CreateIoCompletionPort((HANDLE)c, p, XOM_KEY, 0);
    memset(ov, 0, sizeof ov); wb.buf = b; wb.len = 8;
    TRE("recv=%d,%d", U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov[0], NULL));
    TRE("alc=%d,%d", U(WSAIoctl)(c, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, (LPWSAOVERLAPPED)&ov[1], NULL));
    T("close=%d", U(closesocket)(c));
    for (i = 0; i < 2; i++) {
        BOOL ok; DWORD e;
        SetLastError(0); ok = GetQueuedCompletionStatus(p, &got, &key, &po, 3000); e = GetLastError();
        T("pkt%d=%d,%lu,ov%d", i, ok, po ? e : 0, po == &ov[0] ? 0 : po == &ov[1] ? 1 : 9);
    }
    T("st0=%lx st1=%lx", (DWORD)ov[0].Internal, (DWORD)ov[1].Internal);
    FO_DONE();
    CloseHandle(p); fo_close(s);
}

/* --- ioctl without overlapped ---------------------------------------------------- */
TEST(address_list_change_nonblocking_returns_wouldblock)
{
    FO("alc/nonblocking"); SOCKET s; u_long nb = 1; DWORD n = 77; int r;
    XOM_UP();
    s = fo_tcp(WSA_FLAG_OVERLAPPED);
    U(ioctlsocket)(s, FIONBIO, &nb);
    r = U(WSAIoctl)(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, NULL, NULL);
    T("r=%d e=%d n=%lu", r, U(WSAGetLastError)(), n);
    FO_DONE();
    fo_close(s);
}

/* --- invalid handles ----------------------------------------------------------- */
TEST(invalid_socket_with_overlapped_fails_without_completion)
{
    FO("invalid/wsasend"); WSABUF wb; char b[4] = "abc"; OVERLAPPED ov; HANDLE p; DWORD n = 0; DWORD got; ULONG_PTR key; LPOVERLAPPED po = NULL;
    XOM_UP();
    p = fo_port();
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); wb.buf = b; wb.len = 3;
    TRE("r=%d e=%d", U(WSASend)(INVALID_SOCKET, &wb, 1, &n, 0, (LPWSAOVERLAPPED)&ov, NULL));
    T("ev=%d", WaitForSingleObject(ov.hEvent, 0) == WAIT_OBJECT_0);
    T("pkt=%d", GetQueuedCompletionStatus(p, &got, &key, &po, 50) || po != NULL);
    FO_NEXT("invalid/readfile");
    { BOOL k_; SetLastError(0); k_ = ReadFile(INVALID_HANDLE_VALUE, b, 3, &n, &ov); T("ret=%d e=%lu", k_, GetLastError()); }
    FO_NEXT("invalid/wsarecv");
    { DWORD fl = 0; TRE("r=%d e=%d", U(WSARecv)(INVALID_SOCKET, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL)); }
    FO_NEXT("invalid/acceptex");
    { LPFN_ACCEPTEX fx; SOCKET t = fo_tcp(WSA_FLAG_OVERLAPPED); char buf[64];
      fx = (LPFN_ACCEPTEX)xom_ext(t, (GUID)WSAID_ACCEPTEX);
      SetLastError(0); U(WSASetLastError)(0);
      TRE("ret=%d e=%d", fx(INVALID_SOCKET, INVALID_SOCKET, buf, 0, 32, 32, &n, &ov));
      fo_close(t); }
    FO_DONE();
    CloseHandle(ov.hEvent); CloseHandle(p);
}

/* --- zero-length transfers ------------------------------------------------------- */
TEST(zero_byte_receive_completes_when_data_arrives_without_consuming)
{
    FO("zero/recv"); SOCKET c, s; WSABUF wb; char b[8]; OVERLAPPED ov; DWORD n = 0, fl = 0; int r; char t[8]; int got;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    wb.buf = b; wb.len = 0;
    r = U(WSARecv)(c, &wb, 1, &n, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d", r, U(WSAGetLastError)());
    U(send)(s, "hello", 5, 0);
    T("signalled=%d", WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
    T("bytes=%lu status=%lx", (DWORD)ov.InternalHigh, (DWORD)ov.Internal);
    got = U(recv)(c, t, sizeof t, 0);
    T("data_left=%d", got);
    FO_DONE();
    CloseHandle(ov.hEvent); fo_close(c); fo_close(s);
}
TEST(zero_byte_send_completes_immediately)
{
    FO("zero/send"); SOCKET c, s; WSABUF wb; char b[8]; OVERLAPPED ov; DWORD n = 77; int r; HANDLE p;
    ULONG_PTR key; LPOVERLAPPED po = NULL; DWORD by = 77;
    XOM_UP();
    if (!fo_connected(&c, &s, WSA_FLAG_OVERLAPPED)) { t_skip("no pair"); return; }
    p = fo_port(); CreateIoCompletionPort((HANDLE)c, p, XOM_KEY, 0);
    memset(&ov, 0, sizeof ov); wb.buf = b; wb.len = 0;
    r = U(WSASend)(c, &wb, 1, &n, 0, (LPWSAOVERLAPPED)&ov, NULL);
    T("r=%d e=%d n=%lu", r, r ? U(WSAGetLastError)() : 0, n);
    if (r) fo_wait_done(&ov, 2000);
    { BOOL k_ = GetQueuedCompletionStatus(p, &by, &key, &po, 200); T("pkt=%d b=%lu", k_ != 0, by); }
    T("peer_readable=%d", xom_readable(s, 100));
    FO_DONE();
    CloseHandle(p); fo_close(c); fo_close(s);
}
