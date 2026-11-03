/* WSARecv completion semantics on a connected loopback TCP pair: partial and scatter reads, the
 * alertable wait of non-overlapped calls, pending overlapped operations and their error on reset,
 * completion routines, and the restriction on routines for sockets bound to a completion port.
 */
#include "l8.h"

/* Wait (bounded) until the socket has data readable without blocking. */
static void wait_readable(SOCKET s)
{
    POLL_MASK_IS(s, POLLRDNORM, POLLRDNORM);
}

TEST(l8_wsarecv_partial_reads_are_synchronous_without_apc)
{
    SOCKET src, dst;
    char buf[20];
    WSABUF wb = { 1, buf };
    DWORD got = 0xdeadbeef, fl = 0;
    volatile unsigned apcs = 0;
    NEED_WS();
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);

    L8_EQ(w_send(src, "ab", 2, 0), 2);
    /* A non-overlapped receive only waits alertably when it actually blocks; make sure it will not. */
    wait_readable(dst);
    CHECK(QueueUserAPC(l8_apc_count, GetCurrentThread(), (ULONG_PTR)&apcs));

    SetLastError(0xdeadbeef);
    L8_EQ(w_WSARecv(dst, &wb, 1, &got, &fl, NULL, NULL), 0);
    L8_EQ(got, 1);
    L8_EQ(GetLastError(), 0);
    L8_EQ(apcs, 0);          /* completed immediately, so the queued APC has not run */
    SleepEx(0, TRUE);
    L8_EQ(apcs, 1);

    got = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    L8_EQ(w_WSARecv(dst, &wb, 1, &got, &fl, NULL, NULL), 0);
    L8_EQ(got, 1);
    L8_EQ(GetLastError(), 0);
    w_closesocket(src);
    w_closesocket(dst);
}

TEST(l8_wsarecv_full_message_single_buffer)
{
    SOCKET src, dst;
    char buf[20];
    WSABUF wb = { 4, buf };
    DWORD got = 0xdeadbeef, fl = 0;
    NEED_WS();
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);
    SetLastError(0xdeadbeef);
    L8_EQ(w_send(src, "test", 4, 0), 4);
    L8_EQ(GetLastError(), 0);
    SetLastError(0xdeadbeef);
    L8_EQ(w_WSARecv(dst, &wb, 1, &got, &fl, NULL, NULL), 0);
    L8_EQ(got, 4);
    L8_EQ(GetLastError(), 0);
    CHECK(!memcmp(buf, "test", 4));
    w_closesocket(src);
    w_closesocket(dst);
}

TEST(l8_wsarecv_scatter_two_buffers)
{
    SOCKET src, dst;
    char buf[20];
    WSABUF wb[2] = { { 4, buf }, { 5, buf + 10 } };
    DWORD got = 0xdeadbeef, fl = 0;
    NEED_WS();
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);
    L8_EQ(w_send(src, "deadbeefs", 9, 0), 9);
    SetLastError(0xdeadbeef);
    L8_EQ(w_WSARecv(dst, wb, 2, &got, &fl, NULL, NULL), 0);
    L8_EQ(got, 9);
    L8_EQ(GetLastError(), 0);
    CHECK(!memcmp(buf, "dead", 4));
    CHECK(!memcmp(buf + 10, "beefs", 5));
    w_closesocket(src);
    w_closesocket(dst);
}

/* A pending overlapped receive fails with a "network name deleted" error when the peer resets. */
static void pending_then_reset(int pass_count_pointer)
{
    SOCKET src, dst;
    char buf[20];
    WSABUF wb = { sizeof buf, buf };
    DWORD got = 0xdeadbeef, fl = 0;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);

    SetLastError(0xdeadbeef);
    L8_EQ(w_WSARecv(dst, &wb, 1, pass_count_pointer ? &got : NULL, &fl, &ov, NULL), SOCKET_ERROR);
    EXPECT_ERR(ERROR_IO_PENDING);

    l8_close_rst(src);
    L8_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);

    got = 0xdeadbeef;
    SetLastError(0);
    L8_EQ(GetOverlappedResult((HANDLE)dst, &ov, &got, FALSE), FALSE);
    EXPECT_ERR(ERROR_NETNAME_DELETED);
    L8_EQ(got, 0);
    w_closesocket(dst);
    CloseHandle(ov.hEvent);
}

TEST(l8_wsarecv_overlapped_pending_then_reset)
{
    NEED_WS();
    pending_then_reset(0);
}

TEST(l8_wsarecv_overlapped_pending_with_count_pointer)
{
    NEED_WS();
    pending_then_reset(1);
}

/* ---- non-overlapped receive in a worker thread; an APC queued to it runs during the wait ---- */

struct apc_send { SOCKET sock; volatile unsigned count; };
struct rx_thread { SOCKET sock; int ret; int werr; DWORD len; };

static void WINAPI apc_send_proc(ULONG_PTR p)
{
    struct apc_send *a = (struct apc_send *)p;
    a->count++;
    w_send(a->sock, "test", 4, 0);
}

static DWORD WINAPI rx_thread_proc(void *arg)
{
    struct rx_thread *t = arg;
    char buf[32];
    WSABUF wb = { sizeof buf, buf };
    DWORD fl = 0;
    SetLastError(0xdeadbeef);
    t->ret = w_WSARecv(t->sock, &wb, 1, &t->len, &fl, NULL, NULL);
    t->werr = GetLastError();
    return 0;
}

TEST(l8_wsarecv_blocking_call_is_alertable)
{
    SOCKET src, dst;
    struct apc_send ap;
    struct rx_thread rt;
    HANDLE th;
    NEED_WS();
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);
    ap.sock = src; ap.count = 0;
    rt.sock = dst; rt.ret = -2; rt.werr = -1; rt.len = 0;
    th = CreateThread(NULL, 0, rx_thread_proc, &rt, 0, NULL);
    Sleep(100);
    CHECK(QueueUserAPC(apc_send_proc, th, (ULONG_PTR)&ap));
    L8_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    CloseHandle(th);
    /* The APC ran inside the blocked receive; the data it sent is what the receive returned. */
    L8_EQ(ap.count, 1);
    L8_EQ(rt.ret, 0);
    L8_EQ(rt.werr, 0);
    L8_EQ(rt.len, 4);
    w_closesocket(src);
    w_closesocket(dst);
}

/* ---- completion routines ---- */

static volatile int g_routine_calls;
static void WINAPI routine(DWORD err, DWORD n, LPWSAOVERLAPPED ov, DWORD fl) { g_routine_calls++; }

TEST(l8_wsarecv_completion_routine_runs_in_alertable_wait)
{
    SOCKET src, dst;
    char buf[20];
    WSABUF wb = { sizeof buf, buf };
    DWORD fl = 0;
    OVERLAPPED ov;
    NEED_WS();
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(0);
    L8_EQ(w_WSARecv(dst, &wb, 1, NULL, &fl, &ov, routine), SOCKET_ERROR);
    EXPECT_ERR(ERROR_IO_PENDING);
    L8_EQ(w_send(src, "test message", 13, 0), 13);

    g_routine_calls = 0;
    L8_EQ(SleepEx(3000, TRUE), WAIT_IO_COMPLETION);
    L8_EQ(g_routine_calls, 1);
    /* With a routine the event is not signalled. */
    L8_EQ(WaitForSingleObject(ov.hEvent, 1), WAIT_TIMEOUT);
    CloseHandle(ov.hEvent);
    w_closesocket(src);
    w_closesocket(dst);
}

TEST(l8_wsarecv_completion_routine_rejected_with_completion_port)
{
    SOCKET src, dst;
    char buf[20];
    WSABUF wb = { sizeof buf, buf };
    DWORD fl = 0;
    OVERLAPPED ov;
    HANDLE port;
    NEED_WS();
    l8_pair(&src, &dst, WSA_FLAG_OVERLAPPED);
    port = CreateIoCompletionPort((HANDLE)dst, NULL, 0, 0);
    CHECK(port != NULL);
    memset(&ov, 0, sizeof ov);
    g_routine_calls = 0;
    SetLastError(0);
    L8_EQ(w_WSARecv(dst, &wb, 1, NULL, &fl, &ov, routine), SOCKET_ERROR);
    EXPECT_ERR(WSAEINVAL);
    L8_EQ(g_routine_calls, 0);
    w_closesocket(dst);
    w_closesocket(src);
    if (port) CloseHandle(port);
}
