/* Measures the lifetime of pending change-notification controls (SIO_ADDRESS_LIST_CHANGE and
 * SIO_ROUTING_INTERFACE_CHANGE): several outstanding requests on one socket, cancellation with CancelIoEx,
 * completion by closing the socket, completion-routine delivery of the abort, and the result a
 * waiting thread sees.  No network change is ever awaited; every request ends by cancellation. */
#include "ib.h"

typedef struct { DWORD code; const char *name; int needs_input; } ib_change_ctl;
static const ib_change_ctl ib_changes[] = {
    {IB_ADDRLIST_CHANGE, "SIO_ADDRESS_LIST_CHANGE", 0},
    {IB_ROUTING_CHANGE, "SIO_ROUTING_INTERFACE_CHANGE", 1},
};

static int ib_start_change(SOCKET s, const ib_change_ctl *c, WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr, DWORD *n)
{
    struct sockaddr_in a;
    ib_loop4(&a, 0);
    memset(ov, 0, sizeof *ov);
    if (!cr) ov->hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ib_seterr(0);
    return U(WSAIoctl)(s, c->code, c->needs_input ? (void *)&a : NULL, c->needs_input ? sizeof a : 0, NULL, 0, n, ov, cr);
}

IBTEST(ib_change_cancelio_completes_with_operation_aborted)
{
    unsigned i;
    for (i = 0; i < 2; ++i) {
        IB_SOCK(s, K_TCP4);
        WSAOVERLAPPED ov;
        DWORD n = IB_UNSET, t = 0, fl = 0;
        int r = ib_start_change(s, &ib_changes[i], &ov, NULL, &n);
        CHECKF(r == SOCKET_ERROR && ib_err() == WSA_IO_PENDING, "%s: r=%d err=%d", ib_changes[i].name, r, ib_err());
        CHECK(WaitForSingleObject(ov.hEvent, 100) == WAIT_TIMEOUT);
        CHECK(CancelIoEx((HANDLE)s, (LPOVERLAPPED)&ov));
        CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
        ib_seterr(0);
        CHECK(!U(WSAGetOverlappedResult)(s, &ov, &t, FALSE, &fl));
        CHECKF(ib_err() == WSA_OPERATION_ABORTED, "%s: err=%d", ib_changes[i].name, ib_err());
        CHECK(t == 0);
        CHECK((NTSTATUS)ov.Internal == (NTSTATUS)0xC0000120);
        CloseHandle(ov.hEvent);
        ib_close(s);
    }
}

IBTEST(ib_change_two_outstanding_requests_both_cancelled_by_close)
{
    unsigned i;
    for (i = 0; i < 2; ++i) {
        IB_SOCK(s, K_TCP4);
        WSAOVERLAPPED a, b;
        DWORD n1 = IB_UNSET, n2 = IB_UNSET;
        int r1 = ib_start_change(s, &ib_changes[i], &a, NULL, &n1);
        int e1 = ib_err();
        int r2 = ib_start_change(s, &ib_changes[i], &b, NULL, &n2);
        int e2 = ib_err();
        CHECKF(r1 == SOCKET_ERROR && e1 == WSA_IO_PENDING && r2 == SOCKET_ERROR && e2 == WSA_IO_PENDING,
               "%s: %d/%d %d/%d", ib_changes[i].name, r1, e1, r2, e2);
        CHECK(WaitForSingleObject(a.hEvent, 100) == WAIT_TIMEOUT);
        CHECK(WaitForSingleObject(b.hEvent, 0) == WAIT_TIMEOUT);
        ib_close(s);
        CHECK(WaitForSingleObject(a.hEvent, 3000) == WAIT_OBJECT_0);
        CHECK(WaitForSingleObject(b.hEvent, 3000) == WAIT_OBJECT_0);
        CHECK((NTSTATUS)a.Internal == (NTSTATUS)0xC0000120 && (NTSTATUS)b.Internal == (NTSTATUS)0xC0000120);
        CloseHandle(a.hEvent); CloseHandle(b.hEvent);
    }
}

IBTEST(ib_change_cancel_one_leaves_other_pending)
{
    IB_SOCK(s, K_TCP4);
    WSAOVERLAPPED a, b;
    DWORD n1 = IB_UNSET, n2 = IB_UNSET;
    ib_start_change(s, &ib_changes[0], &a, NULL, &n1);
    ib_start_change(s, &ib_changes[0], &b, NULL, &n2);
    CHECK(CancelIoEx((HANDLE)s, (LPOVERLAPPED)&a));
    CHECK(WaitForSingleObject(a.hEvent, 3000) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(b.hEvent, 150) == WAIT_TIMEOUT);
    ib_close(s);
    CHECK(WaitForSingleObject(b.hEvent, 3000) == WAIT_OBJECT_0);
    CloseHandle(a.hEvent); CloseHandle(b.hEvent);
}

static volatile LONG ib_cr_count;
static volatile DWORD ib_cr_err, ib_cr_bytes;
static void CALLBACK ib_cr(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD fl)
{
    InterlockedIncrement(&ib_cr_count);
    ib_cr_err = err; ib_cr_bytes = bytes;
}

IBTEST(ib_change_completion_routine_receives_abort_on_close)
{
    unsigned i;
    for (i = 0; i < 2; ++i) {
        IB_SOCK(s, K_TCP4);
        WSAOVERLAPPED ov;
        DWORD n = IB_UNSET;
        int r;
        ib_cr_count = 0; ib_cr_err = 0; ib_cr_bytes = 99;
        r = ib_start_change(s, &ib_changes[i], &ov, ib_cr, &n);
        CHECKF(r == SOCKET_ERROR && ib_err() == WSA_IO_PENDING, "%s: r=%d err=%d", ib_changes[i].name, r, ib_err());
        SleepEx(100, TRUE);
        CHECK(ib_cr_count == 0);
        ib_close(s);
        SleepEx(1000, TRUE);
        CHECKF(ib_cr_count == 1 && ib_cr_err == WSA_OPERATION_ABORTED && ib_cr_bytes == 0, "%s: count=%ld err=%lu bytes=%lu",
               ib_changes[i].name, ib_cr_count, ib_cr_err, ib_cr_bytes);
    }
}

typedef struct { SOCKET s; const ib_change_ctl *c; DWORD err; BOOL ok; DWORD bytes; } ib_waiter;
static DWORD WINAPI ib_waiter_thread(LPVOID p)
{
    ib_waiter *w = p;
    WSAOVERLAPPED ov;
    DWORD n = IB_UNSET, fl = 0;
    int r = ib_start_change(w->s, w->c, &ov, NULL, &n);
    if (r == SOCKET_ERROR && ib_err() == WSA_IO_PENDING) {
        w->ok = U(WSAGetOverlappedResult)(w->s, &ov, &w->bytes, TRUE, &fl);     /* waits for the cancellation */
        w->err = w->ok ? 0 : (DWORD)ib_err();
    } else w->err = 0xffffffffu;
    CloseHandle(ov.hEvent);
    return 0;
}

IBTEST(ib_change_waiting_thread_is_released_by_close)
{
    unsigned i;
    for (i = 0; i < 2; ++i) {
        IB_SOCK(s, K_TCP4);
        ib_waiter w;
        HANDLE h;
        w.s = s; w.c = &ib_changes[i]; w.err = 0; w.ok = TRUE; w.bytes = 99;
        h = CreateThread(NULL, 0, ib_waiter_thread, &w, 0, NULL);
        Sleep(200);
        CHECK(WaitForSingleObject(h, 0) == WAIT_TIMEOUT);
        ib_close(s);
        CHECK(WaitForSingleObject(h, 5000) == WAIT_OBJECT_0);
        CHECKF(!w.ok && w.err == WSA_OPERATION_ABORTED && w.bytes == 0, "%s: ok=%d err=%lu bytes=%lu", ib_changes[i].name, w.ok, w.err, w.bytes);
        CloseHandle(h);
    }
}

IBTEST(ib_change_cancelled_request_does_not_block_other_controls)
{
    IB_SOCK(s, K_TCP4);
    WSAOVERLAPPED ov;
    DWORD n = IB_UNSET;
    DWORD out = IB_UNSET;
    ib_res x;
    ib_start_change(s, &ib_changes[0], &ov, NULL, &n);
    x = ib_io(s, IB_FIONREAD, NULL, 0, &out, sizeof out, 1);
    CHECKF(IB_OK(x) && out == 0, "FIONREAD while change pending: r=%d err=%d", x.r, x.err);
    x = ib_io(s, IB_BASE_HANDLE, NULL, 0, &out, 4, 1);
    CHECKF(IB_FAILS(x, WSAEFAULT), "base handle with short output: r=%d err=%d", x.r, x.err);
    ib_close(s);
    WaitForSingleObject(ov.hEvent, 3000);
    CloseHandle(ov.hEvent);
}

IBTEST(ib_change_on_datagram_and_listening_sockets_pends)
{
    static const int kinds[] = {K_UDP4, K_LISTEN4, K_TCP6, K_UDP6};
    unsigned i;
    for (i = 0; i < 4; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        WSAOVERLAPPED ov;
        DWORD n = IB_UNSET;
        int r;
        if (s == INVALID_SOCKET) continue;
        r = ib_start_change(s, &ib_changes[0], &ov, NULL, &n);
        CHECKF(r == SOCKET_ERROR && ib_err() == WSA_IO_PENDING, "kind %d: r=%d err=%d", kinds[i], r, ib_err());
        ib_close(s);
        CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
        CloseHandle(ov.hEvent);
    }
}
