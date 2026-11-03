/* AcceptEx request lifetime: listener closed while pending, CancelIoEx / CancelIo, and the accept socket that
 * survives an aborted request.  Observed statuses: STATUS_CANCELLED in the OVERLAPPED, WSA_OPERATION_ABORTED
 * (995) from the result query, zero bytes, and the output DWORD never touched. */
#include "fx.h"

/* Closing the listener completes a pending zero-length request with the cancelled status. */
FX_BOTH(close_listener_aborts_a_pending_request)
{
    SOCKET acc; DWORD got = 77; BOOL ok;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    EXPECT_EQ(c.ov.InternalHigh, 0);
    SetLastError(0);
    ok = GetOverlappedResult((HANDLE)acc, &c.ov, &got, FALSE);
    EXPECT_EQ(ok, FALSE);
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    EXPECT_EQ(got, 0);
    EXPECT_EQ(c.n, FX_POISON);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* A one-byte request that has not yet seen a connection is aborted the same way. */
FX_BOTH(close_listener_aborts_a_one_byte_request_without_connection)
{
    SOCKET acc;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 1), WSA_IO_PENDING);
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* The accept socket of an aborted request is untouched and can be handed to a new listener. */
FX_BOTH(close_accept_socket_is_reusable_after_listener_abort)
{
    SOCKET acc, z; struct fx f2; fx_addr a2; DWORD n2 = 0, got = 9, err = 9; int cr;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    WaitForSingleObject(c.ov.hEvent, 3000);
    f2 = c.f;
    f2.lst = fx_listener_on(af, &a2, 4);
    CHECK(f2.lst != INVALID_SOCKET);
    c.ov.Internal = 0; ResetEvent(c.ov.hEvent);
    FX_EQ(fx_post(&f2, acc, c.buf, 0, f2.slot, f2.slot, &n2, &c.ov), WSA_IO_PENDING);
    z = fx_stream(af);
    cr = fx_connect(z, &a2.sa, f2.alen);
    EXPECT_EQ(cr, 0);
    CHECK(fx_result(f2.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 0);
    fx_close_all(z, acc, f2.lst);
    fxc_close(&c);
}

/* CancelIoEx naming the request: TRUE, the request completes cancelled, the listener keeps accepting. */
FX_BOTH(close_cancelioex_cancels_one_request_and_the_listener_lives)
{
    SOCKET acc, cl; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    FX_EQ(CancelIoEx((HANDLE)c.f.lst, &c.ov), TRUE);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    CHECK(!fx_result(c.f.lst, &c.ov, &got, 100, &err));
    EXPECT_EQ(err, WSA_OPERATION_ABORTED);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* CancelIo on the listener handle cancels the request issued by this thread. */
FX_BOTH(close_cancelio_cancels_the_request_of_this_thread)
{
    SOCKET acc; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    FX_EQ(CancelIo((HANDLE)c.f.lst), TRUE);
    CHECK(!fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(err, WSA_OPERATION_ABORTED);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* A cancelled one-byte request leaves a later connection and its data alone: nothing is consumed. */
FX_BOTH(close_cancelled_request_consumes_nothing)
{
    SOCKET acc, cl, acc2; DWORD got = 0, err = 0; char b[2] = {0};
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    CancelIoEx((HANDLE)c.f.lst, &c.ov);
    WaitForSingleObject(c.ov.hEvent, 3000);
    cl = fx_client(&c.f);
    fx_send(cl, "k", 1, 0);
    acc2 = fx_accept(c.f.lst, NULL, NULL);
    CHECK(acc2 != INVALID_SOCKET);
    FX_EQ(fx_recv_n(acc2, b, 1, 2000), 1);
    EXPECT_EQ(b[0], 'k');
    fx_close_all(cl, acc, acc2);
    fxc_close(&c);
}

/* CancelIoEx for a request that is already finished (or never existed) fails with ERROR_NOT_FOUND. */
FX_BOTH(close_cancelioex_without_a_matching_request_is_not_found)
{
    SOCKET acc; BOOL ok; DWORD e;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    SetLastError(0);
    FX_EQ(CancelIoEx((HANDLE)c.f.lst, &c.ov), TRUE);
    WaitForSingleObject(c.ov.hEvent, 3000);
    SetLastError(0); ok = CancelIoEx((HANDLE)c.f.lst, &c.ov); e = GetLastError();
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(e, ERROR_NOT_FOUND);
    SetLastError(0); ok = CancelIoEx((HANDLE)c.f.lst, NULL); e = GetLastError();
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(e, ERROR_NOT_FOUND);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* The request belongs to the listener handle: cancelling through the accept socket handle finds nothing and the
 * request stays pending, as does CancelIo (which reports success because the accept socket has no request). */
FX_BOTH(close_cancel_through_the_accept_socket_does_not_reach_the_request)
{
    SOCKET acc, cl; DWORD got = 0, err = 0, e; BOOL ok;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    SetLastError(0); ok = CancelIoEx((HANDLE)acc, &c.ov); e = GetLastError();
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(e, ERROR_NOT_FOUND);
    SetLastError(0); ok = CancelIoEx((HANDLE)acc, NULL); e = GetLastError();
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(e, ERROR_NOT_FOUND);
    FX_EQ(CancelIo((HANDLE)acc), TRUE);
    CHECK(!fx_done_within(&c.ov, 300));
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* CancelIo issued by another thread leaves the request pending; CancelIoEx from any thread still works. */
struct cth { HANDLE h; BOOL r; };
static DWORD WINAPI cancelio_thread(LPVOID p) { struct cth *t = (struct cth *)p; t->r = CancelIo(t->h); return 0; }

FX_BOTH(close_cancelio_from_another_thread_leaves_the_request)
{
    SOCKET acc; struct cth t; HANDLE th;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    t.h = (HANDLE)c.f.lst; t.r = FALSE;
    th = CreateThread(NULL, 0, cancelio_thread, &t, 0, NULL);
    CHECK(th != NULL);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    EXPECT_EQ(t.r, TRUE);
    CHECK(!fx_done_within(&c.ov, 400));
    FX_EQ(CancelIoEx((HANDLE)c.f.lst, &c.ov), TRUE);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* A connection already accepted and waiting for its byte keeps the request alive when the listener is closed; the
 * byte then completes it normally. */
FX_BOTH(close_listener_close_after_connect_leaves_a_waiting_request_alive)
{
    SOCKET acc, cl; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    CHECK(!fx_done_within(&c.ov, 200));
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    CHECK(!fx_done_within(&c.ov, 700));
    FX_EQ(fx_send(cl, "d", 1, 0), 1);
    CHECK(fx_result(acc, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(c.buf[0], 'd');
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Closing the accept socket while the request waits for the byte of an accepted connection completes it with
 * STATUS_CONNECTION_ABORTED and zero bytes. */
FX_BOTH(close_accept_socket_close_aborts_a_waiting_request)
{
    SOCKET acc, cl;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    CHECK(!fx_done_within(&c.ov, 200));
    fx_closesocket(acc);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, 0xC0000241UL);
    EXPECT_EQ(c.ov.InternalHigh, 0);
    fx_closesocket(cl);
    fxc_close(&c);
}

/* Closing the accept socket before any connection: the request is cancelled, not connection-aborted. */
FX_BOTH(close_accept_socket_close_cancels_a_request_without_connection)
{
    SOCKET acc;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    fx_closesocket(acc);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    fxc_close(&c);
}

/* A request left pending by a thread that then exits is cancelled when the thread ends. */
struct pth { struct fxc *c; SOCKET acc; HANDLE posted; };
static DWORD WINAPI post_and_exit(LPVOID p) { struct pth *t = (struct pth *)p; fxc_post(t->c, t->acc, 0); SetEvent(t->posted); return 0; }

FX_BOTH(close_issuing_thread_exit_cancels_the_request)
{
    SOCKET acc; struct pth t; HANDLE th;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    t.c = &c; t.acc = acc; t.posted = fx_event();
    th = CreateThread(NULL, 0, post_and_exit, &t, 0, NULL);
    CHECK(th != NULL);
    WaitForSingleObject(t.posted, 3000);
    WaitForSingleObject(th, 3000);
    CloseHandle(th);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    CloseHandle(t.posted);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* After the accept socket is closed on a waiting request, the already-connected client sees a reset. */
FX_BOTH(close_accept_socket_close_resets_the_connected_client)
{
    SOCKET acc, cl; char ch;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    CHECK(!fx_done_within(&c.ov, 200));
    fx_closesocket(acc);
    WaitForSingleObject(c.ov.hEvent, 3000);
    CHECK(fx_readable(cl, 3000));
    FX_EQ(fx_recv(cl, &ch, 1, 0), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAECONNRESET);
    fx_closesocket(cl);
    fxc_close(&c);
}

/* A connection still in the backlog when the listener closes is reset for the client. */
FX_BOTH(close_listener_close_resets_a_never_accepted_client)
{
    SOCKET cl; char ch;
    FXC_OPEN(c, af);
    cl = fx_client(&c.f);
    Sleep(50);
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    CHECK(fx_readable(cl, 3000));
    FX_EQ(fx_recv(cl, &ch, 1, 0), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAECONNRESET);
    fx_closesocket(cl);
    fxc_close(&c);
}

/* With a port, the issuing thread's exit still cancels the request, and the cancellation arrives as a failure packet. */
FX_BOTH(close_issuing_thread_exit_with_a_port_posts_an_abort_packet)
{
    SOCKET acc; struct pth t; HANDLE th, port; BOOL ok; DWORD bytes = 9, e = 0; ULONG_PTR key = 0; OVERLAPPED *pov = NULL;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 5));
    acc = fx_stream(af);
    t.c = &c; t.acc = acc; t.posted = fx_event();
    th = CreateThread(NULL, 0, post_and_exit, &t, 0, NULL);
    CHECK(th != NULL);
    WaitForSingleObject(t.posted, 3000);
    WaitForSingleObject(th, 3000);
    CloseHandle(th);
    CHECK(fx_dequeue(port, 3000, &ok, &bytes, &key, &pov, &e));
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(e, ERROR_OPERATION_ABORTED);
    EXPECT_EQ(bytes, 0);
    EXPECT_EQ(key, 5);
    CHECK(pov == &c.ov);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    CloseHandle(t.posted); CloseHandle(port);
    fx_closesocket(acc);
    fxc_close(&c);
}
