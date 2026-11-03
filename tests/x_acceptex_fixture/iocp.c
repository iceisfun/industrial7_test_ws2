/* AcceptEx through an I/O completion port: which handle's port gets the packet, what the packet carries for
 * success and for abort, that a queued connection and the skip-on-success mode still produce a packet (the call
 * itself always reports pending), and that associating only the accept socket produces none. */
#include "fx.h"

struct pk { BOOL ok; DWORD bytes; ULONG_PTR key; OVERLAPPED *ov; DWORD err; int got; };

static struct pk take(HANDLE port, DWORD ms)
{
    struct pk p;
    p.got = fx_dequeue(port, ms, &p.ok, &p.bytes, &p.key, &p.ov, &p.err);
    return p;
}

/* One-byte receive: no packet while waiting, then a success packet with the listener's key, our OVERLAPPED, one byte. */
FX_BOTH(iocp_success_packet_carries_key_overlapped_and_one_byte)
{
    SOCKET acc, cl; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 77));
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 1), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    p = take(port, 300);
    EXPECT_EQ(p.got, 0);
    fx_send(cl, "m", 1, 0);
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.ok, TRUE);
    EXPECT_EQ(p.bytes, 1);
    EXPECT_EQ(p.key, 77);
    CHECK(p.ov == &c.ov);
    EXPECT_EQ(c.n, FX_POISON);
    EXPECT_EQ((ULONG)c.ov.Internal, 0);
    EXPECT_EQ(c.ov.InternalHigh, 1);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(port);
    fxc_close(&c);
}

/* Zero-length receive: the packet arrives on connect alone with zero bytes. */
FX_BOTH(iocp_zero_receive_packet_has_zero_bytes)
{
    SOCKET acc, cl; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 5));
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.ok, TRUE);
    EXPECT_EQ(p.bytes, 0);
    EXPECT_EQ(p.key, 5);
    CHECK(p.ov == &c.ov);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(port);
    fxc_close(&c);
}

/* A connection that was already queued also arrives as a packet; the call itself reported pending. */
FX_BOTH(iocp_queued_connection_still_posts_a_packet)
{
    SOCKET acc, cl; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 9));
    cl = fx_client(&c.f);
    Sleep(50);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.ok, TRUE);
    CHECK(p.ov == &c.ov);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(port);
    fxc_close(&c);
}

/* FILE_SKIP_COMPLETION_PORT_ON_SUCCESS does not suppress the packet: AcceptEx never returns success synchronously,
 * so there is no synchronous success to skip.  The OVERLAPPED event is still signalled. */
FX_BOTH(iocp_skip_on_success_mode_does_not_suppress_the_packet)
{
    SOCKET acc, cl; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 9));
    CHECK(SetFileCompletionNotificationModes((HANDLE)c.f.lst, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE));
    cl = fx_client(&c.f);
    Sleep(50);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    CHECK(p.ov == &c.ov);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 1000), WAIT_OBJECT_0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(port);
    fxc_close(&c);
}

/* The same mode on a pending request: still one packet. */
FX_BOTH(iocp_skip_on_success_mode_pending_request_posts_one_packet)
{
    SOCKET acc, cl; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 9));
    CHECK(SetFileCompletionNotificationModes((HANDLE)c.f.lst, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.bytes, 0);
    p = take(port, 300);
    EXPECT_EQ(p.got, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(port);
    fxc_close(&c);
}

/* Listener closed while pending: a failure packet with WSA_OPERATION_ABORTED, zero bytes, the listener's key. */
FX_BOTH(iocp_listener_close_posts_an_abort_packet)
{
    SOCKET acc; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 42));
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.ok, FALSE);
    EXPECT_EQ(p.err, ERROR_OPERATION_ABORTED);
    EXPECT_EQ(p.bytes, 0);
    EXPECT_EQ(p.key, 42);
    CHECK(p.ov == &c.ov);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    fx_closesocket(acc);
    CloseHandle(port);
    fxc_close(&c);
}

/* Only the accept socket is associated: the OVERLAPPED event fires but no packet reaches that port. */
FX_BOTH(iocp_accept_socket_only_association_gets_no_packet)
{
    SOCKET acc, cl; HANDLE port; struct pk p; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    port = fx_port();
    acc = fx_stream(af);
    CHECK(fx_assoc(port, acc, 88));
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    p = take(port, 300);
    EXPECT_EQ(p.got, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(port);
    fxc_close(&c);
}

/* Listener and accept socket on different ports: only the listener's port gets the packet. */
FX_BOTH(iocp_listener_port_wins_over_accept_socket_port)
{
    SOCKET acc, cl; HANDLE pa, pb; struct pk p;
    FXC_OPEN(c, af);
    pa = fx_port(); pb = fx_port();
    CHECK(fx_assoc(pa, c.f.lst, 11));
    acc = fx_stream(af);
    CHECK(fx_assoc(pb, acc, 22));
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    p = take(pa, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.key, 11);
    p = take(pb, 300);
    EXPECT_EQ(p.got, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    CloseHandle(pa); CloseHandle(pb);
    fxc_close(&c);
}

/* CancelIoEx on a pending request posts one failure packet with the listener's key. */
FX_BOTH(iocp_cancelioex_posts_an_abort_packet)
{
    SOCKET acc; HANDLE port; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 11));
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    FX_EQ(CancelIoEx((HANDLE)c.f.lst, &c.ov), TRUE);
    p = take(port, 3000);
    EXPECT_EQ(p.got, 1);
    EXPECT_EQ(p.ok, FALSE);
    EXPECT_EQ(p.err, ERROR_OPERATION_ABORTED);
    EXPECT_EQ(p.bytes, 0);
    EXPECT_EQ(p.key, 11);
    CHECK(p.ov == &c.ov);
    p = take(port, 200);
    EXPECT_EQ(p.got, 0);
    fx_closesocket(acc);
    CloseHandle(port);
    fxc_close(&c);
}

/* Two outstanding requests produce exactly one packet each, naming their own OVERLAPPED. */
FX_BOTH(iocp_one_packet_per_request)
{
    SOCKET a1, a2, c1, c2; HANDLE port; OVERLAPPED ov2; unsigned char b2[FXC_BUF]; DWORD n2 = 0; int g1 = 0, g2 = 0, i; struct pk p;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 3));
    memset(&ov2, 0, sizeof ov2); ov2.hEvent = fx_event();
    a1 = fx_stream(af); a2 = fx_stream(af);
    fxc_post(&c, a1, 0);
    fx_post(&c.f, a2, b2, 0, c.f.slot, c.f.slot, &n2, &ov2);
    c1 = fx_client(&c.f); c2 = fx_client(&c.f);
    for (i = 0; i < 2; i++) { p = take(port, 3000); if (p.ov == &c.ov) g1++; if (p.ov == &ov2) g2++; }
    EXPECT_EQ(g1, 1);
    EXPECT_EQ(g2, 1);
    p = take(port, 200);
    EXPECT_EQ(p.got, 0);
    fx_close_all(a1, a2, c1); fx_closesocket(c2);
    CloseHandle(ov2.hEvent); CloseHandle(port);
    fxc_close(&c);
}
