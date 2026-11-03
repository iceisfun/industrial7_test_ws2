/* AcceptEx argument and state errors that are reported in the call itself, and a few completion shapes the other
 * files leave out (partial receive, result queried before completion).  A failing row returns FALSE with a Winsock
 * error immediately, never WSA_IO_PENDING, leaves the output DWORD alone, and leaves the listener fully usable:
 * a valid request posted afterwards still takes the next connection.  Rows run once per family. */
#include "fx.h"

enum { R_NULL_OV, R_ACC_IS_LISTENER, R_LST_BOUND_ONLY, R_LST_UNBOUND, R_ACC_BOUND, R_LST_UDP, R_ACC_UDP,
       R_ACC_LISTENING, R_ACC_CONNECTED, R_ACC_INVALID, R_LST_INVALID };

static const char *const what[] = {
    "overlapped is NULL", "accept socket is the listener", "listener bound but not listening",
    "listener neither bound nor listening", "accept socket already bound", "listener is a datagram socket",
    "accept socket is a datagram socket", "accept socket is listening", "accept socket already connected",
    "accept socket is INVALID_SOCKET", "listener is INVALID_SOCKET",
};
static const int want[] = {
    ERROR_INVALID_PARAMETER, WSAEINVAL, WSAEINVAL, WSAEINVAL, WSAEINVAL, WSAEINVAL, WSAEINVAL, WSAEINVAL, WSAEINVAL,
    WSAENOTSOCK, WSAENOTSOCK,
};

static void arg_row(int af, int which)
{
    SOCKET acc, lst, extra = INVALID_SOCKET, probe;
    OVERLAPPED *ov; fx_addr a; BOOL r; int e; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    lst = c.f.lst; acc = fx_stream(af); ov = &c.ov;
    switch (which) {
    case R_NULL_OV: ov = NULL; break;
    case R_ACC_IS_LISTENER: fx_closesocket(acc); acc = c.f.lst; break;
    case R_LST_BOUND_ONLY: extra = fx_stream(af); fx_loopback(af, &a); fx_bind(extra, &a.sa, c.f.alen); lst = extra; break;
    case R_LST_UNBOUND: extra = fx_stream(af); lst = extra; break;
    case R_ACC_BOUND: extra = fx_stream(af); fx_loopback(af, &a); fx_bind(extra, &a.sa, c.f.alen); fx_closesocket(acc); acc = extra; break;
    case R_LST_UDP: extra = fx_socket(af, SOCK_DGRAM, IPPROTO_UDP); lst = extra; break;
    case R_ACC_UDP: extra = fx_socket(af, SOCK_DGRAM, IPPROTO_UDP); fx_closesocket(acc); acc = extra; break;
    case R_ACC_LISTENING: extra = fx_listener_on(af, &a, 2); fx_closesocket(acc); acc = extra; break;
    case R_ACC_CONNECTED: extra = fx_client(&c.f); fx_closesocket(acc); acc = extra; break;
    case R_ACC_INVALID: fx_closesocket(acc); acc = INVALID_SOCKET; break;
    case R_LST_INVALID: lst = INVALID_SOCKET; break;
    }
    c.n = FX_POISON;
    fx_WSASetLastError(0);
    r = c.f.acceptex(lst, acc, c.buf, 0, c.f.slot, c.f.slot, &c.n, ov);
    e = fx_WSAGetLastError();
    CHECKF(r == FALSE, "%s: call returned TRUE", what[which]);
    CHECKF(e == want[which], "%s: error %d want %d", what[which], e, want[which]);
    EXPECT_EQ(c.n, FX_POISON);
    if (acc != INVALID_SOCKET && acc != c.f.lst) fx_closesocket(acc);
    if (extra != INVALID_SOCKET && extra != acc) fx_closesocket(extra);
    /* the listener is untouched: a valid request still completes */
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    probe = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 0);
    fx_close_all(probe, acc, INVALID_SOCKET);
    fxc_close(&c);
}

#define ARG_ROW(nm, which) FX_BOTH(args_##nm) { arg_row(af, which); }
ARG_ROW(null_overlapped_is_invalid_parameter, R_NULL_OV)
ARG_ROW(accept_socket_equal_to_listener, R_ACC_IS_LISTENER)
ARG_ROW(listener_bound_but_not_listening, R_LST_BOUND_ONLY)
ARG_ROW(listener_not_bound_not_listening, R_LST_UNBOUND)
ARG_ROW(accept_socket_already_bound, R_ACC_BOUND)
ARG_ROW(listener_is_datagram, R_LST_UDP)
ARG_ROW(accept_socket_is_datagram, R_ACC_UDP)
ARG_ROW(accept_socket_is_listening, R_ACC_LISTENING)
ARG_ROW(accept_socket_already_connected, R_ACC_CONNECTED)
ARG_ROW(invalid_accept_socket_is_notsock, R_ACC_INVALID)
ARG_ROW(invalid_listener_is_notsock, R_LST_INVALID)

/* The same accept socket cannot wait on two listeners: the second post fails at once and the first stays queued. */
FX_BOTH(args_accept_socket_queued_on_two_listeners)
{
    SOCKET acc, l2, cl; fx_addr a2; OVERLAPPED ov2; unsigned char b2[FXC_BUF]; DWORD n2 = FX_POISON, got = 0, err = 0; BOOL r;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    l2 = fx_listener_on(af, &a2, 4);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    memset(&ov2, 0, sizeof ov2);
    fx_WSASetLastError(0);
    r = c.f.acceptex(l2, acc, b2, 0, c.f.slot, c.f.slot, &n2, &ov2);
    EXPECT_EQ(r, FALSE);
    FX_EQ(fx_WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(n2, FX_POISON);
    CHECK(!fx_done_within(&c.ov, 50));
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_close_all(cl, acc, l2);
    fxc_close(&c);
}

/* A receive buffer larger than what the peer sends completes on the first data, with the bytes that arrived. */
FX_BOTH(shape_partial_receive_completes_with_what_arrived)
{
    SOCKET acc, cl; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 4), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    CHECK(!fx_done_within(&c.ov, 150));
    FX_EQ(fx_send(cl, "ab", 2, 0), 2);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 2);
    EXPECT_EQ(c.buf[0], 'a');
    EXPECT_EQ(c.buf[1], 'b');
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Asking for the result before completion fails with the incomplete code, in both query forms. */
FX_BOTH(shape_result_before_completion_is_incomplete)
{
    SOCKET acc, cl; DWORD got = 5, fl = 0, err = 0; BOOL ok;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    SetLastError(0);
    ok = GetOverlappedResult((HANDLE)c.f.lst, &c.ov, &got, FALSE);
    EXPECT_EQ(ok, FALSE);
    EXPECT_ERR(ERROR_IO_INCOMPLETE);
    fx_WSASetLastError(0);
    ok = fx_WSAGetOverlappedResult(c.f.lst, (LPWSAOVERLAPPED)&c.ov, &got, FALSE, &fl);
    EXPECT_EQ(ok, FALSE);
    FX_EQ(fx_WSAGetLastError(), WSA_IO_INCOMPLETE);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Putting the listener in non-blocking mode does not change AcceptEx: it still pends and then completes. */
FX_BOTH(shape_nonblocking_listener_still_pends_then_completes)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; u_long nb = 1;
    FXC_OPEN(c, af);
    FX_EQ(fx_ioctlsocket(c.f.lst, FIONBIO, &nb), 0);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    CHECK(!fx_done_within(&c.ov, 100));
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Data followed at once by an orderly close still completes the request with the data. */
FX_BOTH(shape_data_then_close_completes_with_the_data)
{
    SOCKET acc, cl; DWORD got = 0, err = 9; BOOL ok;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 4), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    FX_EQ(fx_send(cl, "xy", 2, 0), 2);
    fx_closesocket(cl);
    ok = fx_result(c.f.lst, &c.ov, &got, 3000, &err);
    CHECK(ok);
    EXPECT_EQ(err, 0);
    EXPECT_EQ(got, 2);
    EXPECT_EQ(c.buf[0], 'x');
    EXPECT_EQ(c.buf[1], 'y');
    fx_closesocket(acc);
    fxc_close(&c);
}

/* Later segments do not extend a request that data already completed. */
FX_BOTH(shape_first_segment_completes_a_longer_request)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; char rest[4] = {0};
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 4), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    FX_EQ(fx_send(cl, "a", 1, 0), 1);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    FX_EQ(fx_send(cl, "bc", 2, 0), 2);
    FX_EQ(fx_recv_n(acc, rest, 2, 2000), 2);
    CHECK(!memcmp(rest, "bc", 2));
    EXPECT_EQ(c.buf[1], 0xCC);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* The OVERLAPPED's Offset fields are not used by the request and come back as they were given. */
FX_BOTH(shape_overlapped_offset_fields_are_left_alone)
{
    SOCKET acc, cl; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    c.ov.Offset = 0x1234; c.ov.OffsetHigh = 0x99;
    c.n = FX_POISON; ResetEvent(c.ov.hEvent);
    FX_EQ(fx_post(&c.f, acc, c.buf, 0, c.f.slot, c.f.slot, &c.n, &c.ov), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 0);
    EXPECT_EQ(c.ov.Offset, 0x1234);
    EXPECT_EQ(c.ov.OffsetHigh, 0x99);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* A connection taken by AcceptEx is not announced as FD_ACCEPT to an event-selected listener, and the listener
 * keeps reporting itself as listening. */
FX_BOTH(shape_accepted_connection_raises_no_fd_accept)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; HANDLE ev; WSANETWORKEVENTS ne; int v = -1, l = sizeof v;
    FXC_OPEN(c, af);
    ev = fx_event();
    FX_EQ(UIN("ws2_32.dll", WSAEventSelect)(c.f.lst, ev, FD_ACCEPT), 0);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    Sleep(100);
    CHECK(WaitForSingleObject(ev, 0) != WAIT_OBJECT_0);
    memset(&ne, 0, sizeof ne);
    FX_EQ(UIN("ws2_32.dll", WSAEnumNetworkEvents)(c.f.lst, ev, &ne), 0);
    EXPECT_EQ(ne.lNetworkEvents & FD_ACCEPT, 0);
    FX_EQ(fx_getsockopt(c.f.lst, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &l), 0);
    EXPECT_EQ(v, 1);
    UIN("ws2_32.dll", WSAEventSelect)(c.f.lst, NULL, 0);
    CloseHandle(ev);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Cancelling a request that is already gone is reported as not found. */
FX_BOTH(shape_second_cancel_of_the_same_request_is_not_found)
{
    SOCKET acc; BOOL ok;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    SetLastError(0);
    ok = CancelIoEx((HANDLE)c.f.lst, &c.ov);
    CHECK(ok);
    FX_EQ(WaitForSingleObject(c.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_CANCELLED);
    SetLastError(0);
    ok = CancelIoEx((HANDLE)c.f.lst, &c.ov);
    EXPECT_EQ(ok, FALSE);
    EXPECT_ERR(ERROR_NOT_FOUND);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* Closing the listener with three requests outstanding posts exactly three aborted packets on its port. */
FX_BOTH(shape_listener_close_posts_one_abort_packet_per_request)
{
    enum { N = 3 };
    HANDLE port; SOCKET a[N]; OVERLAPPED ov[N]; unsigned char bb[N][FXC_BUF]; DWORD nn[N]; int k, seen[N] = {0}, packets = 0;
    BOOL ok; DWORD by, e; ULONG_PTR key; OVERLAPPED *po;
    FXC_OPEN(c, af);
    port = fx_port();
    CHECK(fx_assoc(port, c.f.lst, 7));
    for (k = 0; k < N; k++) {
        a[k] = fx_stream(af); memset(&ov[k], 0, sizeof ov[k]);
        FX_EQ(fx_post(&c.f, a[k], bb[k], 0, c.f.slot, c.f.slot, &nn[k], &ov[k]), WSA_IO_PENDING);
    }
    fx_closesocket(c.f.lst); c.f.lst = INVALID_SOCKET;
    for (k = 0; k < N; k++) {
        if (!fx_dequeue(port, 3000, &ok, &by, &key, &po, &e)) break;
        packets++;
        EXPECT_EQ(ok, FALSE);
        EXPECT_EQ(e, ERROR_OPERATION_ABORTED);
        EXPECT_EQ(by, 0);
        EXPECT_EQ(key, 7);
        { int j; for (j = 0; j < N; j++) if (po == &ov[j]) seen[j]++; }
    }
    EXPECT_EQ(packets, N);
    for (k = 0; k < N; k++) EXPECT_EQ(seen[k], 1);
    CHECK(!fx_dequeue(port, 200, &ok, &by, &key, &po, &e));
    for (k = 0; k < N; k++) fx_closesocket(a[k]);
    CloseHandle(port);
    fxc_close(&c);
}
