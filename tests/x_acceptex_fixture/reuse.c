/* Re-using the accept socket after DisconnectEx(TF_REUSE_SOCKET): the disconnect completes only once the peer
 * has finished its half, the socket returns to a fresh unconnected state, and the same handle then takes another
 * AcceptEx.  Without TF_REUSE_SOCKET the socket cannot be accepted onto again. */
#include "fx.h"

/* Accept one connection onto acc via AcceptEx (one byte), returning the client. */
static SOCKET take_one(struct fxc *c, SOCKET acc, char tag)
{
    DWORD got = 0, err = 0; SOCKET cl;
    if (fxc_post(c, acc, 1) != WSA_IO_PENDING) return INVALID_SOCKET;
    cl = fx_client(&c->f);
    fx_send(cl, &tag, 1, 0);
    if (!fx_result(c->f.lst, &c->ov, &got, 3000, &err) || got != 1 || c->buf[0] != (unsigned char)tag) { fx_closesocket(cl); return INVALID_SOCKET; }
    return cl;
}

/* Disconnect with reuse; the peer must read EOF and shut down its send side for the disconnect to complete. */
static int reuse_disconnect(struct fxc *c, SOCKET acc, SOCKET cl, int check_pending)
{
    OVERLAPPED d; DWORD got = 0, err = 0; int ok, r;
    memset(&d, 0, sizeof d); d.hEvent = fx_event();
    r = c->f.disconnectex(acc, &d, TF_REUSE_SOCKET, 0);
    if (r || fx_WSAGetLastError() != WSA_IO_PENDING) { CloseHandle(d.hEvent); return 0; }
    if (check_pending) CHECK(!fx_done_within(&d, 300));
    CHECK(fx_at_eof(cl, 3000));
    fx_shutdown(cl, SD_SEND);
    ok = fx_result(acc, &d, &got, 5000, &err);
    CloseHandle(d.hEvent);
    return ok;
}

/* Full cycle: accept, reuse, state is fresh, accept again on the same listener and receive the second byte. */
FX_BOTH(reuse_accept_disconnect_accept_again)
{
    SOCKET acc, c1, c2; int ct = 0, l = sizeof ct; fx_addr nm; int nl = sizeof nm;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    c1 = take_one(&c, acc, 'a');
    CHECK(c1 != INVALID_SOCKET);
    CHECK(fx_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&c.f.lst, sizeof c.f.lst) == 0);
    CHECK(reuse_disconnect(&c, acc, c1, 1));
    FX_EQ(fx_getsockname(acc, &nm.sa, &nl), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAEINVAL);
    FX_EQ(fx_getsockopt(acc, SOL_SOCKET, SO_CONNECT_TIME, (char *)&ct, &l), 0);
    EXPECT_EQ(ct, -1);
    c2 = take_one(&c, acc, 'b');
    CHECK(c2 != INVALID_SOCKET);
    fx_close_all(c1, c2, acc);
    fxc_close(&c);
}

/* Without TF_REUSE_SOCKET the disconnect finishes but AcceptEx on that socket fails at once with WSAEINVAL. */
FX_BOTH(reuse_plain_disconnect_then_acceptex_is_einval)
{
    SOCKET acc, cl; OVERLAPPED d; DWORD got = 0, err = 0; int r;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    cl = take_one(&c, acc, 'p');
    CHECK(cl != INVALID_SOCKET);
    memset(&d, 0, sizeof d); d.hEvent = fx_event();
    r = c.f.disconnectex(acc, &d, 0, 0);
    EXPECT_EQ(r, FALSE);
    FX_EQ(fx_WSAGetLastError(), WSA_IO_PENDING);
    CHECK(fx_at_eof(cl, 3000));
    fx_shutdown(cl, SD_SEND);
    CHECK(fx_result(acc, &d, &got, 5000, &err));
    FX_EQ(fxc_post(&c, acc, 0), WSAEINVAL);
    CloseHandle(d.hEvent);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Three consecutive reuse cycles on one socket, each delivering its own byte. */
FX_BOTH(reuse_three_cycles_deliver_each_byte)
{
    SOCKET acc = INVALID_SOCKET; int i;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    for (i = 0; i < 3; i++) {
        SOCKET cl = take_one(&c, acc, (char)('0' + i));
        CHECKF(cl != INVALID_SOCKET, "cycle %d", i);
        if (cl == INVALID_SOCKET) break;
        if (i < 2) CHECKF(reuse_disconnect(&c, acc, cl, 0), "cycle %d", i);
        fx_closesocket(cl);
    }
    fx_closesocket(acc);
    fxc_close(&c);
}

/* The reuse disconnect issued while the peer stays silent does not complete on its own. */
FX_BOTH(reuse_disconnect_waits_for_the_peer)
{
    SOCKET acc, cl; OVERLAPPED d; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    cl = take_one(&c, acc, 'w');
    CHECK(cl != INVALID_SOCKET);
    memset(&d, 0, sizeof d); d.hEvent = fx_event();
    FX_EQ(c.f.disconnectex(acc, &d, TF_REUSE_SOCKET, 0), FALSE);
    FX_EQ(fx_WSAGetLastError(), WSA_IO_PENDING);
    CHECK(!fx_done_within(&d, 500));
    CHECK(fx_at_eof(cl, 3000));
    CHECK(!fx_done_within(&d, 300));
    fx_shutdown(cl, SD_SEND);
    CHECK(fx_result(acc, &d, &got, 5000, &err));
    CloseHandle(d.hEvent);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* After a reuse disconnect the same handle can be handed to a different listener, and the packet goes to that
 * listener's port only. */
FX_BOTH(reuse_accept_socket_moves_to_another_listener)
{
    SOCKET acc, c1, c3; struct fx f2; fx_addr a2; HANDLE pa, pb; struct { BOOL ok; DWORD b, e; ULONG_PTR k; OVERLAPPED *ov; } p; DWORD n2 = 0;
    FXC_OPEN(c, af);
    f2 = c.f;
    f2.lst = fx_listener_on(af, &a2, 4);
    CHECK(f2.lst != INVALID_SOCKET);
    f2.addr = a2;
    pa = fx_port(); pb = fx_port();
    CHECK(fx_assoc(pa, c.f.lst, 11));
    CHECK(fx_assoc(pb, f2.lst, 33));
    acc = fx_stream(af);
    c1 = take_one(&c, acc, 'm');
    CHECK(c1 != INVALID_SOCKET);
    CHECK(reuse_disconnect(&c, acc, c1, 0));
    while (fx_dequeue(pa, 100, &p.ok, &p.b, &p.k, &p.ov, &p.e)) ;
    c.ov.Internal = 0; ResetEvent(c.ov.hEvent);
    FX_EQ(fx_post(&f2, acc, c.buf, 0, f2.slot, f2.slot, &n2, &c.ov), WSA_IO_PENDING);
    c3 = fx_client(&f2);
    CHECK(c3 != INVALID_SOCKET);
    CHECK(fx_dequeue(pb, 3000, &p.ok, &p.b, &p.k, &p.ov, &p.e));
    EXPECT_EQ(p.k, 33);
    CHECK(p.ov == &c.ov);
    CHECK(!fx_dequeue(pa, 300, &p.ok, &p.b, &p.k, &p.ov, &p.e));
    fx_close_all(c1, c3, acc);
    fx_closesocket(f2.lst);
    CloseHandle(pa); CloseHandle(pb);
    fxc_close(&c);
}

/* A reuse disconnect is a completion on the accept socket's own port, under that socket's key, zero bytes, success. */
FX_BOTH(reuse_disconnect_packet_goes_to_the_accept_socket_port)
{
    SOCKET acc, cl; OVERLAPPED d; HANDLE port; BOOL ok; DWORD bytes = 9, e = 0; ULONG_PTR key = 0; OVERLAPPED *pov = NULL;
    FXC_OPEN(c, af);
    port = fx_port();
    acc = fx_stream(af);
    CHECK(fx_assoc(port, acc, 22));
    cl = take_one(&c, acc, 'q');
    CHECK(cl != INVALID_SOCKET);
    memset(&d, 0, sizeof d); d.hEvent = fx_event();
    FX_EQ(c.f.disconnectex(acc, &d, TF_REUSE_SOCKET, 0), FALSE);
    FX_EQ(fx_WSAGetLastError(), WSA_IO_PENDING);
    CHECK(fx_at_eof(cl, 3000));
    fx_shutdown(cl, SD_SEND);
    CHECK(fx_dequeue(port, 5000, &ok, &bytes, &key, &pov, &e));
    EXPECT_EQ(ok, TRUE);
    EXPECT_EQ(bytes, 0);
    EXPECT_EQ(key, 22);
    CHECK(pov == &d);
    CloseHandle(d.hEvent); CloseHandle(port);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Without a context update the socket is not connected after reuse: names and transfers report WSAENOTCONN, and
 * the local name is gone (WSAEINVAL) because the socket is unbound again. */
FX_BOTH(reuse_socket_is_unconnected_after_reuse)
{
    SOCKET acc, cl; fx_addr nm; int nl = sizeof nm; char ch = 'x';
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    cl = take_one(&c, acc, 'r');
    CHECK(cl != INVALID_SOCKET);
    CHECK(reuse_disconnect(&c, acc, cl, 0));
    FX_EQ(fx_getpeername(acc, &nm.sa, &nl), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAENOTCONN);
    nl = sizeof nm;
    FX_EQ(fx_getsockname(acc, &nm.sa, &nl), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAEINVAL);
    FX_EQ(fx_send(acc, &ch, 1, 0), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAENOTCONN);
    FX_EQ(fx_shutdown(acc, SD_SEND), SOCKET_ERROR);
    FX_EQ(fx_WSAGetLastError(), WSAENOTCONN);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}
