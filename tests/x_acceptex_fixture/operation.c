/* AcceptEx operation, kept apart from discovery: the pending contract (FALSE with ERROR_IO_PENDING, status 0x103,
 * output DWORD never written), when a request completes (connect alone for a zero-length receive, first data for a
 * one-byte receive), what the byte count is and where it comes from, the address space and its layout, and how the
 * completion differs for FIN and RST.  Everything runs on loopback listeners bound to port 0, once per family. */
#include "fx.h"

/* Wait until the request has not completed for ms: the bounded negative wait. */
static int still_pending(struct fxc *c, int ms) { return !fx_done_within(&c->ov, ms); }

/* A zero-length receive completes on connect alone, with zero bytes, and the output DWORD never changes. */
FX_BOTH(op_zero_receive_completes_on_connect_alone)
{
    SOCKET acc, cl; DWORD got = 77, err = 0; int r;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    r = fxc_post(&c, acc, 0);
    FX_EQ(r, WSA_IO_PENDING);
    FX_EQ((ULONG)c.ov.Internal, FX_STATUS_PENDING);
    CHECK(still_pending(&c, 100));
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 0);
    EXPECT_EQ(err, 0);
    EXPECT_EQ((ULONG)c.ov.Internal, 0);
    EXPECT_EQ(c.ov.InternalHigh, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* The call always returns FALSE; the output DWORD is never written, not at the call and not at completion. */
FX_BOTH(op_output_dword_is_never_written)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; BOOL ret;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    c.n = FX_POISON;
    fx_WSASetLastError(0);
    ret = c.f.acceptex(c.f.lst, acc, c.buf, 1, c.f.slot, c.f.slot, &c.n, &c.ov);
    EXPECT_EQ(ret, FALSE);
    FX_EQ(fx_WSAGetLastError(), WSA_IO_PENDING);
    EXPECT_EQ(c.n, FX_POISON);
    cl = fx_client(&c.f);
    CHECK(still_pending(&c, 200));
    EXPECT_EQ(c.n, FX_POISON);
    fx_send(cl, "z", 1, 0);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(c.n, FX_POISON);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* A one-byte receive buffer: connect, withhold the byte, stay pending; send it, complete with exactly one byte. */
FX_BOTH(op_one_byte_receive_waits_for_the_byte)
{
    SOCKET acc, cl; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 1), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    CHECK(still_pending(&c, 300));
    EXPECT_EQ((ULONG)c.ov.Internal, FX_STATUS_PENDING);
    FX_EQ(fx_send(cl, "Q", 1, 0), 1);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(c.ov.InternalHigh, 1);
    EXPECT_EQ(c.buf[0], 'Q');
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* The pending completion's byte count comes from the OVERLAPPED result, which differs from the stale DWORD. */
FX_BOTH(op_byte_count_comes_from_the_overlapped_result)
{
    SOCKET acc, cl; DWORD got = 0, err = 0, viaGor = 0;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    fx_send(cl, "Z", 1, 0);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    CHECK(GetOverlappedResult((HANDLE)c.f.lst, &c.ov, &viaGor, FALSE));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(viaGor, 1);
    CHECK(c.n != got);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Only one byte is consumed even when more are sent; the rest stays readable on the accepted socket, with no
 * SO_UPDATE_ACCEPT_CONTEXT needed to read it. */
FX_BOTH(op_surplus_bytes_stay_on_the_accepted_socket)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; char rest[8] = {0};
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    fx_send(cl, "ABCDE", 5, 0);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(c.buf[0], 'A');
    FX_EQ(fx_recv_n(acc, rest, 4, 2000), 4);
    CHECK(!memcmp(rest, "BCDE", 4));
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* A connection already queued when AcceptEx is called is still reported through the pending protocol. */
FX_BOTH(op_queued_connection_still_follows_the_pending_protocol)
{
    SOCKET acc, cl; DWORD got = 5, err = 0;
    FXC_OPEN(c, af);
    cl = fx_client(&c.f);
    Sleep(50);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    EXPECT_EQ(c.n, FX_POISON);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 0);
    EXPECT_EQ(c.n, FX_POISON);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Queued connection with data already waiting: the first byte is delivered into the buffer. */
FX_BOTH(op_queued_connection_with_data_delivers_the_byte)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; char rest[2] = {0};
    FXC_OPEN(c, af);
    cl = fx_client(&c.f);
    fx_send(cl, "xy", 2, 0);
    Sleep(50);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 1), WSA_IO_PENDING);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(c.ov.InternalHigh, 1);
    EXPECT_EQ(c.buf[0], 'x');
    FX_EQ(fx_recv_n(acc, rest, 1, 2000), 1);
    EXPECT_EQ(rest[0], 'y');
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Queued connection but no data: the one-byte request keeps waiting until the byte arrives. */
FX_BOTH(op_queued_connection_without_data_keeps_waiting)
{
    SOCKET acc, cl; DWORD got = 0, err = 0;
    FXC_OPEN(c, af);
    cl = fx_client(&c.f);
    Sleep(50);
    acc = fx_stream(af);
    FX_EQ(fxc_post(&c, acc, 1), WSA_IO_PENDING);
    CHECK(still_pending(&c, 300));
    fx_send(cl, "w", 1, 0);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 1);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* A FIN with no data completes a one-byte request successfully with zero bytes. */
FX_BOTH(op_peer_fin_without_data_completes_with_zero_bytes)
{
    SOCKET acc, cl; DWORD got = 9, err = 9;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    CHECK(still_pending(&c, 100));
    fx_shutdown(cl, SD_SEND);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, 0);
    EXPECT_EQ(err, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* An abortive close (RST) before any data fails a one-byte request with WSAECONNRESET and zero bytes. */
FX_BOTH(op_peer_reset_without_data_fails_with_connreset)
{
    SOCKET acc, cl; DWORD got = 9, err = 0; LINGER lg = { 1, 0 };
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    CHECK(still_pending(&c, 100));
    fx_setsockopt(cl, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg);
    fx_closesocket(cl);
    CHECK(!fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(err, WSAECONNRESET);
    EXPECT_EQ(got, 0);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* The zero-length request is unaffected by the same abortive close: connect alone already completed it. */
FX_BOTH(op_zero_receive_completes_before_a_later_reset)
{
    SOCKET acc, cl; DWORD got = 9, err = 9; LINGER lg = { 1, 0 };
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_setsockopt(cl, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg);
    fx_closesocket(cl);
    EXPECT_EQ(got, 0);
    EXPECT_EQ(err, 0);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* A NULL output-DWORD pointer is accepted with an OVERLAPPED. */
FX_BOTH(op_null_output_dword_is_accepted)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; BOOL ret;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fx_WSASetLastError(0);
    ret = c.f.acceptex(c.f.lst, acc, c.buf, 0, c.f.slot, c.f.slot, NULL, &c.ov);
    EXPECT_EQ(ret, FALSE);
    FX_EQ(fx_WSAGetLastError(), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* The same OVERLAPPED serves consecutive requests. */
FX_BOTH(op_overlapped_is_reusable_for_consecutive_requests)
{
    int i;
    FXC_OPEN(c, af);
    for (i = 0; i < 3; i++) {
        SOCKET acc = fx_stream(af), cl; DWORD got = 9, err = 9; char tag = (char)('a' + i);
        FX_EQ(fxc_post(&c, acc, 1), WSA_IO_PENDING);
        cl = fx_client(&c.f);
        fx_send(cl, &tag, 1, 0);
        CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
        EXPECT_EQ(got, 1);
        EXPECT_EQ(c.buf[0], tag);
        fx_close_all(cl, acc, INVALID_SOCKET);
    }
    fxc_close(&c);
}

/* The accepted socket works before SO_UPDATE_ACCEPT_CONTEXT for data transfer in both directions. */
FX_BOTH(op_accepted_socket_transfers_data_without_context_update)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; char b[2] = {0}; int accepting = -1, l = sizeof accepting; u_long avail = 99;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    FX_EQ(fx_send(acc, "s", 1, 0), 1);
    FX_EQ(fx_recv_n(cl, b, 1, 2000), 1);
    EXPECT_EQ(b[0], 's');
    FX_EQ(fx_send(cl, "c", 1, 0), 1);
    FX_EQ(fx_recv_n(acc, b, 1, 2000), 1);
    EXPECT_EQ(b[0], 'c');
    FX_EQ(fx_getsockopt(acc, SOL_SOCKET, SO_ACCEPTCONN, (char *)&accepting, &l), 0);
    EXPECT_EQ(accepting, 0);
    FX_EQ(fx_ioctlsocket(acc, FIONREAD, &avail), 0);
    EXPECT_EQ(avail, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* The result can be fetched through the listener handle or the accept socket handle, with the same byte count and flags. */
FX_BOTH(op_result_through_either_handle)
{
    SOCKET acc, cl; DWORD got = 99, fl = 0xFFFF; BOOL ok;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    fx_send(cl, "h", 1, 0);
    WaitForSingleObject(c.ov.hEvent, 3000);
    ok = fx_WSAGetOverlappedResult(acc, (LPWSAOVERLAPPED)&c.ov, &got, FALSE, &fl);
    CHECK(ok);
    EXPECT_EQ(got, 1);
    EXPECT_EQ(fl, 0);
    got = 99; fl = 0xFFFF;
    ok = fx_WSAGetOverlappedResult(c.f.lst, (LPWSAOVERLAPPED)&c.ov, &got, TRUE, &fl);
    CHECK(ok);
    EXPECT_EQ(got, 1);
    EXPECT_EQ(fl, 0);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Accept socket variants the call takes without complaint: created without WSA_FLAG_OVERLAPPED, and with protocol 0. */
FX_BOTH(op_accept_socket_creation_variants_are_accepted)
{
    int v;
    FXC_OPEN(c, af);
    for (v = 0; v < 2; v++) {
        SOCKET acc = v == 0 ? fx_WSASocketW(af, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0) : fx_socket(af, SOCK_STREAM, 0);
        SOCKET cl; DWORD got = 9, err = 9;
        CHECK(acc != INVALID_SOCKET);
        FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
        cl = fx_client(&c.f);
        CHECKF(fx_result(c.f.lst, &c.ov, &got, 3000, &err), "variant %d", v);
        EXPECT_EQ(got, 0);
        fx_close_all(cl, acc, INVALID_SOCKET);
    }
    fxc_close(&c);
}

/* An accept socket of the other family is not rejected at the call: the request pends. */
FX_BOTH(op_accept_socket_of_the_other_family_is_pending)
{
    int oaf = af == AF_INET ? AF_INET6 : AF_INET;
    SOCKET acc;
    FXC_OPEN(c, af);
    acc = fx_stream(oaf);
    if (acc == INVALID_SOCKET) { fxc_close(&c); t_skip("other family unavailable"); return; }
    FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
    CHECK(still_pending(&c, 100));
    fx_drain(&c.f, &c.ov);
    fx_closesocket(acc);
    fxc_close(&c);
}

/* Two outstanding requests: both complete, each on its own accept socket, one connection each. */
FX_BOTH(op_two_outstanding_requests_each_take_one_connection)
{
    SOCKET a1, a2, c1, c2; OVERLAPPED ov2; unsigned char b2[FXC_BUF]; DWORD n2 = 0, got = 0, err = 0;
    FXC_OPEN(c, af);
    memset(&ov2, 0, sizeof ov2); ov2.hEvent = fx_event();
    a1 = fx_stream(af); a2 = fx_stream(af);
    FX_EQ(fxc_post(&c, a1, 0), WSA_IO_PENDING);
    FX_EQ(fx_post(&c.f, a2, b2, 0, c.f.slot, c.f.slot, &n2, &ov2), WSA_IO_PENDING);
    c1 = fx_client(&c.f); c2 = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    CHECK(fx_result(c.f.lst, &ov2, &got, 3000, &err));
    fx_close_all(a1, a2, c1); fx_closesocket(c2);
    CloseHandle(ov2.hEvent);
    fxc_close(&c);
}
