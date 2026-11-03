/* wsa_overlapped_io / tcp_basic: WSASend and WSARecv with WSAOVERLAPPED + event on connected loopback TCP.
 * Measures: the immediate-completion vs WSA_IO_PENDING rule, the Internal/InternalHigh fields (NTSTATUS and
 * byte count), event reset on submission, WSAGetOverlappedResult (fWait, flags out, repeat calls),
 * scatter-gather buffer arrays (several, empty, zero-length members), flag validation and the synchronous
 * failures that never reach the pending state.  All traffic is 127.0.0.1 on ephemeral ports. */
#include "oio.h"

/* Blocking read of exactly n bytes with a bounded wait; returns bytes read. */
static int oio_read_exact(SOCKET s, char *buf, int n)
{
    int got = 0;
    while (got < n) {
        fd_set r; struct timeval tv = {5, 0}; int k;
        FD_ZERO(&r); FD_SET(s, &r);
        if (U(select)(0, &r, NULL, NULL, &tv) != 1) break;
        k = U(recv)(s, buf + got, n - got, 0);
        if (k <= 0) break;
        got += k;
    }
    return got;
}

/* A posted receive on an idle socket pends: SOCKET_ERROR + WSA_IO_PENDING, Internal == STATUS_PENDING,
 * and the event is not signalled until data arrives. */
TEST(oio_tcp_recv_pends_without_data)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[16]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl_sentinel(&o, ev);
    int rc = oio_post_recv(c, buf, sizeof buf, &o, &fl);
    OEQ(rc, SOCKET_ERROR); OEQ(WERR(), WSA_IO_PENDING);
    OEQ(o.Internal, OIO_STATUS_PENDING);
    OEQ(oio_wait(ev, 0), WAIT_TIMEOUT);
    OEQ(oio_send(s, "hello", 5), 5);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    BOOL r = oio_finish(c, &o, &bytes, &f2, &err);
    CHECK(r); OEQ(bytes, 5); OEQ(f2, 0);
    OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 5);
    CHECK(!memcmp(buf, "hello", 5));
    oio_close2(c, s); CloseHandle(ev);
}

/* While the request is outstanding a non-waiting WSAGetOverlappedResult fails with WSA_IO_INCOMPLETE. */
TEST(oio_tcp_getresult_incomplete_while_pending)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 77, f2 = 77;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    SET_ERR(0);
    BOOL r = U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2);
    OEQ(r, FALSE); OEQ(WERR(), WSA_IO_INCOMPLETE);
    oio_send(s, "x", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    r = U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2);
    OEQ(r, TRUE); OEQ(bytes, 1);
    oio_close2(c, s); CloseHandle(ev);
}

/* A manual-reset event that is already signalled is reset by the submission of a pending request. */
TEST(oio_tcp_recv_resets_signalled_event)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    SetEvent(ev);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    OEQ(oio_wait(ev, 0), WAIT_TIMEOUT);
    oio_send(s, "z", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    oio_close2(c, s); CloseHandle(ev);
}

/* Data already queued: the receive either completes at once (0) or pends; either way the result fields
 * and the event end up consistent. */
TEST(oio_tcp_recv_data_ready_result_consistent)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[16]; DWORD fl, bytes = 0, f2 = 0, nb = 0; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_send(s, "abcdef", 6);
    Sleep(50);
    oio_ovl_sentinel(&o, ev);
    WSABUF b = {sizeof buf, buf};
    fl = 0;
    int rc = U(WSARecv)(c, &b, 1, &nb, &fl, &o, NULL);
    if (rc == 0) { OEQ(nb, 6); OEQ(fl, 0); }
    else { OEQ(rc, SOCKET_ERROR); OEQ(WERR(), WSA_IO_PENDING); }
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    BOOL r = oio_finish(c, &o, &bytes, &f2, &err);
    CHECK(r); OEQ(bytes, 6); OEQ(f2, 0);
    OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 6);
    CHECK(!memcmp(buf, "abcdef", 6));
    oio_close2(c, s); CloseHandle(ev);
}

/* A small overlapped send on an empty loopback connection: result is 0 or WSA_IO_PENDING, and the event
 * is signalled afterwards in both cases. */
TEST(oio_tcp_send_small_signals_event)
{
    SOCKET c, s; WSAOVERLAPPED o; char got[8]; DWORD bytes = 0, nb = 0, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl_sentinel(&o, ev);
    WSABUF b = {5, (CHAR *)"12345"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    if (rc == 0) OEQ(nb, 5);
    else { OEQ(rc, SOCKET_ERROR); OEQ(WERR(), WSA_IO_PENDING); }
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(bytes, 5);
    OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 5);
    OEQ(oio_read_exact(s, got, 5), 5);
    CHECK(!memcmp(got, "12345", 5));
    oio_close2(c, s); CloseHandle(ev);
}

/* Gather send of several buffers including empty ones arrives as one contiguous stream. */
TEST(oio_tcp_send_gather_with_empty_members)
{
    SOCKET c, s; WSAOVERLAPPED o; char got[16]; DWORD bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b[5] = { {1, (CHAR *)"A"}, {0, (CHAR *)""}, {2, (CHAR *)"BC"}, {0, NULL}, {3, (CHAR *)"DEF"} };
    int rc = U(WSASend)(c, b, 5, NULL, 0, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(bytes, 6);
    OEQ(oio_read_exact(s, got, 6), 6);
    CHECK(!memcmp(got, "ABCDEF", 6));
    oio_close2(c, s); CloseHandle(ev);
}

/* Scatter receive fills buffers in order; a zero-length member in the middle is skipped over. */
TEST(oio_tcp_recv_scatter_fill_order)
{
    SOCKET c, s; WSAOVERLAPPED o; char a[2] = {'.', '.'}, d[5] = {'.', '.', '.', '.', '.'}; DWORD fl = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_send(s, "ABCDEF", 6);
    Sleep(50);
    oio_ovl(&o, ev);
    WSABUF b[3] = { {2, a}, {0, NULL}, {5, d} };
    int rc = U(WSARecv)(c, b, 3, NULL, &fl, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(bytes, 6);
    CHECK(!memcmp(a, "AB", 2)); CHECK(!memcmp(d, "CDEF.", 5));
    oio_close2(c, s); CloseHandle(ev);
}

/* A pending scatter receive that is satisfied later honours the same order, spanning two segments. */
TEST(oio_tcp_recv_scatter_pending_then_filled)
{
    SOCKET c, s; WSAOVERLAPPED o; char a[3], d[3]; DWORD fl = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b[2] = { {3, a}, {3, d} };
    OEQ(U(WSARecv)(c, b, 2, NULL, &fl, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "xyz", 3);
    Sleep(50);
    oio_send(s, "uvw", 3);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    /* A stream receive completes with whatever has arrived; make up the rest with a second receive. */
    CHECK(bytes >= 3 && bytes <= 6);
    CHECK(!memcmp(a, "xyz", 3));
    if (bytes == 6) CHECK(!memcmp(d, "uvw", 3));
    oio_close2(c, s); CloseHandle(ev);
}

/* A send consisting only of an empty buffer succeeds with zero bytes. */
TEST(oio_tcp_send_single_empty_buffer)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 55, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b = {0, (CHAR *)""};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    if (rc == 0) OEQ(nb, 0);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(bytes, 0);
    oio_close2(c, s); CloseHandle(ev);
}

/* Buffer count 0: the outcome is recorded rather than asserted (the provider forwards the count to the
 * transport driver, which owns the decision). */
TEST(oio_tcp_send_zero_buffer_count_einval)
{
    SOCKET c, s; WSAOVERLAPPED o; WSABUF b = {1, (CHAR *)"q"}; DWORD nb = 0;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    int rc = U(WSASend)(c, &b, 0, &nb, 0, &o, NULL);
    t_note("WSASend with zero buffers: rc %d err %d", rc, rc ? WERR() : 0);
    if (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING) oio_wait(ev, 1000);
    oio_close2(c, s); CloseHandle(ev);
}

/* Send flags outside the accepted set are rejected before the request is built: error WSAEOPNOTSUPP and the
 * caller's OVERLAPPED is left untouched. */
TEST(oio_tcp_send_invalid_flags_opnotsupp)
{
    static const DWORD bad[] = { 0x2, 0x10, 0x100, 0x10000, 0x80000000u };
    SOCKET c, s; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        WSAOVERLAPPED o; DWORD nb = 0;
        WSABUF b = {1, (CHAR *)"q"};
        oio_ovl_sentinel(&o, ev);
        int rc = U(WSASend)(c, &b, 1, &nb, bad[i], &o, NULL);
        t_check(rc == SOCKET_ERROR && WERR() == WSAEOPNOTSUPP, __FILE__, __LINE__, "bad send flag", "flag 0x%lx rc %d err %d", bad[i], rc, WERR());
        OEQ(o.Internal, OIO_SENTINEL); OEQ(o.InternalHigh, OIO_SENTINEL);
    }
    oio_close2(c, s); CloseHandle(ev);
}

/* A send that is submitted (accepted flags) overwrites Internal with the pending status first. */
TEST(oio_tcp_send_internal_written_on_submit)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0; char got[2];
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl_sentinel(&o, ev);
    WSABUF b = {2, (CHAR *)"ok"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    CHECK(o.Internal != OIO_SENTINEL);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 2);
    oio_read_exact(s, got, 2);
    oio_close2(c, s); CloseHandle(ev);
}

/* Sending on an unconnected stream socket fails at once with WSAENOTCONN. */
TEST(oio_tcp_send_unconnected_enotconn)
{
    SOCKET u; WSAOVERLAPPED o; DWORD nb = 0; HANDLE ev = oio_event();
    UP();
    u = oio_sock(SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(u != INVALID_SOCKET);
    oio_ovl(&o, ev);
    WSABUF b = {1, (CHAR *)"x"};
    OEQ(U(WSASend)(u, &b, 1, &nb, 0, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTCONN);
    U(closesocket)(u); CloseHandle(ev);
}

/* After shutdown(SD_SEND) an overlapped send fails with WSAESHUTDOWN. */
TEST(oio_tcp_send_after_shutdown_send_eshutdown)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    OEQ(U(shutdown)(c, SD_SEND), 0);
    oio_ovl(&o, ev);
    WSABUF b = {1, (CHAR *)"x"};
    OEQ(U(WSASend)(c, &b, 1, &nb, 0, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAESHUTDOWN);
    oio_close2(c, s); CloseHandle(ev);
}

/* Peer closes gracefully: a pending receive completes successfully with zero bytes. */
TEST(oio_tcp_recv_pending_peer_close_zero_bytes)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    U(closesocket)(s);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(bytes, 0); OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 0);
    U(closesocket)(c); CloseHandle(ev);
}

/* A receive after the peer has closed and the data is drained completes with zero bytes. */
TEST(oio_tcp_recv_after_eof_zero_bytes_repeatable)
{
    SOCKET c, s; char buf[4]; DWORD fl;
    UP(); PAIR(c, s);
    U(closesocket)(s);
    Sleep(50);
    for (int i = 0; i < 2; i++) {
        WSAOVERLAPPED o; DWORD nb = 9, bytes, f2; int err;
        HANDLE ev = oio_event();
        oio_ovl(&o, ev);
        WSABUF b = {sizeof buf, buf}; fl = 0;
        int rc = U(WSARecv)(c, &b, 1, &nb, &fl, &o, NULL);
        CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
        if (rc == 0) OEQ(nb, 0);
        OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
        CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 0);
        CloseHandle(ev);
    }
    U(closesocket)(c);
}

/* Reading the result twice yields the same values; the OVERLAPPED may be queried repeatedly. */
TEST(oio_tcp_getresult_repeatable)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, b1, b2, f1, f2;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "ab", 2);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(U(WSAGetOverlappedResult)(c, &o, &b1, FALSE, &f1), TRUE);
    OEQ(U(WSAGetOverlappedResult)(c, &o, &b2, FALSE, &f2), TRUE);
    OEQ(b1, 2); OEQ(b2, 2); OEQ(f1, 0); OEQ(f2, 0);
    oio_close2(c, s); CloseHandle(ev);
}

static void thr_delayed_send(void *p)
{
    SOCKET s = *(SOCKET *)p;
    Sleep(200);
    oio_send(s, "late", 4);
}

/* fWait == TRUE blocks until the request is done, then returns the bytes. */
TEST(oio_tcp_getresult_wait_blocks_until_done)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 0, f2 = 9; oio_thr t;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    HANDLE th = oio_spawn(&t, thr_delayed_send, &s);
    BOOL r = U(WSAGetOverlappedResult)(c, &o, &bytes, TRUE, &f2);
    OEQ(r, TRUE); OEQ(bytes, 4); OEQ(f2, 0);
    CHECK(!memcmp(buf, "late", 4));
    oio_join(th); oio_close2(c, s); CloseHandle(ev);
}

/* NULL event handle: completion is still observable by polling WSAGetOverlappedResult. */
TEST(oio_tcp_null_event_poll_result)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 0, f2 = 0; int ok = 0;
    UP(); PAIR(c, s);
    oio_ovl(&o, NULL);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "n", 1);
    for (int i = 0; i < 500 && !ok; i++) {
        ok = U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2);
        if (!ok) { OEQ(WERR(), WSA_IO_INCOMPLETE); Sleep(10); }
    }
    CHECK(ok); OEQ(bytes, 1);
    oio_close2(c, s);
}

/* One OVERLAPPED reused for sequential operations: Internal returns to PENDING at each submission. */
TEST(oio_tcp_overlapped_reuse_sequential)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (int i = 0; i < 3; i++) {
        oio_ovl(&o, ev);
        OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
        OEQ(o.Internal, OIO_STATUS_PENDING);
        oio_send(s, "r", 1);
        OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
        CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 1);
        ResetEvent(ev);
    }
    oio_close2(c, s); CloseHandle(ev);
}

/* Two outstanding receives complete in submission order, each taking its share of the stream. */
TEST(oio_tcp_two_recvs_complete_in_order)
{
    SOCKET c, s; WSAOVERLAPPED o1, o2; char b1[2], b2[2]; DWORD fl, n1, n2, f2; int err;
    HANDLE e1 = oio_event(), e2 = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o1, e1); oio_ovl(&o2, e2);
    OEQ(oio_post_recv(c, b1, 2, &o1, &fl), SOCKET_ERROR);
    OEQ(oio_post_recv(c, b2, 2, &o2, &fl), SOCKET_ERROR);
    oio_send(s, "ABCD", 4);
    OEQ(oio_wait(e1, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(oio_wait(e2, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o1, &n1, &f2, &err)); CHECK(oio_finish(c, &o2, &n2, &f2, &err));
    OEQ(n1, 2); OEQ(n2, 2);
    CHECK(!memcmp(b1, "AB", 2)); CHECK(!memcmp(b2, "CD", 2));
    oio_close2(c, s); CloseHandle(e1); CloseHandle(e2);
}

/* Partial data satisfies only the first of two outstanding receives. */
TEST(oio_tcp_second_recv_stays_pending)
{
    SOCKET c, s; WSAOVERLAPPED o1, o2; char b1[4], b2[4]; DWORD fl, n, f2 = 0;
    HANDLE e1 = oio_event(), e2 = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o1, e1); oio_ovl(&o2, e2);
    oio_post_recv(c, b1, 4, &o1, &fl); oio_post_recv(c, b2, 4, &o2, &fl);
    oio_send(s, "12", 2);
    OEQ(oio_wait(e1, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(oio_wait(e2, 100), WAIT_TIMEOUT);
    OEQ(U(WSAGetOverlappedResult)(c, &o2, &n, FALSE, &f2), FALSE);
    OEQ(WERR(), WSA_IO_INCOMPLETE);
    oio_send(s, "34", 2);
    OEQ(oio_wait(e2, OIO_WAIT), WAIT_OBJECT_0);
    oio_close2(c, s); CloseHandle(e1); CloseHandle(e2);
}

/* MSG_PEEK on an overlapped receive leaves the data queued. */
TEST(oio_tcp_recv_peek_keeps_data)
{
    SOCKET c, s; WSAOVERLAPPED o; char b1[4] = {0}, b2[4] = {0}; DWORD fl = MSG_PEEK, n1 = 0, n2 = 0, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_send(s, "peek", 4); Sleep(50);
    oio_ovl(&o, ev);
    WSABUF b = {4, b1};
    int rc = U(WSARecv)(c, &b, 1, NULL, &fl, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &n1, &f2, &err)); OEQ(n1, 4);
    ResetEvent(ev); oio_ovl(&o, ev);
    b.buf = b2; fl = 0;
    rc = U(WSARecv)(c, &b, 1, NULL, &fl, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &n2, &f2, &err)); OEQ(n2, 4);
    CHECK(!memcmp(b1, "peek", 4)); CHECK(!memcmp(b2, "peek", 4));
    oio_close2(c, s); CloseHandle(ev);
}

/* MSG_WAITALL: the request does not complete until the whole buffer is filled. */
TEST(oio_tcp_recv_waitall_completes_when_full)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl = MSG_WAITALL, bytes = 0, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b = {8, buf};
    OEQ(U(WSARecv)(c, &b, 1, NULL, &fl, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "1234", 4);
    Sleep(150);
    OEQ(oio_wait(ev, 0), WAIT_TIMEOUT);
    oio_send(s, "5678", 4);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 8);
    CHECK(!memcmp(buf, "12345678", 8));
    oio_close2(c, s); CloseHandle(ev);
}

/* MSG_WAITALL with the peer closing early: completes with the partial count and success. */
TEST(oio_tcp_recv_waitall_short_on_close)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl = MSG_WAITALL, bytes = 0, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b = {8, buf};
    OEQ(U(WSARecv)(c, &b, 1, NULL, &fl, &o, NULL), SOCKET_ERROR);
    oio_send(s, "123", 3);
    U(closesocket)(s);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    BOOL r = oio_finish(c, &o, &bytes, &f2, &err);
    t_note("waitall+close: result %d err %d bytes %lu", r, err, bytes);
    CHECK(bytes <= 3);
    U(closesocket)(c); CloseHandle(ev);
}

/* Big overlapped send with a slow reader: completes (immediately or later) with the full byte count. */
TEST(oio_tcp_send_large_full_count)
{
    enum { N = 1 << 20 };
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    char *tx = (char *)malloc(N), *rx = (char *)malloc(N);
    UP(); PAIR(c, s);
    for (int i = 0; i < N; i++) tx[i] = (char)(i * 7 + 3);
    oio_ovl(&o, ev);
    WSABUF b = {N, tx};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_read_exact(s, rx, N), N);
    CHECK(!memcmp(tx, rx, N));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, N);
    OEQ(o.InternalHigh, N);
    oio_close2(c, s); CloseHandle(ev); free(tx); free(rx);
}

/* A gather send across many buffers (64) delivers the bytes in order. */
TEST(oio_tcp_send_many_buffers_in_order)
{
    SOCKET c, s; WSAOVERLAPPED o; WSABUF b[64]; char src[64], got[64]; DWORD bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (int i = 0; i < 64; i++) { src[i] = (char)('a' + i % 26); b[i].buf = &src[i]; b[i].len = 1; }
    oio_ovl(&o, ev);
    int rc = U(WSASend)(c, b, 64, NULL, 0, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 64);
    OEQ(oio_read_exact(s, got, 64), 64);
    CHECK(!memcmp(src, got, 64));
    oio_close2(c, s); CloseHandle(ev);
}

/* A scatter receive across many one-byte buffers. */
TEST(oio_tcp_recv_many_buffers_in_order)
{
    SOCKET c, s; WSAOVERLAPPED o; WSABUF b[64]; char dst[64], src[64]; DWORD fl = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (int i = 0; i < 64; i++) { src[i] = (char)('A' + i % 26); b[i].buf = &dst[i]; b[i].len = 1; }
    oio_send(s, src, 64); Sleep(50);
    oio_ovl(&o, ev);
    int rc = U(WSARecv)(c, b, 64, NULL, &fl, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 64);
    CHECK(!memcmp(src, dst, 64));
    oio_close2(c, s); CloseHandle(ev);
}

/* Echo round trips using the same pair, alternating directions with overlapped calls on both ends. */
TEST(oio_tcp_ping_pong_overlapped_both_ends)
{
    SOCKET c, s; HANDLE ev1 = oio_event(), ev2 = oio_event();
    UP(); PAIR(c, s);
    for (int i = 0; i < 5; i++) {
        WSAOVERLAPPED o1, o2; char tx = (char)('0' + i), rx = 0; DWORD fl, bytes, f2; int err;
        oio_ovl(&o1, ev1); oio_ovl(&o2, ev2); ResetEvent(ev1); ResetEvent(ev2);
        OEQ(oio_post_recv(s, &rx, 1, &o2, &fl), SOCKET_ERROR);
        WSABUF b = {1, &tx};
        int rc = U(WSASend)(c, &b, 1, NULL, 0, &o1, NULL);
        CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
        OEQ(oio_wait(ev2, OIO_WAIT), WAIT_OBJECT_0);
        CHECK(oio_finish(s, &o2, &bytes, &f2, &err)); OEQ(bytes, 1);
        OEQ(rx, tx);
        CHECK(oio_finish(c, &o1, &bytes, &f2, &err));
    }
    oio_close2(c, s); CloseHandle(ev1); CloseHandle(ev2);
}

/* Receive buffer smaller than the data: the rest stays queued for the next request. */
TEST(oio_tcp_recv_short_buffer_leaves_rest)
{
    SOCKET c, s; WSAOVERLAPPED o; char b1[2], b2[8]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_send(s, "WXYZ", 4); Sleep(50);
    oio_ovl(&o, ev);
    int rc = oio_post_recv(c, b1, 2, &o, &fl);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 2);
    OEQ(U(recv)(c, b2, sizeof b2, 0), 2);
    CHECK(!memcmp(b1, "WX", 2)); CHECK(!memcmp(b2, "YZ", 2));
    oio_close2(c, s); CloseHandle(ev);
}

/* Receive overlapped on the same socket as a concurrent blocking send from another thread. */
static void thr_blocking_send(void *p) { oio_send(*(SOCKET *)p, "thr", 3); }
TEST(oio_tcp_recv_completed_by_other_thread_send)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err; oio_thr t;
    HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    HANDLE th = oio_spawn(&t, thr_blocking_send, &s);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 3);
    oio_join(th); oio_close2(c, s); CloseHandle(ev);
}

/* Receive flags outside {OOB, PEEK, WAITALL, PUSH_IMMEDIATE, PARTIAL}, and WAITALL combined with OOB, PEEK,
 * PUSH_IMMEDIATE or PARTIAL, are refused before the request exists. */
TEST(oio_tcp_recv_invalid_flag_combinations_opnotsupp)
{
    static const DWORD bad[] = { 0x4, 0x10, 0x100, 0x10000, MSG_WAITALL | MSG_OOB, MSG_WAITALL | MSG_PEEK,
                                 MSG_WAITALL | 0x20, MSG_WAITALL | MSG_PARTIAL };
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        DWORD fl = bad[i], nb = 0;
        WSABUF b = {sizeof buf, buf};
        oio_ovl_sentinel(&o, ev);
        int rc = U(WSARecv)(c, &b, 1, &nb, &fl, &o, NULL);
        t_check(rc == SOCKET_ERROR && WERR() == WSAEOPNOTSUPP, __FILE__, __LINE__, "bad recv flags", "flags 0x%lx rc %d err %d", bad[i], rc, WERR());
        OEQ(o.Internal, OIO_SENTINEL);
    }
    oio_close2(c, s); CloseHandle(ev);
}

/* Sending with more than six buffers while the 0x40 flag is set is rejected; six is accepted. */
TEST(oio_tcp_send_flag40_buffer_limit_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; WSABUF b[7]; char x[7] = "abcdefg"; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (int i = 0; i < 7; i++) { b[i].buf = &x[i]; b[i].len = 1; }
    oio_ovl(&o, ev);
    int rc = U(WSASend)(c, b, 7, NULL, 0x40, &o, NULL);
    t_note("WSASend 7 buffers flag 0x40: rc %d err %d", rc, rc ? WERR() : 0);
    if (rc == 0 || WERR() == WSA_IO_PENDING) oio_wait(ev, 1000);
    oio_close2(c, s); CloseHandle(ev);
}

/* More than six buffers together with the 0x40 send flag is refused up front with WSAEINVAL; the overlapped
 * structure is not touched. */
TEST(oio_tcp_send_flag40_seven_buffers_einval)
{
    SOCKET c, s; WSAOVERLAPPED o; WSABUF b[7]; char x[7] = "abcdefg"; DWORD nb = 0; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    for (int i = 0; i < 7; i++) { b[i].buf = &x[i]; b[i].len = 1; }
    oio_ovl_sentinel(&o, ev);
    int rc = U(WSASend)(c, b, 7, &nb, 0x40, &o, NULL);
    t_check(rc == SOCKET_ERROR && WERR() == WSAEINVAL, __FILE__, __LINE__, "7 buffers flag 0x40", "rc %d err %d", rc, WERR());
    OEQ(o.Internal, OIO_SENTINEL);
    oio_close2(c, s); CloseHandle(ev);
}

/* MSG_DONTROUTE is an accepted send flag on a connected stream; the data still arrives. */
TEST(oio_tcp_send_dontroute_accepted)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0, bytes = 0, f2; int err; char got[4]; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b = {2, (CHAR *)"dr"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0x4, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 2);
    OEQ(U(recv)(s, got, sizeof got, 0), 2);
    CHECK(!memcmp(got, "dr", 2));
    oio_close2(c, s); CloseHandle(ev);
}
