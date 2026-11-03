/* wsa_overlapped_io / disconnect: WSASendDisconnect / WSARecvDisconnect interplay with overlapped
 * traffic, and the OVERLAPPED structure's own fields (Offset/OffsetHigh/hEvent untouched, Internal and
 * InternalHigh as status and byte count, auto-reset event semantics, out-of-band receives). */
#include "oio.h"

static int read_to_eof(SOCKET s, char *buf, int cap, int *saw_eof)
{
    int got = 0; *saw_eof = 0;
    for (;;) {
        fd_set r; struct timeval tv = {5, 0};
        FD_ZERO(&r); FD_SET(s, &r);
        if (U(select)(0, &r, NULL, NULL, &tv) != 1) return got;
        int k = U(recv)(s, buf + got, cap - got, 0);
        if (k == 0) { *saw_eof = 1; return got; }
        if (k < 0) return got;
        got += k;
        if (got >= cap) return got;
    }
}

TEST(oio_disc_senddisconnect_gives_peer_eof)
{
    SOCKET c, s; char buf[4]; UP(); PAIR(c, s);
    OEQ(U(WSASendDisconnect)(c, NULL), 0);
    int eof;
    OEQ(read_to_eof(s, buf, sizeof buf, &eof), 0);
    OEQ(eof, 1);
    oio_close2(c, s);
}

TEST(oio_disc_senddisconnect_blocks_further_sends)
{
    SOCKET c, s; WSAOVERLAPPED o; DWORD nb = 0; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    OEQ(U(WSASendDisconnect)(c, NULL), 0);
    oio_ovl(&o, ev);
    WSABUF b = {1, (CHAR *)"x"};
    OEQ(U(WSASend)(c, &b, 1, &nb, 0, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAESHUTDOWN);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_disc_senddisconnect_keeps_receive_open)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    OEQ(U(WSASendDisconnect)(c, NULL), 0);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "back", 4);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 4);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_disc_senddisconnect_after_pending_data_delivers_all_then_eof)
{
    enum { N = 100000 };
    SOCKET c, s; WSAOVERLAPPED o; static char tx[N], rx[N]; DWORD nb = 0; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    for (int i = 0; i < N; i++) tx[i] = (char)(i * 13);
    oio_ovl(&o, ev);
    WSABUF b = {N, tx};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    int d = U(WSASendDisconnect)(c, NULL);
    t_note("WSASendDisconnect with a send in flight: rc %d err %d", d, d ? WERR() : 0);
    int eof;
    int got = read_to_eof(s, rx, N, &eof);
    OEQ(got, N);
    CHECK(!memcmp(tx, rx, N));
    if (d == 0) {
        char x[1];
        OEQ(U(recv)(s, x, 1, 0), 0);
    }
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_disc_senddisconnect_twice_recorded)
{
    SOCKET c, s; UP(); PAIR(c, s);
    OEQ(U(WSASendDisconnect)(c, NULL), 0);
    int rc = U(WSASendDisconnect)(c, NULL);
    t_note("second WSASendDisconnect: rc %d err %d", rc, rc ? WERR() : 0);
    oio_close2(c, s);
}

TEST(oio_disc_senddisconnect_invalid_socket_notsock)
{
    UP();
    OEQ(U(WSASendDisconnect)(INVALID_SOCKET, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTSOCK);
    OEQ(U(WSARecvDisconnect)(INVALID_SOCKET, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTSOCK);
}

TEST(oio_disc_unconnected_tcp_notconn)
{
    SOCKET u; UP();
    u = oio_sock(SOCK_STREAM, IPPROTO_TCP); REQUIRE(u != INVALID_SOCKET);
    int rc = U(WSASendDisconnect)(u, NULL);
    t_note("WSASendDisconnect on unconnected TCP: rc %d err %d", rc, rc ? WERR() : 0);
    rc = U(WSARecvDisconnect)(u, NULL);
    t_note("WSARecvDisconnect on unconnected TCP: rc %d err %d", rc, rc ? WERR() : 0);
    U(closesocket)(u);
}

TEST(oio_disc_recvdisconnect_then_overlapped_recv_does_not_hang)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes = 0, f2; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    OEQ(U(WSARecvDisconnect)(c, NULL), 0);
    oio_send(s, "data", 4);
    oio_ovl(&o, ev);
    int rc = oio_post_recv(c, buf, sizeof buf, &o, &fl);
    t_note("overlapped recv after WSARecvDisconnect: rc %d err %d", rc, rc ? WERR() : 0);
    if (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING) {
        DWORD w = oio_wait(ev, 500);
        if (w != WAIT_OBJECT_0) { CancelIoEx((HANDLE)c, &o); oio_wait(ev, 2000); }
    }
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_disc_recvdisconnect_pending_recv_outcome_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes = 77, f2 = 0; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    OEQ(U(WSARecvDisconnect)(c, NULL), 0);
    DWORD w = oio_wait(ev, 500);
    t_note("pending recv across WSARecvDisconnect: %s", w == WAIT_OBJECT_0 ? "completed" : "still pending");
    if (w != WAIT_OBJECT_0) { CancelIoEx((HANDLE)c, &o); oio_wait(ev, 2000); }
    oio_close2(c, s); CloseHandle(ev);
}

/* ---- OVERLAPPED field behaviour ---------------------------------------------------------- */
TEST(oio_ovl_offset_fields_untouched_by_recv)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    o.Offset = 0xdead3; o.OffsetHigh = 0xdead4;
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "o", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(o.Offset, 0xdead3); OEQ(o.OffsetHigh, 0xdead4); OEQ(o.hEvent, ev);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_ovl_offset_fields_untouched_by_send)
{
    SOCKET c, s; WSAOVERLAPPED o; char got[4]; DWORD bytes, f2; int err; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    o.Offset = 0x1111; o.OffsetHigh = 0x2222;
    WSABUF b = {1, (CHAR *)"s"};
    int rc = U(WSASend)(c, &b, 1, NULL, 0, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c, &o, &bytes, &f2, &err));
    OEQ(o.Offset, 0x1111); OEQ(o.OffsetHigh, 0x2222);
    U(recv)(s, got, 1, 0);
    oio_close2(c, s); CloseHandle(ev);
}

/* Windows reuses InternalHigh as the byte count only on completion; before it, a pending request leaves
 * whatever was there. */
TEST(oio_ovl_internalhigh_untouched_while_pending)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl_sentinel(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(o.Internal, OIO_STATUS_PENDING);
    t_note("InternalHigh while pending: 0x%llx", (unsigned long long)o.InternalHigh);
    CancelIoEx((HANDLE)c, &o);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_ovl_auto_reset_event_consumed_once)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl;
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL); UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "a", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(oio_wait(ev, 0), WAIT_TIMEOUT);
    oio_close2(c, s); CloseHandle(ev);
}

/* One event shared by two outstanding requests is set by each completion. */
TEST(oio_ovl_shared_event_two_requests)
{
    SOCKET c, s; WSAOVERLAPPED o1, o2; char b1[1], b2[1]; DWORD fl, bytes, f2; int err; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl(&o1, ev); oio_ovl(&o2, ev);
    oio_post_recv(c, b1, 1, &o1, &fl); oio_post_recv(c, b2, 1, &o2, &fl);
    oio_send(s, "AB", 2);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    for (int i = 0; i < 100 && (o1.Internal == OIO_STATUS_PENDING || o2.Internal == OIO_STATUS_PENDING); i++) Sleep(10);
    CHECK(oio_finish(c, &o1, &bytes, &f2, &err)); CHECK(oio_finish(c, &o2, &bytes, &f2, &err));
    CHECK(b1[0] == 'A' && b2[0] == 'B');
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_ovl_getresult_fwait_on_completed_returns_immediately)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes = 0, f2 = 0; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "w", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    DWORD t0 = GetTickCount();
    OEQ(U(WSAGetOverlappedResult)(c, &o, &bytes, TRUE, &f2), TRUE);
    CHECK(GetTickCount() - t0 < 3000);
    OEQ(bytes, 1);
    oio_close2(c, s); CloseHandle(ev);
}

/* Urgent data: a plain overlapped receive with MSG_OOB returns the urgent byte. */
TEST(oio_oob_overlapped_recv_returns_urgent_byte)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[2] = {0, 0}; DWORD fl = MSG_OOB, bytes, f2; int err; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    OEQ(U(send)(s, "!", 1, MSG_OOB), 1);
    Sleep(150);
    oio_ovl(&o, ev);
    WSABUF b = {1, buf};
    int rc = U(WSARecv)(c, &b, 1, NULL, &fl, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    DWORD w = oio_wait(ev, OIO_WAIT);
    if (w == WAIT_OBJECT_0) {
        CHECK(oio_finish(c, &o, &bytes, &f2, &err)); OEQ(bytes, 1); CHECK(buf[0] == '!');
    } else { t_note("OOB receive did not complete"); CancelIoEx((HANDLE)c, &o); oio_wait(ev, 1000); }
    oio_close2(c, s); CloseHandle(ev);
}

/* Without data a MSG_OOB overlapped receive on a connected TCP socket pends rather than failing. */
TEST(oio_oob_overlapped_recv_without_urgent_data_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[2]; DWORD fl = MSG_OOB; HANDLE ev = oio_event(); UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    WSABUF b = {1, buf};
    int rc = U(WSARecv)(c, &b, 1, NULL, &fl, &o, NULL);
    t_note("MSG_OOB overlapped recv with no urgent data: rc %d err %d", rc, rc ? WERR() : 0);
    if (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING) { CancelIoEx((HANDLE)c, &o); oio_wait(ev, 2000); }
    oio_close2(c, s); CloseHandle(ev);
}

/* Thread-affinity: a request issued on a thread that then exits stays alive and completes through an event
 * when no completion port is attached... recorded, since thread exit cancels such requests. */
static void thr_post_recv_and_exit(void *p)
{
    void **a = (void **)p; DWORD fl;
    *(int *)a[2] = oio_post_recv(*(SOCKET *)a[0], a[3], 4, (WSAOVERLAPPED *)a[1], &fl);
}
TEST(oio_ovl_issuing_thread_exit_outcome_recorded)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; HANDLE ev = oio_event(); oio_thr t; int rc = 99; void *a[4];
    UP(); PAIR(c, s);
    oio_ovl(&o, ev);
    a[0] = &c; a[1] = &o; a[2] = &rc; a[3] = buf;
    oio_join(oio_spawn(&t, thr_post_recv_and_exit, a));
    OEQ(rc, SOCKET_ERROR);
    Sleep(100);
    DWORD w = oio_wait(ev, 0);
    t_note("request from exited thread: Internal 0x%llx event %s", (unsigned long long)o.Internal, w == WAIT_OBJECT_0 ? "signalled" : "clear");
    oio_send(s, "q", 1);
    Sleep(100);
    CancelIoEx((HANDLE)c, NULL);
    oio_close2(c, s); CloseHandle(ev);
}
