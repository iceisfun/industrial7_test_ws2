/* Receive paths on loopback TCP pairs: nonblocking sockets combined with overlapped and non-overlapped
 * (WSA_FLAG_OVERLAPPED absent) creation, two outstanding receives on one socket, zero-length receives,
 * SO_RCVTIMEO interaction, and the state of a connection that was reset by its peer. */
#include "lift11.h"

#define IO_PENDING_ERR ERROR_IO_PENDING

static int l11_wsarecv(SOCKET s, char *buf, ULONG len, DWORD *got, DWORD *flags, OVERLAPPED *ov)
{
    WSABUF b;
    b.buf = buf; b.len = len;
    return U(WSARecv)(s, &b, 1, got, flags, ov, NULL);
}

TEST(recv_nonblocking_overlapped_socket_wouldblock)
{
    SOCKET c, s;
    char buf[5];
    DWORD size = 0, flags = 0;
    int r;
    UP();
    PAIR(&c, &s);
    l11_blocking(c, FALSE);
    l11_seterr(0xdeadbeef);
    r = U(recv)(c, buf, sizeof(buf), 0);
    CHECK(r == -1);
    L_EQ(l11_err(), WSAEWOULDBLOCK);
    /* Non-overlapped WSARecv on an empty nonblocking socket: same error. */
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, buf, sizeof(buf), &size, &flags, NULL);
    CHECK(r == -1);
    L_EQ(l11_err(), WSAEWOULDBLOCK);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_nonblocking_overlapped_null_event_pends_then_completes)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[5] = {0};
    DWORD size = 0, flags = 0;
    int r;
    UP();
    PAIR(&c, &s);
    l11_blocking(c, FALSE);
    ov.Internal = 0xdeadbeef;
    ov.InternalHigh = 0xdeadbeef;
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, buf, sizeof(buf), NULL, &flags, &ov);
    CHECK(r == -1);
    L_EQ(l11_err(), IO_PENDING_ERR);
    /* With no event the file object itself is signalled on completion. */
    L_EQ(WaitForSingleObject((HANDLE)c, 0), WAIT_TIMEOUT);
    L_EQ((NTSTATUS)ov.Internal, 0x103);
    L_EQ(ov.InternalHigh, 0xdeadbeef);
    r = U(send)(s, "data", 4, 0);
    L_EQ(r, 4);
    L_EQ(WaitForSingleObject((HANDLE)c, 3000), WAIT_OBJECT_0);
    CHECK(U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    L_EQ(size, 4);
    CHECK(!memcmp(buf, "data", 4));
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_nonblocking_overlapped_with_event_pends_then_completes)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[5] = {0};
    DWORD size = 0, flags = 0;
    int r;
    UP();
    PAIR(&c, &s);
    l11_blocking(c, FALSE);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, buf, sizeof(buf), NULL, &flags, &ov);
    CHECK(r == -1);
    L_EQ(l11_err(), IO_PENDING_ERR);
    L_EQ(WaitForSingleObject(ov.hEvent, 0), WAIT_TIMEOUT);
    L_EQ(U(send)(s, "data", 4, 0), 4);
    L_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    L_EQ(size, 4);
    CHECK(!memcmp(buf, "data", 4));
    CloseHandle(ov.hEvent);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_nonblocking_overlapped_data_already_queued)
{
    /* Data is already waiting: the call either completes inline (0) or reports pending; either way
     * the result is the full four bytes. */
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[5] = {0};
    DWORD size = 0, flags = 0;
    int r;
    UP();
    PAIR(&c, &s);
    l11_blocking(c, FALSE);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    L_EQ(U(send)(s, "data", 4, 0), 4);
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, buf, sizeof(buf), NULL, &flags, &ov);
    CHECKF(r == 0 || l11_err() == IO_PENDING_ERR, "ret %d err %d", r, l11_err());
    L_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    L_EQ(size, 4);
    CHECK(!memcmp(buf, "data", 4));
    CloseHandle(ov.hEvent);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_nonblocking_nonoverlapped_socket_wouldblock)
{
    SOCKET c, s;
    char buf[5];
    DWORD size = 0, flags = 0;
    OVERLAPPED ov = {0};
    int r;
    UP();
    PAIRF(&c, &s, 0);
    l11_blocking(c, FALSE);
    l11_seterr(0xdeadbeef);
    r = U(recv)(c, buf, sizeof(buf), 0);
    CHECK(r == -1);
    L_EQ(l11_err(), WSAEWOULDBLOCK);
    ov.Internal = 0xdeadbeef;
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, buf, sizeof(buf), &size, &flags, NULL);
    CHECK(r == -1);
    L_EQ(l11_err(), WSAEWOULDBLOCK);
    L_EQ(ov.Internal, 0xdeadbeef);
    U(closesocket)(c); U(closesocket)(s);
}

struct l11_blk {
    SOCKET c;
    HANDLE event;
    int ret;
    BOOL gor;
    DWORD size;
    char buf[8];
};

static DWORD WINAPI l11_blocking_ovl_recv(void *arg)
{
    struct l11_blk *p = arg;
    OVERLAPPED ov = {0};
    DWORD flags = 0;
    ov.hEvent = p->event;
    memset(p->buf, 0, sizeof(p->buf));
    p->ret = l11_wsarecv(p->c, p->buf, 5, NULL, &flags, &ov);
    p->gor = U(GetOverlappedResult)((HANDLE)p->c, &ov, &p->size, FALSE);
    return 0;
}

static void l11_blocking_ovl_case(HANDLE event)
{
    /* On a socket created without overlapped capability, WSARecv given an OVERLAPPED still blocks
     * the calling thread until data arrives and then completes inline. */
    struct l11_blk p;
    SOCKET c, s;
    HANDLE th;
    UP();
    PAIRF(&c, &s, 0);
    l11_blocking(c, FALSE);
    memset(&p, 0, sizeof(p));
    p.c = c; p.event = event; p.ret = -99;
    th = CreateThread(NULL, 0, l11_blocking_ovl_recv, &p, 0, NULL);
    L_EQ(WaitForSingleObject(th, 200), WAIT_TIMEOUT);
    L_EQ(U(send)(s, "data", 4, 0), 4);
    if (WaitForSingleObject(th, 3000) != WAIT_OBJECT_0) {
        U(closesocket)(c);
        WaitForSingleObject(th, 3000);
        CHECK(!"blocking overlapped receive never returned");
    } else {
        L_EQ(p.ret, 0);
        CHECK(p.gor);
        L_EQ(p.size, 4);
        CHECK(!strcmp(p.buf, "data"));
        U(closesocket)(c);
    }
    CloseHandle(th);
    U(closesocket)(s);
}

TEST(recv_nonoverlapped_socket_ovl_null_event_blocks)
{
    l11_blocking_ovl_case(NULL);
}

TEST(recv_nonoverlapped_socket_ovl_with_event_blocks)
{
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    l11_blocking_ovl_case(ev);
    CloseHandle(ev);
}

TEST(recv_nonoverlapped_socket_ovl_data_already_queued)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[5] = {0};
    DWORD size = 0, flags = 0;
    UP();
    PAIRF(&c, &s, 0);
    l11_blocking(c, FALSE);
    L_EQ(U(send)(s, "data", 4, 0), 4);
    L_EQ(l11_wsarecv(c, buf, sizeof(buf), NULL, &flags, &ov), 0);
    CHECK(U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    L_EQ(size, 4);
    CHECK(!memcmp(buf, "data", 4));
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_two_outstanding_overlapped_split_one_message)
{
    /* Two pending receives on one socket are filled in submission order from one 32-byte send. */
    static const char msg[32] = "-- Lorem ipsum dolor sit amet -";
    OVERLAPPED ov[2] = {{0}};
    HANDLE ev[2];
    char res[32] = "";
    DWORD flags[2] = {0, 0};
    SOCKET c, s;
    int i;
    UP();
    PAIR(&c, &s);
    for (i = 0; i < 2; i++) {
        ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        ov[i].hEvent = ev[i];
        l11_seterr(0xdeadbeef);
        CHECK(l11_wsarecv(c, res + i * 16, 16, NULL, &flags[i], &ov[i]) == -1);
        L_EQ(l11_err(), IO_PENDING_ERR);
    }
    L_EQ(U(send)(s, msg, sizeof(msg), 0), (int)sizeof(msg));
    for (i = 0; i < 2; i++) {
        DWORD size = 0;
        L_EQ(WaitForSingleObject(ev[i], 3000), WAIT_OBJECT_0);
        CHECK(U(GetOverlappedResult)((HANDLE)c, &ov[i], &size, FALSE));
        L_EQ(size, 16);
        CHECK(!memcmp(res + i * 16, msg + i * 16, 16));
    }
    for (i = 0; i < 2; i++) CloseHandle(ev[i]);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_zero_buffer_count_is_invalid)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    WSABUF b;
    char buf[5];
    DWORD flags = 0;
    UP();
    PAIR(&c, &s);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    l11_seterr(0xdeadbeef);
    CHECK(U(WSARecv)(c, NULL, 0, NULL, &flags, &ov, NULL) == -1);
    L_EQ(l11_err(), WSAEINVAL);
    b.buf = buf; b.len = 0;
    l11_seterr(0xdeadbeef);
    CHECK(U(WSARecv)(c, &b, 0, NULL, &flags, &ov, NULL) == -1);
    L_EQ(l11_err(), WSAEINVAL);
    CloseHandle(ov.hEvent);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_zero_length_buffer_completes_without_consuming)
{
    /* A zero-length receive completes with 0 bytes when data arrives and leaves the data queued. */
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[8] = {0};
    DWORD size = 99, flags = 0;
    int r;
    UP();
    PAIR(&c, &s);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    l11_seterr(0xdeadbeef);
    CHECK(l11_wsarecv(c, buf, 0, NULL, &flags, &ov) == -1);
    L_EQ(l11_err(), IO_PENDING_ERR);
    L_EQ(U(send)(s, "data", 5, 0), 5);
    L_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    L_EQ(size, 0);

    /* A second zero-length receive with data present completes immediately with 0 bytes. */
    size = 99;
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, buf, 0, &size, &flags, &ov);
    CHECKF(r == 0, "ret %d err %d", r, l11_err());
    L_EQ(size, 0);

    L_EQ(U(recv)(c, NULL, 0, 0), 0);
    r = U(recv)(c, buf, sizeof(buf), 0);
    L_EQ(r, 5);
    CHECK(!strcmp(buf, "data"));
    CloseHandle(ov.hEvent);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_rcvtimeo_default_and_roundtrip)
{
    SOCKET c, s;
    DWORD t;
    int len;
    UP();
    PAIR(&c, &s);
    t = 0xdeadbeef; len = sizeof(t);
    l11_seterr(0xdeadbeef);
    L_EQ(U(getsockopt)(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, &len), 0);
    L_EQ(l11_err(), 0);
    L_EQ(len, sizeof(t));
    L_EQ(t, 0);
    t = 100;
    l11_seterr(0xdeadbeef);
    L_EQ(U(setsockopt)(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t)), 0);
    L_EQ(l11_err(), 0);
    t = 0xdeadbeef; len = sizeof(t);
    L_EQ(U(getsockopt)(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, &len), 0);
    L_EQ(t, 100);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_rcvtimeo_blocking_calls_time_out)
{
    SOCKET c, s;
    DWORD size, flags = 0;
    char b;
    int r;
    UP();
    PAIR(&c, &s);
    l11_rcvtimeo(c, 100);
    l11_seterr(0xdeadbeef);
    r = U(recv)(c, &b, 1, 0);
    CHECK(r == -1);
    L_EQ(l11_err(), WSAETIMEDOUT);
    size = 0xdeadbeef;
    l11_seterr(0xdeadbeef);
    r = l11_wsarecv(c, &b, 1, &size, &flags, NULL);
    CHECK(r == -1);
    L_EQ(l11_err(), WSAETIMEDOUT);
    L_EQ(size, 0xdeadbeef);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(recv_rcvtimeo_does_not_apply_to_overlapped_receive)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    DWORD size = 0xdeadbeef, flags = 0;
    char b;
    UP();
    PAIR(&c, &s);
    l11_rcvtimeo(c, 100);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    l11_seterr(0xdeadbeef);
    CHECK(l11_wsarecv(c, &b, 1, &size, &flags, &ov) == -1);
    L_EQ(l11_err(), IO_PENDING_ERR);
    L_EQ(WaitForSingleObject(ov.hEvent, 400), WAIT_TIMEOUT);
    L_EQ(U(send)(s, "a", 1, 0), 1);
    L_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    L_EQ(size, 1);
    CloseHandle(ov.hEvent);
    U(closesocket)(c); U(closesocket)(s);
}

/* ---- connection reset by peer ----------------------------------------- */

static int l11_reset_pair(SOCKET *c, SOCKET *s, OVERLAPPED *ov, char *buf, int pend)
{
    DWORD size = 0xdeadbeef, flags = 0;
    if (!l11_pair(c, s)) return 0;
    ov->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (pend) {
        l11_seterr(0xdeadbeef);
        CHECK(l11_wsarecv(*c, buf, 10, &size, &flags, ov) == -1);
        L_EQ(l11_err(), IO_PENDING_ERR);
    }
    l11_close_rst(*s);
    *s = INVALID_SOCKET;
    return 1;
}

TEST(tcp_reset_pending_receive_fails_netname_deleted)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[10];
    DWORD size = 0xdeadbeef;
    UP();
    if (!l11_reset_pair(&c, &s, &ov, buf, 1)) return;
    L_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(!U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE));
    EXPECT_ERR(ERROR_NETNAME_DELETED);
    L_EQ(size, 0);
    L_EQ((ULONG)ov.Internal, 0xC000020D);
    CloseHandle(ov.hEvent);
    U(closesocket)(c);
}

TEST(tcp_reset_so_error_is_clear_after_failed_receive)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[10];
    DWORD size;
    int err = 0x55, len = sizeof(err);
    UP();
    if (!l11_reset_pair(&c, &s, &ov, buf, 1)) return;
    WaitForSingleObject(ov.hEvent, 3000);
    U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE);
    L_EQ(U(getsockopt)(c, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    L_EQ(err, 0);
    CloseHandle(ov.hEvent);
    U(closesocket)(c);
}

TEST(tcp_reset_following_receive_and_send_report_connreset)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[10];
    DWORD size, flags = 0;
    UP();
    if (!l11_reset_pair(&c, &s, &ov, buf, 1)) return;
    WaitForSingleObject(ov.hEvent, 3000);
    U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE);
    size = 0xdeadbeef;
    l11_seterr(0xdeadbeef);
    CHECK(l11_wsarecv(c, buf, sizeof(buf), &size, &flags, &ov) == -1);
    L_EQ(l11_err(), WSAECONNRESET);
    l11_seterr(0xdeadbeef);
    CHECK(U(send)(c, "data", 5, 0) == -1);
    L_EQ(l11_err(), WSAECONNRESET);
    CloseHandle(ov.hEvent);
    U(closesocket)(c);
}

TEST(tcp_reset_poll_reports_err_hup_wr)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[10];
    DWORD size;
    int cnt = 0;
    short ev;
    UP();
    if (!l11_reset_pair(&c, &s, &ov, buf, 1)) return;
    WaitForSingleObject(ov.hEvent, 3000);
    U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE);
    ev = l11_poll(c, POLLRDNORM | POLLRDBAND | POLLWRNORM, &cnt);
    CHECK(cnt);
    L_EQ(ev, POLLERR | POLLHUP | POLLWRNORM);
    CloseHandle(ov.hEvent);
    U(closesocket)(c);
}

TEST(tcp_reset_select_reports_readable_and_writable_not_except)
{
    OVERLAPPED ov = {0};
    SOCKET c, s;
    char buf[10];
    DWORD size;
    fd_set rd, wr, ex;
    struct timeval tv = {0, 0};
    int r;
    UP();
    if (!l11_reset_pair(&c, &s, &ov, buf, 1)) return;
    WaitForSingleObject(ov.hEvent, 3000);
    U(GetOverlappedResult)((HANDLE)c, &ov, &size, FALSE);
    FD_ZERO(&rd); FD_ZERO(&wr); FD_ZERO(&ex);
    FD_SET(c, &rd); FD_SET(c, &wr); FD_SET(c, &ex);
    r = U(select)(0, &rd, &wr, &ex, &tv);
    L_EQ(r, 2);
    CHECK(l11_isset(c, &rd));
    CHECK(l11_isset(c, &wr));
    CHECK(!l11_isset(c, &ex));
    FD_ZERO(&ex); FD_SET(c, &ex);
    r = U(select)(0, NULL, NULL, &ex, &tv);
    L_EQ(r, 0);
    CHECK(!l11_isset(c, &ex));
    CloseHandle(ov.hEvent);
    U(closesocket)(c);
}
