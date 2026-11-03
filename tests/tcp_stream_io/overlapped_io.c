/* Overlapped WSARecv/WSASend on connected loopback TCP pairs, and calls on handles that are not sockets.
 * Measured: completion codes (WSA_IO_PENDING), transferred byte counts through WSAGetOverlappedResult,
 * flags out, and the error for invalid handles. Every wait is bounded and every socket closed. */
#include "ts.h"

#define WSAGetOverlappedResult(...) W(WSAGetOverlappedResult)(__VA_ARGS__)

/* Gets the result of an overlapped operation, waiting up to the bound. Returns 1 on success. */
static int ov_result(SOCKET s, WSAOVERLAPPED *ov, DWORD *n, DWORD *fl)
{
    return WSAGetOverlappedResult(s, ov, n, TRUE, fl) ? 1 : 0;
}

TEST(ovl_send_recv_invalid_socket_is_notsock)
{
    char b[4];
    NEED_NET();
    WSASetLastError(0);
    EXPECT_EQ(send(INVALID_SOCKET, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0);
    EXPECT_EQ(recv(INVALID_SOCKET, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(ovl_shutdown_invalid_socket_is_notsock)
{
    NEED_NET();
    WSASetLastError(0);
    EXPECT_EQ(shutdown(INVALID_SOCKET, SD_BOTH), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(ovl_wsarecv_invalid_socket_is_notsock)
{
    WSABUF w; DWORD n = 0, fl = 0; char b[4];
    NEED_NET();
    w.buf = b; w.len = sizeof b;
    WSASetLastError(0);
    EXPECT_EQ(WSARecv(INVALID_SOCKET, &w, 1, &n, &fl, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(ovl_wsasend_invalid_socket_is_notsock)
{
    WSABUF w; DWORD n = 0;
    NEED_NET();
    w.buf = "x"; w.len = 1;
    WSASetLastError(0);
    EXPECT_EQ(WSASend(INVALID_SOCKET, &w, 1, &n, 0, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(ovl_wsarecv_pending_then_completes_with_data)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0, fl = 0, got = 0, rf = 0; char b[16]; int r;
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = b; w.len = sizeof b;
    WSASetLastError(0);
    r = WSARecv(s, &w, 1, &n, &fl, &ov, NULL);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 0), WAIT_TIMEOUT);
    EXPECT_EQ(send(c, "hello", 5, 0), 5);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, TS_WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(ov_result(s, &ov, &got, &rf), 1);
    EXPECT_EQ(got, 5);
    CHECK(!memcmp(b, "hello", 5));
    CloseHandle(ov.hEvent);
    ts_close2(c, s);
}

TEST(ovl_wsarecv_with_queued_data_completes_in_place)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0, fl = 0; char b[16]; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = b; w.len = sizeof b;
    r = WSARecv(s, &w, 1, &n, &fl, &ov, NULL);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(n, 3);
    CHECK(!memcmp(b, "abc", 3));
    CloseHandle(ov.hEvent);
    ts_close2(c, s);
}

TEST(ovl_wsarecv_pending_completes_zero_on_peer_close)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0, fl = 0, got = 7, rf = 0; char b[8];
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(WSARecv(s, &w, 1, &n, &fl, &ov, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, TS_WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(ov_result(s, &ov, &got, &rf), 1);
    EXPECT_EQ(got, 0);
    CloseHandle(ov.hEvent);
    ts_close2(c, s);
}

TEST(ovl_wsarecv_pending_fails_with_connreset_on_rst)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0, fl = 0, got = 0, rf = 0; char b[8];
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(WSARecv(s, &w, 1, &n, &fl, &ov, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
    ts_rst_close(c);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, TS_WAIT_MS), WAIT_OBJECT_0);
    WSASetLastError(0);
    EXPECT_EQ(ov_result(s, &ov, &got, &rf), 0);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    CloseHandle(ov.hEvent);
    closesocket(s);
}

TEST(ovl_wsarecv_pending_cancelled_by_closesocket)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0, fl = 0, got = 0, rf = 0; char b[8];
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(WSARecv(s, &w, 1, &n, &fl, &ov, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
    closesocket(s);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, TS_WAIT_MS), WAIT_OBJECT_0);
    /* the buffer and OVERLAPPED stay valid until completion, which has happened */
    CHECK(HasOverlappedIoCompleted((OVERLAPPED *)&ov));
    CloseHandle(ov.hEvent);
    closesocket(c);
}

TEST(ovl_wsasend_overlapped_completes_with_full_count)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0, got = 0, rf = 0; char b[8]; int r;
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = "payload"; w.len = 7;
    r = WSASend(c, &w, 1, &n, 0, &ov, NULL);
    if (r == -1) {
        EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
        EXPECT_EQ(WaitForSingleObject(ov.hEvent, TS_WAIT_MS), WAIT_OBJECT_0);
        EXPECT_EQ(ov_result(c, &ov, &got, &rf), 1);
        EXPECT_EQ(got, 7);
    } else {
        EXPECT_EQ(r, 0);
        EXPECT_EQ(n, 7);
    }
    EXPECT_EQ(ts_recv_n(s, b, 7), 7);
    CHECK(!memcmp(b, "payload", 7));
    CloseHandle(ov.hEvent);
    ts_close2(c, s);
}

TEST(ovl_wsasend_after_shutdown_send_fails_eshutdown)
{
    SOCKET c, s; WSAOVERLAPPED ov; WSABUF w; DWORD n = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ov.hEvent != NULL);
    w.buf = "x"; w.len = 1;
    WSASetLastError(0);
    EXPECT_EQ(WSASend(c, &w, 1, &n, 0, &ov, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    CloseHandle(ov.hEvent);
    ts_close2(c, s);
}

TEST(ovl_wsarecv_scatter_fills_buffers_in_order)
{
    SOCKET c, s; WSABUF w[2]; DWORD n = 0, fl = 0; char a[3], b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "123456", 6, 0), 6);
    EXPECT_EQ(ts_wait_queued(s, 6, TS_WAIT_MS), 6);
    w[0].buf = a; w[0].len = 3;
    w[1].buf = b; w[1].len = sizeof b;
    EXPECT_EQ(WSARecv(s, w, 2, &n, &fl, NULL, NULL), 0);
    EXPECT_EQ(n, 6);
    CHECK(!memcmp(a, "123", 3));
    CHECK(!memcmp(b, "456", 3));
    ts_close2(c, s);
}

TEST(ovl_so_rcvbuf_and_sndbuf_roundtrip_as_relations)
{
    SOCKET c, s; int v = 0, len = sizeof v;
    NEED_PAIR(c, s);
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&v, &len), 0);
    CHECK(v > 0);
    len = sizeof v; v = 0;
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_RCVBUF, (char *)&v, &len), 0);
    CHECK(v > 0);
    ts_close2(c, s);
}
