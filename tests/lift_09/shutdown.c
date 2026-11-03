/* shutdown() semantics on TCP and UDP sockets: which states accept it, what each half-close does to the
 * local and the remote end, the error codes that follow, and how pending overlapped receives react.
 * Measured: return values, WSAGetLastError, EOF delivery, address queries after teardown. */
#include "h9.h"

static const char PAYLOAD[5] = { 't', 'e', 's', 't', 0 };

/* A successful shutdown returns 0 and leaves the last error untouched (or zero). */
#define SHUT_OK(s, how) do { WSASetLastError(POISON); EXPECT_EQ(shutdown((s), (how)), 0); CHECK(h9_err_clean()); } while (0)
#define SEND_FAILS_SHUTDOWN(s) do { WSASetLastError(POISON); int r_ = send((s), PAYLOAD, 5, 0); \
    CHECK(r_ == -1); EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN); } while (0)
#define RECV_FAILS_SHUTDOWN(s) do { char b_[5]; WSASetLastError(POISON); int r_ = recv((s), b_, 5, 0); \
    CHECK(r_ == -1); EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN); } while (0)

TEST(shutdown_unconnected_stream_send)
{
    NEED_NET();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(shutdown(s, SD_SEND) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

TEST(shutdown_unconnected_stream_receive)
{
    NEED_NET();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(shutdown(s, SD_RECEIVE) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

TEST(shutdown_send_is_idempotent_and_blocks_send)
{
    NEED_NET();
    SOCKET c, s;
    NEED_PAIR(c, s);
    h9_nonblock(c, 1);
    SHUT_OK(c, SD_SEND);
    SHUT_OK(c, SD_SEND);               /* a second half-close of the same direction still succeeds */
    SEND_FAILS_SHUTDOWN(c);
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_send_delivers_eof_repeatedly)
{
    NEED_NET();
    SOCKET c, s;
    char b[5];
    NEED_PAIR(c, s);
    SHUT_OK(c, SD_SEND);
    EXPECT_EQ(h9_recv(s, b, sizeof b), 0);   /* FIN seen as a zero-length read ... */
    EXPECT_EQ(h9_recv(s, b, sizeof b), 0);   /* ... and it stays that way */
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_receive_blocks_local_recv)
{
    NEED_NET();
    SOCKET c, s;
    NEED_PAIR(c, s);
    SHUT_OK(s, SD_RECEIVE);
    RECV_FAILS_SHUTDOWN(s);
    RECV_FAILS_SHUTDOWN(s);           /* the error is sticky */
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_receive_leaves_send_direction_usable)
{
    NEED_NET();
    SOCKET c, s;
    char b[8] = { 0 };
    NEED_PAIR(c, s);
    SHUT_OK(s, SD_RECEIVE);
    EXPECT_EQ(send(s, PAYLOAD, 5, 0), 5);
    EXPECT_EQ(h9_recv_all(c, b, 5), 5);
    CHECK(!strcmp(b, "test"));
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_receive_on_client_then_recv_fails_twice)
{
    NEED_NET();
    SOCKET c, s;
    char b[8] = { 0 };
    NEED_PAIR(c, s);
    EXPECT_EQ(send(s, PAYLOAD, 5, 0), 5);
    EXPECT_EQ(h9_recv_all(c, b, 5), 5);
    SHUT_OK(c, SD_RECEIVE);
    RECV_FAILS_SHUTDOWN(c);
    RECV_FAILS_SHUTDOWN(c);
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_send_on_server_blocks_send)
{
    NEED_NET();
    SOCKET c, s;
    NEED_PAIR(c, s);
    SHUT_OK(s, SD_SEND);
    SEND_FAILS_SHUTDOWN(s);
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_half_close_keeps_peer_names)
{
    NEED_NET();
    SOCKET c, s;
    struct sockaddr_in a1, a2, cn, sn;
    int l1 = sizeof a1, l2 = sizeof a2;
    NEED_PAIR(c, s);
    getsockname(s, (struct sockaddr *)&sn, &l1);
    SHUT_OK(c, SD_SEND);
    SHUT_OK(s, SD_RECEIVE);
    SHUT_OK(c, SD_RECEIVE);
    SHUT_OK(s, SD_SEND);
    l1 = sizeof a1;
    EXPECT_EQ(getpeername(c, (struct sockaddr *)&a1, &l1), 0);
    CHECK(!memcmp(&a1, &sn, sizeof sn));
    l1 = sizeof cn;
    EXPECT_EQ(getsockname(c, (struct sockaddr *)&cn, &l1), 0);
    EXPECT_EQ(getpeername(s, (struct sockaddr *)&a2, &l2), 0);
    CHECK(!memcmp(&a2, &cn, sizeof cn));
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_connected_socket_connect_is_eisconn)
{
    NEED_NET();
    SOCKET c, s;
    struct sockaddr_in a;
    int l = sizeof a;
    NEED_PAIR(c, s);
    getpeername(c, (struct sockaddr *)&a, &l);
    SHUT_OK(c, SD_SEND);
    WSASetLastError(POISON);
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEISCONN);
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_invalid_how_values)
{
    NEED_NET();
    SOCKET c, s;
    static const int bad[] = { 3, (int)0xdeadbeef };
    NEED_PAIR(c, s);
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        WSASetLastError(POISON);
        CHECK(shutdown(c, bad[i]) == -1);
        EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    }
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_invalid_socket)
{
    NEED_NET();
    WSASetLastError(POISON);
    CHECK(shutdown(INVALID_SOCKET, SD_SEND) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(shutdown_both_blocks_local_directions)
{
    NEED_NET();
    SOCKET c, s;
    char b[5];
    NEED_PAIR(c, s);
    SHUT_OK(c, SD_BOTH);
    RECV_FAILS_SHUTDOWN(c);
    SEND_FAILS_SHUTDOWN(c);
    EXPECT_EQ(h9_recv(s, b, sizeof b), 0);   /* the peer sees the FIN */
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_both_on_both_ends)
{
    NEED_NET();
    SOCKET c, s;
    NEED_PAIR(c, s);
    SHUT_OK(c, SD_BOTH);
    SHUT_OK(s, SD_BOTH);
    RECV_FAILS_SHUTDOWN(s);
    SEND_FAILS_SHUTDOWN(s);
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_both_keeps_names)
{
    NEED_NET();
    SOCKET c, s;
    struct sockaddr_in a, cn, sn;
    int l;
    NEED_PAIR(c, s);
    l = sizeof sn; getsockname(s, (struct sockaddr *)&sn, &l);
    l = sizeof cn; getsockname(c, (struct sockaddr *)&cn, &l);
    SHUT_OK(c, SD_BOTH);
    SHUT_OK(s, SD_BOTH);
    l = sizeof a;
    EXPECT_EQ(getpeername(c, (struct sockaddr *)&a, &l), 0);
    CHECK(!memcmp(&a, &sn, sizeof sn));
    l = sizeof a;
    EXPECT_EQ(getpeername(s, (struct sockaddr *)&a, &l), 0);
    CHECK(!memcmp(&a, &cn, sizeof cn));
    closesocket(c);
    closesocket(s);
}

/* Data sent to a peer that already closed is answered with a reset; the sender then sees an
 * aborted connection on its next receive. */
TEST(shutdown_send_to_closed_peer_then_recv_is_aborted)
{
    NEED_NET();
    SOCKET c, s;
    char b[5];
    int r;
    NEED_PAIR(c, s);
    SHUT_OK(c, SD_SEND);
    closesocket(c);
    EXPECT_EQ(send(s, PAYLOAD, 5, 0), 5);
    h9_readable(s, 4000);              /* EOF and/or the reset make the socket readable */
    WSASetLastError(POISON);
    r = recv(s, b, sizeof b, 0);
    CHECK(r == -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNABORTED);
    closesocket(s);
}

TEST(shutdown_receive_with_pending_overlapped_recv)
{
    NEED_NET();
    SOCKET c, s;
    OVERLAPPED ov;
    WSABUF wb;
    char b[5];
    DWORD size = 0, flags = 0;
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    h9_nonblock(c, 1);
    wb.buf = b;
    wb.len = sizeof b;
    WSASetLastError(POISON);
    CHECK(WSARecv(c, &wb, 1, &size, &flags, (LPWSAOVERLAPPED)&ov, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), ERROR_IO_PENDING);

    EXPECT_EQ(shutdown(c, SD_RECEIVE), 0);

    /* A new receive on the shut-down direction fails at once ... */
    WSASetLastError(POISON);
    CHECK(WSARecv(c, &wb, 1, &size, &flags, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);

    /* ... but the receive issued earlier still gets the data the peer sends. */
    EXPECT_EQ(send(s, PAYLOAD, 5, 0), 5);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    size = POISON;
    CHECK(GetOverlappedResult((HANDLE)c, &ov, &size, FALSE));
    EXPECT_EQ(size, 5);
    CHECK(!strcmp(b, "test"));

    WSASetLastError(POISON);
    CHECK(WSARecv(c, &wb, 1, &size, &flags, (LPWSAOVERLAPPED)&ov, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);

    /* A peer's receive pending on the other end completes with zero bytes once we shut down sending. */
    WSASetLastError(POISON);
    CHECK(WSARecv(s, &wb, 1, &size, &flags, (LPWSAOVERLAPPED)&ov, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    size = POISON;
    CHECK(GetOverlappedResult((HANDLE)s, &ov, &size, FALSE));
    EXPECT_EQ(size, 0);

    CloseHandle(ov.hEvent);
    closesocket(c);
    closesocket(s);
}

TEST(shutdown_listening_socket_is_notconn)
{
    NEED_NET();
    struct sockaddr_in a;
    SOCKET l = h9_listener(&a, 1, SOCK_STREAM);
    REQUIRE(l != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(shutdown(l, SD_SEND) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    WSASetLastError(POISON);
    CHECK(shutdown(l, SD_RECEIVE) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(l);
}

TEST(shutdown_udp_receive_blocks_recvfrom)
{
    NEED_NET();
    struct sockaddr_in a;
    SOCKET srv = h9_listener(&a, 0, SOCK_DGRAM);
    char b[5];
    REQUIRE(srv != INVALID_SOCKET);
    h9_nonblock(srv, 1);
    SHUT_OK(srv, SD_RECEIVE);
    WSASetLastError(POISON);
    CHECK(recvfrom(srv, b, sizeof b, 0, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    closesocket(srv);
}

TEST(shutdown_udp_send_blocks_sendto)
{
    NEED_NET();
    struct sockaddr_in a;
    SOCKET srv = h9_listener(&a, 0, SOCK_DGRAM);
    SOCKET cli = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(srv != INVALID_SOCKET && cli != INVALID_SOCKET);
    EXPECT_EQ(sendto(cli, PAYLOAD, 5, 0, (struct sockaddr *)&a, sizeof a), 5);
    SHUT_OK(cli, SD_SEND);
    SHUT_OK(cli, SD_SEND);
    WSASetLastError(POISON);
    CHECK(sendto(cli, PAYLOAD, 5, 0, (struct sockaddr *)&a, sizeof a) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    closesocket(cli);
    closesocket(srv);
}

/* The datagram sent before the half-close is still delivered to a receiver that was not shut down. */
TEST(shutdown_udp_send_does_not_discard_earlier_datagram)
{
    NEED_NET();
    struct sockaddr_in a;
    SOCKET srv = h9_listener(&a, 0, SOCK_DGRAM);
    SOCKET cli = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    char b[8] = { 0 };
    REQUIRE(srv != INVALID_SOCKET && cli != INVALID_SOCKET);
    EXPECT_EQ(sendto(cli, PAYLOAD, 5, 0, (struct sockaddr *)&a, sizeof a), 5);
    SHUT_OK(cli, SD_SEND);
    EXPECT_EQ(h9_recv(srv, b, sizeof b), 5);
    CHECK(!strcmp(b, "test"));
    closesocket(cli);
    closesocket(srv);
}
