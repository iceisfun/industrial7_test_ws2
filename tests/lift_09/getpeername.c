/* getpeername(): argument validation order (socket handle, connection state, then buffer arguments) and
 * the exact length protocol for a connected datagram socket. */
#include "h9.h"

/* A bound loopback UDP socket to use as the connect() target. */
static SOCKET udp_target(struct sockaddr_in *a) { return h9_listener(a, 0, SOCK_DGRAM); }

TEST(getpeername_invalid_socket_is_notsock)
{
    NEED_NET();
    WSASetLastError(POISON);
    CHECK(getpeername(INVALID_SOCKET, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(getpeername_unconnected_datagram_is_notconn)
{
    NEED_NET();
    SOCKET s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(getpeername(s, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);   /* connection state is checked before the buffers */
    closesocket(s);
}

TEST(getpeername_state_check_precedes_pointer_check)
{
    NEED_NET();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int len = 0;
    struct sockaddr_in out;
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(getpeername(s, (struct sockaddr *)&out, &len) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

/* sendto() on a datagram socket does not make it connected. */
TEST(getpeername_sendto_does_not_connect)
{
    NEED_NET();
    struct sockaddr_in t;
    SOCKET tgt = udp_target(&t), s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    static const char buf[] = "hello world";
    REQUIRE(tgt != INVALID_SOCKET && s != INVALID_SOCKET);
    CHECK(sendto(s, buf, sizeof buf, 0, (struct sockaddr *)&t, sizeof t) != SOCKET_ERROR);
    WSASetLastError(POISON);
    CHECK(getpeername(s, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
    closesocket(tgt);
}

TEST(getpeername_connected_zero_length_null_name_faults)
{
    NEED_NET();
    struct sockaddr_in t;
    SOCKET tgt = udp_target(&t), s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int len = 0;
    REQUIRE(tgt != INVALID_SOCKET && s != INVALID_SOCKET);
    connect(s, (struct sockaddr *)&t, sizeof t);
    WSASetLastError(POISON);
    CHECK(getpeername(s, NULL, &len) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(len, 0);               /* length is left alone when nothing can be written */
    closesocket(s);
    closesocket(tgt);
}

TEST(getpeername_connected_zero_length_with_buffer_faults)
{
    NEED_NET();
    struct sockaddr_in t;
    SOCKADDR_STORAGE ss;
    SOCKET tgt = udp_target(&t), s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int len = 0;
    REQUIRE(tgt != INVALID_SOCKET && s != INVALID_SOCKET);
    connect(s, (struct sockaddr *)&t, sizeof t);
    WSASetLastError(POISON);
    CHECK(getpeername(s, (struct sockaddr *)&ss, &len) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(len, 0);
    closesocket(s);
    closesocket(tgt);
}

TEST(getpeername_connected_returns_connect_address)
{
    NEED_NET();
    struct sockaddr_in t;
    SOCKADDR_STORAGE ss;
    SOCKET tgt = udp_target(&t), s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int len = sizeof ss;
    REQUIRE(tgt != INVALID_SOCKET && s != INVALID_SOCKET);
    connect(s, (struct sockaddr *)&t, sizeof t);
    EXPECT_EQ(getpeername(s, (struct sockaddr *)&ss, &len), 0);
    CHECK(!memcmp(&t, &ss, sizeof t));
    EXPECT_EQ(len, sizeof t);
    closesocket(s);
    closesocket(tgt);
}

TEST(getpeername_connected_exact_length_buffer)
{
    NEED_NET();
    struct sockaddr_in t, out;
    SOCKET tgt = udp_target(&t), s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int len = sizeof out;
    REQUIRE(tgt != INVALID_SOCKET && s != INVALID_SOCKET);
    connect(s, (struct sockaddr *)&t, sizeof t);
    EXPECT_EQ(getpeername(s, (struct sockaddr *)&out, &len), 0);
    EXPECT_EQ(len, sizeof out);
    CHECK(!memcmp(&t, &out, sizeof t));
    closesocket(s);
    closesocket(tgt);
}
