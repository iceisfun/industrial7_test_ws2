/* SIO_ROUTING_INTERFACE_QUERY via WSAIoctl: input and output buffer validation, the error code for each
 * kind of malformed destination address, required-size reporting, and the three completion modes
 * (plain, overlapped with a completion port, overlapped with an APC routine). */
#include "h9.h"

static SOCKET udp(void) { return socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }

static void loopback_dest(struct sockaddr_in *in)
{
    memset(in, 0, sizeof *in);
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = LOOPBACK_ADDR;
}

TEST(routingquery_missing_bytes_returned_pointer_faults)
{
    NEED_NET();
    struct sockaddr_in in, out;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    memset(&out, 0, sizeof out);
    WSASetLastError(POISON);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, NULL, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}

TEST(routingquery_short_input_is_inval)
{
    NEED_NET();
    struct sockaddr_in in, out;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in - 1, &out, sizeof out, &size, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(size, POISON);
    closesocket(s);
}

TEST(routingquery_null_input_is_inval)
{
    NEED_NET();
    struct sockaddr_in out;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, NULL, sizeof(struct sockaddr_in), &out, sizeof out, &size, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(size, POISON);
    closesocket(s);
}

TEST(routingquery_zero_family_is_afnosupport)
{
    NEED_NET();
    struct sockaddr_in in, out;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    memset(&in, 0, sizeof in);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, &size, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEAFNOSUPPORT);
    EXPECT_EQ(size, POISON);
    closesocket(s);
}

TEST(routingquery_unspecified_ipv4_address_is_inval)
{
    NEED_NET();
    struct sockaddr_in in, out;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    WSASetLastError(POISON);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, &size, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(size, POISON);
    closesocket(s);
}

TEST(routingquery_loopback_destination_succeeds)
{
    NEED_NET();
    struct sockaddr_in in, out;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    memset(&out, 0, sizeof out);
    WSASetLastError(POISON);
    EXPECT_EQ(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, &size, NULL, NULL), 0);
    EXPECT_EQ(WSAGetLastError(), 0);   /* success clears the error rather than leaving it alone */
    EXPECT_EQ(size, sizeof out);
    /* The reported source address is not checked: a loopback route is not guaranteed to exist. */
    closesocket(s);
}

TEST(routingquery_small_output_reports_required_size)
{
    NEED_NET();
    struct sockaddr_in in, out;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out - 1, &size, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(size, sizeof out);
    closesocket(s);
}

TEST(routingquery_null_output_faults)
{
    NEED_NET();
    struct sockaddr_in in;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, NULL, sizeof(struct sockaddr_in), &size, NULL, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(size, POISON);
    closesocket(s);
}

TEST(routingquery_overlapped_requires_bytes_returned)
{
    NEED_NET();
    struct sockaddr_in in, out;
    OVERLAPPED ov;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    memset(&ov, 0, sizeof ov);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, NULL, (LPWSAOVERLAPPED)&ov, NULL) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}

/* The query completes inline, yet a socket attached to a completion port still gets a packet. */
TEST(routingquery_overlapped_completion_port_packet)
{
    NEED_NET();
    struct sockaddr_in in, out;
    OVERLAPPED ov;
    struct h9_dq q;
    DWORD size = POISON;
    SOCKET s = udp();
    HANDLE port;
    REQUIRE(s != INVALID_SOCKET);
    port = CreateIoCompletionPort((HANDLE)s, NULL, 123, 0);
    REQUIRE(port != NULL);
    loopback_dest(&in);
    memset(&ov, 0, sizeof ov);
    ov.Internal = POISON;
    ov.InternalHigh = POISON;
    WSASetLastError(POISON);
    EXPECT_EQ(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, &size, (LPWSAOVERLAPPED)&ov, NULL), 0);
    EXPECT_EQ(WSAGetLastError(), 0);
    EXPECT_EQ(size, sizeof out);

    h9_dequeue(port, 2000, &q);
    CHECK(q.ok);
    EXPECT_EQ(q.bytes, 0);
    EXPECT_EQ(q.key, 123);
    CHECK(q.ov == &ov);
    EXPECT_EQ(ov.Internal, NT_SUCCESS_STATUS);
    EXPECT_EQ(ov.InternalHigh, 0);
    CloseHandle(port);
    closesocket(s);
}

TEST(routingquery_apc_requires_bytes_returned)
{
    NEED_NET();
    struct sockaddr_in in, out;
    OVERLAPPED ov;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    memset(&ov, 0, sizeof ov);
    CHECK(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, NULL, (LPWSAOVERLAPPED)&ov, (LPWSAOVERLAPPED_COMPLETION_ROUTINE)h9_apc) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}

TEST(routingquery_apc_runs_once_with_zero_size)
{
    NEED_NET();
    struct sockaddr_in in, out;
    OVERLAPPED ov;
    DWORD size = POISON;
    SOCKET s = udp();
    REQUIRE(s != INVALID_SOCKET);
    loopback_dest(&in);
    memset(&ov, 0, sizeof ov);
    h9_apc_count = 0;
    h9_apc_error = h9_apc_size = POISON;
    EXPECT_EQ(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof in, &out, sizeof out, &size,
                       (LPWSAOVERLAPPED)&ov, (LPWSAOVERLAPPED_COMPLETION_ROUTINE)h9_apc), 0);
    EXPECT_EQ(size, sizeof out);
    EXPECT_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    EXPECT_EQ(h9_apc_count, 1);
    EXPECT_EQ(h9_apc_error, 0);
    EXPECT_EQ(h9_apc_size, 0);
    EXPECT_EQ(h9_apc_flags, 0);
    CHECK(h9_apc_ov == &ov);
    closesocket(s);
}
