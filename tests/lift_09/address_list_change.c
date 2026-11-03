/* SIO_ADDRESS_LIST_CHANGE: how the ioctl behaves for each combination of blocking mode, overlapped
 * socket flag and overlapped structure, and how a pending request is cancelled when the socket closes.
 * Waiting for a real address change is not exercised: the guest's address list does not change. */
#include "h9.h"

/* Operations stay pending until the socket is closed, so the OVERLAPPED must outlive the test body. */
static OVERLAPPED g_ov;

static SOCKET bound_tcp(DWORD flags, int use_wsasocket, int nonblocking)
{
    struct sockaddr_in a;
    SOCKET s = use_wsasocket ? WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags)
                             : socket(AF_INET, 0, IPPROTO_TCP);
    h9_loop_addr(&a);
    if (s == INVALID_SOCKET) return s;
    if (bind(s, (struct sockaddr *)&a, sizeof a)) { closesocket(s); return INVALID_SOCKET; }
    h9_nonblock(s, nonblocking);
    return s;
}

/* Request a change notification with an OVERLAPPED; it must be left pending; closing aborts it. */
static void pending_then_closed(SOCKET s)
{
    DWORD n = 0;
    int r;
    memset(&g_ov, 0, sizeof g_ov);
    g_ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(POISON);
    r = WSAIoctl(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, (LPWSAOVERLAPPED)&g_ov, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_IO_PENDING);
    closesocket(s);
    EXPECT_EQ(WaitForSingleObject(g_ov.hEvent, 3000), WAIT_OBJECT_0);   /* the close completes the request */
    CloseHandle(g_ov.hEvent);
}

TEST(addresslistchange_default_socket_nonblocking_overlapped_is_pending)
{
    NEED_NET();
    SOCKET s = bound_tcp(0, 0, 1);
    REQUIRE(s != INVALID_SOCKET);
    pending_then_closed(s);
}

TEST(addresslistchange_default_socket_blocking_overlapped_is_pending)
{
    NEED_NET();
    SOCKET s = bound_tcp(0, 0, 0);
    REQUIRE(s != INVALID_SOCKET);
    pending_then_closed(s);
}

TEST(addresslistchange_overlapped_flag_nonblocking_is_pending)
{
    NEED_NET();
    SOCKET s = bound_tcp(WSA_FLAG_OVERLAPPED, 1, 1);
    REQUIRE(s != INVALID_SOCKET);
    pending_then_closed(s);
}

TEST(addresslistchange_overlapped_flag_blocking_is_pending)
{
    NEED_NET();
    SOCKET s = bound_tcp(WSA_FLAG_OVERLAPPED, 1, 0);
    REQUIRE(s != INVALID_SOCKET);
    pending_then_closed(s);
}

/* Without an OVERLAPPED a nonblocking socket reports would-block rather than waiting. */
TEST(addresslistchange_nonblocking_without_overlapped_is_wouldblock)
{
    NEED_NET();
    DWORD n = 0;
    int r;
    SOCKET s = bound_tcp(WSA_FLAG_OVERLAPPED, 1, 1);
    REQUIRE(s != INVALID_SOCKET);
    SetLastError(POISON);
    r = WSAIoctl(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAEWOULDBLOCK);
    closesocket(s);
}

/* A pending request posts nothing to the port while it waits; closing the socket posts one aborted packet. */
TEST(addresslistchange_close_posts_aborted_packet_to_port)
{
    NEED_NET();
    DWORD n = 0;
    int r;
    struct h9_dq q;
    HANDLE port;
    SOCKET s = bound_tcp(WSA_FLAG_OVERLAPPED, 1, 1);
    REQUIRE(s != INVALID_SOCKET);
    port = CreateIoCompletionPort((HANDLE)s, NULL, 0, 0);
    REQUIRE(port != NULL);
    memset(&g_ov, 0, sizeof g_ov);
    SetLastError(POISON);
    r = WSAIoctl(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, (LPWSAOVERLAPPED)&g_ov, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_IO_PENDING);

    h9_dequeue(port, 200, &q);
    CHECK(!q.ok);
    EXPECT_EQ(q.err, WAIT_TIMEOUT);
    CHECK(q.ov == NULL);

    closesocket(s);
    h9_dequeue(port, 3000, &q);
    CHECK(!q.ok);
    EXPECT_EQ(q.err, ERROR_OPERATION_ABORTED);
    CHECK(q.ov == &g_ov);
    CloseHandle(port);
}

TEST(addresslistchange_event_select_flag_is_accepted)
{
    NEED_NET();
    WSAEVENT ev;
    SOCKET s = bound_tcp(WSA_FLAG_OVERLAPPED, 1, 1);
    REQUIRE(s != INVALID_SOCKET);
    ev = WSACreateEvent();
    EXPECT_EQ(WSAEventSelect(s, ev, FD_ADDRESS_LIST_CHANGE), 0);
    closesocket(s);
    WSACloseEvent(ev);
}
