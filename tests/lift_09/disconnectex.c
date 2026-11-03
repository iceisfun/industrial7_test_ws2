/* DisconnectEx extension function (fetched through SIO_GET_EXTENSION_FUNCTION_POINTER): parameter and state
 * validation, overlapped and synchronous completion, and what the connection looks like afterwards
 * (send direction shut down, receive direction and remote address intact). */
#include "h9.h"

typedef BOOL (WINAPI *disconnectex_fn)(SOCKET, LPOVERLAPPED, DWORD, DWORD);

static disconnectex_fn get_disconnectex(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    GUID g = WSAID_DISCONNECTEX;
    disconnectex_fn f;
    if (s == INVALID_SOCKET) return NULL;
    f = (disconnectex_fn)h9_ext(s, g);
    closesocket(s);
    return f;
}

#define NEED_DISCONNECTEX(f) disconnectex_fn f = get_disconnectex(); \
    do { if (!f) { t_skip("DisconnectEx not provided"); return; } } while (0)

TEST(disconnectex_extension_pointer_is_stable)
{
    NEED_NET();
    disconnectex_fn a = get_disconnectex(), b = get_disconnectex();
    CHECK(a != NULL);
    CHECK(a == b);
}

TEST(disconnectex_invalid_socket_is_notsock)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    WSASetLastError(POISON);
    CHECK(!dx(INVALID_SOCKET, &ov, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

TEST(disconnectex_unconnected_is_notconn)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    OVERLAPPED ov;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    memset(&ov, 0, sizeof ov);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(!dx(s, &ov, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    WSASetLastError(POISON);
    CHECK(!dx(s, NULL, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

/* Common post-conditions: sending is shut down, the peer saw EOF, the peer can still talk to us and
 * the address queries still work. */
static void check_disconnected_state(SOCKET c, SOCKET s)
{
    char b[8] = { 0 };
    struct sockaddr_in a, cn, sn;
    int l = sizeof sn;
    getsockname(s, (struct sockaddr *)&sn, &l);

    WSASetLastError(POISON);
    CHECK(connect(c, (struct sockaddr *)&sn, sizeof sn) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEISCONN);

    WSASetLastError(POISON);
    CHECK(send(c, "test", 5, 0) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);

    EXPECT_EQ(h9_recv(s, b, 5), 0);
    EXPECT_EQ(send(s, "test", 5, 0), 5);
    EXPECT_EQ(h9_recv_all(c, b, 5), 5);
    CHECK(!strcmp(b, "test"));

    l = sizeof a;
    EXPECT_EQ(getpeername(c, (struct sockaddr *)&a, &l), 0);
    CHECK(!memcmp(&a, &sn, sizeof sn));
    l = sizeof cn;
    EXPECT_EQ(getsockname(c, (struct sockaddr *)&cn, &l), 0);
    l = sizeof a;
    EXPECT_EQ(getpeername(s, (struct sockaddr *)&a, &l), 0);
    CHECK(!memcmp(&a, &cn, sizeof cn));
}

TEST(disconnectex_overlapped_completes_with_zero_bytes)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    SOCKET c, s;
    OVERLAPPED ov;
    DWORD size;
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSASetLastError(POISON);
    CHECK(!dx(c, &ov, 0, 0));
    EXPECT_EQ(WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    size = POISON;
    CHECK(GetOverlappedResult((HANDLE)c, &ov, &size, FALSE));
    EXPECT_EQ(size, 0);
    CloseHandle(ov.hEvent);
    closesocket(c);
    closesocket(s);
}

TEST(disconnectex_overlapped_leaves_receive_direction_open)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    SOCKET c, s;
    OVERLAPPED ov;
    NEED_PAIR(c, s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(!dx(c, &ov, 0, 0));
    WaitForSingleObject(ov.hEvent, 3000);
    check_disconnected_state(c, s);
    CloseHandle(ov.hEvent);
    closesocket(c);
    closesocket(s);
}

TEST(disconnectex_synchronous_succeeds_without_error)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    SOCKET c, s;
    NEED_PAIR(c, s);
    WSASetLastError(POISON);
    CHECK(dx(c, NULL, 0, 0));
    CHECK(h9_err_clean());
    closesocket(c);
    closesocket(s);
}

TEST(disconnectex_synchronous_twice_succeeds)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    SOCKET c, s;
    NEED_PAIR(c, s);
    CHECK(dx(c, NULL, 0, 0));
    WSASetLastError(POISON);
    CHECK(dx(c, NULL, 0, 0));
    CHECK(h9_err_clean());
    closesocket(c);
    closesocket(s);
}

TEST(disconnectex_synchronous_leaves_receive_direction_open)
{
    NEED_NET();
    NEED_DISCONNECTEX(dx);
    SOCKET c, s;
    NEED_PAIR(c, s);
    CHECK(dx(c, NULL, 0, 0));
    CHECK(dx(c, NULL, 0, 0));
    check_disconnected_state(c, s);
    closesocket(c);
    closesocket(s);
}
