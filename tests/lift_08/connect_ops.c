/* connect() and the ConnectEx extension: invalid socket states, overlapped result codes, initial
 * data sent with the connection, behaviour on already-connected sockets and after a refusal.  The
 * refused-connection cases use an ephemeral loopback port that was bound and released.
 */
#include "l8.h"

struct cx {
    SOCKET lst;
    struct sockaddr_in addr;
    LPFN_CONNECTEX connectex;
    OVERLAPPED ov;
};

static int cx_open(struct cx *c)
{
    GUID g = WSAID_CONNECTEX;
    SOCKET probe;
    memset(c, 0, sizeof *c);
    c->lst = l8_listener(&c->addr, 1);
    probe = w_socket(AF_INET, SOCK_STREAM, 0);
    c->connectex = (LPFN_CONNECTEX)l8_ext(probe, g);
    w_closesocket(probe);
    c->ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    return c->connectex != NULL;
}

static void cx_close(struct cx *c)
{
    w_closesocket(c->lst);
    if (c->ov.hEvent) CloseHandle(c->ov.hEvent);
}

/* New TCP socket bound to a loopback ephemeral port (ConnectEx needs a bound socket). */
static SOCKET bound_socket(void)
{
    struct sockaddr_in a = l8_lo4();
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    CHECK(w_bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    return s;
}

#define CX_FIXTURE(c) \
    NEED_WS(); \
    if (!cx_open(&(c))) { cx_close(&(c)); t_skip("ConnectEx extension not offered"); return; }

/* Call ConnectEx with a sentinel-initialised OVERLAPPED and check the failure shape: the call
 * fails, Internal reads "pending" because it was set before validation, and InternalHigh is left alone. */
static void connectex_expect_fail(struct cx *c, SOCKET s, int wsaerr)
{
    BOOL ok;
    DWORD ret = 0;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.Internal = 0xdeadbeef;
    ov.InternalHigh = 0xdeadbeef;
    w_WSASetLastError(0);
    ok = c->connectex(s, (struct sockaddr *)&c->addr, sizeof c->addr, NULL, 0, &ret, &ov);
    L8_EQ(ok, FALSE);
    L8_EQ(w_WSAGetLastError(), wsaerr);
    L8_EQ((ULONG)ov.Internal, XS_PENDING);
    L8_EQ(ov.InternalHigh, 0xdeadbeef);
}

TEST(l8_connect_to_listening_socket_is_einval)
{
    struct cx c;
    CX_FIXTURE(c);
    w_WSASetLastError(0);
    L8_EQ(w_connect(c.lst, (struct sockaddr *)&c.addr, sizeof c.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    cx_close(&c);
}

TEST(l8_connectex_on_listening_socket_is_einval)
{
    struct cx c;
    CX_FIXTURE(c);
    connectex_expect_fail(&c, c.lst, WSAEINVAL);
    cx_close(&c);
}

TEST(l8_connectex_invalid_socket_is_enotsock)
{
    struct cx c;
    DWORD ret;
    CX_FIXTURE(c);
    w_WSASetLastError(0);
    L8_EQ(c.connectex(INVALID_SOCKET, (struct sockaddr *)&c.addr, sizeof c.addr, NULL, 0, &ret, &c.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), WSAENOTSOCK);
    cx_close(&c);
}

TEST(l8_connectex_unbound_socket_is_einval)
{
    struct cx c;
    SOCKET s;
    DWORD ret;
    CX_FIXTURE(c);
    s = w_socket(AF_INET, SOCK_STREAM, 0);
    w_WSASetLastError(0);
    L8_EQ(c.connectex(s, (struct sockaddr *)&c.addr, sizeof c.addr, NULL, 0, &ret, &c.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    w_closesocket(s);
    cx_close(&c);
}

TEST(l8_connectex_requires_overlapped)
{
    struct cx c;
    SOCKET s;
    DWORD ret;
    CX_FIXTURE(c);
    s = bound_socket();
    w_WSASetLastError(0);
    L8_EQ(c.connectex(s, (struct sockaddr *)&c.addr, sizeof c.addr, NULL, 0, &ret, NULL), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_INVALID_PARAMETER);
    w_closesocket(s);
    cx_close(&c);
}

TEST(l8_connectex_completes_without_data)
{
    struct cx c;
    SOCKET s, a;
    DWORD ret = 0xdeadbeef;
    CX_FIXTURE(c);
    s = bound_socket();
    w_WSASetLastError(0);
    L8_EQ(c.connectex(s, (struct sockaddr *)&c.addr, sizeof c.addr, NULL, 0, &ret, &c.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ(WaitForSingleObject(c.ov.hEvent, 10000), WAIT_OBJECT_0);
    ret = 0xdeadbeef;
    CHECK(GetOverlappedResult((HANDLE)s, &c.ov, &ret, FALSE));
    L8_EQ(ret, 0);
    a = w_accept(c.lst, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    w_closesocket(a);
    w_closesocket(s);
    cx_close(&c);
}

TEST(l8_connectex_sends_initial_data)
{
    struct cx c;
    SOCKET s, a;
    char buf[8] = "123";
    DWORD ret = 0;
    CX_FIXTURE(c);
    s = bound_socket();
    w_WSASetLastError(0);
    L8_EQ(c.connectex(s, (struct sockaddr *)&c.addr, sizeof c.addr, buf, 3, &ret, &c.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ(WaitForSingleObject(c.ov.hEvent, 10000), WAIT_OBJECT_0);
    ret = 0xdeadbeef;
    CHECK(GetOverlappedResult((HANDLE)s, &c.ov, &ret, FALSE));
    L8_EQ(ret, 3);
    a = w_accept(c.lst, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    memset(buf, 0, sizeof buf);
    L8_EQ(l8_wait_recv(a, buf, 3), 3);
    CHECK(!memcmp(buf, "123", 3));
    w_closesocket(a);
    w_closesocket(s);
    cx_close(&c);
}

/* A socket connected by ConnectEx behaves as unconnected for connect() until its connect context is
 * updated, while the accepted peer is an ordinary connected socket. */
TEST(l8_connect_state_after_connectex)
{
    struct cx c;
    SOCKET s, a;
    DWORD ret = 0;
    CX_FIXTURE(c);
    s = bound_socket();
    CHECK(c.connectex(s, (struct sockaddr *)&c.addr, sizeof c.addr, NULL, 0, &ret, &c.ov) == FALSE);
    L8_EQ(WaitForSingleObject(c.ov.hEvent, 10000), WAIT_OBJECT_0);
    a = w_accept(c.lst, NULL, NULL);

    w_WSASetLastError(0);
    L8_EQ(w_connect(s, (struct sockaddr *)&c.addr, sizeof c.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    w_WSASetLastError(0);
    L8_EQ(w_connect(a, (struct sockaddr *)&c.addr, sizeof c.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEISCONN);

    connectex_expect_fail(&c, s, WSAEISCONN);
    connectex_expect_fail(&c, a, WSAEISCONN);
    w_closesocket(a);
    w_closesocket(s);
    cx_close(&c);
}

TEST(l8_connect_on_connected_pair_is_eisconn)
{
    struct cx c;
    SOCKET s, a;
    CX_FIXTURE(c);
    l8_pair(&s, &a, 0);
    w_WSASetLastError(0);
    L8_EQ(w_connect(s, (struct sockaddr *)&c.addr, sizeof c.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEISCONN);
    w_WSASetLastError(0);
    L8_EQ(w_connect(a, (struct sockaddr *)&c.addr, sizeof c.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEISCONN);
    connectex_expect_fail(&c, s, WSAEISCONN);
    connectex_expect_fail(&c, a, WSAEISCONN);
    w_closesocket(s);
    w_closesocket(a);
    cx_close(&c);
}

TEST(l8_connectex_refused_completes_with_error)
{
    struct cx c;
    struct sockaddr_in dead = l8_dead_port();
    SOCKET s;
    DWORD ret = 0;
    CX_FIXTURE(c);
    s = bound_socket();
    SetLastError(0);
    L8_EQ(c.connectex(s, (struct sockaddr *)&dead, sizeof dead, NULL, 0, &ret, &c.ov), FALSE);
    L8_EQ(GetLastError(), ERROR_IO_PENDING);
    L8_EQ(WaitForSingleObject(c.ov.hEvent, 10000), WAIT_OBJECT_0);
    SetLastError(0);
    L8_EQ(GetOverlappedResult((HANDLE)s, &c.ov, &ret, FALSE), FALSE);
    EXPECT_ERR(ERROR_CONNECTION_REFUSED);
    w_closesocket(s);
    cx_close(&c);
}

TEST(l8_connect_usable_after_refusal)
{
    struct cx c;
    struct sockaddr_in dead = l8_dead_port();
    SOCKET s, a;
    CX_FIXTURE(c);
    s = w_socket(AF_INET, SOCK_STREAM, 0);
    L8_EQ(w_connect(s, (struct sockaddr *)&dead, sizeof dead), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAECONNREFUSED);

    l8_nonblocking(s, TRUE);
    L8_EQ(w_connect(s, (struct sockaddr *)&c.addr, sizeof c.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEWOULDBLOCK);
    a = w_accept(c.lst, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    w_closesocket(a);
    w_closesocket(s);
    cx_close(&c);
}
