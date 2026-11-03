/* AcceptEx / GetAcceptExSockaddrs: argument and socket-state validation, the address-length
 * protocol (lengths are only checked when a connection completes), completion codes, behaviour with
 * initial receive data, deferred connections, peer disconnect, and abort on close.  The listener is
 * a nonblocking loopback TCP socket on an ephemeral port.
 */
#include "l8.h"

#define ADDRLEN ((DWORD)(sizeof(struct sockaddr_in) + 16))

struct ax {
    SOCKET lst;
    struct sockaddr_in addr;
    LPFN_ACCEPTEX acceptex;
    LPFN_GETACCEPTEXSOCKADDRS getaddrs;
    LPFN_CONNECTEX connectex;
    OVERLAPPED ov;
    char buf[1024];
};

static int ax_open(struct ax *a, int listening)
{
    GUID ga = WSAID_ACCEPTEX, gs = WSAID_GETACCEPTEXSOCKADDRS, gc = WSAID_CONNECTEX;
    memset(a, 0, sizeof *a);
    a->lst = l8_listener(&a->addr, listening ? 5 : 0);
    l8_nonblocking(a->lst, TRUE);
    a->acceptex = (LPFN_ACCEPTEX)l8_ext(a->lst, ga);
    a->getaddrs = (LPFN_GETACCEPTEXSOCKADDRS)l8_ext(a->lst, gs);
    a->connectex = (LPFN_CONNECTEX)l8_ext(a->lst, gc);
    a->ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    return a->acceptex && a->getaddrs && a->connectex;
}

/* Closing the listener aborts whatever is still pending; wait briefly so the OVERLAPPED is idle. */
static void ax_close(struct ax *a)
{
    CancelIo((HANDLE)a->lst);
    w_closesocket(a->lst);
    WaitForSingleObject(a->ov.hEvent, 100);
    CloseHandle(a->ov.hEvent);
}

static void ax_cancel(struct ax *a)
{
    CancelIo((HANDLE)a->lst);
    WaitForSingleObject(a->ov.hEvent, 1000);
}

static BOOL ax_call(struct ax *a, SOCKET listener, SOCKET acc, void *buf, DWORD rl, DWORD ll, DWORD rr, OVERLAPPED *ov)
{
    DWORD n = 0;
    return a->acceptex(listener, acc, buf, rl, ll, rr, &n, ov);
}

/* An AcceptEx call that must return FALSE with `err`; Internal is "pending" in every case. */
static void ax_expect(struct ax *a, SOCKET listener, SOCKET acc, void *buf, DWORD rl, DWORD ll, DWORD rr, int err)
{
    BOOL r;
    a->ov.Internal = 0xdeadbeef;
    w_WSASetLastError(0);
    r = ax_call(a, listener, acc, buf, rl, ll, rr, &a->ov);
    L8_EQ(r, FALSE);
    L8_EQ(w_WSAGetLastError(), err);
    L8_EQ((ULONG)a->ov.Internal, XS_PENDING);
    if (err == ERROR_IO_PENDING) ax_cancel(a);
}

/* Blocking connect to the listener; *local receives the connecting socket's own address. */
static SOCKET ax_peer(struct ax *a, struct sockaddr_in *local)
{
    int len = sizeof *local;
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(w_connect(s, (struct sockaddr *)&a->addr, sizeof a->addr) == 0);
    if (local) CHECK(w_getsockname(s, (struct sockaddr *)local, &len) == 0);
    return s;
}

#define AX_FIXTURE(a, listening) \
    NEED_WS(); \
    if (!ax_open(&(a), (listening))) { ax_close(&(a)); t_skip("mswsock extensions not offered"); return; }

TEST(l8_acceptex_invalid_listener_is_enotsock)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    ax_expect(&a, INVALID_SOCKET, acc, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, WSAENOTSOCK);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_non_listening_socket_is_einval)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 0);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    ax_expect(&a, a.lst, acc, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, WSAEINVAL);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_invalid_accept_socket_is_enotsock)
{
    struct ax a;
    AX_FIXTURE(a, 1);
    ax_expect(&a, a.lst, INVALID_SOCKET, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, WSAENOTSOCK);
    ax_close(&a);
}

TEST(l8_acceptex_null_buffer_is_efault)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    ax_expect(&a, a.lst, acc, NULL, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, WSAEFAULT);
    w_closesocket(acc);
    ax_close(&a);
}

/* A zero local-address length is not rejected up front: the call goes pending, and on completion
 * GetAcceptExSockaddrs reports only the remote address. */
TEST(l8_acceptex_zero_local_length_pends_and_completes)
{
    struct ax a;
    SOCKET acc, peer;
    struct sockaddr_in local, *pl, *pr;
    int ll, rl;
    DWORD got = 0xdeadbeef;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    a.ov.Internal = 0xdeadbeef;
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, 0, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ((ULONG)a.ov.Internal, XS_PENDING);

    peer = ax_peer(&a, &local);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE));
    L8_EQ((ULONG)a.ov.Internal, XS_SUCCESS);
    L8_EQ(got, 0);

    pl = pr = (struct sockaddr_in *)0xdeadbeef;
    ll = rl = (int)0xdeadbeef;
    a.getaddrs(a.buf, 0, 0, ADDRLEN, (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
    L8_EQ(pl, 0xdeadbeef);     /* local address untouched */
    L8_EQ(ll, (int)0xdeadbeef);
    CHECK(!memcmp(pr, &local, sizeof local));
    L8_EQ(rl, sizeof(struct sockaddr_in));
    w_closesocket(peer);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_datagram_accept_socket_is_einval)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ax_expect(&a, a.lst, acc, a.buf, 0, 0, ADDRLEN, WSAEINVAL);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_bound_accept_socket_is_einval)
{
    struct ax a;
    SOCKET acc;
    struct sockaddr_in b = l8_lo4();
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(w_bind(acc, (struct sockaddr *)&b, sizeof b) == 0);
    ax_expect(&a, a.lst, acc, a.buf, 0, 0, ADDRLEN, WSAEINVAL);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_connected_accept_socket_is_einval)
{
    struct ax a;
    SOCKET c, s;
    AX_FIXTURE(a, 1);
    l8_pair(&c, &s, 0);
    ax_expect(&a, a.lst, c, a.buf, 0, 0, ADDRLEN, WSAEINVAL);
    ax_expect(&a, a.lst, s, a.buf, 0, 0, ADDRLEN, WSAEINVAL);
    w_closesocket(c);
    w_closesocket(s);
    ax_close(&a);
}

/* Address-length checks happen at completion: the connection is consumed and the operation fails. */
static void short_length_case(DWORD local_len)
{
    struct ax a;
    SOCKET acc, peer, extra;
    DWORD got = 0xdeadbeef;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    a.ov.Internal = 0xdeadbeef;
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, local_len, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ((ULONG)a.ov.Internal, XS_PENDING);

    peer = ax_peer(&a, NULL);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    SetLastError(0);
    L8_EQ(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    L8_EQ((ULONG)a.ov.Internal, XS_BUFFER_TOO_SMALL);
    L8_EQ(got, 0);
    w_closesocket(acc);

    /* The failed operation did not take the connection off the queue. */
    extra = w_accept(a.lst, NULL, NULL);
    CHECK(extra != INVALID_SOCKET);
    w_closesocket(extra);
    w_closesocket(peer);
    ax_close(&a);
}

TEST(l8_acceptex_local_length_3_fails_at_completion)    { short_length_case(3); }
TEST(l8_acceptex_local_length_20_fails_at_completion)   { short_length_case(sizeof(struct sockaddr_in) + 4); }

TEST(l8_acceptex_local_length_31_pends)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ax_expect(&a, a.lst, acc, a.buf, 0, sizeof(struct sockaddr_in) + 15, ADDRLEN, ERROR_IO_PENDING);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_zero_remote_length_is_efault)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ax_expect(&a, a.lst, acc, a.buf, 0, ADDRLEN, 0, WSAEFAULT);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_remote_length_31_pends)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ax_expect(&a, a.lst, acc, a.buf, 0, ADDRLEN, sizeof(struct sockaddr_in) + 15, ERROR_IO_PENDING);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_requires_overlapped)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, ADDRLEN, ADDRLEN, NULL), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_INVALID_PARAMETER);
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, 0, 0, NULL), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_INVALID_PARAMETER);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_pending_socket_is_busy)
{
    struct ax a;
    SOCKET acc, peer;
    OVERLAPPED ov2;
    struct sockaddr_in peer_local;
    int len = sizeof peer_local;
    DWORD got = 0xdeadbeef;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    a.ov.Internal = 0xdeadbeef;
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ((ULONG)a.ov.Internal, XS_PENDING);

    /* The same socket cannot be queued twice, nor used to connect while it waits to accept. */
    a.ov.Internal = 0xdeadbeef;
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    L8_EQ((ULONG)a.ov.Internal, XS_PENDING);

    w_WSASetLastError(0);
    L8_EQ(w_connect(acc, (struct sockaddr *)&a.addr, sizeof a.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);

    memset(&ov2, 0, sizeof ov2);
    w_WSASetLastError(0);
    L8_EQ(a.connectex(acc, (struct sockaddr *)&a.addr, sizeof a.addr, NULL, 0, &got, &ov2), FALSE);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);

    peer = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    a.ov.Internal = 0xdeadbeef;
    L8_EQ(w_connect(peer, (struct sockaddr *)&a.addr, sizeof a.addr), 0);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    L8_EQ((ULONG)a.ov.Internal, XS_SUCCESS);
    CHECK(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE));
    L8_EQ(got, 0);

    /* The accepted socket answers getsockname only after its accept context is updated. */
    L8_EQ(w_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&a.lst, sizeof a.lst), 0);
    L8_EQ(w_getsockname(acc, (struct sockaddr *)&peer_local, &len), 0);
    L8_EQ(len, sizeof(struct sockaddr_in));
    w_closesocket(peer);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_waits_for_initial_data_and_decodes_addresses)
{
    struct ax a;
    SOCKET acc, peer;
    struct sockaddr_in local, *pl, *pr;
    int ll = sizeof local, rl = sizeof local;
    DWORD got = 0xdeadbeef;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    peer = w_socket(AF_INET, SOCK_STREAM, 0);
    a.ov.Internal = 0xdeadbeef;
    w_WSASetLastError(0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 2, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ((ULONG)a.ov.Internal, XS_PENDING);

    /* A connection alone does not complete a call that asked for receive data. */
    L8_EQ(w_connect(peer, (struct sockaddr *)&a.addr, sizeof a.addr), 0);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 0), WAIT_TIMEOUT);
    L8_EQ((ULONG)a.ov.Internal, XS_PENDING);
    {
        int len = sizeof local;
        L8_EQ(w_getsockname(peer, (struct sockaddr *)&local, &len), 0);
    }

    L8_EQ(w_send(peer, a.buf, 1, 0), 1);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    L8_EQ((ULONG)a.ov.Internal, XS_SUCCESS);

    a.getaddrs(a.buf, 2, ADDRLEN, ADDRLEN, (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
    L8_EQ(pl->sin_addr.s_addr, a.addr.sin_addr.s_addr);
    L8_EQ(pl->sin_port, a.addr.sin_port);
    L8_EQ(pr->sin_addr.s_addr, local.sin_addr.s_addr);
    L8_EQ(pr->sin_port, local.sin_port);
    L8_EQ(ll, sizeof(struct sockaddr_in));
    L8_EQ(rl, sizeof(struct sockaddr_in));

    CHECK(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE));
    L8_EQ(got, 1);
    w_closesocket(peer);
    w_closesocket(acc);
    ax_close(&a);
}

static int CALLBACK always_defer(LPWSABUF caller_id, LPWSABUF caller_data, LPQOS qos, LPQOS gqos,
                                 LPWSABUF callee_id, LPWSABUF callee_data, GROUP *g, DWORD_PTR user)
{
    return CF_DEFER;
}

/* A connection deferred by a WSAAccept condition function stays queued; AcceptEx later takes the
 * oldest queued connection, not the one a plain accept() takes afterwards. */
TEST(l8_acceptex_takes_oldest_queued_connection)
{
    struct ax a;
    SOCKET acc, c1, c2, got;
    fd_set rd, wr;
    struct timeval tmo = { 3, 0 };
    char b[4];
    DWORD n = 0xdeadbeef;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    c1 = w_socket(AF_INET, SOCK_STREAM, 0);
    c2 = w_socket(AF_INET, SOCK_STREAM, 0);
    l8_nonblocking(c1, TRUE);
    l8_nonblocking(c2, TRUE);

    L8_EQ(w_connect(c1, (struct sockaddr *)&a.addr, sizeof a.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEWOULDBLOCK);
    FD_ZERO(&rd); FD_SET(a.lst, &rd);
    L8_EQ(w_select(0, &rd, NULL, NULL, &tmo), 1);

    got = w_WSAAccept(a.lst, NULL, NULL, always_defer, 0);
    L8_EQ(got, INVALID_SOCKET);
    L8_EQ(w_WSAGetLastError(), WSATRY_AGAIN);

    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 0, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);

    FD_ZERO(&wr); FD_SET(c1, &wr);
    L8_EQ(w_select(0, NULL, &wr, NULL, &tmo), 1);
    L8_EQ(w_send(c1, "1", 1, 0), 1);

    L8_EQ(w_connect(c2, (struct sockaddr *)&a.addr, sizeof a.addr), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEWOULDBLOCK);
    FD_ZERO(&rd); FD_SET(a.lst, &rd);
    L8_EQ(w_select(0, &rd, NULL, NULL, &tmo), 1);

    got = w_accept(a.lst, NULL, NULL);
    CHECK(got != INVALID_SOCKET);
    w_closesocket(got);

    FD_ZERO(&wr); FD_SET(c2, &wr);
    L8_EQ(w_select(0, NULL, &wr, NULL, &tmo), 1);
    L8_EQ(w_send(c2, "2", 1, 0), 1);

    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)a.lst, &a.ov, &n, FALSE));
    L8_EQ(n, 0);

    l8_nonblocking(acc, FALSE);
    memset(b, 0, sizeof b);
    L8_EQ(l8_wait_recv(acc, b, 2), 1);
    L8_EQ(b[0], '1');

    w_closesocket(c1);
    w_closesocket(c2);
    w_closesocket(acc);
    while ((got = w_accept(a.lst, NULL, NULL)) != INVALID_SOCKET) w_closesocket(got);
    ax_close(&a);
}

TEST(l8_acceptex_peer_disconnect_before_data_still_completes)
{
    struct ax a;
    SOCKET acc, peer;
    DWORD got = 123456;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    peer = w_socket(AF_INET, SOCK_STREAM, 0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    L8_EQ(w_connect(peer, (struct sockaddr *)&a.addr, sizeof a.addr), 0);
    w_closesocket(peer);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE));
    L8_EQ(got, 0);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_closing_accept_socket_aborts_call)
{
    struct ax a;
    SOCKET acc;
    DWORD got = 0;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    w_closesocket(acc);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    SetLastError(0);
    L8_EQ(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE), FALSE);
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    ax_close(&a);
}

TEST(l8_acceptex_cancel_through_accept_socket_handle_has_no_effect)
{
    struct ax a;
    SOCKET acc;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    /* The operation belongs to the listener's handle; cancelling by the other handle leaves it pending. */
    CancelIo((HANDLE)acc);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 500), WAIT_TIMEOUT);
    w_closesocket(acc);
    ax_close(&a);
}

TEST(l8_acceptex_closing_listener_aborts_call)
{
    struct ax a;
    SOCKET acc;
    DWORD got = 0;
    AX_FIXTURE(a, 1);
    acc = w_socket(AF_INET, SOCK_STREAM, 0);
    L8_EQ(ax_call(&a, a.lst, acc, a.buf, 1024 - 2 * ADDRLEN, ADDRLEN, ADDRLEN, &a.ov), FALSE);
    L8_EQ(w_WSAGetLastError(), ERROR_IO_PENDING);
    w_closesocket(a.lst);
    L8_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    SetLastError(0);
    L8_EQ(GetOverlappedResult((HANDLE)a.lst, &a.ov, &got, FALSE), FALSE);
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    CloseHandle(a.ov.hEvent);
    w_closesocket(acc);
}
