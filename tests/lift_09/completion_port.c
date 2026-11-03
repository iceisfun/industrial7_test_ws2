/* I/O completion port interaction with sockets: which operations post a packet and with which status,
 * error and byte count (resets, graceful close, immediate completion), and how pending AcceptEx
 * requests are aborted when the listening socket - or the last duplicate of it - is closed. */
#include "h9.h"

typedef BOOL (WINAPI *acceptex_fn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);

#define KEY 125
#define ADDR_SLOT (sizeof(struct sockaddr_in) + 16)
#define BUFSZ 1024

static acceptex_fn get_acceptex(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    GUID g = WSAID_ACCEPTEX;
    acceptex_fn f;
    if (s == INVALID_SOCKET) return NULL;
    f = (acceptex_fn)h9_ext(s, g);
    closesocket(s);
    return f;
}

static HANDLE new_port(void) { return CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); }
static int attach(SOCKET s, HANDLE port, ULONG_PTR key) { return CreateIoCompletionPort((HANDLE)s, port, key, 0) == port; }

/* A nonblocking loopback listener on an ephemeral port, backlog 5. */
static SOCKET iocp_listener(struct sockaddr_in *a)
{
    SOCKET s = h9_listener(a, 5, SOCK_STREAM);
    if (s != INVALID_SOCKET) h9_nonblock(s, 1);
    return s;
}

/* Issue AcceptEx with room for data plus both address slots; the request must be left pending. */
static void post_acceptex(acceptex_fn ax, SOCKET lst, SOCKET acc, char *buf, OVERLAPPED *ov)
{
    DWORD n = 0;
    BOOL r;
    memset(ov, 0, sizeof *ov);
    SetLastError(POISON);
    r = ax(lst, acc, buf, BUFSZ - 2 * ADDR_SLOT, ADDR_SLOT, ADDR_SLOT, &n, ov);
    CHECK(r == FALSE);
    EXPECT_EQ(GetLastError(), ERROR_IO_PENDING);
}

/* The next packet must be the cancellation of `ov` posted under KEY. */
static void expect_cancelled_packet(HANDLE port, OVERLAPPED *ov)
{
    struct h9_dq q;
    h9_dequeue(port, 3000, &q);
    CHECK(!q.ok);
    EXPECT_EQ(q.err, ERROR_OPERATION_ABORTED);
    EXPECT_EQ(q.key, KEY);
    EXPECT_EQ(q.bytes, 0);
    CHECK(q.ov == ov);
    CHECK(q.ov == ov && (ULONG)ov->Internal == NT_CANCELLED);
}

/* ---- receive and send completion ---------------------------------------------------------------- */

TEST(iocp_pending_recv_fails_with_netname_deleted_on_peer_reset)
{
    NEED_NET();
    SOCKET src, dst;
    HANDLE port = new_port();
    OVERLAPPED ov;
    WSABUF wb;
    char buf[BUFSZ];
    DWORD n = 0, flags = 0;
    struct h9_dq q;
    NEED_PAIR(src, dst);
    CHECK(attach(dst, port, KEY));
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    SetLastError(POISON);
    CHECK(WSARecv(dst, &wb, 1, &n, &flags, (LPWSAOVERLAPPED)&ov, NULL) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_IO_PENDING);

    h9_rst_close(src);
    h9_dequeue(port, 3000, &q);
    CHECK(!q.ok);
    EXPECT_EQ(q.err, ERROR_NETNAME_DELETED);
    EXPECT_EQ(q.key, KEY);
    EXPECT_EQ(q.bytes, 0);
    CHECK(q.ov == &ov);
    CHECK_QUEUE_EMPTY(port);
    closesocket(dst);
    CloseHandle(port);
}

TEST(iocp_send_after_peer_reset_fails_inline_without_packet)
{
    NEED_NET();
    SOCKET src, dst;
    HANDLE port = new_port();
    OVERLAPPED ov;
    WSABUF wb;
    char buf[BUFSZ] = { 0 };
    DWORD n = POISON;
    NEED_PAIR(src, dst);
    CHECK(attach(dst, port, KEY));
    h9_nonblock(dst, 1);
    h9_rst_close(src);
    h9_readable(dst, 3000);            /* the reset makes the socket readable */
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    SetLastError(POISON);
    CHECK(WSASend(dst, &wb, 1, &n, 0, (LPWSAOVERLAPPED)&ov, NULL) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAECONNRESET);
    EXPECT_EQ(n, POISON);
    CHECK_QUEUE_EMPTY(port);
    closesocket(dst);
    CloseHandle(port);
}

TEST(iocp_immediate_recv_posts_packet_with_byte_count)
{
    NEED_NET();
    SOCKET src, dst;
    HANDLE port = new_port();
    OVERLAPPED sov, rov;
    WSABUF wb;
    char buf[BUFSZ] = { 0 };
    DWORD n = POISON, flags = 0;
    struct h9_dq q;
    NEED_PAIR(src, dst);
    memset(&sov, 0, sizeof sov);
    memset(&rov, 0, sizeof rov);
    wb.buf = buf; wb.len = sizeof buf;
    EXPECT_EQ(WSASend(src, &wb, 1, &n, 0, (LPWSAOVERLAPPED)&sov, NULL), 0);
    EXPECT_EQ(n, sizeof buf);

    CHECK(attach(dst, port, KEY));
    h9_nonblock(dst, 1);
    CHECK(h9_readable(dst, 3000));
    n = POISON;
    EXPECT_EQ(WSARecv(dst, &wb, 1, &n, &flags, (LPWSAOVERLAPPED)&rov, NULL), 0);
    EXPECT_EQ(n, sizeof buf);

    h9_dequeue(port, 3000, &q);
    CHECK(q.ok);
    EXPECT_EQ(q.err, POISON);          /* a successful dequeue leaves the last error alone */
    EXPECT_EQ(q.key, KEY);
    EXPECT_EQ(q.bytes, sizeof buf);
    CHECK(q.ov == &rov);
    CHECK_QUEUE_EMPTY(port);
    closesocket(src);
    closesocket(dst);
    CloseHandle(port);
}

TEST(iocp_recv_after_graceful_close_posts_zero_byte_packet)
{
    NEED_NET();
    SOCKET src, dst;
    HANDLE port = new_port();
    OVERLAPPED ov;
    WSABUF wb;
    char buf[BUFSZ];
    DWORD n = POISON, flags = 0;
    struct h9_dq q;
    NEED_PAIR(src, dst);
    CHECK(attach(dst, port, KEY));
    h9_nonblock(dst, 1);
    closesocket(src);
    CHECK(h9_readable(dst, 3000));
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    EXPECT_EQ(WSARecv(dst, &wb, 1, &n, &flags, (LPWSAOVERLAPPED)&ov, NULL), 0);
    EXPECT_EQ(n, 0);

    h9_dequeue(port, 3000, &q);
    CHECK(q.ok);
    EXPECT_EQ(q.key, KEY);
    EXPECT_EQ(q.bytes, 0);
    CHECK(q.ov == &ov);
    CHECK_QUEUE_EMPTY(port);
    closesocket(dst);
    CloseHandle(port);
}

TEST(iocp_recv_after_peer_reset_fails_inline_without_packet)
{
    NEED_NET();
    SOCKET src, dst;
    HANDLE port = new_port();
    OVERLAPPED ov;
    WSABUF wb;
    char buf[BUFSZ];
    DWORD n = POISON, flags = 0;
    NEED_PAIR(src, dst);
    CHECK(attach(dst, port, KEY));
    h9_nonblock(dst, 1);
    h9_rst_close(src);
    CHECK(h9_readable(dst, 3000));
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    SetLastError(POISON);
    CHECK(WSARecv(dst, &wb, 1, &n, &flags, (LPWSAOVERLAPPED)&ov, NULL) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAECONNRESET);
    EXPECT_EQ(n, POISON);
    CHECK_QUEUE_EMPTY(port);
    closesocket(dst);
    CloseHandle(port);
}

TEST(iocp_recv_on_unconnected_socket_fails_inline_without_packet)
{
    NEED_NET();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    HANDLE port = new_port();
    OVERLAPPED ov;
    WSABUF wb;
    char buf[BUFSZ];
    DWORD n = POISON, flags = 0;
    REQUIRE(s != INVALID_SOCKET);
    CHECK(attach(s, port, KEY));
    h9_nonblock(s, 1);
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    SetLastError(POISON);
    CHECK(WSARecv(s, &wb, 1, &n, &flags, (LPWSAOVERLAPPED)&ov, NULL) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAENOTCONN);
    EXPECT_EQ(n, POISON);
    CHECK_QUEUE_EMPTY(port);
    closesocket(s);
    CloseHandle(port);
}

/* ---- AcceptEx cancellation on close ------------------------------------------------------------ */

TEST(iocp_acceptex_aborted_on_close_port_attached_after_request)
{
    NEED_NET();
    acceptex_fn ax = get_acceptex();
    REQUIRE(ax);
    struct sockaddr_in a;
    SOCKET lst = iocp_listener(&a), acc = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE port = new_port();
    OVERLAPPED ov;
    char buf[BUFSZ];
    REQUIRE(lst != INVALID_SOCKET && acc != INVALID_SOCKET);
    post_acceptex(ax, lst, acc, buf, &ov);
    CHECK(attach(lst, port, KEY));
    closesocket(lst);
    expect_cancelled_packet(port, &ov);
    CHECK_QUEUE_EMPTY(port);
    closesocket(acc);
    CloseHandle(port);
}

TEST(iocp_acceptex_aborted_on_close_port_attached_before_request)
{
    NEED_NET();
    acceptex_fn ax = get_acceptex();
    REQUIRE(ax);
    struct sockaddr_in a;
    SOCKET lst = iocp_listener(&a), acc = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE port = new_port();
    OVERLAPPED ov;
    char buf[BUFSZ];
    REQUIRE(lst != INVALID_SOCKET && acc != INVALID_SOCKET);
    CHECK(attach(lst, port, KEY));
    post_acceptex(ax, lst, acc, buf, &ov);
    closesocket(lst);
    expect_cancelled_packet(port, &ov);
    CHECK_QUEUE_EMPTY(port);
    closesocket(acc);
    CloseHandle(port);
}

/* Duplicates of a socket share one underlying object: the request is only aborted when the last
 * handle goes away, whichever handle carried it. */
static void duplicated_acceptex(int close_first_dup, int close_first_orig)
{
    acceptex_fn ax = get_acceptex();
    struct sockaddr_in a;
    SOCKET lst, dup, acc;
    HANDLE port;
    WSAPROTOCOL_INFOA info;
    OVERLAPPED ov;
    char buf[BUFSZ];
    if (!ax) { t_skip("AcceptEx not provided"); return; }
    lst = iocp_listener(&a);
    acc = socket(AF_INET, SOCK_STREAM, 0);
    port = new_port();
    if (lst == INVALID_SOCKET || acc == INVALID_SOCKET) { t_skip("socket setup failed"); return; }
    CHECK(attach(lst, port, KEY));
    EXPECT_EQ(WSADuplicateSocketA(lst, GetCurrentProcessId(), &info), 0);
    dup = WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, WSA_FLAG_OVERLAPPED);
    CHECK(dup != INVALID_SOCKET);
    if (dup == INVALID_SOCKET) { closesocket(lst); closesocket(acc); CloseHandle(port); return; }
    post_acceptex(ax, dup, acc, buf, &ov);
    CHECK_QUEUE_EMPTY(port);

    if (close_first_dup) {
        closesocket(dup);
        CHECK_QUEUE_EMPTY(port);       /* the original handle still keeps the object alive */
        closesocket(lst);
    } else if (close_first_orig) {
        closesocket(lst);
        CHECK_QUEUE_EMPTY(port);
        closesocket(dup);
    } else {
        closesocket(lst);
        closesocket(dup);
    }
    expect_cancelled_packet(port, &ov);
    CHECK_QUEUE_EMPTY(port);
    closesocket(acc);
    CloseHandle(port);
}

TEST(iocp_acceptex_duplicate_both_closed_aborts)
{
    NEED_NET();
    duplicated_acceptex(0, 0);
}

TEST(iocp_acceptex_duplicate_closed_first_original_keeps_request)
{
    NEED_NET();
    duplicated_acceptex(1, 0);
}

TEST(iocp_acceptex_duplicate_original_closed_first_duplicate_keeps_request)
{
    NEED_NET();
    duplicated_acceptex(0, 1);
}

TEST(iocp_listener_closed_without_acceptex_posts_nothing)
{
    NEED_NET();
    struct sockaddr_in a;
    SOCKET lst = iocp_listener(&a);
    HANDLE port = new_port();
    REQUIRE(lst != INVALID_SOCKET);
    CHECK(attach(lst, port, KEY));
    closesocket(lst);
    CHECK_QUEUE_EMPTY(port);
    CloseHandle(port);
}

/* ---- AcceptEx completion ----------------------------------------------------------------------- */

TEST(iocp_acceptex_completes_on_connect_and_peer_close)
{
    NEED_NET();
    acceptex_fn ax = get_acceptex();
    REQUIRE(ax);
    struct sockaddr_in a;
    SOCKET lst = iocp_listener(&a), acc = socket(AF_INET, SOCK_STREAM, 0), con = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE port = new_port();
    OVERLAPPED ov;
    struct h9_dq q;
    char buf[BUFSZ];
    REQUIRE(lst != INVALID_SOCKET && acc != INVALID_SOCKET && con != INVALID_SOCKET);
    CHECK(attach(lst, port, KEY));
    CHECK(attach(acc, port, 236));
    post_acceptex(ax, lst, acc, buf, &ov);
    EXPECT_EQ(connect(con, (struct sockaddr *)&a, sizeof a), 0);
    closesocket(con);                  /* no data: the request completes when the connection ends */

    h9_dequeue(port, 3000, &q);
    CHECK(q.ok);
    EXPECT_EQ(q.err, POISON);
    EXPECT_EQ(q.key, KEY);             /* the listener's key, not the accepted socket's */
    EXPECT_EQ(q.bytes, 0);
    CHECK(q.ov == &ov);
    EXPECT_EQ((ULONG)ov.Internal, NT_SUCCESS_STATUS);
    CHECK_QUEUE_EMPTY(port);
    closesocket(acc);
    closesocket(lst);
    CloseHandle(port);
}

TEST(iocp_acceptex_with_data_survives_accepted_socket_close)
{
    NEED_NET();
    acceptex_fn ax = get_acceptex();
    REQUIRE(ax);
    struct sockaddr_in a;
    SOCKET lst = iocp_listener(&a), acc = socket(AF_INET, SOCK_STREAM, 0), con = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE port = new_port();
    OVERLAPPED ov;
    struct h9_dq q;
    char buf[BUFSZ];
    int waited;
    REQUIRE(lst != INVALID_SOCKET && acc != INVALID_SOCKET && con != INVALID_SOCKET);
    CHECK(attach(lst, port, KEY));
    CHECK(attach(acc, port, 236));
    post_acceptex(ax, lst, acc, buf, &ov);
    EXPECT_EQ(connect(con, (struct sockaddr *)&a, sizeof a), 0);
    EXPECT_EQ(send(con, buf, 1, 0), 1);

    /* Once the request has completed (status no longer pending) the accepted socket may be closed
     * without turning the packet into a failure. */
    for (waited = 0; waited < 3000 && !HasOverlappedIoCompleted(&ov); waited += 10) Sleep(10);
    if (!HasOverlappedIoCompleted(&ov)) t_note("status still pending before the packet is dequeued");
    closesocket(acc);

    h9_dequeue(port, 3000, &q);
    CHECK(q.ok);
    EXPECT_EQ(q.key, KEY);
    EXPECT_EQ(q.bytes, 1);
    CHECK(q.ov == &ov);
    EXPECT_EQ((ULONG)ov.Internal, NT_SUCCESS_STATUS);
    CHECK_QUEUE_EMPTY(port);
    closesocket(lst);
    closesocket(con);
    CloseHandle(port);
}

TEST(iocp_acceptex_accepted_socket_closed_before_data_aborts)
{
    NEED_NET();
    acceptex_fn ax = get_acceptex();
    REQUIRE(ax);
    struct sockaddr_in a;
    SOCKET lst = iocp_listener(&a), acc = socket(AF_INET, SOCK_STREAM, 0), con = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE port = new_port();
    OVERLAPPED ov;
    struct h9_dq q;
    char buf[BUFSZ];
    REQUIRE(lst != INVALID_SOCKET && acc != INVALID_SOCKET && con != INVALID_SOCKET);
    CHECK(attach(lst, port, KEY));
    CHECK(attach(acc, port, 236));
    post_acceptex(ax, lst, acc, buf, &ov);
    EXPECT_EQ(connect(con, (struct sockaddr *)&a, sizeof a), 0);
    closesocket(acc);

    h9_dequeue(port, 3000, &q);
    CHECK(!q.ok);
    /* Depending on whether the connection had been matched to the request yet, the request is
     * cancelled or reported as an aborted connection. */
    CHECK(q.err == ERROR_OPERATION_ABORTED || q.err == ERROR_CONNECTION_ABORTED);
    EXPECT_EQ(q.key, KEY);
    EXPECT_EQ(q.bytes, 0);
    CHECK(q.ov == &ov);
    CHECK((ULONG)ov.Internal == NT_CANCELLED || (ULONG)ov.Internal == NT_CONN_ABORTED);
    CHECK_QUEUE_EMPTY(port);
    closesocket(lst);
    closesocket(con);
    CloseHandle(port);
}
