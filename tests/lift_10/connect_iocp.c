/* Completion-port behaviour of connection establishment.
 * Measures which connect paths post a packet to an I/O completion port: plain connect() (blocking and
 * non-blocking) never does; ConnectEx always does when it went pending, with the byte count of the optional
 * send buffer, even when FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is set; an OVERLAPPED event handle with the low
 * bit set suppresses the packet; a refused ConnectEx completes with ERROR_CONNECTION_REFUSED.
 * Loopback only, ephemeral ports, every wait bounded.
 */
#include "w.h"

/* connect() then accept: no packet may reach the port of the connecting socket. */
static void plain_connect_scenario(int nonblocking)
{
    struct sockaddr_in dest;
    SOCKET l = w_listener(&dest, 1), c, a;
    HANDLE port;
    int ret;

    CHECK(l != INVALID_SOCKET);
    if (l == INVALID_SOCKET) return;
    c = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(c != INVALID_SOCKET);
    port = w_port_for(c, 0);
    CHECK(port != NULL);
    if (nonblocking) w_set_blocking(c, 0);

    ret = p_connect(c, (struct sockaddr *)&dest, sizeof dest);
    if (nonblocking) {
        /* A non-blocking connect always reports "in progress", even over loopback. */
        EXPECT_EQ(ret, SOCKET_ERROR);
        EXPECT_EQ(p_WSAGetLastError(), WSAEWOULDBLOCK);
    } else {
        EXPECT_EQ(ret, 0);
    }
    a = w_accept(l, 3000);
    CHECK(a != INVALID_SOCKET);
    if (a != INVALID_SOCKET) p_closesocket(a);

    w_expect_empty(port, 0);

    p_closesocket(c);
    CloseHandle(port);
    p_closesocket(l);
}

TEST(lift10_connect_blocking_posts_no_completion)    { W_BEGIN(); plain_connect_scenario(0); }
TEST(lift10_connect_nonblocking_posts_no_completion) { W_BEGIN(); plain_connect_scenario(1); }

/* ConnectEx over loopback; data/len is the optional send buffer. */
static void connectex_scenario(const char *data, DWORD len, int low_bit, int skip_on_success)
{
    struct sockaddr_in dest, any = w_loop();
    SOCKET l = w_listener(&dest, 1), c, a;
    OVERLAPPED ov;
    HANDLE port, ev;
    LPFN_CONNECTEX cex;
    DWORD sent = W_SENT, size = W_SENT;
    struct w_cp r;
    int ret;

    CHECK(l != INVALID_SOCKET);
    if (l == INVALID_SOCKET) return;
    c = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    cex = w_connectex(c);
    CHECK(cex != NULL);
    if (!cex) { p_closesocket(c); p_closesocket(l); return; }
    port = w_port_for(c, 0);
    CHECK(port != NULL);
    if (skip_on_success)
        CHECK(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    /* ConnectEx needs a socket that is already bound. */
    CHECK(p_bind(c, (struct sockaddr *)&any, sizeof any) == 0);

    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = low_bit ? (HANDLE)((ULONG_PTR)ev | 1) : ev;

    ret = cex(c, (struct sockaddr *)&dest, sizeof dest, (void *)data, len, &sent, &ov);
    CHECK(!ret);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    ret = (int)WaitForSingleObject(ev, 3000);
    EXPECT_EQ(ret, WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)c, &ov, &size, FALSE));
    EXPECT_EQ(size, len);
    a = w_accept(l, 3000);
    CHECK(a != INVALID_SOCKET);
    if (a != INVALID_SOCKET) p_closesocket(a);

    if (low_bit) {
        w_expect_empty(port, 0);
    } else {
        r = w_dequeue(port, 0);
        CHECK(r.ret);
        EXPECT_EQ(r.key, 0);
        EXPECT_EQ(r.bytes, len);
        CHECK(r.ov == &ov);
    }
    p_closesocket(c);
    CloseHandle(port);
    CloseHandle(ev);
    p_closesocket(l);
}

TEST(lift10_connectex_queues_completion)               { W_BEGIN(); connectex_scenario(NULL, 0, 0, 0); }
TEST(lift10_connectex_completion_reports_sent_bytes)   { W_BEGIN(); connectex_scenario("one", 3, 0, 0); }
TEST(lift10_connectex_event_low_bit_suppresses_packet) { W_BEGIN(); connectex_scenario(NULL, 0, 1, 0); }
TEST(lift10_connectex_skip_on_success_still_queues)    { W_BEGIN(); connectex_scenario(NULL, 0, 0, 1); }

/* Nobody listens on the destination: the pending ConnectEx fails with a refusal, and the failure
 * is delivered through the port even though skip-on-success was requested. */
TEST(lift10_connectex_refused_completes_with_error)
{
    struct sockaddr_in dest, any = w_loop();
    SOCKET l, c;
    OVERLAPPED ov;
    HANDLE port, ev;
    LPFN_CONNECTEX cex;
    DWORD sent = 0, size = W_SENT;
    int ret;
    struct w_cp r;
    W_BEGIN();

    l = w_listener(&dest, 1);
    CHECK(l != INVALID_SOCKET);
    if (l == INVALID_SOCKET) return;
    p_closesocket(l);          /* the port is now unused: loopback answers with a reset */

    c = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    cex = w_connectex(c);
    CHECK(cex != NULL);
    if (!cex) { p_closesocket(c); return; }
    port = w_port_for(c, 0);
    CHECK(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    CHECK(p_bind(c, (struct sockaddr *)&any, sizeof any) == 0);
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;

    CHECK(!cex(c, (struct sockaddr *)&dest, sizeof dest, NULL, 0, &sent, &ov));
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    ret = (int)WaitForSingleObject(ev, 5000);
    EXPECT_EQ(ret, WAIT_OBJECT_0);
    SetLastError(0);
    CHECK(!GetOverlappedResult((HANDLE)c, &ov, &size, FALSE));
    EXPECT_ERR(ERROR_CONNECTION_REFUSED);
    EXPECT_EQ(size, 0);

    r = w_dequeue(port, 0);
    CHECK(!r.ret);
    EXPECT_EQ(r.err, ERROR_CONNECTION_REFUSED);
    EXPECT_EQ(r.key, 0);
    EXPECT_EQ(r.bytes, 0);
    CHECK(r.ov == &ov);

    p_closesocket(c);
    CloseHandle(port);
    CloseHandle(ev);
}
