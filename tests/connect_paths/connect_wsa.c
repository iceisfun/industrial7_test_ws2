/* WSAConnect() extras: caller data, callee data and quality-of-service parameters.
 *
 * The stock TCP and UDP providers do not carry connect data and do not honour flow specs.  What must
 * hold regardless of how a particular build answers is an invariant: the call either fails and no
 * connection exists (and nothing reached the listener), or it succeeds and the socket is connected to
 * the requested peer.  Empty buffers are ignored outright.  The exact error numbers for the unsupported
 * cases are recorded as notes.
 */
#include "cp.h"

#define WAIT_MS 3000

static void zero_qos(QOS *q)
{
    memset(q, 0, sizeof *q);
    q->SendingFlowspec.ServiceType = SERVICETYPE_BESTEFFORT;
    q->ReceivingFlowspec.ServiceType = SERVICETYPE_BESTEFFORT;
    q->SendingFlowspec.TokenRate = QOS_NOT_SPECIFIED;
    q->SendingFlowspec.TokenBucketSize = QOS_NOT_SPECIFIED;
    q->SendingFlowspec.PeakBandwidth = QOS_NOT_SPECIFIED;
    q->SendingFlowspec.Latency = QOS_NOT_SPECIFIED;
    q->SendingFlowspec.DelayVariation = QOS_NOT_SPECIFIED;
    q->ReceivingFlowspec = q->SendingFlowspec;
}

/* Call WSAConnect on a fresh TCP socket and apply the invariant; returns the call result. */
static int tcp_invariant(WSABUF *cd, WSABUF *ce, QOS *sq, QOS *gq, const char *what)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 2), s, a = INVALID_SOCKET;
    int r, e;
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    r = cp_WSAConnect(s, (struct sockaddr *)&la, sizeof la, cd, ce, sq, gq);
    e = r ? cp_WSAGetLastError() : 0;
    if (r == 0) {
        t_check(cp_peer_is(s, &la), __FILE__, __LINE__, "connected to the listener", "%s", what);
        t_check(cp_accept_one(l, &a, WAIT_MS), __FILE__, __LINE__, "listener sees the connection", "%s", what);
        if (a != INVALID_SOCKET) cp_closesocket(a);
    } else {
        t_check(r == SOCKET_ERROR, __FILE__, __LINE__, "failure value", "%s: ret %d", what, r);
        t_check(cp_peer_err(s) == WSAENOTCONN, __FILE__, __LINE__, "not connected after failure", "%s", what);
        t_check((cp_wait(l, CP_R, 300) & CP_R) == 0, __FILE__, __LINE__, "listener saw nothing", "%s", what);
    }
    t_note("%s -> %d (err %d)", what, r, e);
    cp_closesocket(s); cp_closesocket(l);
    return r;
}

/* ---- empty parameters are ignored ----------------------------------------------------------------- */

TEST(cpw_all_optional_parameters_null_is_a_plain_connect)
{
    struct sockaddr_in la;
    SOCKET l, s, a = INVALID_SOCKET;
    REQUIRE(U(WSAConnect)); NEED();
    l = cp_listener(&la, 1);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_WSAConnect(s, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL), 0);
    CHECK(cp_peer_is(s, &la));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpw_caller_data_with_zero_length_is_ignored)
{
    char buf[8] = "abcdefg";
    WSABUF cd;
    cd.len = 0; cd.buf = buf;
    REQUIRE(U(WSAConnect)); NEED();
    CP_EQ(tcp_invariant(&cd, NULL, NULL, NULL, "caller data len 0 with a buffer"), 0);
}

TEST(cpw_caller_data_with_null_buffer_is_ignored)
{
    WSABUF cd;
    cd.len = 6; cd.buf = NULL;
    REQUIRE(U(WSAConnect)); NEED();
    CP_EQ(tcp_invariant(&cd, NULL, NULL, NULL, "caller data len 6 without a buffer"), 0);
}

TEST(cpw_caller_data_empty_buffer_on_udp_is_ignored)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = cp_socket(AF_INET, SOCK_DGRAM, 0);
    WSABUF cd;
    char buf[4] = "xyz";
    REQUIRE(U(WSAConnect)); NEED();
    cd.len = 0; cd.buf = buf;
    CP_EQ(cp_WSAConnect(c, (struct sockaddr *)&pa, sizeof pa, &cd, NULL, NULL, NULL), 0);
    CHECK(cp_peer_is(c, &pa));
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpw_callee_data_with_zero_length_is_ignored)
{
    char buf[8] = {0};
    WSABUF ce;
    ce.len = 0; ce.buf = buf;
    REQUIRE(U(WSAConnect)); NEED();
    CP_EQ(tcp_invariant(NULL, &ce, NULL, NULL, "callee data len 0 with a buffer"), 0);
}

TEST(cpw_callee_data_with_null_buffer_is_ignored)
{
    WSABUF ce;
    ce.len = 8; ce.buf = NULL;
    REQUIRE(U(WSAConnect)); NEED();
    CP_EQ(tcp_invariant(NULL, &ce, NULL, NULL, "callee data len 8 without a buffer"), 0);
}

TEST(cpw_zero_length_data_leaves_callee_length_alone)
{
    struct sockaddr_in la;
    SOCKET l, s, a = INVALID_SOCKET;
    WSABUF ce;
    char buf[8];
    REQUIRE(U(WSAConnect)); NEED();
    l = cp_listener(&la, 1);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    memset(buf, 0x77, sizeof buf);
    ce.len = 0; ce.buf = buf;
    CP_EQ(cp_WSAConnect(s, (struct sockaddr *)&la, sizeof la, NULL, &ce, NULL, NULL), 0);
    CP_EQ(ce.len, 0);
    CHECK(ce.buf == buf);
    CHECK((unsigned char)buf[0] == 0x77);
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

/* ---- data on a provider without connect data --------------------------------------------------------- */

TEST(cpw_tcp_caller_data_invariant)
{
    char buf[4] = "abc";
    WSABUF cd;
    cd.len = 4; cd.buf = buf;
    REQUIRE(U(WSAConnect)); NEED();
    tcp_invariant(&cd, NULL, NULL, NULL, "TCP caller data of 4 bytes");
}

TEST(cpw_tcp_callee_data_invariant)
{
    char buf[16] = {0};
    WSABUF ce;
    ce.len = sizeof buf; ce.buf = buf;
    REQUIRE(U(WSAConnect)); NEED();
    tcp_invariant(NULL, &ce, NULL, NULL, "TCP callee buffer of 16 bytes");
}

TEST(cpw_tcp_caller_and_callee_data_invariant)
{
    char a[4] = "abc", b[16] = {0};
    WSABUF cd, ce;
    cd.len = 4; cd.buf = a;
    ce.len = sizeof b; ce.buf = b;
    REQUIRE(U(WSAConnect)); NEED();
    tcp_invariant(&cd, &ce, NULL, NULL, "TCP caller and callee data");
}

TEST(cpw_udp_caller_data_invariant)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = cp_socket(AF_INET, SOCK_DGRAM, 0);
    char buf[4] = "abc";
    WSABUF cd;
    int r, e;
    REQUIRE(U(WSAConnect)); NEED();
    cd.len = 4; cd.buf = buf;
    cp_WSASetLastError(0);
    r = cp_WSAConnect(c, (struct sockaddr *)&pa, sizeof pa, &cd, NULL, NULL, NULL);
    e = r ? cp_WSAGetLastError() : 0;
    if (r == 0) CHECK(cp_peer_is(c, &pa));
    else CP_EQ(cp_peer_err(c), WSAENOTCONN);
    t_note("UDP caller data of 4 bytes -> %d (err %d)", r, e);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpw_failed_data_attempt_leaves_the_socket_connectable)
{
    struct sockaddr_in la;
    SOCKET l, s, a = INVALID_SOCKET;
    char buf[4] = "abc";
    WSABUF cd;
    int r;
    REQUIRE(U(WSAConnect)); NEED();
    l = cp_listener(&la, 2);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cd.len = 4; cd.buf = buf;
    r = cp_WSAConnect(s, (struct sockaddr *)&la, sizeof la, &cd, NULL, NULL, NULL);
    if (r != 0) {
        /* The failed attempt did not consume the socket: a plain connect still works. */
        CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    }
    CHECK(cp_peer_is(s, &la));
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

/* ---- quality of service -------------------------------------------------------------------------------- */

TEST(cpw_tcp_sending_qos_invariant)
{
    QOS q;
    zero_qos(&q);
    REQUIRE(U(WSAConnect)); NEED();
    tcp_invariant(NULL, NULL, &q, NULL, "TCP with a sending QOS");
}

TEST(cpw_tcp_group_qos_invariant)
{
    QOS q;
    zero_qos(&q);
    REQUIRE(U(WSAConnect)); NEED();
    tcp_invariant(NULL, NULL, NULL, &q, "TCP with a group QOS");
}

TEST(cpw_tcp_both_qos_invariant)
{
    QOS q, g;
    zero_qos(&q); zero_qos(&g);
    REQUIRE(U(WSAConnect)); NEED();
    tcp_invariant(NULL, NULL, &q, &g, "TCP with sending and group QOS");
}

TEST(cpw_udp_qos_invariant)
{
    struct sockaddr_in pa;
    SOCKET peer = cp_udp_bound(&pa), c = cp_socket(AF_INET, SOCK_DGRAM, 0);
    QOS q;
    int r, e;
    REQUIRE(U(WSAConnect)); NEED();
    zero_qos(&q);
    cp_WSASetLastError(0);
    r = cp_WSAConnect(c, (struct sockaddr *)&pa, sizeof pa, NULL, NULL, &q, NULL);
    e = r ? cp_WSAGetLastError() : 0;
    if (r == 0) CHECK(cp_peer_is(c, &pa));
    else CP_EQ(cp_peer_err(c), WSAENOTCONN);
    t_note("UDP with a sending QOS -> %d (err %d)", r, e);
    cp_closesocket(c); cp_closesocket(peer);
}

TEST(cpw_qos_does_not_change_argument_validation)
{
    /* Argument errors win over the optional parameters: a short length is still WSAEFAULT. */
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s;
    QOS q;
    char buf[4] = "abc";
    WSABUF cd;
    REQUIRE(U(WSAConnect)); NEED();
    zero_qos(&q);
    cd.len = 4; cd.buf = buf;
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&la, 8, &cd, NULL, &q, &q), WSAEFAULT);
    la.sin_family = AF_UNIX;
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&la, sizeof la, &cd, NULL, &q, &q), WSAEAFNOSUPPORT);
    CP_EQ(cp_wait(l, CP_R, 200), 0);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpw_data_on_already_connected_socket_is_eisconn)
{
    SOCKET c, s;
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    char buf[4] = "abc";
    WSABUF cd;
    REQUIRE(U(WSAConnect)); NEED();
    CHECK(cp_pair(&c, &s));
    cd.len = 4; cd.buf = buf;
    CP_FAILS(cp_WSAConnect(c, (struct sockaddr *)&a, sizeof a, &cd, NULL, NULL, NULL), WSAEISCONN);
    cp_closesocket(c); cp_closesocket(s);
}

/* ---- parity with connect() --------------------------------------------------------------------------------- */

TEST(cpw_dead_port_error_matches_connect)
{
    struct sockaddr_in d;
    SOCKET a, b;
    int e1, e2;
    REQUIRE(U(WSAConnect)); NEED();
    CHECK(cp_dead_port(&d));
    a = cp_socket(AF_INET, SOCK_STREAM, 0);
    b = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    CP_EQ(cp_connect(a, (struct sockaddr *)&d, sizeof d), SOCKET_ERROR);
    e1 = cp_WSAGetLastError();
    cp_WSASetLastError(0);
    CP_EQ(cp_WSAConnect(b, (struct sockaddr *)&d, sizeof d, NULL, NULL, NULL, NULL), SOCKET_ERROR);
    e2 = cp_WSAGetLastError();
    CP_EQ(e1, e2);
    CP_EQ(e1, WSAECONNREFUSED);
    cp_closesocket(a); cp_closesocket(b);
}

TEST(cpw_nonblocking_wouldblock_matches_connect)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 2), a, b, x = INVALID_SOCKET;
    REQUIRE(U(WSAConnect)); NEED();
    a = cp_socket(AF_INET, SOCK_STREAM, 0);
    b = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(a, 1); cp_nb(b, 1);
    CP_FAILS(cp_connect(a, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CP_FAILS(cp_WSAConnect(b, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL), WSAEWOULDBLOCK);
    CHECK(cp_wait(a, CP_W, WAIT_MS) & CP_W);
    CHECK(cp_wait(b, CP_W, WAIT_MS) & CP_W);
    if (cp_accept_one(l, &x, WAIT_MS)) cp_closesocket(x);
    if (cp_accept_one(l, &x, WAIT_MS)) cp_closesocket(x);
    cp_closesocket(a); cp_closesocket(b); cp_closesocket(l);
}

TEST(cpw_wsaconnect_export_is_distinct_from_connect)
{
    /* WSAConnect is its own export in ws2_32; wsock32 does not forward it (it has no such export). */
    REQUIRE(U(WSAConnect));
    CHECK(t_proc_in("ws2_32.dll", "WSAConnect") != t_proc_in("ws2_32.dll", "connect"));
    CHECK(t_proc_in("wsock32.dll", "WSAConnect") == NULL);
}
