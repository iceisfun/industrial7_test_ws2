/* WSADuplicateSocketA / WSASocketA(FROM_PROTOCOL_INFO): argument validation order, the contents of the
 * returned WSAPROTOCOL_INFO, and the rule that a duplicate shares the original's state only if the
 * original was bound before the protocol info was consumed. */
#include "l6.h"

static SOCKET mk(int ty, int pr) { return w_socket(AF_INET, ty, pr); }
static int dup_info(SOCKET s, DWORD pid, WSAPROTOCOL_INFOA *i) { return U(WSADuplicateSocketA)(s, pid, i); }
static SOCKET from_info(WSAPROTOCOL_INFOA *i) { return U(WSASocketA)(0, 0, 0, i, 0, 0); }

TEST(lift06_dup_not_a_socket_handle)
{
    WSAPROTOCOL_INFOA info;
    REQUIRE(U(WSADuplicateSocketA)); NEED_WS();
    /* Handle 0 is not a socket: reported before the pid / buffer arguments are looked at. */
    w_seterr(0);
    CHECK(dup_info(0, 0, NULL) == SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    w_seterr(0);
    CHECK(dup_info(0, GetCurrentProcessId(), &info) == SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
}

TEST(lift06_dup_pid_zero_is_einval)
{
    SOCKET s; WSAPROTOCOL_INFOA info;
    REQUIRE(U(WSADuplicateSocketA)); NEED_WS();
    s = mk(SOCK_STREAM, IPPROTO_TCP);
    CHECK(s != INVALID_SOCKET);
    w_seterr(0);
    CHECK(dup_info(s, 0, NULL) == SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
    w_seterr(0);
    CHECK(dup_info(s, 0, &info) == SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
    w_close(s);
}

TEST(lift06_dup_pid_all_ones_is_einval)
{
    SOCKET s; WSAPROTOCOL_INFOA info;
    REQUIRE(U(WSADuplicateSocketA)); NEED_WS();
    s = mk(SOCK_STREAM, IPPROTO_TCP);
    w_seterr(0);
    CHECK(dup_info(s, (DWORD)~0, &info) == SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
    w_close(s);
}

TEST(lift06_dup_null_info_is_efault)
{
    SOCKET s;
    REQUIRE(U(WSADuplicateSocketA)); NEED_WS();
    s = mk(SOCK_STREAM, IPPROTO_TCP);
    w_seterr(0);
    CHECK(dup_info(s, GetCurrentProcessId(), NULL) == SOCKET_ERROR);
    EQ(w_err(), WSAEFAULT);
    w_close(s);
}

static void check_info(int ty, int pr)
{
    SOCKET s, d; WSAPROTOCOL_INFOA info;
    int v, n = sizeof v;
    s = mk(ty, pr);
    CHECK(s != INVALID_SOCKET);
    memset(&info, 0, sizeof info);
    EQ(dup_info(s, GetCurrentProcessId(), &info), 0);
    EQ(info.iProtocol, pr);
    EQ(info.iAddressFamily, AF_INET);
    EQ(info.iSocketType, ty);
    d = from_info(&info);
    CHECK(d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) {
        v = 0; EQ(w_getsockopt(d, SOL_SOCKET, SO_TYPE, &v, &n), 0);
        EQ(v, ty);
        w_close(d);
    }
    w_close(s);
}
TEST(lift06_dup_info_tcp)
{
    REQUIRE(U(WSADuplicateSocketA)); REQUIRE(U(WSASocketA)); NEED_WS();
    check_info(SOCK_STREAM, IPPROTO_TCP);
}
TEST(lift06_dup_info_udp)
{
    REQUIRE(U(WSADuplicateSocketA)); REQUIRE(U(WSASocketA)); NEED_WS();
    check_info(SOCK_DGRAM, IPPROTO_UDP);
}

/* A datagram sent to the bound original is readable from a duplicate made after the bind. */
TEST(lift06_dup_after_bind_shares_binding)
{
    SOCKET src, dup; WSAPROTOCOL_INFOA info;
    struct sockaddr_in a = lo_addr(0), from; int n = sizeof a, fl = sizeof from;
    char msg[] = "TEST", buf[16];
    REQUIRE(U(WSADuplicateSocketA)); REQUIRE(U(WSASocketA)); REQUIRE(U(sendto)); REQUIRE(U(recvfrom)); NEED_WS();
    src = mk(SOCK_DGRAM, IPPROTO_UDP);
    EQ(w_bind(src, &a, sizeof a), 0);
    EQ(w_getsockname(src, &a, &n), 0);
    CHECK(sa_port_nonzero(&a));
    memset(&info, 0, sizeof info);
    EQ(dup_info(src, GetCurrentProcessId(), &info), 0);
    dup = from_info(&info);
    CHECK(dup != INVALID_SOCKET);
    if (dup != INVALID_SOCKET) {
        w_rcvtimeo(dup, 3000);
        n = sizeof a;
        EQ(U(sendto)(src, msg, sizeof msg, 0, (struct sockaddr *)&a, n), (int)sizeof msg);
        memset(buf, 0, sizeof buf);
        EQ(U(recvfrom)(dup, buf, sizeof msg, 0, (struct sockaddr *)&from, &fl), (int)sizeof msg);
        EXPECT_STR(buf, "TEST");
        w_close(dup);
    }
    w_close(src);
}

/* A duplicate created from info captured while the original was still unbound is an independent,
 * unbound socket even if the original is bound later: receiving on it is invalid. */
TEST(lift06_dup_before_bind_stays_unbound)
{
    SOCKET src, dup; WSAPROTOCOL_INFOA info;
    struct sockaddr_in a = lo_addr(0), from; int n = sizeof a, fl = sizeof from;
    char msg[] = "TEST", buf[16];
    REQUIRE(U(WSADuplicateSocketA)); REQUIRE(U(WSASocketA)); REQUIRE(U(sendto)); REQUIRE(U(recvfrom)); NEED_WS();
    src = mk(SOCK_DGRAM, IPPROTO_UDP);
    memset(&info, 0, sizeof info);
    EQ(dup_info(src, GetCurrentProcessId(), &info), 0);
    dup = from_info(&info);
    CHECK(dup != INVALID_SOCKET);
    EQ(w_bind(src, &a, sizeof a), 0);
    EQ(w_getsockname(src, &a, &n), 0);
    CHECK(sa_port_nonzero(&a));
    EQ(U(sendto)(src, msg, sizeof msg, 0, (struct sockaddr *)&a, n), (int)sizeof msg);
    if (dup != INVALID_SOCKET) {
        w_rcvtimeo(dup, 3000);
        w_seterr(0);
        memset(buf, 0, sizeof buf);
        CHECK(U(recvfrom)(dup, buf, sizeof msg, 0, (struct sockaddr *)&from, &fl) == -1);
        EQ(w_err(), WSAEINVAL);
        w_close(dup);
    }
    w_close(src);
}
