/* getsockopt level validation, SO_MAX_MSG_SIZE / SO_LINGER / SO_DONTLINGER, and getsockname
 * (unbound socket, zero padding, short buffer, bound name round trip). */
#include "l6.h"

TEST(lift06_sockopt_max_msg_size_on_datagram)
{
    SOCKET s; struct sockaddr_in a = lo_addr(0); int v = 0, n = sizeof v;
    NEED_WS(); REQUIRE(U(getsockopt));
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    EQ(w_bind(s, &a, sizeof a), 0);
    EQ(w_getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v, &n), 0);
    /* 65507 on a plain IPv4 provider, 65527 on some builds. */
    CHECKF(v == 65507 || v == 65527, "got %d", v);
    t_note("SO_MAX_MSG_SIZE is the 65507 flavour: %d", v == 65507);
    w_close(s);
}

static void bad_level(int level)
{
    SOCKET s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    int v = 0xdeadbeef, n = sizeof v, r;
    w_seterr(0);
    r = w_getsockopt(s, level, SO_MAX_MSG_SIZE, &v, &n);
    EQ(r, SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
    w_close(s);
}
TEST(lift06_sockopt_level_all_ones_einval)      { NEED_WS(); REQUIRE(U(getsockopt)); bad_level(-1); }
TEST(lift06_sockopt_level_high_garbage_einval)  { NEED_WS(); REQUIRE(U(getsockopt)); bad_level(0x1234ffff); }
TEST(lift06_sockopt_level_sign_garbage_einval)  { NEED_WS(); REQUIRE(U(getsockopt)); bad_level((int)0x8000ffff); }
TEST(lift06_sockopt_level_0x8000_einval)        { NEED_WS(); REQUIRE(U(getsockopt)); bad_level(0x8000); }
TEST(lift06_sockopt_level_0x800_einval)         { NEED_WS(); REQUIRE(U(getsockopt)); bad_level(0x800); }

TEST(lift06_sockopt_linger_unsupported_on_datagram)
{
    SOCKET s; struct linger lg; int n = sizeof lg;
    NEED_WS(); REQUIRE(U(getsockopt));
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    w_seterr(0);
    EQ(w_getsockopt(s, SOL_SOCKET, SO_LINGER, &lg, &n), SOCKET_ERROR);
    EQ(w_err(), WSAENOPROTOOPT);
    w_close(s);
}
TEST(lift06_sockopt_dontlinger_is_inverse_of_linger_on_stream)
{
    SOCKET s; struct linger lg; BOOL dl = 0xdead; int n = sizeof lg, n2 = sizeof dl;
    NEED_WS(); REQUIRE(U(getsockopt));
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    EQ(w_getsockopt(s, SOL_SOCKET, SO_LINGER, &lg, &n), 0);
    EQ(w_getsockopt(s, SOL_SOCKET, SO_DONTLINGER, &dl, &n2), 0);
    CHECK((lg.l_onoff && !dl) || (!lg.l_onoff && dl));
    w_close(s);
}

/* ---- getsockname ---- */
TEST(lift06_getsockname_unbound_is_einval_and_untouched)
{
    SOCKET s; struct sockaddr_in set = lo_addr(0), got; int n = sizeof got;
    NEED_WS(); REQUIRE(U(getsockname));
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    got = set;
    w_seterr(0);
    EQ(w_getsockname(s, &got, &n), SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
    CHECK(!memcmp(&got, &set, sizeof got));
    w_close(s);
}
TEST(lift06_getsockname_bound_wildcard_stream)
{
    SOCKET s; struct sockaddr_in set, got; int n = sizeof got; static const unsigned char z[8];
    NEED_WS(); REQUIRE(U(getsockname));
    memset(&set, 0, sizeof set); set.sin_family = AF_INET;          /* port 0, INADDR_ANY: bind only, no listen */
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    EQ(w_bind(s, &set, sizeof set), 0);
    w_seterr(0);
    memset(&got, 0xff, sizeof got);
    EQ(w_getsockname(s, &got, &n), 0);
    CHECK(w_err() == 0);
    EQ(n, sizeof got);
    EQ(got.sin_family, AF_INET);
    CHECK(got.sin_port != 0);
    EQ(got.sin_addr.s_addr, 0);
    CHECK(!memcmp(got.sin_zero, z, 8));                              /* padding is zeroed */
    w_close(s);
}
TEST(lift06_getsockname_short_buffer_is_efault_length_unchanged)
{
    SOCKET s; struct sockaddr_in set = lo_addr(0), got; int n;
    NEED_WS(); REQUIRE(U(getsockname));
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    EQ(w_bind(s, &set, sizeof set), 0);
    n = sizeof got - 1;
    w_seterr(0);
    EQ(w_getsockname(s, &got, &n), SOCKET_ERROR);
    EQ(w_err(), WSAEFAULT);
    EQ(n, sizeof got - 1);
    w_close(s);
}
TEST(lift06_getsockname_returns_bound_loopback_address)
{
    SOCKET s; struct sockaddr_in set = lo_addr(0), got; int n = sizeof got;
    NEED_WS(); REQUIRE(U(getsockname));
    s = w_socket(AF_INET, SOCK_DGRAM, 0);
    EQ(w_bind(s, &set, sizeof set), 0);
    EQ(w_getsockname(s, &got, &n), 0);
    CHECK(got.sin_addr.s_addr == set.sin_addr.s_addr);
    CHECK(got.sin_port != 0);
    w_close(s);
}
