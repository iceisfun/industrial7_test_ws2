/* listen(): handle / type / state errors, SO_ACCEPTCONN read-only semantics, bind collisions,
 * and a blocking connect to a closed loopback port. */
#include "l6.h"

TEST(lift06_listen_bad_handles)
{
    NEED_WS(); REQUIRE(U(listen));
    w_seterr(0);
    CHECK(w_listen(0, 0) == SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    w_seterr(0);
    CHECK(w_listen((SOCKET)0xdeadbeef, 0) == SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
}

TEST(lift06_listen_on_datagram_socket)
{
    SOCKET s;
    NEED_WS(); REQUIRE(U(listen));
    s = w_socket(AF_INET, SOCK_DGRAM, 0);
    w_seterr(0);
    CHECK(w_listen(s, 1) == SOCKET_ERROR);
    EQ(w_err(), WSAEOPNOTSUPP);
    EQ(w_close(s), 0);
}

/* Unbound stream sockets cannot listen, whatever the backlog (even a negative one). */
static void unbound_listen(int backlog)
{
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    w_seterr(0);
    CHECK(w_listen(s, backlog) == SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
    w_close(s);
}
TEST(lift06_listen_unbound_negative_backlog) { NEED_WS(); REQUIRE(U(listen)); unbound_listen(-2); }
TEST(lift06_listen_unbound_backlog_one)      { NEED_WS(); REQUIRE(U(listen)); unbound_listen(1); }
TEST(lift06_listen_unbound_somaxconn)        { NEED_WS(); REQUIRE(U(listen)); unbound_listen(SOMAXCONN); }

TEST(lift06_listen_acceptconn_lifecycle)
{
    SOCKET a, b; struct sockaddr_in ad = lo_addr(0); int v, n = sizeof v, r;
    NEED_WS(); REQUIRE(U(listen));
    a = w_socket(AF_INET, SOCK_STREAM, 0);
    EQ(w_bind(a, &ad, sizeof ad), 0);
    EQ(w_getsockname(a, &ad, &(int){sizeof ad}), 0);

    v = 0xdead; EQ(w_getsockopt(a, SOL_SOCKET, SO_ACCEPTCONN, &v, &n), 0);
    EQ(v, 0);
    /* SO_ACCEPTCONN is get-only: both values are refused with ENOPROTOOPT. */
    for (v = 1; v >= 0; v--) {
        w_seterr(0);
        r = w_setsockopt(a, SOL_SOCKET, SO_ACCEPTCONN, &v, sizeof v);
        EQ(r, -1);
        EQ(w_err(), WSAENOPROTOOPT);
    }
    EQ(w_listen(a, 0), 0);
    EQ(w_listen(a, SOMAXCONN), 0);              /* listening twice is not an error */
    n = sizeof v; v = 0xdead;
    EQ(w_getsockopt(a, SOL_SOCKET, SO_ACCEPTCONN, &v, &n), 0);
    EQ(v, 1);
    for (v = 1; v >= 0; v--) {
        w_seterr(0);
        r = w_setsockopt(a, SOL_SOCKET, SO_ACCEPTCONN, &v, sizeof v);
        EQ(r, -1);
        EQ(w_err(), WSAENOPROTOOPT);
    }

    /* A second, unbound socket still cannot listen. */
    b = w_socket(AF_INET, SOCK_STREAM, 0);
    w_seterr(0);
    CHECK(w_listen(b, SOMAXCONN) == SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);

    /* Binding to the address the listener owns collides. */
    w_close(b);
    b = w_socket(AF_INET, SOCK_STREAM, 0);
    w_seterr(0);
    CHECK(w_bind(b, &ad, sizeof ad) != 0);
    EQ(w_err(), WSAEADDRINUSE);
    EQ(w_close(a), 0);
    EQ(w_close(b), 0);
}

TEST(lift06_listen_bind_collision_with_unlistened_socket)
{
    SOCKET a, b; struct sockaddr_in ad = lo_addr(0); int n = sizeof ad;
    NEED_WS(); REQUIRE(U(listen));
    a = w_socket(AF_INET, SOCK_STREAM, 0);
    b = w_socket(AF_INET, SOCK_STREAM, 0);
    EQ(w_bind(a, &ad, sizeof ad), 0);
    EQ(w_getsockname(a, &ad, &n), 0);
    w_seterr(0);
    CHECK(w_bind(b, &ad, sizeof ad) != 0);
    EQ(w_err(), WSAEADDRINUSE);
    w_close(a); w_close(b);
}

TEST(lift06_errors_blocking_connect_to_closed_port_is_refused)
{
    SOCKET s; struct sockaddr_in d;
    NEED_WS(); REQUIRE(U(connect));
    d = lo_dead_addr();
    w_seterr(0);
    s = w_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(w_connect(s, &d, sizeof d) == SOCKET_ERROR);
    EQ(w_err(), WSAECONNREFUSED);
    w_close(s);
}

TEST(lift06_errors_failed_connect_socket_not_writable)
{
    SOCKET s; struct sockaddr_in d; fd_set w; struct timeval tv;
    NEED_WS(); REQUIRE(U(connect)); REQUIRE(U(select));
    d = lo_dead_addr();
    s = w_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(w_connect(s, &d, sizeof d) == SOCKET_ERROR);
    fs_zero(&w); fs_add(&w, s);
    tv_set(&tv, 0, 50000);
    EQ(w_select(1, NULL, &w, NULL, &tv), 0);       /* a socket whose connect failed never turns writable */
    EQ(w_close(s), 0);
}
