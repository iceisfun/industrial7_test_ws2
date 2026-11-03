/* Address-sharing rules of bind()/listen(): SO_REUSEADDR, wildcard-versus-specific binds,
 * SO_EXCLUSIVEADDRUSE, and how loopback connections are routed between sockets that share a port.
 * Every case runs on IPv4 and (when IPv6 loopback is usable) IPv6, on a freshly probed
 * ephemeral port. Accepts are bounded so a mis-routed connection fails instead of hanging. */
#include "ws.h"

#define FAMTEST(name) \
    static void name##_body(int af); \
    TEST(name##_v4) { if (!ws_up()) return; name##_body(AF_INET); } \
    TEST(name##_v6) { if (!ws_up()) return; if (!v6_usable()) { t_skip("IPv6 loopback unusable"); return; } name##_body(AF_INET6); } \
    static void name##_body(int af)

static SOCKET mk(int af) { SOCKET s = w_socket(af, SOCK_STREAM, 0); CHECK(s != INVALID_SOCKET); return s; }
static void reuse_on(SOCKET s) { DWORD one = 1; CHECK(w_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0); }
static int bind_kind(SOCKET s, int af, int kind, unsigned short port) {
    struct sockaddr_storage a; int l = mk_addr(&a, af, kind, port);
    return w_bind(s, &a, l);
}
static int connect_loop(SOCKET s, int af, unsigned short port) {
    struct sockaddr_storage a; int l = mk_addr(&a, af, A_LOOP, port);
    return w_connect(s, &a, l);
}
/* connect a fresh client to the loopback port and report whether `listener` is the one that sees it */
static int routed_to(SOCKET listener, int af, unsigned short port) {
    SOCKET c = mk(af), a;
    int ok;
    CHECK(connect_loop(c, af, port) == 0);
    a = w_accept_to(listener, 3000);
    ok = a != INVALID_SOCKET;
    w_close(a); w_close(c);
    return ok;
}

/* A plain socket holds the port; a second socket that opts in alone is still refused (access denied). */
FAMTEST(l5_reuse_second_socket_only_denied) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s1 = mk(af), s2 = mk(af);
    CHECK(bind_kind(s1, af, A_LOOP, p) == 0);
    reuse_on(s2);
    w_seterr(0);
    CHECK(bind_kind(s2, af, A_LOOP, p) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEACCES);
    w_close(s1); w_close(s2);
}

/* Both opt in: the second bind works, a socket that has not opted in is refused, default value is 0. */
FAMTEST(l5_reuse_both_sockets_share_port) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s1 = mk(af), s2 = mk(af);
    DWORD v = 0x1234; int n = sizeof v;
    reuse_on(s1);
    CHECK(bind_kind(s1, af, A_LOOP, p) == 0);
    CHECK(w_getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &v, &n) == 0);
    EXPECT_EQ(v, 0);
    CHECK(bind_kind(s2, af, A_LOOP, p) == SOCKET_ERROR);
    reuse_on(s2);
    CHECK(bind_kind(s2, af, A_LOOP, p) == 0);
    w_close(s1); w_close(s2);
}

/* Sharing sockets can both listen; the first one bound receives the connection. */
FAMTEST(l5_reuse_both_listen_first_gets_connection) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s1 = mk(af), s2 = mk(af);
    reuse_on(s1); reuse_on(s2);
    CHECK(bind_kind(s1, af, A_LOOP, p) == 0);
    CHECK(bind_kind(s2, af, A_LOOP, p) == 0);
    CHECK(w_listen(s1, 1) == 0);
    CHECK(w_listen(s2, 1) == 0);
    CHECK(routed_to(s1, af, p));
    w_close(s1); w_close(s2);
}

/* A wildcard listener does not block a later specific-address bind; the specific socket wins the routing. */
FAMTEST(l5_wildcard_then_specific_specific_wins) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s1 = mk(af), s2 = mk(af);
    CHECK(bind_kind(s1, af, A_ANY, p) == 0);
    CHECK(w_listen(s1, 1) == 0);
    CHECK(bind_kind(s2, af, A_LOOP, p) == 0);
    CHECK(w_listen(s2, 1) == 0);
    CHECK(routed_to(s2, af, p));
    w_close(s1); w_close(s2);
}

/* Reverse order: specific first, wildcard second; the specific listener still gets loopback traffic. */
FAMTEST(l5_specific_then_wildcard_specific_wins) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s1 = mk(af), s2 = mk(af);
    CHECK(bind_kind(s1, af, A_LOOP, p) == 0);
    CHECK(w_listen(s1, 1) == 0);
    CHECK(bind_kind(s2, af, A_ANY, p) == 0);
    CHECK(w_listen(s2, 1) == 0);
    CHECK(routed_to(s1, af, p));
    w_close(s1); w_close(s2);
}

/* Two plain wildcard binds of one port collide. */
FAMTEST(l5_wildcard_twice_addr_in_use) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s1 = mk(af), s2 = mk(af);
    CHECK(bind_kind(s1, af, A_ANY, p) == 0);
    w_seterr(0);
    CHECK(bind_kind(s2, af, A_ANY, p) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEADDRINUSE);
    w_close(s1); w_close(s2);
}

/* Four sharing sockets: connections go to the earliest-bound listener, and as listeners close the
 * next one in line takes over (a bound-but-not-listening socket is skipped until it listens). */
FAMTEST(l5_reuse_successive_listeners_take_over) {
    unsigned short p = free_port(SOCK_STREAM);
    SOCKET s[4];
    int i;
    for (i = 0; i < 4; i++) { s[i] = mk(af); reuse_on(s[i]); }
    CHECK(bind_kind(s[0], af, A_LOOP, p) == 0);
    CHECK(bind_kind(s[1], af, A_LOOP, p) == 0);
    CHECK(w_listen(s[0], 1) == 0);
    CHECK(w_listen(s[1], 1) == 0);
    CHECK(routed_to(s[0], af, p));
    w_close(s[0]);

    CHECK(bind_kind(s[2], af, A_LOOP, p) == 0);
    CHECK(routed_to(s[1], af, p));          /* s[2] is bound but not listening yet */
    w_close(s[1]);

    CHECK(bind_kind(s[3], af, A_LOOP, p) == 0);
    CHECK(w_listen(s[2], 1) == 0);
    CHECK(routed_to(s[2], af, p));
    w_close(s[2]);

    CHECK(w_listen(s[3], 1) == 0);
    CHECK(routed_to(s[3], af, p));
    w_close(s[3]);
}

/* SO_REUSEADDR and SO_EXCLUSIVEADDRUSE cannot be enabled together, in either order. */
TEST(l5_reuse_and_exclusive_mutually_exclusive) {
    SOCKET s;
    DWORD one = 1, zero = 0;
    if (!ws_up()) return;
    s = mk(AF_INET);
    reuse_on(s);
    w_seterr(0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEINVAL);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &zero, sizeof zero) == 0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one) == 0);
    w_seterr(0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEINVAL);
    w_close(s);
}

/* ---- exclusive-use matrix: first socket bound, then second socket bound; expected error of the second ---- */
struct excl_row {
    int af0, kind0, excl0, af1, kind1, excl1;
    int err;                     /* 0 = success */
};
static const struct excl_row excl_rows[] = {
    {AF_INET,  A_ANY,         1, AF_INET, A_LOOP,        0, WSAEACCES},
    {AF_INET6, A_ANY,         1, AF_INET, A_LOOP,        0, WSAEACCES},
    {AF_INET,  A_ANY,         0, AF_INET, A_LOOP,        1, 0},
    {AF_INET,  A_ANY,         1, AF_INET, A_LOOP,        1, WSAEACCES},
    {AF_INET,  A_LOOP,        1, AF_INET, A_ANY,         0, 0},
    {AF_INET,  A_LOOP,        0, AF_INET, A_ANY,         1, WSAEADDRINUSE},
    {AF_INET,  A_LOOP,        0, AF_INET6, A_ANY,        1, WSAEADDRINUSE},
    {AF_INET6, A_LOOP,        0, AF_INET, A_ANY,         1, 0},
    {AF_INET6, A_LOOP,        1, AF_INET, A_LOOP,        1, 0},
    {AF_INET6, A_MAPPED_LOOP, 0, AF_INET, A_ANY,         1, WSAEADDRINUSE},
    {AF_INET6, A_ANY,         1, AF_INET, A_ANY,         0, WSAEACCES},
    {AF_INET6, A_ANY,         0, AF_INET, A_ANY,         1, 0},
    {AF_INET,  A_ANY,         0, AF_INET, A_ANY,         1, WSAEADDRINUSE},
    {AF_INET,  A_ANY,         0, AF_INET, A_ANY,         0, WSAEADDRINUSE},
    {AF_INET6, A_ANY,         0, AF_INET, A_ANY,         0, 0},
    {AF_INET6, A_MAPPED_ANY,  0, AF_INET, A_ANY,         0, WSAEADDRINUSE},
    {AF_INET6, A_MAPPED_LOOP, 0, AF_INET, A_LOOP,        0, WSAEADDRINUSE},
    {AF_INET,  A_LOOP,        0, AF_INET6, A_MAPPED_LOOP, 0, WSAEADDRINUSE},
    {AF_INET,  A_LOOP,        1, AF_INET, A_LOOP,        0, WSAEADDRINUSE},
    {AF_INET,  A_LOOP,        0, AF_INET, A_LOOP,        1, WSAEADDRINUSE},
};

static void run_excl_row(unsigned i) {
    const struct excl_row *r = &excl_rows[i];
    SOCKET s0, s1;
    DWORD one = 1, zero = 0;
    unsigned short p;
    int rc;
    if (!ws_up()) return;
    if ((r->af0 == AF_INET6 || r->af1 == AF_INET6) && !v6_usable()) { t_skip("IPv6 loopback unusable"); return; }
    p = free_port(SOCK_STREAM);
    s0 = w_socket(r->af0, SOCK_STREAM, 0);
    s1 = w_socket(r->af1, SOCK_STREAM, 0);
    CHECK(s0 != INVALID_SOCKET && s1 != INVALID_SOCKET);
    if (r->excl0) CHECK(w_setsockopt(s0, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one) == 0);
    if (r->excl1) CHECK(w_setsockopt(s1, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one) == 0);
    /* dual-stack so that v6 sockets conflict with v4 ones */
    if (r->af0 == AF_INET6) CHECK(w_setsockopt(s0, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) == 0);
    if (r->af1 == AF_INET6) CHECK(w_setsockopt(s1, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) == 0);
    CHECK(bind_kind(s0, r->af0, r->kind0, p) == 0);
    w_seterr(0);
    rc = bind_kind(s1, r->af1, r->kind1, p);
    if (r->err) { CHECK(rc == SOCKET_ERROR); EXPECT_EQ(w_err(), r->err); }
    else CHECK(rc == 0);
    w_close(s0); w_close(s1);
}
#define EXCL(n) TEST(l5_exclusive_matrix_##n) { run_excl_row(n); }
EXCL(0) EXCL(1) EXCL(2) EXCL(3) EXCL(4) EXCL(5) EXCL(6) EXCL(7) EXCL(8) EXCL(9)
EXCL(10) EXCL(11) EXCL(12) EXCL(13) EXCL(14) EXCL(15) EXCL(16) EXCL(17) EXCL(18) EXCL(19)
