/* socket_create: a socket made by each creation path is immediately usable, and a fresh socket starts in the
 * documented initial state. Everything stays on loopback with OS-chosen ports; nothing prints addresses.
 * Initial-state facts: an unbound socket has no local name (getsockname fails WSAEINVAL), an unconnected one has
 * no peer (WSAENOTCONN), stream sockets cannot send, receive or shut down before they are connected, a datagram
 * socket cannot receive before it is bound, and the inherited defaults of the TCP/IP provider are the ones
 * listed per option below. */
#include "sc.h"

static int bind_loop4(SOCKET s, struct sockaddr_in *out) {
    struct sockaddr_in a;
    int l = sizeof a;
    sc_loop4(&a);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return -1;
    if (U(getsockname)(s, (struct sockaddr *)&a, &l)) return -1;
    if (out) *out = a;
    return 0;
}
static int bind_loop6(SOCKET s, struct sockaddr_in6 *out) {
    struct sockaddr_in6 a;
    int l = sizeof a;
    sc_loop6(&a);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return -1;
    if (U(getsockname)(s, (struct sockaddr *)&a, &l)) return -1;
    if (out) *out = a;
    return 0;
}
static int wait_readable(SOCKET s, int ms) {
    fd_set r;
    struct timeval tv;
    FD_ZERO(&r); FD_SET(s, &r);
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv);
}

/* ---- TCP echo of one byte, every creation flavour ---- */
static void tcp_roundtrip4(DWORD lfl, DWORD cfl) {
    SOCKET l = sc_make(AF_INET, SOCK_STREAM, 0, lfl), c = sc_make(AF_INET, SOCK_STREAM, 0, cfl), a = INVALID_SOCKET;
    struct sockaddr_in addr;
    char b = 0;
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    if (l == INVALID_SOCKET || c == INVALID_SOCKET) goto out;
    CHECK(bind_loop4(l, &addr) == 0);
    CHECK(U(listen)(l, 1) == 0);
    CHECK(U(connect)(c, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(wait_readable(l, 5000) == 1);
    a = U(accept)(l, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    if (a == INVALID_SOCKET) goto out;
    SC_EQ(U(send)(c, "q", 1, 0), 1);
    CHECK(wait_readable(a, 5000) == 1);
    SC_EQ(U(recv)(a, &b, 1, 0), 1);
    SC_EQ(b, 'q');
    SC_EQ(sc_sotype(a), SOCK_STREAM);
out:
    sc_close(a); sc_close(c); sc_close(l);
}
TEST(sockcreate_use_tcp4_overlapped_both)      { SC_UP(); tcp_roundtrip4(WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED); }
TEST(sockcreate_use_tcp4_synchronous_both)     { SC_UP(); tcp_roundtrip4(0, 0); }
TEST(sockcreate_use_tcp4_mixed_modes)          { SC_UP(); tcp_roundtrip4(0, WSA_FLAG_OVERLAPPED); tcp_roundtrip4(WSA_FLAG_OVERLAPPED, 0); }
TEST(sockcreate_use_tcp4_noinherit_both)       { SC_UP(); tcp_roundtrip4(WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_NO_HANDLE_INHERIT); }
TEST(sockcreate_use_tcp4_registered_io_connects) {
    SOCKET l, c;
    struct sockaddr_in addr;
    int r;
    SC_UP();
    l = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_REGISTERED_IO);
    c = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_REGISTERED_IO);
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    CHECK(bind_loop4(l, &addr) == 0);
    CHECK(U(listen)(l, 1) == 0);
    r = U(connect)(c, (struct sockaddr *)&addr, sizeof addr);
    CHECK(r == 0);
    sc_close(c); sc_close(l);
}
TEST(sockcreate_use_tcp4_via_socket_function) {
    SOCKET l, c, a;
    struct sockaddr_in addr;
    char b = 0;
    SC_UP();
    l = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    CHECK(bind_loop4(l, &addr) == 0);
    CHECK(U(listen)(l, 1) == 0);
    CHECK(U(connect)(c, (struct sockaddr *)&addr, sizeof addr) == 0);
    a = U(accept)(l, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    SC_EQ(U(send)(a, "z", 1, 0), 1);
    CHECK(wait_readable(c, 5000) == 1);
    SC_EQ(U(recv)(c, &b, 1, 0), 1);
    SC_EQ(b, 'z');
    sc_close(a); sc_close(c); sc_close(l);
}
TEST(sockcreate_use_tcp6_loopback_roundtrip) {
    SOCKET l, c, a;
    struct sockaddr_in6 addr;
    char b = 0;
    SC_UP();
    l = sc_make(AF_INET6, SOCK_STREAM, 0, 1);
    c = sc_make(AF_INET6, SOCK_STREAM, 0, 1);
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    if (bind_loop6(l, &addr)) { t_skip("IPv6 loopback not available"); sc_close(l); sc_close(c); return; }
    CHECK(U(listen)(l, 1) == 0);
    CHECK(U(connect)(c, (struct sockaddr *)&addr, sizeof addr) == 0);
    a = U(accept)(l, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    SC_EQ(U(send)(c, "w", 1, 0), 1);
    CHECK(wait_readable(a, 5000) == 1);
    SC_EQ(U(recv)(a, &b, 1, 0), 1);
    SC_EQ(b, 'w');
    sc_close(a); sc_close(c); sc_close(l);
}

/* ---- UDP to self ---- */
static void udp_self4(DWORD fl) {
    SOCKET s = sc_make(AF_INET, SOCK_DGRAM, 0, fl), t = sc_make(AF_INET, SOCK_DGRAM, 0, fl);
    struct sockaddr_in a, from;
    int fl_ = sizeof from;
    char b[4] = {0};
    CHECK(s != INVALID_SOCKET && t != INVALID_SOCKET);
    if (s == INVALID_SOCKET || t == INVALID_SOCKET) goto out;
    CHECK(bind_loop4(s, &a) == 0);
    SC_EQ(U(sendto)(t, "ab", 2, 0, (struct sockaddr *)&a, sizeof a), 2);
    CHECK(wait_readable(s, 5000) == 1);
    SC_EQ(U(recvfrom)(s, b, sizeof b, 0, (struct sockaddr *)&from, &fl_), 2);
    SC_EQ(b[0], 'a');
    SC_EQ(b[1], 'b');
    SC_EQ(from.sin_family, AF_INET);
    SC_EQ(from.sin_addr.s_addr, 0x0100007f);
out:
    sc_close(s); sc_close(t);
}
TEST(sockcreate_use_udp4_overlapped)  { SC_UP(); udp_self4(WSA_FLAG_OVERLAPPED); }
TEST(sockcreate_use_udp4_synchronous) { SC_UP(); udp_self4(0); }
TEST(sockcreate_use_udp4_registered_io_binds) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, WSA_FLAG_REGISTERED_IO);
    CHECK(s != INVALID_SOCKET);
    CHECK(bind_loop4(s, NULL) == 0);
    sc_close(s);
}
TEST(sockcreate_use_udp6_loopback) {
    SOCKET s = sc_make(AF_INET6, SOCK_DGRAM, 0, 1), t = sc_make(AF_INET6, SOCK_DGRAM, 0, 1);
    struct sockaddr_in6 a, from;
    int fl = sizeof from;
    char b[2] = {0};
    SC_UP();
    CHECK(s != INVALID_SOCKET && t != INVALID_SOCKET);
    if (bind_loop6(s, &a)) { t_skip("IPv6 loopback not available"); sc_close(s); sc_close(t); return; }
    SC_EQ(U(sendto)(t, "c", 1, 0, (struct sockaddr *)&a, sizeof a), 1);
    CHECK(wait_readable(s, 5000) == 1);
    SC_EQ(U(recvfrom)(s, b, sizeof b, 0, (struct sockaddr *)&from, &fl), 1);
    SC_EQ(b[0], 'c');
    SC_EQ(from.sin6_family, AF_INET6);
    sc_close(s); sc_close(t);
}
TEST(sockcreate_use_dual_stack_default_for_inet6_is_v6only) {
    SOCKET s;
    int v, n;
    int i;
    SC_UP();
    for (i = 0; i < 2; i++) {
        s = sc_make(AF_INET6, i ? SOCK_DGRAM : SOCK_STREAM, 0, 1);
        v = 0; n = sizeof v;
        CHECK(sc_gso(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, &n) == 0);
        SC_EQ(v & 0xff, 1);                         /* the option is reported as a single byte */
        t_note("IPV6_V6ONLY optlen after = %d", n);
        sc_close(s);
    }
}

/* ---- the initial state of a new socket ---- */
TEST(sockcreate_state_unbound_has_no_local_name) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 2; i++) {
        SOCKET s = sc_make(rows[i][0], rows[i][1], 0, 1);
        struct sockaddr_in a;
        int l = sizeof a;
        sc_seterr(0);
        CHECK(U(getsockname)(s, (struct sockaddr *)&a, &l) == SOCKET_ERROR);
        SC_EQ(sc_err(), WSAEINVAL);
        sc_close(s);
    }
}
TEST(sockcreate_state_unconnected_has_no_peer) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = sc_make(rows[i][0], rows[i][1], 0, 1);
        struct sockaddr_in6 a;
        int l = sizeof a;
        sc_seterr(0);
        CHECK(U(getpeername)(s, (struct sockaddr *)&a, &l) == SOCKET_ERROR);
        SC_EQ(sc_err(), WSAENOTCONN);
        sc_close(s);
    }
}
TEST(sockcreate_state_stream_io_before_connect_is_enotconn) {
    SOCKET s;
    char b[2] = {0};
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    sc_seterr(0);
    CHECK(U(send)(s, "x", 1, 0) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTCONN);
    sc_seterr(0);
    CHECK(U(recv)(s, b, 1, 0) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTCONN);
    sc_seterr(0);
    CHECK(U(shutdown)(s, SD_BOTH) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTCONN);
    sc_close(s);
}
TEST(sockcreate_state_datagram_receive_before_bind_is_einval) {
    SOCKET s;
    char b[2];
    SC_UP();
    if (t_is_wine()) { t_skip("the emulator blocks instead of failing"); return; }
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    sc_seterr(0);
    CHECK(U(recv)(s, b, 1, 0) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEINVAL);
    sc_close(s);
}
TEST(sockcreate_state_accept_requires_listening) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    sc_seterr(0);
    CHECK(U(accept)(s, NULL, NULL) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEINVAL);
    sc_close(s);
}
TEST(sockcreate_state_listen_before_bind_is_einval) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    sc_seterr(0);
    CHECK(U(listen)(s, 1) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEINVAL);
    sc_close(s);
}
TEST(sockcreate_state_listen_on_datagram_is_eopnotsupp) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    CHECK(bind_loop4(s, NULL) == 0);
    sc_seterr(0);
    CHECK(U(listen)(s, 1) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEOPNOTSUPP);
    sc_close(s);
}

/* ---- default option values ---- */
static int geti(SOCKET s, int lvl, int opt) {
    int v = -999, n = sizeof v;
    if (sc_gso(s, lvl, opt, &v, &n)) return -998;
    return v;
}
TEST(sockcreate_defaults_common_socket_level_options) {
    static const int opts[] = {SO_BROADCAST, SO_DEBUG, SO_REUSEADDR, SO_EXCLUSIVEADDRUSE, SO_ERROR, SO_RCVTIMEO, SO_SNDTIMEO,
                               SO_GROUP_ID, SO_GROUP_PRIORITY, SO_CONDITIONAL_ACCEPT};
    static const char *names[] = {"BROADCAST", "DEBUG", "REUSEADDR", "EXCLUSIVEADDRUSE", "ERROR", "RCVTIMEO", "SNDTIMEO", "GROUP_ID", "GROUP_PRIORITY", "CONDITIONAL_ACCEPT"};
    unsigned i;
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    for (i = 0; i < sizeof opts / sizeof *opts; i++)
        t_check(geti(s, SOL_SOCKET, opts[i]) == 0, __FILE__, __LINE__, "default is zero", "SO_%s", names[i]);
    sc_close(s);
}
TEST(sockcreate_defaults_tcp_socket_level_options) {
    SOCKET s;
    LINGER lg;
    int n = sizeof lg;
    BOOLEAN b = 0x55;
    int bn = sizeof b;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    SC_EQ(geti(s, SOL_SOCKET, SO_ACCEPTCONN), 0);
    CHECK(sc_gso(s, SOL_SOCKET, SO_LINGER, &lg, &n) == 0);
    SC_EQ(lg.l_onoff, 0);
    SC_EQ(lg.l_linger, 0);
    CHECK(sc_gso(s, SOL_SOCKET, SO_KEEPALIVE, &b, &bn) == 0);
    SC_EQ(b, 0);
    bn = sizeof b; b = 0x55;
    CHECK(sc_gso(s, IPPROTO_TCP, TCP_NODELAY, &b, &bn) == 0);
    SC_EQ(b, 0);
    sc_close(s);
}
TEST(sockcreate_defaults_datagram_sizes_and_multicast) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    SC_EQ(geti(s, SOL_SOCKET, SO_MAX_MSG_SIZE), 65507);
    SC_EQ(geti(s, IPPROTO_IP, IP_MULTICAST_TTL), 1);
    SC_EQ(geti(s, IPPROTO_IP, IP_MULTICAST_LOOP), 1);
    SC_EQ(geti(s, IPPROTO_IP, IP_TOS), 0);
    SC_EQ(geti(s, IPPROTO_IP, IP_DONTFRAGMENT), 0);
    t_note("udp4 default IP_TTL %d, SO_RCVBUF %d, SO_SNDBUF %d", geti(s, IPPROTO_IP, IP_TTL), geti(s, SOL_SOCKET, SO_RCVBUF), geti(s, SOL_SOCKET, SO_SNDBUF));
    sc_close(s);
}
TEST(sockcreate_defaults_options_missing_for_the_socket_type) {
    SOCKET u, t;
    int v = 0, n = sizeof v, r;
    SC_UP();
    u = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    t = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    sc_seterr(0);
    CHECK(sc_gso(u, SOL_SOCKET, SO_ACCEPTCONN, &v, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOPROTOOPT);
    sc_seterr(0); n = sizeof v;
    CHECK(sc_gso(u, SOL_SOCKET, SO_KEEPALIVE, &v, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOPROTOOPT);
    sc_seterr(0); n = sizeof v;
    CHECK(sc_gso(u, SOL_SOCKET, SO_OOBINLINE, &v, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOPROTOOPT);
    sc_seterr(0); n = sizeof v;
    r = sc_gso(t, SOL_SOCKET, SO_BROADCAST, &v, &n);
    t_note("SO_BROADCAST on a stream socket: result %d error %d", r, r ? sc_err() : 0);
    sc_close(u); sc_close(t);
}
TEST(sockcreate_defaults_raw_socket_options) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_RAW, IPPROTO_ICMP, 1);
    if (s == INVALID_SOCKET) { t_skip("raw sockets need an elevated token"); return; }
    SC_EQ(geti(s, IPPROTO_IP, IP_HDRINCL), 0);
    SC_EQ(geti(s, SOL_SOCKET, SO_BROADCAST), 0);
    t_note("raw4 SO_MAX_MSG_SIZE %d", geti(s, SOL_SOCKET, SO_MAX_MSG_SIZE));
    sc_close(s);
}
TEST(sockcreate_defaults_v6_hop_limit_present) {
    SOCKET s;
    int v;
    SC_UP();
    s = sc_make(AF_INET6, SOCK_DGRAM, 0, 1);
    v = geti(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS);
    CHECK(v > 0 && v <= 255);
    t_note("udp6 default unicast hops %d", v);
    sc_close(s);
}
