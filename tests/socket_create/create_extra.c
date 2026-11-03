/* socket_create: properties that follow a socket after creation: what an accepted socket inherits from its
 * listener, option plumbing on fresh sockets of every kind, shutdown/close ordering and rebinding rules.
 * Everything runs on loopback with OS-chosen ports; no addresses or ports are printed. */
#include "sc.h"

typedef struct { SOCKET l, c, a; } pair_t;

/* connected TCP pair over IPv4 loopback; fl_l / fl_c are the creation flags of listener and client */
static int make_pair(pair_t *p, DWORD fl_l, DWORD fl_c) {
    struct sockaddr_in a;
    int len = sizeof a;
    fd_set r;
    struct timeval tv = {5, 0};
    p->l = p->c = p->a = INVALID_SOCKET;
    p->l = sc_make(AF_INET, SOCK_STREAM, 0, fl_l);
    p->c = sc_make(AF_INET, SOCK_STREAM, 0, fl_c);
    if (p->l == INVALID_SOCKET || p->c == INVALID_SOCKET) return -1;
    sc_loop4(&a);
    if (U(bind)(p->l, (struct sockaddr *)&a, sizeof a)) return -2;
    if (U(getsockname)(p->l, (struct sockaddr *)&a, &len)) return -3;
    if (U(listen)(p->l, 1)) return -4;
    if (U(connect)(p->c, (struct sockaddr *)&a, sizeof a)) return -5;
    FD_ZERO(&r); FD_SET(p->l, &r);
    if (U(select)(0, &r, NULL, NULL, &tv) != 1) return -6;
    p->a = U(accept)(p->l, NULL, NULL);
    return p->a == INVALID_SOCKET ? -7 : 0;
}
static void pair_close(pair_t *p) { sc_close(p->a); sc_close(p->c); sc_close(p->l); }

static LONG file_mode(SOCKET s, ULONG *mode) {
    sc_NtQueryInformationFile_t q = (sc_NtQueryInformationFile_t)t_proc_in("ntdll.dll", "NtQueryInformationFile");
    ULONG_PTR iosb[2] = {0, 0};
    *mode = 0xffffffff;
    if (!q) return (LONG)0xC0000002;
    return q((HANDLE)s, iosb, mode, sizeof *mode, 16);
}

/* ---- accepted sockets ---- */
TEST(sockcreate_extra_accepted_socket_reports_listener_protocol_info) {
    pair_t p;
    WSAPROTOCOL_INFOW li, ai;
    SC_UP();
    SC_EQ(make_pair(&p, WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED), 0);
    if (p.a != INVALID_SOCKET) {
        CHECK(sc_getinfo(p.l, &li) == 0);
        CHECK(sc_getinfo(p.a, &ai) == 0);
        CHECK(!memcmp(&li, &ai, sizeof li));
        SC_EQ(sc_sotype(p.a), SOCK_STREAM);
        CHECK(p.a != p.l && p.a != p.c);
    }
    pair_close(&p);
}
TEST(sockcreate_extra_accepted_socket_of_overlapped_listener_is_asynchronous) {
    pair_t p;
    ULONG m;
    SC_UP();
    SC_EQ(make_pair(&p, WSA_FLAG_OVERLAPPED, 0), 0);
    if (p.a != INVALID_SOCKET) {
        SC_EQ(file_mode(p.a, &m), 0);
        SC_EQ(m, 0);
    }
    pair_close(&p);
}
TEST(sockcreate_extra_accepted_socket_of_synchronous_listener_is_synchronous) {
    pair_t p;
    ULONG m;
    SC_UP();
    SC_EQ(make_pair(&p, 0, WSA_FLAG_OVERLAPPED), 0);
    if (p.a != INVALID_SOCKET) {
        SC_EQ(file_mode(p.a, &m), 0);
        SC_EQ(m, FILE_SYNCHRONOUS_IO_NONALERT);
    }
    pair_close(&p);
}
TEST(sockcreate_extra_accepted_socket_is_a_pipe_class_file_handle) {
    pair_t p;
    SC_UP();
    SC_EQ(make_pair(&p, 1, 1), 0);
    if (p.a != INVALID_SOCKET) {
        SC_EQ(GetFileType((HANDLE)p.a), FILE_TYPE_PIPE);
        CHECK((p.a & 3) == 0 && p.a != 0);
    }
    pair_close(&p);
}
TEST(sockcreate_extra_accepted_socket_inheritance_recorded) {
    pair_t p;
    DWORD f = 0;
    SC_UP();
    SC_EQ(make_pair(&p, WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED, 1), 0);
    if (p.a != INVALID_SOCKET) {
        CHECK(GetHandleInformation((HANDLE)p.a, &f));
        t_note("accepted from a no-inherit listener: inheritable=%d", (f & HANDLE_FLAG_INHERIT) != 0);
    }
    pair_close(&p);
}
TEST(sockcreate_extra_accepted_socket_survives_listener_close) {
    pair_t p;
    char b = 0;
    SC_UP();
    SC_EQ(make_pair(&p, 1, 1), 0);
    if (p.a != INVALID_SOCKET) {
        SC_EQ(U(closesocket)(p.l), 0);
        p.l = INVALID_SOCKET;
        SC_EQ(U(send)(p.c, "k", 1, 0), 1);
        SC_EQ(U(recv)(p.a, &b, 1, 0), 1);
        SC_EQ(b, 'k');
    }
    pair_close(&p);
}

/* ---- shutdown and close ordering ---- */
TEST(sockcreate_extra_shutdown_invalid_how_is_einval) {
    pair_t p;
    static const int hows[] = {3, 4, -1, 100};
    unsigned i;
    SC_UP();
    SC_EQ(make_pair(&p, 1, 1), 0);
    if (p.a != INVALID_SOCKET)
        for (i = 0; i < sizeof hows / sizeof *hows; i++) {
            sc_seterr(0);
            t_check(U(shutdown)(p.c, hows[i]) == SOCKET_ERROR, __FILE__, __LINE__, "shutdown fails", "how=%d", hows[i]);
            t_check(sc_err() == WSAEINVAL, __FILE__, __LINE__, "WSAEINVAL", "how=%d got %d", hows[i], sc_err());
        }
    pair_close(&p);
}
TEST(sockcreate_extra_shutdown_then_close_returns_zero) {
    pair_t p;
    static const int hows[] = {SD_RECEIVE, SD_SEND, SD_BOTH};
    unsigned i;
    SC_UP();
    for (i = 0; i < 3; i++) {
        SC_EQ(make_pair(&p, 1, 1), 0);
        if (p.a != INVALID_SOCKET) {
            SC_EQ(U(shutdown)(p.c, hows[i]), 0);
            SC_EQ(U(closesocket)(p.c), 0);
            p.c = INVALID_SOCKET;
            SC_EQ(U(closesocket)(p.a), 0);
            p.a = INVALID_SOCKET;
        }
        pair_close(&p);
    }
}
TEST(sockcreate_extra_send_after_shutdown_send_is_eshutdown) {
    pair_t p;
    SC_UP();
    SC_EQ(make_pair(&p, 1, 1), 0);
    if (p.a != INVALID_SOCKET) {
        SC_EQ(U(shutdown)(p.c, SD_SEND), 0);
        sc_seterr(0);
        CHECK(U(send)(p.c, "x", 1, 0) == SOCKET_ERROR);
        SC_EQ(sc_err(), WSAESHUTDOWN);
    }
    pair_close(&p);
}
TEST(sockcreate_extra_close_listener_with_unaccepted_connection) {
    SOCKET l, c;
    struct sockaddr_in a;
    int len = sizeof a;
    SC_UP();
    l = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    c = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    sc_loop4(&a);
    CHECK(U(bind)(l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(U(getsockname)(l, (struct sockaddr *)&a, &len) == 0);
    CHECK(U(listen)(l, 1) == 0);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == 0);
    SC_EQ(U(closesocket)(l), 0);
    SC_EQ(U(closesocket)(c), 0);
}

/* ---- option plumbing on fresh sockets ---- */
TEST(sockcreate_extra_so_type_short_optlen_is_efault) {
    SOCKET s;
    int t = 0, k;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    for (k = 0; k < 4; k++) {
        int n = k;
        sc_seterr(0);
        t_check(sc_gso(s, SOL_SOCKET, SO_TYPE, &t, &n) == SOCKET_ERROR, __FILE__, __LINE__, "short SO_TYPE fails", "optlen=%d", k);
        t_check(sc_err() == WSAEFAULT, __FILE__, __LINE__, "WSAEFAULT", "optlen=%d got %d", k, sc_err());
    }
    sc_close(s);
}
TEST(sockcreate_extra_getsockopt_on_invalid_socket_is_enotsock) {
    int t = 0, n = sizeof t;
    SC_UP();
    sc_seterr(0);
    CHECK(sc_gso(INVALID_SOCKET, SOL_SOCKET, SO_TYPE, &t, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTSOCK);
    sc_seterr(0);
    CHECK(sc_gso(0, SOL_SOCKET, SO_PROTOCOL_INFOW, &t, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTSOCK);
}
TEST(sockcreate_extra_reuseaddr_roundtrip_on_fresh_sockets) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = sc_make(rows[i][0], rows[i][1], 0, 1);
        int v = 1, n = sizeof v;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        SC_EQ(sc_sso(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v), 0);
        v = 0;
        SC_EQ(sc_gso(s, SOL_SOCKET, SO_REUSEADDR, &v, &n), 0);
        CHECK(v != 0);
        v = 0;
        SC_EQ(sc_sso(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v), 0);
        v = 7; n = sizeof v;
        SC_EQ(sc_gso(s, SOL_SOCKET, SO_REUSEADDR, &v, &n), 0);
        SC_EQ(v, 0);
        sc_close(s);
    }
}
TEST(sockcreate_extra_v6only_can_be_cleared_on_fresh_v6_sockets) {
    int i;
    SC_UP();
    for (i = 0; i < 2; i++) {
        SOCKET s = sc_make(AF_INET6, i ? SOCK_DGRAM : SOCK_STREAM, 0, 1);
        int v = 0, n = sizeof v;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        SC_EQ(sc_sso(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof v), 0);
        v = 5;
        SC_EQ(sc_gso(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, &n), 0);
        SC_EQ(v & 0xff, 0);
        sc_close(s);
    }
}
TEST(sockcreate_extra_v6only_option_on_v4_sockets_recorded) {
    int i;
    SC_UP();
    for (i = 0; i < 2; i++) {
        SOCKET s = sc_make(AF_INET, i ? SOCK_DGRAM : SOCK_STREAM, 0, 1);
        int v = 0, n = sizeof v, r;
        CHECK(s != INVALID_SOCKET);
        sc_seterr(0);
        r = sc_gso(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, &n);
        t_note("IPV6_V6ONLY on an IPv4 %s socket: result %d", i ? "datagram" : "stream", r);
        sc_close(s);
    }
}
TEST(sockcreate_extra_buffer_sizes_are_positive) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = sc_make(rows[i][0], rows[i][1], 0, 1);
        int v = 0, n = sizeof v;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        SC_EQ(sc_gso(s, SOL_SOCKET, SO_RCVBUF, &v, &n), 0);
        CHECK(v > 0);
        v = 0; n = sizeof v;
        SC_EQ(sc_gso(s, SOL_SOCKET, SO_SNDBUF, &v, &n), 0);
        CHECK(v >= 0);
        sc_close(s);
    }
}

/* ---- bind rules for fresh sockets ---- */
TEST(sockcreate_extra_bind_port_zero_assigns_a_port) {
    SC_UP();
    {
        int i;
        for (i = 0; i < 4; i++) {
            SOCKET s = sc_make(i & 2 ? AF_INET6 : AF_INET, i & 1 ? SOCK_DGRAM : SOCK_STREAM, 0, 1);
            struct sockaddr_in6 a6;
            struct sockaddr_in a4;
            int l4 = sizeof a4, l6 = sizeof a6;
            CHECK(s != INVALID_SOCKET);
            if (s == INVALID_SOCKET) continue;
            if (i & 2) {
                sc_loop6(&a6);
                if (U(bind)(s, (struct sockaddr *)&a6, sizeof a6)) { t_skip("IPv6 loopback not available"); sc_close(s); return; }
                CHECK(U(getsockname)(s, (struct sockaddr *)&a6, &l6) == 0);
                CHECK(a6.sin6_port != 0);
                SC_EQ(l6, sizeof a6);
            } else {
                sc_loop4(&a4);
                CHECK(U(bind)(s, (struct sockaddr *)&a4, sizeof a4) == 0);
                CHECK(U(getsockname)(s, (struct sockaddr *)&a4, &l4) == 0);
                CHECK(a4.sin_port != 0);
                SC_EQ(a4.sin_addr.s_addr, 0x0100007f);
                SC_EQ(l4, sizeof a4);
            }
            sc_close(s);
        }
    }
}
TEST(sockcreate_extra_second_bind_on_same_socket_is_einval) {
    int i;
    SC_UP();
    for (i = 0; i < 2; i++) {
        SOCKET s = sc_make(AF_INET, i ? SOCK_DGRAM : SOCK_STREAM, 0, 1);
        struct sockaddr_in a;
        sc_loop4(&a);
        CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0);
        sc_seterr(0);
        CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
        SC_EQ(sc_err(), WSAEINVAL);
        sc_close(s);
    }
}
TEST(sockcreate_extra_bind_wrong_family_is_eafnosupport_or_einval_recorded) {
    SOCKET s;
    struct sockaddr_in6 a6;
    int r;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    sc_loop6(&a6);
    sc_seterr(0);
    r = U(bind)(s, (struct sockaddr *)&a6, sizeof a6);
    CHECK(r == SOCKET_ERROR);
    t_note("bind of an IPv6 address on an IPv4 socket: error %d", sc_err());
    sc_close(s);
}
TEST(sockcreate_extra_udp_connect_sets_peer_name) {
    SOCKET a, b;
    struct sockaddr_in addr, peer;
    int l = sizeof addr, pl = sizeof peer;
    SC_UP();
    a = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    b = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    sc_loop4(&addr);
    CHECK(U(bind)(a, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(U(getsockname)(a, (struct sockaddr *)&addr, &l) == 0);
    SC_EQ(U(connect)(b, (struct sockaddr *)&addr, sizeof addr), 0);
    SC_EQ(U(getpeername)(b, (struct sockaddr *)&peer, &pl), 0);
    SC_EQ(peer.sin_port, addr.sin_port);
    SC_EQ(peer.sin_addr.s_addr, 0x0100007f);
    SC_EQ(pl, sizeof peer);
    sc_close(a); sc_close(b);
}

/* ---- the two entry points report one record ---- */
TEST(sockcreate_extra_ansi_and_wide_creation_report_same_protocol_info) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}, {AF_UNIX, SOCK_STREAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 5; i++) {
        SOCKET a = U(WSASocketA)(rows[i][0], rows[i][1], 0, NULL, 0, 1);
        SOCKET w = U(socket)(rows[i][0], rows[i][1], 0);
        WSAPROTOCOL_INFOW ia, iw;
        CHECK(a != INVALID_SOCKET && w != INVALID_SOCKET);
        if (a != INVALID_SOCKET && w != INVALID_SOCKET) {
            CHECK(sc_getinfo(a, &ia) == 0 && sc_getinfo(w, &iw) == 0);
            CHECK(!memcmp(&ia, &iw, sizeof ia));
        }
        sc_close(a); sc_close(w);
    }
}
