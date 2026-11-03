/* sockopt_socket_level: argument validation order and error codes of getsockopt/setsockopt that do not depend on
 * which SOL_SOCKET option is used: stack not started, stale and closed handles, levels, and the order in which
 * the checks run (handle, then value pointer, then level, then option applicability). */
#include "sol.h"

TEST(sol_err_get_before_startup_is_notinitialised)
{
    int v = 0x5a5a5a5a, n = sizeof v;
    wset(0);
    EQ(U(getsockopt)((SOCKET)4, SOL_SOCKET, SO_TYPE, (char *)&v, &n), SOCKET_ERROR);
    EQ(werr(), WSANOTINITIALISED);
    EQ(v, 0x5a5a5a5a);
}
TEST(sol_err_set_before_startup_is_notinitialised)
{
    int v = 1;
    wset(0);
    EQ(U(setsockopt)((SOCKET)4, SOL_SOCKET, SO_KEEPALIVE, (const char *)&v, sizeof v), SOCKET_ERROR);
    EQ(werr(), WSANOTINITIALISED);
}
TEST(sol_err_startup_check_precedes_null_arguments)
{
    wset(0);
    EQ(U(setsockopt)(INVALID_SOCKET, SOL_SOCKET, SO_KEEPALIVE, NULL, 0), SOCKET_ERROR);
    EQ(werr(), WSANOTINITIALISED);
}
TEST(sol_err_after_cleanup_is_notinitialised)
{
    SOCKET s; int v, n = sizeof v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ws_down();
    wset(0);
    EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&v, &n), SOCKET_ERROR);
    EQ(werr(), WSANOTINITIALISED);
    wset(0);
    EQ(U(setsockopt)(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&v, sizeof v), SOCKET_ERROR);
    EQ(werr(), WSANOTINITIALISED);
}

/* Handle checks come first: no later argument is examined for a handle that is not a socket. */
TEST(sol_err_closed_socket_get_is_enotsock_even_with_null_arguments)
{
    SOCKET s; int v = 7, n = sizeof v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    cls(s);
    wset(0); EQ(gso(s, SOL_SOCKET, SO_TYPE, &v, &n), SOCKET_ERROR);   EQ(werr(), WSAENOTSOCK); EQ(n, 4); EQ(v, 7);
    wset(0); EQ(gso(s, SOL_SOCKET, SO_TYPE, NULL, NULL), SOCKET_ERROR); EQ(werr(), WSAENOTSOCK);
    wset(0); EQ(gso(s, 0xfffe, 0x1234, NULL, NULL), SOCKET_ERROR);      EQ(werr(), WSAENOTSOCK);
    ws_down();
}
TEST(sol_err_closed_socket_set_is_enotsock_even_with_null_arguments)
{
    SOCKET s; int v = 1;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    cls(s);
    wset(0); EQ(sso(s, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof v), SOCKET_ERROR); EQ(werr(), WSAENOTSOCK);
    wset(0); EQ(sso(s, SOL_SOCKET, SO_TYPE, NULL, 0), SOCKET_ERROR);           EQ(werr(), WSAENOTSOCK);
    wset(0); EQ(sso(s, 0xfffe, 1, NULL, 0), SOCKET_ERROR);                     EQ(werr(), WSAENOTSOCK);
    ws_down();
}
TEST(sol_err_invalid_socket_value_is_enotsock)
{
    int v = 1, n = sizeof v;
    NEED();
    wset(0); EQ(gso(INVALID_SOCKET, SOL_SOCKET, SO_ERROR, &v, &n), SOCKET_ERROR); EQ(werr(), WSAENOTSOCK);
    wset(0); EQ(sso(INVALID_SOCKET, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v), SOCKET_ERROR); EQ(werr(), WSAENOTSOCK);
    wset(0); EQ(gso((SOCKET)0, SOL_SOCKET, SO_ERROR, &v, &n), SOCKET_ERROR); EQ(werr(), WSAENOTSOCK);
    wset(0); EQ(gso((SOCKET)0x1000, SOL_SOCKET, SO_ERROR, &v, &n), SOCKET_ERROR); EQ(werr(), WSAENOTSOCK);
    ws_down();
}
TEST(sol_err_handle_of_other_object_is_enotsock)
{
    HANDLE ev; int v = 0, n = sizeof v;
    NEED();
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL);
    wset(0);
    EQ(gso((SOCKET)ev, SOL_SOCKET, SO_TYPE, &v, &n), SOCKET_ERROR);
    EQ(werr(), WSAENOTSOCK);
    CloseHandle(ev);
    ws_down();
}
TEST(sol_err_closed_socket_leaves_its_peer_usable)
{
    SOCKET a, b; int v, n = sizeof v;
    NEED();
    if (make_pair(&a, &b)) {
        EQ(cls(a), 0);
        wset(0);
        EQ(gso(a, SOL_SOCKET, SO_ERROR, &v, &n), SOCKET_ERROR);
        EQ(werr(), WSAENOTSOCK);
        EQ(gso(b, SOL_SOCKET, SO_TYPE, &v, &n), 0);       /* the peer is unaffected */
        cls(b);
    } else CHECK(0);
    ws_down();
}

/* The set path checks the value pointer before the level and the option. */
TEST(sol_err_set_null_value_precedes_level_check)
{
    SOCKET s;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0); EQ(sso(s, 0xfffe, 1, NULL, 4), SOCKET_ERROR); EQ(werr(), WSAEFAULT);
    wset(0); EQ(sso(s, SOL_SOCKET, SO_KEEPALIVE, NULL, 4), SOCKET_ERROR); EQ(werr(), WSAEFAULT);
    wset(0); EQ(sso(s, 0x7fff, 1, NULL, 4), SOCKET_ERROR); EQ(werr(), WSAEFAULT);
    cls(s); ws_down();
}
TEST(sol_err_set_null_value_precedes_applicability_check)
{
    SOCKET u; int o;
    static const int stream_only[] = { SO_ACCEPTCONN, SO_KEEPALIVE, SO_LINGER, SO_DONTLINGER, SO_OOBINLINE };
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (o = 0; o < NELEM(stream_only); o++) {
        wset(0);
        EQ(sso(u, SOL_SOCKET, stream_only[o], NULL, 4), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
    }
    cls(u); ws_down();
}
TEST(sol_err_get_null_value_precedes_applicability_check)
{
    SOCKET u, t; int o, n;
    static const int stream_only[] = { SO_ACCEPTCONN, SO_KEEPALIVE, SO_LINGER, SO_DONTLINGER, SO_OOBINLINE };
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP); t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (o = 0; o < NELEM(stream_only); o++) {
        n = 4; wset(0);
        EQ(gso(u, SOL_SOCKET, stream_only[o], NULL, &n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
        wset(0);
        EQ(gso(u, SOL_SOCKET, stream_only[o], &n, NULL), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
    }
    n = 4; wset(0);
    EQ(gso(t, SOL_SOCKET, SO_BROADCAST, NULL, &n), SOCKET_ERROR); EQ(werr(), WSAEFAULT);
    cls(u); cls(t); ws_down();
}
TEST(sol_err_get_zero_length_is_efault_for_every_applicable_option)
{
    static const int opts[] = { SO_DEBUG, SO_ACCEPTCONN, SO_REUSEADDR, SO_KEEPALIVE, SO_DONTROUTE, SO_LINGER, SO_OOBINLINE,
                                SO_DONTLINGER, SO_EXCLUSIVEADDRUSE, SO_SNDBUF, SO_RCVBUF, SO_SNDTIMEO, SO_RCVTIMEO,
                                SO_ERROR, SO_TYPE, SO_GROUP_ID, SO_GROUP_PRIORITY, SO_MAX_MSG_SIZE, SO_CONDITIONAL_ACCEPT,
                                SO_PAUSE_ACCEPT, SO_COMPARTMENT_ID, SO_RANDOMIZE_PORT, SO_PORT_SCALABILITY };
    SOCKET t; int i, n;
    unsigned char b[8];
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (i = 0; i < NELEM(opts); i++) {
        memset(b, 0xaa, sizeof b);
        n = 0; wset(0);
        EQ(gso(t, SOL_SOCKET, opts[i], b, &n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
        EQ(b[0], 0xaa);
        n = -1; wset(0);
        EQ(gso(t, SOL_SOCKET, opts[i], b, &n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
        EQ(n, -1);
    }
    cls(t); ws_down();
}

/* ---- levels: the same option name at other levels ---- */
static const struct { int level; int err; const char *name; } level_rows[] = {
    { 0xfffe, WSAENOPROTOOPT, "0xfffe" },
    { IPPROTO_IP,    WSAENOPROTOOPT, "IPPROTO_IP" },
    { IPPROTO_IPV6,  WSAENOPROTOOPT, "IPPROTO_IPV6" },
    { IPPROTO_UDP,   WSAEINVAL, "IPPROTO_UDP" },
    { -1,            WSAEINVAL, "-1" },
    { 0x7fff,        WSAEINVAL, "0x7fff" },
    { IPPROTO_ICMP,  WSAEINVAL, "IPPROTO_ICMP" },
    { IPPROTO_IGMP,  WSAEINVAL, "IPPROTO_IGMP" },
};
static void level_get(int i)
{
    SOCKET s; int v = 1, n = sizeof v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(gso(s, level_rows[i].level, SO_KEEPALIVE, &v, &n), SOCKET_ERROR);
    EQ(werr(), level_rows[i].err);
    cls(s); ws_down();
}
static void level_set(int i)
{
    SOCKET s; int v = 1;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(sso(s, level_rows[i].level, SO_KEEPALIVE, &v, sizeof v), SOCKET_ERROR);
    EQ(werr(), level_rows[i].err);
    cls(s); ws_down();
}
TEST(sol_err_level_0xfffe_get)   { level_get(0); }
TEST(sol_err_level_0xfffe_set)   { level_set(0); }
TEST(sol_err_level_ip_get)       { level_get(1); }
TEST(sol_err_level_ip_set)       { level_set(1); }
TEST(sol_err_level_ipv6_get)     { level_get(2); }
TEST(sol_err_level_ipv6_set)     { level_set(2); }
TEST(sol_err_level_udp_get)      { level_get(3); }
TEST(sol_err_level_udp_set)      { level_set(3); }
TEST(sol_err_level_minus1_get)   { level_get(4); }
TEST(sol_err_level_minus1_set)   { level_set(4); }
TEST(sol_err_level_0x7fff_get)   { level_get(5); }
TEST(sol_err_level_0x7fff_set)   { level_set(5); }
TEST(sol_err_level_icmp_get)     { level_get(6); }
TEST(sol_err_level_icmp_set)     { level_set(6); }
TEST(sol_err_level_igmp_get)     { level_get(7); }
TEST(sol_err_level_igmp_set)     { level_set(7); }
TEST(sol_err_level_tcp_set_of_socket_level_option_number)
{
    SOCKET s; int v = 1;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(sso(s, IPPROTO_TCP, SO_KEEPALIVE, &v, sizeof v), SOCKET_ERROR);   /* option number 8 is not a TCP option */
    EQ(werr(), WSAENOPROTOOPT);
    cls(s); ws_down();
}
TEST(sol_err_level_failures_do_not_disturb_socket_level_state)
{
    SOCKET s; int v = 1, w, n = sizeof w;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(sso(s, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof v), 0);
    EQ(sso(s, -1, SO_KEEPALIVE, &v, sizeof v) , SOCKET_ERROR);
    v = 0;
    EQ(sso(s, 0xfffe, SO_KEEPALIVE, &v, sizeof v), SOCKET_ERROR);
    w = 0; n = sizeof w;
    EQ(gso(s, SOL_SOCKET, SO_KEEPALIVE, &w, &n), 0);
    EQ(w & 0xff, 1);
    cls(s); ws_down();
}

/* ---- option numbers nothing implements, at the socket level ---- */
static const int unknown_opts[] = { 3, 5, 9, 0x200, 0x1234, 0x3001, 0x4000, 0x7fff, -2 };
TEST(sol_err_unknown_option_numbers_are_refused_on_get_and_set)
{
    SOCKET s; int i;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (i = 0; i < NELEM(unknown_opts); i++) {
        int v = 1, n = sizeof v, w = 0x5a5a5a5a;
        wset(0); EQ(gso(s, SOL_SOCKET, unknown_opts[i], &w, &n), SOCKET_ERROR);
        NE(werr(), 0);
        wset(0); EQ(sso(s, SOL_SOCKET, unknown_opts[i], &v, sizeof v), SOCKET_ERROR);
        NE(werr(), 0);
    }
    cls(s); ws_down();
}
TEST(sol_err_failed_read_through_transport_reports_zero_length)
{
    SOCKET s; int w = 0x5a5a5a5a, n = sizeof w;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(gso(s, SOL_SOCKET, SO_RCVLOWAT, &w, &n), SOCKET_ERROR);
    EQ(werr(), WSAENOPROTOOPT);
    EQ(n, 0);
    EQ(w, 0x5a5a5a5a);
    n = 1; wset(0);
    EQ(gso(s, SOL_SOCKET, SO_USELOOPBACK, &w, &n), SOCKET_ERROR);
    EQ(werr(), WSAENOPROTOOPT);
    EQ(n, 0);
    cls(s); ws_down();
}
TEST(sol_err_lowat_options_are_not_supported)
{
    int k, o;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k);
        if (s == INVALID_SOCKET) continue;
        for (o = SO_SNDLOWAT; o <= SO_RCVLOWAT; o++) {
            int v = 1, n = sizeof v;
            wset(0); EQ(gso(s, SOL_SOCKET, o, &v, &n), SOCKET_ERROR); EQ(werr(), kind_stream(k) ? WSAENOPROTOOPT : WSAEINVAL);
            wset(0); EQ(sso(s, SOL_SOCKET, o, &v, sizeof v), SOCKET_ERROR); EQ(werr(), kind_stream(k) ? WSAENOPROTOOPT : WSAEINVAL);
        }
        cls(s);
    }
    ws_down();
}
TEST(sol_err_useloopback_not_supported)
{
    int k;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k); int v = 1, n = sizeof v, want = kind_stream(k) ? WSAENOPROTOOPT : WSAEINVAL;
        if (s == INVALID_SOCKET) continue;
        wset(0); EQ(gso(s, SOL_SOCKET, SO_USELOOPBACK, &v, &n), SOCKET_ERROR); EQ(werr(), want);
        wset(0); EQ(sso(s, SOL_SOCKET, SO_USELOOPBACK, &v, sizeof v), SOCKET_ERROR); EQ(werr(), want);
        cls(s);
    }
    ws_down();
}
TEST(sol_err_reuse_multicastport_is_write_only_on_datagram_and_absent_on_stream)
{
    SOCKET t, u; int v = 1, n = sizeof v;
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    wset(0); EQ(gso(t, SOL_SOCKET, SO_REUSE_MULTICASTPORT, &v, &n), SOCKET_ERROR); EQ(werr(), WSAENOPROTOOPT);
    wset(0); EQ(sso(t, SOL_SOCKET, SO_REUSE_MULTICASTPORT, &v, sizeof v), SOCKET_ERROR); EQ(werr(), WSAENOPROTOOPT);
    n = sizeof v;
    wset(0); EQ(gso(u, SOL_SOCKET, SO_REUSE_MULTICASTPORT, &v, &n), SOCKET_ERROR); EQ(werr(), WSAEINVAL);
    wset(0); EQ(sso(u, SOL_SOCKET, SO_REUSE_MULTICASTPORT, &v, sizeof v), 0);
    cls(t); cls(u); ws_down();
}
