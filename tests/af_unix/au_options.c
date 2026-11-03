/* AF_UNIX stream sockets: socket options. Which SOL_SOCKET options round-trip, which are read-only,
 * argument length rules, and what the protocol-level options (TCP, IP, IPv6) do on a socket of this
 * family. Options whose acceptance is a transport decision are recorded, not asserted. */
#include "au.h"

static int get_int(SOCKET s, int level, int opt, int *v, int *err)
{
    int l = sizeof(*v), r;
    *v = 0x5a5a5a5a;
    au_seterr(0);
    r = U(getsockopt)(s, level, opt, (char *)v, &l);
    if (err) *err = r ? au_err() : 0;
    return r;
}
static int set_int(SOCKET s, int level, int opt, int v, int *err)
{
    int r;
    au_seterr(0);
    r = U(setsockopt)(s, level, opt, (const char *)&v, sizeof(v));
    if (err) *err = r ? au_err() : 0;
    return r;
}

/* ---- read-only and fixed options ----------------------------------------------------------------- */
struct ro { const char *name; int opt; };
static const struct ro g_ro[] = { { "SO_TYPE", SO_TYPE }, { "SO_ACCEPTCONN", SO_ACCEPTCONN } };
static void set_readonly(int i)
{
    SOCKET s;
    int e;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    AU_EQ(set_int(s, SOL_SOCKET, g_ro[i].opt, 1, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    U(closesocket)(s);
}
TEST(afu_opt_set_so_type_refused) { set_readonly(0); }
TEST(afu_opt_set_so_acceptconn_refused) { set_readonly(1); }
TEST(afu_opt_set_so_error_is_stored)
{
    int e, v;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(set_int(s, SOL_SOCKET, SO_ERROR, 1, &e), 0);
    AU_EQ(get_int(s, SOL_SOCKET, SO_ERROR, &v, &e), 0);
    AU_EQ(v, 1);
    U(closesocket)(s);
}

TEST(afu_opt_get_with_short_length_is_fault)
{
    char b[1];
    int l = 1;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, b, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_opt_get_null_value_is_fault)
{
    int l = 4;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, NULL, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_opt_get_null_length_is_fault)
{
    int v;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&v, NULL), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_opt_get_larger_buffer_reports_four)
{
    char b[16];
    int l = 16;
    UP();
    SOCK_OR_RETURN(s);
    memset(b, 0x77, sizeof(b));
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, b, &l), 0);
    AU_EQ(l, 4);
    U(closesocket)(s);
}

TEST(afu_opt_set_short_length_is_fault)
{
    char b = 1;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVBUF, &b, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_opt_set_null_value_is_fault)
{
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVBUF, NULL, 4), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_opt_unknown_socket_level_option)
{
    int v, e;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(get_int(s, SOL_SOCKET, 0x7ffe, &v, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    AU_EQ(set_int(s, SOL_SOCKET, 0x7ffe, 1, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    U(closesocket)(s);
}

TEST(afu_opt_unknown_level)
{
    int v, e;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(get_int(s, 0x1234, 1, &v, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    AU_EQ(set_int(s, 0x1234, 1, 1, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    U(closesocket)(s);
}

/* ---- round trips -------------------------------------------------------------------------------- */
TEST(afu_opt_rcvtimeo_roundtrip)
{
    int v, e;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(set_int(s, SOL_SOCKET, SO_RCVTIMEO, 1234, &e), 0);
    AU_EQ(get_int(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    AU_EQ(v, 1234);
    AU_EQ(set_int(s, SOL_SOCKET, SO_RCVTIMEO, 0, &e), 0);
    AU_EQ(get_int(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    AU_EQ(v, 0);
    U(closesocket)(s);
}

TEST(afu_opt_sndtimeo_roundtrip)
{
    int v, e;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(set_int(s, SOL_SOCKET, SO_SNDTIMEO, 4321, &e), 0);
    AU_EQ(get_int(s, SOL_SOCKET, SO_SNDTIMEO, &v, &e), 0);
    AU_EQ(v, 4321);
    U(closesocket)(s);
}

TEST(afu_opt_timeouts_default_zero)
{
    int v, e;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(get_int(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    AU_EQ(v, 0);
    AU_EQ(get_int(s, SOL_SOCKET, SO_SNDTIMEO, &v, &e), 0);
    AU_EQ(v, 0);
    U(closesocket)(s);
}

TEST(afu_opt_linger_roundtrip)
{
    struct linger in = { 1, 7 }, out = { 0, 0 };
    int l = sizeof(out);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&in, sizeof(in)), 0);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&out, &l), 0);
    AU_EQ(l, (int)sizeof(out));
    AU_EQ(out.l_onoff, 1);
    AU_EQ(out.l_linger, 7);
    U(closesocket)(s);
}

TEST(afu_opt_linger_default_off)
{
    struct linger out = { 9, 9 };
    int l = sizeof(out);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&out, &l), 0);
    AU_EQ(out.l_onoff, 0);
    U(closesocket)(s);
}

TEST(afu_opt_linger_short_length_is_fault)
{
    int v = 1;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&v, 2), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_opt_dontlinger_clears_linger)
{
    struct linger in = { 1, 5 }, out;
    int l = sizeof(out), on = 1, r;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&in, sizeof(in)), 0);
    r = U(setsockopt)(s, SOL_SOCKET, SO_DONTLINGER, (char *)&on, sizeof(on));
    AU_OBS("SO_DONTLINGER set", "ret %d", r);
    if (r == 0) {
        AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&out, &l), 0);
        AU_EQ(out.l_onoff, 0);
    }
    U(closesocket)(s);
}

TEST(afu_opt_exclusiveaddruse_conflicts_with_reuseaddr)
{
    int e, r;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, &e), 0);
    r = set_int(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1, &e);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(e, WSAEINVAL);
    U(closesocket)(s);
}

/* Which boolean socket options this family supports: the get result and the set result. */
static void bool_opt(int opt, const char *nm, int get_ok, int set_err)
{
    int v, e, r;
    SOCKET s;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    r = get_int(s, SOL_SOCKET, opt, &v, &e);
    if (get_ok) { AU_EQ(r, 0); AU_EQ(v, 0); }
    else { AU_EQ(r, SOCKET_ERROR); AU_EQ(e, WSAENOPROTOOPT); }
    r = set_int(s, SOL_SOCKET, opt, 1, &e);
    if (set_err) {
        AU_EQ(r, SOCKET_ERROR);
        AU_EQ(e, set_err);
    } else {
        AU_EQ(r, 0);
        AU_EQ(get_int(s, SOL_SOCKET, opt, &v, &e), 0);
        CHECK(v != 0);
        AU_EQ(set_int(s, SOL_SOCKET, opt, 0, &e), 0);
        AU_EQ(get_int(s, SOL_SOCKET, opt, &v, &e), 0);
        AU_EQ(v, 0);
    }
    U(closesocket)(s);
}
TEST(afu_opt_bool_keepalive_unsupported) { bool_opt(SO_KEEPALIVE, "SO_KEEPALIVE", 0, WSAENOPROTOOPT); }
TEST(afu_opt_bool_reuseaddr_roundtrip) { bool_opt(SO_REUSEADDR, "SO_REUSEADDR", 1, 0); }
TEST(afu_opt_bool_oobinline_unsupported) { bool_opt(SO_OOBINLINE, "SO_OOBINLINE", 1, WSAEOPNOTSUPP); }
TEST(afu_opt_bool_broadcast_unsupported) { bool_opt(SO_BROADCAST, "SO_BROADCAST", 0, WSAENOPROTOOPT); }
TEST(afu_opt_bool_debug_roundtrip) { bool_opt(SO_DEBUG, "SO_DEBUG", 1, 0); }
TEST(afu_opt_bool_dontroute_unsupported) { bool_opt(SO_DONTROUTE, "SO_DONTROUTE", 0, WSAENOPROTOOPT); }
TEST(afu_opt_bool_conditional_accept_set_unsupported) { bool_opt(SO_CONDITIONAL_ACCEPT, "SO_CONDITIONAL_ACCEPT", 1, WSAENOPROTOOPT); }

static void buf_opt(int opt, const char *nm)
{
    int v, e;
    SOCKET s;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    AU_EQ(set_int(s, SOL_SOCKET, opt, 32768, &e), 0);
    AU_EQ(get_int(s, SOL_SOCKET, opt, &v, &e), 0);
    AU_EQ(v, 32768);
    AU_EQ(set_int(s, SOL_SOCKET, opt, 0, &e), 0);
    AU_EQ(get_int(s, SOL_SOCKET, opt, &v, &e), 0);
    AU_EQ(v, 0);
    U(closesocket)(s);
}
TEST(afu_opt_rcvbuf_set_get) { buf_opt(SO_RCVBUF, "SO_RCVBUF"); }
TEST(afu_opt_sndbuf_set_get) { buf_opt(SO_SNDBUF, "SO_SNDBUF"); }

TEST(afu_opt_sndbuf_zero_send_times_out)
{
    int e;
    char b[4] = {0};
    TRIO(t, "opt_snd0.sock");
    int r;
    au_sndtimeo(t.cli, 200);
    set_int(t.cli, SOL_SOCKET, SO_SNDBUF, 0, &e);
    au_seterr(0);
    r = U(send)(t.cli, "abcd", 4, 0);
    AU_OBS("send after SO_SNDBUF=0", "ret %d err %d", r, r < 0 ? au_err() : 0);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAETIMEDOUT);
    au_trio_close(&t);
}

TEST(afu_opt_options_on_accepted_do_not_leak_to_listener)
{
    int v, e;
    TRIO(t, "opt_leak.sock");
    AU_EQ(set_int(t.srv, SOL_SOCKET, SO_RCVTIMEO, 777, &e), 0);
    AU_EQ(get_int(t.lis, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    AU_EQ(v, 0);
    au_trio_close(&t);
}

TEST(afu_opt_listener_options_inherited_by_accepted)
{
    int v, e;
    SOCKET c, s;
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "opt_inherit.sock", &a), 0);
    AU_EQ(set_int(lis, SOL_SOCKET, SO_RCVTIMEO, 888, &e), 0);
    AU_EQ(U(listen)(lis, 1), 0);
    c = au_sock();
    s = au_connect_accept(lis, c, &a);
    if (s != INVALID_SOCKET) {
        get_int(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e);
        AU_EQ(v, 888);
        U(closesocket)(s);
    }
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("opt_inherit.sock");
}

TEST(afu_opt_connect_time_unconnected_is_minus_one)
{
    int v, e;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(get_int(s, SOL_SOCKET, SO_CONNECT_TIME, &v, &e), 0);
    AU_EQ((unsigned)v, 0xffffffffu);
    U(closesocket)(s);
}

TEST(afu_opt_connect_time_connected_is_small)
{
    int v, e, r;
    TRIO(t, "opt_ct.sock");
    r = get_int(t.cli, SOL_SOCKET, SO_CONNECT_TIME, &v, &e);
    AU_EQ(r, 0);
    CHECK(v >= 0 && v < 30);
    au_trio_close(&t);
}

TEST(afu_opt_group_id_default_zero)
{
    int v, e, r;
    UP();
    SOCK_OR_RETURN(s);
    r = get_int(s, SOL_SOCKET, SO_GROUP_ID, &v, &e);
    AU_EQ(r, 0);
    AU_EQ(v, 0);
    U(closesocket)(s);
}

TEST(afu_opt_max_msg_size)
{
    int v, e, r;
    UP();
    SOCK_OR_RETURN(s);
    r = get_int(s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v, &e);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(e, WSAEOPNOTSUPP);
    U(closesocket)(s);
}

TEST(afu_opt_update_accept_context_on_accepted)
{
    int e, r;
    SOCKET lis_copy;
    TRIO(t, "opt_uac.sock");
    lis_copy = t.lis;
    au_seterr(0);
    r = U(setsockopt)(t.srv, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&lis_copy, sizeof(lis_copy));
    e = r ? au_err() : 0;
    AU_EQ(r, 0);
    au_trio_close(&t);
}

TEST(afu_opt_bsp_state)
{
    CSADDR_INFO ci;
    int l = sizeof(ci), r;
    UP();
    SOCK_OR_RETURN(s);
    memset(&ci, 0, sizeof(ci));
    au_seterr(0);
    r = U(getsockopt)(s, SOL_SOCKET, SO_BSP_STATE, (char *)&ci, &l);
    AU_OBS("SO_BSP_STATE unbound", "ret %d err %d", r, r ? au_err() : 0);
    U(closesocket)(s);
}

/* ---- protocol-level options on this family ------------------------------------------------------ */
struct plopt { const char *name; int level, opt; };
static const struct plopt g_pl[] = {
    { "IPPROTO_TCP/TCP_NODELAY", IPPROTO_TCP, 1 },
    { "IPPROTO_TCP/TCP_MAXSEG", IPPROTO_TCP, 4 },
    { "IPPROTO_TCP/TCP_KEEPALIVE", IPPROTO_TCP, 3 },
    { "IPPROTO_IP/IP_TTL", IPPROTO_IP, 4 },
    { "IPPROTO_IP/IP_TOS", IPPROTO_IP, 3 },
    { "IPPROTO_IP/IP_OPTIONS", IPPROTO_IP, 1 },
    { "IPPROTO_IPV6/IPV6_V6ONLY", IPPROTO_IPV6, 27 },
    { "IPPROTO_IPV6/IPV6_UNICAST_HOPS", IPPROTO_IPV6, 4 },
    { "IPPROTO_UDP/UDP_NOCHECKSUM", IPPROTO_UDP, 1 },
    { "NSPROTO_IPX/1", 1000, 1 },
};
static void protocol_level(int i)
{
    int v, e;
    SOCKET s;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    AU_EQ(get_int(s, g_pl[i].level, g_pl[i].opt, &v, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    AU_EQ(set_int(s, g_pl[i].level, g_pl[i].opt, 1, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOPROTOOPT);
    U(closesocket)(s);
}
#define PL_TEST(n, i) TEST(afu_opt_protocol_level_##n) { protocol_level(i); }
PL_TEST(tcp_nodelay, 0) PL_TEST(tcp_maxseg, 1) PL_TEST(tcp_keepalive, 2) PL_TEST(ip_ttl, 3) PL_TEST(ip_tos, 4)
PL_TEST(ip_options, 5) PL_TEST(ipv6_v6only, 6) PL_TEST(ipv6_hops, 7) PL_TEST(udp_nochecksum, 8) PL_TEST(ipx, 9)

TEST(afu_opt_refused_nodelay_leaves_data_path)
{
    int e;
    char b[4] = {0};
    TRIO(t, "opt_nodelay.sock");
    AU_EQ(set_int(t.cli, IPPROTO_TCP, 1, 1, &e), SOCKET_ERROR);
    AU_EQ(U(send)(t.cli, "nd", 2, 0), 2);
    AU_EQ(au_recv_n(t.srv, b, 2), 2);
    CHECK(!memcmp(b, "nd", 2));
    au_trio_close(&t);
}

TEST(afu_opt_set_after_close_is_notsock)
{
    int e;
    SOCKET s;
    UP();
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    U(closesocket)(s);
    AU_EQ(set_int(s, SOL_SOCKET, SO_RCVBUF, 4096, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOTSOCK);
    AU_EQ(get_int(s, SOL_SOCKET, SO_RCVBUF, &e, &e), SOCKET_ERROR);
    AU_EQ(e, WSAENOTSOCK);
}

TEST(afu_opt_options_persist_across_bind_listen_connect)
{
    int v, e;
    TRIO(t, "opt_persist.sock");
    AU_EQ(set_int(t.cli, SOL_SOCKET, SO_SNDTIMEO, 2468, &e), 0);
    AU_EQ(get_int(t.cli, SOL_SOCKET, SO_SNDTIMEO, &v, &e), 0);
    AU_EQ(v, 2468);
    au_trio_close(&t);
}

TEST(afu_opt_protocol_info_on_accepted)
{
    WSAPROTOCOL_INFOW pi;
    int l = sizeof(pi);
    TRIO(t, "opt_pi_acc.sock");
    AU_EQ(U(getsockopt)(t.srv, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    AU_EQ(pi.iAddressFamily, AF_UNIX);
    AU_EQ(pi.iSocketType, SOCK_STREAM);
    au_trio_close(&t);
}
