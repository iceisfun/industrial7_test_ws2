/* The AF_UNIX socket surface that the other files in this area do not reach: which socket() type and protocol
 * combinations are accepted, the protocol-info record, the default value and writability of each socket option,
 * the error for every data or state call made in the wrong state, the shape of names returned by
 * getsockname/getpeername for each end of a connection, and the behaviour of a connection whose peer went away
 * (plain close versus reset). Each case builds its own socket state. */
#include "xud.h"

/* ---- socket() creation matrix ---- */
struct mk { int type, proto, ok, err; };
static void check_mk(const struct mk *m)
{
    SOCKET s;
    UP();
    s = U(WSASocketW)(AF_UNIX, m->type, m->proto, NULL, 0, 0);
    if (m->ok) {
        CHECK(s != INVALID_SOCKET);
    } else {
        XEQ(s, INVALID_SOCKET);
        XEQ(x_err(), m->err);
    }
    if (s != INVALID_SOCKET) U(closesocket)(s);
}
#define MK(nm, ty, pr, ok, er) TEST(xud_sk_create_##nm) { static const struct mk m = { ty, pr, ok, er }; check_mk(&m); }
MK(type0_proto0, 0, 0, 1, 0)
MK(stream_proto0, SOCK_STREAM, 0, 1, 0)
MK(stream_proto1, SOCK_STREAM, 1, 0, WSAEPROTONOSUPPORT)
MK(stream_proto6, SOCK_STREAM, 6, 0, WSAEPROTONOSUPPORT)
MK(stream_proto17, SOCK_STREAM, 17, 0, WSAEPROTONOSUPPORT)
MK(stream_proto255, SOCK_STREAM, 255, 0, WSAEPROTONOSUPPORT)
MK(type0_proto1, 0, 1, 0, WSAEPROTONOSUPPORT)
MK(dgram_proto0, SOCK_DGRAM, 0, 0, WSAEAFNOSUPPORT)
MK(dgram_proto1, SOCK_DGRAM, 1, 0, WSAEAFNOSUPPORT)
MK(raw_proto0, SOCK_RAW, 0, 0, WSAEAFNOSUPPORT)
MK(rdm_proto0, SOCK_RDM, 0, 0, WSAESOCKTNOSUPPORT)
MK(seqpacket_proto0, SOCK_SEQPACKET, 0, 0, WSAESOCKTNOSUPPORT)
MK(type6_proto0, 6, 0, 0, WSAESOCKTNOSUPPORT)

TEST(xud_sk_create_flags_overlapped_and_plain_both_work)
{
    SOCKET a, b;
    UP();
    a = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, 0);
    b = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET);
    if (a != INVALID_SOCKET) U(closesocket)(a);
    if (b != INVALID_SOCKET) U(closesocket)(b);
}
TEST(xud_sk_create_socket_call_matches_wsasocket)
{
    SOCKET s;
    UP();
    s = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    s = U(socket)(AF_UNIX, SOCK_DGRAM, 0);
    XEQ(s, INVALID_SOCKET);
    XEQ(x_err(), WSAEAFNOSUPPORT);
}

/* ---- protocol information record ---- */
TEST(xud_sk_protocol_info_fields)
{
    WSAPROTOCOL_INFOW pi;
    int l = sizeof pi;
    SOCK_OR_RETURN(s);
    memset(&pi, 0, sizeof pi);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    XEQ(l, sizeof pi);
    XEQ(pi.iAddressFamily, AF_UNIX);
    XEQ(pi.iSocketType, SOCK_STREAM);
    XEQ(pi.iProtocol, 0);
    XEQ(pi.iMinSockAddr, 2);
    XEQ(pi.iMaxSockAddr, sizeof(SOCKADDR_UN));
    XEQ(pi.dwMessageSize, 0);
    XEQ(pi.iSecurityScheme, 0);
    OBS("service flags 0x%lx provider flags 0x%lx", pi.dwServiceFlags1, pi.dwProviderFlags);
    U(closesocket)(s);
}
TEST(xud_sk_protocol_info_small_buffer_reports_needed_size)
{
    char small[4];
    int l = sizeof small;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOA, small, &l), -1);
    XEQ(x_err(), WSAEFAULT);
    XEQ(l, sizeof(WSAPROTOCOL_INFOA));
    U(closesocket)(s);
}
TEST(xud_sk_protocol_info_wide_small_buffer_is_fault)
{
    char small[4];
    int l = sizeof small;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, small, &l), -1);
    XEQ(x_err(), WSAEFAULT);
    XEQ(l, sizeof small);                                    /* the wide form leaves the length alone */
    U(closesocket)(s);
}

/* ---- default option values (fresh socket): name, level, option, expected getsockopt result/value/error ---- */
struct og { const char *nm; int opt; int ok; int val; int err; };
static void check_og(const struct og *o)
{
    int v = -1, l = sizeof v, r;
    SOCK_OR_RETURN(s);
    r = U(getsockopt)(s, SOL_SOCKET, o->opt, (char *)&v, &l);
    if (o->ok) { XEQ(r, 0); XEQ(l, 4); XEQ(v, o->val); }
    else { XEQ(r, -1); XEQ(x_err(), o->err); }
    U(closesocket)(s);
}
#define OG(nm, opt, ok, val, er) TEST(xud_sk_default_##nm) { static const struct og o = { #nm, opt, ok, val, er }; check_og(&o); }
OG(type, SO_TYPE, 1, SOCK_STREAM, 0)
OG(acceptconn, SO_ACCEPTCONN, 1, 0, 0)
OG(sndbuf, SO_SNDBUF, 1, 65536, 0)
OG(rcvbuf, SO_RCVBUF, 1, 65536, 0)
OG(reuseaddr, SO_REUSEADDR, 1, 0, 0)
OG(exclusiveaddruse, SO_EXCLUSIVEADDRUSE, 1, 0, 0)
OG(oobinline, SO_OOBINLINE, 1, 0, 0)
OG(rcvtimeo, SO_RCVTIMEO, 1, 0, 0)
OG(sndtimeo, SO_SNDTIMEO, 1, 0, 0)
OG(conditional_accept, SO_CONDITIONAL_ACCEPT, 1, 0, 0)
OG(debug, SO_DEBUG, 1, 0, 0)
OG(dontlinger, SO_DONTLINGER, 1, 1, 0)
OG(error, SO_ERROR, 1, 0, 0)
OG(group_id, SO_GROUP_ID, 1, 0, 0)
OG(group_priority, SO_GROUP_PRIORITY, 1, 0, 0)
OG(keepalive, SO_KEEPALIVE, 0, 0, WSAENOPROTOOPT)
OG(broadcast, SO_BROADCAST, 0, 0, WSAENOPROTOOPT)
OG(dontroute, SO_DONTROUTE, 0, 0, WSAENOPROTOOPT)
OG(useloopback, SO_USELOOPBACK, 0, 0, WSAENOPROTOOPT)
OG(update_accept_context, SO_UPDATE_ACCEPT_CONTEXT, 0, 0, WSAENOPROTOOPT)
OG(max_msg_size, SO_MAX_MSG_SIZE, 0, 0, WSAEOPNOTSUPP)

TEST(xud_sk_default_linger_is_off)
{
    LINGER lg = { 7, 7 };
    int l = sizeof lg;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, &l), 0);
    XEQ(lg.l_onoff, 0);
    U(closesocket)(s);
}
TEST(xud_sk_linger_roundtrip)
{
    LINGER lg = { 1, 5 };
    int l = sizeof lg;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg), 0);
    lg.l_onoff = 0; lg.l_linger = 0;
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, &l), 0);
    XEQ(lg.l_onoff, 1);
    XEQ(lg.l_linger, 5);
    U(closesocket)(s);
}
TEST(xud_sk_getsockopt_one_byte_buffer_is_fault)
{
    char b;
    int l = 1;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, &b, &l), -1);
    XEQ(x_err(), WSAEFAULT);
    U(closesocket)(s);
}
TEST(xud_sk_getsockopt_oversize_buffer_reports_four)
{
    char b[8];
    int l = sizeof b;
    SOCK_OR_RETURN(s);
    memset(b, 0, sizeof b);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, b, &l), 0);
    XEQ(l, 4);
    XEQ(*(int *)b, SOCK_STREAM);
    U(closesocket)(s);
}
TEST(xud_sk_getsockopt_null_value_is_fault)
{
    int l = 4;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, NULL, &l), -1);
    XEQ(x_err(), WSAEFAULT);
    U(closesocket)(s);
}
TEST(xud_sk_getsockopt_null_length_is_fault)
{
    int v;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&v, NULL), -1);
    XEQ(x_err(), WSAEFAULT);
    U(closesocket)(s);
}
TEST(xud_sk_getsockopt_unknown_level_is_noprotoopt)
{
    int v, l = 4;
    SOCK_OR_RETURN(s);
    XEQ(U(getsockopt)(s, 0x1234, 1, (char *)&v, &l), -1);
    XEQ(x_err(), WSAENOPROTOOPT);
    U(closesocket)(s);
}

/* ---- setsockopt matrix on a fresh socket ---- */
struct os { int opt; int val; int sz; int ok; int err; };
static void check_os(const struct os *o)
{
    int r;
    SOCK_OR_RETURN(s);
    r = U(setsockopt)(s, SOL_SOCKET, o->opt, (const char *)&o->val, o->sz);
    if (o->ok) XEQ(r, 0);
    else { XEQ(r, -1); XEQ(x_err(), o->err); }
    U(closesocket)(s);
}
#define OS(nm, opt, val, sz, ok, er) TEST(xud_sk_set_##nm) { static const struct os o = { opt, val, sz, ok, er }; check_os(&o); }
OS(keepalive, SO_KEEPALIVE, 1, 4, 0, WSAENOPROTOOPT)
OS(broadcast, SO_BROADCAST, 1, 4, 0, WSAENOPROTOOPT)
OS(type_readonly, SO_TYPE, 1, 4, 0, WSAENOPROTOOPT)
OS(acceptconn_readonly, SO_ACCEPTCONN, 1, 4, 0, WSAENOPROTOOPT)
OS(conditional_accept, SO_CONDITIONAL_ACCEPT, 1, 4, 0, WSAENOPROTOOPT)
OS(error_is_accepted, SO_ERROR, 1, 4, 1, 0)
OS(reuseaddr, SO_REUSEADDR, 1, 4, 1, 0)
OS(reuseaddr_one_byte, SO_REUSEADDR, 1, 1, 1, 0)
OS(reuseaddr_zero_bytes, SO_REUSEADDR, 1, 0, 1, 0)
OS(reuseaddr_eight_bytes, SO_REUSEADDR, 1, 8, 1, 0)
OS(sndbuf, SO_SNDBUF, 65536, 4, 1, 0)
OS(sndbuf_zero, SO_SNDBUF, 0, 4, 1, 0)

TEST(xud_sk_set_nodelay_is_noprotoopt)
{
    DWORD x = 1;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, IPPROTO_TCP, 1, (char *)&x, sizeof x), -1);
    XEQ(x_err(), WSAENOPROTOOPT);
    XEQ(U(getsockopt)(s, IPPROTO_TCP, 1, (char *)&x, &(int){ 4 }), -1);
    XEQ(x_err(), WSAENOPROTOOPT);
    U(closesocket)(s);
}
TEST(xud_sk_rcvtimeo_roundtrip)
{
    DWORD v = 1234, g = 0;
    int l = sizeof g;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, sizeof v), 0);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&g, &l), 0);
    XEQ(g, 1234);
    U(closesocket)(s);
}
TEST(xud_sk_sndtimeo_roundtrip)
{
    DWORD v = 4321, g = 0;
    int l = sizeof g;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&v, sizeof v), 0);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&g, &l), 0);
    XEQ(g, 4321);
    U(closesocket)(s);
}
TEST(xud_sk_acceptconn_reads_one_on_listener)
{
    int v = -1, l = 4;
    TRIO(t, "sk_ac.sock");
    XEQ(U(getsockopt)(t.lis, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &l), 0);
    XEQ(v, 1);
    v = -1;
    XEQ(U(getsockopt)(t.cli, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &l), 0);
    XEQ(v, 0);
    x_trio_close(&t);
}

/* ---- wrong-state call table: each case on a socket in its own state ---- */
enum { K_FRESH, K_BOUND, K_LISTEN, K_CONN };
struct sc { int kind; int op; int err; };
enum { O_SEND, O_RECV, O_SHUT, O_LISTEN, O_ACCEPT, O_BIND, O_CONNECT, O_GSN, O_GPN };
static void check_sc(const struct sc *c)
{
    SOCKADDR_UN a, o;
    char b[8];
    int r = 0, l = sizeof o;
    struct x_trio t;
    SOCKET s = INVALID_SOCKET;
    UP();
    t.lis = t.cli = t.srv = INVALID_SOCKET;
    t.path[0] = 0;
    if (c->kind == K_CONN) {
        if (!x_trio_open(&t, "sk_sc.sock")) return;
        s = t.cli;
    } else {
        s = x_sock();
        if (s == INVALID_SOCKET) return;
        x_addr(&a, x_path("sk_sc.sock"));
        strcpy(t.path, a.sun_path);
        if (c->kind >= K_BOUND && x_bind(s, &a)) { t_skip("bind failed"); U(closesocket)(s); return; }
        if (c->kind == K_LISTEN && U(listen)(s, 2)) { t_skip("listen failed"); U(closesocket)(s); DeleteFileA(t.path); return; }
    }
    x_addr(&a, x_path("sk_sc.sock"));
    memset(&o, 0, sizeof o);
    switch (c->op) {
    case O_SEND: r = U(send)(s, b, 1, 0); break;
    case O_RECV: r = U(recv)(s, b, 1, 0); break;
    case O_SHUT: r = U(shutdown)(s, SD_BOTH); break;
    case O_LISTEN: r = U(listen)(s, 3); break;
    case O_ACCEPT: r = U(accept)(s, NULL, NULL) == INVALID_SOCKET ? -1 : 0; break;
    case O_BIND: r = x_bind(s, &a); break;
    case O_CONNECT: r = x_connect(s, &a); break;
    case O_GSN: r = U(getsockname)(s, (struct sockaddr *)&o, &l); break;
    case O_GPN: r = U(getpeername)(s, (struct sockaddr *)&o, &l); break;
    }
    if (c->err) { XEQ(r, -1); XEQ(x_err(), c->err); } else XEQ(r, 0);
    if (c->kind == K_CONN) x_trio_close(&t);
    else { U(closesocket)(s); if (t.path[0]) DeleteFileA(t.path); }
}
#define SC(nm, kind, op, er) TEST(xud_sk_state_##nm) { static const struct sc c = { kind, op, er }; check_sc(&c); }
SC(fresh_send, K_FRESH, O_SEND, WSAENOTCONN)
SC(fresh_recv, K_FRESH, O_RECV, WSAENOTCONN)
SC(fresh_shutdown, K_FRESH, O_SHUT, WSAENOTCONN)
SC(fresh_accept, K_FRESH, O_ACCEPT, WSAEINVAL)
SC(fresh_listen, K_FRESH, O_LISTEN, WSAEINVAL)
SC(fresh_getsockname, K_FRESH, O_GSN, WSAEINVAL)
SC(fresh_getpeername, K_FRESH, O_GPN, WSAENOTCONN)
SC(bound_send, K_BOUND, O_SEND, WSAENOTCONN)
SC(bound_recv, K_BOUND, O_RECV, WSAENOTCONN)
SC(bound_shutdown, K_BOUND, O_SHUT, WSAENOTCONN)
SC(bound_accept, K_BOUND, O_ACCEPT, WSAEINVAL)
SC(bound_getpeername, K_BOUND, O_GPN, WSAENOTCONN)
SC(bound_getsockname, K_BOUND, O_GSN, 0)
SC(bound_listen, K_BOUND, O_LISTEN, 0)
SC(listener_send, K_LISTEN, O_SEND, WSAENOTCONN)
SC(listener_recv, K_LISTEN, O_RECV, WSAENOTCONN)
SC(listener_shutdown, K_LISTEN, O_SHUT, WSAENOTCONN)
SC(listener_bind, K_LISTEN, O_BIND, WSAEINVAL)
SC(listener_connect, K_LISTEN, O_CONNECT, WSAEOPNOTSUPP)
SC(listener_listen_again, K_LISTEN, O_LISTEN, 0)
SC(listener_getpeername, K_LISTEN, O_GPN, WSAENOTCONN)
SC(connected_listen, K_CONN, O_LISTEN, WSAEISCONN)
SC(connected_accept, K_CONN, O_ACCEPT, WSAEINVAL)
SC(connected_bind, K_CONN, O_BIND, WSAEINVAL)
SC(connected_connect_again, K_CONN, O_CONNECT, WSAEISCONN)

TEST(xud_sk_shutdown_invalid_how)
{
    TRIO(t, "sk_how.sock");
    XEQ(U(shutdown)(t.cli, 7), -1);
    XEQ(x_err(), WSAEINVAL);
    XEQ(U(shutdown)(t.cli, -1), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_sk_wrong_family_in_address)
{
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("sk_fam.sock"));
    a.sun_family = AF_INET;
    XEQ(x_bind(s, &a), -1);
    XEQ(x_err(), WSAEAFNOSUPPORT);
    XEQ(x_connect(s, &a), -1);
    XEQ(x_err(), WSAEAFNOSUPPORT);
    a.sun_family = AF_UNSPEC;
    XEQ(x_bind(s, &a), -1);
    XEQ(x_err(), WSAEAFNOSUPPORT);
    XEQ(x_connect(s, &a), -1);
    XEQ(x_err(), WSAEAFNOSUPPORT);
    U(closesocket)(s);
    CHECK(!x_exists(a.sun_path));
}

/* ---- empty-name binds ---- */
static void bind_empty(int len)
{
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    XEQ(x_bind_len(s, &a, len), 0);
    U(closesocket)(s);
}
TEST(xud_sk_bind_empty_name_family_only_len_3) { bind_empty(3); }
TEST(xud_sk_bind_empty_name_full_len) { bind_empty((int)sizeof(SOCKADDR_UN)); }

/* ---- names of each end ---- */
TEST(xud_sk_name_listener_length_counts_terminator)
{
    SOCKADDR_UN o;
    int l = sizeof o;
    TRIO(t, "sk_nm1.sock");
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getsockname)(t.lis, (struct sockaddr *)&o, &l), 0);
    XEQ(l, X_ADDR_BASE + strlen(t.path) + 1);
    XEQ(o.sun_family, AF_UNIX);
    CHECK(!strcmp(o.sun_path, t.path));
    x_trio_close(&t);
}
TEST(xud_sk_name_accepted_socket_carries_listener_name)
{
    SOCKADDR_UN o;
    int l = sizeof o;
    TRIO(t, "sk_nm2.sock");
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getsockname)(t.srv, (struct sockaddr *)&o, &l), 0);
    XEQ(l, X_ADDR_BASE + strlen(t.path) + 1);
    CHECK(!strcmp(o.sun_path, t.path));
    x_trio_close(&t);
}
TEST(xud_sk_name_unbound_client_is_full_size_empty)
{
    SOCKADDR_UN o;
    int l = sizeof o;
    TRIO(t, "sk_nm3.sock");
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getsockname)(t.cli, (struct sockaddr *)&o, &l), 0);
    XEQ(l, sizeof o);
    XEQ(o.sun_family, AF_UNIX);
    XEQ(o.sun_path[0], 0);
    x_trio_close(&t);
}
TEST(xud_sk_name_peer_of_accepted_socket_is_unnamed)
{
    SOCKADDR_UN o;
    int l = sizeof o;
    TRIO(t, "sk_nm4.sock");
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getpeername)(t.srv, (struct sockaddr *)&o, &l), 0);
    XEQ(l, sizeof o);
    XEQ(o.sun_family, AF_UNIX);
    XEQ(o.sun_path[0], 0);
    x_trio_close(&t);
}
TEST(xud_sk_name_peer_of_client_is_listener_path)
{
    SOCKADDR_UN o;
    int l = sizeof o;
    TRIO(t, "sk_nm5.sock");
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getpeername)(t.cli, (struct sockaddr *)&o, &l), 0);
    XEQ(o.sun_family, AF_UNIX);
    CHECK(!strcmp(o.sun_path, t.path));
    OBS("peer name length class: %s", l == (int)sizeof o ? "full" : "short");
    x_trio_close(&t);
}
TEST(xud_sk_name_buffer_exactly_enough_succeeds)
{
    SOCKADDR_UN o;
    TRIO(t, "sk_nm6.sock");
    int l = X_ADDR_BASE + (int)strlen(t.path) + 1;
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getsockname)(t.lis, (struct sockaddr *)&o, &l), 0);
    XEQ(l, X_ADDR_BASE + strlen(t.path) + 1);
    CHECK(!strcmp(o.sun_path, t.path));
    x_trio_close(&t);
}
TEST(xud_sk_name_buffer_one_short_is_fault_and_length_untouched)
{
    SOCKADDR_UN o;
    TRIO(t, "sk_nm7.sock");
    int l = X_ADDR_BASE + (int)strlen(t.path), want = l;
    XEQ(U(getsockname)(t.lis, (struct sockaddr *)&o, &l), -1);
    XEQ(x_err(), WSAEFAULT);
    XEQ(l, want);
    x_trio_close(&t);
}
TEST(xud_sk_name_tiny_lengths_are_fault)
{
    static const int lens[] = { 3, 2, 1, 0, -1 };
    SOCKADDR_UN o;
    unsigned i;
    TRIO(t, "sk_nm8.sock");
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        int l = lens[i];
        XEQ(U(getsockname)(t.lis, (struct sockaddr *)&o, &l), -1);
        XEQ(x_err(), WSAEFAULT);
        XEQ(l, lens[i]);
    }
    x_trio_close(&t);
}
TEST(xud_sk_name_peer_small_buffer_is_fault)
{
    SOCKADDR_UN o;
    int l = 6;
    TRIO(t, "sk_nm9.sock");
    XEQ(U(getpeername)(t.cli, (struct sockaddr *)&o, &l), -1);
    XEQ(x_err(), WSAEFAULT);
    x_trio_close(&t);
}
TEST(xud_sk_name_peer_survives_local_shutdown_and_peer_close)
{
    SOCKADDR_UN o;
    int l = sizeof o;
    TRIO(t, "sk_nm10.sock");
    U(shutdown)(t.cli, SD_BOTH);
    XEQ(U(getpeername)(t.cli, (struct sockaddr *)&o, &l), 0);
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    Sleep(100);
    l = sizeof o;
    XEQ(U(getpeername)(t.cli, (struct sockaddr *)&o, &l), 0);
    x_trio_close(&t);
}

/* ---- peer gone: graceful close versus reset ---- */
static void peer_gone(struct x_trio *t, int reset)
{
    if (reset) { LINGER lg = { 1, 0 }; U(setsockopt)(t->srv, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg); }
    U(closesocket)(t->srv);
    t->srv = INVALID_SOCKET;
    x_readable(t->cli, 3000);
}
TEST(xud_sk_reset_recv_fails_repeatedly)
{
    char b[2];
    TRIO(t, "sk_rs1.sock");
    peer_gone(&t, 1);
    XEQ(U(recv)(t.cli, b, 1, 0), -1);
    XEQ(x_err(), WSAECONNRESET);
    XEQ(U(recv)(t.cli, b, 1, 0), -1);
    XEQ(x_err(), WSAECONNRESET);
    x_trio_close(&t);
}
TEST(xud_sk_reset_send_fails)
{
    TRIO(t, "sk_rs2.sock");
    peer_gone(&t, 1);
    XEQ(U(send)(t.cli, "a", 1, 0), -1);
    XEQ(x_err(), WSAECONNRESET);
    x_trio_close(&t);
}
TEST(xud_sk_reset_so_error_stays_zero)
{
    int v = -1, l = 4;
    TRIO(t, "sk_rs3.sock");
    peer_gone(&t, 1);
    XEQ(U(getsockopt)(t.cli, SOL_SOCKET, SO_ERROR, (char *)&v, &l), 0);
    XEQ(v, 0);
    x_trio_close(&t);
}
TEST(xud_sk_graceful_close_first_send_succeeds_second_resets)
{
    TRIO(t, "sk_rs4.sock");
    peer_gone(&t, 0);
    XEQ(U(send)(t.cli, "a", 1, 0), 1);
    XEQ(U(send)(t.cli, "a", 1, 0), -1);
    XEQ(x_err(), WSAECONNRESET);
    x_trio_close(&t);
}

/* ---- gather/scatter argument validation ---- */
TEST(xud_sk_wsasend_null_buffers_is_inval)
{
    DWORD n = 0;
    TRIO(t, "sk_ws1.sock");
    XEQ(U(WSASend)(t.cli, NULL, 0, &n, 0, NULL, NULL), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_sk_wsasend_zero_buffer_count_is_inval)
{
    DWORD n = 0;
    char c = 'x';
    WSABUF b;
    TRIO(t, "sk_ws2.sock");
    b.len = 1; b.buf = &c;
    XEQ(U(WSASend)(t.cli, &b, 0, &n, 0, NULL, NULL), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_sk_wsarecv_zero_length_buffer_waits_for_data)
{
    DWORD n = 0, f = 0;
    char c;
    WSABUF b;
    TRIO(t, "sk_ws3.sock");
    b.len = 0; b.buf = &c;
    x_rcvtimeo(t.srv, 200);
    XEQ(U(WSARecv)(t.srv, &b, 1, &n, &f, NULL, NULL), -1);
    XEQ(x_err(), WSAETIMEDOUT);
    x_trio_close(&t);
}
TEST(xud_sk_update_contexts_accept_no_value)
{
    SOCKET l;
    TRIO(t, "sk_uc.sock");
    l = t.lis;
    XEQ(U(setsockopt)(t.cli, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), 0);
    XEQ(U(setsockopt)(t.srv, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof l), 0);
    x_trio_close(&t);
}

/* ---- data-call argument and flag handling on a connected pair ---- */
TEST(xud_sk_sendto_on_stream_ignores_the_name)
{
    char b[4];
    TRIO(t, "sk_st1.sock");
    XEQ(U(sendto)(t.cli, "a", 1, 0, (struct sockaddr *)&t.addr, sizeof t.addr), 1);
    XEQ(U(sendto)(t.cli, "b", 1, 0, NULL, 0), 1);
    XEQ(U(sendto)(t.cli, "c", 1, 0, (struct sockaddr *)&t.addr, 1), 1);
    XEQ(x_recv_n(t.srv, b, 3), 3);
    CHECK(!memcmp(b, "abc", 3));
    x_trio_close(&t);
}
TEST(xud_sk_wsasendto_on_stream_succeeds)
{
    DWORD n = 0;
    char c = 'x', r = 0;
    WSABUF b;
    TRIO(t, "sk_st2.sock");
    b.len = 1; b.buf = &c;
    XEQ(U(WSASendTo)(t.cli, &b, 1, &n, 0, (struct sockaddr *)&t.addr, sizeof t.addr, NULL, NULL), 0);
    XEQ(n, 1);
    XEQ(U(recv)(t.srv, &r, 1, 0), 1);
    XEQ(r, 'x');
    x_trio_close(&t);
}
TEST(xud_sk_recvfrom_on_stream_leaves_the_from_buffer_alone)
{
    struct sockaddr_storage ss;
    int l = sizeof ss;
    char c;
    TRIO(t, "sk_st3.sock");
    memset(&ss, 0x55, sizeof ss);
    XEQ(U(send)(t.cli, "a", 1, 0), 1);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(recvfrom)(t.srv, &c, 1, 0, (struct sockaddr *)&ss, &l), 1);
    XEQ(l, sizeof ss);
    XEQ(ss.ss_family, 0x5555);
    x_trio_close(&t);
}
TEST(xud_sk_recvfrom_on_stream_without_from_buffer)
{
    char c;
    TRIO(t, "sk_st4.sock");
    XEQ(U(send)(t.cli, "a", 1, 0), 1);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(recvfrom)(t.srv, &c, 1, 0, NULL, NULL), 1);
    x_trio_close(&t);
}
TEST(xud_sk_send_zero_length_succeeds_with_zero)
{
    TRIO(t, "sk_z1.sock");
    XEQ(U(send)(t.cli, "", 0, 0), 0);
    XEQ(U(send)(t.cli, NULL, 0, 0), 0);
    CHECK(!x_readable(t.srv, 100));                          /* nothing arrived, in particular no end of stream */
    x_trio_close(&t);
}
TEST(xud_sk_recv_zero_length_with_data_returns_zero)
{
    char c;
    TRIO(t, "sk_z2.sock");
    XEQ(U(send)(t.cli, "a", 1, 0), 1);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(recv)(t.srv, &c, 0, 0), 0);
    XEQ(U(recv)(t.srv, &c, 1, 0), 1);                        /* the byte was not consumed */
    x_trio_close(&t);
}
TEST(xud_sk_recv_zero_length_without_data_waits)
{
    char c;
    TRIO(t, "sk_z3.sock");
    x_rcvtimeo(t.srv, 200);
    XEQ(U(recv)(t.srv, &c, 0, 0), -1);
    XEQ(x_err(), WSAETIMEDOUT);
    XEQ(U(recv)(t.srv, NULL, 0, 0), -1);
    XEQ(x_err(), WSAETIMEDOUT);
    x_trio_close(&t);
}
TEST(xud_sk_negative_lengths_are_fault)
{
    char c;
    TRIO(t, "sk_z4.sock");
    XEQ(U(send)(t.cli, &c, -1, 0), -1);
    XEQ(x_err(), WSAEFAULT);
    XEQ(U(recv)(t.srv, &c, -1, 0), -1);
    XEQ(x_err(), WSAEFAULT);
    x_trio_close(&t);
}
TEST(xud_sk_peek_returns_data_and_leaves_it)
{
    char b[4];
    TRIO(t, "sk_pk.sock");
    XEQ(U(send)(t.cli, "ab", 2, 0), 2);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(recv)(t.srv, b, 4, MSG_PEEK), 2);
    XEQ(U(recv)(t.srv, b, 4, 0), 2);
    x_trio_close(&t);
}
TEST(xud_sk_unknown_send_flag_is_opnotsupp)
{
    TRIO(t, "sk_fl1.sock");
    XEQ(U(send)(t.cli, "o", 1, 0x1000), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    x_trio_close(&t);
}
TEST(xud_sk_unknown_recv_flag_is_opnotsupp)
{
    char c;
    TRIO(t, "sk_fl2.sock");
    XEQ(U(recv)(t.srv, &c, 1, 0x40), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    x_trio_close(&t);
}
TEST(xud_sk_send_oob_is_inval)
{
    TRIO(t, "sk_oob1.sock");
    XEQ(U(send)(t.cli, "o", 1, MSG_OOB), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_sk_send_oob_failure_poisons_the_connection)
{
    TRIO(t, "sk_oob2.sock");
    XEQ(U(send)(t.cli, "o", 1, MSG_OOB), -1);
    XEQ(U(send)(t.cli, "o", 1, 0), -1);
    XEQ(x_err(), WSAECONNABORTED);
    x_trio_close(&t);
}
TEST(xud_sk_recv_oob_never_returns_normal_data)
{
    char c;
    TRIO(t, "sk_oob3.sock");
    x_rcvtimeo(t.srv, 200);
    XEQ(U(send)(t.cli, "a", 1, 0), 1);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(recv)(t.srv, &c, 1, MSG_OOB), -1);
    XEQ(x_err(), WSAETIMEDOUT);
    XEQ(U(recv)(t.srv, &c, 1, 0), 1);                        /* the data is still there */
    x_trio_close(&t);
}

/* ---- accept() address argument ---- */
TEST(xud_sk_accept_address_is_full_size_and_unnamed)
{
    SOCKADDR_UN a, o;
    SOCKET c, q;
    int l = 128;
    TRIO(t, "sk_ac1.sock");
    c = x_sock();
    x_addr(&a, t.path);
    x_blocking(c, FALSE);
    x_connect(c, &a);
    CHECK(x_readable(t.lis, 3000));
    memset(&o, 0xaa, sizeof o);
    q = U(accept)(t.lis, (struct sockaddr *)&o, &l);
    CHECK(q != INVALID_SOCKET);
    XEQ(l, sizeof o);
    XEQ(o.sun_family, AF_UNIX);
    XEQ(o.sun_path[0], 0);
    if (q != INVALID_SOCKET) U(closesocket)(q);
    U(closesocket)(c);
    x_trio_close(&t);
}
TEST(xud_sk_accept_length_one_is_fault)
{
    struct sockaddr_storage ss;
    int l = 1;
    TRIO(t, "sk_ac2.sock");
    XEQ(U(accept)(t.lis, (struct sockaddr *)&ss, &l), INVALID_SOCKET);
    XEQ(x_err(), WSAEFAULT);
    XEQ(l, 1);
    x_trio_close(&t);
}

/* ---- option values that stick ---- */
static void opt_roundtrip(int opt, int val, int want)
{
    int v = -1, l = 4;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, opt, (char *)&val, 4), 0);
    XEQ(U(getsockopt)(s, SOL_SOCKET, opt, (char *)&v, &l), 0);
    XEQ(v, want);
    U(closesocket)(s);
}
TEST(xud_sk_set_sndbuf_4096_reads_back) { opt_roundtrip(SO_SNDBUF, 4096, 4096); }
TEST(xud_sk_set_sndbuf_1mb_reads_back) { opt_roundtrip(SO_SNDBUF, 1 << 20, 1 << 20); }
TEST(xud_sk_set_sndbuf_zero_reads_back) { opt_roundtrip(SO_SNDBUF, 0, 0); }
TEST(xud_sk_set_rcvbuf_8192_reads_back) { opt_roundtrip(SO_RCVBUF, 8192, 8192); }
TEST(xud_sk_set_rcvbuf_minus_one_reads_back) { opt_roundtrip(SO_RCVBUF, -1, -1); }
TEST(xud_sk_set_reuseaddr_five_reads_back_one) { opt_roundtrip(SO_REUSEADDR, 5, 1); }
TEST(xud_sk_set_exclusiveaddruse_reads_back_one) { opt_roundtrip(SO_EXCLUSIVEADDRUSE, 1, 1); }
TEST(xud_sk_set_debug_reads_back_one) { opt_roundtrip(SO_DEBUG, 1, 1); }
TEST(xud_sk_set_rcvtimeo_all_ones_reads_back) { opt_roundtrip(SO_RCVTIMEO, -1, -1); }
TEST(xud_sk_set_group_priority_reads_back) { opt_roundtrip(SO_GROUP_PRIORITY, 1, 1); }
TEST(xud_sk_set_oobinline_is_opnotsupp_and_stays_off)
{
    int v = 1, l = 4;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_OOBINLINE, (char *)&v, 4), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_OOBINLINE, (char *)&v, &l), 0);
    XEQ(v, 0);
    U(closesocket)(s);
}
TEST(xud_sk_set_lowat_options_are_noprotoopt)
{
    int v = 1;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_SNDLOWAT, (char *)&v, 4), -1);
    XEQ(x_err(), WSAENOPROTOOPT);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVLOWAT, (char *)&v, 4), -1);
    XEQ(x_err(), WSAENOPROTOOPT);
    U(closesocket)(s);
}
TEST(xud_sk_reuseaddr_then_exclusive_is_inval)
{
    int v = 1;
    SOCK_OR_RETURN(s);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_REUSEADDR, (char *)&v, 4), 0);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&v, 4), -1);
    XEQ(x_err(), WSAEINVAL);
    U(closesocket)(s);
}
TEST(xud_sk_listen_negative_backlog_succeeds)
{
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("sk_lb.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(U(listen)(s, -5), 0);
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}

/* ---- names that start with NUL ---- */
TEST(xud_sk_bind_nul_first_name_makes_no_file_and_does_not_collide)
{
    SOCKET a, b;
    SOCKADDR_UN ad, o;
    int l = sizeof o;
    UP();
    x_cd_scratch();
    a = x_sock(); b = x_sock();
    memset(&ad, 0, sizeof ad);
    ad.sun_family = AF_UNIX;
    ad.sun_path[1] = 'z'; ad.sun_path[2] = 'q';
    XEQ(x_bind(a, &ad), 0);
    XEQ(x_bind(b, &ad), 0);                                  /* a second socket binds the identical name */
    memset(&o, 0xaa, sizeof o);
    XEQ(U(getsockname)(a, (struct sockaddr *)&o, &l), 0);
    XEQ(l, sizeof o);
    XEQ(o.sun_path[0], 0);
    XEQ(o.sun_path[1], 'z');
    CHECK(!x_exists("zq"));
    U(closesocket)(a); U(closesocket)(b);
    x_cd_restore();
}
