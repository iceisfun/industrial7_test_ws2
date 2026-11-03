/* sockopt_socket_level: behaviour of individual SOL_SOCKET options that goes beyond reading and writing a
 * number: error latching, receive timeouts, linger bookkeeping, conditional accept, the update-context
 * options, the per-thread open type and the protocol-info options. Everything runs on fresh loopback
 * sockets with ephemeral ports. */
#include "sol.h"

static int get_int(SOCKET s, int opt, int *out)
{
    int n = sizeof *out;
    *out = 0x5a5a5a5a;
    return gso(s, SOL_SOCKET, opt, out, &n);
}
static int set_int(SOCKET s, int opt, int v) { return sso(s, SOL_SOCKET, opt, &v, sizeof v); }

/* ------------------------------------------------------------------------- SO_TYPE */
static void type_for(int k, int want)
{
    SOCKET s; int v, n = sizeof v;
    NEED();
    s = mk_kind_or_skip(k);
    if (s != INVALID_SOCKET) {
        EQ(get_int(s, SO_TYPE, &v), 0);
        EQ(v, want);
        /* a wider buffer is accepted, cleared in full, and the length comes back as 4 */
        { unsigned char b[8]; memset(b, 0xaa, sizeof b); n = sizeof b;
          EQ(gso(s, SOL_SOCKET, SO_TYPE, b, &n), 0); EQ(n, 4); EQ(b[4], 0); EQ(b[7], 0); }
        cls(s);
    }
    ws_down();
}
TEST(sol_type_tcp4) { type_for(K_TCP4, SOCK_STREAM); }
TEST(sol_type_udp4) { type_for(K_UDP4, SOCK_DGRAM); }
TEST(sol_type_tcp6) { type_for(K_TCP6, SOCK_STREAM); }
TEST(sol_type_udp6) { type_for(K_UDP6, SOCK_DGRAM); }

TEST(sol_type_is_unchanged_by_connect_and_accept)
{
    SOCKET a, b; int v;
    NEED();
    if (make_pair(&a, &b)) {
        EQ(get_int(a, SO_TYPE, &v), 0); EQ(v, SOCK_STREAM);
        EQ(get_int(b, SO_TYPE, &v), 0); EQ(v, SOCK_STREAM);
        cls(a); cls(b);
    } else CHECK(0);
    ws_down();
}
TEST(sol_type_set_is_refused)
{
    SOCKET s; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(set_int(s, SO_TYPE, SOCK_DGRAM), SOCKET_ERROR);
    NE(werr(), 0);
    EQ(get_int(s, SO_TYPE, &v), 0); EQ(v, SOCK_STREAM);
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- SO_ACCEPTCONN */
TEST(sol_acceptconn_follows_listen_state)
{
    SOCKET l, c; struct sockaddr_in a; int v, n = sizeof a;
    NEED();
    l = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(get_int(l, SO_ACCEPTCONN, &v), 0); EQ(v, 0);
    lo4(&a, 0);
    EQ(U(bind)(l, (struct sockaddr *)&a, sizeof a), 0);
    EQ(get_int(l, SO_ACCEPTCONN, &v), 0); EQ(v, 0);
    EQ(U(listen)(l, 1), 0);
    EQ(get_int(l, SO_ACCEPTCONN, &v), 0); EQ(v, 1);
    EQ(U(getsockname)(l, (struct sockaddr *)&a, &n), 0);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    EQ(get_int(c, SO_ACCEPTCONN, &v), 0); EQ(v, 0);
    { SOCKET x = U(accept)(l, NULL, NULL);
      CHECK(x != INVALID_SOCKET);
      if (x != INVALID_SOCKET) { EQ(get_int(x, SO_ACCEPTCONN, &v), 0); EQ(v, 0); cls(x); } }
    EQ(get_int(l, SO_ACCEPTCONN, &v), 0); EQ(v, 1);
    cls(c); cls(l); ws_down();
}
TEST(sol_acceptconn_is_read_only)
{
    SOCKET l; int v;
    NEED();
    l = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(set_int(l, SO_ACCEPTCONN, 1), SOCKET_ERROR);
    EQ(werr(), WSAENOPROTOOPT);
    EQ(get_int(l, SO_ACCEPTCONN, &v), 0); EQ(v, 0);
    cls(l); ws_down();
}
TEST(sol_acceptconn_datagram_has_no_such_option)
{
    SOCKET u; int v;
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    wset(0);
    EQ(get_int(u, SO_ACCEPTCONN, &v), SOCKET_ERROR);
    EQ(werr(), WSAENOPROTOOPT);
    EQ(v, 0x5a5a5a5a);                 /* the output is untouched on failure */
    cls(u); ws_down();
}

/* ------------------------------------------------------------------------- SO_ERROR */
/* Address that nothing listens on: bind a listener to an ephemeral port, read it, close it. */
static void dead_port(struct sockaddr_in *a)
{
    SOCKET l = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); int n = sizeof *a;
    lo4(a, 0);
    U(bind)(l, (struct sockaddr *)a, sizeof *a);
    U(getsockname)(l, (struct sockaddr *)a, &n);
    cls(l);
}
TEST(sol_error_default_is_zero_on_every_kind)
{
    int k, v;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k);
        if (s == INVALID_SOCKET) continue;
        EQ(get_int(s, SO_ERROR, &v), 0); EQ(v, 0);
        cls(s);
    }
    ws_down();
}
TEST(sol_error_nonblocking_connect_refused_is_latched)
{
    SOCKET c; struct sockaddr_in a; WSAPOLLFD p; int v, v2;
    NEED();
    dead_port(&a);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    nonblock(c, 1);
    wset(0);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), SOCKET_ERROR);
    EQ(werr(), WSAEWOULDBLOCK);
    p.fd = c; p.events = POLLWRNORM; p.revents = 0;
    CHECK(U(WSAPoll)(&p, 1, 3000) == 1);
    EQ(get_int(c, SO_ERROR, &v), 0);
    EQ(v, WSAECONNREFUSED);
    /* On this stack the failure stays visible: reading SO_ERROR does not consume it. */
    EQ(get_int(c, SO_ERROR, &v2), 0);
    EQ(v2, WSAECONNREFUSED);
    cls(c); ws_down();
}
TEST(sol_error_blocking_connect_refused_leaves_zero)
{
    SOCKET c; struct sockaddr_in a; int v;
    NEED();
    dead_port(&a);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), SOCKET_ERROR);
    EQ(werr(), WSAECONNREFUSED);
    EQ(get_int(c, SO_ERROR, &v), 0);
    EQ(v, 0);
    cls(c); ws_down();
}
TEST(sol_error_set_zero_clears_a_latched_failure)
{
    SOCKET c; struct sockaddr_in a; WSAPOLLFD p; int v;
    NEED();
    dead_port(&a);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    nonblock(c, 1);
    U(connect)(c, (struct sockaddr *)&a, sizeof a);
    p.fd = c; p.events = POLLWRNORM; p.revents = 0;
    U(WSAPoll)(&p, 1, 3000);
    EQ(get_int(c, SO_ERROR, &v), 0);
    EQ(v, WSAECONNREFUSED);
    EQ(set_int(c, SO_ERROR, 0), 0);
    EQ(get_int(c, SO_ERROR, &v), 0);
    EQ(v, 0);
    cls(c); ws_down();
}

/* ------------------------------------------------------------------------- receive and send timeouts */
TEST(sol_rcvtimeo_tcp_recv_times_out_and_socket_stays_usable)
{
    SOCKET a, b; char c = 0; int r, v;
    NEED();
    if (!make_pair(&a, &b)) { CHECK(0); ws_down(); return; }
    EQ(set_int(a, SO_RCVTIMEO, 100), 0);
    wset(0);
    r = U(recv)(a, &c, 1, 0);
    EQ(r, SOCKET_ERROR);
    EQ(werr(), WSAETIMEDOUT);
    EQ(get_int(a, SO_ERROR, &v), 0); EQ(v, 0);          /* a timeout is not a latched error */
    EQ(U(send)(b, "x", 1, 0), 1);
    wset(0);
    EQ(U(recv)(a, &c, 1, 0), 1);
    EQ(c, 'x');
    cls(a); cls(b); ws_down();
}
TEST(sol_rcvtimeo_udp_recvfrom_times_out)
{
    SOCKET u; struct sockaddr_in a; char c;
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    lo4(&a, 0);
    EQ(U(bind)(u, (struct sockaddr *)&a, sizeof a), 0);
    EQ(set_int(u, SO_RCVTIMEO, 100), 0);
    wset(0);
    EQ(U(recvfrom)(u, &c, 1, 0, NULL, NULL), SOCKET_ERROR);
    EQ(werr(), WSAETIMEDOUT);
    cls(u); ws_down();
}
TEST(sol_rcvtimeo_one_millisecond_still_times_out)
{
    SOCKET a, b; char c;
    NEED();
    if (!make_pair(&a, &b)) { CHECK(0); ws_down(); return; }
    EQ(set_int(a, SO_RCVTIMEO, 1), 0);
    wset(0);
    EQ(U(recv)(a, &c, 1, 0), SOCKET_ERROR);
    EQ(werr(), WSAETIMEDOUT);
    cls(a); cls(b); ws_down();
}
/* The option is a DWORD of milliseconds, not a timeval: an 8-byte timeval is read as its first DWORD. */
TEST(sol_rcvtimeo_timeval_is_read_as_its_first_dword)
{
    SOCKET s; struct timeval tv; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    tv.tv_sec = 1; tv.tv_usec = 0;
    EQ(sso(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv), 0);
    EQ(get_int(s, SO_RCVTIMEO, &v), 0); EQ(v, 1);
    tv.tv_sec = 0; tv.tv_usec = 100000;
    EQ(sso(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv), 0);
    EQ(get_int(s, SO_RCVTIMEO, &v), 0); EQ(v, 0);
    tv.tv_sec = 7; tv.tv_usec = 7;
    EQ(sso(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv), 0);
    EQ(get_int(s, SO_SNDTIMEO, &v), 0); EQ(v, 7);
    cls(s); ws_down();
}
TEST(sol_timeouts_store_the_raw_dword)
{
    static const DWORD vals[] = { 0, 1, 1000, 0x7fffffff, 0x80000000, 0xffffffff };
    int i, o, k;
    NEED();
    for (k = 0; k < 2; k++) {
        SOCKET s = mk(AF_INET, k ? SOCK_DGRAM : SOCK_STREAM, 0);
        for (o = SO_SNDTIMEO; o <= SO_RCVTIMEO; o++)
            for (i = 0; i < NELEM(vals); i++) {
                int v;
                EQ(sso(s, SOL_SOCKET, o, &vals[i], sizeof vals[i]), 0);
                EQ(get_int(s, o, &v), 0);
                EQ((DWORD)v, vals[i]);
            }
        cls(s);
    }
    ws_down();
}
TEST(sol_timeouts_are_independent)
{
    SOCKET s; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    set_int(s, SO_RCVTIMEO, 111); set_int(s, SO_SNDTIMEO, 222);
    get_int(s, SO_RCVTIMEO, &v); EQ(v, 111);
    get_int(s, SO_SNDTIMEO, &v); EQ(v, 222);
    set_int(s, SO_RCVTIMEO, 0);
    get_int(s, SO_SNDTIMEO, &v); EQ(v, 222);
    cls(s); ws_down();
}
TEST(sol_timeouts_short_length_is_efault)
{
    SOCKET s; int v = 5, o;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (o = SO_SNDTIMEO; o <= SO_RCVTIMEO; o++) {
        int n;
        for (n = 0; n < 4; n++) {
            wset(0);
            EQ(sso(s, SOL_SOCKET, o, &v, n), SOCKET_ERROR);
            EQ(werr(), WSAEFAULT);
        }
    }
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- linger bookkeeping */
static void read_linger(SOCKET s, LINGER *l)
{
    int n = sizeof *l;
    memset(l, 0x77, sizeof *l);
    EQ(gso(s, SOL_SOCKET, SO_LINGER, l, &n), 0);
    EQ(n, sizeof *l);
}
TEST(sol_dontlinger_false_turns_lingering_on_with_stored_timeout)
{
    SOCKET s; LINGER l; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(set_int(s, SO_DONTLINGER, 0), 0);
    read_linger(s, &l);
    CHECK(l.l_onoff != 0); EQ(l.l_linger, 0);
    EQ(set_int(s, SO_DONTLINGER, 1), 0);
    read_linger(s, &l);
    EQ(l.l_onoff, 0);
    get_int(s, SO_DONTLINGER, &v); EQ(v, 1);
    cls(s); ws_down();
}
TEST(sol_dontlinger_keeps_the_linger_timeout)
{
    SOCKET s; LINGER l;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l.l_onoff = 1; l.l_linger = 77;
    EQ(sso(s, SOL_SOCKET, SO_LINGER, &l, sizeof l), 0);
    EQ(set_int(s, SO_DONTLINGER, 1), 0);
    read_linger(s, &l);
    EQ(l.l_onoff, 0); EQ(l.l_linger, 77);
    EQ(set_int(s, SO_DONTLINGER, 0), 0);
    read_linger(s, &l);
    CHECK(l.l_onoff != 0); EQ(l.l_linger, 77);
    cls(s); ws_down();
}
TEST(sol_linger_fields_are_stored_unnormalised)
{
    SOCKET s; LINGER l; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l.l_onoff = 2; l.l_linger = (u_short)65535;
    EQ(sso(s, SOL_SOCKET, SO_LINGER, &l, sizeof l), 0);
    read_linger(s, &l);
    EQ(l.l_onoff, 2); EQ(l.l_linger, 65535);
    get_int(s, SO_DONTLINGER, &v); EQ(v, 0);
    cls(s); ws_down();
}
TEST(sol_linger_longer_buffer_is_accepted_shorter_is_efault)
{
    SOCKET s; unsigned char b[8] = { 1, 0, 5, 0, 0xee, 0xee, 0xee, 0xee }; LINGER l;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(sso(s, SOL_SOCKET, SO_LINGER, b, 8), 0);
    read_linger(s, &l);
    EQ(l.l_onoff, 1); EQ(l.l_linger, 5);
    wset(0);
    EQ(sso(s, SOL_SOCKET, SO_LINGER, b, 3), SOCKET_ERROR);
    EQ(werr(), WSAEFAULT);
    read_linger(s, &l);
    EQ(l.l_onoff, 1);
    cls(s); ws_down();
}
TEST(sol_linger_read_with_wide_buffer_reports_four_bytes)
{
    SOCKET s; unsigned char b[12]; int n = sizeof b;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(b, 0xaa, sizeof b);
    EQ(gso(s, SOL_SOCKET, SO_LINGER, b, &n), 0);
    EQ(n, 4);
    /* the whole supplied buffer is cleared first, then the 4-byte structure is filled in */
    EQ(b[4], 0); EQ(b[11], 0);
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- send/receive buffer sizes */
TEST(sol_buffer_sizes_are_stored_verbatim)
{
    static const int vals[] = { 0, 1, 2, 3, 100, 4096, 65536, 1 << 20, 1 << 30, 0x7fffffff, -1, (int)0x80000000 };
    int i, o, k;
    NEED();
    for (k = 0; k < 2; k++) {
        SOCKET s = mk(AF_INET, k ? SOCK_DGRAM : SOCK_STREAM, 0);
        for (o = SO_SNDBUF; o <= SO_RCVBUF; o++)
            for (i = 0; i < NELEM(vals); i++) {
                int v;
                EQ(set_int(s, o, vals[i]), 0);
                EQ(get_int(s, o, &v), 0);
                EQ((DWORD)v, (DWORD)vals[i]);
            }
        cls(s);
    }
    ws_down();
}
TEST(sol_buffer_sizes_are_independent)
{
    SOCKET s; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    set_int(s, SO_SNDBUF, 5000); set_int(s, SO_RCVBUF, 9000);
    get_int(s, SO_SNDBUF, &v); EQ(v, 5000);
    get_int(s, SO_RCVBUF, &v); EQ(v, 9000);
    cls(s); ws_down();
}
TEST(sol_buffer_defaults_are_positive_on_every_kind)
{
    int k, v;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k);
        if (s == INVALID_SOCKET) continue;
        EQ(get_int(s, SO_SNDBUF, &v), 0); CHECKF(v > 0, "%s sndbuf %d", kind_name[k], v);
        t_note("%s default send buffer is a multiple of 1024: %d", kind_name[k], (v % 1024) == 0);
        EQ(get_int(s, SO_RCVBUF, &v), 0); CHECKF(v > 0, "%s rcvbuf %d", kind_name[k], v);
        cls(s);
    }
    ws_down();
}
TEST(sol_buffer_sizes_survive_connect)
{
    SOCKET a, b; int v;
    NEED();
    if (make_pair(&a, &b)) {
        get_int(a, SO_RCVBUF, &v); CHECK(v > 0);
        set_int(a, SO_RCVBUF, 12345);
        get_int(a, SO_RCVBUF, &v); EQ(v, 12345);
        cls(a); cls(b);
    } else CHECK(0);
    ws_down();
}
TEST(sol_udp_rcvbuf_small_datagram_larger_than_recv_buffer_is_msgsize)
{
    SOCKET u, w; struct sockaddr_in a; int n = sizeof a; char buf[8]; WSAPOLLFD p;
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, 0); w = mk(AF_INET, SOCK_DGRAM, 0);
    lo4(&a, 0);
    EQ(U(bind)(u, (struct sockaddr *)&a, sizeof a), 0);
    EQ(U(getsockname)(u, (struct sockaddr *)&a, &n), 0);
    EQ(U(sendto)(w, "hello", 5, 0, (struct sockaddr *)&a, sizeof a), 5);
    p.fd = u; p.events = POLLRDNORM; p.revents = 0;
    CHECK(U(WSAPoll)(&p, 1, 3000) == 1);
    wset(0);
    EQ(U(recv)(u, buf, 3, 0), SOCKET_ERROR);       /* the caller's buffer is what matters, not SO_RCVBUF */
    EQ(werr(), WSAEMSGSIZE);
    cls(u); cls(w); ws_down();
}

/* ------------------------------------------------------------------------- groups */
TEST(sol_group_id_is_zero_and_read_only)
{
    int k, v;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k);
        if (s == INVALID_SOCKET) continue;
        EQ(get_int(s, SO_GROUP_ID, &v), 0); EQ(v, 0);
        wset(0);
        EQ(set_int(s, SO_GROUP_ID, 1), SOCKET_ERROR);
        EQ(werr(), kind_stream(k) ? WSAENOPROTOOPT : WSAEINVAL);
        EQ(get_int(s, SO_GROUP_ID, &v), 0); EQ(v, 0);
        cls(s);
    }
    ws_down();
}
TEST(sol_group_priority_is_stored_verbatim)
{
    static const int vals[] = { 0, 1, -1, 5, 0x7fffffff };
    SOCKET s; int i, v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(get_int(s, SO_GROUP_PRIORITY, &v), 0); EQ(v, 0);
    for (i = 0; i < NELEM(vals); i++) {
        EQ(set_int(s, SO_GROUP_PRIORITY, vals[i]), 0);
        EQ(get_int(s, SO_GROUP_PRIORITY, &v), 0); EQ(v, vals[i]);
    }
    cls(s); ws_down();
}
TEST(sol_group_priority_short_length_is_efault)
{
    SOCKET s; int v = 3, n;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (n = 0; n < 4; n++) {
        wset(0);
        EQ(sso(s, SOL_SOCKET, SO_GROUP_PRIORITY, &v, n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
    }
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- SO_MAX_MSG_SIZE */
TEST(sol_max_msg_size_by_type)
{
    SOCKET t, u; int v;
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    EQ(get_int(t, SO_MAX_MSG_SIZE, &v), 0); EQ(v, -1);
    EQ(get_int(u, SO_MAX_MSG_SIZE, &v), 0); EQ(v, 65507);
    cls(t); cls(u); ws_down();
}
TEST(sol_max_msg_size_set_error_depends_on_type)
{
    SOCKET t, u;
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    wset(0); EQ(set_int(t, SO_MAX_MSG_SIZE, 100), SOCKET_ERROR); EQ(werr(), WSAENOPROTOOPT);
    wset(0); EQ(set_int(u, SO_MAX_MSG_SIZE, 100), SOCKET_ERROR); EQ(werr(), WSAEINVAL);
    cls(t); cls(u); ws_down();
}
TEST(sol_max_msg_size_short_length_is_efault)
{
    SOCKET u; int v, n;
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (n = 1; n < 4; n++) {
        wset(0); v = n;
        EQ(gso(u, SOL_SOCKET, SO_MAX_MSG_SIZE, &v, &n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
    }
    cls(u); ws_down();
}

/* ------------------------------------------------------------------------- SO_CONNECT_TIME */
TEST(sol_connect_time_unconnected_is_all_ones_on_both_types)
{
    SOCKET t, u; int v;
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    EQ(get_int(t, SO_CONNECT_TIME, &v), 0); EQ(v, -1);
    EQ(get_int(u, SO_CONNECT_TIME, &v), 0); EQ(v, -1);
    cls(t); cls(u); ws_down();
}
TEST(sol_connect_time_set_is_refused)
{
    SOCKET t, u;
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    wset(0); EQ(set_int(t, SO_CONNECT_TIME, 1), SOCKET_ERROR); EQ(werr(), WSAENOPROTOOPT);
    wset(0); EQ(set_int(u, SO_CONNECT_TIME, 1), SOCKET_ERROR); EQ(werr(), WSAEINVAL);
    cls(t); cls(u); ws_down();
}
TEST(sol_connect_time_accepted_and_connected_are_small)
{
    SOCKET a, b; int v;
    NEED();
    if (make_pair(&a, &b)) {
        EQ(get_int(a, SO_CONNECT_TIME, &v), 0); CHECKF(v >= 0 && v < 30, "client %d", v);
        EQ(get_int(b, SO_CONNECT_TIME, &v), 0); CHECKF(v >= 0 && v < 30, "accepted %d", v);
        cls(a); cls(b);
    } else CHECK(0);
    ws_down();
}

/* ------------------------------------------------------------------------- SO_CONDITIONAL_ACCEPT */
static int CALLBACK cond_fn(LPWSABUF a, LPWSABUF b, LPQOS c, LPQOS d, LPWSABUF e, LPWSABUF f, GROUP *g, DWORD_PTR user)
{
    return (int)user;
}
static void cond_listener(SOCKET *l, struct sockaddr_in *a, int cond)
{
    int n = sizeof *a;
    *l = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    set_int(*l, SO_CONDITIONAL_ACCEPT, cond);
    lo4(a, 0);
    U(bind)(*l, (struct sockaddr *)a, sizeof *a);
    U(getsockname)(*l, (struct sockaddr *)a, &n);
    U(listen)(*l, 1);
}
TEST(sol_conditional_accept_default_and_roundtrip_on_stream_and_datagram)
{
    int k, v;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k);
        if (s == INVALID_SOCKET) continue;
        EQ(get_int(s, SO_CONDITIONAL_ACCEPT, &v), 0); EQ(v, 0);
        EQ(set_int(s, SO_CONDITIONAL_ACCEPT, 1), 0);
        EQ(get_int(s, SO_CONDITIONAL_ACCEPT, &v), 0); EQ(v, 1);
        EQ(set_int(s, SO_CONDITIONAL_ACCEPT, 0), 0);
        EQ(get_int(s, SO_CONDITIONAL_ACCEPT, &v), 0); EQ(v, 0);
        cls(s);
    }
    ws_down();
}
TEST(sol_conditional_accept_cannot_change_once_listening)
{
    SOCKET l; struct sockaddr_in a; int v;
    NEED();
    cond_listener(&l, &a, 0);
    wset(0);
    EQ(set_int(l, SO_CONDITIONAL_ACCEPT, 1), SOCKET_ERROR);
    EQ(werr(), WSAEINVAL);
    wset(0);
    EQ(set_int(l, SO_CONDITIONAL_ACCEPT, 0), SOCKET_ERROR);
    EQ(werr(), WSAEINVAL);
    get_int(l, SO_CONDITIONAL_ACCEPT, &v); EQ(v, 0);
    cls(l); ws_down();
}
TEST(sol_conditional_accept_value_set_before_listen_is_kept)
{
    SOCKET l; struct sockaddr_in a; int v;
    NEED();
    cond_listener(&l, &a, 1);
    get_int(l, SO_CONDITIONAL_ACCEPT, &v); EQ(v, 1);
    cls(l); ws_down();
}
TEST(sol_conditional_accept_may_be_set_on_connected_socket)
{
    SOCKET a, b; int v;
    NEED();
    if (make_pair(&a, &b)) {
        EQ(set_int(a, SO_CONDITIONAL_ACCEPT, 1), 0);
        get_int(a, SO_CONDITIONAL_ACCEPT, &v); EQ(v, 1);
        EQ(set_int(b, SO_CONDITIONAL_ACCEPT, 1), 0);
        cls(a); cls(b);
    } else CHECK(0);
    ws_down();
}
TEST(sol_conditional_accept_wsaaccept_reject_reports_connrefused)
{
    SOCKET l, c, x; struct sockaddr_in a;
    NEED();
    cond_listener(&l, &a, 1);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    nonblock(c, 1);
    U(connect)(c, (struct sockaddr *)&a, sizeof a);
    wset(0);
    x = U(WSAAccept)(l, NULL, NULL, cond_fn, CF_REJECT);
    EQ(x, INVALID_SOCKET);
    EQ(werr(), WSAECONNREFUSED);
    cls(c); cls(l); ws_down();
}
TEST(sol_conditional_accept_wsaaccept_accept_returns_connection)
{
    SOCKET l, c, x; struct sockaddr_in a;
    NEED();
    cond_listener(&l, &a, 1);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    nonblock(c, 1);
    U(connect)(c, (struct sockaddr *)&a, sizeof a);
    x = U(WSAAccept)(l, NULL, NULL, cond_fn, CF_ACCEPT);
    CHECK(x != INVALID_SOCKET);
    if (x != INVALID_SOCKET) cls(x);
    cls(c); cls(l); ws_down();
}
TEST(sol_conditional_accept_off_wsaaccept_with_callback_accepts)
{
    SOCKET l, c, x; struct sockaddr_in a;
    NEED();
    cond_listener(&l, &a, 0);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    nonblock(c, 1);
    U(connect)(c, (struct sockaddr *)&a, sizeof a);
    x = U(WSAAccept)(l, NULL, NULL, cond_fn, CF_ACCEPT);
    CHECK(x != INVALID_SOCKET);
    if (x != INVALID_SOCKET) cls(x);
    cls(c); cls(l); ws_down();
}

/* ------------------------------------------------------------------------- update-context options */
TEST(sol_update_accept_context_short_length_is_efault)
{
    SOCKET s, inv = INVALID_SOCKET; int n;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (n = 0; n < 8; n++) {
        wset(0);
        EQ(sso(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, &inv, n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
    }
    cls(s); ws_down();
}
TEST(sol_update_accept_context_null_value_is_efault)
{
    SOCKET s;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(sso(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, NULL, 8), SOCKET_ERROR);
    EQ(werr(), WSAEFAULT);
    cls(s); ws_down();
}
TEST(sol_update_accept_context_unknown_listener_is_enotsock)
{
    SOCKET s, inv = INVALID_SOCKET; int n;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (n = 8; n <= 16; n += 8) {
        wset(0);
        EQ(sso(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, &inv, n), SOCKET_ERROR);
        EQ(werr(), WSAENOTSOCK);
    }
    cls(s); ws_down();
}
TEST(sol_update_accept_context_on_unconnected_socket_is_enotconn)
{
    SOCKET s;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wset(0);
    EQ(sso(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, &s, sizeof s), SOCKET_ERROR);
    EQ(werr(), WSAENOTCONN);
    cls(s); ws_down();
}
TEST(sol_update_connect_context_unconnected_is_enotconn)
{
    SOCKET t, u;
    unsigned char b[4] = { 0 };
    NEED();
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    wset(0); EQ(sso(t, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), SOCKET_ERROR); EQ(werr(), WSAENOTCONN);
    wset(0); EQ(sso(t, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, b, 4), SOCKET_ERROR);    EQ(werr(), WSAENOTCONN);
    wset(0); EQ(sso(u, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), SOCKET_ERROR); EQ(werr(), WSAENOTCONN);
    cls(t); cls(u); ws_down();
}
TEST(sol_update_connect_context_on_connected_sockets_succeeds_without_value)
{
    SOCKET a, b;
    NEED();
    if (make_pair(&a, &b)) {
        wset(0); EQ(sso(a, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), 0);
        wset(0); EQ(sso(b, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), 0);
        cls(a); cls(b);
    } else CHECK(0);
    ws_down();
}

/* ------------------------------------------------------------------------- inline out-of-band data */
/* Bounded wait (up to ~3 s) until the socket reports data in the read set (oob=0) or urgent data in the except set. */
static void wait_ready(SOCKET s, int oob)
{
    int i;
    for (i = 0; i < 30; i++) {
        fd_set f; struct timeval tv = { 0, 100000 };
        FD_ZERO(&f); FD_SET(s, &f);
        if (U(select)(0, oob ? NULL : &f, NULL, oob ? &f : NULL, &tv) > 0) return;
    }
}
TEST(sol_oobinline_recv_with_oob_flag_is_einval)
{
    SOCKET a, b; char c = 0;
    NEED();
    if (!make_pair(&a, &b)) { CHECK(0); ws_down(); return; }
    EQ(set_int(b, SO_OOBINLINE, 1), 0);
    EQ(U(send)(a, "y", 1, MSG_OOB), 1);
    wait_ready(b, 0);
    wset(0);
    EQ(U(recv)(b, &c, 1, MSG_OOB), SOCKET_ERROR);
    EQ(werr(), WSAEINVAL);
    EQ(U(recv)(b, &c, 1, 0), 1);
    EQ(c, 'y');
    cls(a); cls(b); ws_down();
}
TEST(sol_oobinline_off_urgent_byte_is_read_with_oob_flag)
{
    SOCKET a, b; char c = 0;
    NEED();
    if (!make_pair(&a, &b)) { CHECK(0); ws_down(); return; }
    EQ(U(send)(a, "x", 1, MSG_OOB), 1);
    wait_ready(b, 1);
    wset(0);
    EQ(U(recv)(b, &c, 1, MSG_OOB), 1);
    EQ(c, 'x');
    cls(a); cls(b); ws_down();
}

/* ------------------------------------------------------------------------- SO_OPENTYPE (per thread) */
static DWORD WINAPI opentype_reader(LPVOID p)
{
    int v = 0x5a5a5a5a, n = sizeof v;
    int r = U(getsockopt)(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&v, &n);
    *(int *)p = r == 0 ? v : -1;
    return 0;
}
TEST(sol_opentype_roundtrip_on_a_socket)
{
    SOCKET s; int v;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(get_int(s, SO_OPENTYPE, &v), 0); EQ(v, 0);
    EQ(set_int(s, SO_OPENTYPE, 0x20), 0);
    EQ(get_int(s, SO_OPENTYPE, &v), 0); EQ(v, 0x20);
    EQ(set_int(s, SO_OPENTYPE, 0), 0);
    EQ(get_int(s, SO_OPENTYPE, &v), 0); EQ(v, 0);
    cls(s); ws_down();
}
TEST(sol_opentype_applies_to_the_calling_thread_not_the_socket)
{
    SOCKET s, t; int v, other = 0x7777; HANDLE h;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(set_int(s, SO_OPENTYPE, 0x20), 0);
    t = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(get_int(t, SO_OPENTYPE, &v), 0); EQ(v, 0x20);          /* another socket sees the same value */
    h = CreateThread(NULL, 0, opentype_reader, &other, 0, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h); }
    EQ(other, 0);                                             /* another thread does not */
    EQ(set_int(s, SO_OPENTYPE, 0), 0);
    cls(s); cls(t); ws_down();
}
TEST(sol_opentype_needs_no_valid_socket_to_read)
{
    int v = 0x5a5a5a5a, n = sizeof v;
    NEED();
    wset(0);
    EQ(U(getsockopt)(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&v, &n), 0);
    EQ(v, 0); EQ(n, 4);
    ws_down();
}
TEST(sol_opentype_short_read_length_is_efault)
{
    SOCKET s; int v, n;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (n = 1; n < 4; n++) {
        wset(0); v = 0x5a5a5a5a;
        EQ(gso(s, SOL_SOCKET, SO_OPENTYPE, &v, &n), SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
        EQ(v, 0x5a5a5a5a);
    }
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- private option 0x8000 */
TEST(sol_private_option_8000_only_takes_one_magic_value)
{
    SOCKET s; short q;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    q = 1;
    wset(0); EQ(sso(s, SOL_SOCKET, 0x8000, &q, 2), SOCKET_ERROR); EQ(werr(), WSAENOPROTOOPT);
    wset(0); EQ(sso(s, SOL_SOCKET, 0x8000, &q, 1), SOCKET_ERROR); EQ(werr(), WSAEFAULT);
    wset(0); EQ(sso(s, SOL_SOCKET, 0x8000, NULL, 2), SOCKET_ERROR); EQ(werr(), WSAEFAULT);
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- protocol info */
static const GUID guid_v4 = { 0xe70f1aa0, 0xab8b, 0x11cf, { 0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92 } };
static const GUID guid_v6 = { 0xf9eab0c0, 0x26d4, 0x11d0, { 0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4 } };

static void protoinfo_detail(int k)
{
    static const struct { int af, type, proto, maxsa; DWORD sf1; DWORD msg; const char *name; } want[K_COUNT] = {
        { AF_INET,  SOCK_STREAM, IPPROTO_TCP, 16, 0x20066, 0,      "MSAFD Tcpip [TCP/IP]" },
        { AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, 16, 0x20609, 0xfff7, "MSAFD Tcpip [UDP/IP]" },
        { AF_INET6, SOCK_STREAM, IPPROTO_TCP, 28, 0x20066, 0,      "MSAFD Tcpip [TCP/IPv6]" },
        { AF_INET6, SOCK_DGRAM,  IPPROTO_UDP, 28, 0x20609, 0xfff7, "MSAFD Tcpip [UDP/IPv6]" },
    };
    SOCKET s; WSAPROTOCOL_INFOW w; WSAPROTOCOL_INFOA a; int n, i; char nm[WSAPROTOCOL_LEN + 1];
    NEED();
    s = mk_kind_or_skip(k);
    if (s == INVALID_SOCKET) { ws_down(); return; }
    n = sizeof w; memset(&w, 0, sizeof w);
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, &n), 0);
    EQ(n, sizeof w);
    EQ(w.iAddressFamily, want[k].af); EQ(w.iSocketType, want[k].type); EQ(w.iProtocol, want[k].proto);
    EQ(w.iMaxSockAddr, want[k].maxsa); EQ(w.iMinSockAddr, want[k].maxsa);
    EQ(w.iVersion, 2); EQ(w.iProtocolMaxOffset, 0); EQ(w.iNetworkByteOrder, 0); EQ(w.iSecurityScheme, 0);
    EQ(w.ProtocolChain.ChainLen, 1); EQ(w.ProtocolChain.ChainEntries[0], 0);
    EQ(w.dwProviderFlags, 8);                          /* PFL_MATCHES_PROTOCOL_ZERO */
    EQ(w.dwServiceFlags1, want[k].sf1);
    EQ(w.dwMessageSize, want[k].msg);
    CHECK(w.dwCatalogEntryId != 0);
    CHECK(!memcmp(&w.ProviderId, k < 2 ? &guid_v4 : &guid_v6, sizeof(GUID)));
    for (i = 0; i < WSAPROTOCOL_LEN + 1; i++) nm[i] = (char)w.szProtocol[i];
    EXPECT_STR(nm, want[k].name);
    n = sizeof a; memset(&a, 0, sizeof a);
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &a, &n), 0);
    EQ(n, sizeof a);
    EQ(a.iAddressFamily, w.iAddressFamily); EQ(a.iSocketType, w.iSocketType); EQ(a.iProtocol, w.iProtocol);
    EQ(a.dwCatalogEntryId, w.dwCatalogEntryId); EQ(a.dwServiceFlags1, w.dwServiceFlags1);
    EXPECT_STR(a.szProtocol, want[k].name);
    cls(s); ws_down();
}
TEST(sol_protoinfo_detail_tcp4) { protoinfo_detail(K_TCP4); }
TEST(sol_protoinfo_detail_udp4) { protoinfo_detail(K_UDP4); }
TEST(sol_protoinfo_detail_tcp6) { protoinfo_detail(K_TCP6); }
TEST(sol_protoinfo_detail_udp6) { protoinfo_detail(K_UDP6); }

TEST(sol_protoinfo_short_buffers_report_required_size)
{
    int k;
    NEED();
    for (k = 0; k < K_COUNT; k++) {
        SOCKET s = mk_kind(k); WSAPROTOCOL_INFOW w; WSAPROTOCOL_INFOA a; int n;
        if (s == INVALID_SOCKET) continue;
        n = sizeof w - 1; wset(0);
        EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, &n), SOCKET_ERROR); EQ(werr(), WSAEFAULT); EQ(n, sizeof w - 1);
        n = 0; wset(0);
        EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, &n), SOCKET_ERROR); EQ(werr(), WSAEFAULT); EQ(n, 0);
        n = sizeof a - 1; wset(0);
        EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &a, &n), SOCKET_ERROR); EQ(werr(), WSAEFAULT); EQ(n, sizeof a);
        n = 100; wset(0);
        EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &a, &n), SOCKET_ERROR); EQ(werr(), WSAEFAULT); EQ(n, sizeof a);
        cls(s);
    }
    ws_down();
}
TEST(sol_protoinfo_is_read_only)
{
    SOCKET s; WSAPROTOCOL_INFOW w;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&w, 0, sizeof w);
    wset(0); EQ(sso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, sizeof w), SOCKET_ERROR); NE(werr(), 0);
    wset(0); EQ(sso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &w, sizeof w), SOCKET_ERROR); EQ(werr(), WSAENOPROTOOPT);
    cls(s); ws_down();
}
TEST(sol_protoinfo_dup_socket_protocol_info_matches_option)
{
    SOCKET s; WSAPROTOCOL_INFOW w, d; int n = sizeof w;
    NEED();
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, &n), 0);
    n = (int)U(WSADuplicateSocketW)(s, GetCurrentProcessId(), &d);
    EQ(n, 0);
    if (!n) {
        EQ(d.iAddressFamily, w.iAddressFamily); EQ(d.iSocketType, w.iSocketType); EQ(d.iProtocol, w.iProtocol);
        EQ(d.dwCatalogEntryId, w.dwCatalogEntryId);
    }
    cls(s); ws_down();
}

/* ------------------------------------------------------------------------- options that do not disturb traffic */
TEST(sol_traffic_flows_with_dontroute_keepalive_and_buffer_options_set)
{
    SOCKET a, b; char c = 0;
    NEED();
    if (!make_pair(&a, &b)) { CHECK(0); ws_down(); return; }
    EQ(set_int(a, SO_DONTROUTE, 1), 0);
    EQ(set_int(a, SO_KEEPALIVE, 1), 0);
    EQ(set_int(a, SO_SNDBUF, 8192), 0);
    EQ(set_int(b, SO_RCVBUF, 8192), 0);
    EQ(set_int(b, SO_RCVTIMEO, 3000), 0);
    EQ(U(send)(a, "z", 1, 0), 1);
    EQ(U(recv)(b, &c, 1, 0), 1);
    EQ(c, 'z');
    cls(a); cls(b); ws_down();
}
TEST(sol_traffic_udp_flows_with_broadcast_and_dontroute_set)
{
    SOCKET u, w; struct sockaddr_in a; int n = sizeof a; char c = 0;
    NEED();
    u = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP); w = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    lo4(&a, 0);
    EQ(U(bind)(u, (struct sockaddr *)&a, sizeof a), 0);
    EQ(U(getsockname)(u, (struct sockaddr *)&a, &n), 0);
    EQ(set_int(w, SO_BROADCAST, 1), 0);
    EQ(set_int(w, SO_DONTROUTE, 1), 0);
    EQ(set_int(u, SO_RCVTIMEO, 3000), 0);
    EQ(U(sendto)(w, "q", 1, 0, (struct sockaddr *)&a, sizeof a), 1);
    EQ(U(recv)(u, &c, 1, 0), 1);
    EQ(c, 'q');
    cls(u); cls(w); ws_down();
}

/* ------------------------------------------------------------------------- inheritance by accepted sockets */
static void inherit_one(int opt, int val, int want_inherited)
{
    SOCKET l = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP), c, x; struct sockaddr_in a; int n = sizeof a, v = -1, w = -1;
    lo4(&a, 0);
    set_int(l, opt, val);
    U(bind)(l, (struct sockaddr *)&a, sizeof a);
    U(getsockname)(l, (struct sockaddr *)&a, &n);
    U(listen)(l, 1);
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    x = U(accept)(l, NULL, NULL);
    CHECK(x != INVALID_SOCKET);
    if (x != INVALID_SOCKET) {
        EQ(get_int(l, opt, &w), 0);
        EQ(get_int(x, opt, &v), 0);
        if (want_inherited) EQ(v & 0xff, w & 0xff); else CHECK((v & 0xff) != (w & 0xff));
        if (want_inherited && opt >= SO_SNDBUF && opt <= SO_RCVTIMEO) EQ(v, val);
        cls(x);
    }
    cls(c); cls(l);
}
TEST(sol_accept_inherits_rcvbuf)        { NEED(); inherit_one(SO_RCVBUF, 12345, 1); ws_down(); }
TEST(sol_accept_inherits_sndbuf)        { NEED(); inherit_one(SO_SNDBUF, 23456, 1); ws_down(); }
TEST(sol_accept_inherits_keepalive)     { NEED(); inherit_one(SO_KEEPALIVE, 1, 1); ws_down(); }
TEST(sol_accept_inherits_oobinline)     { NEED(); inherit_one(SO_OOBINLINE, 1, 1); ws_down(); }
TEST(sol_accept_inherits_rcvtimeo)      { NEED(); inherit_one(SO_RCVTIMEO, 4321, 1); ws_down(); }
TEST(sol_accept_inherits_sndtimeo)      { NEED(); inherit_one(SO_SNDTIMEO, 1234, 1); ws_down(); }
TEST(sol_accept_inherits_debug)         { NEED(); inherit_one(SO_DEBUG, 1, 1); ws_down(); }
TEST(sol_accept_inherits_dontroute)     { NEED(); inherit_one(SO_DONTROUTE, 1, 1); ws_down(); }
TEST(sol_accept_inherits_reuseaddr)     { NEED(); inherit_one(SO_REUSEADDR, 1, 1); ws_down(); }
TEST(sol_accept_does_not_inherit_group_priority) { NEED(); inherit_one(SO_GROUP_PRIORITY, 3, 0); ws_down(); }
