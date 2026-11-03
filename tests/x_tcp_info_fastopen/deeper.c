/* Second-pass measurements for the TCP specifics area: option interplay rules (SO_REUSEADDR against
 * SO_EXCLUSIVEADDRUSE), what a listener hands to the sockets it accepts, keep-alive control-code coding,
 * SO_LINGER companions, TCP-level option presence, TCP_INFO against buffer and timestamp settings, a
 * connection opened with data in the handshake, receive-side shutdown, and bind independence across address
 * families, protocols and distinct loopback addresses. Every expectation is a value observed on Windows 10. */
#include "xt.h"

static const int tcp_kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN, XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED};
#define NTCP ((int)(sizeof tcp_kinds / sizeof tcp_kinds[0]))

static long long rd(SOCKET s, int lvl, int opt) { long long v = -1; xt_geti(s, lvl, opt, &v); return v; }
static int wait_bytes_in(SOCKET s, ULONG64 n)
{
    int i;
    for (i = 0; i < 150; i++) {
        xt_info0 x; DWORD v = 0;
        if (xt_io(s, XT_SIO_TCP_INFO, &v, 4, &x, sizeof x).rc == 0 && x.BytesIn == n) return 1;
        Sleep(20);
    }
    return 0;
}

/* ---- SO_REUSEADDR and SO_EXCLUSIVEADDRUSE exclude each other: whichever is on blocks the other ------------- */
TEST(optx_reuse_blocks_exclusive_and_exclusive_blocks_reuse_in_every_tcp_state)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; const char *n = xt_state_name[tcp_kinds[k]];
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", n); return; }
        /* reuse first: exclusive refused, reuse stays */
        EQ(xt_seti(st.s, SOL_SOCKET, SO_REUSEADDR, 1), 0);
        CHECKF(xt_seti(st.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1) == WSAEINVAL, "%s: exclusive while reuse is on", n);
        CHECKF(rd(st.s, SOL_SOCKET, SO_REUSEADDR) == 1 && rd(st.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE) == 0, "%s: values after refusal", n);
        /* reuse cleared: exclusive allowed, then reuse refused */
        EQ(xt_seti(st.s, SOL_SOCKET, SO_REUSEADDR, 0), 0);
        CHECKF(xt_seti(st.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1) == 0, "%s: exclusive after reuse cleared", n);
        CHECKF(xt_seti(st.s, SOL_SOCKET, SO_REUSEADDR, 1) == WSAEINVAL, "%s: reuse while exclusive is on", n);
        CHECKF(rd(st.s, SOL_SOCKET, SO_REUSEADDR) == 0 && rd(st.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE) == 1, "%s: values after second refusal", n);
        /* clearing is always fine, and the pair can swap */
        EQ(xt_seti(st.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 0), 0);
        EQ(xt_seti(st.s, SOL_SOCKET, SO_REUSEADDR, 1), 0);
        EQ(rd(st.s, SOL_SOCKET, SO_REUSEADDR), 1);
        xt_rmstate(&st);
    }
}
TEST(optx_exclusive_after_bind_is_stored_and_reads_back)
{
    SOCKET s; u_short p = 0;
    NEED();
    s = xt_tcp(); EQ(xt_bind_lo(s, &p), 0);
    EQ(xt_seti(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1), 0); EQ(rd(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE), 1);
    EQ(xt_seti(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 0), 0); EQ(rd(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE), 0);
    xt_close(s);
}
TEST(optx_reuse_and_exclusive_value_coding_any_nonzero_dword_is_on)
{
    static const int vals[] = {0, 1, 2, 255, 256, -1};
    static const int want[] = {0, 1, 1, 1, 1, 1};
    unsigned i;
    NEED();
    for (i = 0; i < 6; i++) {
        SOCKET a = xt_tcp(), b = xt_tcp();
        EQ(xt_seti(a, SOL_SOCKET, SO_REUSEADDR, vals[i]), 0);
        EQ(xt_seti(b, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, vals[i]), 0);
        CHECKF(rd(a, SOL_SOCKET, SO_REUSEADDR) == want[i], "reuse set 0x%x", vals[i]);
        CHECKF(rd(b, SOL_SOCKET, SO_EXCLUSIVEADDRUSE) == want[i], "exclusive set 0x%x", vals[i]);
        xt_close(a); xt_close(b);
    }
}
TEST(optx_reuse_and_exclusive_read_length_rules)
{
    SOCKET s; char b[8]; int n; xt_res r;
    NEED();
    s = xt_tcp();
    n = 1; r = xt_go(s, SOL_SOCKET, SO_REUSEADDR, b, &n); EQ(r.rc, 0); EQ(n, 1);
    n = 1; r = xt_go(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, b, &n); EQ(r.rc, 0); EQ(n, 1);
    n = 8; r = xt_go(s, SOL_SOCKET, SO_REUSEADDR, b, &n); EQ(r.rc, 0); EQ(n, 4);
    n = 8; r = xt_go(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, b, &n); EQ(r.rc, 0); EQ(n, 4);
    xt_close(s);
}

/* ---- what the second bind of the same port does while the first connection is alive ------------------------- */
/* Two clients bound to one local port (both allowed only when both carry SO_REUSEADDR) can each connect to a
 * different peer, but a second connection to the same peer is address-in-use. */
TEST(optx_two_reuse_clients_share_a_port_but_not_a_four_tuple)
{
    SOCKET l, c1, c2, a1, c3, a3; u_short p, q = 0; int rc, ec;
    NEED();
    EQ(xt_listen_lo(&l, &p, 8), 1);
    c1 = xt_tcp(); xt_seti(c1, SOL_SOCKET, SO_REUSEADDR, 1); EQ(xt_bind_lo(c1, &q), 0);
    EQ(xt_connect_lo(c1, p), 0); CHECK(xt_readable(l, 3000)); a1 = xt_accept(l);
    c2 = xt_tcp(); xt_seti(c2, SOL_SOCKET, SO_REUSEADDR, 1); EQ(xt_bind_lo(c2, &q), 0);
    rc = xt_connect_lo(c2, p); ec = rc ? U(WSAGetLastError)() : 0;
    EQ(rc, SOCKET_ERROR); EQ(ec, WSAEADDRINUSE);
    /* the failed connect leaves the socket unconnected and the first connection undisturbed */
    EQ(xt_send(c1, "ok", 2), 2); { char b[4]; EQ(xt_recv_all(a1, b, 2, 3000), 2); }
    /* a different destination port from the shared source port is a different four-tuple */
    {
        u_short p2; SOCKET l2;
        EQ(xt_listen_lo(&l2, &p2, 4), 1);
        c3 = xt_tcp(); xt_seti(c3, SOL_SOCKET, SO_REUSEADDR, 1); EQ(xt_bind_lo(c3, &q), 0);
        EQ(xt_connect_lo(c3, p2), 0); CHECK(xt_readable(l2, 3000)); a3 = xt_accept(l2);
        xt_close(a3); xt_close(c3); xt_close(l2);
    }
    xt_close(c1); xt_close(c2); xt_close(a1); xt_close(l);
}
TEST(optx_explicitly_bound_connected_client_still_holds_its_port_in_the_matrix)
{
    SOCKET l, c1, c2, c3, a1; u_short p, q = 0;
    NEED();
    EQ(xt_listen_lo(&l, &p, 8), 1);
    c1 = xt_tcp(); EQ(xt_bind_lo(c1, &q), 0); EQ(xt_connect_lo(c1, p), 0);
    CHECK(xt_readable(l, 3000)); a1 = xt_accept(l);
    /* the first client holds its port with no option: bound sockets still conflict through the matrix, even
     * though a connected socket of somebody else did not */
    c2 = xt_tcp(); EQ(xt_bind_lo(c2, &q), SOCKET_ERROR);
    EQ(xt_wsaerr(), WSAEADDRINUSE);
    c3 = xt_tcp(); xt_seti(c3, SOL_SOCKET, SO_REUSEADDR, 1); EQ(xt_bind_lo(c3, &q), SOCKET_ERROR);
    EQ(xt_wsaerr(), WSAEACCES);
    xt_close(c1); xt_close(c2); xt_close(c3); xt_close(a1); xt_close(l);
}

/* ---- a listener's options reach the sockets it accepts; the connecting socket is a separate object ---------- */
TEST(inherit_listener_options_are_copied_to_accepted_sockets_and_not_to_the_client)
{
    static const struct { int lvl, opt, val; const char *name; } rows[] = {
        {IPPROTO_TCP, XT_TCP_NODELAY, 1, "TCP_NODELAY"},
        {IPPROTO_TCP, XT_TCP_KEEPCNT, 3, "TCP_KEEPCNT"},
        {IPPROTO_TCP, XT_TCP_KEEPINTVL, 4, "TCP_KEEPINTVL"},
        {IPPROTO_TCP, XT_TCP_KEEPALIVE, 99, "TCP_KEEPALIVE"},
        {IPPROTO_TCP, XT_TCP_MAXRT, 77, "TCP_MAXRT"},
        {IPPROTO_TCP, XT_TCP_MAXRTMS, 5000, "TCP_MAXRTMS"},
        {IPPROTO_TCP, XT_TCP_DELAY_FIN_ACK, 1, "TCP_DELAY_FIN_ACK"},
        {SOL_SOCKET, SO_KEEPALIVE, 1, "SO_KEEPALIVE"},
        {SOL_SOCKET, SO_SNDBUF, 12345, "SO_SNDBUF"},
        {SOL_SOCKET, SO_RCVBUF, 23456, "SO_RCVBUF"},
        {SOL_SOCKET, SO_OOBINLINE, 1, "SO_OOBINLINE"},
        {SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR"},
    };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        SOCKET ref = xt_tcp(), l = xt_tcp(), c, a; u_short p = 0; long long dflt = rd(ref, rows[i].lvl, rows[i].opt);
        EQ(xt_bind_lo(l, &p), 0);
        EQ(xt_seti(l, rows[i].lvl, rows[i].opt, rows[i].val), 0);
        EQ(U(listen)(l, 2), 0);
        c = xt_tcp(); EQ(xt_connect_lo(c, p), 0); CHECK(xt_readable(l, 3000));
        a = xt_accept(l);
        CHECKF(rd(l, rows[i].lvl, rows[i].opt) == rows[i].val, "%s on the listener", rows[i].name);
        CHECKF(rd(a, rows[i].lvl, rows[i].opt) == rows[i].val, "%s on the accepted socket", rows[i].name);
        CHECKF(rd(c, rows[i].lvl, rows[i].opt) == dflt, "%s on the client changed", rows[i].name);
        xt_close(a); xt_close(c); xt_close(l); xt_close(ref);
    }
}
TEST(inherit_fastopen_reaches_the_accepted_socket_and_is_cleared_on_the_connected_client)
{
    SOCKET l, c, a; u_short p;
    NEED();
    EQ(xt_listen_lo(&l, &p, 2), 1);
    EQ(xt_seti(l, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    c = xt_tcp(); EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    EQ(xt_connect_lo(c, p), 0); CHECK(xt_readable(l, 3000));
    a = xt_accept(l);
    EQ(rd(a, IPPROTO_TCP, XT_TCP_FASTOPEN) & 0xff, 1);
    EQ(rd(c, IPPROTO_TCP, XT_TCP_FASTOPEN) & 0xff, 0);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- SIO_KEEPALIVE_VALS: on/off + idle ms + interval ms feed the seconds-based options ------------------------ */
static xt_res kvals(SOCKET s, DWORD on, DWORD t, DWORD i)
{
    struct tcp_keepalive k; k.onoff = on; k.keepalivetime = t; k.keepaliveinterval = i;
    return xt_io(s, SIO_KEEPALIVE_VALS, &k, sizeof k, NULL, 0);
}
/* on == 1 enables and converts both times to whole seconds (truncating); any other value is "off" and leaves
 * the stored times alone */
TEST(kavals_table_on_a_connected_socket)
{
    static const struct { DWORD on, t, i; long long ka, idle, intvl; } rows[] = {
        {1, 20000, 3000, 1, 20, 3},
        {1, 0, 0, 1, 0, 0},
        {1, 0, 1000, 1, 0, 1},
        {1, 1000, 0, 1, 1, 0},
        {1, 500, 500, 1, 0, 0},
        {1, 1, 1, 1, 0, 0},
        {1, 1500, 1500, 1, 1, 1},
        {1, 0xffffffffu, 1000, 1, 4294967, 1},
        {0, 0, 0, 0, 7200, 1},
        {0, 5000, 5000, 0, 7200, 1},
        {2, 5000, 7000, 0, 7200, 1},
        {0xffffffffu, 5000, 7000, 0, 7200, 1},
    };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        SOCKET c, a, l; xt_res r;
        if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
        r = kvals(c, rows[i].on, rows[i].t, rows[i].i);
        CHECKF(r.rc == 0 && r.ret == 0, "row %u: rc %d err %d", i, r.rc, r.err);
        CHECKF(rd(c, SOL_SOCKET, SO_KEEPALIVE) == rows[i].ka, "row %u so_keepalive %lld", i, rd(c, SOL_SOCKET, SO_KEEPALIVE));
        CHECKF(rd(c, IPPROTO_TCP, XT_TCP_KEEPALIVE) == rows[i].idle, "row %u idle %lld", i, rd(c, IPPROTO_TCP, XT_TCP_KEEPALIVE));
        CHECKF(rd(c, IPPROTO_TCP, XT_TCP_KEEPINTVL) == rows[i].intvl, "row %u interval %lld", i, rd(c, IPPROTO_TCP, XT_TCP_KEEPINTVL));
        xt_close(c); xt_close(a); xt_close(l);
    }
}
TEST(kavals_input_length_rules)
{
    static const struct { DWORD len; int ok; } rows[] = {{0, 0}, {4, 0}, {8, 0}, {12, 1}, {16, 1}};
    SOCKET c, a, l; DWORD blk[4] = {1, 30000, 5000, 9}; unsigned i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        xt_res r = xt_io(c, SIO_KEEPALIVE_VALS, blk, rows[i].len, NULL, 0);
        if (rows[i].ok) { CHECKF(r.rc == 0, "len %u: rc %d err %d", (unsigned)rows[i].len, r.rc, r.err); }
        else { CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "len %u: rc %d err %d", (unsigned)rows[i].len, r.rc, r.err); }
    }
    { xt_res r = xt_io(c, SIO_KEEPALIVE_VALS, NULL, 0, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT); }
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(kavals_accepted_in_every_tcp_state_and_matches_the_option_calls)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; xt_res r; const char *n = xt_state_name[tcp_kinds[k]];
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", n); return; }
        r = kvals(st.s, 1, 40000, 6000);
        CHECKF(r.rc == 0, "%s: rc %d err %d", n, r.rc, r.err);
        CHECKF(rd(st.s, IPPROTO_TCP, XT_TCP_KEEPALIVE) == 40 && rd(st.s, IPPROTO_TCP, XT_TCP_KEEPINTVL) == 6, "%s: idle/interval", n);
        xt_rmstate(&st);
    }
}
TEST(kavals_udp_socket_not_supported)
{
    SOCKET s = xt_udp(); xt_res r;
    NEED();
    r = kvals(s, 1, 1000, 1000); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    xt_close(s);
}
TEST(kavals_option_and_so_keepalive_are_independent_switches)
{
    SOCKET s;
    NEED();
    s = xt_tcp();
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_KEEPALIVE, 100), 0);
    EQ(rd(s, SOL_SOCKET, SO_KEEPALIVE), 0);             /* the idle time alone does not turn keep-alive on */
    EQ(xt_seti(s, SOL_SOCKET, SO_KEEPALIVE, 1), 0);
    EQ(rd(s, IPPROTO_TCP, XT_TCP_KEEPALIVE), 100);      /* turning it on keeps the stored idle time */
    EQ(xt_seti(s, SOL_SOCKET, SO_KEEPALIVE, 0), 0);
    EQ(rd(s, IPPROTO_TCP, XT_TCP_KEEPALIVE), 100);
    EQ(rd(s, IPPROTO_TCP, XT_TCP_KEEPCNT), 10);
    EQ(rd(s, IPPROTO_TCP, XT_TCP_KEEPINTVL), 1);
    xt_close(s);
}

/* ---- SO_LINGER companions --------------------------------------------------------------------------------- */
TEST(lingerx_dontlinger_reads_the_inverse_of_linger_enabled)
{
    SOCKET s; DWORD d = 7; int n = 4; struct linger l;
    NEED();
    s = xt_tcp();
    EQ(U(getsockopt)(s, SOL_SOCKET, SO_DONTLINGER, (char *)&d, &n), 0); EQ(d, 1);
    l.l_onoff = 1; l.l_linger = 5; EQ(xt_so(s, SOL_SOCKET, SO_LINGER, &l, sizeof l).rc, 0);
    n = 4; EQ(U(getsockopt)(s, SOL_SOCKET, SO_DONTLINGER, (char *)&d, &n), 0); EQ(d, 0);
    xt_close(s);
}
TEST(lingerx_dontlinger_set_clears_and_restores_only_the_switch)
{
    SOCKET s; struct linger l, g; int n, one = 1, zero = 0;
    NEED();
    s = xt_tcp();
    l.l_onoff = 1; l.l_linger = 5; EQ(xt_so(s, SOL_SOCKET, SO_LINGER, &l, sizeof l).rc, 0);
    EQ(xt_so(s, SOL_SOCKET, SO_DONTLINGER, &one, 4).rc, 0);
    n = sizeof g; EQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&g, &n), 0); EQ(g.l_onoff, 0); EQ(g.l_linger, 5);
    EQ(xt_so(s, SOL_SOCKET, SO_DONTLINGER, &zero, 4).rc, 0);
    n = sizeof g; EQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&g, &n), 0); EQ(g.l_onoff, 1); EQ(g.l_linger, 5);
    xt_close(s);
}
TEST(lingerx_get_length_rules)
{
    SOCKET s; struct linger g[2]; int n; xt_res r;
    NEED();
    s = xt_tcp();
    n = 3; r = xt_go(s, SOL_SOCKET, SO_LINGER, g, &n); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT);
    n = 2; r = xt_go(s, SOL_SOCKET, SO_LINGER, g, &n); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT);
    n = 0; r = xt_go(s, SOL_SOCKET, SO_LINGER, g, &n); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT);
    n = 8; r = xt_go(s, SOL_SOCKET, SO_LINGER, g, &n); EQ(r.rc, 0); EQ(n, 4);
    n = 0; r = xt_go(s, SOL_SOCKET, SO_DONTLINGER, g, &n); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT);
    xt_close(s);
}
TEST(lingerx_udp_socket_has_no_linger_option)
{
    SOCKET s = xt_udp(); struct linger l = {1, 0}; int n = sizeof l, one = 1; xt_res r;
    NEED();
    r = xt_so(s, SOL_SOCKET, SO_LINGER, &l, sizeof l); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAENOPROTOOPT);
    r = xt_go(s, SOL_SOCKET, SO_LINGER, &l, &n); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAENOPROTOOPT);
    r = xt_so(s, SOL_SOCKET, SO_DONTLINGER, &one, 4); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAENOPROTOOPT);
    xt_close(s);
}
TEST(lingerx_abortive_close_on_the_listener_does_not_reset_an_accepted_connection)
{
    SOCKET l, c, a; u_short p; struct linger z = {1, 0}; xt_info0 i; DWORD v = 0; char b[4];
    NEED();
    EQ(xt_listen_lo(&l, &p, 4), 1);
    EQ(xt_so(l, SOL_SOCKET, SO_LINGER, &z, sizeof z).rc, 0);
    c = xt_tcp(); EQ(xt_connect_lo(c, p), 0); CHECK(xt_readable(l, 3000));
    a = xt_accept(l);
    xt_close(l);
    EQ(xt_io(a, XT_SIO_TCP_INFO, &v, 4, &i, sizeof i).rc, 0); EQ(i.State, 4);
    EQ(xt_send(c, "hi", 2), 2); EQ(xt_recv_all(a, b, 2, 3000), 2);
    EQ(xt_send(a, "yo", 2), 2); EQ(xt_recv_all(c, b, 2, 3000), 2);
    xt_close(a); xt_close(c);
}

/* ---- TCP-level option presence on a fresh socket ----------------------------------------------------------- */
TEST(tcpopt_presence_table_on_a_fresh_socket)
{
    /* set1: error of setting 1; get: error of reading (0 = readable). 0 means accepted. */
    static const struct { int opt; int set1; int get; } rows[] = {
        {XT_TCP_NODELAY, 0, 0}, {XT_TCP_EXPEDITED_1122, 0, 0}, {XT_TCP_KEEPALIVE, 0, 0},
        {XT_TCP_MAXSEG, WSAENOPROTOOPT, WSAENOPROTOOPT}, {XT_TCP_MAXRT, 0, 0}, {XT_TCP_STDURG, 0, 0}, {XT_TCP_NOURG, 0, 0},
        {XT_TCP_ATMARK, WSAENOPROTOOPT, 0}, {XT_TCP_NOSYNRETRIES, 0, 0}, {XT_TCP_TIMESTAMPS, 0, 0},
        {XT_TCP_OFFLOAD_PREF, WSAENOPROTOOPT, WSAENOPROTOOPT}, {XT_TCP_CONGESTION, 0, 0}, {XT_TCP_DELAY_FIN_ACK, 0, 0},
        {XT_TCP_FASTOPEN, 0, 0}, {XT_TCP_KEEPCNT, 0, 0}, {XT_TCP_KEEPINTVL, 0, 0}, {XT_TCP_FAIL_CONNECT, 0, 0},
        {0x15, WSAENOPROTOOPT, WSAENOPROTOOPT}, {0x100, WSAENOPROTOOPT, WSAENOPROTOOPT}, {0x7000, WSAENOPROTOOPT, WSAENOPROTOOPT},
    };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        SOCKET s = xt_tcp(); long long v;
        int es = xt_seti(s, IPPROTO_TCP, rows[i].opt, 1), eg = xt_geti(s, IPPROTO_TCP, rows[i].opt, &v);
        CHECKF(es == rows[i].set1, "option 0x%x set: err %d want %d", rows[i].opt, es, rows[i].set1);
        CHECKF(eg == rows[i].get, "option 0x%x get: err %d want %d", rows[i].opt, eg, rows[i].get);
        if (rows[i].get == 0 && rows[i].set1 == 0 && rows[i].opt != XT_TCP_KEEPALIVE) CHECKF((v & 0xff) == 1 || v == 1, "option 0x%x reads back %lld", rows[i].opt, v);
        xt_close(s);
    }
}
TEST(tcpopt_unknown_level_is_invalid_argument_both_ways)
{
    SOCKET s; int one = 1, n = 4; xt_res r;
    NEED();
    s = xt_tcp();
    r = xt_so(s, 12345, 1, &one, 4); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEINVAL);
    r = xt_go(s, 12345, 1, &one, &n); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEINVAL);
    xt_close(s);
}
TEST(tcpopt_urgent_style_flags_are_plain_switches)
{
    static const int opts[] = {XT_TCP_EXPEDITED_1122, XT_TCP_STDURG, XT_TCP_NOURG};
    unsigned i;
    NEED();
    for (i = 0; i < 3; i++) {
        SOCKET s = xt_tcp(); long long v = -1;
        EQ(xt_geti(s, IPPROTO_TCP, opts[i], &v), 0); EQ(v, 0);
        EQ(xt_seti(s, IPPROTO_TCP, opts[i], 1), 0); EQ(rd(s, IPPROTO_TCP, opts[i]), 1);
        EQ(xt_seti(s, IPPROTO_TCP, opts[i], 0), 0); EQ(rd(s, IPPROTO_TCP, opts[i]), 0);
        xt_close(s);
    }
}

/* ---- TCP_INFO against buffer and timestamp settings --------------------------------------------------------- */
static void open_pair(SOCKET *c, SOCKET *a, SOCKET *l, int ts_listener, int ts_client, int rcvbuf)
{
    u_short p = 0;
    *l = xt_tcp(); *c = *a = INVALID_SOCKET;
    if (ts_listener) xt_seti(*l, IPPROTO_TCP, XT_TCP_TIMESTAMPS, 1);
    if (rcvbuf) xt_seti(*l, SOL_SOCKET, SO_RCVBUF, rcvbuf);
    if (xt_bind_lo(*l, &p) || U(listen)(*l, 2)) return;
    *c = xt_tcp();
    if (ts_client) xt_seti(*c, IPPROTO_TCP, XT_TCP_TIMESTAMPS, 1);
    if (rcvbuf) xt_seti(*c, SOL_SOCKET, SO_RCVBUF, rcvbuf);
    if (xt_connect_lo(*c, p)) return;
    xt_readable(*l, 3000);
    *a = U(accept)(*l, NULL, NULL);
}
TEST(infox_rcvbuf_field_equals_the_receive_buffer_option_on_both_ends)
{
    static const int sizes[] = {4096, 8192, 65536, 262144};
    unsigned i;
    NEED();
    for (i = 0; i < 4; i++) {
        SOCKET c, a, l; xt_info0 ic, ia; DWORD v = 0;
        open_pair(&c, &a, &l, 0, 0, sizes[i]);
        if (a == INVALID_SOCKET) { t_skip("pair failed"); xt_close(c); xt_close(l); return; }
        EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ic, sizeof ic).rc, 0); EQ(xt_io(a, XT_SIO_TCP_INFO, &v, 4, &ia, sizeof ia).rc, 0);
        CHECKF(ic.RcvBuf == (DWORD)sizes[i] && ia.RcvBuf == (DWORD)sizes[i], "size %d: client %u accepted %u", sizes[i], (unsigned)ic.RcvBuf, (unsigned)ia.RcvBuf);
        CHECKF(rd(c, SOL_SOCKET, SO_RCVBUF) == sizes[i] && rd(a, SOL_SOCKET, SO_RCVBUF) == sizes[i], "option size %d", sizes[i]);
        xt_close(c); xt_close(a); xt_close(l);
    }
}
TEST(infox_timestamps_negotiate_only_when_both_ends_ask_and_cost_twelve_mss_bytes)
{
    SOCKET c, a, l; xt_info0 base_c, ic, ia; DWORD v = 0; int m;
    NEED();
    open_pair(&c, &a, &l, 0, 0, 0);
    if (a == INVALID_SOCKET) { t_skip("pair failed"); xt_close(c); xt_close(l); return; }
    EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &base_c, sizeof base_c).rc, 0); EQ(base_c.Timestamps, 0);
    xt_close(c); xt_close(a); xt_close(l);
    for (m = 1; m < 4; m++) {
        int both = (m == 3);
        open_pair(&c, &a, &l, m & 1, (m >> 1) & 1, 0);
        if (a == INVALID_SOCKET) { t_skip("pair failed"); xt_close(c); xt_close(l); return; }
        EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ic, sizeof ic).rc, 0); EQ(xt_io(a, XT_SIO_TCP_INFO, &v, 4, &ia, sizeof ia).rc, 0);
        CHECKF(ic.Timestamps == (BYTE)both && ia.Timestamps == (BYTE)both, "listener %d client %d: field %u/%u", m & 1, (m >> 1) & 1, ic.Timestamps, ia.Timestamps);
        CHECKF(ic.Mss == base_c.Mss - (both ? 12 : 0) && ia.Mss == ic.Mss, "listener %d client %d: mss %u (plain %u)", m & 1, (m >> 1) & 1, (unsigned)ic.Mss, (unsigned)base_c.Mss);
        CHECKF(rd(c, IPPROTO_TCP, XT_TCP_TIMESTAMPS) == both, "option on client");
        xt_close(c); xt_close(a); xt_close(l);
    }
}
TEST(infox_overlapped_request_completes_inline_with_the_full_length)
{
    SOCKET c, a, l; DWORD v = 0, ret = 0xCCCCCCCC, got = 0, fl = 0; xt_info0 o; WSAOVERLAPPED ov; int rc;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    rc = U(WSAIoctl)(c, XT_SIO_TCP_INFO, &v, 4, &o, sizeof o, &ret, &ov, NULL);
    EQ(rc, 0); EQ(ret, 88); EQ(o.State, 4);
    EQ(U(WSAGetOverlappedResult)(c, &ov, &got, FALSE, &fl), TRUE); EQ(got, 88);
    ret = 0xCCCCCCCC;
    rc = U(WSAIoctl)(c, XT_SIO_TCP_INFO, &v, 4, &o, 10, &ret, &ov, NULL);
    EQ(rc, SOCKET_ERROR); EQ(U(WSAGetLastError)(), WSAEFAULT);
    U(WSACloseEvent)(ov.hEvent);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(infox_client_whose_connection_sits_unaccepted_in_the_backlog_is_established)
{
    SOCKET l, c; u_short p; xt_info0 i; DWORD v = 0;
    NEED();
    EQ(xt_listen_lo(&l, &p, 2), 1);
    c = xt_tcp(); EQ(xt_connect_lo(c, p), 0);
    EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &i, sizeof i).rc, 0); EQ(i.State, 4);
    xt_close(c); xt_close(l);
}
TEST(infox_data_after_receive_shutdown_aborts_the_connection)
{
    SOCKET c, a, l; xt_info0 ia, ic; DWORD v = 0; char b[8]; int r, e;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(U(shutdown)(a, SD_RECEIVE), 0);
    EQ(xt_send(c, "abc", 3), 3);
    CHECK(xt_wait_state(a, 0, 3000));
    CHECK(xt_wait_state(c, 0, 3000));
    EQ(xt_io(a, XT_SIO_TCP_INFO, &v, 4, &ia, sizeof ia).rc, 0); EQ(ia.State, 0); EQ(ia.BytesIn, 3);
    EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ic, sizeof ic).rc, 0); EQ(ic.State, 0);
    r = U(recv)(a, b, 8, 0); e = r < 0 ? U(WSAGetLastError)() : 0; EQ(r, SOCKET_ERROR); EQ(e, WSAECONNABORTED);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- a connection that carries data in its handshake (ConnectEx) -------------------------------------------- */
TEST(fastopenx_connectex_with_data_delivers_it_and_counts_it)
{
    int fo;
    NEED();
    for (fo = 0; fo < 2; fo++) {
        SOCKET l, c, a; u_short p, z = 0; GUID g = WSAID_CONNECTEX; LPFN_CONNECTEX cx = NULL; DWORD r = 0, sent = 0xCC, got = 0, fl = 0;
        struct sockaddr_in sa; OVERLAPPED ov; BOOL ok; char b[8] = {0}; xt_info0 i; DWORD ver = 0; int k;
        EQ(xt_listen_lo(&l, &p, 2), 1);
        if (fo) EQ(xt_seti(l, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
        c = xt_tcp();
        if (fo) EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
        if (U(WSAIoctl)(c, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &cx, sizeof cx, &r, NULL, NULL) || !cx) { t_skip("no ConnectEx"); xt_close(c); xt_close(l); return; }
        EQ(xt_bind_lo(c, &z), 0);
        memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = U(htonl)(INADDR_LOOPBACK); sa.sin_port = p;
        memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
        ok = cx(c, (struct sockaddr *)&sa, sizeof sa, (PVOID)"hello", 5, &sent, &ov);
        if (!ok) { EQ(U(WSAGetLastError)(), WSA_IO_PENDING); WaitForSingleObject(ov.hEvent, 5000); }
        EQ(U(WSAGetOverlappedResult)(c, &ov, &got, FALSE, &fl), TRUE); EQ(got, 5);
        CHECK(xt_readable(l, 3000)); a = xt_accept(l);
        EQ(xt_recv_all(a, b, 5, 3000), 5); EQ(memcmp(b, "hello", 5), 0);
        for (k = 0; k < 100; k++) { xt_io(c, XT_SIO_TCP_INFO, &ver, 4, &i, sizeof i); if (i.BytesOut == 5) break; Sleep(20); }
        EQ(i.BytesOut, 5); EQ(i.State, 4);
        U(WSACloseEvent)(ov.hEvent);
        xt_close(c); xt_close(a); xt_close(l);
    }
}

/* ---- bind independence ------------------------------------------------------------------------------------- */
static int bind_addr4(SOCKET s, DWORD host_order, u_short *port)
{
    struct sockaddr_in a; int l = sizeof a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = U(htonl)(host_order); a.sin_port = *port;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return U(WSAGetLastError)();
    U(getsockname)(s, (struct sockaddr *)&a, &l); *port = a.sin_port;
    return 0;
}
static void setm(SOCKET s, int m) { if (m == 1) xt_seti(s, SOL_SOCKET, SO_REUSEADDR, 1); if (m == 2) xt_seti(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1); }
TEST(bindx_distinct_loopback_addresses_never_conflict_unless_a_wildcard_is_exclusive)
{
    int m1, m2, w;
    NEED();
    for (w = 0; w < 2; w++) for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET s1 = xt_tcp(), s2 = xt_tcp(); u_short p = 0, q; int e;
        setm(s1, m1); setm(s2, m2);
        EQ(bind_addr4(s1, w ? INADDR_ANY : 0x7f000001u, &p), 0);
        q = p; e = bind_addr4(s2, 0x7f000002u, &q);
        { int want = (w && m1 == 2) ? WSAEACCES : 0;
          CHECKF(e == want, "first %s/%s then 127.0.0.2 %s: err %d want %d", w ? "wildcard" : "127.0.0.1", m1 == 0 ? "plain" : m1 == 1 ? "reuse" : "excl", m2 == 0 ? "plain" : m2 == 1 ? "reuse" : "excl", e, want); }
        xt_close(s1); xt_close(s2);
    }
}
TEST(bindx_other_family_and_other_protocol_never_conflict)
{
    SOCKET s1, s6, s6w, su, suw; u_short p = 0, q; struct sockaddr_in6 a6; int e;
    NEED();
    s1 = xt_tcp(); EQ(xt_bind_lo(s1, &p), 0);
    s6 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s6 == INVALID_SOCKET) { xt_close(s1); t_skip("no IPv6"); return; }
    memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6; a6.sin6_port = p; a6.sin6_addr.u.Byte[15] = 1;
    e = U(bind)(s6, (struct sockaddr *)&a6, sizeof a6) ? U(WSAGetLastError)() : 0; EQ(e, 0);
    s6w = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6; a6.sin6_port = p;
    e = U(bind)(s6w, (struct sockaddr *)&a6, sizeof a6) ? U(WSAGetLastError)() : 0; EQ(e, 0);
    su = xt_udp(); q = p; EQ(bind_addr4(su, INADDR_LOOPBACK, &q), 0);
    suw = xt_udp(); q = p; EQ(bind_addr4(suw, INADDR_ANY, &q), 0);
    xt_close(s1); xt_close(s6); xt_close(s6w); xt_close(su); xt_close(suw);
}
TEST(bindx_ipv6_socket_is_v6_only_by_default)
{
    SOCKET s = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    NEED();
    if (s == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    EQ(rd(s, IPPROTO_IPV6, IPV6_V6ONLY), 1);
    xt_close(s);
}
TEST(bindx_shared_listener_survives_its_twin_closing)
{
    SOCKET l1 = xt_tcp(), l2 = xt_tcp(); u_short p = 0; int i;
    NEED();
    xt_seti(l1, SOL_SOCKET, SO_REUSEADDR, 1); xt_seti(l2, SOL_SOCKET, SO_REUSEADDR, 1);
    EQ(xt_bind_lo(l1, &p), 0); EQ(xt_bind_lo(l2, &p), 0);
    EQ(U(listen)(l1, 4), 0); EQ(U(listen)(l2, 4), 0);
    xt_close(l1);
    for (i = 0; i < 4; i++) {
        SOCKET c = xt_tcp(), a;
        EQ(xt_connect_lo(c, p), 0);
        CHECK(xt_readable(l2, 3000));
        a = xt_accept(l2); CHECK(a != INVALID_SOCKET);
        xt_close(a); xt_close(c);
    }
    xt_close(l2);
}
