/* SO_RANDOMIZE_PORT, SO_PORT_SCALABILITY and SO_REUSE_UNICASTPORT across socket states and lengths. Measured per
 * option and state: whether setting is accepted, what reads back, and the exact error otherwise. */
#include "xt.h"

static const int tcp_kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN, XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED};
#define NTCP ((int)(sizeof tcp_kinds / sizeof tcp_kinds[0]))

/* ---- SO_RANDOMIZE_PORT: settable only before the socket is bound or connected ---------------------------- */
TEST(portopt_randomize_default_off_on_every_tcp_state)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; long long v = -1;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v) == 0 && v == 0, "%s", xt_state_name[tcp_kinds[k]]);
        xt_rmstate(&st);
    }
}
TEST(portopt_randomize_roundtrips_on_a_fresh_tcp_socket)
{
    SOCKET s; long long v;
    NEED();
    s = xt_tcp();
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 1), 0); EQ(xt_geti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v), 0); EQ(v, 1);
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 0), 0); EQ(xt_geti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v), 0); EQ(v, 0);
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 1), 0);
    xt_close(s);
}
TEST(portopt_randomize_refused_once_the_socket_is_bound_or_connected)
{
    int k;
    NEED();
    for (k = 1; k < NTCP; k++) {
        xt_st st; long long v = -1;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        CHECKF(xt_seti(st.s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 1) == WSAEINVAL, "set 1 on %s", xt_state_name[tcp_kinds[k]]);
        CHECKF(xt_seti(st.s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 0) == WSAEINVAL, "set 0 on %s", xt_state_name[tcp_kinds[k]]);
        CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v) == 0 && v == 0, "get on %s", xt_state_name[tcp_kinds[k]]);
        xt_rmstate(&st);
    }
}
TEST(portopt_randomize_set_before_bind_still_binds_a_nonzero_port)
{
    SOCKET s; u_short p = 0;
    NEED();
    s = xt_tcp();
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 1), 0);
    EQ(xt_bind_lo(s, &p), 0);
    CHECK(p != 0);
    xt_close(s);
}
TEST(portopt_randomize_on_udp_behaves_like_a_plain_boolean)
{
    SOCKET s; long long v;
    NEED();
    s = xt_udp();
    EQ(xt_geti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v), 0); EQ(v, 0);
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 1), 0); EQ(xt_geti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v), 0); EQ(v, 1);
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, 0), 0); EQ(xt_geti(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v), 0); EQ(v, 0);
    xt_close(s);
}

/* ---- SO_PORT_SCALABILITY: accepted in every TCP state, refused on datagram sockets ------------------------- */
TEST(portopt_scalability_roundtrips_in_every_tcp_state)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; long long v = -1; const char *n;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        n = xt_state_name[tcp_kinds[k]];
        CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &v) == 0 && v == 0, "default on %s", n);
        CHECKF(xt_seti(st.s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, 1) == 0, "set 1 on %s", n);
        CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &v) == 0 && v == 1, "read 1 on %s", n);
        CHECKF(xt_seti(st.s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, 0) == 0, "set 0 on %s", n);
        CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &v) == 0 && v == 0, "read 0 on %s", n);
        xt_rmstate(&st);
    }
}
TEST(portopt_scalability_refused_on_udp_both_ways)
{
    SOCKET s; long long v;
    NEED();
    s = xt_udp();
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, 1), WSAEINVAL);
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, 0), WSAEINVAL);
    EQ(xt_geti(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &v), WSAEINVAL);
    xt_close(s);
}
TEST(portopt_scalability_makes_every_second_bind_on_the_port_access_denied)
{
    static const int second[3] = {0, 1, 2};   /* second socket: plain, reuse, scalable too */
    int m;
    NEED();
    for (m = 0; m < 3; m++) {
        SOCKET s = xt_tcp(), t = xt_tcp(); u_short p = 0, q; int r;
        EQ(xt_seti(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, 1), 0);
        EQ(xt_bind_lo(s, &p), 0);
        if (second[m] == 1) EQ(xt_seti(t, SOL_SOCKET, SO_REUSEADDR, 1), 0);
        if (second[m] == 2) EQ(xt_seti(t, SOL_SOCKET, XT_SO_PORT_SCALABILITY, 1), 0);
        q = p; r = xt_bind_lo(t, &q);
        CHECKF(r == SOCKET_ERROR && U(WSAGetLastError)() == WSAEACCES, "second socket kind %d: rc %d err %d", m, r, r ? U(WSAGetLastError)() : 0);
        xt_close(s); xt_close(t);
    }
}
TEST(portopt_scalability_value_is_one_byte_boolean_and_randomize_is_a_dword_boolean)
{
    static const int vals[] = {0, 1, 2, 256, -1};
    static const int want_scal[] = {0, 1, 1, 0, 1};
    static const int want_rand[] = {0, 1, 1, 1, 1};
    unsigned i;
    NEED();
    for (i = 0; i < 5; i++) {
        SOCKET a = xt_tcp(), b = xt_tcp(); long long v = -1;
        EQ(xt_seti(a, SOL_SOCKET, XT_SO_PORT_SCALABILITY, vals[i]), 0); EQ(xt_geti(a, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &v), 0);
        CHECKF(v == want_scal[i], "scalability set 0x%x read %lld", vals[i], v);
        EQ(xt_seti(b, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, vals[i]), 0); EQ(xt_geti(b, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &v), 0);
        CHECKF(v == want_rand[i], "randomize set 0x%x read %lld", vals[i], v);
        xt_close(a); xt_close(b);
    }
}
TEST(portopt_option_length_rules)
{
    SOCKET s; BYTE b = 1; WORD w = 1; DWORD d = 1; xt_res r; int n; long long q[2];
    NEED();
    s = xt_tcp();
    /* randomize needs a full dword both ways */
    r = xt_so(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &b, 1); EQ(r.err, WSAEFAULT);
    r = xt_so(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &w, 2); EQ(r.err, WSAEFAULT);
    r = xt_so(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &d, 0); EQ(r.err, WSAEFAULT);
    n = 1; r = xt_go(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &d, &n); EQ(r.err, WSAEFAULT);
    n = 0; r = xt_go(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, &d, &n); EQ(r.err, WSAEFAULT);
    n = 8; r = xt_go(s, SOL_SOCKET, XT_SO_RANDOMIZE_PORT, q, &n); EQ(r.rc, 0); EQ(n, 4);
    /* scalability and unicast port take a byte */
    r = xt_so(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &b, 1); EQ(r.rc, 0);
    r = xt_so(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &w, 2); EQ(r.rc, 0);
    r = xt_so(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &d, 0); EQ(r.err, WSAEFAULT);
    n = 1; r = xt_go(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &d, &n); EQ(r.rc, 0);
    n = 0; r = xt_go(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, &d, &n); EQ(r.err, WSAEFAULT);
    n = 8; r = xt_go(s, SOL_SOCKET, XT_SO_PORT_SCALABILITY, q, &n); EQ(r.rc, 0); EQ(n, 1);
    r = xt_so(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &b, 1); EQ(r.rc, 0);
    r = xt_so(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &w, 2); EQ(r.rc, 0);
    r = xt_so(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &d, 0); EQ(r.err, WSAEFAULT);
    n = 1; r = xt_go(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &d, &n); EQ(r.rc, 0);
    n = 0; r = xt_go(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &d, &n); EQ(r.err, WSAEFAULT);
    n = 8; r = xt_go(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, q, &n); EQ(r.rc, 0); EQ(n, 1);
    xt_close(s);
}

/* ---- SO_REUSE_UNICASTPORT ------------------------------------------------------------------------------------ */
TEST(portopt_unicastport_set_accepted_only_on_fresh_tcp_socket)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; int e1, e0; const char *n;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        n = xt_state_name[tcp_kinds[k]];
        e1 = xt_seti(st.s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, 1);
        e0 = xt_seti(st.s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, 0);
        if (k == 0) { CHECKF(e1 == 0 && e0 == 0, "fresh: %d %d", e1, e0); }
        else { CHECKF(e1 == WSAEINVAL && e0 == WSAEINVAL, "%s: set1 %d set0 %d", n, e1, e0); }
        xt_rmstate(&st);
    }
}
TEST(portopt_unicastport_reads_back_zero_in_every_tcp_state)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; long long v = -1; const char *n;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        n = xt_state_name[tcp_kinds[k]];
        CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &v) == 0 && v == 0, "initial on %s", n);
        if (k == 0) {
            xt_seti(st.s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, 1);
            CHECKF(xt_geti(st.s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &v) == 0 && v == 0, "after set 1 on %s", n);
        }
        xt_rmstate(&st);
    }
}
TEST(portopt_unicastport_refused_on_udp_both_ways)
{
    SOCKET s; long long v;
    NEED();
    s = xt_udp();
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, 1), WSAEINVAL);
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, 0), WSAEINVAL);
    EQ(xt_geti(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, &v), WSAEINVAL);
    xt_close(s);
}
TEST(portopt_unicastport_before_bind_still_binds_a_nonzero_port)
{
    SOCKET s; u_short p = 0;
    NEED();
    s = xt_tcp();
    EQ(xt_seti(s, SOL_SOCKET, XT_SO_REUSE_UNICASTPORT, 1), 0);
    EQ(xt_bind_lo(s, &p), 0);
    CHECK(p != 0);
    xt_close(s);
}
