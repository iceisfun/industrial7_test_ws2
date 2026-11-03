/* TCP_FASTOPEN: a boolean (low byte decides) that is accepted on sockets that have not connected yet (fresh,
 * bound, listening) and refused with WSAEINVAL on connected ones; datagram sockets reject it both ways. Reading
 * works on every TCP socket. Fast open never changes what a plain loopback connection delivers. */
#include "xt.h"

static const int tcp_kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN, XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED};
#define NTCP ((int)(sizeof tcp_kinds / sizeof tcp_kinds[0]))

TEST(fastopen_default_off_in_every_tcp_state)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; long long v = -1;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        CHECKF(xt_geti(st.s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v) == 0 && (v & 0xff) == 0, "%s", xt_state_name[tcp_kinds[k]]);
        xt_rmstate(&st);
    }
}
TEST(fastopen_set_accepted_before_connect_states_refused_after)
{
    int k;
    NEED();
    for (k = 0; k < NTCP; k++) {
        xt_st st; int e1, e0; const char *n;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        n = xt_state_name[tcp_kinds[k]];
        e1 = xt_seti(st.s, IPPROTO_TCP, XT_TCP_FASTOPEN, 1);
        e0 = xt_seti(st.s, IPPROTO_TCP, XT_TCP_FASTOPEN, 0);
        if (k < 3) { CHECKF(e1 == 0 && e0 == 0, "%s: set1 %d set0 %d", n, e1, e0); }
        else { CHECKF(e1 == WSAEINVAL && e0 == WSAEINVAL, "%s: set1 %d set0 %d", n, e1, e0); }
        xt_rmstate(&st);
    }
}
TEST(fastopen_refused_set_leaves_the_value_alone)
{
    int k;
    NEED();
    for (k = 3; k < NTCP; k++) {
        xt_st st; long long v0 = -1, v1 = -1;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        EQ(xt_geti(st.s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v0), 0);
        EQ(xt_seti(st.s, IPPROTO_TCP, XT_TCP_FASTOPEN, v0 ? 0 : 1), WSAEINVAL);
        EQ(xt_geti(st.s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v1), 0);
        CHECKF(v0 == v1, "%s: %lld then %lld", xt_state_name[tcp_kinds[k]], v0, v1);
        xt_rmstate(&st);
    }
}
TEST(fastopen_value_coding_low_byte_decides)
{
    static const struct { int set; int rb; } rows[] = {
        {0, 0}, {1, 1}, {2, 1}, {5, 1}, {255, 1}, {256, 0}, {-1, 1}, {0x1ff, 1}, {0x100, 0}, {0x7fffffff, 1}, {(int)0x80000000u, 0}, {0x01000000, 0},
    };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        SOCKET s = xt_tcp(); long long v = -1;
        EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, rows[i].set), 0);
        EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v), 0);
        CHECKF((v & 0xff) == (long long)rows[i].rb, "set 0x%x read 0x%llx want %d", rows[i].set, v, rows[i].rb);
        xt_close(s);
    }
}
TEST(fastopen_set_length_rules)
{
    SOCKET s; BYTE b1 = 1; WORD w = 1; DWORD d = 1; long long q = 1; xt_res r;
    NEED();
    s = xt_tcp();
    r = xt_so(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &b1, 1); EQ(r.rc, 0);
    r = xt_so(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &w, 2); EQ(r.rc, 0);
    r = xt_so(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &d, 4); EQ(r.rc, 0);
    r = xt_so(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &q, 8); EQ(r.rc, 0);
    r = xt_so(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &d, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEFAULT);
    xt_close(s);
}
TEST(fastopen_listener_value_survives_listen)
{
    SOCKET s; u_short p = 0; long long v = -1;
    int backlogs[] = {1, 2, 5, 20, 200, 0x7fffffff}; unsigned i;
    NEED();
    for (i = 0; i < 6; i++) {
        s = xt_tcp(); p = 0;
        EQ(xt_bind_lo(s, &p), 0);
        EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
        EQ(U(listen)(s, backlogs[i]), 0);
        EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v), 0); EQ(v & 0xff, 1);
        xt_close(s);
    }
}
TEST(fastopen_can_be_set_and_cleared_on_a_live_listener)
{
    SOCKET s; u_short p; long long v = -1;
    NEED();
    EQ(xt_listen_lo(&s, &p, 5), 1);
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0); EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v), 0); EQ(v & 0xff, 1);
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 0), 0); EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v), 0); EQ(v & 0xff, 0);
    xt_close(s);
}
TEST(fastopen_udp_rejects_set_and_get)
{
    SOCKET s; long long v;
    NEED();
    s = xt_udp();
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), WSAEINVAL);
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 0), WSAEINVAL);
    EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, &v), WSAEINVAL);
    xt_close(s);
}
TEST(fastopen_accepted_on_a_fresh_ipv6_socket)
{
    SOCKET s;
    NEED();
    s = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    xt_close(s);
}
TEST(fastopen_listener_and_client_exchange_plain_data)
{
    SOCKET l, c, a; u_short p; char b[8]; xt_info0 i; DWORD z = 0; int k;
    NEED();
    EQ(xt_listen_lo(&l, &p, 5), 1);
    EQ(xt_seti(l, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    c = xt_tcp(); EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    EQ(xt_connect_lo(c, p), 0);
    CHECK(xt_readable(l, 3000)); a = xt_accept(l); CHECK(a != INVALID_SOCKET);
    EQ(xt_send(c, "hello", 5), 5);
    EQ(xt_recv_all(a, b, 5, 3000), 5); EQ(memcmp(b, "hello", 5), 0);
    for (k = 0; k < 100; k++) { xt_io(c, XT_SIO_TCP_INFO, &z, 4, &i, sizeof i); if (i.BytesOut == 5) break; Sleep(20); }
    EQ(i.BytesOut, 5); EQ(i.State, 4);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(fastopen_client_connects_to_a_non_fastopen_listener)
{
    SOCKET l, c, a; u_short p; char b[4];
    NEED();
    EQ(xt_listen_lo(&l, &p, 5), 1);
    c = xt_tcp(); EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    EQ(xt_connect_lo(c, p), 0);
    CHECK(xt_readable(l, 3000)); a = xt_accept(l);
    EQ(xt_send(a, "ok", 2), 2); EQ(xt_recv_all(c, b, 2, 3000), 2);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(fastopen_listener_set_does_not_change_the_nodelay_or_keepalive_options)
{
    SOCKET s; long long v;
    NEED();
    s = xt_tcp();
    EQ(xt_seti(s, IPPROTO_TCP, XT_TCP_FASTOPEN, 1), 0);
    EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_NODELAY, &v), 0); EQ(v & 0xff, 0);
    EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_KEEPALIVE, &v), 0); EQ(v, 7200);
    EQ(xt_geti(s, IPPROTO_TCP, XT_TCP_KEEPCNT, &v), 0); EQ(v, 10);
    xt_close(s);
}
