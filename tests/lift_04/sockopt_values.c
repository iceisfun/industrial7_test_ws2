/* lift_04: setsockopt/getsockopt value round trips and argument validation on stream sockets.
 * Measures: stored values read back unchanged (timeouts, buffer sizes, linger, keep-alive, nodelay),
 * odd option lengths, NULL/short option buffers, bad levels, SO_ERROR as a writable slot, and
 * the error contract on a closed socket. Everything runs on fresh unconnected sockets or a loopback pair. */
#include "l4.h"

#define TMO_A 63000
#define TMO_B 997000

static int int_roundtrip(SOCKET s, int level, int opt, int in, int *out)
{
    int sz = sizeof(int);
    *out = 0x5a5a5a5a;
    if (sso(s, level, opt, &in, sizeof in)) return lerr() ? lerr() : -1;
    if (gso(s, level, opt, out, &sz)) return lerr() ? lerr() : -1;
    return 0;
}

TEST(sockopt_rcvtimeo_roundtrip)
{
    SOCKET s; int v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    EQ(int_roundtrip(s, SOL_SOCKET, SO_RCVTIMEO, TMO_A, &v), 0);
    EQ(v, TMO_A);
    EQ(int_roundtrip(s, SOL_SOCKET, SO_RCVTIMEO, 0, &v), 0);
    EQ(v, 0);
    cl(s); ws_down();
}

TEST(sockopt_sndtimeo_roundtrip)
{
    SOCKET s; int v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(int_roundtrip(s, SOL_SOCKET, SO_SNDTIMEO, TMO_B, &v), 0);
    EQ(v, TMO_B);
    cl(s); ws_down();
}

TEST(sockopt_sndbuf_roundtrip)
{
    SOCKET s; int v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(int_roundtrip(s, SOL_SOCKET, SO_SNDBUF, 4096, &v), 0);
    EQ(v, 4096);
    cl(s); ws_down();
}

TEST(sockopt_rcvbuf_roundtrip_and_zero)
{
    SOCKET s; int v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(int_roundtrip(s, SOL_SOCKET, SO_RCVBUF, 4096, &v), 0);
    EQ(v, 4096);
    /* zero is accepted and reads back as zero (no minimum is enforced on the stored value) */
    EQ(int_roundtrip(s, SOL_SOCKET, SO_RCVBUF, 0, &v), 0);
    EQ(v, 0);
    cl(s); ws_down();
}

/* A tiny receive buffer must not stop a non-blocking reader from draining data in 4 KiB steps. */
TEST(sockopt_small_rcvbuf_still_drains_nonblocking)
{
    SOCKET a, b; int v, sz = sizeof v, i, r;
    static char buf[4096];
    if (!ws_up()) return;
    if (!make_pair(&a, &b, WSA_FLAG_OVERLAPPED)) { CHECK(0); ws_down(); return; }
    nonblock(a, 1); nonblock(b, 1);
    v = 0;
    EQ(sso(a, SOL_SOCKET, SO_SNDBUF, &v, sizeof v), 0);
    v = 0;
    EQ(gso(b, SOL_SOCKET, SO_RCVBUF, &v, &sz), 0);
    if (v < (int)sizeof(buf) * 3) { t_skip("default receive buffer too small (%d)", v); cl(a); cl(b); ws_down(); return; }
    v = 1024;
    EQ(sso(b, SOL_SOCKET, SO_RCVBUF, &v, sizeof v), 0);
    v = 0; sz = sizeof v;
    EQ(gso(b, SOL_SOCKET, SO_RCVBUF, &v, &sz), 0);
    EQ(v, 1024);
    for (i = 0; i < 3; i++) {
        r = U(send)(a, buf, sizeof buf, 0);
        EQ(r, sizeof buf);
    }
    for (i = 0; i < 3; i++) {
        r = sync_recv(b, buf, sizeof buf, 0);
        CHECKF(r == (int)sizeof buf, "chunk %d: recv gave %d err %d", i, r, lerr());
    }
    cl(a); cl(b); ws_down();
}

TEST(sockopt_linger_roundtrip_table)
{
    static const LINGER vals[] = { {0, 0}, {0, 73}, {1, 0}, {5, 189} };
    SOCKET s; int i;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    for (i = 0; i < NELEM(vals); i++) {
        LINGER l = vals[i], g;
        int sz = sizeof g;
        EQ(sso(s, SOL_SOCKET, SO_LINGER, &l, sizeof l), 0);
        memset(&g, 0x77, sizeof g);
        EQ(gso(s, SOL_SOCKET, SO_LINGER, &g, &sz), 0);
        CHECKF(!g.l_onoff == !vals[i].l_onoff, "row %d onoff %d", i, g.l_onoff);
        /* the timeout is only meaningful (and only compared) while lingering is on */
        if (g.l_onoff) CHECKF(g.l_linger == vals[i].l_linger, "row %d linger %d", i, g.l_linger);
    }
    cl(s); ws_down();
}

TEST(sockopt_linger_null_value_is_efault)
{
    SOCKET s;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    lset(0);
    EQ(sso(s, SOL_SOCKET, SO_LINGER, NULL, sizeof(LINGER)), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    lset(0);
    EQ(sso(s, SOL_SOCKET, SO_LINGER, NULL, 0), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    cl(s); ws_down();
}

TEST(sockopt_dontlinger_null_value_is_efault)
{
    SOCKET s;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    lset(0);
    EQ(sso(s, SOL_SOCKET, SO_DONTLINGER, NULL, sizeof(BOOL)), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    lset(0);
    EQ(sso(s, SOL_SOCKET, SO_DONTLINGER, NULL, 0), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    cl(s); ws_down();
}

/* TCP_NODELAY accepts any positive option length; only the first byte decides the value. */
TEST(sockopt_nodelay_accepts_positive_lengths)
{
    static const int lens[] = { 1, 4, 42 };
    SOCKET s; int i;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    for (i = 0; i < NELEM(lens); i++) {
        char big[64]; DWORD v; int sz = sizeof v, r;
        memset(big, 0, sizeof big); big[0] = 1;
        r = sso(s, IPPROTO_TCP, TCP_NODELAY, big, lens[i]);
        CHECKF(r == 0, "len %d: err %d", lens[i], lerr());
        v = 0xff;
        EQ(gso(s, IPPROTO_TCP, TCP_NODELAY, &v, &sz), 0);
        CHECKF(v == 1, "len %d: value %lx", lens[i], v);
        v = 0;
        EQ(sso(s, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v), 0);
    }
    cl(s); ws_down();
}

TEST(sockopt_nodelay_zero_length_is_efault)
{
    SOCKET s; DWORD v = 1; int sz = sizeof v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    lset(0);
    EQ(sso(s, IPPROTO_TCP, TCP_NODELAY, &v, 0), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    v = 0xff;
    EQ(gso(s, IPPROTO_TCP, TCP_NODELAY, &v, &sz), 0);
    EQ(v, 0);                        /* the failed set left it off */
    cl(s); ws_down();
}

TEST(sockopt_nodelay_negative_length_fails)
{
    SOCKET s; DWORD v = 1; int sz = sizeof v, e;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    lset(0);
    EQ(sso(s, IPPROTO_TCP, TCP_NODELAY, &v, -1), SOCKET_ERROR);
    e = lerr();
    CHECKF(e == WSAENOBUFS || e == WSAEFAULT, "err %d", e);
    t_note("TCP_NODELAY optlen -1 -> %s", e == WSAENOBUFS ? "WSAENOBUFS" : "WSAEFAULT");
    v = 0xff;
    EQ(gso(s, IPPROTO_TCP, TCP_NODELAY, &v, &sz), 0);
    EQ(v, 0);
    cl(s); ws_down();
}

TEST(sockopt_nodelay_high_byte_ignored)
{
    SOCKET s; DWORD v = 0x100; int sz = sizeof v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(sso(s, IPPROTO_TCP, TCP_NODELAY, &v, 4), 0);
    v = 0xff;
    EQ(gso(s, IPPROTO_TCP, TCP_NODELAY, &v, &sz), 0);
    EQ(v, 0);                        /* only the low byte of 0x100 counts */
    cl(s); ws_down();
}

TEST(sockopt_tcp_keepalive_roundtrip)
{
    SOCKET s; DWORD v = 3600; int sz = sizeof v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(sso(s, IPPROTO_TCP, TCP_KEEPALIVE, &v, 4), 0);
    v = 0;
    EQ(gso(s, IPPROTO_TCP, TCP_KEEPALIVE, &v, &sz), 0);
    EQ(v, 3600);
    cl(s); ws_down();
}

TEST(sockopt_tcp_keepcnt_keepintvl_roundtrip)
{
    SOCKET s; DWORD v = 5; int sz = sizeof v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(sso(s, IPPROTO_TCP, TCP_KEEPCNT, &v, 4), 0);
    v = 0;
    EQ(gso(s, IPPROTO_TCP, TCP_KEEPCNT, &v, &sz), 0);
    EQ(v, 5);
    v = 5;
    EQ(sso(s, IPPROTO_TCP, TCP_KEEPINTVL, &v, 4), 0);
    v = 0;
    EQ(gso(s, IPPROTO_TCP, TCP_KEEPINTVL, &v, &sz), 0);
    EQ(v, 5);
    cl(s); ws_down();
}

/* Levels that are neither SOL_SOCKET nor a known protocol level are rejected with WSAEINVAL. */
TEST(sockopt_invalid_levels_are_einval)
{
    static const unsigned levels[] = { 0xffffffffu, 0x00008000u };
    SOCKET s; int i, t = TMO_A;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    for (i = 0; i < NELEM(levels); i++) {
        lset(0);
        CHECKF(sso(s, (int)levels[i], SO_RCVTIMEO, &t, sizeof t) == SOCKET_ERROR, "level %x", levels[i]);
        CHECKF(lerr() == WSAEINVAL, "level %x err %d", levels[i], lerr());
    }
    cl(s); ws_down();
}

/* SO_ERROR can be written, succeeds without touching the last-error slot, and reads back what was stored. */
TEST(sockopt_so_error_set_succeeds_and_clears_error)
{
    SOCKET s; int v = 1234;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    SetLastError(0xdeadbeef);
    EQ(sso(s, SOL_SOCKET, SO_ERROR, &v, sizeof v), 0);
    EQ(lerr(), 0);
    cl(s); ws_down();
}

TEST(sockopt_so_error_reads_back_stored_value)
{
    SOCKET s; int v = 1234, sz = sizeof v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    EQ(sso(s, SOL_SOCKET, SO_ERROR, &v, sizeof v), 0);
    v = 4321;
    SetLastError(0xdeadbeef);
    EQ(gso(s, SOL_SOCKET, SO_ERROR, &v, &sz), 0);
    EQ(lerr(), 0);
    EQ(v, 1234);
    cl(s); ws_down();
}

TEST(sockopt_so_error_short_optlen_is_efault)
{
    SOCKET s; int v = 7, sz = 1;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    lset(0);
    EQ(gso(s, SOL_SOCKET, SO_ERROR, &v, &sz), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    cl(s); ws_down();
}

TEST(sockopt_getsockopt_closed_socket_is_enotsock)
{
    SOCKET s; int v = 1234, sz = sizeof v;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    cl(s);
    SetLastError(0xdeadbeef);
    EQ(gso(s, SOL_SOCKET, SO_ERROR, &v, &sz), SOCKET_ERROR);
    EQ(lerr(), WSAENOTSOCK);
    EQ(v, 1234);                     /* output untouched */
    ws_down();
}

TEST(sockopt_setsockopt_closed_socket_is_enotsock)
{
    SOCKET s; int v = 1;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, 0);
    cl(s);
    lset(0);
    EQ(sso(s, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof v), SOCKET_ERROR);
    EQ(lerr(), WSAENOTSOCK);
    cl(INVALID_SOCKET);
    EQ(lerr(), WSAENOTSOCK);
    ws_down();
}

/* Option calls without a prior WSAStartup are rejected before anything else is looked at (see startup file). */

/* A linger of {on, 0} then close sends an RST: the peer's pending read fails with a reset. */
TEST(sockopt_linger_zero_close_resets_peer)
{
    SOCKET a, b; LINGER l = { 1, 0 }; char c; int r;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, WSA_FLAG_OVERLAPPED)) { CHECK(0); ws_down(); return; }
    SetLastError(0xdeadbeef);
    EQ(sso(a, SOL_SOCKET, SO_LINGER, &l, sizeof l), 0);
    EQ(GetLastError(), 0);
    cl(a);
    r = U(recv)(b, &c, 1, 0);
    EQ(r, SOCKET_ERROR);
    EQ(lerr(), WSAECONNRESET);
    cl(b); ws_down();
}
