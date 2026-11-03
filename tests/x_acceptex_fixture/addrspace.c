/* AcceptEx address space: the buffer is [receive data][local slot][remote slot], each slot reserved as
 * sizeof(sockaddr)+16 or more.  Checks the placement GetAcceptExSockaddrs reports, that the addresses are those of
 * the real endpoints, that nothing beyond the reserved region is written, and that the data and the address bytes do
 * not overlap.  Both families. */
#include "fx.h"

static void eq_addr(int af, const struct sockaddr *got, const fx_addr *want)
{
    EXPECT_EQ(got->sa_family, af);
    if (af == AF_INET) {
        const struct sockaddr_in *g = (const struct sockaddr_in *)got;
        EXPECT_EQ(g->sin_port, want->a4.sin_port);
        EXPECT_EQ(g->sin_addr.s_addr, want->a4.sin_addr.s_addr);
    } else {
        const struct sockaddr_in6 *g = (const struct sockaddr_in6 *)got;
        EXPECT_EQ(g->sin6_port, want->a6.sin6_port);
        CHECK(!memcmp(&g->sin6_addr, &want->a6.sin6_addr, 16));
        EXPECT_EQ(g->sin6_scope_id, 0);
        EXPECT_EQ(g->sin6_flowinfo, 0);
    }
}

/* One layout case: rl data bytes, slots slot+lx and slot+rx. */
static void layout_case(int af, DWORD rl, DWORD lx, DWORD rx)
{
    SOCKET acc, cl; DWORD got = 0, err = 0, ll, rr, n = FX_POISON, region; int clen, llen = 0, rlen = 0, i;
    struct sockaddr *lp = NULL, *rp = NULL; fx_addr cn; char data[64];
    FXC_OPEN(c, af);
    ll = c.f.slot + lx; rr = c.f.slot + rx; region = rl + ll + rr;
    acc = fx_stream(af);
    FX_EQ(fx_post(&c.f, acc, c.buf, rl, ll, rr, &n, &c.ov), WSA_IO_PENDING);
    cl = fx_client(&c.f);
    clen = sizeof cn;
    CHECK(fx_getsockname(cl, &cn.sa, &clen) == 0);
    memset(data, 'd', sizeof data);
    if (rl) FX_EQ(fx_send(cl, data, (int)rl, 0), (int)rl);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(got, rl);
    c.f.gaes(c.buf, rl, ll, rr, &lp, &llen, &rp, &rlen);
    EXPECT_EQ((unsigned char *)lp - c.buf, rl);
    EXPECT_EQ((unsigned char *)rp - c.buf, rl + ll);
    EXPECT_EQ(llen, c.f.alen);
    EXPECT_EQ(rlen, c.f.alen);
    eq_addr(af, lp, &c.f.addr);
    eq_addr(af, rp, &cn);
    for (i = 0; i < (int)rl; i++) if (c.buf[i] != 'd') break;
    EXPECT_EQ(i, rl);
    for (i = (int)region; i < FXC_BUF; i++) if (c.buf[i] != 0xCC) break;
    EXPECT_EQ(i, FXC_BUF);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* Table: receive length, extra local slot, extra remote slot. */
static const struct { DWORD rl, lx, rx; } layouts[] = {
    {0, 0, 0}, {1, 0, 0}, {2, 0, 0}, {1, 16, 0}, {1, 0, 16}, {1, 7, 31}, {8, 0, 0}, {8, 64, 64},
    {16, 0, 100}, {32, 100, 0}, {3, 1, 1}, {0, 40, 40}, {0, 0, 200}, {0, 200, 0}, {64, 0, 0}, {1, 100, 100},
};

TEST(addr_layout_table_v4) { unsigned i; for (i = 0; i < sizeof layouts / sizeof *layouts; i++) layout_case(AF_INET, layouts[i].rl, layouts[i].lx, layouts[i].rx); }
TEST(addr_layout_table_v6) { unsigned i; for (i = 0; i < sizeof layouts / sizeof *layouts; i++) layout_case(AF_INET6, layouts[i].rl, layouts[i].lx, layouts[i].rx); }

/* The minimum slots are sizeof(sockaddr)+16, and the family dictates the size: 32 for IPv4, 44 for IPv6. */
TEST(addr_minimum_slot_sizes_per_family)
{
    struct fx f4, f6;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    if (!fx_discover(&f4, AF_INET)) { t_skip("AcceptEx not offered"); return; }
    EXPECT_EQ(f4.slot, 32);
    EXPECT_EQ(sizeof(struct sockaddr_in) + 16, 32);
    if (fx_discover(&f6, AF_INET6)) {
        EXPECT_EQ(f6.slot, 44);
        EXPECT_EQ(sizeof(struct sockaddr_in6) + 16, 44);
    } else t_note("no IPv6");
}

/* Two accepted peers on one listener: each completion reports its own client's address, not a stale one. */
FX_BOTH(addr_each_completion_reports_its_own_peer)
{
    int k;
    FXC_OPEN(c, af);
    for (k = 0; k < 2; k++) {
        SOCKET acc = fx_stream(af), cl; DWORD got = 0, err = 0; fx_addr cn; int clen = sizeof cn, ll = 0, rl = 0; struct sockaddr *lp, *rp;
        FX_EQ(fxc_post(&c, acc, 0), WSA_IO_PENDING);
        cl = fx_client(&c.f);
        CHECK(fx_getsockname(cl, &cn.sa, &clen) == 0);
        CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
        c.f.gaes(c.buf, 0, c.f.slot, c.f.slot, &lp, &ll, &rp, &rl);
        eq_addr(af, rp, &cn);
        fx_close_all(cl, acc, INVALID_SOCKET);
    }
    fxc_close(&c);
}

/* Receive data and addresses never overlap: with a one-byte receive, byte 0 is data and offset 1 starts the local slot. */
FX_BOTH(addr_one_byte_receive_data_precedes_the_address_slots)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; int ll = 0, rl = 0; struct sockaddr *lp, *rp;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 1);
    cl = fx_client(&c.f);
    fx_send(cl, "\x7f", 1, 0);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    EXPECT_EQ(c.buf[0], 0x7f);
    c.f.gaes(c.buf, 1, c.f.slot, c.f.slot, &lp, &ll, &rp, &rl);
    EXPECT_EQ((unsigned char *)lp - c.buf, 1);
    EXPECT_EQ((unsigned char *)rp - c.buf, 1 + c.f.slot);
    EXPECT_EQ(lp->sa_family, af);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* A wrong receive length given to GetAcceptExSockaddrs shifts the reported positions but still points inside the buffer. */
FX_BOTH(addr_parser_positions_follow_the_lengths_it_is_given)
{
    SOCKET acc, cl; DWORD got = 0, err = 0; int ll = -1, rl = -1; struct sockaddr *lp = NULL, *rp = NULL;
    FXC_OPEN(c, af);
    acc = fx_stream(af);
    fxc_post(&c, acc, 0);
    cl = fx_client(&c.f);
    CHECK(fx_result(c.f.lst, &c.ov, &got, 3000, &err));
    c.f.gaes(c.buf, 0, c.f.slot, c.f.slot, &lp, &ll, &rp, &rl);
    EXPECT_EQ((unsigned char *)lp - c.buf, 0);
    EXPECT_EQ((unsigned char *)rp - c.buf, c.f.slot);
    c.f.gaes(c.buf, 5, c.f.slot, c.f.slot, &lp, &ll, &rp, &rl);
    EXPECT_EQ((unsigned char *)lp - c.buf, 5);
    EXPECT_EQ((unsigned char *)rp - c.buf, 5 + c.f.slot);
    fx_close_all(cl, acc, INVALID_SOCKET);
    fxc_close(&c);
}

/* An IPv4 client reaching a dual-stack IPv6 listener is reported as a v4-mapped IPv6 address, in a v6-sized slot. */
TEST(addr_dualstack_listener_reports_a_v4_mapped_remote)
{
    struct fx f; fx_addr la, v4; int len = (int)sizeof(struct sockaddr_in6), off = 0, ll = 0, rl = 0;
    SOCKET l, acc, cl; OVERLAPPED ov; unsigned char buf[FXC_BUF]; DWORD n = FX_POISON; struct sockaddr *lp = NULL, *rp = NULL;
    if (!fx_up()) { t_skip("winsock unavailable"); return; }
    l = fx_stream(AF_INET6);
    if (l == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; }
    if (!fx_discover(&f, AF_INET6)) { fx_closesocket(l); t_skip("AcceptEx not offered"); return; }
    CHECK(fx_setsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof off) == 0);
    memset(&la, 0, sizeof la);
    la.a6.sin6_family = AF_INET6;
    CHECK(fx_bind(l, &la.sa, len) == 0);
    CHECK(fx_getsockname(l, &la.sa, &len) == 0);
    CHECK(fx_listen(l, 4) == 0);
    f.lst = l;
    memset(&ov, 0, sizeof ov); ov.hEvent = fx_event();
    acc = fx_stream(AF_INET6);
    FX_EQ(fx_post(&f, acc, buf, 0, f.slot, f.slot, &n, &ov), WSA_IO_PENDING);
    cl = fx_stream(AF_INET);
    fx_loopback(AF_INET, &v4);
    v4.a4.sin_port = la.a6.sin6_port;
    CHECK(fx_connect(cl, &v4.sa, sizeof(struct sockaddr_in)) == 0);
    CHECK(fx_done_within(&ov, 3000));
    f.gaes(buf, 0, f.slot, f.slot, &lp, &ll, &rp, &rl);
    EXPECT_EQ(rp->sa_family, AF_INET6);
    EXPECT_EQ(rl, sizeof(struct sockaddr_in6));
    EXPECT_EQ(lp->sa_family, AF_INET6);
    EXPECT_EQ(ll, sizeof(struct sockaddr_in6));
    {
        const unsigned char *a = ((struct sockaddr_in6 *)rp)->sin6_addr.u.Byte; int i, z = 0;
        for (i = 0; i < 10; i++) z |= a[i];
        EXPECT_EQ(z, 0);
        EXPECT_EQ(a[10], 0xff);
        EXPECT_EQ(a[11], 0xff);
        EXPECT_EQ(a[12], 127);
        EXPECT_EQ(a[15], 1);
    }
    fx_close_all(cl, acc, l);
    CloseHandle(ov.hEvent);
}
