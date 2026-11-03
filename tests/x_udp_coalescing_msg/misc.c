/* Message-size limits, DONTFRAGMENT, path-MTU discovery modes, the checksum option, broadcast and loopback
 * address flags in WSARecvMsg, dual-stack control data and the network-reset ioctl, all on loopback. Maximum
 * datagram payload is 65507 for IPv4 and 65527 for IPv6 (SO_MAX_MSG_SIZE); the fragmentation options do not
 * change what loopback accepts. */
#include "xu.h"

static xu_rx RX;
static unsigned char BIG[70000];
static int open_pair(xu_ep *a, xu_ep *b, int af) {
    if (af == AF_INET6 && !xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return 0; }
    if (!xu_pair(a, b, af)) return 0;
    xu_setint(a->s, SOL_SOCKET, SO_SNDBUF, 1 << 20); xu_setint(b->s, SOL_SOCKET, SO_RCVBUF, 1 << 20);
    xu_fill(BIG, sizeof BIG, 3);
    return 1;
}

/* ---- maximum datagram size ---- */
static void size_table(int af, int df) {
    static const int N[] = {1, 1472, 1473, 8192, 32768, 65000, 65506, 65507, 65508, 65515, 65527, 65528, 65535, 65536, 65600};
    int maxv = af == AF_INET ? 65507 : 65527; size_t i; xu_ep a, b; int v = -1;
    if (!open_pair(&a, &b, af)) return;
    CHECK(xu_getint(a.s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v) == 0); EXPECT_EQ(v, maxv);
    if (df) { if (af == AF_INET) CHECK(xu_setint(a.s, IPPROTO_IP, XU_IP_DONTFRAGMENT, 1) == 0); else CHECK(xu_setint(a.s, IPPROTO_IPV6, XU_IPV6_DONTFRAG, 1) == 0); }
    for (i = 0; i < sizeof N / sizeof N[0]; i++) {
        DWORD sent = 0; int r, err;
        xu_seterr(0); r = xu_send(a.s, &b, BIG, N[i], NULL, 0, 0, &sent); err = r ? xu_err() : 0;
        if (N[i] <= maxv) {
            CHECKF(r == 0 && sent == (DWORD)N[i], "size %d: r=%d err=%d sent=%lu", N[i], r, err, (unsigned long)sent);
            if (r == 0) {
                xu_recvw(b.s, &RX, 66000, 0, 1, 0);
                CHECKF(RX.r == 0 && RX.got == (DWORD)N[i] && xu_same(RX.data, N[i], 3), "size %d: received %lu", N[i], (unsigned long)RX.got);
            }
        } else {
            CHECKF(r == SOCKET_ERROR && err == WSAEMSGSIZE, "size %d: r=%d err=%d", N[i], r, err);
            CHECK(!xu_ready(b.s, 20));
        }
    }
    xu_free(&a); xu_free(&b);
}
TEST(xm_max_datagram_v4) { UP(); size_table(AF_INET, 0); }
TEST(xm_max_datagram_v6) { UP6(); size_table(AF_INET6, 0); }
TEST(xm_max_datagram_v4_dontfragment) { UP(); size_table(AF_INET, 1); }
TEST(xm_max_datagram_v6_dontfragment) { UP6(); size_table(AF_INET6, 1); }

/* the same limit through sendto and through a message carrying control data */
TEST(xm_max_datagram_with_control_data) {
    xu_ep a, b; unsigned char c[64]; size_t off; DWORD sent; int t = 20, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    off = xu_cmsg_put(c, 0, IPPROTO_IP, 21, &t, 4);
    r = xu_send(a.s, &b, BIG, 65507, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 65507); xu_recvw(b.s, &RX, 66000, 0, 1, 0); EXPECT_EQ(RX.got, 65507);
    xu_seterr(0); r = xu_send(a.s, &b, BIG, 65508, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAEMSGSIZE);
    xu_seterr(0); r = U(sendto)(a.s, (char *)BIG, 65508, 0, (struct sockaddr *)&b.sa, b.len); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAEMSGSIZE);
    xu_free(&a); xu_free(&b);
}
TEST(xm_max_datagram_gathered_from_two_buffers) {
    xu_ep a, b; WSAMSG m; WSABUF bf[2]; DWORD sent = 0; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len; m.lpBuffers = bf; m.dwBufferCount = 2;
    bf[0].buf = (CHAR *)BIG; bf[0].len = 60000; bf[1].buf = (CHAR *)BIG + 60000; bf[1].len = 5507;
    r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 65507);
    xu_recvw(b.s, &RX, 66000, 0, 1, 0); EXPECT_EQ(RX.got, 65507); CHECK(xu_same(RX.data, 65507, 3));
    bf[1].len = 5508; xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAEMSGSIZE);
    xu_free(&a); xu_free(&b);
}
/* ---- path-MTU discovery modes and checksum option leave loopback delivery alone ---- */
TEST(xm_mtu_discover_modes_deliver_oversize_loopback_datagram) {
    int m; UP();
    for (m = 0; m < 4; m++) {
        xu_ep a, b; int r;
        if (!open_pair(&a, &b, AF_INET)) return;
        CHECK(xu_setint(a.s, IPPROTO_IP, XU_IP_MTU_DISCOVER, m) == 0);
        r = U(sendto)(a.s, (char *)BIG, 2000, 0, (struct sockaddr *)&b.sa, b.len); CHECKF(r == 2000, "mode %d: r=%d err=%d", m, r, xu_err());
        xu_recvw(b.s, &RX, 4000, 0, 1, 0); CHECKF(RX.r == 0 && RX.got == 2000, "mode %d: got %lu", m, (unsigned long)RX.got);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xm_dontfragment_oversize_loopback_datagram_still_delivers) {
    xu_ep a, b; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_IP, XU_IP_DONTFRAGMENT, 1) == 0);
    r = U(sendto)(a.s, (char *)BIG, 60000, 0, (struct sockaddr *)&b.sa, b.len); EXPECT_EQ(r, 60000);
    xu_recvw(b.s, &RX, 66000, 0, 1, 0); EXPECT_EQ(RX.got, 60000); CHECK(xu_same(RX.data, 60000, 3));
    CHECK(xu_setint(a.s, IPPROTO_IP, XU_IP_DONTFRAGMENT, 0) == 0);
    xu_free(&a); xu_free(&b);
}
TEST(xm_nochecksum_option_send_still_delivers) {
    xu_ep a, b; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_NOCHECKSUM, 1) == 0);
    r = U(sendto)(a.s, (char *)BIG, 100, 0, (struct sockaddr *)&b.sa, b.len); EXPECT_EQ(r, 100);
    xu_recvw(b.s, &RX, 4000, 0, 1, 0); EXPECT_EQ(RX.got, 100); CHECK(xu_same(RX.data, 100, 3));
    xu_free(&a); xu_free(&b);
}
/* the UDP-Lite style coverage option is not available on a plain datagram socket */
TEST(xm_checksum_coverage_is_einval) {
    SOCKET s; int r; UP(); s = U(socket)(AF_INET, SOCK_DGRAM, 0); REQUIRE(s != INVALID_SOCKET);
    xu_seterr(0); r = xu_setint(s, IPPROTO_UDP, XU_UDP_CHECKSUM_COVERAGE, 8); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAEINVAL);
    xu_close(s);
}

/* ---- broadcast flag ---- */
TEST(xm_loopback_broadcast_sets_msg_bcast) {
    SOCKET r = U(socket)(AF_INET, SOCK_DGRAM, 0), s = U(socket)(AF_INET, SOCK_DGRAM, 0); struct sockaddr_in w, to; int n = sizeof w, rc; UP();
    REQUIRE(r != INVALID_SOCKET && s != INVALID_SOCKET);
    memset(&w, 0, sizeof w); w.sin_family = AF_INET;
    CHECK(U(bind)(r, (struct sockaddr *)&w, sizeof w) == 0); CHECK(U(getsockname)(r, (struct sockaddr *)&w, &n) == 0);
    CHECK(xu_setint(s, SOL_SOCKET, SO_BROADCAST, 1) == 0);
    to = w; to.sin_addr.s_addr = 0xffffff7fu;               /* 127.255.255.255 */
    rc = U(sendto)(s, "bc", 2, 0, (struct sockaddr *)&to, sizeof to);
    if (rc != 2) { t_note("send to 127.255.255.255 failed: %d", xu_err()); xu_close(r); xu_close(s); return; }
    xu_recvw(r, &RX, 16, 0, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 2); EXPECT_EQ(RX.flags, XU_MSG_BCAST);
    to.sin_addr.s_addr = 0x0100007fu;
    CHECK(U(sendto)(s, "uc", 2, 0, (struct sockaddr *)&to, sizeof to) == 2); xu_recvw(r, &RX, 16, 0, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.flags, 0);
    xu_close(r); xu_close(s);
}
/* ---- loopback destination address other than 127.0.0.1 ---- */
TEST(xm_pktinfo_names_the_loopback_alias_destination) {
    SOCKET r = U(socket)(AF_INET, SOCK_DGRAM, 0), s = U(socket)(AF_INET, SOCK_DGRAM, 0); struct sockaddr_in w, to; int n = sizeof w; const unsigned char *p; size_t pn; UP();
    REQUIRE(r != INVALID_SOCKET && s != INVALID_SOCKET);
    memset(&w, 0, sizeof w); w.sin_family = AF_INET;
    CHECK(U(bind)(r, (struct sockaddr *)&w, sizeof w) == 0); CHECK(U(getsockname)(r, (struct sockaddr *)&w, &n) == 0);
    CHECK(xu_setint(r, IPPROTO_IP, XU_IP_PKTINFO, 1) == 0);
    to = w; to.sin_addr.s_addr = 0x0200007fu;               /* 127.0.0.2 */
    if (U(sendto)(s, "ok", 2, 0, (struct sockaddr *)&to, sizeof to) != 2) { t_note("send to 127.0.0.2 failed: %d", xu_err()); xu_close(r); xu_close(s); return; }
    xu_recvw(r, &RX, 16, 128, 1, 0); EXPECT_EQ(RX.r, 0);
    p = xu_cmsg_find(RX.ctl, RX.ctllen, IPPROTO_IP, 19, &pn);
    CHECK(p && pn == sizeof(struct in_pktinfo)); if (p && pn == sizeof(struct in_pktinfo)) EXPECT_EQ(((const struct in_pktinfo *)p)->ipi_addr.s_addr, 0x0200007fu);
    xu_close(r); xu_close(s);
}
/* ---- control data is decided when the datagram arrives ---- */
TEST(xm_switch_applies_to_datagrams_arriving_afterwards) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(U(sendto)(a.s, "ok", 2, 0, (struct sockaddr *)&b.sa, b.len) == 2);
    CHECK(xu_setint(b.s, IPPROTO_IP, XU_IP_PKTINFO, 1) == 0);
    xu_recvw(b.s, &RX, 16, 128, 1, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 0);
    CHECK(U(sendto)(a.s, "ok", 2, 0, (struct sockaddr *)&b.sa, b.len) == 2);
    xu_recvw(b.s, &RX, 16, 128, 1, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 24);
    xu_free(&a); xu_free(&b);
}
/* ---- dual-stack socket receiving an IPv4 datagram ---- */
static void dual_open(SOCKET *s6, SOCKET *s4, struct sockaddr_in *to) {
    struct sockaddr_in6 a6; struct sockaddr_in a4; int n = sizeof a6;
    *s6 = U(socket)(AF_INET6, SOCK_DGRAM, 0); *s4 = U(socket)(AF_INET, SOCK_DGRAM, 0);
    memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6;
    CHECK(xu_setint(*s6, IPPROTO_IPV6, XU_IPV6_V6ONLY, 0) == 0);
    CHECK(U(bind)(*s6, (struct sockaddr *)&a6, sizeof a6) == 0); CHECK(U(getsockname)(*s6, (struct sockaddr *)&a6, &n) == 0);
    memset(&a4, 0, sizeof a4); a4.sin_family = AF_INET; a4.sin_addr.s_addr = 0x0100007fu;
    CHECK(U(bind)(*s4, (struct sockaddr *)&a4, sizeof a4) == 0);
    *to = a4; to->sin_port = a6.sin6_port;
}
TEST(xm_dualstack_v4_datagram_reports_v4_level_control) {
    SOCKET s6, s4; struct sockaddr_in to; const unsigned char *p; size_t n; UP6();
    dual_open(&s6, &s4, &to);
    CHECK(xu_setint(s6, IPPROTO_IP, XU_IP_PKTINFO, 1) == 0); CHECK(xu_setint(s6, IPPROTO_IP, XU_IP_RECVTTL, 1) == 0); CHECK(xu_setint(s6, IPPROTO_IP, XU_IP_RECVTOS, 1) == 0);
    CHECK(xu_setint(s4, IPPROTO_IP, XU_IP_TTL, 33) == 0);
    CHECK(U(sendto)(s4, "d4", 2, 0, (struct sockaddr *)&to, sizeof to) == 2);
    xu_recvw(s6, &RX, 16, 512, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.namelen, sizeof(struct sockaddr_in6)); EXPECT_EQ(RX.ctllen, 72);
    p = xu_cmsg_find(RX.ctl, RX.ctllen, IPPROTO_IP, 4, &n); CHECK(p && n == 4 && *(const int *)p == 33);
    CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, IPPROTO_IP, 19, NULL) != NULL); CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, IPPROTO_IPV6, 19, NULL) == NULL);
    xu_close(s6); xu_close(s4);
}
TEST(xm_dualstack_v4_datagram_ignores_v6_level_switches) {
    SOCKET s6, s4; struct sockaddr_in to; UP6();
    dual_open(&s6, &s4, &to);
    CHECK(xu_setint(s6, IPPROTO_IPV6, XU_IPV6_PKTINFO, 1) == 0); CHECK(xu_setint(s6, IPPROTO_IPV6, XU_IPV6_HOPLIMIT, 1) == 0); CHECK(xu_setint(s6, IPPROTO_IPV6, XU_IPV6_RECVTCLASS, 1) == 0);
    CHECK(U(sendto)(s4, "d4", 2, 0, (struct sockaddr *)&to, sizeof to) == 2);
    xu_recvw(s6, &RX, 16, 512, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 0); EXPECT_EQ(RX.namelen, sizeof(struct sockaddr_in6));
    xu_close(s6); xu_close(s4);
}

/* ---- network-reset ioctl does not change connection-reset reporting ---- */
TEST(xm_netreset_ioctl_does_not_affect_connreset) {
    int pass; UP();
    for (pass = 0; pass < 2; pass++) {
        SOCKET s = U(socket)(AF_INET, SOCK_DGRAM, 0), d = U(socket)(AF_INET, SOCK_DGRAM, 0); struct sockaddr_in x; int n = sizeof x, r; DWORD on = pass, rt = 0; char bf[8];
        REQUIRE(s != INVALID_SOCKET && d != INVALID_SOCKET);
        memset(&x, 0, sizeof x); x.sin_family = AF_INET; x.sin_addr.s_addr = 0x0100007fu;
        CHECK(U(bind)(d, (struct sockaddr *)&x, sizeof x) == 0); CHECK(U(getsockname)(d, (struct sockaddr *)&x, &n) == 0); xu_close(d);
        CHECK(U(connect)(s, (struct sockaddr *)&x, sizeof x) == 0);
        CHECK(U(WSAIoctl)(s, XU_SIO_UDP_NETRESET, &on, 4, NULL, 0, &rt, NULL, NULL) == 0);
        CHECK(U(send)(s, "q", 1, 0) == 1);
        if (!xu_ready(s, 3000)) { CHECK(0); xu_close(s); continue; } xu_seterr(0); r = U(recv)(s, bf, 8, 0);
        EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAECONNRESET);
        xu_close(s);
    }
}
