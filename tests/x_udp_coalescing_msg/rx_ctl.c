/* WSARecvMsg control data on loopback datagram sockets: which control messages each receive option adds,
 * their order, level/type, cmsg_len, alignment padding and values; the source name length; behaviour of a
 * control buffer that is too small (WSAEMSGSIZE, MSG_CTRUNC, the full length reported back, byte-granular
 * prefix copy, datagram consumed); data truncation (MSG_TRUNC) combined with control data; zero-length
 * datagrams. The CMSG layout macros are implemented locally from the documented structure. */
#include "xu.h"

#define L4 IPPROTO_IP
#define L6 IPPROTO_IPV6

static int open_pair(xu_ep *a, xu_ep *b, int af) {
    if (af == AF_INET6 && !xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return 0; }
    return xu_pair(a, b, af);
}
static void v4_all_on(SOCKET s) {
    CHECK(xu_setint(s, L4, XU_IP_RECVTTL, 1) == 0); CHECK(xu_setint(s, L4, XU_IP_RECVTOS, 1) == 0); CHECK(xu_setint(s, L4, XU_IP_PKTINFO, 1) == 0);
}
static void v6_all_on(SOCKET s) {
    CHECK(xu_setint(s, L6, XU_IPV6_HOPLIMIT, 1) == 0); CHECK(xu_setint(s, L6, XU_IPV6_RECVTCLASS, 1) == 0); CHECK(xu_setint(s, L6, XU_IPV6_PKTINFO, 1) == 0);
}
static int send_to(xu_ep *a, xu_ep *b, const void *d, int n) { return U(sendto)(a->s, (const char *)d, n, 0, (struct sockaddr *)&b->sa, b->len); }
/* send one 2-byte datagram and receive it with a 512 byte control buffer */
static int rx1(xu_ep *a, xu_ep *b, xu_rx *o, ULONG cap) {
    if (send_to(a, b, "ok", 2) != 2) return 0;
    if (!xu_ready(b->s, 3000)) return 0;
    xu_recv(b->s, o, 64, cap, 1, 0);
    return 1;
}
static xu_rx RX;

/* Nothing enabled: success, empty control, source name length of the family. */
TEST(xr_no_option_no_control_v4) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 2); EXPECT_EQ(RX.flags, 0); EXPECT_EQ(RX.ctllen, 0); EXPECT_EQ(RX.namelen, sizeof(struct sockaddr_in));
    xu_free(&a); xu_free(&b);
}
TEST(xr_no_option_no_control_v6) {
    xu_ep a, b; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 2); EXPECT_EQ(RX.flags, 0); EXPECT_EQ(RX.ctllen, 0); EXPECT_EQ(RX.namelen, sizeof(struct sockaddr_in6));
    xu_free(&a); xu_free(&b);
}

/* v4: all three switches. Order is packet info, TTL (type 4), TOS (type 3). Each message occupies 24 bytes
 * (16 byte header + data rounded up to 8); the 4-byte values have cmsg_len 20. */
TEST(xr_v4_three_messages_order_and_layout) {
    xu_ep a, b; const unsigned char *p; size_t n; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 72);
    CHECK(xu_cmsg_count(RX.ctl, RX.ctllen) == 3);
    { const WSACMSGHDR *h0 = (const WSACMSGHDR *)RX.ctl, *h1 = (const WSACMSGHDR *)(RX.ctl + 24), *h2 = (const WSACMSGHDR *)(RX.ctl + 48);
      EXPECT_EQ(h0->cmsg_level, IPPROTO_IP); EXPECT_EQ(h0->cmsg_type, 19); EXPECT_EQ(h0->cmsg_len, 16 + sizeof(struct in_pktinfo));
      EXPECT_EQ(h1->cmsg_level, IPPROTO_IP); EXPECT_EQ(h1->cmsg_type, 4);  EXPECT_EQ(h1->cmsg_len, 20);
      EXPECT_EQ(h2->cmsg_level, IPPROTO_IP); EXPECT_EQ(h2->cmsg_type, 3);  EXPECT_EQ(h2->cmsg_len, 20); }
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 19, &n); CHECK(p && n == sizeof(struct in_pktinfo));
    if (p && n == sizeof(struct in_pktinfo)) {
        const struct in_pktinfo *pi = (const struct in_pktinfo *)p;
        EXPECT_EQ(pi->ipi_addr.s_addr, 0x0100007fu); CHECK(pi->ipi_ifindex != 0);
    }
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 4, &n); CHECK(p && n == 4 && *(const int *)p == 128);
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 3, &n); CHECK(p && n == 4 && *(const int *)p == 0);
    xu_free(&a); xu_free(&b);
}
/* each switch alone yields exactly its own message */
TEST(xr_v4_single_switches) {
    static const struct { int opt, type; unsigned len; } T[] = {
        {XU_IP_RECVTTL, 4, 20}, {XU_IP_RECVTOS, 3, 20}, {XU_IP_PKTINFO, 19, 24}, {XU_IP_ECN, 50, 20},
    };
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; const WSACMSGHDR *h;
        if (!open_pair(&a, &b, AF_INET)) return;
        CHECK(xu_setint(b.s, L4, T[i].opt, 1) == 0);
        CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0);
        CHECKF(RX.ctllen == 24, "option %d: control length %lu", T[i].opt, (unsigned long)RX.ctllen);
        h = (const WSACMSGHDR *)RX.ctl;
        CHECKF(h->cmsg_level == IPPROTO_IP && h->cmsg_type == T[i].type && h->cmsg_len == (SIZE_T)(T[i].type == 19 ? 24 : 20), "option %d: level %d type %d len %d", T[i].opt, h->cmsg_level, h->cmsg_type, (int)h->cmsg_len);
        xu_free(&a); xu_free(&b);
    }
}
/* the TTL message carries the sender's TTL on loopback; the TOS message stays 0 whatever IP_TOS the sender set */
TEST(xr_v4_ttl_follows_sender_option) {
    static const int T[] = {1, 2, 64, 77, 128, 255, 0};
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; const unsigned char *p; size_t n;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s);
        CHECK(xu_setint(a.s, L4, XU_IP_TTL, T[i]) == 0);
        CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0);
        p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 4, &n); CHECKF(p && n == 4 && *(const int *)p == T[i], "sender ttl %d", T[i]);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xr_v4_sender_tos_option_is_not_on_the_wire) {
    static const int T[] = {0x28, 0xb8, 0xff, 0x04};
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; const unsigned char *p; size_t n;
        if (!open_pair(&a, &b, AF_INET)) return;
        CHECK(xu_setint(b.s, L4, XU_IP_RECVTOS, 1) == 0);
        CHECK(xu_setint(a.s, L4, XU_IP_TOS, T[i]) == 0);
        CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0);
        p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 3, &n); CHECKF(p && n == 4 && *(const int *)p == 0, "sender tos 0x%x", T[i]);
        xu_free(&a); xu_free(&b);
    }
}
/* the ECN switch on its own reports type 50 with the two ECN bits (0 for a plain datagram) */
TEST(xr_v4_ecn_switch_reports_codepoint_zero_for_plain_send) {
    xu_ep a, b; const unsigned char *p; size_t n; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_ECN, 1) == 0);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0);
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 50, &n); CHECK(p && n == 4 && *(const int *)p == 0);
    xu_free(&a); xu_free(&b);
}
/* switching an option off stops its message; switching on again restores it */
TEST(xr_v4_switch_off_and_on) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    CHECK(xu_setint(b.s, L4, XU_IP_RECVTTL, 0) == 0);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.ctllen, 48);
    CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, L4, 4, NULL) == NULL); CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, L4, 3, NULL) != NULL);
    CHECK(xu_setint(b.s, L4, XU_IP_RECVTTL, 1) == 0);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.ctllen, 72);
    xu_free(&a); xu_free(&b);
}
/* the control data is per datagram: a later datagram after the switch is on still carries it, and a
 * wildcard-bound receiver reports the same destination address */
TEST(xr_v4_pktinfo_on_wildcard_receiver_names_loopback_destination) {
    SOCKET r = U(socket)(AF_INET, SOCK_DGRAM, 0), s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in w, to; int n = sizeof w; const unsigned char *p; size_t pn; UP();
    REQUIRE(r != INVALID_SOCKET && s != INVALID_SOCKET);
    memset(&w, 0, sizeof w); w.sin_family = AF_INET;
    CHECK(U(bind)(r, (struct sockaddr *)&w, sizeof w) == 0); CHECK(U(getsockname)(r, (struct sockaddr *)&w, &n) == 0);
    CHECK(xu_setint(r, L4, XU_IP_PKTINFO, 1) == 0);
    to = w; to.sin_addr.s_addr = 0x0100007fu;
    CHECK(U(sendto)(s, "ok", 2, 0, (struct sockaddr *)&to, sizeof to) == 2);
    xu_recvw(r, &RX, 64, 128, 1, 0); EXPECT_EQ(RX.r, 0);
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 19, &pn); CHECK(p && pn == sizeof(struct in_pktinfo));
    if (p && pn == sizeof(struct in_pktinfo)) EXPECT_EQ(((const struct in_pktinfo *)p)->ipi_addr.s_addr, 0x0100007fu);
    xu_close(r); xu_close(s);
}

/* v6: packet info (40 bytes), hop limit, traffic class (24 each); ECN message sits between info and hop limit */
TEST(xr_v6_three_messages_order_and_layout) {
    xu_ep a, b; const unsigned char *p; size_t n; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    v6_all_on(b.s);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 88);
    CHECK(xu_cmsg_count(RX.ctl, RX.ctllen) == 3);
    { const WSACMSGHDR *h0 = (const WSACMSGHDR *)RX.ctl, *h1 = (const WSACMSGHDR *)(RX.ctl + 40), *h2 = (const WSACMSGHDR *)(RX.ctl + 64);
      EXPECT_EQ(h0->cmsg_level, IPPROTO_IPV6); EXPECT_EQ(h0->cmsg_type, 19); EXPECT_EQ(h0->cmsg_len, 16 + sizeof(struct in6_pktinfo));
      EXPECT_EQ(h1->cmsg_level, IPPROTO_IPV6); EXPECT_EQ(h1->cmsg_type, 21); EXPECT_EQ(h1->cmsg_len, 20);
      EXPECT_EQ(h2->cmsg_level, IPPROTO_IPV6); EXPECT_EQ(h2->cmsg_type, 39); EXPECT_EQ(h2->cmsg_len, 20); }
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L6, 19, &n);
    if (CHECK(p && n == sizeof(struct in6_pktinfo)), p && n == sizeof(struct in6_pktinfo)) {
        const struct in6_pktinfo *pi = (const struct in6_pktinfo *)p; static const unsigned char lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        CHECK(!memcmp(&pi->ipi6_addr, lo, 16)); CHECK(pi->ipi6_ifindex != 0);
    }
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L6, 21, &n); CHECK(p && n == 4 && *(const int *)p == 128);
    p = xu_cmsg_find(RX.ctl, RX.ctllen, L6, 39, &n); CHECK(p && n == 4 && *(const int *)p == 0);
    xu_free(&a); xu_free(&b);
}
TEST(xr_v6_single_switches) {
    static const struct { int opt, type; unsigned len, space; } T[] = {
        {XU_IPV6_HOPLIMIT, 21, 20, 24}, {XU_IPV6_RECVTCLASS, 39, 20, 24}, {XU_IPV6_PKTINFO, 19, 36, 40}, {XU_IPV6_ECN, 50, 20, 24},
    };
    size_t i; UP6();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; const WSACMSGHDR *h;
        if (!open_pair(&a, &b, AF_INET6)) return;
        CHECK(xu_setint(b.s, L6, T[i].opt, 1) == 0);
        CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0);
        CHECKF(RX.ctllen == T[i].space, "option %d: control length %lu", T[i].opt, (unsigned long)RX.ctllen);
        h = (const WSACMSGHDR *)RX.ctl;
        CHECKF(h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == T[i].type && h->cmsg_len == T[i].len, "option %d: level %d type %d len %d", T[i].opt, h->cmsg_level, h->cmsg_type, (int)h->cmsg_len);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xr_v6_ecn_message_sits_between_info_and_hoplimit) {
    xu_ep a, b; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    v6_all_on(b.s); CHECK(xu_setint(b.s, L6, XU_IPV6_ECN, 1) == 0);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 112);
    { const WSACMSGHDR *h1 = (const WSACMSGHDR *)(RX.ctl + 40), *h2 = (const WSACMSGHDR *)(RX.ctl + 64), *h3 = (const WSACMSGHDR *)(RX.ctl + 88);
      EXPECT_EQ(h1->cmsg_type, 50); EXPECT_EQ(h2->cmsg_type, 21); EXPECT_EQ(h3->cmsg_type, 39); }
    xu_free(&a); xu_free(&b);
}
TEST(xr_v6_hoplimit_follows_sender_option) {
    static const int T[] = {1, 2, 64, 77, 128, 255, 0};
    size_t i; UP6();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; const unsigned char *p; size_t n;
        if (!open_pair(&a, &b, AF_INET6)) return;
        CHECK(xu_setint(b.s, L6, XU_IPV6_HOPLIMIT, 1) == 0);
        CHECK(xu_setint(a.s, L6, XU_IPV6_UNICAST_HOPS, T[i]) == 0);
        CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0);
        p = xu_cmsg_find(RX.ctl, RX.ctllen, L6, 21, &n); CHECKF(p && n == 4 && *(const int *)p == T[i], "sender hops %d", T[i]);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xr_v6_switch_off_stops_message) {
    xu_ep a, b; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    v6_all_on(b.s); CHECK(xu_setint(b.s, L6, XU_IPV6_PKTINFO, 0) == 0);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.ctllen, 48);
    CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, L6, 19, NULL) == NULL);
    xu_free(&a); xu_free(&b);
}
/* The packet-info switch of the other family is the same switch on a datagram socket: enabling the IPv6 level
 * one on an AF_INET socket makes the IPv4 packet-info message appear (level IP, type 19), nothing else. */
TEST(xr_v4_socket_v6_level_pktinfo_switch_yields_v4_message) {
    xu_ep a, b; const WSACMSGHDR *h; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L6, XU_IPV6_PKTINFO, 1) == 0);
    CHECK(rx1(&a, &b, &RX, 512)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.ctllen, 24);
    h = (const WSACMSGHDR *)RX.ctl; EXPECT_EQ(h->cmsg_level, IPPROTO_IP); EXPECT_EQ(h->cmsg_type, 19);
    xu_free(&a); xu_free(&b);
}
/* MSG_PEEK returns the control data too and leaves the datagram for the real receive */
TEST(xr_peek_returns_control_and_keeps_datagram) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    CHECK(send_to(&a, &b, "ok", 2) == 2); CHECK(xu_ready(b.s, 3000));
    xu_recv(b.s, &RX, 64, 512, 1, MSG_PEEK); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 2); EXPECT_EQ(RX.flags, 0); EXPECT_EQ(RX.ctllen, 72);
    CHECK(xu_ready(b.s, 100));
    xu_recv(b.s, &RX, 64, 512, 1, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 2); EXPECT_EQ(RX.ctllen, 72);
    CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b);
}
/* data scattered over two buffers, control data alongside */
TEST(xr_scatter_buffers_with_control) {
    xu_ep a, b; WSAMSG m; WSABUF bf[2]; char d1[3], d2[8]; DWORD got = 0; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    CHECK(send_to(&a, &b, "abcdefg", 7) == 7); CHECK(xu_ready(b.s, 3000));
    memset(&m, 0, sizeof m); bf[0].buf = d1; bf[0].len = 3; bf[1].buf = d2; bf[1].len = sizeof d2;
    m.lpBuffers = bf; m.dwBufferCount = 2; memset(RX.ctl, 0xEE, 64); m.Control.buf = (CHAR *)RX.ctl; m.Control.len = 64;
    r = xu_rm(b.s, &m, &got, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 7); EXPECT_EQ(m.dwFlags, 0); EXPECT_EQ(m.Control.len, 24); CHECK(!memcmp(d1, "abc", 3) && !memcmp(d2, "defg", 4));
    xu_free(&a); xu_free(&b);
}

/* ---- control buffer too small ---- */
/* Reference bytes of the three v4 messages: header and data bytes (padding excluded). */
static void ref_v4(xu_ep *a, xu_ep *b, unsigned char *out) {
    xu_rx *r = &RX;
    CHECK(rx1(a, b, r, 512)); EXPECT_EQ(r->ctllen, 72);
    memcpy(out, r->ctl, 72);
}
static int meaningful(int off) { int m = off % 24; return !(off >= 24 && m >= 20); } /* 20..23 of the 2nd and 3rd message are padding */

/* For every capacity below 72 the call fails with WSAEMSGSIZE and MSG_CTRUNC, returns the datagram data, reports
 * the full 72 in Control.len, copies exactly the first cap bytes of the full control area (down to the byte) and
 * leaves the rest of the caller's buffer alone, and the datagram is consumed. */
TEST(xr_ctrunc_prefix_copy_every_capacity) {
    xu_ep a, b; unsigned char ref[72]; ULONG cap; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s); ref_v4(&a, &b, ref);
    for (cap = 0; cap < 72; cap++) {
        int i;
        CHECK(rx1(&a, &b, &RX, cap));
        CHECKF(RX.r == SOCKET_ERROR && RX.err == WSAEMSGSIZE, "cap %lu: r=%d err=%d", (unsigned long)cap, RX.r, RX.err);
        CHECKF(RX.flags == XU_MSG_CTRUNC, "cap %lu: flags 0x%lx", (unsigned long)cap, (unsigned long)RX.flags);
        CHECKF(RX.ctllen == 72, "cap %lu: Control.len %lu", (unsigned long)cap, (unsigned long)RX.ctllen);
        CHECKF(RX.got == 2 && !memcmp(RX.data, "ok", 2), "cap %lu: data got %lu", (unsigned long)cap, (unsigned long)RX.got);
        for (i = 0; i < (int)cap; i++) if (meaningful(i)) { CHECKF(RX.ctl[i] == ref[i], "cap %lu: byte %d", (unsigned long)cap, i); if (RX.ctl[i] != ref[i]) break; }
        for (i = (int)cap; i < (int)sizeof RX.ctl; i++) if (RX.ctl[i] != 0xEE) { CHECKF(0, "cap %lu: byte %d beyond capacity was written", (unsigned long)cap, i); break; }
        CHECKF(!xu_ready(b.s, 50), "cap %lu: datagram was not consumed", (unsigned long)cap);
    }
    xu_free(&a); xu_free(&b);
}
/* exact fit and larger succeed with flags 0 and the same length */
TEST(xr_exact_and_larger_control_capacity_succeed) {
    static const ULONG C[] = {72, 73, 79, 80, 96, 1000};
    xu_ep a, b; size_t i; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    for (i = 0; i < sizeof C / sizeof C[0]; i++) {
        CHECK(rx1(&a, &b, &RX, C[i]));
        CHECKF(RX.r == 0 && RX.flags == 0 && RX.ctllen == 72, "cap %lu: r=%d flags 0x%lx len %lu", (unsigned long)C[i], RX.r, (unsigned long)RX.flags, (unsigned long)RX.ctllen);
    }
    xu_free(&a); xu_free(&b);
}
/* with nothing enabled even a zero capacity is fine; with one switch on a zero capacity is MSG_CTRUNC */
TEST(xr_zero_capacity_without_options_is_success) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(rx1(&a, &b, &RX, 0)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.flags, 0); EXPECT_EQ(RX.ctllen, 0);
    xu_free(&a); xu_free(&b);
}
TEST(xr_zero_capacity_with_option_is_msgsize_ctrunc) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    CHECK(rx1(&a, &b, &RX, 0)); EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEMSGSIZE); EXPECT_EQ(RX.flags, XU_MSG_CTRUNC); EXPECT_EQ(RX.ctllen, 24); EXPECT_EQ(RX.got, 2);
    xu_free(&a); xu_free(&b);
}
TEST(xr_ctrunc_v6_capacities) {
    xu_ep a, b; ULONG cap; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    v6_all_on(b.s);
    for (cap = 0; cap < 88; cap += 8) {
        CHECK(rx1(&a, &b, &RX, cap));
        CHECKF(RX.r == SOCKET_ERROR && RX.err == WSAEMSGSIZE && RX.flags == XU_MSG_CTRUNC && RX.ctllen == 88, "cap %lu: r=%d err=%d flags 0x%lx len %lu", (unsigned long)cap, RX.r, RX.err, (unsigned long)RX.flags, (unsigned long)RX.ctllen);
    }
    CHECK(rx1(&a, &b, &RX, 88)); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.flags, 0);
    xu_free(&a); xu_free(&b);
}

/* ---- data truncation ---- */
TEST(xr_data_truncation_sets_msg_trunc_only) {
    xu_ep a, b; unsigned char big[300]; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    xu_fill(big, sizeof big, 5);
    CHECK(send_to(&a, &b, big, 300) == 300); xu_recvw(b.s, &RX, 100, 64, 1, 0);
    EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEMSGSIZE); EXPECT_EQ(RX.got, 100); EXPECT_EQ(RX.flags, XU_MSG_TRUNC); EXPECT_EQ(RX.ctllen, 0);
    CHECK(xu_same(RX.data, 100, 5)); CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b);
}
TEST(xr_data_truncation_with_control_keeps_control) {
    xu_ep a, b; unsigned char big[300]; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    xu_fill(big, sizeof big, 5); CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    CHECK(send_to(&a, &b, big, 300) == 300); xu_recvw(b.s, &RX, 100, 64, 1, 0);
    EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEMSGSIZE); EXPECT_EQ(RX.flags, XU_MSG_TRUNC); EXPECT_EQ(RX.ctllen, 24);
    CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, L4, 19, NULL) != NULL);
    xu_free(&a); xu_free(&b);
}
TEST(xr_data_and_control_truncation_set_both_flags) {
    xu_ep a, b; unsigned char big[300]; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    xu_fill(big, sizeof big, 5); CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    CHECK(send_to(&a, &b, big, 300) == 300); xu_recvw(b.s, &RX, 100, 0, 1, 0);
    EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEMSGSIZE); EXPECT_EQ(RX.flags, XU_MSG_TRUNC | XU_MSG_CTRUNC); EXPECT_EQ(RX.ctllen, 24); EXPECT_EQ(RX.got, 100);
    xu_free(&a); xu_free(&b);
}
/* exact datagram size is not truncation, one byte less is */
TEST(xr_data_exact_fit_versus_one_short) {
    xu_ep a, b; unsigned char d[64]; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    xu_fill(d, sizeof d, 1);
    CHECK(send_to(&a, &b, d, 64) == 64); xu_recvw(b.s, &RX, 64, 0, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 64); EXPECT_EQ(RX.flags, 0);
    CHECK(send_to(&a, &b, d, 64) == 64); xu_recvw(b.s, &RX, 63, 0, 1, 0);
    EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEMSGSIZE); EXPECT_EQ(RX.got, 63); EXPECT_EQ(RX.flags, XU_MSG_TRUNC);
    xu_free(&a); xu_free(&b);
}

/* ---- zero-length datagrams ---- */
TEST(xr_zero_length_datagram_carries_control) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    CHECK(send_to(&a, &b, "", 0) == 0); xu_recvw(b.s, &RX, 16, 128, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 0); EXPECT_EQ(RX.flags, 0); EXPECT_EQ(RX.ctllen, 72); EXPECT_EQ(RX.namelen, sizeof(struct sockaddr_in));
    xu_free(&a); xu_free(&b);
}
TEST(xr_zero_length_datagram_zero_capacity_buffer) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(send_to(&a, &b, "", 0) == 0); xu_recvw(b.s, &RX, 0, 0, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 0); EXPECT_EQ(RX.flags, 0);
    xu_free(&a); xu_free(&b);
}
TEST(xr_zero_length_datagram_v6_carries_control) {
    xu_ep a, b; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    v6_all_on(b.s);
    CHECK(send_to(&a, &b, "", 0) == 0); xu_recvw(b.s, &RX, 16, 128, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 0); EXPECT_EQ(RX.ctllen, 88);
    xu_free(&a); xu_free(&b);
}

/* ---- ordinary unicast datagrams never carry the broadcast/multicast flags ---- */
TEST(xr_unicast_flags_are_clear) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(rx1(&a, &b, &RX, 128)); EXPECT_EQ(RX.flags & (XU_MSG_BCAST | XU_MSG_MCAST | XU_MSG_TRUNC | XU_MSG_CTRUNC), 0);
    xu_free(&a); xu_free(&b);
}
TEST(xr_unicast_flags_are_clear_v6) {
    xu_ep a, b; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    CHECK(rx1(&a, &b, &RX, 128)); EXPECT_EQ(RX.flags & (XU_MSG_BCAST | XU_MSG_MCAST | XU_MSG_TRUNC | XU_MSG_CTRUNC), 0);
    xu_free(&a); xu_free(&b);
}
/* ---- layout constants ---- */
TEST(xr_cmsg_header_layout_and_macros) {
    UP();
    EXPECT_EQ(sizeof(WSACMSGHDR), 16); EXPECT_EQ(offsetof(WSACMSGHDR, cmsg_len), 0); EXPECT_EQ(offsetof(WSACMSGHDR, cmsg_level), 8); EXPECT_EQ(offsetof(WSACMSGHDR, cmsg_type), 12);
    EXPECT_EQ(XU_CMSG_LEN(4), 20); EXPECT_EQ(XU_CMSG_SPACE(4), 24); EXPECT_EQ(XU_CMSG_SPACE(8), 24); EXPECT_EQ(XU_CMSG_SPACE(9), 32); EXPECT_EQ(XU_CMSG_SPACE(0), 16);
    EXPECT_EQ(sizeof(struct in_pktinfo), 8); EXPECT_EQ(sizeof(struct in6_pktinfo), 20);
    EXPECT_EQ(sizeof(WSAMSG), 56); EXPECT_EQ(offsetof(WSAMSG, Control), 32); EXPECT_EQ(offsetof(WSAMSG, dwFlags), 48);
}
