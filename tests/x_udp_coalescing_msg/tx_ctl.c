/* WSASendMsg with control data on loopback datagram sockets. A control message is validated before the
 * datagram goes out: per-send hop limit (type 21), traffic/ECN bits (types 3 and 50), packet info (type 19),
 * the UDP segment-size message, wrong levels and types, wrong data lengths, headers that overrun the buffer.
 * Where a send succeeds the receiving socket reports what arrived. Note the asymmetry the tables pin down: the
 * hop limit is SENT with type 21 but RECEIVED as type 4 on IPv4 (21 on IPv6). */
#include "xu.h"

#define L4 IPPROTO_IP
#define L6 IPPROTO_IPV6
static xu_rx RX;

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
/* send "xy" with one control message; returns 0/SOCKET_ERROR; *err set */
static int send1(xu_ep *a, xu_ep *b, int level, int type, const void *d, size_t n, size_t cmsg_len_override, int *err) {
    unsigned char c[256]; size_t off = xu_cmsg_put(c, 0, level, type, d, n); DWORD sent = 0; int r;
    if (cmsg_len_override) ((WSACMSGHDR *)c)->cmsg_len = cmsg_len_override;
    r = xu_send(a->s, b, "xy", 2, c, (ULONG)off, 0, &sent);
    *err = r ? xu_err() : 0;
    if (!r) CHECK(sent == 2);
    return r;
}
/* receive what the previous successful send delivered, with a 512 byte control buffer */
static int rx1(xu_ep *b) {
    if (!xu_ready(b->s, 3000)) return 0;
    xu_recv(b->s, &RX, 64, 512, 1, 0);
    return RX.r == 0 && RX.got == 2;
}
static int rx_int(int level, int type, int *v) {
    size_t n; const unsigned char *p = xu_cmsg_find(RX.ctl, RX.ctllen, level, type, &n);
    if (!p || n != 4) return 0;
    *v = *(const int *)p; return 1;
}
#define EINV WSAEINVAL

/* ---- IPv4 hop limit: sent as type 21, received as type 4 ---- */
TEST(xt_v4_hoplimit_message_values) {
    static const struct { int v, err; } T[] = {
        {0,0},{1,0},{2,0},{64,0},{77,0},{128,0},{255,0},{256,EINV},{1000,EINV},{-1,EINV},{65536,EINV},
    };
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, got = -1;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s);
        send1(&a, &b, L4, 21, &T[i].v, 4, 0, &err);
        CHECKF(err == T[i].err, "hop limit %d: error %d want %d", T[i].v, err, T[i].err);
        if (!T[i].err) { CHECK(rx1(&b)); CHECKF(rx_int(L4, 4, &got) && got == T[i].v, "hop limit %d: received %d", T[i].v, got); }
        else CHECK(!xu_ready(b.s, 50));
        xu_free(&a); xu_free(&b);
    }
}
TEST(xt_v4_type4_is_not_a_send_message) {
    static const int T[] = {0, 1, 64, 255, 256, -1};
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err;
        if (!open_pair(&a, &b, AF_INET)) return;
        send1(&a, &b, L4, 4, &T[i], 4, 0, &err);
        CHECKF(err == EINV, "type 4 value %d: error %d", T[i], err);
        CHECK(!xu_ready(b.s, 50));
        xu_free(&a); xu_free(&b);
    }
}
/* the per-send hop limit beats the socket option */
TEST(xt_v4_hoplimit_message_overrides_socket_option) {
    xu_ep a, b; int err, got = -1, v = 9; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s); CHECK(xu_setint(a.s, L4, XU_IP_TTL, 40) == 0);
    send1(&a, &b, L4, 21, &v, 4, 0, &err); EXPECT_EQ(err, 0); CHECK(rx1(&b)); CHECK(rx_int(L4, 4, &got) && got == 9);
    CHECK(U(sendto)(a.s, "xy", 2, 0, (struct sockaddr *)&b.sa, b.len) == 2); CHECK(rx1(&b)); got = -1; CHECK(rx_int(L4, 4, &got) && got == 40);
    xu_free(&a); xu_free(&b);
}
/* ---- IPv4 TOS message: any integer is accepted and has no effect on the wire ---- */
TEST(xt_v4_tos_message_is_accepted_and_ignored) {
    static const int T[] = {0, 1, 2, 3, 0x28, 77, 255, 256, -1};
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, got = -1;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s);
        send1(&a, &b, L4, 3, &T[i], 4, 0, &err);
        CHECKF(err == 0, "tos message %d: error %d", T[i], err);
        CHECK(rx1(&b)); CHECKF(rx_int(L4, 3, &got) && got == 0, "tos message %d: received %d", T[i], got);
        xu_free(&a); xu_free(&b);
    }
}
/* ---- IPv4 ECN message (type 50): 0..2 pass through to the received TOS/ECN values, 3 is refused ---- */
TEST(xt_v4_ecn_message_codepoints) {
    static const struct { int v, err; } T[] = {{0,0},{1,0},{2,0},{3,EINV}};
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, tos = -1, ecn = -1;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s); CHECK(xu_setint(b.s, L4, XU_IP_ECN, 1) == 0);
        send1(&a, &b, L4, XU_IP_ECN, &T[i].v, 4, 0, &err);
        CHECKF(err == T[i].err, "ecn %d: error %d", T[i].v, err);
        if (!err) {
            CHECK(rx1(&b)); CHECK(rx_int(L4, 3, &tos) && tos == T[i].v); CHECK(rx_int(L4, 50, &ecn) && ecn == T[i].v);
        }
        xu_free(&a); xu_free(&b);
    }
}
TEST(xt_v4_ecn_report_follows_receiver_switch) {
    xu_ep a, b; int err, v = 2, got = -1; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_RECVTOS, 1) == 0);
    send1(&a, &b, L4, XU_IP_ECN, &v, 4, 0, &err); EXPECT_EQ(err, 0); CHECK(rx1(&b));
    CHECK(rx_int(L4, 3, &got) && got == 2); CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, L4, 50, NULL) == NULL);
    xu_free(&a); xu_free(&b);
}
/* ---- packet info ---- */
TEST(xt_v4_pktinfo_message_variants_are_accepted) {
    static const struct { unsigned addr; int ifx; } T[] = {
        {0x0100007fu, 0}, {0x0100007fu, 1}, {0x0100007fu, 0x7fff}, {0, 0}, {0x0200007fu, 0}, {0x0100a8c0u, 0},
    };
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; struct in_pktinfo pi; int err; const unsigned char *p; size_t n;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s);
        memset(&pi, 0, sizeof pi); pi.ipi_addr.s_addr = T[i].addr; pi.ipi_ifindex = T[i].ifx;
        send1(&a, &b, L4, 19, &pi, sizeof pi, 0, &err);
        CHECKF(err == 0, "pktinfo row %u: error %d", (unsigned)i, err);
        CHECK(rx1(&b));
        /* the receiver reports its own destination, whatever source/interface the sender asked for */
        p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 19, &n);
        CHECKF(p && n == sizeof pi && ((const struct in_pktinfo *)p)->ipi_addr.s_addr == 0x0100007fu, "pktinfo row %u: destination", (unsigned)i);
        xu_free(&a); xu_free(&b);
    }
}
/* data length of the messages: types 21 and 50 need at least 4 bytes (extra bytes ignored), packet info takes any */
TEST(xt_v4_message_data_length_rules) {
    UP();
    { int dl; for (dl = 0; dl <= 9; dl++) {
        xu_ep a, b; unsigned char d[16]; int err, got = -1;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s); memset(d, 0, sizeof d); d[0] = 33;
        send1(&a, &b, L4, 21, d, dl, 0, &err);
        CHECKF(err == (dl < 4 ? EINV : 0), "hop limit message, %d data bytes: error %d", dl, err);
        if (!err) { CHECK(rx1(&b)); CHECKF(rx_int(L4, 4, &got) && got == 33, "hop limit message, %d data bytes: value %d", dl, got); }
        xu_free(&a); xu_free(&b);
    } }
    { int dl; for (dl = 0; dl <= 9; dl++) {
        xu_ep a, b; unsigned char d[16]; int err, got = -1;
        if (!open_pair(&a, &b, AF_INET)) return;
        v4_all_on(b.s); memset(d, 0, sizeof d); d[0] = 1;
        send1(&a, &b, L4, XU_IP_ECN, d, dl, 0, &err);
        CHECKF(err == (dl < 4 ? EINV : 0), "ecn message, %d data bytes: error %d", dl, err);
        if (!err) { CHECK(rx1(&b)); CHECKF(rx_int(L4, 3, &got) && got == 1, "ecn message, %d data bytes: value %d", dl, got); }
        xu_free(&a); xu_free(&b);
    } }
    { int dl; for (dl = 0; dl <= 12; dl++) {
        xu_ep a, b; unsigned char d[16]; int err;
        if (!open_pair(&a, &b, AF_INET)) return;
        memset(d, 0, sizeof d);
        send1(&a, &b, L4, 19, d, dl, 0, &err);
        CHECKF(err == 0, "pktinfo message, %d data bytes: error %d", dl, err);
        xu_free(&a); xu_free(&b);
    } }
}
/* cmsg_len that disagrees with the buffer */
TEST(xt_v4_cmsg_len_against_buffer) {
    struct in_pktinfo pi; xu_ep a, b; int err; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    memset(&pi, 0, sizeof pi); pi.ipi_addr.s_addr = 0x0100007fu;
    send1(&a, &b, L4, 19, &pi, sizeof pi, XU_HDR + 8 + 2, &err); EXPECT_EQ(err, EINV);    /* longer than the buffer */
    send1(&a, &b, L4, 19, &pi, sizeof pi, XU_HDR + 8 + 8, &err); EXPECT_EQ(err, EINV);
    send1(&a, &b, L4, 19, &pi, sizeof pi, XU_HDR - 1, &err); EXPECT_EQ(err, EINV);        /* shorter than a header */
    send1(&a, &b, L4, 19, &pi, sizeof pi, 1, &err); EXPECT_EQ(err, EINV);
    send1(&a, &b, L4, 19, &pi, sizeof pi, XU_HDR + 4, &err); EXPECT_EQ(err, 0);           /* shorter data part is fine */
    send1(&a, &b, L4, 19, &pi, sizeof pi, XU_HDR, &err); EXPECT_EQ(err, 0);
    xu_free(&a); xu_free(&b);
}
/* level / type that the stack does not know */
TEST(xt_v4_unknown_level_or_type_is_einval) {
    static const struct { int level, type; } T[] = {
        {IPPROTO_IP, 99}, {SOL_SOCKET, 1}, {0xdead, 1}, {IPPROTO_IPV6, 19},
    };
    size_t i; UP();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, v = 1;
        if (!open_pair(&a, &b, AF_INET)) return;
        send1(&a, &b, T[i].level, T[i].type, &v, 4, 0, &err);
        CHECKF(err == EINV, "level %d type %d: error %d", T[i].level, T[i].type, err);
        CHECK(!xu_ready(b.s, 20));
        xu_free(&a); xu_free(&b);
    }
}
/* several messages in one buffer */
TEST(xt_v4_several_messages_in_one_buffer) {
    xu_ep a, b; unsigned char c[256]; size_t off; DWORD sent; struct in_pktinfo pi; int ttl = 55, ecn = 1, got = -1, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s); CHECK(xu_setint(b.s, L4, XU_IP_ECN, 1) == 0);
    memset(&pi, 0, sizeof pi); pi.ipi_addr.s_addr = 0x0100007fu;
    off = xu_cmsg_put(c, 0, L4, 21, &ttl, 4); off = xu_cmsg_put(c, off, L4, XU_IP_ECN, &ecn, 4); off = xu_cmsg_put(c, off, L4, 19, &pi, sizeof pi);
    r = xu_send(a.s, &b, "xy", 2, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 2);
    CHECK(rx1(&b)); EXPECT_EQ(RX.ctllen, 96);
    /* received order: info, ECN, hop limit (type 4), TOS */
    { const WSACMSGHDR *h = (const WSACMSGHDR *)RX.ctl;
      EXPECT_EQ(h[0].cmsg_type, 19); EXPECT_EQ(((const WSACMSGHDR *)(RX.ctl + 24))->cmsg_type, 50); EXPECT_EQ(((const WSACMSGHDR *)(RX.ctl + 48))->cmsg_type, 4); EXPECT_EQ(((const WSACMSGHDR *)(RX.ctl + 72))->cmsg_type, 3); }
    CHECK(rx_int(L4, 4, &got) && got == 55); CHECK(rx_int(L4, 3, &got) && got == 1); CHECK(rx_int(L4, 50, &got) && got == 1);
    xu_free(&a); xu_free(&b);
}
TEST(xt_v4_duplicate_message_first_one_wins) {
    xu_ep a, b; unsigned char c[256]; size_t off; DWORD sent; int t1 = 55, t2 = 10, got = -1, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    off = xu_cmsg_put(c, 0, L4, 21, &t1, 4); off = xu_cmsg_put(c, off, L4, 21, &t2, 4);
    r = xu_send(a.s, &b, "xy", 2, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, 0);
    CHECK(rx1(&b)); CHECK(rx_int(L4, 4, &got) && got == 55);
    xu_free(&a); xu_free(&b);
}
TEST(xt_v4_unknown_message_anywhere_spoils_the_send) {
    xu_ep a, b; unsigned char c[256]; size_t off; DWORD sent; int t1 = 55, t2 = 10, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    off = xu_cmsg_put(c, 0, L4, 21, &t1, 4); off = xu_cmsg_put(c, off, L4, 99, &t2, 4);
    r = xu_send(a.s, &b, "xy", 2, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), EINV);
    off = xu_cmsg_put(c, 0, L4, 99, &t2, 4); off = xu_cmsg_put(c, off, L4, 21, &t1, 4);
    r = xu_send(a.s, &b, "xy", 2, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), EINV);
    CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b);
}
/* the buffer length as a whole */
TEST(xt_v4_control_buffer_length_protocol) {
    xu_ep a, b; unsigned char c[256]; size_t off; DWORD sent; int t = 55, r, got = -1; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    off = xu_cmsg_put(c, 0, L4, 21, &t, 4);
    r = xu_send(a.s, &b, "xy", 2, c, 0, 0, &sent); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAEFAULT);   /* buffer present, length 0 */
    r = xu_send(a.s, &b, "xy", 2, c, 3, 0, &sent); EXPECT_EQ(r, 0);                                              /* too short for a header: ignored */
    CHECK(rx1(&b)); CHECK(rx_int(L4, 4, &got) && got == 128);
    r = xu_send(a.s, &b, "xy", 2, c, 16, 0, &sent); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), EINV);        /* a header whose length overruns */
    r = xu_send(a.s, &b, "xy", 2, NULL, 0, 0, &sent); EXPECT_EQ(r, 0);                                           /* no control at all */
    off = xu_cmsg_put(c, 0, L4, 21, &t, 4); off = xu_cmsg_put(c, off, L4, 21, &t, 4);
    r = xu_send(a.s, &b, "xy", 2, c, (ULONG)(XU_CMSG_SPACE(4) + 4), 0, &sent); EXPECT_EQ(r, 0);                    /* trailing bytes too short for a header */
    xu_drain(b.s, 50);
    xu_free(&a); xu_free(&b);
}
/* ---- IPv6 ---- */
TEST(xt_v6_hoplimit_message_values) {
    static const struct { int v, err; } T[] = {{0,0},{1,0},{77,0},{128,0},{255,0},{256,EINV},{-1,EINV},{1000,EINV}};
    size_t i; UP6();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, got = -1;
        if (!open_pair(&a, &b, AF_INET6)) return;
        v6_all_on(b.s);
        send1(&a, &b, L6, 21, &T[i].v, 4, 0, &err);
        CHECKF(err == T[i].err, "hop limit %d: error %d", T[i].v, err);
        if (!err) { CHECK(rx1(&b)); CHECKF(rx_int(L6, 21, &got) && got == T[i].v, "hop limit %d: received %d", T[i].v, got); }
        xu_free(&a); xu_free(&b);
    }
}
TEST(xt_v6_tclass_message_is_not_accepted) {
    static const int T[] = {0, 1, 3, 0x28, 77, 255, 256, -1};
    size_t i; UP6();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err;
        if (!open_pair(&a, &b, AF_INET6)) return;
        send1(&a, &b, L6, 39, &T[i], 4, 0, &err);
        CHECKF(err == EINV, "traffic class %d: error %d", T[i], err);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xt_v6_ecn_message_codepoints) {
    static const struct { int v, err; } T[] = {{0,0},{1,0},{2,0},{3,EINV}};
    size_t i; UP6();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, tc = -1, ecn = -1;
        if (!open_pair(&a, &b, AF_INET6)) return;
        v6_all_on(b.s); CHECK(xu_setint(b.s, L6, XU_IPV6_ECN, 1) == 0);
        send1(&a, &b, L6, XU_IPV6_ECN, &T[i].v, 4, 0, &err);
        CHECKF(err == T[i].err, "ecn %d: error %d", T[i].v, err);
        if (!err) { CHECK(rx1(&b)); CHECK(rx_int(L6, 39, &tc) && tc == T[i].v); CHECK(rx_int(L6, 50, &ecn) && ecn == T[i].v); }
        xu_free(&a); xu_free(&b);
    }
}
TEST(xt_v6_pktinfo_message_variants_and_lengths) {
    xu_ep a, b; struct in6_pktinfo pi; int err, dl; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    v6_all_on(b.s);
    memset(&pi, 0, sizeof pi); pi.ipi6_addr.u.Byte[15] = 1;
    send1(&a, &b, L6, 19, &pi, sizeof pi, 0, &err); EXPECT_EQ(err, 0); CHECK(rx1(&b));
    pi.ipi6_ifindex = 1; send1(&a, &b, L6, 19, &pi, sizeof pi, 0, &err); EXPECT_EQ(err, 0); CHECK(rx1(&b));
    memset(&pi, 0, sizeof pi); send1(&a, &b, L6, 19, &pi, sizeof pi, 0, &err); EXPECT_EQ(err, 0); CHECK(rx1(&b));
    for (dl = 0; dl <= 8; dl += 4) { send1(&a, &b, L6, 19, &pi, dl, 0, &err); CHECKF(err == 0, "pktinfo with %d data bytes: error %d", dl, err); CHECK(rx1(&b)); }
    xu_free(&a); xu_free(&b);
}
TEST(xt_v6_hoplimit_data_too_short) {
    xu_ep a, b; int err, v = 5; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    send1(&a, &b, L6, 21, &v, 1, 0, &err); EXPECT_EQ(err, EINV);
    xu_free(&a); xu_free(&b);
}
TEST(xt_v6_unknown_level_or_type_is_einval) {
    static const struct { int level, type; } T[] = {{IPPROTO_IPV6, 99}, {IPPROTO_IPV6, 0}, {IPPROTO_IP, 19}, {IPPROTO_IP, 21}, {IPPROTO_IP, 4}, {SOL_SOCKET, 1}, {0xdead, 1}};
    size_t i; UP6();
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, v = 1;
        if (!open_pair(&a, &b, AF_INET6)) return;
        send1(&a, &b, T[i].level, T[i].type, &v, 4, 0, &err);
        CHECKF(err == EINV, "level %d type %d: error %d", T[i].level, T[i].type, err);
        xu_free(&a); xu_free(&b);
    }
}
/* ---- zero-length datagrams ---- */
TEST(xt_zero_length_datagram_with_control_arrives) {
    xu_ep a, b; WSAMSG m; WSABUF bf[2]; char z[4]; unsigned char c[64]; size_t off; DWORD sent = 9; int t = 9, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    v4_all_on(b.s);
    memset(&m, 0, sizeof m); bf[0].buf = z; bf[0].len = 0; bf[1].buf = z; bf[1].len = 0;
    m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len; m.lpBuffers = bf; m.dwBufferCount = 1;
    off = xu_cmsg_put(c, 0, L4, 21, &t, 4); m.Control.buf = (CHAR *)c; m.Control.len = (ULONG)off;
    r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 0);
    xu_recvw(b.s, &RX, 16, 512, 1, 0);
    EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 0); EXPECT_EQ(RX.ctllen, 72); { int got = -1; CHECK(rx_int(L4, 4, &got) && got == 9); }
    m.dwBufferCount = 2; m.Control.buf = NULL; m.Control.len = 0; sent = 9;
    r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 0);
    xu_recvw(b.s, &RX, 16, 512, 1, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 0);
    xu_free(&a); xu_free(&b);
}
TEST(xt_no_buffers_is_einval) {
    xu_ep a, b; WSAMSG m; DWORD sent = 9; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len;
    xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), EINV); CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b);
}
