/* UDP send segmentation (UDP_SEND_MSG_SIZE, as socket option and as a per-send control message) and the receive
 * side coalescing option (UDP_RECV_MAX_COALESCED_SIZE / UDP_COALESCED_INFO) on loopback. A segmentation size makes
 * one send call produce several datagrams of at most that size; the receiver sees ordinary separate datagrams.
 * Loopback has no receive offload, so the coalescing option is accepted but datagrams are never merged and no
 * coalesced-info message is produced. All sockets are loopback with OS-chosen ports. */
#include "xu.h"

static xu_rx RX;
static unsigned char SRC[70000];

static int open_pair(xu_ep *a, xu_ep *b, int af) {
    if (af == AF_INET6 && !xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return 0; }
    if (!xu_pair(a, b, af)) return 0;
    xu_setint(b->s, SOL_SOCKET, SO_RCVBUF, 4 << 20);       /* room for a couple of thousand tiny datagrams */
    xu_fill(SRC, sizeof SRC, 11);
    return 1;
}
/* Receive everything that arrives within a short quiet period; checks that the concatenation equals the first
 * `total` bytes of SRC. Returns the number of datagrams, fills sizes (first 8) and *last. */
static int collect(xu_ep *b, int total, int *first, int *last, int *intact) {
    static unsigned char buf[70000]; int cnt = 0; long got = 0; *last = 0; *intact = 1;
    while (xu_ready(b->s, 300)) {
        int rr = U(recvfrom)(b->s, (char *)buf, sizeof buf, 0, NULL, NULL);
        if (rr < 0) { *intact = 0; break; }
        if (got + rr > total || memcmp(buf, SRC + got, rr)) *intact = 0;
        if (cnt < 8) first[cnt] = rr;
        *last = rr; got += rr; cnt++;
        if (cnt > 20000) break;
    }
    if (got != total) *intact = 0;
    return cnt;
}
static int expect_count(int seg, int total) { return total == 0 ? 1 : (total + seg - 1) / seg; }

/* ---- socket option ---- */
static void seg_table(int af) {
    static const int SEG[] = {1, 10, 100, 1000, 1472, 65000};
    static const int TOT[] = {0, 1, 99, 100, 101, 450, 3000};
    size_t i, k;
    for (i = 0; i < sizeof SEG / sizeof SEG[0]; i++) for (k = 0; k < sizeof TOT / sizeof TOT[0]; k++) {
        xu_ep a, b; DWORD sent = 0; int first[8] = {0}, last, intact, cnt, want, r, j;
        if (!open_pair(&a, &b, af)) return;
        CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, SEG[i]) == 0);
        r = xu_send(a.s, &b, SRC, TOT[k], NULL, 0, 0, &sent);
        CHECKF(r == 0 && sent == (DWORD)TOT[k], "seg %d total %d: r=%d sent=%lu", SEG[i], TOT[k], r, (unsigned long)sent);
        cnt = collect(&b, TOT[k], first, &last, &intact);
        want = expect_count(SEG[i], TOT[k]);
        CHECKF(cnt == want, "seg %d total %d: %d datagrams want %d", SEG[i], TOT[k], cnt, want);
        CHECKF(intact, "seg %d total %d: payload not intact", SEG[i], TOT[k]);
        for (j = 0; j < cnt && j < 8 && j < want - 1; j++) CHECKF(first[j] == SEG[i] || TOT[k] == 0, "seg %d total %d: datagram %d has %d bytes", SEG[i], TOT[k], j, first[j]);
        if (TOT[k] > 0) CHECKF(last == TOT[k] - SEG[i] * (want - 1), "seg %d total %d: last datagram %d", SEG[i], TOT[k], last);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xg_option_segments_loopback_v4) { UP(); seg_table(AF_INET); }
TEST(xg_option_segments_loopback_v6) { UP6(); seg_table(AF_INET6); }

TEST(xg_option_large_segment_count) {
    xu_ep a, b; DWORD sent; int first[8] = {0}, last, intact, cnt, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 10) == 0);
    r = xu_send(a.s, &b, SRC, 10000, NULL, 0, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 10000);
    cnt = collect(&b, 10000, first, &last, &intact); EXPECT_EQ(cnt, 1000); CHECK(intact); EXPECT_EQ(last, 10);
    xu_free(&a); xu_free(&b);
}
TEST(xg_option_one_byte_segments) {
    xu_ep a, b; DWORD sent; int first[8] = {0}, last, intact, cnt, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 1) == 0);
    r = xu_send(a.s, &b, SRC, 450, NULL, 0, 0, &sent); EXPECT_EQ(r, 0);
    cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 450); CHECK(intact);
    xu_free(&a); xu_free(&b);
}
/* sizes at or above the maximum datagram payload are refused when sending (the option itself was accepted) */
TEST(xg_option_too_large_is_refused_at_send) {
    static const int V[] = {65534, 65535, 65536, 100000, -1};
    size_t i; UP();
    for (i = 0; i < sizeof V / sizeof V[0]; i++) {
        xu_ep a, b; DWORD sent = 7; int r, cnt, first[8] = {0}, last, intact;
        if (!open_pair(&a, &b, AF_INET)) return;
        CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, V[i]) == 0);
        xu_seterr(0); r = U(sendto)(a.s, (char *)SRC, 450, 0, (struct sockaddr *)&b.sa, b.len);
        CHECKF(r == SOCKET_ERROR && xu_err() == WSAEINVAL, "sendto with size %d: r=%d err=%d", V[i], r, xu_err());
        xu_seterr(0); r = xu_send(a.s, &b, SRC, 450, NULL, 0, 0, &sent);
        CHECKF(r == SOCKET_ERROR && xu_err() == WSAEINVAL, "WSASendMsg with size %d: r=%d err=%d", V[i], r, xu_err());
        cnt = collect(&b, 0, first, &last, &intact); EXPECT_EQ(cnt, 0);
        CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 0) == 0);
        CHECK(U(sendto)(a.s, (char *)SRC, 450, 0, (struct sockaddr *)&b.sa, b.len) == 450);
        cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 1);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xg_option_zero_turns_segmentation_off_again) {
    xu_ep a, b; int first[8] = {0}, last, intact, cnt; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 100) == 0);
    CHECK(U(sendto)(a.s, (char *)SRC, 450, 0, (struct sockaddr *)&b.sa, b.len) == 450); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 5);
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 0) == 0);
    CHECK(U(sendto)(a.s, (char *)SRC, 450, 0, (struct sockaddr *)&b.sa, b.len) == 450); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 1); CHECK(intact);
    xu_free(&a); xu_free(&b);
}
/* the option is read from the sending socket only */
TEST(xg_option_belongs_to_the_sender) {
    xu_ep a, b; int first[8] = {0}, last, intact, cnt; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 100) == 0);
    CHECK(U(sendto)(a.s, (char *)SRC, 450, 0, (struct sockaddr *)&b.sa, b.len) == 450); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 1); CHECK(intact);
    xu_free(&a); xu_free(&b);
}
/* gather list: the buffers are joined before they are cut (a zero-length buffer in the middle is harmless) */
TEST(xg_option_applies_to_gathered_buffers) {
    xu_ep a, b; WSAMSG m; WSABUF bf[3]; DWORD sent = 0; int first[8] = {0}, last, intact, cnt, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 100) == 0);
    memset(&m, 0, sizeof m); bf[0].buf = (CHAR *)SRC; bf[0].len = 150; bf[1].buf = (CHAR *)SRC + 150; bf[1].len = 0; bf[2].buf = (CHAR *)SRC + 150; bf[2].len = 120;
    m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len; m.lpBuffers = bf; m.dwBufferCount = 3;
    r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 270);
    cnt = collect(&b, 270, first, &last, &intact); EXPECT_EQ(cnt, 3); CHECK(intact); EXPECT_EQ(first[0], 100); EXPECT_EQ(first[1], 100); EXPECT_EQ(last, 70);
    xu_free(&a); xu_free(&b);
}
/* connected sockets: send, WSASend and the unconnected send() failure */
TEST(xg_option_with_connected_socket) {
    xu_ep a, b; WSABUF bf; DWORD s2 = 0; int first[8] = {0}, last, intact, cnt, r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 100) == 0);
    xu_seterr(0); r = U(send)(a.s, (char *)SRC, 10, 0); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAENOTCONN);
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    r = U(send)(a.s, (char *)SRC, 450, 0); EXPECT_EQ(r, 450); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 5); CHECK(intact);
    bf.buf = (CHAR *)SRC; bf.len = 450; r = U(WSASend)(a.s, &bf, 1, &s2, 0, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(s2, 450);
    cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 5); CHECK(intact);
    xu_free(&a); xu_free(&b);
}
/* each segment is a datagram of its own for the receiver: a small receive buffer truncates exactly one of them */
TEST(xg_segments_are_independent_datagrams) {
    xu_ep a, b; DWORD sent; int i; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 100) == 0);
    CHECK(xu_send(a.s, &b, SRC, 250, NULL, 0, 0, &sent) == 0);
    for (i = 0; i < 3; i++) {
        xu_recvw(b.s, &RX, 60, 0, 1, 0);
        if (i < 2) { EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEMSGSIZE); EXPECT_EQ(RX.got, 60); EXPECT_EQ(RX.flags, XU_MSG_TRUNC); }
        else { EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 50); EXPECT_EQ(RX.flags, 0); }
    }
    CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b);
}

/* ---- per-send control message ---- */
static int send_seg_msg(xu_ep *a, xu_ep *b, const void *val, size_t vlen, int total, int *err) {
    unsigned char c[64]; size_t off = xu_cmsg_put(c, 0, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, val, vlen); DWORD sent = 0;
    int r = xu_send(a->s, b, SRC, total, c, (ULONG)off, 0, &sent);
    *err = r ? xu_err() : 0;
    return r;
}
static void cmsg_table(int af) {
    static const struct { int v, dgrams, err; } T[] = {
        {0, 1, 0}, {1, 450, 0}, {100, 5, 0}, {450, 1, 0}, {1472, 1, 0}, {65534, 0, WSAEINVAL}, {65535, 0, WSAEINVAL},
    };
    size_t i; DWORD sentinel;
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        xu_ep a, b; int err, first[8] = {0}, last, intact, cnt, r;
        if (!open_pair(&a, &b, af)) return;
        sentinel = (DWORD)T[i].v;
        r = send_seg_msg(&a, &b, &sentinel, 4, 450, &err);
        CHECKF(err == T[i].err, "segment message %d: error %d want %d", T[i].v, err, T[i].err);
        CHECK((r == 0) == (T[i].err == 0));
        cnt = collect(&b, T[i].err ? 0 : 450, first, &last, &intact);
        CHECKF(cnt == T[i].dgrams, "segment message %d: %d datagrams want %d", T[i].v, cnt, T[i].dgrams);
        if (!T[i].err) CHECK(intact);
        xu_free(&a); xu_free(&b);
    }
}
TEST(xg_message_values_v4) { UP(); cmsg_table(AF_INET); }
TEST(xg_message_values_v6) { UP6(); cmsg_table(AF_INET6); }
/* the data of the message must be a 32-bit value: 1, 2 byte values are refused */
TEST(xg_message_data_size_must_be_four) {
    xu_ep a, b; int err; DWORD v = 100; WORD w = 100; BYTE y = 100; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    send_seg_msg(&a, &b, &y, 1, 450, &err); EXPECT_EQ(err, WSAEINVAL);
    send_seg_msg(&a, &b, &w, 2, 450, &err); EXPECT_EQ(err, WSAEINVAL);
    send_seg_msg(&a, &b, &v, 4, 450, &err); EXPECT_EQ(err, 0);
    xu_drain(b.s, 200);
    xu_free(&a); xu_free(&b);
}
/* message beats the option for that send only */
TEST(xg_message_overrides_option_for_one_send) {
    xu_ep a, b; int err, first[8] = {0}, last, intact, cnt, v = -1; DWORD m = 0; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 200) == 0);
    send_seg_msg(&a, &b, &m, 4, 450, &err); EXPECT_EQ(err, 0); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 1);
    CHECK(U(sendto)(a.s, (char *)SRC, 450, 0, (struct sockaddr *)&b.sa, b.len) == 450); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 3);
    CHECK(xu_getint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, &v) == 0); EXPECT_EQ(v, 200);
    m = 1; send_seg_msg(&a, &b, &m, 4, 450, &err); EXPECT_EQ(err, 0); cnt = collect(&b, 450, first, &last, &intact); EXPECT_EQ(cnt, 450);
    xu_free(&a); xu_free(&b);
}
/* the segment message and a hop limit message in one buffer: all the segments carry the hop limit */
TEST(xg_message_combined_with_hoplimit_message) {
    xu_ep a, b; unsigned char c[64]; size_t off; DWORD sent, seg = 100; int ttl = 33, i, r; const unsigned char *p; size_t n; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, IPPROTO_IP, XU_IP_RECVTTL, 1) == 0);
    off = xu_cmsg_put(c, 0, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, &seg, 4); off = xu_cmsg_put(c, off, IPPROTO_IP, 21, &ttl, 4);
    r = xu_send(a.s, &b, SRC, 250, c, (ULONG)off, 0, &sent); EXPECT_EQ(r, 0);
    for (i = 0; i < 3; i++) {
        xu_recvw(b.s, &RX, 200, 128, 1, 0); EXPECT_EQ(RX.r, 0);
        p = xu_cmsg_find(RX.ctl, RX.ctllen, IPPROTO_IP, 4, &n); CHECK(p && n == 4 && *(const int *)p == 33);
    }
    xu_free(&a); xu_free(&b);
}

/* ---- receive coalescing ---- */
TEST(xg_coalescing_option_does_not_merge_on_loopback) {
    xu_ep a, b; int i; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, IPPROTO_UDP, XU_UDP_RECV_MAX_COALESCED_SIZE, 65000) == 0);
    for (i = 0; i < 5; i++) CHECK(U(sendto)(a.s, (char *)SRC, 100 + i, 0, (struct sockaddr *)&b.sa, b.len) == 100 + i);
    for (i = 0; i < 5; i++) {
        xu_recvw(b.s, &RX, 65000, 128, 1, 0);
        CHECKF(RX.r == 0 && RX.got == (DWORD)(100 + i) && RX.flags == 0 && RX.ctllen == 0, "datagram %d: r=%d got=%lu ctl=%lu", i, RX.r, (unsigned long)RX.got, (unsigned long)RX.ctllen);
        CHECK(xu_cmsg_find(RX.ctl, RX.ctllen, IPPROTO_UDP, XU_UDP_COALESCED_INFO, NULL) == NULL);
    }
    xu_free(&a); xu_free(&b);
}
TEST(xg_coalescing_with_segmented_sender) {
    xu_ep a, b; int i; DWORD sent; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, IPPROTO_UDP, XU_UDP_RECV_MAX_COALESCED_SIZE, 65000) == 0);
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 200) == 0);
    CHECK(xu_send(a.s, &b, SRC, 1000, NULL, 0, 0, &sent) == 0);
    for (i = 0; i < 5; i++) {
        xu_recvw(b.s, &RX, 65000, 128, 1, 0);
        CHECKF(RX.r == 0 && RX.got == 200 && RX.ctllen == 0, "segment %d: r=%d got=%lu ctl=%lu", i, RX.r, (unsigned long)RX.got, (unsigned long)RX.ctllen);
    }
    CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b);
}
