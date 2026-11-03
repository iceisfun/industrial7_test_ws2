/* Datagram boundaries on UDP loopback: zero-length datagrams, one-recv-per-send, ordering of a
 * ping-pong exchange, MSG_PEEK (including the address output and repeated peeks), the pending-size
 * ioctl, the recvfrom address-length protocol and the receive flag validation. Sizes are table driven.
 * Only relations and fixed values are checked; ports are OS chosen and never printed. */
#include "ud.h"

/* A datagram of N bytes is delivered as exactly one N-byte receive, for sizes around the usual
 * boundaries (0, 1, power-of-two edges, close to the single-datagram maximum used elsewhere). */
static const int k_sizes[] = { 0, 1, 2, 3, 7, 8, 15, 16, 17, 63, 64, 65, 127, 128, 255, 256, 511, 512, 513,
                               1023, 1024, 1025, 1399, 1400, 1472, 1473, 2047, 2048, 4095, 4096, 8191, 8192,
                               16383, 16384, 32767, 32768, 60000 };

TEST(udp_size_matrix_roundtrip_ipv4) {
    ud_ep a, b; unsigned i; static unsigned char tx[65536], rx[65536];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < sizeof k_sizes / sizeof *k_sizes; i++) {
        int n = k_sizes[i], r;
        ud_fill(tx, n, (int)i);
        memset(rx, 0xEE, sizeof rx);
        r = ud_sendto(&a, &b, tx, n);
        CHECKF(r == n, "size %d send gave %d err %d", n, r, ud_err());
        r = ud_recv_to(b.s, rx, sizeof rx, 0, NULL, NULL, 3000);
        CHECKF(r == n, "size %d recv gave %d err %d", n, r, ud_err());
        if (r == n) CHECKF(ud_same(rx, n, (int)i), "size %d payload mismatch", n);
        CHECKF(rx[n] == 0xEE, "size %d wrote past the datagram", n);
    }
    ud_free(&a); ud_free(&b);
}

TEST(udp_size_matrix_roundtrip_ipv6) {
    ud_ep a, b; unsigned i; static unsigned char tx[65536], rx[65536];
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    if (!ud_pair(&a, &b, AF_INET6)) return;
    for (i = 0; i < sizeof k_sizes / sizeof *k_sizes; i++) {
        int n = k_sizes[i], r;
        if (n > 32768) continue;
        ud_fill(tx, n, (int)i + 3);
        r = ud_sendto(&a, &b, tx, n);
        CHECKF(r == n, "size %d send gave %d err %d", n, r, ud_err());
        r = ud_recv_to(b.s, rx, sizeof rx, 0, NULL, NULL, 3000);
        CHECKF(r == n, "size %d recv gave %d err %d", n, r, ud_err());
        if (r == n) CHECKF(ud_same(rx, n, (int)i + 3), "size %d payload mismatch", n);
    }
    ud_free(&a); ud_free(&b);
}

/* ---- zero-length datagrams ---- */

TEST(udp_zero_length_send_returns_zero) {
    ud_ep a, b; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ud_seterr(0);
    r = ud_sendto(&a, &b, "", 0);
    EXPECT_EQ(r, 0);
    CHECK(ud_ready(b.s, 3000));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_send_null_buffer) {
    ud_ep a, b; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    r = U(sendto)(a.s, NULL, 0, 0, (struct sockaddr *)&b.sa, b.len);
    EXPECT_EQ(r, 0);
    CHECK(ud_ready(b.s, 3000));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_recv_returns_zero_with_sender) {
    ud_ep a, b; int r, fl; struct sockaddr_storage from; char tmp[8];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "", 0) == 0);
    memset(&from, 0, sizeof from); fl = sizeof from;
    r = ud_recv_to(b.s, tmp, sizeof tmp, 0, &from, &fl, 3000);
    EXPECT_EQ(r, 0);
    CHECK(ud_sameaddr(&a, &from, fl));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_datagram_with_zero_length_receive_buffer) {
    ud_ep a, b; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "", 0) == 0);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recvfrom)(b.s, NULL, 0, 0, NULL, NULL);
    t_note("recvfrom(NULL, 0) on an empty datagram: r=%d err=%d", r, r ? ud_err() : 0);
    if (r != 0) CHECK(ud_recv_to(b.s, &r, 0, 0, NULL, NULL, 3000) == 0);
    CHECK(!ud_ready(b.s, 200));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_datagram_is_counted_not_merged) {
    ud_ep a, b; int i, got = 0, r; char buf[8];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < 5; i++) CHECK(ud_sendto(&a, &b, "", 0) == 0);
    for (i = 0; i < 5; i++) {
        r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000);
        if (r == 0) got++;
    }
    EXPECT_EQ(got, 5);
    CHECK(!ud_ready(b.s, 200));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_between_data_datagrams_keeps_order) {
    ud_ep a, b; int r; char buf[16];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "one", 3) == 3);
    CHECK(ud_sendto(&a, &b, "", 0) == 0);
    CHECK(ud_sendto(&a, &b, "three", 5) == 5);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000); EXPECT_EQ(r, 3); CHECK(!memcmp(buf, "one", 3));
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000); EXPECT_EQ(r, 0);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000); EXPECT_EQ(r, 5); CHECK(!memcmp(buf, "three", 5));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_peek_leaves_datagram_queued) {
    ud_ep a, b; int r; char buf[4];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "", 0) == 0);
    r = ud_recv_to(b.s, buf, sizeof buf, MSG_PEEK, NULL, NULL, 3000); EXPECT_EQ(r, 0);
    r = ud_recv_to(b.s, buf, sizeof buf, MSG_PEEK, NULL, NULL, 3000); EXPECT_EQ(r, 0);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000);        EXPECT_EQ(r, 0);
    CHECK(!ud_ready(b.s, 200));
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_via_wsasendto_and_wsarecvfrom) {
    ud_ep a, b; WSABUF sb, rb; DWORD sent = 77, got = 77, fl = 0; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    sb.buf = (char *)""; sb.len = 0;
    r = U(WSASendTo)(a.s, &sb, 1, &sent, 0, (struct sockaddr *)&b.sa, b.len, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(sent, 0);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 0); EXPECT_EQ(fl, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_buffer_count_wsasendto_sends_empty_datagram) {
    ud_ep a, b; DWORD sent = 77; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    r = U(WSASendTo)(a.s, NULL, 0, &sent, 0, (struct sockaddr *)&b.sa, b.len, NULL, NULL);
    t_note("WSASendTo with zero buffers: r=%d sent=%lu err=%d", r, sent, r ? ud_err() : 0);
    if (r == 0) { EXPECT_EQ(sent, 0); CHECK(ud_ready(b.s, 3000)); }
    ud_free(&a); ud_free(&b);
}

/* ---- boundaries and ordering ---- */

TEST(udp_two_datagrams_never_coalesce) {
    ud_ep a, b; char buf[64]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "AAAA", 4) == 4);
    CHECK(ud_sendto(&a, &b, "BBBBBB", 6) == 6);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000); EXPECT_EQ(r, 4);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000); EXPECT_EQ(r, 6);
    CHECK(!memcmp(buf, "BBBBBB", 6));
    ud_free(&a); ud_free(&b);
}

TEST(udp_ordered_burst_arrives_in_order_on_loopback) {
    ud_ep a, b; int i, bad = 0, n = 0; unsigned char buf[8];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < 40; i++) { unsigned char p[4] = { (unsigned char)i, (unsigned char)~i, 1, 2 }; CHECK(ud_sendto(&a, &b, p, 4) == 4); }
    for (i = 0; i < 40; i++) {
        int r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000);
        if (r != 4) { bad++; break; }
        n++;
        if (buf[0] != (unsigned char)i || buf[1] != (unsigned char)~i) bad++;
    }
    EXPECT_EQ(n, 40); EXPECT_EQ(bad, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_ping_pong_keeps_request_reply_pairing) {
    ud_ep a, b; int i, bad = 0; char buf[16];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < 25; i++) {
        struct sockaddr_storage from; int fl = sizeof from, r;
        char msg[8]; msg[0] = 'q'; msg[1] = (char)('a' + i % 26);
        if (ud_sendto(&a, &b, msg, 2) != 2) { bad++; break; }
        r = ud_recv_to(b.s, buf, sizeof buf, 0, &from, &fl, 3000);
        if (r != 2 || buf[0] != 'q' || buf[1] != msg[1]) { bad++; break; }
        buf[0] = 'r';
        if (U(sendto)(b.s, buf, 2, 0, (struct sockaddr *)&from, fl) != 2) { bad++; break; }
        r = ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000);
        if (r != 2 || buf[0] != 'r' || buf[1] != msg[1]) { bad++; break; }
    }
    EXPECT_EQ(bad, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_reply_goes_to_the_sender_port_not_the_receiver) {
    ud_ep a, b, c; struct sockaddr_storage from; int fl = sizeof from; char buf[8];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(ud_sendto(&c, &b, "x", 1) == 1);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, &from, &fl, 3000) == 1);
    CHECK(ud_sameaddr(&c, &from, fl));
    CHECK(!ud_sameaddr(&a, &from, fl));
    CHECK(!ud_ready(a.s, 100));
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_send_to_self_delivers_on_same_socket) {
    ud_ep a; char buf[8]; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &a, "self", 4) == 4);
    r = ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 4);
    ud_free(&a);
}

TEST(udp_sender_from_address_matches_getsockname_ipv4) {
    ud_ep a, b; struct sockaddr_storage from; int fl = sizeof from; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "1", 1) == 1);
    CHECK(ud_recv_to(b.s, &c, 1, 0, &from, &fl, 3000) == 1);
    EXPECT_EQ(fl, sizeof(struct sockaddr_in));
    CHECK(ud_sameaddr(&a, &from, fl));
    ud_free(&a); ud_free(&b);
}

TEST(udp_sender_from_address_matches_getsockname_ipv6) {
    ud_ep a, b; struct sockaddr_storage from; int fl = sizeof from; char c;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    if (!ud_pair(&a, &b, AF_INET6)) return;
    CHECK(ud_sendto(&a, &b, "1", 1) == 1);
    CHECK(ud_recv_to(b.s, &c, 1, 0, &from, &fl, 3000) == 1);
    EXPECT_EQ(fl, sizeof(struct sockaddr_in6));
    CHECK(ud_sameaddr(&a, &from, fl));
    ud_free(&a); ud_free(&b);
}

TEST(udp_recv_without_address_still_consumes_datagram) {
    ud_ep a, b; char buf[8];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "ab", 2) == 2);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 2);
    CHECK(!ud_ready(b.s, 150));
    ud_free(&a); ud_free(&b);
}

/* ---- MSG_PEEK ---- */

TEST(udp_peek_returns_data_without_consuming) {
    ud_ep a, b; char p1[16] = {0}, p2[16] = {0}, g[16] = {0};
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "peekme", 6) == 6);
    CHECK(ud_recv_to(b.s, p1, sizeof p1, MSG_PEEK, NULL, NULL, 3000) == 6);
    CHECK(ud_recv_to(b.s, p2, sizeof p2, MSG_PEEK, NULL, NULL, 3000) == 6);
    CHECK(ud_recv_to(b.s, g, sizeof g, 0, NULL, NULL, 3000) == 6);
    CHECK(!memcmp(p1, "peekme", 6)); CHECK(!memcmp(p2, "peekme", 6)); CHECK(!memcmp(g, "peekme", 6));
    CHECK(!ud_ready(b.s, 150));
    ud_free(&a); ud_free(&b);
}

TEST(udp_peek_reports_sender_address) {
    ud_ep a, b; struct sockaddr_storage f1, f2; int l1 = sizeof f1, l2 = sizeof f2; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "z", 1) == 1);
    CHECK(ud_recv_to(b.s, &c, 1, MSG_PEEK, &f1, &l1, 3000) == 1);
    CHECK(ud_sameaddr(&a, &f1, l1));
    CHECK(ud_recv_to(b.s, &c, 1, 0, &f2, &l2, 3000) == 1);
    CHECK(ud_sameaddr(&a, &f2, l2));
    ud_free(&a); ud_free(&b);
}

TEST(udp_peek_sees_first_datagram_only) {
    ud_ep a, b; char buf[16];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "first", 5) == 5);
    CHECK(ud_sendto(&a, &b, "second!", 7) == 7);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, MSG_PEEK, NULL, NULL, 3000) == 5);
    CHECK(!memcmp(buf, "first", 5));
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 5);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, MSG_PEEK, NULL, NULL, 3000) == 7);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 7);
    ud_free(&a); ud_free(&b);
}

TEST(udp_peek_on_empty_nonblocking_socket_would_block) {
    ud_ep a; char buf[4]; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_nonblock(a.s, 1);
    ud_seterr(0);
    r = U(recv)(a.s, buf, sizeof buf, MSG_PEEK);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEWOULDBLOCK);
    ud_free(&a);
}

TEST(udp_nonblocking_recv_on_empty_socket_would_block) {
    ud_ep a; char buf[4]; int r, i;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_nonblock(a.s, 1);
    for (i = 0; i < 3; i++) {
        ud_seterr(0);
        r = U(recvfrom)(a.s, buf, sizeof buf, 0, NULL, NULL);
        EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEWOULDBLOCK);
    }
    ud_free(&a);
}

TEST(udp_wsarecvfrom_flags_are_zero_after_plain_receive) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0xdeadbeef; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "abc", 3) == 3);
    CHECK(ud_ready(b.s, 3000));
    fl = 0; rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 3); EXPECT_EQ(fl, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_peek_flag_in_is_not_echoed_back) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = MSG_PEEK; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "abc", 3) == 3);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 3);
    t_note("flags after a peeking WSARecvFrom: 0x%lx", fl);
    CHECK(ud_ready(b.s, 1000));
    ud_free(&a); ud_free(&b);
}

/* ---- receive flag validation (MSG_OOB is meaningless for datagrams) ---- */

TEST(udp_recv_msg_oob_is_rejected) {
    ud_ep a, b; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recv)(b.s, buf, sizeof buf, MSG_OOB);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEOPNOTSUPP);
    /* the datagram survives the rejected call */
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_recvfrom_unknown_flag_bits_are_rejected) {
    static const int flags[] = { 0x4, 0x8, 0x10, 0x40, 0x100, 0x1000, 0x20000, 0x40000000 };
    ud_ep a, b; char buf[8]; unsigned i;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < sizeof flags / sizeof *flags; i++) {
        int r;
        CHECK(ud_sendto(&a, &b, "x", 1) == 1);
        CHECK(ud_ready(b.s, 3000));
        ud_seterr(0);
        r = U(recv)(b.s, buf, sizeof buf, flags[i]);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEOPNOTSUPP, "flag 0x%x gave r=%d err=%d", flags[i], r, ud_err());
        if (r == SOCKET_ERROR) CHECKF(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 1, "flag 0x%x lost the datagram", flags[i]);
    }
    ud_free(&a); ud_free(&b);
}

/* ---- recvfrom address length protocol ---- */

TEST(udp_recvfrom_address_without_length_is_efault) {
    ud_ep a, b; struct sockaddr_storage from; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recvfrom)(b.s, buf, sizeof buf, 0, (struct sockaddr *)&from, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    CHECK(ud_ready(b.s, 1000));                        /* still queued */
    ud_free(&a); ud_free(&b);
}

TEST(udp_recvfrom_address_with_zero_length_is_efault) {
    ud_ep a, b; struct sockaddr_storage from; char buf[8]; int r, fl = 0;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recvfrom)(b.s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    EXPECT_EQ(fl, 0);
    CHECK(ud_ready(b.s, 1000));
    ud_free(&a); ud_free(&b);
}

TEST(udp_recvfrom_every_short_length_is_efault_and_keeps_datagram) {
    ud_ep a, b; char buf[8]; int len;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    for (len = 1; len < (int)sizeof(struct sockaddr_in); len++) {
        struct sockaddr_storage from; int fl = len, r;
        memset(&from, 0x5a, sizeof from);
        if (!ud_ready(b.s, 300)) { t_note("datagram consumed by a short-length receive (len %d)", len); break; }
        ud_seterr(0);
        r = U(recvfrom)(b.s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEFAULT, "len %d gave r=%d err=%d", len, r, ud_err());
        CHECKF(((unsigned char *)&from)[0] == 0x5a, "len %d wrote the address", len);
    }
    if (ud_ready(b.s, 300)) CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_recvfrom_exact_length_succeeds_and_reports_it) {
    ud_ep a, b; struct sockaddr_in from; char buf[8]; int fl = sizeof from, r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, &from, &fl, 3000);
    EXPECT_EQ(r, 1); EXPECT_EQ(fl, sizeof from);
    EXPECT_EQ(from.sin_family, AF_INET);
    ud_free(&a); ud_free(&b);
}

TEST(udp_recvfrom_v6_short_length_is_efault) {
    ud_ep a, b; struct sockaddr_in6 from; char buf[8]; int fl = sizeof(struct sockaddr_in), r;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    if (!ud_pair(&a, &b, AF_INET6)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recvfrom)(b.s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    fl = sizeof from;
    r = ud_recv_to(b.s, buf, sizeof buf, 0, &from, &fl, 1000);
    t_note("datagram after the rejected short-length v6 receive: r=%d", r);
    if (r == 1) EXPECT_EQ(fl, sizeof from);
    ud_free(&a); ud_free(&b);
}

TEST(udp_recvfrom_null_address_with_length_is_not_dereferenced_note) {
    ud_ep a, b; char buf[8]; int fl = 16, r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recvfrom)(b.s, buf, sizeof buf, 0, NULL, &fl);
    t_note("recvfrom(from=NULL, fromlen=&16): r=%d err=%d", r, r < 0 ? ud_err() : 0);
    if (r < 0) CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

/* ---- pending-size ioctl ---- */

TEST(udp_fionread_zero_when_empty) {
    ud_ep a; u_long n = 0xdeadbeef;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    EXPECT_EQ(U(ioctlsocket)(a.s, FIONREAD, &n), 0);
    EXPECT_EQ(n, 0);
    ud_free(&a);
}

TEST(udp_fionread_reports_total_queued_bytes) {
    ud_ep a, b; u_long n = 0; char buf[64];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "12345", 5) == 5);
    CHECK(ud_sendto(&a, &b, "1234567890", 10) == 10);
    CHECK(ud_ready(b.s, 3000));
    Sleep(50);
    EXPECT_EQ(U(ioctlsocket)(b.s, FIONREAD, &n), 0);
    EXPECT_EQ(n, 15);                 /* all queued bytes, not just the first datagram */
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 5);
    n = 0;
    EXPECT_EQ(U(ioctlsocket)(b.s, FIONREAD, &n), 0);
    EXPECT_EQ(n, 10);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 10);
    ud_free(&a); ud_free(&b);
}

TEST(udp_fionread_does_not_consume) {
    ud_ep a, b; u_long n = 0, m = 0; char buf[16];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "abcdef", 6) == 6);
    CHECK(ud_ready(b.s, 3000));
    U(ioctlsocket)(b.s, FIONREAD, &n);
    U(ioctlsocket)(b.s, FIONREAD, &m);
    EXPECT_EQ(n, m);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 6);
    ud_free(&a); ud_free(&b);
}

TEST(udp_fionread_null_argument_is_efault_note) {
    ud_ep a; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_seterr(0);
    r = U(ioctlsocket)(a.s, FIONREAD, NULL);
    t_note("ioctlsocket(FIONREAD, NULL): r=%d err=%d", r, r ? ud_err() : 0);
    ud_free(&a);
}

TEST(udp_select_readable_only_while_datagram_queued) {
    ud_ep a, b; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(!ud_ready(b.s, 50));
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    CHECK(ud_ready(b.s, 0));
    CHECK(ud_recv_to(b.s, &c, 1, 0, NULL, NULL, 3000) == 1);
    CHECK(!ud_ready(b.s, 50));
    ud_free(&a); ud_free(&b);
}

TEST(udp_select_writable_immediately) {
    ud_ep a; fd_set w; TIMEVAL tv = { 0, 0 };
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    w.fd_count = 1; w.fd_array[0] = a.s;
    EXPECT_EQ(U(select)(0, NULL, &w, NULL, &tv), 1);
    ud_free(&a);
}

TEST(udp_recv_blocks_until_data_with_rcvtimeo) {
    ud_ep a; char c; int r; DWORD t = 300;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(U(setsockopt)(a.s, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t) == 0);
    ud_seterr(0);
    r = U(recv)(a.s, &c, 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAETIMEDOUT);
    ud_free(&a);
}

TEST(udp_late_datagram_wakes_blocked_receiver) {
    ud_ep a, b; char c; int r; DWORD t = 4000;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(setsockopt)(b.s, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t) == 0);
    /* the datagram is already queued when recv runs; the receive must not block for the timeout */
    CHECK(ud_sendto(&a, &b, "w", 1) == 1);
    r = U(recv)(b.s, &c, 1, 0);
    EXPECT_EQ(r, 1);
    ud_free(&a); ud_free(&b);
}
