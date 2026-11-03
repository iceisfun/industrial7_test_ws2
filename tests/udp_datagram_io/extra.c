/* Additional UDP datagram checks found while reviewing the area: queue-size accounting,
 * receive on an unbound socket, send/recv buffer defaults, peek-then-consume pairing and
 * recv-flag acceptance. All traffic is loopback, all waits bounded. */
#include "ud.h"

TEST(udp_recv_on_unbound_socket_is_einval) {
    SOCKET s; char c; int r;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    CHECK(s != INVALID_SOCKET);
    ud_nonblock(s, 1);
    ud_seterr(0);
    r = U(recv)(s, &c, 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEINVAL);
    ud_close(s);
}

TEST(udp_nonblocking_empty_recv_is_ewouldblock) {
    ud_ep a; char c; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_nonblock(a.s, 1);
    ud_seterr(0);
    r = U(recv)(a.s, &c, 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEWOULDBLOCK);
    ud_free(&a);
}

TEST(udp_fionread_counts_all_queued_datagrams_and_drops_on_receive) {
    ud_ep a, b; u_long n = 0; char buf[32];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "aaa", 3) == 3);
    CHECK(ud_sendto(&a, &b, "bbbb", 4) == 4);
    CHECK(ud_sendto(&a, &b, "cc", 2) == 2);
    CHECK(ud_ready(b.s, 3000));
    Sleep(50);
    EXPECT_EQ(U(ioctlsocket)(b.s, FIONREAD, &n), 0); EXPECT_EQ(n, 9);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 3);
    EXPECT_EQ(U(ioctlsocket)(b.s, FIONREAD, &n), 0); EXPECT_EQ(n, 6);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, MSG_PEEK, NULL, NULL, 3000) == 4);
    EXPECT_EQ(U(ioctlsocket)(b.s, FIONREAD, &n), 0); EXPECT_EQ(n, 6);
    ud_drain(b.s, 100);
    EXPECT_EQ(U(ioctlsocket)(b.s, FIONREAD, &n), 0); EXPECT_EQ(n, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_peek_then_receive_returns_the_same_datagram) {
    ud_ep a, b; char p[16], r[16]; int n1, n2;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "first", 5) == 5);
    CHECK(ud_sendto(&a, &b, "second!", 7) == 7);
    n1 = ud_recv_to(b.s, p, sizeof p, MSG_PEEK, NULL, NULL, 3000);
    n2 = ud_recv_to(b.s, r, sizeof r, 0, NULL, NULL, 3000);
    EXPECT_EQ(n1, 5); EXPECT_EQ(n2, 5);
    CHECK(!memcmp(p, "first", 5) && !memcmp(r, "first", 5));
    n1 = ud_recv_to(b.s, r, sizeof r, 0, NULL, NULL, 3000);
    EXPECT_EQ(n1, 7);
    ud_free(&a); ud_free(&b);
}

TEST(udp_default_buffer_sizes_are_positive) {
    SOCKET s; int rc = 0, sn = 0;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    EXPECT_EQ(ud_getint(s, SOL_SOCKET, SO_RCVBUF, &rc), 0);
    EXPECT_EQ(ud_getint(s, SOL_SOCKET, SO_SNDBUF, &sn), 0);
    CHECK(rc > 0 && sn > 0);
    ud_close(s);
}

TEST(udp_so_type_is_dgram_and_not_listening) {
    SOCKET s; int t = 0;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    EXPECT_EQ(ud_getint(s, SOL_SOCKET, SO_TYPE, &t), 0);
    EXPECT_EQ(t, SOCK_DGRAM);
    ud_seterr(0);
    EXPECT_EQ(U(listen)(s, 1), SOCKET_ERROR);
    EXPECT_EQ(ud_err(), WSAEOPNOTSUPP);
    ud_close(s);
}

TEST(udp_wsarecvfrom_scatter_into_two_buffers) {
    ud_ep a, b; WSABUF w[2]; char x[3], y[8]; DWORD got = 0, fl = 0; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "abcdefg", 7) == 7);
    CHECK(ud_ready(b.s, 3000));
    w[0].buf = x; w[0].len = 3; w[1].buf = y; w[1].len = sizeof y;
    r = U(WSARecvFrom)(b.s, w, 2, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 7);
    CHECK(!memcmp(x, "abc", 3) && !memcmp(y, "defg", 4));
    ud_free(&a); ud_free(&b);
}

TEST(udp_recv_flag_0x20_is_accepted_note) {
    ud_ep a, b; char c; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    r = U(recv)(b.s, &c, 1, 0x20);
    t_note("recv with flag 0x20: r=%d", r);
    ud_free(&a); ud_free(&b);
}
