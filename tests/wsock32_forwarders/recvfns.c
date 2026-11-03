/* recv, recvfrom and WSARecvEx as the Winsock 1.1 layer exposes them.
 *
 * wsock32's recv and recvfrom are not forwarders: each builds a one-element buffer array and goes through
 * WSARecv / WSARecvFrom, returning -1 on failure; if the completed flags carry MSG_PARTIAL (0x8000) the
 * byte count is negated and the error is set to WSAEMSGSIZE. WSARecvEx (mswsock, reached through the
 * wsock32 forwarder) always clears the caller's flags word first, runs WSARecv, and when that fails with
 * WSAEMSGSIZE reports the bytes copied with MSG_PARTIAL set instead of failing.
 *
 * Measures: data delivery and partial reads, MSG_PEEK, orderly close, non-blocking and unconnected errors,
 * datagram truncation and the from-address contract for recvfrom, WSARecvEx flag handling, and the
 * not-initialised result. Equivalence with the ws2_32 recv/recvfrom is checked on twin socket pairs. */
#include "wf.h"

#define RCV_PARTIAL 0x8000

static int send_all(SOCKET s, const char *p, int n) { return W2(send)(s, p, n, 0) == n; }

/* ---------------------------------------------------------------- recv over TCP */
TEST(recv_delivers_sent_bytes) {
    p_recv r = WS(recv); SOCKET c, a; char b[16] = {0};
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "hello", 5));
    WEQ(r(a, b, sizeof b, 0), 5);
    CHECK(!memcmp(b, "hello", 5));
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recv_short_buffer_splits_stream) {
    p_recv r = WS(recv); SOCKET c, a; char b[16] = {0};
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "abcdefgh", 8));
    WEQ(r(a, b, 3, 0), 3);
    CHECK(!memcmp(b, "abc", 3));
    WEQ(r(a, b, 3, 0), 3);
    CHECK(!memcmp(b, "def", 3));
    WEQ(r(a, b, 16, 0), 2);
    CHECK(!memcmp(b, "gh", 2));
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recv_peek_does_not_consume) {
    p_recv r = WS(recv); SOCKET c, a; char b[16];
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "peek", 4));
    memset(b, 0, sizeof b);
    WEQ(r(a, b, 16, MSG_PEEK), 4);
    CHECK(!memcmp(b, "peek", 4));
    memset(b, 0, sizeof b);
    WEQ(r(a, b, 16, MSG_PEEK), 4);
    memset(b, 0, sizeof b);
    WEQ(r(a, b, 16, 0), 4);
    CHECK(!memcmp(b, "peek", 4));
    wf_nonblock(a, 1);
    wf_seterr(0);
    WEQ(r(a, b, 16, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recv_after_orderly_close_returns_zero) {
    p_recv r = WS(recv); SOCKET c, a; char b[8];
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "x", 1));
    W2(closesocket)(c);
    WEQ(r(a, b, sizeof b, 0), 1);
    WEQ(r(a, b, sizeof b, 0), 0);
    WEQ(r(a, b, sizeof b, 0), 0);          /* and it stays closed */
    W2(closesocket)(a);
    wf_down();
}
TEST(recv_after_peer_shutdown_send_returns_zero) {
    p_recv r = WS(recv); SOCKET c, a; char b[8];
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(W2(shutdown)(c, SD_SEND) == 0);
    WEQ(r(a, b, sizeof b, 0), 0);
    CHECK(send_all(a, "back", 4));               /* the other direction still works */
    WEQ(r(c, b, sizeof b, 0), 4);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recv_nonblocking_empty_would_block) {
    p_recv r = WS(recv); SOCKET c, a; char b[8];
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    wf_nonblock(a, 1);
    wf_seterr(0);
    WEQ(r(a, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recv_blocking_times_out_with_rcvtimeo) {
    p_recv r = WS(recv); SOCKET c, a; char b[8]; DWORD ms = 300;
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    W2(setsockopt)(a, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    wf_seterr(0);
    WEQ(r(a, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAETIMEDOUT);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recv_reset_connection_reports_connreset) {
    p_recv r = WS(recv); SOCKET c, a; char b[8]; struct linger l = { 1, 0 };
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    W2(setsockopt)(c, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l);
    W2(closesocket)(c);                          /* abortive close sends a reset */
    wf_seterr(0);
    WEQ(r(a, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAECONNRESET);
    W2(closesocket)(a);
    wf_down();
}
TEST(recv_large_transfer_arrives_in_order) {
    p_recv r = WS(recv); SOCKET c, a; static char out[20000], in[20000]; int got = 0, i;
    REQUIRE(r);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    for (i = 0; i < (int)sizeof out; i++) out[i] = (char)(i * 7 + (i >> 8));
    CHECK(send_all(c, out, sizeof out));
    while (got < (int)sizeof in) {
        int n = r(a, in + got, (int)sizeof in - got, 0);
        if (n <= 0) break;
        got += n;
    }
    WEQ(got, sizeof in);
    CHECK(!memcmp(in, out, sizeof in));
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}

/* ---------------------------------------------------------------- recv error results */
TEST(recv_unconnected_stream_is_notconn) {
    p_recv r = WS(recv); SOCKET s; char b[8];
    REQUIRE(r);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_nonblock(s, 1);
    wf_seterr(0);
    WEQ(r(s, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);
    W2(closesocket)(s);
    wf_down();
}
TEST(recv_on_listening_socket_is_notconn) {
    p_recv r = WS(recv); SOCKET s; struct sockaddr_in a = wf_lo(0); char b[8];
    REQUIRE(r);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(W2(bind)(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W2(listen)(s, 1) == 0);
    wf_nonblock(s, 1);
    wf_seterr(0);
    WEQ(r(s, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);
    W2(closesocket)(s);
    wf_down();
}
TEST(recv_on_unbound_datagram_socket_is_inval) {
    p_recv r = WS(recv); SOCKET s; char b[8];
    REQUIRE(r);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_nonblock(s, 1);
    wf_seterr(0);
    WEQ(r(s, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(s);
    wf_down();
}
TEST(recv_invalid_socket_is_notsock) {
    p_recv r = WS(recv); char b[8];
    REQUIRE(r);
    WF_UP();
    wf_seterr(0);
    WEQ(r(INVALID_SOCKET, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(recv_closed_socket_is_notsock) {
    p_recv r = WS(recv); SOCKET s; char b[8];
    REQUIRE(r);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    W2(closesocket)(s);
    wf_seterr(0);
    WEQ(r(s, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(recv_oob_without_oob_data_matches_ws2_32) {
    p_recv r1 = WS(recv), r2 = W2(recv); SOCKET c, a, c2, a2; char b[8]; int x, ex, y, ey;
    REQUIRE(r1); REQUIRE(r2);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL) || !wf_tcp_pair(&c2, &a2, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    wf_nonblock(a, 1); wf_nonblock(a2, 1);
    wf_seterr(0); x = r1(a, b, sizeof b, MSG_OOB); ex = wf_err();
    wf_seterr(0); y = r2(a2, b, sizeof b, MSG_OOB); ey = wf_err();
    WEQ(x, SOCKET_ERROR);
    WEQ(y, SOCKET_ERROR);
    WEQ(ex, ey);
    t_note("MSG_OOB with nothing pending -> %d", ex);
    W2(closesocket)(c); W2(closesocket)(a); W2(closesocket)(c2); W2(closesocket)(a2);
    wf_down();
}
TEST(recv_unknown_flag_bits_match_ws2_32) {
    p_recv r1 = WS(recv), r2 = W2(recv); SOCKET c, a, c2, a2; char b[8]; int x, ex, y, ey;
    static const int flags[] = { 0x4, 0x10, 0x20, 0x100, 0x4000 };
    unsigned i;
    REQUIRE(r1); REQUIRE(r2);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL) || !wf_tcp_pair(&c2, &a2, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    wf_nonblock(a, 1); wf_nonblock(a2, 1);
    for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        wf_seterr(0); x = r1(a, b, sizeof b, flags[i]); ex = wf_err();
        wf_seterr(0); y = r2(a2, b, sizeof b, flags[i]); ey = wf_err();
        CHECKF(x == y && ex == ey, "flags %#x: %d/%d vs %d/%d", flags[i], x, ex, y, ey);
    }
    W2(closesocket)(c); W2(closesocket)(a); W2(closesocket)(c2); W2(closesocket)(a2);
    wf_down();
}
TEST(recv_error_result_is_minus_one_not_other_negative) {
    p_recv r = WS(recv); char b[4];
    REQUIRE(r);
    WF_UP();
    WEQ(r(INVALID_SOCKET, b, sizeof b, 0), -1);
    wf_down();
}

/* ---------------------------------------------------------------- recv over UDP */
TEST(recv_datagram_boundaries_kept) {
    p_recv r = WS(recv); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[32];
    REQUIRE(r);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "one", 3, 0, (struct sockaddr *)&a2, sizeof a2) == 3);
    CHECK(W2(sendto)(u1, "second", 6, 0, (struct sockaddr *)&a2, sizeof a2) == 6);
    memset(b, 0, sizeof b);
    WEQ(r(u2, b, sizeof b, 0), 3);
    CHECK(!memcmp(b, "one", 3));
    WEQ(r(u2, b, sizeof b, 0), 6);
    CHECK(!memcmp(b, "second", 6));
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recv_datagram_truncated_fails_msgsize_and_copies_prefix) {
    p_recv r = WS(recv); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[8];
    REQUIRE(r);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "0123456789", 10, 0, (struct sockaddr *)&a2, sizeof a2) == 10);
    memset(b, 'z', sizeof b);
    wf_seterr(0);
    WEQ(r(u2, b, 4, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEMSGSIZE);
    CHECK(!memcmp(b, "0123", 4));
    WEQ(b[4], 'z');
    /* the excess of the datagram is discarded, not delivered by the next call */
    wf_nonblock(u2, 1);
    wf_seterr(0);
    WEQ(r(u2, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recv_datagram_peek_then_read) {
    p_recv r = WS(recv); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[16];
    REQUIRE(r);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "dgram", 5, 0, (struct sockaddr *)&a2, sizeof a2) == 5);
    memset(b, 0, sizeof b);
    WEQ(r(u2, b, sizeof b, MSG_PEEK), 5);
    WEQ(r(u2, b, sizeof b, 0), 5);
    wf_nonblock(u2, 1);
    wf_seterr(0);
    WEQ(r(u2, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recv_empty_datagram_returns_zero) {
    p_recv r = WS(recv); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[8];
    REQUIRE(r);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, b, 0, 0, (struct sockaddr *)&a2, sizeof a2) == 0);
    WEQ(r(u2, b, sizeof b, 0), 0);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recv_connected_udp_filters_other_senders) {
    p_recv r = WS(recv); SOCKET u1, u2, u3; struct sockaddr_in a1, a2, a3; char b[8];
    REQUIRE(r);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2); u3 = wf_udp(&a3);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET || u3 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(connect)(u2, (struct sockaddr *)&a1, sizeof a1) == 0);       /* u2 only accepts u1 */
    CHECK(W2(sendto)(u3, "bad", 3, 0, (struct sockaddr *)&a2, sizeof a2) == 3);
    CHECK(W2(sendto)(u1, "ok", 2, 0, (struct sockaddr *)&a2, sizeof a2) == 2);
    memset(b, 0, sizeof b);
    WEQ(r(u2, b, sizeof b, 0), 2);
    CHECK(!memcmp(b, "ok", 2));
    W2(closesocket)(u1); W2(closesocket)(u2); W2(closesocket)(u3);
    wf_down();
}

/* ---------------------------------------------------------------- recvfrom */
TEST(recvfrom_reports_sender_address) {
    p_recvfrom rf = WS(recvfrom); SOCKET u1, u2; struct sockaddr_in a1, a2, from; int fl = sizeof from; char b[16];
    REQUIRE(rf);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "from-me", 7, 0, (struct sockaddr *)&a2, sizeof a2) == 7);
    memset(&from, 0xEE, sizeof from);
    WEQ(rf(u2, b, sizeof b, 0, (struct sockaddr *)&from, &fl), 7);
    WEQ(fl, sizeof(struct sockaddr_in));
    WEQ(from.sin_family, AF_INET);
    WEQ(from.sin_port, a1.sin_port);
    WEQ(from.sin_addr.s_addr, a1.sin_addr.s_addr);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvfrom_null_from_is_allowed) {
    p_recvfrom rf = WS(recvfrom); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[16];
    REQUIRE(rf);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "anon", 4, 0, (struct sockaddr *)&a2, sizeof a2) == 4);
    WEQ(rf(u2, b, sizeof b, 0, NULL, NULL), 4);
    CHECK(!memcmp(b, "anon", 4));
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvfrom_truncation_fails_msgsize_with_address) {
    p_recvfrom rf = WS(recvfrom); SOCKET u1, u2; struct sockaddr_in a1, a2, from; int fl = sizeof from; char b[8];
    REQUIRE(rf);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "0123456789", 10, 0, (struct sockaddr *)&a2, sizeof a2) == 10);
    memset(b, 'z', sizeof b);
    memset(&from, 0, sizeof from);
    wf_seterr(0);
    WEQ(rf(u2, b, 4, 0, (struct sockaddr *)&from, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAEMSGSIZE);
    CHECK(!memcmp(b, "0123", 4));
    WEQ(from.sin_port, a1.sin_port);       /* the source is still reported for a truncated datagram */
    wf_nonblock(u2, 1);
    wf_seterr(0);
    WEQ(rf(u2, b, sizeof b, 0, NULL, NULL), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvfrom_small_fromlen_is_fault) {
    p_recvfrom rf = WS(recvfrom); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[16]; char tiny[4]; int fl = sizeof tiny;
    REQUIRE(rf);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "tiny", 4, 0, (struct sockaddr *)&a2, sizeof a2) == 4);
    wf_seterr(0);
    WEQ(rf(u2, b, sizeof b, 0, (struct sockaddr *)tiny, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    t_note("fromlen after the too-small call = %d", fl);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvfrom_nonblocking_empty_would_block) {
    p_recvfrom rf = WS(recvfrom); SOCKET u; struct sockaddr_in a, from; int fl = sizeof from; char b[8];
    REQUIRE(rf);
    WF_UP();
    u = wf_udp(&a);
    if (u == INVALID_SOCKET) { wf_down(); t_skip("udp socket"); return; }
    wf_nonblock(u, 1);
    wf_seterr(0);
    WEQ(rf(u, b, sizeof b, 0, (struct sockaddr *)&from, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(u);
    wf_down();
}
TEST(recvfrom_unbound_datagram_socket_is_inval) {
    p_recvfrom rf = WS(recvfrom); SOCKET s; struct sockaddr_in from; int fl = sizeof from; char b[8];
    REQUIRE(rf);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_nonblock(s, 1);
    wf_seterr(0);
    WEQ(rf(s, b, sizeof b, 0, (struct sockaddr *)&from, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(s);
    wf_down();
}
TEST(recvfrom_invalid_socket_is_notsock) {
    p_recvfrom rf = WS(recvfrom); char b[8];
    REQUIRE(rf);
    WF_UP();
    wf_seterr(0);
    WEQ(rf(INVALID_SOCKET, b, sizeof b, 0, NULL, NULL), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(recvfrom_on_tcp_returns_data_and_matches_ws2_32_peer_report) {
    p_recvfrom r1 = WS(recvfrom), r2 = W2(recvfrom); SOCKET c, a, c2, a2; char b[8], b2[8];
    struct sockaddr_in f1, f2; int l1 = sizeof f1, l2 = sizeof f2;
    REQUIRE(r1); REQUIRE(r2);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL) || !wf_tcp_pair(&c2, &a2, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "tcp", 3)); CHECK(send_all(c2, "tcp", 3));
    memset(&f1, 0, sizeof f1); memset(&f2, 0, sizeof f2);
    WEQ(r1(a, b, sizeof b, 0, (struct sockaddr *)&f1, &l1), 3);
    WEQ(r2(a2, b2, sizeof b2, 0, (struct sockaddr *)&f2, &l2), 3);
    WEQ(l1, l2);
    WEQ(f1.sin_family, f2.sin_family);
    t_note("recvfrom on a connected stream reports family %d length %d", f1.sin_family, l1);
    W2(closesocket)(c); W2(closesocket)(a); W2(closesocket)(c2); W2(closesocket)(a2);
    wf_down();
}
TEST(recvfrom_ipv6_sender_family) {
    p_recvfrom rf = WS(recvfrom); SOCKET u1, u2; struct sockaddr_in6 a1, a2, from; int n = sizeof a1, fl = sizeof from; char b[8];
    REQUIRE(rf);
    WF_UP();
    u1 = W2(socket)(AF_INET6, SOCK_DGRAM, 0); u2 = W2(socket)(AF_INET6, SOCK_DGRAM, 0);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("no IPv6"); return; }
    memset(&a1, 0, sizeof a1); a1.sin6_family = AF_INET6; a1.sin6_addr.s6_addr[15] = 1;
    a2 = a1;
    if (W2(bind)(u1, (struct sockaddr *)&a1, sizeof a1) || W2(bind)(u2, (struct sockaddr *)&a2, sizeof a2)) {
        W2(closesocket)(u1); W2(closesocket)(u2); wf_down(); t_skip("no IPv6 loopback"); return;
    }
    W2(getsockname)(u1, (struct sockaddr *)&a1, &n); n = sizeof a2; W2(getsockname)(u2, (struct sockaddr *)&a2, &n);
    wf_rcvtimeo(u2, 3000);
    CHECK(W2(sendto)(u1, "v6", 2, 0, (struct sockaddr *)&a2, sizeof a2) == 2);
    memset(&from, 0, sizeof from);
    WEQ(rf(u2, b, sizeof b, 0, (struct sockaddr *)&from, &fl), 2);
    WEQ(fl, sizeof from);
    WEQ(from.sin6_family, AF_INET6);
    WEQ(from.sin6_port, a1.sin6_port);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}

/* ---------------------------------------------------------------- WSARecvEx */
TEST(recvex_not_exported_by_ws2_32) {
    CHECK(t_proc_in("ws2_32.dll", "WSARecvEx") == NULL);
    CHECK(t_proc_in("wsock32.dll", "WSARecvEx") == t_proc_in("mswsock.dll", "WSARecvEx"));
}
TEST(recvex_delivers_and_clears_flags) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET c, a; char b[16] = {0}; int fl = 0x1234;
    REQUIRE(rx);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "recvex", 6));
    WEQ(rx(a, b, sizeof b, &fl), 6);
    CHECK(!memcmp(b, "recvex", 6));
    WEQ(fl, 0);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recvex_input_flags_are_ignored_peek_consumes) {
    /* the flags word is zeroed before the receive, so a MSG_PEEK passed in does not peek */
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET c, a; char b[16]; int fl = MSG_PEEK;
    REQUIRE(rx);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "once", 4));
    WEQ(rx(a, b, sizeof b, &fl), 4);
    WEQ(fl, 0);
    wf_nonblock(a, 1);
    wf_seterr(0);
    WEQ(W2(recv)(a, b, sizeof b, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recvex_oob_input_flag_is_ignored) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET c, a; char b[16]; int fl = MSG_OOB;
    REQUIRE(rx);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    CHECK(send_all(c, "normal", 6));
    Sleep(50);
    wf_nonblock(a, 1);                           /* keeps an emulation that honours the flag from blocking */
    WEQ(rx(a, b, sizeof b, &fl), 6);        /* ordinary data comes back although MSG_OOB was asked for */
    WEQ(fl, 0);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recvex_orderly_close_returns_zero_flags_clear) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET c, a; char b[8]; int fl = 0x55;
    REQUIRE(rx);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    W2(closesocket)(c);
    WEQ(rx(a, b, sizeof b, &fl), 0);
    WEQ(fl, 0);
    W2(closesocket)(a);
    wf_down();
}
TEST(recvex_truncated_datagram_reports_partial) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[8]; int fl = 0;
    REQUIRE(rx);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "0123456789", 10, 0, (struct sockaddr *)&a2, sizeof a2) == 10);
    memset(b, 'z', sizeof b);
    wf_seterr(0);
    WEQ(rx(u2, b, 4, &fl), 4);              /* bytes copied, not an error return */
    WEQ(fl, RCV_PARTIAL);
    CHECK(!memcmp(b, "0123", 4));
    WEQ(wf_err(), WSAEMSGSIZE);             /* the error value from the underlying call is left in place */
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvex_exact_fit_datagram_is_not_partial) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[8]; int fl = 0x77;
    REQUIRE(rx);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "abcd", 4, 0, (struct sockaddr *)&a2, sizeof a2) == 4);
    WEQ(rx(u2, b, 4, &fl), 4);
    WEQ(fl, 0);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvex_truncated_datagram_excess_is_discarded) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET u1, u2; struct sockaddr_in a1, a2; char b[8]; int fl = 0;
    REQUIRE(rx);
    WF_UP();
    u1 = wf_udp(&a1); u2 = wf_udp(&a2);
    if (u1 == INVALID_SOCKET || u2 == INVALID_SOCKET) { wf_down(); t_skip("udp sockets"); return; }
    CHECK(W2(sendto)(u1, "ABCDEFGH", 8, 0, (struct sockaddr *)&a2, sizeof a2) == 8);
    WEQ(rx(u2, b, 3, &fl), 3);
    wf_nonblock(u2, 1);
    fl = 0;
    wf_seterr(0);
    WEQ(rx(u2, b, sizeof b, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    WEQ(fl, 0);
    W2(closesocket)(u1); W2(closesocket)(u2);
    wf_down();
}
TEST(recvex_would_block_leaves_flags_zero) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET c, a; char b[8]; int fl = 0x4321;
    REQUIRE(rx);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("no loopback pair"); return; }
    wf_nonblock(a, 1);
    wf_seterr(0);
    WEQ(rx(a, b, sizeof b, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    WEQ(fl, 0);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(recvex_invalid_socket_is_notsock_flags_zero) {
    p_WSARecvEx rx = WS(WSARecvEx); char b[8]; int fl = 0x4321;
    REQUIRE(rx);
    WF_UP();
    wf_seterr(0);
    WEQ(rx(INVALID_SOCKET, b, sizeof b, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    WEQ(fl, 0);
    wf_down();
}
TEST(recvex_unconnected_stream_is_notconn) {
    p_WSARecvEx rx = WS(WSARecvEx); SOCKET s; char b[8]; int fl = 0;
    REQUIRE(rx);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_nonblock(s, 1);
    wf_seterr(0);
    WEQ(rx(s, b, sizeof b, &fl), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);
    W2(closesocket)(s);
    wf_down();
}
TEST(recvex_partial_flag_value_is_0x8000) {
    CHECK(MSG_PARTIAL == 0x8000);
    CHECK(RCV_PARTIAL == MSG_PARTIAL);
}

/* ---------------------------------------------------------------- not initialised */
CHILD(wf_recv_nostartup) {
    HMODULE m = LoadLibraryA("wsock32.dll");
    p_recv r; p_recvfrom rf; p_WSARecvEx rx; p_WSAGetLastError e; char b[8]; int fl = 0x99, fl2 = 0, which = argc > 1 ? atoi(argv[1]) : 0;
    struct sockaddr_in from; int fln = sizeof from;
    if (!m) return 1;
    r = (p_recv)GetProcAddress(m, "recv"); rf = (p_recvfrom)GetProcAddress(m, "recvfrom");
    rx = (p_WSARecvEx)GetProcAddress(m, "WSARecvEx"); e = (p_WSAGetLastError)GetProcAddress(m, "WSAGetLastError");
    if (!r || !rf || !rx || !e) return 2;
    (void)fl2;
    if (which == 0) { if (r(INVALID_SOCKET, b, sizeof b, 0) != SOCKET_ERROR) return 3; }
    if (which == 1) { if (rf(INVALID_SOCKET, b, sizeof b, 0, (struct sockaddr *)&from, &fln) != SOCKET_ERROR) return 3; }
    if (which == 2) { if (rx(INVALID_SOCKET, b, sizeof b, &fl) != SOCKET_ERROR) return 3; if (fl != 0) return 5; }
    return e() == WSANOTINITIALISED ? 0 : 4;
}
TEST(recv_without_startup_reports_notinitialised) { WF_RUN_CHILD("wf_recv_nostartup", "0"); }
TEST(recvfrom_without_startup_reports_notinitialised) { WF_RUN_CHILD("wf_recv_nostartup", "1"); }
TEST(recvex_without_startup_reports_notinitialised) { WF_RUN_CHILD("wf_recv_nostartup", "2"); }
