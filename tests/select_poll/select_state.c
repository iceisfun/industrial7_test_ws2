/* select(): what each socket state reports in the read, write and except sets. Stream pairs (data,
 * partial reads, FIN, RST, out-of-band), listeners (pending connections, backlog drain), non-blocking
 * connect, datagram sockets (queued datagrams, truncation, ICMP-driven errors) and wake-up of a blocked
 * select from another thread. Many cases run once per address family.
 *
 * Mapping used by the stack (read set: data, FIN, RST, pending accept; write set: send possible;
 * except set: out-of-band data or a failed connect) is stated per test where it matters.
 */
#include "sp.h"

/* ---------------------------------------------------------------- fresh pair */
FAMILY_TEST(sp_sel_pair_initially_writable_only)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_readable(a, 0), 0);
    SPEQ(sp_readable(b, 0), 0);
    SPEQ(sp_writable(a, 100), 1);
    SPEQ(sp_writable(b, 100), 1);
    SPEQ(sp_excepted(a, 0), 0);
    SPEQ(sp_excepted(b, 0), 0);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_data_makes_peer_readable)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "hello", 5, 0), 5);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_readable(b, 0), 1);
    SPEQ(sp_readable(a, 0), 0);       /* the sender itself has nothing to read */
    SPEQ(sp_excepted(b, 0), 0);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_readability_is_level_triggered)
{
    SOCKET a, b;
    int i;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "abc", 3, 0), 3);
    CHECK(sp_wait_readable(b));
    for (i = 0; i < 5; i++) SPEQ(sp_readable(b, 0), 1);   /* nothing consumes it */
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_partial_read_keeps_socket_readable)
{
    SOCKET a, b;
    char buf[8];
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "0123456789", 10, 0), 10);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_recv(b, buf, 4, 0), 4);
    SPEQ(sp_readable(b, 0), 1);
    SPEQ(sp_recv(b, buf, 6, 0), 6);
    SPEQ(sp_readable(b, 0), 0);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_peek_does_not_clear_readability)
{
    SOCKET a, b;
    char c;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "Q", 1, 0), 1);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_recv(b, &c, 1, MSG_PEEK), 1);
    SPEQ(c, 'Q');
    SPEQ(sp_readable(b, 0), 1);
    SPEQ(sp_recv(b, &c, 1, 0), 1);
    SPEQ(sp_readable(b, 0), 0);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_writability_returns_after_drain_both_directions)
{
    SOCKET a, b;
    char c;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "1", 1, 0), 1);
    SPEQ(sp_send(b, "2", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    CHECK(sp_wait_readable(b));
    SPEQ(sp_writable(a, 0), 1);
    SPEQ(sp_writable(b, 0), 1);
    SPEQ(sp_recv(a, &c, 1, 0), 1);
    SPEQ(sp_recv(b, &c, 1, 0), 1);
    SPEQ(sp_readable(a, 0), 0);
    SPEQ(sp_readable(b, 0), 0);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- orderly close */
FAMILY_TEST(sp_sel_peer_close_is_readable_and_recv_returns_zero)
{
    SOCKET a, b;
    char c;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    sp_close(a);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_recv(b, &c, 1, 0), 0);
    sp_close(b);
}
FAMILY_TEST(sp_sel_eof_stays_readable_after_recv_reports_it)
{
    SOCKET a, b;
    char c;
    int i;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    sp_close(a);
    CHECK(sp_wait_readable(b));
    for (i = 0; i < 3; i++) {
        SPEQ(sp_recv(b, &c, 1, 0), 0);
        SPEQ(sp_readable(b, 0), 1);
    }
    sp_close(b);
}
FAMILY_TEST(sp_sel_eof_is_not_an_except_condition)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    sp_close(a);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_excepted(b, 0), 0);
    sp_close(b);
}
FAMILY_TEST(sp_sel_data_then_fin_reads_data_before_eof)
{
    SOCKET a, b;
    char buf[8];
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "tail", 4, 0), 4);
    SPEQ(U(shutdown)(a, SD_SEND), 0);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_recv(b, buf, sizeof buf, 0), 4);
    SPEQ(sp_readable(b, 0), 1);       /* now the EOF is what is pending */
    SPEQ(sp_recv(b, buf, sizeof buf, 0), 0);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_local_shutdown_send_keeps_socket_writable)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(U(shutdown)(a, SD_SEND), 0);
    SPEQ(sp_writable(a, 100), 1);
    SPEQ(sp_readable(a, 0), 0);
    CHECK(sp_wait_readable(b));       /* the peer sees the FIN */
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_sel_peer_shutdown_send_leaves_us_writable)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(U(shutdown)(a, SD_SEND), 0);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_writable(b, 100), 1);     /* half-close: b may still send */
    SPEQ(sp_send(b, "back", 4, 0), 4);
    CHECK(sp_wait_readable(a));
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- abortive close */
FAMILY_TEST(sp_sel_reset_by_peer_is_readable_and_recv_fails_connreset)
{
    SOCKET a, b;
    char c;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    sp_linger0(a);
    sp_close(a);                       /* RST instead of FIN */
    CHECK(sp_wait_readable(b));
    sp_seterr(0);
    SPEQ(sp_recv(b, &c, 1, 0), SOCKET_ERROR);
    SPEQ(sp_err(), WSAECONNRESET);
    SPEQ(sp_readable(b, 0), 1);       /* the abort condition persists */
    sp_close(b);
}
FAMILY_TEST(sp_sel_reset_is_not_an_except_condition)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    sp_linger0(a);
    sp_close(a);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_excepted(b, 0), 0);
    sp_close(b);
}
FAMILY_TEST(sp_sel_send_after_reset_fails_without_wsaewouldblock)
{
    SOCKET a, b;
    int r;
    NEED_WS();
    CHECK(sp_pair_af(af, &a, &b));
    sp_linger0(a);
    sp_close(a);
    CHECK(sp_wait_readable(b));
    sp_seterr(0);
    r = sp_send(b, "x", 1, 0);
    if (r == SOCKET_ERROR) {
        int e = sp_err();
        CHECKF(e == WSAECONNRESET || e == WSAECONNABORTED, "error %d", e);
    } else t_note("send on a reset connection returned %d", r);
    sp_close(b);
}

/* ---------------------------------------------------------------- out-of-band */
TEST(sp_sel_oob_sets_except_and_not_read)
{
    SOCKET a, b;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_excepted(b));
    SPEQ(sp_excepted(b, 0), 1);
    SPEQ(sp_readable(b, 0), 0);       /* urgent byte is out of the normal stream */
    sp_close(a); sp_close(b);
}
TEST(sp_sel_oob_with_ordinary_data_sets_both)
{
    SOCKET a, b;
    fd_set r, x;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "plain", 5, 0), 5);
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_excepted(b));
    CHECK(sp_wait_readable(b));
    sp_set1(&r, b); sp_set1(&x, b);
    SPEQ(sp_sel(&r, NULL, &x, 0), 2);
    SPEQ(r.fd_count, 1);
    SPEQ(x.fd_count, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_sel_consuming_oob_clears_except_only)
{
    SOCKET a, b;
    char c;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "data", 4, 0), 4);
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_excepted(b));
    CHECK(sp_wait_readable(b));
    SPEQ(sp_recv(b, &c, 1, MSG_OOB), 1);
    SPEQ(c, '!');
    SPEQ(sp_excepted(b, 0), 0);
    SPEQ(sp_readable(b, 0), 1);
    sp_close(a); sp_close(b);
}
TEST(sp_sel_oob_inline_never_reaches_except_set)
{
    SOCKET a, b;
    int on = 1;
    char c;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_setopt(b, SOL_SOCKET, SO_OOBINLINE, &on, sizeof on), 0);
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_excepted(b, 0), 0);
    SPEQ(sp_recv(b, &c, 1, 0), 1);
    SPEQ(c, '!');
    sp_close(a); sp_close(b);
}
TEST(sp_sel_oob_recv_without_pending_urgent_data_fails)
{
    SOCKET a, b;
    char c;
    int r;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_nonblock(b, 1), 0);       /* never block here whatever the stack decides */
    SPEQ(sp_send(a, "n", 1, 0), 1);
    CHECK(sp_wait_readable(b));
    sp_seterr(0);
    r = sp_recv(b, &c, 1, MSG_OOB);
    SPEQ(r, SOCKET_ERROR);
    SPEQ(sp_err(), WSAEWOULDBLOCK);
    SPEQ(sp_readable(b, 0), 1);       /* the failed urgent read did not consume the ordinary byte */
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- listeners */
FAMILY_TEST(sp_sel_listener_idle_then_pending_then_drained)
{
    sp_addr ad;
    SOCKET l = INVALID_SOCKET, c, s;
    NEED_WS();
    l = sp_listener(af, &ad, 4);
    CHECK(l != INVALID_SOCKET);
    SPEQ(sp_readable(l, 0), 0);
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_connect(c, &ad, sp_alen(af)), 0);
    CHECK(sp_wait_readable(l));
    s = sp_accept(l);
    CHECK(s != INVALID_SOCKET);
    SPEQ(sp_readable(l, 0), 0);
    sp_close(s); sp_close(c); sp_close(l);
}
FAMILY_TEST(sp_sel_listener_stays_readable_until_all_pending_accepted)
{
    enum { N = 3 };
    sp_addr ad;
    SOCKET l, c[N], s[N];
    int i;
    NEED_WS();
    l = sp_listener(af, &ad, 8);
    CHECK(l != INVALID_SOCKET);
    for (i = 0; i < N; i++) { c[i] = sp_sock(af, SOCK_STREAM, 0); SPEQ(sp_connect(c[i], &ad, sp_alen(af)), 0); }
    CHECK(sp_wait_readable(l));
    for (i = 0; i < N; i++) {
        SPEQ(sp_readable(l, 1000), 1);
        s[i] = sp_accept(l);
        CHECK(s[i] != INVALID_SOCKET);
    }
    SPEQ(sp_readable(l, 0), 0);
    for (i = 0; i < N; i++) { sp_close(c[i]); sp_close(s[i]); }
    sp_close(l);
}
FAMILY_TEST(sp_sel_listener_is_never_writable_or_exceptional)
{
    sp_addr ad;
    SOCKET l, c;
    NEED_WS();
    l = sp_listener(af, &ad, 4);
    SPEQ(sp_writable(l, 20), 0);
    SPEQ(sp_excepted(l, 0), 0);
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_connect(c, &ad, sp_alen(af)), 0);
    CHECK(sp_wait_readable(l));
    SPEQ(sp_writable(l, 20), 0);
    SPEQ(sp_excepted(l, 0), 0);
    sp_close(c); sp_close(l);
}
TEST(sp_sel_bound_but_not_listening_stream_reports_nothing)
{
    SOCKET s;
    sp_addr a;
    fd_set r, w, x;
    NEED_WS();
    s = sp_sock(AF_INET, SOCK_STREAM, 0);
    sp_loaddr(AF_INET, &a);
    SPEQ(sp_bind(s, &a, sizeof a.a4), 0);
    sp_set1(&r, s); sp_set1(&w, s); sp_set1(&x, s);
    SPEQ(sp_sel(&r, &w, &x, 20), 0);
    sp_close(s);
}
TEST(sp_sel_listener_with_accepted_pair_in_one_call)
{
    sp_addr ad;
    SOCKET l, c, s, c2;
    fd_set r, w;
    NEED_WS();
    l = sp_listener(AF_INET, &ad, 4);
    c = sp_sock(AF_INET, SOCK_STREAM, 0);
    SPEQ(sp_connect(c, &ad, sizeof ad.a4), 0);
    CHECK(sp_wait_readable(l));
    s = sp_accept(l);
    c2 = sp_sock(AF_INET, SOCK_STREAM, 0);
    SPEQ(sp_connect(c2, &ad, sizeof ad.a4), 0);
    CHECK(sp_wait_readable(l));
    sp_zero(&r); sp_put(&r, l); sp_put(&r, c); sp_put(&r, s);
    sp_zero(&w); sp_put(&w, l); sp_put(&w, c); sp_put(&w, s);
    SPEQ(sp_sel(&r, &w, NULL, 0), 3);   /* listener readable; c and s writable */
    SPEQ(r.fd_count, 1);
    SPEQ(r.fd_array[0], l);
    SPEQ(w.fd_count, 2);
    sp_close(c); sp_close(s); sp_close(c2); sp_close(l);
}

/* ---------------------------------------------------------------- non-blocking connect */
FAMILY_TEST(sp_sel_nonblocking_connect_completes_as_writable)
{
    sp_addr ad;
    SOCKET l, c;
    fd_set w, x, r;
    int e;
    NEED_WS();
    l = sp_listener(af, &ad, 4);
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_nonblock(c, 1), 0);
    e = sp_connect(c, &ad, sp_alen(af));
    CHECK(e == 0 || sp_err() == WSAEWOULDBLOCK);
    sp_set1(&w, c);
    SPEQ(sp_sel(NULL, &w, NULL, 4000), 1);
    sp_set1(&w, c); sp_set1(&x, c); sp_set1(&r, c);
    SPEQ(sp_sel(&r, &w, &x, 0), 1);
    SPEQ(w.fd_count, 1);
    SPEQ(r.fd_count, 0);
    SPEQ(x.fd_count, 0);
    SPEQ(sp_getopt_int(c, SOL_SOCKET, SO_ERROR), 0);
    sp_close(c); sp_close(l);
}
FAMILY_TEST(sp_sel_connecting_peer_is_accepted_and_both_sides_writable)
{
    sp_addr ad;
    SOCKET l, c, s;
    NEED_WS();
    l = sp_listener(af, &ad, 4);
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_nonblock(c, 1), 0);
    sp_connect(c, &ad, sp_alen(af));
    CHECK(sp_wait_readable(l));
    s = sp_accept(l);
    CHECK(s != INVALID_SOCKET);
    SPEQ(sp_writable(c, 4000), 1);
    SPEQ(sp_writable(s, 4000), 1);
    SPEQ(sp_excepted(c, 0), 0);
    sp_close(c); sp_close(s); sp_close(l);
}

/* ---------------------------------------------------------------- datagram sockets */
FAMILY_TEST(sp_sel_udp_idle_is_writable_not_readable)
{
    SOCKET u;
    NEED_WS();
    u = sp_udp(af, NULL);
    CHECK(u != INVALID_SOCKET);
    SPEQ(sp_writable(u, 100), 1);
    SPEQ(sp_readable(u, 0), 0);
    SPEQ(sp_excepted(u, 0), 0);
    sp_close(u);
}
FAMILY_TEST(sp_sel_udp_datagram_makes_readable_until_received)
{
    sp_addr ad;
    SOCKET rx, tx;
    char buf[16];
    NEED_WS();
    rx = sp_udp(af, &ad);
    tx = sp_sock(af, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(sp_sendto(tx, "dgram", 5, &ad, sp_alen(af)), 5);
    CHECK(sp_wait_readable(rx));
    SPEQ(sp_readable(rx, 0), 1);
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, 0), 5);
    SPEQ(sp_readable(rx, 0), 0);
    sp_close(rx); sp_close(tx);
}
FAMILY_TEST(sp_sel_udp_two_datagrams_need_two_receives)
{
    sp_addr ad;
    SOCKET rx, tx;
    char buf[16];
    NEED_WS();
    rx = sp_udp(af, &ad);
    tx = sp_sock(af, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(sp_sendto(tx, "one", 3, &ad, sp_alen(af)), 3);
    SPEQ(sp_sendto(tx, "three", 5, &ad, sp_alen(af)), 5);
    CHECK(sp_wait_readable(rx));
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, 0), 3);
    SPEQ(sp_readable(rx, 1000), 1);
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, 0), 5);
    SPEQ(sp_readable(rx, 0), 0);
    sp_close(rx); sp_close(tx);
}
FAMILY_TEST(sp_sel_udp_peek_keeps_datagram_pending)
{
    sp_addr ad;
    SOCKET rx, tx;
    char buf[16];
    NEED_WS();
    rx = sp_udp(af, &ad);
    tx = sp_sock(af, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(sp_sendto(tx, "peek", 4, &ad, sp_alen(af)), 4);
    CHECK(sp_wait_readable(rx));
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, MSG_PEEK), 4);
    SPEQ(sp_readable(rx, 0), 1);
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, 0), 4);
    SPEQ(sp_readable(rx, 0), 0);
    sp_close(rx); sp_close(tx);
}
FAMILY_TEST(sp_sel_udp_truncated_receive_consumes_the_datagram)
{
    sp_addr ad;
    SOCKET rx, tx;
    char buf[2];
    NEED_WS();
    rx = sp_udp(af, &ad);
    tx = sp_sock(af, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(sp_sendto(tx, "toolong", 7, &ad, sp_alen(af)), 7);
    CHECK(sp_wait_readable(rx));
    sp_seterr(0);
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, 0), SOCKET_ERROR);
    SPEQ(sp_err(), WSAEMSGSIZE);
    SPEQ(sp_readable(rx, 0), 0);      /* the remainder is discarded */
    sp_close(rx); sp_close(tx);
}
TEST(sp_sel_udp_connected_peer_traffic_both_ways)
{
    sp_addr a1, a2;
    SOCKET s1, s2;
    char c;
    NEED_WS();
    s1 = sp_udp(AF_INET, &a1);
    s2 = sp_udp(AF_INET, &a2);
    SPEQ(sp_connect(s1, &a2, sizeof a2.a4), 0);
    SPEQ(sp_connect(s2, &a1, sizeof a1.a4), 0);
    SPEQ(sp_send(s1, "x", 1, 0), 1);
    CHECK(sp_wait_readable(s2));
    SPEQ(sp_readable(s1, 0), 0);
    SPEQ(sp_recv(s2, &c, 1, 0), 1);
    SPEQ(sp_writable(s1, 100), 1);
    SPEQ(sp_writable(s2, 100), 1);
    sp_close(s1); sp_close(s2);
}
TEST(sp_sel_udp_zero_length_datagram_observed)
{
    sp_addr ad;
    SOCKET rx, tx;
    char buf[4];
    int r;
    NEED_WS();
    rx = sp_udp(AF_INET, &ad);
    tx = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    r = sp_sendto(tx, "", 0, &ad, sizeof ad.a4);
    SPEQ(r, 0);
    CHECK(sp_wait_readable(rx));
    r = sp_recvfrom(rx, buf, sizeof buf, 0);
    SPEQ(r, 0);
    sp_close(rx); sp_close(tx);
}
TEST(sp_sel_udp_icmp_port_unreachable_makes_socket_readable_with_connreset)
{
    sp_addr dead = sp_dead_udp(AF_INET);
    SOCKET u;
    char c;
    NEED_WS();
    u = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(sp_connect(u, &dead, sizeof dead.a4), 0);
    SPEQ(sp_send(u, "ping", 4, 0), 4);
    if (sp_readable(u, 3000) != 1) { t_skip("no ICMP port-unreachable delivered (filtered?)"); sp_close(u); return; }
    sp_seterr(0);
    SPEQ(sp_recv(u, &c, 1, 0), SOCKET_ERROR);
    SPEQ(sp_err(), WSAECONNRESET);
    SPEQ(sp_readable(u, 0), 0);       /* reported once */
    sp_close(u);
}
TEST(sp_sel_udp_connreset_can_be_disabled_with_sio_udp_connreset)
{
    sp_addr dead = sp_dead_udp(AF_INET);
    SOCKET u;
    BOOL off = FALSE;
    DWORD got = 0;
    NEED_WS();
    u = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(U(WSAIoctl)(u, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &got, NULL, NULL), 0);
    SPEQ(sp_connect(u, &dead, sizeof dead.a4), 0);
    SPEQ(sp_send(u, "ping", 4, 0), 4);
    Sleep(300);
    SPEQ(sp_readable(u, 0), 0);
    sp_close(u);
}

/* ---------------------------------------------------------------- non-overlapped sockets */
TEST(sp_sel_non_overlapped_socket_pair)
{
    sp_addr ad;
    SOCKET l, c, s;
    NEED_WS();
    REQUIRE(U(WSASocketW));
    l = sp_listener(AF_INET, &ad, 4);
    c = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);   /* no WSA_FLAG_OVERLAPPED */
    CHECK(c != INVALID_SOCKET);
    SPEQ(sp_connect(c, &ad, sizeof ad.a4), 0);
    s = sp_accept(l);
    SPEQ(sp_send(s, "n", 1, 0), 1);
    CHECK(sp_wait_readable(c));
    SPEQ(sp_writable(c, 100), 1);
    sp_close(c); sp_close(s); sp_close(l);
}

/* ---------------------------------------------------------------- blocking select woken from elsewhere */
TEST(sp_sel_blocked_select_wakes_on_data)
{
    SOCKET a, b;
    HANDLE h;
    fd_set r;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, sp_job_send1, (void *)(ULONG_PTR)a);
    sp_set1(&r, b);
    SPEQ(U(select)(0, &r, NULL, NULL, NULL), 1);      /* no timeout: waits for the sender */
    SPEQ(r.fd_array[0], b);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b);
}
TEST(sp_sel_blocked_select_wakes_on_incoming_connection)
{
    sp_addr ad;
    SOCKET l;
    HANDLE h;
    sp_conn_arg ca;
    fd_set r;
    NEED_WS();
    l = sp_listener(AF_INET, &ad, 4);
    ca.s = INVALID_SOCKET; ca.to = &ad; ca.af = AF_INET;
    h = sp_after(150, sp_job_connect, &ca);
    sp_set1(&r, l);
    SPEQ(sp_sel(&r, NULL, NULL, 5000), 1);
    CHECK(sp_join(h, 4000));
    sp_close(ca.s); sp_close(l);
}
TEST(sp_sel_blocked_select_wakes_on_peer_fin)
{
    SOCKET a, b;
    HANDLE h;
    fd_set r;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, sp_job_shutsend, (void *)(ULONG_PTR)a);
    sp_set1(&r, b);
    SPEQ(sp_sel(&r, NULL, NULL, 5000), 1);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b);
}
TEST(sp_sel_blocked_select_wakes_on_peer_close)
{
    SOCKET a, b;
    HANDLE h;
    fd_set r;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, sp_job_close, (void *)(ULONG_PTR)a);
    sp_set1(&r, b);
    SPEQ(sp_sel(&r, NULL, NULL, 5000), 1);
    CHECK(sp_join(h, 4000));
    sp_close(b);
}
static void job_oob(void *p) { sp_send((SOCKET)(ULONG_PTR)p, "!", 1, MSG_OOB); }
TEST(sp_sel_blocked_except_wait_wakes_on_oob)
{
    SOCKET a, b;
    HANDLE h;
    fd_set x;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, job_oob, (void *)(ULONG_PTR)a);
    sp_set1(&x, b);
    SPEQ(sp_sel(NULL, NULL, &x, 5000), 1);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- concurrent selectors */
typedef struct { SOCKET s; int ret; } sel_thr;
static DWORD WINAPI sel_reader(void *p)
{
    sel_thr *t = (sel_thr *)p;
    fd_set r;
    sp_set1(&r, t->s);
    t->ret = sp_sel(&r, NULL, NULL, 6000);
    return 0;
}
TEST(sp_sel_two_threads_wait_on_the_same_socket)
{
    SOCKET a, b;
    sel_thr t1, t2;
    HANDLE h1, h2;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    t1.s = t2.s = b; t1.ret = t2.ret = -7;
    h1 = CreateThread(NULL, 0, sel_reader, &t1, 0, NULL);
    h2 = CreateThread(NULL, 0, sel_reader, &t2, 0, NULL);
    Sleep(200);
    SPEQ(sp_send(a, "w", 1, 0), 1);
    CHECK(sp_join(h1, 8000));
    CHECK(sp_join(h2, 8000));
    SPEQ(t1.ret, 1);                  /* readiness is not consumed by the first waiter */
    SPEQ(t2.ret, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_sel_two_threads_wait_on_different_sockets)
{
    SOCKET a, b, c, d;
    sel_thr t1, t2;
    HANDLE h1, h2;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    CHECK(sp_pair(&c, &d));
    t1.s = b; t2.s = d; t1.ret = t2.ret = -7;
    h1 = CreateThread(NULL, 0, sel_reader, &t1, 0, NULL);
    h2 = CreateThread(NULL, 0, sel_reader, &t2, 0, NULL);
    Sleep(150);
    SPEQ(sp_send(c, "2", 1, 0), 1);
    CHECK(sp_join(h2, 8000));
    SPEQ(t2.ret, 1);
    Sleep(100);
    SPEQ(sp_send(a, "1", 1, 0), 1);
    CHECK(sp_join(h1, 8000));
    SPEQ(t1.ret, 1);
    sp_close(a); sp_close(b); sp_close(c); sp_close(d);
}

/* ---------------------------------------------------------------- inherited sockets */
CHILD(sp_sel_inherited)
{
    WSADATA d;
    fd_set r;
    char c = 0;
    SOCKET s;
    int (WSAAPI *up)(WORD, LPWSADATA) = (int (WSAAPI *)(WORD, LPWSADATA))t_proc_in("ws2_32.dll", "WSAStartup");
    int (WSAAPI *sel)(int, fd_set *, fd_set *, fd_set *, const struct timeval *) =
        (int (WSAAPI *)(int, fd_set *, fd_set *, fd_set *, const struct timeval *))t_proc_in("ws2_32.dll", "select");
    int (WSAAPI *rcv)(SOCKET, char *, int, int) = (int (WSAAPI *)(SOCKET, char *, int, int))t_proc_in("ws2_32.dll", "recv");
    struct timeval tv = { 5, 0 };
    if (argc < 2 || !up || !sel || !rcv) return 90;
    s = (SOCKET)_strtoui64(argv[1], NULL, 16);
    if (up(MAKEWORD(2, 2), &d)) return 91;
    r.fd_count = 1; r.fd_array[0] = s;
    if (sel(0, &r, NULL, NULL, &tv) != 1) return 92;
    if (rcv(s, &c, 1, 0) != 1 || c != 'Z') return 93;
    return 0;
}
TEST(sp_sel_socket_inherited_by_child_process_is_selectable)
{
    SOCKET a, b;
    char arg[64];
    PROCESS_INFORMATION pi;
    HANDLE h;
    DWORD code = 0xDEAD;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SetHandleInformation((HANDLE)b, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    snprintf(arg, sizeof arg, "%llx", (unsigned long long)b);
    h = t_spawn_child("sp_sel_inherited", arg, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    CHECK(h != NULL);
    if (h) {
        Sleep(200);
        SPEQ(sp_send(a, "Z", 1, 0), 1);
        if (WaitForSingleObject(h, 10000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); t_note("child timed out"); }
        else { GetExitCodeProcess(h, &code); SPEQ(code, 0); }
        CloseHandle(pi.hThread); CloseHandle(h);
    }
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- duplicated socket handles */
TEST(sp_sel_wsaduplicatesocket_clone_sees_the_same_data)
{
    SOCKET a, b, d;
    WSAPROTOCOL_INFOW pi;
    fd_set r;
    NEED_WS();
    REQUIRE(U(WSADuplicateSocketW));
    REQUIRE(U(WSASocketW));
    CHECK(sp_pair(&a, &b));
    SPEQ(U(WSADuplicateSocketW)(b, GetCurrentProcessId(), &pi), 0);
    d = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, 0);
    CHECK(d != INVALID_SOCKET);
    CHECK(d != b);
    SPEQ(sp_send(a, "dup", 3, 0), 3);
    CHECK(sp_wait_readable(b));
    sp_zero(&r); sp_put(&r, b); sp_put(&r, d);
    SPEQ(sp_sel(&r, NULL, NULL, 0), 2);   /* two handles, one endpoint: both are readable */
    sp_close(d); sp_close(a); sp_close(b);
}
