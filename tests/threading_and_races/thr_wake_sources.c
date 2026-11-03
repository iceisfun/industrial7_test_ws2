/* A thread blocks in a receive-side call and a different thread wakes it by acting on the connection:
 * sending data, shutting down a direction, closing gracefully, resetting, or connecting.
 *
 * Measures the wake-up semantics (return value, byte count, WSAGetLastError) of recv / recvfrom / select /
 * WSAPoll / accept when the event arrives from another thread rather than from the blocked thread itself:
 * orderly release (0), reset (WSAECONNRESET), data exactness, datagram boundaries, a blocked blocking send that
 * is freed by the peer reading, and which local shutdown directions do or do not release a reader.
 */
#include "thr.h"

/* ---- data wakes a reader ---------------------------------------------------------------------------------------- */
TEST(thr_wake_recv_by_data)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 64);
    CHECK(!finished(b.th));
    EQV(snd(c, "hello", 5), 5);
    CHECK(blk_join(&b));
    EQV(b.ret, 5);
    CHECK(!memcmp(b.buf, "hello", 5));
    cls(c); cls(s);
}
TEST(thr_wake_recv_returns_at_most_len)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 3);
    snd(c, "abcdefgh", 8);
    CHECK(blk_join(&b));
    EQV(b.ret, 3);
    CHECK(!memcmp(b.buf, "abc", 3));
    cls(c); cls(s);
}
TEST(thr_wake_wsarecv_by_data)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_WSARECV, s, 64);
    snd(c, "wxyz", 4);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    EQV(b.bytes, 4);
    cls(c); cls(s);
}
TEST(thr_wake_peek_does_not_consume)
{
    SOCKET c, s;
    struct blk b;
    char x[8] = { 0 };
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV_PEEK, s, 64);
    snd(c, "peek", 4);
    CHECK(blk_join(&b));
    EQV(b.ret, 4);
    EQV(rcv(s, x, 8), 4);
    CHECK(!memcmp(x, "peek", 4));
    cls(c); cls(s);
}
TEST(thr_wake_waitall_needs_full_length)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV_WAITALL, s, 8);
    snd(c, "abc", 3);
    SETTLE();
    CHECK(!finished(b.th));              /* three of eight bytes do not satisfy MSG_WAITALL */
    snd(c, "defgh", 5);
    CHECK(blk_join(&b));
    EQV(b.ret, 8);
    CHECK(!memcmp(b.buf, "abcdefgh", 8));
    cls(c); cls(s);
}
TEST(thr_wake_waitall_released_early_by_peer_fin)
{
    /* part of the data arrived, then the peer ends the stream: the call returns what it has */
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV_WAITALL, s, 8);
    snd(c, "abc", 3);
    SETTLE();
    U(shutdown)(c, SD_SEND);
    CHECK(blk_join(&b));
    EQV(b.ret, 3);
    cls(c); cls(s);
}

/* ---- the peer ends or resets the stream -------------------------------------------------------------------------------- */
TEST(thr_wake_recv_by_peer_shutdown_send)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    EQV(U(shutdown)(c, SD_SEND), 0);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    cls(c); cls(s);
}
TEST(thr_wake_recv_by_peer_shutdown_both)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    EQV(U(shutdown)(c, SD_BOTH), 0);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    cls(c); cls(s);
}
TEST(thr_wake_recv_by_peer_close)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    cls(c);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    cls(s);
}
TEST(thr_wake_wsarecv_by_peer_close)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_WSARECV, s, 8);
    cls(c);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    EQV(b.bytes, 0);
    cls(s);
}
TEST(thr_wake_recv_by_peer_reset)
{
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    lg.l_onoff = 1; lg.l_linger = 0;
    EQV(sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg), 0);
    cls(c);                                  /* abortive close sends RST */
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAECONNRESET);
    cls(s);
}
TEST(thr_wake_wsarecv_by_peer_reset)
{
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_WSARECV, s, 8);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAECONNRESET);
    cls(s);
}
TEST(thr_wake_reset_error_is_sticky)
{
    /* after the reset was reported to a blocked reader the next call on the socket fails again */
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    char x;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    CHECK(blk_join(&b));
    wset(0);
    EQV(rcv(s, &x, 1), SOCKET_ERROR);
    EQV(werr(), WSAECONNRESET);
    cls(s);
}
TEST(thr_wake_reset_discards_unread_data_for_reader)
{
    /* data queued before the reset is lost: the reader sees the reset, not the bytes */
    SOCKET c, s;
    struct linger lg;
    char x[8];
    int r;
    NEED();
    CHECK(pair(&c, &s));
    snd(c, "late", 4);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    SETTLE();
    r = rcv(s, x, 8);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSAECONNRESET);
    cls(s);
}

/* Wait up to ms for a blocker to finish; if it does not, report and release it by closing its socket. */
static int released_or_force(struct blk *b, const char *what, DWORD ms)
{
    DWORD t;
    for (t = 0; t < ms && !finished(b->th); t += 20) Sleep(20);
    if (finished(b->th)) return 1;
    t_note("%s: not released by the shutdown within %lu ms", what, ms);
    cls(b->s);
    return 0;
}

/* ---- local shutdown from another thread --------------------------------------------------------------------------------- */
TEST(thr_wake_local_shutdown_send_does_not_release_reader)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    EQV(U(shutdown)(s, SD_SEND), 0);
    SETTLE();
    CHECK(!finished(b.th));              /* the receive direction is untouched */
    snd(c, "k", 1);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(c); cls(s);
}
TEST(thr_wake_local_shutdown_receive_keeps_reader)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    EQV(U(shutdown)(s, SD_RECEIVE), 0);
    CHECKF(!released_or_force(&b, "recv/SD_RECEIVE", 1500), "a local SD_RECEIVE released the blocked reader");
    CHECK(blk_join(&b));
    cls(c);
}
TEST(thr_wake_local_shutdown_both_keeps_reader)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    EQV(U(shutdown)(s, SD_BOTH), 0);
    CHECKF(!released_or_force(&b, "recv/SD_BOTH", 1500), "a local SD_BOTH released the blocked reader");
    CHECK(blk_join(&b));
    cls(c);
}
TEST(thr_wake_local_shutdown_receive_keeps_wsarecv)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_WSARECV, s, 8);
    EQV(U(shutdown)(s, SD_RECEIVE), 0);
    CHECKF(!released_or_force(&b, "WSARecv/SD_RECEIVE", 1500), "a local SD_RECEIVE released the blocked WSARecv");
    CHECK(blk_join(&b));
    cls(c);
}
TEST(thr_wake_local_shutdown_receive_keeps_select)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_R, s, 0);
    EQV(U(shutdown)(s, SD_RECEIVE), 0);
    CHECKF(!released_or_force(&b, "select/SD_RECEIVE", 1500), "a local SD_RECEIVE released the blocked select");
    CHECK(blk_join(&b));
    cls(c);
}
TEST(thr_wake_after_shutdown_receive_recv_is_eshutdown)
{
    SOCKET c, s;
    char x;
    int r;
    NEED();
    CHECK(pair(&c, &s));
    U(shutdown)(s, SD_RECEIVE);
    wset(0);
    r = rcv(s, &x, 1);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSAESHUTDOWN);
    cls(c); cls(s);
}

/* ---- select / WSAPoll woken from another thread ---------------------------------------------------------------------- */
TEST(thr_wake_select_by_data)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_R, s, 0);
    snd(c, "d", 1);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(c); cls(s);
}
TEST(thr_wake_select_by_peer_fin)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_R, s, 0);
    U(shutdown)(c, SD_SEND);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);                       /* readable: a receive would complete with 0 */
    cls(c); cls(s);
}
TEST(thr_wake_select_by_peer_reset)
{
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_R, s, 0);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(s);
}
TEST(thr_wake_select_listener_by_connection)
{
    struct sockaddr_in a; SOCKET l, d;
    struct blk b;
    NEED();
    l = listener(&a, 4);
    blk_start(&b, B_SELECT_R, l, 0);
    d = dial(&a);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    cls(d); cls(l);
}
TEST(thr_wake_select_except_by_nothing_times_out_only)
{
    /* nothing happens on the connection: the except-set select is still blocked after the settle time */
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_SELECT_X, s, 0);
    SETTLE();
    CHECK(!finished(b.th));
    cls(s);
    CHECK(blk_join(&b));
    cls(c);
}
TEST(thr_wake_poll_by_data)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_POLL_IN, s, 0);
    snd(c, "d", 1);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    CHECK(b.flags & POLLRDNORM);
    cls(c); cls(s);
}
TEST(thr_wake_poll_by_peer_fin)
{
    SOCKET c, s;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_POLL_IN, s, 0);
    U(shutdown)(c, SD_SEND);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    EQV(b.flags, POLLHUP);
    cls(c); cls(s);
}
TEST(thr_wake_poll_by_peer_reset)
{
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    NEED();
    CHECK(pair(&c, &s));
    blk_start(&b, B_POLL_IN, s, 0);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(c);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    EQV(b.flags, POLLERR | POLLHUP);
    cls(s);
}
TEST(thr_wake_poll_listener_by_connection)
{
    struct sockaddr_in a; SOCKET l, d;
    struct blk b;
    NEED();
    l = listener(&a, 4);
    blk_start(&b, B_POLL_IN, l, 0);
    d = dial(&a);
    CHECK(blk_join(&b));
    EQV(b.ret, 1);
    CHECK(b.flags & POLLRDNORM);
    cls(d); cls(l);
}

/* ---- accept woken by a connection from another thread -------------------------------------------------------------------- */
TEST(thr_wake_accept_by_connect)
{
    struct sockaddr_in a; SOCKET l, d;
    struct blk b;
    NEED();
    l = listener(&a, 4);
    blk_start(&b, B_ACCEPT, l, 0);
    d = dial(&a);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    cls(d); cls(l);
}
TEST(thr_wake_wsaaccept_by_connect)
{
    struct sockaddr_in a; SOCKET l, d;
    struct blk b;
    NEED();
    l = listener(&a, 4);
    blk_start(&b, B_WSAACCEPT, l, 0);
    d = dial(&a);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);
    cls(d); cls(l);
}
TEST(thr_wake_accepted_socket_is_usable_across_threads)
{
    struct sockaddr_in a; SOCKET l, d, s;
    NEED();
    l = listener(&a, 4);
    d = dial(&a);
    s = U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    {
        struct blk b;
        blk_start(&b, B_RECV, s, 8);   /* a thread that did not create the socket can read from it */
        snd(d, "m", 1);
        CHECK(blk_join(&b));
        EQV(b.ret, 1);
    }
    cls(s); cls(d); cls(l);
}

/* ---- datagrams ----------------------------------------------------------------------------------------------------------- */
TEST(thr_wake_recvfrom_by_datagram)
{
    struct sockaddr_in a; SOCKET r, t;
    struct blk b;
    NEED();
    r = udp_bound(&a);
    t = udp();
    blk_start(&b, B_RECVFROM, r, 64);
    EQV(U(sendto)(t, "dgram", 5, 0, (struct sockaddr *)&a, sizeof a), 5);
    CHECK(blk_join(&b));
    EQV(b.ret, 5);
    CHECK(!memcmp(b.buf, "dgram", 5));
    cls(t); cls(r);
}
struct dsend { SOCKET s; struct sockaddr_in to; HANDLE th; };
static DWORD WINAPI dsend_main(void *p)
{
    struct dsend *d = (struct dsend *)p;
    Sleep(150);
    U(sendto)(d->s, "w", 1, 0, (struct sockaddr *)&d->to, sizeof d->to);
    return 0;
}
TEST(thr_wake_recvfrom_reports_sender_name)
{
    /* the receiving thread (this one) blocks; a helper thread sends from a socket whose name we know */
    struct sockaddr_in a, sender, from;
    SOCKET r, t;
    int fl = sizeof from, got;
    char x;
    struct dsend d;
    NEED();
    r = udp_bound(&a);
    t = udp_bound(&sender);
    d.s = t; d.to = a;
    d.th = CreateThread(NULL, 0, dsend_main, &d, 0, NULL);
    memset(&from, 0, sizeof from);
    got = U(recvfrom)(r, &x, 1, 0, (struct sockaddr *)&from, &fl);
    EQV(got, 1);
    EQV(fl, sizeof from);
    EQV(from.sin_family, AF_INET);
    EQV(from.sin_port, sender.sin_port);
    EQV(from.sin_addr.s_addr, sender.sin_addr.s_addr);
    CHECK(join(d.th, 5000));
    cls(t); cls(r);
}
TEST(thr_wake_recvfrom_zero_length_datagram)
{
    struct sockaddr_in a; SOCKET r, t;
    struct blk b;
    NEED();
    r = udp_bound(&a);
    t = udp();
    blk_start(&b, B_RECVFROM, r, 16);
    EQV(U(sendto)(t, "", 0, 0, (struct sockaddr *)&a, sizeof a), 0);
    CHECK(blk_join(&b));
    EQV(b.ret, 0);                       /* an empty datagram is a successful 0-byte receive */
    cls(t); cls(r);
}
TEST(thr_wake_recvfrom_truncates_to_msgsize)
{
    struct sockaddr_in a; SOCKET r, t;
    struct blk b;
    NEED();
    r = udp_bound(&a);
    t = udp();
    blk_start(&b, B_RECVFROM, r, 4);
    U(sendto)(t, "0123456789", 10, 0, (struct sockaddr *)&a, sizeof a);
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    EQV(b.err, WSAEMSGSIZE);
    cls(t); cls(r);
}
TEST(thr_wake_udp_two_readers_two_datagrams)
{
    struct sockaddr_in a; SOCKET r, t;
    struct blk b1, b2;
    NEED();
    r = udp_bound(&a);
    t = udp();
    blk_start(&b1, B_RECVFROM, r, 16);
    blk_start(&b2, B_RECVFROM, r, 16);
    U(sendto)(t, "A", 1, 0, (struct sockaddr *)&a, sizeof a);
    U(sendto)(t, "B", 1, 0, (struct sockaddr *)&a, sizeof a);
    CHECK(blk_join(&b1));
    CHECK(blk_join(&b2));
    EQV(b1.ret, 1);
    EQV(b2.ret, 1);
    CHECK(b1.buf[0] != b2.buf[0]);       /* each datagram goes to exactly one reader */
    CHECK((b1.buf[0] == 'A' || b1.buf[0] == 'B') && (b2.buf[0] == 'A' || b2.buf[0] == 'B'));
    cls(t); cls(r);
}

/* ---- blocking send freed by the peer reading ------------------------------------------------------------------------------ */
TEST(thr_wake_blocked_send_completes_when_peer_reads)
{
    SOCKET c, s;
    struct blk b;
    long long q;
    char sink[4096];
    long long got = 0;
    int r, spin;
    NEED();
    CHECK(pair(&c, &s));
    small_bufs(c); small_bufs(s);
    q = fill_send(c);
    if (q < 0) { cls(c); cls(s); t_skip("send path never filled"); return; }
    blk_start(&b, B_SEND, c, 1 << 18);
    CHECK(!finished(b.th));
    /* drain everything: first the bytes queued by fill_send, then the 256 KiB of the blocked send */
    for (spin = 0; spin < 100000 && got < q + (1 << 18); spin++) {
        r = rcv(s, sink, sizeof sink);
        if (r <= 0) break;
        got += r;
    }
    CHECK(blk_join(&b));
    EQV(b.ret, 1 << 18);                 /* a blocking send reports the full length once everything is queued */
    EQV(got, q + (1 << 18));
    cls(c); cls(s);
}
TEST(thr_wake_blocked_send_released_by_peer_reset)
{
    SOCKET c, s;
    struct blk b;
    struct linger lg;
    long long q;
    NEED();
    CHECK(pair(&c, &s));
    small_bufs(c); small_bufs(s);
    q = fill_send(c);
    if (q < 0) { cls(c); cls(s); t_skip("send path never filled"); return; }
    blk_start(&b, B_SEND, c, 1 << 18);
    lg.l_onoff = 1; lg.l_linger = 0;
    sso(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    cls(s);
    CHECK(blk_join(&b));
    EQV(b.ret, SOCKET_ERROR);
    t_note("blocked send released by peer RST: err=%d", b.err);
    EQV(b.err, WSAECONNRESET);
    cls(c);
}
