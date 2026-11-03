/* IPv6 UDP loopback (sender address shape, connected filtering, dual-stack mapped addresses),
 * receive-queue overflow expressed only as relations (some loss, order preserved, no duplicates,
 * socket not wedged), a threaded producer, FIFO completion of several posted overlapped receives,
 * and the WSARecvFrom address-length protocol. */
#include "ud.h"

/* ---- IPv6 ---- */

#define NEED_V6() do { UP(); if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; } } while (0)

TEST(udp6_sender_address_has_zero_scope_and_flowinfo) {
    ud_ep a, b; struct sockaddr_in6 from; int fl = sizeof from; char c;
    NEED_V6();
    if (!ud_pair(&a, &b, AF_INET6)) return;
    memset(&from, 0xA5, sizeof from);
    CHECK(ud_sendto(&a, &b, "1", 1) == 1);
    CHECK(ud_recv_to(b.s, &c, 1, 0, &from, &fl, 3000) == 1);
    EXPECT_EQ(fl, sizeof from);
    EXPECT_EQ(from.sin6_family, AF_INET6);
    EXPECT_EQ(from.sin6_scope_id, 0);
    EXPECT_EQ(from.sin6_flowinfo, 0);
    CHECK(ud_sameaddr(&a, (struct sockaddr_storage *)&from, fl));
    ud_free(&a); ud_free(&b);
}

TEST(udp6_zero_length_and_truncation) {
    ud_ep a, b; char buf[2]; int r;
    NEED_V6();
    if (!ud_pair(&a, &b, AF_INET6)) return;
    CHECK(ud_sendto(&a, &b, "", 0) == 0);
    CHECK(ud_sendto(&a, &b, "abcdef", 6) == 6);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000); EXPECT_EQ(r, 0);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recv)(b.s, buf, sizeof buf, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!memcmp(buf, "ab", 2));
    ud_free(&a); ud_free(&b);
}

TEST(udp6_peek_does_not_consume) {
    ud_ep a, b; char b1[8], b2[8];
    NEED_V6();
    if (!ud_pair(&a, &b, AF_INET6)) return;
    CHECK(ud_sendto(&a, &b, "peek6", 5) == 5);
    CHECK(ud_recv_to(b.s, b1, sizeof b1, MSG_PEEK, NULL, NULL, 3000) == 5);
    CHECK(ud_recv_to(b.s, b2, sizeof b2, 0, NULL, NULL, 3000) == 5);
    CHECK(!memcmp(b1, b2, 5));
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp6_connected_filter_drops_other_senders) {
    ud_ep a, b, c; char buf[8]; int r;
    NEED_V6();
    if (!ud_pair(&a, &b, AF_INET6)) return;
    if (!ud_open(&c, AF_INET6)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(ud_sendto(&c, &a, "no", 2) == 2);
    CHECK(ud_sendto(&b, &a, "yes", 3) == 3);
    r = ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 3);
    CHECK(!ud_ready(a.s, 150));
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp6_ping_pong) {
    ud_ep a, b; int i, bad = 0; char buf[4];
    NEED_V6();
    if (!ud_pair(&a, &b, AF_INET6)) return;
    for (i = 0; i < 15; i++) {
        buf[0] = (char)i;
        if (ud_sendto(&a, &b, buf, 1) != 1) { bad++; break; }
        if (ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) != 1) { bad++; break; }
        buf[0] = (char)(buf[0] + 100);
        if (ud_sendto(&b, &a, buf, 1) != 1) { bad++; break; }
        if (ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000) != 1 || buf[0] != (char)(i + 100)) { bad++; break; }
    }
    EXPECT_EQ(bad, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp6_send_to_closed_port_reports_connreset_by_default) {
    ud_ep a, t; char c; int r;
    NEED_V6();
    if (!ud_open(&a, AF_INET6) || !ud_open(&t, AF_INET6)) { t_skip("endpoint"); return; }
    ud_free(&t);
    CHECK(ud_sendto(&a, &t, "p", 1) == 1);
    if (!ud_ready(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); return; }
    ud_seterr(0);
    r = U(recv)(a.s, &c, 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAECONNRESET);
    ud_free(&a);
}

/* ---- dual-stack ---- */

static int dual_socket(ud_ep *e) {
    int n;
    memset(e, 0, sizeof *e);
    e->af = AF_INET6;
    e->s = U(socket)(AF_INET6, SOCK_DGRAM, 0);
    if (e->s == INVALID_SOCKET) return 0;
    if (ud_setint(e->s, IPPROTO_IPV6, IPV6_V6ONLY, 0) != 0) { ud_close(e->s); return 0; }
    memset(&e->sa, 0, sizeof e->sa);
    ((struct sockaddr_in6 *)&e->sa)->sin6_family = AF_INET6;
    e->len = sizeof(struct sockaddr_in6);
    if (U(bind)(e->s, (struct sockaddr *)&e->sa, e->len) != 0) { ud_close(e->s); return 0; }
    n = sizeof e->sa;
    U(getsockname)(e->s, (struct sockaddr *)&e->sa, &n);
    return 1;
}

TEST(udp_dual_stack_socket_sees_v4_sender_as_mapped_address) {
    ud_ep d, v4; struct sockaddr_in6 from; int fl = sizeof from; char c; int r;
    NEED_V6();
    if (!dual_socket(&d)) { t_skip("dual-stack socket unavailable"); return; }
    if (!ud_open(&v4, AF_INET)) { ud_free(&d); t_skip("endpoint"); return; }
    {   /* send to the dual-stack socket's port over IPv4 loopback */
        struct sockaddr_in to; ud_lo4(&to, ((struct sockaddr_in6 *)&d.sa)->sin6_port);
        CHECK(U(sendto)(v4.s, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);
    }
    memset(&from, 0, sizeof from);
    r = ud_recv_to(d.s, &c, 1, 0, &from, &fl, 3000);
    EXPECT_EQ(r, 1);
    EXPECT_EQ(fl, sizeof from);
    EXPECT_EQ(from.sin6_family, AF_INET6);
    {
        static const unsigned char mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
        CHECK(!memcmp(from.sin6_addr.u.Byte, mapped, 12));
        EXPECT_EQ(from.sin6_addr.u.Byte[12], 127);
        EXPECT_EQ(from.sin6_addr.u.Byte[15], 1);
        EXPECT_EQ(from.sin6_port, ((struct sockaddr_in *)&v4.sa)->sin_port);
    }
    ud_free(&d); ud_free(&v4);
}

TEST(udp_dual_stack_sendto_mapped_address_reaches_v4_socket) {
    ud_ep d, v4; struct sockaddr_in6 to; struct sockaddr_in from; int fl = sizeof from; char c;
    NEED_V6();
    if (!dual_socket(&d)) { t_skip("dual-stack socket unavailable"); return; }
    if (!ud_open(&v4, AF_INET)) { ud_free(&d); t_skip("endpoint"); return; }
    memset(&to, 0, sizeof to);
    to.sin6_family = AF_INET6;
    to.sin6_port = ((struct sockaddr_in *)&v4.sa)->sin_port;
    to.sin6_addr.u.Byte[10] = 0xff; to.sin6_addr.u.Byte[11] = 0xff;
    to.sin6_addr.u.Byte[12] = 127;  to.sin6_addr.u.Byte[15] = 1;
    CHECK(U(sendto)(d.s, "m", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);
    CHECK(ud_recv_to(v4.s, &c, 1, 0, &from, &fl, 3000) == 1);
    EXPECT_EQ(from.sin_family, AF_INET);
    EXPECT_EQ(from.sin_addr.s_addr, 0x0100007fu);
    ud_free(&d); ud_free(&v4);
}

TEST(udp_v6only_socket_sendto_mapped_address_note) {
    ud_ep a, v4; struct sockaddr_in6 to; int r;
    NEED_V6();
    if (!ud_open(&a, AF_INET6) || !ud_open(&v4, AF_INET)) { t_skip("endpoint"); return; }
    memset(&to, 0, sizeof to);
    to.sin6_family = AF_INET6;
    to.sin6_port = ((struct sockaddr_in *)&v4.sa)->sin_port;
    to.sin6_addr.u.Byte[10] = 0xff; to.sin6_addr.u.Byte[11] = 0xff;
    to.sin6_addr.u.Byte[12] = 127;  to.sin6_addr.u.Byte[15] = 1;
    ud_seterr(0);
    r = U(sendto)(a.s, "m", 1, 0, (struct sockaddr *)&to, sizeof to);
    t_note("sendto IPv4-mapped address from a V6ONLY socket: r=%d err=%d delivered=%d", r, r < 0 ? ud_err() : 0, r == 1 ? ud_ready(v4.s, 500) : 0);
    ud_free(&a); ud_free(&v4);
}

/* ---- receive queue overflow, relations only ---- */

/* Sends n numbered datagrams of size sz without receiving, then drains. Returns the number received and
 * checks that sequence numbers are strictly increasing. */
static int overflow_run(int rcvbuf, int n, int sz, int *ordered_out, int *sendfail_out) {
    ud_ep a, b; unsigned char tx[1400], rx[1500]; int i, got = 0, ordered = 1, last = -1, sendfail = 0;
    if (!ud_pair(&a, &b, AF_INET)) return -1;
    if (rcvbuf > 0) ud_setint(b.s, SOL_SOCKET, SO_RCVBUF, rcvbuf);
    memset(tx, 0x77, sizeof tx);
    for (i = 0; i < n; i++) {
        tx[0] = (unsigned char)(i & 0xff); tx[1] = (unsigned char)(i >> 8);
        if (ud_sendto(&a, &b, tx, sz) != sz) sendfail++;
    }
    Sleep(100);
    while (ud_ready(b.s, 300)) {
        int r = U(recvfrom)(b.s, (char *)rx, sizeof rx, 0, NULL, NULL), seq;
        if (r != sz) { ordered = 0; break; }
        seq = rx[0] | (rx[1] << 8);
        if (seq <= last) ordered = 0;
        last = seq;
        got++;
    }
    /* the socket is not wedged afterwards */
    tx[0] = 0xfe; tx[1] = 0xfe;
    if (ud_sendto(&a, &b, tx, sz) != sz || ud_recv_to(b.s, rx, sizeof rx, 0, NULL, NULL, 3000) != sz) ordered = 0;
    ud_free(&a); ud_free(&b);
    *ordered_out = ordered; *sendfail_out = sendfail;
    return got;
}

TEST(udp_small_rcvbuf_overflow_drops_but_keeps_order) {
    int ordered = 0, sf = 0, got = overflow_run(4096, 300, 1000, &ordered, &sf);
    UP();
    if (got < 0) { t_skip("endpoint"); return; }
    t_note("small buffer: received a strict subset=%d", got < 300);
    CHECK(got >= 1);
    CHECK(got < 300);
    EXPECT_EQ(sf, 0);
    EXPECT_EQ(ordered, 1);
}

TEST(udp_larger_rcvbuf_keeps_at_least_as_many) {
    int o1 = 0, o2 = 0, s1 = 0, s2 = 0, small, big;
    UP();
    small = overflow_run(4096, 200, 1000, &o1, &s1);
    big = overflow_run(1 << 20, 200, 1000, &o2, &s2);
    if (small < 0 || big < 0) { t_skip("endpoint"); return; }
    CHECK(big >= small);
    EXPECT_EQ(o1, 1); EXPECT_EQ(o2, 1);
    EXPECT_EQ(s1, 0); EXPECT_EQ(s2, 0);
}

TEST(udp_zero_length_datagrams_flood_does_not_fail_sender) {
    ud_ep a, b; int i, sf = 0, got = 0; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ud_setint(b.s, SOL_SOCKET, SO_RCVBUF, 4096);
    for (i = 0; i < 500; i++) if (ud_sendto(&a, &b, "", 0) != 0) sf++;
    EXPECT_EQ(sf, 0);
    while (ud_ready(b.s, 200)) { if (U(recv)(b.s, &c, 1, 0) != 0) break; got++; }
    CHECK(got >= 1);
    CHECK(got <= 500);
    ud_free(&a); ud_free(&b);
}

TEST(udp_rcvbuf_set_before_and_after_bind_both_work) {
    SOCKET s; ud_ep a; struct sockaddr_in me; int r1, r2;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    r1 = ud_setint(s, SOL_SOCKET, SO_RCVBUF, 65536);
    ud_lo4(&me, 0);
    CHECK(U(bind)(s, (struct sockaddr *)&me, sizeof me) == 0);
    r2 = ud_setint(s, SOL_SOCKET, SO_RCVBUF, 131072);
    EXPECT_EQ(r1, 0); EXPECT_EQ(r2, 0);
    ud_close(s);
    (void)a;
}

TEST(udp_rcvbuf_zero_still_delivers_note) {
    ud_ep a, b; char buf[200]; int r, rs;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    rs = ud_setint(b.s, SOL_SOCKET, SO_RCVBUF, 0);
    CHECK(ud_sendto(&a, &b, "z", 1) == 1);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 1500);
    t_note("SO_RCVBUF=0: setsockopt=%d, one-byte datagram received=%d", rs, r == 1);
    ud_free(&a); ud_free(&b);
}

/* ---- producer thread ---- */

typedef struct { ud_ep *from, *to; int n; volatile LONG done; } prod_t;
static DWORD WINAPI producer(LPVOID p_) {
    prod_t *p = (prod_t *)p_; int i;
    for (i = 0; i < p->n; i++) {
        unsigned char m[4] = { (unsigned char)i, (unsigned char)(i >> 8), 0x42, 0x43 };
        while (ud_sendto(p->from, p->to, m, 4) != 4) Sleep(1);
        if ((i % 16) == 15) Sleep(1);
    }
    InterlockedExchange(&p->done, 1);
    return 0;
}

TEST(udp_threaded_producer_delivers_in_order) {
    ud_ep a, b; prod_t p; HANDLE h; int got = 0, last = -1, bad = 0;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ud_setint(b.s, SOL_SOCKET, SO_RCVBUF, 1 << 20);
    p.from = &a; p.to = &b; p.n = 400; p.done = 0;
    h = CreateThread(NULL, 0, producer, &p, 0, NULL);
    CHECK(h != NULL);
    while (got < 400) {
        unsigned char m[8]; int r = ud_recv_to(b.s, m, sizeof m, 0, NULL, NULL, 3000), seq;
        if (r != 4) break;
        seq = m[0] | (m[1] << 8);
        if (seq <= last || m[2] != 0x42 || m[3] != 0x43) bad++;
        last = seq; got++;
    }
    if (h) { WaitForSingleObject(h, 5000); CloseHandle(h); }
    EXPECT_EQ(bad, 0);
    CHECK(got >= 1);
    t_note("producer received all=%d", got == 400);
    ud_free(&a); ud_free(&b);
}

/* ---- several posted overlapped receives ---- */

TEST(udp_posted_overlapped_receives_complete_in_posting_order) {
    ud_ep a, b; WSAOVERLAPPED ov[3]; WSABUF wb[3]; char buf[3][8]; DWORD got, fl; int i, ok = 1;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < 3; i++) {
        memset(&ov[i], 0, sizeof ov[i]);
        ov[i].hEvent = U(WSACreateEvent)();
        wb[i].buf = buf[i]; wb[i].len = sizeof buf[i];
        got = 0; fl = 0;
        if (U(WSARecvFrom)(b.s, &wb[i], 1, &got, &fl, NULL, NULL, &ov[i], NULL) != SOCKET_ERROR || ud_err() != WSA_IO_PENDING) ok = 0;
    }
    EXPECT_EQ(ok, 1);
    CHECK(ud_sendto(&a, &b, "one", 3) == 3);
    CHECK(ud_sendto(&a, &b, "two", 3) == 3);
    CHECK(ud_sendto(&a, &b, "three", 5) == 5);
    for (i = 0; i < 3; i++) {
        DWORD x = 0, xf = 0; static const char *want[3] = { "one", "two", "three" };
        if (U(WaitForSingleObject)(ov[i].hEvent, 3000) != WAIT_OBJECT_0) { CHECKF(0, "receive %d never completed", i); continue; }
        CHECK(U(WSAGetOverlappedResult)(b.s, &ov[i], &x, FALSE, &xf));
        EXPECT_EQ(x, strlen(want[i]));
        CHECK(!memcmp(buf[i], want[i], strlen(want[i])));
    }
    for (i = 0; i < 3; i++) U(WSACloseEvent)(ov[i].hEvent);
    ud_free(&a); ud_free(&b);
}

TEST(udp_close_cancels_all_posted_receives) {
    ud_ep a, b; WSAOVERLAPPED ov[3]; WSABUF wb; char buf[8]; DWORD got, fl; int i, done = 0;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < 3; i++) {
        memset(&ov[i], 0, sizeof ov[i]);
        ov[i].hEvent = U(WSACreateEvent)();
        wb.buf = buf; wb.len = sizeof buf; got = 0; fl = 0;
        CHECK(U(WSARecvFrom)(b.s, &wb, 1, &got, &fl, NULL, NULL, &ov[i], NULL) == SOCKET_ERROR && ud_err() == WSA_IO_PENDING);
    }
    ud_free(&b);
    for (i = 0; i < 3; i++) if (U(WaitForSingleObject)(ov[i].hEvent, 3000) == WAIT_OBJECT_0) done++;
    EXPECT_EQ(done, 3);
    for (i = 0; i < 3; i++) U(WSACloseEvent)(ov[i].hEvent);
    ud_free(&a);
}

/* ---- WSARecvFrom address-length protocol ---- */

TEST(udp_wsarecvfrom_address_without_length_is_efault) {
    ud_ep a, b; struct sockaddr_storage from; WSABUF rb; DWORD got = 0, fl = 0; char c; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = &c; rb.len = 1;
    ud_seterr(0);
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, (struct sockaddr *)&from, NULL, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_drain(b.s, 200);
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_short_address_length_is_efault) {
    ud_ep a, b; struct sockaddr_storage from; WSABUF rb; DWORD got = 0, fl = 0; char c; int r, fl2 = 8;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = &c; rb.len = 1;
    ud_seterr(0);
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, (struct sockaddr *)&from, &fl2, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_drain(b.s, 200);
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_without_address_ignores_length) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0; char c; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = &c; rb.len = 1;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_reports_address_and_length) {
    ud_ep a, b; struct sockaddr_storage from; WSABUF rb; DWORD got = 0, fl = 0; char c; int r, fl2 = sizeof from;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "x", 1) == 1);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = &c; rb.len = 1;
    memset(&from, 0, sizeof from);
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, (struct sockaddr *)&from, &fl2, NULL, NULL);
    EXPECT_EQ(r, 0);
    CHECK(ud_sameaddr(&a, &from, fl2));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecv_on_unconnected_bound_socket_reads_datagram) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "plain", 5) == 5);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecv)(b.s, &rb, 1, &got, &fl, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 5);
    ud_free(&a); ud_free(&b);
}

TEST(udp_so_type_and_max_msg_size_describe_datagram_socket) {
    SOCKET s; int t = 0, m = 0;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(ud_getint(s, SOL_SOCKET, SO_TYPE, &t) == 0);
    EXPECT_EQ(t, SOCK_DGRAM);
    CHECK(ud_getint(s, SOL_SOCKET, SO_MAX_MSG_SIZE, &m) == 0);
    CHECK(m > 0);
    ud_close(s);
}
