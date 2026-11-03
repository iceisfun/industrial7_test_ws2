/* Receive-buffer-too-small behaviour of UDP datagram sockets: WSAEMSGSIZE, how many bytes land in
 * the buffer, that the rest of the datagram is discarded (no MSG_PARTIAL remainder), that the next
 * datagram is intact, MSG_PEEK interaction, scatter buffers, and the overlapped completion status.
 * Table driven over datagram size and buffer size. */
#include "ud.h"

/* One datagram of dg bytes received into a buf-byte buffer (buf < dg): the call fails with
 * WSAEMSGSIZE, the first buf bytes are delivered, and nothing of the datagram remains queued. */
static const struct { int dg, buf; } k_trunc[] = {
    { 2, 1 }, { 3, 2 }, { 4, 3 }, { 10, 9 }, { 10, 5 }, { 10, 1 }, { 10, 0 },
    { 16, 15 }, { 64, 32 }, { 100, 99 }, { 512, 511 }, { 1024, 1 }, { 1024, 1023 },
    { 1472, 1471 }, { 4096, 4095 }, { 4096, 2048 }, { 9000, 8999 }, { 30000, 1 }, { 60000, 59999 }, { 65507, 65506 },
};

static void trunc_case(int af, int dg, int buf) {
    ud_ep a, b; static unsigned char tx[65536], rx[65536]; int r, e;
    if (!ud_pair(&a, &b, af)) return;
    ud_fill(tx, dg, dg + buf);
    memset(rx, 0xCC, sizeof rx);
    r = ud_sendto(&a, &b, tx, dg);
    CHECKF(r == dg, "send %d gave %d err %d", dg, r, ud_err());
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recvfrom)(b.s, (char *)rx, buf, 0, NULL, NULL);
    e = ud_err();
    CHECKF(r == SOCKET_ERROR && e == WSAEMSGSIZE, "dg=%d buf=%d r=%d err=%d", dg, buf, r, e);
    CHECKF(ud_same(rx, buf, dg + buf), "dg=%d buf=%d delivered prefix differs", dg, buf);
    CHECKF(rx[buf] == 0xCC, "dg=%d buf=%d wrote past the buffer", dg, buf);
    CHECKF(!ud_ready(b.s, 100), "dg=%d buf=%d remainder still queued", dg, buf);
    ud_free(&a); ud_free(&b);
}

TEST(udp_truncation_matrix_ipv4) {
    unsigned i;
    UP();
    for (i = 0; i < sizeof k_trunc / sizeof *k_trunc; i++) trunc_case(AF_INET, k_trunc[i].dg, k_trunc[i].buf);
}

TEST(udp_truncation_matrix_ipv6) {
    unsigned i;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    for (i = 0; i < sizeof k_trunc / sizeof *k_trunc; i++)
        if (k_trunc[i].dg <= 32768) trunc_case(AF_INET6, k_trunc[i].dg, k_trunc[i].buf);
}

/* A buffer that is exactly large enough, or larger, does not fail. */
TEST(udp_exact_fit_and_larger_buffers_succeed) {
    static const int dg[] = { 1, 5, 64, 1000, 8000 };
    unsigned i;
    UP();
    for (i = 0; i < sizeof dg / sizeof *dg; i++) {
        int pad;
        for (pad = 0; pad <= 1; pad++) {
            ud_ep a, b; unsigned char tx[8000], rx[8100]; int r;
            if (!ud_pair(&a, &b, AF_INET)) return;
            ud_fill(tx, dg[i], 9);
            CHECK(ud_sendto(&a, &b, tx, dg[i]) == dg[i]);
            r = ud_recv_to(b.s, rx, dg[i] + pad * 50, 0, NULL, NULL, 3000);
            CHECKF(r == dg[i], "dg=%d pad=%d r=%d err=%d", dg[i], pad * 50, r, ud_err());
            ud_free(&a); ud_free(&b);
        }
    }
}

TEST(udp_truncated_datagram_is_consumed_next_one_is_intact) {
    ud_ep a, b; char buf[16]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    CHECK(ud_sendto(&a, &b, "second", 6) == 6);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recv)(b.s, buf, 4, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!memcmp(buf, "0123", 4));
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 6);
    CHECK(!memcmp(buf, "second", 6));
    ud_free(&a); ud_free(&b);
}

TEST(udp_truncation_repeats_for_each_oversized_datagram) {
    ud_ep a, b; char buf[2]; int i, bad = 0;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < 6; i++) CHECK(ud_sendto(&a, &b, "abcdef", 6) == 6);
    for (i = 0; i < 6; i++) {
        int r;
        CHECK(ud_ready(b.s, 3000));
        ud_seterr(0);
        r = U(recv)(b.s, buf, sizeof buf, 0);
        if (r != SOCKET_ERROR || ud_err() != WSAEMSGSIZE || buf[0] != 'a' || buf[1] != 'b') bad++;
    }
    EXPECT_EQ(bad, 0);
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_truncation_error_is_per_call_not_sticky) {
    ud_ep a, b; char buf[2], big[16]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "abcdef", 6) == 6);
    CHECK(ud_ready(b.s, 3000));
    r = U(recv)(b.s, buf, sizeof buf, 0);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECK(ud_sendto(&a, &b, "ok", 2) == 2);
    ud_seterr(0);
    r = ud_recv_to(b.s, big, sizeof big, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 2); EXPECT_EQ(ud_err(), 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_truncation_does_not_set_so_error) {
    ud_ep a, b; char buf[2]; int e = 77, r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "abcdef", 6) == 6);
    CHECK(ud_ready(b.s, 3000));
    r = U(recv)(b.s, buf, sizeof buf, 0);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(ud_getint(b.s, SOL_SOCKET, SO_ERROR, &e), 0);
    EXPECT_EQ(e, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_truncated_receive_still_reports_sender_address_note) {
    ud_ep a, b; struct sockaddr_storage from; int fl = sizeof from, r; char buf[2];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    memset(&from, 0, sizeof from);
    CHECK(ud_sendto(&a, &b, "abcdef", 6) == 6);
    CHECK(ud_ready(b.s, 3000));
    r = U(recvfrom)(b.s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    t_note("sender address on a truncated receive: len=%d matches=%d", fl, ud_sameaddr(&a, &from, fl));
    ud_free(&a); ud_free(&b);
}

/* ---- zero-length receive buffer ---- */

TEST(udp_zero_length_buffer_for_data_datagram_is_msgsize) {
    ud_ep a, b; char c; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "xyz", 3) == 3);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recv)(b.s, &c, 0, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!ud_ready(b.s, 100));                 /* the datagram is discarded */
    ud_free(&a); ud_free(&b);
}

TEST(udp_zero_length_buffer_peek_keeps_datagram) {
    ud_ep a, b; char c, buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "xyz", 3) == 3);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recv)(b.s, &c, 0, MSG_PEEK);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 3);
    ud_free(&a); ud_free(&b);
}

/* ---- MSG_PEEK with a small buffer ---- */

TEST(udp_peek_truncated_keeps_datagram_for_full_read) {
    ud_ep a, b; char small[4], big[32]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    CHECK(ud_ready(b.s, 3000));
    ud_seterr(0);
    r = U(recv)(b.s, small, sizeof small, MSG_PEEK);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!memcmp(small, "0123", 4));
    r = ud_recv_to(b.s, big, sizeof big, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 10);
    CHECK(!memcmp(big, "0123456789", 10));
    ud_free(&a); ud_free(&b);
}

TEST(udp_peek_truncated_twice_then_consumed_by_small_read) {
    ud_ep a, b; char small[3]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "ABCDEFGH", 8) == 8);
    CHECK(ud_ready(b.s, 3000));
    r = U(recv)(b.s, small, sizeof small, MSG_PEEK); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    r = U(recv)(b.s, small, sizeof small, MSG_PEEK); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    r = U(recv)(b.s, small, sizeof small, 0);        EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

/* ---- WSARecvFrom ---- */

TEST(udp_wsarecvfrom_truncation_reports_msgsize_and_zero_flags) {
    ud_ep a, b; WSABUF rb; DWORD got = 0xdeadbeef, fl = 0; char buf[4]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = buf; rb.len = sizeof buf;
    ud_seterr(0);
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!memcmp(buf, "0123", 4));
    EXPECT_EQ(fl & MSG_PARTIAL, 0);
    t_note("WSARecvFrom truncated: bytes=0x%lx flags=0x%lx", got, fl);
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecv_truncation_reports_msgsize) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0; char buf[4]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = buf; rb.len = sizeof buf;
    ud_seterr(0);
    r = U(WSARecv)(b.s, &rb, 1, &got, &fl, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    EXPECT_EQ(fl & MSG_PARTIAL, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_scatter_fills_buffers_in_order_on_truncation) {
    ud_ep a, b; WSABUF rb[3]; DWORD got = 0, fl = 0; char x[3], y[3], z[3]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    memset(x, '.', 3); memset(y, '.', 3); memset(z, '.', 3);
    CHECK(ud_sendto(&a, &b, "ABCDEFGHIJKL", 12) == 12);
    CHECK(ud_ready(b.s, 3000));
    rb[0].buf = x; rb[0].len = 3; rb[1].buf = y; rb[1].len = 3; rb[2].buf = z; rb[2].len = 3;
    ud_seterr(0);
    r = U(WSARecvFrom)(b.s, rb, 3, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!memcmp(x, "ABC", 3)); CHECK(!memcmp(y, "DEF", 3)); CHECK(!memcmp(z, "GHI", 3));
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_scatter_exact_fit_succeeds) {
    ud_ep a, b; WSABUF rb[2]; DWORD got = 0, fl = 0; char x[4], y[4]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "ABCDEFGH", 8) == 8);
    CHECK(ud_ready(b.s, 3000));
    rb[0].buf = x; rb[0].len = 4; rb[1].buf = y; rb[1].len = 4;
    r = U(WSARecvFrom)(b.s, rb, 2, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(got, 8);
    CHECK(!memcmp(x, "ABCD", 4)); CHECK(!memcmp(y, "EFGH", 4));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_scatter_with_empty_first_buffer) {
    ud_ep a, b; WSABUF rb[2]; DWORD got = 0, fl = 0; char y[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "PQRS", 4) == 4);
    CHECK(ud_ready(b.s, 3000));
    rb[0].buf = y; rb[0].len = 0; rb[1].buf = y; rb[1].len = sizeof y;
    r = U(WSARecvFrom)(b.s, rb, 2, &got, &fl, NULL, NULL, NULL, NULL);
    t_note("WSARecvFrom with a leading empty buffer: r=%d got=%lu err=%d", r, got, r ? ud_err() : 0);
    if (r == 0) { EXPECT_EQ(got, 4); CHECK(!memcmp(y, "PQRS", 4)); }
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsarecvfrom_msg_partial_input_flag_note) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = MSG_PARTIAL; char buf[4]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    CHECK(ud_ready(b.s, 3000));
    rb.buf = buf; rb.len = sizeof buf;
    ud_seterr(0);
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    t_note("MSG_PARTIAL receive of an oversized datagram: r=%d err=%d got=%lu flags=0x%lx", r, r ? ud_err() : 0, got, fl);
    ud_drain(b.s, 100);
    ud_free(&a); ud_free(&b);
}

/* ---- overlapped completion of a truncated receive ---- */

TEST(udp_overlapped_truncated_receive_completes_with_buffer_overflow) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0, xfer = 0xdeadbeef, xfl = 0; char buf[4]; int r, ok;
    WSAOVERLAPPED ov; WSAEVENT ev;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ev = U(WSACreateEvent)();
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, &ov, NULL);
    CHECK(r == SOCKET_ERROR && ud_err() == WSA_IO_PENDING);
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    EXPECT_EQ(U(WaitForSingleObject)(ev, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((unsigned)(ov.Internal & 0xffffffffu), 0x80000005u);
    ud_seterr(0);
    ok = U(WSAGetOverlappedResult)(b.s, &ov, &xfer, FALSE, &xfl);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!memcmp(buf, "0123", 4));
    t_note("overlapped truncated: transferred=%lu flags=0x%lx", xfer, xfl);
    U(WSACloseEvent)(ev);
    ud_free(&a); ud_free(&b);
}

TEST(udp_overlapped_exact_receive_completes_with_success) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0, xfer = 0, xfl = 0; char buf[10]; int r, ok;
    WSAOVERLAPPED ov; WSAEVENT ev;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ev = U(WSACreateEvent)();
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, &ov, NULL);
    CHECK(r == SOCKET_ERROR && ud_err() == WSA_IO_PENDING);
    CHECK(ud_sendto(&a, &b, "0123456789", 10) == 10);
    EXPECT_EQ(U(WaitForSingleObject)(ev, 3000), WAIT_OBJECT_0);
    ok = U(WSAGetOverlappedResult)(b.s, &ov, &xfer, FALSE, &xfl);
    EXPECT_EQ(ok, TRUE); EXPECT_EQ(xfer, 10); EXPECT_EQ(xfl, 0);
    U(WSACloseEvent)(ev);
    ud_free(&a); ud_free(&b);
}

TEST(udp_overlapped_zero_length_datagram_completes_with_zero_bytes) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0, xfer = 77, xfl = 0; char buf[10]; int r, ok;
    WSAOVERLAPPED ov; WSAEVENT ev;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ev = U(WSACreateEvent)();
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, &ov, NULL);
    CHECK(r == SOCKET_ERROR && ud_err() == WSA_IO_PENDING);
    CHECK(ud_sendto(&a, &b, "", 0) == 0);
    EXPECT_EQ(U(WaitForSingleObject)(ev, 3000), WAIT_OBJECT_0);
    ok = U(WSAGetOverlappedResult)(b.s, &ov, &xfer, FALSE, &xfl);
    EXPECT_EQ(ok, TRUE); EXPECT_EQ(xfer, 0);
    U(WSACloseEvent)(ev);
    ud_free(&a); ud_free(&b);
}

TEST(udp_overlapped_receive_cancelled_by_close_completes_aborted) {
    ud_ep a, b; WSABUF rb; DWORD got = 0, fl = 0, xfer = 0, xfl = 0; char buf[10]; int r, ok;
    WSAOVERLAPPED ov; WSAEVENT ev;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ev = U(WSACreateEvent)();
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    rb.buf = buf; rb.len = sizeof buf;
    r = U(WSARecvFrom)(b.s, &rb, 1, &got, &fl, NULL, NULL, &ov, NULL);
    CHECK(r == SOCKET_ERROR && ud_err() == WSA_IO_PENDING);
    ud_free(&b);
    EXPECT_EQ(U(WaitForSingleObject)(ev, 3000), WAIT_OBJECT_0);
    ud_seterr(0);
    ok = U(WSAGetOverlappedResult)(a.s, &ov, &xfer, FALSE, &xfl);
    t_note("pending UDP receive after closesocket: ok=%d err=%d status=0x%x", ok, ok ? 0 : ud_err(), (unsigned)ov.Internal);
    U(WSACloseEvent)(ev);
    ud_free(&a);
}
