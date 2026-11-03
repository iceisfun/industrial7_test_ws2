/* Datagram transfers over loopback with RIOSendEx / RIOReceive / RIOReceiveEx / RIOSend and the completion
 * results that come back through RIODequeueCompletion.
 *
 * Measured on Windows 10: a completion carries the NT-style status already translated to a Winsock error
 * (0, WSAEMSGSIZE for a truncated or oversized datagram, WSAEINVAL for descriptor problems found at execution
 * time, WSA_OPERATION_ABORTED (995) for requests cancelled by closesocket), the byte count, and the 64-bit socket
 * and request contexts verbatim. Completions of one queue and one kind are FIFO. A datagram address buffer must
 * be at least sizeof(SOCKADDR_INET) (28 bytes) for the Ex calls; only the family-sized prefix (16 bytes for
 * IPv4) is written. */
#include "rio.h"

TEST(rio_udp_roundtrip_completions_and_data)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    memcpy(p.mem + PR_SEND, "hello", 5);
    CHECK(pair_recv(&p, PR_RECV, 64, RQV(1), 0));
    EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 2), 0);       /* nothing yet */
    CHECK(pair_send(&p, PR_SEND, 5, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 5);
    EXPECT_EQ(r[0].SocketContext, CTX_B); EXPECT_EQ(r[0].RequestContext, RQV(1));
    CHECK(!memcmp(p.mem + PR_RECV, "hello", 5));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 5);
    EXPECT_EQ(r[0].SocketContext, CTX_A); EXPECT_EQ(r[0].RequestContext, RQV(2));
    pair_close(&p);
}
TEST(rio_udp_payload_size_matrix)
{
    static const ULONG sizes[] = {1, 2, 7, 100, 1472, 4096, 8000};
    NEED_PAIR(p, t, 4);
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        RIORES r[2]; ULONG n = sizes[i];
        for (ULONG k = 0; k < n; k++) p.mem[PR_SEND + k] = (char)(k * 7 + i);
        memset(p.mem + PR_RECV, 0, 0x4000);
        CHECK(pair_recv(&p, PR_RECV, 0x4000, RQV(i), 0));
        CHECK(pair_send(&p, PR_SEND, n, RQV(100 + i), 0));
        EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
        EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, n); EXPECT_EQ(r[0].RequestContext, RQV(i));
        CHECKF(!memcmp(p.mem + PR_SEND, p.mem + PR_RECV, n), "size %lu payload", n);
        EXPECT_EQ(p.mem[PR_RECV + n], 0);
        EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
        EXPECT_EQ(r[0].BytesTransferred, n); EXPECT_EQ(r[0].RequestContext, RQV(100 + i));
    }
    pair_close(&p);
}
TEST(rio_udp_receive_does_not_touch_bytes_outside_its_descriptor)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    memset(p.mem + PR_RECV, 0x5A, 0x100);
    memcpy(p.mem + PR_SEND, "abcdef", 6);
    CHECK(pair_recv(&p, PR_RECV + 0x10, 32, RQV(1), 0));
    CHECK(pair_send(&p, PR_SEND, 6, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 6);
    CHECK(!memcmp(p.mem + PR_RECV + 0x10, "abcdef", 6));
    EXPECT_EQ((unsigned char)p.mem[PR_RECV + 0x0f], 0x5A);
    EXPECT_EQ((unsigned char)p.mem[PR_RECV + 0x10 + 6], 0x5A);
    pair_close(&p);
}
TEST(rio_udp_receives_complete_in_posting_order)
{
    RIORES r[4];
    NEED_PAIR(p, t, 4);
    for (int i = 0; i < 3; i++) CHECK(pair_recv(&p, PR_RECV + i * 0x100, 16, RQV(10 + i), 0));
    for (int i = 0; i < 3; i++) { p.mem[PR_SEND + i] = (char)('A' + i); CHECK(pair_send(&p, PR_SEND + i, 1, RQV(20 + i), 0)); }
    EXPECT_EQ(rio_wait(t, p.cqb, r, 4, 3), 3);
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(r[i].RequestContext, RQV(10 + i)); EXPECT_EQ(r[i].BytesTransferred, 1);
        EXPECT_EQ(p.mem[PR_RECV + i * 0x100], 'A' + i);
    }
    EXPECT_EQ(rio_wait(t, p.cqa, r, 4, 3), 3);
    for (int i = 0; i < 3; i++) EXPECT_EQ(r[i].RequestContext, RQV(20 + i));
    pair_close(&p);
}
TEST(rio_udp_dequeue_array_size_limits_the_batch)
{
    RIORES r[8];
    NEED_PAIR(p, t, 4);
    for (int i = 0; i < 3; i++) CHECK(pair_recv(&p, PR_RECV + i * 0x100, 16, RQV(1 + i), 0));
    for (int i = 0; i < 3; i++) CHECK(pair_send(&p, PR_SEND, 2, RQV(50 + i), 0));
    Sleep(150);                                              /* all three completions are queued by now */
    EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 0), 0);        /* zero-sized array takes nothing */
    EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 2), 2);
    EXPECT_EQ(r[0].RequestContext, RQV(1)); EXPECT_EQ(r[1].RequestContext, RQV(2));
    EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 8), 1);
    EXPECT_EQ(r[0].RequestContext, RQV(3));
    EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 8), 0);
    pair_close(&p);
}
TEST(rio_udp_truncated_datagram_completes_with_emsgsize)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    memcpy(p.mem + PR_SEND, "0123456789", 10);
    memset(p.mem + PR_RECV, 'x', 16);
    CHECK(pair_recv(&p, PR_RECV, 4, RQV(1), 0));
    CHECK(pair_send(&p, PR_SEND, 10, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, WSAEMSGSIZE); EXPECT_EQ(r[0].BytesTransferred, 4);
    CHECK(!memcmp(p.mem + PR_RECV, "0123xxxx", 8));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 10);   /* the sender is not told */
    pair_close(&p);
}
TEST(rio_udp_zero_length_datagram_is_delivered)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    CHECK(pair_send(&p, PR_SEND, 0, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(1));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0);
    pair_close(&p);
}
TEST(rio_udp_connected_send_and_count_zero_requests)
{
    RIORES r[2]; RIO_BUF s5, none;
    NEED_PAIR(p, t, 4);
    EXPECT_EQ(connect(p.a, (struct sockaddr *)&p.ba, sizeof p.ba), 0);
    memcpy(p.mem + PR_SEND, "hello", 5);
    s5.BufferId = p.id; s5.Offset = PR_SEND; s5.Length = 5;
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    CHECK(t->Send(p.ra, &s5, 1, 0, RQC(2)));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 5); CHECK(!memcmp(p.mem + PR_RECV, "hello", 5));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 5);
    /* a request with count 0 and no descriptor is a zero-length datagram */
    memset(&none, 0, sizeof none);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(3), 0));
    CHECK(t->Send(p.ra, NULL, 0, 0, RQC(4)));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(3));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(4));
    pair_close(&p);
}
TEST(rio_udp_count_zero_ignores_a_descriptor)
{
    RIORES r[2]; RIO_BUF s5;
    NEED_PAIR(p, t, 4);
    EXPECT_EQ(connect(p.a, (struct sockaddr *)&p.ba, sizeof p.ba), 0);
    s5.BufferId = p.id; s5.Offset = PR_SEND; s5.Length = 5;
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    CHECK(t->Send(p.ra, &s5, 0, 0, RQC(2)));                 /* count 0: the descriptor is not looked at */
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0);
    pair_close(&p);
}

TEST(rio_udp_receiveex_reports_both_addresses)
{
    RIORES r[2]; RIO_BUF d, la, rem; struct sockaddr_in *x;
    NEED_PAIR(p, t, 4);
    memset(p.mem + PR_LOC, 0xEE, 0x200);
    d.BufferId = la.BufferId = rem.BufferId = p.id; d.Offset = PR_RECV; d.Length = 16;
    la.Offset = PR_LOC; la.Length = 28; rem.Offset = PR_REM; rem.Length = 28;
    memcpy(p.mem + PR_SEND, "ping", 4);
    CHECK(t->ReceiveEx(p.rb, &d, 1, &la, &rem, NULL, NULL, 0, RQC(1)));
    CHECK(pair_send(&p, PR_SEND, 4, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 4);
    x = (struct sockaddr_in *)(p.mem + PR_REM);
    EXPECT_EQ(x->sin_family, AF_INET); EXPECT_EQ(x->sin_port, p.aa.sin_port); EXPECT_EQ(x->sin_addr.s_addr, RIO_LOOPBACK);
    x = (struct sockaddr_in *)(p.mem + PR_LOC);
    EXPECT_EQ(x->sin_family, AF_INET); EXPECT_EQ(x->sin_port, p.ba.sin_port); EXPECT_EQ(x->sin_addr.s_addr, RIO_LOOPBACK);
    EXPECT_EQ((unsigned char)p.mem[PR_REM + 27], 0xEE);      /* only the IPv4-sized prefix is written */
    EXPECT_EQ((unsigned char)p.mem[PR_LOC + 27], 0xEE);
    pair_close(&p);
}
TEST(rio_udp_receiveex_with_only_one_address)
{
    RIORES r[2]; RIO_BUF d, a1; struct sockaddr_in *x;
    NEED_PAIR(p, t, 4);
    d.BufferId = a1.BufferId = p.id; d.Offset = PR_RECV; d.Length = 16; a1.Offset = PR_REM; a1.Length = 28;
    memcpy(p.mem + PR_SEND, "ping", 4);
    memset(p.mem + PR_REM, 0, 28);
    CHECK(t->ReceiveEx(p.rb, &d, 1, NULL, &a1, NULL, NULL, 0, RQC(1)));       /* remote only */
    CHECK(pair_send(&p, PR_SEND, 4, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    x = (struct sockaddr_in *)(p.mem + PR_REM); EXPECT_EQ(x->sin_port, p.aa.sin_port);
    memset(p.mem + PR_LOC, 0, 28); a1.Offset = PR_LOC;
    CHECK(t->ReceiveEx(p.rb, &d, 1, &a1, NULL, NULL, NULL, 0, RQC(3)));       /* local only */
    CHECK(pair_send(&p, PR_SEND, 4, RQV(4), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    x = (struct sockaddr_in *)(p.mem + PR_LOC); EXPECT_EQ(x->sin_port, p.ba.sin_port);
    pair_close(&p);
}
TEST(rio_udp_address_buffer_length_matrix)
{
    static const struct { ULONG len; int ok; } m[] = {{0, 0}, {8, 0}, {16, 0}, {27, 0}, {28, 1}, {32, 1}, {64, 1}};
    NEED_PAIR(p, t, 8);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIO_BUF d = {p.id, PR_SEND, 4}, to = {p.id, PR_TOB, m[i].len}, rd = {p.id, PR_RECV, 16}, la = {p.id, PR_LOC, m[i].len}, rem = {p.id, PR_REM, m[i].len};
        BOOL r;
        WSASetLastError(0);
        r = t->SendEx(p.ra, &d, 1, NULL, &to, NULL, NULL, 0, RQC(1));
        CHECKF(!!r == m[i].ok, "SendEx remote length %lu", m[i].len);
        if (!m[i].ok) EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
        WSASetLastError(0);
        r = t->ReceiveEx(p.rb, &rd, 1, &la, &rem, NULL, NULL, 0, RQC(2));
        CHECKF(!!r == m[i].ok, "ReceiveEx address length %lu", m[i].len);
        if (!m[i].ok) EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
        WSASetLastError(0);
        r = t->ReceiveEx(p.rb, &rd, 1, &la, NULL, NULL, NULL, 0, RQC(3));
        CHECKF(!!r == m[i].ok, "ReceiveEx local-only length %lu", m[i].len);
        if (r) { RIORES rr[8]; rio_wait(t, p.cqb, rr, 8, 1); rio_wait(t, p.cqa, rr, 8, 1); }
    }
    pair_close(&p);
}
TEST(rio_udp_sendex_local_address_is_rejected)
{
    NEED_PAIR(p, t, 4);
    RIO_BUF d = {p.id, PR_SEND, 4}, to = {p.id, PR_TOB, 28}, loc = {p.id, PR_LOC, 28};
    WSASetLastError(0);
    CHECK(!t->SendEx(p.ra, &d, 1, &loc, &to, NULL, NULL, 0, RQC(1))); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0);
    CHECK(!t->SendEx(p.ra, &d, 1, &loc, NULL, NULL, NULL, 0, RQC(1))); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    pair_close(&p);
}
TEST(rio_udp_sendex_without_destination_completes_einval)
{
    RIORES r[2]; RIO_BUF d;
    NEED_PAIR(p, t, 4);
    d.BufferId = p.id; d.Offset = PR_SEND; d.Length = 4;
    CHECK(t->SendEx(p.ra, &d, 1, NULL, NULL, NULL, NULL, 0, RQC(1)));   /* accepted ... */
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);                         /* ... and failed when executed */
    EXPECT_EQ(r[0].Status, WSAEINVAL); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(1));
    pair_close(&p);
}
TEST(rio_udp_oversized_datagram_completes_with_emsgsize)
{
    static const ULONG lens[] = {65508, 65536};
    NEED_PAIR(p, t, 4);
    for (int i = 0; i < 2; i++) {
        RIORES r[2];
        CHECKF(pair_send(&p, 0, lens[i], RQV(i), 0), "length %lu accepted", lens[i]);
        EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
        EXPECT_EQ(r[0].Status, WSAEMSGSIZE); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(i));
    }
    pair_close(&p);
}
TEST(rio_udp_send_on_unbound_socket_completes_einval_and_stays_unbound)
{
    RIORES r[2]; RIO_BUF d, to; struct sockaddr_in x; int l = sizeof x;
    NEED_PAIR(p, t, 4);
    SOCKET u = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    RIO_RQ ru = t->CreateRequestQueue(u, 2, 1, 2, 1, p.cqa, p.cqa, (PVOID)(ULONG_PTR)CTX_A);
    CHECK(ru != NULL);
    d.BufferId = to.BufferId = p.id; d.Offset = PR_SEND; d.Length = 4; to.Offset = PR_TOB; to.Length = 28;
    CHECK(t->SendEx(ru, &d, 1, NULL, &to, NULL, NULL, 0, RQC(1)));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, WSAEINVAL);
    WSASetLastError(0);
    EXPECT_EQ(getsockname(u, (struct sockaddr *)&x, &l), -1); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);   /* still not bound */
    closesocket(u); pair_close(&p);
}
TEST(rio_udp_receive_on_unbound_socket_posts_and_aborts_on_close)
{
    RIORES r[2]; RIO_BUF d;
    NEED_PAIR(p, t, 4);
    SOCKET u = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    RIO_RQ ru = t->CreateRequestQueue(u, 2, 1, 2, 1, p.cqa, p.cqa, (PVOID)(ULONG_PTR)CTX_A);
    d.BufferId = p.id; d.Offset = PR_RECV; d.Length = 16;
    CHECK(t->Receive(ru, &d, 1, 0, RQC(1)));
    rio_settle(); EXPECT_EQ(t->DequeueCompletion(p.cqa, r, 2), 0);
    closesocket(u);
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 995); EXPECT_EQ(r[0].RequestContext, RQV(1));
    pair_close(&p);
}

/* Descriptors the library cannot check when the request is queued are reported in the completion. */
TEST(rio_udp_send_bad_descriptor_completes_einval)
{
    NEED_PAIR(p, t, 4);
    char *tiny = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID dead = t->RegisterBuffer(tiny, 16);
    static const struct { const char *n; int id; ULONG off, len; LONG status; ULONG bytes; } m[] = {
        {"valid", 0, 0, 16, 0, 16},
        {"length past the region", 0, 0x1ff00, 0x200, WSAEINVAL, 0},
        {"offset past the region", 0, 0x30000, 1, WSAEINVAL, 0},
        {"offset at the end, length 1", 0, 0x20000, 1, WSAEINVAL, 0},
        {"offset at the end, length 0", 0, 0x20000, 0, 0, 0},
        {"offset plus length wraps", 0, 0xfffffff0, 0x20, WSAEINVAL, 0},
        {"deregistered id", 1, 0, 4, WSAEINVAL, 0},
    };
    t->DeregisterBuffer(dead);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIORES r[2]; RIO_BUF d, to;
        d.BufferId = m[i].id ? dead : p.id; d.Offset = m[i].off; d.Length = m[i].len;
        to.BufferId = p.id; to.Offset = PR_TOB; to.Length = 28;
        CHECKF(t->SendEx(p.ra, &d, 1, NULL, &to, NULL, NULL, 0, RQC(i)), "%s: posted", m[i].n);
        EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
        CHECKF(r[0].Status == m[i].status && r[0].BytesTransferred == m[i].bytes, "%s: status %ld bytes %lu", m[i].n, r[0].Status, r[0].BytesTransferred);
        EXPECT_EQ(r[0].RequestContext, RQV(i));
    }
    pair_close(&p);
    VirtualFree(tiny, 0, MEM_RELEASE);
}
TEST(rio_udp_two_registrations_one_transfer)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    char *other = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID id2 = t->RegisterBuffer(other + 3, 0x1000);            /* odd start: no alignment is needed */
    RIO_BUF d, to;
    CHECK(id2 != RIO_INVALID_BUFFERID);
    memcpy(p.mem + PR_SEND, "twice", 5);
    d.BufferId = id2; d.Offset = 8; d.Length = 16;
    CHECK(t->Receive(p.rb, &d, 1, 0, RQC(1)));
    CHECK(pair_send(&p, PR_SEND, 5, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 5); CHECK(!memcmp(other + 3 + 8, "twice", 5));
    /* and the other way round: send out of the second registration */
    memcpy(other + 3 + 100, "back!", 5);
    to.BufferId = p.id; to.Offset = PR_TOA; to.Length = 28;
    d.BufferId = id2; d.Offset = 100; d.Length = 5;
    CHECK(t->Receive(p.ra, &(RIO_BUF){p.id, PR_RECV, 16}, 1, 0, RQC(3)));
    CHECK(t->SendEx(p.rb, &d, 1, NULL, &to, NULL, NULL, 0, RQC(4)));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 2), 2);          /* the first send's completion is still queued, then the new receive */
    EXPECT_EQ(r[0].RequestContext, RQV(2)); EXPECT_EQ(r[1].RequestContext, RQV(3));
    CHECK(!memcmp(p.mem + PR_RECV, "back!", 5));
    pair_close(&p); t->DeregisterBuffer(id2); VirtualFree(other, 0, MEM_RELEASE);
}
TEST(rio_udp_waitall_on_a_datagram_receive_completes_with_the_datagram)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    memcpy(p.mem + PR_SEND, "dgram", 5);
    CHECK(pair_recv(&p, PR_RECV, 64, RQV(1), RIO_MSG_WAITALL));
    CHECK(pair_send(&p, PR_SEND, 5, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 5);
    pair_close(&p);
}
TEST(rio_udp_many_roundtrips)
{
    NEED_PAIR(p, t, 4);
    for (int i = 0; i < 100; i++) {
        RIORES r[2]; char msg[16]; int n = sprintf(msg, "msg-%03d", i);
        memcpy(p.mem + PR_SEND, msg, n);
        CHECK(pair_recv(&p, PR_RECV, 32, RQV(i), 0));
        CHECK(pair_send(&p, PR_SEND, n, RQV(1000 + i), 0));
        if (rio_wait(t, p.cqb, r, 2, 1) != 1 || rio_wait(t, p.cqa, r + 1, 1, 1) != 1) { CHECK(0); break; }
        if (r[0].RequestContext != RQV(i) || r[0].BytesTransferred != (ULONG)n || memcmp(p.mem + PR_RECV, msg, n)) { CHECKF(0, "round %d", i); break; }
    }
    pair_close(&p);
}
TEST(rio_udp_two_sockets_share_one_completion_queue)
{
    RIORES r[8]; RIO_BUF d, to; int seen_a = 0, seen_b = 0;
    NEED_PAIR(p, t, 4);
    RIO_CQ shared = t->CreateCompletionQueue(16, NULL);
    SOCKET x = rio_ubind(NULL), y = rio_ubind(NULL); struct sockaddr_in yy; int l = sizeof yy;
    RIO_RQ rx, ry;
    getsockname(y, (struct sockaddr *)&yy, &l);
    rx = t->CreateRequestQueue(x, 2, 1, 2, 1, shared, shared, (PVOID)(ULONG_PTR)CTX_A);
    ry = t->CreateRequestQueue(y, 2, 1, 2, 1, shared, shared, (PVOID)(ULONG_PTR)CTX_B);
    CHECK(rx && ry);
    memcpy(p.mem + PR_TOB, &yy, sizeof yy);
    d.BufferId = to.BufferId = p.id; d.Offset = PR_RECV; d.Length = 16;
    CHECK(t->Receive(ry, &d, 1, 0, RQC(1)));
    d.Offset = PR_SEND; d.Length = 3; to.Offset = PR_TOB; to.Length = 28;
    CHECK(t->SendEx(rx, &d, 1, NULL, &to, NULL, NULL, 0, RQC(2)));
    EXPECT_EQ(rio_wait(t, shared, r, 8, 2), 2);
    for (int i = 0; i < 2; i++) {
        if (r[i].SocketContext == CTX_A && r[i].RequestContext == RQV(2)) seen_a++;
        if (r[i].SocketContext == CTX_B && r[i].RequestContext == RQV(1)) seen_b++;
    }
    EXPECT_EQ(seen_a, 1); EXPECT_EQ(seen_b, 1);
    closesocket(x); closesocket(y); t->CloseCompletionQueue(shared);
    pair_close(&p);
}
TEST(rio_udp_ipv6_roundtrip_reports_v6_addresses)
{
    NEED_RIO(t);
    SOCKET a = rio_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, RIO_FL), b = rio_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    struct sockaddr_in6 aa, ba; int l = sizeof aa; RIORES r[2];
    memset(&aa, 0, sizeof aa); aa.sin6_family = AF_INET6; aa.sin6_addr.s6_addr[15] = 1; ba = aa;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET || bind(a, (struct sockaddr *)&aa, sizeof aa) || bind(b, (struct sockaddr *)&ba, sizeof ba)) {
        if (a != INVALID_SOCKET) closesocket(a);
        if (b != INVALID_SOCKET) closesocket(b);
        t_skip("IPv6 loopback unavailable"); return;
    }
    getsockname(a, (struct sockaddr *)&aa, &l); l = sizeof ba; getsockname(b, (struct sockaddr *)&ba, &l);
    RIO_CQ cqa = t->CreateCompletionQueue(8, NULL), cqb = t->CreateCompletionQueue(8, NULL);
    RIO_RQ ra = t->CreateRequestQueue(a, 2, 1, 2, 1, cqa, cqa, (PVOID)(ULONG_PTR)CTX_A), rb = t->CreateRequestQueue(b, 2, 1, 2, 1, cqb, cqb, (PVOID)(ULONG_PTR)CTX_B);
    char *mem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID id = t->RegisterBuffer(mem, 0x1000);
    RIO_BUF d = {id, 0x200, 16}, s = {id, 0, 4}, to = {id, 0x100, 28}, loc = {id, 0x300, 28}, rem = {id, 0x400, 28};
    struct sockaddr_in6 *x;
    CHECK(ra && rb && id != RIO_INVALID_BUFFERID);
    memcpy(mem, "six!", 4); memcpy(mem + 0x100, &ba, sizeof ba);
    CHECK(t->ReceiveEx(rb, &d, 1, &loc, &rem, NULL, NULL, 0, RQC(1)));
    CHECK(t->SendEx(ra, &s, 1, NULL, &to, NULL, NULL, 0, RQC(2)));
    EXPECT_EQ(rio_wait(t, cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 4);
    CHECK(!memcmp(mem + 0x200, "six!", 4));
    x = (struct sockaddr_in6 *)(mem + 0x400); EXPECT_EQ(x->sin6_family, AF_INET6); EXPECT_EQ(x->sin6_port, aa.sin6_port); EXPECT_EQ(x->sin6_addr.s6_addr[15], 1);
    x = (struct sockaddr_in6 *)(mem + 0x300); EXPECT_EQ(x->sin6_family, AF_INET6); EXPECT_EQ(x->sin6_port, ba.sin6_port);
    closesocket(a); closesocket(b); t->DeregisterBuffer(id); t->CloseCompletionQueue(cqa); t->CloseCompletionQueue(cqb);
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(rio_udp_close_aborts_pending_receives)
{
    RIORES r[4];
    NEED_PAIR(p, t, 4);
    for (int i = 0; i < 3; i++) CHECK(pair_recv(&p, PR_RECV + i * 0x100, 16, RQV(1 + i), 0));
    rio_settle(); EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 4), 0);
    closesocket(p.b); p.b = INVALID_SOCKET;
    EXPECT_EQ(rio_wait(t, p.cqb, r, 4, 3), 3);
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(r[i].Status, 995); EXPECT_EQ(r[i].BytesTransferred, 0); EXPECT_EQ(r[i].SocketContext, CTX_B); EXPECT_EQ(r[i].RequestContext, RQV(1 + i));
    }
    pair_close(&p);
}
TEST(rio_udp_deregister_with_pending_receive_does_not_hang)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    t->DeregisterBuffer(p.id); p.id = RIO_INVALID_BUFFERID;
    closesocket(p.b); p.b = INVALID_SOCKET;
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 995);
    pair_close(&p);
}
TEST(rio_udp_outstanding_limit_is_enobufs)
{
    RIORES r[8];
    NEED_PAIR(p, t, 2);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0)); CHECK(pair_recv(&p, PR_RECV + 0x100, 16, RQV(2), 0));
    WSASetLastError(0);
    CHECK(!pair_recv(&p, PR_RECV + 0x200, 16, RQV(3), 0)); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);
    /* the slot comes back after a completion */
    CHECK(pair_send(&p, PR_SEND, 1, RQV(10), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 8, 1), 1);
    CHECK(pair_recv(&p, PR_RECV + 0x200, 16, RQV(4), 0));
    pair_close(&p);
}
TEST(rio_udp_request_queue_resize_lets_more_requests_in)
{
    NEED_PAIR(p, t, 2);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0)); CHECK(pair_recv(&p, PR_RECV + 0x100, 16, RQV(2), 0));
    CHECK(!pair_recv(&p, PR_RECV + 0x200, 16, RQV(3), 0));
    CHECK(t->ResizeRequestQueue(p.rb, 3, 2));
    CHECK(pair_recv(&p, PR_RECV + 0x200, 16, RQV(3), 0));
    WSASetLastError(0);
    CHECK(!pair_recv(&p, PR_RECV + 0x300, 16, RQV(4), 0)); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);
    pair_close(&p);
}
TEST(rio_udp_receive_queue_depth_zero_takes_no_receive)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); SOCKET s = rio_ubind(NULL);
    RIO_RQ rq = t->CreateRequestQueue(s, 0, 1, 2, 1, cq, cq, NULL);
    char buf[16]; RIO_BUFFERID id = t->RegisterBuffer(buf, sizeof buf); RIO_BUF d = {id, 0, 16};
    CHECK(rq != NULL);
    WSASetLastError(0);
    CHECK(!t->Receive(rq, &d, 1, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);
    t->DeregisterBuffer(id); closesocket(s); t->CloseCompletionQueue(cq);
}
TEST(rio_udp_deferred_send_waits_for_commit)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    memcpy(p.mem + PR_SEND, "later", 5);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    CHECK(pair_send(&p, PR_SEND, 5, RQV(2), RIO_MSG_DEFER));
    rio_settle();
    EXPECT_EQ(t->DequeueCompletion(p.cqa, r, 2), 0);
    EXPECT_EQ(t->DequeueCompletion(p.cqb, r, 2), 0);
    CHECK(t->Send(p.ra, NULL, 0, RIO_MSG_COMMIT_ONLY, NULL));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 5); CHECK(!memcmp(p.mem + PR_RECV, "later", 5));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].RequestContext, RQV(2));
    pair_close(&p);
}
TEST(rio_udp_deferred_requests_fill_the_queue)
{
    RIORES r[4];
    NEED_PAIR(p, t, 2);
    CHECK(pair_send(&p, PR_SEND, 1, RQV(1), RIO_MSG_DEFER)); CHECK(pair_send(&p, PR_SEND, 1, RQV(2), RIO_MSG_DEFER));
    WSASetLastError(0);
    CHECK(!pair_send(&p, PR_SEND, 1, RQV(3), RIO_MSG_DEFER)); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);
    CHECK(t->Send(p.ra, NULL, 0, RIO_MSG_COMMIT_ONLY, NULL));
    EXPECT_EQ(rio_wait(t, p.cqa, r, 4, 2), 2);
    EXPECT_EQ(r[0].RequestContext, RQV(1)); EXPECT_EQ(r[1].RequestContext, RQV(2));
    pair_close(&p);
}
TEST(rio_udp_deferred_receive_is_delivered_after_commit)
{
    RIORES r[2];
    NEED_PAIR(p, t, 4);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), RIO_MSG_DEFER));
    CHECK(pair_send(&p, PR_SEND, 2, RQV(2), 0));
    rio_settle();
    CHECK(t->Receive(p.rb, NULL, 0, RIO_MSG_COMMIT_ONLY, NULL));
    EXPECT_EQ(rio_wait(t, p.cqb, r, 2, 1), 1);          /* by now the datagram has been delivered either way */
    EXPECT_EQ(r[0].BytesTransferred, 2); EXPECT_EQ(r[0].RequestContext, RQV(1));
    pair_close(&p);
}
