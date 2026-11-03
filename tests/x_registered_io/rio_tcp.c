/* Stream transfers with RIOSend / RIOReceive on a connected loopback TCP pair, the TCP-specific rules, and the
 * completion statuses for connection events.
 *
 * Measured on Windows 10. A stream queue needs a real descriptor for Send/Receive (count 0 is WSAEINVAL) and
 * refuses the Ex variants with WSAEPROTONOSUPPORT. RIO_MSG_WAITALL holds a receive until the whole descriptor is
 * filled. After the peer's shutdown or close a receive completes with 0 bytes and status 0, repeatedly; after a
 * reset every pending and later request completes with WSAECONNRESET (10054). A send on an unconnected socket is
 * accepted and completes with WSAENOTCONN; a send after the local shutdown(SD_SEND) completes with WSAEINVAL. */
#include "rio.h"

typedef struct {
    RIO_TABLE *t; SOCKET ls, c, s; RIO_CQ cqc, cqs; RIO_RQ rc, rs; char *mem; RIO_BUFFERID id;
} TP;
#define TP_SEND 0x0000
#define TP_RECV 0x20000
static int tp_open(TP *x, RIO_TABLE *t)
{
    struct sockaddr_in la; int l = sizeof la;
    memset(x, 0, sizeof *x); x->t = t; x->ls = x->c = x->s = INVALID_SOCKET;
    x->ls = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL); x->c = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL);
    rio_loop4(&la);
    if (x->ls == INVALID_SOCKET || x->c == INVALID_SOCKET || bind(x->ls, (struct sockaddr *)&la, sizeof la) || getsockname(x->ls, (struct sockaddr *)&la, &l) || listen(x->ls, 1)) return 0;
    if (connect(x->c, (struct sockaddr *)&la, sizeof la)) return 0;
    x->s = accept(x->ls, NULL, NULL);
    if (x->s == INVALID_SOCKET) return 0;
    x->cqc = t->CreateCompletionQueue(16, NULL); x->cqs = t->CreateCompletionQueue(16, NULL);
    x->mem = VirtualAlloc(NULL, 0x40000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!x->cqc || !x->cqs || !x->mem) return 0;
    x->rc = t->CreateRequestQueue(x->c, 4, 1, 4, 1, x->cqc, x->cqc, (PVOID)(ULONG_PTR)CTX_A);
    x->rs = t->CreateRequestQueue(x->s, 4, 1, 4, 1, x->cqs, x->cqs, (PVOID)(ULONG_PTR)CTX_B);
    x->id = t->RegisterBuffer(x->mem, 0x40000);
    return x->rc && x->rs && x->id != RIO_INVALID_BUFFERID;
}
static void tp_close(TP *x)
{
    if (x->c != INVALID_SOCKET) closesocket(x->c);
    if (x->s != INVALID_SOCKET) closesocket(x->s);
    if (x->ls != INVALID_SOCKET) closesocket(x->ls);
    if (x->id && x->id != RIO_INVALID_BUFFERID) x->t->DeregisterBuffer(x->id);
    if (x->cqc) x->t->CloseCompletionQueue(x->cqc);
    if (x->cqs) x->t->CloseCompletionQueue(x->cqs);
    if (x->mem) VirtualFree(x->mem, 0, MEM_RELEASE);
}
#define NEED_TCP(x, t) TP x; RIO_TABLE *t; NEED_NET(); t = rio_tbl(); if (!t) { t_skip("RIO unavailable"); return; } \
    if (!tp_open(&x, t)) { tp_close(&x); t_skip("loopback RIO TCP pair unavailable"); return; }

/* c = client side (context CTX_A, queue cqc), s = accepted side (context CTX_B, queue cqs). */
static BOOL c_send(TP *x, ULONG off, ULONG len, ULONGLONG ctx, DWORD fl) { RIO_BUF d = {x->id, off, len}; return x->t->Send(x->rc, &d, 1, fl, (PVOID)(ULONG_PTR)ctx); }
static BOOL c_recv(TP *x, ULONG off, ULONG len, ULONGLONG ctx, DWORD fl) { RIO_BUF d = {x->id, off, len}; return x->t->Receive(x->rc, &d, 1, fl, (PVOID)(ULONG_PTR)ctx); }
static BOOL s_send(TP *x, ULONG off, ULONG len, ULONGLONG ctx, DWORD fl) { RIO_BUF d = {x->id, off, len}; return x->t->Send(x->rs, &d, 1, fl, (PVOID)(ULONG_PTR)ctx); }
static BOOL s_recv(TP *x, ULONG off, ULONG len, ULONGLONG ctx, DWORD fl) { RIO_BUF d = {x->id, off, len}; return x->t->Receive(x->rs, &d, 1, fl, (PVOID)(ULONG_PTR)ctx); }

TEST(rio_tcp_roundtrip_both_directions)
{
    RIORES r[2];
    NEED_TCP(x, t);
    memcpy(x.mem + TP_SEND, "to-server", 9);
    CHECK(s_recv(&x, TP_RECV, 32, RQV(1), 0)); CHECK(c_send(&x, TP_SEND, 9, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 9); EXPECT_EQ(r[0].SocketContext, CTX_B); EXPECT_EQ(r[0].RequestContext, RQV(1));
    CHECK(!memcmp(x.mem + TP_RECV, "to-server", 9));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 9); EXPECT_EQ(r[0].SocketContext, CTX_A); EXPECT_EQ(r[0].RequestContext, RQV(2));
    memcpy(x.mem + TP_SEND, "to-client", 9);
    CHECK(c_recv(&x, TP_RECV + 0x100, 32, RQV(3), 0)); CHECK(s_send(&x, TP_SEND, 9, RQV(4), 0));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 9); EXPECT_EQ(r[0].RequestContext, RQV(3));
    CHECK(!memcmp(x.mem + TP_RECV + 0x100, "to-client", 9));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].RequestContext, RQV(4));
    tp_close(&x);
}
TEST(rio_tcp_receive_returns_what_has_arrived)
{
    RIORES r[2];
    NEED_TCP(x, t);
    CHECK(s_recv(&x, TP_RECV, 64, RQV(1), 0)); CHECK(c_send(&x, TP_SEND, 8, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 8);
    tp_close(&x);
}
TEST(rio_tcp_waitall_holds_until_the_descriptor_is_full)
{
    RIORES r[2];
    NEED_TCP(x, t);
    memcpy(x.mem + TP_SEND, "01234567", 8);
    CHECK(s_recv(&x, TP_RECV, 16, RQV(1), RIO_MSG_WAITALL));
    CHECK(c_send(&x, TP_SEND, 8, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);            /* the send is done ... */
    rio_settle();
    EXPECT_EQ(t->DequeueCompletion(x.cqs, r, 2), 0);      /* ... the receive still waits for 8 more bytes */
    CHECK(c_send(&x, TP_SEND, 8, RQV(3), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 16); EXPECT_EQ(r[0].RequestContext, RQV(1));
    CHECK(!memcmp(x.mem + TP_RECV, "0123456701234567", 16));
    tp_close(&x);
}
TEST(rio_tcp_large_transfer_with_waitall)
{
    RIORES r[2];
    NEED_TCP(x, t);
    memset(x.mem, 'q', 0x20000); memset(x.mem + 0x20000, 0, 0x20000);
    CHECK(s_recv(&x, 0x20000, 0x20000, RQV(1), RIO_MSG_WAITALL));
    CHECK(c_send(&x, 0, 0x20000, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0x20000);
    CHECK(!memcmp(x.mem, x.mem + 0x20000, 0x20000));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0x20000);
    tp_close(&x);
}
TEST(rio_tcp_sends_arrive_in_order)
{
    RIORES r[4];
    NEED_TCP(x, t);
    memcpy(x.mem + TP_SEND, "abc", 3); memcpy(x.mem + TP_SEND + 0x100, "def", 3);
    CHECK(s_recv(&x, TP_RECV, 6, RQV(1), RIO_MSG_WAITALL));
    CHECK(c_send(&x, TP_SEND, 3, RQV(2), 0)); CHECK(c_send(&x, TP_SEND + 0x100, 3, RQV(3), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 4, 1), 1);
    EXPECT_EQ(r[0].BytesTransferred, 6); CHECK(!memcmp(x.mem + TP_RECV, "abcdef", 6));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 4, 2), 2);
    EXPECT_EQ(r[0].RequestContext, RQV(2)); EXPECT_EQ(r[1].RequestContext, RQV(3));
    tp_close(&x);
}
TEST(rio_tcp_pending_receives_fill_in_order)
{
    RIORES r[4];
    NEED_TCP(x, t);
    memcpy(x.mem + TP_SEND, "AAAABBBB", 8);
    CHECK(s_recv(&x, TP_RECV, 4, RQV(1), RIO_MSG_WAITALL)); CHECK(s_recv(&x, TP_RECV + 0x100, 4, RQV(2), RIO_MSG_WAITALL));
    CHECK(c_send(&x, TP_SEND, 8, RQV(3), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 4, 2), 2);
    EXPECT_EQ(r[0].RequestContext, RQV(1)); EXPECT_EQ(r[1].RequestContext, RQV(2));
    CHECK(!memcmp(x.mem + TP_RECV, "AAAA", 4)); CHECK(!memcmp(x.mem + TP_RECV + 0x100, "BBBB", 4));
    tp_close(&x);
}
TEST(rio_tcp_zero_length_send_completes_ok)
{
    RIORES r[2];
    NEED_TCP(x, t);
    CHECK(c_send(&x, TP_SEND, 0, RQV(1), 0));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0);
    tp_close(&x);
}

TEST(rio_tcp_shutdown_gives_zero_byte_receives)
{
    RIORES r[2];
    NEED_TCP(x, t);
    CHECK(s_recv(&x, TP_RECV, 16, RQV(1), 0));
    EXPECT_EQ(shutdown(x.c, SD_SEND), 0);
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(1));
    for (int i = 0; i < 3; i++) {
        CHECK(s_recv(&x, TP_RECV, 16, RQV(2 + i), 0));
        EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
        EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].RequestContext, RQV(2 + i));
    }
    tp_close(&x);
}
TEST(rio_tcp_send_after_local_shutdown_completes_einval)
{
    RIORES r[2];
    NEED_TCP(x, t);
    EXPECT_EQ(shutdown(x.c, SD_SEND), 0);
    CHECK(c_send(&x, TP_SEND, 4, RQV(1), 0));
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, WSAEINVAL); EXPECT_EQ(r[0].BytesTransferred, 0);
    tp_close(&x);
}
TEST(rio_tcp_peer_close_gives_zero_byte_receive)
{
    RIORES r[2];
    NEED_TCP(x, t);
    CHECK(c_recv(&x, TP_RECV, 16, RQV(1), 0));
    closesocket(x.s); x.s = INVALID_SOCKET;
    EXPECT_EQ(rio_wait(t, x.cqc, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, 0); EXPECT_EQ(r[0].BytesTransferred, 0);
    tp_close(&x);
}
TEST(rio_tcp_reset_fails_pending_and_later_requests)
{
    RIORES r[4]; struct linger lg = {1, 0};
    NEED_TCP(x, t);
    CHECK(s_recv(&x, TP_RECV, 16, RQV(1), 0)); CHECK(s_recv(&x, TP_RECV + 0x100, 16, RQV(2), 0));
    setsockopt(x.c, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg);
    closesocket(x.c); x.c = INVALID_SOCKET;
    EXPECT_EQ(rio_wait(t, x.cqs, r, 4, 2), 2);
    for (int i = 0; i < 2; i++) { EXPECT_EQ(r[i].Status, WSAECONNRESET); EXPECT_EQ(r[i].BytesTransferred, 0); EXPECT_EQ(r[i].RequestContext, RQV(1 + i)); }
    CHECK(s_recv(&x, TP_RECV, 16, RQV(3), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 4, 1), 1);
    EXPECT_EQ(r[0].Status, WSAECONNRESET); EXPECT_EQ(r[0].RequestContext, RQV(3));
    CHECK(s_send(&x, TP_SEND, 4, RQV(4), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 4, 1), 1);
    EXPECT_EQ(r[0].Status, WSAECONNRESET); EXPECT_EQ(r[0].RequestContext, RQV(4));
    tp_close(&x);
}
TEST(rio_tcp_unconnected_send_completes_enotconn)
{
    RIORES r[2];
    NEED_RIO(t);
    SOCKET c = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); RIO_RQ rq = t->CreateRequestQueue(c, 1, 1, 1, 1, cq, cq, NULL);
    char buf[16] = "x"; RIO_BUFFERID id = t->RegisterBuffer(buf, sizeof buf); RIO_BUF d = {id, 0, 4};
    CHECK(rq != NULL);
    CHECK(t->Send(rq, &d, 1, 0, RQC(1)));
    EXPECT_EQ(rio_wait(t, cq, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, WSAENOTCONN); EXPECT_EQ(r[0].BytesTransferred, 0);
    t->DeregisterBuffer(id); closesocket(c); t->CloseCompletionQueue(cq);
}
TEST(rio_tcp_close_aborts_a_pending_receive)
{
    RIORES r[2];
    NEED_TCP(x, t);
    CHECK(s_recv(&x, TP_RECV, 16, RQV(1), 0));
    rio_settle(); EXPECT_EQ(t->DequeueCompletion(x.cqs, r, 2), 0);
    closesocket(x.s); x.s = INVALID_SOCKET;
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    EXPECT_EQ(r[0].Status, WSAECONNABORTED); EXPECT_EQ(r[0].BytesTransferred, 0); EXPECT_EQ(r[0].SocketContext, CTX_B);   /* unlike a datagram receive (995) */
    tp_close(&x);
}

TEST(rio_tcp_stream_queue_needs_a_real_descriptor)
{
    NEED_TCP(x, t);
    WSASetLastError(0); CHECK(!t->Receive(x.rs, NULL, 0, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->Send(x.rc, NULL, 0, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    CHECK(t->Receive(x.rs, NULL, 0, RIO_MSG_COMMIT_ONLY, NULL));      /* commit-only needs no descriptor */
    CHECK(t->Send(x.rc, NULL, 0, RIO_MSG_COMMIT_ONLY, NULL));
    tp_close(&x);
}
TEST(rio_tcp_ex_variants_are_unsupported)
{
    NEED_TCP(x, t);
    RIO_BUF d = {x.id, TP_SEND, 4}, ad = {x.id, 0x300, 28};
    WSASetLastError(0); CHECK(!t->ReceiveEx(x.rs, &d, 1, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEPROTONOSUPPORT);
    WSASetLastError(0); CHECK(!t->ReceiveEx(x.rs, &d, 1, NULL, &ad, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEPROTONOSUPPORT);
    WSASetLastError(0); CHECK(!t->SendEx(x.rc, &d, 1, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEPROTONOSUPPORT);
    tp_close(&x);
}
TEST(rio_tcp_outstanding_limit_is_enobufs)
{
    RIORES r[2];
    NEED_TCP(x, t);
    for (int i = 0; i < 4; i++) CHECK(s_recv(&x, TP_RECV + i * 0x100, 8, RQV(1 + i), 0));
    WSASetLastError(0); CHECK(!s_recv(&x, TP_RECV + 0x500, 8, RQV(9), 0)); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);
    CHECK(c_send(&x, TP_SEND, 1, RQV(10), 0));
    EXPECT_EQ(rio_wait(t, x.cqs, r, 2, 1), 1);
    CHECK(s_recv(&x, TP_RECV + 0x500, 8, RQV(9), 0));
    tp_close(&x);
}
