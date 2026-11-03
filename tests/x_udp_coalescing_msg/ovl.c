/* Overlapped WSARecvMsg / WSASendMsg on loopback datagram sockets (pending status, event signalling, what is
 * written into the message structure at completion, truncation results, immediate completion, cancellation by
 * closing the socket, completion routines) and the SIO_UDP_CONNRESET semantics (a datagram sent to a closed
 * loopback port makes a later receive fail once with WSAECONNRESET unless the ioctl switched that off). */
#include "xu.h"

#define L4 IPPROTO_IP
#define NOGOT 0xFFFFFFFFu
static xu_rx RX;
static int open_pair(xu_ep *a, xu_ep *b, int af) {
    if (af == AF_INET6 && !xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return 0; }
    return xu_pair(a, b, af);
}
static int tx(xu_ep *a, xu_ep *b, const char *d, int n) { return U(sendto)(a->s, d, n, 0, (struct sockaddr *)&b->sa, b->len); }
#define ERRIF(r) ((r) ? xu_err() : 0)
static int ev_set(WSAEVENT e, int ms) { return U(WSAWaitForMultipleEvents)(1, &e, TRUE, ms, FALSE) == WSA_WAIT_EVENT_0; }

typedef struct { WSAMSG m; WSABUF b; WSAOVERLAPPED ov; unsigned char data[64]; unsigned char ctl[128] __attribute__((aligned(8))); struct sockaddr_storage from; DWORD got; } ovrx;
static void ov_init(ovrx *o, DWORD datacap, ULONG ctlcap) {
    memset(o, 0, sizeof *o);
    o->ov.hEvent = U(WSACreateEvent)();
    o->b.buf = (CHAR *)o->data; o->b.len = datacap;
    o->m.lpBuffers = &o->b; o->m.dwBufferCount = 1; o->m.name = (LPSOCKADDR)&o->from; o->m.namelen = sizeof o->from;
    o->m.Control.buf = ctlcap ? (CHAR *)o->ctl : NULL; o->m.Control.len = ctlcap;
    o->got = 0x7777;
}
static void ov_fini(ovrx *o) { U(WSACloseEvent)(o->ov.hEvent); }

/* A receive on an empty socket is pending; the event is not set until a datagram arrives; the byte count and
 * flags come from the overlapped result; the control length and name length are filled in the message. */
TEST(xv_receive_pending_then_completes) {
    xu_ep a, b; ovrx o; DWORD n = 0, fl = 0xDEAD; int r, e; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    ov_init(&o, 64, 64);
    xu_seterr(0); r = xu_rm(b.s, &o.m, &o.got, &o.ov, NULL); e = ERRIF(r);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSA_IO_PENDING); EXPECT_EQ(o.got, 0x7777); CHECK(!ev_set(o.ov.hEvent, 0));
    CHECK(tx(&a, &b, "hello", 5) == 5);
    CHECK(ev_set(o.ov.hEvent, 3000));
    r = U(WSAGetOverlappedResult)(b.s, &o.ov, &n, FALSE, &fl);
    CHECKF(r == TRUE && n == 5 && fl == 0, "result r=%d n=%lu flags=%lu", r, (unsigned long)n, (unsigned long)fl);
    EXPECT_EQ(o.m.Control.len, 24); EXPECT_EQ(o.m.namelen, sizeof(struct sockaddr_in)); EXPECT_EQ(o.m.dwFlags, 0);
    CHECK(!memcmp(o.data, "hello", 5)); CHECK(xu_cmsg_find(o.ctl, o.m.Control.len, L4, 19, NULL) != NULL);
    ov_fini(&o); xu_free(&a); xu_free(&b);
}
/* control data does not fit: the overlapped result is an error (WSAEMSGSIZE), the datagram is consumed, the
 * message structure reports MSG_CTRUNC and the full control length */
TEST(xv_receive_control_truncation_at_completion) {
    xu_ep a, b; ovrx o; DWORD n = 0, fl = 0; int r, e; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    ov_init(&o, 64, 8);
    xu_seterr(0); r = xu_rm(b.s, &o.m, &o.got, &o.ov, NULL); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSA_IO_PENDING);
    CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(ev_set(o.ov.hEvent, 3000));
    xu_seterr(0); r = U(WSAGetOverlappedResult)(b.s, &o.ov, &n, FALSE, &fl); e = ERRIF(!r);
    CHECKF(r == FALSE && e == WSAEMSGSIZE && n == 5, "result r=%d err=%d n=%lu", r, e, (unsigned long)n);
    EXPECT_EQ(o.m.dwFlags, XU_MSG_CTRUNC); EXPECT_EQ(o.m.Control.len, 24);
    CHECK(!xu_ready(b.s, 30));
    ov_fini(&o); xu_free(&a); xu_free(&b);
}
TEST(xv_receive_data_truncation_at_completion) {
    xu_ep a, b; ovrx o; DWORD n = 0, fl = 0; int r, e; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(b.s, L4, XU_IP_PKTINFO, 1) == 0);
    ov_init(&o, 3, 64);
    xu_seterr(0); r = xu_rm(b.s, &o.m, &o.got, &o.ov, NULL); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSA_IO_PENDING);
    CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(ev_set(o.ov.hEvent, 3000));
    xu_seterr(0); r = U(WSAGetOverlappedResult)(b.s, &o.ov, &n, FALSE, &fl); e = ERRIF(!r);
    CHECKF(r == FALSE && e == WSAEMSGSIZE && n == 3, "result r=%d err=%d n=%lu", r, e, (unsigned long)n);
    EXPECT_EQ(o.m.dwFlags, XU_MSG_TRUNC); EXPECT_EQ(o.m.Control.len, 24); EXPECT_EQ(o.m.namelen, sizeof(struct sockaddr_in));
    CHECK(!memcmp(o.data, "hel", 3));
    ov_fini(&o); xu_free(&a); xu_free(&b);
}
/* a datagram already queued completes the call at once: result 0, count written, event signalled */
TEST(xv_receive_immediate_completion) {
    xu_ep a, b; ovrx o; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(xu_ready(b.s, 3000));
    ov_init(&o, 64, 0);
    xu_seterr(0); r = xu_rm(b.s, &o.m, &o.got, &o.ov, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(o.got, 5); CHECK(ev_set(o.ov.hEvent, 0)); EXPECT_EQ(o.m.namelen, sizeof(struct sockaddr_in));
    ov_fini(&o); xu_free(&a); xu_free(&b);
}
/* closing the socket cancels a pending receive: the event is set, the status is cancelled and the result is
 * the aborted-operation error */
TEST(xv_close_cancels_pending_receive) {
    xu_ep a, b; ovrx o; DWORD n = 5, fl = 0; int r, e; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    ov_init(&o, 64, 0);
    xu_seterr(0); r = xu_rm(b.s, &o.m, &o.got, &o.ov, NULL); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSA_IO_PENDING);
    xu_close(b.s); b.s = INVALID_SOCKET;
    CHECK(ev_set(o.ov.hEvent, 3000));
    EXPECT_EQ((unsigned long)o.ov.Internal, 0xC0000120ul);
    xu_seterr(0); r = U(WSAGetOverlappedResult)(a.s, &o.ov, &n, FALSE, &fl); e = ERRIF(!r);
    CHECKF(r == FALSE && e == WSA_OPERATION_ABORTED && n == 0, "result r=%d err=%d n=%lu", r, e, (unsigned long)n);
    ov_fini(&o); xu_free(&a);
}
/* completion routines run once the thread waits alertably, with no error and the transferred size */
static volatile LONG g_cr_calls; static volatile DWORD g_cr_err, g_cr_bytes, g_cr_flags;
static VOID CALLBACK cr_note(DWORD err, DWORD cb, LPWSAOVERLAPPED o, DWORD fl) { (void)o; g_cr_err = err; g_cr_bytes = cb; g_cr_flags = fl; InterlockedIncrement(&g_cr_calls); }
TEST(xv_completion_routine_receive_and_send) {
    xu_ep a, b; ovrx o; WSAMSG m; WSABUF bf; WSAOVERLAPPED sov; DWORD sent = 0, w; int r, e; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    ov_init(&o, 64, 0); g_cr_calls = 0;
    xu_seterr(0); r = xu_rm(b.s, &o.m, &o.got, &o.ov, cr_note); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSA_IO_PENDING);
    EXPECT_EQ(g_cr_calls, 0);
    CHECK(tx(&a, &b, "hello", 5) == 5);
    w = SleepEx(3000, TRUE); EXPECT_EQ(w, WAIT_IO_COMPLETION); EXPECT_EQ(g_cr_calls, 1); EXPECT_EQ(g_cr_err, 0); EXPECT_EQ(g_cr_bytes, 5); EXPECT_EQ(g_cr_flags, 0);
    /* a send with a completion routine reports pending even though the datagram is already out */
    g_cr_calls = 0; memset(&sov, 0, sizeof sov); memset(&m, 0, sizeof m); bf.buf = (CHAR *)"abc"; bf.len = 3; m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len; m.lpBuffers = &bf; m.dwBufferCount = 1;
    xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, &sov, cr_note); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSA_IO_PENDING);
    w = SleepEx(3000, TRUE); EXPECT_EQ(w, WAIT_IO_COMPLETION); EXPECT_EQ(g_cr_calls, 1); EXPECT_EQ(g_cr_err, 0); EXPECT_EQ(g_cr_bytes, 3);
    xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 3);
    ov_fini(&o); xu_free(&a); xu_free(&b);
}
/* an overlapped send with an event completes at once: result 0, count written, event set, count may be NULL */
TEST(xv_send_with_event_completes_immediately) {
    xu_ep a, b; WSAMSG m; WSABUF bf; WSAOVERLAPPED ov; DWORD sent = 77, n = 0, fl = 0; int r; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    memset(&m, 0, sizeof m); bf.buf = (CHAR *)"hello"; bf.len = 5; m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len; m.lpBuffers = &bf; m.dwBufferCount = 1;
    xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, &ov, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 5); CHECK(ev_set(ov.hEvent, 0));
    CHECK(U(WSAGetOverlappedResult)(a.s, &ov, &n, FALSE, &fl)); EXPECT_EQ(n, 5);
    xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 5);
    U(WSAResetEvent)(ov.hEvent); memset((void *)&ov.Internal, 0, 2 * sizeof(ULONG_PTR));
    xu_seterr(0); r = xu_sm(a.s, &m, 0, NULL, &ov, NULL); EXPECT_EQ(r, 0);
    xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 5);
    U(WSACloseEvent)(ov.hEvent); xu_free(&a); xu_free(&b);
}

/* ---- SIO_UDP_CONNRESET ---- */
typedef struct { SOCKET s; struct sockaddr_storage dead; int len; } cr_t;
/* a connected (or just bound) socket aimed at a loopback port nothing listens on */
static int cr_make(cr_t *c, int af, int connect_it) {
    SOCKET d; struct sockaddr_storage w; int n = sizeof w, wl;
    memset(c, 0, sizeof *c); c->s = INVALID_SOCKET;
    if (af == AF_INET6 && !xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return 0; }
    memset(&w, 0, sizeof w); w.ss_family = (ADDRESS_FAMILY)af;
    if (af == AF_INET) { ((struct sockaddr_in *)&w)->sin_addr.s_addr = 0x0100007fu; wl = sizeof(struct sockaddr_in); }
    else { ((struct sockaddr_in6 *)&w)->sin6_addr.u.Byte[15] = 1; wl = sizeof(struct sockaddr_in6); }
    d = U(socket)(af, SOCK_DGRAM, 0); c->s = U(socket)(af, SOCK_DGRAM, 0);
    if (d == INVALID_SOCKET || c->s == INVALID_SOCKET) { xu_close(d); xu_close(c->s); c->s = INVALID_SOCKET; t_skip("socket unavailable"); return 0; }
    if (U(bind)(d, (struct sockaddr *)&w, wl) || U(getsockname)(d, (struct sockaddr *)&c->dead, &n)) { xu_close(d); xu_close(c->s); c->s = INVALID_SOCKET; t_skip("bind unavailable"); return 0; }
    c->len = n; xu_close(d);
    if (connect_it) CHECK(U(connect)(c->s, (struct sockaddr *)&c->dead, c->len) == 0);
    else CHECK(U(bind)(c->s, (struct sockaddr *)&w, wl) == 0);
    return 1;
}
static int cr_poke(cr_t *c, int connected) {
    return connected ? U(send)(c->s, "q", 1, 0) : U(sendto)(c->s, "q", 1, 0, (struct sockaddr *)&c->dead, c->len);
}
static int cr_ioctl(SOCKET s, DWORD code, DWORD on, int inlen, DWORD *ret) {
    DWORD r = 0xFFFF; int x = U(WSAIoctl)(s, code, &on, inlen, NULL, 0, &r, NULL, NULL); if (ret) *ret = r; return x;
}
/* a recv that must not block: returns the result and error */
static int nb_recv(SOCKET s, int *err) {
    char bf[8]; int r; xu_nonblock(s, 1); xu_seterr(0); r = U(recv)(s, bf, sizeof bf, 0); *err = r < 0 ? xu_err() : 0; return r;
}
TEST(xv_connreset_ioctl_argument_sizes) {
    int lens[] = {0, 1, 2, 3, 4, 5, 8}; size_t i; UP();
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        SOCKET s = U(socket)(AF_INET, SOCK_DGRAM, 0); DWORD ret = 0; int r, e;
        REQUIRE(s != INVALID_SOCKET);
        xu_seterr(0); r = cr_ioctl(s, SIO_UDP_CONNRESET, 0, lens[i], &ret); e = ERRIF(r);
        if (lens[i] == 0) CHECKF(r == SOCKET_ERROR && e == WSAEFAULT, "input length 0: r=%d err=%d", r, e);
        else CHECKF(r == 0, "input length %d: r=%d err=%d", lens[i], r, e);
        xu_close(s);
    }
}
TEST(xv_connreset_and_netreset_need_a_datagram_socket) {
    SOCKET t; DWORD ret; int r, e; UP();
    t = U(socket)(AF_INET, SOCK_STREAM, 0); REQUIRE(t != INVALID_SOCKET);
    xu_seterr(0); r = cr_ioctl(t, SIO_UDP_CONNRESET, 0, 4, &ret); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL);
    xu_seterr(0); r = cr_ioctl(t, XU_SIO_UDP_NETRESET, 0, 4, &ret); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL);
    xu_close(t);
}
/* by default the error is reported by the next receive, exactly once; select reports the socket readable */
static void connreset_default(int af, int connected) {
    cr_t c; int r, e; if (!cr_make(&c, af, connected)) return;
    CHECK(cr_poke(&c, connected) == 1); CHECK(xu_ready(c.s, 3000));
    r = nb_recv(c.s, &e); CHECKF(r == SOCKET_ERROR && e == WSAECONNRESET, "first receive: r=%d err=%d", r, e);
    r = nb_recv(c.s, &e); CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "second receive: r=%d err=%d", r, e);
    xu_close(c.s);
}
TEST(xv_connreset_default_connected_v4) { UP(); connreset_default(AF_INET, 1); }
TEST(xv_connreset_default_unconnected_v4) { UP(); connreset_default(AF_INET, 0); }
TEST(xv_connreset_default_connected_v6) { UP6(); connreset_default(AF_INET6, 1); }
TEST(xv_connreset_default_unconnected_v6) { UP6(); connreset_default(AF_INET6, 0); }
/* the same error comes out of every receive entry point */
TEST(xv_connreset_all_receive_calls) {
    int k; UP();
    for (k = 0; k < 4; k++) {
        cr_t c; int r = 0, e = 0; char bf[8]; WSABUF wb; DWORD got = 5, fl = 0; WSAMSG m; if (!cr_make(&c, AF_INET, 1)) return;
        CHECK(cr_poke(&c, 1) == 1); CHECK(xu_ready(c.s, 3000)); xu_nonblock(c.s, 1);
        wb.buf = bf; wb.len = sizeof bf; xu_seterr(0);
        if (k == 0) r = U(recvfrom)(c.s, bf, sizeof bf, 0, NULL, NULL);
        else if (k == 1) r = U(WSARecv)(c.s, &wb, 1, &got, &fl, NULL, NULL);
        else if (k == 2) { memset(&m, 0, sizeof m); m.lpBuffers = &wb; m.dwBufferCount = 1; r = xu_rm(c.s, &m, &got, NULL, NULL); CHECK(m.dwFlags == 0); }
        else { memset(&RX, 0, sizeof RX.ctl); xu_recv(c.s, &RX, 8, 0, 0, 0); r = RX.r; e = RX.err; got = RX.got; }
        if (k != 3) e = ERRIF(r);
        CHECKF(r == SOCKET_ERROR && e == WSAECONNRESET && got == (k == 3 ? NOGOT : 5), "call %d: r=%d err=%d got=%lu", k, r, e, (unsigned long)got);
        xu_close(c.s);
    }
}
/* with the ioctl off the stray error never shows; a real datagram from a peer is the first thing received */
TEST(xv_connreset_disabled_never_reports) {
    cr_t c; xu_ep peer; int r, e; UP(); if (!cr_make(&c, AF_INET, 0)) return;
    if (!xu_open(&peer, AF_INET)) { xu_close(c.s); t_skip("udp endpoint unavailable"); return; }
    CHECK(cr_ioctl(c.s, SIO_UDP_CONNRESET, 0, 4, NULL) == 0);
    CHECK(cr_poke(&c, 0) == 1);
    { struct sockaddr_storage me; int n = sizeof me; CHECK(U(getsockname)(c.s, (struct sockaddr *)&me, &n) == 0); CHECK(U(sendto)(peer.s, "ok", 2, 0, (struct sockaddr *)&me, n) == 2); }
    CHECK(xu_ready(c.s, 3000));
    r = nb_recv(c.s, &e); CHECKF(r == 2 && e == 0, "first receive: r=%d err=%d", r, e);
    r = nb_recv(c.s, &e); CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "second receive: r=%d err=%d", r, e);
    xu_close(c.s); xu_free(&peer);
}
/* off, then on again: the error is reported again; an explicit "on" is also fine on a fresh socket */
TEST(xv_connreset_toggle_back_on) {
    cr_t c; int r, e; UP(); if (!cr_make(&c, AF_INET, 1)) return;
    CHECK(cr_ioctl(c.s, SIO_UDP_CONNRESET, 0, 4, NULL) == 0); CHECK(cr_ioctl(c.s, SIO_UDP_CONNRESET, 1, 4, NULL) == 0);
    CHECK(cr_poke(&c, 1) == 1); CHECK(xu_ready(c.s, 3000));
    r = nb_recv(c.s, &e); CHECKF(r == SOCKET_ERROR && e == WSAECONNRESET, "after toggling: r=%d err=%d", r, e);
    xu_close(c.s);
}
/* the reset error is ordered ahead of datagrams that arrive later; SO_ERROR does not show it; peeking
 * does not consume it, a real receive does */
TEST(xv_connreset_order_peek_and_so_error) {
    cr_t c; xu_ep peer; struct sockaddr_storage me; int n = sizeof me, r, e, v = -1; char bf[8]; UP(); if (!cr_make(&c, AF_INET, 0)) return;
    if (!xu_open(&peer, AF_INET)) { xu_close(c.s); t_skip("udp endpoint unavailable"); return; }
    CHECK(U(getsockname)(c.s, (struct sockaddr *)&me, &n) == 0);
    CHECK(cr_poke(&c, 0) == 1); CHECK(xu_ready(c.s, 3000));
    CHECK(U(sendto)(peer.s, "real", 4, 0, (struct sockaddr *)&me, n) == 4);
    CHECK(xu_getint(c.s, SOL_SOCKET, SO_ERROR, &v) == 0); EXPECT_EQ(v, 0);
    xu_nonblock(c.s, 1);
    xu_seterr(0); r = U(recv)(c.s, bf, 8, MSG_PEEK); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAECONNRESET);
    xu_seterr(0); r = U(recv)(c.s, bf, 8, MSG_PEEK); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAECONNRESET);
    r = nb_recv(c.s, &e); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAECONNRESET);
    r = nb_recv(c.s, &e); EXPECT_EQ(r, 4); EXPECT_EQ(e, 0);
    r = nb_recv(c.s, &e); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEWOULDBLOCK);
    xu_close(c.s); xu_free(&peer);
}
/* a pending overlapped receive fails with the reset error as soon as the ICMP error arrives */
TEST(xv_connreset_completes_pending_overlapped_receive) {
    cr_t c; ovrx o; DWORD n = 5, fl = 0; int r, e; UP(); if (!cr_make(&c, AF_INET, 1)) return;
    ov_init(&o, 64, 0);
    xu_seterr(0); r = xu_rm(c.s, &o.m, &o.got, &o.ov, NULL); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(xu_err(), WSA_IO_PENDING);
    CHECK(cr_poke(&c, 1) == 1); CHECK(ev_set(o.ov.hEvent, 3000));
    xu_seterr(0); r = U(WSAGetOverlappedResult)(c.s, &o.ov, &n, FALSE, &fl); e = ERRIF(!r);
    CHECKF(r == FALSE && e == WSAECONNRESET && n == 0, "result r=%d err=%d n=%lu", r, e, (unsigned long)n);
    ov_fini(&o); xu_close(c.s);
}
