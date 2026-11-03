/* The WSARecvMsg / WSASendMsg call contract on datagram sockets, apart from the control data itself:
 * which input flags are accepted, wrong socket kinds and handles, empty and zero-sized buffers, destination
 * and source name length rules for both families, connected-socket behaviour, overlapped completion
 * (pending status, immediate completion, truncation flags after completion, cancellation by close,
 * completion routines), the extension-function lookup, and the SIO_UDP_CONNRESET semantics (a datagram sent
 * to a closed loopback port makes the next receive fail once with WSAECONNRESET unless the ioctl switched
 * that off). Everything is loopback with OS-chosen ports; waits are bounded. */
#include "xu.h"

#define L4 IPPROTO_IP
#define NOGOT 0xFFFFFFFFu
static xu_rx RX;
static int open_pair(xu_ep *a, xu_ep *b, int af) {
    if (af == AF_INET6 && !xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return 0; }
    return xu_pair(a, b, af);
}
static int tx(xu_ep *a, xu_ep *b, const char *d, int n) { return U(sendto)(a->s, d, n, 0, (struct sockaddr *)&b->sa, b->len); }
/* the last Winsock error of a failed call, captured before anything else can overwrite it */
#define ERRIF(r) ((r) ? xu_err() : 0)

/* ---- input flags ---- */
/* WSARecvMsg takes 0 or MSG_PEEK as input flags; anything else is refused before the queue is looked at, the
 * datagram stays queued, the byte count is not written and the flags field is left as given. */
TEST(xa_recv_input_flags_accepted_and_refused) {
    static const DWORD BAD[] = {1, 3, 8, 0x10, 0x20, 0x100, 0x200, 0x400, 0x800, 0x8000, 0x80000000u};
    xu_ep a, b; size_t i; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_nonblock(b.s, 1) == 0);   /* a receive that finds nothing must fail, not wait */
    for (i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(xu_ready(b.s, 3000));
        xu_recv(b.s, &RX, 8, 0, 0, BAD[i]);
        CHECKF(RX.r == SOCKET_ERROR && RX.err == WSAEOPNOTSUPP && RX.got == NOGOT && RX.flags == BAD[i], "flags 0x%lx: r=%d err=%d flags 0x%lx", (unsigned long)BAD[i], RX.r, RX.err, (unsigned long)RX.flags);
        xu_recv(b.s, &RX, 8, 0, 0, 0);
        CHECKF(RX.r == 0 && RX.got == 5, "flags 0x%lx: datagram still queued", (unsigned long)BAD[i]);
    }
    CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(xu_ready(b.s, 3000));
    xu_recv(b.s, &RX, 8, 0, 0, MSG_PEEK); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 5); EXPECT_EQ(RX.flags, 0);
    xu_free(&a); xu_free(&b);
}
/* the input flags are checked ahead of the queue state: on an empty non-blocking socket MSG_PEEK reports
 * WSAEWOULDBLOCK while a refused flag still reports WSAEOPNOTSUPP */
TEST(xa_recv_input_flags_checked_before_queue) {
    xu_ep a, b; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    CHECK(xu_nonblock(b.s, 1) == 0);
    xu_recv(b.s, &RX, 8, 0, 0, MSG_PEEK); EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEWOULDBLOCK);
    xu_recv(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEWOULDBLOCK); EXPECT_EQ(RX.got, NOGOT); EXPECT_EQ(RX.flags, 0);
    xu_recv(b.s, &RX, 8, 0, 0, 1); EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEOPNOTSUPP);
    xu_recv(b.s, &RX, 8, 0, 0, 0x100); EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEOPNOTSUPP);
    xu_free(&a); xu_free(&b);
}
/* WSASendMsg: out-of-band, do-not-route and partial are tolerated on a datagram socket, peek and the
 * receive-only result bits are refused */
TEST(xa_send_flags_accepted_and_refused) {
    static const DWORD OK[] = {0, 1, 4, 0x8000};
    static const DWORD BAD[] = {2, 0x100, 0x80000000u};
    xu_ep a, b; size_t i; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < sizeof OK / sizeof OK[0]; i++) {
        DWORD sent = 0; int r = xu_send(a.s, &b, "x", 1, NULL, 0, OK[i], &sent);
        CHECKF(r == 0 && sent == 1, "send flags 0x%lx: r=%d err=%d", (unsigned long)OK[i], r, ERRIF(r));
        xu_recvw(b.s, &RX, 8, 0, 0, 0); CHECKF(RX.r == 0 && RX.got == 1, "send flags 0x%lx: not delivered", (unsigned long)OK[i]);
    }
    for (i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        DWORD sent = 0; int r = xu_send(a.s, &b, "x", 1, NULL, 0, BAD[i], &sent), e = ERRIF(r);
        CHECKF(r == SOCKET_ERROR && e == WSAEOPNOTSUPP, "send flags 0x%lx: r=%d err=%d", (unsigned long)BAD[i], r, e);
        CHECKF(!xu_ready(b.s, 20), "send flags 0x%lx: a datagram arrived", (unsigned long)BAD[i]);
    }
    xu_free(&a); xu_free(&b);
}

/* ---- handles and socket kinds ---- */
TEST(xa_stream_socket_is_refused) {
    SOCKET t; WSAMSG m; WSABUF bf; char buf[8]; DWORD got = 5; int r, e; UP();
    t = U(socket)(AF_INET, SOCK_STREAM, 0); REQUIRE(t != INVALID_SOCKET);
    memset(&m, 0, sizeof m); bf.buf = buf; bf.len = sizeof buf; m.lpBuffers = &bf; m.dwBufferCount = 1;
    xu_seterr(0); r = xu_rm(t, &m, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL);
    xu_seterr(0); r = xu_sm(t, &m, 0, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL);
    EXPECT_EQ(got, 5);
    xu_close(t);
}
TEST(xa_closed_and_invalid_handles) {
    SOCKET c; WSAMSG m; WSABUF bf; char buf[8]; DWORD got = 5; int r, e; UP();
    c = U(socket)(AF_INET, SOCK_DGRAM, 0); REQUIRE(c != INVALID_SOCKET); xu_close(c);
    memset(&m, 0, sizeof m); bf.buf = buf; bf.len = sizeof buf; m.lpBuffers = &bf; m.dwBufferCount = 1;
    xu_seterr(0); r = xu_rm(c, &m, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAENOTSOCK);
    xu_seterr(0); r = xu_sm(c, &m, 0, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAENOTSOCK);
    xu_seterr(0); r = xu_rm(INVALID_SOCKET, &m, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAENOTSOCK);
    xu_seterr(0); r = xu_sm(INVALID_SOCKET, &m, 0, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAENOTSOCK);
    EXPECT_EQ(got, 5);
}
/* a receive on a socket that was never bound is invalid; a send from it binds it to the wildcard address */
TEST(xa_unbound_receive_invalid_send_autobinds) {
    xu_ep dst; SOCKET c; struct sockaddr_in q; int n = sizeof q, r; DWORD sent = 0; UP(); if (!xu_open(&dst, AF_INET)) { t_skip("udp endpoint unavailable"); return; }
    c = U(socket)(AF_INET, SOCK_DGRAM, 0); REQUIRE(c != INVALID_SOCKET);
    CHECK(xu_nonblock(c, 1) == 0); xu_recv(c, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.r, SOCKET_ERROR); EXPECT_EQ(RX.err, WSAEINVAL);
    r = xu_send(c, &dst, "x", 1, NULL, 0, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 1);
    memset(&q, 0xAA, sizeof q); CHECK(U(getsockname)(c, (struct sockaddr *)&q, &n) == 0);
    CHECK(q.sin_family == AF_INET && q.sin_port != 0 && q.sin_addr.s_addr == 0);
    xu_recvw(dst.s, &RX, 8, 0, 1, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 1);
    CHECK(((struct sockaddr_in *)&RX.from)->sin_port == q.sin_port);
    xu_close(c); xu_free(&dst);
}

/* ---- empty and zero-sized buffers ---- */
/* receiving with no room at all fails with WSAEMSGSIZE and MSG_TRUNC, reports zero bytes and consumes the datagram */
TEST(xa_receive_without_buffer_space_truncates) {
    xu_ep a, b; WSAMSG m; WSABUF bf; DWORD got; int r, e; int k; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    for (k = 0; k < 2; k++) {
        CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(xu_ready(b.s, 3000));
        memset(&m, 0, sizeof m); bf.buf = NULL; bf.len = 0;
        if (k) { m.lpBuffers = &bf; m.dwBufferCount = 1; }
        got = 9; xu_seterr(0); r = xu_rm(b.s, &m, &got, NULL, NULL); e = ERRIF(r);
        CHECKF(r == SOCKET_ERROR && e == WSAEMSGSIZE && got == 0 && m.dwFlags == XU_MSG_TRUNC, "variant %d: r=%d err=%d got=%lu flags 0x%lx", k, r, e, (unsigned long)got, (unsigned long)m.dwFlags);
        CHECKF(!xu_ready(b.s, 50), "variant %d: datagram not consumed", k);
    }
    xu_free(&a); xu_free(&b);
}
TEST(xa_send_buffer_list_rules) {
    xu_ep a, b; WSAMSG m; WSABUF bf; DWORD sent; int r, e; char z[8] = "abcde"; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&b.sa; m.namelen = b.len;
    /* no buffers at all: invalid, nothing sent */
    sent = 9; xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL); EXPECT_EQ(sent, 9); CHECK(!xu_ready(b.s, 20));
    /* one empty buffer: an empty datagram goes out */
    bf.buf = NULL; bf.len = 0; m.lpBuffers = &bf; m.dwBufferCount = 1; sent = 9; xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 0);
    xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 0);
    /* a NULL pointer with a length is a fault */
    bf.buf = NULL; bf.len = 5; sent = 9; xu_seterr(0); r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEFAULT); CHECK(!xu_ready(b.s, 20));
    /* a real buffer works */
    bf.buf = z; bf.len = 5; sent = 0; r = xu_sm(a.s, &m, 0, &sent, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 5);
    xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 5);
    xu_free(&a); xu_free(&b);
}

/* ---- destination names ---- */
TEST(xa_send_requires_destination_when_unconnected) {
    xu_ep a, b; DWORD sent = 9; int r, e; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    xu_seterr(0); r = xu_send(a.s, NULL, "x", 1, NULL, 0, 0, &sent); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL);
    xu_seterr(0); r = U(send)(a.s, "x", 1, 0); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAENOTCONN);
    xu_free(&a); xu_free(&b);
}
/* IPv4 socket: only the exact structure length is a valid name length for sending; a larger length is also a fault */
TEST(xa_send_name_length_v4) {
    xu_ep a, b, e; int ln, r, er; DWORD sent; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    for (ln = 0; ln <= 28; ln += 4) {
        e = b; e.len = ln; sent = 9; xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r);
        if (ln == 16) { CHECKF(r == 0 && sent == 1, "namelen 16: r=%d err=%d", r, er); xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 1); }
        else { CHECKF(r == SOCKET_ERROR && er == WSAEFAULT, "namelen %d: r=%d err=%d", ln, r, er); CHECKF(!xu_ready(b.s, 10), "namelen %d: datagram arrived", ln); }
    }
    xu_free(&a); xu_free(&b);
}
TEST(xa_send_name_content_v4) {
    xu_ep a, b, e; struct sockaddr_in d; int r, er; DWORD sent; UP(); if (!open_pair(&a, &b, AF_INET)) return;
    /* wildcard destination: no such address */
    e = b; memcpy(&d, &b.sa, sizeof d); d.sin_addr.s_addr = 0; memcpy(&e.sa, &d, sizeof d);
    xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(er, WSAEADDRNOTAVAIL);
    /* a name of the wrong or no family */
    { static const int FAM[] = {AF_INET6, 0, 99}; size_t i;
      for (i = 0; i < 3; i++) {
          memcpy(&d, &b.sa, sizeof d); d.sin_family = (ADDRESS_FAMILY)FAM[i]; memcpy(&e.sa, &d, sizeof d); e.len = 16;
          xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r);
          CHECKF(r == SOCKET_ERROR && er == WSAEAFNOSUPPORT, "family %d: r=%d err=%d", FAM[i], r, er);
      } }
    /* port 0 is accepted by the call */
    e = b; memcpy(&d, &b.sa, sizeof d); d.sin_port = 0; memcpy(&e.sa, &d, sizeof d);
    sent = 0; xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 1);
    xu_free(&a); xu_free(&b);
}
TEST(xa_send_name_length_v6) {
    xu_ep a, b, e; int ln, r, er; DWORD sent; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    for (ln = 0; ln <= 32; ln += 4) {
        e = b; e.len = ln; sent = 9; xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r);
        if (ln == 28) { CHECKF(r == 0 && sent == 1, "namelen 28: r=%d err=%d", r, er); xu_recvw(b.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 1); }
        else { CHECKF(r == SOCKET_ERROR && er == WSAEFAULT, "namelen %d: r=%d err=%d", ln, r, er); CHECKF(!xu_ready(b.s, 10), "namelen %d: datagram arrived", ln); }
    }
    xu_free(&a); xu_free(&b);
}
TEST(xa_send_name_content_v6) {
    xu_ep a, b, e; struct sockaddr_in v4; struct sockaddr_in6 d; int r, er; DWORD sent; UP6(); if (!open_pair(&a, &b, AF_INET6)) return;
    /* an IPv4 name on an IPv6 socket is too short for the socket's family */
    e = b; memset(&v4, 0, sizeof v4); v4.sin_family = AF_INET; v4.sin_addr.s_addr = 0x0100007fu; v4.sin_port = 1; memcpy(&e.sa, &v4, sizeof v4); e.len = sizeof v4;
    xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(er, WSAEFAULT);
    /* unspecified address, and a scope id that names no interface */
    e = b; memcpy(&d, &b.sa, sizeof d); d.sin6_addr = (struct in6_addr){{{0}}}; memcpy(&e.sa, &d, sizeof d);
    xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(er, WSAEADDRNOTAVAIL);
    e = b; memcpy(&d, &b.sa, sizeof d); d.sin6_scope_id = 0x7777; memcpy(&e.sa, &d, sizeof d);
    xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); er = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(er, WSAEADDRNOTAVAIL);
    e = b; memcpy(&d, &b.sa, sizeof d); d.sin6_port = 0; memcpy(&e.sa, &d, sizeof d);
    sent = 0; xu_seterr(0); r = xu_send(a.s, &e, "x", 1, NULL, 0, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 1);
    xu_free(&a); xu_free(&b);
}

/* ---- source name on receive ---- */
/* The name buffer must hold the whole source address. Too small: WSAEFAULT with the name untouched; a zero
 * length (or no name pointer at all) leaves the datagram queued, a short non-zero length has already taken it. */
static void name_rx(int af, int cap, int *r, int *e, int *queued, int *untouched, int *outlen, DWORD *got) {
    xu_ep a, b; WSAMSG m; WSABUF bf; struct sockaddr_storage ss; char buf[8];
    *r = -2; *e = 0; *queued = -1; *untouched = 0; *outlen = -1; *got = 0;
    if (!open_pair(&a, &b, af)) return;
    xu_nonblock(b.s, 1);
    CHECK(tx(&a, &b, "hello", 5) == 5); CHECK(xu_ready(b.s, 3000));
    memset(&ss, 0x77, sizeof ss); memset(&m, 0, sizeof m); bf.buf = buf; bf.len = sizeof buf; m.lpBuffers = &bf; m.dwBufferCount = 1;
    m.name = cap < 0 ? NULL : (LPSOCKADDR)&ss; m.namelen = cap < 0 ? 16 : cap;
    xu_seterr(0); *r = xu_rm(b.s, &m, got, NULL, NULL); *e = ERRIF(*r);
    *queued = xu_ready(b.s, 50); *untouched = ((unsigned char *)&ss)[0] == 0x77; *outlen = m.namelen;
    xu_free(&a); xu_free(&b);
}
TEST(xa_receive_name_length_v4) {
    int cap, r, e, q, u, n; DWORD got; UP();
    for (cap = 0; cap <= 20; cap += 4) {
        name_rx(AF_INET, cap, &r, &e, &q, &u, &n, &got);
        if (cap >= 16) CHECKF(r == 0 && got == 5 && n == 16 && !u && !q, "namelen %d: r=%d err=%d got=%lu out=%d", cap, r, e, (unsigned long)got, n);
        else CHECKF(r == SOCKET_ERROR && e == WSAEFAULT && u && n == cap && q == (cap == 0), "namelen %d: r=%d err=%d untouched=%d out=%d queued=%d", cap, r, e, u, n, q);
    }
    name_rx(AF_INET, -1, &r, &e, &q, &u, &n, &got);
    CHECKF(r == SOCKET_ERROR && e == WSAEFAULT && q == 1, "no name pointer: r=%d err=%d queued=%d", r, e, q);
}
TEST(xa_receive_name_length_v6) {
    int cap, r, e, q, u, n; DWORD got; UP6();
    for (cap = 0; cap <= 32; cap += 4) {
        name_rx(AF_INET6, cap, &r, &e, &q, &u, &n, &got);
        if (cap >= 28) CHECKF(r == 0 && got == 5 && n == 28 && !u && !q, "namelen %d: r=%d err=%d got=%lu out=%d", cap, r, e, (unsigned long)got, n);
        else CHECKF(r == SOCKET_ERROR && e == WSAEFAULT && u && n == cap && q == (cap == 0), "namelen %d: r=%d err=%d untouched=%d out=%d queued=%d", cap, r, e, u, n, q);
    }
}

/* ---- connected datagram sockets ---- */
TEST(xa_connected_filters_foreign_senders_in_order) {
    xu_ep a, b, c; UP(); if (!open_pair(&a, &b, AF_INET) || !xu_open(&c, AF_INET)) { t_skip("udp endpoint unavailable"); return; }
    CHECK(U(connect)(b.s, (struct sockaddr *)&a.sa, a.len) == 0);
    CHECK(tx(&c, &b, "cc", 2) == 2); CHECK(tx(&a, &b, "aaa", 3) == 3);
    xu_recvw(b.s, &RX, 8, 0, 1, 0); EXPECT_EQ(RX.r, 0); EXPECT_EQ(RX.got, 3);
    CHECK(!xu_ready(b.s, 50));
    xu_free(&a); xu_free(&b); xu_free(&c);
}
/* WSASendMsg and sendto on a connected datagram socket may name another destination; omitting it uses the peer */
TEST(xa_connected_send_may_override_destination) {
    xu_ep a, b, c; DWORD sent = 0; int r; UP(); if (!open_pair(&a, &b, AF_INET) || !xu_open(&c, AF_INET)) { t_skip("udp endpoint unavailable"); return; }
    CHECK(U(connect)(b.s, (struct sockaddr *)&a.sa, a.len) == 0);
    r = xu_send(b.s, &c, "x", 1, NULL, 0, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 1);
    xu_recvw(c.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 1);
    r = xu_send(b.s, NULL, "yy", 2, NULL, 0, 0, &sent); EXPECT_EQ(r, 0); EXPECT_EQ(sent, 2);
    xu_recvw(a.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 2);
    r = U(sendto)(b.s, "zzz", 3, 0, (struct sockaddr *)&c.sa, c.len); EXPECT_EQ(r, 3);
    xu_recvw(c.s, &RX, 8, 0, 0, 0); EXPECT_EQ(RX.got, 3);
    CHECK(!xu_ready(a.s, 30));
    xu_free(&a); xu_free(&b); xu_free(&c);
}
/* control data is decided per datagram: two senders with different hop limits queue two datagrams that are
 * read back in arrival order each with its own value */
TEST(xa_queued_datagrams_each_carry_own_control) {
    xu_ep a, c, b; int i; static const int TTL[2] = {10, 20}; UP(); if (!xu_open(&a, AF_INET) || !xu_open(&c, AF_INET) || !xu_open(&b, AF_INET)) { t_skip("udp endpoint unavailable"); return; }
    CHECK(xu_setint(b.s, L4, XU_IP_RECVTTL, 1) == 0); CHECK(xu_setint(a.s, L4, XU_IP_TTL, TTL[0]) == 0); CHECK(xu_setint(c.s, L4, XU_IP_TTL, TTL[1]) == 0);
    CHECK(tx(&a, &b, "a", 1) == 1); CHECK(tx(&c, &b, "c", 1) == 1);
    for (i = 0; i < 2; i++) {
        const unsigned char *p; size_t n;
        xu_recvw(b.s, &RX, 8, 64, 1, 0); EXPECT_EQ(RX.r, 0);
        CHECKF(RX.data[0] == (i ? 'c' : 'a'), "datagram %d from the wrong sender", i);
        p = xu_cmsg_find(RX.ctl, RX.ctllen, L4, 4, &n); CHECKF(p && n == 4 && *(const int *)p == TTL[i], "datagram %d hop limit", i);
        { const xu_ep *who = i ? &c : &a; CHECK(((struct sockaddr_in *)&RX.from)->sin_port == ((const struct sockaddr_in *)&who->sa)->sin_port); }
    }
    xu_free(&a); xu_free(&b); xu_free(&c);
}

/* ---- extension function lookup ---- */
TEST(xa_extension_function_lookup_rules) {
    SOCKET s4, s6, t; GUID gr = WSAID_WSARECVMSG, gs = WSAID_WSASENDMSG, bad = {1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
    void *r4 = 0, *r6 = 0, *rt = 0, *s4p = 0, *small = 0; DWORD got; int r, e; UP();
    s4 = U(socket)(AF_INET, SOCK_DGRAM, 0); s6 = U(socket)(AF_INET6, SOCK_DGRAM, 0); t = U(socket)(AF_INET, SOCK_STREAM, 0);
    REQUIRE(s4 != INVALID_SOCKET && t != INVALID_SOCKET);
    got = 0; r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, &r4, sizeof r4, &got, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(got, 8); CHECK(r4 != NULL);
    r = U(WSAIoctl)(t, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, &rt, sizeof rt, &got, NULL, NULL); EXPECT_EQ(r, 0); CHECK(rt == r4);
    if (s6 != INVALID_SOCKET) { r = U(WSAIoctl)(s6, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, &r6, sizeof r6, &got, NULL, NULL); EXPECT_EQ(r, 0); CHECK(r6 == r4); }
    r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &gs, sizeof gs, &s4p, sizeof s4p, &got, NULL, NULL); EXPECT_EQ(r, 0); CHECK(s4p != NULL && s4p != r4);
    /* output buffer too small: fault, and the required size is reported */
    got = 0; xu_seterr(0); r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, &small, 4, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEFAULT);
    xu_seterr(0); r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, &small, 0, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEFAULT);
    /* input buffer too short for a GUID */
    xu_seterr(0); r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, 15, &small, 8, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEFAULT);
    /* unknown function id */
    xu_seterr(0); r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &bad, sizeof bad, &small, 8, &got, NULL, NULL); e = ERRIF(r); EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(e, WSAEINVAL);
    /* a larger output buffer is fine and only 8 bytes are written */
    { unsigned char big[16]; memset(big, 0x5A, sizeof big); got = 0; r = U(WSAIoctl)(s4, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, big, sizeof big, &got, NULL, NULL); EXPECT_EQ(r, 0); EXPECT_EQ(got, 8); CHECK(big[8] == 0x5A && big[15] == 0x5A); }
    xu_close(s4); xu_close(s6); xu_close(t);
}
