/* accept() and WSAAccept() without a condition function: error ladder, address-length protocol, non-blocking
 * behaviour and what the accepted socket looks like.
 *
 * The checks run in the order the implementation applies them: handle (WSAENOTSOCK), socket type
 * (WSAEOPNOTSUPP for datagram sockets), listening state (WSAEINVAL), then the address buffer
 * (WSAEFAULT when the supplied length cannot hold the peer's sockaddr), and only then is the queue consulted.
 * A buffer failure therefore leaves the pending connection in place for the next call.
 */
#include "bla.h"

#define SENT 0x5a

/* Both entry points are exercised by every test through one switch. */
static SOCKET do_accept(int wsa, SOCKET s, void *a, int *n)
{
    return wsa ? wacc(s, a, n, NULL, 0) : acc(s, a, n);
}

#define BOTH(name) \
    static void name##_body(int wsa); \
    TEST(name##_accept)    { NEED(); name##_body(0); } \
    TEST(name##_wsaaccept) { NEED(); name##_body(1); } \
    static void name##_body(int wsa)

/* ---- the error ladder ---- */

BOTH(bla_acc_closed_socket)
{
    struct sockaddr_in a;
    int n = sizeof a;
    SOCKET s = tcp();
    EQ(cls(s), 0);
    FAILS(do_accept(wsa, s, &a, &n), WSAENOTSOCK);
    EQ(n, sizeof a);
}

BOTH(bla_acc_closed_socket_null_args)
{
    SOCKET s = tcp();
    EQ(cls(s), 0);
    FAILS(do_accept(wsa, s, NULL, NULL), WSAENOTSOCK);
}

BOTH(bla_acc_bad_handles)
{
    FAILS(do_accept(wsa, 0, NULL, NULL), WSAENOTSOCK);
    FAILS(do_accept(wsa, (SOCKET)0xdeadbeef, NULL, NULL), WSAENOTSOCK);
    FAILS(do_accept(wsa, INVALID_SOCKET, NULL, NULL), WSAENOTSOCK);
}

BOTH(bla_acc_udp_unbound)
{
    SOCKET s = udp();
    FAILS(do_accept(wsa, s, NULL, NULL), WSAEOPNOTSUPP);
    cls(s);
}

BOTH(bla_acc_udp_bound)
{
    struct sockaddr_in a;
    SOCKET s = udp();
    EQ(bind_lo(s, &a), 0);
    FAILS(do_accept(wsa, s, NULL, NULL), WSAEOPNOTSUPP);
    cls(s);
}

BOTH(bla_acc_udp_type_precedes_buffer_checks)
{
    struct sockaddr_in a;
    int n = 0;
    SOCKET s = udp();
    FAILS(do_accept(wsa, s, &a, &n), WSAEOPNOTSUPP);
    cls(s);
}

BOTH(bla_acc_unbound_tcp)
{
    SOCKET s = tcp();
    FAILS(do_accept(wsa, s, NULL, NULL), WSAEINVAL);
    cls(s);
}

BOTH(bla_acc_bound_but_not_listening)
{
    struct sockaddr_in a;
    SOCKET s = tcp();
    EQ(bind_lo(s, &a), 0);
    FAILS(do_accept(wsa, s, NULL, NULL), WSAEINVAL);
    cls(s);
}

BOTH(bla_acc_state_precedes_buffer_checks)
{
    struct sockaddr_in a;
    int n = 0;
    SOCKET s = tcp();
    EQ(bind_lo(s, &a), 0);
    FAILS(do_accept(wsa, s, &a, &n), WSAEINVAL);       /* not listening beats the zero-length buffer */
    cls(s);
}

BOTH(bla_acc_connected_client)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a);
    FAILS(do_accept(wsa, c, NULL, NULL), WSAEINVAL);
    cls(c); cls(l);
}

BOTH(bla_acc_accepted_socket)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s = acc_wait(l, NULL, NULL, 3000);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        FAILS(do_accept(wsa, s, NULL, NULL), WSAEINVAL);
        cls(s);
    }
    cls(c); cls(l);
}

BOTH(bla_acc_v6_unbound)
{
    SOCKET s;
    NEED6();
    s = tcp6();
    FAILS(do_accept(wsa, s, NULL, NULL), WSAEINVAL);
    cls(s);
}

BOTH(bla_acc_failed_bind_socket)
{
    struct sockaddr_in a;
    SOCKET s1 = tcp(), s2 = tcp();
    EQ(bind_lo(s1, &a), 0);
    FAILS(bnd(s2, &a, sizeof a), WSAEADDRINUSE);
    FAILS(do_accept(wsa, s2, NULL, NULL), WSAEINVAL);
    cls(s1); cls(s2);
}

/* ---- non-blocking listener ---- */

BOTH(bla_acc_nonblocking_empty_queue)
{
    struct sockaddr_in a, p;
    int n = sizeof p;
    SOCKET l = listener(&a, 1);
    EQ(nbio(l, 1), 0);
    FAILS(do_accept(wsa, l, &p, &n), WSAEWOULDBLOCK);
    EQ(n, sizeof p);                                    /* untouched */
    FAILS(do_accept(wsa, l, NULL, NULL), WSAEWOULDBLOCK);
    cls(l);
}

BOTH(bla_acc_nonblocking_returns_queued_connection_then_wouldblock)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c, s;
    EQ(nbio(l, 1), 0);
    c = dial(&a);
    CHECK(c != INVALID_SOCKET);
    CHECK(readable(l, 3000));
    s = do_accept(wsa, l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    FAILS(do_accept(wsa, l, NULL, NULL), WSAEWOULDBLOCK);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_nonblocking_drains_three_in_order)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 5), c[3], s[3];
    struct sockaddr_in cn[3], pn;
    int i, n;
    EQ(nbio(l, 1), 0);
    for (i = 0; i < 3; i++) {
        c[i] = dial(&a);
        n = sizeof cn[i];
        EQ(gsn(c[i], &cn[i], &n), 0);
    }
    CHECK(readable(l, 3000));
    for (i = 0; i < 3; i++) {
        n = sizeof pn;
        s[i] = do_accept(wsa, l, &pn, &n);
        CHECK(s[i] != INVALID_SOCKET);
        CHECK(pn.sin_port == cn[i].sin_port);
    }
    FAILS(do_accept(wsa, l, NULL, NULL), WSAEWOULDBLOCK);
    for (i = 0; i < 3; i++) { if (s[i] != INVALID_SOCKET) cls(s[i]); cls(c[i]); }
    cls(l);
}

BOTH(bla_acc_type_error_wins_over_wouldblock)
{
    SOCKET u = udp(), t = tcp();
    EQ(nbio(u, 1), 0);
    EQ(nbio(t, 1), 0);
    FAILS(do_accept(wsa, u, NULL, NULL), WSAEOPNOTSUPP);
    FAILS(do_accept(wsa, t, NULL, NULL), WSAEINVAL);
    cls(u); cls(t);
}

/* ---- address buffer protocol ---- */

struct abuf { int len; int ok; };
static const struct abuf arows[] = {
    { 0, 0 }, { 1, 0 }, { 2, 0 }, { 8, 0 }, { 15, 0 },
    { 16, 1 }, { 17, 1 }, { 28, 1 }, { 64, 1 }, { 128, 1 },
};

static void accept_len(int wsa, int len, int ok)
{
    struct sockaddr_in a, cn;
    union { struct sockaddr_in a; unsigned char raw[256]; } buf, ref;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    int n = len, m = sizeof cn;
    EQ(gsn(c, &cn, &m), 0);
    memset(&buf, SENT, sizeof buf);
    ref = buf;
    wset(0x5a5a);
    s = do_accept(wsa, l, &buf, &n);
    if (!ok) {
        EQ(s, INVALID_SOCKET);
        EQ(werr(), WSAEFAULT);
        EQ(n, len);
        CHECK(!memcmp(&buf, &ref, sizeof buf));
        /* whether the connection stays queued after the refusal is recorded, not required */
        n = sizeof buf.a;
        s = readable(l, 3000) ? do_accept(wsa, l, &buf, &n) : INVALID_SOCKET;
        t_note("connection after short-buffer accept: %s", s != INVALID_SOCKET ? "still queued" : "consumed");
        if (s != INVALID_SOCKET) CHECK(buf.a.sin_port == cn.sin_port);
    } else {
        CHECK(s != INVALID_SOCKET);
        EQ(n, sizeof(struct sockaddr_in));
        CHECK(buf.a.sin_port == cn.sin_port);
        CHECK(is_lo4(&buf.a));
        CHECK(!memcmp(buf.raw + sizeof(struct sockaddr_in), ref.raw + sizeof(struct sockaddr_in),
                      sizeof buf - sizeof(struct sockaddr_in)));
    }
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}
#define ALEN(i) \
    TEST(bla_acc_addrlen_row_##i##_accept)    { NEED(); accept_len(0, arows[i].len, arows[i].ok); } \
    TEST(bla_acc_addrlen_row_##i##_wsaaccept) { NEED(); accept_len(1, arows[i].len, arows[i].ok); }
ALEN(0) ALEN(1) ALEN(2) ALEN(3) ALEN(4) ALEN(5) ALEN(6) ALEN(7) ALEN(8) ALEN(9)

BOTH(bla_acc_negative_length)
{
    struct sockaddr_in a, buf;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    int n = -1;
    s = do_accept(wsa, l, &buf, &n);
    t_note("accept with length -1 -> %s", s != INVALID_SOCKET ? "succeeded" : werr_class(werr()));
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_name_without_length_is_ignored)
{
    struct sockaddr_in a;
    unsigned char buf[32], ref[32];
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    memset(buf, SENT, sizeof buf);
    memcpy(ref, buf, sizeof buf);
    s = do_accept(wsa, l, buf, NULL);
    CHECK(s != INVALID_SOCKET);
    CHECK(!memcmp(buf, ref, sizeof buf));
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_length_without_name_is_ignored)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    int n = 16;
    s = do_accept(wsa, l, NULL, &n);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_storage_sized_buffer_reports_actual_size)
{
    struct sockaddr_in a, cn;
    SOCKADDR_STORAGE ss;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    int n = sizeof ss, m = sizeof cn;
    EQ(gsn(c, &cn, &m), 0);
    memset(&ss, SENT, sizeof ss);
    s = do_accept(wsa, l, &ss, &n);
    CHECK(s != INVALID_SOCKET);
    EQ(n, sizeof(struct sockaddr_in));
    EQ(ss.ss_family, AF_INET);
    CHECK(!memcmp(&ss, &cn, sizeof cn));
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_peer_address_matches_getpeername)
{
    struct sockaddr_in a, from, pn;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    int n = sizeof from, m = sizeof pn;
    s = do_accept(wsa, l, &from, &n);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        EQ(gpn(s, &pn, &m), 0);
        CHECK(!memcmp(&from, &pn, sizeof from));
        cls(s);
    }
    cls(c); cls(l);
}

BOTH(bla_acc_v6_peer_address)
{
    struct sockaddr_in6 la = lo6(0), ln, from;
    SOCKET l, c, s;
    int n = sizeof ln, m = sizeof from;
    NEED6();
    l = tcp6();
    EQ(bnd(l, &la, sizeof la), 0);
    EQ(gsn(l, &ln, &n), 0);
    EQ(lsn(l, 1), 0);
    c = tcp6();
    EQ(con(c, &ln, sizeof ln), 0);
    memset(&from, SENT, sizeof from);
    s = acc_wait(l, NULL, NULL, 3000);
    cls(s);
    /* second connection through the entry point under test */
    cls(c);
    c = tcp6();
    EQ(con(c, &ln, sizeof ln), 0);
    s = do_accept(wsa, l, &from, &m);
    CHECK(s != INVALID_SOCKET);
    EQ(m, sizeof from);
    EQ(from.sin6_family, AF_INET6);
    CHECK(from.sin6_port != 0);
    CHECK(!memcmp(&from.sin6_addr, &ln.sin6_addr, sizeof ln.sin6_addr));
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_v6_short_buffer_is_efault)
{
    struct sockaddr_in6 la = lo6(0), ln, from;
    SOCKET l, c, s;
    int n = sizeof ln, m;
    NEED6();
    l = tcp6();
    EQ(bnd(l, &la, sizeof la), 0);
    EQ(gsn(l, &ln, &n), 0);
    EQ(lsn(l, 1), 0);
    c = tcp6();
    EQ(con(c, &ln, sizeof ln), 0);
    m = sizeof(struct sockaddr_in);                      /* big enough for IPv4 but not for this family */
    FAILS(do_accept(wsa, l, &from, &m), WSAEFAULT);
    EQ(m, sizeof(struct sockaddr_in));
    m = sizeof from;
    s = readable(l, 3000) ? do_accept(wsa, l, &from, &m) : INVALID_SOCKET;
    t_note("v6 connection after short-buffer accept: %s", s != INVALID_SOCKET ? "still queued" : "consumed");
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

/* ---- accepted socket ---- */

BOTH(bla_acc_result_is_a_new_handle)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    s = do_accept(wsa, l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    CHECK(s != l && s != c);
    cls(s);
    cls(c); cls(l);
}

BOTH(bla_acc_result_carries_data_both_ways)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    char buf[8];
    s = do_accept(wsa, l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        rcvto(s, 3000); rcvto(c, 3000);
        EQ(snd(c, "ping", 4), 4);
        EQ(rcv(s, buf, sizeof buf), 4);
        CHECK(!memcmp(buf, "ping", 4));
        EQ(snd(s, "pong", 4), 4);
        EQ(rcv(c, buf, sizeof buf), 4);
        CHECK(!memcmp(buf, "pong", 4));
        cls(s);
    }
    cls(c); cls(l);
}

BOTH(bla_acc_result_acceptconn_zero_listener_one)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    DWORD v = 0xdead;
    int n = sizeof v;
    s = do_accept(wsa, l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        EQ(gso(s, SOL_SOCKET, SO_ACCEPTCONN, &v, &n), 0);
        EQ(v, 0);
        cls(s);
    }
    n = sizeof v;
    EQ(gso(l, SOL_SOCKET, SO_ACCEPTCONN, &v, &n), 0);
    EQ(v, 1);                                           /* the listener keeps listening */
    cls(c); cls(l);
}

BOTH(bla_acc_listener_serves_many_in_sequence)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1);
    int i;
    for (i = 0; i < 8; i++) {
        SOCKET c = dial(&a), s;
        CHECK(c != INVALID_SOCKET);
        s = acc_wait(l, NULL, NULL, 3000);
        if (s == INVALID_SOCKET) { cls(c); break; }
        cls(s);
        cls(c);
    }
    EQ(i, 8);
    cls(l);
}

BOTH(bla_acc_client_closed_before_accept_still_accepted)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), c = dial(&a), s;
    char b;
    cls(c);
    CHECK(readable(l, 3000));
    s = do_accept(wsa, l, NULL, NULL);
    t_note("accept of a connection whose client already closed -> %s", s != INVALID_SOCKET ? "succeeded" : werr_class(werr()));
    if (s != INVALID_SOCKET) {
        rcvto(s, 3000);
        EQ(rcv(s, &b, 1), 0);                           /* the orderly close is delivered as end of stream */
        cls(s);
    }
    cls(l);
}

/* ---- blocking accept woken by a late connection ---- */

static DWORD WINAPI late_connect(void *p)
{
    struct cth *c = (struct cth *)p;
    Sleep(150);
    c->s = tcp();
    c->rc = con(c->s, &c->addr, sizeof c->addr);
    c->err = werr();
    return 0;
}

BOTH(bla_acc_blocking_waits_for_connection)
{
    struct sockaddr_in a, from;
    SOCKET l = listener(&a, 1), s;
    struct cth c;
    int n = sizeof from;
    memset(&c, 0, sizeof c);
    c.addr = a; c.s = INVALID_SOCKET; c.rc = -2;
    c.th = CreateThread(NULL, 0, late_connect, &c, 0, NULL);
    s = do_accept(wsa, l, &from, &n);                    /* nothing queued yet: blocks until the helper connects */
    CHECK(s != INVALID_SOCKET);
    CHECK(cth_finish(&c, 5000));
    EQ(c.rc, 0);
    if (s != INVALID_SOCKET) cls(s);
    if (c.s != INVALID_SOCKET) cls(c.s);
    cls(l);
}

static DWORD WINAPI close_later(void *p)
{
    SOCKET *s = (SOCKET *)p;
    Sleep(200);
    cls(*s);
    return 0;
}

BOTH(bla_acc_blocked_call_fails_when_listener_closed)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 1), r;
    HANDLE th = CreateThread(NULL, 0, close_later, &l, 0, NULL);
    SOCKET saved = l;
    r = do_accept(wsa, saved, NULL, NULL);
    CHECK(r == INVALID_SOCKET);
    t_note("accept released by closesocket -> %s", werr() == WSAEINTR ? "INTR" : werr() == WSAENOTSOCK ? "NOTSOCK" :
           werr() == WSAEINVAL ? "INVAL" : werr_class(werr()));
    CHECK(join(th, 5000));
}
