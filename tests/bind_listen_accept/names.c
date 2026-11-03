/* getsockname() and getpeername(): handle and state errors, the length protocol, and which name each end of
 * a loopback connection reports.
 *
 * Measures: an unbound socket has no name (WSAEINVAL) and an unconnected one no peer (WSAENOTCONN); a
 * buffer shorter than the family's sockaddr fails with WSAEFAULT and leaves both buffer and length alone;
 * a longer buffer receives exactly one sockaddr, its length is rewritten and the bytes beyond are not
 * touched; a wildcard-bound listener reports the wildcard while its accepted sockets report the concrete
 * address; accepted and connecting ends mirror each other.
 */
#include "bla.h"

#define SENT 0x5a

/* ---- getsockname: handle and state ---- */

TEST(bla_name_closed_socket_is_notsock)
{
    struct sockaddr_in a;
    int n = sizeof a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(cls(s), 0);
    FAILS(gsn(s, &a, &n), WSAENOTSOCK);
    EQ(n, sizeof a);
}

TEST(bla_name_closed_socket_null_args_is_notsock)
{
    SOCKET s;
    NEED();
    s = tcp();
    EQ(cls(s), 0);
    FAILS(gsn(s, NULL, NULL), WSAENOTSOCK);       /* the handle is judged before the pointers */
    FAILS(gpn(s, NULL, NULL), WSAENOTSOCK);
}

TEST(bla_name_bad_handles)
{
    struct sockaddr_in a;
    int n = sizeof a;
    NEED();
    FAILS(gsn(0, &a, &n), WSAENOTSOCK);
    FAILS(gsn((SOCKET)0xdeadbeef, &a, &n), WSAENOTSOCK);
    FAILS(gsn(INVALID_SOCKET, &a, &n), WSAENOTSOCK);
    FAILS(gpn(0, &a, &n), WSAENOTSOCK);
    FAILS(gpn((SOCKET)0xdeadbeef, &a, &n), WSAENOTSOCK);
}

TEST(bla_name_unbound_tcp_is_einval)
{
    struct sockaddr_in a, ref;
    int n = sizeof a;
    SOCKET s;
    NEED();
    s = tcp();
    memset(&a, SENT, sizeof a);
    ref = a;
    FAILS(gsn(s, &a, &n), WSAEINVAL);
    EQ(n, sizeof a);
    CHECK(!memcmp(&a, &ref, sizeof a));                 /* the buffer is left alone */
    cls(s);
}

TEST(bla_name_unbound_udp_is_einval)
{
    struct sockaddr_in a;
    int n = sizeof a;
    SOCKET s;
    NEED();
    s = udp();
    FAILS(gsn(s, &a, &n), WSAEINVAL);
    cls(s);
}

TEST(bla_name_unbound_v6_is_einval)
{
    struct sockaddr_in6 a;
    int n = sizeof a;
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    FAILS(gsn(s, &a, &n), WSAEINVAL);
    cls(s);
    s = udp6();
    FAILS(gsn(s, &a, &n), WSAEINVAL);
    cls(s);
}

TEST(bla_name_unbound_state_checked_before_short_length)
{
    struct sockaddr_in a;
    int n = 1;
    SOCKET s;
    NEED();
    s = tcp();
    FAILS(gsn(s, &a, &n), WSAEINVAL);                   /* state first, then the buffer size */
    EQ(n, 1);
    cls(s);
}

/* ---- getsockname: length protocol ---- */

struct len_row { int len; int ok; };
static const struct len_row sn_rows[] = {
    { 0, 0 }, { 1, 0 }, { 2, 0 }, { 8, 0 }, { 15, 0 },
    { 16, 1 }, { 17, 1 }, { 20, 1 }, { 28, 1 }, { 64, 1 }, { 128, 1 },
};

static void sockname_len(int len, int ok)
{
    union { struct sockaddr_in a; unsigned char raw[256]; } buf, ref;
    struct sockaddr_in bound;
    int n = len, r;
    SOCKET s = tcp();
    EQ(bind_lo(s, &bound), 0);
    memset(&buf, SENT, sizeof buf);
    ref = buf;
    wset(0x5a5a);
    r = gsn(s, &buf, &n);
    if (!ok) {
        EQ(r, SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
        EQ(n, len);                                     /* length untouched on failure */
        CHECK(!memcmp(&buf, &ref, sizeof buf));         /* and so is the buffer */
    } else {
        EQ(r, 0);
        EQ(n, sizeof(struct sockaddr_in));
        CHECK(buf.a.sin_port == bound.sin_port);
        CHECK(is_lo4(&buf.a));
        /* nothing past one sockaddr_in is written */
        CHECK(!memcmp(buf.raw + sizeof(struct sockaddr_in), ref.raw + sizeof(struct sockaddr_in),
                      sizeof buf - sizeof(struct sockaddr_in)));
    }
    cls(s);
}
#define SNLEN(i) TEST(bla_name_getsockname_len_row_##i) { NEED(); sockname_len(sn_rows[i].len, sn_rows[i].ok); }
SNLEN(0) SNLEN(1) SNLEN(2) SNLEN(3) SNLEN(4) SNLEN(5) SNLEN(6) SNLEN(7) SNLEN(8) SNLEN(9) SNLEN(10)

TEST(bla_name_getsockname_negative_length)
{
    struct sockaddr_in a, bound;
    int n = -1;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &bound), 0);
    wset(0x5a5a);
    CHECK(gsn(s, &a, &n) == SOCKET_ERROR);
    t_note("getsockname with length -1 -> %s", werr_class(werr()));
    EQ(n, -1);
    cls(s);
}

TEST(bla_name_getsockname_v6_lengths)
{
    struct sockaddr_in6 a = lo6(0), got;
    static const int bad[] = { 0, 4, 16, 24, 27 };
    unsigned i;
    int n;
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    EQ(bnd(s, &a, sizeof a), 0);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        n = bad[i];
        memset(&got, SENT, sizeof got);
        FAILS(gsn(s, &got, &n), WSAEFAULT);
        EQ(n, bad[i]);
    }
    n = sizeof got;
    EQ(gsn(s, &got, &n), 0);
    EQ(n, sizeof got);
    EQ(got.sin6_family, AF_INET6);
    cls(s);
}

TEST(bla_name_getsockname_v6_longer_buffer_gets_28_bytes)
{
    union { struct sockaddr_in6 a; unsigned char raw[128]; } buf;
    struct sockaddr_in6 bound = lo6(0);
    int n = sizeof buf, i;
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    EQ(bnd(s, &bound, sizeof bound), 0);
    memset(&buf, SENT, sizeof buf);
    EQ(gsn(s, &buf, &n), 0);
    EQ(n, sizeof(struct sockaddr_in6));
    for (i = sizeof(struct sockaddr_in6); i < (int)sizeof buf; i++) EQ(buf.raw[i], SENT);
    cls(s);
}

TEST(bla_name_getsockname_is_repeatable)
{
    struct sockaddr_in a, b, c;
    int n = sizeof a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    n = sizeof b; EQ(gsn(s, &b, &n), 0);
    n = sizeof c; EQ(lsn(s, 1), 0); EQ(gsn(s, &c, &n), 0);        /* listening does not change the name */
    CHECK(!memcmp(&a, &b, sizeof a));
    CHECK(!memcmp(&a, &c, sizeof a));
    cls(s);
}

TEST(bla_name_getsockname_wildcard_listener_keeps_wildcard)
{
    struct sockaddr_in w = any4(0), got;
    int n = sizeof got;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bnd(s, &w, sizeof w), 0);
    EQ(lsn(s, 1), 0);
    EQ(gsn(s, &got, &n), 0);
    CHECK(is_any4(&got));
    CHECK(got.sin_port != 0);
    cls(s);
}

/* ---- getsockname after implicit binds ---- */

TEST(bla_name_udp_sendto_binds_wildcard_with_port)
{
    struct sockaddr_in target, got;
    int n = sizeof got;
    SOCKET s, t;
    NEED();
    t = udp();
    EQ(bind_lo(t, &target), 0);
    s = udp();
    EQ(U(sendto)(s, "x", 1, 0, (struct sockaddr *)&target, sizeof target), 1);
    EQ(gsn(s, &got, &n), 0);
    CHECK(is_any4(&got));
    CHECK(got.sin_port != 0);
    cls(s); cls(t);
}

TEST(bla_name_udp_connect_binds_loopback_source)
{
    struct sockaddr_in target, got;
    int n = sizeof got;
    SOCKET s, t;
    NEED();
    t = udp();
    EQ(bind_lo(t, &target), 0);
    s = udp();
    EQ(con(s, &target, sizeof target), 0);
    EQ(gsn(s, &got, &n), 0);
    CHECK(is_lo4(&got));
    CHECK(got.sin_port != 0);
    CHECK(got.sin_port != target.sin_port);
    cls(s); cls(t);
}

TEST(bla_name_tcp_connect_binds_loopback_source)
{
    struct sockaddr_in a, got;
    int n = sizeof got;
    SOCKET l, c;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    EQ(gsn(c, &got, &n), 0);
    CHECK(is_lo4(&got));
    CHECK(got.sin_port != 0);
    CHECK(got.sin_port != a.sin_port);
    cls(c); cls(l);
}

TEST(bla_name_udp_sendto_second_destination_keeps_local_port)
{
    struct sockaddr_in t1, t2, g1, g2;
    int n = sizeof g1;
    SOCKET s, a, b;
    NEED();
    a = udp(); b = udp();
    EQ(bind_lo(a, &t1), 0);
    EQ(bind_lo(b, &t2), 0);
    s = udp();
    EQ(U(sendto)(s, "x", 1, 0, (struct sockaddr *)&t1, sizeof t1), 1);
    EQ(gsn(s, &g1, &n), 0);
    EQ(U(sendto)(s, "y", 1, 0, (struct sockaddr *)&t2, sizeof t2), 1);
    n = sizeof g2;
    EQ(gsn(s, &g2, &n), 0);
    CHECK(g1.sin_port == g2.sin_port);
    cls(s); cls(a); cls(b);
}

/* ---- connected pair: the two ends mirror each other ---- */

struct pair { SOCKET l, c, s; struct sockaddr_in la; };
static int mkpair(struct pair *p, int wildcard)
{
    memset(p, 0, sizeof *p);
    p->l = tcp(); p->c = INVALID_SOCKET; p->s = INVALID_SOCKET;
    if (p->l == INVALID_SOCKET) return 0;
    if (wildcard) {
        struct sockaddr_in w = any4(0);
        int n = sizeof p->la;
        if (bnd(p->l, &w, sizeof w) || gsn(p->l, &p->la, &n)) return 0;
        p->la.sin_addr.s_addr = 0x0100007f;               /* dial the loopback address of the wildcard port */
    } else if (bind_lo(p->l, &p->la)) return 0;
    if (lsn(p->l, 1)) return 0;
    p->c = dial(&p->la);
    if (p->c == INVALID_SOCKET) return 0;
    p->s = acc_wait(p->l, NULL, NULL, 3000);
    return p->s != INVALID_SOCKET;
}
static void pair_close(struct pair *p)
{
    if (p->s != INVALID_SOCKET && p->s) cls(p->s);
    if (p->c != INVALID_SOCKET && p->c) cls(p->c);
    if (p->l != INVALID_SOCKET && p->l) cls(p->l);
}

TEST(bla_name_client_peer_is_listener_name)
{
    struct pair p;
    struct sockaddr_in pn;
    int n = sizeof pn;
    NEED();
    CHECK(mkpair(&p, 0));
    EQ(gpn(p.c, &pn, &n), 0);
    EQ(n, sizeof pn);
    CHECK(!memcmp(&pn, &p.la, sizeof pn));
    pair_close(&p);
}

TEST(bla_name_accepted_sockname_equals_listener_name)
{
    struct pair p;
    struct sockaddr_in sn;
    int n = sizeof sn;
    NEED();
    CHECK(mkpair(&p, 0));
    EQ(gsn(p.s, &sn, &n), 0);
    CHECK(!memcmp(&sn, &p.la, sizeof sn));
    pair_close(&p);
}

TEST(bla_name_accepted_peer_equals_client_sockname)
{
    struct pair p;
    struct sockaddr_in cn, pn;
    int n = sizeof cn, m = sizeof pn;
    NEED();
    CHECK(mkpair(&p, 0));
    EQ(gsn(p.c, &cn, &n), 0);
    EQ(gpn(p.s, &pn, &m), 0);
    CHECK(!memcmp(&cn, &pn, sizeof cn));
    pair_close(&p);
}

TEST(bla_name_wildcard_listener_accepted_socket_reports_concrete_address)
{
    struct pair p;
    struct sockaddr_in sn, ln;
    int n = sizeof sn, m = sizeof ln;
    NEED();
    CHECK(mkpair(&p, 1));
    EQ(gsn(p.s, &sn, &n), 0);
    EQ(gsn(p.l, &ln, &m), 0);
    CHECK(is_lo4(&sn));                    /* the address the client dialled */
    CHECK(is_any4(&ln));                   /* the listener itself is still the wildcard */
    CHECK(sn.sin_port == ln.sin_port);
    pair_close(&p);
}

TEST(bla_name_client_and_accepted_ports_are_distinct)
{
    struct pair p;
    struct sockaddr_in cn, sn;
    int n = sizeof cn, m = sizeof sn;
    NEED();
    CHECK(mkpair(&p, 0));
    EQ(gsn(p.c, &cn, &n), 0);
    EQ(gsn(p.s, &sn, &m), 0);
    CHECK(cn.sin_port != sn.sin_port);
    pair_close(&p);
}

TEST(bla_name_accepted_name_survives_listener_close)
{
    struct pair p;
    struct sockaddr_in before, after;
    int n = sizeof before, m = sizeof after;
    NEED();
    CHECK(mkpair(&p, 0));
    EQ(gsn(p.s, &before, &n), 0);
    cls(p.l); p.l = INVALID_SOCKET;
    EQ(gsn(p.s, &after, &m), 0);
    CHECK(!memcmp(&before, &after, sizeof before));
    pair_close(&p);
}

/* ---- getpeername: state ---- */

TEST(bla_peer_tcp_unconnected_is_notconn)
{
    struct sockaddr_in a;
    int n = sizeof a;
    SOCKET s;
    NEED();
    s = tcp();
    FAILS(gpn(s, &a, &n), WSAENOTCONN);
    EQ(n, sizeof a);
    EQ(bind_lo(s, NULL), 0);
    n = sizeof a;
    FAILS(gpn(s, &a, &n), WSAENOTCONN);                 /* bound is still not connected */
    cls(s);
}

TEST(bla_peer_listening_socket_is_notconn)
{
    struct sockaddr_in a, p;
    int n = sizeof p;
    SOCKET l;
    NEED();
    l = listener(&a, 1);
    FAILS(gpn(l, &p, &n), WSAENOTCONN);
    cls(l);
}

TEST(bla_peer_state_error_does_not_touch_buffer)
{
    struct sockaddr_in a, ref;
    int n = sizeof a;
    SOCKET s;
    NEED();
    s = tcp();
    memset(&a, SENT, sizeof a);
    ref = a;
    FAILS(gpn(s, &a, &n), WSAENOTCONN);
    CHECK(!memcmp(&a, &ref, sizeof a));
    cls(s);
}

TEST(bla_peer_udp_bound_unconnected_is_notconn)
{
    struct sockaddr_in a, p;
    int n = sizeof p;
    SOCKET s;
    NEED();
    s = udp();
    EQ(bind_lo(s, &a), 0);
    FAILS(gpn(s, &p, &n), WSAENOTCONN);
    cls(s);
}

TEST(bla_peer_failed_connect_is_notconn)
{
    struct sockaddr_in dst = dead_port(), p;
    int n = sizeof p;
    SOCKET s;
    NEED();
    s = tcp();
    CHECK(con(s, &dst, sizeof dst) == SOCKET_ERROR);
    FAILS(gpn(s, &p, &n), WSAENOTCONN);
    cls(s);
}

/* ---- getpeername: length protocol ---- */

static const struct len_row pn_rows[] = {
    { 1, 0 }, { 2, 0 }, { 8, 0 }, { 15, 0 },
    { 16, 1 }, { 17, 1 }, { 32, 1 }, { 128, 1 },
};
static void peername_len(int len, int ok)
{
    union { struct sockaddr_in a; unsigned char raw[256]; } buf, ref;
    struct pair p;
    int n = len, r;
    CHECK(mkpair(&p, 0));
    memset(&buf, SENT, sizeof buf);
    ref = buf;
    wset(0x5a5a);
    r = gpn(p.c, &buf, &n);
    if (!ok) {
        EQ(r, SOCKET_ERROR);
        EQ(werr(), WSAEFAULT);
        EQ(n, len);
        CHECK(!memcmp(&buf, &ref, sizeof buf));
    } else {
        EQ(r, 0);
        EQ(n, sizeof(struct sockaddr_in));
        CHECK(!memcmp(&buf.a, &p.la, sizeof p.la));
        CHECK(!memcmp(buf.raw + sizeof(struct sockaddr_in), ref.raw + sizeof(struct sockaddr_in),
                      sizeof buf - sizeof(struct sockaddr_in)));
    }
    pair_close(&p);
}
#define PNLEN(i) TEST(bla_peer_getpeername_len_row_##i) { NEED(); peername_len(pn_rows[i].len, pn_rows[i].ok); }
PNLEN(0) PNLEN(1) PNLEN(2) PNLEN(3) PNLEN(4) PNLEN(5) PNLEN(6) PNLEN(7)

TEST(bla_peer_negative_length)
{
    struct pair p;
    struct sockaddr_in a;
    int n = -4;
    NEED();
    CHECK(mkpair(&p, 0));
    wset(0x5a5a);
    CHECK(gpn(p.c, &a, &n) == SOCKET_ERROR);
    EQ(werr(), WSAEFAULT);
    EQ(n, -4);
    pair_close(&p);
}

TEST(bla_peer_accepted_socket_has_peer)
{
    struct pair p;
    struct sockaddr_in a;
    int n = sizeof a;
    NEED();
    CHECK(mkpair(&p, 0));
    EQ(gpn(p.s, &a, &n), 0);
    CHECK(is_lo4(&a));
    pair_close(&p);
}

TEST(bla_peer_after_local_close_of_peer_is_still_reported_by_other_end)
{
    struct pair p;
    struct sockaddr_in a;
    int n = sizeof a;
    char c;
    NEED();
    CHECK(mkpair(&p, 0));
    cls(p.s); p.s = INVALID_SOCKET;
    rcvto(p.c, 3000);
    EQ(rcv(p.c, &c, 1), 0);                              /* orderly close seen as end of stream */
    wset(0x5a5a);
    n = sizeof a;
    if (gpn(p.c, &a, &n) == 0) t_note("peer name still reported after the remote close");
    else t_note("peer name after the remote close -> %s", werr() == WSAENOTCONN ? "NOTCONN" : werr_class(werr()));
    pair_close(&p);
}

TEST(bla_peer_udp_connect_to_wildcard_like_target)
{
    struct sockaddr_in t, got;
    int n = sizeof got;
    SOCKET s, u;
    NEED();
    u = udp();
    EQ(bind_lo(u, &t), 0);
    s = udp();
    EQ(con(s, &t, sizeof t), 0);
    EQ(gpn(s, &got, &n), 0);
    CHECK(!memcmp(&got, &t, sizeof t));
    cls(s); cls(u);
}

TEST(bla_peer_udp_reconnect_changes_peer)
{
    struct sockaddr_in t1, t2, got;
    int n = sizeof got;
    SOCKET s, a, b;
    NEED();
    a = udp(); b = udp();
    EQ(bind_lo(a, &t1), 0);
    EQ(bind_lo(b, &t2), 0);
    s = udp();
    EQ(con(s, &t1, sizeof t1), 0);
    EQ(con(s, &t2, sizeof t2), 0);
    EQ(gpn(s, &got, &n), 0);
    CHECK(got.sin_port == t2.sin_port);
    cls(s); cls(a); cls(b);
}

/* ---- IPv6 pair ---- */

TEST(bla_name_v6_pair_mirrors)
{
    struct sockaddr_in6 la = lo6(0), cn, sn, pn, ln;
    int n, m;
    SOCKET l, c, s;
    NEED(); NEED6();
    l = tcp6();
    EQ(bnd(l, &la, sizeof la), 0);
    n = sizeof ln; EQ(gsn(l, &ln, &n), 0);
    EQ(lsn(l, 1), 0);
    c = tcp6();
    EQ(con(c, &ln, sizeof ln), 0);
    s = acc_wait(l, NULL, NULL, 3000);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        n = sizeof cn; EQ(gsn(c, &cn, &n), 0);
        m = sizeof pn; EQ(gpn(s, &pn, &m), 0);
        EQ(m, sizeof pn);
        EQ(pn.sin6_family, AF_INET6);
        CHECK(pn.sin6_port == cn.sin6_port);
        CHECK(!memcmp(&pn.sin6_addr, &cn.sin6_addr, sizeof pn.sin6_addr));
        n = sizeof sn; EQ(gsn(s, &sn, &n), 0);
        CHECK(sn.sin6_port == ln.sin6_port);
        CHECK(!memcmp(&sn.sin6_addr, &ln.sin6_addr, sizeof sn.sin6_addr));
        cls(s);
    }
    cls(c); cls(l);
}

TEST(bla_peer_v6_short_buffer_is_efault)
{
    struct sockaddr_in6 la = lo6(0), ln, pn;
    int n = sizeof ln, m;
    SOCKET l, c, s;
    NEED(); NEED6();
    l = tcp6();
    EQ(bnd(l, &la, sizeof la), 0);
    EQ(gsn(l, &ln, &n), 0);
    EQ(lsn(l, 1), 0);
    c = tcp6();
    EQ(con(c, &ln, sizeof ln), 0);
    s = acc_wait(l, NULL, NULL, 3000);
    m = 16;
    FAILS(gpn(c, &pn, &m), WSAEFAULT);
    EQ(m, 16);
    m = 27;
    FAILS(gpn(c, &pn, &m), WSAEFAULT);
    m = sizeof pn;
    EQ(gpn(c, &pn, &m), 0);
    EQ(m, sizeof pn);
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}
