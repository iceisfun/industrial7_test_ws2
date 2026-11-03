/* Ancillary data over WSARecvMsg / WSASendMsg for IPv6 and dual-stack sockets, plus the IPv4
 * equivalents when mixed on one receiver.  The control-message walk uses the documented WSACMSGHDR
 * layout directly (16-byte header on x64, data aligned to 8), not the SDK macros.
 * Measures: structure sizes and offsets; which control messages appear for which socket options; their
 * level / type / length / payload; hop limit propagation; behaviour when options are switched off;
 * truncation of the control and data buffers (flags and error codes); sender name reporting through the
 * message structure; scatter/gather; WSASendMsg with and without control data. */
#include "d6.h"

#define LVL_IP   0   /* IPPROTO_IP */
#define LVL_IPV6 41  /* IPPROTO_IPV6 */
#define T_PKTINFO 19
#define T_V6_HOPLIMIT 21
#define T_V4_TTL 4
#define T_V6_TCLASS 39
#define T_V4_TOS 8
static const char PL[] = "cmsg-payload";

/* receiver (v6, bound to `kind`) + sender (v6, loopback) with a ready WSARecvMsg pointer */
typedef struct { usk r, s; LPFN_WSARECVMSG rm; } duo6;
static int duo6_open(duo6 *d, int kind, int v6only) {
    memset(d, 0, sizeof *d);
    if (!usk_open6(&d->r, kind, v6only) || !usk_open6(&d->s, K_LOOP, -1)) return 0;
    d->rm = d_get_recvmsg(d->r.s);
    if (!d->rm) { t_skip("WSARecvMsg not available"); return 0; }
    return 1;
}
static void duo6_close(duo6 *d) { d_close(d->r.s); d_close(d->s.s); }
static int duo6_send(duo6 *d) {
    struct sockaddr_in6 a; mk6(&a, K_LOOP, d->r.port);
    return d_sendto(d->s.s, PL, sizeof PL, &a, sizeof a);
}
/* wait for a datagram and receive it with control data; returns the WSARecvMsg result */
static int duo6_recv(duo6 *d, rmsg *m) {
    rmsg_init(m);
    if (!d_readable(d->r.s, 3000)) return -2;
    return d->rm(d->r.s, &m->m, &m->got, NULL, NULL);
}
static void on(SOCKET s, int lvl, int opt) { CHECK(d_setint(s, lvl, opt, 1) == 0); }

TEST(ds6_cmsg_structure_sizes_and_offsets) {
    EXPECT_EQ(sizeof(WSACMSGHDR), 16);
    EXPECT_EQ(offsetof(WSACMSGHDR, cmsg_len), 0);
    EXPECT_EQ(offsetof(WSACMSGHDR, cmsg_level), 8);
    EXPECT_EQ(offsetof(WSACMSGHDR, cmsg_type), 12);
    EXPECT_EQ(sizeof(WSAMSG), 56);
    EXPECT_EQ(offsetof(WSAMSG, name), 0);
    EXPECT_EQ(offsetof(WSAMSG, namelen), 8);
    EXPECT_EQ(offsetof(WSAMSG, lpBuffers), 16);
    EXPECT_EQ(offsetof(WSAMSG, dwBufferCount), 24);
    EXPECT_EQ(offsetof(WSAMSG, Control), 32);
    EXPECT_EQ(offsetof(WSAMSG, dwFlags), 48);
    EXPECT_EQ(sizeof(struct in6_pktinfo), 20);
    EXPECT_EQ(sizeof(struct in_pktinfo), 8);
}

TEST(ds6_cmsg_extension_pointers_are_distinct_and_stable) {
    SOCKET a, b; LPFN_WSARECVMSG r1, r2; LPFN_WSASENDMSG s1;
    NEED_V6();
    a = d_sock(AF_INET6, SOCK_DGRAM); b = d_sock(AF_INET, SOCK_DGRAM);
    r1 = d_get_recvmsg(a); r2 = d_get_recvmsg(b); s1 = d_get_sendmsg(a);
    CHECK(r1 != NULL && r2 != NULL && s1 != NULL);
    CHECK((void *)r1 != (void *)s1);
    CHECK(r1 == r2);                         /* the same entry point serves every socket */
    d_close(a); d_close(b);
}

TEST(ds6_cmsg_none_enabled_reports_empty_control) {
    duo6 d; rmsg m;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    EXPECT_EQ(m.got, sizeof PL);
    EXPECT_EQ(m.m.Control.len, 0);
    EXPECT_EQ(m.m.dwFlags, 0);
    duo6_close(&d);
}

TEST(ds6_cmsg_v6_pktinfo_layout) {
    duo6 d; rmsg m; WSACMSGHDR *c; struct in6_pktinfo *pi;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    c = d_cmsg_find(&m.m, LVL_IPV6, T_PKTINFO);
    CHECK(c != NULL);
    if (c) {
        EXPECT_EQ(c->cmsg_len, D_CMSG_HDR + sizeof(struct in6_pktinfo));
        pi = d_cmsg_data(c);
        CHECK(is_v6_loop(&(struct sockaddr_in6){ .sin6_family = AF_INET6, .sin6_addr = pi->ipi6_addr }));
        CHECK(pi->ipi6_ifindex != 0);
        CHECK(m.m.Control.len >= D_CMSG_HDR + sizeof *pi && m.m.Control.len <= D_ALIGN(D_CMSG_HDR + sizeof *pi));
    }
    CHECK(c && d_cmsg_next(&m.m, c) == NULL);     /* nothing else was requested */
    duo6_close(&d);
}

TEST(ds6_cmsg_v6_pktinfo_on_wildcard_receiver_reports_destination) {
    duo6 d; rmsg m; WSACMSGHDR *c;
    NEED_V6();
    if (!duo6_open(&d, K_ANY, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    c = d_cmsg_find(&m.m, LVL_IPV6, T_PKTINFO);
    CHECK(c != NULL);
    if (c) {
        struct in6_pktinfo *pi = d_cmsg_data(c);
        struct sockaddr_in6 t = { .sin6_family = AF_INET6, .sin6_addr = pi->ipi6_addr };
        CHECK(is_v6_loop(&t));               /* the specific destination, not the wildcard */
    }
    duo6_close(&d);
}

TEST(ds6_cmsg_v6_hoplimit_follows_sender_option) {
    duo6 d; rmsg m; WSACMSGHDR *c; static const int vals[] = {1, 77, 255}; int i;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_HOPLIMIT);
    for (i = 0; i < 3; i++) {
        CHECK(d_setint(d.s.s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, vals[i]) == 0);
        CHECK(duo6_send(&d) == (int)sizeof PL);
        EQC(duo6_recv(&d, &m), 0);
        c = d_cmsg_find(&m.m, LVL_IPV6, T_V6_HOPLIMIT);
        CHECK(c != NULL);
        if (c) {
            EXPECT_EQ(c->cmsg_len, D_CMSG_HDR + sizeof(int));
            EXPECT_EQ(*(int *)d_cmsg_data(c), vals[i]);
        }
    }
    duo6_close(&d);
}

TEST(ds6_cmsg_v6_all_three_options_in_one_message) {
    duo6 d; rmsg m; WSACMSGHDR *c; size_t sum = 0; int n = 0;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    on(d.r.s, IPPROTO_IPV6, IPV6_HOPLIMIT);
    on(d.r.s, IPPROTO_IPV6, IPV6_RECVTCLASS);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    CHECK(d_cmsg_find(&m.m, LVL_IPV6, T_PKTINFO) != NULL);
    CHECK(d_cmsg_find(&m.m, LVL_IPV6, T_V6_HOPLIMIT) != NULL);
    CHECK(d_cmsg_find(&m.m, LVL_IPV6, T_V6_TCLASS) != NULL);
    for (c = d_cmsg_first(&m.m); c; c = d_cmsg_next(&m.m, c)) {
        n++;
        EXPECT_EQ(c->cmsg_level, LVL_IPV6);
        sum += D_ALIGN(c->cmsg_len);
        CHECK(((ULONG_PTR)c % 8) == 0);      /* every header lands on an 8-byte boundary */
    }
    EXPECT_EQ(n, 3);
    CHECK(m.m.Control.len <= sum && m.m.Control.len + 8 > sum);
    duo6_close(&d);
}

TEST(ds6_cmsg_v6_tclass_cmsg_layout) {
    duo6 d; rmsg m; WSACMSGHDR *c;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_RECVTCLASS);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    c = d_cmsg_find(&m.m, LVL_IPV6, T_V6_TCLASS);
    CHECK(c != NULL);
    if (c) {
        EXPECT_EQ(c->cmsg_len, D_CMSG_HDR + sizeof(int));
        EXPECT_EQ(*(int *)d_cmsg_data(c), 0);   /* default traffic class */
    }
    duo6_close(&d);
}

TEST(ds6_cmsg_option_switched_off_stops_delivery) {
    duo6 d; rmsg m;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_HOPLIMIT);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    CHECK(d_cmsg_find(&m.m, LVL_IPV6, T_V6_HOPLIMIT) != NULL);
    CHECK(d_setint(d.r.s, IPPROTO_IPV6, IPV6_HOPLIMIT, 0) == 0);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    EXPECT_EQ(m.m.Control.len, 0);
    duo6_close(&d);
}

TEST(ds6_cmsg_options_read_back_booleans) {
    SOCKET s; int v, i; static const int opts[] = {IPV6_PKTINFO, IPV6_HOPLIMIT, IPV6_RECVTCLASS};
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    for (i = 0; i < 3; i++) {
        CHECK(d_getint(s, IPPROTO_IPV6, opts[i], &v) == 0); EXPECT_EQ(v, 0);
        CHECK(d_setint(s, IPPROTO_IPV6, opts[i], 7) == 0);
        CHECK(d_getint(s, IPPROTO_IPV6, opts[i], &v) == 0); EXPECT_EQ(v, 1);
        CHECK(d_setint(s, IPPROTO_IPV6, opts[i], 0) == 0);
        CHECK(d_getint(s, IPPROTO_IPV6, opts[i], &v) == 0); EXPECT_EQ(v, 0);
    }
    d_close(s);
}

TEST(ds6_cmsg_sender_name_in_message) {
    duo6 d; rmsg m; struct sockaddr_in6 *f;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    EXPECT_EQ(m.m.namelen, SZ_SA6);
    f = (struct sockaddr_in6 *)&m.from;
    CHECK(is_v6_loop(f));
    EXPECT_EQ(f->sin6_port, d.s.port);
    duo6_close(&d);
}

TEST(ds6_cmsg_short_name_buffer_note) {
    duo6 d; rmsg m; int rc;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    CHECK(duo6_send(&d) == (int)sizeof PL);
    rmsg_init(&m);
    m.m.namelen = 16;
    CHECK(d_readable(d.r.s, 3000));
    d_seterr(0);
    rc = d.rm(d.r.s, &m.m, &m.got, NULL, NULL);
    t_note("WSARecvMsg with namelen 16 for an IPv6 sender: rc %d err %d", rc, rc ? d_err() : 0);
    duo6_close(&d);
}

TEST(ds6_cmsg_data_truncation_sets_msg_trunc) {
    duo6 d; rmsg m; int rc;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    CHECK(duo6_send(&d) == (int)sizeof PL);
    rmsg_init(&m);
    m.buf.len = 5;
    CHECK(d_readable(d.r.s, 3000));
    d_seterr(0);
    rc = d.rm(d.r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEMSGSIZE);
    CHECK(!memcmp(m.data, PL, 5));
    t_note("data truncation: dwFlags has MSG_TRUNC: %d", (m.m.dwFlags & MSG_TRUNC) != 0);
    duo6_close(&d);
}

TEST(ds6_cmsg_control_truncation_sets_ctrunc) {
    duo6 d; rmsg m; int rc; ULONG lens[3]; int i;
    NEED_V6();
    lens[0] = 8; lens[1] = (ULONG)D_CMSG_HDR; lens[2] = (ULONG)(D_CMSG_HDR + sizeof(struct in6_pktinfo) - 1);
    for (i = 0; i < 3; i++) {
        if (!duo6_open(&d, K_LOOP, -1)) return;
        on(d.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
        CHECK(duo6_send(&d) == (int)sizeof PL);
        rmsg_init(&m);
        m.m.Control.len = lens[i];
        CHECK(d_readable(d.r.s, 3000));
        d_seterr(0);
        rc = d.rm(d.r.s, &m.m, &m.got, NULL, NULL);
        EXPECT_EQ(rc, SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEMSGSIZE);
        CHECK((m.m.dwFlags & MSG_CTRUNC) != 0);
        duo6_close(&d);
    }
}

TEST(ds6_cmsg_control_exact_fit_note) {
    duo6 d; rmsg m; int rc;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    rmsg_init(&m);
    m.m.Control.len = (ULONG)(D_CMSG_HDR + sizeof(struct in6_pktinfo));
    CHECK(d_readable(d.r.s, 3000));
    d_seterr(0);
    rc = d.rm(d.r.s, &m.m, &m.got, NULL, NULL);
    t_note("PKTINFO control buffer of exactly cmsg_len bytes: rc %d err %d flags 0x%lx", rc, rc ? d_err() : 0, (unsigned long)m.m.dwFlags);
    duo6_close(&d);
}

TEST(ds6_cmsg_scatter_buffers_reassemble_payload) {
    duo6 d; rmsg m; WSABUF b[3]; char p0[4], p1[5], p2[64]; int rc;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    CHECK(duo6_send(&d) == (int)sizeof PL);
    rmsg_init(&m);
    b[0].buf = p0; b[0].len = sizeof p0;
    b[1].buf = p1; b[1].len = sizeof p1;
    b[2].buf = p2; b[2].len = sizeof p2;
    m.m.lpBuffers = b; m.m.dwBufferCount = 3;
    CHECK(d_readable(d.r.s, 3000));
    rc = d.rm(d.r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(m.got, sizeof PL);
    CHECK(!memcmp(p0, PL, 4));
    CHECK(!memcmp(p1, PL + 4, 5));
    CHECK(!memcmp(p2, PL + 9, sizeof PL - 9));
    duo6_close(&d);
}

TEST(ds6_cmsg_dualstack_v4_sender_pktinfo_is_mapped) {
    usk r; usk s4; struct sockaddr_in to; rmsg m; LPFN_WSARECVMSG rm; WSACMSGHDR *c; int rc;
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, 0)); CHECK(usk_open4(&s4, 1));
    rm = d_get_recvmsg(r.s);
    if (!rm) { t_skip("no WSARecvMsg"); return; }
    on(r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    mk4(&to, 1, r.port);
    CHECK(d_sendto(s4.s, PL, sizeof PL, &to, sizeof to) == (int)sizeof PL);
    rmsg_init(&m);
    CHECK(d_readable(r.s, 3000));
    rc = rm(r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(m.m.namelen, SZ_SA6);
    CHECK(is_mapped_loop((struct sockaddr_in6 *)&m.from));
    c = d_cmsg_find(&m.m, LVL_IPV6, T_PKTINFO);
    if (!c) t_note("dual-stack IPv6 socket got no IPV6_PKTINFO for an IPv4 datagram");
    else {
        struct in6_pktinfo *pi = d_cmsg_data(c);
        struct sockaddr_in6 t = { .sin6_family = AF_INET6, .sin6_addr = pi->ipi6_addr };
        CHECK(is_mapped_loop(&t));
    }
    d_close(r.s); d_close(s4.s);
}

TEST(ds6_cmsg_dualstack_v4_sender_hoplimit_is_sender_ttl_note) {
    usk r; usk s4; struct sockaddr_in to; rmsg m; LPFN_WSARECVMSG rm; WSACMSGHDR *c; int rc;
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, 0)); CHECK(usk_open4(&s4, 1));
    rm = d_get_recvmsg(r.s);
    if (!rm) { t_skip("no WSARecvMsg"); return; }
    on(r.s, IPPROTO_IPV6, IPV6_HOPLIMIT);
    CHECK(d_setint(s4.s, IPPROTO_IP, IP_TTL, 55) == 0);
    mk4(&to, 1, r.port);
    CHECK(d_sendto(s4.s, PL, sizeof PL, &to, sizeof to) == (int)sizeof PL);
    rmsg_init(&m);
    CHECK(d_readable(r.s, 3000));
    rc = rm(r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    c = d_cmsg_find(&m.m, LVL_IPV6, T_V6_HOPLIMIT);
    if (!c) t_note("no IPV6_HOPLIMIT cmsg for IPv4 datagram on dual-stack socket");
    else t_note("IPV6_HOPLIMIT for IPv4 datagram %s sender TTL", *(int *)d_cmsg_data(c) == 55 ? "equals" : "differs from");
    d_close(r.s); d_close(s4.s);
}

TEST(ds6_cmsg_v4_options_on_v4_socket_combined) {
    usk r, s; struct sockaddr_in to; rmsg m; LPFN_WSARECVMSG rm; WSACMSGHDR *c; int rc;
    NEED_V6();
    CHECK(usk_open4(&r, 1)); CHECK(usk_open4(&s, 1));
    rm = d_get_recvmsg(r.s);
    if (!rm) { t_skip("no WSARecvMsg"); return; }
    on(r.s, IPPROTO_IP, IP_PKTINFO);
    on(r.s, IPPROTO_IP, IP_RECVTTL);
    CHECK(d_setint(s.s, IPPROTO_IP, IP_TTL, 55) == 0);
    mk4(&to, 1, r.port);
    CHECK(d_sendto(s.s, PL, sizeof PL, &to, sizeof to) == (int)sizeof PL);
    rmsg_init(&m);
    CHECK(d_readable(r.s, 3000));
    rc = rm(r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    c = d_cmsg_find(&m.m, LVL_IP, T_PKTINFO);
    CHECK(c != NULL);
    if (c) {
        struct in_pktinfo *pi = d_cmsg_data(c);
        EXPECT_EQ(c->cmsg_len, D_CMSG_HDR + sizeof *pi);
        EXPECT_EQ(pi->ipi_addr.s_addr, d_h32(0x7f000001u));
        CHECK(pi->ipi_ifindex != 0);
    }
    c = d_cmsg_find(&m.m, LVL_IP, T_V4_TTL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cmsg_len, D_CMSG_HDR + sizeof(int)); EXPECT_EQ(*(int *)d_cmsg_data(c), 55); }
    d_close(r.s); d_close(s.s);
}

TEST(ds6_cmsg_v4_and_v6_loopback_interface_index_agree_note) {
    duo6 d; rmsg m; usk r4, s4; struct sockaddr_in to; WSACMSGHDR *c6, *c4; LPFN_WSARECVMSG rm4; int rc;
    NEED_V6();
    if (!duo6_open(&d, K_LOOP, -1)) return;
    on(d.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    CHECK(duo6_send(&d) == (int)sizeof PL);
    EQC(duo6_recv(&d, &m), 0);
    c6 = d_cmsg_find(&m.m, LVL_IPV6, T_PKTINFO);
    CHECK(usk_open4(&r4, 1)); CHECK(usk_open4(&s4, 1));
    rm4 = d_get_recvmsg(r4.s);
    on(r4.s, IPPROTO_IP, IP_PKTINFO);
    mk4(&to, 1, r4.port);
    CHECK(d_sendto(s4.s, PL, sizeof PL, &to, sizeof to) == (int)sizeof PL);
    rmsg_init(&m);
    CHECK(d_readable(r4.s, 3000));
    rc = rm4 ? rm4(r4.s, &m.m, &m.got, NULL, NULL) : -1;
    c4 = d_cmsg_find(&m.m, LVL_IP, T_PKTINFO);
    CHECK(rc == 0 && c4 && c6);
    duo6_close(&d); d_close(r4.s); d_close(s4.s);
}

/* ---- WSASendMsg ------------------------------------------------------------- */
typedef struct { usk r, s; LPFN_WSARECVMSG rm; LPFN_WSASENDMSG sm; } sendkit;
static int sendkit_open(sendkit *k) {
    memset(k, 0, sizeof *k);
    if (!usk_open6(&k->r, K_LOOP, -1) || !usk_open6(&k->s, K_LOOP, -1)) return 0;
    k->rm = d_get_recvmsg(k->r.s); k->sm = d_get_sendmsg(k->s.s);
    if (!k->rm || !k->sm) { t_skip("WSASendMsg/WSARecvMsg unavailable"); return 0; }
    return 1;
}

TEST(ds6_sendmsg_two_buffers_to_named_destination) {
    sendkit k; struct sockaddr_in6 to; WSABUF b[2]; WSAMSG m; DWORD sent = 0; char rcv[64]; int n;
    NEED_V6();
    if (!sendkit_open(&k)) return;
    mk6(&to, K_LOOP, k.r.port);
    b[0].buf = (char *)PL; b[0].len = 4; b[1].buf = (char *)PL + 4; b[1].len = sizeof PL - 4;
    memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&to; m.namelen = sizeof to; m.lpBuffers = b; m.dwBufferCount = 2;
    CHECK(k.sm(k.s.s, &m, 0, &sent, NULL, NULL) == 0);
    EXPECT_EQ(sent, sizeof PL);
    CHECK(d_readable(k.r.s, 3000));
    n = d_recv(k.r.s, rcv, sizeof rcv);
    EXPECT_EQ(n, sizeof PL);
    CHECK(!memcmp(rcv, PL, sizeof PL));
    d_close(k.r.s); d_close(k.s.s);
}

TEST(ds6_sendmsg_connected_socket_without_name) {
    sendkit k; struct sockaddr_in6 to; WSABUF b; WSAMSG m; DWORD sent = 0; char rcv[64];
    NEED_V6();
    if (!sendkit_open(&k)) return;
    mk6(&to, K_LOOP, k.r.port);
    CHECK(d_connect(k.s.s, &to, sizeof to) == 0);
    b.buf = (char *)PL; b.len = sizeof PL;
    memset(&m, 0, sizeof m);
    m.lpBuffers = &b; m.dwBufferCount = 1;
    CHECK(k.sm(k.s.s, &m, 0, &sent, NULL, NULL) == 0);
    EXPECT_EQ(sent, sizeof PL);
    CHECK(d_readable(k.r.s, 3000));
    EQC(d_recv(k.r.s, rcv, sizeof rcv), sizeof PL);
    d_close(k.r.s); d_close(k.s.s);
}

TEST(ds6_sendmsg_unconnected_without_name_is_einval) {
    sendkit k; WSABUF b; WSAMSG m; DWORD sent = 0; int rc;
    NEED_V6();
    if (!sendkit_open(&k)) return;
    b.buf = (char *)PL; b.len = sizeof PL;
    memset(&m, 0, sizeof m);
    m.lpBuffers = &b; m.dwBufferCount = 1;
    d_seterr(0);
    rc = k.sm(k.s.s, &m, 0, &sent, NULL, NULL);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(k.r.s); d_close(k.s.s);
}

TEST(ds6_sendmsg_pktinfo_control_selects_source) {
    sendkit k; struct sockaddr_in6 to; WSABUF b; WSAMSG m; DWORD sent = 0; rmsg rm; char ctl[64] __attribute__((aligned(8)));
    WSACMSGHDR *c = (WSACMSGHDR *)ctl; struct in6_pktinfo *pi; int rc;
    NEED_V6();
    if (!sendkit_open(&k)) return;
    mk6(&to, K_LOOP, k.r.port);
    memset(ctl, 0, sizeof ctl);
    c->cmsg_len = D_CMSG_HDR + sizeof *pi; c->cmsg_level = LVL_IPV6; c->cmsg_type = T_PKTINFO;
    pi = d_cmsg_data(c);
    pi->ipi6_addr = to.sin6_addr;            /* ::1, interface left to the stack */
    pi->ipi6_ifindex = 0;
    b.buf = (char *)PL; b.len = sizeof PL;
    memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&to; m.namelen = sizeof to; m.lpBuffers = &b; m.dwBufferCount = 1;
    m.Control.buf = ctl; m.Control.len = (ULONG)D_ALIGN(c->cmsg_len);
    d_seterr(0);
    rc = k.sm(k.s.s, &m, 0, &sent, NULL, NULL);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(sent, sizeof PL);
    on(k.r.s, IPPROTO_IPV6, IPV6_PKTINFO);
    rmsg_init(&rm);
    CHECK(d_readable(k.r.s, 3000));
    rc = k.rm(k.r.s, &rm.m, &rm.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    d_close(k.r.s); d_close(k.s.s);
}

TEST(ds6_sendmsg_hoplimit_control_note) {
    sendkit k; struct sockaddr_in6 to; WSABUF b; WSAMSG m; DWORD sent = 0; rmsg rm; char ctl[64] __attribute__((aligned(8)));
    WSACMSGHDR *c = (WSACMSGHDR *)ctl, *g; int rc;
    NEED_V6();
    if (!sendkit_open(&k)) return;
    on(k.r.s, IPPROTO_IPV6, IPV6_HOPLIMIT);
    mk6(&to, K_LOOP, k.r.port);
    memset(ctl, 0, sizeof ctl);
    c->cmsg_len = D_CMSG_HDR + sizeof(int); c->cmsg_level = LVL_IPV6; c->cmsg_type = T_V6_HOPLIMIT;
    *(int *)d_cmsg_data(c) = 33;
    b.buf = (char *)PL; b.len = sizeof PL;
    memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&to; m.namelen = sizeof to; m.lpBuffers = &b; m.dwBufferCount = 1;
    m.Control.buf = ctl; m.Control.len = (ULONG)D_ALIGN(c->cmsg_len);
    d_seterr(0);
    rc = k.sm(k.s.s, &m, 0, &sent, NULL, NULL);
    t_note("WSASendMsg with IPV6_HOPLIMIT control: rc %d err %d", rc, rc ? d_err() : 0);
    if (rc == 0) {
        rmsg_init(&rm);
        CHECK(d_readable(k.r.s, 3000));
        CHECK(k.rm(k.r.s, &rm.m, &rm.got, NULL, NULL) == 0);
        g = d_cmsg_find(&rm.m, LVL_IPV6, T_V6_HOPLIMIT);
        if (g) t_note("  receiver saw hop limit %s 33", *(int *)d_cmsg_data(g) == 33 ? "equal to" : "different from");
    }
    d_close(k.r.s); d_close(k.s.s);
}

TEST(ds6_sendmsg_to_mapped_destination_on_dualstack_socket) {
    usk r4; SOCKET s; LPFN_WSASENDMSG sm; struct sockaddr_in6 to; WSABUF b; WSAMSG m; DWORD sent = 0; char rcv[64];
    NEED_V6();
    CHECK(usk_open4(&r4, 1));
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    sm = d_get_sendmsg(s);
    if (!sm) { t_skip("no WSASendMsg"); d_close(s); d_close(r4.s); return; }
    mk6(&to, K_MAP_LOOP, r4.port);
    b.buf = (char *)PL; b.len = sizeof PL;
    memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&to; m.namelen = sizeof to; m.lpBuffers = &b; m.dwBufferCount = 1;
    CHECK(sm(s, &m, 0, &sent, NULL, NULL) == 0);
    CHECK(d_readable(r4.s, 3000));
    EQC(d_recv(r4.s, rcv, sizeof rcv), sizeof PL);
    d_close(s); d_close(r4.s);
}
