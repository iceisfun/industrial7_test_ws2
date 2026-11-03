/* getsockopt / setsockopt as implemented inside wsock32.dll (they are not forwarders).
 *
 * The Winsock 1.1 layer translates the old BSD-style IPPROTO_IP option numbers into the Winsock 2 numbers
 * (2->9 multicast interface, 3->10 multicast TTL, 4->11 multicast loop, 5->12 add membership, 6->13 drop
 * membership, 7->4 TTL, 8->3 TOS, 9->14 don't-fragment) when the level is 0, and maps the IPPROTO_TCP
 * option 0x7000 (BSD urgent data) onto TCP_EXPEDITED_1122 (2); that option has the opposite sense, so the
 * stored value is the logical inverse of what the caller wrote or reads (observed on both the set and the
 * get side, on the first byte of the value). All other levels and
 * option numbers go straight through to the ws2_32 function with the same name; the return value on success
 * is 0 and on failure -1 with the error left by ws2_32.
 *
 * Measures: every mapped number against the ws2_32 equivalent (reads and writes), the unmapped numbers and
 * other levels as pass-through, the inversion asymmetry, and the error results for bad sockets and sizes. */
#include "wf.h"

typedef struct { int ret, err, len; unsigned char buf[64]; } optres;

static void get_via(p_getsockopt f, SOCKET s, int lvl, int opt, optres *r, int len) {
    memset(r->buf, 0xAA, sizeof r->buf);
    r->len = len;
    wf_seterr(0);
    r->ret = f(s, lvl, opt, (char *)r->buf, &r->len);
    r->err = r->ret ? wf_err() : 0;
}
static int same_res(const optres *a, const optres *b) {
    if (a->ret != b->ret || a->err != b->err) return 0;
    if (a->ret == 0) return a->len == b->len && !memcmp(a->buf, b->buf, (size_t)a->len);
    return !memcmp(a->buf, b->buf, sizeof a->buf);   /* untouched on failure */
}
static int get_dword(p_getsockopt f, SOCKET s, int lvl, int opt, DWORD *v) {
    int len = sizeof *v; *v = 0;   /* some options (TCP_NODELAY, V6ONLY) return a single byte */
    return f(s, lvl, opt, (char *)v, &len);
}
static int set_dword(p_setsockopt f, SOCKET s, int lvl, int opt, DWORD v) { return f(s, lvl, opt, (const char *)&v, sizeof v); }

/* ---------------------------------------------------------------- IP level: old option numbers */
static const struct { int old_no, new_no; const char *name; } ipmap[] = {
    { 2, 9, "multicast_if" }, { 3, 10, "multicast_ttl" }, { 4, 11, "multicast_loop" }, { 5, 12, "add_membership" },
    { 6, 13, "drop_membership" }, { 7, 4, "ttl" }, { 8, 3, "tos" }, { 9, 14, "dontfragment" }
};

/* reading through wsock32 with the old number gives exactly what ws2_32 gives for the new number */
static void ip_read_equivalence(int type, int idx) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s;
    optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, type, 0);
    if (s == INVALID_SOCKET) { wf_down(); t_skip("socket"); return; }
    get_via(g1, s, IPPROTO_IP, ipmap[idx].old_no, &a, 16);
    get_via(g2, s, IPPROTO_IP, ipmap[idx].new_no, &b, 16);
    CHECKF(same_res(&a, &b), "old %d: ret %d err %d len %d vs new %d: ret %d err %d len %d", ipmap[idx].old_no, a.ret, a.err, a.len,
           ipmap[idx].new_no, b.ret, b.err, b.len);
    W2(closesocket)(s);
    wf_down();
}
#define IPREAD(i, nm) \
    TEST(sockopt_get_ip_old_##nm##_udp) { ip_read_equivalence(SOCK_DGRAM, i); } \
    TEST(sockopt_get_ip_old_##nm##_tcp) { ip_read_equivalence(SOCK_STREAM, i); }
IPREAD(0, multicast_if)
IPREAD(1, multicast_ttl)
IPREAD(2, multicast_loop)
IPREAD(3, add_membership)
IPREAD(4, drop_membership)
IPREAD(5, ttl)
IPREAD(6, tos)
IPREAD(7, dontfragment)

/* the shifted numbers: what ws2_32 calls IP_TTL (4) is a different option when it goes through wsock32 */
TEST(sockopt_get_ip_number_4_through_wsock32_is_multicast_loop) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; optres a, b, ttl;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    get_via(g1, s, IPPROTO_IP, 4, &a, 4);
    get_via(g2, s, IPPROTO_IP, IP_MULTICAST_LOOP, &b, 4);
    get_via(g2, s, IPPROTO_IP, IP_TTL, &ttl, 4);
    CHECK(same_res(&a, &b));
    WEQ(a.ret, 0);
    if (a.ret == 0 && ttl.ret == 0) {
        DWORD loop = *(DWORD *)a.buf, t = *(DWORD *)ttl.buf;
        CHECK(loop != t);   /* loop is a 0/1 flag, TTL a hop count */
    }
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_get_ip_ttl_default_matches_old_number_7) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; DWORD a = 0, b = 1;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(get_dword(g1, s, IPPROTO_IP, 7, &a), 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_TTL, &b), 0);
    WEQ(a, b);
    CHECK(a >= 1 && a <= 255);
    W2(closesocket)(s);
    wf_down();
}

/* writing through wsock32 with the old number reaches the ws2_32 option */
TEST(sockopt_set_ip_old_7_sets_ttl) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; DWORD v = 0;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0);
    WEQ(set_dword(s1, s, IPPROTO_IP, 7, 77), 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_TTL, &v), 0);
    WEQ(v, 77);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_old_7_read_back_with_old_7) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt);
    SOCKET s; DWORD v = 0;
    REQUIRE(s1); REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    WEQ(set_dword(s1, s, IPPROTO_IP, 7, 33), 0);
    WEQ(get_dword(g1, s, IPPROTO_IP, 7, &v), 0);
    WEQ(v, 33);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_old_7_ttl_values_table) {
    static const DWORD vals[] = { 1, 2, 64, 128, 200, 255 };
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; unsigned i;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        DWORD v = 0;
        CHECKF(set_dword(s1, s, IPPROTO_IP, 7, vals[i]) == 0, "ttl %lu", vals[i]);
        CHECKF(get_dword(g2, s, IPPROTO_IP, IP_TTL, &v) == 0 && v == vals[i], "ttl %lu read %lu", vals[i], v);
    }
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_number_4_does_not_touch_ttl) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; DWORD before = 0, after = 0, loop = 7;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_TTL, &before), 0);
    WEQ(set_dword(s1, s, IPPROTO_IP, 4, 0), 0);          /* goes to multicast loop */
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_TTL, &after), 0);
    WEQ(before, after);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop), 0);
    WEQ(loop, 0);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_old_4_toggles_multicast_loop) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; DWORD v = 9, d1 = 9;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_MULTICAST_LOOP, &d1), 0);
    WEQ(d1, 1);                                           /* default: looped back */
    WEQ(set_dword(s1, s, IPPROTO_IP, 4, 0), 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_MULTICAST_LOOP, &v), 0);
    WEQ(v, 0);
    WEQ(set_dword(s1, s, IPPROTO_IP, 4, 1), 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_MULTICAST_LOOP, &v), 0);
    WEQ(v, 1);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_old_3_sets_multicast_ttl) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; DWORD v = 0;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(set_dword(s1, s, IPPROTO_IP, 3, 9), 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_MULTICAST_TTL, &v), 0);
    WEQ(v, 9);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_new_10_is_multicast_ttl_too) {
    /* 10 is not remapped: wsock32 and ws2_32 agree it is the multicast TTL */
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; DWORD v = 0;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(set_dword(s1, s, IPPROTO_IP, 10, 5), 0);
    WEQ(get_dword(g2, s, IPPROTO_IP, IP_MULTICAST_TTL, &v), 0);
    WEQ(v, 5);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_ip_old_2_matches_new_9_multicast_if) {
    p_setsockopt s1 = WS(setsockopt), s2 = W2(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET a, b; struct in_addr lo; int ra, rb, ea, eb;
    REQUIRE(s1); REQUIRE(s2); REQUIRE(g2);
    WF_UP();
    lo.s_addr = wf_lo(0).sin_addr.s_addr;
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0); b = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); ra = s1(a, IPPROTO_IP, 2, (const char *)&lo, sizeof lo); ea = ra ? wf_err() : 0;
    wf_seterr(0); rb = s2(b, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&lo, sizeof lo); eb = rb ? wf_err() : 0;
    WEQ(ra, rb);
    WEQ(ea, eb);
    if (ra == 0) {
        struct in_addr x, y; int la = sizeof x, lb = sizeof y;
        WEQ(g2(a, IPPROTO_IP, IP_MULTICAST_IF, (char *)&x, &la), 0);
        WEQ(g2(b, IPPROTO_IP, IP_MULTICAST_IF, (char *)&y, &lb), 0);
        WEQ(x.s_addr, y.s_addr);
        WEQ(x.s_addr, lo.s_addr);
    } else t_note("setting the multicast interface to loopback failed with %d", ea);
    W2(closesocket)(a); W2(closesocket)(b);
    wf_down();
}
TEST(sockopt_set_ip_old_8_matches_new_3_tos) {
    p_setsockopt s1 = WS(setsockopt), s2 = W2(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET a, b; int ra, rb, ea, eb; DWORD va = 1, vb = 2;
    REQUIRE(s1); REQUIRE(s2); REQUIRE(g2);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0); b = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); ra = set_dword(s1, a, IPPROTO_IP, 8, 0x10); ea = ra ? wf_err() : 0;
    wf_seterr(0); rb = set_dword(s2, b, IPPROTO_IP, IP_TOS, 0x10); eb = rb ? wf_err() : 0;
    WEQ(ra, rb); WEQ(ea, eb);
    ra = get_dword(g2, a, IPPROTO_IP, IP_TOS, &va);
    rb = get_dword(g2, b, IPPROTO_IP, IP_TOS, &vb);
    WEQ(ra, rb);
    if (ra == 0 && rb == 0) WEQ(va, vb);
    t_note("TOS read back after setting 0x10 = %lu", va);
    W2(closesocket)(a); W2(closesocket)(b);
    wf_down();
}
TEST(sockopt_set_ip_old_9_matches_new_14_dontfragment) {
    p_setsockopt s1 = WS(setsockopt), s2 = W2(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET a, b; int ra, rb, ea, eb; DWORD va = 5, vb = 6;
    REQUIRE(s1); REQUIRE(s2); REQUIRE(g2);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0); b = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); ra = set_dword(s1, a, IPPROTO_IP, 9, 1); ea = ra ? wf_err() : 0;
    wf_seterr(0); rb = set_dword(s2, b, IPPROTO_IP, IP_DONTFRAGMENT, 1); eb = rb ? wf_err() : 0;
    WEQ(ra, rb); WEQ(ea, eb);
    ra = get_dword(g2, a, IPPROTO_IP, IP_DONTFRAGMENT, &va);
    rb = get_dword(g2, b, IPPROTO_IP, IP_DONTFRAGMENT, &vb);
    WEQ(ra, rb);
    if (ra == 0 && rb == 0) WEQ(va, vb);
    W2(closesocket)(a); W2(closesocket)(b);
    wf_down();
}

/* membership options with a non-multicast group fail identically through both numberings */
static void membership_pair(int old_no, int new_no) {
    p_setsockopt s1 = WS(setsockopt), s2 = W2(setsockopt);
    SOCKET a, b; struct ip_mreq m; int ra, rb, ea, eb;
    REQUIRE(s1); REQUIRE(s2);
    WF_UP();
    memset(&m, 0, sizeof m);
    m.imr_multiaddr.s_addr = wf_lo(0).sin_addr.s_addr;      /* 127.0.0.1 is not a multicast group */
    m.imr_interface.s_addr = wf_lo(0).sin_addr.s_addr;
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0); b = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); ra = s1(a, IPPROTO_IP, old_no, (const char *)&m, sizeof m); ea = wf_err();
    wf_seterr(0); rb = s2(b, IPPROTO_IP, new_no, (const char *)&m, sizeof m); eb = wf_err();
    WEQ(ra, SOCKET_ERROR);
    WEQ(rb, SOCKET_ERROR);
    WEQ(ea, eb);
    WEQ(ea, WSAEADDRNOTAVAIL);
    W2(closesocket)(a); W2(closesocket)(b);
    wf_down();
}
TEST(sockopt_set_ip_old_5_add_membership_matches_12) { membership_pair(5, 12); }
TEST(sockopt_set_ip_old_6_drop_membership_matches_13) { membership_pair(6, 13); }

TEST(sockopt_set_ip_old_5_add_then_old_6_drop_loopback_group) {
    p_setsockopt s1 = WS(setsockopt);
    SOCKET a; struct ip_mreq m; int r1, r2, e1;
    REQUIRE(s1);
    WF_UP();
    memset(&m, 0, sizeof m);
    ((unsigned char *)&m.imr_multiaddr)[0] = 239; ((unsigned char *)&m.imr_multiaddr)[1] = 255;
    ((unsigned char *)&m.imr_multiaddr)[2] = 77; ((unsigned char *)&m.imr_multiaddr)[3] = 3;
    m.imr_interface.s_addr = wf_lo(0).sin_addr.s_addr;
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); r1 = s1(a, IPPROTO_IP, 5, (const char *)&m, sizeof m); e1 = r1 ? wf_err() : 0;
    if (r1 != 0) { t_note("joining 239.255.77.3 via loopback failed with %d", e1); W2(closesocket)(a); wf_down(); return; }
    r2 = s1(a, IPPROTO_IP, 6, (const char *)&m, sizeof m);
    WEQ(r2, 0);
    wf_seterr(0);
    r2 = s1(a, IPPROTO_IP, 6, (const char *)&m, sizeof m);     /* second drop: no longer a member */
    WEQ(r2, SOCKET_ERROR);
    WEQ(wf_err(), WSAEADDRNOTAVAIL);
    W2(closesocket)(a);
    wf_down();
}

/* numbers that are not remapped, swept on a UDP and a TCP socket: identical to calling ws2_32 directly */
static void ip_sweep(int type) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; int opt, bad = 0;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, type, 0);
    for (opt = 0; opt <= 40; opt++) {
        optres a, b;
        if (opt >= 2 && opt <= 9) continue;               /* the remapped numbers */
        get_via(g1, s, IPPROTO_IP, opt, &a, 16);
        get_via(g2, s, IPPROTO_IP, opt, &b, 16);
        if (!same_res(&a, &b)) { bad++; t_note("IP option %d differs: %d/%d vs %d/%d", opt, a.ret, a.err, b.ret, b.err); }
    }
    WEQ(bad, 0);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_get_ip_unmapped_numbers_pass_through_udp) { ip_sweep(SOCK_DGRAM); }
TEST(sockopt_get_ip_unmapped_numbers_pass_through_tcp) { ip_sweep(SOCK_STREAM); }

TEST(sockopt_get_ip_options_above_the_map_are_not_shifted) {
    /* 10, 11 are valid Winsock 2 numbers that the map leaves alone */
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    get_via(g1, s, IPPROTO_IP, 10, &a, 4); get_via(g2, s, IPPROTO_IP, IP_MULTICAST_TTL, &b, 4);
    CHECK(same_res(&a, &b)); WEQ(a.ret, 0);
    get_via(g1, s, IPPROTO_IP, 11, &a, 4); get_via(g2, s, IPPROTO_IP, IP_MULTICAST_LOOP, &b, 4);
    CHECK(same_res(&a, &b)); WEQ(a.ret, 0);
    W2(closesocket)(s);
    wf_down();
}

/* ---------------------------------------------------------------- IPv6 level is not remapped */
TEST(sockopt_ipv6_level_is_not_remapped) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; DWORD v = 0;
    REQUIRE(s1); REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET6, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) { wf_down(); t_skip("no IPv6 sockets"); return; }
    /* option 4 at level 0 is remapped (multicast loop); at the IPv6 level it is IPV6_UNICAST_HOPS */
    WEQ(set_dword(s1, s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 21), 0);
    WEQ(get_dword(g2, s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v), 0);
    WEQ(v, 21);
    WEQ(get_dword(g1, s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v), 0);
    WEQ(v, 21);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_ipv6_v6only_round_trip_through_wsock32) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt);
    SOCKET s; DWORD v = 7;
    REQUIRE(s1); REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET6, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { wf_down(); t_skip("no IPv6 sockets"); return; }
    WEQ(set_dword(s1, s, IPPROTO_IPV6, IPV6_V6ONLY, 0), 0);
    WEQ(get_dword(g1, s, IPPROTO_IPV6, IPV6_V6ONLY, &v), 0);
    WEQ(v, 0);
    WEQ(set_dword(s1, s, IPPROTO_IPV6, IPV6_V6ONLY, 1), 0);
    WEQ(get_dword(g1, s, IPPROTO_IPV6, IPV6_V6ONLY, &v), 0);
    WEQ(v, 1);
    W2(closesocket)(s);
    wf_down();
}

/* ---------------------------------------------------------------- TCP level */
TEST(sockopt_tcp_nodelay_round_trip_via_wsock32) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; DWORD v = 5;
    REQUIRE(s1); REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    WEQ(get_dword(g1, s, IPPROTO_TCP, TCP_NODELAY, &v), 0);
    WEQ(v, 0);
    WEQ(set_dword(s1, s, IPPROTO_TCP, TCP_NODELAY, 1), 0);
    WEQ(get_dword(g2, s, IPPROTO_TCP, TCP_NODELAY, &v), 0);
    WEQ(v, 1);
    WEQ(get_dword(g1, s, IPPROTO_TCP, TCP_NODELAY, &v), 0);
    WEQ(v, 1);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_tcp_option_2_reads_without_inversion) {
    /* TCP_EXPEDITED_1122 itself (2) is not touched by the wrapper */
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    get_via(g1, s, IPPROTO_TCP, 2, &a, 4);
    get_via(g2, s, IPPROTO_TCP, 2, &b, 4);
    CHECK(same_res(&a, &b));
    WEQ(a.ret, 0);
    WEQ(a.buf[0], 0);                       /* default: off */
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_tcp_bsdurgent_read_is_first_byte_inverted) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    get_via(g1, s, IPPROTO_TCP, 0x7000, &a, 4);
    get_via(g2, s, IPPROTO_TCP, 2, &b, 4);
    WEQ(a.ret, b.ret);
    WEQ(a.err, b.err);
    if (a.ret == 0) {
        WEQ(a.len, b.len);
        WEQ(a.buf[0], b.buf[0] == 0);
        CHECK(!memcmp(a.buf + 1, b.buf + 1, (size_t)a.len - 1));   /* the other bytes are left alone */
    } else CHECK(a.buf[0] == 0xAA);                               /* nothing flipped when the read fails */
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_tcp_bsdurgent_set_stores_the_inverse) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET a; DWORD v = 9, w = 9; int r;
    REQUIRE(s1); REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    r = set_dword(s1, a, IPPROTO_TCP, 0x7000, 1);
    WEQ(r, 0);
    WEQ(get_dword(g2, a, IPPROTO_TCP, 2, &v), 0);
    WEQ(v & 0xff, 0);                      /* BSD urgent on == RFC 1122 urgent off */
    WEQ(get_dword(g1, a, IPPROTO_TCP, 0x7000, &w), 0);
    WEQ(w & 0xff, 1);                      /* and reads back as it was written */
    WEQ(set_dword(s1, a, IPPROTO_TCP, 0x7000, 0), 0);
    WEQ(get_dword(g2, a, IPPROTO_TCP, 2, &v), 0);
    WEQ(v & 0xff, 1);
    WEQ(get_dword(g1, a, IPPROTO_TCP, 0x7000, &w), 0);
    WEQ(w & 0xff, 0);
    W2(closesocket)(a);
    wf_down();
}
TEST(sockopt_tcp_option_2_set_is_not_inverted) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET a; DWORD v = 9;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    WEQ(set_dword(s1, a, IPPROTO_TCP, 2, 1), 0);
    WEQ(get_dword(g2, a, IPPROTO_TCP, 2, &v), 0);
    WEQ(v & 0xff, 1);
    W2(closesocket)(a);
    wf_down();
}
TEST(sockopt_tcp_bsdurgent_on_udp_socket_fails_untouched) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    get_via(g1, s, IPPROTO_TCP, 0x7000, &a, 4);
    get_via(g2, s, IPPROTO_TCP, 2, &b, 4);
    WEQ(a.ret, b.ret);
    WEQ(a.err, b.err);
    if (a.ret != 0) CHECK(a.buf[0] == 0xAA);
    WEQ(a.ret, SOCKET_ERROR);
    WEQ(a.err, WSAEINVAL);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_tcp_0x7000_at_other_levels_not_mapped) {
    /* the BSD-urgent mapping applies to level 6 only */
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    SOCKET s; optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    get_via(g1, s, SOL_SOCKET, 0x7000, &a, 4);
    get_via(g2, s, SOL_SOCKET, 0x7000, &b, 4);
    CHECK(same_res(&a, &b));
    get_via(g1, s, IPPROTO_IP, 0x7000, &a, 4);
    get_via(g2, s, IPPROTO_IP, 0x7000, &b, 4);
    CHECK(same_res(&a, &b));
    WEQ(a.ret, SOCKET_ERROR);        /* no such IP-level option; the number is passed on untouched */
    W2(closesocket)(s);
    wf_down();
}

/* ---------------------------------------------------------------- SOL_SOCKET pass-through */
TEST(sockopt_sol_socket_type_values) {
    p_getsockopt g1 = WS(getsockopt);
    SOCKET u, t; DWORD v = 0;
    REQUIRE(g1);
    WF_UP();
    u = W2(socket)(AF_INET, SOCK_DGRAM, 0); t = W2(socket)(AF_INET, SOCK_STREAM, 0);
    WEQ(get_dword(g1, u, SOL_SOCKET, SO_TYPE, &v), 0);
    WEQ(v, SOCK_DGRAM);
    WEQ(get_dword(g1, t, SOL_SOCKET, SO_TYPE, &v), 0);
    WEQ(v, SOCK_STREAM);
    W2(closesocket)(u); W2(closesocket)(t);
    wf_down();
}
TEST(sockopt_sol_socket_sweep_matches_ws2_32) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt);
    static const int opts[] = { SO_ACCEPTCONN, SO_BROADCAST, SO_DEBUG, SO_DONTROUTE, SO_ERROR, SO_KEEPALIVE, SO_LINGER, SO_OOBINLINE,
                                SO_RCVBUF, SO_REUSEADDR, SO_SNDBUF, SO_TYPE, SO_RCVTIMEO, SO_SNDTIMEO, SO_EXCLUSIVEADDRUSE,
                                SO_MAX_MSG_SIZE, SO_CONDITIONAL_ACCEPT, SO_PROTOCOL_INFOA, SO_PROTOCOL_INFOW, SO_DONTLINGER,
                                SO_GROUP_ID, SO_GROUP_PRIORITY, SO_UPDATE_ACCEPT_CONTEXT, SO_CONNECT_TIME };
    SOCKET s; unsigned i; int bad = 0;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    for (i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        optres a, b;
        get_via(g1, s, SOL_SOCKET, opts[i], &a, 64);
        get_via(g2, s, SOL_SOCKET, opts[i], &b, 64);
        if (!same_res(&a, &b)) { bad++; t_note("SOL_SOCKET %#x differs", opts[i]); }
    }
    WEQ(bad, 0);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_sol_socket_set_and_read_broadcast) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt);
    SOCKET s; DWORD v = 5;
    REQUIRE(s1); REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(get_dword(g1, s, SOL_SOCKET, SO_BROADCAST, &v), 0);
    WEQ(v, 0);
    WEQ(set_dword(s1, s, SOL_SOCKET, SO_BROADCAST, 1), 0);
    WEQ(get_dword(g1, s, SOL_SOCKET, SO_BROADCAST, &v), 0);
    EXPECT_NE(v, 0);
    WEQ(set_dword(s1, s, SOL_SOCKET, SO_BROADCAST, 0), 0);
    WEQ(get_dword(g1, s, SOL_SOCKET, SO_BROADCAST, &v), 0);
    WEQ(v, 0);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_sol_socket_reuseaddr_round_trip) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g2 = W2(getsockopt);
    SOCKET s; DWORD v = 5;
    REQUIRE(s1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    WEQ(set_dword(s1, s, SOL_SOCKET, SO_REUSEADDR, 1), 0);
    WEQ(get_dword(g2, s, SOL_SOCKET, SO_REUSEADDR, &v), 0);
    EXPECT_NE(v, 0);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_sol_socket_rcvtimeo_via_wsock32) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt);
    SOCKET s; DWORD v = 5;
    REQUIRE(s1); REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(set_dword(s1, s, SOL_SOCKET, SO_RCVTIMEO, 1234), 0);
    WEQ(get_dword(g1, s, SOL_SOCKET, SO_RCVTIMEO, &v), 0);
    WEQ(v, 1234);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_sol_socket_linger_struct) {
    p_setsockopt s1 = WS(setsockopt); p_getsockopt g1 = WS(getsockopt);
    SOCKET s; struct linger l, r; int n = sizeof r;
    REQUIRE(s1); REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_STREAM, 0);
    l.l_onoff = 1; l.l_linger = 7;
    WEQ(s1(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l), 0);
    memset(&r, 0, sizeof r);
    WEQ(g1(s, SOL_SOCKET, SO_LINGER, (char *)&r, &n), 0);
    WEQ(n, sizeof r);
    WEQ(r.l_onoff, 1);
    WEQ(r.l_linger, 7);
    W2(closesocket)(s);
    wf_down();
}

/* ---------------------------------------------------------------- errors */
TEST(sockopt_get_invalid_socket_is_notsock) {
    p_getsockopt g1 = WS(getsockopt); char b[8]; int n = sizeof b;
    REQUIRE(g1);
    WF_UP();
    wf_seterr(0);
    WEQ(g1(INVALID_SOCKET, SOL_SOCKET, SO_TYPE, b, &n), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(sockopt_set_invalid_socket_is_notsock) {
    p_setsockopt s1 = WS(setsockopt);
    REQUIRE(s1);
    WF_UP();
    wf_seterr(0);
    WEQ(set_dword(s1, INVALID_SOCKET, SOL_SOCKET, SO_REUSEADDR, 1), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(sockopt_get_closed_socket_is_notsock) {
    p_getsockopt g1 = WS(getsockopt); SOCKET s; DWORD v;
    REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    W2(closesocket)(s);
    wf_seterr(0);
    WEQ(get_dword(g1, s, SOL_SOCKET, SO_TYPE, &v), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(sockopt_get_ip_old_numbers_on_invalid_socket_still_notsock) {
    p_getsockopt g1 = WS(getsockopt); DWORD v; int i;
    REQUIRE(g1);
    WF_UP();
    for (i = 2; i <= 9; i++) {
        wf_seterr(0);
        CHECKF(get_dword(g1, INVALID_SOCKET, IPPROTO_IP, i, &v) == SOCKET_ERROR && wf_err() == WSAENOTSOCK, "old option %d", i);
    }
    wf_down();
}
TEST(sockopt_get_bsdurgent_on_invalid_socket_not_touched) {
    p_getsockopt g1 = WS(getsockopt); optres a;
    REQUIRE(g1);
    WF_UP();
    get_via(g1, INVALID_SOCKET, IPPROTO_TCP, 0x7000, &a, 4);
    WEQ(a.ret, SOCKET_ERROR);
    WEQ(a.err, WSAENOTSOCK);
    WEQ(a.buf[0], 0xAA);
    wf_down();
}
TEST(sockopt_get_unknown_option_is_inval) {
    p_getsockopt g1 = WS(getsockopt); SOCKET s; optres a;
    REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    get_via(g1, s, SOL_SOCKET, 0x0777, &a, 4);
    WEQ(a.ret, SOCKET_ERROR);
    WEQ(a.err, WSAEINVAL);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_get_null_optlen_is_fault) {
    p_getsockopt g1 = WS(getsockopt); SOCKET s; DWORD v = 0;
    REQUIRE(g1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0);
    WEQ(g1(s, SOL_SOCKET, SO_TYPE, (char *)&v, NULL), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_get_short_buffer_matches_ws2_32) {
    p_getsockopt g1 = WS(getsockopt), g2 = W2(getsockopt); SOCKET s; optres a, b;
    REQUIRE(g1); REQUIRE(g2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    get_via(g1, s, SOL_SOCKET, SO_TYPE, &a, 1);
    get_via(g2, s, SOL_SOCKET, SO_TYPE, &b, 1);
    CHECK(same_res(&a, &b));
    WEQ(a.ret, SOCKET_ERROR);
    WEQ(a.err, WSAEFAULT);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_short_buffer_matches_ws2_32) {
    p_setsockopt s1 = WS(setsockopt), s2 = W2(setsockopt); SOCKET s; char one = 1; int ra, ea, rb, eb;
    REQUIRE(s1); REQUIRE(s2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); ra = s1(s, SOL_SOCKET, SO_RCVBUF, &one, 1); ea = wf_err();
    wf_seterr(0); rb = s2(s, SOL_SOCKET, SO_RCVBUF, &one, 1); eb = wf_err();
    WEQ(ra, SOCKET_ERROR);
    WEQ(rb, SOCKET_ERROR);
    WEQ(ea, WSAEFAULT);
    WEQ(eb, WSAEFAULT);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_unknown_option_is_inval_like_ws2_32) {
    p_setsockopt s1 = WS(setsockopt), s2 = W2(setsockopt); SOCKET s; int ra, ea, rb, eb;
    DWORD v = 1;
    REQUIRE(s1); REQUIRE(s2);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0); ra = s1(s, SOL_SOCKET, 0x0777, (const char *)&v, sizeof v); ea = wf_err();
    wf_seterr(0); rb = s2(s, SOL_SOCKET, 0x0777, (const char *)&v, sizeof v); eb = wf_err();
    WEQ(ra, SOCKET_ERROR); WEQ(rb, SOCKET_ERROR);
    WEQ(ea, eb);
    WEQ(ea, WSAEINVAL);
    W2(closesocket)(s);
    wf_down();
}
TEST(sockopt_set_return_value_is_zero_or_minus_one) {
    p_setsockopt s1 = WS(setsockopt); SOCKET s; int r;
    REQUIRE(s1);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    r = set_dword(s1, s, SOL_SOCKET, SO_BROADCAST, 1);
    WEQ(r, 0);
    r = set_dword(s1, s, SOL_SOCKET, 0x0777, 1);
    WEQ(r, -1);
    W2(closesocket)(s);
    wf_down();
}

/* ---------------------------------------------------------------- without Winsock started */
CHILD(wf_sockopt_nostartup) {
    p_getsockopt g = (p_getsockopt)GetProcAddress(LoadLibraryA("wsock32.dll"), "getsockopt");
    p_setsockopt s = (p_setsockopt)GetProcAddress(LoadLibraryA("wsock32.dll"), "setsockopt");
    p_WSAGetLastError e = (p_WSAGetLastError)GetProcAddress(LoadLibraryA("wsock32.dll"), "WSAGetLastError");
    DWORD v = 0; int n = sizeof v;
    if (!g || !s || !e) return 1;
    if (g(INVALID_SOCKET, SOL_SOCKET, SO_TYPE, (char *)&v, &n) != SOCKET_ERROR) return 2;
    if (e() != WSANOTINITIALISED) return 3;
    if (s(INVALID_SOCKET, SOL_SOCKET, SO_REUSEADDR, (const char *)&v, sizeof v) != SOCKET_ERROR) return 4;
    if (e() != WSANOTINITIALISED) return 5;
    if (g(INVALID_SOCKET, IPPROTO_IP, 7, (char *)&v, &n) != SOCKET_ERROR) return 6;
    if (e() != WSANOTINITIALISED) return 7;
    {
        unsigned char b = 0xAA; n = 1;
        if (g(INVALID_SOCKET, IPPROTO_TCP, 0x7000, (char *)&b, &n) != SOCKET_ERROR) return 8;
        if (b != 0xAA) return 9;
    }
    return 0;
}
TEST(sockopt_without_startup_reports_notinitialised) { WF_RUN_CHILD("wf_sockopt_nostartup", ""); }
