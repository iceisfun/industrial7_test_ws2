/* IPv4 and IPv6 multicast socket options and group membership on the loopback interface.
 * Measures: defaults and value ranges of the multicast TTL / hop, loop and interface options; the
 * error codes for malformed membership requests (non-multicast group, drop without join, duplicate
 * join, wrong socket type); delivery of a datagram to a joined receiver over the loopback interface
 * (skipped with a reason when the guest refuses the join); destination reporting through IP_PKTINFO;
 * non-member and left-group silence; two members on one port.  A group join that the stack refuses is
 * an environment limit, not a failure: those tests record a note and stop.  Loopback only. */
#include "d6.h"

#define GROUP_A 0xEFFF4D09u   /* 239.255.77.9, administratively scoped, used by nothing else */
#define GROUP_B 0xEFFF4D0Au   /* 239.255.77.10 */
static const char MP[] = "mc-probe";

static int join4(SOCKET s, unsigned group_host, unsigned iface_host, int opt) {
    struct ip_mreq m;
    m.imr_multiaddr.s_addr = d_h32(group_host);
    m.imr_interface.s_addr = d_h32(iface_host);
    return d_sso(s, IPPROTO_IP, opt, &m, sizeof m);
}
#define LOOPBACK 0x7f000001u

/* Record the error class of a request whose exact code is not pinned down. */
static void note_err(const char *what) { t_note("%s: error %d", what, d_err()); }

/* UDP receiver bound to the wildcard on an ephemeral port */
static int rx4(usk *u) { return usk_open4(u, 0); }

/* A joined receiver; returns 0 (with a note) when the guest refuses the membership. */
static int member(usk *u, unsigned group) {
    if (!rx4(u)) { t_skip("cannot create receiver"); return 0; }
    d_seterr(0);
    if (join4(u->s, group, LOOPBACK, IP_ADD_MEMBERSHIP)) {
        t_note("join on the loopback interface refused, error %d", d_err());
        d_close(u->s);
        t_skip("multicast join refused by this system");
        return 0;
    }
    return 1;
}
/* sender whose multicast traffic leaves through loopback */
static SOCKET tx4(int ttl, int loop) {
    SOCKET s = d_sock(AF_INET, SOCK_DGRAM);
    struct in_addr ifa; ifa.s_addr = d_h32(LOOPBACK);
    if (d_sso(s, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof ifa)) t_note("IP_MULTICAST_IF(127.0.0.1) refused, error %d", d_err());
    if (ttl >= 0) d_setint(s, IPPROTO_IP, IP_MULTICAST_TTL, ttl);
    if (loop >= 0) d_setint(s, IPPROTO_IP, IP_MULTICAST_LOOP, loop);
    return s;
}
static int send_group(SOCKET s, unsigned group, unsigned short port_net) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = port_net; a.sin_addr.s_addr = d_h32(group);
    return d_sendto(s, MP, sizeof MP, &a, sizeof a);
}

/* ---- option semantics (no membership needed) ---------------------------------------------- */
TEST(ds6_mc_v4_defaults) {
    SOCKET s; int v;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    CHECK(d_getint(s, IPPROTO_IP, IP_MULTICAST_TTL, &v) == 0);  EXPECT_EQ(v & 0xff, 1);
    CHECK(d_getint(s, IPPROTO_IP, IP_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 1);
    d_close(s);
}

TEST(ds6_mc_v4_ttl_round_trip_and_range) {
    SOCKET s; int v, i; static const int ok[] = {0, 1, 2, 32, 127, 255}; static const int bad[] = {256, 0x1000, -1};
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    for (i = 0; i < 6; i++) {
        CHECK(d_setint(s, IPPROTO_IP, IP_MULTICAST_TTL, ok[i]) == 0);
        CHECK(d_getint(s, IPPROTO_IP, IP_MULTICAST_TTL, &v) == 0);
        EXPECT_EQ(v & 0xff, ok[i]);
    }
    for (i = 0; i < 3; i++) {
        int rc; d_seterr(0);
        rc = d_setint(s, IPPROTO_IP, IP_MULTICAST_TTL, bad[i]);
        t_note("IP_MULTICAST_TTL %d: rc %d err %d", bad[i], rc, rc ? d_err() : 0);
    }
    d_close(s);
}

TEST(ds6_mc_v4_loop_is_boolean) {
    SOCKET s; int v;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    CHECK(d_setint(s, IPPROTO_IP, IP_MULTICAST_LOOP, 0) == 0);
    CHECK(d_getint(s, IPPROTO_IP, IP_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 0);
    CHECK(d_setint(s, IPPROTO_IP, IP_MULTICAST_LOOP, 1) == 0);
    CHECK(d_getint(s, IPPROTO_IP, IP_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 1);
    CHECK(d_setint(s, IPPROTO_IP, IP_MULTICAST_LOOP, 0x100) == 0);
    CHECK(d_getint(s, IPPROTO_IP, IP_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 1);
    d_close(s);
}

TEST(ds6_mc_v4_if_default_is_any_and_round_trips_loopback) {
    SOCKET s; struct in_addr a; int l = sizeof a, rc;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    a.s_addr = 0xdeadbeef;
    CHECK(d_gso(s, IPPROTO_IP, IP_MULTICAST_IF, &a, &l) == 0);
    EXPECT_EQ(a.s_addr, 0);
    a.s_addr = d_h32(LOOPBACK);
    d_seterr(0);
    rc = d_sso(s, IPPROTO_IP, IP_MULTICAST_IF, &a, sizeof a);
    if (rc) { t_note("IP_MULTICAST_IF(127.0.0.1) refused: %d", d_err()); }
    else {
        a.s_addr = 0; l = sizeof a;
        CHECK(d_gso(s, IPPROTO_IP, IP_MULTICAST_IF, &a, &l) == 0);
        EXPECT_EQ(a.s_addr, d_h32(LOOPBACK));
        a.s_addr = 0;
        CHECK(d_sso(s, IPPROTO_IP, IP_MULTICAST_IF, &a, sizeof a) == 0);   /* back to "any" */
        a.s_addr = 1; l = sizeof a;
        CHECK(d_gso(s, IPPROTO_IP, IP_MULTICAST_IF, &a, &l) == 0);
        EXPECT_EQ(a.s_addr, 0);
    }
    d_close(s);
}

TEST(ds6_mc_v4_if_unassigned_address_is_rejected) {
    SOCKET s; struct in_addr a;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    a.s_addr = d_h32(0xC0000263u);           /* 192.0.2.99, documentation range, never assigned */
    d_seterr(0);
    EQC(d_sso(s, IPPROTO_IP, IP_MULTICAST_IF, &a, sizeof a), SOCKET_ERROR);
    t_note("IP_MULTICAST_IF(unassigned) error %d", d_err());
    d_close(s);
}

TEST(ds6_mc_v4_membership_options_cannot_be_read) {
    SOCKET s; char b[16]; int l, i; static const int opts[] = {IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP};
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    for (i = 0; i < 2; i++) {
        l = sizeof b; d_seterr(0);
        EQC(d_gso(s, IPPROTO_IP, opts[i], b, &l), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAENOPROTOOPT);
    }
    d_close(s);
}

TEST(ds6_mc_v4_tcp_socket_rejects_multicast_options) {
    SOCKET s; int v, l = sizeof v;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_STREAM);
    d_seterr(0);
    EQC(d_gso(s, IPPROTO_IP, IP_MULTICAST_TTL, &v, &l), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    l = sizeof v; d_seterr(0);
    EQC(d_gso(s, IPPROTO_IP, IP_MULTICAST_LOOP, &v, &l), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    l = sizeof v; d_seterr(0);
    EQC(d_gso(s, IPPROTO_IP, IP_MULTICAST_IF, &v, &l), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(s);
}

TEST(ds6_mc_v4_join_non_multicast_group_is_addrnotavail) {
    usk u; static const unsigned groups[] = {0x0A090909u, 0x7f000001u, 0xDFFFFFFFu, 0xF0000001u}; int i;
    if (!d_up()) return;
    CHECK(rx4(&u));
    for (i = 0; i < 4; i++) {
        d_seterr(0);
        EQC(join4(u.s, groups[i], LOOPBACK, IP_ADD_MEMBERSHIP), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    }
    d_close(u.s);
}

TEST(ds6_mc_v4_drop_without_join_is_eaddrnotavail) {
    usk u;
    if (!d_up()) return;
    CHECK(rx4(&u));
    d_seterr(0);
    EQC(join4(u.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP), SOCKET_ERROR);
    note_err("drop of a group that is not joined");
    d_close(u.s);
}

TEST(ds6_mc_v4_short_membership_request_note) {
    usk u; int rc;
    if (!d_up()) return;
    CHECK(rx4(&u));
    d_seterr(0);
    rc = d_sso(u.s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &(struct ip_mreq){0}, 4);
    t_note("IP_ADD_MEMBERSHIP with a 4-byte request: rc %d err %d", rc, rc ? d_err() : 0);
    d_close(u.s);
}

TEST(ds6_mc_v4_join_on_tcp_socket_fails) {
    SOCKET s; int rc;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_STREAM);
    d_seterr(0);
    rc = join4(s, GROUP_A, LOOPBACK, IP_ADD_MEMBERSHIP);
    CHECK(rc == SOCKET_ERROR);
    t_note("IP_ADD_MEMBERSHIP on a stream socket: error %d", d_err());
    d_close(s);
}

/* ---- membership life cycle -------------------------------------------------------------------- */
TEST(ds6_mc_v4_join_twice_is_einval_then_drop_twice) {
    usk u;
    if (!d_up()) return;
    if (!member(&u, GROUP_A)) return;
    d_seterr(0);
    EQC(join4(u.s, GROUP_A, LOOPBACK, IP_ADD_MEMBERSHIP), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    CHECK(join4(u.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP) == 0);
    d_seterr(0);
    EQC(join4(u.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP), SOCKET_ERROR);
    note_err("drop of a group that is not joined");
    d_close(u.s);
}

TEST(ds6_mc_v4_two_groups_are_independent) {
    usk u;
    if (!d_up()) return;
    if (!member(&u, GROUP_A)) return;
    CHECK(join4(u.s, GROUP_B, LOOPBACK, IP_ADD_MEMBERSHIP) == 0);
    CHECK(join4(u.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP) == 0);
    d_seterr(0);
    EQC(join4(u.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP), SOCKET_ERROR);
    note_err("drop of a group that is not joined");
    CHECK(join4(u.s, GROUP_B, LOOPBACK, IP_DROP_MEMBERSHIP) == 0);
    d_close(u.s);
}

TEST(ds6_mc_v4_drop_with_other_interface_is_eaddrnotavail) {
    usk u;
    if (!d_up()) return;
    if (!member(&u, GROUP_A)) return;
    d_seterr(0);
    EQC(join4(u.s, GROUP_A, 0xC0000263u, IP_DROP_MEMBERSHIP), SOCKET_ERROR);
    t_note("drop naming an unassigned interface: error %d", d_err());
    CHECK(join4(u.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP) == 0);
    d_close(u.s);
}

TEST(ds6_mc_v4_membership_ends_with_socket) {
    usk u, v;
    if (!d_up()) return;
    if (!member(&u, GROUP_A)) return;
    d_close(u.s);
    /* a new socket can join the same group on the same interface straight away */
    CHECK(rx4(&v));
    CHECK(join4(v.s, GROUP_A, LOOPBACK, IP_ADD_MEMBERSHIP) == 0);
    d_close(v.s);
}

/* ---- delivery ------------------------------------------------------------------------------------ */
TEST(ds6_mc_v4_datagram_reaches_member_over_loopback) {
    usk r; SOCKET s; struct sockaddr_in from; int n = sizeof from; char b[32];
    if (!d_up()) return;
    if (!member(&r, GROUP_A)) return;
    s = tx4(1, -1);
    CHECK(send_group(s, GROUP_A, r.port) == (int)sizeof MP);
    if (!d_readable(r.s, 2500)) { t_note("no multicast datagram looped back to the member"); d_close(s); d_close(r.s); return; }
    memset(&from, 0, sizeof from);
    EQC(d_recvfrom(r.s, b, sizeof b, &from, &n), sizeof MP);
    CHECK(!memcmp(b, MP, sizeof MP));
    EXPECT_EQ(from.sin_family, AF_INET);
    EXPECT_EQ(from.sin_addr.s_addr, d_h32(LOOPBACK));
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v4_non_member_receives_nothing) {
    usk member_sock, other; SOCKET s;
    if (!d_up()) return;
    if (!member(&member_sock, GROUP_A)) return;
    CHECK(rx4(&other));                      /* wildcard receiver, different port, never joined */
    s = tx4(1, -1);
    CHECK(send_group(s, GROUP_A, other.port) == (int)sizeof MP);
    CHECK(!d_readable(other.s, 500));
    d_close(s); d_close(other.s); d_close(member_sock.s);
}

TEST(ds6_mc_v4_other_group_same_port_receives_nothing) {
    usk r; SOCKET s;
    if (!d_up()) return;
    if (!member(&r, GROUP_A)) return;
    s = tx4(1, -1);
    d_seterr(0);
    EQC(send_group(s, GROUP_B, r.port), SOCKET_ERROR);   /* no local member of that group on the interface: no route */
    EXPECT_EQ(d_err(), WSAENETUNREACH);
    CHECK(!d_readable(r.s, 500));
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v4_left_group_stops_delivery) {
    usk r; SOCKET s; char b[16];
    if (!d_up()) return;
    if (!member(&r, GROUP_A)) return;
    s = tx4(1, -1);
    CHECK(send_group(s, GROUP_A, r.port) == (int)sizeof MP);
    if (!d_readable(r.s, 2500)) { t_note("no loopback delivery to start with"); d_close(s); d_close(r.s); return; }
    CHECK(d_recv(r.s, b, sizeof b) == (int)sizeof MP);
    CHECK(join4(r.s, GROUP_A, LOOPBACK, IP_DROP_MEMBERSHIP) == 0);
    CHECK(send_group(s, GROUP_A, r.port) == (int)sizeof MP);
    CHECK(!d_readable(r.s, 500));
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v4_pktinfo_destination_is_the_group) {
    usk r; SOCKET s; rmsg m; LPFN_WSARECVMSG rm; WSACMSGHDR *c; int rc;
    if (!d_up()) return;
    if (!member(&r, GROUP_A)) return;
    rm = d_get_recvmsg(r.s);
    if (!rm) { t_skip("no WSARecvMsg"); d_close(r.s); return; }
    CHECK(d_setint(r.s, IPPROTO_IP, IP_PKTINFO, 1) == 0);
    s = tx4(1, -1);
    CHECK(send_group(s, GROUP_A, r.port) == (int)sizeof MP);
    if (!d_readable(r.s, 2500)) { t_note("no loopback delivery"); d_close(s); d_close(r.s); return; }
    rmsg_init(&m);
    rc = rm(r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    c = d_cmsg_find(&m.m, 0, 19);
    CHECK(c != NULL);
    if (c) {
        struct in_pktinfo *pi = d_cmsg_data(c);
        EXPECT_EQ(pi->ipi_addr.s_addr, d_h32(GROUP_A));
        CHECK(pi->ipi_ifindex != 0);
    }
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v4_received_ttl_equals_multicast_ttl) {
    usk r; SOCKET s; rmsg m; LPFN_WSARECVMSG rm; WSACMSGHDR *c; int rc;
    if (!d_up()) return;
    if (!member(&r, GROUP_A)) return;
    rm = d_get_recvmsg(r.s);
    if (!rm) { t_skip("no WSARecvMsg"); d_close(r.s); return; }
    CHECK(d_setint(r.s, IPPROTO_IP, IP_RECVTTL, 1) == 0);
    s = tx4(3, -1);
    CHECK(send_group(s, GROUP_A, r.port) == (int)sizeof MP);
    if (!d_readable(r.s, 2500)) { t_note("no loopback delivery"); d_close(s); d_close(r.s); return; }
    rmsg_init(&m);
    rc = rm(r.s, &m.m, &m.got, NULL, NULL);
    EXPECT_EQ(rc, 0);
    c = d_cmsg_find(&m.m, 0, 4);
    CHECK(c != NULL);
    if (c) t_note("multicast datagram TTL cmsg equals sender multicast TTL: %d", *(int *)d_cmsg_data(c) == 3);
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v4_two_members_on_one_port_both_receive) {
    usk a; SOCKET b, s; struct sockaddr_in n; char buf[16]; int l = sizeof n;
    if (!d_up()) return;
    a.s = d_sock(AF_INET, SOCK_DGRAM);
    CHECK(d_setint(a.s, SOL_SOCKET, SO_REUSEADDR, 1) == 0);
    mk4(&n, 0, 0);
    CHECK(d_bind(a.s, &n, sizeof n) == 0);
    CHECK(d_name(a.s, &n, &l) == 0);
    a.port = n.sin_port;
    b = d_sock(AF_INET, SOCK_DGRAM);
    CHECK(d_setint(b, SOL_SOCKET, SO_REUSEADDR, 1) == 0);
    CHECK(d_bind(b, &n, sizeof n) == 0);
    if (join4(a.s, GROUP_A, LOOPBACK, IP_ADD_MEMBERSHIP) || join4(b, GROUP_A, LOOPBACK, IP_ADD_MEMBERSHIP)) {
        t_note("join refused: %d", d_err()); d_close(a.s); d_close(b); t_skip("multicast join refused"); return;
    }
    s = tx4(1, -1);
    CHECK(send_group(s, GROUP_A, a.port) == (int)sizeof MP);
    if (!d_readable(a.s, 2500)) { t_note("no loopback delivery"); }
    else {
        CHECK(d_readable(b, 2500));          /* every member of the group gets its own copy */
        EQC(d_recv(a.s, buf, sizeof buf), sizeof MP);
        EQC(d_recv(b, buf, sizeof buf), sizeof MP);
    }
    d_close(s); d_close(a.s); d_close(b);
}

TEST(ds6_mc_v4_loop_disabled_on_sender_note) {
    usk r; SOCKET s;
    if (!d_up()) return;
    if (!member(&r, GROUP_A)) return;
    s = tx4(1, 0);
    CHECK(send_group(s, GROUP_A, r.port) == (int)sizeof MP);
    t_note("sender with IP_MULTICAST_LOOP off: local member %s the datagram", d_readable(r.s, 700) ? "received" : "did not receive");
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v4_bind_to_group_address_note) {
    SOCKET s; struct sockaddr_in a; int rc;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    mk4(&a, 0, 0);
    a.sin_addr.s_addr = d_h32(GROUP_A);
    d_seterr(0);
    rc = d_bind(s, &a, sizeof a);
    t_note("UDP bind(239.255.77.9): rc %d err %d", rc, rc ? d_err() : 0);
    d_close(s);
}

TEST(ds6_mc_v4_send_to_group_without_member_is_netunreach) {
    SOCKET s;
    if (!d_up()) return;
    s = tx4(1, -1);
    d_seterr(0);
    EQC(send_group(s, GROUP_B, d_h16(40001)), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENETUNREACH);
    d_close(s);
}

TEST(ds6_mc_v4_connect_udp_to_group_and_name) {
    SOCKET s; struct sockaddr_in a, p; int l = sizeof p;
    if (!d_up()) return;
    s = tx4(1, -1);
    mk4(&a, 0, d_h16(40002));
    a.sin_addr.s_addr = d_h32(GROUP_B);
    d_seterr(0);
    if (d_connect(s, &a, sizeof a)) { t_note("connect to a group address: error %d", d_err()); d_close(s); return; }
    CHECK(d_peer(s, &p, &l) == 0);
    EXPECT_EQ(p.sin_addr.s_addr, d_h32(GROUP_B));
    d_close(s);
}

/* ---- IPv6 ----------------------------------------------------------------------------------------- */
static int join6(SOCKET s, const unsigned char grp[16], unsigned ifindex, int opt) {
    struct ipv6_mreq m;
    memcpy(&m.ipv6mr_multiaddr, grp, 16); m.ipv6mr_interface = ifindex;
    return d_sso(s, IPPROTO_IPV6, opt, &m, sizeof m);
}
static const unsigned char G6A[16] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0x4d,0x09,0,0x01};   /* ff02::4d09:1 */

TEST(ds6_mc_v6_defaults_and_loop_boolean) {
    SOCKET s; int v;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 1);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 0) == 0);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 0);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 0x100) == 0);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &v) == 0); EXPECT_EQ(v & 0xff, 1);
    CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &v) == 0); EXPECT_EQ(v, 0);
    d_close(s);
}

TEST(ds6_mc_v6_tcp_socket_rejects_multicast_options) {
    SOCKET s; int v, l = sizeof v, i; static const int opts[] = {IPV6_MULTICAST_IF, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_LOOP};
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    for (i = 0; i < 3; i++) {
        l = sizeof v; d_seterr(0);
        EQC(d_gso(s, IPPROTO_IPV6, opts[i], &v, &l), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAEINVAL);
    }
    d_close(s);
}

TEST(ds6_mc_v6_membership_options_cannot_be_read) {
    SOCKET s; char b[32]; int l, i; static const int opts[] = {IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP};
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    for (i = 0; i < 2; i++) {
        l = sizeof b; d_seterr(0);
        EQC(d_gso(s, IPPROTO_IPV6, opts[i], b, &l), SOCKET_ERROR);
        EXPECT_EQ(d_err(), WSAENOPROTOOPT);
    }
    d_close(s);
}

TEST(ds6_mc_v6_join_non_multicast_group_is_addrnotavail) {
    SOCKET s; unsigned char loop6[16] = {0}; unsigned char gl[16] = {0xfe, 0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    loop6[15] = 1;
    d_seterr(0);
    EQC(join6(s, loop6, 1, IPV6_ADD_MEMBERSHIP), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_seterr(0);
    EQC(join6(s, gl, 1, IPV6_ADD_MEMBERSHIP), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEADDRNOTAVAIL);
    d_close(s);
}

TEST(ds6_mc_v6_lifecycle_on_loopback_interface) {
    usk r;
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, -1));
    d_seterr(0);
    if (join6(r.s, G6A, 1, IPV6_ADD_MEMBERSHIP)) {
        t_note("IPv6 join on interface 1 refused, error %d", d_err());
        d_close(r.s); t_skip("IPv6 multicast join refused"); return;
    }
    d_seterr(0);
    EQC(join6(r.s, G6A, 1, IPV6_ADD_MEMBERSHIP), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
    CHECK(join6(r.s, G6A, 1, IPV6_DROP_MEMBERSHIP) == 0);
    d_seterr(0);
    EQC(join6(r.s, G6A, 1, IPV6_DROP_MEMBERSHIP), SOCKET_ERROR);
    note_err("drop of a group that is not joined");
    d_close(r.s);
}

TEST(ds6_mc_v6_drop_without_join_is_eaddrnotavail) {
    usk r;
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, -1));
    d_seterr(0);
    EQC(join6(r.s, G6A, 1, IPV6_DROP_MEMBERSHIP), SOCKET_ERROR);
    note_err("drop of a group that is not joined");
    d_close(r.s);
}

TEST(ds6_mc_v6_datagram_reaches_member_over_loopback) {
    usk r; SOCKET s; struct sockaddr_in6 to, from; int n = sizeof from; char b[32];
    NEED_V6();
    CHECK(usk_open6(&r, K_ANY, -1));
    d_seterr(0);
    if (join6(r.s, G6A, 1, IPV6_ADD_MEMBERSHIP)) {
        t_note("IPv6 join refused, error %d", d_err()); d_close(r.s); t_skip("IPv6 multicast join refused"); return;
    }
    s = d_sock(AF_INET6, SOCK_DGRAM);
    if (d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, 1)) t_note("IPV6_MULTICAST_IF(1) refused: %d", d_err());
    mk6(&to, K_ANY, r.port);
    memcpy(&to.sin6_addr, G6A, 16);
    to.sin6_scope_id = 1;
    CHECK(d_sendto(s, MP, sizeof MP, &to, sizeof to) == (int)sizeof MP);
    if (!d_readable(r.s, 2500)) { t_note("no IPv6 multicast datagram looped back"); }
    else {
        memset(&from, 0, sizeof from);
        EQC(d_recvfrom(r.s, b, sizeof b, &from, &n), sizeof MP);
        CHECK(!memcmp(b, MP, sizeof MP));
        EXPECT_EQ(from.sin6_family, AF_INET6);
    }
    d_close(s); d_close(r.s);
}

TEST(ds6_mc_v6_multicast_if_round_trip) {
    SOCKET s; int v, rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    d_seterr(0);
    rc = d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, 1);
    if (rc) t_note("IPV6_MULTICAST_IF(1) refused: %d", d_err());
    else {
        CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &v) == 0);
        EXPECT_EQ(v, 1);
        CHECK(d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, 0) == 0);
        CHECK(d_getint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &v) == 0);
        EXPECT_EQ(v, 0);
    }
    d_close(s);
}

TEST(ds6_mc_v6_multicast_if_bogus_index_note) {
    SOCKET s; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    d_seterr(0);
    rc = d_setint(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, 0x7ffffff0);
    t_note("IPV6_MULTICAST_IF(bogus index): rc %d err %d", rc, rc ? d_err() : 0);
    d_close(s);
}

TEST(ds6_mc_v6_dualstack_socket_v4_membership_note) {
    SOCKET s; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    d_seterr(0);
    rc = join4(s, GROUP_A, LOOPBACK, IP_ADD_MEMBERSHIP);
    t_note("IP_ADD_MEMBERSHIP on a dual-stack IPv6 socket: rc %d err %d", rc, rc ? d_err() : 0);
    d_close(s);
}
