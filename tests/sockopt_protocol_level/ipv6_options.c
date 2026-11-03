/* IPPROTO_IPV6 socket options on IPv6 datagram and stream sockets, and how the IPv4 and IPv6 option levels alias
 * each other: defaults, value ranges (hop limits are bytes, the on/off options look at the whole 32-bit value except
 * IPV6_V6ONLY on datagram sockets), protection level, interface index validation, multicast group membership rules,
 * the options a stream socket refuses, and the option-length protocol. Loopback only. Tests skip when the machine
 * has no IPv6 stack. */
#include "spl.h"

#define EINV WSAEINVAL
#define EFLT WSAEFAULT
#define ENOOPT WSAENOPROTOOPT
#define EADDR WSAEADDRNOTAVAIL

static const struct spl_row hops_rows[] = {
    {7, 0, 7}, {0, 0, 0}, {1, 0, 1}, {64, 0, 64}, {128, 0, 128}, {255, 0, 255}, {256, EINV, 0}, {1000, EINV, 0},
    {65535, EINV, 0}, {0x7fffffff, EINV, 0}, {(int)0x80000000, EINV, 0}, {-1, 0, 255}, {2, 0, 2},
};
static const struct spl_row flag_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {-1, 0, 1}, {2, 0, 1}, {255, 0, 1}, {256, 0, 1}, {1000, 0, 1},
    {65535, 0, 1}, {0x7fffffff, 0, 1}, {(int)0x80000000, 0, 1}, {0x01000000, 0, 1}, {0, 0, 0},
};
/* IPV6_V6ONLY: datagram sockets keep the low byte, stream sockets the whole value. */
static const struct spl_row v6only_udp_rows[] = {
    {0, 0, 0}, {1, 0, 1}, {-1, 0, 1}, {2, 0, 1}, {256, 0, 0}, {1000, 0, 1}, {65535, 0, 1}, {(int)0x80000000, 0, 0}, {0x7fffffff, 0, 1}, {0, 0, 0},
};
static const struct spl_row v6only_tcp_rows[] = {
    {0, 0, 0}, {1, 0, 1}, {-1, 0, 1}, {2, 0, 1}, {256, 0, 1}, {1000, 0, 1}, {(int)0x80000000, 0, 1}, {0, 0, 0},
};
static const struct spl_row mtud_rows[] = {
    {0, 0, 0}, {1, 0, 1}, {2, 0, 2}, {3, 0, 3}, {4, EINV, 0}, {5, EINV, 0}, {-1, EINV, 0}, {1000, EINV, 0}, {256, 0, 0}, {2, 0, 2},
};
static const struct spl_row mcast_if_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {9999, EINV, 0}, {-1, EINV, 0}, {0x7fffffff, EINV, 0}, {(int)0x80000000, EINV, 0}, {1, 0, 1},
};
static const struct spl_row unicast_if_rows[] = {
    {1, 0, 1}, {9999, EINV, 0}, {-1, EINV, 0}, {1000, EINV, 0}, {0, 0, 0},
};
static const struct spl_row protlevel_rows[] = {
    {30, 0, 30}, {10, 0, 10}, {20, 0, 20}, {0, EINV, 0}, {1, EINV, 0}, {5, EINV, 0}, {9, EINV, 0}, {11, EINV, 0}, {19, EINV, 0},
    {21, EINV, 0}, {29, EINV, 0}, {31, EINV, 0}, {40, EINV, 0}, {64, EINV, 0},
    {255, EINV, 0}, {1000, EINV, 0}, {0x7fffffff, EINV, 0}, {30, 0, 30},
};

/* ---- defaults ------------------------------------------------------------------------------------------ */
SPL_DEFTEST(ipv6_default_unicast_hops_udp_is_128, spl_udp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 0xffffffff, 128)
SPL_DEFTEST(ipv6_default_unicast_hops_tcp_is_128, spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 0xffffffff, 128)
SPL_DEFTEST(ipv6_default_multicast_hops_is_1,     spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_HOPS, 0xffffffff, 1)
SPL_DEFTEST(ipv6_default_multicast_loop_on,       spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_LOOP, 0xffffffff, 1)
SPL_DEFTEST(ipv6_default_multicast_if_none,       spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_IF, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_unicast_if_none,         spl_udp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_IF, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_unicast_if_none_tcp,     spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_IF, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_pktinfo_off,             spl_udp6, SPL_LVL_IPV6, SPL_IPV6_PKTINFO, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_hoplimit_off,            spl_udp6, SPL_LVL_IPV6, SPL_IPV6_HOPLIMIT, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_recvtclass_off,          spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVTCLASS, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_recvif_off,              spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVIF, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_recvdstaddr_off,         spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVDSTADDR, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_recvrthdr_off,           spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVRTHDR, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_mtu_discover_notset,     spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MTU_DISCOVER, 0xffffffff, 0)
SPL_DEFTEST(ipv6_default_protection_level_unrestricted_udp, spl_udp6, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL, 0xffffffff, 10)
SPL_DEFTEST(ipv6_default_protection_level_unrestricted_tcp, spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL, 0xffffffff, 10)
SPL_DEFTEST(ipv6_default_v6only_on_udp,           spl_udp6, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 0xff, 1)
SPL_DEFTEST(ipv6_default_v6only_on_tcp,           spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 0xffffffff, 1)
SPL_DEFTEST(ipv6_default_dontfrag_off_udp,        spl_udp6, SPL_LVL_IPV6, SPL_IPV6_DONTFRAG, 0xffffffff, 0)

/* ---- value coding ---------------------------------------------------------------------------------------- */
SPL_ROWTEST(ipv6_unicast_hops_values_udp,   spl_udp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 0xffffffff, hops_rows)
SPL_ROWTEST(ipv6_unicast_hops_values_tcp,   spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 0xffffffff, hops_rows)
SPL_ROWTEST(ipv6_multicast_hops_values,     spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_HOPS, 0xffffffff, hops_rows)
SPL_ROWTEST(ipv6_multicast_loop_values,     spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_LOOP, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_dontfrag_values_udp,       spl_udp6, SPL_LVL_IPV6, SPL_IPV6_DONTFRAG, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_dontfrag_values_tcp,       spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_DONTFRAG, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_pktinfo_values,            spl_udp6, SPL_LVL_IPV6, SPL_IPV6_PKTINFO, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_hoplimit_values,           spl_udp6, SPL_LVL_IPV6, SPL_IPV6_HOPLIMIT, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_recvtclass_values,         spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVTCLASS, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_recvif_values,             spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVIF, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_recvdstaddr_values,        spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVDSTADDR, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_recvrthdr_values,          spl_udp6, SPL_LVL_IPV6, SPL_IPV6_RECVRTHDR, 0xffffffff, flag_rows)
SPL_ROWTEST(ipv6_v6only_values_udp,         spl_udp6, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 0xff, v6only_udp_rows)
SPL_ROWTEST(ipv6_v6only_values_tcp,         spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 0xffffffff, v6only_tcp_rows)
SPL_ROWTEST(ipv6_mtu_discover_values_udp,   spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MTU_DISCOVER, 0xffffffff, mtud_rows)
SPL_ROWTEST(ipv6_mtu_discover_values_tcp,   spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_MTU_DISCOVER, 0xffffffff, mtud_rows)
SPL_ROWTEST(ipv6_multicast_if_values,       spl_udp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_IF, 0xffffffff, mcast_if_rows)
SPL_ROWTEST(ipv6_unicast_if_values_udp,     spl_udp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_IF, 0xffffffff, unicast_if_rows)
SPL_ROWTEST(ipv6_unicast_if_values_tcp,     spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_UNICAST_IF, 0xffffffff, unicast_if_rows)
SPL_ROWTEST(ipv6_protection_level_values_udp, spl_udp6, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL, 0xffffffff, protlevel_rows)
SPL_ROWTEST(ipv6_protection_level_values_tcp, spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL, 0xffffffff, protlevel_rows)

/* ---- refusals -------------------------------------------------------------------------------------------- */
SPL_REFUSETEST(ipv6_tcp_refuses_multicast_if,    spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_IF, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_multicast_hops,  spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_HOPS, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_multicast_loop,  spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_LOOP, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_pktinfo,         spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_PKTINFO, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_hoplimit,        spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_HOPLIMIT, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_recvif,          spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_RECVIF, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_recvdstaddr,     spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_RECVDSTADDR, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_recvrthdr,       spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_RECVRTHDR, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_recvtclass,      spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_RECVTCLASS, EINV)
SPL_REFUSETEST(ipv6_tcp_refuses_hdrincl,         spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_HDRINCL, EINV)
SPL_REFUSETEST(ipv6_udp_refuses_hdrincl,         spl_udp6, SPL_LVL_IPV6, SPL_IPV6_HDRINCL, EINV)
SPL_REFUSETEST(ipv6_tclass_unknown_udp,          spl_udp6, SPL_LVL_IPV6, SPL_IPV6_TCLASS, ENOOPT)
SPL_REFUSETEST(ipv6_tclass_unknown_tcp,          spl_tcp6, SPL_LVL_IPV6, SPL_IPV6_TCLASS, ENOOPT)
SPL_REFUSETEST(ipv6_option_zero_unknown,         spl_udp6, SPL_LVL_IPV6, 0, ENOOPT)
SPL_REFUSETEST(ipv6_option_1000_unknown,         spl_tcp6, SPL_LVL_IPV6, 1000, ENOOPT)
SPL_REFUSETEST(ipv6_option_172_unknown,           spl_udp6, SPL_LVL_IPV6, 172, ENOOPT)

TEST(ipv6_mtu_unconnected_get_notconn_set_unsupported)
{
    SOCKET s; int v = 0, l = 4, e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    SEQ(spl_get(s, SPL_LVL_IPV6, SPL_IPV6_MTU, &v, &l, &e), SOCKET_ERROR); SEQ(e, WSAENOTCONN);
    v = 1400;
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_MTU, &v, 4, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    spl_close(s);
}
TEST(ipv6_mtu_connected_tcp_reports_path_mtu)
{
    SOCKET c, a, l; int v, e;
    if (!spl_up() || !spl_have6()) return;
    if (!spl_pair(1, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    SEQ(spl_geti(c, SPL_LVL_IPV6, SPL_IPV6_MTU, &v, &e), 0);
    CHECKF(v >= 1280, "path MTU %d is below the IPv6 minimum", v);
    t_note("loopback IPv6 path MTU observed");
    spl_close(c); spl_close(a); spl_close(l);
}

/* ---- level aliasing between the two families ------------------------------------------------------------ */
TEST(ipv6_level_set_accepted_on_ipv4_socket)
{
    /* An AF_INET socket answers IPPROTO_IPV6 hop-limit requests exactly like IPPROTO_IP ones. */
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 33, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS), 33);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 33);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TTL, 34, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS), 34);
    spl_close(s);
}
TEST(ipv6_level_get_matches_ipv4_level_defaults_on_ipv4_socket)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS), 128);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_HOPS), 1);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_LOOP), 1);
    spl_close(s);
}
TEST(ipv6_level_unicast_hops_on_ipv4_tcp_socket)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 5, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 5);
    spl_close(s);
}
TEST(ipv6_tclass_refused_on_ipv4_socket_through_ipv6_level)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_TCLASS, 1, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    spl_close(s);
}
TEST(ipv4_level_set_refused_on_ipv6_socket)
{
    /* Setting IPv4-level options on an AF_INET6 socket is invalid; reading them works. */
    SOCKET s; int e, i;
    static const struct { int opt, val; } t[] = {{SPL_IP_TOS, 5}, {SPL_IP_TTL, 5}, {SPL_IP_MULTICAST_TTL, 5}, {SPL_IP_MULTICAST_LOOP, 1}};
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    for (i = 0; i < 4; i++) {
        int before = spl_rb(s, SPL_LVL_IP, t[i].opt);
        CHECKF(before != SPL_BAD, "get opt %d failed", t[i].opt);
        SEQ(spl_seti(s, SPL_LVL_IP, t[i].opt, t[i].val, &e), SOCKET_ERROR); SEQ(e, EINV);
        SEQ(spl_rb(s, SPL_LVL_IP, t[i].opt), before);
    }
    spl_close(s);
}
TEST(ipv4_level_ttl_get_on_ipv6_socket_reads_hop_limit)
{
    SOCKET s; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 128);
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 42, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 42);
    spl_close(s);
}
TEST(ipv4_level_set_refused_on_ipv6_tcp_socket)
{
    SOCKET s; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_tcp6();
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TTL, 5, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 128);
    spl_close(s);
}
TEST(ipv6_tcp_level_options_work_on_ipv6_tcp_socket)
{
    SOCKET s; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_tcp6();
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 5, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 5);
    SEQ(spl_seti(s, SPL_LVL_TCP, TCP_NODELAY, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, TCP_NODELAY) & 0xff, 1);
    spl_close(s);
}

/* ---- option length protocol ----------------------------------------------------------------------------------- */
TEST(ipv6_set_byte_options_accept_one_byte)
{
    SOCKET s; int i;
    static const int opts[] = {SPL_IPV6_UNICAST_HOPS, SPL_IPV6_MULTICAST_HOPS, SPL_IPV6_MULTICAST_LOOP, SPL_IPV6_DONTFRAG,
                               SPL_IPV6_V6ONLY};
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) spl_len_protocol(s, SPL_LVL_IPV6, opts[i], 1, 1, EFLT);
    spl_close(s);
}
TEST(ipv6_set_protection_level_needs_four_bytes_and_reports_invalid)
{
    SOCKET s;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    spl_len_protocol(s, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL, 30, 4, EINV);
    spl_close(s);
}
TEST(ipv6_get_hop_options_buffer_sizes)
{
    SOCKET s; int i;
    static const int opts[] = {SPL_IPV6_UNICAST_HOPS, SPL_IPV6_MULTICAST_HOPS};
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    for (i = 0; i < 2; i++) spl_get_protocol(s, SPL_LVL_IPV6, opts[i], 1, EFLT, 1, 4, 4);
    spl_close(s);
}
TEST(ipv6_get_v6only_buffer_sizes)
{
    SOCKET s;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    spl_get_protocol(s, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 1, EFLT, 1, 1, 1);
    spl_close(s);
    s = spl_tcp6();
    spl_get_protocol(s, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 4, EFLT, 0, 4, 4);
    spl_close(s);
}
TEST(ipv6_multicast_if_needs_four_bytes)
{
    SOCKET s; int idx = 1, l, e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    for (l = 0; l <= 8; l++) {
        int r = spl_set(s, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_IF, &idx, l, &e);
        if (l < 4) { CHECKF(r == SOCKET_ERROR && e == EFLT, "len %d rc %d err %d", l, r, e); } else CHECKF(r == 0, "len %d rc %d err %d", l, r, e);
    }
    spl_close(s);
}

/* ---- multicast membership -------------------------------------------------------------------------------------- */
static void mreq6(struct ipv6_mreq *m, unsigned char b0, unsigned ifindex)
{
    memset(m, 0, sizeof *m);
    m->ipv6mr_multiaddr.s6_addr[0] = b0;
    m->ipv6mr_multiaddr.s6_addr[1] = 0x02;
    m->ipv6mr_multiaddr.s6_addr[15] = 0xfb;
    m->ipv6mr_interface = ifindex;
}
TEST(ipv6_membership_join_and_leave_default_interface)
{
    SOCKET s; struct ipv6_mreq m; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    mreq6(&m, 0xff, 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
TEST(ipv6_membership_join_and_leave_loopback_interface)
{
    SOCKET s; struct ipv6_mreq m; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    mreq6(&m, 0xff, 1);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
TEST(ipv6_membership_group_must_be_multicast)
{
    SOCKET s; struct ipv6_mreq m; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    mreq6(&m, 0, 1);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    spl_close(s);
}
TEST(ipv6_membership_unknown_interface_index)
{
    SOCKET s; struct ipv6_mreq m; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    mreq6(&m, 0xff, 9999);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    spl_close(s);
}
TEST(ipv6_membership_requires_twenty_bytes)
{
    SOCKET s; struct ipv6_mreq m; int l, e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    mreq6(&m, 0xff, 1);
    for (l = 0; l <= 24; l += 4) {
        int r = spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, l, &e);
        if (l < 20) { CHECKF(r == SOCKET_ERROR && e == EFLT, "len %d rc %d err %d", l, r, e); }
        else { CHECKF(r == 0, "len %d rc %d err %d", l, r, e); spl_set(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, sizeof m, &e); }
    }
    spl_close(s);
}
TEST(ipv6_membership_refused_on_tcp_socket)
{
    SOCKET s; struct ipv6_mreq m; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_tcp6();
    mreq6(&m, 0xff, 1);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR);
    CHECKF(e == EINV || e == ENOOPT || e == WSAEOPNOTSUPP, "err %d", e);
    t_note("IPv6 join on a TCP socket fails with %d", e);
    spl_close(s);
}
TEST(ipv6_membership_options_cannot_be_read)
{
    SOCKET s; struct ipv6_mreq m; int l = sizeof m, e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    SEQ(spl_get(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, &l, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    l = sizeof m;
    SEQ(spl_get(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, &l, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    spl_close(s);
}
TEST(ipv6_multicast_if_then_join_default_interface)
{
    SOCKET s; struct ipv6_mreq m; int e;
    if (!spl_up() || !spl_have6()) return;
    s = spl_udp6();
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_MULTICAST_IF, 1, &e), 0);
    mreq6(&m, 0xff, 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IPV6, SPL_IPV6_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
