/* IPPROTO_IP socket options on IPv4 datagram and stream sockets: defaults, value ranges (TTL/TOS/multicast hop
 * limit are bytes: -1 means 255 for the hop limits, anything above 255 is refused), boolean options that take the
 * whole 32-bit value, the options TCP refuses, interface selection and multicast membership error rules, IP_OPTIONS
 * length rules and the option-length protocol. Loopback only; no packet leaves the machine. */
#include "spl.h"

#define EINV WSAEINVAL
#define EFLT WSAEFAULT
#define ENOOPT WSAENOPROTOOPT
#define EADDR WSAEADDRNOTAVAIL

/* ---- tables ------------------------------------------------------------------------------------------ */
static const struct spl_row hops_rows[] = {      /* IP_TTL, IP_MULTICAST_TTL */
    {7, 0, 7}, {0, 0, 0}, {1, 0, 1}, {64, 0, 64}, {128, 0, 128}, {255, 0, 255}, {256, EINV, 0}, {1000, EINV, 0},
    {65535, EINV, 0}, {0x7fffffff, EINV, 0}, {(int)0x80000000, EINV, 0}, {-1, 0, 255}, {2, 0, 2},
};
static const struct spl_row tos_rows[] = {
    {7, 0, 7}, {0, 0, 0}, {1, 0, 1}, {4, 0, 4}, {0x28, 0, 0x28}, {0xb8, 0, 0xb8}, {255, 0, 255}, {256, EINV, 0},
    {1000, EINV, 0}, {65535, EINV, 0}, {0x7fffffff, EINV, 0}, {(int)0x80000000, EINV, 0}, {-1, EINV, 0}, {3, 0, 3},
};
/* On/off options look at the whole 32-bit value. */
static const struct spl_row flag_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {-1, 0, 1}, {2, 0, 1}, {255, 0, 1}, {256, 0, 1}, {0x100, 0, 1}, {1000, 0, 1},
    {65535, 0, 1}, {0x7fffffff, 0, 1}, {(int)0x80000000, 0, 1}, {0x01000000, 0, 1}, {0, 0, 0},
};
/* IP_MTU_DISCOVER keeps only the low byte, which must be 0..3. */
static const struct spl_row mtud_rows[] = {
    {0, 0, 0}, {1, 0, 1}, {2, 0, 2}, {3, 0, 3}, {4, EINV, 0}, {5, EINV, 0}, {-1, EINV, 0}, {10, EINV, 0},
    {1000, EINV, 0}, {65535, EINV, 0}, {256, 0, 0}, {0x2, 0, 2}, {(int)0x80000000, 0, 0},
};
static const struct spl_row unicast_if_rows[] = {
    {0x01000000, 0, 1}, {1, EADDR, 0}, {0x02000000, EINV, 0}, {0x63000000, EINV, 0}, {256, EINV, 0}, {(int)0x80000000, EINV, 0}, {0, 0, 0},
};

/* ---- defaults -------------------------------------------------------------------------------------------- */
SPL_DEFTEST(ip_default_tos_udp,             spl_udp4, SPL_LVL_IP, SPL_IP_TOS, 0xffffffff, 0)
SPL_DEFTEST(ip_default_ttl_udp_is_128,      spl_udp4, SPL_LVL_IP, SPL_IP_TTL, 0xffffffff, 128)
SPL_DEFTEST(ip_default_ttl_tcp_is_128,      spl_tcp4, SPL_LVL_IP, SPL_IP_TTL, 0xffffffff, 128)
SPL_DEFTEST(ip_default_tos_tcp,             spl_tcp4, SPL_LVL_IP, SPL_IP_TOS, 0xffffffff, 0)
SPL_DEFTEST(ip_default_multicast_ttl_is_1,  spl_udp4, SPL_LVL_IP, SPL_IP_MULTICAST_TTL, 0xffffffff, 1)
SPL_DEFTEST(ip_default_multicast_loop_on,   spl_udp4, SPL_LVL_IP, SPL_IP_MULTICAST_LOOP, 0xffffffff, 1)
SPL_DEFTEST(ip_default_multicast_if_none,   spl_udp4, SPL_LVL_IP, SPL_IP_MULTICAST_IF, 0xffffffff, 0)
SPL_DEFTEST(ip_default_unicast_if_none,     spl_udp4, SPL_LVL_IP, SPL_IP_UNICAST_IF, 0xffffffff, 0)
SPL_DEFTEST(ip_default_unicast_if_none_tcp, spl_tcp4, SPL_LVL_IP, SPL_IP_UNICAST_IF, 0xffffffff, 0)
SPL_DEFTEST(ip_default_pktinfo_off,         spl_udp4, SPL_LVL_IP, SPL_IP_PKTINFO, 0xffffffff, 0)
SPL_DEFTEST(ip_default_recvttl_off,         spl_udp4, SPL_LVL_IP, SPL_IP_RECVTTL, 0xffffffff, 0)
SPL_DEFTEST(ip_default_recvtos_off,         spl_udp4, SPL_LVL_IP, SPL_IP_RECVTOS, 0xffffffff, 0)
SPL_DEFTEST(ip_default_recvif_off,          spl_udp4, SPL_LVL_IP, SPL_IP_RECVIF, 0xffffffff, 0)
SPL_DEFTEST(ip_default_recvdstaddr_off,     spl_udp4, SPL_LVL_IP, SPL_IP_RECVDSTADDR, 0xffffffff, 0)
SPL_DEFTEST(ip_default_recvrthdr_off,       spl_udp4, SPL_LVL_IP, SPL_IP_RECVRTHDR, 0xffffffff, 0)
SPL_DEFTEST(ip_default_original_arrival_if_off, spl_udp4, SPL_LVL_IP, SPL_IP_ORIGINAL_ARRIVAL_IF, 0xffffffff, 0)
SPL_DEFTEST(ip_default_receive_broadcast_on, spl_udp4, SPL_LVL_IP, SPL_IP_RECEIVE_BROADCAST, 0xffffffff, 1)
SPL_DEFTEST(ip_default_mtu_discover_notset, spl_udp4, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 0xffffffff, 0)
SPL_DEFTEST(ip_default_mtu_discover_notset_tcp, spl_tcp4, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 0xffffffff, 0)

/* ---- hop limit and type of service ----------------------------------------------------------------------- */
SPL_ROWTEST(ip_ttl_values_udp,              spl_udp4, SPL_LVL_IP, SPL_IP_TTL, 0xffffffff, hops_rows)
SPL_ROWTEST(ip_ttl_values_tcp,              spl_tcp4, SPL_LVL_IP, SPL_IP_TTL, 0xffffffff, hops_rows)
SPL_ROWTEST(ip_multicast_ttl_values,        spl_udp4, SPL_LVL_IP, SPL_IP_MULTICAST_TTL, 0xffffffff, hops_rows)
SPL_ROWTEST(ip_tos_values_udp,              spl_udp4, SPL_LVL_IP, SPL_IP_TOS, 0xffffffff, tos_rows)
SPL_ROWTEST(ip_tos_values_tcp,              spl_tcp4, SPL_LVL_IP, SPL_IP_TOS, 0xffffffff, tos_rows)

/* ---- boolean options -------------------------------------------------------------------------------------- */
SPL_ROWTEST(ip_multicast_loop_values,       spl_udp4, SPL_LVL_IP, SPL_IP_MULTICAST_LOOP, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_dontfragment_values_udp,     spl_udp4, SPL_LVL_IP, SPL_IP_DONTFRAGMENT, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_dontfragment_values_tcp,     spl_tcp4, SPL_LVL_IP, SPL_IP_DONTFRAGMENT, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_pktinfo_values,              spl_udp4, SPL_LVL_IP, SPL_IP_PKTINFO, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_recvttl_values,              spl_udp4, SPL_LVL_IP, SPL_IP_RECVTTL, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_recvtos_values,              spl_udp4, SPL_LVL_IP, SPL_IP_RECVTOS, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_recvif_values,               spl_udp4, SPL_LVL_IP, SPL_IP_RECVIF, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_recvdstaddr_values,          spl_udp4, SPL_LVL_IP, SPL_IP_RECVDSTADDR, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_recvrthdr_values,            spl_udp4, SPL_LVL_IP, SPL_IP_RECVRTHDR, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_receive_broadcast_values,    spl_udp4, SPL_LVL_IP, SPL_IP_RECEIVE_BROADCAST, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_original_arrival_if_values,  spl_udp4, SPL_LVL_IP, SPL_IP_ORIGINAL_ARRIVAL_IF, 0xffffffff, flag_rows)
SPL_ROWTEST(ip_mtu_discover_values_udp,     spl_udp4, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 0xffffffff, mtud_rows)
SPL_ROWTEST(ip_mtu_discover_values_tcp,     spl_tcp4, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 0xffffffff, mtud_rows)
SPL_ROWTEST(ip_unicast_if_values_udp,       spl_udp4, SPL_LVL_IP, SPL_IP_UNICAST_IF, 0xffffffff, unicast_if_rows)
SPL_ROWTEST(ip_unicast_if_values_tcp,       spl_tcp4, SPL_LVL_IP, SPL_IP_UNICAST_IF, 0xffffffff, unicast_if_rows)

/* ---- options a stream socket refuses (get and set both WSAEINVAL) --------------------------------------- */
SPL_REFUSETEST(ip_tcp_refuses_multicast_if,      spl_tcp4, SPL_LVL_IP, SPL_IP_MULTICAST_IF, EINV)
SPL_REFUSETEST(ip_tcp_refuses_multicast_ttl,     spl_tcp4, SPL_LVL_IP, SPL_IP_MULTICAST_TTL, EINV)
SPL_REFUSETEST(ip_tcp_refuses_multicast_loop,    spl_tcp4, SPL_LVL_IP, SPL_IP_MULTICAST_LOOP, EINV)
SPL_REFUSETEST(ip_tcp_refuses_pktinfo,           spl_tcp4, SPL_LVL_IP, SPL_IP_PKTINFO, EINV)
SPL_REFUSETEST(ip_tcp_refuses_recvttl,           spl_tcp4, SPL_LVL_IP, SPL_IP_RECVTTL, EINV)
SPL_REFUSETEST(ip_tcp_refuses_receive_broadcast, spl_tcp4, SPL_LVL_IP, SPL_IP_RECEIVE_BROADCAST, EINV)
SPL_REFUSETEST(ip_tcp_refuses_recvif,            spl_tcp4, SPL_LVL_IP, SPL_IP_RECVIF, EINV)
SPL_REFUSETEST(ip_tcp_refuses_recvdstaddr,       spl_tcp4, SPL_LVL_IP, SPL_IP_RECVDSTADDR, EINV)
SPL_REFUSETEST(ip_tcp_refuses_recvrthdr,         spl_tcp4, SPL_LVL_IP, SPL_IP_RECVRTHDR, EINV)
SPL_REFUSETEST(ip_tcp_refuses_recvtos,           spl_tcp4, SPL_LVL_IP, SPL_IP_RECVTOS, EINV)
SPL_REFUSETEST(ip_tcp_refuses_original_arrival_if, spl_tcp4, SPL_LVL_IP, SPL_IP_ORIGINAL_ARRIVAL_IF, EINV)
SPL_REFUSETEST(ip_tcp_refuses_hdrincl,           spl_tcp4, SPL_LVL_IP, SPL_IP_HDRINCL, EINV)
SPL_REFUSETEST(ip_udp_refuses_hdrincl,           spl_udp4, SPL_LVL_IP, SPL_IP_HDRINCL, EINV)
/* Options the stack knows nothing about, on the IPv4 level. */
SPL_REFUSETEST(ip_option_zero_unknown_tcp,       spl_tcp4, SPL_LVL_IP, 0, ENOOPT)
SPL_REFUSETEST(ip_option_zero_unknown_udp,       spl_udp4, SPL_LVL_IP, 0, ENOOPT)
SPL_REFUSETEST(ip_option_39_tclass_unknown_on_v4_udp, spl_udp4, SPL_LVL_IP, SPL_IP_TCLASS, ENOOPT)
SPL_REFUSETEST(ip_option_39_tclass_unknown_on_v4_tcp, spl_tcp4, SPL_LVL_IP, SPL_IP_TCLASS, ENOOPT)
SPL_REFUSETEST(ip_option_1000_unknown,           spl_udp4, SPL_LVL_IP, 1000, ENOOPT)
TEST(ip_mtu_unconnected_get_notconn_set_unsupported)
{
    SOCKET s; int v = 0, l = 4, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_MTU, &v, &l, &e), SOCKET_ERROR); SEQ(e, WSAENOTCONN);
    v = 1400;
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MTU, &v, 4, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    spl_close(s);
    s = spl_tcp4();
    l = 4;
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_MTU, &v, &l, &e), SOCKET_ERROR); SEQ(e, WSAENOTCONN);
    spl_close(s);
}

/* ---- option length protocol -------------------------------------------------------------------------------- */
TEST(ip_set_byte_options_accept_one_byte)
{
    /* TTL, TOS, multicast TTL/loop and DONTFRAGMENT accept any optlen >= 1; zero is a fault. */
    SOCKET s; int i;
    static const int opts[] = {SPL_IP_TTL, SPL_IP_TOS, SPL_IP_MULTICAST_TTL, SPL_IP_MULTICAST_LOOP, SPL_IP_DONTFRAGMENT};
    if (!spl_up()) return;
    s = spl_udp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) spl_len_protocol(s, SPL_LVL_IP, opts[i], 5, 1, EFLT);
    spl_close(s);
}
TEST(ip_set_one_byte_uses_only_that_byte)
{
    /* With a short buffer the value is the first byte alone; the 0x100 bit that would make it invalid is not seen. */
    SOCKET s; int v = 0x1c8, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_TTL, &v, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 0xc8);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_TOS, &v, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TOS), 0xc8);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_TTL, &v, 3, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_MULTICAST_TTL), 0xc8);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_TTL, &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 0xc8);
    spl_close(s);
}
TEST(ip_set_one_byte_minus_one_means_255_for_hop_limits_only)
{
    SOCKET s; int v = 0xff, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_TTL, &v, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 255);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_TOS, &v, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TOS), 255);
    spl_close(s);
}
TEST(ip_get_byte_options_buffer_sizes)
{
    SOCKET s; int i;
    static const int opts[] = {SPL_IP_TTL, SPL_IP_TOS, SPL_IP_MULTICAST_TTL};
    if (!spl_up()) return;
    s = spl_udp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) spl_get_protocol(s, SPL_LVL_IP, opts[i], 1, EFLT, 1, 4, 4);
    spl_close(s);
}
TEST(ip_get_byte_option_short_buffer_returns_low_byte)
{
    SOCKET s; unsigned char b[4]; int l = 1, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TTL, 77, &e), 0);
    memset(b, 0xcc, sizeof b);
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_TTL, b, &l, &e), 0);
    SEQ(l, 1); SEQ(b[0], 77); SEQ(b[1], 0xcc);
    spl_close(s);
}
TEST(ip_set_flag_options_zero_length_is_fault)
{
    SOCKET s; int i, e, v = 1;
    static const int opts[] = {SPL_IP_PKTINFO, SPL_IP_RECVTTL, SPL_IP_RECVTOS, SPL_IP_RECVIF, SPL_IP_RECVDSTADDR, SPL_IP_RECEIVE_BROADCAST};
    if (!spl_up()) return;
    s = spl_udp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) {
        SEQ(spl_set(s, SPL_LVL_IP, opts[i], &v, 0, &e), SOCKET_ERROR); SEQ(e, EFLT);
        SEQ(spl_set(s, SPL_LVL_IP, opts[i], &v, 4, &e), 0);
    }
    spl_close(s);
}
TEST(ip_multicast_if_set_needs_four_bytes)
{
    SOCKET s; struct in_addr a; int l, e;
    if (!spl_up()) return;
    s = spl_udp4();
    a.s_addr = 0x0100007f;
    for (l = 0; l <= 8; l++) {
        int r = spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &a, l, &e);
        if (l < 4) { SEQ(r, SOCKET_ERROR); SEQ(e, EFLT); } else SEQ(r, 0);
    }
    spl_close(s);
}
TEST(ip_mtu_discover_length_rules)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_udp4();
    spl_len_protocol(s, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 2, 1, EFLT);
    spl_close(s);
}

/* ---- the IP_OPTIONS blob ------------------------------------------------------------------------------------ */
TEST(ip_options_default_is_empty)
{
    SOCKET s; unsigned char b[44]; int l = sizeof b, e;
    if (!spl_up()) return;
    s = spl_udp4();
    memset(b, 0xcc, sizeof b);
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_OPTIONS, b, &l, &e), 0);
    SEQ(l, 0);
    SEQ(b[0], 0xcc);
    l = 0;
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_OPTIONS, b, &l, &e), SOCKET_ERROR); SEQ(e, EFLT);
    spl_close(s);
}
TEST(ip_options_set_length_rules)
{
    /* Option bytes are padding (NOP, value 1). One byte is refused; 2..40 are accepted; more than 40 is refused. */
    SOCKET s; unsigned char o[64]; int l, e;
    if (!spl_up()) return;
    s = spl_udp4();
    memset(o, 1, sizeof o);
    for (l = 0; l <= 48; l++) {
        int r = spl_set(s, SPL_LVL_IP, SPL_IP_OPTIONS, o, l, &e);
        if (l == 1 || l > 40) { CHECKF(r == SOCKET_ERROR && e == EINV, "len %d rc %d err %d", l, r, e); }
        else CHECKF(r == 0, "len %d rc %d err %d", l, r, e);
    }
    spl_close(s);
}
TEST(ip_options_round_trip_and_clear)
{
    SOCKET s; unsigned char o[8] = {1, 1, 1, 1}, g[44]; int l = sizeof g, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_OPTIONS, o, 4, &e), 0);
    memset(g, 0xcc, sizeof g);
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_OPTIONS, g, &l, &e), 0);
    SEQ(l, 4); SEQ(g[0], 1); SEQ(g[3], 1);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_OPTIONS, o, 0, &e), 0);
    l = sizeof g;
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_OPTIONS, g, &l, &e), 0);
    SEQ(l, 0);
    spl_close(s);
}
TEST(ip_options_set_on_tcp_socket)
{
    SOCKET s; unsigned char o[4] = {1, 1, 1, 1}; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_OPTIONS, o, 4, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_OPTIONS, o, 1, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}

/* ---- multicast interface and membership ---------------------------------------------------------------------- */
TEST(ip_multicast_if_accepts_loopback_address_and_any)
{
    SOCKET s; struct in_addr a; int e, v;
    if (!spl_up()) return;
    s = spl_udp4();
    a.s_addr = 0x0100007f;
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &a, 4, &e), 0);
    SEQ(spl_geti(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &v, &e), 0);
    SEQ((unsigned)v, 0x0100007fu);
    a.s_addr = 0;
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &a, 4, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF), 0);
    spl_close(s);
}
TEST(ip_multicast_if_accepts_interface_index_form)
{
    /* A value whose top byte is the interface index (network order) and the rest zero names that interface; index 1 is loopback. */
    SOCKET s; int e, v;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, 0x01000000, &e), 0);
    SEQ(spl_geti(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &v, &e), 0);
    SEQ((unsigned)v, 0x01000000u);
    spl_close(s);
}
TEST(ip_multicast_if_rejects_nonexistent_interface_index)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, 0x63000000, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF), 0);
    spl_close(s);
}
TEST(ip_multicast_if_refused_value_leaves_previous)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, 0x0100007f, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, 0x63000000, &e), SOCKET_ERROR);
    SEQ((unsigned)spl_rb(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF), 0x0100007fu);
    spl_close(s);
}
TEST(ip_multicast_if_set_bound_and_connected_udp)
{
    SOCKET s, d; u_short p = 0; struct sockaddr_in a; struct in_addr lo; int e;
    if (!spl_up()) return;
    s = spl_udp4(); d = spl_udp4();
    spl_bind4(d, &p); spl_bind4(s, NULL);
    lo.s_addr = 0x0100007f;
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &lo, 4, &e), 0);
    spl_loop4(&a); a.sin_port = p;
    SEQ(spl_connect(s, (struct sockaddr *)&a, sizeof a), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &lo, 4, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_MULTICAST_TTL, 3, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_MULTICAST_TTL), 3);
    spl_close(s); spl_close(d);
}

static void mreq_set(struct ip_mreq *m, unsigned group, unsigned ifaddr)
{
    memset(m, 0, sizeof *m);
    m->imr_multiaddr.s_addr = group;
    m->imr_interface.s_addr = ifaddr;
}
#define G_MDNS 0xfb0000e0u    /* 224.0.0.251, network order */
TEST(ip_membership_add_then_drop_on_loopback_interface)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&m, G_MDNS, 0x0100007f);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
TEST(ip_membership_add_twice_is_invalid)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&m, G_MDNS, 0x0100007f);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);   /* can join again after leaving */
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
TEST(ip_membership_drop_without_join_is_address_not_available)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&m, G_MDNS, 0x0100007f);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    spl_close(s);
}
TEST(ip_membership_default_interface_join_and_leave)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&m, G_MDNS, 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
TEST(ip_membership_group_must_be_multicast)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&m, 0x0100007f, 0x0100007f);     /* 127.0.0.1 is not a group */
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    mreq_set(&m, 0, 0x0100007f);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    mreq_set(&m, 0xffffffff, 0x0100007f);     /* limited broadcast */
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EADDR);
    spl_close(s);
}
TEST(ip_membership_requires_eight_bytes)
{
    SOCKET s; struct ip_mreq m; int l, e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&m, G_MDNS, 0x0100007f);
    for (l = 0; l <= 12; l++) {
        int r = spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, l, &e);
        if (l < 8) { CHECKF(r == SOCKET_ERROR && e == EFLT, "len %d rc %d err %d", l, r, e); }
        else { CHECKF(r == 0, "len %d rc %d err %d", l, r, e); spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e); }
    }
    mreq_set(&m, G_MDNS, 0x0100007f);
    for (l = 0; l <= 7; l++) {
        int r = spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, l, &e);
        CHECKF(r == SOCKET_ERROR && e == EFLT, "drop len %d rc %d err %d", l, r, e);
    }
    spl_close(s);
}
TEST(ip_membership_options_cannot_be_read)
{
    SOCKET s; struct ip_mreq m; int l = sizeof m, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, &l, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    l = sizeof m;
    SEQ(spl_get(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, &l, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    spl_close(s);
}
TEST(ip_membership_on_bound_socket)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_bind4(s, NULL), 0);
    mreq_set(&m, G_MDNS, 0x0100007f);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
}
TEST(ip_membership_two_groups_independent)
{
    SOCKET s; struct ip_mreq a, b; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    mreq_set(&a, G_MDNS, 0x0100007f); mreq_set(&b, 0x010000e0 | 0xfc000000u, 0x0100007f);
    b.imr_multiaddr.s_addr = 0xfc0000e0u;     /* 224.0.0.252 */
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &a, sizeof a, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &b, sizeof b, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &a, sizeof a, &e), 0);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &a, sizeof a, &e), SOCKET_ERROR); SEQ(e, EADDR);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &b, sizeof b, &e), 0);
    spl_close(s);
}
TEST(ip_membership_dropped_on_close_allows_other_socket_to_join)
{
    SOCKET s, t; struct ip_mreq m; int e;
    if (!spl_up()) return;
    mreq_set(&m, G_MDNS, 0x0100007f);
    s = spl_udp4();
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(s);
    t = spl_udp4();
    SEQ(spl_set(t, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), 0);   /* state belongs to the socket */
    SEQ(spl_set(t, SPL_LVL_IP, SPL_IP_DROP_MEMBERSHIP, &m, sizeof m, &e), 0);
    spl_close(t);
}
