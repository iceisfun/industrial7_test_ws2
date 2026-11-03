/* Protocol-level options on raw IPv4/IPv6 sockets (elevation is needed to create them; tests skip otherwise):
 * IP_HDRINCL is the one IPv4 option that exists only for raw sockets, and TCP/UDP-level options are refused on them. */
#include "spl.h"

#define EINV WSAEINVAL

static SOCKET raw4(void)
{
    SOCKET s = spl_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) t_skip("raw socket not available (error %d)", spl_WSAGetLastError());
    return s;
}
static SOCKET raw6(void)
{
    SOCKET s = spl_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (s == INVALID_SOCKET) t_skip("raw IPv6 socket not available (error %d)", spl_WSAGetLastError());
    return s;
}
TEST(raw_ip_hdrincl_round_trip)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = raw4(); if (s == INVALID_SOCKET) return;
    if (!spl_elevated()) {
        /* an ICMP raw socket can be opened without elevation, but header inclusion cannot be enabled */
        SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_HDRINCL, 1, &e), SOCKET_ERROR); SEQ(e, WSAEACCES);
        SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_HDRINCL), 0);
        spl_close(s);
        return;
    }
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_HDRINCL, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_HDRINCL), 1);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_HDRINCL, 0, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_HDRINCL), 0);
    spl_close(s);
}
TEST(raw_ipv6_hdrincl_round_trip)
{
    SOCKET s; int e;
    if (!spl_up() || !spl_have6()) return;
    s = raw6(); if (s == INVALID_SOCKET) return;
    if (!spl_elevated()) {
        /* an ICMP raw socket can be opened without elevation, but header inclusion cannot be enabled */
        SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_HDRINCL, 1, &e), SOCKET_ERROR); SEQ(e, WSAEACCES);
        SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_HDRINCL), 0);
        spl_close(s);
        return;
    }
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_HDRINCL, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_HDRINCL), 1);
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_HDRINCL, 0, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_HDRINCL), 0);
    spl_close(s);
}
TEST(raw_ip_ttl_and_tos_values)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = raw4(); if (s == INVALID_SOCKET) return;
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TTL, 5, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 5);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TTL, 256, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TOS, 8, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TOS), 8);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_TOS, 256, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}
TEST(raw_tcp_and_udp_level_options_refused)
{
    SOCKET s; int e, v = 1, l = 4;
    if (!spl_up()) return;
    s = raw4(); if (s == INVALID_SOCKET) return;
    SEQ(spl_set(s, SPL_LVL_TCP, TCP_NODELAY, &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_get(s, SPL_LVL_TCP, TCP_NODELAY, &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_set(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    l = 4;
    SEQ(spl_get(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}
TEST(raw_ip_options_that_need_a_datagram_service_still_set)
{
    /* A raw socket takes the receive-info flags like a UDP socket does. */
    SOCKET s; int e, i;
    static const int opts[] = {SPL_IP_PKTINFO, SPL_IP_RECVTTL, SPL_IP_RECVTOS, SPL_IP_DONTFRAGMENT};
    if (!spl_up()) return;
    s = raw4(); if (s == INVALID_SOCKET) return;
    for (i = 0; i < 4; i++) {
        SEQ(spl_seti(s, SPL_LVL_IP, opts[i], 1, &e), 0);
        SEQ(spl_rb(s, SPL_LVL_IP, opts[i]), 1);
    }
    spl_close(s);
}
