/* x_raw_icmp_elevated / opts2: option survey on raw ICMP sockets.
 *
 * One row per option: the result of getsockopt on a fresh socket (error or value and returned length), the result
 * of setting 1, and the value read back. Every row is logged with t_note as a fixed line so the surface of raw
 * sockets can be compared between Windows builds; the rows that are documented behaviour carry hard checks
 * (an unknown option level or number is refused, a short buffer is refused, results do not depend on the family
 * for the socket-level options). */
#include "rawh.h"

struct orow { int lvl, opt; const char *name; };
static const struct orow sol[] = {
    {SOL_SOCKET, SO_DEBUG, "SO_DEBUG"}, {SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE"}, {SOL_SOCKET, SO_DONTROUTE, "SO_DONTROUTE"},
    {SOL_SOCKET, SO_OOBINLINE, "SO_OOBINLINE"}, {SOL_SOCKET, SO_RCVLOWAT, "SO_RCVLOWAT"}, {SOL_SOCKET, SO_SNDLOWAT, "SO_SNDLOWAT"},
    {SOL_SOCKET, SO_ERROR, "SO_ERROR"}, {SOL_SOCKET, SO_USELOOPBACK, "SO_USELOOPBACK"}, {SOL_SOCKET, 0x2001 /* SO_GROUP_ID */, "SO_GROUP_ID"},
    {SOL_SOCKET, 0x2002 /* SO_GROUP_PRIORITY */, "SO_GROUP_PRIORITY"}, {SOL_SOCKET, SO_MAX_MSG_SIZE, "SO_MAX_MSG_SIZE"},
    {SOL_SOCKET, SO_CONDITIONAL_ACCEPT, "SO_CONDITIONAL_ACCEPT"}, {SOL_SOCKET, SO_RCVTIMEO, "SO_RCVTIMEO"}, {SOL_SOCKET, SO_SNDTIMEO, "SO_SNDTIMEO"},
    {SOL_SOCKET, 0x3005, "SO_RANDOMIZE_PORT"}, {SOL_SOCKET, 0x3006, "SO_PORT_SCALABILITY"},
    {SOL_SOCKET, SO_CONNECT_TIME, "SO_CONNECT_TIME"}, {SOL_SOCKET, SO_BROADCAST, "SO_BROADCAST"}, {SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR"},
    {SOL_SOCKET, SO_EXCLUSIVEADDRUSE, "SO_EXCLUSIVEADDRUSE"}, {SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF"}, {SOL_SOCKET, SO_SNDBUF, "SO_SNDBUF"},
    {SOL_SOCKET, 0x7010 /* SO_UPDATE_ACCEPT_CONTEXT */, "SO_UPDATE_ACCEPT_CONTEXT"}, {SOL_SOCKET, 0x700B /* SO_OPENTYPE */, "SO_OPENTYPE"},
};
static const struct orow ipl[] = {
    {IPPROTO_IP, 1, "IP_OPTIONS"}, {IPPROTO_IP, 2, "IP_HDRINCL"}, {IPPROTO_IP, 3, "IP_TOS"}, {IPPROTO_IP, 4, "IP_TTL"},
    {IPPROTO_IP, 9, "IP_MULTICAST_IF"}, {IPPROTO_IP, 10, "IP_MULTICAST_TTL"}, {IPPROTO_IP, 11, "IP_MULTICAST_LOOP"},
    {IPPROTO_IP, 14, "IP_DONTFRAGMENT"}, {IPPROTO_IP, 19, "IP_PKTINFO"}, {IPPROTO_IP, 21, "IP_RECVTTL"},
    {IPPROTO_IP, 22, "IP_RECEIVE_BROADCAST"}, {IPPROTO_IP, 24, "IP_RECVIF"}, {IPPROTO_IP, 31, "IP_UNICAST_IF"},
    {IPPROTO_IP, 40, "IP_RECVTCLASS"}, {IPPROTO_IP, 47, "IP_ORIGINAL_ARRIVAL_IF"}, {IPPROTO_IP, 71, "IP_MTU_DISCOVER"},
    {IPPROTO_IP, 73, "IP_MTU"}, {IPPROTO_IP, 75, "IP_RECVERR"}, {IPPROTO_IP, 0x7ff0, "unknown_IP_option"},
};
static void survey(SOCKET s, const struct orow *r, int n, const char *fam)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned char b[64]; int len = sizeof b, g, se, s2, len2 = sizeof b; int one = 1, g2;
        memset(b, 0, sizeof b); rw_seterr(0);
        g = U(getsockopt)(s, r[i].lvl, r[i].opt, (char *)b, &len); se = g ? rw_err() : 0;
        t_note("%s %s get: %s%d len=%d first=%d", fam, r[i].name, g ? "err=" : "ok=", g ? se : 0, g ? 0 : len, g ? 0 : *(int *)b);
        rw_seterr(0); s2 = U(setsockopt)(s, r[i].lvl, r[i].opt, (char *)&one, 4); g2 = s2 ? rw_err() : 0;
        memset(b, 0, sizeof b); rw_seterr(0);
        g = U(getsockopt)(s, r[i].lvl, r[i].opt, (char *)b, &len2);
        t_note("%s %s set1: %s%d after get: %s len=%d first=%d", fam, r[i].name, s2 ? "err=" : "ok=", g2, g ? "err" : "ok", g ? 0 : len2, g ? 0 : *(int *)b);
    }
}
TEST(rawopt2_survey_solevel_v4) { SOCKET s; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; } survey(s, sol, sizeof sol / sizeof sol[0], "v4"); rw_close(s); }
TEST(rawopt2_survey_solevel_v6) { SOCKET s; RW_UP(); s = rw_raw(AF_INET6, IPPROTO_ICMPV6); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; } survey(s, sol, sizeof sol / sizeof sol[0], "v6"); rw_close(s); }
TEST(rawopt2_survey_iplevel_v4) { SOCKET s; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; } survey(s, ipl, sizeof ipl / sizeof ipl[0], "v4"); rw_close(s); }

TEST(rawopt2_unknown_levels_and_options_refused) {
    SOCKET s; int v = 0, n, r; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; }
    n = 4; rw_seterr(0); r = U(getsockopt)(s, SOL_SOCKET, 0x7fff, (char *)&v, &n); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); r = U(setsockopt)(s, SOL_SOCKET, 0x7fff, (char *)&v, 4); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    n = 4; rw_seterr(0); r = U(getsockopt)(s, 0x7123, 1, (char *)&v, &n); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); r = U(setsockopt)(s, 0x7123, 1, (char *)&v, 4); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    n = 4; rw_seterr(0); r = U(getsockopt)(s, IPPROTO_IP, 0x7ff0, (char *)&v, &n); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOPROTOOPT);
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, 0x7ff0, (char *)&v, 4); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOPROTOOPT);
    rw_close(s);
}
#define ANY (-0x7fffffff)
struct trow { int lvl, opt; const char *name; int get_err, get_val, set_err, back; };
/* a fresh socket per row so that no option can influence another */
static void table(int af, int proto, const struct trow *t, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        SOCKET s = rw_raw(af, proto); int v, len, r, one = 1;
        if (s == INVALID_SOCKET) { t_skip("raw refused"); return; }
        len = 4; v = 0x5a5a5a5a; rw_seterr(0); r = U(getsockopt)(s, t[i].lvl, t[i].opt, (char *)&v, &len);
        t_check((r ? rw_err() : 0) == t[i].get_err, __FILE__, __LINE__, "get result", "%s: got %d want %d", t[i].name, r ? rw_err() : 0, t[i].get_err);
        if (!r && t[i].get_val != ANY) t_check(v == t[i].get_val, __FILE__, __LINE__, "get value", "%s: got %d want %d", t[i].name, v, t[i].get_val);
        rw_seterr(0); r = U(setsockopt)(s, t[i].lvl, t[i].opt, (char *)&one, 4);
        t_check((r ? rw_err() : 0) == t[i].set_err, __FILE__, __LINE__, "set result", "%s: got %d want %d", t[i].name, r ? rw_err() : 0, t[i].set_err);
        if (!r && t[i].back != ANY) {
            len = 4; v = 0x5a5a5a5a; r = U(getsockopt)(s, t[i].lvl, t[i].opt, (char *)&v, &len);
            t_check(r == 0 && v == t[i].back, __FILE__, __LINE__, "readback", "%s: got %d want %d", t[i].name, v, t[i].back);
        }
        rw_close(s);
    }
}
static const struct trow sock_rows[] = {
    {SOL_SOCKET, SO_DEBUG, "SO_DEBUG", 0, 0, 0, 1},
    {SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE", WSAENOPROTOOPT, 0, WSAENOPROTOOPT, ANY},
    {SOL_SOCKET, SO_OOBINLINE, "SO_OOBINLINE", WSAENOPROTOOPT, 0, WSAENOPROTOOPT, ANY},
    {SOL_SOCKET, SO_RCVLOWAT, "SO_RCVLOWAT", WSAEINVAL, 0, WSAEINVAL, ANY},
    {SOL_SOCKET, SO_SNDLOWAT, "SO_SNDLOWAT", WSAEINVAL, 0, WSAEINVAL, ANY},
    {SOL_SOCKET, SO_USELOOPBACK, "SO_USELOOPBACK", WSAEINVAL, 0, WSAEINVAL, ANY},
    {SOL_SOCKET, 0x2001, "SO_GROUP_ID", 0, 0, WSAEINVAL, 0},
    {SOL_SOCKET, 0x2002, "SO_GROUP_PRIORITY", 0, 0, 0, 1},
    {SOL_SOCKET, SO_CONDITIONAL_ACCEPT, "SO_CONDITIONAL_ACCEPT", 0, 0, 0, 1},
    {SOL_SOCKET, SO_RCVTIMEO, "SO_RCVTIMEO", 0, 0, 0, 1},
    {SOL_SOCKET, SO_SNDTIMEO, "SO_SNDTIMEO", 0, 0, 0, 1},
    {SOL_SOCKET, 0x3005, "SO_RANDOMIZE_PORT", WSAEINVAL, 0, WSAEINVAL, ANY},
    {SOL_SOCKET, 0x3006, "SO_PORT_SCALABILITY", WSAEINVAL, 0, WSAEINVAL, ANY},
    {SOL_SOCKET, SO_CONNECT_TIME, "SO_CONNECT_TIME", 0, -1, WSAEINVAL, -1},
    {SOL_SOCKET, SO_BROADCAST, "SO_BROADCAST", 0, 0, 0, 1},
    {SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR", 0, 0, 0, 1},
    {SOL_SOCKET, SO_EXCLUSIVEADDRUSE, "SO_EXCLUSIVEADDRUSE", 0, 0, 0, 1},
    {SOL_SOCKET, SO_ERROR, "SO_ERROR", 0, 0, 0, ANY},
};
TEST(rawopt2_solevel_table_v4) { RW_UP(); table(AF_INET, IPPROTO_ICMP, sock_rows, sizeof sock_rows / sizeof sock_rows[0]); }
TEST(rawopt2_solevel_table_v6) { RW_UP(); table(AF_INET6, IPPROTO_ICMPV6, sock_rows, sizeof sock_rows / sizeof sock_rows[0]); }
static const struct trow ip_rows[] = {
    {IPPROTO_IP, 3, "IP_TOS", 0, 0, 0, 1},
    {IPPROTO_IP, 4, "IP_TTL", 0, 128, 0, 1},
    {IPPROTO_IP, 9, "IP_MULTICAST_IF", 0, 0, WSAEADDRNOTAVAIL, ANY},
    {IPPROTO_IP, 10, "IP_MULTICAST_TTL", 0, 1, 0, 1},
    {IPPROTO_IP, 11, "IP_MULTICAST_LOOP", 0, 1, 0, 1},
    {IPPROTO_IP, 14, "IP_DONTFRAGMENT", 0, 0, 0, 1},
    {IPPROTO_IP, 19, "IP_PKTINFO", 0, 0, 0, 1},
    {IPPROTO_IP, 21, "IP_RECVTTL", 0, 0, 0, 1},
    {IPPROTO_IP, 22, "IP_RECEIVE_BROADCAST", 0, 1, 0, 1},
    {IPPROTO_IP, 24, "IP_RECVIF", 0, 0, 0, 1},
    {IPPROTO_IP, 31, "IP_UNICAST_IF", 0, 0, WSAEADDRNOTAVAIL, ANY},
    {IPPROTO_IP, 40, "IP_RECVTCLASS", 0, 0, 0, 1},
    {IPPROTO_IP, 47, "IP_ORIGINAL_ARRIVAL_IF", 0, 0, 0, 1},
    {IPPROTO_IP, 71, "IP_MTU_DISCOVER", 0, 0, 0, 1},
    {IPPROTO_IP, 73, "IP_MTU", WSAENOTCONN, 0, WSAENOPROTOOPT, ANY},
    {IPPROTO_IP, 75, "IP_RECVERR", WSAEINVAL, 0, WSAEINVAL, ANY},
};
TEST(rawopt2_iplevel_table_v4) { RW_UP(); table(AF_INET, IPPROTO_ICMP, ip_rows, sizeof ip_rows / sizeof ip_rows[0]); }
TEST(rawopt2_getsockopt_zero_length_is_efault) {
    SOCKET s; int v = 0, n = 0, r; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; }
    rw_seterr(0); r = U(getsockopt)(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, &n);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT); RW_EQ(n, 0);
    rw_seterr(0); r = U(getsockopt)(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, NULL); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(s);
}
static const struct orow ip6l[] = {
    {IPPROTO_IPV6, 2, "IPV6_HDRINCL"}, {IPPROTO_IPV6, 4, "IPV6_UNICAST_HOPS"}, {IPPROTO_IPV6, 9, "IPV6_MULTICAST_IF"},
    {IPPROTO_IPV6, 10, "IPV6_MULTICAST_HOPS"}, {IPPROTO_IPV6, 11, "IPV6_MULTICAST_LOOP"}, {IPPROTO_IPV6, 14, "IPV6_DONTFRAG"},
    {IPPROTO_IPV6, 19, "IPV6_PKTINFO"}, {IPPROTO_IPV6, 21, "IPV6_HOPLIMIT"}, {IPPROTO_IPV6, 23, "IPV6_PROTECTION_LEVEL"},
    {IPPROTO_IPV6, 24, "IPV6_RECVIF"}, {IPPROTO_IPV6, 25, "IPV6_RECVDSTADDR"}, {IPPROTO_IPV6, 26, "IPV6_CHECKSUM"},
    {IPPROTO_IPV6, 27, "IPV6_V6ONLY"}, {IPPROTO_IPV6, 31, "IPV6_UNICAST_IF"}, {IPPROTO_IPV6, 39, "IPV6_TCLASS"},
    {IPPROTO_IPV6, 40, "IPV6_RECVTCLASS"}, {IPPROTO_IPV6, 71, "IPV6_MTU_DISCOVER"}, {IPPROTO_IPV6, 72, "IPV6_MTU"},
    {IPPROTO_IPV6, 0x7ff0, "unknown_IPV6_option"},
};
TEST(rawopt2_survey_ipv6level_v6) {
    int i; RW_UP();
    for (i = 0; i < (int)(sizeof ip6l / sizeof ip6l[0]); i++) {
        SOCKET s = rw_raw(AF_INET6, IPPROTO_ICMPV6); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; }
        survey(s, &ip6l[i], 1, "v6"); rw_close(s);
    }
}
static const struct trow ip6_rows[] = {
    {IPPROTO_IPV6, 4, "IPV6_UNICAST_HOPS", 0, 128, 0, 1},
    {IPPROTO_IPV6, 9, "IPV6_MULTICAST_IF", 0, 0, 0, 1},
    {IPPROTO_IPV6, 10, "IPV6_MULTICAST_HOPS", 0, 1, 0, 1},
    {IPPROTO_IPV6, 11, "IPV6_MULTICAST_LOOP", 0, 1, 0, 1},
    {IPPROTO_IPV6, 14, "IPV6_DONTFRAG", 0, 0, 0, 1},
    {IPPROTO_IPV6, 19, "IPV6_PKTINFO", 0, 0, 0, 1},
    {IPPROTO_IPV6, 21, "IPV6_HOPLIMIT", 0, 0, 0, 1},
    {IPPROTO_IPV6, 23, "IPV6_PROTECTION_LEVEL", 0, 10, WSAEINVAL, 10},
    {IPPROTO_IPV6, 24, "IPV6_RECVIF", 0, 0, 0, 1},
    {IPPROTO_IPV6, 25, "IPV6_RECVDSTADDR", 0, 0, 0, 1},
    {IPPROTO_IPV6, 26, "IPV6_CHECKSUM", WSAENOPROTOOPT, 0, WSAENOPROTOOPT, ANY},
    {IPPROTO_IPV6, 31, "IPV6_UNICAST_IF", 0, 0, 0, 1},
    {IPPROTO_IPV6, 39, "IPV6_TCLASS", WSAENOPROTOOPT, 0, WSAENOPROTOOPT, ANY},
    {IPPROTO_IPV6, 40, "IPV6_RECVTCLASS", 0, 0, 0, 1},
    {IPPROTO_IPV6, 71, "IPV6_MTU_DISCOVER", 0, 0, 0, 1},
    {IPPROTO_IPV6, 72, "IPV6_MTU", WSAENOTCONN, 0, WSAENOPROTOOPT, ANY},
    {IPPROTO_IPV6, 0x7ff0, "unknown_IPV6_option", WSAENOPROTOOPT, 0, WSAENOPROTOOPT, ANY},
};
TEST(rawopt2_iplevel_table_v6) { RW_UP(); table(AF_INET6, IPPROTO_ICMPV6, ip6_rows, sizeof ip6_rows / sizeof ip6_rows[0]); }
TEST(rawopt2_dontfragment_excludes_mtu_discover) {
    SOCKET s; int one = 1, r; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw refused"); return; }
    RW_EQ(U(setsockopt)(s, IPPROTO_IP, 14, (char *)&one, 4), 0);
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, 71, (char *)&one, 4); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
