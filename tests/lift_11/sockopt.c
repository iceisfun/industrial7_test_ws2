/* Socket option behaviour: SO_DEBUG normalisation, SO_CONNECT_TIME for TCP/UDP, and a validity matrix
 * stating for each IP / IPv6 level option whether getsockopt and setsockopt succeed or which WSA error
 * they give, per socket type (TCP, UDP, raw), plus options queried on a non-socket file handle. */
#include "lift11.h"

#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME 0x700C
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif
#ifndef IPV6_ECN
#define IPV6_ECN 50
#endif
#ifndef IPV6_RECVERR
#define IPV6_RECVERR 75
#endif
#ifndef IPV6_USER_MTU
#define IPV6_USER_MTU 76
#endif

TEST(sockopt_so_debug_default_is_zero)
{
    SOCKET s;
    DWORD v = 0xdeadbeef;
    int len = sizeof(v);
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    l11_seterr(0xdeadbeef);
    L_EQ(U(getsockopt)(s, SOL_SOCKET, SO_DEBUG, (char *)&v, &len), 0);
    L_EQ(l11_err(), 0);
    L_EQ(len, sizeof(v));
    L_EQ(v, 0);
    U(closesocket)(s);
}

TEST(sockopt_so_debug_nonzero_reads_back_as_one)
{
    SOCKET s;
    DWORD v = 2;
    int len = sizeof(v);
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    l11_seterr(0xdeadbeef);
    L_EQ(U(setsockopt)(s, SOL_SOCKET, SO_DEBUG, (char *)&v, sizeof(v)), 0);
    L_EQ(l11_err(), 0);
    v = 0xdeadbeef;
    l11_seterr(0xdeadbeef);
    L_EQ(U(getsockopt)(s, SOL_SOCKET, SO_DEBUG, (char *)&v, &len), 0);
    L_EQ(l11_err(), 0);
    L_EQ(len, sizeof(v));
    L_EQ(v, 1);
    U(closesocket)(s);
}

static unsigned l11_connect_time(SOCKET s, int *rc, DWORD *lasterr, int *len_out)
{
    unsigned t = 0x1234;
    int len = sizeof(t);
    SetLastError(0xdeadbeef);
    *rc = U(getsockopt)(s, SOL_SOCKET, SO_CONNECT_TIME, (char *)&t, &len);
    *lasterr = GetLastError();
    *len_out = len;
    return t;
}

TEST(sockopt_connect_time_unconnected_tcp_is_all_ones)
{
    SOCKET s;
    int rc, len;
    DWORD e;
    unsigned t;
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    t = l11_connect_time(s, &rc, &e, &len);
    L_EQ(rc, 0);
    L_EQ(e, 0);
    L_EQ(len, sizeof(t));
    L_EQ(t, 0xffffffffu);
    U(closesocket)(s);
}

TEST(sockopt_connect_time_connected_tcp_counts_seconds)
{
    /* Both ends of an established connection report a small elapsed-seconds value (not all ones). */
    SOCKET c, s;
    int rc, len;
    DWORD e;
    unsigned t;
    UP();
    PAIR(&c, &s);
    t = l11_connect_time(c, &rc, &e, &len);
    L_EQ(rc, 0); L_EQ(e, 0); L_EQ(len, sizeof(t));
    CHECKF(t < 60, "client time %u", t);
    t = l11_connect_time(s, &rc, &e, &len);
    L_EQ(rc, 0); L_EQ(e, 0); L_EQ(len, sizeof(t));
    CHECKF(t < 60, "server time %u", t);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(sockopt_connect_time_udp_stays_all_ones_even_when_connected)
{
    SOCKET c, s;
    struct sockaddr_in a;
    int len = sizeof(a), rc, l2;
    DWORD e;
    unsigned t;
    UP();
    c = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(c != INVALID_SOCKET && s != INVALID_SOCKET);
    l11_loopback(&a);
    L_EQ(U(bind)(s, (struct sockaddr *)&a, sizeof(a)), 0);
    L_EQ(U(getsockname)(s, (struct sockaddr *)&a, &len), 0);
    L_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
    t = l11_connect_time(c, &rc, &e, &l2);
    L_EQ(rc, 0); L_EQ(e, 0); L_EQ(l2, sizeof(t));
    L_EQ(t, 0xffffffffu);
    t = l11_connect_time(s, &rc, &e, &l2);
    L_EQ(rc, 0); L_EQ(e, 0);
    L_EQ(t, 0xffffffffu);
    U(closesocket)(c); U(closesocket)(s);
}

/* ---- validity matrix --------------------------------------------------- */

enum { COL_TCP, COL_UDP, COL_RAW };
struct l11_optrow { int opt; short get[3], set[3]; };
#define OR(o, tg, ts, ug, us, rg, rs) { o, {tg, ug, rg}, {ts, us, rs} }
#define E_INV WSAEINVAL
#define E_NOP WSAENOPROTOOPT
#define E_NC  WSAENOTCONN

/* Options introduced after the classic set: an older stack answers WSAENOPROTOOPT instead. */
static int l11_recent_option(int opt)
{
    switch (opt) {
    case 47: case 50: case 51: case 60: case 70: case 71: case 73: case 75: case 76:
        return 1;
    default:
        return 0;
    }
}

static const struct l11_optrow l11_ip4_rows[] = {
    OR(-1,                     E_NOP,0, E_NOP,0, E_NOP,0),
    OR(IP_OPTIONS,             0,0, 0,0, 0,0),
    OR(IP_HDRINCL,             E_INV,0, E_INV,0, 0,0),
    OR(IP_TOS,                 0,0, 0,0, 0,0),
    OR(IP_TTL,                 0,0, 0,0, 0,0),
    OR(IP_MULTICAST_IF,        E_INV,0, 0,0, 0,0),
    OR(IP_MULTICAST_TTL,       E_INV,0, 0,0, 0,0),
    OR(IP_MULTICAST_LOOP,      E_INV,0, 0,0, 0,0),
    OR(IP_ADD_MEMBERSHIP,      E_NOP,0, E_NOP,0, E_NOP,0),
    OR(IP_DROP_MEMBERSHIP,     E_NOP,0, E_NOP,0, E_NOP,0),
    OR(IP_DONTFRAGMENT,        0,0, 0,0, 0,0),
    OR(IP_PKTINFO,             E_INV,0, 0,0, 0,0),
    OR(IP_RECVTTL,             E_INV,0, 0,0, 0,0),
    OR(IP_RECEIVE_BROADCAST,   E_INV,0, 0,0, 0,0),
    OR(IP_RECVIF,              E_INV,0, 0,0, 0,0),
    OR(IP_RECVDSTADDR,         E_INV,0, 0,0, 0,0),
    OR(IP_IFLIST,              0,0, 0,0, 0,0),
    OR(IP_UNICAST_IF,          0,0, 0,0, 0,0),
    OR(IP_RTHDR,               0,0, 0,0, 0,0),
    OR(IP_GET_IFLIST,          E_INV,0, E_INV,0, E_INV,0),
    OR(IP_RECVRTHDR,           E_INV,0, 0,0, 0,0),
    OR(IP_RECVTOS,             E_INV,0, 0,0, 0,0),
    OR(IP_ORIGINAL_ARRIVAL_IF, E_INV,0, 0,0, 0,0),
    OR(IP_ECN,                 E_INV,0, 0,0, 0,0),
    OR(IP_PKTINFO_EX,          E_INV,0, 0,0, 0,0),
    OR(IP_WFP_REDIRECT_RECORDS,E_INV,0, 0,0, 0,0),
    OR(IP_WFP_REDIRECT_CONTEXT,E_INV,0, 0,0, 0,0),
    OR(IP_MTU_DISCOVER,        0,E_INV, 0,E_INV, 0,E_INV),
    OR(IP_MTU,                 E_NC,0, E_NC,0, E_NC,0),
    OR(IP_RECVERR,             E_INV,0, 0,0, E_INV,0),
    OR(IP_USER_MTU,            0,0, 0,0, 0,0),
};

static const struct l11_optrow l11_ip6_rows[] = {
    OR(-1,                       E_NOP,0, E_NOP,0, E_NOP,0),
    OR(IPV6_HOPOPTS,             0,0, 0,0, 0,0),
    OR(IPV6_HDRINCL,             E_INV,0, E_INV,0, 0,0),
    OR(IPV6_UNICAST_HOPS,        0,0, 0,0, 0,0),
    OR(IPV6_MULTICAST_IF,        E_INV,0, 0,0, 0,0),
    OR(IPV6_MULTICAST_HOPS,      E_INV,0, 0,0, 0,0),
    OR(IPV6_MULTICAST_LOOP,      E_INV,0, 0,0, 0,0),
    OR(IPV6_ADD_MEMBERSHIP,      E_NOP,0, E_NOP,0, E_NOP,0),
    OR(IPV6_DROP_MEMBERSHIP,     E_NOP,0, E_NOP,0, E_NOP,0),
    OR(IPV6_DONTFRAG,            0,0, 0,0, 0,0),
    OR(IPV6_PKTINFO,             E_INV,0, 0,0, 0,0),
    OR(IPV6_HOPLIMIT,            E_INV,0, 0,0, 0,0),
    OR(IPV6_PROTECTION_LEVEL,    0,0, 0,0, 0,0),
    OR(IPV6_RECVIF,              E_INV,0, 0,0, 0,0),
    OR(IPV6_RECVDSTADDR,         E_INV,0, 0,0, 0,0),
    OR(IPV6_V6ONLY,              0,0, 0,0, 0,0),
    OR(IPV6_IFLIST,              0,0, 0,0, 0,0),
    OR(IPV6_UNICAST_IF,          0,0, 0,0, 0,0),
    OR(IPV6_RTHDR,               0,0, 0,0, 0,0),
    OR(IPV6_GET_IFLIST,          E_INV,0, E_INV,0, E_INV,0),
    OR(IPV6_RECVRTHDR,           E_INV,0, 0,0, 0,0),
    OR(IPV6_RECVTCLASS,          E_INV,0, 0,0, 0,0),
    OR(IP_ORIGINAL_ARRIVAL_IF,   E_INV,0, 0,0, 0,0),
    OR(IPV6_ECN,                 E_INV,0, 0,0, 0,0),
    OR(IPV6_PKTINFO_EX,          E_INV,0, 0,0, 0,0),
    OR(IPV6_WFP_REDIRECT_RECORDS,E_INV,0, 0,0, 0,0),
    OR(IPV6_WFP_REDIRECT_CONTEXT,E_INV,0, 0,0, 0,0),
    OR(IPV6_MTU_DISCOVER,        0,E_INV, 0,E_INV, 0,E_INV),
    OR(IPV6_MTU,                 E_NC,0, E_NC,0, E_NC,0),
    OR(IPV6_RECVERR,             E_INV,0, 0,0, E_INV,0),
    OR(IPV6_USER_MTU,            0,0, 0,0, 0,0),
};

/* Run one column of a matrix against a socket; count mismatches and report the first. */
static void l11_run_rows(SOCKET sock, int level, const struct l11_optrow *rows, unsigned n, int col)
{
    unsigned i, bad = 0;
    int first_opt = 0;
    char first[160] = "";
    for (i = 0; i < n; i++) {
        char val[256];
        int count = sizeof(val), rc, e, want_get = rows[i].get[col], want_set = rows[i].set[col];
        int recent = l11_recent_option(rows[i].opt);
        memset(val, 0, sizeof(val));
        l11_seterr(0);
        rc = U(getsockopt)(sock, level, rows[i].opt, val, &count);
        e = l11_err();
        if (rc == SOCKET_ERROR && e == WSAENOPROTOOPT && want_get != WSAENOPROTOOPT && recent) {
            t_note("option %d not recognised by this build", rows[i].opt);
            continue;
        }
        if ((want_get ? rc != SOCKET_ERROR : rc != 0) || e != want_get) {
            if (!bad) { first_opt = rows[i].opt; snprintf(first, sizeof(first), "getsockopt rc %d err %d want err %d", rc, e, want_get); }
            bad++;
            continue;
        }
        if (want_get) continue;
        l11_seterr(0);
        rc = U(setsockopt)(sock, level, rows[i].opt, val, count);
        e = l11_err();
        if ((want_set ? rc != SOCKET_ERROR : rc != 0) || e != want_set) {
            if (!bad) { first_opt = rows[i].opt; snprintf(first, sizeof(first), "setsockopt rc %d err %d want err %d", rc, e, want_set); }
            bad++;
        }
    }
    CHECKF(bad == 0, "%u options differ; first option %d: %s", bad, first_opt, first);
}

static void l11_matrix(int af, int type, int proto, int level, const struct l11_optrow *rows, unsigned n, int col)
{
    SOCKET s;
    UP();
    s = U(socket)(af, type, proto);
    if (s == INVALID_SOCKET) {
        if (type == SOCK_RAW && l11_err() == WSAEACCES) { t_skip("raw sockets not permitted"); return; }
        if (af == AF_INET6 && l11_err() == WSAEAFNOSUPPORT) { t_skip("IPv6 unavailable"); return; }
        CHECKF(0, "socket failed, error %d", l11_err());
        return;
    }
    l11_run_rows(s, level, rows, n, col);
    U(closesocket)(s);
}

#define NROWS(a) (sizeof(a) / sizeof((a)[0]))
TEST(sockopt_matrix_ipv4_tcp) { l11_matrix(AF_INET, SOCK_STREAM, IPPROTO_TCP, IPPROTO_IP, l11_ip4_rows, NROWS(l11_ip4_rows), COL_TCP); }
TEST(sockopt_matrix_ipv4_udp) { l11_matrix(AF_INET, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IP, l11_ip4_rows, NROWS(l11_ip4_rows), COL_UDP); }
TEST(sockopt_matrix_ipv4_raw) { l11_matrix(AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_IP, l11_ip4_rows, NROWS(l11_ip4_rows), COL_RAW); }
TEST(sockopt_matrix_ipv6_tcp) { l11_matrix(AF_INET6, SOCK_STREAM, IPPROTO_TCP, IPPROTO_IPV6, l11_ip6_rows, NROWS(l11_ip6_rows), COL_TCP); }
TEST(sockopt_matrix_ipv6_udp) { l11_matrix(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6, l11_ip6_rows, NROWS(l11_ip6_rows), COL_UDP); }
TEST(sockopt_matrix_ipv6_raw) { l11_matrix(AF_INET6, SOCK_RAW, IPPROTO_RAW, IPPROTO_IPV6, l11_ip6_rows, NROWS(l11_ip6_rows), COL_RAW); }

TEST(sockopt_on_plain_file_handle)
{
    /* A handle that is not a socket: generic options fail with WSAENOTSOCK, but SO_OPENTYPE is a
     * per-thread setting and works without a socket. */
    static const struct l11_optrow rows[] = {
        OR(-1,           WSAENOTSOCK,0, 0,0, 0,0),
        OR(SO_TYPE,      WSAENOTSOCK,0, 0,0, 0,0),
        OR(SO_OPENTYPE,  0,0, 0,0, 0,0),
    };
    char path[MAX_PATH];
    HANDLE f;
    UP();
    t_tmpfile(path, sizeof(path), "sockopt_file.dat");
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    l11_run_rows((SOCKET)f, SOL_SOCKET, rows, NROWS(rows), COL_TCP);
    CloseHandle(f);
    DeleteFileA(path);
}
