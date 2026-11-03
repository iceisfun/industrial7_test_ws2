/* lift_04: per-option length protocol of setsockopt/getsockopt.
 * For each option in a table the test measures: a 64-bit write, a negative length, a zero length,
 * a 4-byte write of 0x100 (large value), and 1/2/4-byte writes and reads with the value and returned
 * size each width yields. The table columns say whether short lengths are accepted, which sizes/values
 * come back, and whether a value above 1 is accepted. */
#include "l4.h"

struct optrow {
    const char *name;
    int af, type, level, optname;
    int accepts_short_len;
    unsigned sizes[3];      /* returned size when read with a 1, 2, 4 byte buffer */
    DWORD values[3];        /* expected value for those reads (0 = the plain value 1) */
    int accepts_large_value;
    int bool_value;
};

static const struct optrow rows[] = {
    { "so_broadcast",    AF_INET, SOCK_DGRAM,  SOL_SOCKET, SO_BROADCAST,    1, {1, 1, 4}, {0, 0xdead0001, 0}, 1, 1 },
    { "so_dontlinger",   AF_INET, SOCK_STREAM, SOL_SOCKET, SO_DONTLINGER,   1, {1, 1, 4}, {0, 0xdead0001, 0}, 1, 1 },
    { "so_linger",       AF_INET, SOCK_STREAM, SOL_SOCKET, SO_LINGER,       0, {1, 2, 4}, {0xdeadbe00, 0xdead0000}, 1, 0 },
    { "so_oobinline",    AF_INET, SOCK_STREAM, SOL_SOCKET, SO_OOBINLINE,    1, {1, 1, 4}, {0, 0xdead0001, 0}, 1, 1 },
    { "so_rcvbuf",       AF_INET, SOCK_STREAM, SOL_SOCKET, SO_RCVBUF,       0, {1, 2, 4}, {0xdeadbe00, 0xdead0000}, 1, 0 },
    { "so_keepalive",    AF_INET, SOCK_STREAM, SOL_SOCKET, SO_KEEPALIVE,    1, {1, 1, 1}, {0}, 1, 0 },
    { "so_dontroute",    AF_INET, SOCK_STREAM, SOL_SOCKET, SO_DONTROUTE,    1, {1, 1, 1}, {0}, 1, 0 },
    { "so_rcvtimeo",     AF_INET, SOCK_STREAM, SOL_SOCKET, SO_RCVTIMEO,     0, {1, 2, 4}, {0}, 1, 0 },
    { "so_reuseaddr",    AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,    1, {1, 1, 4}, {0, 0xdead0001, 0}, 1, 1 },
    { "so_exclusiveaddruse", AF_INET, SOCK_STREAM, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1, {1, 1, 4}, {0, 0xdead0001, 0}, 1, 1 },
    { "so_sndbuf",       AF_INET, SOCK_STREAM, SOL_SOCKET, SO_SNDBUF,       0, {1, 2, 4}, {0xdeadbe00, 0xdead0000}, 1, 0 },
    { "so_sndtimeo",     AF_INET, SOCK_STREAM, SOL_SOCKET, SO_SNDTIMEO,     0, {1, 2, 4}, {0}, 1, 0 },
    { "so_opentype",     AF_INET, SOCK_STREAM, SOL_SOCKET, SO_OPENTYPE,     0, {1, 2, 4}, {0}, 1, 0 },
    { "tcp_nodelay",     AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY,    1, {1, 1, 1}, {0}, 1, 0 },
    { "tcp_keepalive",   AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_KEEPALIVE,  0, {0, 0, 4}, {0}, 1, 0 },
    { "tcp_keepcnt",     AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_KEEPCNT,    0, {0, 0, 4}, {0}, 0, 0 },
    { "tcp_keepintvl",   AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_KEEPINTVL,  0, {0, 0, 4}, {0}, 1, 0 },
    { "ip_multicast_loop", AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_MULTICAST_LOOP, 1, {1, 1, 4}, {0}, 1, 1 },
    { "ip_multicast_ttl", AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_MULTICAST_TTL, 1, {1, 1, 4}, {0}, 0, 0 },
    { "ip_pktinfo",      AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_PKTINFO,       0, {0, 0, 4}, {0}, 1, 1 },
    { "ip_recvtos",      AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_RECVTOS,       0, {0, 0, 4}, {0}, 1, 1 },
    { "ip_recvttl",      AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_RECVTTL,       0, {0, 0, 4}, {0}, 1, 1 },
    { "ip_tos",          AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_TOS,           1, {1, 1, 4}, {0}, 0, 0 },
    { "ip_ttl",          AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_TTL,           1, {1, 1, 4}, {0}, 0, 0 },
    { "ipv6_dontfrag",   AF_INET6, SOCK_STREAM, IPPROTO_IPV6, IPV6_DONTFRAG, 1, {1, 1, 4}, {0}, 1, 1 },
    { "ipv6_hoplimit",   AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_HOPLIMIT, 0, {0, 0, 4}, {0}, 1, 1 },
    { "ipv6_multicast_hops", AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 1, {1, 1, 4}, {0}, 0, 0 },
    { "ipv6_multicast_loop", AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1, {1, 1, 4}, {0}, 1, 1 },
    { "ipv6_pktinfo",    AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_PKTINFO,  0, {0, 0, 4}, {0}, 1, 1 },
    { "ipv6_recvtclass", AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_RECVTCLASS, 0, {0, 0, 4}, {0}, 1, 1 },
    { "ipv6_unicast_hops", AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 1, {1, 1, 4}, {0}, 0, 0 },
    { "ipv6_v6only",     AF_INET6, SOCK_DGRAM, IPPROTO_IPV6, IPV6_V6ONLY,   1, {1, 1, 1}, {0}, 1, 0 },
};

#define CK(c, ...) t_check(!!(c), __FILE__, __LINE__, #c, __VA_ARGS__)

static void run_row(int ri)
{
    const struct optrow *r = &rows[ri];
    SOCKET s;
    DWORD save, value, expected_value;
    UINT64 v64;
    int size, err, expected_err, expected_size, j;
    int lasterr, expected_last;

    if (!ws_up()) return;
    s = sk(r->af, r->type, 0);
    if (s == INVALID_SOCKET) { t_skip("%s: socket family unavailable (%d)", r->name, lerr()); ws_down(); return; }

    size = sizeof save;
    err = gso(s, r->level, r->optname, &save, &size);
    if (err) { CK(0, "%s: initial getsockopt failed, wsa error %d", r->name, lerr()); cl(s); ws_down(); return; }

    /* A 64-bit write is accepted; the read-back size is the option's natural size. */
    v64 = 0xffffffff00000001ull;
    lset(0);
    err = sso(s, r->level, r->optname, &v64, sizeof v64);
    CK(err == 0, "%s: 8-byte set -> %d wsa %d", r->name, err, lerr());
    CK(lerr() == 0, "%s: wsa error after 8-byte set %d", r->name, lerr());
    size = sizeof v64;
    err = gso(s, r->level, r->optname, &v64, &size);
    CK(err == 0, "%s: 8-byte get -> %d", r->name, err);
    CK(size == (int)r->sizes[2], "%s: size %d want %u", r->name, size, r->sizes[2]);

    /* Negative length: byte-sized options and every non-SOL_SOCKET option report WSAENOBUFS;
     * the remaining SOL_SOCKET options take the value as-is. */
    if (r->sizes[2] == 1 || r->level != SOL_SOCKET) { expected_err = -1; expected_last = WSAENOBUFS; }
    else { expected_err = 0; expected_last = 0; }
    value = 1;
    lset(0);
    err = sso(s, r->level, r->optname, &value, -1);
    lasterr = lerr();
    CK(err == expected_err, "%s: set optlen -1 -> %d want %d", r->name, err, expected_err);
    CK(lasterr == expected_last, "%s: set optlen -1 wsa %d want %d", r->name, lasterr, expected_last);

    /* Negative *optlen on get: only SO_OPENTYPE (a per-thread, socket-less option) is exempt. */
    size = -1; value = 0xdeadbeef;
    lset(0);
    err = gso(s, r->level, r->optname, &value, &size);
    if (r->optname == SO_OPENTYPE) {
        CK(err == 0 && lerr() == 0, "%s: get optlen -1 -> %d wsa %d", r->name, err, lerr());
        CK(size == 4, "%s: opentype size %d", r->name, size);
    } else {
        CK(err == -1, "%s: get optlen -1 -> %d", r->name, err);
        CK(lerr() == WSAEFAULT, "%s: get optlen -1 wsa %d", r->name, lerr());
        CK(size == -1, "%s: size changed to %d", r->name, size);
    }

    /* Zero length write: only boolean SOL_SOCKET options take it (nothing is read from the buffer). */
    if (r->level == SOL_SOCKET && r->bool_value) { expected_err = 0; expected_last = 0; }
    else { expected_err = -1; expected_last = WSAEFAULT; }
    value = 1;
    SetLastError(0xdeadbeef);
    err = sso(s, r->level, r->optname, &value, 0);
    CK(err == expected_err, "%s: set optlen 0 -> %d want %d", r->name, err, expected_err);
    CK(lerr() == expected_last, "%s: set optlen 0 wsa %d want %d", r->name, lerr(), expected_last);

    size = 0;
    err = gso(s, r->level, r->optname, &value, &size);
    CK(err == -1, "%s: get *optlen 0 -> %d", r->name, err);
    CK(lerr() == WSAEFAULT, "%s: get *optlen 0 wsa %d", r->name, lerr());

    /* 4-byte write of 0x100: options that take only a byte or a small range reject it with WSAEINVAL. */
    expected_size = r->sizes[2];
    if (expected_size == 1) expected_value = 0xdeadbe00;
    else expected_value = r->bool_value ? 0x1 : 0x100;
    if (r->accepts_large_value) { expected_err = 0; expected_last = 0; }
    else { expected_err = -1; expected_last = WSAEINVAL; }
    value = 0x100;
    SetLastError(0xdeadbeef);
    err = sso(s, r->level, r->optname, &value, 4);
    CK(err == expected_err, "%s: set 0x100 -> %d want %d", r->name, err, expected_err);
    CK(lerr() == expected_last, "%s: set 0x100 wsa %d want %d", r->name, lerr(), expected_last);
    if (r->accepts_large_value) {
        value = 0xdeadbeef; size = 4;
        SetLastError(0xdeadbeef);
        err = gso(s, r->level, r->optname, &value, &size);
        CK(err == 0 && lerr() == 0, "%s: get after 0x100 -> %d wsa %d", r->name, err, lerr());
        CK(value == expected_value, "%s: value %#lx want %#lx", r->name, value, expected_value);
        CK(size == expected_size, "%s: size %d want %d", r->name, size, expected_size);
    }

    /* Widths 1, 2, 4: write with that length, read with that length. */
    for (j = 0; j < 3; j++) {
        size = 1 << j;
        value = 1;
        expected_value = r->values[j] ? r->values[j] : 0xdeadbeef;
        if (r->accepts_short_len || size == 4) {
            expected_err = 0; expected_last = 0;
            expected_size = r->sizes[j];
            if (!r->values[j]) memcpy(&expected_value, &value, expected_size);
        } else {
            expected_err = -1; expected_last = WSAEFAULT;
            expected_size = r->sizes[j];
        }
        SetLastError(0xdeadbeef);
        err = sso(s, r->level, r->optname, &value, size);
        CK(err == expected_err, "%s len %d: set -> %d want %d", r->name, 1 << j, err, expected_err);
        CK(lerr() == expected_last, "%s len %d: set wsa %d want %d", r->name, 1 << j, lerr(), expected_last);

        value = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        err = gso(s, r->level, r->optname, &value, &size);
        CK(err == expected_err, "%s len %d: get -> %d want %d", r->name, 1 << j, err, expected_err);
        CK(lerr() == expected_last, "%s len %d: get wsa %d want %d", r->name, 1 << j, lerr(), expected_last);
        CK(value == expected_value, "%s len %d: value %#lx want %#lx", r->name, 1 << j, value, expected_value);
        CK(size == expected_size, "%s len %d: size %d want %d", r->name, 1 << j, size, expected_size);
    }

    err = sso(s, r->level, r->optname, &save, sizeof save);
    CK(err == 0, "%s: restore -> %d", r->name, err);
    cl(s);
    ws_down();
}

#define ROW(n, i) TEST(sockopt_len_##n) { run_row(i); }
ROW(so_broadcast, 0)  ROW(so_dontlinger, 1)  ROW(so_linger, 2)  ROW(so_oobinline, 3)
ROW(so_rcvbuf, 4)  ROW(so_keepalive, 5)  ROW(so_dontroute, 6)  ROW(so_rcvtimeo, 7)
ROW(so_reuseaddr, 8)  ROW(so_exclusiveaddruse, 9)  ROW(so_sndbuf, 10)  ROW(so_sndtimeo, 11)
ROW(so_opentype, 12)  ROW(tcp_nodelay, 13)  ROW(tcp_keepalive, 14)  ROW(tcp_keepcnt, 15)
ROW(tcp_keepintvl, 16)  ROW(ip_multicast_loop, 17)  ROW(ip_multicast_ttl, 18)  ROW(ip_pktinfo, 19)
ROW(ip_recvtos, 20)  ROW(ip_recvttl, 21)  ROW(ip_tos, 22)  ROW(ip_ttl, 23)
ROW(ipv6_dontfrag, 24)  ROW(ipv6_hoplimit, 25)  ROW(ipv6_multicast_hops, 26)  ROW(ipv6_multicast_loop, 27)
ROW(ipv6_pktinfo, 28)  ROW(ipv6_recvtclass, 29)  ROW(ipv6_unicast_hops, 30)  ROW(ipv6_v6only, 31)

/* Table sanity: the row names above must stay in step with the ROW() list. */
TEST(sockopt_len_table_size) { EQ(NELEM(rows), 32); }
