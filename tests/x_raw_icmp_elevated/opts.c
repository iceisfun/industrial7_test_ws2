/* x_raw_icmp_elevated / opts: socket options of raw ICMP sockets.
 *
 * Defaults, ranges and error codes observed on Windows 10 22H2 for the options that matter to raw senders:
 * IP_TTL (default 128, 0..255, -1 means 255, 256 is invalid), IP_TOS, IP_DONTFRAGMENT, IP_OPTIONS (0..40 bytes),
 * IP_HDRINCL (set needs elevation: a standard user gets WSAEACCES even when clearing it, the check runs before
 * the length check), IPV6_UNICAST_HOPS/IPV6_HDRINCL on IPv6 raw sockets and the absence of IPV6_CHECKSUM
 * (WSAENOPROTOOPT) on raw ICMPv6 sockets. Both tokens can open ICMP/ICMPv6 raw sockets, so most rows run in
 * both modes; HDRINCL rows branch on elevation. */
#include "rawh.h"

static int gi(SOCKET s, int lvl, int opt, int *v, int *len) {
    int n = sizeof *v; *v = 0x5a5a5a5a; rw_seterr(0);
    int r = U(getsockopt)(s, lvl, opt, (char *)v, &n); if (len) *len = n; return r;
}
static int si(SOCKET s, int lvl, int opt, int v) { rw_seterr(0); return U(setsockopt)(s, lvl, opt, (char *)&v, sizeof v); }
#define OPEN4() SOCKET s; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw ICMP socket refused (%d)", rw_err()); return; }
#define OPEN6() SOCKET s; RW_UP(); s = rw_raw(AF_INET6, IPPROTO_ICMPV6); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 socket refused (%d)", rw_err()); return; }

/* get of an int option: result, value and returned length */
static void want_get(SOCKET s, int lvl, int opt, int val, const char *tag) {
    int v, n, r = gi(s, lvl, opt, &v, &n);
    t_check(r == 0, __FILE__, __LINE__, tag, "getsockopt failed %d", rw_err());
    t_check(v == val, __FILE__, __LINE__, tag, "got %d want %d", v, val);
    t_check(n == 4, __FILE__, __LINE__, tag, "length %d", n);
}
static void want_set_ok(SOCKET s, int lvl, int opt, int val, int readback, const char *tag) {
    int r = si(s, lvl, opt, val);
    t_check(r == 0, __FILE__, __LINE__, tag, "setsockopt(%d) failed %d", val, rw_err());
    want_get(s, lvl, opt, readback, tag);
}
static void want_set_err(SOCKET s, int lvl, int opt, int val, int err, const char *tag) {
    int r = si(s, lvl, opt, val), e = rw_err();
    t_check(r == -1 && e == err, __FILE__, __LINE__, tag, "setsockopt(%d) -> %d err %d, want err %d", val, r, e, err);
}

/* ---- socket level ---- */
TEST(rawopt_so_type_is_raw) { OPEN4(); want_get(s, SOL_SOCKET, SO_TYPE, SOCK_RAW, "SO_TYPE"); rw_close(s); }
TEST(rawopt_so_max_msg_size) { OPEN4(); want_get(s, SOL_SOCKET, SO_MAX_MSG_SIZE, 65515, "SO_MAX_MSG_SIZE"); rw_close(s); }
TEST(rawopt_so_max_msg_size_v6) { OPEN6(); want_get(s, SOL_SOCKET, SO_MAX_MSG_SIZE, 65535, "SO_MAX_MSG_SIZE v6"); rw_close(s); }
TEST(rawopt_so_rcvbuf_default) { OPEN4(); want_get(s, SOL_SOCKET, SO_RCVBUF, 65536, "SO_RCVBUF"); rw_close(s); }
TEST(rawopt_so_sndbuf_default) { OPEN4(); want_get(s, SOL_SOCKET, SO_SNDBUF, 65536, "SO_SNDBUF"); rw_close(s); }
TEST(rawopt_so_broadcast_default_off) { OPEN4(); want_get(s, SOL_SOCKET, SO_BROADCAST, 0, "SO_BROADCAST"); want_set_ok(s, SOL_SOCKET, SO_BROADCAST, 1, 1, "SO_BROADCAST set"); rw_close(s); }
TEST(rawopt_so_acceptconn_unsupported) {
    OPEN4(); int v, r = gi(s, SOL_SOCKET, SO_ACCEPTCONN, &v, NULL); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOPROTOOPT); rw_close(s);
}
TEST(rawopt_protocol_info_small_buffer) {
    OPEN4(); int v, n; (void)n; int r = gi(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &v, NULL); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT); rw_close(s);
}
TEST(rawopt_so_rcvbuf_roundtrip_small) {
    OPEN4(); int v, r = si(s, SOL_SOCKET, SO_RCVBUF, 4096); RW_EQ(r, 0);
    r = gi(s, SOL_SOCKET, SO_RCVBUF, &v, NULL); RW_EQ(r, 0); t_note("RCVBUF after set 4096 reads %d", v);
    rw_close(s);
}

/* ---- IPv4 level, both tokens ---- */
TEST(rawopt_ip_ttl_default) { OPEN4(); want_get(s, IPPROTO_IP, IP_TTL, 128, "IP_TTL default"); rw_close(s); }
TEST(rawopt_ip_ttl_values) {
    static const int ok[] = {0, 1, 2, 64, 127, 128, 254, 255}; size_t i;
    OPEN4();
    for (i = 0; i < sizeof ok / sizeof ok[0]; i++) want_set_ok(s, IPPROTO_IP, IP_TTL, ok[i], ok[i], "IP_TTL value");
    rw_close(s);
}
TEST(rawopt_ip_ttl_out_of_range) {
    static const int bad[] = {256, 257, 1000, 65535, 0x10000}; size_t i;
    OPEN4(); want_set_ok(s, IPPROTO_IP, IP_TTL, 33, 33, "IP_TTL set");
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) { want_set_err(s, IPPROTO_IP, IP_TTL, bad[i], WSAEINVAL, "IP_TTL range"); want_get(s, IPPROTO_IP, IP_TTL, 33, "IP_TTL unchanged"); }
    rw_close(s);
}
TEST(rawopt_ip_ttl_minus_one_is_255) { OPEN4(); want_set_ok(s, IPPROTO_IP, IP_TTL, -1, 255, "IP_TTL -1"); rw_close(s); }
TEST(rawopt_ip_ttl_short_option_lengths) {
    OPEN4(); char b = 9; short h = 11; int r;
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_TTL, &b, 1); RW_EQ(r, 0);
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_TTL, (char *)&h, 2); RW_EQ(r, 0);
    rw_close(s);
}
TEST(rawopt_ip_tos_roundtrip) {
    static const int v[] = {0, 8, 0x10, 0xb8, 0xff}; size_t i; OPEN4();
    want_get(s, IPPROTO_IP, IP_TOS, 0, "IP_TOS default");
    for (i = 0; i < sizeof v / sizeof v[0]; i++) want_set_ok(s, IPPROTO_IP, IP_TOS, v[i], v[i], "IP_TOS");
    rw_close(s);
}
TEST(rawopt_ip_dontfragment_roundtrip) {
    OPEN4(); want_get(s, IPPROTO_IP, IP_DONTFRAGMENT, 0, "IP_DONTFRAGMENT default");
    want_set_ok(s, IPPROTO_IP, IP_DONTFRAGMENT, 1, 1, "DF on"); want_set_ok(s, IPPROTO_IP, IP_DONTFRAGMENT, 0, 0, "DF off"); rw_close(s);
}
TEST(rawopt_ip_multicast_defaults) {
    OPEN4(); want_get(s, IPPROTO_IP, IP_MULTICAST_TTL, 1, "IP_MULTICAST_TTL"); want_get(s, IPPROTO_IP, IP_MULTICAST_LOOP, 1, "IP_MULTICAST_LOOP"); rw_close(s);
}
TEST(rawopt_ip_recv_flags_roundtrip) {
    static const int o[] = {IP_PKTINFO, IP_RECVTTL, IP_RECVTOS}; size_t i; OPEN4();
    for (i = 0; i < 3; i++) { want_get(s, IPPROTO_IP, o[i], 0, "recv flag default"); want_set_ok(s, IPPROTO_IP, o[i], 1, 1, "recv flag on"); want_set_ok(s, IPPROTO_IP, o[i], 0, 0, "recv flag off"); }
    rw_close(s);
}

/* ---- IP_OPTIONS ---- */
TEST(rawopt_ip_options_default_empty) {
    OPEN4(); unsigned char b[44]; int n = sizeof b, r; memset(b, 0xee, sizeof b);
    rw_seterr(0); r = U(getsockopt)(s, IPPROTO_IP, IP_OPTIONS, (char *)b, &n); RW_EQ(r, 0); RW_EQ(n, 0); rw_close(s);
}
TEST(rawopt_ip_options_roundtrip) {
    OPEN4(); unsigned char o[4] = {1, 1, 1, 0}, b[44]; int n = sizeof b, r; memset(b, 0xee, sizeof b);
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_OPTIONS, (char *)o, 4); RW_EQ(r, 0);
    r = U(getsockopt)(s, IPPROTO_IP, IP_OPTIONS, (char *)b, &n); RW_EQ(r, 0); RW_EQ(n, 4); CHECK(!memcmp(b, o, 4));
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_OPTIONS, (char *)o, 0); RW_EQ(r, 0);
    n = sizeof b; r = U(getsockopt)(s, IPPROTO_IP, IP_OPTIONS, (char *)b, &n); RW_EQ(r, 0); RW_EQ(n, 0);
    rw_close(s);
}
TEST(rawopt_ip_options_length_limits) {
    static const struct { int len, err; } t[] = {{1, WSAEINVAL}, {41, WSAEINVAL}, {44, WSAEINVAL}, {100, WSAEINVAL}, {40, 0}, {8, 0}, {4, 0}, {0, 0}};
    unsigned char o[128]; size_t i; OPEN4(); memset(o, 0, sizeof o);
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        int r; rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_OPTIONS, (char *)o, t[i].len);
        t_check(t[i].err ? (r == -1 && rw_err() == t[i].err) : r == 0, __FILE__, __LINE__, "IP_OPTIONS length", "len %d r=%d err=%d", t[i].len, r, rw_err());
    }
    rw_close(s);
}

/* ---- IP_HDRINCL: needs elevation to set ---- */
TEST(rawopt_ip_hdrincl_default_off) { OPEN4(); want_get(s, IPPROTO_IP, IP_HDRINCL, 0, "IP_HDRINCL default"); rw_close(s); }
TEST(rawopt_ip_hdrincl_set_elevated) {
    RW_NEED_ADM(); { OPEN4();
    want_set_ok(s, IPPROTO_IP, IP_HDRINCL, 1, 1, "on"); want_set_ok(s, IPPROTO_IP, IP_HDRINCL, 0, 0, "off");
    want_set_ok(s, IPPROTO_IP, IP_HDRINCL, 7, 1, "any nonzero reads back as 1"); want_set_ok(s, IPPROTO_IP, IP_HDRINCL, -1, 1, "-1 reads back as 1");
    rw_close(s); }
}
TEST(rawopt_ip_hdrincl_set_refused_standard) {
    RW_NEED_STD(); { OPEN4(); int v;
    want_set_err(s, IPPROTO_IP, IP_HDRINCL, 1, WSAEACCES, "set on"); want_set_err(s, IPPROTO_IP, IP_HDRINCL, 0, WSAEACCES, "set off refused too");
    RW_EQ(gi(s, IPPROTO_IP, IP_HDRINCL, &v, NULL), 0); RW_EQ(v, 0);
    rw_close(s); }
}
TEST(rawopt_ip_hdrincl_bad_length_elevated) {
    RW_NEED_ADM(); { OPEN4(); char one = 1; int n = 0, r, v;
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_HDRINCL, &one, 1); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_HDRINCL, &one, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_seterr(0); r = U(getsockopt)(s, IPPROTO_IP, IP_HDRINCL, (char *)&v, &n); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(s); }
}
TEST(rawopt_ip_hdrincl_bad_length_standard) {
    RW_NEED_STD(); { OPEN4(); char one = 1; int r;
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_HDRINCL, &one, 1); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEACCES);
    rw_seterr(0); r = U(setsockopt)(s, IPPROTO_IP, IP_HDRINCL, &one, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEACCES);
    rw_close(s); }
}

/* ---- options of another level are not defined on a raw ICMP socket ---- */
TEST(rawopt_ipv6_checksum_unsupported_v4_socket) {
    OPEN4(); int v, r = gi(s, IPPROTO_IPV6, IPV6_CHECKSUM, &v, NULL); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOPROTOOPT);
    RW_EQ(si(s, IPPROTO_IPV6, IPV6_CHECKSUM, 2), -1); RW_EQ(rw_err(), WSAENOPROTOOPT); rw_close(s);
}
TEST(rawopt_ipv6_aliases_on_v4_socket) {
    /* the IPv6-level hop-limit option number is shared with IP_TTL on an IPv4 socket */
    OPEN4(); int v, r = si(s, IP_TTL == 4 ? IPPROTO_IP : IPPROTO_IP, IP_TTL, 77); RW_EQ(r, 0);
    r = gi(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, NULL); t_note("IPV6_UNICAST_HOPS on v4 raw: r=%d v=%d", r, v);
    rw_close(s);
}

/* ---- IPv6 raw ICMPv6 socket ---- */
TEST(rawopt6_hops_default) { OPEN6(); want_get(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 128, "hops default"); rw_close(s); }
TEST(rawopt6_hops_values) {
    static const int ok[] = {0, 1, 5, 64, 255}; size_t i; OPEN6();
    for (i = 0; i < sizeof ok / sizeof ok[0]; i++) want_set_ok(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ok[i], ok[i], "hops");
    want_set_ok(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, -1, 255, "hops -1");
    want_set_ok(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 9, 9, "hops 9");
    want_set_err(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 256, WSAEINVAL, "hops 256"); want_get(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 9, "hops unchanged");
    rw_close(s);
}
TEST(rawopt6_checksum_option_unsupported) {
    static const int vals[] = {-1, 0, 2, 3}; size_t i; OPEN6(); int v;
    RW_EQ(gi(s, IPPROTO_IPV6, IPV6_CHECKSUM, &v, NULL), -1); RW_EQ(rw_err(), WSAENOPROTOOPT);
    for (i = 0; i < 4; i++) { RW_EQ(si(s, IPPROTO_IPV6, IPV6_CHECKSUM, vals[i]), -1); RW_EQ(rw_err(), WSAENOPROTOOPT); }
    rw_close(s);
}
TEST(rawopt6_hdrincl_default_off) { OPEN6(); want_get(s, IPPROTO_IPV6, IPV6_HDRINCL, 0, "IPV6_HDRINCL default"); rw_close(s); }
TEST(rawopt6_hdrincl_set_elevated) {
    RW_NEED_ADM(); { OPEN6(); want_set_ok(s, IPPROTO_IPV6, IPV6_HDRINCL, 1, 1, "on"); want_set_ok(s, IPPROTO_IPV6, IPV6_HDRINCL, 0, 0, "off"); rw_close(s); }
}
TEST(rawopt6_hdrincl_set_refused_standard) {
    RW_NEED_STD(); { OPEN6(); want_set_err(s, IPPROTO_IPV6, IPV6_HDRINCL, 1, WSAEACCES, "on"); want_set_err(s, IPPROTO_IPV6, IPV6_HDRINCL, 0, WSAEACCES, "off"); want_get(s, IPPROTO_IPV6, IPV6_HDRINCL, 0, "unchanged"); rw_close(s); }
}
TEST(rawopt6_v6only_length_is_one_byte) {
    OPEN6(); char b[8] = {0x55}; int n = sizeof b; int r = U(getsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, b, &n);
    t_note("IPV6_V6ONLY on raw6: r=%d len=%d val=%d", r, n, b[0]); rw_close(s);
}
