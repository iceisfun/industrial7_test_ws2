/* x_raw_icmp_elevated / create: SOCK_RAW creation and the privilege boundary.
 *
 * A raw socket for an arbitrary IP protocol needs an elevated token; the refusal is WSAEACCES (10013).
 * Observed on Windows 10 22H2: a standard (non-elevated, non-admin) user may still open raw sockets for
 * exactly two protocols, IPPROTO_ICMP (1) and IPPROTO_ICMPV6 (58), in BOTH address families; every other
 * protocol in 0..255 is refused with WSAEACCES. Protocol numbers outside 0..255 never get that far and fail
 * with WSAEPROTONOSUPPORT (10043) for everybody; a non-raw socket type asked for protocol IPPROTO_RAW fails
 * with the same errors in both modes (type known but protocol not: 10043; type unknown: 10044).
 * Every row below therefore carries an expectation for the elevated and one for the standard token. */
#include "rawh.h"

struct crow { int af, proto, adm, std; };
static const struct crow rows[] = {
    /* IPv4 */
    {AF_INET, 0, 0, WSAEACCES}, {AF_INET, 1, 0, 0}, {AF_INET, 2, 0, WSAEACCES}, {AF_INET, 3, 0, WSAEACCES},
    {AF_INET, 4, 0, WSAEACCES}, {AF_INET, 6, 0, WSAEACCES}, {AF_INET, 17, 0, WSAEACCES}, {AF_INET, 41, 0, WSAEACCES},
    {AF_INET, 47, 0, WSAEACCES}, {AF_INET, 50, 0, WSAEACCES}, {AF_INET, 58, 0, 0}, {AF_INET, 59, 0, WSAEACCES},
    {AF_INET, 132, 0, WSAEACCES}, {AF_INET, 253, 0, WSAEACCES}, {AF_INET, 254, 0, WSAEACCES}, {AF_INET, 255, 0, WSAEACCES},
    {AF_INET, 256, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT}, {AF_INET, 257, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT},
    {AF_INET, 65536, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT}, {AF_INET, -1, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT},
    /* IPv6 */
    {AF_INET6, 0, 0, WSAEACCES}, {AF_INET6, 1, 0, 0}, {AF_INET6, 2, 0, WSAEACCES}, {AF_INET6, 6, 0, WSAEACCES},
    {AF_INET6, 17, 0, WSAEACCES}, {AF_INET6, 41, 0, WSAEACCES}, {AF_INET6, 58, 0, 0}, {AF_INET6, 59, 0, WSAEACCES},
    {AF_INET6, 253, 0, WSAEACCES}, {AF_INET6, 254, 0, WSAEACCES}, {AF_INET6, 255, 0, WSAEACCES},
    {AF_INET6, 256, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT}, {AF_INET6, -1, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT},
};

/* every row: socket() and WSASocketW (plain and overlapped) agree, and a created socket reports SO_TYPE raw */
TEST(rawcreate_protocol_matrix) {
    int adm; size_t i;
    RW_UP(); adm = rw_elevated();
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        const struct crow *r = &rows[i]; int want = adm ? r->adm : r->std;
        int fl[3] = {-1, 0, WSA_FLAG_OVERLAPPED}, k;
        for (k = 0; k < 3; k++) {
            SOCKET s; int got;
            rw_seterr(0);
            s = fl[k] < 0 ? U(socket)(r->af, SOCK_RAW, r->proto) : U(WSASocketW)(r->af, SOCK_RAW, r->proto, NULL, 0, fl[k]);
            got = s == INVALID_SOCKET ? rw_err() : 0;
            t_check(got == want, __FILE__, __LINE__, "raw create result", "af=%d proto=%d via=%d got %d want %d", r->af, r->proto, k, got, want);
            if (s != INVALID_SOCKET) {
                int ty = 0, n = sizeof ty;
                t_check(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &n) == 0 && ty == SOCK_RAW, __FILE__, __LINE__, "SO_TYPE raw", "af=%d proto=%d", r->af, r->proto);
                rw_close(s);
            }
        }
    }
}
/* one named test per family/protocol keeps the privilege boundary visible in the run list */
static void one(int af, int proto, int adm_err, int std_err) {
    SOCKET s; int want, got;
    RW_UP();
    want = rw_elevated() ? adm_err : std_err;
    rw_seterr(0); s = rw_raw(af, proto);
    got = s == INVALID_SOCKET ? rw_err() : 0;
    RW_EQ(got, want);
    if (s != INVALID_SOCKET) { RW_EQ(U(closesocket)(s), 0); }
}
TEST(rawcreate_v4_icmp_both_tokens)   { one(AF_INET, IPPROTO_ICMP, 0, 0); }
TEST(rawcreate_v4_icmpv6_both_tokens) { one(AF_INET, IPPROTO_ICMPV6, 0, 0); }
TEST(rawcreate_v6_icmp_both_tokens)   { one(AF_INET6, IPPROTO_ICMP, 0, 0); }
TEST(rawcreate_v6_icmpv6_both_tokens) { one(AF_INET6, IPPROTO_ICMPV6, 0, 0); }
TEST(rawcreate_v4_udp_needs_elevation)   { one(AF_INET, IPPROTO_UDP, 0, WSAEACCES); }
TEST(rawcreate_v4_tcp_needs_elevation)   { one(AF_INET, IPPROTO_TCP, 0, WSAEACCES); }
TEST(rawcreate_v4_raw255_needs_elevation){ one(AF_INET, IPPROTO_RAW, 0, WSAEACCES); }
TEST(rawcreate_v4_proto0_needs_elevation){ one(AF_INET, 0, 0, WSAEACCES); }
TEST(rawcreate_v4_igmp_needs_elevation)  { one(AF_INET, IPPROTO_IGMP, 0, WSAEACCES); }
TEST(rawcreate_v6_udp_needs_elevation)   { one(AF_INET6, IPPROTO_UDP, 0, WSAEACCES); }
TEST(rawcreate_v6_raw255_needs_elevation){ one(AF_INET6, IPPROTO_RAW, 0, WSAEACCES); }
TEST(rawcreate_v6_proto0_needs_elevation){ one(AF_INET6, 0, 0, WSAEACCES); }
TEST(rawcreate_protocol_256_is_unsupported) { one(AF_INET, 256, WSAEPROTONOSUPPORT, WSAEPROTONOSUPPORT); }

/* a refusal leaves no socket behind and does not poison the error state of the next call */
TEST(rawcreate_refusal_then_success) {
    SOCKET s;
    RW_UP();
    if (rw_elevated()) { t_skip("refusal path needs a non-elevated token"); return; }
    rw_seterr(0); s = rw_raw(AF_INET, IPPROTO_UDP);
    CHECK(s == INVALID_SOCKET); RW_EQ(rw_err(), WSAEACCES);
    s = rw_raw(AF_INET, IPPROTO_ICMP);
    CHECK(s != INVALID_SOCKET);
    rw_close(s);
}
/* non-raw types asked for the raw-IP protocol number */
TEST(rawcreate_non_raw_types_with_raw_protocol) {
    static const struct { int ty, err; } t[] = {{SOCK_STREAM, WSAEPROTONOSUPPORT}, {SOCK_DGRAM, WSAEPROTONOSUPPORT},
        {SOCK_RDM, WSAESOCKTNOSUPPORT}, {SOCK_SEQPACKET, WSAESOCKTNOSUPPORT}};
    size_t i;
    RW_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s; rw_seterr(0); s = U(socket)(AF_INET, t[i].ty, IPPROTO_RAW);
        t_check(s == INVALID_SOCKET, __FILE__, __LINE__, "non-raw type refused", "type %d", t[i].ty);
        t_check(rw_err() == t[i].err, __FILE__, __LINE__, "error code", "type %d got %d want %d", t[i].ty, rw_err(), t[i].err);
        rw_close(s);
    }
}
/* a raw socket is not listening, accepting or connection oriented */
TEST(rawcreate_info_flags_v4) {
    SOCKET s; WSAPROTOCOL_INFOW pi; int n = sizeof pi;
    RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) { t_skip("raw ICMP socket not available"); return; }
    memset(&pi, 0, sizeof pi);
    RW_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &n), 0);
    RW_EQ(pi.iAddressFamily, AF_INET); RW_EQ(pi.iSocketType, SOCK_RAW);
    CHECK(pi.dwServiceFlags1 & XP1_CONNECTIONLESS);
    CHECK(pi.dwServiceFlags1 & XP1_MESSAGE_ORIENTED);
    CHECK(!(pi.dwServiceFlags1 & XP1_GUARANTEED_DELIVERY));
    RW_EQ(pi.iMaxSockAddr, 16);
    rw_close(s);
}
