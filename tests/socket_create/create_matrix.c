/* socket_create: the (family, type, protocol) resolution done by socket/WSASocketW.
 *
 * The WS2 layer walks its protocol catalog and reports how far the best candidate got:
 *   - no entry has the requested socket type          -> WSAESOCKTNOSUPPORT (10044)
 *   - a type matched but never together with the family -> WSAEAFNOSUPPORT    (10047)
 *   - type and family matched, protocol did not          -> WSAEPROTONOSUPPORT (10043)
 * and a request with family 0 and protocol 0 is rejected up front with WSAEINVAL (10022), whatever the
 * type is. Because the error depends on the furthest match, an unknown family next to a perfectly good
 * type reports 10047 while the same family next to an unknown type reports 10044.
 * A protocol of 0 selects the catalog entries flagged PFL_MATCHES_PROTOCOL_ZERO; RAW entries cover the
 * protocol range 0..255. Combinations that depend on optional hardware (Bluetooth, Hyper-V) are only
 * noted. Raw sockets need an elevated token: when creation fails with WSAEACCES the row is skipped.
 * Rows already asserted by the first-pass lifts are not repeated here. */
#include "sc.h"

#define E_INVAL      WSAEINVAL
#define E_AF         WSAEAFNOSUPPORT
#define E_SOCKT      WSAESOCKTNOSUPPORT
#define E_PROTO      WSAEPROTONOSUPPORT

/* create with WSASocketW and no flags, report the error; closes the socket when it was created */
static int try_create(int af, int ty, int pr, DWORD fl) {
    SOCKET s;
    sc_seterr(0xdeadbeef);
    s = sc_make(af, ty, pr, fl);
    if (s != INVALID_SOCKET) { sc_close(s); return 0; }
    return sc_err();
}
/* a failing combination: INVALID_SOCKET and the given error, through socket() and WSASocketW alike */
static void want_err(int af, int ty, int pr, int err) {
    SOCKET s;
    sc_seterr(0xdeadbeef);
    s = U(socket)(af, ty, pr);
    t_check(s == INVALID_SOCKET, __FILE__, __LINE__, "socket() fails", "af=%d ty=%d pr=%d", af, ty, pr);
    t_check(sc_err() == err, __FILE__, __LINE__, "socket() error", "af=%d ty=%d pr=%d got %d want %d", af, ty, pr, sc_err(), err);
    sc_close(s);
    sc_seterr(0xdeadbeef);
    s = sc_make(af, ty, pr, 0);
    t_check(s == INVALID_SOCKET, __FILE__, __LINE__, "WSASocketW fails", "af=%d ty=%d pr=%d", af, ty, pr);
    t_check(sc_err() == err, __FILE__, __LINE__, "WSASocketW error", "af=%d ty=%d pr=%d got %d want %d", af, ty, pr, sc_err(), err);
    sc_close(s);
}
/* a succeeding combination: the socket reports the resolved family/type/protocol */
static void want_ok(int af, int ty, int pr, int raf, int rty, int rpr) {
    SOCKET s;
    WSAPROTOCOL_INFOW pi;
    sc_seterr(0xdeadbeef);
    s = sc_make(af, ty, pr, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        t_check(0, __FILE__, __LINE__, "creation succeeds", "af=%d ty=%d pr=%d error %d", af, ty, pr, sc_err());
        return;
    }
    t_check(sc_getinfo(s, &pi) == 0, __FILE__, __LINE__, "SO_PROTOCOL_INFOW", "af=%d ty=%d pr=%d", af, ty, pr);
    t_check(pi.iAddressFamily == raf, __FILE__, __LINE__, "family", "af=%d ty=%d pr=%d got %d want %d", af, ty, pr, pi.iAddressFamily, raf);
    t_check(pi.iSocketType == rty, __FILE__, __LINE__, "type", "af=%d ty=%d pr=%d got %d want %d", af, ty, pr, pi.iSocketType, rty);
    t_check(pi.iProtocol == rpr, __FILE__, __LINE__, "protocol", "af=%d ty=%d pr=%d got %d want %d", af, ty, pr, pi.iProtocol, rpr);
    t_check(sc_sotype(s) == rty, __FILE__, __LINE__, "SO_TYPE", "af=%d ty=%d pr=%d", af, ty, pr);
    sc_close(s);
}
/* raw rows: success or WSAEACCES (not elevated). Returns 1 when the socket could be created. */
static int raw_ok(int af, int pr, int rty_expect) {
    SOCKET s;
    sc_seterr(0);
    s = sc_make(af, SOCK_RAW, pr, 0);
    if (s == INVALID_SOCKET) {
        t_check(sc_err() == WSAEACCES, __FILE__, __LINE__, "raw denial is WSAEACCES", "af=%d pr=%d got %d", af, pr, sc_err());
        return 0;
    }
    t_check(sc_sotype(s) == rty_expect, __FILE__, __LINE__, "raw SO_TYPE", NULL);
    sc_close(s);
    return 1;
}

/* ---- unsupported socket types: 10044 whatever the family and protocol ---- */
static const int bad_types[] = {SOCK_RDM, SOCK_SEQPACKET, 6, 7, 8, 100, 255, 256, SC_BAD, 0x7fffffff, -1, -2, (int)0x80000000};
static const int probe_protos[] = {1, 6, 17, 58, 255, 256, -1, SC_BAD};

static void types_unsupported_for(int af, int with_zero_proto) {
    unsigned i, j;
    for (i = 0; i < sizeof bad_types / sizeof *bad_types; i++) {
        if (with_zero_proto) want_err(af, bad_types[i], 0, E_SOCKT);
        for (j = 0; j < sizeof probe_protos / sizeof *probe_protos; j++)
            want_err(af, bad_types[i], probe_protos[j], E_SOCKT);
    }
}
TEST(sockcreate_matrix_unsupported_type_inet)   { SC_UP(); types_unsupported_for(AF_INET, 1); }
TEST(sockcreate_matrix_unsupported_type_inet6)  { SC_UP(); types_unsupported_for(AF_INET6, 1); }
TEST(sockcreate_matrix_unsupported_type_unix)   { SC_UP(); types_unsupported_for(AF_UNIX, 1); }
TEST(sockcreate_matrix_unsupported_type_ipx)    { SC_UP(); types_unsupported_for(6, 1); }
TEST(sockcreate_matrix_unsupported_type_netbios){ SC_UP(); types_unsupported_for(17, 1); }
TEST(sockcreate_matrix_unsupported_type_unknown_family) {
    SC_UP();
    types_unsupported_for(SC_BAD, 1);
    types_unsupported_for(-1, 1);
}
/* family 0 with a protocol: still 10044 for a type that nothing implements */
TEST(sockcreate_matrix_unsupported_type_unspec_with_protocol) {
    unsigned i, j;
    SC_UP();
    for (i = 0; i < sizeof bad_types / sizeof *bad_types; i++)
        for (j = 0; j < sizeof probe_protos / sizeof *probe_protos; j++)
            want_err(AF_UNSPEC, bad_types[i], probe_protos[j], E_SOCKT);
}
/* family 0 + protocol 0 is refused before the catalog is consulted: 10022 for every type */
TEST(sockcreate_matrix_unspec_zero_protocol_is_einval) {
    static const int tys[] = {0, 1, 2, 3, 4, 5, 6, SC_BAD, -1};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof tys / sizeof *tys; i++) want_err(AF_UNSPEC, tys[i], 0, E_INVAL);
}

/* ---- known type, unknown family: 10047 ---- */
static const int absent_families[] = {3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                      24, 25, 27, 28, 29, 30, 31, 35, 36, 64, 255, 256, SC_BAD, 0x7fff, -1, -5};
static void family_absent_for_type(int ty) {
    static const int prs[] = {0, 1, 6, 17, 58, 256, -1};
    unsigned i, j;
    for (i = 0; i < sizeof absent_families / sizeof *absent_families; i++)
        for (j = 0; j < sizeof prs / sizeof *prs; j++)
            want_err(absent_families[i], ty, prs[j], E_AF);
}
TEST(sockcreate_matrix_unknown_family_stream) { SC_UP(); family_absent_for_type(SOCK_STREAM); }
TEST(sockcreate_matrix_unknown_family_dgram)  { SC_UP(); family_absent_for_type(SOCK_DGRAM); }
TEST(sockcreate_matrix_unknown_family_raw)    { SC_UP(); family_absent_for_type(SOCK_RAW); }
/* AF_UNIX has a stream entry only: a datagram or raw request finds the type elsewhere and the family nowhere */
TEST(sockcreate_matrix_unix_dgram_and_raw_are_afnosupport) {
    static const int prs[] = {0, 1, 6, 17, 256, -1, SC_BAD};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) {
        want_err(AF_UNIX, SOCK_DGRAM, prs[i], E_AF);
        want_err(AF_UNIX, SOCK_RAW, prs[i], E_AF);
    }
}
/* AF_UNIX stream accepts protocol 0 only; any other number is a protocol error, not a family error */
TEST(sockcreate_matrix_unix_stream_nonzero_protocol) {
    static const int prs[] = {1, 2, 6, 17, 58, 255, 256, -1, SC_BAD};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) {
        want_err(AF_UNIX, SOCK_STREAM, prs[i], E_PROTO);
        want_err(AF_UNIX, 0, prs[i], E_PROTO);
    }
}
TEST(sockcreate_matrix_unix_stream_success) {
    SC_UP();
    want_ok(AF_UNIX, SOCK_STREAM, 0, AF_UNIX, SOCK_STREAM, 0);
    want_ok(AF_UNIX, 0, 0, AF_UNIX, SOCK_STREAM, 0);
}

/* ---- known family and type, wrong protocol: 10043 ---- */
static void stream_wrong_proto(int af) {
    static const int prs[] = {1, 2, 17, 41, 58, 132, 255, 256, -1, SC_BAD};
    unsigned i;
    for (i = 0; i < sizeof prs / sizeof *prs; i++) want_err(af, SOCK_STREAM, prs[i], E_PROTO);
}
static void dgram_wrong_proto(int af) {
    static const int prs[] = {1, 2, 6, 41, 58, 132, 255, 256, -1, SC_BAD};
    unsigned i;
    for (i = 0; i < sizeof prs / sizeof *prs; i++) want_err(af, SOCK_DGRAM, prs[i], E_PROTO);
}
TEST(sockcreate_matrix_inet_stream_wrong_protocol)  { SC_UP(); stream_wrong_proto(AF_INET); }
TEST(sockcreate_matrix_inet6_stream_wrong_protocol) { SC_UP(); stream_wrong_proto(AF_INET6); }
TEST(sockcreate_matrix_inet_dgram_wrong_protocol)   { SC_UP(); dgram_wrong_proto(AF_INET); }
TEST(sockcreate_matrix_inet6_dgram_wrong_protocol)  { SC_UP(); dgram_wrong_proto(AF_INET6); }
/* with type 0 the protocol alone has to identify a catalog entry */
TEST(sockcreate_matrix_inet_untyped_unknown_protocol) {
    static const int prs[] = {256, 257, 1000, 65536, -1, -6, SC_BAD};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) {
        want_err(AF_INET, 0, prs[i], E_PROTO);
        want_err(AF_INET6, 0, prs[i], E_PROTO);
    }
}
/* unspecified family: the protocol has to name something in the catalog */
TEST(sockcreate_matrix_unspec_stream_wrong_protocol) {
    static const int prs[] = {2, 17, 41, 58, 255, -1, SC_BAD};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) want_err(AF_UNSPEC, SOCK_STREAM, prs[i], E_PROTO);
}
TEST(sockcreate_matrix_unspec_dgram_wrong_protocol) {
    static const int prs[] = {1, 2, 6, 41, 58, 255, 256, -1, SC_BAD};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) want_err(AF_UNSPEC, SOCK_DGRAM, prs[i], E_PROTO);
}
TEST(sockcreate_matrix_unspec_untyped_unknown_protocol) {
    SC_UP();
    want_err(AF_UNSPEC, 0, -1, E_PROTO);
    want_err(AF_UNSPEC, 0, SC_BAD, E_PROTO);
    want_err(AF_UNSPEC, 0, 65536, E_PROTO);
}

/* ---- raw sockets: protocol range 0..255 ---- */
TEST(sockcreate_matrix_raw_protocol_out_of_range) {
    static const int prs[] = {256, 257, 300, 1000, 65536, -1, -6, SC_BAD, 0x7fffffff};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) {
        want_err(AF_INET, SOCK_RAW, prs[i], E_PROTO);        /* classification precedes the privilege check */
        want_err(AF_INET6, SOCK_RAW, prs[i], E_PROTO);
        want_err(AF_UNSPEC, SOCK_RAW, prs[i], E_PROTO);
    }
}
TEST(sockcreate_matrix_raw_every_protocol_number_inet) {
    int pr, made = 0;
    SC_UP();
    for (pr = 0; pr <= 255; pr++) {
        SOCKET s;
        sc_seterr(0);
        s = sc_make(AF_INET, SOCK_RAW, pr, 0);
        if (s == INVALID_SOCKET) {
            if (!made && sc_err() == WSAEACCES) { t_skip("raw sockets need an elevated token"); return; }
            t_check(0, __FILE__, __LINE__, "raw creation", "pr=%d error %d", pr, sc_err());
            continue;
        }
        made++;
        sc_close(s);
    }
    SC_EQ(made, 256);
}
TEST(sockcreate_matrix_raw_every_protocol_number_inet6) {
    int pr, made = 0;
    SC_UP();
    for (pr = 0; pr <= 255; pr++) {
        SOCKET s;
        sc_seterr(0);
        s = sc_make(AF_INET6, SOCK_RAW, pr, 0);
        if (s == INVALID_SOCKET) {
            if (!made && sc_err() == WSAEACCES) { t_skip("raw sockets need an elevated token"); return; }
            t_check(0, __FILE__, __LINE__, "raw creation", "pr=%d error %d", pr, sc_err());
            continue;
        }
        made++;
        sc_close(s);
    }
    SC_EQ(made, 256);
}
TEST(sockcreate_matrix_raw_info_reports_protocol_zero) {
    static const int prs[] = {IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_RAW, 113, 132, 255};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof prs / sizeof *prs; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_RAW, prs[i], 0);
        WSAPROTOCOL_INFOW pi;
        if (s == INVALID_SOCKET) { t_skip("raw sockets need an elevated token"); return; }
        CHECK(sc_getinfo(s, &pi) == 0);
        SC_EQ(pi.iProtocol, 0);                 /* the single RAW entry is registered with protocol 0 ... */
        SC_EQ(pi.iProtocolMaxOffset, 255);      /* ... and a 0..255 range */
        SC_EQ(pi.iSocketType, SOCK_RAW);
        sc_close(s);
    }
}
TEST(sockcreate_matrix_raw_type_inferred_from_protocol_or_zero) {
    SC_UP();
    /* type 0 with a protocol other than TCP/UDP: the first entry whose range holds it is the RAW one */
    if (raw_ok(AF_INET, IPPROTO_ICMP, SOCK_RAW)) {
        SOCKET s = sc_make(AF_UNSPEC, 0, IPPROTO_ICMP, 0);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(sc_sotype(s), SOCK_RAW);
        sc_close(s);
        sc_seterr(0);
        s = sc_make(AF_INET, 0, IPPROTO_IGMP, 0);
        if (sc_elevated()) {
            CHECK(s != INVALID_SOCKET);
            SC_EQ(sc_sotype(s), SOCK_RAW);
        } else {
            /* without elevation only ICMP and ICMPv6 raw sockets are allowed */
            CHECK(s == INVALID_SOCKET);
            SC_EQ(sc_err(), WSAEACCES);
        }
        sc_close(s);
        s = sc_make(AF_INET6, 0, 58, 0);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(sc_sotype(s), SOCK_RAW);
        sc_close(s);
    }
}
TEST(sockcreate_matrix_raw_unspec_picks_inet_first) {
    SC_UP();
    if (raw_ok(AF_INET, IPPROTO_ICMP, SOCK_RAW)) {
        WSAPROTOCOL_INFOW pi;
        SOCKET s = sc_make(AF_UNSPEC, SOCK_RAW, 58, 0);     /* IPv4 entries precede IPv6 ones in the catalog */
        CHECK(s != INVALID_SOCKET);
        CHECK(sc_getinfo(s, &pi) == 0);
        SC_EQ(pi.iAddressFamily, AF_INET);
        sc_close(s);
    }
}

/* ---- successful resolutions that the first-pass lifts do not list ---- */
TEST(sockcreate_matrix_inet6_success_rows) {
    SC_UP();
    want_ok(AF_INET6, SOCK_STREAM, 0, AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    want_ok(AF_INET6, SOCK_STREAM, IPPROTO_TCP, AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    want_ok(AF_INET6, SOCK_DGRAM, 0, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    want_ok(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    want_ok(AF_INET6, 0, IPPROTO_TCP, AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    want_ok(AF_INET6, 0, IPPROTO_UDP, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    want_ok(AF_INET6, 0, 0, AF_INET6, SOCK_STREAM, IPPROTO_TCP);
}
TEST(sockcreate_matrix_inet_protocol_zero_picks_by_type) {
    SC_UP();
    want_ok(AF_INET, SOCK_STREAM, IPPROTO_IP, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    want_ok(AF_INET, SOCK_DGRAM, IPPROTO_IP, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}
TEST(sockcreate_matrix_unspec_infers_from_type_and_protocol) {
    SC_UP();
    want_ok(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    want_ok(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}
TEST(sockcreate_matrix_unspec_untyped_tcp_udp) {
    SC_UP();
    want_ok(AF_UNSPEC, 0, IPPROTO_TCP, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    want_ok(AF_UNSPEC, 0, IPPROTO_UDP, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}
TEST(sockcreate_matrix_unix_family_only_selects_stream) {
    SC_UP();
    want_ok(AF_UNIX, 0, 0, AF_UNIX, SOCK_STREAM, 0);
}

/* ---- precedence of the three errors ---- */
TEST(sockcreate_matrix_precedence_type_beats_family_and_protocol) {
    SC_UP();
    want_err(SC_BAD, SC_BAD, SC_BAD, E_SOCKT);
    want_err(SC_BAD, SC_BAD, IPPROTO_TCP, E_SOCKT);
    want_err(AF_INET, SC_BAD, SC_BAD, E_SOCKT);
    want_err(AF_INET6, SOCK_SEQPACKET, IPPROTO_TCP, E_SOCKT);
    want_err(AF_INET, SOCK_RDM, IPPROTO_UDP, E_SOCKT);
}
TEST(sockcreate_matrix_precedence_family_beats_protocol) {
    SC_UP();
    want_err(SC_BAD, SOCK_STREAM, SC_BAD, E_AF);
    want_err(SC_BAD, SOCK_DGRAM, SC_BAD, E_AF);
    want_err(SC_BAD, SOCK_RAW, SC_BAD, E_AF);
    want_err(AF_UNIX, SOCK_DGRAM, SC_BAD, E_AF);
}
TEST(sockcreate_matrix_precedence_unspec_zero_protocol_beats_everything) {
    SC_UP();
    want_err(AF_UNSPEC, SC_BAD, 0, E_INVAL);
    want_err(AF_UNSPEC, SOCK_SEQPACKET, 0, E_INVAL);
    want_err(AF_UNSPEC, SOCK_STREAM, 0, E_INVAL);
}
TEST(sockcreate_matrix_precedence_unspec_with_protocol_reports_type_first) {
    SC_UP();
    want_err(AF_UNSPEC, SC_BAD, IPPROTO_TCP, E_SOCKT);
    want_err(AF_UNSPEC, SC_BAD, SC_BAD, E_SOCKT);
    want_err(AF_UNSPEC, SOCK_STREAM, SC_BAD, E_PROTO);
}

/* ---- the failure value and the two error views ---- */
TEST(sockcreate_matrix_failure_is_all_ones_64bit) {
    SOCKET s;
    SC_UP();
    s = U(socket)(SC_BAD, SOCK_STREAM, 0);
    SC_EQ(s, (ULONG_PTR)~(ULONG_PTR)0);
    s = sc_make(AF_INET, SOCK_SEQPACKET, 0, 0);
    SC_EQ(s, (ULONG_PTR)~(ULONG_PTR)0);
    s = U(WSASocketA)(AF_UNSPEC, 0, 0, NULL, 0, 0);
    SC_EQ(s, (ULONG_PTR)~(ULONG_PTR)0);
    CHECK(sizeof(SOCKET) == 8);
}
TEST(sockcreate_matrix_win32_and_wsa_error_agree) {
    SC_UP();
    SetLastError(0);
    CHECK(U(socket)(AF_INET, SOCK_SEQPACKET, 0) == INVALID_SOCKET);
    SC_EQ(GetLastError(), WSAESOCKTNOSUPPORT);
    SC_EQ(sc_err(), WSAESOCKTNOSUPPORT);
    SetLastError(0);
    CHECK(U(socket)(SC_BAD, SOCK_STREAM, 0) == INVALID_SOCKET);
    SC_EQ(GetLastError(), WSAEAFNOSUPPORT);
    sc_seterr(WSAEINTR);
    CHECK(U(socket)(AF_UNSPEC, SOCK_STREAM, 0) == INVALID_SOCKET);
    SC_EQ(GetLastError(), WSAEINVAL);
}
TEST(sockcreate_matrix_error_is_replaced_not_sticky) {
    SOCKET s;
    SC_UP();
    CHECK(U(socket)(AF_INET, SOCK_SEQPACKET, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAESOCKTNOSUPPORT);
    CHECK(U(socket)(SC_BAD, SOCK_STREAM, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEAFNOSUPPORT);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    sc_close(s);
}

/* ---- the A/W entry points share the resolution logic ---- */
TEST(sockcreate_matrix_wsasocketa_matches_wsasocketw_errors) {
    static const int rows[][3] = {
        {AF_INET, SOCK_SEQPACKET, 0}, {SC_BAD, SOCK_STREAM, 0}, {AF_INET, SOCK_STREAM, IPPROTO_UDP}, {AF_UNSPEC, 0, 0},
        {AF_UNIX, SOCK_DGRAM, 0}, {AF_INET6, SOCK_DGRAM, IPPROTO_TCP}, {AF_UNSPEC, SC_BAD, IPPROTO_TCP}, {AF_UNIX, SOCK_STREAM, 6}};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof rows / sizeof *rows; i++) {
        int ea, ew;
        SOCKET a, w;
        sc_seterr(0);
        a = U(WSASocketA)(rows[i][0], rows[i][1], rows[i][2], NULL, 0, 0);
        ea = sc_err();
        sc_seterr(0);
        w = sc_make(rows[i][0], rows[i][1], rows[i][2], 0);
        ew = sc_err();
        CHECK(a == INVALID_SOCKET && w == INVALID_SOCKET);
        SC_EQ(ea, ew);
        sc_close(a); sc_close(w);
    }
}
TEST(sockcreate_matrix_socket_matches_wsasocketw_errors) {
    static const int rows[][3] = {
        {AF_INET, SOCK_RDM, 0}, {-1, SOCK_STREAM, 6}, {AF_INET6, SOCK_STREAM, IPPROTO_UDP}, {AF_UNSPEC, SOCK_DGRAM, 0},
        {AF_UNIX, SOCK_RAW, 0}, {AF_INET, SOCK_RAW, 300}, {AF_UNSPEC, 0, SC_BAD}};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof rows / sizeof *rows; i++) {
        int e1, e2;
        sc_seterr(0);
        CHECK(U(socket)(rows[i][0], rows[i][1], rows[i][2]) == INVALID_SOCKET);
        e1 = sc_err();
        sc_seterr(0);
        CHECK(sc_make(rows[i][0], rows[i][1], rows[i][2], WSA_FLAG_OVERLAPPED) == INVALID_SOCKET);
        e2 = sc_err();
        SC_EQ(e1, e2);
    }
}

/* ---- optional hardware families: only recorded ---- */
TEST(sockcreate_matrix_optional_families_are_notes) {
    int e;
    SC_UP();
    e = try_create(32, SOCK_STREAM, 3, 0);              /* Bluetooth RFCOMM */
    t_note("bluetooth rfcomm create -> %d", e);
    e = try_create(34, SOCK_STREAM, 1, 0);              /* Hyper-V sockets */
    t_note("hyperv raw create -> %d", e);
    /* a Bluetooth request with a datagram type has no entry at all: the family is the missing piece */
    want_err(32, SOCK_DGRAM, 0, E_AF);
    want_err(34, SOCK_DGRAM, 0, E_AF);
    want_err(32, SOCK_RAW, 0, E_AF);
}

/* ---- individual rows kept as separate tests so one failure pinpoints the combination ---- */
struct row { int af, ty, pr, err, raf, rty, rpr; };
static const struct row rows[] = {
    /* 0 */ {AF_INET6, SOCK_STREAM, IPPROTO_UDP, E_PROTO},
    {AF_INET6, SOCK_DGRAM, IPPROTO_TCP, E_PROTO},
    {AF_INET, SOCK_RAW, 256, E_PROTO},
    {AF_INET, SOCK_SEQPACKET, IPPROTO_TCP, E_SOCKT},
    {AF_INET, SOCK_RDM, IPPROTO_UDP, E_SOCKT},
    {AF_INET6, SOCK_SEQPACKET, 0, E_SOCKT},
    {AF_UNIX, SOCK_SEQPACKET, 0, E_SOCKT},
    {AF_UNIX, SOCK_DGRAM, 0, E_AF},
    {AF_UNIX, SOCK_STREAM, 1, E_PROTO},
    {AF_UNIX, SOCK_RAW, 0, E_AF},
    /* 10 */ {6, SOCK_DGRAM, 1000, E_AF},
    {6, SOCK_STREAM, 0, E_AF},
    {17, SOCK_DGRAM, 1, E_AF},
    {17, SOCK_STREAM, 0, E_AF},
    {16, SOCK_STREAM, 0, E_AF},
    {AF_UNSPEC, SOCK_RAW, 256, E_PROTO},
    {AF_UNSPEC, SOCK_SEQPACKET, 0, E_INVAL},
    {AF_UNSPEC, SOCK_SEQPACKET, IPPROTO_TCP, E_SOCKT},
    {AF_UNSPEC, SOCK_DGRAM, IPPROTO_TCP, E_PROTO},
    {AF_UNSPEC, SOCK_STREAM, IPPROTO_UDP, E_PROTO},
    /* 20 */ {AF_INET6, 0, 0, 0, AF_INET6, SOCK_STREAM, IPPROTO_TCP},
    {AF_INET6, 0, IPPROTO_UDP, 0, AF_INET6, SOCK_DGRAM, IPPROTO_UDP},
    {AF_INET6, SOCK_DGRAM, 0, 0, AF_INET6, SOCK_DGRAM, IPPROTO_UDP},
    {AF_UNIX, 0, 0, 0, AF_UNIX, SOCK_STREAM, 0},
    {AF_UNIX, SOCK_STREAM, 0, 0, AF_UNIX, SOCK_STREAM, 0},
    {AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, 0, AF_INET, SOCK_DGRAM, IPPROTO_UDP},
};
static void run_row(unsigned i) {
    const struct row *r = &rows[i];
    SC_UP();
    if (r->err) want_err(r->af, r->ty, r->pr, r->err);
    else want_ok(r->af, r->ty, r->pr, r->raf, r->rty, r->rpr);
}
#define ROW(n) TEST(sockcreate_matrix_row_##n) { run_row(n); }
ROW(0) ROW(1) ROW(2) ROW(3) ROW(4) ROW(5) ROW(6) ROW(7) ROW(8) ROW(9)
ROW(10) ROW(11) ROW(12) ROW(13) ROW(14) ROW(15) ROW(16) ROW(17) ROW(18) ROW(19)
ROW(20) ROW(21) ROW(22) ROW(23) ROW(24) ROW(25)
