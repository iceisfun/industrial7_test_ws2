/* WSASocketA() parameter resolution: invalid (family, type, protocol) combinations and their error
 * codes, defaults when a field is 0, AF_UNSPEC inference, use of a WSAPROTOCOL_INFO structure and its
 * precedence over explicit arguments, the first-match rules over the WSAEnumProtocols catalog,
 * SO_TYPE immutability, raw sockets, and (when the families exist) IPX and Bluetooth. */
#include "ws.h"

#define BAD_VAL 0xdead
#define NO_ERR 0

static SOCKET w_wsasocket(int af, int ty, int pr, WSAPROTOCOL_INFOA *pi) {
    return U(WSASocketA)(af, ty, pr, pi, 0, 0);
}
static int sock_type_of(SOCKET s) {
    int t = 0xdead, n = sizeof t;
    CHECK(w_getsockopt(s, SOL_SOCKET, SO_TYPE, &t, &n) == 0);
    return t;
}

struct sock_row {
    int family, type, protocol;
    DWORD error;                       /* 0 = must succeed */
    int ret_family, ret_type, ret_protocol;
};
static const struct sock_row sock_rows[] = {
    /* 0 */
    {BAD_VAL,   SOCK_STREAM, IPPROTO_TCP, WSAEAFNOSUPPORT},
    {-1,        SOCK_STREAM, IPPROTO_TCP, WSAEAFNOSUPPORT},
    {AF_INET,   BAD_VAL,     IPPROTO_TCP, WSAESOCKTNOSUPPORT},
    {AF_INET,   -1,          IPPROTO_TCP, WSAESOCKTNOSUPPORT},
    {AF_INET,   SOCK_STREAM, BAD_VAL,     WSAEPROTONOSUPPORT},
    {AF_INET,   SOCK_STREAM, -1,          WSAEPROTONOSUPPORT},
    {BAD_VAL,   BAD_VAL,     IPPROTO_TCP, WSAESOCKTNOSUPPORT},
    {BAD_VAL,   SOCK_STREAM, BAD_VAL,     WSAEAFNOSUPPORT},
    {AF_INET,   BAD_VAL,     BAD_VAL,     WSAESOCKTNOSUPPORT},
    {BAD_VAL,   SOCK_STREAM, IPPROTO_UDP, WSAEAFNOSUPPORT},
    /* 10 */
    {AF_INET,   SOCK_STREAM, 0,           NO_ERR, AF_INET, SOCK_STREAM, IPPROTO_TCP},
    {AF_INET,   SOCK_DGRAM,  0,           NO_ERR, AF_INET, SOCK_DGRAM,  IPPROTO_UDP},
    {AF_INET,   BAD_VAL,     0,           WSAESOCKTNOSUPPORT},
    {AF_INET,   0,           IPPROTO_TCP, NO_ERR, AF_INET, SOCK_STREAM, IPPROTO_TCP},
    {AF_INET,   0,           IPPROTO_UDP, NO_ERR, AF_INET, SOCK_DGRAM,  IPPROTO_UDP},
    {AF_INET,   0,           BAD_VAL,     WSAEPROTONOSUPPORT},
    {AF_INET,   0,           0,           NO_ERR, AF_INET, SOCK_STREAM, IPPROTO_TCP},
    {AF_INET,   SOCK_STREAM, IPPROTO_UDP, WSAEPROTONOSUPPORT},
    {AF_INET,   SOCK_DGRAM,  IPPROTO_TCP, WSAEPROTONOSUPPORT},
    /* 19 */
    {AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, NO_ERR, AF_INET, SOCK_STREAM, IPPROTO_TCP},
    {AF_UNSPEC, SOCK_STREAM, BAD_VAL,     WSAEPROTONOSUPPORT},
    {AF_UNSPEC, BAD_VAL,     IPPROTO_UDP, WSAESOCKTNOSUPPORT},
    {AF_UNSPEC, SOCK_STREAM, 0,           WSAEINVAL},
    {AF_UNSPEC, SOCK_DGRAM,  0,           WSAEINVAL},
    {AF_UNSPEC, BAD_VAL,     0,           WSAEINVAL},
    {AF_UNSPEC, 0,           IPPROTO_TCP, NO_ERR, AF_INET, SOCK_STREAM, IPPROTO_TCP},
    {AF_UNSPEC, 0,           IPPROTO_UDP, NO_ERR, AF_INET, SOCK_DGRAM,  IPPROTO_UDP},
    {AF_UNSPEC, 0,           BAD_VAL,     WSAEPROTONOSUPPORT},
    {AF_UNSPEC, 0,           0,           WSAEINVAL},
};

/* Every call resets the last-error to 0 on success; failures leave the documented error. */
static void run_sock_row(unsigned i) {
    const struct sock_row *r = &sock_rows[i];
    SOCKET s;
    if (!ws_up()) return;
    SetLastError(0xdeadbeef);
    s = w_wsasocket(r->family, r->type, r->protocol, NULL);
    EXPECT_EQ((DWORD)w_err(), r->error);
    if (r->error) {
        CHECK(s == INVALID_SOCKET);
    } else {
        WSAPROTOCOL_INFOA info; int n = sizeof info;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) return;
        CHECK(w_getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &info, &n) == 0);
        EXPECT_EQ(info.iAddressFamily, r->ret_family);
        EXPECT_EQ(info.iSocketType, r->ret_type);
        EXPECT_EQ(info.iProtocol, r->ret_protocol);
        w_close(s);
    }
}
#define ROW(n) TEST(l5_wsasocket_args_row_##n) { run_sock_row(n); }
ROW(0) ROW(1) ROW(2) ROW(3) ROW(4) ROW(5) ROW(6) ROW(7) ROW(8) ROW(9)
ROW(10) ROW(11) ROW(12) ROW(13) ROW(14) ROW(15) ROW(16) ROW(17) ROW(18) ROW(19)
ROW(20) ROW(21) ROW(22) ROW(23) ROW(24) ROW(25) ROW(26) ROW(27) ROW(28)

/* ---- catalog helpers ---- */
static WSAPROTOCOL_INFOA *enum_all(const int *filter, int *count) {
    DWORD sz = 0; int n; WSAPROTOCOL_INFOA *pi;
    n = U(WSAEnumProtocolsA)((LPINT)filter, NULL, &sz);
    CHECK(n == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAENOBUFS);
    CHECK(sz > 0);
    if (!sz) { *count = 0; return NULL; }
    pi = (WSAPROTOCOL_INFOA *)HeapAlloc(GetProcessHeap(), 0, sz);
    n = U(WSAEnumProtocolsA)((LPINT)filter, pi, &sz);
    CHECK(n != SOCKET_ERROR);
    *count = n > 0 ? n : 0;
    return pi;
}
static void free_enum(WSAPROTOCOL_INFOA *pi) { if (pi) HeapFree(GetProcessHeap(), 0, pi); }

/* A zero-size enumeration reports WSAENOBUFS and a positive size, for both filtered and unfiltered lists. */
TEST(l5_wsasocket_enum_zero_buffer_reports_size) {
    static const int filt[] = {IPPROTO_TCP, IPPROTO_IP, 0};
    int n; WSAPROTOCOL_INFOA *pi;
    if (!ws_up()) return;
    pi = enum_all(filt, &n); CHECK(n > 0); free_enum(pi);
    pi = enum_all(NULL, &n); CHECK(n > 0); free_enum(pi);
}

/* FROM_PROTOCOL_INFO for all three parameters takes everything from the structure. */
TEST(l5_wsasocket_from_protocol_info) {
    static const int filt[] = {IPPROTO_TCP, IPPROTO_IP, 0};
    int n; WSAPROTOCOL_INFOA *pi; SOCKET s;
    if (!ws_up()) return;
    pi = enum_all(filt, &n);
    if (n == 0) { t_skip("no protocols enumerated"); free_enum(pi); return; }
    s = w_wsasocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi[0]);
    CHECK(s != INVALID_SOCKET);
    w_close(s);
    free_enum(pi);
}

/* Explicit family 0 / type 0 with a protocol, next to a structure holding -1 fields: the structure
 * is consulted and its bad family is what gets reported. */
TEST(l5_wsasocket_info_invalid_fields_rejected) {
    static const int filt[] = {IPPROTO_TCP, IPPROTO_IP, 0};
    int n; WSAPROTOCOL_INFOA *pi; SOCKET s;
    if (!ws_up()) return;
    pi = enum_all(filt, &n);
    if (n == 0) { t_skip("no protocols enumerated"); free_enum(pi); return; }
    pi[0].iProtocol = -1; pi[0].iSocketType = -1; pi[0].iAddressFamily = -1;
    s = w_wsasocket(0, 0, IPPROTO_UDP, &pi[0]);
    CHECK(s == INVALID_SOCKET);
    EXPECT_EQ(w_err(), WSAEAFNOSUPPORT);
    w_close(s);
    free_enum(pi);
}

/* A structure whose family, type and protocol are all zero cannot satisfy a request that only
 * names a protocol. */
TEST(l5_wsasocket_info_zero_fields_rejected) {
    static const int filt[] = {IPPROTO_TCP, IPPROTO_IP, 0};
    int n; WSAPROTOCOL_INFOA *pi; SOCKET s;
    if (!ws_up()) return;
    pi = enum_all(filt, &n);
    if (n == 0) { t_skip("no protocols enumerated"); free_enum(pi); return; }
    pi[0].iProtocol = 0; pi[0].iSocketType = 0; pi[0].iAddressFamily = 0;
    s = w_wsasocket(0, 0, IPPROTO_UDP, &pi[0]);
    CHECK(s == INVALID_SOCKET);
    EXPECT_EQ(w_err(), WSAEAFNOSUPPORT);
    w_close(s);
    free_enum(pi);
}

/* With (0,0,0) the structure's own family/type/protocol decide, and the type cannot be changed later. */
TEST(l5_wsasocket_info_fields_select_udp_and_so_type_fixed) {
    static const int filt[] = {IPPROTO_TCP, IPPROTO_IP, 0};
    int n, t; WSAPROTOCOL_INFOA *pi; SOCKET s;
    if (!ws_up()) return;
    pi = enum_all(filt, &n);
    if (n == 0) { t_skip("no protocols enumerated"); free_enum(pi); return; }
    pi[0].iProtocol = IPPROTO_UDP; pi[0].iSocketType = SOCK_DGRAM; pi[0].iAddressFamily = AF_INET;
    s = w_wsasocket(0, 0, 0, &pi[0]);
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sock_type_of(s), SOCK_DGRAM);
    t = SOCK_STREAM; w_seterr(0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_TYPE, &t, sizeof t) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEINVAL);
    t = SOCK_DGRAM; w_seterr(0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_TYPE, &t, sizeof t) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEINVAL);
    w_close(s);
    free_enum(pi);
}

/* With explicit arguments plus a structure, the explicit ones win; SO_TYPE is read-only (ENOPROTOOPT). */
TEST(l5_wsasocket_explicit_args_win_over_info) {
    static const int filt[] = {IPPROTO_TCP, IPPROTO_IP, 0};
    int n, t; WSAPROTOCOL_INFOA *pi; SOCKET s;
    if (!ws_up()) return;
    pi = enum_all(filt, &n);
    if (n == 0) { t_skip("no protocols enumerated"); free_enum(pi); return; }
    pi[0].iProtocol = IPPROTO_UDP; pi[0].iSocketType = SOCK_DGRAM; pi[0].iAddressFamily = AF_INET;
    s = w_wsasocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, &pi[0]);
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sock_type_of(s), SOCK_STREAM);
    t = SOCK_STREAM; w_seterr(0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_TYPE, &t, sizeof t) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAENOPROTOOPT);
    t = SOCK_DGRAM; w_seterr(0);
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_TYPE, &t, sizeof t) == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAENOPROTOOPT);
    w_close(s);
    free_enum(pi);
}

/* (AF_INET, 0, 0): the first AF_INET catalog entry flagged PFL_MATCHES_PROTOCOL_ZERO supplies the type. */
TEST(l5_wsasocket_zero_protocol_uses_first_matches_zero_entry) {
    int n, i; WSAPROTOCOL_INFOA *pi; SOCKET s;
    if (!ws_up()) return;
    pi = enum_all(NULL, &n);
    s = w_wsasocket(AF_INET, 0, 0, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        int st = sock_type_of(s), found = 0;
        for (i = 0; i < n; i++)
            if (pi[i].iAddressFamily == AF_INET && (pi[i].dwProviderFlags & PFL_MATCHES_PROTOCOL_ZERO)) {
                EXPECT_EQ(st, pi[i].iSocketType);
                found = 1;
                break;
            }
        CHECK(found);
    }
    w_close(s);
    free_enum(pi);
}

/* (0, 0, proto): the socket type comes from the first catalog entry for that protocol. */
static void auto_type(int proto) {
    int n, j, found = 0; WSAPROTOCOL_INFOA *pi; SOCKET s;
    pi = enum_all(NULL, &n);
    s = w_wsasocket(0, 0, proto, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        int st = sock_type_of(s);
        for (j = 0; j < n; j++)
            if (pi[j].iProtocol == proto) { EXPECT_EQ(st, pi[j].iSocketType); found = 1; break; }
        CHECK(found);
    }
    w_close(s);
    free_enum(pi);
}
TEST(l5_wsasocket_protocol_only_tcp_type) { if (ws_up()) auto_type(IPPROTO_TCP); }
TEST(l5_wsasocket_protocol_only_udp_type) { if (ws_up()) auto_type(IPPROTO_UDP); }

/* ---- raw sockets: allowed only with sufficient rights; creation itself reports the denial ---- */
TEST(l5_wsasocket_raw_icmp_denied_or_described) {
    SOCKET s; int err;
    if (!ws_up()) return;
    SetLastError(0xdeadbeef);
    s = w_wsasocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL);
    if (s == INVALID_SOCKET) {
        err = w_err();
        EXPECT_EQ(err, WSAEACCES);
        t_skip("raw sockets not permitted for this account");
        return;
    }
    {
        WSAPROTOCOL_INFOW info; int n = sizeof info;
        EXPECT_EQ(sock_type_of(s), SOCK_RAW);
        CHECK(w_getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &info, &n) == 0);
        EXPECT_EQ(info.iAddressFamily, AF_INET);
        EXPECT_EQ(info.iSocketType, SOCK_RAW);
        EXPECT_EQ(info.iMaxSockAddr, 0x10);
        EXPECT_EQ(info.iMinSockAddr, 0x10);
        EXPECT_EQ(info.iProtocol, 0);                        /* the raw entry is protocol 0 whatever was requested */
        EXPECT_EQ(info.iProtocolMaxOffset, 255);
        EXPECT_EQ(info.dwProviderFlags, PFL_MATCHES_PROTOCOL_ZERO | PFL_HIDDEN);
        EXPECT_EQ(info.dwServiceFlags1, XP1_IFS_HANDLES | XP1_SUPPORT_BROADCAST | XP1_SUPPORT_MULTIPOINT |
                                         XP1_MESSAGE_ORIENTED | XP1_CONNECTIONLESS);
    }
    w_close(s);
}

TEST(l5_wsasocket_raw_protocol_only_variants) {
    SOCKET s;
    if (!ws_up()) return;
    s = w_wsasocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL);
    if (s == INVALID_SOCKET) { t_skip("raw sockets not permitted for this account"); return; }
    w_close(s);
    s = w_wsasocket(0, 0, IPPROTO_RAW, NULL);
    if (s == INVALID_SOCKET && w_err() == WSAEACCES) { t_skip("raw sockets not permitted for this account"); return; }
    CHECKF(s != INVALID_SOCKET, "err=%d", w_err());
    if (s != INVALID_SOCKET) { EXPECT_EQ(sock_type_of(s), SOCK_RAW); w_close(s); }
    s = w_wsasocket(AF_INET, SOCK_RAW, IPPROTO_TCP, NULL);
    CHECKF(s != INVALID_SOCKET, "err=%d", w_err());
    if (s != INVALID_SOCKET) { EXPECT_EQ(sock_type_of(s), SOCK_RAW); w_close(s); }
}

/* ---- IPX: removed from current Windows; if it is present the full contract is checked ---- */
TEST(l5_wsasocket_ipx_family_unsupported_or_complete) {
    SOCKET s; WSAPROTOCOL_INFOA info; int n, i, t;
    if (!ws_up()) return;
    SetLastError(0xdeadbeef);
    s = w_wsasocket(AF_IPX, SOCK_DGRAM, NSPROTO_IPX, NULL);
    if (s == INVALID_SOCKET) {
        EXPECT_EQ(w_err(), WSAEAFNOSUPPORT);
        t_skip("IPX not present");
        return;
    }
    w_close(s);
    s = w_wsasocket(0, 0, NSPROTO_IPX, NULL);
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sock_type_of(s), SOCK_DGRAM);
    n = sizeof info;
    CHECK(w_getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &info, &n) == 0);
    EXPECT_EQ(info.iProtocol, NSPROTO_IPX);
    EXPECT_EQ(info.iAddressFamily, AF_IPX);
    EXPECT_EQ(info.iSocketType, SOCK_DGRAM);
    w_close(s);
    w_seterr(0);
    s = w_wsasocket(AF_IPX, SOCK_STREAM, NSPROTO_IPX, NULL);
    CHECK(s == INVALID_SOCKET);
    EXPECT_EQ(w_err(), WSAEPROTONOSUPPORT);
    w_close(s);
    for (i = 0; i <= 255; i += 17) {                 /* NSPROTO_IPX + n selects packet type n */
        s = w_wsasocket(0, 0, NSPROTO_IPX + i, NULL);
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        t = -1; n = sizeof t;
        CHECK(w_getsockopt(s, NSPROTO_IPX, IPX_PTYPE, &t, &n) == 0);
        EXPECT_EQ(t, i);
        w_close(s);
    }
}

/* ---- Bluetooth RFCOMM: same pattern ---- */
TEST(l5_wsasocket_bluetooth_unsupported_or_complete) {
    SOCKET s; WSAPROTOCOL_INFOA info; int n, err;
    if (!ws_up()) return;
    SetLastError(0xdeadbeef);
    s = w_wsasocket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM, NULL);
    if (s == INVALID_SOCKET) {
        err = w_err();
        CHECK(err == WSAEAFNOSUPPORT || err == WSAEPROTONOSUPPORT);
        t_skip("Bluetooth not present");
        return;
    }
    w_close(s);
    s = w_wsasocket(0, SOCK_STREAM, BTHPROTO_RFCOMM, NULL);
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sock_type_of(s), SOCK_STREAM);
    n = sizeof info;
    CHECK(w_getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &info, &n) == 0);
    EXPECT_EQ(info.iProtocol, BTHPROTO_RFCOMM);
    EXPECT_EQ(info.iAddressFamily, AF_BTH);
    EXPECT_EQ(info.iSocketType, SOCK_STREAM);
    w_close(s);
    w_seterr(0);
    s = w_wsasocket(AF_BTH, SOCK_DGRAM, BTHPROTO_RFCOMM, NULL);
    CHECK(s == INVALID_SOCKET);
    EXPECT_EQ(w_err(), WSAEAFNOSUPPORT);
    w_close(s);
}
