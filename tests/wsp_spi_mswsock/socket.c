/* WSPSocket / WSPCloseSocket / WSPGetSockOpt / WSPSetSockOpt of the base provider, called through the
 * procedure table the provider hands out.
 *
 * Measures: creation of every address-family / type pair the provider serves, the "take it from the protocol
 * info" convention (-1 and 0 for family and type, -1 for protocol), the exact error numbers for pairs the
 * provider does not serve, handle properties (valid kernel handle, inheritance flag, released on close),
 * the single WPUModifyIFSHandle upcall per created socket, default option values and the protocol-info
 * option, and closing (double close, non-socket handles).  Errors come back through lpErrno, never through
 * WSAGetLastError, so each check reads the out parameter.
 */
#include "spi.h"

static int in_set(int v, const int *set, int n) { int i; for (i = 0; i < n; i++) if (set[i] == v) return 1; return 0; }

/* ---- creation ---- */
#define MAKE_TEST(nm, af, ty, pr) \
TEST(socket_create_##nm) { \
    int e = 0; SOCKET s; SP_NEED(); \
    s = sp_sock(af, ty, pr, &e); \
    if (s == INVALID_SOCKET && (af) == AF_INET6 && e == SE_AFNOSUPPORT) { t_skip("no IPv6 here"); return; } \
    CHECKF(s != INVALID_SOCKET, "err %d", e); \
    sp_close(s); \
}
MAKE_TEST(tcp4, AF_INET, SOCK_STREAM, IPPROTO_TCP)
MAKE_TEST(udp4, AF_INET, SOCK_DGRAM, IPPROTO_UDP)
MAKE_TEST(tcp6, AF_INET6, SOCK_STREAM, IPPROTO_TCP)
MAKE_TEST(udp6, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)

TEST(socket_create_raw4)
{
    int e = 0; SOCKET s;
    SP_NEED();
    s = sp_sock(AF_INET, SOCK_RAW, IPPROTO_ICMP, &e);
    if (s == INVALID_SOCKET) { t_note("raw socket refused here, error %d", e); return; }
    sp_close(s);
}
TEST(socket_create_distinct_handles)
{
    SOCKET a, b;
    SP_NEED();
    a = sp_tcp(); b = sp_tcp();
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET);
    CHECK(a != b);
    sp_close(a); sp_close(b);
}
TEST(socket_handle_is_a_kernel_handle)
{
    DWORD fl = 0; SOCKET s;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    CHECK(GetHandleInformation((HANDLE)s, &fl));
    sp_close(s);
}
TEST(socket_handle_inheritable_by_default)
{
    DWORD fl = 0; SOCKET s;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    CHECK(GetHandleInformation((HANDLE)s, &fl));
    CHECK((fl & HANDLE_FLAG_INHERIT) != 0);
    sp_close(s);
}
TEST(socket_handle_not_inheritable_with_flag)
{
    DWORD fl = 0; SOCKET s; int e = 0;
    SP_NEED();
    s = sp_sock_flags(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT, &e);
    CHECKF(s != INVALID_SOCKET, "err %d", e);
    if (s == INVALID_SOCKET) return;
    CHECK(GetHandleInformation((HANDLE)s, &fl));
    CHECK((fl & HANDLE_FLAG_INHERIT) == 0);
    sp_close(s);
}
TEST(socket_without_overlapped_flag_is_created)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_sock_flags(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, &e);
    CHECKF(s != INVALID_SOCKET, "err %d", e);
    sp_close(s);
}
TEST(socket_close_releases_kernel_handle)
{
    DWORD fl = 0; SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPCloseSocket(s, &e), 0);
    CHECK(!GetHandleInformation((HANDLE)s, &fl));
}

/* ---- "from protocol info" convention ---- */
static void from_info_case(int af_arg, int ty_arg, int pr_arg, int af, int ty, int pr, int want_type)
{
    int e = 0, type = 0, len = sizeof type; SOCKET s;
    const WSAPROTOCOL_INFOW *pi = sp_pi(af, ty, pr);
    s = P.lpWSPSocket(af_arg, ty_arg, pr_arg, (LPWSAPROTOCOL_INFOW)pi, 0, WSA_FLAG_OVERLAPPED, &e);
    CHECKF(s != INVALID_SOCKET, "err %d", e);
    if (s == INVALID_SOCKET) return;
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len, &e), 0);
    EXPECT_EQ(type, want_type);
    sp_close(s);
}
TEST(socket_all_from_info_tcp) { SP_NEED(); from_info_case(-1, -1, -1, AF_INET, SOCK_STREAM, IPPROTO_TCP, SOCK_STREAM); }
TEST(socket_all_from_info_udp) { SP_NEED(); from_info_case(-1, -1, -1, AF_INET, SOCK_DGRAM, IPPROTO_UDP, SOCK_DGRAM); }
TEST(socket_zero_family_and_type_from_info_tcp) { SP_NEED(); from_info_case(0, 0, -1, AF_INET, SOCK_STREAM, IPPROTO_TCP, SOCK_STREAM); }
TEST(socket_zero_family_and_type_from_info_udp) { SP_NEED(); from_info_case(0, 0, -1, AF_INET, SOCK_DGRAM, IPPROTO_UDP, SOCK_DGRAM); }
TEST(socket_family_from_info_type_explicit) { SP_NEED(); from_info_case(-1, SOCK_STREAM, IPPROTO_TCP, AF_INET, SOCK_STREAM, IPPROTO_TCP, SOCK_STREAM); }
TEST(socket_type_from_info_family_explicit) { SP_NEED(); from_info_case(AF_INET, -1, IPPROTO_UDP, AF_INET, SOCK_DGRAM, IPPROTO_UDP, SOCK_DGRAM); }
TEST(socket_protocol_from_info_only_for_minus_one)
{
    /* Protocol 0 is an explicit "any" and still lands on TCP for a stream socket. */
    SP_NEED();
    from_info_case(AF_INET, SOCK_STREAM, 0, AF_INET, SOCK_STREAM, IPPROTO_TCP, SOCK_STREAM);
}
TEST(socket_udp_protocol_zero_is_udp)
{
    SP_NEED();
    from_info_case(AF_INET, SOCK_DGRAM, 0, AF_INET, SOCK_DGRAM, IPPROTO_UDP, SOCK_DGRAM);
}
TEST(socket_from_info_v6)
{
    int e = 0; SOCKET s;
    SP_NEED();
    s = sp_sock(AF_INET6, SOCK_STREAM, IPPROTO_TCP, &e);
    if (s == INVALID_SOCKET) { t_skip("no IPv6 here"); return; }
    sp_close(s);
    from_info_case(-1, -1, -1, AF_INET6, SOCK_STREAM, IPPROTO_TCP, SOCK_STREAM);
}

/* ---- error numbers for pairs the provider does not serve ---- */
static void bad_socket(int af, int ty, int pr, const int *ok, int nok, const char *what)
{
    int e = 0x5555; SOCKET s;
    sp_up_reset(&sp_upA);
    s = P.lpWSPSocket(af, ty, pr, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), 0, WSA_FLAG_OVERLAPPED, &e);
    CHECKF(s == INVALID_SOCKET, "%s: unexpectedly created", what);
    if (s != INVALID_SOCKET) { sp_close(s); return; }
    CHECKF(in_set(e, ok, nok), "%s: error %d", what, e);
    EXPECT_EQ(sp_upA.n[UP_MODIFYIFSHANDLE], 0);
}
TEST(socket_unknown_family)
{
    static const int ok[] = { SE_AFNOSUPPORT };
    SP_NEED();
    bad_socket(99, SOCK_STREAM, IPPROTO_TCP, ok, 1, "family 99");
}
TEST(socket_unknown_family_large)
{
    static const int ok[] = { SE_AFNOSUPPORT };
    SP_NEED();
    bad_socket(0x7f00, SOCK_STREAM, 0, ok, 1, "family 0x7f00");
}
TEST(socket_unknown_type_for_inet)
{
    static const int ok[] = { SE_SOCKTNOSUP };
    SP_NEED();
    bad_socket(AF_INET, 99, 0, ok, 1, "type 99");
}
TEST(socket_rdm_type_for_inet)
{
    static const int ok[] = { SE_SOCKTNOSUP };
    SP_NEED();
    bad_socket(AF_INET, SOCK_RDM, 0, ok, 1, "SOCK_RDM");
}
TEST(socket_seqpacket_type_for_inet)
{
    static const int ok[] = { SE_SOCKTNOSUP };
    SP_NEED();
    bad_socket(AF_INET, SOCK_SEQPACKET, 0, ok, 1, "SOCK_SEQPACKET");
}
TEST(socket_stream_with_udp_protocol)
{
    static const int ok[] = { SE_PROTONOSUP, SE_PROTOTYPE, SE_INVAL };
    SP_NEED();
    bad_socket(AF_INET, SOCK_STREAM, IPPROTO_UDP, ok, 3, "stream/udp");
}
TEST(socket_dgram_with_tcp_protocol)
{
    static const int ok[] = { SE_PROTONOSUP, SE_PROTOTYPE, SE_INVAL };
    SP_NEED();
    bad_socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP, ok, 3, "dgram/tcp");
}
TEST(socket_stream_with_unknown_protocol)
{
    static const int ok[] = { SE_PROTONOSUP, SE_PROTOTYPE, SE_INVAL };
    SP_NEED();
    bad_socket(AF_INET, SOCK_STREAM, 200, ok, 3, "stream/200");
}
TEST(socket_failed_create_leaves_no_open_handle)
{
    /* A refused create must not leak: the next create works and the count of handles does not grow. */
    DWORD before = 0, after = 0; int i, e = 0; SOCKET s;
    SP_NEED();
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (i = 0; i < 20; i++) {
        s = P.lpWSPSocket(99, SOCK_STREAM, 0, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), 0, 1, &e);
        if (s != INVALID_SOCKET) sp_close(s);
    }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    CHECKF(after <= before + 2, "handles %lu -> %lu", before, after);
}

/* ---- flags the stream provider refuses ---- */
#define FLAG_TEST(nm, f) \
TEST(socket_tcp_refuses_flag_##nm) { \
    int e = 0; SOCKET s; SP_NEED(); \
    s = sp_sock_flags(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED | (f), &e); \
    CHECK(s == INVALID_SOCKET); \
    EXPECT_EQ(e, SE_INVAL); \
    if (s != INVALID_SOCKET) sp_close(s); \
}
FLAG_TEST(multipoint_c_root, WSA_FLAG_MULTIPOINT_C_ROOT)
FLAG_TEST(multipoint_c_leaf, WSA_FLAG_MULTIPOINT_C_LEAF)
FLAG_TEST(multipoint_d_root, WSA_FLAG_MULTIPOINT_D_ROOT)
FLAG_TEST(multipoint_d_leaf, WSA_FLAG_MULTIPOINT_D_LEAF)

/* ---- option reads on a fresh socket ---- */
static int gi(SOCKET s, int lvl, int opt, void *v, int len)
{
    int e = 0, l = len;
    int r = P.lpWSPGetSockOpt(s, lvl, opt, (char *)v, &l, &e);
    return r == 0 ? l : -e - 1000000;
}
static void expect_int_opt(SOCKET s, int lvl, int opt, int want, const char *nm)
{
    int v = 0x5a5a5a5a, r = gi(s, lvl, opt, &v, sizeof v);
    CHECKF(r == (int)sizeof v, "%s read failed (%d)", nm, r);
    CHECKF(v == want, "%s = %d want %d", nm, v, want);
}
/* A few options are kept as a single byte: a 4-byte request comes back with length 1 and only the low byte written. */
static void expect_byte_opt(SOCKET s, int lvl, int opt, int want, const char *nm)
{
    unsigned char b[4] = { 0x5a, 0x5a, 0x5a, 0x5a }; int r = gi(s, lvl, opt, b, 4);
    CHECKF(r == 1, "%s length %d", nm, r);
    CHECKF(b[0] == want, "%s = %d want %d", nm, b[0], want);
    CHECKF(b[1] == 0x5a && b[2] == 0x5a && b[3] == 0x5a, "%s wrote beyond the first byte", nm);
}
TEST(defaults_tcp_so_type) { SOCKET s; SP_NEED(); s = sp_tcp(); expect_int_opt(s, SOL_SOCKET, SO_TYPE, SOCK_STREAM, "SO_TYPE"); sp_close(s); }
TEST(defaults_udp_so_type) { SOCKET s; SP_NEED(); s = sp_udp(); expect_int_opt(s, SOL_SOCKET, SO_TYPE, SOCK_DGRAM, "SO_TYPE"); sp_close(s); }
TEST(defaults_raw_so_type)
{
    int e = 0; SOCKET s;
    SP_NEED();
    s = sp_sock(AF_INET, SOCK_RAW, IPPROTO_ICMP, &e);
    if (s == INVALID_SOCKET) { t_skip("raw refused here"); return; }
    expect_int_opt(s, SOL_SOCKET, SO_TYPE, SOCK_RAW, "SO_TYPE");
    sp_close(s);
}
TEST(defaults_tcp_flags_are_off)
{
    SOCKET s;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    expect_int_opt(s, SOL_SOCKET, SO_ACCEPTCONN, 0, "SO_ACCEPTCONN");
    expect_int_opt(s, SOL_SOCKET, SO_ERROR, 0, "SO_ERROR");
    expect_int_opt(s, SOL_SOCKET, SO_REUSEADDR, 0, "SO_REUSEADDR");
    expect_byte_opt(s, SOL_SOCKET, SO_KEEPALIVE, 0, "SO_KEEPALIVE");
    expect_int_opt(s, SOL_SOCKET, SO_OOBINLINE, 0, "SO_OOBINLINE");
    expect_int_opt(s, SOL_SOCKET, SO_DEBUG, 0, "SO_DEBUG");
    expect_byte_opt(s, SOL_SOCKET, SO_DONTROUTE, 0, "SO_DONTROUTE");
    expect_int_opt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 0, "SO_EXCLUSIVEADDRUSE");
    expect_byte_opt(s, IPPROTO_TCP, TCP_NODELAY, 0, "TCP_NODELAY");
    sp_close(s);
}
TEST(defaults_udp_broadcast_off)
{
    SOCKET s;
    SP_NEED();
    s = sp_udp();
    CHECK(s != INVALID_SOCKET);
    expect_int_opt(s, SOL_SOCKET, SO_BROADCAST, 0, "SO_BROADCAST");
    sp_close(s);
}
TEST(defaults_buffers_are_positive)
{
    SOCKET s; int v = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_RCVBUF, &v, 4), 4);
    CHECK(v > 0);
    v = 0;
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_SNDBUF, &v, 4), 4);
    CHECK(v > 0);
    sp_close(s);
}
TEST(defaults_linger_off_on_stream)
{
    SOCKET s; struct linger lg;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    memset(&lg, 0x55, sizeof lg);
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg), (int)sizeof lg);
    EXPECT_EQ(lg.l_onoff, 0);
    sp_close(s);
}
TEST(linger_not_supported_on_datagram)
{
    SOCKET s; struct linger lg; int e = 0, l = sizeof lg;
    SP_NEED();
    s = sp_udp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_LINGER, (char *)&lg, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAENOPROTOOPT);
    sp_close(s);
}
TEST(protocol_info_option_tcp)
{
    SOCKET s; WSAPROTOCOL_INFOW out; const WSAPROTOCOL_INFOW *pi;
    SP_NEED();
    pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    memset(&out, 0, sizeof out);
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &out, sizeof out), (int)sizeof out);
    EXPECT_EQ(out.iAddressFamily, AF_INET);
    EXPECT_EQ(out.iSocketType, SOCK_STREAM);
    EXPECT_EQ(out.iProtocol, IPPROTO_TCP);
    EXPECT_EQ(out.ProtocolChain.ChainLen, 1);
    EXPECT_EQ(out.dwCatalogEntryId, pi->dwCatalogEntryId);
    CHECK(!memcmp(&out.ProviderId, &pi->ProviderId, sizeof(GUID)));
    sp_close(s);
}
TEST(protocol_info_option_udp)
{
    SOCKET s; WSAPROTOCOL_INFOW out;
    SP_NEED();
    s = sp_udp();
    CHECK(s != INVALID_SOCKET);
    memset(&out, 0, sizeof out);
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &out, sizeof out), (int)sizeof out);
    EXPECT_EQ(out.iSocketType, SOCK_DGRAM);
    EXPECT_EQ(out.iProtocol, IPPROTO_UDP);
    CHECK((out.dwServiceFlags1 & XP1_CONNECTIONLESS) != 0);
    sp_close(s);
}
TEST(protocol_info_option_matches_tcp_flags)
{
    SOCKET s; WSAPROTOCOL_INFOW out;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    memset(&out, 0, sizeof out);
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &out, sizeof out), (int)sizeof out);
    CHECK((out.dwServiceFlags1 & XP1_CONNECTIONLESS) == 0);
    CHECK((out.dwServiceFlags1 & XP1_GUARANTEED_DELIVERY) != 0);
    CHECK((out.dwServiceFlags1 & XP1_IFS_HANDLES) != 0);
    sp_close(s);
}

/* ---- option errors ---- */
TEST(getsockopt_invalid_handle)
{
    int v = 0, l = 4, e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPGetSockOpt(INVALID_SOCKET, SOL_SOCKET, SO_TYPE, (char *)&v, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(setsockopt_invalid_handle)
{
    int v = 1, e = 0;
    SP_NEED();
    EXPECT_EQ(P.lpWSPSetSockOpt(INVALID_SOCKET, SOL_SOCKET, SO_REUSEADDR, (const char *)&v, 4, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(getsockopt_unknown_socket_level_option)
{
    SOCKET s; int v = 0, l = 4, e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, 0x6666, (char *)&v, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAENOPROTOOPT);
    sp_close(s);
}
TEST(setsockopt_unknown_socket_level_option)
{
    SOCKET s; int v = 1, e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, 0x6666, (const char *)&v, 4, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAENOPROTOOPT);
    sp_close(s);
}
TEST(setsockopt_so_type_is_read_only)
{
    SOCKET s; int v = SOCK_STREAM, e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_TYPE, (const char *)&v, 4, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAENOPROTOOPT);
    sp_close(s);
}
TEST(setsockopt_so_acceptconn_is_read_only)
{
    SOCKET s; int v = 1, e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_ACCEPTCONN, (const char *)&v, 4, &e), SOCKET_ERROR);
    EXPECT_EQ(e, WSAENOPROTOOPT);
    sp_close(s);
}

/* ---- option round trips ---- */
static void roundtrip_flag(int lvl, int opt, int udp, const char *nm)
{
    SOCKET s = udp ? sp_udp() : sp_tcp(); int on = 1, e = 0, got = 0; int want_len = 4;
    if (opt == SO_KEEPALIVE || opt == SO_DONTROUTE || (lvl == IPPROTO_TCP && opt == TCP_NODELAY)) want_len = 1;
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;
    CHECKF(P.lpWSPSetSockOpt(s, lvl, opt, (const char *)&on, sizeof on, &e) == 0, "%s set err %d", nm, e);
    got = 0;
    CHECKF(gi(s, lvl, opt, &got, 4) == want_len, "%s get", nm);
    CHECKF(got != 0, "%s reads back 0 after set 1", nm);
    on = 0;
    CHECKF(P.lpWSPSetSockOpt(s, lvl, opt, (const char *)&on, sizeof on, &e) == 0, "%s clear err %d", nm, e);
    got = 0x7000;
    CHECKF(gi(s, lvl, opt, &got, 4) == want_len, "%s get2", nm);
    CHECKF((got & 0xff) == 0, "%s reads back %d after clear", nm, got);
    sp_close(s);
}
TEST(roundtrip_reuseaddr) { SP_NEED(); roundtrip_flag(SOL_SOCKET, SO_REUSEADDR, 0, "SO_REUSEADDR"); }
TEST(roundtrip_keepalive) { SP_NEED(); roundtrip_flag(SOL_SOCKET, SO_KEEPALIVE, 0, "SO_KEEPALIVE"); }
TEST(roundtrip_oobinline) { SP_NEED(); roundtrip_flag(SOL_SOCKET, SO_OOBINLINE, 0, "SO_OOBINLINE"); }
TEST(roundtrip_dontroute) { SP_NEED(); roundtrip_flag(SOL_SOCKET, SO_DONTROUTE, 0, "SO_DONTROUTE"); }
TEST(roundtrip_tcp_nodelay) { SP_NEED(); roundtrip_flag(IPPROTO_TCP, TCP_NODELAY, 0, "TCP_NODELAY"); }
TEST(roundtrip_broadcast_udp) { SP_NEED(); roundtrip_flag(SOL_SOCKET, SO_BROADCAST, 1, "SO_BROADCAST"); }
TEST(roundtrip_linger_stream)
{
    SOCKET s; struct linger lg, got; int e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    lg.l_onoff = 1; lg.l_linger = 7;
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg, &e), 0);
    memset(&got, 0, sizeof got);
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_LINGER, &got, sizeof got), (int)sizeof got);
    EXPECT_EQ(got.l_onoff != 0, 1);
    EXPECT_EQ(got.l_linger, 7);
    sp_close(s);
}
TEST(roundtrip_rcvbuf_is_accepted)
{
    SOCKET s; int v = 32768, e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&v, 4, &e), 0);
    v = 0;
    EXPECT_EQ(gi(s, SOL_SOCKET, SO_RCVBUF, &v, 4), 4);
    CHECK(v > 0);
    sp_close(s);
}
TEST(exclusive_and_reuse_conflict_is_refused)
{
    /* SO_EXCLUSIVEADDRUSE and SO_REUSEADDR exclude each other on one socket. */
    SOCKET s; int on = 1, e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, 4, &e), 0);
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, 4, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}

/* ---- close ---- */
TEST(close_invalid_handles)
{
    static const SOCKET bad[] = { 0, INVALID_SOCKET, 0x7ff0, 0xFFFFF0, 4 };
    int i, e;
    SP_NEED();
    for (i = 0; i < 4; i++) {   /* handle 4 may be live: left out */
        e = 0;
        CHECKF(P.lpWSPCloseSocket(bad[i], &e) == SOCKET_ERROR, "handle %llx", (unsigned long long)bad[i]);
        EXPECT_EQ(e, SE_NOTSOCK);
    }
}
TEST(close_twice)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPCloseSocket(s, &e), 0);
    e = 0;
    EXPECT_EQ(P.lpWSPCloseSocket(s, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(close_non_socket_handle_is_refused_and_untouched)
{
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); DWORD fl = 0; int e = 0;
    SP_NEED();
    CHECK(ev != NULL);
    EXPECT_EQ(P.lpWSPCloseSocket((SOCKET)ev, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTSOCK);
    CHECK(GetHandleInformation(ev, &fl));
    CloseHandle(ev);
}
TEST(close_udp_and_tcp_both_zero)
{
    SOCKET a, b; int e = 0;
    SP_NEED();
    a = sp_tcp(); b = sp_udp();
    EXPECT_EQ(P.lpWSPCloseSocket(a, &e), 0);
    EXPECT_EQ(P.lpWSPCloseSocket(b, &e), 0);
}
TEST(close_operations_on_closed_handle_fail_notsock)
{
    SOCKET s; int e = 0, v = 0, l = 4; struct sockaddr_in a; int al = sizeof a;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(P.lpWSPCloseSocket(s, &e), 0);
    e = 0; EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_TYPE, (char *)&v, &l, &e), SOCKET_ERROR); EXPECT_EQ(e, SE_NOTSOCK);
    e = 0; EXPECT_EQ(P.lpWSPGetSockName(s, (struct sockaddr *)&a, &al, &e), SOCKET_ERROR); EXPECT_EQ(e, SE_NOTSOCK);
    e = 0; EXPECT_EQ(P.lpWSPShutdown(s, SD_BOTH, &e), SOCKET_ERROR); EXPECT_EQ(e, SE_NOTSOCK);
    e = 0; EXPECT_EQ(P.lpWSPListen(s, 1, &e), SOCKET_ERROR); EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(many_sockets_open_and_close)
{
    SOCKET s[48]; int i, n = 0, e = 0;
    SP_NEED();
    for (i = 0; i < 48; i++) { s[i] = sp_udp(); if (s[i] != INVALID_SOCKET) n++; }
    EXPECT_EQ(n, 48);
    for (i = 0; i < 48; i++) if (s[i] != INVALID_SOCKET) EXPECT_EQ(P.lpWSPCloseSocket(s[i], &e), 0);
}
TEST(create_close_cycles)
{
    int i, bad = 0, e = 0; SOCKET s;
    SP_NEED();
    for (i = 0; i < 100; i++) {
        s = sp_tcp();
        if (s == INVALID_SOCKET || P.lpWSPCloseSocket(s, &e) != 0) bad++;
    }
    EXPECT_EQ(bad, 0);
}
