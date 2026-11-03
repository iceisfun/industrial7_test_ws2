/* How socket-creation flags show up on the endpoint handle.
 *
 * The Winsock provider turns WSASocket() flags into the arguments of the NtCreateFile that opens the
 * endpoint: WSA_FLAG_OVERLAPPED (and WSA_FLAG_REGISTERED_IO) select an asynchronous open, anything
 * else asks for FILE_SYNCHRONOUS_IO_NONALERT; WSA_FLAG_NO_HANDLE_INHERIT (and REGISTERED_IO) drop
 * OBJ_INHERIT. This file creates real sockets through ws2_32 and reads both properties back from the
 * handle with NtQueryInformationFile(FileModeInformation) and GetHandleInformation, so an alternative
 * AFD sees which open it must support for each flag combination. It also checks the open-time
 * failures the provider reports for flag/type combinations it cannot map. */
#include "aec.h"

#define F_OVERLAPPED      0x01
#define F_MPOINT_C_ROOT   0x02
#define F_MPOINT_C_LEAF   0x04
#define F_MPOINT_D_ROOT   0x08
#define F_MPOINT_D_LEAF   0x10
#define F_NO_INHERIT      0x80
#define F_REGISTERED_IO   0x100

typedef struct { ULONG mode; DWORD hflags; int ok; int werr; } skprop_t;

static skprop_t sock_props(int af, int type, int proto, DWORD flags)
{
    skprop_t r; SOCKET s; IO_STATUS_BLOCK io;
    memset(&r, 0, sizeof(r));
    s = ws_sock(af, type, proto, flags);
    if (s == INVALID_SOCKET) { r.werr = N.WSAGetLastError(); return r; }
    r.ok = 1;
    r.mode = 0xDEAD;
    N.NtQueryInformationFile((HANDLE)s, &io, &r.mode, sizeof(r.mode), FileModeInformation_);
    GetHandleInformation((HANDLE)s, &r.hflags);
    N.closesocket(s);
    return r;
}

/* one row = one socket kind x one flag set; sync/inherit are the expected properties */
#define SOCKROW(tname, af, type, proto, flags, want_sync, want_inherit) \
    TEST(tname) { skprop_t p; NEED(); p = sock_props(af, type, proto, flags); \
        if (!p.ok) { t_skip("socket not created (wsa error class %d)", p.werr == WSAEACCES ? 1 : 0); return; } \
        EXPECT_EQ(p.mode, (want_sync) ? FILE_SYNCHRONOUS_IO_NONALERT : 0); \
        EXPECT_EQ((p.hflags & HANDLE_FLAG_INHERIT) != 0, (want_inherit) ? 1 : 0); }

/* ---- TCP / IPv4 -------------------------------------------------------------------------- */
SOCKROW(aecs_tcp4_flags_none,              AF_INET, SOCK_STREAM, IPPROTO_TCP, 0,                          1, 1)
SOCKROW(aecs_tcp4_flags_overlapped,        AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED,               0, 1)
SOCKROW(aecs_tcp4_flags_no_inherit,        AF_INET, SOCK_STREAM, IPPROTO_TCP, F_NO_INHERIT,               1, 0)
SOCKROW(aecs_tcp4_flags_overlapped_no_inherit, AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_NO_INHERIT, 0, 0)
SOCKROW(aecs_tcp4_proto_zero_overlapped,   AF_INET, SOCK_STREAM, 0,           F_OVERLAPPED,               0, 1)
SOCKROW(aecs_tcp4_proto_zero_none,         AF_INET, SOCK_STREAM, 0,           0,                          1, 1)
/* ---- UDP / IPv4 -------------------------------------------------------------------------- */
SOCKROW(aecs_udp4_flags_none,              AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0,                           1, 1)
SOCKROW(aecs_udp4_flags_overlapped,        AF_INET, SOCK_DGRAM, IPPROTO_UDP, F_OVERLAPPED,                0, 1)
SOCKROW(aecs_udp4_flags_no_inherit,        AF_INET, SOCK_DGRAM, IPPROTO_UDP, F_NO_INHERIT,                1, 0)
SOCKROW(aecs_udp4_flags_overlapped_no_inherit, AF_INET, SOCK_DGRAM, IPPROTO_UDP, F_OVERLAPPED | F_NO_INHERIT, 0, 0)
SOCKROW(aecs_udp4_proto_zero_overlapped,   AF_INET, SOCK_DGRAM, 0,           F_OVERLAPPED,                0, 1)
/* ---- TCP / UDP over IPv6 ------------------------------------------------------------------ */
SOCKROW(aecs_tcp6_flags_none,              AF_INET6, SOCK_STREAM, IPPROTO_TCP, 0,                         1, 1)
SOCKROW(aecs_tcp6_flags_overlapped,        AF_INET6, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED,              0, 1)
SOCKROW(aecs_tcp6_flags_no_inherit,        AF_INET6, SOCK_STREAM, IPPROTO_TCP, F_NO_INHERIT,              1, 0)
SOCKROW(aecs_tcp6_flags_overlapped_no_inherit, AF_INET6, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_NO_INHERIT, 0, 0)
SOCKROW(aecs_udp6_flags_none,              AF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0,                          1, 1)
SOCKROW(aecs_udp6_flags_overlapped,        AF_INET6, SOCK_DGRAM, IPPROTO_UDP, F_OVERLAPPED,               0, 1)
SOCKROW(aecs_udp6_flags_no_inherit,        AF_INET6, SOCK_DGRAM, IPPROTO_UDP, F_NO_INHERIT,               1, 0)
/* ---- raw (needs an elevated token; otherwise the row skips) ------------------------------ */
SOCKROW(aecs_raw4_icmp_flags_none,         AF_INET, SOCK_RAW, IPPROTO_ICMP, 0,                            1, 1)
SOCKROW(aecs_raw4_icmp_flags_overlapped,   AF_INET, SOCK_RAW, IPPROTO_ICMP, F_OVERLAPPED,                 0, 1)
SOCKROW(aecs_raw4_icmp_no_inherit,         AF_INET, SOCK_RAW, IPPROTO_ICMP, F_NO_INHERIT,                 1, 0)
SOCKROW(aecs_raw4_proto_255_overlapped,    AF_INET, SOCK_RAW, 255,          F_OVERLAPPED,                 0, 1)
SOCKROW(aecs_raw6_icmp6_overlapped,        AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, F_OVERLAPPED,              0, 1)

/* ---- the plain socket() entry point opens with overlapped semantics --------------------- */
TEST(aecs_socket_call_is_overlapped_tcp)
{
    SOCKET s; IO_STATUS_BLOCK io; ULONG m = 0xDEAD; DWORD hf = 0; NEED();
    s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    EXPECT_NT(N.NtQueryInformationFile((HANDLE)s, &io, &m, sizeof(m), FileModeInformation_), ST_SUCCESS);
    EXPECT_EQ(m, 0);
    CHECK(GetHandleInformation((HANDLE)s, &hf));
    EXPECT_EQ(hf & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    N.closesocket(s);
}
TEST(aecs_socket_call_is_overlapped_udp)
{
    SOCKET s; IO_STATUS_BLOCK io; ULONG m = 0xDEAD; NEED();
    s = N.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    EXPECT_NT(N.NtQueryInformationFile((HANDLE)s, &io, &m, sizeof(m), FileModeInformation_), ST_SUCCESS);
    EXPECT_EQ(m, 0);
    N.closesocket(s);
}
TEST(aecs_socket_call_is_overlapped_tcp6)
{
    SOCKET s; IO_STATUS_BLOCK io; ULONG m = 0xDEAD; NEED();
    s = N.socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    EXPECT_NT(N.NtQueryInformationFile((HANDLE)s, &io, &m, sizeof(m), FileModeInformation_), ST_SUCCESS);
    EXPECT_EQ(m, 0);
    N.closesocket(s);
}

/* ---- socket handles are endpoint handles ------------------------------------------------ */
TEST(aecs_socket_handle_object_type_file)
{
    SOCKET s; struct { USHORT Length, Max; PWSTR Buffer; WCHAR text[64]; } t; NEED();
    s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) { CHECK(!"socket"); return; }
    memset(&t, 0, sizeof(t));
    EXPECT_NT(N.NtQueryObject((HANDLE)s, 2, &t, sizeof(t), NULL), ST_SUCCESS);
    CHECK(t.Length == 8 && t.Buffer && !wcsncmp(t.Buffer, L"File", 4));
    N.closesocket(s);
}
TEST(aecs_socket_handle_file_type_pipe)
{
    SOCKET s; NEED();
    s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) { CHECK(!"socket"); return; }
    EXPECT_EQ(GetFileType((HANDLE)s), FILE_TYPE_PIPE);
    N.closesocket(s);
}
TEST(aecs_socket_handle_device_type_named_pipe_class)
{
    SOCKET s; IO_STATUS_BLOCK io; ULONG d[2] = {0, 0}; NEED();
    s = N.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if (s == INVALID_SOCKET) { CHECK(!"socket"); return; }
    EXPECT_NT(N.NtQueryVolumeInformationFile((HANDLE)s, &io, d, sizeof(d), FSDEVICE_INFO), ST_SUCCESS);
    EXPECT_EQ(d[0], 0x11);   /* FILE_DEVICE_NAMED_PIPE */
    N.closesocket(s);
}
TEST(aecs_socket_handle_access_information_matches_object_query)
{
    SOCKET s; IO_STATUS_BLOCK io; ULONG acc = 0xDEAD; objbasic_t b; NEED();
    s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) { CHECK(!"socket"); return; }
    EXPECT_NT(N.NtQueryInformationFile((HANDLE)s, &io, &acc, sizeof(acc), FileAccessInformation_), ST_SUCCESS);
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject((HANDLE)s, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(acc, b.GrantedAccess);
    EXPECT_EQ(acc, FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
    N.closesocket(s);
}
TEST(aecs_socket_handle_close_via_nt_close_invalidates)
{
    /* closing the handle behind the provider's back leaves a stale SOCKET; the handle itself is gone */
    SOCKET s; IO_STATUS_BLOCK io; ULONG m = 0; NEED();
    s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) { CHECK(!"socket"); return; }
    EXPECT_NT(N.NtClose((HANDLE)s), ST_SUCCESS);
    EXPECT_NT(N.NtQueryInformationFile((HANDLE)s, &io, &m, sizeof(m), FileModeInformation_), ST_INVALID_HANDLE);
}

/* ---- combinations the provider cannot map ----------------------------------------------- */
#define SOCKFAIL(tname, af, type, proto, flags) \
    TEST(tname) { SOCKET s; NEED(); s = ws_sock(af, type, proto, flags); \
        CHECK(s == INVALID_SOCKET); \
        if (s != INVALID_SOCKET) { N.closesocket(s); return; } \
        EXPECT_EQ(N.WSAGetLastError(), WSAEINVAL); }
/* registered-I/O sockets exist only for TCP and UDP over IPv4/IPv6 */
SOCKFAIL(aecs_fail_rio_raw4,   AF_INET,  SOCK_RAW, IPPROTO_ICMP,   F_OVERLAPPED | F_REGISTERED_IO)
SOCKFAIL(aecs_fail_rio_raw6,   AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, F_OVERLAPPED | F_REGISTERED_IO)
SOCKFAIL(aecs_fail_rio_raw4_alone, AF_INET, SOCK_RAW, IPPROTO_ICMP, F_REGISTERED_IO)
/* multipoint roles need a multipoint-capable provider; the TCP provider is not one */
SOCKFAIL(aecs_fail_tcp_c_root, AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_MPOINT_C_ROOT)
SOCKFAIL(aecs_fail_tcp_c_leaf, AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_MPOINT_C_LEAF)
SOCKFAIL(aecs_fail_tcp_d_root, AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_MPOINT_D_ROOT)
SOCKFAIL(aecs_fail_tcp_d_leaf, AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_MPOINT_D_LEAF)
SOCKFAIL(aecs_fail_tcp6_c_root, AF_INET6, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_MPOINT_C_ROOT)

/* multipoint root roles fail on UDP as well (the datagram provider offers leaves only);
 * flags the provider does not define are refused with the same error */
SOCKFAIL(aecs_fail_udp_c_root, AF_INET, SOCK_DGRAM, IPPROTO_UDP, F_OVERLAPPED | F_MPOINT_C_ROOT)
SOCKFAIL(aecs_fail_udp_d_root, AF_INET, SOCK_DGRAM, IPPROTO_UDP, F_OVERLAPPED | F_MPOINT_D_ROOT)
SOCKFAIL(aecs_fail_undefined_flag_0x200, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0x200)
SOCKFAIL(aecs_fail_undefined_flag_0x10000, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0x10000)
SOCKFAIL(aecs_fail_access_system_security, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0x40)

/* registered-I/O sockets are asynchronous and never inheritable, with or without the overlapped flag */
SOCKROW(aecs_tcp4_rio_overlapped,      AF_INET,  SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_REGISTERED_IO, 0, 0)
SOCKROW(aecs_tcp4_rio_alone,           AF_INET,  SOCK_STREAM, IPPROTO_TCP, F_REGISTERED_IO, 0, 0)
SOCKROW(aecs_udp4_rio_overlapped,      AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, F_OVERLAPPED | F_REGISTERED_IO, 0, 0)
SOCKROW(aecs_tcp6_rio_overlapped,      AF_INET6, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_REGISTERED_IO, 0, 0)
SOCKROW(aecs_tcp4_rio_no_inherit,      AF_INET,  SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED | F_REGISTERED_IO | F_NO_INHERIT, 0, 0)
/* multipoint leaves are plain datagram opens */
SOCKROW(aecs_udp4_c_leaf,              AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, F_OVERLAPPED | F_MPOINT_C_LEAF, 0, 1)
SOCKROW(aecs_udp4_d_leaf,              AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, F_OVERLAPPED | F_MPOINT_D_LEAF, 0, 1)

/* ---- accepted and duplicated sockets keep the mode of their source --------------------- */
static void accept_mode_case(DWORD flags, const char *label)
{
    SOCKET l, c, a; struct sockaddr_in sa; int len = sizeof(sa); IO_STATUS_BLOCK io; ULONG m = 0xDEAD, lm = 0xDEAD;
    DWORD tmo = 3000;
    l = ws_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, flags);
    c = ws_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, F_OVERLAPPED);
    if (l == INVALID_SOCKET || c == INVALID_SOCKET) { t_skip("socket"); goto out; }
    memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_addr.s_addr = 0x0100007Fu;
    if (N.bind(l, (struct sockaddr *)&sa, sizeof(sa)) || N.listen(l, 1) || N.getsockname(l, (struct sockaddr *)&sa, &len)) { t_skip("loopback setup"); goto out; }
    N.setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof(tmo));
    N.setsockopt(l, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof(tmo));
    if (N.connect(c, (struct sockaddr *)&sa, sizeof(sa))) { t_skip("loopback connect"); goto out; }
    {
        typedef SOCKET (WINAPI *acc_fn)(SOCKET, struct sockaddr *, int *);
        acc_fn acc = (acc_fn)GetProcAddress(t_module("ws2_32.dll"), "accept");
        a = acc ? acc(l, NULL, NULL) : INVALID_SOCKET;
    }
    if (a == INVALID_SOCKET) { t_skip("accept"); goto out; }
    N.NtQueryInformationFile((HANDLE)l, &io, &lm, sizeof(lm), FileModeInformation_);
    N.NtQueryInformationFile((HANDLE)a, &io, &m, sizeof(m), FileModeInformation_);
    /* the accepted endpoint is opened like its listener */
    EXPECT_EQ(lm, (flags & F_OVERLAPPED) ? 0 : FILE_SYNCHRONOUS_IO_NONALERT);
    EXPECT_EQ(m, lm);
    N.closesocket(a);
out:
    if (c != INVALID_SOCKET) N.closesocket(c);
    if (l != INVALID_SOCKET) N.closesocket(l);
}
TEST(aecs_accepted_socket_mode_follows_overlapped_listener) { NEED(); accept_mode_case(F_OVERLAPPED, "overlapped listener"); }
TEST(aecs_accepted_socket_mode_follows_plain_listener)      { NEED(); accept_mode_case(0, "plain listener"); }
