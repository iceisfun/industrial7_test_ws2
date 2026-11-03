/* Byte-order helpers, the legacy wsock32 address entry points, and sockaddr layout.
 * Measures: htons/htonl/ntohs/ntohl exact values and that the h/n pairs are one function, the
 * absence of 64-bit helpers among the exports, WSAHtons/WSAHtonl/WSANtohs/WSANtohl through live
 * sockets (values, WSAENOTSOCK for bad handles, WSAEFAULT for a NULL result pointer, the argument
 * check order), the wsock32 forwarders and inet_network, and that the sockaddr structures have the
 * layout the stack reads and writes (sizes, field offsets, and a bind/getsockname round trip through
 * hand-built byte images). */
#include "ac.h"

/* ---------------------------------------------------------------- htons / htonl */

static unsigned short sw16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }
static unsigned long sw32(unsigned long v) { return ((v & 0xffUL) << 24) | ((v & 0xff00UL) << 8) | ((v >> 8) & 0xff00UL) | ((v >> 24) & 0xffUL); }

#define H16(name, in, out) TEST(ac_htons_##name) { \
    if (!U(htons) || !U(ntohs)) { t_skip("missing export"); return; } \
    EXPECT_EQ(U(htons)(in), out); EXPECT_EQ(U(ntohs)(in), out); }
#define H32(name, in, out) TEST(ac_htonl_##name) { \
    if (!U(htonl) || !U(ntohl)) { t_skip("missing export"); return; } \
    EXPECT_EQ(U(htonl)(in), out); EXPECT_EQ(U(ntohl)(in), out); }

H16(zero,            0x0000, 0x0000)
H16(one,             0x0001, 0x0100)
H16(low_byte_only,   0x00ff, 0xff00)
H16(high_byte_only,  0xff00, 0x00ff)
H16(ascending,       0x1234, 0x3412)
H16(sign_bit,        0x8000, 0x0080)
H16(all_ones,        0xffff, 0xffff)
H16(palindrome,      0xabab, 0xabab)
H16(http_port,       80,     0x5000)
H16(ephemeral_start, 49152,  0x00c0)

H32(zero,            0x00000000UL, 0x00000000UL)
H32(one,             0x00000001UL, 0x01000000UL)
H32(ascending,       0x12345678UL, 0x78563412UL)
H32(sign_bit,        0x80000000UL, 0x00000080UL)
H32(all_ones,        0xffffffffUL, 0xffffffffUL)
H32(loopback,        0x7f000001UL, 0x0100007fUL)
H32(alternating,     0xff00ff00UL, 0x00ff00ffUL)
H32(inner_bytes,     0x00ffff00UL, 0x00ffff00UL)
H32(low_word_only,   0x0000ffffUL, 0xffff0000UL)
H32(single_byte_3,   0x00010000UL, 0x00000100UL)

TEST(ac_htons_every_value) {
    unsigned v;
    REQUIRE(U(htons)); REQUIRE(U(ntohs));
    for (v = 0; v < 65536; v++) {
        unsigned short n = U(htons)((unsigned short)v);
        if (n != sw16((unsigned short)v)) { CHECKF(0, "htons(%04x) = %04x", v, n); break; }
        if (U(ntohs)(n) != v) { CHECKF(0, "ntohs(htons(%04x)) = %04x", v, U(ntohs)(n)); break; }
    }
}

TEST(ac_htonl_sampled_values) {
    unsigned long v; unsigned i;
    REQUIRE(U(htonl)); REQUIRE(U(ntohl));
    for (i = 0, v = 1; i < 20000; i++, v = v * 1664525UL + 1013904223UL) {
        unsigned long n = U(htonl)(v);
        if (n != sw32(v)) { CHECKF(0, "htonl(%08lx) = %08lx", v, n); break; }
        if (U(ntohl)(n) != v) { CHECKF(0, "ntohl(htonl(%08lx)) = %08lx", v, U(ntohl)(n)); break; }
    }
}

TEST(ac_htonl_each_single_bit) {
    int b;
    REQUIRE(U(htonl));
    for (b = 0; b < 32; b++) {
        unsigned long v = 1UL << b;
        CHECKF(U(htonl)(v) == sw32(v), "bit %d", b);
    }
}

/* The host-to-network and network-to-host exports are one function (same code). */
TEST(ac_htons_and_ntohs_are_the_same_function) {
    CHECK(t_proc_in("ws2_32.dll", "htons") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "htons") == t_proc_in("ws2_32.dll", "ntohs"));
}
TEST(ac_htonl_and_ntohl_are_the_same_function) {
    CHECK(t_proc_in("ws2_32.dll", "htonl") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "htonl") == t_proc_in("ws2_32.dll", "ntohl"));
}
TEST(ac_htons_and_htonl_are_different_functions) {
    CHECK(t_proc_in("ws2_32.dll", "htons") != t_proc_in("ws2_32.dll", "htonl"));
}

/* 64-bit and floating helpers are header-only: ws2_32 does not export them. */
#define NOEXP(name) TEST(ac_no_export_##name) { \
    HMODULE m = t_module("ws2_32.dll"); if (!m) { t_skip("no ws2_32"); return; } \
    SetLastError(0); CHECK(GetProcAddress(m, #name) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
NOEXP(htonll)
NOEXP(ntohll)
NOEXP(htonf)
NOEXP(ntohf)
NOEXP(htond)
NOEXP(ntohd)

/* The header's 64-bit conversion is two htonl calls, high word last-in-memory. */
TEST(ac_htonll_by_composition) {
    unsigned long long v = 0x0102030405060708ULL, n; unsigned char *p;
    unsigned long hi, lo;
    REQUIRE(U(htonl));
    hi = U(htonl)((unsigned long)(v >> 32)); lo = U(htonl)((unsigned long)v);
    n = ((unsigned long long)lo << 32) | hi;
    p = (unsigned char *)&n;
    CHECK(p[0] == 1 && p[1] == 2 && p[2] == 3 && p[3] == 4 && p[4] == 5 && p[5] == 6 && p[6] == 7 && p[7] == 8);
}

/* ---------------------------------------------------------------- wsock32 */

#define FWD(name) TEST(ac_wsock32_forwards_##name) { \
    FARPROC a = t_proc_in("wsock32.dll", #name), b = t_proc_in("ws2_32.dll", #name); \
    if (!a) { t_skip("no wsock32 export"); return; } CHECK(a == b); }
FWD(htons)
FWD(htonl)
FWD(ntohs)
FWD(ntohl)
FWD(inet_addr)
FWD(inet_ntoa)

/* inet_network is exported by wsock32 (forwarded to mswsock) but not by ws2_32. */
TEST(ac_inet_network_forwarder_target) {
    FARPROC a = t_proc_in("wsock32.dll", "inet_network"), b = t_proc_in("mswsock.dll", "inet_network");
    if (!a) { t_skip("no wsock32 inet_network"); return; }
    CHECK(b != NULL); CHECK(a == b);
    CHECK(t_proc_in("ws2_32.dll", "inet_network") == NULL);
}

/* On Windows 10 the implementation does nothing and answers 0 whatever it is given. */
TEST(ac_inet_network_is_a_stub_returning_zero) {
    unsigned long (WSAAPI *f)(const char *) = (unsigned long (WSAAPI *)(const char *))t_proc_in("wsock32.dll", "inet_network");
    if (!f) { t_skip("no wsock32 inet_network"); return; }
    EXPECT_EQ(f("1.2.3.4"), 0);
    EXPECT_EQ(f("127.0.0.1"), 0);
    EXPECT_EQ(f("255.255.255.255"), 0);
    EXPECT_EQ(f("not an address"), 0);
    EXPECT_EQ(f(""), 0);
}

TEST(ac_wsock32_byteorder_and_addr_work_through_forwarders) {
    unsigned short (WSAAPI *hs)(unsigned short) = (void *)t_proc_in("wsock32.dll", "htons");
    unsigned long (WSAAPI *hl)(unsigned long) = (void *)t_proc_in("wsock32.dll", "ntohl");
    unsigned long (WSAAPI *ia)(const char *) = (void *)t_proc_in("wsock32.dll", "inet_addr");
    char *(WSAAPI *nt)(struct in_addr) = (void *)t_proc_in("wsock32.dll", "inet_ntoa");
    struct in_addr in;
    if (!hs || !hl || !ia || !nt) { t_skip("no wsock32 exports"); return; }
    EXPECT_EQ(hs(0x1234), 0x3412);
    EXPECT_EQ(hl(0x12345678UL), 0x78563412UL);
    EXPECT_EQ(ia("10.20.30.40"), AC_RAW(10, 20, 30, 40));
    in.s_addr = AC_RAW(10, 20, 30, 40);
    {   char *p = nt(in); CHECK(p != NULL); if (p) EXPECT_STR(p, "10.20.30.40"); }
}

/* ---------------------------------------------------------------- WSAHtons family */

static SOCKET mk(int af, int type, int proto) {
    if (!U(socket)) return INVALID_SOCKET;
    return U(socket)(af, type, proto);
}

typedef int (WSAAPI *wsa16_fn)(SOCKET, u_short, u_short *);
typedef int (WSAAPI *wsa32_fn)(SOCKET, u_long, u_long *);

static void wsa_values_on(SOCKET s) {
    wsa16_fn hs = (wsa16_fn)t_proc_in("ws2_32.dll", "WSAHtons"), ns = (wsa16_fn)t_proc_in("ws2_32.dll", "WSANtohs");
    wsa32_fn hl = (wsa32_fn)t_proc_in("ws2_32.dll", "WSAHtonl"), nl = (wsa32_fn)t_proc_in("ws2_32.dll", "WSANtohl");
    static const unsigned short v16[] = { 0, 1, 0x1234, 0x8000, 0xff00, 0xffff, 0xabcd };
    static const unsigned long v32[] = { 0, 1, 0x12345678UL, 0x80000000UL, 0xff00ff00UL, 0xffffffffUL, 0xdeadbeefUL };
    unsigned i;
    for (i = 0; i < AC_COUNT(v16); i++) {
        u_short o = 0x5a5a; int r;
        r = hs(s, v16[i], &o); CHECKF(r == 0 && o == sw16(v16[i]), "WSAHtons(%04x): ret %d out %04x", v16[i], r, o);
        o = 0x5a5a;
        r = ns(s, v16[i], &o); CHECKF(r == 0 && o == sw16(v16[i]), "WSANtohs(%04x): ret %d out %04x", v16[i], r, o);
    }
    for (i = 0; i < AC_COUNT(v32); i++) {
        u_long o = 0x5a5a5a5aUL; int r;
        r = hl(s, v32[i], &o); CHECKF(r == 0 && o == sw32(v32[i]), "WSAHtonl(%08lx): ret %d out %08lx", v32[i], r, o);
        o = 0x5a5a5a5aUL;
        r = nl(s, v32[i], &o); CHECKF(r == 0 && o == sw32(v32[i]), "WSANtohl(%08lx): ret %d out %08lx", v32[i], r, o);
    }
}

static int wsa_ready(void) {
    if (!t_proc_in("ws2_32.dll", "WSAHtons") || !t_proc_in("ws2_32.dll", "WSAHtonl") ||
        !t_proc_in("ws2_32.dll", "WSANtohs") || !t_proc_in("ws2_32.dll", "WSANtohl") ||
        !U(socket) || !U(closesocket) || !U(WSASetLastError) || !U(WSAGetLastError)) { t_skip("missing export"); return 0; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return 0; }
    return 1;
}

TEST(ac_wsahtons_values_tcp_v4) {
    SOCKET s; if (!wsa_ready()) return;
    s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) { t_skip("no tcp socket"); return; }
    wsa_values_on(s); U(closesocket)(s);
}
TEST(ac_wsahtons_values_udp_v4) {
    SOCKET s; if (!wsa_ready()) return;
    s = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if (s == INVALID_SOCKET) { t_skip("no udp socket"); return; }
    wsa_values_on(s); U(closesocket)(s);
}
TEST(ac_wsahtons_values_tcp_v6) {
    SOCKET s; if (!wsa_ready()) return;
    s = mk(AF_INET6, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) { t_skip("no ipv6 socket"); return; }
    wsa_values_on(s); U(closesocket)(s);
}
TEST(ac_wsahtons_values_udp_v6) {
    SOCKET s; if (!wsa_ready()) return;
    s = mk(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); if (s == INVALID_SOCKET) { t_skip("no ipv6 socket"); return; }
    wsa_values_on(s); U(closesocket)(s);
}

/* The WSA forms agree with the plain functions for a stream socket. */
TEST(ac_wsahtons_agrees_with_htons) {
    SOCKET s; unsigned v;
    if (!wsa_ready()) return;
    REQUIRE(U(htons)); REQUIRE(U(htonl));
    s = mk(AF_INET, SOCK_STREAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    for (v = 0; v < 65536; v += 251) {
        u_short o = 0; u_long ol = 0;
        U(WSAHtons)(s, (u_short)v, &o);
        CHECKF(o == U(htons)((u_short)v), "value %04x", v);
        U(WSAHtonl)(s, v * 65537UL, &ol);
        CHECKF(ol == U(htonl)(v * 65537UL), "value %08lx", v * 65537UL);
    }
    U(closesocket)(s);
}

static void wsa_bad_socket(SOCKET s, const char *what) {
    u_short o16 = 0x5a5a; u_long o32 = 0x5a5a5a5aUL; int r;
    r = U(WSAHtons)(s, 1, &o16);
    CHECKF(r == SOCKET_ERROR && U(WSAGetLastError)() == AC_ENOTSOCK, "%s WSAHtons: ret %d err %d", what, r, U(WSAGetLastError)());
    U(WSASetLastError)(0);
    r = U(WSANtohs)(s, 1, &o16);
    CHECKF(r == SOCKET_ERROR && U(WSAGetLastError)() == AC_ENOTSOCK, "%s WSANtohs: ret %d err %d", what, r, U(WSAGetLastError)());
    U(WSASetLastError)(0);
    r = U(WSAHtonl)(s, 1, &o32);
    CHECKF(r == SOCKET_ERROR && U(WSAGetLastError)() == AC_ENOTSOCK, "%s WSAHtonl: ret %d err %d", what, r, U(WSAGetLastError)());
    U(WSASetLastError)(0);
    r = U(WSANtohl)(s, 1, &o32);
    CHECKF(r == SOCKET_ERROR && U(WSAGetLastError)() == AC_ENOTSOCK, "%s WSANtohl: ret %d err %d", what, r, U(WSAGetLastError)());
    CHECKF(o16 == 0x5a5a && o32 == 0x5a5a5a5aUL, "%s: result written on failure", what);
}

TEST(ac_wsahtons_invalid_socket_is_enotsock) {
    if (!wsa_ready()) return;
    U(WSASetLastError)(0);
    wsa_bad_socket(INVALID_SOCKET, "INVALID_SOCKET");
}
TEST(ac_wsahtons_zero_socket_is_enotsock) {
    if (!wsa_ready()) return;
    U(WSASetLastError)(0);
    wsa_bad_socket(0, "handle 0");
}
TEST(ac_wsahtons_closed_socket_is_enotsock) {
    SOCKET s;
    if (!wsa_ready()) return;
    s = mk(AF_INET, SOCK_STREAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    U(closesocket)(s);
    U(WSASetLastError)(0);
    wsa_bad_socket(s, "closed socket");
}
TEST(ac_wsahtons_event_handle_is_enotsock) {
    HANDLE ev;
    if (!wsa_ready()) return;
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL); if (!ev) return;
    U(WSASetLastError)(0);
    wsa_bad_socket((SOCKET)ev, "event handle");
    CloseHandle(ev);
}

/* A NULL result pointer is rejected before the socket is looked at: WSAEFAULT even for a bad handle. */
TEST(ac_wsahtons_null_result_is_efault_before_socket_check) {
    int r;
    if (!wsa_ready()) return;
    U(WSASetLastError)(0); r = U(WSAHtons)(INVALID_SOCKET, 1, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = U(WSANtohs)(INVALID_SOCKET, 1, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = U(WSAHtonl)(INVALID_SOCKET, 1, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = U(WSANtohl)(INVALID_SOCKET, 1, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
}
TEST(ac_wsahtons_null_result_with_good_socket_is_efault) {
    SOCKET s; int r;
    if (!wsa_ready()) return;
    s = mk(AF_INET, SOCK_STREAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    U(WSASetLastError)(0); r = U(WSAHtons)(s, 1, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = U(WSANtohl)(s, 1, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(closesocket)(s);
}
TEST(ac_wsahtons_success_keeps_last_error) {
    SOCKET s; u_short o; u_long ol;
    if (!wsa_ready()) return;
    s = mk(AF_INET, SOCK_STREAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    U(WSASetLastError)(0x2345); EXPECT_EQ(U(WSAHtons)(s, 1, &o), 0); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(WSASetLastError)(0x2345); EXPECT_EQ(U(WSANtohs)(s, 1, &o), 0); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(WSASetLastError)(0x2345); EXPECT_EQ(U(WSAHtonl)(s, 1, &ol), 0); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(WSASetLastError)(0x2345); EXPECT_EQ(U(WSANtohl)(s, 1, &ol), 0); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(closesocket)(s);
}
/* Only the result variable is written. */
TEST(ac_wsahtons_writes_only_the_result) {
    SOCKET s; struct { u_short before; u_short out; u_short after; } g = { 0x1111, 0, 0x2222 };
    if (!wsa_ready()) return;
    s = mk(AF_INET, SOCK_STREAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    EXPECT_EQ(U(WSAHtons)(s, 0x0102, &g.out), 0);
    CHECK(g.before == 0x1111 && g.out == 0x0201 && g.after == 0x2222);
    U(closesocket)(s);
}

/* ---------------------------------------------------------------- structure sizes and offsets */

TEST(ac_layout_sockaddr_sizes) {
    EXPECT_EQ(sizeof(SOCKADDR), 16);
    EXPECT_EQ(sizeof(SOCKADDR_IN), 16);
    EXPECT_EQ(sizeof(SOCKADDR_IN6), 28);
    EXPECT_EQ(sizeof(SOCKADDR_STORAGE), 128);
    EXPECT_EQ(sizeof(IN_ADDR), 4);
    EXPECT_EQ(sizeof(IN6_ADDR), 16);
    EXPECT_EQ(sizeof(ADDRESS_FAMILY), 2);
}
TEST(ac_layout_sockaddr_in_offsets) {
    EXPECT_EQ(offsetof(SOCKADDR_IN, sin_family), 0);
    EXPECT_EQ(offsetof(SOCKADDR_IN, sin_port), 2);
    EXPECT_EQ(offsetof(SOCKADDR_IN, sin_addr), 4);
    EXPECT_EQ(offsetof(SOCKADDR_IN, sin_zero), 8);
    EXPECT_EQ(sizeof(((SOCKADDR_IN *)0)->sin_zero), 8);
}
TEST(ac_layout_sockaddr_in6_offsets) {
    EXPECT_EQ(offsetof(SOCKADDR_IN6, sin6_family), 0);
    EXPECT_EQ(offsetof(SOCKADDR_IN6, sin6_port), 2);
    EXPECT_EQ(offsetof(SOCKADDR_IN6, sin6_flowinfo), 4);
    EXPECT_EQ(offsetof(SOCKADDR_IN6, sin6_addr), 8);
    EXPECT_EQ(offsetof(SOCKADDR_IN6, sin6_scope_id), 24);
}
TEST(ac_layout_sockaddr_storage_offsets) {
    EXPECT_EQ(offsetof(SOCKADDR_STORAGE, ss_family), 0);
    CHECK(offsetof(SOCKADDR_STORAGE, __ss_align) == 8);
    EXPECT_EQ(sizeof(((SOCKADDR_STORAGE *)0)->__ss_pad1), 6);
}
TEST(ac_layout_family_constants) {
    EXPECT_EQ(AF_UNSPEC, 0);
    EXPECT_EQ(AF_UNIX, 1);
    EXPECT_EQ(AF_INET, 2);
    EXPECT_EQ(AF_INET6, 23);
    EXPECT_EQ(AF_BTH, 32);
}

/* A bound socket reports a sockaddr whose fields sit at the documented offsets. */
TEST(ac_layout_getsockname_v4_bytes) {
    SOCKET s; unsigned char req[16], got[128]; static const unsigned char lo[4] = { 127, 0, 0, 1 };
    int len = sizeof got, r; unsigned port;
    if (!wsa_ready()) return;
    REQUIRE(U(bind)); REQUIRE(U(getsockname));
    s = mk(AF_INET, SOCK_DGRAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    ac_raw_v4(req, 0, lo);
    r = U(bind)(s, (SOCKADDR *)req, 16);
    EXPECT_EQ(r, 0);
    memset(got, 0xcd, sizeof got);
    r = U(getsockname)(s, (SOCKADDR *)got, &len);
    EXPECT_EQ(r, 0); EXPECT_EQ(len, 16);
    CHECK(got[0] == AF_INET && got[1] == 0);
    CHECK(got[4] == 127 && got[5] == 0 && got[6] == 0 && got[7] == 1);
    port = ((unsigned)got[2] << 8) | got[3];
    CHECK(port != 0);
    CHECK(U(ntohs)(*(u_short *)(got + 2)) == port);
    { int i, z = 1; for (i = 8; i < 16; i++) if (got[i]) z = 0; CHECK(z); }
    CHECK(got[16] == 0xcd); /* nothing written past the 16 bytes */
    U(closesocket)(s);
}

TEST(ac_layout_getsockname_v6_bytes) {
    SOCKET s; unsigned char req[28], got[128], ip[16] = {0}; int len = sizeof got, r; unsigned port;
    if (!wsa_ready()) return;
    REQUIRE(U(bind)); REQUIRE(U(getsockname));
    s = mk(AF_INET6, SOCK_DGRAM, 0); if (s == INVALID_SOCKET) { t_skip("no ipv6 socket"); return; }
    ip[15] = 1;
    ac_raw_v6(req, 0, 0, ip, 0);
    r = U(bind)(s, (SOCKADDR *)req, 28);
    if (r != 0) { t_skip("cannot bind ::1 (error %d)", U(WSAGetLastError)()); U(closesocket)(s); return; }
    memset(got, 0xcd, sizeof got);
    r = U(getsockname)(s, (SOCKADDR *)got, &len);
    EXPECT_EQ(r, 0); EXPECT_EQ(len, 28);
    CHECK(got[0] == AF_INET6 && got[1] == 0);
    CHECK(!memcmp(got + 8, ip, 16));
    port = ((unsigned)got[2] << 8) | got[3];
    CHECK(port != 0);
    CHECK(got[4] == 0 && got[5] == 0 && got[6] == 0 && got[7] == 0);       /* flow info */
    CHECK(got[24] == 0 && got[25] == 0 && got[26] == 0 && got[27] == 0);   /* scope id */
    CHECK(got[28] == 0xcd);
    U(closesocket)(s);
}

/* sin_zero is not interpreted by bind. */
TEST(ac_layout_bind_ignores_sin_zero) {
    SOCKET s; unsigned char req[16]; static const unsigned char lo[4] = { 127, 0, 0, 1 }; int r;
    if (!wsa_ready()) return;
    REQUIRE(U(bind));
    s = mk(AF_INET, SOCK_DGRAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    ac_raw_v4(req, 0, lo);
    memset(req + 8, 0xff, 8);
    r = U(bind)(s, (SOCKADDR *)req, 16); EXPECT_EQ(r, 0);
    U(closesocket)(s);
}

/* A text -> sockaddr -> bind -> getsockname -> text round trip keeps the host part. */
TEST(ac_layout_text_to_bound_name_roundtrip) {
    SOCKET s; unsigned char sa[28], got[128]; int len = 28, glen = sizeof got, r; DWORD slen = 64; char txt[64];
    if (!wsa_ready()) return;
    REQUIRE(U(bind)); REQUIRE(U(getsockname)); REQUIRE(AC_S2A_A); REQUIRE(AC_A2S_A);
    s = mk(AF_INET, SOCK_DGRAM, 0); if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    CHECK(AC_S2A_A("127.0.0.1", AF_INET, NULL, (LPSOCKADDR)sa, &len) == 0);
    r = U(bind)(s, (SOCKADDR *)sa, len); EXPECT_EQ(r, 0);
    r = U(getsockname)(s, (SOCKADDR *)got, &glen); EXPECT_EQ(r, 0);
    CHECK(AC_A2S_A((LPSOCKADDR)got, glen, NULL, txt, &slen) == 0);
    CHECK(!strncmp(txt, "127.0.0.1:", 10) && txt[10] != 0);
    U(closesocket)(s);
}
