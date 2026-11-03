/* WSAEnumProtocolsA / WSAEnumProtocolsW: the installed transport protocol catalog.
 * Measures: the buffer-size protocol (NULL / zero-length buffer -> SOCKET_ERROR + WSAENOBUFS and the
 * required size), that the returned list has names, hides PFL_HIDDEN entries and reports the fixed
 * service-flag sets for TCP and UDP over IP, and that a protocol filter list restricts the result to
 * the requested protocol numbers (unknown numbers are simply absent, not an error). */
#include "l2.h"

#define TCP_FLAGS (XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE | XP1_EXPEDITED_DATA | XP1_IFS_HANDLES)
#define UDP_FLAGS (XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED | XP1_SUPPORT_BROADCAST | XP1_SUPPORT_MULTIPOINT | XP1_IFS_HANDLES)

/* Filter list: two real protocols between unassigned ones, terminated by 0. */
static INT filter_list[] = { 0xdead, IPPROTO_TCP, 0xcafe, IPPROTO_UDP, 0xbeef, 0 };

typedef INT (WSAAPI *enum_a_fn)(LPINT, LPWSAPROTOCOL_INFOA, LPDWORD);
typedef INT (WSAAPI *enum_w_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD);

static void check_service_flags(int family, int version, int type, int proto, DWORD flags) {
    DWORD want = 0;
    if (type == SOCK_STREAM && proto == IPPROTO_TCP) want = TCP_FLAGS;
    if (type == SOCK_DGRAM && proto == IPPROTO_UDP) want = UDP_FLAGS;
    if ((family == AF_INET || family == AF_INET6) && version == 2 && want) {
        flags &= ~XP1_QOS_SUPPORTED; /* QOS support depends on installed components */
        CHECKF(flags == want, "family %d type %d proto %d flags %lx want %lx", family, type, proto, flags, want);
    }
}

/* One template instantiated for the ANSI and wide structure types. */
#define ENUM_TESTS(sfx, FN, INFO, NAMELEN) \
TEST(enum_protocols_##sfx##_null_buffer_enobufs) { \
    enum_##sfx##_fn f = (enum_##sfx##_fn)t_proc_in("ws2_32.dll", FN); \
    DWORD len = 0; INT r; \
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA(); \
    U(WSASetLastError)(0); \
    r = f(NULL, NULL, &len); \
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS); \
    CHECK(len > 0); \
} \
TEST(enum_protocols_##sfx##_zero_length_enobufs) { \
    enum_##sfx##_fn f = (enum_##sfx##_fn)t_proc_in("ws2_32.dll", FN); \
    INFO one; DWORD len = 0; INT r; \
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA(); \
    memset(&one, 0, sizeof one); \
    U(WSASetLastError)(0); \
    r = f(NULL, &one, &len); \
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS); \
    CHECK(len >= sizeof(INFO)); \
} \
TEST(enum_protocols_##sfx##_full_list) { \
    enum_##sfx##_fn f = (enum_##sfx##_fn)t_proc_in("ws2_32.dll", FN); \
    DWORD len = 0; INT n, i; INFO *buf; \
    REQUIRE(f); L2_NEED_WSA(); \
    f(NULL, NULL, &len); \
    buf = (INFO *)HeapAlloc(GetProcessHeap(), 0, len); \
    REQUIRE(buf); \
    n = f(NULL, buf, &len); \
    CHECK(n > 0); \
    for (i = 0; i < n; i++) { \
        CHECKF(buf[i].szProtocol[0] != 0, "entry %d has no name", i); \
        CHECKF(!(buf[i].dwProviderFlags & PFL_HIDDEN), "entry %d is hidden", i); \
        check_service_flags(buf[i].iAddressFamily, buf[i].iVersion, buf[i].iSocketType, buf[i].iProtocol, buf[i].dwServiceFlags1); \
    } \
    HeapFree(GetProcessHeap(), 0, buf); \
} \
TEST(enum_protocols_##sfx##_filter_null_buffer_enobufs) { \
    enum_##sfx##_fn f = (enum_##sfx##_fn)t_proc_in("ws2_32.dll", FN); \
    DWORD len = 0; INT r; \
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA(); \
    U(WSASetLastError)(0); \
    r = f(filter_list, NULL, &len); \
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAENOBUFS); \
} \
TEST(enum_protocols_##sfx##_filter_selects_requested) { \
    enum_##sfx##_fn f = (enum_##sfx##_fn)t_proc_in("ws2_32.dll", FN); \
    DWORD len = 0; INT n, i, j, found = 0; INFO *buf; \
    REQUIRE(f); L2_NEED_WSA(); \
    f(filter_list, NULL, &len); \
    buf = (INFO *)HeapAlloc(GetProcessHeap(), 0, len); \
    REQUIRE(buf); \
    n = f(filter_list, buf, &len); \
    CHECKF(n >= 2, "only %d entries", n); \
    for (i = 0; i < n; i++) \
        for (j = 0; j < (int)L2_COUNT(filter_list); j++) \
            if (buf[i].iProtocol == filter_list[j]) { found |= 1 << j; break; } \
    /* Only the TCP and UDP slots (1 and 3) are populated; nothing else matched. */ \
    EXPECT_EQ(found, 0x0A); \
    HeapFree(GetProcessHeap(), 0, buf); \
}
ENUM_TESTS(a, "WSAEnumProtocolsA", WSAPROTOCOL_INFOA, 256)
ENUM_TESTS(w, "WSAEnumProtocolsW", WSAPROTOCOL_INFOW, 256)

/* The ANSI and wide catalogs describe the same entries in the same order. */
TEST(enum_protocols_a_w_same_count) {
    enum_a_fn fa = (enum_a_fn)t_proc_in("ws2_32.dll", "WSAEnumProtocolsA");
    enum_w_fn fw = (enum_w_fn)t_proc_in("ws2_32.dll", "WSAEnumProtocolsW");
    DWORD la = 0, lw = 0; INT na, nw, i;
    WSAPROTOCOL_INFOA *a; WSAPROTOCOL_INFOW *w;
    REQUIRE(fa); REQUIRE(fw); L2_NEED_WSA();
    fa(NULL, NULL, &la); fw(NULL, NULL, &lw);
    a = HeapAlloc(GetProcessHeap(), 0, la); w = HeapAlloc(GetProcessHeap(), 0, lw);
    if (a && w) {
        na = fa(NULL, a, &la); nw = fw(NULL, w, &lw);
        EXPECT_EQ(na, nw);
        for (i = 0; i < na && i < nw; i++) {
            CHECKF(a[i].iProtocol == w[i].iProtocol && a[i].iAddressFamily == w[i].iAddressFamily &&
                   a[i].iSocketType == w[i].iSocketType && a[i].dwCatalogEntryId == w[i].dwCatalogEntryId,
                   "entry %d differs between A and W", i);
        }
    }
    if (a) HeapFree(GetProcessHeap(), 0, a);
    if (w) HeapFree(GetProcessHeap(), 0, w);
}
