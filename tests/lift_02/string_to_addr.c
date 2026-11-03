/* WSAStringToAddressA / WSAStringToAddressW.
 * Measures: the size-query protocol (zero length -> WSAEFAULT and the required sockaddr size), the
 * AF_INET grammar (1-4 numeric parts, decimal/octal/hex, optional ":port" with its own base rules,
 * rejection of white space, stray characters and out-of-range parts), the AF_INET6 grammar (brackets,
 * ":port", embedded groups), the exact error (WSAEINVAL) and what is left in the output sockaddr and
 * length on failure: the structure is zeroed apart from fields the parser had already stored. */
#include "l2.h"
#include "vec_s2a.h"

typedef INT (WSAAPI *s2a_a_fn)(LPSTR, INT, LPWSAPROTOCOL_INFOA, LPSOCKADDR, LPINT);
typedef INT (WSAAPI *s2a_w_fn)(LPWSTR, INT, LPWSAPROTOCOL_INFOW, LPSOCKADDR, LPINT);
#define S2A_A ((s2a_a_fn)t_proc_in("ws2_32.dll", "WSAStringToAddressA"))
#define S2A_W ((s2a_w_fn)t_proc_in("ws2_32.dll", "WSAStringToAddressW"))

TEST(str2addr_v4_zero_length_reports_size) {
    s2a_a_fn f = S2A_A; SOCKADDR_IN sa; int len = 0, r;
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    U(WSASetLastError)(0);
    r = f((LPSTR)"1.1.1.1", AF_INET, NULL, (SOCKADDR *)&sa, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    CHECK(len >= (int)sizeof(sa));
}

/* mode 0 = ANSI, 1 = wide */
static void run_v4(int mode) {
    s2a_a_fn fa = S2A_A; s2a_w_fn fw = S2A_W;
    unsigned i;
    for (i = 0; i < L2_COUNT(s2a4_vec); i++) {
        SOCKADDR_IN sa; WCHAR w[64]; int len = (int)sizeof(sa) + 10, want_len, r, err;
        want_len = s2a4_vec[i].err ? len : (int)sizeof(sa);
        memset(&sa, 0xab, sizeof sa);
        U(WSASetLastError)(0);
        if (mode == 0) r = fa((LPSTR)s2a4_vec[i].text, AF_INET, NULL, (SOCKADDR *)&sa, &len);
        else { l2_widen(s2a4_vec[i].text, w, L2_COUNT(w)); r = fw(w, AF_INET, NULL, (SOCKADDR *)&sa, &len); }
        err = U(WSAGetLastError)();
        CHECKF(r == (s2a4_vec[i].err ? SOCKET_ERROR : 0), "row %u \"%s\": ret %d", i, s2a4_vec[i].text, r);
        CHECKF(err == s2a4_vec[i].err, "row %u \"%s\": error %d", i, s2a4_vec[i].text, err);
        CHECKF(sa.sin_family == (s2a4_vec[i].err ? 0 : AF_INET), "row %u \"%s\": family %#x", i, s2a4_vec[i].text, sa.sin_family);
        CHECKF(sa.sin_addr.s_addr == l2_swap32(s2a4_vec[i].addr), "row %u \"%s\": addr %08lx", i, s2a4_vec[i].text, sa.sin_addr.s_addr);
        CHECKF(sa.sin_port == l2_swap16(s2a4_vec[i].port), "row %u \"%s\": port %u", i, s2a4_vec[i].text, sa.sin_port);
        CHECKF(len == want_len, "row %u \"%s\": len %d", i, s2a4_vec[i].text, len);
    }
}

TEST(str2addr_v4_ansi_table) {
    REQUIRE(S2A_A); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    run_v4(0);
}

TEST(str2addr_v4_wide_table) {
    REQUIRE(S2A_W); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    run_v4(1);
}

static void run_v6(int mode) {
    s2a_a_fn fa = S2A_A; s2a_w_fn fw = S2A_W;
    unsigned i;
    for (i = 0; i < L2_COUNT(s2a6_vec); i++) {
        SOCKADDR_IN6 sa; WCHAR w[96]; unsigned char want[16];
        int len = (int)sizeof(sa) + 10, want_len, r, err;
        want_len = s2a6_vec[i].err ? len : (int)sizeof(sa);
        if (s2a6_vec[i].hex[0] != '?') l2_unhex(s2a6_vec[i].hex, want, 16);
        memset(&sa, 0xab, sizeof sa);
        U(WSASetLastError)(0);
        if (mode == 0) r = fa((LPSTR)s2a6_vec[i].text, AF_INET6, NULL, (SOCKADDR *)&sa, &len);
        else { l2_widen(s2a6_vec[i].text, w, L2_COUNT(w)); r = fw(w, AF_INET6, NULL, (SOCKADDR *)&sa, &len); }
        err = U(WSAGetLastError)();
        CHECKF(r == (s2a6_vec[i].err ? SOCKET_ERROR : 0), "row %u \"%s\": ret %d", i, s2a6_vec[i].text, r);
        CHECKF(err == s2a6_vec[i].err, "row %u \"%s\": error %d", i, s2a6_vec[i].text, err);
        CHECKF(s2a6_vec[i].hex[0] == '?' || !memcmp(&sa.sin6_addr, want, 16), "row %u \"%s\": address bytes differ", i, s2a6_vec[i].text);
        CHECKF(sa.sin6_family == (s2a6_vec[i].err ? 0 : AF_INET6), "row %u \"%s\": family %#x", i, s2a6_vec[i].text, sa.sin6_family);
        CHECKF(len == want_len, "row %u \"%s\": len %d", i, s2a6_vec[i].text, len);
        CHECKF(sa.sin6_scope_id == 0, "row %u \"%s\": scope %lu", i, s2a6_vec[i].text, sa.sin6_scope_id);
        CHECKF(sa.sin6_port == s2a6_vec[i].port, "row %u \"%s\": port %u", i, s2a6_vec[i].text, sa.sin6_port);
        CHECKF(sa.sin6_flowinfo == 0, "row %u \"%s\": flowinfo %lu", i, s2a6_vec[i].text, sa.sin6_flowinfo);
    }
}

TEST(str2addr_v6_ansi_table) {
    REQUIRE(S2A_A); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    if (!l2_have_ipv6()) { t_skip("IPv6 not available"); return; }
    run_v6(0);
}

TEST(str2addr_v6_wide_table) {
    REQUIRE(S2A_W); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    if (!l2_have_ipv6()) { t_skip("IPv6 not available"); return; }
    run_v6(1);
}
