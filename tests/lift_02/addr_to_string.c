/* WSAAddressToStringA / WSAAddressToStringW.
 * Measures: the size-query protocol (NULL or too-small buffer -> SOCKET_ERROR/WSAEFAULT and the
 * required length in characters, terminator included), the text for AF_INET (optional ":port"),
 * AF_INET6 (compression, "[addr]:port" form, "%scope"), and AF_BTH ("(AA:BB:..)" with optional
 * ":port"; only the low six bytes of the 8-byte address are shown), and that the A and W forms
 * agree. Socket address fields are given in network byte order, as the API expects. */
#include "l2.h"

typedef INT (WSAAPI *a2s_a_fn)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOA, LPSTR, LPDWORD);
typedef INT (WSAAPI *a2s_w_fn)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
#define A2S_A ((a2s_a_fn)t_proc_in("ws2_32.dll", "WSAAddressToStringA"))
#define A2S_W ((a2s_w_fn)t_proc_in("ws2_32.dll", "WSAAddressToStringW"))

static void set_v4(SOCKADDR_IN *sa, ULONG addr, USHORT port) {
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET; sa->sin_addr.s_addr = addr; sa->sin_port = port;
}

TEST(addr2str_v4_size_query_ansi) {
    a2s_a_fn f = A2S_A; SOCKADDR_IN sa; char out[64]; DWORD len = 0; INT r;
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    set_v4(&sa, 0, 0);
    U(WSASetLastError)(0);
    r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    EXPECT_EQ(len, 8); /* "0.0.0.0" + NUL */
}

TEST(addr2str_v4_size_query_wide_null_buffer) {
    a2s_w_fn f = A2S_W; SOCKADDR_IN sa; DWORD len = 0; INT r;
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    set_v4(&sa, 0, 0);
    U(WSASetLastError)(0);
    r = f((SOCKADDR *)&sa, sizeof sa, NULL, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    EXPECT_EQ(len, 8);
}

TEST(addr2str_v4_small_buffer_reports_required) {
    a2s_a_fn f = A2S_A; SOCKADDR_IN sa; char out[64]; DWORD len; INT r;
    REQUIRE(f); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    set_v4(&sa, 0xffffffff, 0xffff);
    len = 7; /* needs 22 for "255.255.255.255:65535" */
    U(WSASetLastError)(0);
    r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    EXPECT_EQ(len, 22);
}

TEST(addr2str_v4_exact_length_wide) {
    a2s_w_fn f = A2S_W; SOCKADDR_IN sa; WCHAR out[64]; DWORD len = 64; INT r;
    REQUIRE(f); L2_NEED_WSA();
    set_v4(&sa, 0, 0);
    memset(out, 0, sizeof out);
    r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
    EXPECT_EQ(r, 0); EXPECT_EQ(len, 8);
    CHECK(!wcscmp(out, L"0.0.0.0"));
}

static const struct { ULONG addr; USHORT port; const char *text; } v4_vec[] = {
    { 0, 0, "0.0.0.0" }, { 0xffffffff, 0, "255.255.255.255" },
    { 0, 0xffff, "0.0.0.0:65535" }, { 0xffffffff, 0xffff, "255.255.255.255:65535" },
};

TEST(addr2str_v4_vectors_ansi) {
    a2s_a_fn f = A2S_A; unsigned i;
    REQUIRE(f); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(v4_vec); i++) {
        SOCKADDR_IN sa; char out[64]; DWORD len = sizeof out; INT r;
        set_v4(&sa, v4_vec[i].addr, v4_vec[i].port);
        memset(out, 0, sizeof out);
        r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
        CHECKF(r == 0, "row %u failed", i);
        CHECKF(!strcmp(out, v4_vec[i].text), "row %u got \"%s\"", i, out);
        CHECKF(len == strlen(v4_vec[i].text) + 1, "row %u len %lu", i, len);
    }
}

TEST(addr2str_v4_vectors_wide) {
    a2s_w_fn f = A2S_W; unsigned i;
    REQUIRE(f); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(v4_vec); i++) {
        SOCKADDR_IN sa; WCHAR out[64], want[64]; DWORD len = L2_COUNT(out); INT r;
        set_v4(&sa, v4_vec[i].addr, v4_vec[i].port);
        l2_widen(v4_vec[i].text, want, L2_COUNT(want));
        memset(out, 0, sizeof out);
        r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
        CHECKF(r == 0, "row %u failed", i);
        CHECKF(!wcscmp(out, want), "row %u text differs", i);
        CHECKF(len == wcslen(want) + 1, "row %u len %lu", i, len);
    }
}

/* Words are stored as they sit in memory; the 8 groups are given in big-endian-agnostic form via bytes. */
static const struct { unsigned char addr[16]; ULONG scope; USHORT port; const char *text; } v6_vec[] = {
    { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 },             0,      0,      "::1" },
    { { 0x20,0xab,0,0,0,0,0,0,0,0,0,0,0,0,0,1 },       0,      0,      "20ab::1" },
    { { 0x20,0xab,0,0,0,0,0,0,0,0,0,0,0,0,0x20,0x01 }, 0,      0xfa81, "[20ab::2001]:33274" },
    { { 0x20,0xab,0,0,0,0,0,0,0,0,0,0,0,0,0x20,0x01 }, 0x1234, 0xfa81, "[20ab::2001%4660]:33274" },
    { { 0x20,0xab,0,0,0,0,0,0,0,0,0,0,0,0,0x20,0x01 }, 0x1234, 0,      "20ab::2001%4660" },
};

TEST(addr2str_v6_vectors_ansi) {
    a2s_a_fn f = A2S_A; unsigned i;
    REQUIRE(f); L2_NEED_WSA();
    if (!l2_have_ipv6()) { t_skip("IPv6 not available"); return; }
    for (i = 0; i < L2_COUNT(v6_vec); i++) {
        SOCKADDR_IN6 sa; char out[64]; DWORD len = sizeof out; INT r;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6; sa.sin6_scope_id = v6_vec[i].scope; sa.sin6_port = v6_vec[i].port;
        memcpy(sa.sin6_addr.s6_addr, v6_vec[i].addr, 16);
        r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
        CHECKF(r == 0, "row %u failed", i);
        CHECKF(!strcmp(out, v6_vec[i].text), "row %u got \"%s\"", i, out);
        CHECKF(len == strlen(v6_vec[i].text) + 1, "row %u len %lu", i, len);
    }
}

TEST(addr2str_v6_vectors_wide) {
    a2s_w_fn f = A2S_W; unsigned i;
    REQUIRE(f); L2_NEED_WSA();
    if (!l2_have_ipv6()) { t_skip("IPv6 not available"); return; }
    for (i = 0; i < L2_COUNT(v6_vec); i++) {
        SOCKADDR_IN6 sa; WCHAR out[64], want[64]; DWORD len = L2_COUNT(out); INT r;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6; sa.sin6_scope_id = v6_vec[i].scope; sa.sin6_port = v6_vec[i].port;
        memcpy(sa.sin6_addr.s6_addr, v6_vec[i].addr, 16);
        l2_widen(v6_vec[i].text, want, L2_COUNT(want));
        r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
        CHECKF(r == 0, "row %u failed", i);
        CHECKF(!wcscmp(out, want), "row %u text differs", i);
        CHECKF(len == wcslen(want) + 1, "row %u len %lu", i, len);
    }
}

static const struct { unsigned long long addr; ULONG port; const char *text; } bth_vec[] = {
    { 0, 0, "(00:00:00:00:00:00)" },
    { 0, 200, "(00:00:00:00:00:00):200" },
    { 0xdeadbeefcafeULL, 0, "(DE:AD:BE:EF:CA:FE)" },
    { 0xdeadbeefcafeULL, 4294967295UL, "(DE:AD:BE:EF:CA:FE):4294967295" },
    /* Only the low 48 bits of the 64-bit BTH_ADDR are formatted. */
    { 0xdeadbeefdeadbeefULL, 0, "(BE:EF:DE:AD:BE:EF)" },
    { 0xdeadbeefdeadbeefULL, 4294967295UL, "(BE:EF:DE:AD:BE:EF):4294967295" },
};

TEST(addr2str_bth_vectors_ansi) {
    a2s_a_fn f = A2S_A; unsigned i;
    REQUIRE(f); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(bth_vec); i++) {
        SOCKADDR_BTH sa; char out[64]; DWORD len = sizeof out; INT r;
        memset(&sa, 0, sizeof sa);
        sa.addressFamily = AF_BTH; sa.btAddr = bth_vec[i].addr; sa.port = bth_vec[i].port;
        r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
        CHECKF(r == 0, "row %u failed (err %d)", i, U(WSAGetLastError)());
        if (r) continue;
        CHECKF(!strcmp(out, bth_vec[i].text), "row %u got \"%s\"", i, out);
        CHECKF(len == strlen(bth_vec[i].text) + 1, "row %u len %lu", i, len);
    }
}

TEST(addr2str_bth_vectors_wide) {
    a2s_w_fn f = A2S_W; unsigned i;
    REQUIRE(f); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(bth_vec); i++) {
        SOCKADDR_BTH sa; WCHAR out[64], want[64]; DWORD len = L2_COUNT(out); INT r;
        memset(&sa, 0, sizeof sa);
        sa.addressFamily = AF_BTH; sa.btAddr = bth_vec[i].addr; sa.port = bth_vec[i].port;
        l2_widen(bth_vec[i].text, want, L2_COUNT(want));
        r = f((SOCKADDR *)&sa, sizeof sa, NULL, out, &len);
        CHECKF(r == 0, "row %u failed (err %d)", i, U(WSAGetLastError)());
        if (r) continue;
        CHECKF(!wcscmp(out, want), "row %u text differs", i);
        CHECKF(len == wcslen(want) + 1, "row %u len %lu", i, len);
    }
}
