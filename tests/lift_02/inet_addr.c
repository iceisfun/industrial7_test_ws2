/* inet_addr / inet_ntoa: the legacy dotted-quad parser and formatter.
 * Measures: which spellings inet_addr accepts (decimal/octal/hex parts, short forms, whitespace
 * tails), what it returns for everything else (INADDR_NONE), that it never touches the thread's
 * WinSock error on parse failure, and that inet_ntoa keeps
 * a per-thread result buffer. */
#include "l2.h"
#include "vec_inet.h"

TEST(inet_addr_vector_table) {
    unsigned i;
    REQUIRE(U(inet_addr)); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(addr_vec); i++) {
        unsigned long r;
        U(WSASetLastError)(0x1234);
        r = U(inet_addr)(addr_vec[i].text);
        CHECKF(r == addr_vec[i].raw, "row %u \"%s\": got %08lx want %08lx", i, addr_vec[i].text, r, addr_vec[i].raw);
        /* A parse result, valid or INADDR_NONE, never goes through WSASetLastError. */
        CHECKF(U(WSAGetLastError)() == 0x1234, "row %u \"%s\": error changed to %d", i, addr_vec[i].text, U(WSAGetLastError)());
    }
}

/* inet_addr(NULL) faults on Windows 10 rather than failing with WSAEFAULT, so it is not exercised. */

/* "1.2.3" followed by one extra byte: only white space after the last component is tolerated. */
TEST(inet_addr_trailing_byte_sweep) {
    unsigned c;
    REQUIRE(U(inet_addr));
    L2_NEED_WSA();
    for (c = 1; c < 256; c++) {
        char s[8] = "1.2.3";
        unsigned long r, want;
        int space = (c >= 9 && c <= 13) || c == 32;
        if (c >= '0' && c <= '9') continue;
        s[5] = (char)c; s[6] = 0;
        want = space ? 0x03000201UL : 0xffffffffUL;
        r = U(inet_addr)(s);
        CHECKF(r == want, "trailing byte 0x%02x: got %08lx want %08lx", c, r, want);
    }
}

TEST(inet_addr_broadcast_is_none_alias) {
    /* 255.255.255.255 and the failure value coincide; both yield all-ones. */
    REQUIRE(U(inet_addr));
    L2_NEED_WSA();
    EXPECT_EQ(U(inet_addr)("255.255.255.255"), 0xffffffffUL);
    EXPECT_EQ(U(inet_addr)("255.255.255.254"), 0xfeffffffUL);
}

TEST(inet_ntoa_vectors) {
    static const struct { unsigned long raw; const char *text; } v[] = {
        { 0x00000000UL, "0.0.0.0" }, { 0x20201015UL, "21.16.32.32" }, { 0x0100007fUL, "127.0.0.1" },
        { 0xffffffffUL, "255.255.255.255" }, { 0x04030201UL, "1.2.3.4" },
    };
    unsigned i;
    REQUIRE(U(inet_ntoa));
    L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(v); i++) {
        struct in_addr a; const char *s;
        a.s_addr = v[i].raw;
        s = U(inet_ntoa)(a);
        CHECKF(s != NULL, "row %u null", i);
        if (s) CHECKF(!strcmp(s, v[i].text), "row %u got \"%s\" want \"%s\"", i, s, v[i].text);
    }
}

TEST(inet_ntoa_inet_addr_roundtrip) {
    struct in_addr a; const char *s;
    REQUIRE(U(inet_ntoa)); REQUIRE(U(inet_addr));
    L2_NEED_WSA();
    a.s_addr = U(inet_addr)("1.2.3.4");
    EXPECT_EQ(a.s_addr, l2_swap32(0x01020304UL));
    s = U(inet_ntoa)(a);
    CHECK(s && !strcmp(s, "1.2.3.4"));
}

/* inet_ntoa returns a thread-private buffer: another thread's call must not disturb it. */
struct ntoa_ctx { HANDLE ready, go; int ok; };
static DWORD WINAPI ntoa_worker(void *p) {
    struct ntoa_ctx *c = p;
    struct in_addr a;
    const char *s;
    a.s_addr = U(inet_addr)("4.3.2.1");
    s = U(inet_ntoa)(a);
    c->ok = (a.s_addr == l2_swap32(0x04030201UL)) && s && !strcmp(s, "4.3.2.1");
    SetEvent(c->ready);
    WaitForSingleObject(c->go, 5000);
    return 0;
}

TEST(inet_ntoa_buffer_is_per_thread) {
    struct ntoa_ctx c; struct in_addr a; const char *mine; HANDLE th;
    REQUIRE(U(inet_ntoa)); REQUIRE(U(inet_addr));
    L2_NEED_WSA();
    a.s_addr = U(inet_addr)("1.2.3.4");
    mine = U(inet_ntoa)(a);
    CHECK(mine && !strcmp(mine, "1.2.3.4"));
    c.ok = 0;
    c.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    c.go = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, ntoa_worker, &c, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        EXPECT_EQ(WaitForSingleObject(c.ready, 5000), WAIT_OBJECT_0);
        CHECK(c.ok);
        CHECK(mine && !strcmp(mine, "1.2.3.4")); /* untouched by the other thread's call */
        SetEvent(c.go);
        EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
        CloseHandle(th);
    }
    CloseHandle(c.ready); CloseHandle(c.go);
}
