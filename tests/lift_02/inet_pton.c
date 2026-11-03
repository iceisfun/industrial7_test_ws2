/* inet_pton / InetPtonW / inet_ntop: presentation <-> binary address conversion.
 * Measures: strict dotted-quad-only parsing for AF_INET, the RFC-style IPv6 grammar (embedded IPv4,
 * "::" compression, group-width limits), the exact return codes (1 / 0 / -1) and WinSock errors
 * (WSAEFAULT, WSAEAFNOSUPPORT, WSAEINVAL for the wide form), which output bytes a failing parse has
 * already written, and the buffer-size protocol of inet_ntop. */
#include "l2.h"
#include "vec_inet.h"

typedef INT (WSAAPI *pton_a_fn)(INT, PCSTR, PVOID);
typedef INT (WSAAPI *pton_w_fn)(INT, PCWSTR, PVOID);
typedef PCSTR (WSAAPI *ntop_a_fn)(INT, const VOID *, PSTR, size_t);

#define PTON_A ((pton_a_fn)t_proc_in("ws2_32.dll", "inet_pton"))
#define PTON_W ((pton_w_fn)t_proc_in("ws2_32.dll", "InetPtonW"))
#define NTOP_A ((ntop_a_fn)t_proc_in("ws2_32.dll", "inet_ntop"))

TEST(inet_pton_null_text_is_efault) {
    unsigned char buf[32];
    pton_a_fn pa = PTON_A; pton_w_fn pw = PTON_W;
    int ret;
    REQUIRE(pa); REQUIRE(pw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    U(WSASetLastError)(0x1234); ret = pa(AF_UNSPEC, NULL, buf);
    EXPECT_EQ(ret, -1); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    U(WSASetLastError)(0x1234); ret = pa(AF_INET, NULL, buf);
    EXPECT_EQ(ret, -1); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    U(WSASetLastError)(0x1234); ret = pw(AF_UNSPEC, NULL, buf);
    EXPECT_EQ(ret, -1); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
    U(WSASetLastError)(0x1234); ret = pw(AF_INET, NULL, buf);
    EXPECT_EQ(ret, -1); EXPECT_EQ(U(WSAGetLastError)(), WSAEFAULT);
}

TEST(inet_pton_unspec_family_is_afnosupport) {
    unsigned char buf[32];
    pton_a_fn pa = PTON_A;
    int ret;
    REQUIRE(pa); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    U(WSASetLastError)(0x1234); ret = pa(AF_UNSPEC, "127.0.0.1", buf);
    EXPECT_EQ(ret, -1); EXPECT_EQ(U(WSAGetLastError)(), WSAEAFNOSUPPORT);
    U(WSASetLastError)(0x1234); ret = pa(AF_UNSPEC, "2607:f0d0:1002:51::4", buf);
    EXPECT_EQ(ret, -1); EXPECT_EQ(U(WSAGetLastError)(), WSAEAFNOSUPPORT);
}

/* ANSI form: the error state is not touched at all, success or not. */
TEST(inet_pton_v4_ansi_table) {
    pton_a_fn pa = PTON_A;
    unsigned i;
    REQUIRE(pa); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(pton4_vec); i++) {
        unsigned long out = L2_SENTINEL; int ret;
        U(WSASetLastError)(0x1234);
        ret = pa(AF_INET, pton4_vec[i].text, &out);
        CHECKF(ret == pton4_vec[i].ret, "row %u \"%s\": ret %d want %d", i, pton4_vec[i].text, ret, pton4_vec[i].ret);
        CHECKF(U(WSAGetLastError)() == 0x1234, "row %u \"%s\": error changed to %d", i, pton4_vec[i].text, U(WSAGetLastError)());
        CHECKF(out == pton4_vec[i].raw, "row %u \"%s\": out %08lx want %08lx", i, pton4_vec[i].text, out, pton4_vec[i].raw);
    }
}

/* Wide form: same results and output bytes, but a failure sets WSAEINVAL. */
TEST(inet_pton_v4_wide_table) {
    pton_w_fn pw = PTON_W;
    unsigned i;
    REQUIRE(pw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(pton4_vec); i++) {
        WCHAR w[64]; unsigned long out = L2_SENTINEL; int ret, err;
        l2_widen(pton4_vec[i].text, w, L2_COUNT(w));
        U(WSASetLastError)(0x1234);
        ret = pw(AF_INET, w, &out);
        err = U(WSAGetLastError)();
        CHECKF(ret == pton4_vec[i].ret, "row %u \"%s\": ret %d want %d", i, pton4_vec[i].text, ret, pton4_vec[i].ret);
        CHECKF(err == (ret ? 0x1234 : WSAEINVAL), "row %u \"%s\": error %d", i, pton4_vec[i].text, err);
        CHECKF(out == pton4_vec[i].raw, "row %u \"%s\": out %08lx want %08lx", i, pton4_vec[i].text, out, pton4_vec[i].raw);
    }
}

TEST(inet_pton_v6_ansi_table) {
    pton_a_fn pa = PTON_A;
    unsigned i;
    REQUIRE(pa); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(pton6_vec); i++) {
        unsigned char out[16], want[16]; int ret;
        memset(out, 0xab, sizeof out);
        if (pton6_vec[i].hex[0] != '?') l2_unhex(pton6_vec[i].hex, want, 16);
        U(WSASetLastError)(0x1234);
        ret = pa(AF_INET6, pton6_vec[i].text, out);
        CHECKF(ret == pton6_vec[i].ret, "row %u \"%s\": ret %d want %d", i, pton6_vec[i].text, ret, pton6_vec[i].ret);
        CHECKF(U(WSAGetLastError)() == 0x1234, "row %u \"%s\": error changed to %d", i, pton6_vec[i].text, U(WSAGetLastError)());
        CHECKF(pton6_vec[i].hex[0] == '?' || !memcmp(out, want, 16), "row %u \"%s\": output bytes differ", i, pton6_vec[i].text);
    }
}

TEST(inet_pton_v6_wide_table) {
    pton_w_fn pw = PTON_W;
    unsigned i;
    REQUIRE(pw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(pton6_vec); i++) {
        WCHAR w[96]; unsigned char out[16], want[16]; int ret, err;
        memset(out, 0xab, sizeof out);
        if (pton6_vec[i].hex[0] != '?') l2_unhex(pton6_vec[i].hex, want, 16);
        l2_widen(pton6_vec[i].text, w, L2_COUNT(w));
        U(WSASetLastError)(0x1234);
        ret = pw(AF_INET6, w, out);
        err = U(WSAGetLastError)();
        CHECKF(ret == pton6_vec[i].ret, "row %u \"%s\": ret %d want %d", i, pton6_vec[i].text, ret, pton6_vec[i].ret);
        CHECKF(err == (ret ? 0x1234 : WSAEINVAL), "row %u \"%s\": error %d", i, pton6_vec[i].text, err);
        CHECKF(pton6_vec[i].hex[0] == '?' || !memcmp(out, want, 16), "row %u \"%s\": output bytes differ", i, pton6_vec[i].text);
    }
}

/* ---- inet_ntop ---- */

static const unsigned char ntop_v6_mapped[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xfe,0xcc,0x98,0xbd,0x74 };
static const unsigned char ntop_v6_prefix[16]  = { 0x20,0x30,0xa4,0xb1 };
static const unsigned char ntop_v6_compat[16]  = { 0,0,0,0,0,0,0,0,0,0,0,0,0xcc,0x98,0xbd,0x74 };

TEST(inet_ntop_v4_basic) {
    unsigned long raw0 = 0, raw1 = 0x20201015UL;
    char buf[16]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt);
    L2_NEED_WSA();
    r = nt(AF_INET, &raw0, buf, sizeof buf);
    CHECK(r == buf); if (r) EXPECT_STR(r, "0.0.0.0");
    r = nt(AF_INET, &raw1, buf, sizeof buf);
    CHECK(r == buf); if (r) EXPECT_STR(r, "21.16.32.32");
}

TEST(inet_ntop_v4_larger_length_ok) {
    unsigned long raw = 0x20201015UL; char buf[32]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt);
    L2_NEED_WSA();
    r = nt(AF_INET, &raw, buf, 17);
    CHECK(r != NULL); if (r) EXPECT_STR(r, "21.16.32.32");
}

TEST(inet_ntop_unsupported_family) {
    unsigned long raw = 0x20201015UL; char buf[16]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    U(WSASetLastError)(0);
    r = nt(1, &raw, buf, sizeof buf);
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEAFNOSUPPORT);
}

/* Bad destination / size: reported as WSAEINVAL on Windows 10. */
TEST(inet_ntop_v4_bad_destination) {
    unsigned long raw = 0x20201015UL; char buf[16]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    U(WSASetLastError)(0);
    r = nt(AF_INET, &raw, NULL, sizeof buf);
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
    U(WSASetLastError)(0);
    r = nt(AF_INET, &raw, buf, 0);
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
    U(WSASetLastError)(0);
    r = nt(AF_INET, &raw, buf, 6); /* "21.16.32.32" needs 12 */
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
}

TEST(inet_ntop_v6_text_forms) {
    char buf[64]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt);
    L2_NEED_WSA();
    r = nt(AF_INET6, ntop_v6_mapped, buf, sizeof buf);
    CHECK(r != NULL); if (r) EXPECT_STR(r, "::fffe:cc98:bd74");
    r = nt(AF_INET6, ntop_v6_prefix, buf, sizeof buf);
    CHECK(r != NULL); if (r) EXPECT_STR(r, "2030:a4b1::");
    /* IPv4-compatible form is printed with an embedded dotted quad. */
    r = nt(AF_INET6, ntop_v6_compat, buf, sizeof buf);
    CHECK(r != NULL); if (r) EXPECT_STR(r, "::204.152.189.116");
}

TEST(inet_ntop_v6_bad_destination) {
    char buf[64]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    L2_NEED_WSA();
    U(WSASetLastError)(0);
    r = nt(AF_INET6, ntop_v6_mapped, NULL, sizeof buf);
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
    U(WSASetLastError)(0);
    r = nt(AF_INET6, ntop_v6_mapped, buf, 0);
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
    U(WSASetLastError)(0);
    r = nt(AF_INET6, ntop_v6_mapped, buf, 16); /* "::fffe:cc98:bd74" needs 17 */
    CHECK(r == NULL); EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
}

TEST(inet_ntop_v6_larger_length_ok) {
    char buf[64]; const char *r;
    ntop_a_fn nt = NTOP_A;
    REQUIRE(nt);
    L2_NEED_WSA();
    r = nt(AF_INET6, ntop_v6_mapped, buf, 18);
    CHECK(r != NULL);
}
