/* WSAStartup version negotiation and the WSADATA it fills in, one process per requested version.
 *
 * Measures, for a grid of requested (major, minor) pairs well beyond the usual 1.0/1.1/2.2 set:
 *   - the return value (0, or WSAVERNOTSUPPORTED only when the major byte is 0),
 *   - wVersion / wHighVersion / iMaxSockets / iMaxUdpDg,
 *   - that exactly the description and status strings are written (nothing past their terminators),
 *   - that lpVendorInfo is never touched,
 *   - that a failed negotiation still fills WSADATA yet takes no reference,
 *   - that two startups with different requests each get their own answer.
 * The rules reproduced here: major 0 fails; major 1 answers 1.0 only for minor 0, else 1.1; major 2 echoes
 * minors 0..2 and answers 2.2 for anything higher; any major above 2 answers 2.2 and succeeds. */
#include "sc.h"

static WORD want_version(unsigned lo, unsigned hi)
{
    if (lo == 1) return hi == 0 ? 0x0001 : 0x0101;
    if (lo == 2 && hi <= 2) return (WORD)((hi << 8) | 2);
    return 0x0202;
}

static int want_ret(unsigned lo) { return lo == 0 ? WSAVERNOTSUPPORTED : 0; }

/* argv[1] = major byte, argv[2] = minor byte (decimal) */
CHILD(ver_grid)
{
    if (argc < 3) return 90;
    unsigned lo = (unsigned)atoi(argv[1]), hi = (unsigned)atoi(argv[2]);
    WORD ask = MAKEWORD(lo, hi);
    WSADATA d;
    char marker = 0;
    memset(&d, 0xcc, sizeof d);
    d.lpVendorInfo = &marker;
    STEP(91, U(WSAStartup) && U(WSACleanup));

    int r = U(WSAStartup)(ask, &d);
    STEP(1, r == want_ret(lo));
    STEP(2, d.wVersion == want_version(lo, hi));
    STEP(3, d.wHighVersion == 0x0202);
    STEP(4, d.iMaxSockets == (lo == 1 ? 32767 : 0));
    STEP(5, d.iMaxUdpDg == (lo == 1 ? 65467 : 0));
    STEP(6, d.lpVendorInfo == &marker);
    /* strings: terminated, and the bytes behind the terminator are still the fill pattern */
    size_t n1 = strlen(d.szDescription), n2 = strlen(d.szSystemStatus);
    STEP(7, n1 < sizeof d.szDescription && n2 < sizeof d.szSystemStatus);
    STEP(8, n1 > 0 && n2 > 0);
    /* whether the bytes behind the terminators are left alone is an implementation detail: observe only */
    for (size_t i = n1 + 1; i < sizeof d.szDescription; i++) SOFT((unsigned char)d.szDescription[i] == 0xcc, "szDescription tail bytes were rewritten");
    for (size_t i = n2 + 1; i < sizeof d.szSystemStatus; i++) SOFT((unsigned char)d.szSystemStatus[i] == 0xcc, "szSystemStatus tail bytes were rewritten");
    STEP(11, !strcmp(d.szDescription, "WinSock 2.0") && !strcmp(d.szSystemStatus, "Running"));

    if (lo == 0) {
        /* no reference was taken: nothing to clean up */
        SETWSAERR(0);
        STEP(12, U(WSACleanup)() == SOCKET_ERROR);
        STEP(13, WSAERR() == WSANOTINITIALISED);
        return 0;
    }
    /* a second startup with a different request answers on its own terms */
    WSADATA e;
    memset(&e, 0xcc, sizeof e);
    STEP(14, U(WSAStartup)(MAKEWORD(2, 2), &e) == 0);
    STEP(15, e.wVersion == 0x0202 && e.wHighVersion == 0x0202);
    STEP(16, e.iMaxSockets == 0 && e.iMaxUdpDg == 0);
    STEP(17, U(WSACleanup)() == 0);
    STEP(18, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(19, U(WSACleanup)() == SOCKET_ERROR);
    STEP(20, WSAERR() == WSANOTINITIALISED);
    return 0;
}

#define VG(lo, hi) TEST(startup_ver_grid_##lo##_##hi) { REQUIRE(U(WSAStartup)); RUN_CHILD("ver_grid", #lo " " #hi, 20000); }
#define VG_ROW(lo) VG(lo, 0) VG(lo, 1) VG(lo, 2) VG(lo, 3) VG(lo, 127) VG(lo, 255)
VG_ROW(0) VG_ROW(1) VG_ROW(2) VG_ROW(3) VG_ROW(4) VG_ROW(16) VG_ROW(128) VG_ROW(255)

/* ---- the answer does not depend on what an earlier startup in the same process asked for ---------------- */
static const WORD kSeq[] = { 0x0101, 0x0202, 0x0002, 0x0001, 0x0102, 0x0302, 0x0000, 0x0201, 0xffff };

/* argv[1] = index of the first request; each later request is answered independently of earlier ones. */
CHILD(ver_sequence)
{
    int start = argc > 1 ? atoi(argv[1]) : 0;
    int ok = 0;
    for (size_t k = 0; k < ARRSZ(kSeq); k++) {
        WORD ask = kSeq[(start + k) % ARRSZ(kSeq)];
        WSADATA d;
        memset(&d, 0, sizeof d);
        int r = U(WSAStartup)(ask, &d);
        unsigned lo = LOBYTE(ask), hi = HIBYTE(ask);
        STEP(1 + (int)k, r == want_ret(lo));
        STEP(20 + (int)k, d.wVersion == want_version(lo, hi));
        if (r == 0) ok++;
    }
    for (int i = 0; i < ok; i++) STEP(40, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(41, U(WSACleanup)() == SOCKET_ERROR);
    STEP(42, WSAERR() == WSANOTINITIALISED);
    return 0;
}
#define VSEQ(n) TEST(startup_ver_sequence_##n) { REQUIRE(U(WSAStartup)); RUN_CHILD("ver_sequence", #n, 20000); }
VSEQ(0) VSEQ(1) VSEQ(2) VSEQ(3) VSEQ(4) VSEQ(5) VSEQ(6) VSEQ(7) VSEQ(8)

/* ---- WSAVERNOTSUPPORTED leaves WSADATA fully populated ---------------------------------------------------- */
TEST(startup_ver_zero_major_still_fills_wsadata)
{
    REQUIRE(U(WSAStartup));
    /* In-process is safe: a refused request takes no reference. */
    WSADATA d;
    memset(&d, 0, sizeof d);
    int r = U(WSAStartup)(0x0000, &d);
    EXPECT_EQ(r, WSAVERNOTSUPPORTED);
    EXPECT_EQ(d.wVersion, 0x0202);
    EXPECT_EQ(d.wHighVersion, 0x0202);
    EXPECT_STR(d.szDescription, "WinSock 2.0");
    EXPECT_STR(d.szSystemStatus, "Running");
}

TEST(startup_ver_zero_major_any_minor_refused)
{
    REQUIRE(U(WSAStartup));
    for (unsigned hi = 0; hi < 256; hi += 5) {
        WSADATA d;
        memset(&d, 0, sizeof d);
        int r = U(WSAStartup)(MAKEWORD(0, hi), &d);
        CHECKF(r == WSAVERNOTSUPPORTED, "minor %u gave %d", hi, r);
        CHECKF(d.wVersion == 0x0202, "minor %u wVersion %04x", hi, d.wVersion);
    }
}

CHILD(ver_refused_no_ref)
{
    WSADATA d;
    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(2, U(WSAStartup)(MAKEWORD(0, 5), &d) == WSAVERNOTSUPPORTED);
    STEP(3, U(WSACleanup)() == 0);          /* releases the one real reference */
    SETWSAERR(0);
    STEP(4, U(WSACleanup)() == SOCKET_ERROR);   /* the refused request added none */
    STEP(5, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_ver_refused_request_takes_no_reference) { REQUIRE(U(WSAStartup)); RUN_CHILD("ver_refused_no_ref", "", 15000); }

/* ---- all fields of a successful startup, 2.2 case, compared as one image ------------------------------ */
TEST(startup_ver_2_2_full_image)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    WSADATA d;
    memset(&d, 0x5a, sizeof d);
    EXPECT_EQ(U(WSAStartup)(MAKEWORD(2, 2), &d), 0);
    EXPECT_EQ(d.wVersion, 0x0202);
    EXPECT_EQ(d.wHighVersion, 0x0202);
    EXPECT_EQ(d.iMaxSockets, 0);
    EXPECT_EQ(d.iMaxUdpDg, 0);
    EXPECT_STR(d.szDescription, "WinSock 2.0");
    EXPECT_STR(d.szSystemStatus, "Running");
    /* lpVendorInfo is not written by WSAStartup */
    EXPECT_EQ((ULONG_PTR)d.lpVendorInfo, (ULONG_PTR)0x5a5a5a5a5a5a5a5aULL);
    EXPECT_EQ(U(WSACleanup)(), 0);
}

TEST(startup_ver_2_0_echoes_minor)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    WSADATA d;
    EXPECT_EQ(U(WSAStartup)(MAKEWORD(2, 0), &d), 0);
    EXPECT_EQ(d.wVersion, MAKEWORD(2, 0));
    EXPECT_EQ(d.wHighVersion, MAKEWORD(2, 2));
    EXPECT_EQ(U(WSACleanup)(), 0);
}

TEST(startup_ver_2_1_echoes_minor)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    WSADATA d;
    EXPECT_EQ(U(WSAStartup)(MAKEWORD(2, 1), &d), 0);
    EXPECT_EQ(d.wVersion, MAKEWORD(2, 1));
    EXPECT_EQ(U(WSACleanup)(), 0);
}

TEST(startup_ver_2_ff_caps_at_2_2)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    WSADATA d;
    EXPECT_EQ(U(WSAStartup)(MAKEWORD(2, 255), &d), 0);
    EXPECT_EQ(d.wVersion, MAKEWORD(2, 2));
    EXPECT_EQ(U(WSACleanup)(), 0);
}

TEST(startup_ver_major_above_2_succeeds_with_2_2)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    /* Unlike the usual reading of the docs, a higher major version does not fail: it negotiates down. */
    for (unsigned lo = 3; lo < 256; lo += 12) {
        WSADATA d;
        memset(&d, 0, sizeof d);
        int r = U(WSAStartup)(MAKEWORD(lo, 1), &d);
        CHECKF(r == 0, "major %u gave %d", lo, r);
        CHECKF(d.wVersion == 0x0202, "major %u wVersion %04x", lo, d.wVersion);
        if (r == 0) U(WSACleanup)();
    }
}

/* ---- the version word arrives in the right byte order: low byte is the major version ------------------- */
TEST(startup_ver_byte_order_is_major_in_low_byte)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    WSADATA d;
    /* 0x0200 would be "major 0, minor 2" and must be refused; 0x0002 is 2.0 and accepted */
    EXPECT_EQ(U(WSAStartup)(0x0200, &d), WSAVERNOTSUPPORTED);
    EXPECT_EQ(U(WSAStartup)(0x0002, &d), 0);
    EXPECT_EQ(d.wVersion, 0x0002);
    EXPECT_EQ(U(WSACleanup)(), 0);
}

TEST(startup_ver_high_version_constant)
{
    REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup));
    static const WORD asks[] = { 0x0002, 0x0102, 0x0202, 0x0502, 0x0302 };
    for (size_t i = 0; i < ARRSZ(asks); i++) {
        WSADATA d;
        memset(&d, 0, sizeof d);
        CHECK(U(WSAStartup)(asks[i], &d) == 0);
        CHECKF(d.wHighVersion == 0x0202, "ask %04x high %04x", asks[i], d.wHighVersion);
        U(WSACleanup)();
    }
}
