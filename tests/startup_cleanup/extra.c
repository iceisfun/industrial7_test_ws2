/* Further startup/cleanup edge cases: a NULL WSADATA, last-error handling by WSACleanup, the WSADATA
 * struct layout, and repeatability of the version answer.
 *
 * The facts here that were observed on genuine Windows: a NULL data pointer yields WSAEFAULT for any
 * non-zero major byte (and WSAVERNOTSUPPORTED for a zero major byte, which is checked first); a
 * successful WSACleanup, whether or not it releases the last reference, leaves the thread's last error
 * at zero; a surplus WSACleanup fails with WSANOTINITIALISED. */
#include "sc.h"
#include <stddef.h>

/* ---- WSADATA layout (x64) ------------------------------------------------------------------------------- */
TEST(startup_wsadata_layout)
{
    EXPECT_EQ(offsetof(WSADATA, wVersion), 0);
    EXPECT_EQ(offsetof(WSADATA, wHighVersion), 2);
    EXPECT_EQ(offsetof(WSADATA, iMaxSockets), 4);
    EXPECT_EQ(offsetof(WSADATA, iMaxUdpDg), 6);
    EXPECT_EQ(offsetof(WSADATA, lpVendorInfo), 8);
    EXPECT_EQ(offsetof(WSADATA, szDescription), 16);
    EXPECT_EQ(offsetof(WSADATA, szSystemStatus), 16 + 257);
    EXPECT_EQ(sizeof(WSADATA), 408);
}

/* ---- NULL WSADATA --------------------------------------------------------------------------------------- */
/* argv[1] = major, argv[2] = minor */
CHILD(ex_null_data)
{
    unsigned lo = (unsigned)atoi(argv[1]), hi = (unsigned)atoi(argv[2]);
    int r = U(WSAStartup)(MAKEWORD(lo, hi), NULL);
    STEP(1, r == (lo == 0 ? WSAVERNOTSUPPORTED : WSAEFAULT));
    /* the stack is still usable by a proper startup afterwards, and balances */
    WSADATA d;
    STEP(2, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(3, d.wVersion == 0x0202);
    STEP(4, U(WSACleanup)() == 0);
    return 0;
}
#define NUL(lo, hi) TEST(startup_null_wsadata_##lo##_##hi) { REQUIRE(U(WSAStartup)); RUN_CHILD("ex_null_data", #lo " " #hi, 15000); }
NUL(0, 0) NUL(0, 1) NUL(0, 255) NUL(1, 0) NUL(1, 1) NUL(1, 255) NUL(2, 0) NUL(2, 2) NUL(2, 255) NUL(3, 0) NUL(255, 0) NUL(255, 255)

/* ---- WSACleanup and the last-error slot ----------------------------------------------------------------- */
/* argv[1] = major, argv[2] = minor of the (doubled) startup */
CHILD(ex_cleanup_clears_error)
{
    unsigned lo = (unsigned)atoi(argv[1]), hi = (unsigned)atoi(argv[2]);
    WSADATA d;
    STEP(1, U(WSAStartup)(MAKEWORD(lo, hi), &d) == 0);
    STEP(2, U(WSAStartup)(MAKEWORD(lo, hi), &d) == 0);
    SETWSAERR(0xdeadbeef);
    STEP(3, U(WSACleanup)() == 0);              /* not the last reference */
    STEP(4, WSAERR() == 0);
    SETWSAERR(0xdeadbeef);
    STEP(5, U(WSACleanup)() == 0);              /* the last reference */
    STEP(6, WSAERR() == 0);
    SETWSAERR(0xdeadbeef);
    STEP(7, U(WSACleanup)() == SOCKET_ERROR);
    STEP(8, WSAERR() == WSANOTINITIALISED);
    return 0;
}
#define CCE(lo, hi) TEST(startup_cleanup_resets_error_##lo##_##hi) { REQUIRE(U(WSAStartup)); RUN_CHILD("ex_cleanup_clears_error", #lo " " #hi, 15000); }
CCE(1, 0) CCE(1, 1) CCE(2, 0) CCE(2, 1) CCE(2, 2) CCE(2, 3) CCE(3, 0)

/* the failing surplus cleanup is repeatable and each time re-sets the slot */
CHILD(ex_surplus_repeat)
{
    for (int i = 0; i < 5; i++) {
        SETWSAERR(0x1000 + i);
        STEP(1, U(WSACleanup)() == SOCKET_ERROR);
        STEP(2, WSAERR() == WSANOTINITIALISED);
    }
    return 0;
}
TEST(startup_cleanup_surplus_repeatable) { REQUIRE(U(WSACleanup)); RUN_CHILD("ex_surplus_repeat", "", 15000); }

/* the same cleanup failure seen on a thread that never started anything */
static volatile LONG g_tc_ret = 99, g_tc_err;
static DWORD WINAPI th_surplus(LPVOID p)
{
    SETWSAERR(0);
    g_tc_ret = U(WSACleanup)();
    g_tc_err = WSAERR();
    return 0;
}
CHILD(ex_surplus_thread)
{
    HANDLE h = CreateThread(NULL, 0, th_surplus, NULL, 0, NULL);
    STEP(1, h != NULL);
    STEP(2, WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    STEP(3, g_tc_ret == SOCKET_ERROR && g_tc_err == WSANOTINITIALISED);
    return 0;
}
TEST(startup_cleanup_surplus_on_fresh_thread) { REQUIRE(U(WSACleanup)); RUN_CHILD("ex_surplus_thread", "", 15000); }

/* ---- the answer is repeatable and per call -------------------------------------------------------------- */
CHILD(ex_repeat_same)
{
    unsigned lo = (unsigned)atoi(argv[1]), hi = (unsigned)atoi(argv[2]);
    WSADATA a, b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    STEP(1, U(WSAStartup)(MAKEWORD(lo, hi), &a) == 0);
    STEP(2, U(WSAStartup)(MAKEWORD(lo, hi), &b) == 0);
    STEP(3, a.wVersion == b.wVersion && a.wHighVersion == b.wHighVersion);
    STEP(4, a.iMaxSockets == b.iMaxSockets && a.iMaxUdpDg == b.iMaxUdpDg);
    STEP(5, !strcmp(a.szDescription, b.szDescription) && !strcmp(a.szSystemStatus, b.szSystemStatus));
    STEP(6, U(WSACleanup)() == 0 && U(WSACleanup)() == 0);
    return 0;
}
#define RSM(lo, hi) TEST(startup_repeat_same_answer_##lo##_##hi) { REQUIRE(U(WSAStartup)); RUN_CHILD("ex_repeat_same", #lo " " #hi, 15000); }
RSM(1, 0) RSM(1, 1) RSM(2, 0) RSM(2, 1) RSM(2, 2) RSM(2, 9) RSM(7, 7)

/* ---- a failed startup does not disturb a live one -------------------------------------------------------- */
CHILD(ex_fail_while_live)
{
    WSADATA d;
    STEP(1, sc_up() == 0);
    SOCKET s = U(socket)(AF_INET, SOCK_STREAM, 0);
    STEP(2, s != INVALID_SOCKET);
    STEP(3, U(WSAStartup)(MAKEWORD(0, 0), &d) == WSAVERNOTSUPPORTED);
    STEP(4, U(WSAStartup)(MAKEWORD(2, 2), NULL) != 0);
    int t = 0, len = sizeof t;
    STEP(5, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&t, &len) == 0 && t == SOCK_STREAM);
    U(closesocket)(s);
    /* a NULL-data failure may or may not hold a reference; drain until the stack reports it is gone */
    for (int i = 0; i < 4 && U(WSACleanup)() == 0; i++) {}
    SETWSAERR(0);
    STEP(6, U(WSACleanup)() == SOCKET_ERROR && WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_failed_startup_leaves_live_stack_intact) { REQUIRE(U(WSAStartup)); RUN_CHILD("ex_fail_while_live", "", 15000); }

/* ---- closing a socket after the stack is gone ------------------------------------------------------------- */
CHILD(ex_close_after_cleanup)
{
    STEP(1, sc_up() == 0);
    SOCKET s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    STEP(2, s != INVALID_SOCKET);
    U(closesocket)(s);
    STEP(3, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(4, U(closesocket)(s) == SOCKET_ERROR);
    STEP(5, WSAERR() == WSANOTINITIALISED);
    SETWSAERR(0);
    STEP(6, U(closesocket)(SC_BOGUS_SOCKET) == SOCKET_ERROR);
    STEP(7, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_closesocket_after_cleanup_not_initialised) { REQUIRE(U(closesocket)); RUN_CHILD("ex_close_after_cleanup", "", 15000); }

/* ---- error constants of the startup family are distinct and stable ------------------------------------------ */
TEST(startup_status_codes_are_distinct)
{
    int v[] = { WSASYSNOTREADY, WSAVERNOTSUPPORTED, WSANOTINITIALISED, WSAEINPROGRESS, WSAEPROCLIM, WSAEFAULT };
    for (size_t i = 0; i < ARRSZ(v); i++)
        for (size_t j = i + 1; j < ARRSZ(v); j++) CHECK(v[i] != v[j]);
    EXPECT_EQ(WSAEPROCLIM, 10067);
}
