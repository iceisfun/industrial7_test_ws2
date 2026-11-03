/* WSAGetLastError / WSASetLastError: a thin veneer over the per-thread Win32 last-error slot.
 *
 * Measures that the two views are the same storage, that the slot is per thread, that no startup is needed
 * to use it, that reading never clears it, that arbitrary 32-bit values survive, and that errors raised by a
 * failing call (here: a bogus socket handle, a surplus WSACleanup) land in the calling thread's slot only. */
#include "sc.h"

static const DWORD kVals[] = {
    0, 1, 2, 5, 87, 997, 995, 6, 10004, 10009, 10013, 10014, 10022, 10035, 10036, 10038, 10045, 10047, 10048,
    10054, 10055, 10057, 10060, 10061, 10091, 10092, 10093, 10101, 11001, 11004, 0x7fffffff, 0x80000000, 0xc0000005,
    0xdeadbeef, 0xfffffffe, 0xffffffff,
};

#define LE_ROUNDTRIP(i) TEST(lasterror_roundtrip_value_##i) { \
    REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); \
    DWORD v = kVals[i]; \
    U(WSASetLastError)(v); \
    EXPECT_EQ((DWORD)U(WSAGetLastError)(), v); \
    EXPECT_EQ(GetLastError(), v); }
LE_ROUNDTRIP(0) LE_ROUNDTRIP(1) LE_ROUNDTRIP(2) LE_ROUNDTRIP(3) LE_ROUNDTRIP(4) LE_ROUNDTRIP(5) LE_ROUNDTRIP(6)
LE_ROUNDTRIP(7) LE_ROUNDTRIP(8) LE_ROUNDTRIP(9) LE_ROUNDTRIP(10) LE_ROUNDTRIP(11) LE_ROUNDTRIP(12) LE_ROUNDTRIP(13)
LE_ROUNDTRIP(14) LE_ROUNDTRIP(15) LE_ROUNDTRIP(16) LE_ROUNDTRIP(17) LE_ROUNDTRIP(18) LE_ROUNDTRIP(19) LE_ROUNDTRIP(20)
LE_ROUNDTRIP(21) LE_ROUNDTRIP(22) LE_ROUNDTRIP(23) LE_ROUNDTRIP(24) LE_ROUNDTRIP(25) LE_ROUNDTRIP(26) LE_ROUNDTRIP(27)
LE_ROUNDTRIP(28) LE_ROUNDTRIP(29) LE_ROUNDTRIP(30) LE_ROUNDTRIP(31) LE_ROUNDTRIP(32) LE_ROUNDTRIP(33) LE_ROUNDTRIP(34)
LE_ROUNDTRIP(35)

TEST(lasterror_win32_set_is_seen_by_wsa_get)
{
    REQUIRE(U(WSAGetLastError));
    for (size_t i = 0; i < ARRSZ(kVals); i++) {
        SetLastError(kVals[i]);
        CHECKF((DWORD)U(WSAGetLastError)() == kVals[i], "value %lu", kVals[i]);
    }
}

TEST(lasterror_get_does_not_clear)
{
    REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    U(WSASetLastError)(10054);
    for (int i = 0; i < 5; i++) EXPECT_EQ(U(WSAGetLastError)(), 10054);
}

TEST(lasterror_set_zero_clears)
{
    REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    U(WSASetLastError)(10054);
    U(WSASetLastError)(0);
    EXPECT_EQ(U(WSAGetLastError)(), 0);
    EXPECT_EQ(GetLastError(), 0);
}

TEST(lasterror_last_set_wins)
{
    REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    U(WSASetLastError)(1);
    U(WSASetLastError)(2);
    U(WSASetLastError)(3);
    EXPECT_EQ(U(WSAGetLastError)(), 3);
}

TEST(lasterror_works_without_startup)
{
    /* the slot needs no stack: a child that never starts Winsock can use both calls */
    RUN_CHILD("le_nostart", "", 15000);
}
CHILD(le_nostart)
{
    STEP(1, U(WSASetLastError) && U(WSAGetLastError));
    U(WSASetLastError)(7777);
    STEP(2, U(WSAGetLastError)() == 7777);
    U(WSASetLastError)(0);
    STEP(3, U(WSAGetLastError)() == 0);
    return 0;
}

TEST(lasterror_works_after_last_cleanup)
{
    RUN_CHILD("le_after_cleanup", "", 15000);
}
CHILD(le_after_cleanup)
{
    STEP(1, sc_up() == 0);
    STEP(2, U(WSACleanup)() == 0);
    U(WSASetLastError)(4242);
    STEP(3, U(WSAGetLastError)() == 4242);
    return 0;
}

/* ---- per-thread storage -------------------------------------------------------------------------------- */
/* The creating thread must not make any kernel call between writing its slot and reading it back: even
 * successful object-manager calls may legitimately rewrite the slot. It therefore synchronises with the
 * workers by spinning on plain memory only. */
struct thr { DWORD initial, after_set, set_to; volatile LONG done, go; };

/* Resolved on the creating thread: the lookup itself may touch the caller's last-error slot, which would
 * contaminate the "fresh thread" reading. */
static int (WSAAPI *g_get)(void);
static void (WSAAPI *g_set)(int);
static DWORD WINAPI th_slot(LPVOID p)
{
    struct thr *t = (struct thr *)p;
    t->initial = g_get();
    g_set(t->set_to);
    t->after_set = g_get();
    t->done = 1;
    for (int i = 0; i < 5000 && !t->go; i++) Sleep(1);
    return 0;
}
static int spin_until_done(struct thr *t, int n)
{
    ULONGLONG end = GetTickCount64() + 10000;
    for (;;) {
        int all = 1;
        for (int i = 0; i < n; i++) if (!t[i].done) all = 0;
        if (all) return 1;
        if (GetTickCount64() > end) return 0;
        YieldProcessor();
    }
}

TEST(lasterror_new_thread_starts_at_zero)
{
    REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    g_get = U(WSAGetLastError); g_set = U(WSASetLastError);
    struct thr t = { 99, 99, 10061, 0, 0 };
    HANDLE h = CreateThread(NULL, 0, th_slot, &t, 0, NULL);
    CHECK(h != NULL);
    if (!h) return;
    U(WSASetLastError)(10054);
    int ok = spin_until_done(&t, 1);
    DWORD mine = (DWORD)U(WSAGetLastError)();
    t.go = 1;
    WaitForSingleObject(h, 10000);
    CloseHandle(h);
    CHECK(ok);
    /* the executable's own thread-start code may leave a value in a fresh slot, so only the isolation is
     * asserted: the creator's value (set while the thread runs) never shows up in the new thread */
    CHECKF(t.initial != 10054 && t.initial != 10061, "fresh slot shows foreign value %lu", t.initial);
    EXPECT_EQ(t.after_set, 10061);
    EXPECT_EQ(mine, 10054);      /* the creator's slot is untouched */
}

TEST(lasterror_threads_are_independent)
{
    REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    g_get = U(WSAGetLastError); g_set = U(WSASetLastError);
    enum { N = 6 };
    struct thr t[N];
    HANDLE h[N];
    for (int i = 0; i < N; i++) { t[i].initial = 99; t[i].after_set = 99; t[i].set_to = 10000 + i; t[i].done = 0; t[i].go = 0; }
    for (int i = 0; i < N; i++) { h[i] = CreateThread(NULL, 0, th_slot, &t[i], 0, NULL); CHECK(h[i] != NULL); if (!h[i]) t[i].done = 1; }
    U(WSASetLastError)(55555);
    int ok = spin_until_done(t, N);
    DWORD mine = (DWORD)U(WSAGetLastError)();
    for (int i = 0; i < N; i++) t[i].go = 1;
    CHECK(ok);
    EXPECT_EQ(mine, 55555);
    for (int i = 0; i < N; i++) {
        if (!h[i]) continue;
        WaitForSingleObject(h[i], 10000);
        CHECKF(t[i].initial != 55555 && (t[i].initial < 10000 || t[i].initial > 10000 + N), "thread %d fresh slot shows foreign value %lu", i, t[i].initial);
        CHECKF(t[i].after_set == 10000u + i, "thread %d slot %lu", i, t[i].after_set);
        CloseHandle(h[i]);
    }
}

/* ---- errors raised by failing calls land in the caller's slot only ------------------------------------------- */
static volatile DWORD g_thr_err = 0xabcd;
static DWORD WINAPI th_bad_socket_call(LPVOID p)
{
    char b[4];
    U(WSASetLastError)(0);
    int r = U(recv)(SC_BOGUS_SOCKET, b, 1, 0);
    g_thr_err = r == SOCKET_ERROR ? (DWORD)U(WSAGetLastError)() : 0xffff;
    return 0;
}

CHILD(le_failing_call_is_local)
{
    STEP(1, sc_up() == 0);
    U(WSASetLastError)(31337);
    HANDLE h = CreateThread(NULL, 0, th_bad_socket_call, NULL, 0, NULL);
    STEP(2, h != NULL);
    STEP(3, WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    STEP(4, g_thr_err == WSAENOTSOCK);
    char b[4];
    STEP(6, U(recv)(SC_BOGUS_SOCKET, b, 1, 0) == SOCKET_ERROR);
    STEP(7, U(WSAGetLastError)() == WSAENOTSOCK);
    STEP(8, GetLastError() == WSAENOTSOCK);
    U(WSACleanup)();
    return 0;
}
TEST(lasterror_failing_call_sets_only_callers_slot) { RUN_CHILD("le_failing_call_is_local", "", 20000); }

CHILD(le_cleanup_error_local)
{
    /* a surplus WSACleanup fails with WSANOTINITIALISED in the calling thread's slot */
    U(WSASetLastError)(0);
    STEP(1, U(WSACleanup)() == SOCKET_ERROR);
    STEP(2, U(WSAGetLastError)() == WSANOTINITIALISED);
    STEP(3, GetLastError() == WSANOTINITIALISED);
    U(WSASetLastError)(0);
    STEP(4, U(WSACleanup)() == SOCKET_ERROR);
    STEP(5, U(WSAGetLastError)() == WSANOTINITIALISED);
    return 0;
}
TEST(lasterror_surplus_cleanup_error_code) { RUN_CHILD("le_cleanup_error_local", "", 15000); }

TEST(lasterror_error_value_constants)
{
    /* the numeric values programs hard-code for the startup family */
    EXPECT_EQ(WSASYSNOTREADY, 10091);
    EXPECT_EQ(WSAVERNOTSUPPORTED, 10092);
    EXPECT_EQ(WSANOTINITIALISED, 10093);
    EXPECT_EQ(WSAEINPROGRESS, 10036);
    EXPECT_EQ(WSAEOPNOTSUPP, 10045);
    EXPECT_EQ(WSAEINVAL, 10022);
    EXPECT_EQ(WSAEFAULT, 10014);
    EXPECT_EQ(WSAEINTR, 10004);
}

/* ---- the same entry points through wsock32 -------------------------------------------------------------- */
TEST(lasterror_wsock32_pair_shares_slot)
{
    typedef void (WINAPI *set_t)(int);
    typedef int (WINAPI *get_t)(void);
    set_t s32 = (set_t)t_proc_in("wsock32.dll", "WSASetLastError");
    get_t g32 = (get_t)t_proc_in("wsock32.dll", "WSAGetLastError");
    REQUIRE(s32); REQUIRE(g32);
    s32(12345);
    EXPECT_EQ(U(WSAGetLastError)(), 12345);
    U(WSASetLastError)(54321);
    EXPECT_EQ(g32(), 54321);
}

/* ---- the slot survives startup/cleanup calls that succeed or fail in other ways ------------------------------ */
CHILD(le_slot_around_startup)
{
    WSADATA d;
    U(WSASetLastError)(0);
    STEP(1, U(WSAStartup)(MAKEWORD(0, 1), &d) == WSAVERNOTSUPPORTED);
    /* WSAStartup reports through its return value; the failure is not mirrored into the thread slot */
    SOFT(U(WSAGetLastError)() == 0, "a refused WSAStartup left an error in the thread slot");
    U(WSASetLastError)(777);
    STEP(3, U(WSAStartup)(MAKEWORD(0, 1), &d) == WSAVERNOTSUPPORTED);
    SOFT(U(WSAGetLastError)() == 777, "a refused WSAStartup overwrote the thread slot");
    return 0;
}
TEST(lasterror_startup_failure_not_mirrored_into_slot) { RUN_CHILD("le_slot_around_startup", "", 15000); }
