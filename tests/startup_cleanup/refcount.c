/* WSAStartup / WSACleanup reference counting: nesting depth, interleaving, cross-thread use, restart cycles.
 *
 * The count is per process, not per thread: a startup made on one thread is released by a cleanup on any
 * other, and every thread can use the stack once one startup is outstanding. Reaching zero tears the stack
 * down; a cleanup past zero fails with WSANOTINITIALISED. Each scenario runs in its own child so the count
 * begins at zero. */
#include "sc.h"

static int mk_sock(int type)
{
    SOCKET s = U(socket)(AF_INET, type, 0);
    if (s == INVALID_SOCKET) return 0;
    U(closesocket)(s);
    return 1;
}

/* ---- nesting depth ------------------------------------------------------------------------------------------ */
CHILD(rc_depth)
{
    int n = argc > 1 ? atoi(argv[1]) : 1;
    WSADATA d;
    for (int i = 0; i < n; i++) STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    for (int i = 0; i < n; i++) {
        STEP(2, mk_sock(SOCK_STREAM));   /* stack alive until the last reference is gone */
        STEP(3, U(WSACleanup)() == 0);
    }
    SETWSAERR(0);
    STEP(4, U(WSACleanup)() == SOCKET_ERROR);
    STEP(5, WSAERR() == WSANOTINITIALISED);
    SETWSAERR(0);
    STEP(6, U(socket)(AF_INET, SOCK_STREAM, 0) == INVALID_SOCKET);
    STEP(7, WSAERR() == WSANOTINITIALISED);
    return 0;
}
#define RCD(n) TEST(startup_refcount_depth_##n) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_depth", #n, 30000); }
RCD(1) RCD(2) RCD(3) RCD(4) RCD(5) RCD(8) RCD(16) RCD(31) RCD(32) RCD(33) RCD(64) RCD(100) RCD(255) RCD(256) RCD(257) RCD(1000)

/* ---- the stack stays alive exactly while the count is above zero ------------------------------------------- */
CHILD(rc_alive_until_zero)
{
    int n = argc > 1 ? atoi(argv[1]) : 3;
    WSADATA d;
    for (int i = 0; i < n; i++) STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    for (int left = n; left > 0; left--) {
        STEP(2, mk_sock(SOCK_DGRAM));
        STEP(3, U(WSACleanup)() == 0);
        SETWSAERR(0);
        SOCKET s = U(socket)(AF_INET, SOCK_DGRAM, 0);
        if (left > 1) { STEP(4, s != INVALID_SOCKET); U(closesocket)(s); }
        else { STEP(5, s == INVALID_SOCKET); STEP(6, WSAERR() == WSANOTINITIALISED); }
    }
    return 0;
}
#define RCA(n) TEST(startup_refcount_alive_until_zero_##n) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_alive_until_zero", #n, 30000); }
RCA(1) RCA(2) RCA(3) RCA(6) RCA(20)

/* ---- interleaved startups and cleanups -------------------------------------------------------------------- */
CHILD(rc_interleave)
{
    /* argv[1]: pattern of '+' (startup) and '-' (cleanup); the running count never goes below zero */
    const char *p = argc > 1 ? argv[1] : "+-";
    WSADATA d;
    int depth = 0, step = 10;
    for (; *p; p++, step++) {
        if (*p == '+') { STEP(step, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0); depth++; }
        else if (*p == '-') { STEP(step, U(WSACleanup)() == 0); depth--; }
        if (depth > 0) STEP(step + 100, mk_sock(SOCK_STREAM));
    }
    while (depth-- > 0) STEP(2, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(3, U(WSACleanup)() == SOCKET_ERROR);
    STEP(4, WSAERR() == WSANOTINITIALISED);
    return 0;
}
#define RCI(id, pat) TEST(startup_refcount_interleave_##id) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_interleave", pat, 20000); }
RCI(a, "+-+-+-") RCI(b, "++--") RCI(c, "+++---") RCI(d, "++-+-+--") RCI(e, "+-++-") RCI(f, "+++-+++---")
RCI(g, "++++++++-------") RCI(h, "+") RCI(i, "++") RCI(j, "+-+-+-+-+-+-+-+-+-+-")

/* ---- full teardown and restart ---------------------------------------------------------------------------- */
CHILD(rc_restart_cycles)
{
    int cycles = argc > 1 ? atoi(argv[1]) : 10;
    WSADATA d;
    for (int i = 0; i < cycles; i++) {
        STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
        SOCKET s = U(socket)(AF_INET, SOCK_STREAM, 0);
        STEP(2, s != INVALID_SOCKET);
        STEP(3, U(WSACleanup)() == 0);           /* destroys s with the stack */
        STEP(4, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
        int t = 0, len = sizeof t;
        SETWSAERR(0);
        STEP(5, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&t, &len) == SOCKET_ERROR);   /* old handle is dead */
        STEP(6, WSAERR() == WSAENOTSOCK);
        STEP(7, U(WSACleanup)() == 0);
    }
    return 0;
}
#define RCR(n) TEST(startup_refcount_restart_cycles_##n) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_restart_cycles", #n, 60000); }
RCR(1) RCR(2) RCR(10) RCR(40)

/* ---- reference count is per process: threads ------------------------------------------------------------- */
static DWORD WINAPI th_cleanup(LPVOID p) { *(int *)p = U(WSACleanup)(); return 0; }
static DWORD WINAPI th_startup(LPVOID p)
{
    WSADATA d;
    *(int *)p = U(WSAStartup)(MAKEWORD(2, 2), &d);
    return 0;
}
static DWORD WINAPI th_socket(LPVOID p)
{
    *(int *)p = mk_sock(SOCK_STREAM);
    return 0;
}
static int run_thread(LPTHREAD_START_ROUTINE f, int *out)
{
    HANDLE h = CreateThread(NULL, 0, f, out, 0, NULL);
    if (!h) return 0;
    int ok = WaitForSingleObject(h, 15000) == WAIT_OBJECT_0;
    CloseHandle(h);
    return ok;
}

CHILD(rc_cleanup_from_other_thread)
{
    WSADATA d;
    int res = -2;
    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(2, run_thread(th_cleanup, &res));
    STEP(3, res == 0);                       /* a thread that never called WSAStartup may release the reference */
    SETWSAERR(0);
    STEP(4, U(WSACleanup)() == SOCKET_ERROR);
    STEP(5, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_refcount_cleanup_from_other_thread) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_cleanup_from_other_thread", "", 30000); }

CHILD(rc_startup_in_thread_used_in_main)
{
    int res = -2;
    STEP(1, run_thread(th_startup, &res));
    STEP(2, res == 0);
    STEP(3, mk_sock(SOCK_STREAM));           /* the thread has exited; its startup still counts */
    STEP(4, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(5, U(WSACleanup)() == SOCKET_ERROR);
    STEP(6, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_refcount_startup_in_exited_thread_persists) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_startup_in_thread_used_in_main", "", 30000); }

CHILD(rc_other_thread_uses_stack)
{
    int res = 0;
    STEP(1, sc_up() == 0);
    STEP(2, run_thread(th_socket, &res));
    STEP(3, res == 1);
    STEP(4, U(WSACleanup)() == 0);
    return 0;
}
TEST(startup_refcount_other_thread_uses_stack) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_other_thread_uses_stack", "", 30000); }

CHILD(rc_thread_without_startup_before)
{
    int res = 1;
    SETWSAERR(0);
    STEP(1, run_thread(th_socket, &res));
    STEP(2, res == 0);                       /* nothing started in this process yet */
    return 0;
}
TEST(startup_refcount_thread_before_any_startup_fails) { REQUIRE(U(socket)); RUN_CHILD("rc_thread_without_startup_before", "", 30000); }

/* many threads hammer startup/cleanup pairs; the count must balance exactly */
#define NTHR 8
static volatile LONG g_pair_fail;
static DWORD WINAPI th_pairs(LPVOID p)
{
    WSADATA d;
    int iters = (int)(INT_PTR)p;
    for (int i = 0; i < iters; i++) {
        if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) InterlockedIncrement(&g_pair_fail);
        if (!mk_sock(SOCK_STREAM)) InterlockedIncrement(&g_pair_fail);
        if (U(WSACleanup)() != 0) InterlockedIncrement(&g_pair_fail);
    }
    return 0;
}
CHILD(rc_concurrent_pairs)
{
    HANDLE h[NTHR];
    WSADATA d;
    STEP(1, sc_up() == 0);                    /* keep the stack alive so teardown is not raced */
    for (int i = 0; i < NTHR; i++) { h[i] = CreateThread(NULL, 0, th_pairs, (LPVOID)(INT_PTR)60, 0, NULL); STEP(2, h[i] != NULL); }
    STEP(3, WaitForMultipleObjects(NTHR, h, TRUE, 30000) == WAIT_OBJECT_0);
    for (int i = 0; i < NTHR; i++) CloseHandle(h[i]);
    STEP(4, g_pair_fail == 0);
    STEP(5, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(6, U(WSACleanup)() == SOCKET_ERROR);
    STEP(7, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_refcount_concurrent_pairs_balance) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_concurrent_pairs", "", 60000); }

/* the same, but without a holder: full teardown races with the next startup and must never fail */
CHILD(rc_concurrent_pairs_no_holder)
{
    HANDLE h[NTHR];
    for (int i = 0; i < NTHR; i++) { h[i] = CreateThread(NULL, 0, th_pairs, (LPVOID)(INT_PTR)40, 0, NULL); STEP(1, h[i] != NULL); }
    STEP(2, WaitForMultipleObjects(NTHR, h, TRUE, 30000) == WAIT_OBJECT_0);
    for (int i = 0; i < NTHR; i++) CloseHandle(h[i]);
    STEP(3, g_pair_fail == 0);
    SETWSAERR(0);
    STEP(4, U(WSACleanup)() == SOCKET_ERROR);
    STEP(5, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_refcount_concurrent_pairs_with_full_teardown) { REQUIRE(U(WSAStartup)); RUN_CHILD("rc_concurrent_pairs_no_holder", "", 60000); }

/* ---- forwarders in wsock32 are the same functions ---------------------------------------------------------- */
static const char *const kFwd[] = { "WSAStartup", "WSACleanup", "WSAGetLastError", "WSASetLastError", "WSAIsBlocking",
                                    "WSASetBlockingHook", "WSAUnhookBlockingHook", "WSACancelBlockingCall" };
TEST(startup_wsock32_forwarders_resolve_to_ws2_32)
{
    for (size_t i = 0; i < ARRSZ(kFwd); i++) {
        FARPROC a = t_proc_in("ws2_32.dll", kFwd[i]), b = t_proc_in("wsock32.dll", kFwd[i]);
        if (!a || !b) { t_skip("missing %s", kFwd[i]); continue; }
        CHECKF(a == b, "%s differs between ws2_32 and wsock32", kFwd[i]);
    }
}

/* Startup through wsock32 and cleanup through ws2_32 share one count. */
CHILD(rc_mixed_modules)
{
    WSADATA d;
    typedef int (WINAPI *su_t)(WORD, LPWSADATA);
    typedef int (WINAPI *cu_t)(void);
    su_t su32 = (su_t)t_proc_in("wsock32.dll", "WSAStartup");
    cu_t cu32 = (cu_t)t_proc_in("wsock32.dll", "WSACleanup");
    STEP(1, su32 && cu32);
    STEP(2, su32(MAKEWORD(2, 2), &d) == 0);
    STEP(3, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(4, cu32() == 0);
    STEP(5, mk_sock(SOCK_STREAM));
    STEP(6, U(WSACleanup)() == 0);
    SETWSAERR(0);
    STEP(7, cu32() == SOCKET_ERROR);
    STEP(8, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_refcount_wsock32_and_ws2_32_share_count) { REQUIRE(t_proc_in("wsock32.dll", "WSAStartup")); RUN_CHILD("rc_mixed_modules", "", 30000); }
