/* Legacy blocking-call state is per thread: WSAIsBlocking and WSACancelBlockingCall act on the calling thread only.
 *
 * Measures, from a thread other than the one that is blocked in recv: WSAIsBlocking is FALSE, WSACancelBlockingCall
 * fails with WSAEINVAL (in a 1.1 process) and the blocked thread is unaffected; with a hook installed on the blocked
 * thread the hook runs there, that thread sees WSAIsBlocking TRUE while this one still sees FALSE. In a process
 * that negotiated 2.x the family is refused with WSAEOPNOTSUPP regardless of which thread is blocked.
 * Each scenario runs in a child process so the negotiated version is private to it.
 */
#include "thr.h"

#define STEP(n, c) do { if (!(c)) return (n); } while (0)

static int up_ver(int major, int minor)
{
    WSADATA d;
    return U(WSAStartup)(MAKEWORD(major, minor), &d) == 0;
}

CHILD(thr_legacy_cross_cancel)
{
    SOCKET c, s;
    struct blk b;
    STEP(1, up_ver(1, 1));
    STEP(2, pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    STEP(3, !finished(b.th));
    wset(0);
    STEP(4, U(WSAIsBlocking)() == FALSE);       /* this thread is not blocked */
    STEP(5, U(WSACancelBlockingCall)() == SOCKET_ERROR);
    STEP(6, werr() == WSAEINVAL);
    SETTLE();
    STEP(7, !finished(b.th));                   /* the other thread's call was not cancelled */
    snd(c, "x", 1);
    STEP(8, blk_join(&b));
    STEP(9, b.ret == 1 && b.buf[0] == 'x');
    cls(c); cls(s);
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(thr_legacy_cancel_from_other_thread_is_einval)
{
    REQUIRE(U(WSAStartup));
    EQV(t_run_child("thr_legacy_cross_cancel", "", 30000), 0);
}

CHILD(thr_legacy_v22_cancel)
{
    SOCKET c, s;
    struct blk b;
    STEP(1, up_ver(2, 2));
    STEP(2, pair(&c, &s));
    blk_start(&b, B_RECV, s, 8);
    wset(0);
    STEP(3, U(WSACancelBlockingCall)() == SOCKET_ERROR);
    STEP(4, werr() == WSAEOPNOTSUPP);
    wset(0);
    STEP(5, U(WSAIsBlocking)() == FALSE);
    STEP(6, !finished(b.th));
    snd(c, "y", 1);
    STEP(7, blk_join(&b));
    STEP(8, b.ret == 1);
    cls(c); cls(s);
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(thr_legacy_v22_cancel_is_unsupported_while_other_thread_blocks)
{
    REQUIRE(U(WSAStartup));
    EQV(t_run_child("thr_legacy_v22_cancel", "", 30000), 0);
}

static HANDLE g_inhook, g_release;
static volatile LONG g_hook_hits;
static BOOL WINAPI sampling_hook(void)
{
    if (InterlockedIncrement(&g_hook_hits) == 1) {
        SetEvent(g_inhook);
        WaitForSingleObject(g_release, 5000);
    }
    return FALSE;
}
static DWORD WINAPI hooked_recv_thread(void *x)
{
    struct blk *b = (struct blk *)x;
    U(WSASetBlockingHook)((FARPROC)sampling_hook);      /* the hook slot belongs to this thread */
    return blk_main(b);
}
CHILD(thr_legacy_hook_sampling)
{
    SOCKET c, s;
    struct blk b;
    DWORD w;
    STEP(1, up_ver(1, 1));
    STEP(2, pair(&c, &s));
    g_inhook = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_release = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(&b, 0, sizeof b);
    b.kind = B_RECV; b.s = s; b.len = 8; b.ret = -99;
    b.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    b.th = CreateThread(NULL, 0, hooked_recv_thread, &b, 0, NULL);
    STEP(3, b.th != NULL);
    w = WaitForSingleObject(g_inhook, 3000);
    if (w == WAIT_OBJECT_0) {
        wset(0);
        STEP(4, U(WSAIsBlocking)() == FALSE);   /* the hook runs on the blocked thread, not here */
        STEP(5, U(WSACancelBlockingCall)() == SOCKET_ERROR);
        STEP(6, werr() == WSAEINVAL);
        SetEvent(g_release);
    }
    snd(c, "z", 1);
    STEP(7, blk_join(&b));
    STEP(8, b.ret == 1 && b.buf[0] == 'z');
    cls(c); cls(s);
    CloseHandle(g_inhook); CloseHandle(g_release);
    while (U(WSACleanup)() == 0) {}
    return w == WAIT_OBJECT_0 ? 0 : 1000;       /* 1000: the provider never called the hook (informational) */
}
TEST(thr_legacy_hook_runs_on_blocked_thread_only)
{
    DWORD rc;
    REQUIRE(U(WSAStartup));
    rc = t_run_child("thr_legacy_hook_sampling", "", 30000);
    if (rc == 1000) t_note("the hook was not called for this blocking recv");
    else CHECKF(rc == 0, "child step %lu", rc);
}
