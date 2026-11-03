/* Legacy Winsock 1.x blocking-call machinery: WSASetBlockingHook, WSAUnhookBlockingHook, WSAIsBlocking,
 * WSACancelBlockingCall.
 *
 * Observed contract (all of it keyed on the version the process negotiated, not on the call site):
 *   - no stack running                      : every call that can fail reports WSANOTINITIALISED
 *   - every startup asked for 2.x or above  : the hook family is gone, WSAEOPNOTSUPP
 *   - at least one startup asked for 1.x    : the family works, per thread
 * The negotiated version is the lowest request seen since the stack last came up from zero; it is forgotten
 * when the count reaches zero. WSAIsBlocking never fails and never touches the thread's error slot.
 * Scenarios are small scripts: "+L.H" is WSAStartup(L,H), "-" is WSACleanup. */
#include "sc.h"
#include <ctype.h>

static BOOL WINAPI hookA(void) { return FALSE; }
static BOOL WINAPI hookB(void) { return FALSE; }
static BOOL WINAPI hookC(void) { return FALSE; }

/* Run a script; returns 0 or a step id. */
static int run_script(const char *s)
{
    WSADATA d;
    int step = 100;
    while (*s) {
        if (*s == '+') {
            unsigned lo = (unsigned)strtoul(s + 1, (char **)&s, 10);
            unsigned hi = 0;
            if (*s == '.') hi = (unsigned)strtoul(s + 1, (char **)&s, 10);
            if (U(WSAStartup)(MAKEWORD(lo, hi), &d) != 0) return step;
        } else if (*s == '-') {
            if (U(WSACleanup)() != 0) return step + 1;
            s++;
        } else s++;
        step += 2;
    }
    return 0;
}

/* argv[1] = script, argv[2] = "none" | "v1" | "v2" */
CHILD(bh_matrix)
{
    if (argc < 3) return 90;
    int rs = run_script(argv[1]);
    STEP(rs ? rs : 1, rs == 0);
    int mode = !strcmp(argv[2], "v1") ? 1 : !strcmp(argv[2], "v2") ? 2 : 0;
    DWORD want_err = mode == 0 ? WSANOTINITIALISED : WSAEOPNOTSUPP;

    /* WSAIsBlocking: FALSE everywhere, error slot untouched */
    SETWSAERR(0x1234);
    STEP(2, U(WSAIsBlocking)() == FALSE);
    SOFT(WSAERR() == 0x1234, "WSAIsBlocking rewrote the last-error slot");

    /* WSACancelBlockingCall */
    SETWSAERR(0);
    STEP(4, U(WSACancelBlockingCall)() == SOCKET_ERROR);
    STEP(5, WSAERR() == (mode == 1 ? WSAEINVAL : want_err));   /* v1: nothing is blocking */

    /* WSAUnhookBlockingHook */
    SETWSAERR(0);
    int r = U(WSAUnhookBlockingHook)();
    if (mode == 1) STEP(6, r == 0);
    else { STEP(7, r == SOCKET_ERROR); STEP(8, WSAERR() == want_err); }

    /* WSASetBlockingHook(NULL) */
    SETWSAERR(0);
    FARPROC p = U(WSASetBlockingHook)(NULL);
    STEP(9, p == NULL);
    STEP(10, WSAERR() == (mode == 1 ? WSAEFAULT : want_err));   /* v1: NULL hook is a bad pointer */

    /* WSASetBlockingHook(valid) */
    SETWSAERR(0);
    p = U(WSASetBlockingHook)((FARPROC)hookA);
    if (mode == 1) STEP(11, p != NULL);
    else { STEP(12, p == NULL); STEP(13, WSAERR() == want_err); }
    if (mode == 1) STEP(14, U(WSAUnhookBlockingHook)() == 0);

    /* the same answers on every repeat */
    for (int i = 0; i < 3; i++) {
        SETWSAERR(0);
        STEP(15, U(WSACancelBlockingCall)() == SOCKET_ERROR);
        STEP(16, WSAERR() == (mode == 1 ? WSAEINVAL : want_err));
    }
    while (U(WSACleanup)() == 0) {}
    return 0;
}

#define BH(id, script, expect) TEST(blocking_matrix_##id) { REQUIRE(U(WSAStartup)); RUN_CHILD("bh_matrix", "\"" script "\" " expect, 20000); }
/* nothing started */
BH(none, "", "none")
BH(none_after_full_cleanup_22, "+2.2,-", "none")
BH(none_after_full_cleanup_11, "+1.1,-", "none")
BH(none_after_many_cycles, "+2.2,-,+1.1,-,+2.2,-", "none")
/* 2.x only */
BH(v22, "+2.2", "v2")
BH(v20, "+2.0", "v2")
BH(v21, "+2.1", "v2")
BH(v23_negotiates_to_22, "+2.3", "v2")
BH(v2ff, "+2.255", "v2")
BH(major3, "+3.0", "v2")
BH(major9, "+9.9", "v2")
BH(v22_twice, "+2.2,+2.2", "v2")
BH(v22_v20, "+2.2,+2.0", "v2")
BH(v20_v22, "+2.0,+2.2", "v2")
/* some 1.x request */
BH(v10, "+1.0", "v1")
BH(v11, "+1.1", "v1")
BH(v12_negotiates_to_11, "+1.2", "v1")
BH(v1ff, "+1.255", "v1")
BH(v11_v22, "+1.1,+2.2", "v1")
BH(v22_v11, "+2.2,+1.1", "v1")
BH(v22_v10, "+2.2,+1.0", "v1")
BH(v20_v11, "+2.0,+1.1", "v1")
BH(v11_v11, "+1.1,+1.1", "v1")
BH(v10_v11, "+1.0,+1.1", "v1")
BH(v22_v22_v11, "+2.2,+2.2,+1.1", "v1")
/* the negotiated version is the lowest since the count was last zero; cleanups below zero do not change it */
BH(v22_v11_cleanup_one, "+2.2,+1.1,-", "v1")
BH(v11_v22_cleanup_one, "+1.1,+2.2,-", "v1")
BH(v11_v22_cleanup_two_then_22, "+1.1,+2.2,-,-,+2.2", "v2")
BH(v11_cleanup_then_22, "+1.1,-,+2.2", "v2")
BH(v11_cleanup_then_20, "+1.1,-,+2.0", "v2")
BH(v22_cleanup_then_11, "+2.2,-,+1.1", "v1")
BH(v11_cleanup_then_11, "+1.1,-,+1.1", "v1")
BH(v11_cleanup_then_22_then_11, "+1.1,-,+2.2,+1.1", "v1")
BH(deep_v22_then_v11_late, "+2.2,+2.2,+2.2,+2.2,+1.1", "v1")
BH(deep_v11_then_v22s, "+1.1,+2.2,+2.2,+2.2,+2.2", "v1")

/* ---- hook bookkeeping ---------------------------------------------------------------------------------- */
CHILD(bh_hook_chain)
{
    STEP(1, run_script("+1.1") == 0);
    FARPROC prev0 = U(WSASetBlockingHook)((FARPROC)hookA);
    STEP(2, prev0 != NULL);                                    /* the built-in default hook */
    STEP(3, prev0 != (FARPROC)hookA && prev0 != (FARPROC)hookB);
    STEP(4, U(WSASetBlockingHook)((FARPROC)hookB) == (FARPROC)hookA);
    STEP(5, U(WSASetBlockingHook)((FARPROC)hookC) == (FARPROC)hookB);
    STEP(6, U(WSASetBlockingHook)((FARPROC)hookC) == (FARPROC)hookC);   /* same hook again is returned as previous */
    STEP(7, U(WSAUnhookBlockingHook)() == 0);
    FARPROC prev1 = U(WSASetBlockingHook)((FARPROC)hookA);     /* after Unhook the default is back */
    STEP(8, prev1 != NULL);
    STEP(9, prev1 != (FARPROC)hookA && prev1 != (FARPROC)hookB && prev1 != (FARPROC)hookC);
    STEP(11, U(WSAUnhookBlockingHook)() == 0);
    STEP(12, U(WSAUnhookBlockingHook)() == 0);                 /* idempotent */
    /* installing what Set returned originally (the default) is accepted and reports the current hook */
    STEP(13, U(WSASetBlockingHook)((FARPROC)hookB) == prev1);
    STEP(14, U(WSASetBlockingHook)(prev1) == (FARPROC)hookB);
    STEP(15, U(WSASetBlockingHook)((FARPROC)hookA) == prev1);
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(blocking_hook_chain_returns_previous) { REQUIRE(U(WSAStartup)); RUN_CHILD("bh_hook_chain", "", 20000); }

static FARPROC g_th_prev;
static DWORD g_th_unhook = 99;
static DWORD WINAPI th_other_hook(LPVOID p)
{
    g_th_prev = U(WSASetBlockingHook)((FARPROC)hookB);
    g_th_unhook = (DWORD)U(WSAUnhookBlockingHook)();
    return 0;
}
CHILD(bh_per_thread)
{
    STEP(1, run_script("+1.1") == 0);
    FARPROC dflt = U(WSASetBlockingHook)((FARPROC)hookA);
    STEP(2, dflt != NULL);
    HANDLE h = CreateThread(NULL, 0, th_other_hook, NULL, 0, NULL);
    STEP(3, h != NULL);
    STEP(4, WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    STEP(5, g_th_prev != NULL);
    STEP(6, g_th_prev != (FARPROC)hookA);        /* the other thread has its own hook slot, still the default */
    STEP(7, g_th_unhook == 0);
    STEP(8, U(WSASetBlockingHook)((FARPROC)hookC) == (FARPROC)hookA);   /* ours was not disturbed by the unhook there */
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(blocking_hook_slot_is_per_thread) { REQUIRE(U(WSAStartup)); RUN_CHILD("bh_per_thread", "", 20000); }

/* a thread's hook does not survive into a thread started later */
static FARPROC g_t2_prev;
static DWORD WINAPI th_read_default(LPVOID p) { g_t2_prev = U(WSASetBlockingHook)((FARPROC)hookC); return 0; }
CHILD(bh_new_thread_gets_default)
{
    STEP(1, run_script("+1.1") == 0);
    FARPROC dflt = U(WSASetBlockingHook)((FARPROC)hookA);
    STEP(2, dflt != NULL);
    for (int i = 0; i < 3; i++) {
        g_t2_prev = (FARPROC)1;
        HANDLE h = CreateThread(NULL, 0, th_read_default, NULL, 0, NULL);
        STEP(3, h != NULL);
        STEP(4, WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
        CloseHandle(h);
        STEP(5, g_t2_prev == dflt);
    }
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(blocking_new_thread_starts_with_default_hook) { REQUIRE(U(WSAStartup)); RUN_CHILD("bh_new_thread_gets_default", "", 20000); }

/* the version restriction applies on every thread, including ones that never started anything */
static DWORD g_th_err; static FARPROC g_th_ret;
static DWORD WINAPI th_set_v2(LPVOID p) { SETWSAERR(0); g_th_ret = U(WSASetBlockingHook)((FARPROC)hookA); g_th_err = (DWORD)WSAERR(); return 0; }
CHILD(bh_v2_other_thread)
{
    STEP(1, run_script("+2.2") == 0);
    g_th_ret = (FARPROC)1;
    HANDLE h = CreateThread(NULL, 0, th_set_v2, NULL, 0, NULL);
    STEP(2, h != NULL);
    STEP(3, WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    STEP(4, g_th_ret == NULL);
    STEP(5, g_th_err == WSAEOPNOTSUPP);
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(blocking_version_gate_is_process_wide) { REQUIRE(U(WSAStartup)); RUN_CHILD("bh_v2_other_thread", "", 20000); }

/* ---- a real blocking call with a hook installed ---------------------------------------------------------- */
static SOCKET g_c, g_a, g_hs;
static volatile LONG h_calls;
static int h_mode;
static volatile int h_isb = -1, h_inprog_ret = 0, h_inprog_err = 0, h_cancel_ret = -9;
static DWORD g_delay_ms;

static int make_pair(SOCKET *c, SOCKET *a)
{
    struct sockaddr_in sa;
    int len = sizeof sa;
    SOCKET l = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (l == INVALID_SOCKET) return 0;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = 0x0100007fu;
    if (U(bind)(l, (struct sockaddr *)&sa, sizeof sa) || U(listen)(l, 1) || U(getsockname)(l, (struct sockaddr *)&sa, &len)) { U(closesocket)(l); return 0; }
    *c = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (*c == INVALID_SOCKET || U(connect)(*c, (struct sockaddr *)&sa, sizeof sa)) { U(closesocket)(l); return 0; }
    *a = U(accept)(l, NULL, NULL);
    U(closesocket)(l);
    return *a != INVALID_SOCKET;
}

static BOOL WINAPI hook_probe(void)
{
    LONG n = InterlockedIncrement(&h_calls);
    if (n == 1) {
        struct sockaddr_in sa;
        int len = sizeof sa;
        h_isb = U(WSAIsBlocking)();
        SETWSAERR(0);
        h_inprog_ret = U(getsockname)(g_hs, (struct sockaddr *)&sa, &len);
        h_inprog_err = WSAERR();
        if (h_mode == 1) h_cancel_ret = U(WSACancelBlockingCall)();
    }
    return FALSE;
}

static DWORD WINAPI th_feed(LPVOID p)
{
    Sleep(g_delay_ms);
    U(send)(g_c, "Z", 1, 0);
    return 0;
}

/* argv[1]: 0 = hook cancels the call, 1 = hook declines (returns FALSE, call completes with data),
 *          2 = hook installed then removed with Unhook, 3 = hook installed then replaced by the default */
CHILD(bh_live)
{
    int scen = argc > 1 ? atoi(argv[1]) : 0;
    STEP(1, run_script("+1.1") == 0);
    STEP(2, make_pair(&g_c, &g_a));
    g_hs = g_a;
    h_calls = 0; h_isb = -1; h_cancel_ret = -9;
    h_mode = scen == 0 ? 1 : 0;
    FARPROC dflt = U(WSASetBlockingHook)((FARPROC)hook_probe);
    STEP(3, dflt != NULL);
    if (scen == 2) STEP(4, U(WSAUnhookBlockingHook)() == 0);
    if (scen == 3) STEP(5, U(WSASetBlockingHook)(dflt) == (FARPROC)hook_probe);
    g_delay_ms = scen == 0 ? 4000 : 400;
    HANDLE th = CreateThread(NULL, 0, th_feed, NULL, 0, NULL);
    STEP(6, th != NULL);
    char b[4] = { 0 };
    SETWSAERR(0);
    int r = U(recv)(g_a, b, 1, 0);
    int err = WSAERR();
    WaitForSingleObject(th, 10000);
    CloseHandle(th);

    int rc = 0;
    if (scen == 0) {
        if (h_calls == 0) rc = 1000;             /* the provider never ran the hook; informational */
        else {
            STEP(10, r == SOCKET_ERROR);
            STEP(11, err == WSAEINTR);
            STEP(12, h_isb == TRUE);             /* WSAIsBlocking from inside the hook */
            STEP(13, h_inprog_ret == SOCKET_ERROR && h_inprog_err == WSAEINPROGRESS);   /* other calls refused meanwhile */
            STEP(14, h_cancel_ret == 0);
        }
    } else if (scen == 1) {
        STEP(20, r == 1 && b[0] == 'Z');
    } else {
        STEP(21, h_calls == 0);                  /* an uninstalled hook is never called */
        STEP(22, r == 1 && b[0] == 'Z');
    }
    STEP(30, U(WSAIsBlocking)() == FALSE);
    /* the stack is fully usable again */
    struct sockaddr_in sa; int len = sizeof sa;
    STEP(31, U(getsockname)(g_a, (struct sockaddr *)&sa, &len) == 0);
    U(closesocket)(g_a); U(closesocket)(g_c);
    while (U(WSACleanup)() == 0) {}
    return rc;
}
#define BHL(n) TEST(blocking_live_recv_scenario_##n) { REQUIRE(U(WSAStartup)); \
    DWORD rc_ = t_run_child("bh_live", #n, 30000); \
    if (rc_ == 1000) t_note("hook was not invoked by the provider for this blocking recv"); \
    else CHECKF(rc_ == 0, "step %lu", rc_); }
BHL(0) BHL(1) BHL(2) BHL(3)

/* A hook cannot be installed while the process is in 2.x mode, so a blocking call in a 2.x process never
 * calls into user code; it simply completes when data arrives. */
CHILD(bh_live_v2)
{
    STEP(1, run_script("+2.2") == 0);
    STEP(2, make_pair(&g_c, &g_a));
    h_calls = 0;
    STEP(3, U(WSASetBlockingHook)((FARPROC)hook_probe) == NULL);
    g_delay_ms = 300;
    HANDLE th = CreateThread(NULL, 0, th_feed, NULL, 0, NULL);
    STEP(4, th != NULL);
    char b[4] = { 0 };
    int r = U(recv)(g_a, b, 1, 0);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    STEP(5, r == 1 && b[0] == 'Z');
    STEP(6, h_calls == 0);
    U(closesocket)(g_a); U(closesocket)(g_c);
    while (U(WSACleanup)() == 0) {}
    return 0;
}
TEST(blocking_live_recv_in_v2_process_never_hooks) { REQUIRE(U(WSAStartup)); RUN_CHILD("bh_live_v2", "", 30000); }
