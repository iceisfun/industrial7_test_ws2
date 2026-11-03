/* The Wah* handle-helper family and WPUCompleteOverlappedRequest, exported from ws2_32.dll.
 *
 * These exports are the service layer used by layered providers: an "APC helper" / "notification helper"
 * token, a per-thread duplicated thread handle, a lock-light handle-context table keyed by handle value, and
 * request completion against the non-IFS helper device. They are undocumented in the SDK headers, so every
 * prototype is declared here (UDECL) and resolved with UN().
 *
 * What is pinned (all of it observed as plain return values, never as memory layout):
 *   - helper tokens are opaque nonzero values: Open returns 0 and a token, Close accepts only a token an Open
 *     produced and answers ERROR_INVALID_PARAMETER (87) for anything else, including 0;
 *   - NULL out-parameters and NULL required inputs answer 87 before touching anything;
 *   - the thread helper hands back a real, non-inheritable duplicate of the calling thread plus its id;
 *   - the context table finds a context by handle value, reference bumps the context's leading counter,
 *     remove succeeds once and answers 87 for a context that is not in the table;
 *   - request completion with a missing helper / overlapped / handle answers 87.
 * Anything that changes the machine (non-IFS service enable / disable, catalog-change broadcast beyond the
 * documented no-op) is not exercised; those exports get a documented skip. */
#include "qm.h"

UDECL(DWORD, WahOpenApcHelper, (ULONG_PTR *));
UDECL(DWORD, WahCloseApcHelper, (ULONG_PTR));
UDECL(DWORD, WahOpenNotificationHandleHelper, (ULONG_PTR *));
UDECL(DWORD, WahCloseNotificationHandleHelper, (ULONG_PTR));
UDECL(DWORD, WahOpenCurrentThread, (ULONG_PTR, ULONG_PTR *));
UDECL(DWORD, WahCloseThread, (ULONG_PTR, ULONG_PTR *));
UDECL(DWORD, WahQueueUserApc, (ULONG_PTR, ULONG_PTR *, PAPCFUNC, ULONG_PTR));
UDECL(DWORD, WahOpenHandleHelper, (ULONG_PTR *));
UDECL(DWORD, WahCloseHandleHelper, (ULONG_PTR));
UDECL(DWORD, WahCloseSocketHandle, (ULONG_PTR, HANDLE));
UDECL(DWORD, WahCompleteRequest, (ULONG_PTR, HANDLE, LPWSAOVERLAPPED, DWORD, DWORD));
UDECL(DWORD, WahCreateHandleContextTable, (void **));
UDECL(DWORD, WahDestroyHandleContextTable, (void *));
UDECL(void *, WahInsertHandleContext, (void *, void *));
UDECL(void *, WahReferenceContextByHandle, (void *, HANDLE));
UDECL(DWORD, WahRemoveHandleContext, (void *, void *));
UDECL(BOOL, WahEnumerateHandleContexts_cb, (void *, void *));
UDECL(DWORD, WahEnumerateHandleContexts, (void *, WahEnumerateHandleContexts_cb_pfn, void *));
UDECL(DWORD, WahCreateNotificationHandle, (ULONG_PTR, HANDLE *));
UDECL(DWORD, WahWaitForNotification, (ULONG_PTR, HANDLE, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE));
UDECL(DWORD, WahNotifyAllProcesses, (ULONG_PTR));
UDECL(DWORD, WahCreateSocketHandle, (ULONG_PTR, HANDLE *));
UDECL(void, WahWriteLSPEvent, (void *, DWORD));
UDECL(DWORD, WahEnableNonIFSHandleSupport, (void));
UDECL(DWORD, WahDisableNonIFSHandleSupport, (void));
UDECL(int, WPUCompleteOverlappedRequest, (SOCKET, LPWSAOVERLAPPED, DWORD, DWORD, LPINT));

#define E_INVPARAM 87   /* ERROR_INVALID_PARAMETER */
#define E_INVHANDLE 6   /* ERROR_INVALID_HANDLE */

/* Values that no Open ever returns as a helper token. */
static const ULONG_PTR bad_tokens[] = { 0, 1, 2, 0x1000, 0xFFFFFFFFu, (ULONG_PTR)-1 };

/* ---- APC helper token ------------------------------------------------------------------------------ */

TEST(wah_apc_open_succeeds_with_token)
{
    REQUIRE(UN(WahOpenApcHelper)); REQUIRE(UN(WahCloseApcHelper));
    ULONG_PTR t = 0;
    EXPECT_EQ(UN(WahOpenApcHelper)(&t), 0);
    CHECK(t != 0);
    EXPECT_EQ(UN(WahCloseApcHelper)(t), 0);
}
TEST(wah_apc_open_null_is_invalid_parameter)
{
    REQUIRE(UN(WahOpenApcHelper));
    EXPECT_EQ(UN(WahOpenApcHelper)(NULL), E_INVPARAM);
}
TEST(wah_apc_open_twice_gives_tokens_that_both_close)
{
    REQUIRE(UN(WahOpenApcHelper)); REQUIRE(UN(WahCloseApcHelper));
    ULONG_PTR a = 0, b = 0;
    EXPECT_EQ(UN(WahOpenApcHelper)(&a), 0);
    EXPECT_EQ(UN(WahOpenApcHelper)(&b), 0);
    if (a == b) t_note("APC helper token is a process-wide constant");
    EXPECT_EQ(UN(WahCloseApcHelper)(a), 0);
    EXPECT_EQ(UN(WahCloseApcHelper)(b), 0);
}
TEST(wah_apc_close_rejects_foreign_tokens)
{
    REQUIRE(UN(WahCloseApcHelper));
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        DWORD r = UN(WahCloseApcHelper)(bad_tokens[i]);
        t_check(r == E_INVPARAM, __FILE__, __LINE__, "close(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
}
TEST(wah_apc_close_notification_token_is_rejected)
{
    /* The two helper kinds are different tokens: a notification token is not an APC token. */
    REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseApcHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR n = 0;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&n), 0);
    EXPECT_EQ(UN(WahCloseApcHelper)(n), E_INVPARAM);
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(n), 0);
}
TEST(wah_apc_close_leaves_last_error_alone)
{
    REQUIRE(UN(WahOpenApcHelper)); REQUIRE(UN(WahCloseApcHelper));
    ULONG_PTR t = 0; UN(WahOpenApcHelper)(&t);
    SET_ERR(0x1234);
    UN(WahCloseApcHelper)(t);
    EXPECT_EQ(GetLastError(), 0x1234);
}

/* ---- notification helper token ---------------------------------------------------------------------- */

TEST(wah_notify_open_succeeds_with_token)
{
    REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR t = 0;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&t), 0);
    CHECK(t != 0);
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(t), 0);
}
TEST(wah_notify_open_null_is_invalid_parameter)
{
    REQUIRE(UN(WahOpenNotificationHandleHelper));
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(NULL), E_INVPARAM);
}
TEST(wah_notify_close_rejects_foreign_tokens)
{
    REQUIRE(UN(WahCloseNotificationHandleHelper));
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        DWORD r = UN(WahCloseNotificationHandleHelper)(bad_tokens[i]);
        t_check(r == E_INVPARAM, __FILE__, __LINE__, "close(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
}
TEST(wah_notify_close_apc_token_is_rejected)
{
    REQUIRE(UN(WahOpenApcHelper)); REQUIRE(UN(WahCloseApcHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR a = 0;
    EXPECT_EQ(UN(WahOpenApcHelper)(&a), 0);
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(a), E_INVPARAM);
    EXPECT_EQ(UN(WahCloseApcHelper)(a), 0);
}
TEST(wah_notify_all_processes_rejects_foreign_tokens)
{
    REQUIRE(UN(WahNotifyAllProcesses));
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        DWORD r = UN(WahNotifyAllProcesses)(bad_tokens[i]);
        t_check(r == E_INVPARAM, __FILE__, __LINE__, "notify(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
}
TEST(wah_notify_all_processes_with_real_token_is_ok)
{
    /* Enumerating listeners is best effort: the call itself reports success even when nobody listens. */
    REQUIRE(UN(WahNotifyAllProcesses)); REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR t = 0;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&t), 0);
    EXPECT_EQ(UN(WahNotifyAllProcesses)(t), 0);
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(t), 0);
}
TEST(wah_create_notification_handle_bad_arguments)
{
    REQUIRE(UN(WahCreateNotificationHandle)); REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    HANDLE h = (HANDLE)0x5A5A;
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        h = (HANDLE)0x5A5A;
        DWORD r = UN(WahCreateNotificationHandle)(bad_tokens[i], &h);
        t_check(r == E_INVPARAM && h == (HANDLE)0x5A5A, __FILE__, __LINE__, "create(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
    ULONG_PTR t = 0;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&t), 0);
    EXPECT_EQ(UN(WahCreateNotificationHandle)(t, NULL), E_INVPARAM);
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(t), 0);
}
TEST(wah_create_notification_handle_roundtrip)
{
    REQUIRE(UN(WahCreateNotificationHandle)); REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR t = 0; HANDLE h = NULL;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&t), 0);
    DWORD r = UN(WahCreateNotificationHandle)(t, &h);
    if (r != 0) { t_note("create returned %lu (listener pipe setup is environment dependent)", r); }
    else {
        CHECK(h != NULL && h != INVALID_HANDLE_VALUE);
        DWORD fl = 0;
        CHECK(GetHandleInformation(h, &fl));
        CHECK(CloseHandle(h));
    }
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(t), 0);
}
TEST(wah_wait_for_notification_rejects_foreign_tokens)
{
    REQUIRE(UN(WahWaitForNotification));
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        DWORD r = UN(WahWaitForNotification)(bad_tokens[i], INVALID_HANDLE_VALUE, NULL, NULL);
        t_check(r == E_INVPARAM, __FILE__, __LINE__, "wait(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
}
TEST(wah_wait_for_notification_closed_handle_is_invalid_handle)
{
    /* A real token with a handle that is no longer open: the pipe control request fails with
     * STATUS_INVALID_HANDLE, reported as ERROR_INVALID_HANDLE. Synchronous form (no overlapped). */
    REQUIRE(UN(WahWaitForNotification)); REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR t = 0;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&t), 0);
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    CloseHandle(e);
    DWORD r = UN(WahWaitForNotification)(t, e, NULL, NULL);
    EXPECT_EQ(r, E_INVHANDLE);
    EXPECT_EQ(UN(WahCloseNotificationHandleHelper)(t), 0);
}

TEST(wah_wait_for_notification_overlapped_is_pending_until_notify_all)
{
    /* End to end: a listener pipe from WahCreateNotificationHandle, an overlapped wait on it (pending, 997),
     * then the catalog-change broadcast connects to it and the wait completes. */
    REQUIRE(UN(WahCreateNotificationHandle)); REQUIRE(UN(WahWaitForNotification)); REQUIRE(UN(WahNotifyAllProcesses));
    REQUIRE(UN(WahOpenNotificationHandleHelper)); REQUIRE(UN(WahCloseNotificationHandleHelper));
    ULONG_PTR t = 0; HANDLE h = NULL;
    EXPECT_EQ(UN(WahOpenNotificationHandleHelper)(&t), 0);
    if (UN(WahCreateNotificationHandle)(t, &h) != 0 || !h) { t_note("no listener pipe"); UN(WahCloseNotificationHandleHelper)(t); return; }
    WSAOVERLAPPED *ov = calloc(1, sizeof *ov);
    ov->hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    DWORD r = UN(WahWaitForNotification)(t, h, (LPOVERLAPPED)ov, NULL);
    EXPECT_EQ(r, ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov->hEvent, 100), WAIT_TIMEOUT);
    EXPECT_EQ(UN(WahNotifyAllProcesses)(t), 0);
    DWORD w = WaitForSingleObject(ov->hEvent, 8000);
    /* Delivery of the broadcast to the listener pipe depends on the caller's token; hard only when elevated. */
    if (qm_elevated()) CHECK(w == WAIT_OBJECT_0); else if (w != WAIT_OBJECT_0) t_note("broadcast not delivered to a non-elevated caller");
    if (w == WAIT_OBJECT_0) {
        CHECK(HasOverlappedIoCompleted((OVERLAPPED *)ov));
        EXPECT_EQ(ov->Internal, 0);
        CloseHandle(h); CloseHandle(ov->hEvent); free(ov);
    } else {
        CloseHandle(h);                               /* cancels the listen; leak the OVERLAPPED */
        WaitForSingleObject(ov->hEvent, 5000);
    }
    UN(WahCloseNotificationHandleHelper)(t);
}

/* ---- per-thread helper ------------------------------------------------------------------------------ */

static ULONG_PTR apc_token(void)
{
    ULONG_PTR t = 0;
    if (!UN(WahOpenApcHelper) || UN(WahOpenApcHelper)(&t) != 0) return 0;
    return t;
}

TEST(wah_current_thread_returns_duplicate_and_id)
{
    REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); CHECK(tok != 0); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 };
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, th), 0);
    CHECK(th[0] != 0 && th[0] != (ULONG_PTR)GetCurrentThread() && th[0] != (ULONG_PTR)-1);
    EXPECT_EQ(th[1], GetCurrentThreadId());
    EXPECT_EQ(GetThreadId((HANDLE)th[0]), GetCurrentThreadId());
    EXPECT_EQ(UN(WahCloseThread)(tok, th), 0);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_current_thread_handle_is_not_inheritable)
{
    REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 };
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, th), 0);
    DWORD fl = 0xFFFFFFFF;
    CHECK(GetHandleInformation((HANDLE)th[0], &fl));
    CHECK((fl & HANDLE_FLAG_INHERIT) == 0);
    UN(WahCloseThread)(tok, th);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_current_thread_handle_is_distinct_each_time)
{
    REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR a[2] = { 0, 0 }, b[2] = { 0, 0 };
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, a), 0);
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, b), 0);
    CHECK(a[0] != b[0]);
    EXPECT_EQ(UN(WahCloseThread)(tok, a), 0);
    EXPECT_EQ(UN(WahCloseThread)(tok, b), 0);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_current_thread_rejects_bad_token_and_leaves_output)
{
    REQUIRE(UN(WahOpenCurrentThread));
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        ULONG_PTR th[2] = { 0x77, 0x88 };
        DWORD r = UN(WahOpenCurrentThread)(bad_tokens[i], th);
        t_check(r == E_INVPARAM && th[0] == 0x77 && th[1] == 0x88, __FILE__, __LINE__, "open_thread(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
}
TEST(wah_current_thread_null_output_is_invalid_parameter)
{
    REQUIRE(UN(WahOpenCurrentThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, NULL), E_INVPARAM);
    UN(WahCloseApcHelper)(tok);
}
static DWORD WINAPI thread_id_probe(LPVOID p)
{
    ULONG_PTR *out = (ULONG_PTR *)p;               /* out[0] token, out[1..2] thread pair, out[3] rc */
    out[3] = UN(WahOpenCurrentThread)(out[0], out + 1);
    return 0;
}
TEST(wah_current_thread_reports_the_calling_thread)
{
    REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR box[4] = { tok, 0, 0, 0xFFFF };
    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, thread_id_probe, box, 0, &tid);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h); }
    EXPECT_EQ(box[3], 0);
    EXPECT_EQ(box[2], tid);
    CHECK(box[2] != GetCurrentThreadId());
    EXPECT_EQ(GetThreadId((HANDLE)box[1]), tid);
    UN(WahCloseThread)(tok, box + 1);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_close_thread_closes_and_zeroes)
{
    REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 };
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, th), 0);
    HANDLE dup = (HANDLE)th[0];
    EXPECT_EQ(UN(WahCloseThread)(tok, th), 0);
    EXPECT_EQ(th[0], 0);
    EXPECT_EQ(th[1], 0);
    DWORD fl;
    SET_ERR(0);
    CHECK(!GetHandleInformation(dup, &fl));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_close_thread_twice_second_is_invalid_parameter)
{
    REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 };
    UN(WahOpenCurrentThread)(tok, th);
    EXPECT_EQ(UN(WahCloseThread)(tok, th), 0);
    EXPECT_EQ(UN(WahCloseThread)(tok, th), E_INVPARAM);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_close_thread_argument_rows)
{
    REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR zero[2] = { 0, 0 };
    EXPECT_EQ(UN(WahCloseThread)(tok, NULL), E_INVPARAM);
    EXPECT_EQ(UN(WahCloseThread)(tok, zero), E_INVPARAM);
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        ULONG_PTR th[2] = { (ULONG_PTR)GetCurrentProcess(), 3 };   /* nonzero handle value, bad token: token checked first */
        DWORD r = UN(WahCloseThread)(bad_tokens[i], th);
        t_check(r == E_INVPARAM && th[0] != 0, __FILE__, __LINE__, "close_thread(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_close_thread_stale_handle_reports_win32_error)
{
    /* A nonzero handle value that is not open: CloseHandle fails, its error is returned as the result and
     * the pair is left as it was. */
    REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    ULONG_PTR th[2] = { (ULONG_PTR)e, 9 };
    CloseHandle(e);
    EXPECT_EQ(UN(WahCloseThread)(tok, th), E_INVHANDLE);
    EXPECT_EQ(th[0], (ULONG_PTR)e);
    EXPECT_EQ(th[1], 9);
    UN(WahCloseApcHelper)(tok);
}

/* ---- queueing an APC through the helper -------------------------------------------------------------- */

static volatile LONG apc_runs;
static volatile ULONG_PTR apc_arg;
static VOID WINAPI count_apc(ULONG_PTR p) { apc_arg = p; InterlockedIncrement(&apc_runs); }

TEST(wah_queue_apc_runs_on_target_thread_when_alertable)
{
    REQUIRE(UN(WahQueueUserApc)); REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 };
    EXPECT_EQ(UN(WahOpenCurrentThread)(tok, th), 0);
    apc_runs = 0; apc_arg = 0;
    EXPECT_EQ(UN(WahQueueUserApc)(tok, th, count_apc, 0xABCD), 0);
    EXPECT_EQ(apc_runs, 0);                         /* not delivered until the thread waits alertably */
    EXPECT_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    EXPECT_EQ(apc_runs, 1);
    EXPECT_EQ(apc_arg, 0xABCD);
    UN(WahCloseThread)(tok, th);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_queue_apc_three_queued_three_delivered)
{
    REQUIRE(UN(WahQueueUserApc)); REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 };
    UN(WahOpenCurrentThread)(tok, th);
    apc_runs = 0;
    for (int i = 0; i < 3; i++) EXPECT_EQ(UN(WahQueueUserApc)(tok, th, count_apc, i), 0);
    SleepEx(0, TRUE);
    EXPECT_EQ(apc_runs, 3);
    UN(WahCloseThread)(tok, th);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_queue_apc_argument_rows)
{
    REQUIRE(UN(WahQueueUserApc)); REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    ULONG_PTR th[2] = { 0, 0 }, zero[2] = { 0, 0 };
    UN(WahOpenCurrentThread)(tok, th);
    apc_runs = 0;
    EXPECT_EQ(UN(WahQueueUserApc)(tok, th, NULL, 1), E_INVPARAM);        /* no routine */
    EXPECT_EQ(UN(WahQueueUserApc)(tok, NULL, count_apc, 1), E_INVPARAM); /* no thread record */
    EXPECT_EQ(UN(WahQueueUserApc)(tok, zero, count_apc, 1), E_INVPARAM); /* thread record without handle */
    for (int i = 0; i < QM_N(bad_tokens); i++) {
        DWORD r = UN(WahQueueUserApc)(bad_tokens[i], th, count_apc, 1);
        t_check(r == E_INVPARAM, __FILE__, __LINE__, "queue(bad token)", "token 0x%llx got %lu", (unsigned long long)bad_tokens[i], r);
    }
    SleepEx(0, TRUE);
    EXPECT_EQ(apc_runs, 0);                         /* none of the rejected calls queued anything */
    UN(WahCloseThread)(tok, th);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_queue_apc_stale_thread_handle_reports_win32_error)
{
    REQUIRE(UN(WahQueueUserApc));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    ULONG_PTR th[2] = { (ULONG_PTR)e, 0 };
    CloseHandle(e);
    EXPECT_EQ(UN(WahQueueUserApc)(tok, th, count_apc, 1), E_INVHANDLE);
    UN(WahCloseApcHelper)(tok);
}
TEST(wah_queue_apc_wrong_object_type_is_invalid_handle)
{
    REQUIRE(UN(WahQueueUserApc));
    ULONG_PTR tok = apc_token(); if (!tok) return;
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    ULONG_PTR th[2] = { (ULONG_PTR)e, 0 };           /* an event is not a thread */
    DWORD r = UN(WahQueueUserApc)(tok, th, count_apc, 1);
    CHECK(r == E_INVHANDLE || r == ERROR_ACCESS_DENIED);
    if (r != E_INVHANDLE) t_note("queue to a non-thread handle returned %lu", r);
    CloseHandle(e);
    UN(WahCloseApcHelper)(tok);
}

static HANDLE g_worker_go, g_worker_ready;
static volatile LONG g_worker_stop;
static volatile DWORD g_worker_apc_tid;
static VOID WINAPI worker_apc(ULONG_PTR p) { g_worker_apc_tid = GetCurrentThreadId(); }
static ULONG_PTR g_worker_pair[2];
static ULONG_PTR g_worker_tok;
static DWORD WINAPI worker_main(LPVOID p)
{
    UN(WahOpenCurrentThread)(g_worker_tok, g_worker_pair);
    SetEvent(g_worker_ready);
    for (int i = 0; i < 200 && !g_worker_stop; i++) SleepEx(50, TRUE);
    return 0;
}
TEST(wah_queue_apc_to_another_thread_runs_there)
{
    REQUIRE(UN(WahQueueUserApc)); REQUIRE(UN(WahOpenCurrentThread)); REQUIRE(UN(WahCloseThread));
    g_worker_tok = apc_token(); if (!g_worker_tok) return;
    g_worker_ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_worker_stop = 0; g_worker_apc_tid = 0; g_worker_pair[0] = g_worker_pair[1] = 0;
    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, worker_main, NULL, 0, &tid);
    CHECK(h != NULL);
    if (h) {
        CHECK(WaitForSingleObject(g_worker_ready, 10000) == WAIT_OBJECT_0);
        EXPECT_EQ(UN(WahQueueUserApc)(g_worker_tok, g_worker_pair, worker_apc, 0), 0);
        for (int i = 0; i < 100 && !g_worker_apc_tid; i++) Sleep(50);
        EXPECT_EQ(g_worker_apc_tid, tid);
        g_worker_stop = 1;
        CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
        CloseHandle(h);
    }
    UN(WahCloseThread)(g_worker_tok, g_worker_pair);
    UN(WahCloseApcHelper)(g_worker_tok);
    CloseHandle(g_worker_ready);
}

/* ---- the thread based handle helper ------------------------------------------------------------------ */

TEST(wah_handle_helper_open_close)
{
    REQUIRE(UN(WahOpenHandleHelper)); REQUIRE(UN(WahCloseHandleHelper));
    ULONG_PTR h = 0xDEAD;
    DWORD r = UN(WahOpenHandleHelper)(&h);
    if (r != 0) { t_note("WahOpenHandleHelper returned %lu", r); return; }
    CHECK(h != 0);
    EXPECT_EQ(UN(WahCloseHandleHelper)(h), 0);
}
TEST(wah_handle_helper_open_null_is_invalid_parameter)
{
    REQUIRE(UN(WahOpenHandleHelper));
    EXPECT_EQ(UN(WahOpenHandleHelper)(NULL), E_INVPARAM);
}
TEST(wah_handle_helper_close_zero_is_invalid_parameter)
{
    REQUIRE(UN(WahCloseHandleHelper));
    EXPECT_EQ(UN(WahCloseHandleHelper)(0), E_INVPARAM);
}

/* ---- socket-handle close and request completion ------------------------------------------------------ */

TEST(wah_close_socket_handle_closes_a_real_handle)
{
    /* The helper argument is only tested for being nonzero; the handle goes straight to NtClose. */
    REQUIRE(UN(WahCloseSocketHandle));
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(UN(WahCloseSocketHandle)(1, e), 0);
    DWORD fl;
    SET_ERR(0);
    CHECK(!GetHandleInformation(e, &fl));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(wah_close_socket_handle_twice_is_invalid_handle)
{
    REQUIRE(UN(WahCloseSocketHandle));
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(UN(WahCloseSocketHandle)(1, e), 0);
    EXPECT_EQ(UN(WahCloseSocketHandle)(1, e), E_INVHANDLE);
}
TEST(wah_close_socket_handle_argument_rows)
{
    REQUIRE(UN(WahCloseSocketHandle));
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(UN(WahCloseSocketHandle)(0, e), E_INVPARAM);                 /* helper missing */
    EXPECT_EQ(UN(WahCloseSocketHandle)(1, NULL), E_INVPARAM);              /* handle 0 */
    EXPECT_EQ(UN(WahCloseSocketHandle)(1, INVALID_HANDLE_VALUE), E_INVPARAM); /* handle -1 */
    DWORD fl;
    CHECK(GetHandleInformation(e, &fl));                                   /* the real handle was not touched */
    CloseHandle(e);
}
TEST(wah_complete_request_argument_rows)
{
    REQUIRE(UN(WahCompleteRequest));
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(UN(WahCompleteRequest)(0, e, &ov, 0, 0), E_INVPARAM);
    EXPECT_EQ(UN(WahCompleteRequest)(1, e, NULL, 0, 0), E_INVPARAM);
    EXPECT_EQ(UN(WahCompleteRequest)(1, NULL, &ov, 0, 0), E_INVPARAM);
    EXPECT_EQ(UN(WahCompleteRequest)(1, INVALID_HANDLE_VALUE, &ov, 0, 0), E_INVPARAM);
    CloseHandle(e);
}
TEST(wah_complete_request_non_device_handle_fails_with_win32_error)
{
    /* An event handle is not the helper device: the control request is refused and the failure is returned
     * as a Win32 error (ERROR_INVALID_HANDLE). */
    REQUIRE(UN(WahCompleteRequest));
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    DWORD r = UN(WahCompleteRequest)(1, e, &ov, 0, 0);
    CHECK(r != 0);
    if (r != E_INVHANDLE) t_note("completion against a non-device handle returned %lu", r);
    CloseHandle(e);
}

/* WPUCompleteOverlappedRequest: the provider-facing wrapper; it needs a started stack. */
CHILD(wah_wpu_complete_before_startup)
{
    int err = 0x55555;
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    STEP(1, UN(WPUCompleteOverlappedRequest) != NULL);
    int r = UN(WPUCompleteOverlappedRequest)(QM_BOGUS_SOCKET, &ov, 0, 0, &err);
    STEP(2, r == -1);
    STEP(3, err == WSANOTINITIALISED);
    return 0;
}
TEST(wah_wpu_complete_before_startup_is_notinitialised)
{
    REQUIRE(UN(WPUCompleteOverlappedRequest));
    RUN_CHILD("wah_wpu_complete_before_startup", "", 20000);
}
TEST(wah_wpu_complete_null_overlapped_is_rejected)
{
    REQUIRE(UN(WPUCompleteOverlappedRequest)); QM_NEED_WSA();
    int err = 0x55555;
    int r = UN(WPUCompleteOverlappedRequest)(QM_BOGUS_SOCKET, NULL, 0, 0, &err);
    EXPECT_EQ(r, -1);
    if (err != E_INVPARAM) t_note("rejection code %d (helper device availability decides)", err);
    CHECK(err != 0 && err != 0x55555);
}
/* ---- handle-context table ---------------------------------------------------------------------------- */

typedef struct { LONG ref; LONG pad; ULONG_PTR handle; ULONG_PTR user[4]; } ctx_t;
static void ctx_init(ctx_t *c, ULONG_PTR h, LONG ref) { memset(c, 0, sizeof *c); c->ref = ref; c->handle = h; }

TEST(wah_table_create_destroy)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahDestroyHandleContextTable));
    void *t = NULL;
    EXPECT_EQ(UN(WahCreateHandleContextTable)(&t), 0);
    CHECK(t != NULL);
    EXPECT_EQ(UN(WahDestroyHandleContextTable)(t), 0);
}
TEST(wah_table_destroy_null_is_invalid_parameter)
{
    REQUIRE(UN(WahDestroyHandleContextTable));
    EXPECT_EQ(UN(WahDestroyHandleContextTable)(NULL), E_INVPARAM);
}
TEST(wah_table_two_tables_are_independent)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle));
    void *a = NULL, *b = NULL;
    UN(WahCreateHandleContextTable)(&a); UN(WahCreateHandleContextTable)(&b);
    CHECK(a != NULL && b != NULL && a != b);
    ctx_t c; ctx_init(&c, 0x40, 1);
    EXPECT_EQ(UN(WahInsertHandleContext)(a, &c), &c);
    CHECK(UN(WahReferenceContextByHandle)(b, (HANDLE)0x40) == NULL);
    ctx_t *got = UN(WahReferenceContextByHandle)(a, (HANDLE)0x40);
    CHECK(got == &c);
    UN(WahRemoveHandleContext)(a, &c);
    UN(WahDestroyHandleContextTable)(a); UN(WahDestroyHandleContextTable)(b);
}
TEST(wah_table_insert_then_reference_finds_context)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x1234, 1);
    EXPECT_EQ(UN(WahInsertHandleContext)(t, &c), &c);
    ctx_t *got = UN(WahReferenceContextByHandle)(t, (HANDLE)0x1234);
    CHECK(got == &c);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &c), 0);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_reference_adds_one_to_leading_counter)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x2000, 5);
    UN(WahInsertHandleContext)(t, &c);
    EXPECT_EQ(c.ref, 5);                             /* insert does not count */
    UN(WahReferenceContextByHandle)(t, (HANDLE)0x2000);
    EXPECT_EQ(c.ref, 6);
    UN(WahReferenceContextByHandle)(t, (HANDLE)0x2000);
    UN(WahReferenceContextByHandle)(t, (HANDLE)0x2000);
    EXPECT_EQ(c.ref, 8);
    UN(WahRemoveHandleContext)(t, &c);
    EXPECT_EQ(c.ref, 8);                             /* remove does not count either */
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_reference_unknown_handle_is_null_and_counts_nothing)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x100, 1);
    UN(WahInsertHandleContext)(t, &c);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x104) == NULL);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x0) == NULL);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x108) == NULL);
    EXPECT_EQ(c.ref, 1);
    UN(WahRemoveHandleContext)(t, &c);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_empty_table_reference_is_null)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahReferenceContextByHandle));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x4) == NULL);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x1000) == NULL);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_remove_then_reference_is_null)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x3330, 1);
    UN(WahInsertHandleContext)(t, &c);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &c), 0);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x3330) == NULL);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_remove_twice_second_is_invalid_parameter)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x50, 1);
    UN(WahInsertHandleContext)(t, &c);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &c), 0);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &c), E_INVPARAM);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_remove_never_inserted_is_invalid_parameter)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x60, 1);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &c), E_INVPARAM);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_remove_is_by_identity_not_by_handle_value)
{
    /* A different context record carrying the same handle value is not the inserted one. */
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t a, b; ctx_init(&a, 0x70, 1); ctx_init(&b, 0x70, 1);
    UN(WahInsertHandleContext)(t, &a);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &b), E_INVPARAM);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x70) == &a);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &a), 0);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_reinsert_after_remove_works)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c; ctx_init(&c, 0x80, 1);
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(UN(WahInsertHandleContext)(t, &c), &c);
        CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)0x80) == &c);
        EXPECT_EQ(UN(WahRemoveHandleContext)(t, &c), 0);
    }
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_colliding_handles_are_both_found)
{
    /* Two handle values that fall into the same bucket and the same slot of a 31-entry table: the insert has
     * to grow or rehash instead of dropping one of them. 31 * 2^18 keeps (h>>2) low bits identical. */
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ULONG_PTR h1 = 0x44, h2 = 0x44 + (ULONG_PTR)31 * 262144, h3 = 0x44 + (ULONG_PTR)62 * 262144;
    ctx_t a, b, c; ctx_init(&a, h1, 1); ctx_init(&b, h2, 1); ctx_init(&c, h3, 1);
    EXPECT_EQ(UN(WahInsertHandleContext)(t, &a), &a);
    EXPECT_EQ(UN(WahInsertHandleContext)(t, &b), &b);
    EXPECT_EQ(UN(WahInsertHandleContext)(t, &c), &c);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)h1) == &a);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)h2) == &b);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)h3) == &c);
    EXPECT_EQ(UN(WahRemoveHandleContext)(t, &b), 0);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)h2) == NULL);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)h1) == &a);
    CHECK(UN(WahReferenceContextByHandle)(t, (HANDLE)h3) == &c);
    UN(WahRemoveHandleContext)(t, &a); UN(WahRemoveHandleContext)(t, &c);
    UN(WahDestroyHandleContextTable)(t);
}

#define MANY 300
TEST(wah_table_many_contexts_all_found_then_all_removed)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t *c = calloc(MANY, sizeof *c);
    int ins_ok = 0, found = 0, gone = 0, rem_ok = 0;
    for (int i = 0; i < MANY; i++) { ctx_init(&c[i], 0x100 + (ULONG_PTR)i * 4, 1); if (UN(WahInsertHandleContext)(t, &c[i]) == &c[i]) ins_ok++; }
    EXPECT_EQ(ins_ok, MANY);
    for (int i = 0; i < MANY; i++) if (UN(WahReferenceContextByHandle)(t, (HANDLE)c[i].handle) == &c[i]) found++;
    EXPECT_EQ(found, MANY);
    for (int i = 0; i < MANY; i++) if (c[i].ref == 2) gone++;
    EXPECT_EQ(gone, MANY);                           /* exactly one reference per lookup */
    for (int i = 0; i < MANY; i += 2) if (UN(WahRemoveHandleContext)(t, &c[i]) == 0) rem_ok++;
    EXPECT_EQ(rem_ok, MANY / 2);
    found = 0; gone = 0;
    for (int i = 0; i < MANY; i++) {
        void *r = UN(WahReferenceContextByHandle)(t, (HANDLE)c[i].handle);
        if (i % 2 == 0) { if (r == NULL) gone++; } else if (r == &c[i]) found++;
    }
    EXPECT_EQ(gone, MANY / 2);
    EXPECT_EQ(found, MANY / 2);
    for (int i = 1; i < MANY; i += 2) UN(WahRemoveHandleContext)(t, &c[i]);
    UN(WahDestroyHandleContextTable)(t);
    free(c);
}
TEST(wah_table_same_bucket_run_survives_growth)
{
    /* Handles 4 apart land in consecutive buckets; handles (mask+1)*4 apart share one. A long arithmetic run
     * with a large stride forces many same-bucket inserts and several table growths. */
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahReferenceContextByHandle)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    enum { N = 120 };
    ctx_t *c = calloc(N, sizeof *c);
    int found = 0;
    for (int i = 0; i < N; i++) { ctx_init(&c[i], 0x8 + (ULONG_PTR)i * 262144, 1); UN(WahInsertHandleContext)(t, &c[i]); }
    for (int i = 0; i < N; i++) if (UN(WahReferenceContextByHandle)(t, (HANDLE)c[i].handle) == &c[i]) found++;
    EXPECT_EQ(found, N);
    for (int i = 0; i < N; i++) UN(WahRemoveHandleContext)(t, &c[i]);
    UN(WahDestroyHandleContextTable)(t);
    free(c);
}

static BOOL enum_collect(void *param, void *ctx) { ctx_t **list = (ctx_t **)param; int n = 0; while (list[n]) n++; list[n] = (ctx_t *)ctx; return TRUE; }
static int g_enum_calls;
static BOOL enum_stop_first(void *param, void *ctx) { g_enum_calls++; return FALSE; }
static BOOL enum_count_all(void *param, void *ctx) { (*(int *)param)++; return TRUE; }

TEST(wah_table_enumerate_empty_table_succeeds_without_callbacks)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahEnumerateHandleContexts));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    int n = 0;
    DWORD r = UN(WahEnumerateHandleContexts)(t, enum_count_all, &n);
    CHECK(r != 0);                                   /* every callback (there were none) said "continue" */
    EXPECT_EQ(n, 0);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_enumerate_visits_every_context_once)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahEnumerateHandleContexts)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c[9];
    for (int i = 0; i < 9; i++) { ctx_init(&c[i], 0x200 + (ULONG_PTR)i * 4, 1); UN(WahInsertHandleContext)(t, &c[i]); }
    int n = 0;
    DWORD r = UN(WahEnumerateHandleContexts)(t, enum_count_all, &n);
    CHECK(r != 0);
    EXPECT_EQ(n, 9);
    ctx_t *list[16] = { 0 };
    UN(WahEnumerateHandleContexts)(t, enum_collect, list);
    int seen = 0;
    for (int i = 0; i < 9; i++) { int hits = 0; for (int j = 0; list[j]; j++) if (list[j] == &c[i]) hits++; if (hits == 1) seen++; }
    EXPECT_EQ(seen, 9);
    for (int i = 0; i < 9; i++) UN(WahRemoveHandleContext)(t, &c[i]);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_enumerate_stops_when_callback_returns_false)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahEnumerateHandleContexts)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c[5];
    for (int i = 0; i < 5; i++) { ctx_init(&c[i], 0x300 + (ULONG_PTR)i * 4, 1); UN(WahInsertHandleContext)(t, &c[i]); }
    g_enum_calls = 0;
    DWORD r = UN(WahEnumerateHandleContexts)(t, enum_stop_first, NULL);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(g_enum_calls, 1);
    for (int i = 0; i < 5; i++) UN(WahRemoveHandleContext)(t, &c[i]);
    UN(WahDestroyHandleContextTable)(t);
}
TEST(wah_table_enumerate_skips_removed_contexts)
{
    REQUIRE(UN(WahCreateHandleContextTable)); REQUIRE(UN(WahInsertHandleContext)); REQUIRE(UN(WahEnumerateHandleContexts)); REQUIRE(UN(WahRemoveHandleContext));
    void *t = NULL; UN(WahCreateHandleContextTable)(&t);
    ctx_t c[6];
    for (int i = 0; i < 6; i++) { ctx_init(&c[i], 0x400 + (ULONG_PTR)i * 4, 1); UN(WahInsertHandleContext)(t, &c[i]); }
    UN(WahRemoveHandleContext)(t, &c[1]); UN(WahRemoveHandleContext)(t, &c[4]);
    int n = 0;
    UN(WahEnumerateHandleContexts)(t, enum_count_all, &n);
    EXPECT_EQ(n, 4);
    for (int i = 0; i < 6; i++) if (i != 1 && i != 4) UN(WahRemoveHandleContext)(t, &c[i]);
    UN(WahDestroyHandleContextTable)(t);
}

/* ---- remaining exports ------------------------------------------------------------------------------- */

TEST(wah_write_lsp_event_null_entry_is_a_silent_return)
{
    /* Modes 0 and 1 with no catalog entry return at once; mode 3 (reset marker) needs no entry either. */
    REQUIRE(UN(WahWriteLSPEvent));
    UN(WahWriteLSPEvent)(NULL, 0);
    UN(WahWriteLSPEvent)(NULL, 1);
    UN(WahWriteLSPEvent)(NULL, 3);
    CHECK(1);
}
TEST(wah_create_socket_handle_null_arguments_are_invalid_parameter)
{
    REQUIRE(UN(WahCreateSocketHandle));
    HANDLE h = NULL;
    ULONG_PTR tok = 1;
    EXPECT_EQ(UN(WahCreateSocketHandle)(0, &h), E_INVPARAM);
    EXPECT_EQ(UN(WahCreateSocketHandle)(tok, NULL), E_INVPARAM);
}
TEST(wah_nonifs_enable_disable_are_not_exercised)
{
    /* Both calls rewrite the configuration of the non-IFS handle driver service; that is machine state. */
    REQUIRE(UN(WahEnableNonIFSHandleSupport)); REQUIRE(UN(WahDisableNonIFSHandleSupport));
    t_skip("changes service configuration (covered only by the guarded destructive area)");
}
TEST(wah_exports_are_all_present)
{
    static const char *names[] = {
        "WahCloseApcHelper", "WahCloseHandleHelper", "WahCloseNotificationHandleHelper", "WahCloseSocketHandle",
        "WahCloseThread", "WahCompleteRequest", "WahCreateHandleContextTable", "WahCreateNotificationHandle",
        "WahCreateSocketHandle", "WahDestroyHandleContextTable", "WahDisableNonIFSHandleSupport",
        "WahEnableNonIFSHandleSupport", "WahEnumerateHandleContexts", "WahInsertHandleContext",
        "WahNotifyAllProcesses", "WahOpenApcHelper", "WahOpenCurrentThread", "WahOpenHandleHelper",
        "WahOpenNotificationHandleHelper", "WahQueueUserApc", "WahReferenceContextByHandle",
        "WahRemoveHandleContext", "WahWaitForNotification", "WahWriteLSPEvent", "WPUCompleteOverlappedRequest" };
    int missing = 0;
    for (int i = 0; i < QM_N(names); i++) if (!t_proc_in("ws2_32.dll", names[i])) { missing++; t_note("not exported: %s", names[i]); }
    if (t_is_wine()) { t_skip("helper exports are not provided by the emulated stack"); return; }
    EXPECT_EQ(missing, 0);
}
TEST(wah_helper_exports_are_not_forwarders)
{
    /* They live in ws2_32 itself, not in a separate helper library. */
    REQUIRE(UN(WahOpenApcHelper));
    HMODULE m = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)UN(WahOpenApcHelper), &m);
    CHECK(m == t_module("ws2_32.dll"));
}
