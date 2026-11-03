/* Measures WSAWaitForMultipleEvents: return-value indexing (WSA_WAIT_EVENT_0 + lowest signalled index),
 * wait-any versus wait-all, timeouts, the 64-handle boundary, argument failures (count 0, count 65,
 * closed or NULL handle) and their error codes, auto-reset consumption, alertable waits with queued
 * APCs and overlapped completion routines, and waiting on non-event kernel objects. */
#include "ese.h"

static DWORD es_wfme(DWORD n, const HANDLE *h, BOOL all, DWORD ms, BOOL alert)
{
    return U(WSAWaitForMultipleEvents)(n, h, all, ms, alert);
}
static void es_mk(HANDLE *h, int n) { int i; for (i = 0; i < n; ++i) h[i] = es_ev(); }
static void es_rm(HANDLE *h, int n) { int i; for (i = 0; i < n; ++i) if (h[i]) U(WSACloseEvent)(h[i]); }

ESTEST(ese_wait_one_unsignalled_zero_timeout)
{
    HANDLE h[1]; es_mk(h, 1);
    ES_EQ(es_wfme(1, h, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    es_rm(h, 1);
}
ESTEST(ese_wait_one_signalled_returns_event_0)
{
    HANDLE h[1]; es_mk(h, 1);
    U(WSASetEvent)(h[0]);
    ES_EQ(es_wfme(1, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    es_rm(h, 1);
}
ESTEST(ese_wait_short_timeout_expires)
{
    HANDLE h[1]; es_mk(h, 1);
    ES_EQ(es_wfme(1, h, FALSE, 30, FALSE), WSA_WAIT_TIMEOUT);
    es_rm(h, 1);
}
ESTEST(ese_wait_all_short_timeout_expires)
{
    HANDLE h[3]; es_mk(h, 3);
    ES_EQ(es_wfme(3, h, TRUE, 30, FALSE), WSA_WAIT_TIMEOUT);
    es_rm(h, 3);
}
ESTEST(ese_wait_any_index_of_each_position)
{
    HANDLE h[8]; int i;
    es_mk(h, 8);
    for (i = 0; i < 8; ++i) {
        U(WSASetEvent)(h[i]);
        ES_EQ(es_wfme(8, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + i);
        U(WSAResetEvent)(h[i]);
    }
    es_rm(h, 8);
}
ESTEST(ese_wait_any_lowest_index_wins)
{
    HANDLE h[5]; es_mk(h, 5);
    U(WSASetEvent)(h[4]); U(WSASetEvent)(h[2]); U(WSASetEvent)(h[3]);
    ES_EQ(es_wfme(5, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 2);
    U(WSAResetEvent)(h[2]);
    ES_EQ(es_wfme(5, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 3);
    U(WSAResetEvent)(h[3]);
    ES_EQ(es_wfme(5, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 4);
    es_rm(h, 5);
}
ESTEST(ese_wait_any_does_not_reset_manual_events)
{
    HANDLE h[2]; es_mk(h, 2);
    U(WSASetEvent)(h[1]);
    ES_EQ(es_wfme(2, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 1);
    ES_EQ(es_wfme(2, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 1);
    CHECK(es_signalled(h[1]));
    es_rm(h, 2);
}
ESTEST(ese_wait_any_resets_only_the_satisfying_auto_event)
{
    HANDLE h[3]; int i;
    for (i = 0; i < 3; ++i) h[i] = CreateEventW(NULL, FALSE, TRUE, NULL);
    REQUIRE(h[0] && h[1] && h[2]);
    ES_EQ(es_wfme(3, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    CHECK(!es_signalled(h[0]));                     /* consumed */
    CHECK(es_signalled(h[1]));                      /* neighbours untouched */
    CHECK(es_signalled(h[2]));
    for (i = 0; i < 3; ++i) CloseHandle(h[i]);
}
ESTEST(ese_wait_all_all_signalled_returns_event_0)
{
    HANDLE h[4]; int i; es_mk(h, 4);
    for (i = 0; i < 4; ++i) U(WSASetEvent)(h[i]);
    ES_EQ(es_wfme(4, h, TRUE, 0, FALSE), WSA_WAIT_EVENT_0);
    es_rm(h, 4);
}
ESTEST(ese_wait_all_one_missing_times_out)
{
    HANDLE h[4]; int i; es_mk(h, 4);
    for (i = 0; i < 4; ++i) if (i != 2) U(WSASetEvent)(h[i]);
    ES_EQ(es_wfme(4, h, TRUE, 0, FALSE), WSA_WAIT_TIMEOUT);
    U(WSASetEvent)(h[2]);
    ES_EQ(es_wfme(4, h, TRUE, 0, FALSE), WSA_WAIT_EVENT_0);
    es_rm(h, 4);
}
ESTEST(ese_wait_all_does_not_consume_on_timeout)
{
    /* A failed wait-all leaves auto-reset members signalled. */
    HANDLE h[2];
    h[0] = CreateEventW(NULL, FALSE, TRUE, NULL);
    h[1] = CreateEventW(NULL, FALSE, FALSE, NULL);
    REQUIRE(h[0] && h[1]);
    ES_EQ(es_wfme(2, h, TRUE, 0, FALSE), WSA_WAIT_TIMEOUT);
    CHECK(es_signalled(h[0]));
    SetEvent(h[0]); SetEvent(h[1]);
    ES_EQ(es_wfme(2, h, TRUE, 0, FALSE), WSA_WAIT_EVENT_0);
    CHECK(!es_signalled(h[0]) && !es_signalled(h[1]));   /* both consumed on success */
    CloseHandle(h[0]); CloseHandle(h[1]);
}
ESTEST(ese_wait_all_index_is_always_event_0)
{
    HANDLE h[3]; int i; es_mk(h, 3);
    for (i = 0; i < 3; ++i) U(WSASetEvent)(h[i]);
    ES_EQ(es_wfme(3, h, TRUE, 100, FALSE), 0);
    es_rm(h, 3);
}
ESTEST(ese_wait_count_zero_fails_invalid_parameter)
{
    HANDLE h[1]; es_mk(h, 1);
    U(WSASetEvent)(h[0]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(0, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 1);
}
ESTEST(ese_wait_count_zero_wait_all_fails_invalid_parameter)
{
    HANDLE h[1]; es_mk(h, 1);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(0, h, TRUE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 1);
}
ESTEST(ese_wait_count_zero_infinite_still_fails_at_once)
{
    HANDLE h[1]; es_mk(h, 1);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(0, h, FALSE, WSA_INFINITE, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 1);
}
ESTEST(ese_wait_count_zero_null_array_fails_invalid_parameter)
{
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(0, NULL, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
}
ESTEST(ese_wait_count_64_all_clear_times_out)
{
    HANDLE h[64]; es_mk(h, 64);
    ES_EQ(es_wfme(64, h, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    ES_EQ(es_wfme(64, h, TRUE, 0, FALSE), WSA_WAIT_TIMEOUT);
    es_rm(h, 64);
}
ESTEST(ese_wait_count_64_last_index)
{
    HANDLE h[64]; es_mk(h, 64);
    U(WSASetEvent)(h[63]);
    ES_EQ(es_wfme(64, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 63);
    es_rm(h, 64);
}
ESTEST(ese_wait_count_64_first_index_with_others_set)
{
    HANDLE h[64]; int i; es_mk(h, 64);
    for (i = 0; i < 64; ++i) U(WSASetEvent)(h[i]);
    ES_EQ(es_wfme(64, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    ES_EQ(es_wfme(64, h, TRUE, 0, FALSE), WSA_WAIT_EVENT_0);
    es_rm(h, 64);
}
ESTEST(ese_wait_count_64_wait_all_needs_the_last)
{
    HANDLE h[64]; int i; es_mk(h, 64);
    for (i = 0; i < 63; ++i) U(WSASetEvent)(h[i]);
    ES_EQ(es_wfme(64, h, TRUE, 0, FALSE), WSA_WAIT_TIMEOUT);
    U(WSASetEvent)(h[63]);
    ES_EQ(es_wfme(64, h, TRUE, 0, FALSE), WSA_WAIT_EVENT_0);
    es_rm(h, 64);
}
ESTEST(ese_wait_count_65_fails_invalid_parameter)
{
    HANDLE h[65]; int i; es_mk(h, 65);
    for (i = 0; i < 65; ++i) U(WSASetEvent)(h[i]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(65, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 65);
}
ESTEST(ese_wait_count_65_wait_all_fails_invalid_parameter)
{
    HANDLE h[65]; int i; es_mk(h, 65);
    for (i = 0; i < 65; ++i) U(WSASetEvent)(h[i]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(65, h, TRUE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 65);
}
ESTEST(ese_wait_count_65_first_64_signalled_still_fails)
{
    HANDLE h[65]; int i; es_mk(h, 65);
    for (i = 0; i < 64; ++i) U(WSASetEvent)(h[i]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(65, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 65);
}
ESTEST(ese_wait_count_128_valid_handles_fails)
{
    HANDLE h[128]; int i; es_mk(h, 128);
    for (i = 0; i < 128; ++i) U(WSASetEvent)(h[i]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(128, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(128, h, TRUE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_PARAM);
    es_rm(h, 128);
}
ESTEST(ese_wait_closed_handle_fails_invalid_handle)
{
    HANDLE h[1]; es_mk(h, 1);
    U(WSACloseEvent)(h[0]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(1, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}
ESTEST(ese_wait_null_handle_fails_invalid_handle)
{
    HANDLE h[1] = { NULL };
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(1, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}
ESTEST(ese_wait_closed_handle_among_good_ones_fails)
{
    HANDLE h[3]; es_mk(h, 3);
    U(WSASetEvent)(h[0]);
    U(WSACloseEvent)(h[2]);
    U(WSASetLastError)(0);
    /* the invalid member is detected even though an earlier one is already signalled */
    ES_EQ(es_wfme(3, h, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_HANDLE);
    es_rm(h, 2);
}
ESTEST(ese_wait_closed_handle_wait_all_fails)
{
    HANDLE h[2]; es_mk(h, 2);
    U(WSASetEvent)(h[0]); U(WSASetEvent)(h[1]);
    U(WSACloseEvent)(h[1]);
    U(WSASetLastError)(0);
    ES_EQ(es_wfme(2, h, TRUE, 0, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), ES_ERR_HANDLE);
    es_rm(h, 1);
}
ESTEST(ese_wait_failed_value_is_all_ones)
{
    HANDLE h[1] = { NULL };
    DWORD r = es_wfme(1, h, FALSE, 0, FALSE);
    ES_EQ(r, 0xFFFFFFFFu);
    ES_EQ(r, WAIT_FAILED);
}
ESTEST(ese_wait_duplicate_handle_in_wait_any)
{
    HANDLE h[3]; es_mk(h, 1);
    h[1] = h[0]; h[2] = h[0];
    ES_EQ(es_wfme(3, h, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    U(WSASetEvent)(h[0]);
    ES_EQ(es_wfme(3, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    es_rm(h, 1);
}
ESTEST(ese_wait_accepts_non_event_objects)
{
    HANDLE h[3];
    h[0] = CreateSemaphoreW(NULL, 0, 4, NULL);
    h[1] = CreateMutexW(NULL, FALSE, NULL);     /* free mutex: acquired by the waiter */
    h[2] = es_ev();
    REQUIRE(h[0] && h[1] && h[2]);
    ES_EQ(es_wfme(2, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 1);
    ReleaseMutex(h[1]);
    ReleaseSemaphore(h[0], 1, NULL);
    ES_EQ(es_wfme(3, h, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    ES_EQ(es_wfme(1, h, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);   /* semaphore count consumed */
    CloseHandle(h[0]); CloseHandle(h[1]); U(WSACloseEvent)(h[2]);
}
ESTEST(ese_wait_on_thread_handle_completion)
{
    HANDLE h[2], th;
    DWORD WINAPI quick(void *a) { return 0; }
    h[0] = es_ev();
    th = CreateThread(NULL, 0, quick, NULL, 0, NULL);
    REQUIRE(h[0] && th);
    h[1] = th;
    ES_EQ(es_wfme(2, h, FALSE, 5000, FALSE), WSA_WAIT_EVENT_0 + 1);
    CloseHandle(th); U(WSACloseEvent)(h[0]);
}
ESTEST(ese_wait_other_thread_signals_second_event)
{
    HANDLE h[2], th;
    DWORD WINAPI w(void *a) { Sleep(40); U(WSASetEvent)(((HANDLE *)a)[1]); return 0; }
    es_mk(h, 2);
    th = CreateThread(NULL, 0, w, h, 0, NULL);
    REQUIRE(th);
    ES_EQ(es_wfme(2, h, FALSE, 5000, FALSE), WSA_WAIT_EVENT_0 + 1);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    es_rm(h, 2);
}
ESTEST(ese_wait_all_other_thread_completes_set)
{
    HANDLE h[3], th;
    DWORD WINAPI w(void *a) { HANDLE *e = a; Sleep(20); U(WSASetEvent)(e[0]); Sleep(20); U(WSASetEvent)(e[2]); return 0; }
    es_mk(h, 3);
    U(WSASetEvent)(h[1]);
    th = CreateThread(NULL, 0, w, h, 0, NULL);
    REQUIRE(th);
    ES_EQ(es_wfme(3, h, TRUE, 5000, FALSE), WSA_WAIT_EVENT_0);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    es_rm(h, 3);
}

/* ---- alertable waits ---------------------------------------------------------------------------------- */
static volatile LONG es_apc_hits;
static void WINAPI es_apc(ULONG_PTR p) { InterlockedIncrement(&es_apc_hits); }

ESTEST(ese_wait_alertable_runs_queued_apc)
{
    HANDLE h[1]; es_mk(h, 1);
    es_apc_hits = 0;
    CHECK(QueueUserAPC(es_apc, GetCurrentThread(), 0));
    ES_EQ(es_wfme(1, h, FALSE, 2000, TRUE), WSA_WAIT_IO_COMPLETION);
    ES_EQ(es_apc_hits, 1);
    es_rm(h, 1);
}
ESTEST(ese_wait_nonalertable_leaves_apc_queued)
{
    HANDLE h[1]; es_mk(h, 1);
    es_apc_hits = 0;
    CHECK(QueueUserAPC(es_apc, GetCurrentThread(), 0));
    ES_EQ(es_wfme(1, h, FALSE, 30, FALSE), WSA_WAIT_TIMEOUT);
    ES_EQ(es_apc_hits, 0);
    ES_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    ES_EQ(es_apc_hits, 1);
    es_rm(h, 1);
}
ESTEST(ese_wait_alertable_with_signalled_event_and_queued_apc)
{
    /* Which of the two the call reports is a scheduling detail; both must be consistent with the APC. */
    HANDLE h[1]; es_mk(h, 1);
    es_apc_hits = 0;
    U(WSASetEvent)(h[0]);
    CHECK(QueueUserAPC(es_apc, GetCurrentThread(), 0));
    { DWORD r = es_wfme(1, h, FALSE, 0, TRUE);
      CHECKF(r == WSA_WAIT_EVENT_0 || r == WSA_WAIT_IO_COMPLETION, "r=%lu", r);
      t_note("signalled+alertable wait reported %s", r == WSA_WAIT_EVENT_0 ? "event" : "apc"); }
    SleepEx(0, TRUE);
    ES_EQ(es_apc_hits, 1);
    es_rm(h, 1);
}
ESTEST(ese_wait_alertable_two_apcs_both_run_before_return)
{
    HANDLE h[1]; es_mk(h, 1);
    es_apc_hits = 0;
    QueueUserAPC(es_apc, GetCurrentThread(), 0);
    QueueUserAPC(es_apc, GetCurrentThread(), 0);
    ES_EQ(es_wfme(1, h, FALSE, 2000, TRUE), WSA_WAIT_IO_COMPLETION);
    ES_EQ(es_apc_hits, 2);
    es_rm(h, 1);
}
ESTEST(ese_wait_alertable_wait_all_also_alertable)
{
    HANDLE h[2]; es_mk(h, 2);
    es_apc_hits = 0;
    QueueUserAPC(es_apc, GetCurrentThread(), 0);
    ES_EQ(es_wfme(2, h, TRUE, 2000, TRUE), WSA_WAIT_IO_COMPLETION);
    ES_EQ(es_apc_hits, 1);
    es_rm(h, 2);
}
static volatile LONG es_cr_hits; static volatile DWORD es_cr_err, es_cr_len;
static void CALLBACK es_cr(DWORD err, DWORD len, LPWSAOVERLAPPED ov, DWORD fl)
{
    es_cr_err = err; es_cr_len = len; InterlockedIncrement(&es_cr_hits);
}
ESTEST(ese_wait_alertable_runs_overlapped_completion_routine)
{
    struct sockaddr_in a; SOCKET rx = es_udp(&a), tx = es_udp(NULL);
    HANDLE h[1]; WSAOVERLAPPED ov; WSABUF wb; char buf[8]; DWORD got = 0, fl = 0; int r;
    REQUIRE(rx != INVALID_SOCKET && tx != INVALID_SOCKET);
    es_mk(h, 1);
    memset(&ov, 0, sizeof(ov)); es_cr_hits = 0; es_cr_err = 99; es_cr_len = 99;
    wb.buf = buf; wb.len = sizeof(buf);
    SOCKET ovs = U(WSASocketW)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    REQUIRE(ovs != INVALID_SOCKET);
    { struct sockaddr_in b; int bl = sizeof(b); es_addr(&b, 0); U(bind)(ovs, (struct sockaddr *)&b, sizeof(b)); U(getsockname)(ovs, (struct sockaddr *)&b, &bl); a = b; }
    r = U(WSARecvFrom)(ovs, &wb, 1, &got, &fl, NULL, NULL, &ov, es_cr);
    CHECK(r == SOCKET_ERROR && es_err() == WSA_IO_PENDING);
    CHECK(es_udp_send(tx, &a, "abc", 3) == 3);
    ES_EQ(es_wfme(1, h, FALSE, 3000, TRUE), WSA_WAIT_IO_COMPLETION);
    ES_EQ(es_cr_hits, 1);
    ES_EQ(es_cr_err, 0);
    ES_EQ(es_cr_len, 3);
    es_close(rx); es_close(tx); es_close(ovs); es_rm(h, 1);
}
ESTEST(ese_wait_wsa_constants_match_kernel32)
{
    CHECK(WSA_WAIT_EVENT_0 == WAIT_OBJECT_0);
    CHECK(WSA_WAIT_TIMEOUT == WAIT_TIMEOUT);
    CHECK(WSA_WAIT_IO_COMPLETION == WAIT_IO_COMPLETION);
    CHECK(WSA_WAIT_FAILED == WAIT_FAILED);
    CHECK(WSA_MAXIMUM_WAIT_EVENTS == MAXIMUM_WAIT_OBJECTS);
}
