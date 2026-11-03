/* Event objects and the per-thread error slot, seen through the Winsock event API.
 *
 * WSACreateEvent / WSASetEvent / WSAResetEvent / WSACloseEvent are thin layers over the kernel event
 * calls: they need no started stack, report failures as Win32 errors in the shared per-thread slot, and
 * hand back handles that interoperate with the plain Win32 wait and signal calls. WSAWaitForMultipleEvents
 * adds the Winsock names for the wait outcomes and an argument check on the count. These tests pin the
 * argument and state errors and the wait-outcome numbering; every wait is polled (zero timeout) or has a
 * signalled object, so nothing here depends on elapsed time. */
#include "qm.h"

static VOID CALLBACK noop_apc(ULONG_PTR p) { (void)p; }

static DWORD WINAPI slot_thread(LPVOID p)
{
    /* out[0] records what the slot holds at thread start (not asserted: the loader may leave a value). */
    LONG *out = (LONG *)p;
    out[0] = (LONG)U(WSAGetLastError)();
    U(WSASetLastError)(WSAEMFILE);
    out[1] = (LONG)U(WSAGetLastError)();
    return 0;
}

TEST(event_create_is_manual_reset_and_not_signalled)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    CHECK(e != WSA_INVALID_EVENT && e != NULL);
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_TIMEOUT);
    CHECK(SetEvent(e));
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);        /* a wait does not reset a manual-reset event */
    CHECK(U(WSACloseEvent)(e));
}
TEST(event_create_gives_distinct_handles)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE a = U(WSACreateEvent)(), b = U(WSACreateEvent)();
    CHECK(a != b);
    CHECK(U(WSASetEvent)(a));
    EXPECT_EQ(WaitForSingleObject(b, 0), WAIT_TIMEOUT);         /* signalling one leaves the other alone */
    U(WSACloseEvent)(a); U(WSACloseEvent)(b);
}
TEST(event_set_and_reset_are_idempotent)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSASetEvent)); REQUIRE(U(WSAResetEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    EXPECT_EQ(U(WSAResetEvent)(e), TRUE);                       /* resetting a clear event is not an error */
    EXPECT_EQ(U(WSASetEvent)(e), TRUE);
    EXPECT_EQ(U(WSASetEvent)(e), TRUE);                         /* setting a set event is not an error */
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);
    EXPECT_EQ(U(WSAResetEvent)(e), TRUE);
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_TIMEOUT);
    U(WSACloseEvent)(e);
}
TEST(event_set_reset_on_closed_handle_are_invalid_handle)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSASetEvent)); REQUIRE(U(WSAResetEvent));
    HANDLE e = U(WSACreateEvent)();
    CHECK(CloseHandle(e));
    SET_ERR(0);
    EXPECT_EQ(U(WSASetEvent)(e), FALSE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    SET_ERR(0);
    EXPECT_EQ(U(WSAResetEvent)(e), FALSE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
}
TEST(event_set_reset_on_wrong_object_type_are_invalid_handle)
{
    REQUIRE(U(WSASetEvent)); REQUIRE(U(WSAResetEvent));
    HANDLE m = CreateMutexA(NULL, FALSE, NULL);
    SET_ERR(0);
    EXPECT_EQ(U(WSASetEvent)(m), FALSE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    SET_ERR(0);
    EXPECT_EQ(U(WSAResetEvent)(m), FALSE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    CloseHandle(m);
}
TEST(event_set_reset_on_never_valid_values_are_invalid_handle)
{
    REQUIRE(U(WSASetEvent)); REQUIRE(U(WSAResetEvent));
    static const ULONG_PTR rows[] = { 0, 0x6FFFC, (ULONG_PTR)-2 };
    for (int i = 0; i < QM_N(rows); i++) {
        SET_ERR(0);
        BOOL a = U(WSASetEvent)((HANDLE)rows[i]);
        DWORD ea = GetLastError();
        SET_ERR(0);
        BOOL b = U(WSAResetEvent)((HANDLE)rows[i]);
        DWORD eb = GetLastError();
        t_check(!a && !b && ea == ERROR_INVALID_HANDLE && eb == ERROR_INVALID_HANDLE, __FILE__, __LINE__, "event call on invalid value",
                "row %d set %d/%lu reset %d/%lu", i, a, ea, b, eb);
    }
}
TEST(event_close_succeeds_and_leaves_the_slot_alone)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    SET_ERR(0x5151);
    EXPECT_EQ(U(WSACloseEvent)(e), TRUE);
    EXPECT_EQ(GetLastError(), 0x5151);
}
TEST(event_close_twice_second_is_invalid_handle)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    EXPECT_EQ(U(WSACloseEvent)(e), TRUE);
    SET_ERR(0);
    EXPECT_EQ(U(WSACloseEvent)(e), FALSE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
}
TEST(event_set_on_a_closed_handle_does_not_signal_a_new_one)
{
    /* The failure is a clean error on the stale value, not an effect on whatever object may live there now. */
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSASetEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    HANDLE other = U(WSACreateEvent)();
    U(WSACloseEvent)(e);
    EXPECT_EQ(U(WSASetEvent)(e), FALSE);
    EXPECT_EQ(WaitForSingleObject(other, 0), WAIT_TIMEOUT);
    U(WSACloseEvent)(other);
}

/* ---- WSAWaitForMultipleEvents outcomes --------------------------------------------------------------- */

TEST(wait_any_reports_the_index_of_a_signalled_event)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE ev[3];
    for (int i = 0; i < 3; i++) ev[i] = U(WSACreateEvent)();
    CHECK(SetEvent(ev[2]));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(3, ev, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 2);
    CHECK(SetEvent(ev[1]));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(3, ev, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + 1);     /* lowest index wins */
    for (int i = 0; i < 3; i++) U(WSACloseEvent)(ev[i]);
}
TEST(wait_all_needs_every_event)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE ev[2] = { U(WSACreateEvent)(), U(WSACreateEvent)() };
    CHECK(SetEvent(ev[0]));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(2, ev, TRUE, 0, FALSE), WSA_WAIT_TIMEOUT);
    CHECK(SetEvent(ev[1]));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(2, ev, TRUE, 0, FALSE), WSA_WAIT_EVENT_0);
    U(WSACloseEvent)(ev[0]); U(WSACloseEvent)(ev[1]);
}
TEST(wait_sixty_four_events_is_allowed)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE ev[WSA_MAXIMUM_WAIT_EVENTS];
    for (int i = 0; i < WSA_MAXIMUM_WAIT_EVENTS; i++) ev[i] = U(WSACreateEvent)();
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(WSA_MAXIMUM_WAIT_EVENTS, ev, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    CHECK(SetEvent(ev[WSA_MAXIMUM_WAIT_EVENTS - 1]));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(WSA_MAXIMUM_WAIT_EVENTS, ev, FALSE, 0, FALSE), WSA_WAIT_EVENT_0 + WSA_MAXIMUM_WAIT_EVENTS - 1);
    for (int i = 0; i < WSA_MAXIMUM_WAIT_EVENTS; i++) U(WSACloseEvent)(ev[i]);
}
TEST(wait_outcome_constants_are_the_win32_ones)
{
    EXPECT_EQ(WSA_WAIT_EVENT_0, WAIT_OBJECT_0);
    EXPECT_EQ(WSA_WAIT_TIMEOUT, WAIT_TIMEOUT);
    EXPECT_EQ(WSA_WAIT_IO_COMPLETION, WAIT_IO_COMPLETION);
    EXPECT_EQ(WSA_WAIT_FAILED, WAIT_FAILED);
    EXPECT_EQ(WSA_MAXIMUM_WAIT_EVENTS, MAXIMUM_WAIT_OBJECTS);
}
TEST(wait_alertable_with_a_queued_apc_returns_io_completion)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    CHECK(QueueUserAPC(noop_apc, GetCurrentThread(), 0));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 5000, TRUE), WSA_WAIT_IO_COMPLETION);
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, TRUE), WSA_WAIT_TIMEOUT);     /* the APC was consumed */
    U(WSACloseEvent)(e);
}
TEST(wait_non_alertable_leaves_a_queued_apc_pending)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    HANDLE e = U(WSACreateEvent)();
    CHECK(QueueUserAPC(noop_apc, GetCurrentThread(), 0));
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    EXPECT_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);                                    /* drain it */
    U(WSACloseEvent)(e);
}
TEST(wait_on_a_non_event_waitable_works_like_the_win32_wait)
{
    /* The wait is the plain kernel wait: any waitable handle is accepted, not only events. */
    REQUIRE(U(WSAWaitForMultipleEvents));
    HANDLE m = CreateMutexA(NULL, FALSE, NULL);
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(1, &m, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);
    ReleaseMutex(m);
    CloseHandle(m);
}
TEST(wait_count_errors_do_not_need_startup)
{
    REQUIRE(U(WSAWaitForMultipleEvents));
    RUN_CHILD("wait_no_startup", "", 20000);
}
CHILD(wait_no_startup)
{
    HANDLE e = CreateEventA(NULL, TRUE, TRUE, NULL);
    STEP(1, U(WSAWaitForMultipleEvents) != NULL);
    STEP(2, U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE) == WSA_WAIT_EVENT_0);
    SET_ERR(0);
    STEP(3, U(WSAWaitForMultipleEvents)(0, &e, FALSE, 0, FALSE) == WSA_WAIT_FAILED);
    STEP(4, GetLastError() == WSA_INVALID_PARAMETER);
    CloseHandle(e);
    return 0;
}

/* ---- the per-thread error slot ---------------------------------------------------------------------- */

TEST(errslot_wsa_set_and_get_round_trip_through_getlasterror)
{
    REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    U(WSASetLastError)(WSAEMFILE);
    EXPECT_EQ(U(WSAGetLastError)(), WSAEMFILE);
    EXPECT_EQ(GetLastError(), WSAEMFILE);
    SET_ERR(ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(U(WSAGetLastError)(), ERROR_FILE_NOT_FOUND);
    U(WSASetLastError)(0);
    EXPECT_EQ(GetLastError(), 0);
}
TEST(errslot_is_per_thread)
{
    REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    LONG out[2] = { -1, -1 };
    U(WSASetLastError)(WSAECONNRESET);
    HANDLE t = CreateThread(NULL, 0, slot_thread, out, 0, NULL);
    if (!t) { t_skip("no thread"); return; }
    EXPECT_EQ(WaitForSingleObject(t, 5000), WAIT_OBJECT_0);
    CloseHandle(t);
    CHECK(out[0] != WSAECONNRESET);                     /* the creator's value is not inherited */
    EXPECT_EQ(out[1], WSAEMFILE);
    EXPECT_EQ(U(WSAGetLastError)(), WSAECONNRESET);     /* the other thread's writes did not reach this slot */
}
TEST(errslot_set_accepts_any_value_without_a_stack)
{
    REQUIRE(U(WSASetLastError));
    RUN_CHILD("slot_no_startup", "", 20000);
}
CHILD(slot_no_startup)
{
    STEP(1, U(WSASetLastError) != NULL && U(WSAGetLastError) != NULL);
    U(WSASetLastError)(0x12345);
    STEP(2, U(WSAGetLastError)() == 0x12345);
    STEP(3, GetLastError() == 0x12345);
    return 0;
}
TEST(isblocking_is_false_on_a_thread_that_never_blocked)
{
    REQUIRE(U(WSAIsBlocking)); QM_NEED_WSA();
    EXPECT_EQ(U(WSAIsBlocking)(), FALSE);
}
CHILD(isblocking_no_startup)
{
    STEP(1, U(WSAIsBlocking) != NULL);
    STEP(2, U(WSAIsBlocking)() == FALSE);
    return 0;
}
TEST(isblocking_before_startup_is_false)
{
    REQUIRE(U(WSAIsBlocking));
    RUN_CHILD("isblocking_no_startup", "", 20000);
}

/* ---- the socket-flavoured byte-order helpers on handles that are not live sockets ------------------- */

TEST(wsa_byteorder_helpers_on_a_closed_socket_are_enotsock)
{
    REQUIRE(U(WSAHtonl)); REQUIRE(U(WSAHtons)); REQUIRE(U(WSANtohl)); REQUIRE(U(WSANtohs)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM); qm_close(s);
    u_long l = 0x01020304; u_short w = 0x0102;
    SETWSAERR(0);
    EXPECT_EQ(U(WSAHtonl)(s, l, &l), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    SETWSAERR(0);
    EXPECT_EQ(U(WSANtohl)(s, l, &l), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    SETWSAERR(0);
    EXPECT_EQ(U(WSAHtons)(s, w, &w), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    SETWSAERR(0);
    EXPECT_EQ(U(WSANtohs)(s, w, &w), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
}
TEST(wsa_byteorder_helpers_on_an_event_handle_are_enotsock)
{
    REQUIRE(U(WSAHtonl)); REQUIRE(U(WSAHtons)); QM_NEED_WSA();
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL);
    u_long l = 1; u_short w = 1;
    SETWSAERR(0);
    EXPECT_EQ(U(WSAHtonl)((SOCKET)e, l, &l), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    SETWSAERR(0);
    EXPECT_EQ(U(WSAHtons)((SOCKET)e, w, &w), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    CloseHandle(e);
}
TEST(wsa_byteorder_helpers_on_a_live_socket_swap)
{
    REQUIRE(U(WSAHtonl)); REQUIRE(U(WSAHtons)); REQUIRE(U(WSANtohl)); REQUIRE(U(WSANtohs)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM);
    u_long l = 0, l2 = 0; u_short w = 0, w2 = 0;
    EXPECT_EQ(U(WSAHtonl)(s, 0x01020304, &l), 0);
    EXPECT_EQ(l, 0x04030201);
    EXPECT_EQ(U(WSANtohl)(s, l, &l2), 0);
    EXPECT_EQ(l2, 0x01020304);
    EXPECT_EQ(U(WSAHtons)(s, 0x0102, &w), 0);
    EXPECT_EQ(w, 0x0201);
    EXPECT_EQ(U(WSANtohs)(s, w, &w2), 0);
    EXPECT_EQ(w2, 0x0102);
    qm_close(s);
}
