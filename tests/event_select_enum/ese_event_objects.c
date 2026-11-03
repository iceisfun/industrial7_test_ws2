/* Measures the WSA event-object API: WSACreateEvent (a manual-reset, non-signalled, unnamed,
 * non-inheritable event), WSASetEvent / WSAResetEvent / WSACloseEvent on good and bad handles, and the
 * mapping of their failures to ERROR_INVALID_HANDLE.  The wait function is covered in ese_wait.c. */
#include "ese.h"

ESTEST(ese_wait_constants)
{
    CHECK(WSA_WAIT_EVENT_0 == 0);
    CHECK(WSA_WAIT_TIMEOUT == 258);
    CHECK(WSA_WAIT_IO_COMPLETION == 192);
    CHECK(WSA_WAIT_FAILED == (DWORD)0xFFFFFFFF);
    CHECK(WSA_INFINITE == (DWORD)0xFFFFFFFF);
    CHECK(WSA_MAXIMUM_WAIT_EVENTS == 64);
    CHECK(WSA_INVALID_HANDLE == 6);
    CHECK(WSA_INVALID_PARAMETER == 87);
}

ESTEST(ese_fd_constants)
{
    CHECK(FD_READ == 0x01 && FD_WRITE == 0x02 && FD_OOB == 0x04 && FD_ACCEPT == 0x08);
    CHECK(FD_CONNECT == 0x10 && FD_CLOSE == 0x20 && FD_QOS == 0x40 && FD_GROUP_QOS == 0x80);
    CHECK(FD_ROUTING_INTERFACE_CHANGE == 0x100 && FD_ADDRESS_LIST_CHANGE == 0x200);
    CHECK(FD_ALL_EVENTS == 0x3ff);
    CHECK(FD_MAX_EVENTS == 10);
    CHECK(sizeof(WSANETWORKEVENTS) == 4 + 4 * FD_MAX_EVENTS);
}

ESTEST(ese_create_returns_handle)
{
    HANDLE ev = es_ev();
    CHECK(ev != NULL);
    CHECK(ev != INVALID_HANDLE_VALUE);
    U(WSACloseEvent)(ev);
}

ESTEST(ese_create_not_signalled)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    U(WSACloseEvent)(ev);
}

ESTEST(ese_create_is_manual_reset)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSASetEvent)(ev));
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    U(WSACloseEvent)(ev);
}

ESTEST(ese_create_distinct_handles)
{
    HANDLE a = es_ev(), b = es_ev();
    REQUIRE(a && b);
    CHECK(a != b);
    CHECK(U(WSASetEvent)(a));
    ES_EQ(WaitForSingleObject(b, 0), WAIT_TIMEOUT);
    U(WSACloseEvent)(a); U(WSACloseEvent)(b);
}

ESTEST(ese_create_not_inheritable)
{
    HANDLE ev = es_ev(); DWORD fl = 0xFFFF;
    REQUIRE(ev);
    CHECK(GetHandleInformation(ev, &fl));
    CHECK((fl & HANDLE_FLAG_INHERIT) == 0);
    U(WSACloseEvent)(ev);
}

ESTEST(ese_create_event_reachable_by_kernel32_calls)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(SetEvent(ev));
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    CHECK(ResetEvent(ev));
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    CHECK(U(WSACloseEvent)(ev));
}

ESTEST(ese_create_many_then_close_all)
{
    HANDLE ev[32]; int i;
    for (i = 0; i < 32; ++i) { ev[i] = es_ev(); CHECK(ev[i] != NULL); }
    for (i = 0; i < 32; ++i) CHECK(U(WSACloseEvent)(ev[i]));
}

ESTEST(ese_set_returns_true_and_signals)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSASetEvent)(ev) == TRUE);
    CHECK(es_signalled(ev));
    U(WSACloseEvent)(ev);
}

ESTEST(ese_set_twice_is_fine)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSASetEvent)(ev) == TRUE);
    CHECK(U(WSASetEvent)(ev) == TRUE);
    CHECK(es_signalled(ev));
    U(WSACloseEvent)(ev);
}

ESTEST(ese_reset_returns_true_and_clears)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    U(WSASetEvent)(ev);
    CHECK(U(WSAResetEvent)(ev) == TRUE);
    CHECK(!es_signalled(ev));
    U(WSACloseEvent)(ev);
}

ESTEST(ese_reset_of_clear_event_is_fine)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAResetEvent)(ev) == TRUE);
    CHECK(U(WSAResetEvent)(ev) == TRUE);
    CHECK(!es_signalled(ev));
    U(WSACloseEvent)(ev);
}

ESTEST(ese_set_reset_cycle)
{
    HANDLE ev = es_ev(); int i;
    REQUIRE(ev);
    for (i = 0; i < 10; ++i) {
        CHECK(U(WSASetEvent)(ev));
        CHECK(es_signalled(ev));
        CHECK(U(WSAResetEvent)(ev));
        CHECK(!es_signalled(ev));
    }
    U(WSACloseEvent)(ev);
}

ESTEST(ese_set_reset_work_on_auto_reset_event)
{
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    REQUIRE(ev);
    CHECK(U(WSASetEvent)(ev));
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);       /* auto-reset consumed */
    CHECK(U(WSASetEvent)(ev));
    CHECK(U(WSAResetEvent)(ev));
    ES_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    CHECK(U(WSACloseEvent)(ev));
}

ESTEST(ese_close_returns_true)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSACloseEvent)(ev) == TRUE);
}

ESTEST(ese_close_invalidates_handle)
{
    HANDLE ev = es_ev(); DWORD r;
    REQUIRE(ev);
    CHECK(U(WSACloseEvent)(ev));
    SetLastError(0);
    r = WaitForSingleObject(ev, 0);
    CHECK(r == WAIT_FAILED);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

ESTEST(ese_close_twice_fails_with_invalid_handle)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSACloseEvent)(ev));
    U(WSASetLastError)(0);
    CHECK(U(WSACloseEvent)(ev) == FALSE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_close_null_fails_with_invalid_handle)
{
    U(WSASetLastError)(0);
    CHECK(U(WSACloseEvent)(NULL) == FALSE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_close_other_object_types_succeeds)
{
    /* WSACloseEvent is a plain handle close: any kernel handle is accepted. */
    HANDLE m = CreateMutexW(NULL, FALSE, NULL);
    HANDLE s = CreateSemaphoreW(NULL, 0, 1, NULL);
    REQUIRE(m && s);
    CHECK(U(WSACloseEvent)(m));
    CHECK(U(WSACloseEvent)(s));
}

ESTEST(ese_close_failure_sets_wsa_error_not_just_win32)
{
    /* The failure code is visible through both error accessors. */
    U(WSASetLastError)(0);
    SetLastError(0);
    CHECK(U(WSACloseEvent)(NULL) == FALSE);
    ES_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_set_null_fails_with_invalid_handle)
{
    U(WSASetLastError)(0);
    CHECK(U(WSASetEvent)(NULL) == FALSE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_reset_null_fails_with_invalid_handle)
{
    U(WSASetLastError)(0);
    CHECK(U(WSAResetEvent)(NULL) == FALSE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_set_closed_handle_fails_with_invalid_handle)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    U(WSACloseEvent)(ev);
    U(WSASetLastError)(0);
    CHECK(U(WSASetEvent)(ev) == FALSE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_reset_closed_handle_fails_with_invalid_handle)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    U(WSACloseEvent)(ev);
    U(WSASetLastError)(0);
    CHECK(U(WSAResetEvent)(ev) == FALSE);
    ES_EQ(es_err(), ES_ERR_HANDLE);
}

ESTEST(ese_set_wrong_object_type_fails)
{
    HANDLE m = CreateMutexW(NULL, FALSE, NULL);
    REQUIRE(m);
    U(WSASetLastError)(0);
    CHECK(U(WSASetEvent)(m) == FALSE);
    t_note("WSASetEvent(mutex) error is %s", es_err() == ERROR_INVALID_HANDLE ? "invalid-handle" : "other");
    CloseHandle(m);
}

ESTEST(ese_reset_wrong_object_type_fails)
{
    HANDLE s = CreateSemaphoreW(NULL, 1, 1, NULL);
    REQUIRE(s);
    U(WSASetLastError)(0);
    CHECK(U(WSAResetEvent)(s) == FALSE);
    t_note("WSAResetEvent(semaphore) error is %s", es_err() == ERROR_INVALID_HANDLE ? "invalid-handle" : "other");
    CloseHandle(s);
}

ESTEST(ese_success_calls_error_state_observed)
{
    HANDLE ev = es_ev();
    REQUIRE(ev);
    U(WSASetLastError)(777);
    CHECK(U(WSASetEvent)(ev));
    CHECK(U(WSAResetEvent)(ev));
    CHECK(U(WSACloseEvent)(ev));
    t_note("last error after successful event calls is %s", es_err() == 777 ? "untouched" : "changed");
}

ESTEST(ese_close_event_in_flight_selected_socket_survives)
{
    /* Closing the event while a socket still has it selected neither fails nor disturbs the socket. */
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev(); int r;
    REQUIRE(s != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(s, ev, FD_READ | FD_CLOSE) == 0);
    CHECK(U(WSACloseEvent)(ev));
    r = es_mask(s, NULL);
    ES_EQ(r, 0);
    es_close(s);
}

ESTEST(ese_set_event_from_other_thread_wakes_waiter)
{
    struct tp { HANDLE ev; } p;
    HANDLE ev = es_ev(), th; DWORD r;
    DWORD WINAPI worker(void *a) { Sleep(50); U(WSASetEvent)(((struct tp *)a)->ev); return 0; }
    REQUIRE(ev);
    p.ev = ev;
    th = CreateThread(NULL, 0, worker, &p, 0, NULL);
    REQUIRE(th);
    r = WaitForSingleObject(ev, 5000);
    ES_EQ(r, WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0);
    CloseHandle(th);
    U(WSACloseEvent)(ev);
}
