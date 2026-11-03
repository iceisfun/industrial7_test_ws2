/* Measures start-up dependence: the event-object API (create, set, reset, close, wait) works in a
 * process that never called WSAStartup, while WSAEventSelect and WSAEnumNetworkEvents fail with
 * WSANOTINITIALISED before the first WSAStartup and after the matching WSACleanup.  Each scenario runs in
 * a fresh child process so that the parent's own start-up does not mask it. */
#include "ese.h"

static int es_bad;
#define KCHK(c) do { if (!(c)) { ++es_bad; printf("  child check failed at line %d: %s\n", __LINE__, #c); } } while (0)

CHILD(noinit_events)
{
    HANDLE ev[2]; DWORD r;
    ev[0] = U(WSACreateEvent)(); ev[1] = U(WSACreateEvent)();
    KCHK(ev[0] && ev[1]);
    KCHK(U(WSASetEvent)(ev[0]) == TRUE);
    r = U(WSAWaitForMultipleEvents)(2, ev, FALSE, 0, FALSE);
    KCHK(r == WSA_WAIT_EVENT_0);
    KCHK(U(WSAResetEvent)(ev[0]) == TRUE);
    r = U(WSAWaitForMultipleEvents)(2, ev, FALSE, 0, FALSE);
    KCHK(r == WSA_WAIT_TIMEOUT);
    r = U(WSAWaitForMultipleEvents)(0, ev, FALSE, 0, FALSE);
    KCHK(r == WSA_WAIT_FAILED);
    KCHK(U(WSACloseEvent)(ev[0]) == TRUE);
    KCHK(U(WSACloseEvent)(ev[1]) == TRUE);
    KCHK(U(WSACloseEvent)(NULL) == FALSE);
    return es_bad;
}
CHILD(noinit_select)
{
    HANDLE ev = U(WSACreateEvent)(); SOCKET fake = (SOCKET)ev; int r;
    WSANETWORKEVENTS ne;
    KCHK(ev != NULL);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(INVALID_SOCKET, ev, FD_READ);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(fake, ev, FD_READ);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(INVALID_SOCKET, NULL, 0);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSASetLastError)(0);
    memset(&ne, 0xCC, sizeof(ne));
    r = U(WSAEnumNetworkEvents)(INVALID_SOCKET, ev, &ne);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSASetLastError)(0);
    r = U(WSAEnumNetworkEvents)(fake, NULL, &ne);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSACloseEvent)(ev);
    return es_bad;
}
CHILD(after_cleanup)
{
    WSADATA d; SOCKET s; HANDLE ev; int r; WSANETWORKEVENTS ne;
    KCHK(U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    KCHK(s != INVALID_SOCKET);
    ev = U(WSACreateEvent)();
    KCHK(U(WSAEventSelect)(s, ev, FD_READ) == 0);
    KCHK(U(WSAEnumNetworkEvents)(s, ev, &ne) == 0);
    KCHK(U(WSACleanup)() == 0);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, ev, FD_READ);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSASetLastError)(0);
    r = U(WSAEnumNetworkEvents)(s, ev, &ne);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    KCHK(U(WSACloseEvent)(ev) == TRUE);                  /* plain handle close, no start-up needed */
    return es_bad;
}
CHILD(nested_startup)
{
    WSADATA d; SOCKET s; HANDLE ev; int r; WSANETWORKEVENTS ne;
    KCHK(U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    KCHK(U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    KCHK(s != INVALID_SOCKET);
    ev = U(WSACreateEvent)();
    KCHK(U(WSACleanup)() == 0);                          /* one reference left */
    KCHK(U(WSAEventSelect)(s, ev, FD_READ) == 0);
    KCHK(U(WSAEnumNetworkEvents)(s, ev, &ne) == 0);
    KCHK(U(WSACleanup)() == 0);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, ev, FD_READ);
    KCHK(r == SOCKET_ERROR);
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED);
    U(WSACloseEvent)(ev);
    return es_bad;
}
CHILD(startup_then_events_on_new_socket)
{
    WSADATA d; SOCKET s; HANDLE ev; WSANETWORKEVENTS ne;
    KCHK(U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    KCHK(U(WSACleanup)() == 0);
    KCHK(U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);        /* restart works */
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ev = U(WSACreateEvent)();
    KCHK(s != INVALID_SOCKET && ev);
    KCHK(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE) == 0);
    KCHK(U(WSAEnumNetworkEvents)(s, ev, &ne) == 0);
    U(closesocket)(s); U(WSACloseEvent)(ev);
    U(WSACleanup)();
    return es_bad;
}

TEST(ese_init_events_work_without_startup)        { ES_EQ(t_run_child("noinit_events", "", 20000), 0); }
TEST(ese_init_select_and_enum_need_startup)       { ES_EQ(t_run_child("noinit_select", "", 20000), 0); }
TEST(ese_init_select_and_enum_fail_after_cleanup) { ES_EQ(t_run_child("after_cleanup", "", 20000), 0); }
TEST(ese_init_nested_startup_counts_references)   { ES_EQ(t_run_child("nested_startup", "", 20000), 0); }
TEST(ese_init_restart_after_cleanup)              { ES_EQ(t_run_child("startup_then_events_on_new_socket", "", 20000), 0); }
