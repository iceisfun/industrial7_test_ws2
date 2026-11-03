/* x_error_mapping / numeric values of the Winsock error and wait constants, and their relation to the Win32 ones. */
#include "xe.h"

typedef struct { const char *name; long have; long want; } kv;
#define K(n, v) { #n, (long)(n), (long)(v) }
static void check_table(const kv *t, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++) t_check(t[i].have == t[i].want, "x_error_mapping", 0, t[i].name, "%s: %ld vs %ld", t[i].name, t[i].have, t[i].want);
}
#define TABLE(name, ...) TEST(name) { static const kv t[] = { __VA_ARGS__ }; check_table(t, sizeof t / sizeof t[0]); }

TABLE(xeconst_wsae_block_10004,
    K(WSAEINTR, 10004), K(WSAEBADF, 10009), K(WSAEACCES, 10013), K(WSAEFAULT, 10014), K(WSAEINVAL, 10022), K(WSAEMFILE, 10024))
TABLE(xeconst_wsae_block_10035,
    K(WSAEWOULDBLOCK, 10035), K(WSAEINPROGRESS, 10036), K(WSAEALREADY, 10037), K(WSAENOTSOCK, 10038), K(WSAEDESTADDRREQ, 10039),
    K(WSAEMSGSIZE, 10040), K(WSAEPROTOTYPE, 10041), K(WSAENOPROTOOPT, 10042), K(WSAEPROTONOSUPPORT, 10043), K(WSAESOCKTNOSUPPORT, 10044),
    K(WSAEOPNOTSUPP, 10045), K(WSAEPFNOSUPPORT, 10046), K(WSAEAFNOSUPPORT, 10047), K(WSAEADDRINUSE, 10048), K(WSAEADDRNOTAVAIL, 10049))
TABLE(xeconst_wsae_block_10050,
    K(WSAENETDOWN, 10050), K(WSAENETUNREACH, 10051), K(WSAENETRESET, 10052), K(WSAECONNABORTED, 10053), K(WSAECONNRESET, 10054),
    K(WSAENOBUFS, 10055), K(WSAEISCONN, 10056), K(WSAENOTCONN, 10057), K(WSAESHUTDOWN, 10058), K(WSAETOOMANYREFS, 10059),
    K(WSAETIMEDOUT, 10060), K(WSAECONNREFUSED, 10061), K(WSAELOOP, 10062), K(WSAENAMETOOLONG, 10063), K(WSAEHOSTDOWN, 10064),
    K(WSAEHOSTUNREACH, 10065), K(WSAENOTEMPTY, 10066), K(WSAEPROCLIM, 10067), K(WSAEUSERS, 10068), K(WSAEDQUOT, 10069),
    K(WSAESTALE, 10070), K(WSAEREMOTE, 10071))
TABLE(xeconst_wsa_system_block,
    K(WSASYSNOTREADY, 10091), K(WSAVERNOTSUPPORTED, 10092), K(WSANOTINITIALISED, 10093), K(WSAEDISCON, 10101), K(WSAENOMORE, 10102),
    K(WSAECANCELLED, 10103), K(WSAEINVALIDPROCTABLE, 10104), K(WSAEINVALIDPROVIDER, 10105), K(WSAEPROVIDERFAILEDINIT, 10106),
    K(WSASYSCALLFAILURE, 10107), K(WSASERVICE_NOT_FOUND, 10108), K(WSATYPE_NOT_FOUND, 10109), K(WSA_E_NO_MORE, 10110),
    K(WSA_E_CANCELLED, 10111), K(WSAEREFUSED, 10112))
TABLE(xeconst_name_service_block,
    K(WSAHOST_NOT_FOUND, 11001), K(WSATRY_AGAIN, 11002), K(WSANO_RECOVERY, 11003), K(WSANO_DATA, 11004), K(WSA_QOS_RECEIVERS, 11005),
    K(WSA_QOS_SENDERS, 11006), K(WSA_QOS_NO_SENDERS, 11007), K(WSA_QOS_NO_RECEIVERS, 11008), K(WSA_QOS_REQUEST_CONFIRMED, 11009),
    K(WSA_QOS_ADMISSION_FAILURE, 11010), K(WSA_QOS_POLICY_FAILURE, 11011), K(WSA_QOS_BAD_STYLE, 11012), K(WSA_QOS_BAD_OBJECT, 11013),
    K(WSA_QOS_TRAFFIC_CTRL_ERROR, 11014), K(WSA_QOS_GENERIC_ERROR, 11015), K(WSA_QOS_ESERVICETYPE, 11016), K(WSA_QOS_EFLOWSPEC, 11017),
    K(WSA_QOS_EPROVSPECBUF, 11018), K(WSA_QOS_EFILTERSTYLE, 11019), K(WSA_QOS_EFILTERTYPE, 11020), K(WSA_QOS_EFILTERCOUNT, 11021),
    K(WSA_QOS_EOBJLENGTH, 11022), K(WSA_QOS_EFLOWCOUNT, 11023), K(WSA_QOS_EUNKOWNPSOBJ, 11024), K(WSA_QOS_EPOLICYOBJ, 11025),
    K(WSA_QOS_EFLOWDESC, 11026), K(WSA_QOS_EPSFLOWSPEC, 11027), K(WSA_QOS_EPSFILTERSPEC, 11028), K(WSA_QOS_ESDMODEOBJ, 11029),
    K(WSA_QOS_ESHAPERATEOBJ, 11030), K(WSA_QOS_RESERVED_PETYPE, 11031))
TABLE(xeconst_wsa_aliases_of_win32_errors,
    K(WSA_IO_PENDING, ERROR_IO_PENDING), K(WSA_IO_INCOMPLETE, ERROR_IO_INCOMPLETE), K(WSA_INVALID_HANDLE, ERROR_INVALID_HANDLE),
    K(WSA_INVALID_PARAMETER, ERROR_INVALID_PARAMETER), K(WSA_NOT_ENOUGH_MEMORY, ERROR_NOT_ENOUGH_MEMORY),
    K(WSA_OPERATION_ABORTED, ERROR_OPERATION_ABORTED))
TABLE(xeconst_wsa_alias_literals,
    K(WSA_IO_PENDING, 997), K(WSA_IO_INCOMPLETE, 996), K(WSA_INVALID_HANDLE, 6), K(WSA_INVALID_PARAMETER, 87),
    K(WSA_NOT_ENOUGH_MEMORY, 8), K(WSA_OPERATION_ABORTED, 995))
TABLE(xeconst_wait_constants,
    K(WSA_WAIT_FAILED, -1), K(WSA_WAIT_EVENT_0, 0), K(WSA_WAIT_IO_COMPLETION, 192), K(WSA_WAIT_TIMEOUT, 258),
    K(WSA_MAXIMUM_WAIT_EVENTS, 64))
TABLE(xeconst_wait_alias_relations,
    K(WSA_WAIT_FAILED, WAIT_FAILED), K(WSA_WAIT_EVENT_0, WAIT_OBJECT_0), K(WSA_WAIT_IO_COMPLETION, WAIT_IO_COMPLETION),
    K(WSA_WAIT_TIMEOUT, WAIT_TIMEOUT), K(WSA_MAXIMUM_WAIT_EVENTS, MAXIMUM_WAIT_OBJECTS))
TABLE(xeconst_eai_equals_wsa_error,
    K(EAI_AGAIN, WSATRY_AGAIN), K(EAI_BADFLAGS, WSAEINVAL), K(EAI_FAIL, WSANO_RECOVERY), K(EAI_FAMILY, WSAEAFNOSUPPORT),
    K(EAI_MEMORY, WSA_NOT_ENOUGH_MEMORY), K(EAI_NONAME, WSAHOST_NOT_FOUND), K(EAI_SERVICE, WSATYPE_NOT_FOUND),
    K(EAI_SOCKTYPE, WSAESOCKTNOSUPPORT))
TABLE(xeconst_eai_literals,
    K(EAI_AGAIN, 11002), K(EAI_BADFLAGS, 10022), K(EAI_FAIL, 11003), K(EAI_FAMILY, 10047), K(EAI_MEMORY, 8), K(EAI_NONAME, 11001),
    K(EAI_SERVICE, 10109), K(EAI_SOCKTYPE, 10044))
TABLE(xeconst_h_errno_names,
    K(HOST_NOT_FOUND, 11001), K(TRY_AGAIN, 11002), K(NO_RECOVERY, 11003), K(NO_DATA, 11004), K(NO_ADDRESS, 11004))
TABLE(xeconst_socket_error_values, K(SOCKET_ERROR, -1), K(INVALID_SOCKET, -1), K(WSABASEERR, 10000))

/* ---- the constants as seen through real calls ---- */
TEST(xeconst_wait_timeout_value_from_dll) {
    WSAEVENT e; DWORD r; XE_UP();
    e = WSACreateEvent(); r = WSAWaitForMultipleEvents(1, &e, FALSE, 0, FALSE);
    CHECK(r == WSA_WAIT_TIMEOUT); CHECK(r == 258); WSACloseEvent(e);
}
TEST(xeconst_wait_event_index_from_dll) {
    WSAEVENT e[3]; DWORD r; int i; XE_UP();
    for (i = 0; i < 3; i++) e[i] = WSACreateEvent();
    WSASetEvent(e[2]); r = WSAWaitForMultipleEvents(3, e, FALSE, 0, FALSE);
    CHECK(r == WSA_WAIT_EVENT_0 + 2);
    WSAResetEvent(e[2]); WSASetEvent(e[0]); r = WSAWaitForMultipleEvents(3, e, FALSE, 0, FALSE);
    CHECK(r == WSA_WAIT_EVENT_0);
    for (i = 0; i < 3; i++) WSACloseEvent(e[i]);
}
TEST(xeconst_wait_all_returns_event_0_when_all_set) {
    WSAEVENT e[2]; DWORD r; XE_UP();
    e[0] = WSACreateEvent(); e[1] = WSACreateEvent(); WSASetEvent(e[0]); WSASetEvent(e[1]);
    r = WSAWaitForMultipleEvents(2, e, TRUE, 0, FALSE); CHECK(r == WSA_WAIT_EVENT_0);
    WSAResetEvent(e[1]); r = WSAWaitForMultipleEvents(2, e, TRUE, 0, FALSE); CHECK(r == WSA_WAIT_TIMEOUT);
    WSACloseEvent(e[0]); WSACloseEvent(e[1]);
}
static void CALLBACK apc_nop(ULONG_PTR p) { (void)p; }
TEST(xeconst_wait_io_completion_value_from_dll) {
    WSAEVENT e; DWORD r; XE_UP();
    e = WSACreateEvent(); QueueUserAPC(apc_nop, GetCurrentThread(), 0);
    r = WSAWaitForMultipleEvents(1, &e, FALSE, 1000, TRUE);
    CHECK(r == WSA_WAIT_IO_COMPLETION); CHECK(r == 192); WSACloseEvent(e);
}
TEST(xeconst_wait_failed_value_from_dll) {
    DWORD r; XE_UP();
    r = WSAWaitForMultipleEvents(0, NULL, FALSE, 0, FALSE);
    CHECK(r == WSA_WAIT_FAILED); CHECK(r == 0xffffffffu); CHECK(WSAGetLastError() == WSA_INVALID_PARAMETER);
}
TEST(xeconst_maximum_wait_events_accepted) {
    WSAEVENT e[64]; DWORD r; int i; XE_UP();
    for (i = 0; i < 64; i++) e[i] = WSACreateEvent();
    r = WSAWaitForMultipleEvents(64, e, FALSE, 0, FALSE); CHECK(r == WSA_WAIT_TIMEOUT);
    for (i = 0; i < 64; i++) WSACloseEvent(e[i]);
}
TEST(xeconst_wsa_io_pending_from_overlapped_receive) {
    SOCKET c, s; char b[4]; WSABUF wb = { 4, b }; DWORD n, f = 0; OVERLAPPED o; int rc; XE_UP();
    xe_pair(&c, &s); memset(&o, 0, sizeof o); o.hEvent = WSACreateEvent();
    rc = WSARecv(c, &wb, 1, &n, &f, &o, NULL);
    CHECK(rc == SOCKET_ERROR); CHECK(WSAGetLastError() == WSA_IO_PENDING); CHECK(WSAGetLastError() == ERROR_IO_PENDING);
    CHECK(!WSAGetOverlappedResult(c, &o, &n, FALSE, &f)); CHECK(WSAGetLastError() == WSA_IO_INCOMPLETE);
    closesocket(c); WaitForSingleObject(o.hEvent, 2000); WSACloseEvent(o.hEvent); xe_close(s);
}
TEST(xeconst_wsa_operation_aborted_from_cancel) {
    SOCKET c, s; char b[4]; WSABUF wb = { 4, b }; DWORD n, f = 0; OVERLAPPED o; XE_UP();
    xe_pair(&c, &s); memset(&o, 0, sizeof o); o.hEvent = WSACreateEvent();
    WSARecv(c, &wb, 1, &n, &f, &o, NULL); CancelIoEx((HANDLE)c, &o); WaitForSingleObject(o.hEvent, 2000);
    CHECK(!WSAGetOverlappedResult(c, &o, &n, FALSE, &f)); CHECK(WSAGetLastError() == WSA_OPERATION_ABORTED);
    WSACloseEvent(o.hEvent); xe_close(c); xe_close(s);
}
TEST(xeconst_wsa_invalid_handle_from_event_calls) {
    XE_UP();
    CHECK(!WSASetEvent(NULL)); CHECK(WSAGetLastError() == WSA_INVALID_HANDLE);
    CHECK(!WSAResetEvent(NULL)); CHECK(WSAGetLastError() == WSA_INVALID_HANDLE);
    CHECK(!WSACloseEvent(NULL)); CHECK(WSAGetLastError() == WSA_INVALID_HANDLE);
}
TEST(xeconst_wsa_invalid_parameter_from_wait_with_no_events) {
    XE_UP();
    CHECK(WSAWaitForMultipleEvents(0, NULL, FALSE, 0, FALSE) == WSA_WAIT_FAILED); CHECK(WSAGetLastError() == WSA_INVALID_PARAMETER);
}
TEST(xeconst_wsa_event_create_close_roundtrip) {
    WSAEVENT e; XE_UP();
    e = WSACreateEvent(); CHECK(e != WSA_INVALID_EVENT && e != NULL);
    CHECK(WaitForSingleObject(e, 0) == WAIT_TIMEOUT); CHECK(WSASetEvent(e)); CHECK(WaitForSingleObject(e, 0) == WAIT_OBJECT_0);
    CHECK(WSAResetEvent(e)); CHECK(WaitForSingleObject(e, 0) == WAIT_TIMEOUT); CHECK(WSACloseEvent(e));
}
