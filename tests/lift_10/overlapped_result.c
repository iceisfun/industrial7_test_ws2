/* WSAGetOverlappedResult.
 * Measures: a value that is not a socket (a bogus number, or a plain duplicated handle) fails with WSAENOTSOCK;
 * the OVERLAPPED status word (Internal) is translated to a result: success statuses return TRUE, STATUS_PENDING
 * and every failure/warning status return FALSE; the thread error is set to the translated Winsock error for
 * failures and to the translated DOS error for successes; unmapped failure statuses become WSAEINVAL; and a
 * wait on an already-signalled event reports completion without running queued user APCs (the wait is not
 * alertable).
 */
#include "w.h"

typedef ULONG (NTAPI *RtlNtStatusToDosErrorNoTeb_pfn)(LONG);

static const struct { LONG status; DWORD error; } k_map[] = {
    { STATUS_PENDING, ERROR_IO_INCOMPLETE },
    { STATUS_BUFFER_OVERFLOW, WSAEMSGSIZE },
    { STATUS_NOT_IMPLEMENTED, WSAEOPNOTSUPP },
    { STATUS_ACCESS_VIOLATION, WSAEFAULT },
    { STATUS_PAGEFILE_QUOTA, WSAENOBUFS },
    { STATUS_INVALID_HANDLE, WSAENOTSOCK },
    { STATUS_NO_SUCH_DEVICE, WSAENETDOWN },
    { STATUS_NO_SUCH_FILE, WSAENETDOWN },
    { STATUS_NO_MEMORY, WSAENOBUFS },
    { STATUS_CONFLICTING_ADDRESSES, WSAENOBUFS },
    { STATUS_ACCESS_DENIED, WSAEACCES },
    { STATUS_BUFFER_TOO_SMALL, WSAEFAULT },
    { STATUS_OBJECT_TYPE_MISMATCH, WSAENOTSOCK },
    { STATUS_OBJECT_NAME_NOT_FOUND, WSAENETDOWN },
    { STATUS_OBJECT_PATH_NOT_FOUND, WSAENETDOWN },
    { STATUS_SHARING_VIOLATION, WSAEADDRINUSE },
    { STATUS_QUOTA_EXCEEDED, WSAENOBUFS },
    { STATUS_TOO_MANY_PAGING_FILES, WSAENOBUFS },
    { STATUS_INSUFFICIENT_RESOURCES, WSAENOBUFS },
    { STATUS_WORKING_SET_QUOTA, WSAENOBUFS },
    { STATUS_DEVICE_NOT_READY, WSAEWOULDBLOCK },
    { STATUS_PIPE_DISCONNECTED, WSAESHUTDOWN },
    { STATUS_IO_TIMEOUT, WSAETIMEDOUT },
    { STATUS_NOT_SUPPORTED, WSAEOPNOTSUPP },
    { STATUS_REMOTE_NOT_LISTENING, WSAECONNREFUSED },
    { STATUS_BAD_NETWORK_PATH, WSAENETUNREACH },
    { STATUS_NETWORK_BUSY, WSAENETDOWN },
    { STATUS_INVALID_NETWORK_RESPONSE, WSAENETDOWN },
    { STATUS_UNEXPECTED_NETWORK_ERROR, WSAENETDOWN },
    { STATUS_REQUEST_NOT_ACCEPTED, WSAEWOULDBLOCK },
    { STATUS_CANCELLED, ERROR_OPERATION_ABORTED },
    { STATUS_COMMITMENT_LIMIT, WSAENOBUFS },
    { STATUS_LOCAL_DISCONNECT, WSAECONNABORTED },
    { STATUS_REMOTE_DISCONNECT, WSAECONNRESET },
    { STATUS_REMOTE_RESOURCES, WSAENOBUFS },
    { STATUS_LINK_FAILED, WSAECONNRESET },
    { STATUS_LINK_TIMEOUT, WSAETIMEDOUT },
    { STATUS_INVALID_CONNECTION, WSAENOTCONN },
    { STATUS_INVALID_ADDRESS, WSAEADDRNOTAVAIL },
    { STATUS_INVALID_BUFFER_SIZE, WSAEMSGSIZE },
    { STATUS_INVALID_ADDRESS_COMPONENT, WSAEADDRNOTAVAIL },
    { STATUS_TOO_MANY_ADDRESSES, WSAENOBUFS },
    { STATUS_ADDRESS_ALREADY_EXISTS, WSAEADDRINUSE },
    { STATUS_CONNECTION_DISCONNECTED, WSAECONNRESET },
    { STATUS_CONNECTION_RESET, WSAECONNRESET },
    { STATUS_TRANSACTION_ABORTED, WSAECONNABORTED },
    { STATUS_CONNECTION_REFUSED, WSAECONNREFUSED },
    { STATUS_GRACEFUL_DISCONNECT, WSAEDISCON },
    { STATUS_CONNECTION_ACTIVE, WSAEISCONN },
    { STATUS_NETWORK_UNREACHABLE, WSAENETUNREACH },
    { STATUS_HOST_UNREACHABLE, WSAEHOSTUNREACH },
    { STATUS_PROTOCOL_UNREACHABLE, WSAENETUNREACH },
    { STATUS_PORT_UNREACHABLE, WSAECONNRESET },
    { STATUS_REQUEST_ABORTED, WSAEINTR },
    { STATUS_CONNECTION_ABORTED, WSAECONNABORTED },
    { STATUS_DATATYPE_MISALIGNMENT_ERROR, WSAEFAULT },
    { STATUS_HOST_DOWN, WSAEHOSTDOWN },
    { (LONG)(0x80070000 | ERROR_IO_INCOMPLETE), ERROR_IO_INCOMPLETE },
    { (LONG)(0xc0010000 | ERROR_IO_INCOMPLETE), ERROR_IO_INCOMPLETE },
    { (LONG)(0xc0070000 | ERROR_IO_INCOMPLETE), ERROR_IO_INCOMPLETE },
};

static RtlNtStatusToDosErrorNoTeb_pfn dos_error_of;

static DWORD expected_error(LONG status)
{
    unsigned i;
    for (i = 0; i < sizeof k_map / sizeof k_map[0]; i++)
        if (k_map[i].status == status) return k_map[i].error;
    return status >= 0 ? dos_error_of(status) : WSAEINVAL;
}

/* One status through the API; returns nonzero on any deviation (and records the first deviating status). */
static int probe_status(SOCKET s, LONG status, LONG *first_bad)
{
    OVERLAPPED ov;
    DWORD size = 0, flags = 0, expect = expected_error(status), err;
    BOOL expect_ret = status >= 0 && status != STATUS_PENDING, ret;
    memset(&ov, 0, sizeof ov);
    ov.Internal = (ULONG_PTR)(ULONG)status;
    p_WSASetLastError(W_SENT);
    ret = p_WSAGetOverlappedResult(s, &ov, &size, FALSE, &flags);
    err = p_WSAGetLastError();
    if (!!ret != !!expect_ret || err != expect) {
        if (!*first_bad) *first_bad = status;
        return 1;
    }
    return 0;
}

static int setup_probe(SOCKET *s)
{
    if (!w_ready()) { t_skip("winsock entry points unavailable"); return 0; }
    dos_error_of = (RtlNtStatusToDosErrorNoTeb_pfn)t_proc_in("ntdll.dll", "RtlNtStatusToDosErrorNoTeb");
    if (!dos_error_of) { t_skip("RtlNtStatusToDosErrorNoTeb unavailable"); return 0; }
    *s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    return *s != INVALID_SOCKET;
}

TEST(lift10_wsagetoverlappedresult_bogus_socket_is_enotsock)
{
    OVERLAPPED ov;
    DWORD size, flags;
    BOOL ret;
    W_BEGIN();
    memset(&ov, 0, sizeof ov);
    p_WSASetLastError(W_SENT);
    ret = p_WSAGetOverlappedResult((SOCKET)0xdeadbeef, &ov, &size, FALSE, &flags);
    CHECK(!ret);
    EXPECT_EQ(p_WSAGetLastError(), WSAENOTSOCK);
}

TEST(lift10_wsagetoverlappedresult_duplicated_handle_is_enotsock)
{
    OVERLAPPED ov;
    DWORD size, flags;
    HANDLE h = NULL;
    SOCKET s;
    BOOL ret;
    W_BEGIN();
    memset(&ov, 0, sizeof ov);
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS));
    p_WSASetLastError(W_SENT);
    ret = p_WSAGetOverlappedResult((SOCKET)h, &ov, &size, FALSE, &flags);
    CHECK(!ret);
    EXPECT_EQ(p_WSAGetLastError(), WSAENOTSOCK);
    CloseHandle(h);
    p_closesocket(s);
}

TEST(lift10_wsagetoverlappedresult_status_translation_table)
{
    SOCKET s;
    unsigned i, bad = 0;
    LONG first = 0;
    if (!setup_probe(&s)) return;
    for (i = 0; i < sizeof k_map / sizeof k_map[0]; i++) bad += probe_status(s, k_map[i].status, &first);
    CHECKF(bad == 0, "%u of %u statuses mistranslated, first %#lx", bad, (unsigned)(sizeof k_map / sizeof k_map[0]), first);
    p_closesocket(s);
}

/* Sweep contiguous status ranges: every code in them is classified (success/failure) and translated by the rules. */
static void sweep(LONG lo, LONG hi)
{
    SOCKET s;
    LONG st, first = 0;
    unsigned bad = 0;
    if (!setup_probe(&s)) return;
    for (st = lo; st != hi; st++) bad += probe_status(s, st, &first);
    CHECKF(bad == 0, "range %#lx..%#lx: %u mistranslated, first %#lx", lo, hi, bad, first);
    p_closesocket(s);
}

TEST(lift10_wsagetoverlappedresult_sweep_success_range)        { sweep(0x0, 0x10000); }
TEST(lift10_wsagetoverlappedresult_sweep_informational_range)  { sweep(0x40000000, 0x40001000); }
TEST(lift10_wsagetoverlappedresult_sweep_warning_range)        { sweep((LONG)0x80000000, (LONG)0x80001000); }
TEST(lift10_wsagetoverlappedresult_sweep_win32_warning_range)  { sweep((LONG)0x80070000, (LONG)0x80080000); }
TEST(lift10_wsagetoverlappedresult_sweep_error_range)          { sweep((LONG)0xc0000000, (LONG)0xc0001000); }
TEST(lift10_wsagetoverlappedresult_sweep_win32_error_range)    { sweep((LONG)0xc0070000, (LONG)0xc0080000); }
TEST(lift10_wsagetoverlappedresult_sweep_customer_error_range) { sweep((LONG)0xd0000000, (LONG)0xd0001000); }
TEST(lift10_wsagetoverlappedresult_sweep_customer_win32_range) { sweep((LONG)0xd0070000, (LONG)0xd0080000); }

/* A pending status with a signalled event and wait=TRUE returns TRUE immediately; the wait is not alertable,
 * so a queued APC runs only at the next alertable wait. */
static unsigned g_apc_runs;
static void WINAPI count_apc(ULONG_PTR arg) { ++*(unsigned *)arg; }

TEST(lift10_wsagetoverlappedresult_wait_with_signalled_event_is_not_alertable)
{
    OVERLAPPED ov;
    DWORD size, flags;
    SOCKET s;
    BOOL ret;
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&ov, 0, sizeof ov);
    ov.Internal = (ULONG_PTR)(ULONG)STATUS_PENDING;
    ov.hEvent = CreateEventW(NULL, TRUE, TRUE, NULL);

    g_apc_runs = 0;
    CHECK(QueueUserAPC(count_apc, GetCurrentThread(), (ULONG_PTR)&g_apc_runs));
    SetLastError(W_SENT);
    p_WSASetLastError(W_SENT);
    ret = p_WSAGetOverlappedResult(s, &ov, &size, TRUE, &flags);
    CHECK(ret);
    CHECK(p_WSAGetLastError() == ERROR_IO_PENDING || p_WSAGetLastError() == 0);
    EXPECT_EQ(g_apc_runs, 0);
    SleepEx(0, TRUE);
    EXPECT_EQ(g_apc_runs, 1);

    CloseHandle(ov.hEvent);
    p_closesocket(s);
}
