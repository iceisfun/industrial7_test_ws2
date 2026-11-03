/* WSAGetOverlappedResult: handle validation (invalid value, duplicated handle) and the translation of
 * the OVERLAPPED.Internal NTSTATUS into the return value and WSAGetLastError(), swept over
 * several status ranges, plus the alertable-wait behaviour when the I/O is still marked pending. */
#include "lift11.h"

UDECL(ULONG, RtlNtStatusToDosErrorNoTeb, (LONG status));

struct l11_map { LONG status; DWORD err; };

/* Statuses whose Winsock error is not the generic "invalid parameter" fallback. */
static const struct l11_map l11_status_map[] = {
    {0x00000103, ERROR_IO_INCOMPLETE},
    {(LONG)0x80000005, WSAEMSGSIZE},
    {(LONG)0xC0000002, WSAEOPNOTSUPP}, {(LONG)0xC0000005, WSAEFAULT}, {(LONG)0xC0000007, WSAENOBUFS},
    {(LONG)0xC0000008, WSAENOTSOCK}, {(LONG)0xC000000E, WSAENETDOWN}, {(LONG)0xC000000F, WSAENETDOWN},
    {(LONG)0xC0000017, WSAENOBUFS}, {(LONG)0xC0000018, WSAENOBUFS}, {(LONG)0xC0000022, WSAEACCES},
    {(LONG)0xC0000023, WSAEFAULT}, {(LONG)0xC0000024, WSAENOTSOCK}, {(LONG)0xC0000034, WSAENETDOWN},
    {(LONG)0xC000003A, WSAENETDOWN}, {(LONG)0xC0000043, WSAEADDRINUSE}, {(LONG)0xC0000044, WSAENOBUFS},
    {(LONG)0xC0000097, WSAENOBUFS}, {(LONG)0xC000009A, WSAENOBUFS}, {(LONG)0xC00000A1, WSAENOBUFS},
    {(LONG)0xC00000A3, WSAEWOULDBLOCK}, {(LONG)0xC00000B0, WSAESHUTDOWN}, {(LONG)0xC00000B5, WSAETIMEDOUT},
    {(LONG)0xC00000BB, WSAEOPNOTSUPP}, {(LONG)0xC00000BC, WSAECONNREFUSED}, {(LONG)0xC00000BE, WSAENETUNREACH},
    {(LONG)0xC00000BF, WSAENETDOWN}, {(LONG)0xC00000C3, WSAENETDOWN}, {(LONG)0xC00000C4, WSAENETDOWN},
    {(LONG)0xC00000D0, WSAEWOULDBLOCK}, {(LONG)0xC0000120, ERROR_OPERATION_ABORTED}, {(LONG)0xC000012D, WSAENOBUFS},
    {(LONG)0xC000013B, WSAECONNABORTED}, {(LONG)0xC000013C, WSAECONNRESET}, {(LONG)0xC000013D, WSAENOBUFS},
    {(LONG)0xC000013E, WSAECONNRESET}, {(LONG)0xC000013F, WSAETIMEDOUT}, {(LONG)0xC0000140, WSAENOTCONN},
    {(LONG)0xC0000141, WSAEADDRNOTAVAIL}, {(LONG)0xC0000206, WSAEMSGSIZE}, {(LONG)0xC0000207, WSAEADDRNOTAVAIL},
    {(LONG)0xC0000209, WSAENOBUFS}, {(LONG)0xC000020A, WSAEADDRINUSE}, {(LONG)0xC000020C, WSAECONNRESET},
    {(LONG)0xC000020D, WSAECONNRESET}, {(LONG)0xC000020F, WSAECONNABORTED}, {(LONG)0xC0000236, WSAECONNREFUSED},
    {(LONG)0xC0000237, WSAEDISCON}, {(LONG)0xC000023B, WSAEISCONN}, {(LONG)0xC000023C, WSAENETUNREACH},
    {(LONG)0xC000023D, WSAEHOSTUNREACH}, {(LONG)0xC000023E, WSAENETUNREACH}, {(LONG)0xC000023F, WSAECONNRESET},
    {(LONG)0xC0000240, WSAEINTR}, {(LONG)0xC0000241, WSAECONNABORTED}, {(LONG)0xC00002C5, WSAEFAULT},
    {(LONG)0xC0000350, WSAEHOSTDOWN},
    {(LONG)(0x80070000 | ERROR_IO_INCOMPLETE), ERROR_IO_INCOMPLETE},
    {(LONG)(0xC0010000 | ERROR_IO_INCOMPLETE), ERROR_IO_INCOMPLETE},
    {(LONG)(0xC0070000 | ERROR_IO_INCOMPLETE), ERROR_IO_INCOMPLETE},
};

static DWORD l11_expected_error(LONG status)
{
    unsigned i;
    for (i = 0; i < sizeof(l11_status_map) / sizeof(l11_status_map[0]); i++)
        if (l11_status_map[i].status == status) return l11_status_map[i].err;
    if (status >= 0) {
        RtlNtStatusToDosErrorNoTeb_pfn f = UN(RtlNtStatusToDosErrorNoTeb);
        return f ? f(status) : 0;
    }
    return WSAEINVAL;
}

TEST(goverlapped_invalid_socket_value)
{
    OVERLAPPED ov = {0};
    DWORD size, flags;
    BOOL r;
    UP();
    l11_seterr(0xdeadbeef);
    r = U(WSAGetOverlappedResult)((SOCKET)0xdeadbeef, &ov, &size, FALSE, &flags);
    CHECK(!r);
    L_EQ(l11_err(), WSAENOTSOCK);
}

TEST(goverlapped_duplicated_handle_is_not_a_socket)
{
    /* The function only accepts handles in the per-process socket table; a DuplicateHandle copy
     * of a live socket is a different handle value and is rejected. */
    OVERLAPPED ov = {0};
    DWORD size, flags;
    HANDLE dup = NULL;
    SOCKET s;
    BOOL r;
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    r = U(WSAGetOverlappedResult)((SOCKET)dup, &ov, &size, FALSE, &flags);
    CHECK(!r);
    L_EQ(l11_err(), WSAENOTSOCK);
    if (dup) CloseHandle(dup);
    U(closesocket)(s);
}

static void l11_status_sweep(LONG lo, LONG hi)
{
    /* For each status placed in OVERLAPPED.Internal: success statuses other than STATUS_PENDING
     * return TRUE and set the mapped error; everything else returns FALSE with the mapped error. */
    OVERLAPPED ov = {0};
    DWORD size, flags;
    unsigned long bad = 0, total = 0;
    LONG first_bad = 0;
    DWORD first_got = 0, first_want = 0;
    LONG st;
    SOCKET s;
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    for (st = lo; (ULONG)st < (ULONG)hi; st++) {
        BOOL want_ret = st >= 0 && st != 0x103;
        DWORD want_err = l11_expected_error(st);
        BOOL r;
        DWORD got;
        ov.Internal = (ULONG_PTR)(ULONG)st;
        l11_seterr(0xdeadbeef);
        r = U(WSAGetOverlappedResult)(s, &ov, &size, FALSE, &flags);
        got = l11_err();
        total++;
        if ((r != 0) != (want_ret != 0) || got != want_err) {
            if (!bad) { first_bad = st; first_got = got; first_want = want_err; }
            bad++;
        }
    }
    CHECKF(bad == 0, "%lu of %lu statuses wrong; first 0x%lx gave error %lu want %lu",
           bad, total, (unsigned long)first_bad, (unsigned long)first_got, (unsigned long)first_want);
    U(closesocket)(s);
}

TEST(goverlapped_status_sweep_success_0000_ffff) { l11_status_sweep(0x0, 0x10000); }
TEST(goverlapped_status_sweep_informational_4000) { l11_status_sweep(0x40000000, 0x40001000); }
TEST(goverlapped_status_sweep_warning_8000) { l11_status_sweep((LONG)0x80000000, (LONG)0x80001000); }
TEST(goverlapped_status_sweep_warning_win32_facility) { l11_status_sweep((LONG)0x80070000, (LONG)0x80080000); }
TEST(goverlapped_status_sweep_error_c000) { l11_status_sweep((LONG)0xc0000000, (LONG)0xc0001000); }
TEST(goverlapped_status_sweep_error_win32_facility) { l11_status_sweep((LONG)0xc0070000, (LONG)0xc0080000); }
TEST(goverlapped_status_sweep_customer_d000) { l11_status_sweep((LONG)0xd0000000, (LONG)0xd0001000); }
TEST(goverlapped_status_sweep_customer_win32_facility) { l11_status_sweep((LONG)0xd0070000, (LONG)0xd0080000); }

static volatile LONG l11_apc_hits;
static void WINAPI l11_apc(ULONG_PTR p) { InterlockedIncrement((volatile LONG *)p); }

TEST(goverlapped_wait_on_signalled_event_does_not_run_apcs)
{
    /* Status still pending but the event is already signalled: with fWait the call returns at once
     * with TRUE and a pending/zero error, and does NOT enter an alertable wait (the queued APC only
     * runs at the later SleepEx). */
    OVERLAPPED ov = {0};
    DWORD size, flags, err;
    BOOL r;
    SOCKET s;
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ov.Internal = 0x103;
    ov.hEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    l11_apc_hits = 0;
    CHECK(QueueUserAPC(l11_apc, GetCurrentThread(), (ULONG_PTR)&l11_apc_hits));
    SetLastError(0xdeadbeef);
    l11_seterr(0xdeadbeef);
    r = U(WSAGetOverlappedResult)(s, &ov, &size, TRUE, &flags);
    err = GetLastError();
    CHECKF(r && (err == ERROR_IO_PENDING || err == 0), "ret %d err %lu", r, err);
    L_EQ(l11_apc_hits, 0);
    SleepEx(0, TRUE);
    L_EQ(l11_apc_hits, 1);
    CloseHandle(ov.hEvent);
    U(closesocket)(s);
}
