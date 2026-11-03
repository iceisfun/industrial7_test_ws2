/* GetAddrInfoExW / GetAddrInfoExOverlappedResult / FreeAddrInfoExW: synchronous argument handling, the
 * overlapped protocol (pending return, event signalling, final status in OVERLAPPED, Pointer field) and the
 * rule that an event and a completion routine cannot be combined. Only "localhost" is resolved. */
#include "lift03.h"

static const WCHAR xEmpty[] = {0};
static const WCHAR xLocalhost[] = {'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0};
static ADDRINFOEXW x_sentinel;

#define NEED_X() \
    do { REQUIRE(U(GetAddrInfoExW)); REQUIRE(U(FreeAddrInfoExW)); REQUIRE(UN(GetAddrInfoExOverlappedResult)); \
         if (l3_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define DONE_X() l3_down()

TEST(gaiex_null_name_fails_synchronously)
{
    NEED_X();
    ADDRINFOEXW *res = &x_sentinel;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoExW)(NULL, NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, WSAHOST_NOT_FOUND);
    EXPECT_EQ(WSERR(), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    DONE_X();
}

TEST(gaiex_empty_name_succeeds_and_clears_error)
{
    NEED_X();
    ADDRINFOEXW *res = NULL;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoExW)(xEmpty, NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0);
    CHECK(res != NULL);
    EXPECT_EQ(WSERR(), 0);
    if (res) U(FreeAddrInfoExW)(res);
    DONE_X();
}

TEST(gaiex_localhost_sync_succeeds)
{
    NEED_X();
    ADDRINFOEXW *res = NULL;
    int r = U(GetAddrInfoExW)(xLocalhost, NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, 0);
    CHECK(res != NULL);
    if (res) U(FreeAddrInfoExW)(res);
    DONE_X();
}

/* The result-query helper rejects a NULL OVERLAPPED with WSAEINVAL. */
TEST(gaiex_overlapped_result_null_is_einval)
{
    NEED_X();
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(NULL), WSAEINVAL);
    DONE_X();
}

/* Event-signalled completion: pending return, result pointer cleared, event set, status 0, fields preserved. */
TEST(gaiex_overlapped_event_localhost)
{
    NEED_X();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ADDRINFOEXW *res = &x_sentinel;
    OVERLAPPED ov;
    memset(&ov, 0xcc, sizeof ov);
    ov.hEvent = ev;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoExW)(xLocalhost, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov, NULL, NULL);
    EXPECT_EQ(r, ERROR_IO_PENDING);
    EXPECT_EQ(WSERR(), ERROR_IO_PENDING);
    CHECK(res != &x_sentinel); /* cleared (or already filled in) by the call */
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    CHECK(ov.hEvent == ev);
    EXPECT_EQ(ov.Internal, 0);
    CHECK(ov.Pointer == (PVOID)&res);
    CHECK(res != NULL);
    if (res) {
        CHECK(res->ai_blob == NULL);
        EXPECT_EQ(res->ai_bloblen, 0);
        CHECK(res->ai_provider == NULL);
        U(FreeAddrInfoExW)(res);
    }
    CloseHandle(ev);
    DONE_X();
}

/* Overlapped with a hint set and the all-namespaces selector still follows the same protocol. */
TEST(gaiex_overlapped_event_with_hints)
{
    NEED_X();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ADDRINFOEXW hints, *res = &x_sentinel;
    OVERLAPPED ov;
    memset(&ov, 0xcc, sizeof ov);
    ov.hEvent = ev;
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_ALL | AI_V4MAPPED;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoExW)(xLocalhost, NULL, NS_ALL, NULL, &hints, &res, NULL, &ov, NULL, NULL);
    EXPECT_EQ(r, ERROR_IO_PENDING);
    EXPECT_EQ(WSERR(), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    int fin = UN(GetAddrInfoExOverlappedResult)(&ov);
    CHECKF(fin == 0 || fin == WSAHOST_NOT_FOUND || fin == WSANO_DATA, "final status %d", fin);
    if (fin == 0) { CHECK(res != NULL); if (res) U(FreeAddrInfoExW)(res); }
    else t_note("AF_INET6/UDP mapped lookup of localhost did not succeed");
    CloseHandle(ev);
    DONE_X();
}

/* A NULL name is rejected synchronously even when an OVERLAPPED is supplied: nothing is queued. */
TEST(gaiex_null_name_with_overlapped_fails_synchronously)
{
    NEED_X();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ADDRINFOEXW *res = &x_sentinel;
    OVERLAPPED ov;
    memset(&ov, 0xcc, sizeof ov);
    ov.hEvent = ev;
    SETWSERR(0x1234);
    int r = U(GetAddrInfoExW)(NULL, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov, NULL, NULL);
    EXPECT_EQ(r, WSAHOST_NOT_FOUND);
    EXPECT_EQ(WSERR(), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    CloseHandle(ev);
    DONE_X();
}

/* Supplying both an event in the OVERLAPPED and a completion routine is invalid. */
static void CALLBACK never_called(DWORD e, DWORD b, LPWSAOVERLAPPED o) { (void)e; (void)b; (void)o; }
TEST(gaiex_event_plus_completion_routine_is_einval)
{
    NEED_X();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ADDRINFOEXW *res = &x_sentinel;
    OVERLAPPED ov;
    memset(&ov, 0xcc, sizeof ov);
    ov.hEvent = ev;
    int r = U(GetAddrInfoExW)(xLocalhost, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov,
                              (LPLOOKUPSERVICE_COMPLETION_ROUTINE)never_called, NULL);
    EXPECT_EQ(r, WSAEINVAL);
    CloseHandle(ev);
    DONE_X();
}

/* Completion-routine mode: the routine runs on its own (non-waiting) thread; the main thread only waits on a
 * private event the routine sets. Values observed inside the routine are recorded and checked afterwards. */
static struct {
    HANDLE done;
    volatile LONG calls;
    DWORD err, bytes;
    LPWSAOVERLAPPED ov;
    ULONG_PTR internal;
    PVOID pointer;
    HANDLE hevent;
} g_cr;

static void CALLBACK record_cr(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov)
{
    g_cr.err = err; g_cr.bytes = bytes; g_cr.ov = ov;
    g_cr.internal = ov->Internal; g_cr.pointer = ov->Pointer; g_cr.hevent = ov->hEvent;
    InterlockedIncrement(&g_cr.calls);
    SetEvent(g_cr.done);
}

TEST(gaiex_completion_routine_localhost)
{
    NEED_X();
    memset(&g_cr, 0, sizeof g_cr);
    g_cr.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    ADDRINFOEXW *res = &x_sentinel;
    OVERLAPPED ov;
    memset(&ov, 0xcc, sizeof ov);
    ov.hEvent = NULL;
    int r = U(GetAddrInfoExW)(xLocalhost, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov, record_cr, NULL);
    EXPECT_EQ(r, ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_cr.done, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(g_cr.calls, 1);
    EXPECT_EQ(g_cr.err, 0);
    EXPECT_EQ(g_cr.bytes, 0);
    CHECK(g_cr.ov == &ov);
    EXPECT_EQ(g_cr.internal, 0);
    CHECK(g_cr.pointer == (PVOID)&res);
    CHECK(g_cr.hevent == NULL);
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    CHECK(ov.hEvent == NULL);
    EXPECT_EQ(ov.Internal, 0);
    CHECK(ov.Pointer == (PVOID)&res);
    CHECK(res != NULL);
    if (res) U(FreeAddrInfoExW)(res);
    CloseHandle(g_cr.done);
    DONE_X();
}
