/* GetAddrInfoExW / GetAddrInfoExA / GetAddrInfoExCancel / GetAddrInfoExOverlappedResult / FreeAddrInfoEx* /
 * SetAddrInfoEx*: argument contracts of the extended resolver.
 *
 * Measures: which combinations of timeout / OVERLAPPED / completion routine / name handle are valid (all four
 * need an OVERLAPPED; an OVERLAPPED needs exactly one of event or routine), the ANSI variant refusing every
 * asynchronous argument, synchronous completion of NULL names and numeric literals even when an OVERLAPPED is
 * supplied, pending completion of a real name with event and routine, the cancel return values for NULL,
 * empty and completed handles, GetAddrInfoExOverlappedResult returning the low 32 bits of Internal, ADDRINFOEX
 * structure offsets as seen from the library's answers, namespace selectors NS_DNS / NS_ALL for local data,
 * freeing NULL, and the argument gate of SetAddrInfoEx (which is only called with arguments that are refused
 * before any registration could happen). Only "localhost", numeric literals and NULL names are resolved. */
#include "gf.h"

static const WCHAR gx_localhost[] = { 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0 };
static const WCHAR gx_lit4[] = { '1', '0', '.', '1', '.', '2', '.', '3', 0 };
static const WCHAR gx_80[] = { '8', '0', 0 };
static ADDRINFOEXW gx_sentinel;

#define GX_BEGIN() \
    do { if (!U(GetAddrInfoExW) || !U(FreeAddrInfoExW) || !UN(GetAddrInfoExOverlappedResult) || !U(WSAGetLastError) || !U(WSASetLastError)) \
             { t_skip("missing export"); return; } \
         if (gf_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define GX_END() gf_down()

/* After the completion event fires the library still finishes with the request (it may signal again), so give it a
   moment before the event handle is released and the overlapped block is reused by the next test. */
static void gx_close(HANDLE h) { Sleep(150); CloseHandle(h); }

static void CALLBACK gx_routine(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov) { (void)err; (void)bytes; (void)ov; }

/* Run one extended call with the asynchronous arguments given; every pointer is valid or NULL. */
static int gx_call(const WCHAR *name, const WCHAR *serv, DWORD ns, const ADDRINFOEXW *hints, ADDRINFOEXW **res,
                   struct timeval *tmo, OVERLAPPED *ov, int with_routine, HANDLE *handle)
{
    return U(GetAddrInfoExW)(name, serv, ns, NULL, hints, res, tmo, ov,
                             with_routine ? (LPLOOKUPSERVICE_COMPLETION_ROUTINE)gx_routine : NULL, handle);
}

/* ---- every asynchronous argument needs an OVERLAPPED ----------------------------------------------- */
TEST(gfx_timeout_without_overlapped_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    struct timeval tv = { 5, 0 };
    GX_BEGIN();
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, &tv, NULL, 0, NULL), WSAEINVAL);
    EXPECT_EQ(WSERR(), WSAEINVAL);
    CHECK(res == NULL);
    GX_END();
}
TEST(gfx_routine_without_overlapped_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    GX_BEGIN();
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, NULL, 1, NULL), WSAEINVAL);
    EXPECT_EQ(WSERR(), WSAEINVAL);
    CHECK(res == NULL);
    GX_END();
}
TEST(gfx_handle_without_overlapped_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static HANDLE h = (HANDLE)gf_sent;
    GX_BEGIN();
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, NULL, 0, &h), WSAEINVAL);
    EXPECT_EQ(WSERR(), WSAEINVAL);
    CHECK(res == NULL);
    CHECK(h == NULL);              /* the handle slot is cleared before the arguments are judged */
    GX_END();
}
TEST(gfx_all_async_without_overlapped_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static HANDLE h = NULL;
    struct timeval tv = { 5, 0 };
    GX_BEGIN();
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, &tv, NULL, 1, &h), WSAEINVAL);
    CHECK(res == NULL);
    GX_END();
}
/* An OVERLAPPED with neither event nor routine cannot signal anything. */
TEST(gfx_overlapped_without_event_or_routine_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, NULL), WSAEINVAL);
    EXPECT_EQ(WSERR(), WSAEINVAL);
    CHECK(res == NULL);
    EXPECT_EQ((DWORD)ov.Internal, 10036);    /* the status field was primed with "in progress" before the check */
    GX_END();
}
TEST(gfx_overlapped_without_event_or_routine_with_timeout_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    struct timeval tv = { 5, 0 };
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, &tv, &ov, 0, NULL), WSAEINVAL);
    GX_END();
}
TEST(gfx_event_and_routine_is_einval)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 1, NULL), WSAEINVAL);
    CHECK(res == NULL);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 0), WAIT_TIMEOUT);
    gx_close(ov.hEvent);
    GX_END();
}
/* The argument gate comes after the both-names-NULL gate and before the hints gate. */
TEST(gfx_null_names_beat_async_argument_error)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    struct timeval tv = { 5, 0 };
    GX_BEGIN();
    EXPECT_EQ(gx_call(NULL, NULL, NS_DNS, NULL, &res, &tv, NULL, 0, NULL), WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    GX_END();
}
TEST(gfx_async_argument_error_beats_dirty_hint)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint;
    struct timeval tv = { 5, 0 };
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_addrlen = 4;
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, &hint, &res, &tv, NULL, 0, NULL), WSAEINVAL);
    GX_END();
}
TEST(gfx_dirty_hint_with_valid_overlapped_is_no_recovery)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_addrlen = 4;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, &hint, &res, NULL, &ov, 0, NULL), WSANO_RECOVERY);
    CHECK(res == NULL);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 0), WAIT_TIMEOUT);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_bad_family_with_valid_overlapped_fails_synchronously)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_UNIX;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, &hint, &res, NULL, &ov, 0, NULL), WSAEAFNOSUPPORT);
    EXPECT_EQ(WSERR(), WSAEAFNOSUPPORT);
    CHECK(res == NULL);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 0), WAIT_TIMEOUT);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_canonname_without_name_with_valid_overlapped)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_CANONNAME;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(NULL, gx_80, NS_DNS, &hint, &res, NULL, &ov, 0, NULL), WSAEINVAL);
    CHECK(res == NULL);
    gx_close(ov.hEvent);
    GX_END();
}

/* ---- the ANSI call has no asynchronous mode ---------------------------------------------------------- */
static int gx_call_a(const char *name, struct timeval *tmo, OVERLAPPED *ov, int with_routine, HANDLE *h, ADDRINFOEXA **res)
{
    return U(GetAddrInfoExA)(name, NULL, NS_DNS, NULL, NULL, res, tmo, ov,
                             with_routine ? (LPLOOKUPSERVICE_COMPLETION_ROUTINE)gx_routine : NULL, h);
}
#define GXA_BEGIN() \
    do { if (!U(GetAddrInfoExA) || !U(FreeAddrInfoEx) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gf_up()) { t_skip("WSAStartup failed"); return; } } while (0)
TEST(gfx_a_timeout_is_einval)
{
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    struct timeval tv = { 5, 0 };
    GXA_BEGIN();
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call_a("10.1.2.3", &tv, NULL, 0, NULL, &res), WSAEINVAL);
    EXPECT_EQ(WSERR(), WSAEINVAL);
    CHECK(res == NULL);
    GX_END();
}
TEST(gfx_a_overlapped_is_einval)
{
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    static OVERLAPPED ov;
    GXA_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call_a("10.1.2.3", NULL, &ov, 0, NULL, &res), WSAEINVAL);
    EXPECT_EQ(WSERR(), WSAEINVAL);
    CHECK(res == NULL);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 0), WAIT_TIMEOUT);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_a_routine_is_einval)
{
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    GXA_BEGIN();
    EXPECT_EQ(gx_call_a("10.1.2.3", NULL, NULL, 1, NULL, &res), WSAEINVAL);
    CHECK(res == NULL);
    GX_END();
}
TEST(gfx_a_handle_is_einval)
{
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    static HANDLE h = NULL;
    GXA_BEGIN();
    EXPECT_EQ(gx_call_a("10.1.2.3", NULL, NULL, 0, &h, &res), WSAEINVAL);
    CHECK(res == NULL);
    GX_END();
}
TEST(gfx_a_async_refused_even_for_localhost)
{
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    static OVERLAPPED ov;
    GXA_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call_a("localhost", NULL, &ov, 0, NULL, &res), WSAEINVAL);
    gx_close(ov.hEvent);
    GX_END();
}
/* The async-argument refusal in the ANSI call precedes the both-names-NULL check of the wide call. */
TEST(gfx_a_async_beats_null_names)
{
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    struct timeval tv = { 5, 0 };
    GXA_BEGIN();
    EXPECT_EQ(gx_call_a(NULL, &tv, NULL, 0, NULL, &res), WSAEINVAL);
    GX_END();
}
/* A hints structure that asks for a resolution handle must carry a known structure version. */
static int gx_a_version_call(int version)
{
    unsigned char buf[0x80];
    static ADDRINFOEXA *res = (ADDRINFOEXA *)gf_sent;
    memset(buf, 0, sizeof buf);
    *(int *)(buf + 0) = (int)0x80000000u;      /* AI_RETURN_RESOLUTION_HANDLE */
    *(int *)(buf + 0x48) = version;            /* ai_version */
    return U(GetAddrInfoExA)("10.1.2.3", NULL, NS_DNS, NULL, (const ADDRINFOEXA *)buf, &res, NULL, NULL, NULL, NULL);
}
TEST(gfx_a_hint_version_0_is_einval) { GXA_BEGIN(); EXPECT_EQ(gx_a_version_call(0), WSAEINVAL); GX_END(); }
TEST(gfx_a_hint_version_1_is_einval) { GXA_BEGIN(); EXPECT_EQ(gx_a_version_call(1), WSAEINVAL); GX_END(); }
TEST(gfx_a_hint_version_5_is_einval) { GXA_BEGIN(); EXPECT_EQ(gx_a_version_call(5), WSAEINVAL); GX_END(); }
TEST(gfx_a_hint_version_99_is_einval){ GXA_BEGIN(); EXPECT_EQ(gx_a_version_call(99), WSAEINVAL); GX_END(); }
TEST(gfx_a_hint_version_neg_is_einval){ GXA_BEGIN(); EXPECT_EQ(gx_a_version_call(-1), WSAEINVAL); GX_END(); }

/* ---- synchronous completion with an OVERLAPPED supplied ------------------------------------------------ */
/* Numeric literals and the NULL name need no lookup: the call returns 0 at once and the result is filled in. */
TEST(gfx_literal_with_overlapped_completes_synchronously)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    static HANDLE h = (HANDLE)gf_sent;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(gx_lit4, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, &h), 0);
    EXPECT_EQ(WSERR(), 0);
    CHECK(res != &gx_sentinel && res != NULL);
    CHECK(h == NULL);           /* nothing is pending, so no cancel handle is produced */
    if (res && res != &gx_sentinel) U(FreeAddrInfoExW)(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_literal_with_routine_completes_synchronously)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(gx_call(gx_lit4, NULL, NS_DNS, NULL, &res, NULL, &ov, 1, NULL), 0);
    CHECK(res != &gx_sentinel && res != NULL);
    if (res && res != &gx_sentinel) U(FreeAddrInfoExW)(res);
    GX_END();
}
TEST(gfx_literal_with_timeout_and_overlapped_completes_synchronously)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    struct timeval tv = { 5, 0 };
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_lit4, NULL, NS_DNS, NULL, &res, &tv, &ov, 0, NULL), 0);
    CHECK(res != &gx_sentinel && res != NULL);
    if (res && res != &gx_sentinel) U(FreeAddrInfoExW)(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_null_name_with_overlapped_completes_synchronously)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_INET;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SETWSERR(0x1234);
    EXPECT_EQ(gx_call(NULL, gx_80, NS_DNS, &hint, &res, NULL, &ov, 0, NULL), 0);
    EXPECT_EQ(WSERR(), 0);
    CHECK(res != &gx_sentinel && res != NULL);
    if (res && res != &gx_sentinel) {
        EXPECT_EQ(res->ai_family, AF_INET);
        CHECK(res->ai_next == NULL);
        U(FreeAddrInfoExW)(res);
    }
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_literal_sync_result_equals_plain_call)
{
    ADDRINFOEXW *a = NULL, *b = NULL;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_lit4, gx_80, NS_DNS, NULL, &a, NULL, NULL, 0, NULL), 0);
    EXPECT_EQ(gx_call(gx_lit4, gx_80, NS_DNS, NULL, &b, NULL, &ov, 0, NULL), 0);
    CHECK(a && b);
    if (a && b) {
        EXPECT_EQ(a->ai_family, b->ai_family);
        EXPECT_EQ(a->ai_addrlen, b->ai_addrlen);
        CHECK(!memcmp(a->ai_addr, b->ai_addr, a->ai_addrlen));
        EXPECT_EQ(a->ai_flags, b->ai_flags);
    }
    if (a) U(FreeAddrInfoExW)(a);
    if (b) U(FreeAddrInfoExW)(b);
    gx_close(ov.hEvent);
    GX_END();
}

/* ---- pending completion of a real name -------------------------------------------------------------- */
static void gx_free(ADDRINFOEXW *r) { if (r && r != &gx_sentinel) U(FreeAddrInfoExW)(r); }

TEST(gfx_pending_handle_is_produced)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    static HANDLE h = NULL;
    int r;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    r = gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, &h);
    EXPECT_EQ(r, ERROR_IO_PENDING);
    CHECK(h != NULL);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_pending_wsa_error_is_io_pending)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SETWSERR(0);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WSERR(), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_pending_with_timeout_completes)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    struct timeval tv = { 10, 0 };
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, &tv, &ov, 0, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    CHECK(res != &gx_sentinel && res != NULL);
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_pending_result_pointer_cleared_until_completion)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, NULL), ERROR_IO_PENDING);
    CHECK(res != &gx_sentinel);          /* cleared (or already filled) when the call returns */
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    CHECK(res != NULL && res != &gx_sentinel);
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_pending_inet_hint_returns_only_v4)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint, *p;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_INET;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, gx_80, NS_DNS, &hint, &res, NULL, &ov, 0, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    for (p = res; p && p != &gx_sentinel; p = p->ai_next) {
        EXPECT_EQ(p->ai_family, AF_INET);
        if (p->ai_addr && p->ai_addrlen >= sizeof(SOCKADDR_IN)) EXPECT_EQ(((SOCKADDR_IN *)p->ai_addr)->sin_port, 0x5000);
    }
    CHECK(res != NULL && res != &gx_sentinel);
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_pending_ov_fields_after_completion)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    HANDLE ev;
    GX_BEGIN();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0xcc, sizeof ov);
    ov.hEvent = ev;
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    CHECK(ov.hEvent == ev);
    EXPECT_EQ(ov.Internal, 0);
    gx_free(res);
    gx_close(ev);
    GX_END();
}
TEST(gfx_pending_ov_reused_for_second_lookup)
{
    static OVERLAPPED ov;
    int i;
    GX_BEGIN();
    if (t_is_wine()) { t_skip("emulator crashes when an OVERLAPPED is reused for consecutive lookups"); GX_END(); return; }
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < 3; i++) {
        ADDRINFOEXW *res = &gx_sentinel;
        ResetEvent(ov.hEvent);
        EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, NULL), ERROR_IO_PENDING);
        EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
        CHECK(res != NULL && res != &gx_sentinel);
        gx_free(res);
        Sleep(150);                  /* a late second signal of this lookup must not be mistaken for the next one's */
    }
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_pending_several_in_flight)
{
    enum { N = 6 };
    static ADDRINFOEXW *res[N];
    static OVERLAPPED ov[N];
    int i;
    GX_BEGIN();
    for (i = 0; i < N; i++) {
        res[i] = &gx_sentinel;
        memset(&ov[i], 0, sizeof ov[i]);
        ov[i].hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res[i], NULL, &ov[i], 0, NULL), ERROR_IO_PENDING);
    }
    for (i = 0; i < N; i++) {
        EXPECT_EQ(WaitForSingleObject(ov[i].hEvent, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov[i]), 0);
        CHECK(res[i] != NULL && res[i] != &gx_sentinel);
        gx_free(res[i]);
        gx_close(ov[i].hEvent);
    }
    GX_END();
}

/* ---- completion routine ------------------------------------------------------------------------------ */
static struct { HANDLE done; volatile LONG calls; DWORD err, bytes; LPWSAOVERLAPPED ov; } gx_cr;
/* the routine is invoked twice per completed lookup on Windows 10; wait (bounded) until n calls arrived */
static int gx_wait_calls(LONG n, DWORD ms)
{
    DWORD t0 = GetTickCount();
    while (gx_cr.calls < n && GetTickCount() - t0 < ms) Sleep(10);
    return gx_cr.calls >= n;
}
static void CALLBACK gx_record(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov)
{
    gx_cr.err = err; gx_cr.bytes = bytes; gx_cr.ov = ov;
    InterlockedIncrement(&gx_cr.calls);
    SetEvent(gx_cr.done);
}
TEST(gfx_routine_called_twice_with_zero_error)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&gx_cr, 0, sizeof gx_cr);
    gx_cr.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(U(GetAddrInfoExW)(gx_localhost, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov,
                                (LPLOOKUPSERVICE_COMPLETION_ROUTINE)gx_record, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(gx_cr.done, 10000), WAIT_OBJECT_0);
    CHECK(gx_wait_calls(2, 5000));
    Sleep(300);                        /* and no third one follows */
    EXPECT_EQ(gx_cr.calls, 2);
    EXPECT_EQ(gx_cr.err, 0);
    EXPECT_EQ(gx_cr.bytes, 0);
    CHECK(gx_cr.ov == &ov);
    CHECK(res != NULL && res != &gx_sentinel);
    gx_free(res);
    gx_close(gx_cr.done);
    GX_END();
}
TEST(gfx_routine_does_not_need_alertable_wait)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&gx_cr, 0, sizeof gx_cr);
    gx_cr.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(U(GetAddrInfoExW)(gx_localhost, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov,
                                (LPLOOKUPSERVICE_COMPLETION_ROUTINE)gx_record, NULL), ERROR_IO_PENDING);
    /* a plain (non-alertable) wait: the routine still runs, on a library thread */
    EXPECT_EQ(WaitForSingleObject(gx_cr.done, 10000), WAIT_OBJECT_0);
    CHECK(gx_wait_calls(2, 5000));
    gx_free(res);
    gx_close(gx_cr.done);
    GX_END();
}
static DWORD g_routine_tid;
static void CALLBACK gx_tid(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov) { g_routine_tid = GetCurrentThreadId(); InterlockedIncrement(&gx_cr.calls); SetEvent(gx_cr.done); }
TEST(gfx_routine_runs_on_other_thread)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    GX_BEGIN();
    memset(&gx_cr, 0, sizeof gx_cr);
    gx_cr.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_routine_tid = 0;
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(U(GetAddrInfoExW)(gx_localhost, NULL, NS_DNS, NULL, NULL, &res, NULL, &ov,
                                (LPLOOKUPSERVICE_COMPLETION_ROUTINE)gx_tid, NULL), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(gx_cr.done, 10000), WAIT_OBJECT_0);
    CHECK(g_routine_tid != 0 && g_routine_tid != GetCurrentThreadId());
    CHECK(gx_wait_calls(2, 5000));
    gx_free(res);
    gx_close(gx_cr.done);
    GX_END();
}

/* ---- cancel ------------------------------------------------------------------------------------------- */
TEST(gfx_cancel_null_pointer_is_invalid_handle)
{
    GX_BEGIN();
    if (!UN(GetAddrInfoExCancel)) { t_skip("no GetAddrInfoExCancel"); GX_END(); return; }
    EXPECT_EQ(UN(GetAddrInfoExCancel)(NULL), 6);
    GX_END();
}
TEST(gfx_cancel_null_handle_is_invalid_handle)
{
    static HANDLE h = NULL;
    GX_BEGIN();
    if (!UN(GetAddrInfoExCancel)) { t_skip("no GetAddrInfoExCancel"); GX_END(); return; }
    EXPECT_EQ(UN(GetAddrInfoExCancel)(&h), 6);
    GX_END();
}
TEST(gfx_cancel_completed_lookup_is_invalid_handle)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    static HANDLE h = NULL;
    GX_BEGIN();
    if (!UN(GetAddrInfoExCancel)) { t_skip("no GetAddrInfoExCancel"); GX_END(); return; }
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, &h), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(GetAddrInfoExCancel)(&h), 6);
    EXPECT_EQ(UN(GetAddrInfoExCancel)(&h), 6);   /* and again: still nothing to cancel */
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}
TEST(gfx_cancel_completed_does_not_disturb_result)
{
    static ADDRINFOEXW *res = &gx_sentinel;
    static OVERLAPPED ov;
    static HANDLE h = NULL;
    GX_BEGIN();
    if (!UN(GetAddrInfoExCancel)) { t_skip("no GetAddrInfoExCancel"); GX_END(); return; }
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(gx_call(gx_localhost, NULL, NS_DNS, NULL, &res, NULL, &ov, 0, &h), ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 10000), WAIT_OBJECT_0);
    (void)UN(GetAddrInfoExCancel)(&h);
    /* The event can be signalled slightly before the worker finishes its bookkeeping, so a cancel in that
     * window may still turn the result into WSA_E_CANCELLED; either outcome is legitimate, nothing else is. */
    {
        DWORD rr = UN(GetAddrInfoExOverlappedResult)(&ov);
        CHECK(rr == 0 || rr == 0x277f);
        if (rr == 0) CHECK(res != NULL && res != &gx_sentinel);
    }
    gx_free(res);
    gx_close(ov.hEvent);
    GX_END();
}

/* ---- GetAddrInfoExOverlappedResult ----------------------------------------------------------------------- */
/* It returns the low 32 bits of OVERLAPPED.Internal and nothing else. */
static void ovres(ULONG_PTR internal, DWORD want)
{
    static OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.Internal = internal;
    ov.InternalHigh = 0x77;
    EXPECT_EQ((DWORD)UN(GetAddrInfoExOverlappedResult)(&ov), want);
    EXPECT_EQ(ov.Internal, internal);
    EXPECT_EQ(ov.InternalHigh, 0x77);
}
TEST(gfx_ovres_zero)        { GX_BEGIN(); ovres(0, 0); GX_END(); }
TEST(gfx_ovres_small)       { GX_BEGIN(); ovres(5, 5); GX_END(); }
TEST(gfx_ovres_wsa_code)    { GX_BEGIN(); ovres(WSAHOST_NOT_FOUND, WSAHOST_NOT_FOUND); GX_END(); }
TEST(gfx_ovres_cancelled)   { GX_BEGIN(); ovres(WSA_E_CANCELLED, WSA_E_CANCELLED); GX_END(); }
TEST(gfx_ovres_timed_out)   { GX_BEGIN(); ovres(WSAETIMEDOUT, WSAETIMEDOUT); GX_END(); }
TEST(gfx_ovres_in_progress) { GX_BEGIN(); ovres(10036, 10036); GX_END(); }
TEST(gfx_ovres_u32_max)     { GX_BEGIN(); ovres(0xffffffffu, 0xffffffffu); GX_END(); }
#ifdef _WIN64
TEST(gfx_ovres_high_half_ignored) { GX_BEGIN(); ovres(((ULONG_PTR)0x55 << 32) | 7u, 7u); GX_END(); }
TEST(gfx_ovres_high_only_is_zero) { GX_BEGIN(); ovres((ULONG_PTR)0x1234 << 32, 0); GX_END(); }
#endif
TEST(gfx_ovres_does_not_need_wsa_startup)
{
    static OVERLAPPED ov;
    if (!UN(GetAddrInfoExOverlappedResult)) { t_skip("missing export"); return; }
    memset(&ov, 0, sizeof ov);
    ov.Internal = 9;
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 9);
    EXPECT_EQ(UN(GetAddrInfoExOverlappedResult)(NULL), WSAEINVAL);
}

/* ---- freeing ------------------------------------------------------------------------------------------- */
TEST(gfx_free_null_everywhere)
{
    GX_BEGIN();
    if (U(freeaddrinfo)) U(freeaddrinfo)(NULL);
    if (U(FreeAddrInfoW)) U(FreeAddrInfoW)(NULL);
    U(FreeAddrInfoExW)(NULL);
    if (U(FreeAddrInfoEx)) U(FreeAddrInfoEx)(NULL);
    CHECK(1);
    GX_END();
}
TEST(gfx_free_null_without_startup)
{
    if (U(freeaddrinfo)) U(freeaddrinfo)(NULL);
    if (U(FreeAddrInfoW)) U(FreeAddrInfoW)(NULL);
    if (U(FreeAddrInfoExW)) U(FreeAddrInfoExW)(NULL);
    if (U(FreeAddrInfoEx)) U(FreeAddrInfoEx)(NULL);
    CHECK(1);
}
/* FreeAddrInfoEx and FreeAddrInfoExW are the same routine. */
TEST(gfx_free_ex_a_and_w_same_entry)
{
    FARPROC a = t_proc_in("ws2_32.dll", "FreeAddrInfoEx"), w = t_proc_in("ws2_32.dll", "FreeAddrInfoExW");
    if (!a || !w) { t_skip("missing export"); return; }
    CHECK(a == w);
}
TEST(gfx_free_aw_alias)
{
    FARPROC a = t_proc_in("ws2_32.dll", "freeaddrinfo"), w = t_proc_in("ws2_32.dll", "FreeAddrInfoW");
    if (!a || !w) { t_skip("missing export"); return; }
    CHECK(a == w);
}
TEST(gfx_free_a_result_with_w_free)
{
    /* the plain and wide result lists share one allocator layout for the fields the free routine releases */
    ADDRINFOW *w = NULL;
    GX_BEGIN();
    if (!U(GetAddrInfoW) || !U(freeaddrinfo)) { t_skip("missing export"); GX_END(); return; }
    EXPECT_EQ(U(GetAddrInfoW)(NULL, gx_80, NULL, &w), 0);
    if (w) U(freeaddrinfo)((LPADDRINFO)w);
    GX_END();
}

/* ---- namespace selectors ------------------------------------------------------------------------------------- */
static void ns_literal(DWORD ns)
{
    ADDRINFOEXW *res = &gx_sentinel;
    SETWSERR(0x1234);
    EXPECT_EQ(U(GetAddrInfoExW)(gx_lit4, NULL, ns, NULL, NULL, &res, NULL, NULL, NULL, NULL), 0);
    CHECK(res != NULL && res != &gx_sentinel);
    if (res && res != &gx_sentinel) {
        EXPECT_EQ(res->ai_family, AF_INET);
        EXPECT_EQ(res->ai_addrlen, sizeof(SOCKADDR_IN));
        CHECK(res->ai_next == NULL);
        U(FreeAddrInfoExW)(res);
    }
}
TEST(gfx_ns_dns_literal) { GX_BEGIN(); ns_literal(NS_DNS); GX_END(); }
TEST(gfx_ns_all_literal) { GX_BEGIN(); ns_literal(NS_ALL); GX_END(); }
static void ns_nullname(DWORD ns)
{
    ADDRINFOEXW *res = &gx_sentinel, hint;
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_INET;
    hint.ai_flags = AI_PASSIVE;
    EXPECT_EQ(U(GetAddrInfoExW)(NULL, gx_80, ns, NULL, &hint, &res, NULL, NULL, NULL, NULL), 0);
    CHECK(res != NULL && res != &gx_sentinel);
    if (res && res != &gx_sentinel) {
        EXPECT_EQ(res->ai_family, AF_INET);
        if (res->ai_addr && res->ai_addrlen >= sizeof(SOCKADDR_IN)) {
            EXPECT_EQ(((SOCKADDR_IN *)res->ai_addr)->sin_addr.s_addr, 0);
            EXPECT_EQ(((SOCKADDR_IN *)res->ai_addr)->sin_port, 0x5000);
        }
        U(FreeAddrInfoExW)(res);
    }
}
TEST(gfx_ns_dns_nullname_passive) { GX_BEGIN(); ns_nullname(NS_DNS); GX_END(); }
TEST(gfx_ns_all_nullname_passive) { GX_BEGIN(); ns_nullname(NS_ALL); GX_END(); }
/* Only a DNS query is subject to the family gate: with NS_DNS an unsupported family is refused. */
TEST(gfx_ns_dns_bad_family_refused)
{
    static ADDRINFOEXW *res = &gx_sentinel, hint;
    GX_BEGIN();
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_NETBIOS;
    EXPECT_EQ(U(GetAddrInfoExW)(gx_lit4, NULL, NS_DNS, NULL, &hint, &res, NULL, NULL, NULL, NULL), WSAEAFNOSUPPORT);
    CHECK(res == NULL);
    GX_END();
}
/* NS_DNS and NS_ALL answers for the same literal are identical. */
TEST(gfx_ns_dns_and_all_agree)
{
    ADDRINFOEXW *a = NULL, *b = NULL;
    GX_BEGIN();
    EXPECT_EQ(U(GetAddrInfoExW)(gx_lit4, gx_80, NS_DNS, NULL, NULL, &a, NULL, NULL, NULL, NULL), 0);
    EXPECT_EQ(U(GetAddrInfoExW)(gx_lit4, gx_80, NS_ALL, NULL, NULL, &b, NULL, NULL, NULL, NULL), 0);
    if (a && b) {
        EXPECT_EQ(a->ai_family, b->ai_family);
        EXPECT_EQ(a->ai_addrlen, b->ai_addrlen);
        CHECK(!memcmp(a->ai_addr, b->ai_addr, a->ai_addrlen));
    }
    if (a) U(FreeAddrInfoExW)(a);
    if (b) U(FreeAddrInfoExW)(b);
    GX_END();
}

/* ---- structure layout, as seen from the answers ---------------------------------------------------------------- */
TEST(gfx_header_layout_v1)
{
    CHECK(sizeof(ADDRINFOEXW) == 0x48);
    CHECK(sizeof(ADDRINFOEXA) == 0x48);
    CHECK(offsetof(ADDRINFOEXW, ai_flags) == 0);
    CHECK(offsetof(ADDRINFOEXW, ai_family) == 4);
    CHECK(offsetof(ADDRINFOEXW, ai_socktype) == 8);
    CHECK(offsetof(ADDRINFOEXW, ai_protocol) == 12);
    CHECK(offsetof(ADDRINFOEXW, ai_addrlen) == 0x10);
    CHECK(offsetof(ADDRINFOEXW, ai_canonname) == 0x18);
    CHECK(offsetof(ADDRINFOEXW, ai_addr) == 0x20);
    CHECK(offsetof(ADDRINFOEXW, ai_blob) == 0x28);
    CHECK(offsetof(ADDRINFOEXW, ai_bloblen) == 0x30);
    CHECK(offsetof(ADDRINFOEXW, ai_provider) == 0x38);
    CHECK(offsetof(ADDRINFOEXW, ai_next) == 0x40);
}
TEST(gfx_answer_raw_offsets)
{
    static ADDRINFOEXW *res = NULL;
    const unsigned char *raw;
    GX_BEGIN();
    {
        ADDRINFOEXW hint;
        memset(&hint, 0, sizeof hint);
        hint.ai_family = AF_INET; hint.ai_socktype = SOCK_DGRAM; hint.ai_protocol = IPPROTO_UDP;
        EXPECT_EQ(U(GetAddrInfoExW)(gx_lit4, gx_80, NS_DNS, NULL, &hint, &res, NULL, NULL, NULL, NULL), 0);
    }
    CHECK(res != NULL);
    if (!res) { GX_END(); return; }
    raw = (const unsigned char *)res;
    EXPECT_EQ(*(const int *)(raw + 4), AF_INET);
    EXPECT_EQ(*(const int *)(raw + 8), SOCK_DGRAM);
    EXPECT_EQ(*(const int *)(raw + 12), IPPROTO_UDP);
    EXPECT_EQ(*(const size_t *)(raw + 0x10), sizeof(SOCKADDR_IN));
    CHECK(*(void *const *)(raw + 0x18) == NULL);          /* no canonical name asked */
    CHECK(*(void *const *)(raw + 0x20) != NULL);          /* ai_addr */
    CHECK(*(void *const *)(raw + 0x28) == NULL);          /* ai_blob */
    EXPECT_EQ(*(const size_t *)(raw + 0x30), 0);          /* ai_bloblen */
    CHECK(*(void *const *)(raw + 0x38) == NULL);          /* ai_provider */
    CHECK(*(void *const *)(raw + 0x40) == NULL);          /* ai_next */
    U(FreeAddrInfoExW)(res);
    GX_END();
}
TEST(gfx_answer_not_inline_addr)
{
    /* ai_addr points to separately owned memory, not into the ADDRINFOEX block */
    static ADDRINFOEXW *res = NULL;
    GX_BEGIN();
    EXPECT_EQ(U(GetAddrInfoExW)(gx_lit4, NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL), 0);
    if (res) {
        const unsigned char *b = (const unsigned char *)res, *a = (const unsigned char *)res->ai_addr;
        CHECK(a < b || a >= b + sizeof(ADDRINFOEXW));
        U(FreeAddrInfoExW)(res);
    }
    GX_END();
}

/* ---- SetAddrInfoEx: only the refusals that happen before any registration --------------------------------------- */
UDECL(int, SetAddrInfoExW_, (PCWSTR name, PCWSTR serv, SOCKET_ADDRESS *addrs, DWORD count, LPBLOB blob, DWORD flags, DWORD ns,
                             LPGUID nsp, struct timeval *tmo, LPOVERLAPPED ov, void *routine, LPHANDLE handle));
static int set_call(struct timeval *tmo, LPOVERLAPPED ov, void *routine, LPHANDLE h)
{
    FARPROC p = t_proc_in("ws2_32.dll", "SetAddrInfoExW");
    return ((SetAddrInfoExW__pfn)p)(NULL, NULL, NULL, 0, NULL, 0, NS_DNS, NULL, tmo, ov, routine, h);
}
TEST(gfx_set_timeout_is_einval)
{
    struct timeval tv = { 1, 0 };
    GX_BEGIN();
    if (!t_proc_in("ws2_32.dll", "SetAddrInfoExW")) { t_skip("no SetAddrInfoExW"); GX_END(); return; }
    EXPECT_EQ(set_call(&tv, NULL, NULL, NULL), WSAEINVAL);
    GX_END();
}
TEST(gfx_set_overlapped_is_einval)
{
    static OVERLAPPED ov;
    GX_BEGIN();
    if (!t_proc_in("ws2_32.dll", "SetAddrInfoExW")) { t_skip("no SetAddrInfoExW"); GX_END(); return; }
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(set_call(NULL, &ov, NULL, NULL), WSAEINVAL);
    GX_END();
}
TEST(gfx_set_routine_is_einval)
{
    GX_BEGIN();
    if (!t_proc_in("ws2_32.dll", "SetAddrInfoExW")) { t_skip("no SetAddrInfoExW"); GX_END(); return; }
    EXPECT_EQ(set_call(NULL, NULL, (void *)gx_routine, NULL), WSAEINVAL);
    GX_END();
}
TEST(gfx_set_handle_is_einval)
{
    static HANDLE h = NULL;
    GX_BEGIN();
    if (!t_proc_in("ws2_32.dll", "SetAddrInfoExW")) { t_skip("no SetAddrInfoExW"); GX_END(); return; }
    EXPECT_EQ(set_call(NULL, NULL, NULL, &h), WSAEINVAL);
    GX_END();
}
TEST(gfx_set_a_async_is_einval)
{
    static OVERLAPPED ov;
    FARPROC p = t_proc_in("ws2_32.dll", "SetAddrInfoExA");
    GX_BEGIN();
    if (!p) { t_skip("no SetAddrInfoExA"); GX_END(); return; }
    memset(&ov, 0, sizeof ov);
    EXPECT_EQ(((int (WINAPI *)(PCSTR, PCSTR, SOCKET_ADDRESS *, DWORD, LPBLOB, DWORD, DWORD, LPGUID, struct timeval *, LPOVERLAPPED, void *, LPHANDLE))p)
              (NULL, NULL, NULL, 0, NULL, 0, NS_DNS, NULL, NULL, &ov, NULL, NULL), WSAEINVAL);
    GX_END();
}
