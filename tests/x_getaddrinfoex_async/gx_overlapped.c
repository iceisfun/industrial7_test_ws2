/* GetAddrInfoExW asynchronous modes: event completion, completion routine, the hEvent low-bit form, and the
 * rule that literal addresses complete synchronously even when an OVERLAPPED is supplied. Also the
 * argument rules tying timeout / handle / completion routine to the OVERLAPPED, and
 * GetAddrInfoExOverlappedResult. No external name server is ever required: host names used are
 * "localhost" (answered locally, asynchronously) and numeric literals. */
#include "gx.h"

#define NSALL 0
#define NSDNS 12
#define SENT_IH ((ULONG_PTR)0x1122334455667788ull)

static void ov_init(OVERLAPPED *ov, HANDLE ev)
{
    memset(ov, 0, sizeof *ov);
    ov->Internal = 0xcafe;                 /* proves the call (re)initialises or leaves it */
    ov->InternalHigh = SENT_IH;
    ov->Pointer = (PVOID)(ULONG_PTR)0xabcdef;
    ov->hEvent = ev;
}

/* ---- literals complete synchronously -------------------------------------------------------------- */
static const char *const syncnames[] = {"127.0.0.1", "::1", "[::1]", "1.2.3.4", "fe80::1%1", "::ffff:1.2.3.4"};
TEST(xov_literal_with_event_completes_synchronously)
{
    unsigned i; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(syncnames); i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x55;
        OVERLAPPED ov;
        GXEX *res = &gx_sentinel_ex;
        int r;
        ov_init(&ov, ev);
        SETWSERR(0x7777);
        r = GXW()(gx_w(syncnames[i]), NULL, ns ? NSDNS : NSALL, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h);
        CHECKF(r == 0 && WSERR() == 0, "%s ns=%d ret=%d wsa=%d", syncnames[i], ns, r, WSERR());
        CHECK(res != NULL && res != &gx_sentinel_ex);
        CHECK(h == NULL);                                   /* no job exists, so no cancel handle */
        GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT); /* event is not signalled for a synchronous answer */
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), WSAEINPROGRESS); /* the OVERLAPPED was left "in progress" */
        CHECK(ov.hEvent == ev);
        if (res && res != &gx_sentinel_ex) GXFREE(res);
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xov_literal_with_completion_routine_never_calls_back)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(syncnames); i++) {
        OVERLAPPED ov;
        GXEX *res = &gx_sentinel_ex;
        int r;
        gx_cb_reset();
        ov_init(&ov, NULL);
        r = GXW()(gx_w(syncnames[i]), NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, gx_cb_routine, NULL);
        GX_EQ(r, 0);
        GX_EQ(WaitForSingleObject(gx_cbs.done, 200), WAIT_TIMEOUT);
        GX_EQ(gx_cbs.calls, 0);
        if (res && res != &gx_sentinel_ex) GXFREE(res);
        gx_cb_close();
    }
    GX_END();
}
TEST(xov_literal_sync_leaves_pointer_and_counts_untouched)
{
    GX_BEGIN();
    OVERLAPPED ov; GXEX *res = NULL; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ov_init(&ov, ev);
    GX_EQ(GXW()(gx_lit4, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), 0);
    CHECK(ov.Pointer == (PVOID)(ULONG_PTR)0xabcdef);
    GX_EQ(ov.InternalHigh, SENT_IH);
    if (res) GXFREE(res);
    CloseHandle(ev);
    GX_END();
}

/* ---- a host name completes asynchronously ----------------------------------------------------------- */
TEST(xov_localhost_event_protocol_both_selectors)
{
    int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = NULL;
        OVERLAPPED ov;
        GXEX *res = &gx_sentinel_ex;
        int r;
        ov_init(&ov, ev);
        SETWSERR(0x7777);
        r = GXW()(gx_localhost, NULL, ns ? NSDNS : NSALL, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h);
        GX_EQ(r, ERROR_IO_PENDING);
        GX_EQ(WSERR(), ERROR_IO_PENDING);
        CHECK(h != NULL);                                  /* cancel handle issued for a pending job */
        GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
        GX_EQ(ov.Internal, 0);
        CHECK(ov.Pointer == (PVOID)&res);                 /* completion publishes the result-slot address */
        CHECK(ov.hEvent == ev);
        GX_EQ(ov.InternalHigh, SENT_IH);               /* byte count field is not used */
        CHECK(res != NULL && res != &gx_sentinel_ex);
        if (res && res != &gx_sentinel_ex) { GX_EQ(gx_count(res), 2); GXFREE(res); }
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xov_localhost_event_with_low_bit_still_signals)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex;
    int r;
    ov_init(&ov, (HANDLE)((ULONG_PTR)ev | 1));
    gx_cb_reset();
    r = GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL);
    GX_EQ(r, ERROR_IO_PENDING);
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    CHECK(ov.hEvent == (HANDLE)((ULONG_PTR)ev | 1));
    CHECK(res != NULL && res != &gx_sentinel_ex);
    if (res && res != &gx_sentinel_ex) GXFREE(res);
    gx_cb_close();
    CloseHandle(ev);
    GX_END();
}
TEST(xov_event_wait_sees_signal_before_result_read)
{
    /* the result slot is filled before the event is signalled: read it only after the wait */
    int i;
    GX_BEGIN();
    for (i = 0; i < 10; i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        OVERLAPPED ov; GXEX *res = NULL;
        ov_init(&ov, ev);
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
        GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
        CHECK(res != NULL);
        if (res) { GX_EQ(gx_count(res), 2); GXFREE(res); }
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xov_localhost_with_hints_and_event)
{
    GX_BEGIN();
    static const struct { int fam; const char *fams; } rows[] = {{AF_INET, "2"}, {AF_INET6, "23"}, {AF_UNSPEC, "23,2"}};
    unsigned i;
    for (i = 0; i < NARR(rows); i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        OVERLAPPED ov; GXEX *res = NULL; GXEX h = gx_hint(0, rows[i].fam, SOCK_STREAM, 0);
        ov_init(&ov, ev);
        GX_EQ(GXW()(gx_localhost, gx_w("80"), NSDNS, NULL, &h, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
        GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
        CHECK(res != NULL);
        if (res) { CHECKF(!strcmp(gx_fams(res), rows[i].fams), "fams %s", gx_fams(res)); GX_EQ(gx_port(res->ai_addr), 80); GXFREE(res); }
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xov_localhost_async_answer_equals_sync_answer)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = NULL, *a, *b;
    gx_res s = gx_call("localhost", NULL, NSDNS, NULL);
    ov_init(&ov, ev);
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    GX_EQ(gx_count(res), gx_count(s.res));
    for (a = res, b = s.res == &gx_sentinel_ex ? NULL : s.res; a && b; a = a->ai_next, b = b->ai_next) {
        GX_EQ(a->ai_family, b->ai_family); GX_EQ(a->ai_flags, b->ai_flags); GX_EQ(a->ai_addrlen, b->ai_addrlen);
        CHECK(!memcmp(a->ai_addr, b->ai_addr, a->ai_addrlen));
    }
    if (res) GXFREE(res);
    gx_release(&s);
    CloseHandle(ev);
    GX_END();
}

/* ---- completion routine ----------------------------------------------------------------------------- */
TEST(xov_localhost_completion_routine_arguments)
{
    GX_BEGIN();
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; HANDLE h = NULL;
    int r;
    gx_cb_reset();
    ov_init(&ov, NULL);
    r = GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, gx_cb_routine, &h);
    GX_EQ(r, ERROR_IO_PENDING);
    CHECK(h != NULL);
    GX_EQ(WaitForSingleObject(gx_cbs.done, 5000), WAIT_OBJECT_0);
    GX_EQ(gx_cbs.calls, 1);
    GX_EQ(gx_cbs.err, 0);
    GX_EQ(gx_cbs.bytes, 0);
    CHECK(gx_cbs.ov == &ov);
    CHECK(gx_cbs.tid != GetCurrentThreadId());           /* runs on a worker thread, not as a queued APC here */
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    CHECK(res != NULL && res != &gx_sentinel_ex);
    if (res && res != &gx_sentinel_ex) { GX_EQ(gx_count(res), 2); GXFREE(res); }
    gx_cb_close();
    GX_END();
}
TEST(xov_completion_routine_called_exactly_once)
{
    GX_BEGIN();
    OVERLAPPED ov; GXEX *res = NULL;
    gx_cb_reset();
    ov_init(&ov, NULL);
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, gx_cb_routine, NULL), ERROR_IO_PENDING);
    GX_EQ(WaitForSingleObject(gx_cbs.done, 5000), WAIT_OBJECT_0);
    Sleep(150);
    GX_EQ(gx_cbs.calls, 1);
    if (res) GXFREE(res);
    gx_cb_close();
    GX_END();
}

/* ---- a selector without a provider fails asynchronously, even for a literal ------------------------- */
TEST(xov_unsupported_selector_fails_through_completion_event)
{
    static const DWORD sel[] = {15, 1, 13, 99};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(sel); i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = NULL;
        OVERLAPPED ov; GXEX *res = &gx_sentinel_ex;
        int r;
        ov_init(&ov, ev);
        r = GXW()(gx_lit4, NULL, sel[i], NULL, NULL, (void **)&res, NULL, &ov, NULL, &h);
        CHECKF(r == ERROR_IO_PENDING, "ns %lu ret=%d", (unsigned long)sel[i], r);
        if (r == ERROR_IO_PENDING) {
            GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
            GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), WSASERVICE_NOT_FOUND);
            GX_EQ(ov.Internal, WSASERVICE_NOT_FOUND);
            CHECK(res == NULL);
        }
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xov_unsupported_selector_fails_through_completion_routine)
{
    GX_BEGIN();
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex;
    gx_cb_reset();
    ov_init(&ov, NULL);
    GX_EQ(GXW()(gx_lit4, NULL, 15, NULL, NULL, (void **)&res, NULL, &ov, gx_cb_routine, NULL), ERROR_IO_PENDING);
    GX_EQ(WaitForSingleObject(gx_cbs.done, 5000), WAIT_OBJECT_0);
    GX_EQ(gx_cbs.calls, 1);
    GX_EQ(gx_cbs.err, WSASERVICE_NOT_FOUND);
    GX_EQ(gx_cbs.bytes, 0);
    CHECK(gx_cbs.ov == &ov);
    CHECK(res == NULL);
    gx_cb_close();
    GX_END();
}

/* ---- argument rules --------------------------------------------------------------------------------- */
/* Without an OVERLAPPED, a timeout, a cancel handle or a completion routine is invalid. */
TEST(xov_extras_without_overlapped_are_einval)
{
    static const char *const names[] = {"127.0.0.1", "localhost", "", "::1"};
    unsigned i; int variant;
    GX_BEGIN();
    for (variant = 0; variant < 3; variant++) for (i = 0; i < NARR(names); i++) {
        struct timeval tv = {5, 0};
        HANDLE h = (HANDLE)0x55;
        GXEX *res = &gx_sentinel_ex;
        SETWSERR(0x7777);
        int r = GXW()(gx_w(names[i]), NULL, NSDNS, NULL, NULL, (void **)&res,
                      variant == 0 ? &tv : NULL, NULL, variant == 1 ? (PVOID)gx_cb_routine : NULL, variant == 2 ? &h : NULL);
        CHECKF(r == WSAEINVAL && WSERR() == WSAEINVAL, "variant %d name '%s' ret=%d wsa=%d", variant, names[i], r, WSERR());
        CHECK(res == NULL);
        if (variant == 2) CHECK(h == NULL);                 /* the handle slot is cleared before validation */
    }
    GX_END();
}
TEST(xov_event_and_completion_routine_together_is_einval_for_any_name)
{
    static const char *const names[] = {"127.0.0.1", "localhost", "::1"};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(names); i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        OVERLAPPED ov; GXEX *res = &gx_sentinel_ex;
        ov_init(&ov, ev);
        int r = GXW()(gx_w(names[i]), NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, gx_cb_routine, NULL);
        CHECKF(r == WSAEINVAL, "%s ret=%d", names[i], r);
        CHECK(res == NULL);
        GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xov_null_name_null_service_rejected_before_queueing)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x55;
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex;
    ov_init(&ov, ev);
    int r = GXW()(NULL, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h);
    GX_EQ(r, WSAHOST_NOT_FOUND);
    CHECK(res == NULL); CHECK(h == NULL);
    GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    GX_EQ(ov.Internal, 0xcafe);                        /* nothing was written into the OVERLAPPED */
    CloseHandle(ev);
    GX_END();
}
TEST(xov_dirty_hint_with_overlapped_fails_synchronously)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; GXEX h = gx_hint(0, 0, 0, 0);
    h.ai_addrlen = 4;
    ov_init(&ov, ev);
    int r = GXW()(gx_localhost, NULL, NSDNS, NULL, &h, (void **)&res, NULL, &ov, NULL, NULL);
    GX_EQ(r, WSANO_RECOVERY);
    CHECK(res == NULL);
    GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    CloseHandle(ev);
    GX_END();
}
TEST(xov_unsupported_family_with_overlapped_fails_synchronously)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x55;
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; GXEX hint = gx_hint(0, AF_UNIX, 0, 0);
    ov_init(&ov, ev);
    int r = GXW()(gx_localhost, NULL, NSDNS, NULL, &hint, (void **)&res, NULL, &ov, NULL, &h);
    CHECKF(r == WSAEAFNOSUPPORT || r == ERROR_IO_PENDING, "ret=%d", r);
    if (r == ERROR_IO_PENDING) { gx_wait(ev); if (res) GXFREE(res); t_note("AF_UNIX family hint failed asynchronously"); }
    else { CHECK(res == NULL); CHECK(h == NULL); GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT); }
    CloseHandle(ev);
    GX_END();
}

/* ---- GetAddrInfoExOverlappedResult ------------------------------------------------------------------- */
TEST(xov_overlapped_result_returns_low_dword_of_internal)
{
    static const struct { ULONG_PTR internal; int want; } rows[] = {
        {0, 0}, {0x2af9, 11001}, {0x103, 259}, {0x277f, 10111}, {0x277c, 10108}, {0x2734, 10036}, {1, 1},
        {0xffffffffu, -1}, {0x100000005ull, 5}, {0x7fffffff00000000ull, 0},
    };
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(rows); i++) {
        OVERLAPPED ov;
        memset(&ov, 0, sizeof ov);
        ov.Internal = rows[i].internal;
        CHECKF(UN(GetAddrInfoExOverlappedResult)(&ov) == rows[i].want, "internal %llx", (unsigned long long)rows[i].internal);
    }
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(NULL), WSAEINVAL);
    GX_END();
}
TEST(xov_overlapped_result_does_not_modify_overlapped)
{
    GX_BEGIN();
    OVERLAPPED ov, copy;
    ov_init(&ov, (HANDLE)0x44);
    copy = ov;
    UN(GetAddrInfoExOverlappedResult)(&ov);
    CHECK(!memcmp(&ov, &copy, sizeof ov));
    GX_END();
}
TEST(xov_overlapped_result_repeatable_after_completion)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = NULL;
    ov_init(&ov, ev);
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    if (res) GXFREE(res);
    CloseHandle(ev);
    GX_END();
}

/* ---- concurrency --------------------------------------------------------------------------------------- */
TEST(xov_several_queries_in_flight_all_complete)
{
    enum { N = 6 };
    HANDLE ev[N]; OVERLAPPED ov[N]; GXEX *res[N]; int i;
    GX_BEGIN();
    for (i = 0; i < N; i++) {
        res[i] = NULL;
        ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        ov_init(&ov[i], ev[i]);
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res[i], NULL, &ov[i], NULL, NULL), ERROR_IO_PENDING);
    }
    GX_EQ(WaitForMultipleObjects(N, ev, TRUE, 5000), WAIT_OBJECT_0);
    for (i = 0; i < N; i++) {
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov[i]), 0);
        CHECK(res[i] != NULL);
        if (res[i]) { GX_EQ(gx_count(res[i]), 2); GXFREE(res[i]); }
        CloseHandle(ev[i]);
    }
    GX_END();
}
TEST(xov_same_overlapped_reused_sequentially)
{
    int k;
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = NULL;
    for (k = 0; k < 3; k++) {
        ov_init(&ov, ev);
        ResetEvent(ev);
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
        GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
        if (res) { GXFREE(res); res = NULL; }
    }
    CloseHandle(ev);
    GX_END();
}
TEST(xov_sync_and_async_calls_interleave)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = NULL;
    ov_init(&ov, ev);
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
    { gx_res s = gx_call("localhost", NULL, NSDNS, NULL); GX_EQ(s.ret, 0); gx_release(&s); }
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    if (res) GXFREE(res);
    CloseHandle(ev);
    GX_END();
}
