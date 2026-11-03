/* GetAddrInfoExW timeout (timeval) rules. The timeout is only meaningful with an OVERLAPPED; it is validated
 * eagerly: zero and negative values are invalid arguments; positive values are accepted and, for local
 * answers, never expire. No assertion depends on elapsed time. */
#include "gx.h"

#define NSALL 0
#define NSDNS 12

/* ---- invalid values -------------------------------------------------------------------------------- */
static const struct timeval badtv[] = {{0, 0}, {-1, 0}, {0, -1}, {-1, -1}, {-5, 100}};
static const char *const tvnames[] = {"127.0.0.1", "localhost", "", "nosuch.invalid", "::1"};
TEST(xtmo_zero_and_negative_values_are_einval_with_overlapped)
{
    unsigned i, j; int ns;
    GX_BEGIN();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(badtv); i++) for (j = 0; j < NARR(tvnames); j++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x44;
        OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; struct timeval tv = badtv[i];
        memset(&ov, 0, sizeof ov); ov.hEvent = ev;
        SETWSERR(0x7777);
        int r = GXW()(gx_w(tvnames[j]), NULL, ns ? NSDNS : NSALL, NULL, NULL, (void **)&res, &tv, &ov, NULL, &h);
        CHECKF(r == WSAEINVAL && WSERR() == WSAEINVAL, "tv %ld.%ld name '%s' ns=%d ret=%d", tv.tv_sec, tv.tv_usec, tvnames[j], ns, r);
        CHECK(res == NULL);
        CHECK(h == NULL);
        GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
        CHECK(tv.tv_sec == badtv[i].tv_sec && tv.tv_usec == badtv[i].tv_usec);
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xtmo_any_value_without_overlapped_is_einval)
{
    static const struct timeval tvs[] = {{0, 0}, {0, 1}, {1, 0}, {5, 0}, {-1, 0}};
    unsigned i, j;
    GX_BEGIN();
    for (i = 0; i < NARR(tvs); i++) for (j = 0; j < NARR(tvnames); j++) {
        GXEX *res = &gx_sentinel_ex; struct timeval tv = tvs[i];
        SETWSERR(0x7777);
        int r = GXW()(gx_w(tvnames[j]), NULL, NSDNS, NULL, NULL, (void **)&res, &tv, NULL, NULL, NULL);
        CHECKF(r == WSAEINVAL && WSERR() == WSAEINVAL, "tv %ld.%ld '%s' ret=%d", tv.tv_sec, tv.tv_usec, tvnames[j], r);
        CHECK(res == NULL);
    }
    GX_END();
}

/* ---- accepted values -------------------------------------------------------------------------------- */
static const struct timeval goodtv[] = {{0, 1}, {0, 1000}, {1, 0}, {5, 0}, {0, 2000000}, {30, 999999}};
TEST(xtmo_positive_values_literal_still_synchronous)
{
    unsigned i, j;
    GX_BEGIN();
    for (i = 0; i < NARR(goodtv); i++) for (j = 0; j < 3; j++) {
        static const char *const lits[] = {"127.0.0.1", "::1", "1.2.3.4"};
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x44;
        OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; struct timeval tv = goodtv[i];
        memset(&ov, 0, sizeof ov); ov.hEvent = ev;
        int r = GXW()(gx_w(lits[j]), NULL, NSDNS, NULL, NULL, (void **)&res, &tv, &ov, NULL, &h);
        CHECKF(r == 0, "tv %ld.%ld %s ret=%d", tv.tv_sec, tv.tv_usec, lits[j], r);
        CHECK(res != NULL && res != &gx_sentinel_ex);
        CHECK(h == NULL);
        GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
        if (res && res != &gx_sentinel_ex) GXFREE(res);
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xtmo_positive_values_localhost_pending_then_success)
{
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(goodtv); i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = NULL;
        OVERLAPPED ov; GXEX *res = NULL; struct timeval tv = goodtv[i];
        memset(&ov, 0, sizeof ov); ov.hEvent = ev;
        int r = GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, &tv, &ov, NULL, &h);
        CHECKF(r == ERROR_IO_PENDING, "tv %ld.%ld ret=%d", tv.tv_sec, tv.tv_usec, r);
        CHECK(h != NULL);
        GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
        /* a one-microsecond timeout does not expire a local answer */
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
        CHECK(res != NULL);
        if (res) { GX_EQ(gx_count(res), 2); GXFREE(res); }
        GX_EQ(tv.tv_sec, goodtv[i].tv_sec);
        CloseHandle(ev);
    }
    GX_END();
}
TEST(xtmo_positive_value_with_completion_routine)
{
    GX_BEGIN();
    OVERLAPPED ov; GXEX *res = NULL; struct timeval tv = {1, 0};
    gx_cb_reset();
    memset(&ov, 0, sizeof ov);
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, &tv, &ov, gx_cb_routine, NULL), ERROR_IO_PENDING);
    GX_EQ(WaitForSingleObject(gx_cbs.done, 5000), WAIT_OBJECT_0);
    GX_EQ(gx_cbs.err, 0);
    if (res) GXFREE(res);
    gx_cb_close();
    GX_END();
}
TEST(xtmo_unsupported_selector_with_timeout)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; struct timeval tv = {1, 0};
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    GX_EQ(GXW()(gx_lit4, NULL, 15, NULL, NULL, (void **)&res, &tv, &ov, NULL, NULL), ERROR_IO_PENDING);
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), WSASERVICE_NOT_FOUND);
    CloseHandle(ev);
    GX_END();
}
TEST(xtmo_dns_miss_with_timeout_is_pending_and_cancellable)
{
    GX_BEGIN();
    gx_slot *s = gx_slot_new();
    struct timeval tv = {5, 0};
    int c, fin;
    s->res = &gx_sentinel_ex;
    GX_EQ(GXW()(gx_w("nosuch.invalid"), NULL, NSDNS, NULL, NULL, (void **)&s->res, &tv, &s->ov, NULL, &s->h), ERROR_IO_PENDING);
    c = UN(GetAddrInfoExCancel)(&s->h);
    CHECK(c == 0 || c == 6);
    GX_EQ(gx_wait(s->ev), WAIT_OBJECT_0);
    fin = UN(GetAddrInfoExOverlappedResult)(&s->ov);
    CHECKF(fin == (c == 0 ? 10111 : WSAHOST_NOT_FOUND), "cancel %d final %d", c, fin);
    GX_END();
}
