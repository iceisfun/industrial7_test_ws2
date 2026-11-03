/* GetAddrInfoExCancel: argument errors, the one-shot nature of the cancel handle, and the invariants between
 * the cancel result, the final status and the result slot when cancelling right after a call returns
 * pending. Whether the cancel wins the race is not asserted; what each outcome must look like is. */
#include "gx.h"

#define NSDNS 12
#define ERR_INVALID_HANDLE 6        /* ERROR_INVALID_HANDLE: the cancel handle is unknown or already used */
#define WSA_CANCELLED 10111         /* WSA_E_CANCELLED */

/* ---- argument errors -------------------------------------------------------------------------------- */
TEST(xcan_null_pointer_is_invalid_handle)
{
    GX_BEGIN();
    GX_EQ(UN(GetAddrInfoExCancel)(NULL), ERR_INVALID_HANDLE);
    GX_END();
}
TEST(xcan_null_handle_value_is_invalid_handle)
{
    GX_BEGIN();
    HANDLE h = NULL;
    GX_EQ(UN(GetAddrInfoExCancel)(&h), ERR_INVALID_HANDLE);
    GX_EQ(UN(GetAddrInfoExCancel)(&h), ERR_INVALID_HANDLE);
    CHECK(h == NULL);
    GX_END();
}
TEST(xcan_never_issued_handle_values_are_invalid_handle)
{
    static const ULONG_PTR vals[] = {1, 4, 0x1234567, 0xfffe, 0x7fffffff};
    unsigned i;
    GX_BEGIN();
    for (i = 0; i < NARR(vals); i++) {
        HANDLE h = (HANDLE)vals[i];
        CHECKF(UN(GetAddrInfoExCancel)(&h) == ERR_INVALID_HANDLE, "value %llx", (unsigned long long)vals[i]);
        CHECK(h == (HANDLE)vals[i]);
    }
    GX_END();
}
TEST(xcan_handle_from_synchronous_literal_is_null)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x44;
    OVERLAPPED ov; GXEX *res = NULL;
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    GX_EQ(GXW()(gx_lit4, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h), 0);
    CHECK(h == NULL);
    GX_EQ(UN(GetAddrInfoExCancel)(&h), ERR_INVALID_HANDLE);
    if (res) GXFREE(res);
    CloseHandle(ev);
    GX_END();
}
TEST(xcan_handle_cleared_by_failing_call)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x44;
    OVERLAPPED ov; GXEX *res = NULL;
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    GX_EQ(GXW()(NULL, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h), WSAHOST_NOT_FOUND);
    CHECK(h == NULL);
    CloseHandle(ev);
    GX_END();
}

/* ---- cancel right after a pending call -------------------------------------------------------------- */
/* Outcome A (cancel result 0): the job is cancelled; the event is signalled and the final status is
 * WSA_E_CANCELLED; the handle value is not modified by the cancel call. Outcome B (cancel result 6): the
 * lookup finished first and the final status is the lookup's own. In both outcomes a cancel issued after the
 * completion event reports an invalid handle: a cancel handle is good for one successful use. */
static void cancel_round(const char *name, DWORD ns, int *wins)
{
    gx_slot *s = gx_slot_new();
    HANDLE hcopy;
    int r, c1, c2, fin;
    s->res = &gx_sentinel_ex;
    r = GXW()(gx_w(name), NULL, ns, NULL, NULL, (void **)&s->res, NULL, &s->ov, NULL, &s->h);
    CHECKF(r == ERROR_IO_PENDING, "%s ret=%d", name, r);
    if (r != ERROR_IO_PENDING) return;
    CHECK(s->h != NULL);
    hcopy = s->h;
    c1 = UN(GetAddrInfoExCancel)(&s->h);
    CHECK(s->h == hcopy);
    CHECKF(c1 == 0 || c1 == ERR_INVALID_HANDLE, "first cancel %d", c1);
    GX_EQ(gx_wait(s->ev), WAIT_OBJECT_0);
    fin = UN(GetAddrInfoExOverlappedResult)(&s->ov);
    c2 = UN(GetAddrInfoExCancel)(&s->h);
    GX_EQ(c2, ERR_INVALID_HANDLE);
    if (c1 == 0) {
        (*wins)++;
        GX_EQ(fin, WSA_CANCELLED);
        GX_EQ(s->ov.Internal, WSA_CANCELLED);
    } else {
        CHECKF(fin == 0 || fin == WSAHOST_NOT_FOUND, "lost-race status %d", fin);
        if (fin == 0) CHECK(s->res != NULL && s->res != &gx_sentinel_ex);
    }
    if (s->res && s->res != &gx_sentinel_ex && fin == 0) GXFREE(s->res);
}
TEST(xcan_cancel_pending_localhost_invariants)
{
    int i, wins = 0;
    GX_BEGIN();
    for (i = 0; i < 8; i++) cancel_round("localhost", NSDNS, &wins);
    GX_END();
}
TEST(xcan_cancel_pending_localhost_selector_all)
{
    int i, wins = 0;
    GX_BEGIN();
    for (i = 0; i < 4; i++) cancel_round("localhost", 0, &wins);
    GX_END();
}
TEST(xcan_cancel_pending_empty_name_invariants)
{
    int i, wins = 0;
    GX_BEGIN();
    for (i = 0; i < 4; i++) cancel_round("", NSDNS, &wins);
    GX_END();
}
TEST(xcan_cancel_pending_dns_miss_invariants)
{
    int wins = 0;
    GX_BEGIN();
    /* a name that no local source resolves goes to the (absent) resolver; the answer may take a while, but
     * cancelling completes it immediately */
    cancel_round("nosuch.invalid", NSDNS, &wins);
    cancel_round("nosuch.invalid", 0, &wins);
    GX_END();
}
TEST(xcan_cancel_unsupported_selector_job)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 4; i++) {
        gx_slot *s = gx_slot_new();
        int c1, fin;
        s->res = &gx_sentinel_ex;
        GX_EQ(GXW()(gx_lit4, NULL, 15, NULL, NULL, (void **)&s->res, NULL, &s->ov, NULL, &s->h), ERROR_IO_PENDING);
        c1 = UN(GetAddrInfoExCancel)(&s->h);
        CHECKF(c1 == 0 || c1 == ERR_INVALID_HANDLE, "cancel %d", c1);
        GX_EQ(gx_wait(s->ev), WAIT_OBJECT_0);
        fin = UN(GetAddrInfoExOverlappedResult)(&s->ov);
        CHECKF(fin == (c1 == 0 ? WSA_CANCELLED : WSASERVICE_NOT_FOUND), "cancel %d final %d", c1, fin);
    }
    GX_END();
}
TEST(xcan_cancel_after_completion_is_invalid_handle)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 4; i++) {
        gx_slot *s = gx_slot_new();
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&s->res, NULL, &s->ov, NULL, &s->h), ERROR_IO_PENDING);
        GX_EQ(gx_wait(s->ev), WAIT_OBJECT_0);
        GX_EQ(UN(GetAddrInfoExCancel)(&s->h), ERR_INVALID_HANDLE);
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&s->ov), 0);        /* a late cancel does not change the result */
        CHECK(s->res != NULL);
        if (s->res) GXFREE(s->res);
    }
    GX_END();
}
TEST(xcan_cancel_with_completion_routine)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 4; i++) {
        gx_slot *s = gx_slot_new();
        int c1;
        gx_cb_reset();
        s->ov.hEvent = NULL;                                       /* an event and a routine cannot be combined */
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&s->res, NULL, &s->ov, gx_cb_routine, &s->h), ERROR_IO_PENDING);
        c1 = UN(GetAddrInfoExCancel)(&s->h);
        GX_EQ(WaitForSingleObject(gx_cbs.done, 5000), WAIT_OBJECT_0);
        Sleep(50);
        GX_EQ(gx_cbs.calls, 1);                                    /* routine runs once, cancelled or not */
        CHECK(gx_cbs.ov == &s->ov);
        GX_EQ(gx_cbs.bytes, 0);
        if (c1 == 0) GX_EQ(gx_cbs.err, WSA_CANCELLED);
        else { CHECKF(c1 == ERR_INVALID_HANDLE, "cancel %d", c1); GX_EQ(gx_cbs.err, 0); }
        if (c1 != 0 && s->res) GXFREE(s->res);
        gx_cb_close();
    }
    GX_END();
}
TEST(xcan_cancel_one_of_two_leaves_other_intact)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 3; i++) {
        gx_slot *s[2];
        int k, c;
        for (k = 0; k < 2; k++) {
            s[k] = gx_slot_new();
            GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&s[k]->res, NULL, &s[k]->ov, NULL, &s[k]->h), ERROR_IO_PENDING);
        }
        c = UN(GetAddrInfoExCancel)(&s[0]->h);
        CHECKF(c == 0 || c == ERR_INVALID_HANDLE, "cancel %d", c);
        for (k = 0; k < 2; k++) GX_EQ(gx_wait(s[k]->ev), WAIT_OBJECT_0);
        GX_EQ(UN(GetAddrInfoExOverlappedResult)(&s[1]->ov), 0);        /* the other query is unaffected */
        CHECK(s[1]->res != NULL);
        if (s[1]->res) GXFREE(s[1]->res);
        if (c != 0 && s[0]->res) GXFREE(s[0]->res);
    }
    GX_END();
}
