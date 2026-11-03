/* Calls made when the Winsock startup count is zero, and completion bookkeeping on the caller's OVERLAPPED.
 * Without WSAStartup every entry point reports "not initialised" and leaves its output untouched. The
 * startup count is drained inside the test and restored before it returns. */
#include "gx.h"

#define NSDNS 12
#define WSANOTINIT 10093

typedef int (WINAPI *gni_fn)(const struct sockaddr *, int, char *, DWORD, char *, DWORD, int);
typedef int (WINAPI *gai_fn)(const char *, const char *, const void *, void **);

static int drain_startup(void)
{
    int n = 0;
    while (U(WSACleanup)() == 0 && n < 50) n++;
    return n;
}

TEST(xstate_extended_lookup_without_startup)
{
    static const struct { const char *name; DWORD ns; } rows[] = {{"localhost", NSDNS}, {"127.0.0.1", NSDNS}, {NULL, NSDNS}, {"127.0.0.1", 15}, {"localhost", 0}};
    unsigned i;
    GX_BEGIN();
    drain_startup();
    for (i = 0; i < NARR(rows); i++) {
        GXEX *res = &gx_sentinel_ex;
        int r;
        SETWSERR(0x7777);
        r = GXW()(rows[i].name ? gx_w(rows[i].name) : NULL, NULL, rows[i].ns, NULL, NULL, (void **)&res, NULL, NULL, NULL, NULL);
        CHECKF(r == WSANOTINIT && WSERR() == WSANOTINIT && res == &gx_sentinel_ex, "row %u ret=%d wsa=%d", i, r, WSERR());
    }
    GX_EQ(gx_up(), 0);
    GX_END();
}
TEST(xstate_overlapped_lookup_without_startup_fails_synchronously)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), h = (HANDLE)0x44;
    OVERLAPPED ov; GXEX *res = &gx_sentinel_ex;
    int r;
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    drain_startup();
    SETWSERR(0x7777);
    r = GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h);
    CHECKF(r == WSANOTINIT && WSERR() == WSANOTINIT, "ret=%d wsa=%d", r, WSERR());
    CHECK(res == &gx_sentinel_ex);
    CHECK(h == (HANDLE)0x44);                                  /* the cancel handle is not touched */
    GX_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    GX_EQ(gx_up(), 0);
    CloseHandle(ev);
    GX_END();
}
TEST(xstate_name_info_and_classic_lookup_without_startup)
{
    struct sockaddr_in sa;
    char buf[64], *dummy = NULL;
    gni_fn gni = (gni_fn)t_proc("getnameinfo");
    gai_fn gai = (gai_fn)t_proc("getaddrinfo");
    GX_BEGIN();
    if (!gni || !gai) { t_skip("missing export"); return; }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(0x7f000001);
    drain_startup();
    SETWSERR(0x7777);
    GX_EQ(gni((struct sockaddr *)&sa, sizeof sa, buf, sizeof buf, NULL, 0, NI_NUMERICHOST), WSANOTINIT);
    GX_EQ(WSERR(), WSANOTINIT);
    SETWSERR(0x7777);
    GX_EQ(gai("localhost", NULL, NULL, (void **)&dummy), WSANOTINIT);
    GX_EQ(WSERR(), WSANOTINIT);
    CHECK(dummy == NULL);
    GX_EQ(gx_up(), 0);
    GX_END();
}
TEST(xstate_service_lookup_begin_without_startup)
{
    WSAQUERYSETW qs;
    GUID g = gx_svcid_hostname;
    HANDLE h = NULL;
    GX_BEGIN();
    memset(&qs, 0, sizeof qs);
    qs.dwSize = sizeof qs; qs.lpszServiceInstanceName = (LPWSTR)gx_localhost; qs.lpServiceClassId = &g; qs.dwNameSpace = NSDNS;
    drain_startup();
    SETWSERR(0x7777);
    GX_EQ(U(WSALookupServiceBeginW)(&qs, LUP_RETURN_NAME, &h), -1);
    GX_EQ(WSERR(), WSANOTINIT);
    GX_EQ(gx_up(), 0);
    GX_END();
}
TEST(xstate_lookup_works_again_after_restart)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 3; i++) {
        gx_res r;
        drain_startup();
        GX_EQ(gx_up(), 0);
        r = gx_call("localhost", NULL, NSDNS, NULL);
        GX_EQ(r.ret, 0);
        if (r.ret == 0) CHECK(!strcmp(gx_fams(r.res), "23,2"));
        gx_release(&r);
    }
    GX_END();
}

/* ---- completion bookkeeping on the caller's OVERLAPPED ----------------------------------------------------- */
TEST(xstate_overlapped_without_event_or_routine_is_einval)
{
    GX_BEGIN();
    static const char *const names[] = {"localhost", "127.0.0.1", "nosuch.invalid"};
    unsigned i;
    for (i = 0; i < NARR(names); i++) {
        OVERLAPPED ov; GXEX *res = &gx_sentinel_ex; HANDLE h = (HANDLE)0x55;
        int r;
        memset(&ov, 0, sizeof ov);
        SETWSERR(0x7777);
        r = GXW()(gx_w(names[i]), NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, &h);
        CHECKF(r == WSAEINVAL && WSERR() == WSAEINVAL, "'%s' ret=%d wsa=%d", names[i], r, WSERR());
        CHECK(res == NULL);
        CHECK(h == NULL);
    }
    GX_END();
}
/* After an asynchronous completion the status words describe success: Internal is zero and the caller's
 * InternalHigh value is left alone. */
TEST(xstate_async_completion_status_words)
{
    GX_BEGIN();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov; GXEX *res = NULL;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev; ov.Internal = 0x1234; ov.InternalHigh = 0x55;
    GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
    GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
    GX_EQ(ov.Internal, 0);
    GX_EQ(ov.InternalHigh, 0x55);
    GX_EQ(UN(GetAddrInfoExOverlappedResult)(&ov), 0);
    if (res) GXFREE(res);
    CloseHandle(ev);
    GX_END();
}
