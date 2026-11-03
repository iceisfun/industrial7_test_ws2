/* Concurrency and cross-API relations for GetAddrInfoEx: queries issued from several threads at once, a
 * cancel issued from a different thread than the one that started the query, and agreement between the
 * extended call and the classic getaddrinfo / GetAddrInfoW entry points for loopback data. */
#include "gx.h"

#define NSDNS 12

/* ---- several threads resolving at once ---------------------------------------------------------------- */
typedef struct { volatile LONG bad; int rounds; } worker_arg;
static DWORD WINAPI sync_worker(LPVOID p)
{
    worker_arg *a = p;
    int i;
    for (i = 0; i < a->rounds; i++) {
        GXEX *res = NULL;
        int r = GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, NULL, NULL, NULL);
        if (r != 0 || !res || strcmp(gx_fams(res), "23,2")) InterlockedIncrement(&a->bad);
        if (res) GXFREE(res);
    }
    return 0;
}
TEST(xdeep_sync_queries_from_four_threads)
{
    HANDLE th[4]; worker_arg arg[4]; int i;
    GX_BEGIN();
    for (i = 0; i < 4; i++) {
        arg[i].bad = 0; arg[i].rounds = 25;
        th[i] = CreateThread(NULL, 0, sync_worker, &arg[i], 0, NULL);
    }
    for (i = 0; i < 4; i++) {
        CHECK(th[i] != NULL);
        if (th[i]) { GX_EQ(WaitForSingleObject(th[i], 20000), WAIT_OBJECT_0); CloseHandle(th[i]); }
        GX_EQ(arg[i].bad, 0);
    }
    GX_END();
}
static DWORD WINAPI async_worker(LPVOID p)
{
    worker_arg *a = p;
    int i;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < a->rounds; i++) {
        OVERLAPPED ov; GXEX *res = NULL;
        memset(&ov, 0, sizeof ov); ov.hEvent = ev; ResetEvent(ev);
        int r = GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL);
        if (r != ERROR_IO_PENDING || WaitForSingleObject(ev, 5000) != WAIT_OBJECT_0 ||
            UN(GetAddrInfoExOverlappedResult)(&ov) != 0 || !res || strcmp(gx_fams(res), "23,2")) InterlockedIncrement(&a->bad);
        if (res) GXFREE(res);
    }
    CloseHandle(ev);
    return 0;
}
TEST(xdeep_overlapped_queries_from_four_threads)
{
    HANDLE th[4]; worker_arg arg[4]; int i;
    GX_BEGIN();
    for (i = 0; i < 4; i++) {
        arg[i].bad = 0; arg[i].rounds = 10;
        th[i] = CreateThread(NULL, 0, async_worker, &arg[i], 0, NULL);
    }
    for (i = 0; i < 4; i++) {
        CHECK(th[i] != NULL);
        if (th[i]) { GX_EQ(WaitForSingleObject(th[i], 30000), WAIT_OBJECT_0); CloseHandle(th[i]); }
        GX_EQ(arg[i].bad, 0);
    }
    GX_END();
}

/* ---- cancel from another thread ----------------------------------------------------------------------- */
static DWORD WINAPI cancel_thread(LPVOID p)
{
    gx_slot *s = p;
    return (DWORD)UN(GetAddrInfoExCancel)(&s->h);
}
TEST(xdeep_cancel_from_other_thread)
{
    int i;
    GX_BEGIN();
    for (i = 0; i < 4; i++) {
        gx_slot *s = gx_slot_new();
        HANDLE th; DWORD c = 99; int fin;
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&s->res, NULL, &s->ov, NULL, &s->h), ERROR_IO_PENDING);
        th = CreateThread(NULL, 0, cancel_thread, s, 0, NULL);
        CHECK(th != NULL);
        if (th) { GX_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0); GetExitCodeThread(th, &c); CloseHandle(th); }
        CHECKF(c == 0 || c == 6, "cancel %lu", (unsigned long)c);
        GX_EQ(gx_wait(s->ev), WAIT_OBJECT_0);
        fin = UN(GetAddrInfoExOverlappedResult)(&s->ov);
        if (c == 0) GX_EQ(fin, 10111);
        else { GX_EQ(fin, 0); if (s->res) GXFREE(s->res); }
    }
    GX_END();
}

/* ---- agreement with the classic entry points ---------------------------------------------------------- */
TEST(xdeep_classic_getaddrinfow_matches_extended_for_loopback)
{
    static const char *const names[] = {"localhost", "127.0.0.1", "::1", "LOCALHOST"};
    unsigned i;
    GX_BEGIN();
    if (!U(GetAddrInfoW) || !U(FreeAddrInfoW)) { t_skip("no GetAddrInfoW"); return; }
    for (i = 0; i < NARR(names); i++) {
        ADDRINFOW *c = NULL, *ce;
        gx_res x = gx_call(names[i], "80", NSDNS, NULL);
        int r = U(GetAddrInfoW)(gx_w(names[i]), gx_w("80"), NULL, &c);
        GX_EQ(r, 0); GX_EQ(x.ret, 0);
        if (r == 0 && x.ret == 0) {
            GXEX *e = x.res;
            for (ce = c; ce && e; ce = ce->ai_next, e = e->ai_next) {
                GX_EQ(ce->ai_family, e->ai_family);
                GX_EQ(ce->ai_socktype, e->ai_socktype);
                GX_EQ(ce->ai_protocol, e->ai_protocol);
                GX_EQ(ce->ai_addrlen, e->ai_addrlen);
                CHECK(!memcmp(ce->ai_addr, e->ai_addr, e->ai_addrlen));
            }
            CHECK(ce == NULL && e == NULL);
        }
        if (c) U(FreeAddrInfoW)(c);
        gx_release(&x);
    }
    GX_END();
}
