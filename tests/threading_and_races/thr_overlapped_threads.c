/* Overlapped receive/send issued from one thread and completed, waited on, cancelled or abandoned by another.
 *
 * Measures: completion routines (APCs) run only on the issuing thread and only while it is alertable; a
 * thread that ends with a request outstanding gets that request cancelled (the routine never runs and the data
 * stays queued); CancelIo cancels only the calling thread's requests while CancelIoEx cancels by overlapped;
 * WSAGetOverlappedResult works from a thread other than the issuer; closesocket from another thread aborts the
 * request with WSA_OPERATION_ABORTED (and runs the routine on the issuer with that error); pending receives on one
 * socket are satisfied in issue order.
 */
#include "thr.h"

#ifndef WSA_IO_PENDING
#define WSA_IO_PENDING 997
#endif

enum { M_ALERT, M_NONALERT_THEN_ALERT, M_EXIT, M_WSAWAIT, M_EVENT_EXIT, M_EVENT_ALERT };

struct iss {
    SOCKET        s;
    int           mode;
    int           use_routine;
    HANDLE        issued, go, th;
    WSAOVERLAPPED ov;
    WSABUF        wb;
    char          buf[64];
    DWORD         n, f;
    int           ret, err;
    volatile LONG hits;
    LONG          hits_mid;
    DWORD         tid, cb_tid, cb_err, cb_bytes, cb_flags;
    WSAOVERLAPPED *cb_ov;
    DWORD         sleep_ret, wait_ret;
};

static void CALLBACK iss_routine(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD flags)
{
    struct iss *p = CONTAINING_RECORD(ov, struct iss, ov);
    p->cb_tid = GetCurrentThreadId();
    p->cb_err = err; p->cb_bytes = bytes; p->cb_flags = flags; p->cb_ov = ov;
    InterlockedIncrement(&p->hits);
}

static DWORD WINAPI iss_main(void *x)
{
    struct iss *p = (struct iss *)x;
    WSAEVENT dummy = NULL;
    p->tid = GetCurrentThreadId();
    p->wb.buf = p->buf; p->wb.len = (ULONG)(sizeof p->buf);
    memset(&p->ov, 0, sizeof p->ov);
    if (!p->use_routine || p->mode == M_EVENT_EXIT || p->mode == M_EVENT_ALERT) p->ov.hEvent = U(WSACreateEvent)();
    wset(0);
    p->ret = U(WSARecv)(p->s, &p->wb, 1, &p->n, &p->f, &p->ov, p->use_routine ? iss_routine : NULL);
    p->err = werr();
    SetEvent(p->issued);
    switch (p->mode) {
    case M_ALERT:
    case M_EVENT_ALERT:
        p->sleep_ret = SleepEx(8000, TRUE);
        break;
    case M_NONALERT_THEN_ALERT:
        WaitForSingleObject(p->go, 8000);
        p->hits_mid = p->hits;
        p->sleep_ret = SleepEx(2000, TRUE);
        break;
    case M_WSAWAIT:
        dummy = U(WSACreateEvent)();
        p->wait_ret = U(WSAWaitForMultipleEvents)(1, &dummy, FALSE, 8000, TRUE);
        U(WSACloseEvent)(dummy);
        break;
    default:
        break;
    }
    return 0;
}
static void iss_start(struct iss *p, SOCKET s, int mode, int use_routine)
{
    memset(p, 0, sizeof *p);
    p->s = s; p->mode = mode; p->use_routine = use_routine;
    p->issued = CreateEventA(NULL, TRUE, FALSE, NULL);
    p->go = CreateEventA(NULL, TRUE, FALSE, NULL);
    p->th = CreateThread(NULL, 0, iss_main, p, 0, NULL);
    WaitForSingleObject(p->issued, 3000);
}
static int iss_join(struct iss *p)
{
    int ok = join(p->th, 10000);
    p->th = NULL;
    CloseHandle(p->issued); CloseHandle(p->go);
    if (p->ov.hEvent) { U(WSACloseEvent)(p->ov.hEvent); p->ov.hEvent = NULL; }
    return ok;
}
#define PENDING(p) do { EQV((p)->ret, SOCKET_ERROR); EQV((p)->err, WSA_IO_PENDING); } while (0)

/* ---- completion routines --------------------------------------------------------------------------------------------- */
TEST(thr_ovl_routine_runs_on_issuing_thread)
{
    SOCKET c, s;
    struct iss p;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    PENDING(&p);
    snd(c, "abc", 3);
    CHECK(iss_join(&p));
    EQV(p.hits, 1);
    EQV(p.cb_tid, p.tid);
    EQV(p.cb_err, 0);
    EQV(p.cb_bytes, 3);
    EQV(p.cb_flags, 0);
    CHECK(p.cb_ov == &p.ov);
    EQV(p.sleep_ret, WAIT_IO_COMPLETION);
    CHECK(!memcmp(p.buf, "abc", 3));
    CHECK(p.tid != GetCurrentThreadId());
    cls(c); cls(s);
}
TEST(thr_ovl_routine_not_run_on_other_alertable_thread)
{
    SOCKET c, s;
    struct iss p;
    DWORD r;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_NONALERT_THEN_ALERT, 1);
    PENDING(&p);
    snd(c, "x", 1);
    SETTLE();
    r = SleepEx(300, TRUE);              /* this thread is alertable, but the request is not ours */
    EQV(r, 0);
    EQV(p.hits, 0);
    SetEvent(p.go);
    CHECK(iss_join(&p));
    EQV(p.hits, 1);
    EQV(p.cb_tid, p.tid);
    cls(c); cls(s);
}
TEST(thr_ovl_routine_waits_for_alertable_state)
{
    SOCKET c, s;
    struct iss p;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_NONALERT_THEN_ALERT, 1);
    snd(c, "xy", 2);
    SETTLE();
    SetEvent(p.go);                      /* the issuer wakes from a plain wait, records the count, then goes alertable */
    CHECK(iss_join(&p));
    EQV(p.hits_mid, 0);                  /* the completion had arrived, the routine had not run */
    EQV(p.hits, 1);
    EQV(p.sleep_ret, WAIT_IO_COMPLETION);
    EQV(p.cb_bytes, 2);
    cls(c); cls(s);
}
TEST(thr_ovl_routine_runs_during_wsawait_alertable)
{
    SOCKET c, s;
    struct iss p;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_WSAWAIT, 1);
    snd(c, "w", 1);
    CHECK(iss_join(&p));
    EQV(p.hits, 1);
    EQV(p.wait_ret, WSA_WAIT_IO_COMPLETION);
    EQV(p.cb_tid, p.tid);
    cls(c); cls(s);
}
TEST(thr_ovl_each_thread_runs_its_own_routine)
{
    SOCKET c1, s1, c2, s2;
    struct iss p1, p2;
    NEED();
    CHECK(pair(&c1, &s1));
    CHECK(pair(&c2, &s2));
    iss_start(&p1, s1, M_ALERT, 1);
    iss_start(&p2, s2, M_ALERT, 1);
    snd(c2, "2", 1);
    snd(c1, "1", 1);
    CHECK(iss_join(&p1));
    CHECK(iss_join(&p2));
    EQV(p1.hits, 1); EQV(p2.hits, 1);
    EQV(p1.cb_tid, p1.tid);
    EQV(p2.cb_tid, p2.tid);
    CHECK(p1.tid != p2.tid);
    EQV(p1.buf[0], '1'); EQV(p2.buf[0], '2');
    cls(c1); cls(s1); cls(c2); cls(s2);
}
struct twin {
    SOCKET s[2]; WSAOVERLAPPED ov[2]; WSABUF wb[2]; char buf[2][8];
    HANDLE issued, go, th; volatile LONG hits; LONG hits_before; DWORD sleep_ret; DWORD tids[2];
};
static void CALLBACK twin_routine(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD flags)
{
    struct twin *t = (struct twin *)ov->hEvent;       /* hEvent is free for application use with a routine */
    int i = ov == &t->ov[1];
    t->tids[i] = GetCurrentThreadId();
    InterlockedIncrement(&t->hits);
}
static DWORD WINAPI twin_main(void *x)
{
    struct twin *t = (struct twin *)x;
    DWORD n, f;
    int i;
    for (i = 0; i < 2; i++) {
        memset(&t->ov[i], 0, sizeof t->ov[i]);
        t->ov[i].hEvent = (HANDLE)t;
        t->wb[i].buf = t->buf[i]; t->wb[i].len = 8;
        n = f = 0;
        U(WSARecv)(t->s[i], &t->wb[i], 1, &n, &f, &t->ov[i], twin_routine);
    }
    SetEvent(t->issued);
    WaitForSingleObject(t->go, 8000);
    t->hits_before = t->hits;
    t->sleep_ret = SleepEx(2000, TRUE);
    return 0;
}
TEST(thr_ovl_two_routines_one_thread_one_alertable_call)
{
    /* two sockets, one issuing thread: both completions are queued while it is not alertable; one alertable call runs both */
    SOCKET c1, s1, c2, s2;
    struct twin t;
    NEED();
    CHECK(pair(&c1, &s1));
    CHECK(pair(&c2, &s2));
    memset(&t, 0, sizeof t);
    t.s[0] = s1; t.s[1] = s2;
    t.issued = CreateEventA(NULL, TRUE, FALSE, NULL);
    t.go = CreateEventA(NULL, TRUE, FALSE, NULL);
    t.th = CreateThread(NULL, 0, twin_main, &t, 0, NULL);
    WaitForSingleObject(t.issued, 3000);
    snd(c1, "a", 1);
    snd(c2, "b", 1);
    SETTLE();
    SetEvent(t.go);
    CHECK(join(t.th, 10000));
    EQV(t.hits_before, 0);
    EQV(t.hits, 2);
    EQV(t.sleep_ret, WAIT_IO_COMPLETION);
    EQV(t.tids[0], t.tids[1]);
    CloseHandle(t.issued); CloseHandle(t.go);
    cls(c1); cls(s1); cls(c2); cls(s2);
}

/* ---- thread exit with a request outstanding -------------------------------------------------------------------------------- */
TEST(thr_ovl_exit_cancels_routine_request)
{
    SOCKET c, s;
    struct iss p;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_EXIT, 1);
    PENDING(&p);
    CHECK(iss_join(&p));                 /* the issuing thread is gone with the request still outstanding */
    SleepEx(100, TRUE);
    EQV(p.hits, 0);                      /* a routine owned by a dead thread can never run */
    cls(c); cls(s);
}
TEST(thr_ovl_exit_leaves_data_for_next_reader)
{
    SOCKET c, s;
    struct iss p;
    char x[8] = { 0 };
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_EXIT, 1);
    CHECK(iss_join(&p));
    snd(c, "kept", 4);
    SETTLE();
    EQV(rcv(s, x, 8), 4);                /* nobody consumed the bytes: the abandoned request was cancelled */
    CHECK(!memcmp(x, "kept", 4));
    EQV(p.hits, 0);
    cls(c); cls(s);
}
TEST(thr_ovl_exit_event_request_is_aborted)
{
    SOCKET c, s;
    struct iss p;
    DWORD n = 77, f = 77;
    BOOL ok;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_EVENT_EXIT, 0);
    PENDING(&p);
    {
        HANDLE ev = p.ov.hEvent;
        DWORD w;
        WaitForSingleObject(p.th, 10000);
        w = WaitForSingleObject(ev, 1000);
        EQV(w, WAIT_OBJECT_0);           /* the cancellation completes the request, which signals its event */
        wset(0);
        ok = U(WSAGetOverlappedResult)(s, &p.ov, &n, FALSE, &f);
        EQV(ok, FALSE);
        EQV(werr(), WSA_OPERATION_ABORTED);
        EQV(n, 0);
        CHECK(HasOverlappedIoCompleted(&p.ov));
    }
    CHECK(iss_join(&p));
    cls(c); cls(s);
}

/* ---- cancellation from another thread ----------------------------------------------------------------------------------------- */
TEST(thr_ovl_cancelioex_from_other_thread_aborts_with_routine)
{
    SOCKET c, s;
    struct iss p;
    BOOL ok;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    PENDING(&p);
    ok = CancelIoEx((HANDLE)s, &p.ov);
    CHECK(ok);
    CHECK(iss_join(&p));
    EQV(p.hits, 1);
    EQV(p.cb_err, WSA_OPERATION_ABORTED);
    EQV(p.cb_bytes, 0);
    EQV(p.cb_tid, p.tid);
    cls(c); cls(s);
}
TEST(thr_ovl_cancelio_from_other_thread_leaves_request_pending)
{
    /* CancelIo only cancels requests issued by the calling thread; the issuer's request stays pending */
    SOCKET c, s;
    struct iss p;
    BOOL ok;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    PENDING(&p);
    ok = CancelIo((HANDLE)s);
    t_note("CancelIo with nothing of ours pending: %d", (int)ok);
    SETTLE();
    EQV(p.hits, 0);
    CHECK(!finished(p.th));
    snd(c, "ok", 2);
    CHECK(iss_join(&p));
    EQV(p.hits, 1);
    EQV(p.cb_err, 0);
    EQV(p.cb_bytes, 2);
    cls(c); cls(s);
}
TEST(thr_ovl_closesocket_from_other_thread_aborts_routine_request)
{
    SOCKET c, s;
    struct iss p;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    PENDING(&p);
    EQV(cls(s), 0);
    CHECK(iss_join(&p));
    EQV(p.hits, 1);
    EQV(p.cb_err, WSAECONNABORTED);
    EQV(p.cb_bytes, 0);
    EQV(p.cb_tid, p.tid);
    cls(c);
}
TEST(thr_ovl_closesocket_from_other_thread_aborts_event_request)
{
    SOCKET c, s;
    struct iss p;
    DWORD n = 55, f = 55;
    BOOL ok;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_EVENT_ALERT, 0);
    PENDING(&p);
    EQV(cls(s), 0);
    CHECK(WaitForSingleObject(p.ov.hEvent, 5000) == WAIT_OBJECT_0);
    wset(0);
    ok = U(WSAGetOverlappedResult)(s, &p.ov, &n, FALSE, &f);
    EQV(ok, FALSE);
    EQV(werr(), WSAENOTSOCK);            /* the handle is gone, so the result query itself fails */
    CHECK(iss_join(&p));
    cls(c);
}

/* ---- result queries from a thread that did not issue ----------------------------------------------------------------------------- */
struct waitres { SOCKET s; WSAOVERLAPPED *ov; DWORD n, f; BOOL ok; int err; HANDLE th, ready; };
static DWORD WINAPI waitres_main(void *x)
{
    struct waitres *w = (struct waitres *)x;
    SetEvent(w->ready);
    wset(0);
    w->ok = U(WSAGetOverlappedResult)(w->s, w->ov, &w->n, TRUE, &w->f);
    w->err = werr();
    return 0;
}
TEST(thr_ovl_getoverlappedresult_wait_in_other_thread)
{
    /* this thread issues, a second thread waits for the result with fWait=TRUE */
    SOCKET c, s;
    WSAOVERLAPPED ov;
    WSABUF wb;
    char buf[16];
    DWORD n = 0, f = 0;
    struct waitres w;
    int r;
    NEED();
    CHECK(pair(&c, &s));
    memset(&ov, 0, sizeof ov);
    ov.hEvent = U(WSACreateEvent)();
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(s, &wb, 1, &n, &f, &ov, NULL);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSA_IO_PENDING);
    memset(&w, 0, sizeof w);
    w.s = s; w.ov = &ov;
    w.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    w.th = CreateThread(NULL, 0, waitres_main, &w, 0, NULL);
    WaitForSingleObject(w.ready, 3000);
    SETTLE();
    CHECK(!finished(w.th));
    snd(c, "res", 3);
    CHECK(join(w.th, 5000));
    EQV(w.ok, TRUE);
    EQV(w.n, 3);
    EQV(w.f, 0);
    CloseHandle(w.ready);
    U(WSACloseEvent)(ov.hEvent);
    cls(c); cls(s);
}
TEST(thr_ovl_getoverlappedresult_nowait_in_other_thread_incomplete)
{
    SOCKET c, s;
    WSAOVERLAPPED ov;
    WSABUF wb;
    char buf[16];
    DWORD n = 0, f = 0;
    int r;
    NEED();
    CHECK(pair(&c, &s));
    memset(&ov, 0, sizeof ov);
    ov.hEvent = U(WSACreateEvent)();
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(s, &wb, 1, &n, &f, &ov, NULL);
    EQV(r, SOCKET_ERROR);
    EQV(werr(), WSA_IO_PENDING);
    wset(0);
    EQV(U(WSAGetOverlappedResult)(s, &ov, &n, FALSE, &f), FALSE);
    EQV(werr(), WSA_IO_INCOMPLETE);
    snd(c, "q", 1);
    EQV(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
    EQV(U(WSAGetOverlappedResult)(s, &ov, &n, FALSE, &f), TRUE);
    EQV(n, 1);
    U(WSACloseEvent)(ov.hEvent);
    cls(c); cls(s);
}

/* ---- pending receives on one socket from two threads --------------------------------------------------------------------------------- */
TEST(thr_ovl_two_pending_receives_complete_in_issue_order)
{
    SOCKET c, s;
    struct iss p1, p2;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p1, s, M_ALERT, 1);       /* issued first */
    iss_start(&p2, s, M_ALERT, 1);       /* issued second */
    PENDING(&p1); PENDING(&p2);
    snd(c, "1", 1);
    SETTLE();
    snd(c, "2", 1);
    CHECK(iss_join(&p1));
    CHECK(iss_join(&p2));
    EQV(p1.hits, 1); EQV(p2.hits, 1);
    EQV(p1.buf[0], '1');
    EQV(p2.buf[0], '2');
    cls(c); cls(s);
}
TEST(thr_ovl_pending_receive_and_blocking_recv_from_two_threads)
{
    /* an outstanding overlapped receive owns the next bytes; a blocking recv started later gets the ones after */
    SOCKET c, s;
    struct iss p;
    struct blk b;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    PENDING(&p);
    blk_start(&b, B_RECV, s, 8);
    snd(c, "1", 1);
    SETTLE();
    snd(c, "2", 1);
    CHECK(iss_join(&p));
    CHECK(blk_join(&b));
    EQV(p.buf[0], '1');
    EQV(b.ret, 1);
    EQV(b.buf[0], '2');
    cls(c); cls(s);
}

/* ---- completion ports: workers receiving completions of different sockets ------------------------------------------------------------ */
#define NSOCK 4
struct cp_item { ULONG_PTR key; LPOVERLAPPED ov; DWORD bytes; DWORD err; BOOL ok; DWORD tid; };
struct cp_ctx { HANDLE port; struct cp_item items[32]; volatile LONG n; HANDLE ths[4]; int nth; };

static DWORD WINAPI cp_worker(void *x)
{
    struct cp_ctx *c = (struct cp_ctx *)x;
    for (;;) {
        DWORD bytes = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
        BOOL ok = GetQueuedCompletionStatus(c->port, &bytes, &key, &ov, 8000);
        DWORD err = ok ? 0 : GetLastError();
        if (!ov && !ok) return 1;                    /* timeout: the test failed */
        if (!ov && key == 0 && ok) return 0;         /* sentinel */
        {
            LONG i = InterlockedIncrement(&c->n) - 1;
            if (i < 32) {
                c->items[i].key = key; c->items[i].ov = ov; c->items[i].bytes = bytes;
                c->items[i].err = err; c->items[i].ok = ok; c->items[i].tid = GetCurrentThreadId();
            }
        }
    }
}
static void cp_start(struct cp_ctx *c, int nth)
{
    int i;
    memset(c, 0, sizeof *c);
    c->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    c->nth = nth;
    for (i = 0; i < nth; i++) c->ths[i] = CreateThread(NULL, 0, cp_worker, c, 0, NULL);
}
static int cp_stop(struct cp_ctx *c)
{
    int i, ok = 1;
    for (i = 0; i < c->nth; i++) PostQueuedCompletionStatus(c->port, 0, 0, NULL);
    for (i = 0; i < c->nth; i++) {
        DWORD code = 99;
        if (WaitForSingleObject(c->ths[i], 10000) != WAIT_OBJECT_0) { ok = 0; continue; }
        GetExitCodeThread(c->ths[i], &code);
        if (code != 0) ok = 0;
        CloseHandle(c->ths[i]);
    }
    CloseHandle(c->port);
    return ok;
}
/* Wait until n completions have been recorded (bounded). */
static int cp_wait(struct cp_ctx *c, LONG n)
{
    int i;
    for (i = 0; i < 400 && c->n < n; i++) Sleep(10);
    return c->n >= n;
}

struct sockrec { SOCKET c, s; WSAOVERLAPPED ov; WSABUF wb; char buf[16]; };

TEST(thr_ovl_iocp_workers_receive_completions_of_distinct_sockets)
{
    struct sockrec r[NSOCK];
    struct cp_ctx cp;
    int i, k;
    DWORD n, f;
    NEED();
    cp_start(&cp, 3);
    for (i = 0; i < NSOCK; i++) {
        CHECK(pair(&r[i].c, &r[i].s));
        CHECK(CreateIoCompletionPort((HANDLE)r[i].s, cp.port, (ULONG_PTR)(i + 1), 0) == cp.port);
        memset(&r[i].ov, 0, sizeof r[i].ov);
        r[i].wb.buf = r[i].buf; r[i].wb.len = sizeof r[i].buf;
        n = f = 0;
        EQV(U(WSARecv)(r[i].s, &r[i].wb, 1, &n, &f, &r[i].ov, NULL), SOCKET_ERROR);
        EQV(werr(), WSA_IO_PENDING);
    }
    for (i = NSOCK - 1; i >= 0; i--) snd(r[i].c, "p", 1);
    CHECK(cp_wait(&cp, NSOCK));
    CHECK(cp_stop(&cp));
    EQV(cp.n, NSOCK);
    for (i = 0; i < NSOCK; i++) {
        int seen = 0;
        for (k = 0; k < NSOCK && k < cp.n; k++) {
            if (cp.items[k].key == (ULONG_PTR)(i + 1)) {
                seen++;
                CHECK(cp.items[k].ov == &r[i].ov);
                EQV(cp.items[k].ok, TRUE);
                EQV(cp.items[k].bytes, 1);
                CHECK(cp.items[k].tid != GetCurrentThreadId());
            }
        }
        EQV(seen, 1);
        EQV(r[i].buf[0], 'p');
        cls(r[i].c); cls(r[i].s);
    }
}
TEST(thr_ovl_iocp_sends_from_two_threads_complete_on_workers)
{
    struct sockrec r[2];
    struct cp_ctx cp;
    DWORD n, f;
    int i;
    NEED();
    cp_start(&cp, 2);
    for (i = 0; i < 2; i++) {
        CHECK(pair(&r[i].c, &r[i].s));
        CHECK(CreateIoCompletionPort((HANDLE)r[i].c, cp.port, (ULONG_PTR)(10 + i), 0) == cp.port);
        memset(&r[i].ov, 0, sizeof r[i].ov);
        memset(r[i].buf, 'a' + i, 8);
        r[i].wb.buf = r[i].buf; r[i].wb.len = 8;
        n = 0; f = 0;
        r[i].ov.hEvent = NULL;
        {
            int rc = U(WSASend)(r[i].c, &r[i].wb, 1, &n, 0, &r[i].ov, NULL);
            CHECK(rc == 0 || werr() == WSA_IO_PENDING);
        }
    }
    CHECK(cp_wait(&cp, 2));
    CHECK(cp_stop(&cp));
    EQV(cp.n, 2);
    for (i = 0; i < 2; i++) {
        int k, seen = 0;
        for (k = 0; k < 2; k++) if (cp.items[k].key == (ULONG_PTR)(10 + i)) { seen++; EQV(cp.items[k].bytes, 8); CHECK(cp.items[k].ov == &r[i].ov); }
        EQV(seen, 1);
        cls(r[i].c); cls(r[i].s);
    }
}

struct closer2 { SOCKET *s; int n; HANDLE th; };
static DWORD WINAPI closer2_main(void *x)
{
    struct closer2 *c = (struct closer2 *)x;
    int i;
    for (i = 0; i < c->n; i++) cls(c->s[i]);
    return 0;
}
TEST(thr_ovl_iocp_two_threads_close_eight_sockets_all_abort)
{
    struct sockrec r[8];
    SOCKET lo[4], hi[4];
    struct closer2 c1, c2;
    struct cp_ctx cp;
    DWORD n, f;
    int i, k;
    NEED();
    cp_start(&cp, 2);
    for (i = 0; i < 8; i++) {
        CHECK(pair(&r[i].c, &r[i].s));
        CHECK(CreateIoCompletionPort((HANDLE)r[i].s, cp.port, (ULONG_PTR)(i + 1), 0) == cp.port);
        memset(&r[i].ov, 0, sizeof r[i].ov);
        r[i].wb.buf = r[i].buf; r[i].wb.len = sizeof r[i].buf;
        n = f = 0;
        EQV(U(WSARecv)(r[i].s, &r[i].wb, 1, &n, &f, &r[i].ov, NULL), SOCKET_ERROR);
    }
    for (i = 0; i < 4; i++) { lo[i] = r[i].s; hi[i] = r[i + 4].s; }
    c1.s = lo; c1.n = 4; c2.s = hi; c2.n = 4;
    c1.th = CreateThread(NULL, 0, closer2_main, &c1, 0, NULL);
    c2.th = CreateThread(NULL, 0, closer2_main, &c2, 0, NULL);
    CHECK(join(c1.th, 5000));
    CHECK(join(c2.th, 5000));
    CHECK(cp_wait(&cp, 8));
    CHECK(cp_stop(&cp));
    EQV(cp.n, 8);
    for (i = 0; i < 8; i++) {
        int seen = 0;
        for (k = 0; k < 8 && k < cp.n; k++) {
            if (cp.items[k].key == (ULONG_PTR)(i + 1)) {
                seen++;
                CHECK(cp.items[k].ov == &r[i].ov);
                EQV(cp.items[k].ok, FALSE);
                CHECK(cp.items[k].err == ERROR_OPERATION_ABORTED || cp.items[k].err == ERROR_CONNECTION_ABORTED);
                EQV(cp.items[k].bytes, 0);
            }
        }
        EQV(seen, 1);
        cls(r[i].c);
    }
}

/* ---- CancelIoEx on the other request kinds ------------------------------------------------------------------------------------ */
TEST(thr_ovl_cancelioex_cancels_only_the_named_request)
{
    SOCKET c1, s1, c2, s2;
    struct iss p1, p2;
    NEED();
    CHECK(pair(&c1, &s1));
    CHECK(pair(&c2, &s2));
    iss_start(&p1, s1, M_ALERT, 1);
    iss_start(&p2, s2, M_ALERT, 1);
    PENDING(&p1); PENDING(&p2);
    CHECK(CancelIoEx((HANDLE)s1, &p1.ov));
    CHECK(iss_join(&p1));
    EQV(p1.hits, 1);
    EQV(p1.cb_err, WSA_OPERATION_ABORTED);
    CHECK(!finished(p2.th));              /* the other socket's request is untouched */
    snd(c2, "k", 1);
    CHECK(iss_join(&p2));
    EQV(p2.cb_err, 0);
    EQV(p2.cb_bytes, 1);
    cls(c1); cls(s1); cls(c2); cls(s2);
}
TEST(thr_ovl_cancelioex_on_completed_request_is_not_found)
{
    SOCKET c, s;
    struct iss p;
    BOOL ok;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    snd(c, "d", 1);
    CHECK(iss_join(&p));
    SetLastError(0);
    ok = CancelIoEx((HANDLE)s, &p.ov);
    EQV(ok, FALSE);
    EQV(GetLastError(), ERROR_NOT_FOUND);
    cls(c); cls(s);
}
TEST(thr_ovl_cancelioex_null_cancels_every_request_on_handle)
{
    SOCKET c, s;
    struct iss p1, p2;
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p1, s, M_ALERT, 1);
    iss_start(&p2, s, M_ALERT, 1);
    PENDING(&p1); PENDING(&p2);
    CHECK(CancelIoEx((HANDLE)s, NULL));   /* issued by two different threads: both are cancelled */
    CHECK(iss_join(&p1));
    CHECK(iss_join(&p2));
    EQV(p1.cb_err, WSA_OPERATION_ABORTED);
    EQV(p2.cb_err, WSA_OPERATION_ABORTED);
    cls(c); cls(s);
}
TEST(thr_ovl_cancelled_request_does_not_swallow_later_data)
{
    SOCKET c, s;
    struct iss p;
    char x[8] = { 0 };
    NEED();
    CHECK(pair(&c, &s));
    iss_start(&p, s, M_ALERT, 1);
    CHECK(CancelIoEx((HANDLE)s, &p.ov));
    CHECK(iss_join(&p));
    snd(c, "late", 4);
    SETTLE();
    EQV(rcv(s, x, 8), 4);
    CHECK(!memcmp(x, "late", 4));
    cls(c); cls(s);
}
