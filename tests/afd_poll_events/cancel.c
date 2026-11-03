/* Cancellation and request lifetime for IOCTL_AFD_POLL.
 * Measures: the completion status of a cancelled poll, cancelling one request by its status block while a
 * sibling on the same handle keeps waiting, the not-found result for a block that identifies nothing, the
 * per-thread scope of the classic cancel versus the all-requests scope of the extended one, reuse of the
 * same event and status block after a cancel, the interplay of timeout and cancel, and how several
 * non-exclusive requests on one handle complete independently. */
#include "ap.h"

typedef struct { ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev; } preq;

static void preq_init(preq *p, SOCKET target, ULONG mask, LONGLONG to)
{
    memset(p, 0, sizeof(*p));
    ap_fill(&p->in, to, 0, 1, &target, mask);
    p->ev = ap_event();
    memset(&p->io, 0xcc, sizeof(p->io));
}

static LONG preq_go(preq *p, HANDLE carrier)
{
    memset(&p->out, 0, sizeof(p->out));
    ResetEvent(p->ev);
    return ap_submit(carrier, p->ev, &p->io, &p->in, AP_SZ(1), &p->out, AP_SZ(1));
}

static int done(preq *p, DWORD ms) { return WaitForSingleObject(p->ev, ms) == WAIT_OBJECT_0; }

/* Issue a poll from a helper thread that stays alive until pthr_end(): a pending request is cancelled when the
 * thread that issued it exits, and requests of one thread on one socket do not wake each other's siblings
 * (see apev_second_poll_same_thread_*), so independent requests need independent issuing threads. */
typedef struct { preq *p; HANDLE car, issued, stop, th; LONG st; } pthr;
static DWORD WINAPI pthr_main(LPVOID v)
{
    pthr *t = (pthr *)v;
    t->st = preq_go(t->p, t->car);
    SetEvent(t->issued);
    WaitForSingleObject(t->stop, 20000);
    return 0;
}
static LONG pthr_start(pthr *t, preq *p, HANDLE car)
{
    t->p = p; t->car = car; t->st = (LONG)0xdeadbeef;
    t->issued = CreateEventW(NULL, TRUE, FALSE, NULL);
    t->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    t->th = CreateThread(NULL, 0, pthr_main, t, 0, NULL);
    if (!t->th || WaitForSingleObject(t->issued, 5000) != WAIT_OBJECT_0) return (LONG)0xdeadbeef;
    return t->st;
}
static void pthr_end(pthr *t)
{
    SetEvent(t->stop);
    if (t->th) { WaitForSingleObject(t->th, 5000); CloseHandle(t->th); }
    CloseHandle(t->issued); CloseHandle(t->stop);
}

typedef LONG (NTAPI *cancelex_fn)(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);

TEST(apev_cancel_completes_with_cancelled_status)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); preq p; IO_STATUS_BLOCK cio;
    preq_init(&p, l, APE_ACCEPT, AP_INFINITE);
    CK_ST(preq_go(&p, (HANDLE)l), APS_PENDING);
    CHECK(!done(&p, 150));
    memset(&cio, 0xcc, sizeof(cio));
    CK_ST(X.cancel_all((HANDLE)l, &cio), APS_SUCCESS);
    CHECK(done(&p, 3000));
    CK_ST(p.io.Status, APS_CANCELLED);
    CHECK(p.out.n == 0 || p.out.n == 1);
    CloseHandle(p.ev); ap_closeS(l);
}

TEST(apev_cancel_with_nothing_pending_succeeds)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); IO_STATUS_BLOCK cio;
    memset(&cio, 0xcc, sizeof(cio));
    CK_ST(X.cancel_all((HANDLE)l, &cio), APS_SUCCESS);
    CK_ST(cio.Status, APS_SUCCESS);
    ap_closeS(l);
}

/* A request that already completed cannot be cancelled: the status block identifies nothing. */
TEST(apev_cancel_ex_completed_request_not_found)
{
    AP_BEGIN();
    SOCKET c, s; preq p; IO_STATUS_BLOCK cio;
    if (!ap_init() || !X.cancel_ex) { t_skip("NtCancelIoFileEx unavailable"); return; }
    ap_pair(&c, &s);
    preq_init(&p, c, APE_SEND, AP_REL_MS(1000));
    CK_ST(preq_go(&p, (HANDLE)c), APS_SUCCESS);
    memset(&cio, 0xcc, sizeof(cio));
    CK_ST(X.cancel_ex((HANDLE)c, &p.io, &cio), APS_NOT_FOUND);
    CloseHandle(p.ev); ap_closeS(c); ap_closeS(s);
}

/* Cancelling by status block ends exactly that request; its sibling on the same handle keeps waiting
 * and later completes normally. */
TEST(apev_cancel_ex_by_iosb_leaves_sibling_pending)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), cl; preq p1, p2; IO_STATUS_BLOCK cio; pthr t2;
    if (!ap_init() || !X.cancel_ex) { t_skip("NtCancelIoFileEx unavailable"); return; }
    preq_init(&p1, l, APE_ACCEPT, AP_INFINITE);
    preq_init(&p2, l, APE_ACCEPT, AP_INFINITE);
    CK_ST(preq_go(&p1, (HANDLE)l), APS_PENDING);
    CK_ST(pthr_start(&t2, &p2, (HANDLE)l), APS_PENDING);
    memset(&cio, 0xcc, sizeof(cio));
    CK_ST(X.cancel_ex((HANDLE)l, &p1.io, &cio), APS_SUCCESS);
    CHECK(done(&p1, 3000));
    CK_ST(p1.io.Status, APS_CANCELLED);
    CHECK(!done(&p2, 200));
    cl = ap_dial(&a);
    CHECK(done(&p2, 3000));
    CK_ST(p2.io.Status, APS_SUCCESS);
    CHECK(p2.out.n == 1 && p2.out.e[0].ev == APE_ACCEPT);
    pthr_end(&t2);
    CloseHandle(p1.ev); CloseHandle(p2.ev); ap_closeS(cl); ap_closeS(l);
}

/* The status block, the event and the buffers are free for reuse once the cancelled request completed. */
TEST(apev_cancel_then_reuse_same_block_and_event)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), cl; preq p; IO_STATUS_BLOCK cio;
    preq_init(&p, l, APE_ACCEPT, AP_INFINITE);
    CK_ST(preq_go(&p, (HANDLE)l), APS_PENDING);
    X.cancel_all((HANDLE)l, &cio);
    CHECK(done(&p, 3000));
    CK_ST(p.io.Status, APS_CANCELLED);
    CK_ST(preq_go(&p, (HANDLE)l), APS_PENDING);
    CHECK(!done(&p, 100));
    cl = ap_dial(&a);
    CHECK(done(&p, 3000));
    CK_ST(p.io.Status, APS_SUCCESS);
    CHECK(p.out.n == 1);
    CloseHandle(p.ev); ap_closeS(cl); ap_closeS(l);
}

/* The classic cancel only reaches requests issued by the calling thread; the extended cancel without a
 * status block reaches every request on the handle. */
typedef struct { SOCKET l; preq p; HANDLE issued, release; LONG ret; } thr_ctx;

static DWORD WINAPI thr_issue(void *arg)
{
    thr_ctx *t = arg;
    t->ret = preq_go(&t->p, (HANDLE)t->l);
    SetEvent(t->issued);
    WaitForSingleObject(t->release, 8000);        /* stay alive: a finished thread cancels its own requests */
    return 0;
}

TEST(apev_cancel_is_per_thread_for_classic_cancel)
{
    AP_BEGIN();
    typedef BOOL (WINAPI *cancelioex_t)(HANDLE, LPOVERLAPPED);
    cancelioex_t cancelex = (cancelioex_t)t_proc_in("kernel32.dll", "CancelIoEx");
    thr_ctx t; HANDLE th; IO_STATUS_BLOCK cio;
    if (!cancelex) { t_skip("CancelIoEx unavailable"); return; }
    memset(&t, 0, sizeof(t));
    t.l = ap_listener(NULL, 1);
    preq_init(&t.p, t.l, APE_ACCEPT, AP_INFINITE);
    t.issued = ap_event(); t.release = ap_event();
    th = CreateThread(NULL, 0, thr_issue, &t, 0, NULL);
    CHECK(th != NULL);
    CHECK(WaitForSingleObject(t.issued, 4000) == WAIT_OBJECT_0);
    CK_ST(t.ret, APS_PENDING);
    X.cancel_all((HANDLE)t.l, &cio);                   /* issued by another thread: untouched */
    CHECK(!done(&t.p, 250));
    CHECK(cancelex((HANDLE)t.l, NULL) != 0);           /* all requests on the handle */
    CHECK(done(&t.p, 3000));
    CK_ST(t.p.io.Status, APS_CANCELLED);
    SetEvent(t.release);
    WaitForSingleObject(th, 4000);
    CloseHandle(th); CloseHandle(t.issued); CloseHandle(t.release); CloseHandle(t.p.ev); ap_closeS(t.l);
}

/* A cancel that arrives after the deadline ended the request changes nothing. */
TEST(apev_cancel_after_timeout_keeps_timeout_status)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); preq p; IO_STATUS_BLOCK cio;
    preq_init(&p, l, APE_ACCEPT, AP_REL_MS(40));
    CK_ST(preq_go(&p, (HANDLE)l), APS_PENDING);
    CHECK(done(&p, 4000));
    CK_ST(p.io.Status, APS_TIMEOUT);
    CK_ST(X.cancel_all((HANDLE)l, &cio), APS_SUCCESS);
    CK_ST(p.io.Status, APS_TIMEOUT);
    CloseHandle(p.ev); ap_closeS(l);
}

/* Non-exclusive requests on one handle are independent: an event that satisfies one of them, both when
 * they ask for the same thing, completes each with its own entry. */
TEST(apev_two_requests_same_socket_both_complete)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), cl; preq p1, p2; pthr t2;
    preq_init(&p1, l, APE_ACCEPT, AP_REL_MS(5000));
    preq_init(&p2, l, APE_ACCEPT | APE_RECEIVE, AP_REL_MS(5000));
    CK_ST(preq_go(&p1, (HANDLE)l), APS_PENDING);
    CK_ST(pthr_start(&t2, &p2, (HANDLE)l), APS_PENDING);
    cl = ap_dial(&a);
    CHECK(done(&p1, 3000)); CHECK(done(&p2, 3000));
    CK_ST(p1.io.Status, APS_SUCCESS); CK_ST(p2.io.Status, APS_SUCCESS);
    CHECK(p1.out.n == 1 && p1.out.e[0].ev == APE_ACCEPT);
    CHECK(p2.out.n == 1 && p2.out.e[0].ev == APE_ACCEPT);       /* the requested but absent bit is not reported */
    pthr_end(&t2);
    CloseHandle(p1.ev); CloseHandle(p2.ev); ap_closeS(cl); ap_closeS(l);
}

/* A request that watches a different socket than the one it was issued on is woken by that socket and
 * by nothing that happens to the issuing handle. */
TEST(apev_request_follows_polled_socket_not_carrier)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), other = ap_listener(NULL, 1), cl; preq p; struct sockaddr_in oa;
    preq_init(&p, l, APE_ACCEPT, AP_REL_MS(5000));
    CK_ST(preq_go(&p, (HANDLE)other), APS_PENDING);
    { int n = sizeof(oa); CHECK(X.getsockname(other, (struct sockaddr *)&oa, &n) == 0); }
    { SOCKET c2 = ap_dial(&oa); CHECK(!done(&p, 200)); ap_closeS(c2); }     /* a connection to the carrier: no effect */
    cl = ap_dial(&a);
    CHECK(done(&p, 3000));
    CK_ST(p.io.Status, APS_SUCCESS);
    CHECK(p.out.n == 1 && p.out.e[0].h == l);
    CloseHandle(p.ev); ap_closeS(cl); ap_closeS(l); ap_closeS(other);
}

/* Several requests for different bits of one connected socket: each is completed by the event it asked for. */
TEST(apev_requests_complete_by_their_own_bits)
{
    AP_BEGIN();
    SOCKET c, s; preq rcv, hup; pthr th;
    ap_pair(&c, &s);
    preq_init(&rcv, s, APE_RECEIVE, AP_REL_MS(5000));
    preq_init(&hup, s, APE_DISCONNECT, AP_REL_MS(5000));
    CK_ST(preq_go(&rcv, (HANDLE)s), APS_PENDING);
    CK_ST(pthr_start(&th, &hup, (HANDLE)s), APS_PENDING);
    ap_send_n(c, 2);
    CHECK(done(&rcv, 3000));
    CHECK(!done(&hup, 200));
    CK_ST(rcv.io.Status, APS_SUCCESS);
    CHECK(rcv.out.n == 1 && rcv.out.e[0].ev == APE_RECEIVE);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CHECK(done(&hup, 3000));
    CK_ST(hup.io.Status, APS_SUCCESS);
    CHECK(hup.out.n == 1 && hup.out.e[0].ev == APE_DISCONNECT);
    pthr_end(&th);
    CloseHandle(rcv.ev); CloseHandle(hup.ev); ap_closeS(c); ap_closeS(s);
}

/* Two non-exclusive requests from the same thread for the same socket: only the first one is ever woken by the
 * socket's events. The later one stays pending, ends by its own timeout, or by a cancel, and an event that
 * completes the first does not complete it. */
TEST(apev_second_poll_same_thread_same_socket_is_not_woken_by_events)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 2), c1, c2; preq p1, p2; IO_STATUS_BLOCK cio;
    preq_init(&p1, l, APE_ACCEPT, AP_INFINITE);
    preq_init(&p2, l, APE_ACCEPT, AP_INFINITE);
    CK_ST(preq_go(&p1, (HANDLE)l), APS_PENDING);
    CK_ST(preq_go(&p2, (HANDLE)l), APS_PENDING);
    c1 = ap_dial(&a);
    CHECK(done(&p1, 3000));
    CK_ST(p1.io.Status, APS_SUCCESS);
    CHECK(p1.out.n == 1 && p1.out.e[0].ev == APE_ACCEPT);
    CHECK(!done(&p2, 1000));
    c2 = ap_dial(&a);                                              /* a further connection changes nothing for it */
    CHECK(!done(&p2, 500));
    memset(&cio, 0xcc, sizeof(cio));
    CK_ST(X.cancel_all((HANDLE)l, &cio), APS_SUCCESS);             /* the cancel still reaches it */
    CHECK(done(&p2, 3000));
    CK_ST(p2.io.Status, APS_CANCELLED);
    CloseHandle(p1.ev); CloseHandle(p2.ev); ap_closeS(c1); ap_closeS(c2); ap_closeS(l);
}

TEST(apev_second_poll_same_thread_same_socket_still_times_out)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1); preq p1, p2; IO_STATUS_BLOCK cio;
    preq_init(&p1, l, APE_ACCEPT, AP_INFINITE);
    preq_init(&p2, l, APE_ACCEPT, AP_REL_MS(500));
    CK_ST(preq_go(&p1, (HANDLE)l), APS_PENDING);
    CK_ST(preq_go(&p2, (HANDLE)l), APS_PENDING);
    CHECK(done(&p2, 4000));
    CK_ST(p2.io.Status, APS_TIMEOUT);
    CHECK(p2.out.n == 0);
    CHECK(!done(&p1, 100));
    X.cancel_all((HANDLE)l, &cio);
    CHECK(done(&p1, 3000));
    CK_ST(p1.io.Status, APS_CANCELLED);
    CloseHandle(p1.ev); CloseHandle(p2.ev); ap_closeS(l);
}

/* The ordinary sequential use: a request issued after the previous one ended is woken as usual. */
TEST(apev_poll_issued_after_previous_one_ended_is_woken)
{
    AP_BEGIN();
    SOCKET c, s; preq rcv, hup;
    ap_pair(&c, &s);
    preq_init(&rcv, s, APE_RECEIVE, AP_REL_MS(5000));
    preq_init(&hup, s, APE_DISCONNECT, AP_REL_MS(5000));
    CK_ST(preq_go(&rcv, (HANDLE)s), APS_PENDING);
    ap_send_n(c, 2);
    CHECK(done(&rcv, 3000));
    CK_ST(rcv.io.Status, APS_SUCCESS);
    CK_ST(preq_go(&hup, (HANDLE)s), APS_PENDING);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CHECK(done(&hup, 3000));
    CK_ST(hup.io.Status, APS_SUCCESS);
    CHECK(hup.out.n == 1 && hup.out.e[0].ev == APE_DISCONNECT);
    CloseHandle(rcv.ev); CloseHandle(hup.ev); ap_closeS(c); ap_closeS(s);
}

/* ---- completion delivery: user APC and event ---------------------------------------------------- */

static volatile LONG g_apc_hits;
static PVOID g_apc_ctx;
static PIO_STATUS_BLOCK g_apc_io;
static void NTAPI poll_apc(PVOID ctx, PIO_STATUS_BLOCK io, ULONG rsv)
{
    g_apc_ctx = ctx; g_apc_io = io;
    InterlockedIncrement(&g_apc_hits);
}

/* A pending request with an APC routine runs it, once, with the context and the status block, when the
 * waiting thread is alertable after the completion. */
TEST(apev_apc_runs_after_pending_completion)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), cl; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    g_apc_hits = 0; g_apc_ctx = NULL; g_apc_io = NULL;
    ap_fill(&in, AP_REL_MS(5000), 0, 1, &l, APE_ACCEPT);
    memset(&out, 0, sizeof(out));
    CK_ST(X.ioctl((HANDLE)l, ev, poll_apc, (PVOID)(ULONG_PTR)0x1234, &io, AP_IOCTL_POLL, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    CHECK(g_apc_hits == 0);
    cl = ap_dial(&a);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    SleepEx(1000, TRUE);                               /* alertable: the queued routine runs here */
    CHECK(g_apc_hits == 1);
    CHECK(g_apc_ctx == (PVOID)(ULONG_PTR)0x1234);
    CHECK(g_apc_io == &io);
    CK_ST(io.Status, APS_SUCCESS);
    CloseHandle(ev); ap_closeS(cl); ap_closeS(l);
}

/* A request completed inside the call still queues its APC and signals its event. */
TEST(apev_immediate_completion_still_signals_event_and_apc)
{
    AP_BEGIN();
    SOCKET c, s; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_pair(&c, &s);
    g_apc_hits = 0; g_apc_ctx = NULL; g_apc_io = NULL;
    ap_fill(&in, AP_REL_MS(1000), 0, 1, &c, APE_SEND);
    memset(&out, 0, sizeof(out));
    CK_ST(X.ioctl((HANDLE)c, ev, poll_apc, (PVOID)(ULONG_PTR)0x77, &io, AP_IOCTL_POLL, &in, AP_SZ(1), &out, AP_SZ(1)), APS_SUCCESS);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(io.Information == AP_SZ(1));
    CHECK(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
    SleepEx(0, TRUE);
    CHECK(g_apc_hits == 1);
    CHECK(g_apc_ctx == (PVOID)(ULONG_PTR)0x77);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

/* The status block is also valid when the request is queued: it holds the final status after the event. */
TEST(apev_pending_request_final_block_matches_output)
{
    AP_BEGIN();
    SOCKET c, s; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_pair(&c, &s);
    ap_fill(&in, AP_REL_MS(5000), 0, 1, &s, APE_RECEIVE);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)s, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    ap_send_n(c, 1);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(io.Information == AP_SZ(out.n));
    CHECK(out.n == 1 && out.e[0].h == s && out.e[0].ev == APE_RECEIVE && out.e[0].st == 0);
    CHECK(out.to == AP_REL_MS(5000));
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}
