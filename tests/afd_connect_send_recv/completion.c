/* Completion delivery of AFD data requests: event, APC and I/O completion port, status block contents,
 * cancellation (NtCancelIoFile, CancelIoEx), and what happens to several pending requests when the socket
 * is closed.
 *
 * These are the NT-level rules every AFD user relies on: a request that returns "pending" is completed later
 * through the event, the APC routine or a completion packet whose overlapped pointer is the ApcContext supplied
 * at submission; the status block then holds the final status and the byte count.
 */
#include "csr.h"

static HANDLE new_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

typedef struct { volatile LONG calls; PVOID ctx; PIO_STATUS_BLOCK iosb; LONG status; ULONG_PTR info; } APCREC;
static void NTAPI apc_record(PVOID ctx, PIO_STATUS_BLOCK io, ULONG reserved) {
    APCREC *r = (APCREC *)ctx;
    InterlockedIncrement(&r->calls);
    r->ctx = ctx; r->iosb = io; r->status = io->Status; r->info = io->Information;
}

/* a pending one-buffer receive request of up to 16 bytes */
typedef struct { char buf[16]; WSABUF wb; CS_DATA d; } RQ;
static void rq_init(RQ *q) {
    memset(q, 0, sizeof *q);
    q->wb.len = sizeof q->buf; q->wb.buf = q->buf;
    q->d.buf = &q->wb; q->d.count = 1; q->d.tdi = CS_TDI_NORMAL;
}
static LONG rq_submit(SOCKET s, RQ *q, HANDLE ev, CS_APC apc, void *ctx, IO_STATUS_BLOCK *io) {
    return cs_submit(s, ev, apc, ctx, io, CS_IOCTL_RECV, &q->d, sizeof q->d, NULL, 0);
}

/* ---- event ----------------------------------------------------------------------------------------------- */
TEST(csrcomp_event_signalled_after_pending_completion) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    HANDLE ev = new_event();
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, ev, NULL, NULL, &io), CS_PENDING);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);
    CHECK(X.send(s, "evt", 3, 0) == 3);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 3);
    CHECK(!memcmp(q.buf, "evt", 3));
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrcomp_auto_reset_event_wakes_once) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, ev, NULL, NULL, &io), CS_PENDING);
    CHECK(X.send(s, "x", 1, 0) == 1);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrcomp_event_with_synchronous_completion) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "now", 3, 0) == 3);
    CHECK(cs_readable(c, CS_WAIT));
    RQ q; rq_init(&q);
    HANDLE ev = new_event();
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = rq_submit(c, &q, ev, NULL, NULL, &io);
    CHECK_ST2(st, CS_SUCCESS, CS_PENDING);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);       /* the event is signalled either way */
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 3);
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrcomp_status_block_is_set_pending_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    HANDLE ev = new_event();
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, ev, NULL, NULL, &io), CS_PENDING);
    t_note("status block right after a pending submit: status 0x%08lx", (unsigned long)io.Status);
    CHECK(X.send(s, "x", 1, 0) == 1);
    CHECK(cs_await(c, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    CloseHandle(ev); cs_close(c); cs_close(s);
}

/* ---- APC ------------------------------------------------------------------------------------------------- */
TEST(csrcomp_apc_runs_in_alertable_wait_after_pending_completion) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    APCREC rec; memset(&rec, 0, sizeof rec);
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, NULL, apc_record, &rec, &io), CS_PENDING);
    CHECK(X.send(s, "apc", 3, 0) == 3);
    DWORD w = U(SleepEx)(CS_WAIT, TRUE);
    CHECK(w == WAIT_IO_COMPLETION);
    CHECK(rec.calls == 1);
    CHECK(rec.ctx == &rec);
    CHECK(rec.iosb == &io);
    CHECK_ST(rec.status, CS_SUCCESS);
    CHECK(rec.info == 3);
    cs_close(c); cs_close(s);
}
TEST(csrcomp_apc_does_not_run_without_alertable_wait) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    APCREC rec; memset(&rec, 0, sizeof rec);
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, NULL, apc_record, &rec, &io), CS_PENDING);
    CHECK(X.send(s, "x", 1, 0) == 1);
    for (int i = 0; i < 100 && io.Status != 0; i++) Sleep(10);      /* completion is visible in the block */
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(rec.calls == 0);                                           /* but the routine has not been called */
    U(SleepEx)(1000, TRUE);
    CHECK(rec.calls == 1);
    cs_close(c); cs_close(s);
}
TEST(csrcomp_apc_receives_cancelled_status) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    APCREC rec; memset(&rec, 0, sizeof rec);
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, NULL, apc_record, &rec, &io), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    U(SleepEx)(CS_WAIT, TRUE);
    CHECK(rec.calls == 1);
    CHECK_ST(rec.status, CS_CANCELLED);
    CHECK(rec.info == 0);
    cs_close(c); cs_close(s);
}
TEST(csrcomp_apc_with_synchronous_completion_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "now", 3, 0) == 3);
    CHECK(cs_readable(c, CS_WAIT));
    RQ q; rq_init(&q);
    APCREC rec; memset(&rec, 0, sizeof rec);
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = rq_submit(c, &q, NULL, apc_record, &rec, &io);
    CHECK_ST2(st, CS_SUCCESS, CS_PENDING);
    U(SleepEx)(500, TRUE);
    t_note("submit 0x%08lx, routine called %ld times", (unsigned long)st, (long)rec.calls);
    CHECK(io.Status == 0 && io.Information == 3);
    cs_close(c); cs_close(s);
}

/* ---- completion port ------------------------------------------------------------------------------------ */
typedef struct { IO_STATUS_BLOCK io; } PKT;                         /* the block doubles as the overlapped */
TEST(csrcomp_port_packet_for_pending_receive) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE port = U(CreateIoCompletionPort)(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(port != NULL);
    CHECK(U(CreateIoCompletionPort)((HANDLE)c, port, (ULONG_PTR)0x1234, 0) == port);
    RQ q; rq_init(&q);
    PKT p; memset(&p, 0xAB, sizeof p);
    CHECK_ST(rq_submit(c, &q, NULL, NULL, &p.io, &p.io), CS_PENDING);   /* the context is what the port returns */
    CHECK(X.send(s, "port", 4, 0) == 4);
    DWORD n = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    BOOL ok = U(GetQueuedCompletionStatus)(port, &n, &key, &ov, CS_WAIT);
    CHECK(ok);
    CHECK(ov == (LPOVERLAPPED)&p.io);
    CHECK(key == 0x1234);
    CHECK(n == 4);
    CHECK_ST(p.io.Status, CS_SUCCESS);
    CHECK(!memcmp(q.buf, "port", 4));
    CloseHandle(port); cs_close(c); cs_close(s);
}
TEST(csrcomp_port_packet_for_cancelled_request) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE port = U(CreateIoCompletionPort)(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(U(CreateIoCompletionPort)((HANDLE)c, port, (ULONG_PTR)7, 0) == port);
    RQ q; rq_init(&q);
    PKT p; memset(&p, 0xAB, sizeof p);
    CHECK_ST(rq_submit(c, &q, NULL, NULL, &p.io, &p.io), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    DWORD n = 99; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    SetLastError(0);
    BOOL ok = U(GetQueuedCompletionStatus)(port, &n, &key, &ov, CS_WAIT);
    CHECK(!ok);
    CHECK(ov == (LPOVERLAPPED)&p.io);                                /* a failed I/O still dequeues a packet */
    CHECK(n == 0);
    CHECK_ST(p.io.Status, CS_CANCELLED);
    CloseHandle(port); cs_close(c); cs_close(s);
}
TEST(csrcomp_port_packets_arrive_in_completion_order) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE port = U(CreateIoCompletionPort)(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(U(CreateIoCompletionPort)((HANDLE)c, port, (ULONG_PTR)1, 0) == port);
    RQ q1, q2; rq_init(&q1); rq_init(&q2);
    PKT p1, p2; memset(&p1, 0xAB, sizeof p1); memset(&p2, 0xAB, sizeof p2);
    CHECK_ST(rq_submit(c, &q1, NULL, NULL, &p1.io, &p1.io), CS_PENDING);
    CHECK_ST(rq_submit(c, &q2, NULL, NULL, &p2.io, &p2.io), CS_PENDING);
    CHECK(X.send(s, "AA", 2, 0) == 2);
    DWORD n; ULONG_PTR key; LPOVERLAPPED ov = NULL;
    CHECK(U(GetQueuedCompletionStatus)(port, &n, &key, &ov, CS_WAIT) && ov == (LPOVERLAPPED)&p1.io && n == 2);
    CHECK(X.send(s, "BBB", 3, 0) == 3);
    CHECK(U(GetQueuedCompletionStatus)(port, &n, &key, &ov, CS_WAIT) && ov == (LPOVERLAPPED)&p2.io && n == 3);
    CloseHandle(port); cs_close(c); cs_close(s);
}
TEST(csrcomp_port_packet_for_large_send) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE port = U(CreateIoCompletionPort)(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(U(CreateIoCompletionPort)((HANDLE)c, port, (ULONG_PTR)5, 0) == port);
    const ULONG total = 2u << 20;
    char *data = (char *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) { t_skip("no memory"); CloseHandle(port); cs_close(c); cs_close(s); return; }
    WSABUF wb = { total, data };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1;
    PKT p; memset(&p, 0xAB, sizeof p);
    LONG lst = cs_submit(c, NULL, NULL, &p.io, &p.io, CS_IOCTL_SEND, &d, sizeof d, NULL, 0);
    CHECK_ST2(lst, CS_PENDING, CS_SUCCESS);
    static char sink[65536];
    ULONG got = 0;
    while (got < total && cs_readable(s, CS_WAIT)) { int n = X.recv(s, sink, sizeof sink, 0); if (n <= 0) break; got += n; }
    CHECK(got == total);
    DWORD n = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    CHECK(U(GetQueuedCompletionStatus)(port, &n, &key, &ov, CS_WAIT));
    CHECK(ov == (LPOVERLAPPED)&p.io && n == total && key == 5);
    CloseHandle(port); VirtualFree(data, 0, MEM_RELEASE); cs_close(c); cs_close(s);
}
TEST(csrcomp_port_with_queued_data_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE port = U(CreateIoCompletionPort)(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(U(CreateIoCompletionPort)((HANDLE)c, port, (ULONG_PTR)3, 0) == port);
    CHECK(X.send(s, "q", 1, 0) == 1);
    CHECK(cs_readable(c, CS_WAIT));
    RQ q; rq_init(&q);
    PKT p; memset(&p, 0xAB, sizeof p);
    LONG st = rq_submit(c, &q, NULL, NULL, &p.io, &p.io);
    CHECK_ST2(st, CS_SUCCESS, CS_PENDING);
    DWORD n = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    BOOL ok = U(GetQueuedCompletionStatus)(port, &n, &key, &ov, 500);
    t_note("request completed in the submit call (0x%08lx), packet queued: %d", (unsigned long)st, (int)ok);
    CHECK(p.io.Status == 0 && p.io.Information == 1);
    CloseHandle(port); cs_close(c); cs_close(s);
}

/* ---- cancellation ---------------------------------------------------------------------------------------- */
TEST(csrcomp_cancel_with_nothing_pending_succeeds) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    IO_STATUS_BLOCK cio; memset(&cio, 0xAB, sizeof cio);
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    CHECK_ST(cio.Status, CS_SUCCESS);
    CHECK(cio.Information == 0);
    cs_close(c); cs_close(s);
}
TEST(csrcomp_cancel_targets_only_requests_of_that_handle) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q1, q2; rq_init(&q1); rq_init(&q2);
    HANDLE e1 = new_event(), e2 = new_event();
    IO_STATUS_BLOCK i1, i2; memset(&i1, 0xAB, sizeof i1); memset(&i2, 0xAB, sizeof i2);
    CHECK_ST(rq_submit(c, &q1, e1, NULL, NULL, &i1), CS_PENDING);
    CHECK_ST(rq_submit(s, &q2, e2, NULL, NULL, &i2), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    CHECK(WaitForSingleObject(e1, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(i1.Status, CS_CANCELLED);
    CHECK(WaitForSingleObject(e2, 100) == WAIT_TIMEOUT);              /* the peer's request is untouched */
    CHECK(X.send(c, "ok", 2, 0) == 2);
    CHECK(WaitForSingleObject(e2, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(i2.Status, CS_SUCCESS);
    CHECK(i2.Information == 2);
    CloseHandle(e1); CloseHandle(e2); cs_close(c); cs_close(s);
}
TEST(csrcomp_cancel_cancels_every_pending_request) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q1, q2; rq_init(&q1); rq_init(&q2);
    HANDLE e1 = new_event(), e2 = new_event();
    IO_STATUS_BLOCK i1, i2; memset(&i1, 0xAB, sizeof i1); memset(&i2, 0xAB, sizeof i2);
    CHECK_ST(rq_submit(c, &q1, e1, NULL, NULL, &i1), CS_PENDING);
    CHECK_ST(rq_submit(c, &q2, e2, NULL, NULL, &i2), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    CHECK(WaitForSingleObject(e1, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(e2, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(i1.Status, CS_CANCELLED);
    CHECK_ST(i2.Status, CS_CANCELLED);
    cs_close(c); cs_close(s);
}
TEST(csrcomp_cancel_ex_on_one_receive_cancels_every_queued_receive) {
    CS_BEGIN();
    if (!U(CancelIoEx)) { t_skip("CancelIoEx missing"); return; }
    SOCKET c, s; cs_pair(&c, &s);
    RQ q1, q2; rq_init(&q1); rq_init(&q2);
    HANDLE e1 = new_event(), e2 = new_event();
    IO_STATUS_BLOCK i1, i2; memset(&i1, 0xAB, sizeof i1); memset(&i2, 0xAB, sizeof i2);
    CHECK_ST(rq_submit(c, &q1, e1, NULL, NULL, &i1), CS_PENDING);
    CHECK_ST(rq_submit(c, &q2, e2, NULL, NULL, &i2), CS_PENDING);
    CHECK(U(CancelIoEx)((HANDLE)c, (LPOVERLAPPED)&i2));
    /* the receives of one stream endpoint are cancelled together, whichever one was named */
    CHECK(WaitForSingleObject(e2, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(e1, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(i2.Status, CS_CANCELLED);
    CHECK_ST(i1.Status, CS_CANCELLED);
    CHECK(X.send(s, "z", 1, 0) == 1);                      /* the data now stays queued for a later receive */
    char b[4] = {0};
    CHECK(cs_readable(c, CS_WAIT) && X.recv(c, b, sizeof b, 0) == 1 && b[0] == 'z');
    CloseHandle(e1); CloseHandle(e2); cs_close(c); cs_close(s);
}
TEST(csrcomp_cancel_ex_unknown_request_fails_not_found) {
    CS_BEGIN();
    if (!U(CancelIoEx)) { t_skip("CancelIoEx missing"); return; }
    SOCKET c, s; cs_pair(&c, &s);
    OVERLAPPED ov; memset(&ov, 0, sizeof ov);
    SetLastError(0);
    CHECK(!U(CancelIoEx)((HANDLE)c, &ov));
    EXPECT_ERR(ERROR_NOT_FOUND);
    cs_close(c); cs_close(s);
}
TEST(csrcomp_close_completes_all_pending_requests_aborted) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q1, q2; rq_init(&q1); rq_init(&q2);
    HANDLE e1 = new_event(), e2 = new_event();
    IO_STATUS_BLOCK i1, i2; memset(&i1, 0xAB, sizeof i1); memset(&i2, 0xAB, sizeof i2);
    CHECK_ST(rq_submit(c, &q1, e1, NULL, NULL, &i1), CS_PENDING);
    CHECK_ST(rq_submit(c, &q2, e2, NULL, NULL, &i2), CS_PENDING);
    cs_close(c);
    CHECK(WaitForSingleObject(e1, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(e2, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(i1.Status, CS_CONNECTION_ABORTED);
    CHECK_ST(i2.Status, CS_CONNECTION_ABORTED);
    CHECK(i1.Information == 0 && i2.Information == 0);
    CloseHandle(e1); CloseHandle(e2); cs_close(s);
}
TEST(csrcomp_close_posts_aborted_packets_to_port) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE port = U(CreateIoCompletionPort)(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(U(CreateIoCompletionPort)((HANDLE)c, port, (ULONG_PTR)9, 0) == port);
    RQ q; rq_init(&q);
    PKT p; memset(&p, 0xAB, sizeof p);
    CHECK_ST(rq_submit(c, &q, NULL, NULL, &p.io, &p.io), CS_PENDING);
    cs_close(c);
    DWORD n = 1; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    BOOL ok = U(GetQueuedCompletionStatus)(port, &n, &key, &ov, CS_WAIT);
    CHECK(!ok);
    CHECK(ov == (LPOVERLAPPED)&p.io);
    CHECK_ST(p.io.Status, CS_CONNECTION_ABORTED);
    CloseHandle(port); cs_close(s);
}
TEST(csrcomp_peer_close_completes_receive_with_zero) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    RQ q; rq_init(&q);
    HANDLE ev = new_event();
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(rq_submit(c, &q, ev, NULL, NULL, &io), CS_PENDING);
    cs_close(s);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 0);
    CloseHandle(ev); cs_close(c);
}
