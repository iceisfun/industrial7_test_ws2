/* Asynchronous AFD requests and their lifetime rules.
 *
 *  - a request submitted from a thread that then exits (or is terminated) is cancelled with STATUS_CANCELLED,
 *    unless the handle is attached to a completion port and the request has a completion context but no event;
 *  - a poll request on a handle attached to a completion port may not carry an APC routine;
 *  - closing the last handle cancels pending requests; a duplicate of the handle (here or in another process)
 *    keeps them alive, with one exception for requests that were issued here and signal only the port;
 *  - NtReadFile / NtWriteFile on a socket handle: offsets are mandatory on overlapped handles, ignored when valid,
 *    and a synchronous handle blocks in NtReadFile even when the socket is in nonblocking mode.
 */
#include "afdx.h"

static volatile LONG g_apc_hits;
static void NTAPI apc_proc(PVOID ctx, PIO_STATUS_BLOCK io, ULONG reserved) { InterlockedIncrement(&g_apc_hits); }

typedef struct {
    HANDLE handle, event; AX_APC apc; PVOID ctx; IO_STATUS_BLOCK *io; ULONG code;
    PVOID in; ULONG insz; PVOID out; ULONG outsz;
    LONG ret; HANDLE done; BOOL kill;
} TJOB;
static DWORD WINAPI job_thread(void *arg) {
    TJOB *j = arg;
    j->ret = X.ioctl(j->handle, j->event, j->apc, j->ctx, j->io, j->code, j->in, j->insz, j->out, j->outsz);
    SetEvent(j->done);
    if (j->kill) Sleep(3000);                         /* parked here until the owner terminates the thread */
    return 0;
}
/* Runs one ioctl on a short-lived thread; with kill the thread is terminated instead of exiting normally. */
static LONG ioctl_on_thread(BOOL kill, HANDLE h, HANDLE ev, AX_APC apc, PVOID ctx, IO_STATUS_BLOCK *io,
                            ULONG code, PVOID in, ULONG insz, PVOID out, ULONG outsz) {
    TJOB j = { h, ev, apc, ctx, io, code, in, insz, out, outsz, 0, CreateEventW(NULL, FALSE, FALSE, NULL), kill };
    HANDLE th = CreateThread(NULL, 0, job_thread, &j, 0, NULL);
    CHECK(th != NULL);
    CHECK(WaitForSingleObject(j.done, AX_WAIT) == WAIT_OBJECT_0);
    if (kill) TerminateThread(th, (DWORD)-1);
    CHECK(WaitForSingleObject(th, AX_WAIT) == WAIT_OBJECT_0);
    CloseHandle(th); CloseHandle(j.done);
    SleepEx(0, TRUE);                                 /* let any queued user APC run */
    return j.ret;
}

static const struct { BOOL kill; BOOL event; AX_APC apc; PVOID ctx; } thr_cases[] = {
    {0,1,NULL,NULL}, {1,1,NULL,NULL}, {0,0,NULL,NULL}, {1,0,NULL,NULL},
    {0,1,apc_proc,NULL}, {1,1,apc_proc,NULL}, {0,0,apc_proc,NULL}, {1,0,apc_proc,NULL},
    {0,1,NULL,(PVOID)0xdeadbeef}, {1,1,NULL,(PVOID)0xdeadbeef}, {0,0,NULL,(PVOID)0xdeadbeef}, {1,0,NULL,(PVOID)0xdeadbeef},
    {0,1,apc_proc,(PVOID)0xdeadbeef}, {1,1,apc_proc,(PVOID)0xdeadbeef}, {0,0,apc_proc,(PVOID)0xdeadbeef}, {1,0,apc_proc,(PVOID)0xdeadbeef},
};
#define NCASES ((int)(sizeof thr_cases / sizeof thr_cases[0]))

/* Poll request over a single entry with a long timeout (cancelled long before it elapses). */
static void make_poll(AX_POLL *p, SOCKET s) {
    memset(p, 0, sizeof *p);
    p->count = 1; p->timeout = -10LL * 1000 * 1000 * 5;
    p->sockets[0].socket = s; p->sockets[0].flags = ~0u; p->sockets[0].status = 0xdeadbeef;
}

TEST(afdasync_thread_exit_cancels_without_port) {
    AFDX_BEGIN();
    SOCKET l; AX_POLL in, out; IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    afdx_listener(&l, NULL);
    make_poll(&in, l);
    g_apc_hits = 0;
    for (int i = 0; i < NCASES; i++) {
        FILL_IOSB(io, 0xcc); ResetEvent(ev);
        LONG st = ioctl_on_thread(thr_cases[i].kill, (HANDLE)l, thr_cases[i].event ? ev : NULL, thr_cases[i].apc,
                                  thr_cases[i].ctx, &io, AX_IOCTL_POLL, &in, sizeof in, &out, sizeof out);
        CHECKF((ULONG)st == AX_STATUS_PENDING, "case %d status 0x%08lx", i, (unsigned long)st);
        CHECKF((ULONG)io.Status == AX_STATUS_CANCELLED, "case %d iosb 0x%08lx", i, (unsigned long)io.Status);
        if (thr_cases[i].event) CHECKF(WaitForSingleObject(ev, AX_WAIT) == WAIT_OBJECT_0, "case %d event", i);
    }
    SleepEx(0, TRUE);
    CHECK(g_apc_hits == 0);                           /* the owning thread is gone: its APC never runs */
    afdx_close(l); CloseHandle(ev);
}

TEST(afdasync_thread_exit_with_port) {
    AFDX_BEGIN();
    SOCKET l; AX_POLL in, out; IO_STATUS_BLOCK io; LARGE_INTEGER zero = {{0}}; ULONG_PTR key, val;
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL), port;
    afdx_listener(&l, NULL);
    make_poll(&in, l);
    port = U(CreateIoCompletionPort)((HANDLE)l, NULL, 0, 0);
    CHECK(port != NULL);
    for (int i = 0; i < NCASES; i++) {
        FILL_IOSB(io, 0xcc); ResetEvent(ev);
        LONG st = ioctl_on_thread(thr_cases[i].kill, (HANDLE)l, thr_cases[i].event ? ev : NULL, thr_cases[i].apc,
                                  thr_cases[i].ctx, &io, AX_IOCTL_POLL, &in, sizeof in, &out, sizeof out);
        if (thr_cases[i].apc) {                       /* an APC cannot be combined with a completion port */
            CHECKF((ULONG)st == AX_STATUS_INVALID_PARAMETER, "case %d status 0x%08lx", i, (unsigned long)st);
            continue;
        }
        CHECKF((ULONG)st == AX_STATUS_PENDING, "case %d status 0x%08lx", i, (unsigned long)st);
        if (!thr_cases[i].ctx || thr_cases[i].event) {
            CHECKF((ULONG)io.Status == AX_STATUS_CANCELLED, "case %d iosb 0x%08lx", i, (unsigned long)io.Status);
            FILL_IOSB(io, 0xcc); key = 0xcc; val = 0;
            LONG rc = X.remove_completion(port, &key, &val, &io, &zero);
            if (thr_cases[i].ctx) {                   /* a completion context makes the cancel visible on the port */
                CHECKF(rc == 0, "case %d remove 0x%08lx", i, (unsigned long)rc);
                CHECKF(key == 0 && val == 0xdeadbeef, "case %d key/value", i);
                CHECKF((ULONG)io.Status == AX_STATUS_CANCELLED, "case %d port iosb", i);
            } else CHECKF((ULONG)rc == AX_STATUS_TIMEOUT, "case %d remove 0x%08lx", i, (unsigned long)rc);
            continue;
        }
        /* context but no event: the thread's end does not cancel the request */
        CHECKF(io.Status == (LONG)0xcccccccc, "case %d iosb 0x%08lx", i, (unsigned long)io.Status);
        FILL_IOSB(io, 0xcc); key = 0xcc; val = 0;
        CHECK((ULONG)X.remove_completion(port, &key, &val, &io, &zero) == AX_STATUS_TIMEOUT);
        U(CancelIoEx)((HANDLE)l, NULL);
        CHECK(X.remove_completion(port, &key, &val, &io, &zero) == 0);
        CHECK(key == 0 && val == 0xdeadbeef);
        CHECK((ULONG)io.Status == AX_STATUS_CANCELLED);
    }
    CloseHandle(port); CloseHandle(ev); afdx_close(l);
}

CHILD(afdsleeper) { Sleep(60000); return 0; }         /* holds duplicated handles; the parent terminates it */

/* One iteration of the close-with-duplicate matrix: other = duplicate lives in a second process. */
static void close_matrix_case(int other, int event, PVOID ctx, HANDLE child) {
    SOCKET l; AX_POLL in, out; IO_STATUS_BLOCK io; LARGE_INTEGER zero = {{0}}; ULONG_PTR key, val;
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL), port, dup = NULL;
    afdx_listener(&l, NULL);
    port = U(CreateIoCompletionPort)((HANDLE)l, NULL, 0, 0);
    CHECK(port != NULL);
    make_poll(&in, l);
    FILL_IOSB(io, 0xcc);
    CHECK((ULONG)X.ioctl((HANDLE)l, event ? ev : NULL, NULL, ctx, &io, AX_IOCTL_POLL, &in, sizeof in, &out, sizeof out) == AX_STATUS_PENDING);
    CHECK(io.Status == (LONG)0xcccccccc);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)l, other ? child : GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    X.closesocket(l);
    /* the request survives in every case except an other-process duplicate with a bare completion context;
     * there the cancel is visible only on the port, and the status block is not written before it is removed */
    int cancelled = other && ctx && !event;
    CHECK(io.Status == (LONG)0xcccccccc);
    FILL_IOSB(io, 0xcc); key = 0xcc; val = 0;
    LONG rc = X.remove_completion(port, &key, &val, &io, &zero);
    if (cancelled) {
        CHECK(rc == 0);
        CHECK(key == 0 && val == 0xdeadbeef);
        CHECK((ULONG)io.Status == AX_STATUS_CANCELLED);
    } else CHECK((ULONG)rc == AX_STATUS_TIMEOUT);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);
    if (other) {                                      /* take the duplicate back and close it here */
        HANDLE back = NULL;
        CHECK(DuplicateHandle(child, dup, GetCurrentProcess(), &back, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE));
        if (back) CloseHandle(back);
    } else CloseHandle(dup);
    CloseHandle(port); CloseHandle(ev);
}

static void close_matrix(int other) {
    AFDX_BEGIN();
    PROCESS_INFORMATION pi;
    HANDLE child = NULL;
    if (other) {
        child = t_spawn_child("afdsleeper", "", 0, NULL, NULL, NULL, FALSE, NULL, &pi);
        if (!child) { t_skip("cannot start helper process"); return; }
        CloseHandle(pi.hThread);
    }
    /* event / context combinations without an APC (an APC is refused on a port-attached handle) */
    close_matrix_case(other, 1, NULL, child);
    close_matrix_case(other, 0, NULL, child);
    close_matrix_case(other, 1, (PVOID)0xdeadbeef, child);
    close_matrix_case(other, 0, (PVOID)0xdeadbeef, child);
    if (child) { TerminateProcess(child, 0); WaitForSingleObject(child, 5000); CloseHandle(child); }
}
TEST(afdasync_close_with_duplicate_in_same_process) { close_matrix(0); }
TEST(afdasync_close_with_duplicate_in_other_process) { close_matrix(1); }

TEST(afdasync_apc_on_port_handle_refused_at_submission) {
    AFDX_BEGIN();
    SOCKET l; AX_POLL in, out; IO_STATUS_BLOCK io; HANDLE port;
    afdx_listener(&l, NULL);
    port = U(CreateIoCompletionPort)((HANDLE)l, NULL, 0, 0);
    CHECK(port != NULL);
    make_poll(&in, l);
    CHECK((ULONG)X.ioctl((HANDLE)l, NULL, apc_proc, NULL, &io, AX_IOCTL_POLL, &in, sizeof in, &out, sizeof out) == AX_STATUS_INVALID_PARAMETER);
    CHECK((ULONG)X.ioctl((HANDLE)l, NULL, apc_proc, (PVOID)0xdeadbeef, &io, AX_IOCTL_POLL, &in, sizeof in, &out, sizeof out) == AX_STATUS_INVALID_PARAMETER);
    CloseHandle(port); afdx_close(l);
}

/* ---- NtReadFile / NtWriteFile ---- */
static LONG rd(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, void *buf, ULONG n, LARGE_INTEGER *off) {
    return X.read((HANDLE)s, ev, NULL, NULL, io, buf, n, off, NULL);
}
static LONG wr(SOCKET s, IO_STATUS_BLOCK *io, const char *p, ULONG n, LARGE_INTEGER *off) {
    return X.write((HANDLE)s, NULL, NULL, NULL, io, (PVOID)p, n, off, NULL);
}

TEST(afdfile_sync_handle_write_then_read) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; char buf[5];
    afdx_pair_sync(&c, &s);                           /* synchronous handles on both ends */
    afdx_set_blocking(s, 0);
    FILL_IOSB(io, 0xcc);
    CHECK(wr(c, &io, "data", 4, NULL) == 0);
    CHECK_IOSB(io, 0, 4);
    memset(buf, 0xcc, sizeof buf); FILL_IOSB(io, 0xcc);
    { LONG st = rd(s, NULL, &io, buf, sizeof buf, NULL);
      CHECKF(st == 0, "status 0x%08lx iosb 0x%08lx", (unsigned long)st, (unsigned long)io.Status); }
    CHECK_IOSB(io, 0, 4);
    CHECK(!memcmp(buf, "data", 4));
    afdx_close(c); afdx_close(s);
}

TEST(afdfile_partial_read_keeps_read_event_armed) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; char buf[5]; WSANETWORKEVENTS ne;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&c, &s, 0);
    CHECK(X.send(s, "data", 4, 0) == 4);
    CHECK(X.WSAEventSelect(c, ev, FD_READ) == 0);
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == FD_READ);
    memset(buf, 0xcc, sizeof buf);
    CHECK(rd(c, NULL, &io, buf, 1, NULL) == 0);
    CHECK(io.Information == 1 && buf[0] == 'd');
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == FD_READ);              /* three bytes are still queued, so the event is raised again */
    memset(buf, 0xcc, sizeof buf);
    CHECK(rd(c, NULL, &io, buf, sizeof buf, NULL) == 0);
    CHECK(io.Information == 3 && !memcmp(buf, "ata", 3));
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

typedef struct { SOCKET s; LONG st; ULONG_PTR info; char buf[5]; } RDJOB;
static DWORD WINAPI blocking_read(void *arg) {
    RDJOB *j = arg; IO_STATUS_BLOCK io;
    memset(j->buf, 0xcc, sizeof j->buf); FILL_IOSB(io, 0xcc);
    j->st = rd(j->s, NULL, &io, j->buf, sizeof j->buf, NULL);
    j->info = io.Information;
    return 0;
}
TEST(afdfile_sync_read_blocks_on_nonblocking_socket) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; RDJOB j;
    afdx_pair_sync(&c, &s);
    afdx_set_blocking(s, 0);                          /* nonblocking mode does not apply to NtReadFile */
    j.s = s; j.st = -1;
    HANDLE th = CreateThread(NULL, 0, blocking_read, &j, 0, NULL);
    CHECKF(WaitForSingleObject(th, 150) == WAIT_TIMEOUT, "read st 0x%08lx", (unsigned long)j.st);
    CHECK(wr(c, &io, "data", 4, NULL) == 0);
    CHECK(WaitForSingleObject(th, AX_WAIT) == WAIT_OBJECT_0);
    CHECK(j.st == 0 && j.info == 4 && !memcmp(j.buf, "data", 4));
    CloseHandle(th);
    afdx_close(c); afdx_close(s);
}

TEST(afdfile_overlapped_read_needs_explicit_offset) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; char buf[5]; LARGE_INTEGER off;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    LONG st = rd(s, ev, &io, buf, sizeof buf, NULL);
    CHECK_ST(st, AX_STATUS_INVALID_PARAMETER);        /* no offset on an asynchronous handle */
    if ((ULONG)st == AX_STATUS_PENDING) { U(CancelIo)((HANDLE)s); WaitForSingleObject(ev, 1000); }
    off.QuadPart = -1;                                /* "current position" needs a synchronous handle */
    st = rd(s, ev, &io, buf, sizeof buf, &off);
    CHECK_ST(st, AX_STATUS_INVALID_PARAMETER);
    if ((ULONG)st == AX_STATUS_PENDING) { U(CancelIo)((HANDLE)s); WaitForSingleObject(ev, 1000); }
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdfile_overlapped_offsets_are_ignored_but_validated) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io, io2; char buf[5]; LARGE_INTEGER off;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    memset(buf, 0xcc, sizeof buf); FILL_IOSB(io, 0xcc);
    off.QuadPart = 1;
    CHECK_ST(rd(s, ev, &io, buf, sizeof buf, &off), AX_STATUS_PENDING);
    /* writes obey the same offset rules as reads */
    CHECK_ST(wr(c, &io2, "data", 4, NULL), AX_STATUS_INVALID_PARAMETER);
    off.QuadPart = -3;
    CHECK_ST(wr(c, &io2, "data", 4, &off), AX_STATUS_INVALID_PARAMETER);
    FILL_IOSB(io2, 0xcc);
    off.QuadPart = 2;
    CHECK_ST(wr(c, &io2, "data", 4, &off), AX_STATUS_SUCCESS);
    CHECK_IOSB(io2, 0, 4);
    CHECK(WaitForSingleObject(ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(io, 0, 4);
    CHECK(!memcmp(buf, "data", 4));                   /* the offset did not position anything */
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}
