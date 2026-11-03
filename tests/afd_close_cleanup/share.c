/* One endpoint, several handles: duplication at the NT level (NtDuplicateObject), closing through a duplicate,
 * and last-close semantics, i.e. that the connection only ends, resets or cancels its requests when the final
 * handle to the endpoint goes away, including when that final handle belongs to another process that exits.
 */
#include "acc.h"

static LONG nt_dup(HANDLE src, HANDLE *out, ACCESS_MASK acc, ULONG attrs, ULONG opts)
{
    HANDLE n = NULL; LONG st;
    st = UN(NtDuplicateObject)(GetCurrentProcess(), src, GetCurrentProcess(), &n, acc, attrs, opts);
    *out = n;
    return st;
}
#define DUP_CLOSE_SOURCE 1
#define DUP_SAME_ACCESS  2
#define DUP_SAME_ATTRS   4

/* ---- NtDuplicateObject on an endpoint ----------------------------------------------------------------------- */
TEST(cc_dup_same_access_creates_distinct_handle)
{
    SOCKET s; HANDLE d; IO_STATUS_BLOCK io; ULONG a1 = 0, a2 = 0;
    UP();
    s = acc_sock(SOCK_STREAM);
    EXPECT_ST(nt_dup((HANDLE)s, &d, 0, 0, DUP_SAME_ACCESS), ST_SUCCESS);
    CHECK(d != NULL && d != (HANDLE)s);
    EXPECT_ST(UN(NtQueryInformationFile)((HANDLE)s, &io, &a1, 4, FI_Access), ST_SUCCESS);
    EXPECT_ST(UN(NtQueryInformationFile)(d, &io, &a2, 4, FI_Access), ST_SUCCESS);
    EXPECT_EQ(a1, a2);
    UN(NtClose)(d); CLOSES(s);
}

/* Within one process the source slot is released first, so the duplicate lands in the same slot: same value, and
 * the endpoint (never closed, only re-handled) still works. */
TEST(cc_dup_close_source_same_process_reuses_slot)
{
    SOCKET s; HANDLE d; ULONG x; int type = 0, len = sizeof type;
    UP();
    s = acc_sock(SOCK_STREAM);
    EXPECT_ST(nt_dup((HANDLE)s, &d, 0, 0, DUP_SAME_ACCESS | DUP_CLOSE_SOURCE), ST_SUCCESS);
    if (d != (HANDLE)s) t_note("duplicate handle value differs from source slot");
    CHECK(GetHandleInformation(d, &x));
    CHECK(U(getsockopt)((SOCKET)d, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0 && type == SOCK_STREAM);
    EXPECT_ST(UN(NtClose)(d), ST_SUCCESS);
    EXPECT_ST(UN(NtClose)(d), ST_INVALID_HANDLE);
}

/* Closing the source into a second process leaves a valid duplicate there; here the source is simply gone. */
TEST(cc_dup_close_source_into_other_process_removes_source)
{
    SOCKET s; HANDLE d = NULL, self = GetCurrentProcess(), me = NULL; ULONG x; LONG st;
    UP();
    s = acc_sock(SOCK_STREAM);
    CHECK(DuplicateHandle(self, self, self, &me, PROCESS_DUP_HANDLE, FALSE, 0));
    st = UN(NtDuplicateObject)(self, (HANDLE)s, me, &d, 0, 0, DUP_SAME_ACCESS | DUP_CLOSE_SOURCE);
    EXPECT_ST(st, ST_SUCCESS);
    CHECK(d != NULL);
    SetLastError(0);
    if (d != (HANDLE)s) { CHECK(!GetHandleInformation((HANDLE)s, &x)); EXPECT_ERR(ERROR_INVALID_HANDLE); }
    UN(NtClose)(d); CloseHandle(me);
}

/* A duplicate made with close-source and no target handle is a plain close of the source handle. */
TEST(cc_dup_close_source_without_target_is_a_close)
{
    SOCKET s; ULONG x;
    UP();
    s = acc_sock(SOCK_STREAM);
    EXPECT_ST(UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, NULL, NULL, 0, 0, DUP_CLOSE_SOURCE), ST_SUCCESS);
    CHECK(!GetHandleInformation((HANDLE)s, &x));
    EXPECT_ST(UN(NtClose)((HANDLE)s), ST_INVALID_HANDLE);
}

/* ...and as the last handle it cancels what the endpoint has in flight, like any other close. */
TEST(cc_dup_close_source_without_target_cancels_pending)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_RECV_UDP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    EXPECT_ST(UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)p.target, NULL, NULL, 0, 0, DUP_CLOSE_SOURCE), ST_SUCCESS);
    p.target = INVALID_SOCKET;
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(acc_pend_status(&p), ST_CANCELLED);
    acc_pend_done(&p);
}

/* Without a target handle and without close-source nothing happens. */
TEST(cc_dup_no_target_no_close_is_invalid_parameter)
{
    SOCKET s; ULONG x;
    UP();
    s = acc_sock(SOCK_STREAM);
    /* a target process with no target handle pointer is only meaningful with close-source */
    EXPECT_ST(UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, NULL, NULL, 0, 0, DUP_SAME_ACCESS), ST_INVALID_PARAMETER);
    CHECK(GetHandleInformation((HANDLE)s, &x));
    CLOSES(s);
}

TEST(cc_dup_invalid_source_handle)
{
    HANDLE d = (HANDLE)1;
    UP();
    EXPECT_ST(nt_dup((HANDLE)(ULONG_PTR)0x7ffc, &d, 0, 0, DUP_SAME_ACCESS), ST_INVALID_HANDLE);
    CHECK(d == NULL);
}

TEST(cc_dup_null_source_handle)
{
    HANDLE d = NULL;
    UP();
    EXPECT_ST(nt_dup(NULL, &d, 0, 0, DUP_SAME_ACCESS), ST_INVALID_HANDLE);
}

/* Closing the source of a failed duplicate leaves it alone. */
TEST(cc_dup_closed_source_cannot_be_duplicated)
{
    SOCKET s; HANDLE d = NULL;
    UP();
    s = acc_sock(SOCK_STREAM);
    CLOSES(s);
    EXPECT_ST(nt_dup((HANDLE)s, &d, 0, 0, DUP_SAME_ACCESS), ST_INVALID_HANDLE);
}

/* The process handle needs PROCESS_DUP_HANDLE: a query-only handle to ourselves is refused. */
TEST(cc_dup_process_handle_without_dup_right_refused)
{
    SOCKET s; HANDLE p, d = NULL; LONG st;
    UP();
    s = acc_sock(SOCK_STREAM);
    p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    REQUIRE(p);
    st = UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, p, &d, 0, 0, DUP_SAME_ACCESS);
    EXPECT_ST(st, ST_ACCESS_DENIED);
    st = UN(NtDuplicateObject)(p, (HANDLE)s, GetCurrentProcess(), &d, 0, 0, DUP_SAME_ACCESS);
    EXPECT_ST(st, ST_ACCESS_DENIED);
    CloseHandle(p); CLOSES(s);
}

/* Attributes: the duplicate's inheritance follows the request, or the source with SAME_ATTRIBUTES. */
TEST(cc_dup_attributes_inherit_flag)
{
    SOCKET s; HANDLE d; DWORD f = 0;
    UP();
    s = acc_sock(SOCK_STREAM);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    EXPECT_ST(nt_dup((HANDLE)s, &d, 0, 0, DUP_SAME_ACCESS), ST_SUCCESS);
    GetHandleInformation(d, &f); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, 0);
    UN(NtClose)(d);
    EXPECT_ST(nt_dup((HANDLE)s, &d, 0, 2 /* OBJ_INHERIT */, DUP_SAME_ACCESS), ST_SUCCESS);
    GetHandleInformation(d, &f); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    UN(NtClose)(d);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    EXPECT_ST(nt_dup((HANDLE)s, &d, 0, 0, DUP_SAME_ACCESS | DUP_SAME_ATTRS), ST_SUCCESS);
    GetHandleInformation(d, &f); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    UN(NtClose)(d); CLOSES(s);
}

/* ---- last-close semantics within one process ------------------------------------------------------------- */
static int quiet(SOCKET s, int ms) { return acc_wait_readable(s, ms) == 0; }

TEST(cc_last_close_peer_sees_end_only_after_final_handle)
{
    HANDLE d; char b[4]; int e = 0;
    UP();
    PAIR(c, s);
    EXPECT_ST(nt_dup((HANDLE)c, &d, 0, 0, DUP_SAME_ACCESS), ST_SUCCESS);
    CLOSES(c);
    CHECK(quiet(s, 300));                          /* the duplicate keeps the connection up */
    UN(NtClose)(d);
    EXPECT_EQ(acc_recv(s, b, 4, &e), 0);
    CLOSES(s);
}

/* SO_LINGER {1,0} set before duplicating: the first closesocket, though not the final close, already resets the
 * connection, because the abortive disconnect is issued by closesocket itself. */
TEST(cc_last_close_linger_zero_closesocket_resets_despite_duplicate)
{
    HANDLE d; char b[4]; int e = 0, r;
    UP();
    PAIR(c, s);
    acc_linger(c, 1, 0);
    EXPECT_ST(nt_dup((HANDLE)c, &d, 0, 0, DUP_SAME_ACCESS), ST_SUCCESS);
    CLOSES(c);
    r = acc_recv(s, b, 4, &e);               /* the abortive disconnect is done by closesocket itself, at once */
    CHECK(r < 0); EXPECT_EQ(e, WSAECONNRESET);
    UN(NtClose)(d);
    CLOSES(s);
}

TEST(cc_last_close_three_handles_any_order)
{
    HANDLE d1, d2; char b[4]; int e = 0;
    UP();
    PAIR(c, s);
    nt_dup((HANDLE)c, &d1, 0, 0, DUP_SAME_ACCESS);
    nt_dup((HANDLE)c, &d2, 0, 0, DUP_SAME_ACCESS);
    UN(NtClose)(d1);
    CHECK(quiet(s, 150));
    CLOSES(c);
    CHECK(quiet(s, 150));
    CHECK(U(send)((SOCKET)d2, "k", 1, 0) == 1);   /* still connected, through the last handle */
    EXPECT_EQ(acc_recv(s, b, 4, &e), 1);
    UN(NtClose)(d2);
    EXPECT_EQ(acc_recv(s, b, 4, &e), 0);
    CLOSES(s);
}

/* The duplicate is a full alias: data written through the original is read through the peer, and the
 * duplicate can read what the peer sends. */
TEST(cc_last_close_duplicate_is_full_alias)
{
    HANDLE d; char b[4]; int e = 0;
    UP();
    PAIR(c, s);
    nt_dup((HANDLE)c, &d, 0, 0, DUP_SAME_ACCESS);
    CHECK(U(send)(s, "ab", 2, 0) == 2);
    acc_timeo((SOCKET)d, ACC_WAIT);
    EXPECT_EQ(acc_recv((SOCKET)d, b, 4, &e), 2);
    CHECK(U(send)((SOCKET)d, "cd", 2, 0) == 2);
    acc_timeo(s, ACC_WAIT);
    EXPECT_EQ(acc_recv(s, b, 4, &e), 2);
    UN(NtClose)(d); CLOSES(c); CLOSES(s);
}

/* Cleanup runs once for the endpoint, not per handle: a request queued through the original is still in flight
 * after the original is closed, and finishes when the duplicate (the last handle) goes. */
TEST(cc_last_close_pending_request_survives_nonfinal_close)
{
    pend_t p; HANDLE d;
    UP();
    if (!acc_pend_start(&p, OP_RECV_TCP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    EXPECT_ST(nt_dup((HANDLE)p.target, &d, 0, 0, DUP_SAME_ACCESS), ST_SUCCESS);
    UN(NtClose)((HANDLE)p.target); p.target = INVALID_SOCKET;
    EXPECT_EQ(WaitForSingleObject(p.ev, 200), WAIT_TIMEOUT);
    EXPECT_ST(acc_pend_status(&p), ST_PENDING);
    UN(NtClose)(d);
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(acc_pend_status(&p), ST_CONN_ABORTED);
    acc_pend_done(&p);
}

/* Explicit cancel through the duplicate cancels requests issued through the original (same file object). */
TEST(cc_last_close_cancelioex_through_duplicate_reaches_request)
{
    pend_t p; HANDLE d;
    UP();
    if (!acc_pend_start(&p, OP_RECV_UDP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    nt_dup((HANDLE)p.target, &d, 0, 0, DUP_SAME_ACCESS);
    CHECK(CancelIoEx(d, &p.ov));
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(acc_pend_status(&p), ST_CANCELLED);
    UN(NtClose)(d); acc_pend_done(&p);
}

/* A duplicate made after a request was queued does not see the request as its own issue: NtCancelIoFile
 * on the duplicate (same thread) still cancels it, because cancel is by file object and thread. */
TEST(cc_last_close_ntcancelio_through_duplicate)
{
    pend_t p; HANDLE d; IO_STATUS_BLOCK io;
    UP();
    if (!acc_pend_start(&p, OP_RECV_UDP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    nt_dup((HANDLE)p.target, &d, 0, 0, DUP_SAME_ACCESS);
    EXPECT_ST(UN(NtCancelIoFile)(d, &io), ST_SUCCESS);
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(acc_pend_status(&p), ST_CANCELLED);
    UN(NtClose)(d); acc_pend_done(&p);
}

/* ---- another process holds the last handle ------------------------------------------------------------------- */
/* A process that exits (or is killed) while it still holds the endpoint aborts the connection: the peer sees a reset,
 * unlike an explicit CloseHandle by that process. Child: reads a handle value line then one command byte from stdin.
 *   'C' closes the handle with CloseHandle and exits    'X' exits holding it    'R' sets linger 0 and exits holding it
 *   'W' waits for another byte first (used to keep it alive while the parent acts) */
CHILD(acc_holder)
{
    char line[40] = {0}, cmd = 0; DWORD n; int i = 0; HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    ULONG_PTR hv;
    while (i < 38 && ReadFile(in, &line[i], 1, &n, NULL) && n == 1 && line[i] != '\n') i++;
    line[i] = 0;
    hv = (ULONG_PTR)_strtoui64(line, NULL, 10);
    if (!ReadFile(in, &cmd, 1, &n, NULL) || n != 1) return 3;
    if (cmd == 'C') return CloseHandle((HANDLE)hv) ? 0 : 4;
    if (cmd == 'R') {
        WSADATA d; struct linger lg = { 1, 0 };
        U(WSAStartup)(MAKEWORD(2, 2), &d);
        if (U(setsockopt)((SOCKET)hv, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg)) return 5;
        return 0;
    }
    return 0;      /* 'X' */
}

typedef struct { HANDLE proc, wr; PROCESS_INFORMATION pi; } holder_t;
static int holder_start(holder_t *h, SOCKET s)
{
    HANDLE rd, remote = NULL; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; char line[40]; DWORD n;
    CreatePipe(&rd, &h->wr, &sa, 0);
    SetHandleInformation(h->wr, HANDLE_FLAG_INHERIT, 0);
    h->proc = t_spawn_child("acc_holder", "", 0, rd, NULL, NULL, TRUE, NULL, &h->pi);
    CloseHandle(rd);
    if (!h->proc) return 0;
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)s, h->proc, &remote, 0, FALSE, DUPLICATE_SAME_ACCESS)) return 0;
    sprintf(line, "%llu\n", (unsigned long long)(ULONG_PTR)remote);
    WriteFile(h->wr, line, (DWORD)strlen(line), &n, NULL);
    return 1;
}
static DWORD holder_finish(holder_t *h, char cmd)
{
    DWORD n, code = 0xdead;
    if (cmd) WriteFile(h->wr, &cmd, 1, &n, NULL);
    if (WaitForSingleObject(h->proc, ACC_WAIT) != WAIT_OBJECT_0) TerminateProcess(h->proc, 99);
    GetExitCodeProcess(h->proc, &code);
    CloseHandle(h->wr); CloseHandle(h->proc); CloseHandle(h->pi.hThread);
    return code;
}

static void holder_case(char cmd, int parent_keeps, int expect_reset)
{
    holder_t h; char b[4]; int e = 0, r; DWORD code;
    UP();
    PAIR(c, s);
    SetHandleInformation((HANDLE)c, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    if (!holder_start(&h, c)) { t_skip("could not start child"); CLOSES(c); CLOSES(s); return; }
    if (!parent_keeps) CLOSES(c);
    CHECK(quiet(s, 300));                        /* child's handle alone keeps the connection up */
    code = holder_finish(&h, cmd);
    EXPECT_EQ(code, 0);
    if (parent_keeps) {
        CHECK(quiet(s, 300));                    /* child gone, parent still holds the endpoint */
        CLOSES(c);
    }
    r = acc_recv(s, b, 4, &e);
    if (expect_reset) { CHECK(r < 0); EXPECT_EQ(e, WSAECONNRESET); }
    else EXPECT_EQ(r, 0);
    CLOSES(s);
}
TEST(cc_proc_child_exit_holding_last_handle_aborts_stream)       { holder_case('X', 0, 1); }
TEST(cc_proc_child_closehandle_as_last_handle_ends_stream)     { holder_case('C', 0, 0); }
TEST(cc_proc_child_linger_zero_exit_resets_peer)               { holder_case('R', 0, 1); }
TEST(cc_proc_child_exit_while_parent_holds_keeps_stream)       { holder_case('X', 1, 0); }
TEST(cc_proc_child_close_while_parent_holds_keeps_stream)      { holder_case('C', 1, 0); }

/* A process killed outright releases its handles the same way. */
TEST(cc_proc_terminated_child_aborts_stream)
{
    holder_t h; char b[4]; int e = 0; DWORD n;
    UP();
    PAIR(c, s);
    SetHandleInformation((HANDLE)c, HANDLE_FLAG_INHERIT, 0);
    if (!holder_start(&h, c)) { t_skip("could not start child"); CLOSES(c); CLOSES(s); return; }
    CLOSES(c);
    CHECK(quiet(s, 300));
    TerminateProcess(h.proc, 42);
    WaitForSingleObject(h.proc, ACC_WAIT);
    { int r = acc_recv(s, b, 4, &e); CHECKF(r < 0, "r=%d", r); EXPECT_EQ(e, WSAECONNRESET); }
    CloseHandle(h.wr); CloseHandle(h.proc); CloseHandle(h.pi.hThread);
    CLOSES(s);
}

/* Unread data in the dying holder's endpoint turns its teardown into a reset for the peer. */
TEST(cc_proc_terminated_child_with_unread_data_resets_peer)
{
    holder_t h; char b[4]; int e = 0, r, i;
    UP();
    PAIR(c, s);
    SetHandleInformation((HANDLE)c, HANDLE_FLAG_INHERIT, 0);
    if (!holder_start(&h, c)) { t_skip("could not start child"); CLOSES(c); CLOSES(s); return; }
    CHECK(U(send)(s, "dead", 4, 0) == 4);
    for (i = 0; i < 100 && acc_avail(c) < 4; i++) Sleep(10);
    CLOSES(c);
    TerminateProcess(h.proc, 42);
    WaitForSingleObject(h.proc, ACC_WAIT);
    r = acc_recv(s, b, 4, &e);
    CHECK(r < 0); EXPECT_EQ(e, WSAECONNRESET);
    CloseHandle(h.wr); CloseHandle(h.proc); CloseHandle(h.pi.hThread);
    CLOSES(s);
}

/* The parent can pull the child's copy back with close-source; the child then no longer has the endpoint. */
TEST(cc_proc_pull_back_with_close_source_then_peer_sees_end)
{
    holder_t h; HANDLE back = NULL; char b[4]; int e = 0; DWORD n; ULONG_PTR remote;
    HANDLE rd, rem = NULL; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; char line[40];
    UP();
    PAIR(c, s);
    SetHandleInformation((HANDLE)c, HANDLE_FLAG_INHERIT, 0);
    CreatePipe(&rd, &h.wr, &sa, 0);
    SetHandleInformation(h.wr, HANDLE_FLAG_INHERIT, 0);
    h.proc = t_spawn_child("acc_holder", "", 0, rd, NULL, NULL, TRUE, NULL, &h.pi);
    CloseHandle(rd);
    REQUIRE(h.proc);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, h.proc, &rem, 0, FALSE, DUPLICATE_SAME_ACCESS));
    sprintf(line, "%llu\n", (unsigned long long)(ULONG_PTR)rem);
    WriteFile(h.wr, line, (DWORD)strlen(line), &n, NULL);
    CLOSES(c);
    CHECK(quiet(s, 200));
    CHECK(DuplicateHandle(h.proc, rem, GetCurrentProcess(), &back, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE));
    CHECK(quiet(s, 200));                        /* the parent now holds it */
    CloseHandle(back);
    EXPECT_EQ(acc_recv(s, b, 4, &e), 0);
    holder_finish(&h, 'X');
    CLOSES(s);
}
