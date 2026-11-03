/* Request validation and completion shape of IOCTL_AFD_POLL (0x12024), beyond the size table and the
 * zero/absolute timeout cases already covered elsewhere.
 * Measures: the exclusive flag as a one-byte boolean that demands an infinite timeout; the input/output
 * size protocol around the entry boundaries and the entry-count limits; the status returned for entries
 * that are not usable socket handles (wrong object type, non-AFD file, closed handle); poll requests issued
 * through very different carrier handles; output sizing (only the reported prefix is written);
 * synchronous carrier handles; and that the request is copied at submission. */
#include "ap.h"

static SOCKET listener1(void) { return ap_listener(NULL, 1); }

/* ---- exclusive flag ------------------------------------------------------ */

/* An exclusive poll only makes sense without a deadline: any timeout other than the infinite value
 * (high dword 0x7fffffff) is refused before anything is queued. */
TEST(apev_exclusive_relative_timeout_rejected)
{
    AP_BEGIN();
    SOCKET l = listener1(); ap_res r;
    ap_run((HANDLE)l, AP_REL_MS(1000), 1, 1, &l, (ULONG[]){ APE_ALL }, 1000, &r);
    CK_ST(r.ret, APS_INVALID_PARAM);
    ap_closeS(l);
}

TEST(apev_exclusive_absolute_timeout_rejected)
{
    AP_BEGIN();
    SOCKET l = listener1(); ap_res r; LARGE_INTEGER now;
    X.systime(&now);
    ap_run((HANDLE)l, now.QuadPart + 600000000LL, 1, 1, &l, (ULONG[]){ APE_ALL }, 1000, &r);
    CK_ST(r.ret, APS_INVALID_PARAM);
    ap_closeS(l);
}

TEST(apev_exclusive_zero_timeout_rejected)
{
    AP_BEGIN();
    SOCKET l = listener1(); ap_res r;
    ap_run((HANDLE)l, 0, 1, 1, &l, (ULONG[]){ APE_ALL }, 1000, &r);
    CK_ST(r.ret, APS_INVALID_PARAM);
    ap_closeS(l);
}

TEST(apev_exclusive_just_below_infinite_rejected)
{
    AP_BEGIN();
    SOCKET l = listener1(); ap_res r;
    ap_run((HANDLE)l, AP_INFINITE - 0x100000000LL, 1, 1, &l, (ULONG[]){ APE_ALL }, 1000, &r);
    CK_ST(r.ret, APS_INVALID_PARAM);
    ap_closeS(l);
}

/* Any nonzero value of the flag byte counts as exclusive. */
TEST(apev_exclusive_any_nonzero_byte_rejected_with_deadline)
{
    AP_BEGIN();
    static const UCHAR vals[] = { 1, 2, 0x7f, 0x80, 0xff };
    SOCKET l = listener1(); size_t i;
    for (i = 0; i < sizeof(vals); i++) {
        ap_res r;
        ap_run((HANDLE)l, AP_REL_MS(1000), vals[i], 1, &l, (ULONG[]){ APE_ALL }, 1000, &r);
        CHECKF((ULONG)r.ret == APS_INVALID_PARAM, "flag byte %#x: got %#lx", vals[i], (unsigned long)r.ret);
    }
    ap_closeS(l);
}

/* Only the first byte after the count is the flag; the three bytes behind it are ignored, so a request
 * whose flag word is 0x100 is an ordinary (non-exclusive) poll and may carry a deadline. */
TEST(apev_exclusive_flag_is_one_byte)
{
    AP_BEGIN();
    SOCKET l = listener1(); HANDLE ev = ap_event(); ap_req in, out; IO_STATUS_BLOCK io;
    ap_fill(&in, AP_REL_MS(60), 0, 1, &l, APE_ALL);
    in.pad[0] = 1; in.pad[1] = 0xff; in.pad[2] = 0x55;
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)l, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_TIMEOUT);
    CHECK(io.Information == 16);
    CloseHandle(ev); ap_closeS(l);
}

/* With the infinite timeout the exclusive request is accepted and stays queued until it is cancelled,
 * which completes it with STATUS_CANCELLED. */
TEST(apev_exclusive_infinite_pends_until_cancelled)
{
    AP_BEGIN();
    SOCKET l = listener1(); ap_res r;
    ap_run((HANDLE)l, AP_INFINITE, 1, 1, &l, (ULONG[]){ APE_ALL }, 300, &r);
    CK_ST(r.ret, APS_PENDING);
    CHECK(r.hung);                 /* nothing completed it by itself */
    CK_ST(r.ios, APS_CANCELLED);
    ap_closeS(l);
}

/* ---- size protocol --------------------------------------------------------- */

typedef struct { const char *what; ULONG count, inlen, outlen; ULONG want; } sz_row;
static const sz_row sz_rows[] = {
    { "header only",                    1,  16,   16,  APS_INVALID_PARAM },
    { "one byte short of a first entry", 1, 31,   31,  APS_INVALID_PARAM },
    { "exactly one entry",              1,  32,   32,  APS_SUCCESS },
    { "one entry plus 15 spare bytes",  1,  47,   47,  APS_SUCCESS },
    { "one entry, output twice as big", 1,  32,   64,  APS_SUCCESS },
    { "output one byte too small",      1,  32,   31,  APS_INVALID_PARAM },
    { "input shorter than header",      1,  15,   15,  APS_INVALID_PARAM },
    { "two entries, one byte short",    2,  47,   47,  APS_INVALID_PARAM },
    { "two entries exact",              2,  48,   48,  APS_SUCCESS },
    { "three entries, one byte short",  3,  63,   63,  APS_INVALID_PARAM },
    { "three entries exact",            3,  64,   64,  APS_SUCCESS },
    { "two entries in a roomy buffer",  2,  1000, 1000, APS_SUCCESS },
    { "all-ones count",                 0xFFFFFFFFu, 32, 32, APS_INVALID_PARAM },
    { "count beyond the poll limit",    0x6666662u,  32, 32, APS_INVALID_PARAM },
    { "count of zero",                  0,  32,   32,  APS_INVALID_PARAM },
};

TEST(apev_size_boundary_table)
{
    AP_BEGIN();
    SOCKET l = listener1(); size_t i;
    for (i = 0; i < sizeof(sz_rows) / sizeof(sz_rows[0]); i++) {
        const sz_row *r = &sz_rows[i];
        ap_req in; SOCKET hs[3] = { l, l, l };
        LONG st;
        ap_fill(&in, 0, 0, 3, hs, 0);
        in.n = r->count;          /* the declared count is what the driver trusts */
        st = ap_try((HANDLE)l, &in, r->inlen, r->outlen);
        CHECKF((ULONG)st == r->want, "%s: got %#lx want %#lx", r->what, (unsigned long)st, (unsigned long)r->want);
    }
    ap_closeS(l);
}

/* The count is validated against the buffer before any entry is looked at, so an unusable handle in a
 * region that the buffer does not cover is never reached. */
TEST(apev_count_checked_before_handles)
{
    AP_BEGIN();
    SOCKET l = listener1(); ap_req in; SOCKET hs[2] = { l, 0 };
    ap_fill(&in, 0, 0, 2, hs, 0);
    CK_ST(ap_try((HANDLE)l, &in, AP_SZ(1), AP_SZ(1)), APS_INVALID_PARAM);   /* second entry would be an invalid handle */
    ap_closeS(l);
}

/* ---- entries that are not sockets ------------------------------------------ */

typedef struct { const char *what; HANDLE h; ULONG want; } bad_row;

TEST(apev_entry_object_type_table)
{
    AP_BEGIN();
    SOCKET l = listener1(); HANDLE ev, mtx, sem; size_t i;
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    mtx = CreateMutexW(NULL, FALSE, NULL);
    sem = CreateSemaphoreW(NULL, 0, 1, NULL);
    {
        bad_row rows[] = {
            { "event",           ev,                APS_TYPE_MISMATCH },
            { "mutex",           mtx,               APS_TYPE_MISMATCH },
            { "semaphore",       sem,               APS_TYPE_MISMATCH },
            { "process pseudo",  GetCurrentProcess(), APS_TYPE_MISMATCH },
            { "thread pseudo",   GetCurrentThread(),  APS_TYPE_MISMATCH },
        };
        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            ap_req in; SOCKET hs[2] = { l, (SOCKET)rows[i].h };
            ap_fill(&in, AP_REL_MS(100), 0, 2, hs, APE_ALL);
            LONG st = ap_try((HANDLE)l, &in, AP_SZ(2), AP_SZ(2));
            CHECKF((ULONG)st == rows[i].want, "%s: got %#lx want %#lx", rows[i].what, (unsigned long)st, (unsigned long)rows[i].want);
        }
    }
    CloseHandle(ev); CloseHandle(mtx); CloseHandle(sem); ap_closeS(l);
}

/* A genuine file object that belongs to some other device is refused with an invalid-handle status,
 * not a type mismatch: the type is right, the device is not AFD. */
TEST(apev_entry_non_afd_file_is_invalid_handle)
{
    AP_BEGIN();
    SOCKET l = listener1(); char path[MAX_PATH]; HANDLE f, rd = NULL, wr = NULL; ap_req in; SOCKET hs[1];
    t_tmpfile(path, sizeof(path), "apev_entry.tmp");
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    hs[0] = (SOCKET)f;
    ap_fill(&in, AP_REL_MS(100), 0, 1, hs, APE_ALL);
    CK_ST(ap_try((HANDLE)l, &in, AP_SZ(1), AP_SZ(1)), APS_INVALID_HANDLE);
    CloseHandle(f);
    if (CreatePipe(&rd, &wr, NULL, 0)) {
        hs[0] = (SOCKET)rd;
        ap_fill(&in, AP_REL_MS(100), 0, 1, hs, APE_ALL);
        CK_ST(ap_try((HANDLE)l, &in, AP_SZ(1), AP_SZ(1)), APS_INVALID_HANDLE);
        CloseHandle(rd); CloseHandle(wr);
    }
    ap_closeS(l);
}

TEST(apev_entry_closed_handle_is_invalid_handle)
{
    AP_BEGIN();
    SOCKET l = listener1(), dead = ap_sock(SOCK_STREAM); ap_req in; SOCKET hs[2];
    ap_closeS(dead);
    hs[0] = l; hs[1] = dead;
    ap_fill(&in, AP_REL_MS(100), 0, 2, hs, APE_ALL);
    CK_ST(ap_try((HANDLE)l, &in, AP_SZ(2), AP_SZ(2)), APS_INVALID_HANDLE);
    ap_closeS(l);
}

/* A bad entry fails the whole request: the good entries in front of it do not produce a partial result,
 * and the same request without the bad entry works. */
TEST(apev_bad_entry_fails_whole_request)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); ap_req in; SOCKET hs[3]; ap_res r;
    ap_pair(&c, &s);
    hs[0] = c; hs[1] = s; hs[2] = (SOCKET)ev;
    ap_fill(&in, 0, 0, 3, hs, APE_SEND);
    CK_ST(ap_try((HANDLE)c, &in, AP_SZ(3), AP_SZ(3)), APS_TYPE_MISMATCH);
    ap_run((HANDLE)c, 0, 0, 2, hs, (ULONG[]){ APE_SEND, APE_SEND }, 1000, &r);
    CK_ST(r.ret, APS_SUCCESS);
    CHECK(r.out.n == 2);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

/* ---- the carrier handle ------------------------------------------------------- */

/* The request is issued on one handle and names others; the result does not depend on which kind of
 * handle carried it: stream, listener, datagram and an endpoint-less control open all give the same report. */
TEST(apev_carrier_kinds_report_the_same)
{
    AP_BEGIN();
    SOCKET c, s, bare, udp, l; HANDLE ctl = NULL; size_t i; HANDLE carriers[6];
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; static WCHAR nm[] = L"\\Device\\Afd\\apevctl";
    ap_pair(&c, &s);
    bare = ap_sock(SOCK_STREAM); udp = ap_sock(SOCK_DGRAM); l = listener1();
    us.Buffer = nm; us.Length = sizeof(nm) - sizeof(WCHAR); us.MaximumLength = sizeof(nm);
    InitializeObjectAttributes(&oa, &us, 0, NULL, NULL);
    if (X.open_file(&ctl, SYNCHRONIZE, &oa, &io, 0, 0) != 0) ctl = NULL;
    carriers[0] = (HANDLE)c; carriers[1] = (HANDLE)s; carriers[2] = (HANDLE)bare;
    carriers[3] = (HANDLE)udp; carriers[4] = (HANDLE)l; carriers[5] = ctl;
    for (i = 0; i < 6; i++) {
        ap_res r;
        if (!carriers[i]) { t_note("control open unavailable"); continue; }
        ap_run(carriers[i], AP_REL_MS(1000), 0, 1, &c, (ULONG[]){ APE_SEND }, 3000, &r);
        CHECKF(r.ret == 0 && r.ios == 0 && r.out.n == 1 && r.out.e[0].h == c && r.out.e[0].ev == APE_SEND,
               "carrier %u: ret %#lx ios %#lx n %lu", (unsigned)i, (unsigned long)r.ret, (unsigned long)r.ios, (unsigned long)r.out.n);
    }
    if (ctl) CloseHandle(ctl);
    ap_closeS(c); ap_closeS(s); ap_closeS(bare); ap_closeS(udp); ap_closeS(l);
}

/* Issuing the request on a handle that is not a file object at all is refused by the I/O manager. */
TEST(apev_carrier_event_handle_is_type_mismatch)
{
    AP_BEGIN();
    SOCKET l = listener1(); HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); ap_req in;
    ap_fill(&in, 0, 0, 1, &l, APE_ALL);
    CK_ST(ap_try(ev, &in, AP_SZ(1), AP_SZ(1)), APS_TYPE_MISMATCH);
    CloseHandle(ev); ap_closeS(l);
}

TEST(apev_carrier_closed_handle_is_invalid_handle)
{
    AP_BEGIN();
    SOCKET l = listener1(), dead = ap_sock(SOCK_STREAM); ap_req in;
    ap_closeS(dead);
    ap_fill(&in, 0, 0, 1, &l, APE_ALL);
    CK_ST(ap_try((HANDLE)dead, &in, AP_SZ(1), AP_SZ(1)), APS_INVALID_HANDLE);
    ap_closeS(l);
}

/* ---- completion shape ------------------------------------------------------------ */

/* Only the reported prefix of the output buffer is written. */
TEST(apev_output_beyond_information_untouched)
{
    AP_BEGIN();
    SOCKET c, s, l; ap_res r; SOCKET hs[2]; ULONG m[2] = { APE_SEND, APE_ACCEPT };
    ap_pair(&c, &s); l = listener1();
    hs[0] = c; hs[1] = l;
    ap_run((HANDLE)c, AP_REL_MS(1000), 0, 2, hs, m, 3000, &r);
    CK_ST(r.ret, APS_SUCCESS);
    CK_ST(r.ios, APS_SUCCESS);
    CHECK(r.info == AP_SZ(1));
    CHECK(r.out.n == 1);
    CHECK(r.out.e[0].h == c && r.out.e[0].ev == APE_SEND && r.out.e[0].st == 0);
    CHECK(r.out.e[1].h == (ULONG_PTR)0xcccccccccccccccc);       /* second slot was never written */
    CHECK(r.out.e[1].ev == 0xcccccccc);
    ap_closeS(c); ap_closeS(s); ap_closeS(l);
}

/* The timeout value is handed back untouched, whatever it was, also when the result is immediate. */
TEST(apev_timeout_value_echoed_when_immediate)
{
    AP_BEGIN();
    static const LONGLONG tos[] = { AP_INFINITE, AP_REL_MS(1), AP_REL_MS(86400000LL), 0x7ffffffe00000001LL, 0 };
    SOCKET c, s; size_t i;
    ap_pair(&c, &s);
    for (i = 0; i < sizeof(tos) / sizeof(tos[0]); i++) {
        ap_res r;
        ap_run((HANDLE)c, tos[i], 0, 1, &c, (ULONG[]){ APE_SEND }, 3000, &r);
        CHECKF(r.ret == 0 && r.out.n == 1 && r.out.to == tos[i], "timeout %lld: ret %#lx echo %lld", (long long)tos[i], (unsigned long)r.ret, (long long)r.out.to);
    }
    ap_closeS(c); ap_closeS(s);
}

/* Entries come back in submission order, each with the handle value that was submitted. */
TEST(apev_ready_entries_keep_submission_order)
{
    AP_BEGIN();
    SOCKET a, b, c, d; ap_res r; SOCKET hs[4]; ULONG m[4] = { APE_SEND, APE_SEND, APE_SEND, APE_SEND };
    ap_pair(&a, &b); ap_pair(&c, &d);
    hs[0] = d; hs[1] = a; hs[2] = c; hs[3] = b;
    ap_run((HANDLE)a, 0, 0, 4, hs, m, 3000, &r);
    CK_ST(r.ret, APS_SUCCESS);
    CHECK(r.out.n == 4 && r.info == AP_SZ(4));
    CHECK(r.out.e[0].h == d && r.out.e[1].h == a && r.out.e[2].h == c && r.out.e[3].h == b);
    ap_closeS(a); ap_closeS(b); ap_closeS(c); ap_closeS(d);
}

/* A duplicated handle is a different handle value for the same endpoint; the report names the value
 * that was submitted. */
TEST(apev_duplicate_handle_value_is_reported)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE dup = NULL; ap_res r;
    ap_pair(&c, &s);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    ap_run((HANDLE)s, 0, 0, 1, (SOCKET[]){ (SOCKET)dup }, (ULONG[]){ APE_SEND }, 3000, &r);
    CK_ST(r.ret, APS_SUCCESS);
    CHECK(r.out.n == 1 && r.out.e[0].h == (ULONG_PTR)dup && r.out.e[0].ev == APE_SEND);
    CHECK((ULONG_PTR)dup != c);
    CloseHandle(dup); ap_closeS(c); ap_closeS(s);
}

/* The request is captured at submission: scribbling over the input afterwards changes nothing. */
TEST(apev_input_buffer_copied_at_submission)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), cl; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_fill(&in, AP_REL_MS(3000), 0, 1, &l, APE_ACCEPT);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)l, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    memset(&in, 0x5a, sizeof(in));
    cl = ap_dial(&a);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(out.n == 1 && out.e[0].h == l && out.e[0].ev == APE_ACCEPT);
    CHECK(out.to == AP_REL_MS(3000));
    CloseHandle(ev); ap_closeS(cl); ap_closeS(l);
}

/* An absolute deadline in the future is honoured as an absolute time: the request pends and an event
 * ends it long before the deadline. */
TEST(apev_absolute_future_deadline_ends_on_event)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), cl; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event(); LARGE_INTEGER now;
    X.systime(&now);
    ap_fill(&in, now.QuadPart + 600000000LL, 0, 1, &l, APE_ACCEPT);   /* one minute from now */
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)l, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    cl = ap_dial(&a);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(out.n == 1 && out.e[0].ev == APE_ACCEPT);
    CHECK(out.to == in.to);
    CloseHandle(ev); ap_closeS(cl); ap_closeS(l);
}

/* ---- synchronous carrier handles --------------------------------------------------- */

/* A socket opened without the overlapped flag has a synchronous handle: the call does not return
 * until the request is complete, and a deadline is reported as the return value itself. */
TEST(apev_synchronous_handle_blocks_until_complete)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c, s; ap_req in, out; IO_STATUS_BLOCK io;
    c = X.WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    CHECK(c != INVALID_SOCKET);
    CHECK(X.connect(c, (struct sockaddr *)&a, sizeof(a)) == 0);
    s = X.accept(l, NULL, NULL);
    ap_fill(&in, AP_REL_MS(80), 0, 1, &c, APE_RECEIVE);
    memset(&out, 0, sizeof(out)); memset(&io, 0xcc, sizeof(io));
    CK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_POLL, &in, AP_SZ(1), &out, AP_SZ(1)), APS_TIMEOUT);
    CK_ST(io.Status, APS_TIMEOUT);
    CHECK(io.Information == 16 && out.n == 0);
    ap_fill(&in, AP_REL_MS(3000), 0, 1, &c, APE_SEND);
    memset(&out, 0, sizeof(out)); memset(&io, 0xcc, sizeof(io));
    CK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_POLL, &in, AP_SZ(1), &out, AP_SZ(1)), APS_SUCCESS);
    CHECK(io.Information == AP_SZ(1) && out.n == 1 && out.e[0].ev == APE_SEND);
    ap_closeS(c); ap_closeS(s); ap_closeS(l);
}
