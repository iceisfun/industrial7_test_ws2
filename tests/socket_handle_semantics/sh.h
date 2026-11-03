/* Shared helpers for the socket_handle_semantics area: a socket is a kernel File object handle, so these
 * tests exercise it through kernel32 file/handle APIs and ntdll Nt* entry points as well as Winsock.
 * Nothing here links ws2_32 or ntdll: every entry point is resolved at run time (U / UIN / t_proc_in). */
#ifndef SH_H
#define SH_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif
#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

#define SYNC 0                  /* WSASocket flags 0: synchronous (non-overlapped) handle */
#define OVLD WSA_FLAG_OVERLAPPED
#define PLAIN (-1)              /* socket(): overlapped on this platform */

/* ---- start-up: one WSAStartup for the whole process, never balanced ---- */
static int sh_up(void)
{
    static int done = 0;
    if (!done) {
        WSADATA d;
        if (!U(WSAStartup)) return 0;
        if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 0;
        done = 1;
    }
    return 1;
}
#define UP() do { if (!sh_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

static int  sh_werr(void)      { return U(WSAGetLastError)(); }
static void sh_setwerr(int e)  { U(WSASetLastError)(e); }
static int  sh_closes(SOCKET s) { return U(closesocket)(s); }

/* Compare-once equality checks (the harness EXPECT_EQ evaluates its arguments twice, which would repeat the
 * side effects of a recv or a close). EQ compares as 64-bit signed values, EQ32 as 32-bit patterns (NTSTATUS). */
#define EQ(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define EQ32(a, b) do { unsigned a_ = (unsigned)(a), b_ = (unsigned)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%x want 0x%x", a_, b_); } while (0)

#define SH_WAIT 5000   /* bounded wait, ms */

static struct sockaddr_in sh_lo(unsigned port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007fu;                       /* 127.0.0.1, network order on a little-endian host */
    a.sin_port = (unsigned short)(((port & 0xff) << 8) | ((port >> 8) & 0xff));
    return a;
}

/* flags are WSA_FLAG_* for WSASocketW; -1 means the plain socket() call. */
static SOCKET sh_make(int type, int flags)
{
    if (flags == -1) return U(socket)(AF_INET, type, 0);
    return U(WSASocketW)(AF_INET, type, 0, NULL, 0, (DWORD)flags);
}
static void sh_rcvtimeo(SOCKET s, int ms) { U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms); }
static void sh_sndtimeo(SOCKET s, int ms) { U(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms); }

/* A listener on an ephemeral loopback port. Returns INVALID_SOCKET on failure. */
static SOCKET sh_listener(int flags, struct sockaddr_in *out)
{
    struct sockaddr_in a = sh_lo(0);
    int n = sizeof a;
    SOCKET l = sh_make(SOCK_STREAM, flags);
    if (l == INVALID_SOCKET) return l;
    if (U(bind)(l, (struct sockaddr *)&a, sizeof a) || U(listen)(l, 4) || U(getsockname)(l, (struct sockaddr *)&a, &n)) {
        U(closesocket)(l);
        return INVALID_SOCKET;
    }
    if (out) *out = a;
    return l;
}

/* A connected loopback TCP pair: *c is the connecting side, *s the accepted side (both blocking, 5 s receive
 * timeouts). The listener is closed before returning. Returns 1 on success. */
static int sh_pair(SOCKET *c, SOCKET *s, int flags)
{
    struct sockaddr_in a;
    SOCKET l = sh_listener(flags, &a);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = sh_make(SOCK_STREAM, flags);
    if (*c != INVALID_SOCKET && U(connect)(*c, (struct sockaddr *)&a, sizeof a) == 0)
        *s = U(accept)(l, NULL, NULL);
    U(closesocket)(l);
    if (*c == INVALID_SOCKET || *s == INVALID_SOCKET) {
        if (*c != INVALID_SOCKET) U(closesocket)(*c);
        if (*s != INVALID_SOCKET) U(closesocket)(*s);
        *c = *s = INVALID_SOCKET;
        return 0;
    }
    sh_rcvtimeo(*c, SH_WAIT); sh_rcvtimeo(*s, SH_WAIT);
    return 1;
}
#define PAIR(c, s, fl) do { if (!sh_pair(&(c), &(s), (fl))) { t_skip("cannot build loopback pair"); return; } } while (0)

static int sh_send(SOCKET s, const void *p, int n) { return U(send)(s, (const char *)p, n, 0); }
/* Waits (bounded) until s is readable according to select(); returns 1 if so. */
static int sh_readable(SOCKET s, int ms)
{
    fd_set r;
    struct timeval tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
/* recv() that can never block for more than SH_WAIT: -2 with WSAETIMEDOUT when nothing arrived. */
static int sh_recv(SOCKET s, void *p, int n)
{
    if (!sh_readable(s, SH_WAIT)) { U(WSASetLastError)(WSAETIMEDOUT); return -2; }
    return U(recv)(s, (char *)p, n, 0);
}
/* Reads exactly n bytes (or fewer on error/close/timeout) through recv. */
static int sh_recv_all(SOCKET s, void *p, int n)
{
    int got = 0;
    while (got < n) {
        int r = sh_recv(s, (char *)p + got, n - got);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

/* ---- ntdll entry points not declared (or not stable) in the SDK headers ---- */
typedef struct { LONG_PTR Status; ULONG_PTR Information; } sh_iosb;
typedef LONG (NTAPI *sh_NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *sh_NtQueryInformationFile_t)(HANDLE, sh_iosb *, PVOID, ULONG, ULONG);
typedef LONG (NTAPI *sh_NtQueryVolumeInformationFile_t)(HANDLE, sh_iosb *, PVOID, ULONG, ULONG);
typedef LONG (NTAPI *sh_NtSetInformationFile_t)(HANDLE, sh_iosb *, PVOID, ULONG, ULONG);
typedef LONG (NTAPI *sh_NtClose_t)(HANDLE);
typedef LONG (NTAPI *sh_NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, HANDLE *, ULONG, ULONG, ULONG);
typedef LONG (NTAPI *sh_NtSetInformationObject_t)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (NTAPI *sh_NtCancelIoFile_t)(HANDLE, sh_iosb *);
typedef LONG (NTAPI *sh_NtCancelIoFileEx_t)(HANDLE, PVOID, sh_iosb *);
typedef LONG (NTAPI *sh_NtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, sh_iosb *, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef LONG (NTAPI *sh_NtWriteFile_t)(HANDLE, HANDLE, PVOID, PVOID, sh_iosb *, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef LONG (NTAPI *sh_NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef LONG (NTAPI *sh_NtDeviceIoControlFile_t)(HANDLE, HANDLE, PVOID, PVOID, sh_iosb *, ULONG, PVOID, ULONG, PVOID, ULONG);
#define NTFN(type, name) ((type)t_proc_in("ntdll.dll", name))

#define ST_SUCCESS             ((LONG)0x00000000)
#define ST_PENDING             ((LONG)0x00000103)
#define ST_INVALID_INFO_CLASS  ((LONG)0xC0000003)
#define ST_INFO_LENGTH_MISMATCH ((LONG)0xC0000004)
#define ST_INVALID_HANDLE      ((LONG)0xC0000008)
#define ST_INVALID_PARAMETER   ((LONG)0xC000000D)
#define ST_INVALID_DEVICE_REQUEST ((LONG)0xC0000010)
#define ST_ACCESS_DENIED       ((LONG)0xC0000022)
#define ST_BUFFER_TOO_SMALL    ((LONG)0xC0000023)
#define ST_OBJECT_TYPE_MISMATCH ((LONG)0xC0000024)
#define ST_NOT_SUPPORTED       ((LONG)0xC00000BB)
#define ST_CANCELLED           ((LONG)0xC0000120)
#define ST_HANDLE_NOT_CLOSABLE ((LONG)0xC0000235)

/* OBJECT_BASIC_INFORMATION (class 0) */
typedef struct {
    ULONG Attributes; ACCESS_MASK GrantedAccess; ULONG HandleCount; ULONG PointerCount;
    ULONG PagedPoolCharge; ULONG NonPagedPoolCharge; ULONG Reserved[3];
    ULONG NameInfoSize; ULONG TypeInfoSize; ULONG SecurityDescriptorSize; LARGE_INTEGER CreationTime;
} sh_objbasic;

/* Queries the object type name of a handle into out (ASCII, "" on failure); returns the NTSTATUS. */
static LONG sh_type_name(HANDLE h, char *out, size_t cap)
{
    union { char raw[512]; struct { USHORT Length, Max; PWSTR Buf; } u; } b;
    sh_NtQueryObject_t q = NTFN(sh_NtQueryObject_t, "NtQueryObject");
    LONG st;
    ULONG ret = 0;
    out[0] = 0;
    if (!q) return ST_NOT_SUPPORTED;
    memset(&b, 0, sizeof b);
    st = q(h, 2, &b, sizeof b, &ret);
    if (st == 0) {
        size_t i, n = b.u.Length / 2;
        for (i = 0; i < n && i + 1 < cap; i++) out[i] = (char)b.u.Buf[i];
        out[i] = 0;
    }
    return st;
}

static HANDLE sh_dup(HANDLE h, DWORD access, BOOL inherit, DWORD opts)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, access, inherit, opts)) return NULL;
    return d;
}
static BOOL sh_hinfo(HANDLE h, DWORD *f) { return U(GetHandleInformation)(h, f); }

static HANDLE sh_event(void) { return CreateEventA(NULL, TRUE, FALSE, NULL); }
static void sh_ovl(OVERLAPPED *o, HANDLE ev) { memset(o, 0, sizeof *o); o->hEvent = ev; }
static DWORD sh_wait(HANDLE h) { return WaitForSingleObject(h, SH_WAIT); }

/* Run ReadFile on a worker thread so a request that should never block cannot hang the run: the call is
 * abandoned (and cancelled) after SH_WAIT. Returns 1 if the call returned within the bound. */
typedef struct { HANDLE h; void *buf; DWORD len; DWORD got; BOOL ret; DWORD err; OVERLAPPED *o; int write; } sh_rwjob;
static DWORD WINAPI sh_rw_thread(LPVOID p)
{
    sh_rwjob *j = (sh_rwjob *)p;
    j->ret = j->write ? WriteFile(j->h, j->buf, j->len, &j->got, j->o) : ReadFile(j->h, j->buf, j->len, &j->got, j->o);
    j->err = GetLastError();
    return 0;
}
static int sh_rw_bounded(int write, HANDLE h, void *buf, DWORD len, OVERLAPPED *o, BOOL *ret, DWORD *got, DWORD *err)
{
    sh_rwjob j;
    HANDLE t;
    int done = 1;
    memset(&j, 0, sizeof j);
    j.h = h; j.buf = buf; j.len = len; j.o = o; j.write = write; j.got = 0xdeadbeef;
    t = CreateThread(NULL, 0, sh_rw_thread, &j, 0, NULL);
    if (!t) return 0;
    if (WaitForSingleObject(t, SH_WAIT) != WAIT_OBJECT_0) {
        done = 0;
        CancelIoEx(h, NULL);
        CancelSynchronousIo(t);
        if (WaitForSingleObject(t, SH_WAIT) != WAIT_OBJECT_0) TerminateThread(t, 0);
    }
    CloseHandle(t);
    *ret = j.ret; *got = j.got; *err = j.err;
    return done;
}
/* Bounded ReadFile/WriteFile with no OVERLAPPED. */
static BOOL sh_readfile(HANDLE h, void *buf, DWORD len, DWORD *got, DWORD *err)
{
    BOOL r = FALSE; DWORD e = 0;
    if (!sh_rw_bounded(0, h, buf, len, NULL, &r, got, &e)) { *err = 0xFFFF0000; return FALSE; }
    *err = e;
    return r;
}
static BOOL sh_writefile(HANDLE h, const void *buf, DWORD len, DWORD *got, DWORD *err)
{
    BOOL r = FALSE; DWORD e = 0;
    if (!sh_rw_bounded(1, h, (void *)buf, len, NULL, &r, got, &e)) { *err = 0xFFFF0000; return FALSE; }
    *err = e;
    return r;
}
#define SH_BLOCKED 0xFFFF0000u
/* Drop-in replacements for ReadFile / WriteFile that cannot hang a run when the call would block: with a NULL
 * OVERLAPPED the call runs on a worker thread that is abandoned (and its I/O cancelled) after SH_WAIT, in which
 * case the result is FALSE with ERROR_TIMEOUT. With an OVERLAPPED they call straight through. */
static BOOL sh_rf(HANDLE h, void *b, DWORD n, DWORD *got, OVERLAPPED *o)
{
    BOOL r = FALSE; DWORD e = 0, g = 0;
    if (o) return ReadFile(h, b, n, got, o);
    if (!sh_rw_bounded(0, h, b, n, NULL, &r, &g, &e)) { if (got) *got = 0; SetLastError(ERROR_TIMEOUT); return FALSE; }
    if (got) *got = g;
    SetLastError(e);
    return r;
}
static BOOL sh_wf(HANDLE h, const void *b, DWORD n, DWORD *got, OVERLAPPED *o)
{
    BOOL r = FALSE; DWORD e = 0, g = 0;
    if (o) return WriteFile(h, b, n, got, o);
    if (!sh_rw_bounded(1, h, (void *)b, n, NULL, &r, &g, &e)) { if (got) *got = 0; SetLastError(ERROR_TIMEOUT); return FALSE; }
    if (got) *got = g;
    SetLastError(e);
    return r;
}
#endif
