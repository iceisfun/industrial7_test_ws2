/* Shared helpers for the endpoint close / cleanup area.
 *
 * An AFD endpoint is a file object on the AFD device; this area measures what happens to it when handles
 * are closed, duplicated, shared, associated with completion ports, or left with requests in flight.
 * Winsock is used to create and drive endpoints; ntdll Nt* entry points are used to look underneath.
 * Nothing is linked: every entry point is resolved at run time (U / UN).
 */
#ifndef ACC_H
#define ACC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define ST_SUCCESS           ((LONG)0x00000000)
#define ST_PENDING           ((LONG)0x00000103)
#define ST_TIMEOUT           ((LONG)0x00000102)
#define ST_INVALID_HANDLE    ((LONG)0xC0000008)
#define ST_INVALID_PARAMETER ((LONG)0xC000000D)
#define ST_INFO_MISMATCH     ((LONG)0xC0000004)
#define ST_INVALID_INFO      ((LONG)0xC0000003)
#define ST_NOT_IMPLEMENTED   ((LONG)0xC0000002)
#define ST_INVALID_DEVREQ    ((LONG)0xC0000010)
#define ST_TYPE_MISMATCH     ((LONG)0xC0000024)
#define ST_ACCESS_DENIED     ((LONG)0xC0000022)
#define ST_CANCELLED         ((LONG)0xC0000120)
#define ST_NOT_FOUND         ((LONG)0xC0000225)
#define ST_PORT_DISCONNECTED ((LONG)0xC0000037)
#define ST_HANDLE_NOT_CLOSABLE ((LONG)0xC0000235)
#define ST_CONN_ABORTED      ((LONG)0xC0000241)
#define ST_REMOTE_DISCONNECT ((LONG)0xC000013C)
#define ST_LOCAL_DISCONNECT  ((LONG)0xC000013B)
#define ST_CONN_RESET        ((LONG)0xC000020D)
#define ST_CONN_DISCONNECTED ((LONG)0xC000020C)
#define ST_PIPE_DISCONNECTED ((LONG)0xC00000B0)

#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)
#define EXPECT_ST(call, want) do { LONG st_ = (LONG)(call); t_check(st_ == (LONG)(want), __FILE__, __LINE__, #call " == " #want, "got %#lx want %#lx", (unsigned long)st_, (unsigned long)(LONG)(want)); } while (0)
#define ACC_WAIT 5000   /* bounded wait, ms */

#define AFD_IOCTL_POLL   0x00012024u
#define AFD_POLL_RECEIVE 0x0001
#define AFD_POLL_SEND    0x0004
#define AFD_POLL_DISC    0x0008
#define AFD_POLL_ABORT   0x0010
#define AFD_POLL_CLOSE   0x0020
#define AFD_POLL_ACCEPT  0x0080

enum { FI_Basic = 4, FI_Standard = 5, FI_Internal = 6, FI_Ea = 7, FI_Access = 8, FI_Name = 9, FI_Rename = 10,
       FI_Disposition = 13, FI_Position = 14, FI_All = 18, FI_Mode = 16, FI_Alignment = 17, FI_Completion = 30,
       FI_IoCompletionNotification = 41, FI_NetworkOpen = 34, FI_Max = 77 };

UDECL(LONG, NtClose, (HANDLE));
UDECL(LONG, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, HANDLE *, ACCESS_MASK, ULONG, ULONG));
UDECL(LONG, NtQueryInformationFile, (HANDLE, IO_STATUS_BLOCK *, void *, ULONG, int));
UDECL(LONG, NtSetInformationFile, (HANDLE, IO_STATUS_BLOCK *, void *, ULONG, int));
UDECL(LONG, NtDeviceIoControlFile, (HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, ULONG, void *, ULONG, void *, ULONG));
UDECL(LONG, NtReadFile, (HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, ULONG, LARGE_INTEGER *, ULONG *));
UDECL(LONG, NtWriteFile, (HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, ULONG, LARGE_INTEGER *, ULONG *));
UDECL(LONG, NtCancelIoFile, (HANDLE, IO_STATUS_BLOCK *));
UDECL(LONG, NtCancelIoFileEx, (HANDLE, IO_STATUS_BLOCK *, IO_STATUS_BLOCK *));
UDECL(LONG, NtRemoveIoCompletion, (HANDLE, ULONG_PTR *, ULONG_PTR *, IO_STATUS_BLOCK *, LARGE_INTEGER *));
UDECL(LONG, NtCreateIoCompletion, (HANDLE *, ACCESS_MASK, void *, ULONG));
UDECL(LONG, NtSetIoCompletion, (HANDLE, ULONG_PTR, ULONG_PTR, LONG, ULONG_PTR));
UDECL(LONG, NtQueryObject, (HANDLE, int, void *, ULONG, ULONG *));
UDECL(LONG, NtWaitForSingleObject, (HANDLE, BOOLEAN, LARGE_INTEGER *));

static int acc_up(void)
{
    static int done = 0;
    WSADATA d;
    if (done) return 1;
    if (!U(WSAStartup) || !UN(NtClose) || !UN(NtQueryInformationFile) || !UN(NtDeviceIoControlFile)) return 0;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 0;
    done = 1;
    return 1;
}
#define UP() do { if (!acc_up()) { t_skip("winsock/ntdll entry points unavailable"); return; } } while (0)

#define WERR()      (U(WSAGetLastError)())
#define WSETERR(e)  (U(WSASetLastError)(e))
#define CLOSES(s)   (U(closesocket)(s))

static struct sockaddr_in acc_lo(unsigned port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007fu;
    a.sin_port = (unsigned short)(((port & 0xff) << 8) | ((port >> 8) & 0xff));
    return a;
}

static SOCKET acc_sock(int type)   /* overlapped endpoint, the socket() default */
{
    return U(WSASocketW)(AF_INET, type, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
}
static SOCKET acc_sock_sync(int type) { return U(WSASocketW)(AF_INET, type, 0, NULL, 0, 0); }

static void acc_timeo(SOCKET s, int ms)
{
    U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    U(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms);
}

/* bind to loopback port 0; returns 0 on success, address in *out */
static int acc_bind(SOCKET s, struct sockaddr_in *out)
{
    struct sockaddr_in a = acc_lo(0);
    int n = sizeof a;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return -1;
    if (U(getsockname)(s, (struct sockaddr *)&a, &n)) return -1;
    if (out) *out = a;
    return 0;
}

static SOCKET acc_listener(struct sockaddr_in *out)
{
    SOCKET l = acc_sock(SOCK_STREAM);
    if (l == INVALID_SOCKET) return l;
    if (acc_bind(l, out) || U(listen)(l, 4)) { CLOSES(l); return INVALID_SOCKET; }
    return l;
}

/* connected loopback TCP pair: *c connects, *s is accepted; both overlapped endpoints with 5 s timeouts */
static int acc_pair(SOCKET *c, SOCKET *s)
{
    struct sockaddr_in a;
    SOCKET l = acc_listener(&a), cl, sv;
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    cl = acc_sock(SOCK_STREAM);
    if (cl == INVALID_SOCKET || U(connect)(cl, (struct sockaddr *)&a, sizeof a)) { CLOSES(l); if (cl != INVALID_SOCKET) CLOSES(cl); return 0; }
    acc_timeo(l, ACC_WAIT);
    sv = U(accept)(l, NULL, NULL);
    CLOSES(l);
    if (sv == INVALID_SOCKET) { CLOSES(cl); return 0; }
    acc_timeo(cl, ACC_WAIT); acc_timeo(sv, ACC_WAIT);
    *c = cl; *s = sv;
    return 1;
}
#define PAIR(c, s) SOCKET c, s; do { if (!acc_pair(&c, &s)) { t_skip("loopback pair unavailable"); return; } } while (0)

/* bound UDP socket on loopback */
static SOCKET acc_udp(struct sockaddr_in *out)
{
    SOCKET s = acc_sock(SOCK_DGRAM);
    if (s == INVALID_SOCKET) return s;
    if (acc_bind(s, out)) { CLOSES(s); return INVALID_SOCKET; }
    return s;
}

static void acc_linger(SOCKET s, int on, int secs)
{
    struct linger lg; lg.l_onoff = (u_short)on; lg.l_linger = (u_short)secs;
    U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
}
static void acc_rst_close(SOCKET s) { acc_linger(s, 1, 0); CLOSES(s); }

static void acc_nonblock(SOCKET s, int on)
{
    u_long v = on;
    U(ioctlsocket)(s, FIONBIO, &v);
}

/* how a handle is released */
enum { CL_SOCKET, CL_HANDLE, CL_NT };
static void acc_close(SOCKET s, int how)
{
    if (how == CL_SOCKET) CLOSES(s);
    else if (how == CL_HANDLE) CloseHandle((HANDLE)s);
    else UN(NtClose)((HANDLE)s);
}
static const char *const acc_how_name[] = { "closesocket", "CloseHandle", "NtClose" };

/* a fresh auto-reset-off event */
static HANDLE acc_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

/* OVERLAPPED helpers: Internal holds the NTSTATUS, InternalHigh the Information */
static void acc_ov_init(OVERLAPPED *ov, HANDLE ev)
{
    memset(ov, 0, sizeof *ov);
    ov->hEvent = ev;
}
#define OV_STATUS(ov) ((LONG)(ov)->Internal)
#define OV_PENDING(ov) ((LONG)(ov)->Internal == ST_PENDING)

/* number of bytes of loopback data readable without blocking */
static int acc_avail(SOCKET s)
{
    u_long n = 0;
    if (U(ioctlsocket)(s, FIONREAD, &n)) return -1;
    return (int)n;
}

/* Wait for a socket to become readable (poll via select), up to ms; returns select() result */
static int acc_wait_readable(SOCKET s, int ms)
{
    fd_set r; struct timeval tv;
    FD_ZERO(&r); FD_SET(s, &r);
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv);
}

/* recv with a bounded wait; returns recv() result, *err gets the winsock error on failure */
static int acc_recv(SOCKET s, void *buf, int len, int *err)
{
    int r = U(recv)(s, (char *)buf, len, 0);
    if (r < 0 && err) *err = WERR();
    return r;
}

/* Keep sending until the stream can take no more (non-blocking send reports WOULDBLOCK) or cap bytes went out.
 * Returns bytes queued. Used to put a peer's receive window and our send buffer in the full state. */
static size_t acc_fill_send(SOCKET s, size_t cap)
{
    static char blk[16384];
    size_t total = 0;
    acc_nonblock(s, 1);
    while (total < cap) {
        int r = U(send)(s, blk, sizeof blk, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    acc_nonblock(s, 0);
    return total;
}

static HANDLE acc_port(void) { return CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); }

/* NtRemoveIoCompletion with a bounded wait; returns the NTSTATUS, fills key/apc/io */
static LONG acc_remove(HANDLE port, ULONG_PTR *key, ULONG_PTR *apc, IO_STATUS_BLOCK *io, int ms)
{
    LARGE_INTEGER to;
    to.QuadPart = -(LONGLONG)ms * 10000;
    memset(io, 0xCD, sizeof *io);
    return UN(NtRemoveIoCompletion)(port, key, apc, io, &to);
}

/* handle count of this process, for leak relations */
static DWORD acc_handles(void)
{
    DWORD n = 0;
    GetProcessHandleCount(GetCurrentProcess(), &n);
    return n;
}

/* WSAIoctl extension lookups */
static int acc_ext(SOCKET s, GUID g, void *out, DWORD outlen)
{
    DWORD got = 0;
    return U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, out, outlen, &got, NULL, NULL);
}

/* pending-request kinds shared by several files */
enum { OP_RECV_TCP, OP_RECV_UDP, OP_ACCEPT, OP_ADDRCHANGE, OP_SEND_FULL, OP_NTREAD, OP_POLL, OP_COUNT };
static const char *const acc_op_name[] = { "recv_tcp", "recv_udp", "acceptex", "addrchange", "send_full", "ntread", "poll" };

/* Everything one pending request owns. */
typedef struct {
    int op;
    SOCKET target;          /* the endpoint the request is queued on */
    SOCKET other;           /* peer or helper, closed by acc_pend_done */
    SOCKET extra;           /* accept socket */
    SOCKET holder;          /* second endpoint whose handle value is polled (OP_POLL) */
    OVERLAPPED ov;
    IO_STATUS_BLOCK io;     /* for the raw Nt requests */
    HANDLE ev;
    int is_nt;
    char buf[1024];
    char poll[64];
    WSABUF wb;
    DWORD flags;
    struct sockaddr_in from; int fromlen;
} pend_t;

/* Queue one request of the given kind; returns 1 when it is verifiably pending, 0 -> caller skips. */
int acc_pend_start(pend_t *p, int op, HANDLE port, ULONG_PTR key);
/* Close every socket the request owns that is still open (those listed as INVALID_SOCKET are skipped). */
void acc_pend_done(pend_t *p);
/* True when the request has completed (event signalled). */
int acc_pend_wait(pend_t *p, int ms);
/* Status of a finished request, whichever way it was issued. */
LONG acc_pend_status(const pend_t *p);
#endif
