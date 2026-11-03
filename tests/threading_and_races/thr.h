/* Shared helpers for the threading_and_races area.
 *
 * Everything under test is reached through U() (LoadLibrary -> GetProcAddress); nothing links the DLL.
 * All endpoints are loopback with ephemeral ports, every wait is bounded, every thread is joined, every socket
 * is closed by the test that created it. Tests never print ports, addresses, handles or timings.
 *
 * "Blocker" threads: a worker performs one blocking Winsock call on a socket owned by the test, signals
 * `ready` right before the call and records the return value plus WSAGetLastError() immediately after it
 * returns. The main thread lets the call settle (a short sleep, only used to make "still blocked" likely,
 * never asserted as a duration) and then acts on the socket from its own thread.
 */
#ifndef THR_H
#define THR_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef WSA_OPERATION_ABORTED
#define WSA_OPERATION_ABORTED 995
#endif

/* ---- start-up: one WSAStartup per process, never balanced --------------------------------------------- */
static int thr_up(void)
{
    static int done;
    if (!done) {
        WSADATA d;
        if (!U(WSAStartup) || U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 0;
        done = 1;
    }
    return 1;
}
#define NEED() do { if (!thr_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

/* ---- thin wrappers ---------------------------------------------------------------------------------------- */
static int    werr(void)          { return U(WSAGetLastError)(); }
static void   wset(int e)         { U(WSASetLastError)(e); }
static SOCKET tcp(void)           { return U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
static SOCKET udp(void)           { return U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
static int    cls(SOCKET s)       { return U(closesocket)(s); }
static int    snd(SOCKET s, const void *b, int n) { return U(send)(s, (const char *)b, n, 0); }
static int    rcv(SOCKET s, void *b, int n)       { return U(recv)(s, (char *)b, n, 0); }
static int    nbio(SOCKET s, int on) { u_long v = on ? 1 : 0; return U(ioctlsocket)(s, FIONBIO, &v); }
static int    gso(SOCKET s, int lvl, int opt, void *v, int *n) { return U(getsockopt)(s, lvl, opt, (char *)v, n); }
static int    sso(SOCKET s, int lvl, int opt, const void *v, int n) { return U(setsockopt)(s, lvl, opt, (const char *)v, n); }

static struct sockaddr_in lo4(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;                 /* 127.0.0.1, port 0 */
    return a;
}

/* Listening TCP socket on loopback, ephemeral port; *a receives the bound name. */
static SOCKET listener(struct sockaddr_in *a, int backlog)
{
    struct sockaddr_in b = lo4();
    int n = sizeof b;
    SOCKET s = tcp();
    if (s == INVALID_SOCKET) return s;
    if (U(bind)(s, (struct sockaddr *)&b, sizeof b) || U(getsockname)(s, (struct sockaddr *)&b, &n) ||
        U(listen)(s, backlog)) { cls(s); return INVALID_SOCKET; }
    if (a) *a = b;
    return s;
}
static SOCKET dial(const struct sockaddr_in *a)
{
    SOCKET s = tcp();
    if (s == INVALID_SOCKET) return s;
    if (U(connect)(s, (const struct sockaddr *)a, sizeof *a)) { cls(s); return INVALID_SOCKET; }
    return s;
}
/* Connected loopback TCP pair: *c is the connecting side, *s the accepted side. */
static int pair(SOCKET *c, SOCKET *s)
{
    struct sockaddr_in a;
    SOCKET l = listener(&a, 4);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = dial(&a);
    if (*c != INVALID_SOCKET) *s = U(accept)(l, NULL, NULL);
    cls(l);
    if (*c == INVALID_SOCKET || *s == INVALID_SOCKET) {
        if (*c != INVALID_SOCKET) cls(*c);
        if (*s != INVALID_SOCKET) cls(*s);
        return 0;
    }
    return 1;
}
/* Connected IPv6 loopback pair; returns 0 when IPv6 loopback is not usable. */
static int pair6(SOCKET *c, SOCKET *s)
{
    struct sockaddr_in6 a;
    int n = sizeof a;
    SOCKET l = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr.u.Byte[15] = 1;
    if (U(bind)(l, (struct sockaddr *)&a, sizeof a) || U(getsockname)(l, (struct sockaddr *)&a, &n) || U(listen)(l, 4)) { cls(l); return 0; }
    *c = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (*c != INVALID_SOCKET && U(connect)(*c, (struct sockaddr *)&a, sizeof a) == 0) *s = U(accept)(l, NULL, NULL);
    cls(l);
    if (*c == INVALID_SOCKET || *s == INVALID_SOCKET) {
        if (*c != INVALID_SOCKET) cls(*c);
        if (*s != INVALID_SOCKET) cls(*s);
        return 0;
    }
    return 1;
}
/* Bound (not connected) loopback UDP socket; *a receives its name. */
static SOCKET udp_bound(struct sockaddr_in *a)
{
    struct sockaddr_in b = lo4();
    int n = sizeof b;
    SOCKET s = udp();
    if (s == INVALID_SOCKET) return s;
    if (U(bind)(s, (struct sockaddr *)&b, sizeof b) || U(getsockname)(s, (struct sockaddr *)&b, &n)) { cls(s); return INVALID_SOCKET; }
    if (a) *a = b;
    return s;
}

/* ---- thread helpers ---------------------------------------------------------------------------------------- */
/* Wait for a thread and close its handle; returns 1 when the thread finished within ms. */
static int join(HANDLE h, DWORD ms)
{
    int ok;
    if (!h) return 0;
    ok = WaitForSingleObject(h, ms) == WAIT_OBJECT_0;
    if (ok) CloseHandle(h);
    return ok;
}
static int finished(HANDLE h) { return WaitForSingleObject(h, 0) == WAIT_OBJECT_0; }
#define SETTLE() Sleep(150)

/* A call or request torn down by a local closesocket / cancel carries one of a small set of codes depending on the
 * call path (NT status mapping): interrupted, connection aborted, operation aborted, not-a-socket. The exact member
 * is recorded with t_note by the tests; membership is what is asserted. */
static int abort_err(int e)
{
    return e == WSAEINTR || e == WSAECONNABORTED || e == WSAENOTSOCK || e == WSA_OPERATION_ABORTED ||
           e == ERROR_CONNECTION_ABORTED;
}

/* Equality check that evaluates its first argument exactly once (the harness macro evaluates twice). */
#define EQV(expr, want) do { long long v_ = (long long)(expr); \
    t_check(v_ == (long long)(want), __FILE__, __LINE__, #expr " == " #want, "got %lld want %lld", v_, (long long)(want)); } while (0)

/* ---- blocker threads ----------------------------------------------------------------------------------------- */
enum {
    B_ACCEPT, B_WSAACCEPT, B_RECV, B_RECVFROM, B_WSARECV, B_WSARECVFROM, B_SELECT_R, B_SELECT_X, B_POLL_IN,
    B_SEND, B_WSASEND, B_RECV_PEEK, B_RECV_WAITALL, B_CONNECT_WAIT
};
struct blk {
    int     kind;
    SOCKET  s;
    int     len;            /* buffer size for receive kinds */
    HANDLE  ready, th;
    int     ret;            /* raw return value of the call */
    int     err;            /* WSAGetLastError() right after, when ret is a failure */
    int     bytes;          /* WSA* byte counts */
    int     flags;
    char    buf[512];
};

static char sendbuf[1 << 18];                       /* payload of the blocking send kinds */

static DWORD WINAPI blk_main(void *p)
{
    struct blk *b = (struct blk *)p;
    struct sockaddr_in from;
    int fl = (int)sizeof from;
    DWORD got = 0, f = 0;
    WSABUF wb;
    fd_set fds;
    struct timeval tv;
    WSAPOLLFD pf;
    wb.buf = b->buf;
    wb.len = (ULONG)(b->len ? b->len : 1);
    FD_ZERO(&fds);
    FD_SET(b->s, &fds);
    tv.tv_sec = 8; tv.tv_usec = 0;
    pf.fd = b->s; pf.events = POLLRDNORM; pf.revents = 0;
    wset(0);
    SetEvent(b->ready);
    switch (b->kind) {
    case B_ACCEPT: {
        SOCKET r = U(accept)(b->s, NULL, NULL);
        b->ret = r == INVALID_SOCKET ? -1 : 0;
        if (r != INVALID_SOCKET) cls(r);
        break;
    }
    case B_WSAACCEPT: {
        typedef SOCKET (WINAPI *wa_t)(SOCKET, struct sockaddr *, LPINT, LPCONDITIONPROC, DWORD_PTR);
        SOCKET r = ((wa_t)t_proc("WSAAccept"))(b->s, NULL, NULL, NULL, 0);
        b->ret = r == INVALID_SOCKET ? -1 : 0;
        if (r != INVALID_SOCKET) cls(r);
        break;
    }
    case B_RECV:        b->ret = U(recv)(b->s, b->buf, b->len ? b->len : 1, 0); break;
    case B_RECV_PEEK:   b->ret = U(recv)(b->s, b->buf, b->len ? b->len : 1, MSG_PEEK); break;
    case B_RECV_WAITALL:b->ret = U(recv)(b->s, b->buf, b->len ? b->len : 1, MSG_WAITALL); break;
    case B_RECVFROM:    b->ret = U(recvfrom)(b->s, b->buf, b->len ? b->len : 1, 0, (struct sockaddr *)&from, &fl); break;
    case B_WSARECV:     b->ret = U(WSARecv)(b->s, &wb, 1, &got, &f, NULL, NULL); b->bytes = (int)got; break;
    case B_WSARECVFROM: b->ret = U(WSARecvFrom)(b->s, &wb, 1, &got, &f, (struct sockaddr *)&from, &fl, NULL, NULL); b->bytes = (int)got; break;
    case B_SELECT_R:    b->ret = U(select)(0, &fds, NULL, NULL, &tv); break;
    case B_SELECT_X:    b->ret = U(select)(0, NULL, NULL, &fds, &tv); break;
    case B_POLL_IN:     b->ret = U(WSAPoll)(&pf, 1, 8000); b->flags = pf.revents; break;
    case B_SEND:        b->ret = U(send)(b->s, sendbuf, b->len, 0); break;
    case B_WSASEND:     wb.buf = sendbuf; wb.len = (ULONG)b->len; b->ret = U(WSASend)(b->s, &wb, 1, &got, 0, NULL, NULL); b->bytes = (int)got; break;
    default:            b->ret = -2; break;
    }
    b->err = werr();
    return 0;
}
static void blk_start(struct blk *b, int kind, SOCKET s, int len)
{
    memset(b, 0, sizeof *b);
    b->kind = kind; b->s = s; b->len = len; b->ret = -99;
    b->ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    b->th = CreateThread(NULL, 0, blk_main, b, 0, NULL);
    if (b->th) WaitForSingleObject(b->ready, 3000);
    SETTLE();
}
/* Wait for the blocker to end (bounded) and release its event. */
static int blk_join(struct blk *b)
{
    int ok = join(b->th, 10000);
    b->th = NULL;
    if (b->ready) { CloseHandle(b->ready); b->ready = NULL; }
    return ok;
}

/* Fill the send path of s (non-blocking) until it would block; returns bytes queued or -1 if the cap was hit. */
static long long fill_send(SOCKET s)
{
    static char chunk[8192];
    long long tot = 0;
    int r, i;
    nbio(s, 1);
    for (i = 0; i < 16384; i++) {          /* hard cap: 128 MB */
        r = snd(s, chunk, sizeof chunk);
        if (r == SOCKET_ERROR) {
            int e = werr();
            nbio(s, 0);
            return e == WSAEWOULDBLOCK ? tot : -1;
        }
        tot += r;
    }
    nbio(s, 0);
    return -1;
}
/* Small socket buffers so the send path fills quickly. */
static void small_bufs(SOCKET s)
{
    int v = 4096;
    sso(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    sso(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
}

/* Closer thread: closes a socket after a short pause (used where the test body must block itself). */
struct delayed { SOCKET s; int how; DWORD ms; HANDLE th; };
static DWORD WINAPI delayed_main(void *p)
{
    struct delayed *d = (struct delayed *)p;
    Sleep(d->ms);
    if (d->how < 0) cls(d->s); else U(shutdown)(d->s, d->how);
    return 0;
}
static void delayed_start(struct delayed *d, SOCKET s, int how, DWORD ms)
{
    d->s = s; d->how = how; d->ms = ms;
    d->th = CreateThread(NULL, 0, delayed_main, d, 0, NULL);
}
#endif
