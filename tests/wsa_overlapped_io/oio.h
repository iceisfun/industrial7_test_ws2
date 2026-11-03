/* Shared helpers for the wsa_overlapped_io area: lazy WSAStartup, loopback TCP/UDP socket setups,
 * overlapped bookkeeping and a few thread helpers.  Every Winsock call under test goes through U();
 * the harness only uses plain kernel32 services (events, ports, threads) which are not under test. */
#ifndef OIO_H
#define OIO_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define OIO_STATUS_SUCCESS          0x00000000u
#define OIO_STATUS_PENDING          0x00000103u
#define OIO_STATUS_BUFFER_OVERFLOW  0x80000005u
#define OIO_STATUS_CANCELLED        0xC0000120u
#define OIO_STATUS_CONN_ABORTED     0xC0000241u  /* closesocket on a pending receive */
#define OIO_STATUS_LOCAL_DISCONNECT 0xC000013Bu  /* closesocket on a pending send */
#define OIO_STATUS_INVALID_PARAM    0xC000000Du
#define OIO_SENTINEL                0xA5A5A5A5u

#ifndef MSG_PARTIAL
#define MSG_PARTIAL 0x8000
#endif
#ifndef MSG_WAITALL
#define MSG_WAITALL 0x8
#endif

/* Non-evaluating-twice comparison. */
#define OEQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)

static int oio_up_state;
static int oio_up(void)
{
    if (!oio_up_state) {
        WSADATA d;
        __typeof__(&WSAStartup) f = U(WSAStartup);
        oio_up_state = (f && f(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (oio_up_state < 0) t_skip("WSAStartup unavailable");
    return oio_up_state > 0;
}
#define UP() do { if (!oio_up()) return; } while (0)

static int WERR(void) { return U(WSAGetLastError)(); }

static struct sockaddr_in oio_lo(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f; /* 127.0.0.1 in network order */
    return a;
}

static HANDLE oio_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

static void oio_ovl(WSAOVERLAPPED *o, HANDLE ev)
{
    memset(o, 0, sizeof *o);
    o->hEvent = ev;
}
/* Fill the internal fields with a sentinel so "untouched" can be told from "written". */
static void oio_ovl_sentinel(WSAOVERLAPPED *o, HANDLE ev)
{
    oio_ovl(o, ev);
    o->Internal = OIO_SENTINEL;
    o->InternalHigh = OIO_SENTINEL;
}

/* Overlapped-capable socket. */
static SOCKET oio_sock(int type, int proto)
{
    return U(WSASocketW)(AF_INET, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED);
}
static SOCKET oio_sock_plain(int type, int proto)
{
    return U(WSASocketW)(AF_INET, type, proto, NULL, 0, 0);
}

/* Connected loopback TCP pair.  Listener is closed again.  flags: WSASocket flags for both ends. */
static int oio_pair_flags(SOCKET *cli, SOCKET *srv, DWORD flags)
{
    struct sockaddr_in a = oio_lo();
    int len = sizeof a, ok = 1;
    SOCKET lis = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    SOCKET c = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    *cli = *srv = INVALID_SOCKET;
    if (lis == INVALID_SOCKET || c == INVALID_SOCKET) ok = 0;
    if (ok && (U(bind)(lis, (struct sockaddr *)&a, sizeof a) || U(getsockname)(lis, (struct sockaddr *)&a, &len) ||
               U(listen)(lis, 1) || U(connect)(c, (struct sockaddr *)&a, sizeof a))) ok = 0;
    if (ok) {
        fd_set r;
        struct timeval tv = {5, 0};
        FD_ZERO(&r); FD_SET(lis, &r);
        if (U(select)(0, &r, NULL, NULL, &tv) == 1) {
            len = sizeof a;
            *srv = U(accept)(lis, (struct sockaddr *)&a, &len);
        }
    }
    if (lis != INVALID_SOCKET) U(closesocket)(lis);
    if (*srv == INVALID_SOCKET) {
        if (c != INVALID_SOCKET) U(closesocket)(c);
        *cli = INVALID_SOCKET;
        t_skip("could not build a loopback TCP pair");
        return 0;
    }
    *cli = c;
    return 1;
}
#define PAIR(c, s) do { if (!oio_pair_flags(&(c), &(s), WSA_FLAG_OVERLAPPED)) return; } while (0)
#define PAIR_PLAIN(c, s) do { if (!oio_pair_flags(&(c), &(s), 0)) return; } while (0)

/* Two bound loopback UDP sockets; *aa / *ba receive their addresses. */
static int oio_udp_pair(SOCKET *a, SOCKET *b, struct sockaddr_in *aa, struct sockaddr_in *ba)
{
    struct sockaddr_in x = oio_lo(), y = oio_lo();
    int l1 = sizeof x, l2 = sizeof y;
    *a = oio_sock(SOCK_DGRAM, IPPROTO_UDP);
    *b = oio_sock(SOCK_DGRAM, IPPROTO_UDP);
    if (*a == INVALID_SOCKET || *b == INVALID_SOCKET ||
        U(bind)(*a, (struct sockaddr *)&x, sizeof x) || U(bind)(*b, (struct sockaddr *)&y, sizeof y) ||
        U(getsockname)(*a, (struct sockaddr *)&x, &l1) || U(getsockname)(*b, (struct sockaddr *)&y, &l2)) {
        if (*a != INVALID_SOCKET) U(closesocket)(*a);
        if (*b != INVALID_SOCKET) U(closesocket)(*b);
        t_skip("could not build a loopback UDP pair");
        return 0;
    }
    if (aa) *aa = x;
    if (ba) *ba = y;
    return 1;
}
#define UDPAIR(a, b, aa, ba) do { if (!oio_udp_pair(&(a), &(b), &(aa), &(ba))) return; } while (0)

static void oio_close2(SOCKET a, SOCKET b)
{
    if (a != INVALID_SOCKET) U(closesocket)(a);
    if (b != INVALID_SOCKET) U(closesocket)(b);
}

static int oio_send(SOCKET s, const void *p, int n) { return U(send)(s, (const char *)p, n, 0); }

/* Bounded wait for a handle; returns WaitForSingleObject result. */
#define OIO_WAIT 5000
static DWORD oio_wait(HANDLE h, DWORD ms) { return WaitForSingleObject(h, ms); }

/* Queue a receive of `len` bytes into buf on an overlapped socket. */
static int oio_post_recv(SOCKET s, void *buf, ULONG len, WSAOVERLAPPED *o, DWORD *flags)
{
    WSABUF b;
    b.buf = (CHAR *)buf; b.len = len;
    *flags = 0;
    return U(WSARecv)(s, &b, 1, NULL, flags, o, NULL);
}

/* After a posted receive/send: wait (bounded) until complete, fetch the result.  Returns the
 * WSAGetOverlappedResult value; *bytes, *fl, *err as reported. */
static BOOL oio_finish(SOCKET s, WSAOVERLAPPED *o, DWORD *bytes, DWORD *fl, int *err)
{
    BOOL r;
    *bytes = 0xFFFFFFF0; *fl = 0xFFFFFFF0;
    r = U(WSAGetOverlappedResult)(s, o, bytes, TRUE, fl);
    *err = r ? 0 : WERR();
    return r;
}

/* Thread helper. */
typedef struct { void (*fn)(void *); void *arg; } oio_thr;
static DWORD WINAPI oio_thr_main(LPVOID p) { oio_thr *t = (oio_thr *)p; t->fn(t->arg); return 0; }
static HANDLE oio_spawn(oio_thr *t, void (*fn)(void *), void *arg)
{
    t->fn = fn; t->arg = arg;
    return CreateThread(NULL, 0, oio_thr_main, t, 0, NULL);
}
static void oio_join(HANDLE h)
{
    if (!h) return;
    if (WaitForSingleObject(h, 10000) != WAIT_OBJECT_0) TerminateThread(h, 1);
    CloseHandle(h);
}

/* Shared state used by completion routines. */
typedef struct {
    volatile LONG calls;
    DWORD err, bytes, flags, tid;
    LPWSAOVERLAPPED ov;
    DWORD order[8];
} oio_cr_state;
static oio_cr_state g_cr;
static void CALLBACK oio_cr(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD flags)
{
    LONG i = InterlockedIncrement(&g_cr.calls);
    g_cr.tid = GetCurrentThreadId(); g_cr.err = err; g_cr.bytes = bytes; g_cr.ov = ov; g_cr.flags = flags;
    if (i >= 1 && i <= 8) g_cr.order[i - 1] = (DWORD)(ULONG_PTR)ov->hEvent;
}
static void oio_cr_reset(void) { memset((void *)&g_cr, 0, sizeof g_cr); }

#endif
