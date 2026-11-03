/* Shared helpers for the lift_08 area (IPv6-only option, message sends, receives, polling, connect, AcceptEx).
 *
 * ws2_32 is never linked.  Every Winsock entry point used by the tests is resolved with
 * LoadLibrary/GetProcAddress through U() and wrapped in a tiny w_<name>() forwarder so the test bodies
 * stay readable.  Extension functions (AcceptEx, ConnectEx, WSASendMsg ...) come from WSAIoctl.
 */
#ifndef L8_H
#define L8_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define DEFW(ret, name, params, args) static ret w_##name params { return U(name) args; }

DEFW(int,    WSAStartup, (WORD v, LPWSADATA d), (v, d))
DEFW(int,    WSAGetLastError, (void), ())
DEFW(void,   WSASetLastError, (int e), (e))
DEFW(SOCKET, socket, (int a, int t, int p), (a, t, p))
DEFW(SOCKET, WSASocketW, (int a, int t, int p, LPWSAPROTOCOL_INFOW i, GROUP g, DWORD f), (a, t, p, i, g, f))
DEFW(int,    closesocket, (SOCKET s), (s))
DEFW(int,    bind, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
DEFW(int,    listen, (SOCKET s, int b), (s, b))
DEFW(int,    connect, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
DEFW(SOCKET, accept, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
DEFW(int,    getsockname, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
DEFW(int,    getsockopt, (SOCKET s, int lv, int n, char *v, int *l), (s, lv, n, v, l))
DEFW(int,    setsockopt, (SOCKET s, int lv, int n, const char *v, int l), (s, lv, n, v, l))
DEFW(int,    ioctlsocket, (SOCKET s, long c, u_long *a), (s, c, a))
DEFW(int,    send, (SOCKET s, const char *b, int l, int f), (s, b, l, f))
DEFW(int,    sendto, (SOCKET s, const char *b, int l, int f, const struct sockaddr *a, int al), (s, b, l, f, a, al))
DEFW(int,    recv, (SOCKET s, char *b, int l, int f), (s, b, l, f))
DEFW(int,    recvfrom, (SOCKET s, char *b, int l, int f, struct sockaddr *a, int *al), (s, b, l, f, a, al))
DEFW(int,    shutdown, (SOCKET s, int h), (s, h))
DEFW(int,    select, (int n, fd_set *r, fd_set *w, fd_set *e, const struct timeval *t), (n, r, w, e, t))
DEFW(int,    WSAIoctl, (SOCKET s, DWORD c, LPVOID i, DWORD il, LPVOID o, DWORD ol, LPDWORD r, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, c, i, il, o, ol, r, ov, cr))
DEFW(int,    WSASendTo, (SOCKET s, LPWSABUF b, DWORD n, LPDWORD sent, DWORD f, const struct sockaddr *a, int al, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, b, n, sent, f, a, al, ov, cr))
DEFW(int,    WSARecv, (SOCKET s, LPWSABUF b, DWORD n, LPDWORD got, LPDWORD f, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, b, n, got, f, ov, cr))
DEFW(int,    WSARecvFrom, (SOCKET s, LPWSABUF b, DWORD n, LPDWORD got, LPDWORD f, struct sockaddr *a, LPINT al, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, b, n, got, f, a, al, ov, cr))
DEFW(BOOL,   WSAGetOverlappedResult, (SOCKET s, LPWSAOVERLAPPED ov, LPDWORD len, BOOL wait, LPDWORD fl), (s, ov, len, wait, fl))
DEFW(int,    WSAPoll, (LPWSAPOLLFD f, ULONG n, INT to), (f, n, to))
DEFW(SOCKET, WSAAccept, (SOCKET s, struct sockaddr *a, LPINT l, LPCONDITIONPROC c, DWORD_PTR d), (s, a, l, c, d))

/* Single-evaluation equality check (the harness macro evaluates its arguments twice). */
#define L8_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)

#define XS_PENDING          ((ULONG)0x00000103)
#define XS_BUFFER_TOO_SMALL ((ULONG)0xC0000023)
#define XS_SUCCESS          ((ULONG)0)

#define NEED_WS() do { if (!l8_ws_up()) { t_skip("ws2_32 unavailable"); return; } } while (0)
static inline int l8_ws_up(void)
{
    static int state;   /* 0 unknown, 1 up, -1 failed */
    if (!state) {
        WSADATA d;
        state = (U(WSAStartup) && w_WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}

static inline u_short l8_ns(u_short v) { return (u_short)((v << 8) | (v >> 8)); }

/* 127.0.0.1, port 0 (ephemeral). */
static inline struct sockaddr_in l8_lo4(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;   /* network order 127.0.0.1 */
    return a;
}

static inline int l8_nonblocking(SOCKET s, BOOL on)
{
    u_long v = on ? 1 : 0;
    return w_ioctlsocket(s, FIONBIO, &v);
}

/* Bound (loopback, ephemeral) and listening TCP socket; *addr receives the real address. */
static inline SOCKET l8_listener(struct sockaddr_in *addr, int backlog)
{
    int len = sizeof *addr;
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    *addr = l8_lo4();
    CHECK(s != INVALID_SOCKET);
    CHECK(w_bind(s, (struct sockaddr *)addr, sizeof *addr) == 0);
    CHECK(w_getsockname(s, (struct sockaddr *)addr, &len) == 0);
    if (backlog) CHECK(w_listen(s, backlog) == 0);
    return s;
}

/* A loopback address nothing listens on: an ephemeral port that was bound and released. */
static inline struct sockaddr_in l8_dead_port(void)
{
    struct sockaddr_in a;
    SOCKET s = l8_listener(&a, 0);
    w_closesocket(s);
    return a;
}

/* Connected TCP pair over loopback. */
static inline void l8_pair(SOCKET *c, SOCKET *a, DWORD flags)
{
    struct sockaddr_in addr;
    SOCKET l = l8_listener(&addr, 1);
    *c = w_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    CHECK(*c != INVALID_SOCKET);
    CHECK(w_connect(*c, (struct sockaddr *)&addr, sizeof addr) == 0);
    *a = w_accept(l, NULL, NULL);
    CHECK(*a != INVALID_SOCKET);
    w_closesocket(l);
}

/* Receive through an overlapped WSARecv and a bounded wait; returns bytes or -1. */
static inline int l8_wait_recv(SOCKET s, void *buf, int len)
{
    OVERLAPPED ov;
    WSABUF wb;
    DWORD got = 0, fl = 0;
    int r;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = len;
    r = w_WSARecv(s, &wb, 1, &got, &fl, &ov, NULL);
    if (r == -1 && w_WSAGetLastError() == ERROR_IO_PENDING) {
        r = WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0 ? 0 : -1;
        if (r == 0) r = w_WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl) ? 0 : -1;
        else CancelIo((HANDLE)s);
    }
    CloseHandle(ov.hEvent);
    return r == 0 ? (int)got : -1;
}

/* Poll one socket (timeout 1s) and compare the returned events with `expect`. */
static inline void l8_poll_expect(const char *file, int line, SOCKET s, short mask, short expect)
{
    WSAPOLLFD p;
    int r;
    p.fd = s; p.events = mask; p.revents = (short)0xdead;
    r = w_WSAPoll(&p, 1, 1000);
    t_check(r == (p.revents ? 1 : 0), file, line, "WSAPoll count matches revents", "ret %d revents 0x%x", r, p.revents);
    t_check(p.revents == expect, file, line, "WSAPoll revents", "got 0x%x want 0x%x", p.revents, expect);
}
#define POLL_ALL (POLLRDNORM | POLLRDBAND | POLLWRNORM)
#define POLL_IS(s, expect)          l8_poll_expect(__FILE__, __LINE__, (s), POLL_ALL, (expect))
#define POLL_MASK_IS(s, mask, expect) l8_poll_expect(__FILE__, __LINE__, (s), (mask), (expect))

/* Extension-function lookup through WSAIoctl; returns the pointer or NULL. */
static inline void *l8_ext(SOCKET s, GUID g)
{
    void *fn = NULL;
    DWORD ret = 0;
    if (w_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &ret, NULL, NULL) != 0)
        return NULL;
    return fn;
}

static void WINAPI l8_apc_count(ULONG_PTR p) { ++*(volatile unsigned *)p; }

/* Zero-linger close: sends a reset on the connection. */
static inline void l8_close_rst(SOCKET s)
{
    struct linger lg;
    lg.l_onoff = 1; lg.l_linger = 0;
    CHECK(w_setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg) == 0);
    w_closesocket(s);
}

static inline int l8_v6_available(void)
{
    SOCKET s = w_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    w_closesocket(s);
    return 1;
}
#endif
