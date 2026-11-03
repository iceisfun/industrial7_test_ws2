/* Shared helpers for the gap_03 area (thin-coverage public exports: InetPtonW, WSARecvEx, TransmitFile,
 * GetAcceptExSockaddrs, mswsock WSPStartup).
 *
 * Nothing under test is linked. Core Winsock calls go through g3_<name>() wrappers that resolve the export from
 * ws2_32.dll at call time; the SDK headers supply types and constants only. Extension functions are obtained
 * with SIO_GET_EXTENSION_FUNCTION_POINTER, the way applications do it.
 */
#ifndef G3_H
#define G3_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <ws2spi.h>

#define G3W(ret, name, params, args) static ret g3_##name params { return UIN("ws2_32.dll", name) args; }
G3W(int,    WSAStartup, (WORD v, LPWSADATA d), (v, d))
G3W(int,    WSAGetLastError, (void), ())
G3W(void,   WSASetLastError, (int e), (e))
G3W(SOCKET, socket, (int a, int t, int p), (a, t, p))
G3W(int,    closesocket, (SOCKET s), (s))
G3W(int,    bind, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
G3W(int,    listen, (SOCKET s, int b), (s, b))
G3W(int,    connect, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
G3W(SOCKET, accept, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
G3W(int,    getsockname, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
G3W(int,    send, (SOCKET s, const char *b, int l, int f), (s, b, l, f))
G3W(int,    recv, (SOCKET s, char *b, int l, int f), (s, b, l, f))
G3W(int,    sendto, (SOCKET s, const char *b, int l, int f, const struct sockaddr *a, int al), (s, b, l, f, a, al))
G3W(int,    shutdown, (SOCKET s, int h), (s, h))
G3W(int,    select, (int n, fd_set *r, fd_set *w, fd_set *e, const struct timeval *t), (n, r, w, e, t))
G3W(int,    ioctlsocket, (SOCKET s, long c, u_long *a), (s, c, a))
G3W(int,    WSAIoctl, (SOCKET s, DWORD c, LPVOID i, DWORD il, LPVOID o, DWORD ol, LPDWORD r, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, c, i, il, o, ol, r, ov, cr))

/* Single-evaluation equality (the harness macro evaluates operands twice). */
#define G3_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)a_, (unsigned long long)b_); } while (0)

static inline int g3_up(void)
{
    static int state;
    if (!state) { WSADATA d; state = (UIN("ws2_32.dll", WSAStartup) && g3_WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1; }
    return state > 0;
}
#define G3_NET() do { if (!g3_up()) { t_skip("winsock unavailable"); return; } } while (0)

static inline struct sockaddr_in g3_lo4(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;   /* 127.0.0.1 in network order */
    return a;
}
static inline SOCKET g3_tcp(void) { return g3_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
static inline SOCKET g3_udp(void) { return g3_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }

/* Loopback socket of the given type bound to an ephemeral port; *addr gets the real address. */
static inline SOCKET g3_bound(int type, struct sockaddr_in *addr)
{
    int len = sizeof *addr;
    SOCKET s = g3_socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    *addr = g3_lo4();
    if (s == INVALID_SOCKET) return s;
    if (g3_bind(s, (struct sockaddr *)addr, sizeof *addr) || g3_getsockname(s, (struct sockaddr *)addr, &len)) { g3_closesocket(s); return INVALID_SOCKET; }
    return s;
}
static inline SOCKET g3_listener(struct sockaddr_in *addr)
{
    SOCKET s = g3_bound(SOCK_STREAM, addr);
    if (s != INVALID_SOCKET && g3_listen(s, 4)) { g3_closesocket(s); return INVALID_SOCKET; }
    return s;
}
static inline int g3_readable(SOCKET s, int ms)
{
    fd_set r; struct timeval tv;
    FD_ZERO(&r); FD_SET(s, &r);
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return g3_select(0, &r, NULL, NULL, &tv) == 1;
}
/* Connected loopback stream pair: *c connecting side, *a accepted side. */
static inline int g3_pair(SOCKET *c, SOCKET *a)
{
    struct sockaddr_in addr;
    SOCKET l = g3_listener(&addr);
    *c = *a = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = g3_tcp();
    if (*c == INVALID_SOCKET || g3_connect(*c, (struct sockaddr *)&addr, sizeof addr)) goto fail;
    if (!g3_readable(l, 5000)) goto fail;
    *a = g3_accept(l, NULL, NULL);
    if (*a == INVALID_SOCKET) goto fail;
    g3_closesocket(l);
    return 1;
fail:
    if (*c != INVALID_SOCKET) g3_closesocket(*c);
    g3_closesocket(l);
    *c = *a = INVALID_SOCKET;
    return 0;
}
#define G3_PAIR(c, a) SOCKET c, a; do { G3_NET(); if (!g3_pair(&(c), &(a))) { t_skip("loopback pair unavailable"); return; } } while (0)

/* Receive up to len bytes with bounded waits; returns the count, -1 on error. */
static inline int g3_recv_all(SOCKET s, void *buf, int len, int ms)
{
    int got = 0;
    while (got < len) {
        int r;
        if (!g3_readable(s, ms)) break;
        r = g3_recv(s, (char *)buf + got, len - got, 0);
        if (r < 0) return -1;
        if (r == 0) break;
        got += r;
    }
    return got;
}

static inline void *g3_ext(SOCKET s, GUID g)
{
    void *fn = NULL; DWORD n = 0;
    if (g3_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL)) return NULL;
    return fn;
}
#endif
