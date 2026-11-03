/* Shared helpers for the connect_paths area.
 *
 * Nothing here links the Winsock DLLs: every call goes through LoadLibrary -> GetProcAddress (U / UIN)
 * and is wrapped in a small cp_<name>() forwarder.  All destinations are loopback listeners that the
 * tests create on an ephemeral port; "closed port" destinations are ports that were bound and released.
 */
#ifndef CP_H
#define CP_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010
#endif
#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME 0x700C
#endif
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

#define DEFW(ret, name, params, args) static ret cp_##name params { return U(name) args; }

DEFW(int,    WSAStartup, (WORD v, LPWSADATA d), (v, d))
DEFW(int,    WSAGetLastError, (void), ())
DEFW(void,   WSASetLastError, (int e), (e))
DEFW(SOCKET, socket, (int a, int t, int p), (a, t, p))
DEFW(int,    closesocket, (SOCKET s), (s))
DEFW(int,    bind, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
DEFW(int,    listen, (SOCKET s, int b), (s, b))
DEFW(int,    connect, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
DEFW(int,    WSAConnect, (SOCKET s, const struct sockaddr *a, int l, LPWSABUF cd, LPWSABUF ce, LPQOS sq, LPQOS gq), (s, a, l, cd, ce, sq, gq))
DEFW(SOCKET, accept, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
DEFW(int,    getsockname, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
DEFW(int,    getpeername, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
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
DEFW(WSAEVENT, WSACreateEvent, (void), ())
DEFW(BOOL,   WSACloseEvent, (WSAEVENT e), (e))
DEFW(BOOL,   WSAResetEvent, (WSAEVENT e), (e))
DEFW(int,    WSAEventSelect, (SOCKET s, WSAEVENT e, long m), (s, e, m))
DEFW(int,    WSAEnumNetworkEvents, (SOCKET s, WSAEVENT e, LPWSANETWORKEVENTS n), (s, e, n))
DEFW(DWORD,  WSAWaitForMultipleEvents, (DWORD n, const WSAEVENT *e, BOOL all, DWORD ms, BOOL al), (n, e, all, ms, al))

/* Single-evaluation equality check (the harness macro evaluates its arguments twice). */
#define CP_EQ(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got %lld want %lld", a_, b_); } while (0)
#define CP_NE(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_check(a_ != b_, __FILE__, __LINE__, #a " != " #b, "got %lld", a_); } while (0)

static inline int cp_ws_up(void)
{
    static int state;   /* 0 unknown, 1 up, -1 failed */
    if (!state) {
        WSADATA d;
        state = (U(WSAStartup) && cp_WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED() do { if (!cp_ws_up()) { t_skip("ws2_32 unavailable"); return; } } while (0)

/* Result of a failing call: the return value must be the failure sentinel and the error the wanted one. */
#define CP_FAILS(call, want) do { cp_WSASetLastError(0); int r_ = (call); \
    t_check(r_ == SOCKET_ERROR, __FILE__, __LINE__, #call " fails", "returned %d", r_); \
    int e_ = cp_WSAGetLastError(); \
    t_check(e_ == (want), __FILE__, __LINE__, #call " error == " #want, "got %d want %d", e_, (int)(want)); } while (0)

static inline u_long cp_htonl(u_long v) { return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | (v >> 24); }
static inline u_short cp_ns(u_short v) { return (u_short)((v << 8) | (v >> 8)); }

static inline struct sockaddr_in cp_lo4(u_short port_net)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = cp_htonl(INADDR_LOOPBACK);
    a.sin_port = port_net;
    return a;
}
static inline struct sockaddr_in6 cp_lo6(u_short port_net)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr.u.Byte[15] = 1;
    a.sin6_port = port_net;
    return a;
}

/* A bound (and, when backlog > 0, listening) loopback TCP socket; *addr receives its address. */
static SOCKET cp_listener(struct sockaddr_in *addr, int backlog)
{
    if (!cp_ws_up()) return INVALID_SOCKET;
    struct sockaddr_in a = cp_lo4(0);
    int n = sizeof a;
    SOCKET s = cp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    if (cp_bind(s, (struct sockaddr *)&a, sizeof a) || cp_getsockname(s, (struct sockaddr *)&a, &n) ||
        (backlog > 0 && cp_listen(s, backlog))) {
        cp_closesocket(s);
        return INVALID_SOCKET;
    }
    *addr = a;
    return s;
}
static SOCKET cp_listener6(struct sockaddr_in6 *addr, int backlog)
{
    if (!cp_ws_up()) return INVALID_SOCKET;
    struct sockaddr_in6 a = cp_lo6(0);
    int n = sizeof a;
    SOCKET s = cp_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    if (cp_bind(s, (struct sockaddr *)&a, sizeof a) || cp_getsockname(s, (struct sockaddr *)&a, &n) ||
        (backlog > 0 && cp_listen(s, backlog))) {
        cp_closesocket(s);
        return INVALID_SOCKET;
    }
    *addr = a;
    return s;
}
/* A loopback address with nothing listening: a port that was bound and released. */
static int cp_dead_port(struct sockaddr_in *addr)
{
    SOCKET s = cp_listener(addr, 0);
    if (s == INVALID_SOCKET) return 0;
    cp_closesocket(s);
    return 1;
}
static int cp_dead_port6(struct sockaddr_in6 *addr)
{
    SOCKET s = cp_listener6(addr, 0);
    if (s == INVALID_SOCKET) return 0;
    cp_closesocket(s);
    return 1;
}
static SOCKET cp_udp_bound(struct sockaddr_in *addr)
{
    if (!cp_ws_up()) return INVALID_SOCKET;
    struct sockaddr_in a = cp_lo4(0);
    int n = sizeof a;
    SOCKET s = cp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return s;
    if (cp_bind(s, (struct sockaddr *)&a, sizeof a) || cp_getsockname(s, (struct sockaddr *)&a, &n)) {
        cp_closesocket(s);
        return INVALID_SOCKET;
    }
    *addr = a;
    return s;
}

static int cp_nb(SOCKET s, int on) { u_long v = on ? 1 : 0; return cp_ioctlsocket(s, FIONBIO, &v); }

static int cp_in(const fd_set *s, SOCKET k)
{
    u_int i;
    for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == k) return 1;
    return 0;
}
#define CP_R 1
#define CP_W 2
#define CP_X 4
/* Wait up to ms for one socket; returns a mask of CP_R/CP_W/CP_X (0 on timeout). */
static int cp_wait(SOCKET s, int want, DWORD ms)
{
    fd_set r, w, x;
    struct timeval tv;
    int n, m = 0;
    r.fd_count = w.fd_count = x.fd_count = 0;
    if (want & CP_R) { r.fd_array[0] = s; r.fd_count = 1; }
    if (want & CP_W) { w.fd_array[0] = s; w.fd_count = 1; }
    if (want & CP_X) { x.fd_array[0] = s; x.fd_count = 1; }
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    n = cp_select(0, (want & CP_R) ? &r : NULL, (want & CP_W) ? &w : NULL, (want & CP_X) ? &x : NULL, &tv);
    if (n <= 0) return 0;
    if (cp_in(&r, s)) m |= CP_R;
    if (cp_in(&w, s)) m |= CP_W;
    if (cp_in(&x, s)) m |= CP_X;
    return m;
}
static int cp_so_error(SOCKET s)
{
    int v = -1, n = sizeof v;
    if (cp_getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&v, &n)) return -2;
    return v;
}
static int cp_accept_one(SOCKET l, SOCKET *out, DWORD ms)
{
    if (!(cp_wait(l, CP_R, ms) & CP_R)) return 0;
    *out = cp_accept(l, NULL, NULL);
    return *out != INVALID_SOCKET;
}
/* Connected TCP pair over loopback; *cli is the connecting side, *srv the accepted side. */
static int cp_pair(SOCKET *cli, SOCKET *srv)
{
    struct sockaddr_in a;
    SOCKET l = cp_listener(&a, 1);
    int ok = 0;
    *cli = *srv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *cli = cp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*cli != INVALID_SOCKET && cp_connect(*cli, (struct sockaddr *)&a, sizeof a) == 0)
        ok = cp_accept_one(l, srv, 3000);
    cp_closesocket(l);
    if (!ok) { cp_closesocket(*cli); *cli = INVALID_SOCKET; }
    return ok;
}
static int cp_same_addr(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_family == b->sin_family && a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
}
static int cp_peer_is(SOCKET s, const struct sockaddr_in *want)
{
    struct sockaddr_in p; int n = sizeof p;
    memset(&p, 0, sizeof p);
    if (cp_getpeername(s, (struct sockaddr *)&p, &n)) return 0;
    return n == sizeof p && cp_same_addr(&p, want);
}
/* getpeername() error, or 0 when it succeeds. */
static int cp_peer_err(SOCKET s)
{
    struct sockaddr_in p; int n = sizeof p;
    cp_WSASetLastError(0);
    if (cp_getpeername(s, (struct sockaddr *)&p, &n) == 0) return 0;
    return cp_WSAGetLastError();
}
#endif
