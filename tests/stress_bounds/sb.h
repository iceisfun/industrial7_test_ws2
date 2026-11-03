/* Shared helpers for the stress_bounds area: bounded loops over sockets, handles, events and buffers.
 * ws2_32.dll is never linked: every Winsock call resolves through LoadLibrary/GetProcAddress pinned to
 * ws2_32.dll. The SDK headers provide types and constants only. Each test brackets itself with
 * sb_begin()/sb_end() so the process-wide WSAStartup count is zero outside a test. */
#ifndef SB_H
#define SB_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define W(name) UIN("ws2_32.dll", name)
#define WSAStartup(...)             W(WSAStartup)(__VA_ARGS__)
#define WSACleanup()                W(WSACleanup)()
#define WSAGetLastError()           W(WSAGetLastError)()
#define WSASetLastError(...)        W(WSASetLastError)(__VA_ARGS__)
#define socket(...)                 W(socket)(__VA_ARGS__)
#define closesocket(...)            W(closesocket)(__VA_ARGS__)
#define bind(...)                   W(bind)(__VA_ARGS__)
#define listen(...)                 W(listen)(__VA_ARGS__)
#define accept(...)                 W(accept)(__VA_ARGS__)
#define connect(...)                W(connect)(__VA_ARGS__)
#define send(...)                   W(send)(__VA_ARGS__)
#define recv(...)                   W(recv)(__VA_ARGS__)
#define sendto(...)                 W(sendto)(__VA_ARGS__)
#define recvfrom(...)               W(recvfrom)(__VA_ARGS__)
#define shutdown(...)               W(shutdown)(__VA_ARGS__)
#define getsockname(...)            W(getsockname)(__VA_ARGS__)
#define getsockopt(...)             W(getsockopt)(__VA_ARGS__)
#define setsockopt(...)             W(setsockopt)(__VA_ARGS__)
#define ioctlsocket(...)            W(ioctlsocket)(__VA_ARGS__)
#define select(...)                 W(select)(__VA_ARGS__)
#define WSAPoll(...)                W(WSAPoll)(__VA_ARGS__)
#define WSARecv(...)                W(WSARecv)(__VA_ARGS__)
#define WSASend(...)                W(WSASend)(__VA_ARGS__)
#define WSARecvFrom(...)            W(WSARecvFrom)(__VA_ARGS__)
#define WSACreateEvent()            W(WSACreateEvent)()
#define WSACloseEvent(...)          W(WSACloseEvent)(__VA_ARGS__)
#define WSASetEvent(...)            W(WSASetEvent)(__VA_ARGS__)
#define WSAResetEvent(...)          W(WSAResetEvent)(__VA_ARGS__)
#define WSAEventSelect(...)         W(WSAEventSelect)(__VA_ARGS__)
#define WSAWaitForMultipleEvents(...) W(WSAWaitForMultipleEvents)(__VA_ARGS__)
#define WSAGetOverlappedResult(...) W(WSAGetOverlappedResult)(__VA_ARGS__)
#define WSASocketW(...)             W(WSASocketW)(__VA_ARGS__)

/* The harness EXPECT_EQ evaluates operands twice; calls with side effects need single evaluation. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR sba_ = (ULONG_PTR)(a), sbb_ = (ULONG_PTR)(b); \
    t_check(sba_ == sbb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)sba_, (unsigned long long)sbb_); } while (0)

#define SB_WAIT_MS 5000

static int sb_begin(void)
{
    WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export: WSAStartup"); return 0; }
    if (WSAStartup(MAKEWORD(2, 2), &d) != 0) { t_skip("WSAStartup failed"); return 0; }
    return 1;
}
#define SB_BEGIN() do { if (!sb_begin()) return; } while (0)
static void sb_end(void) { WSACleanup(); }

static void sb_loopback(struct sockaddr_in *a, unsigned port_net)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007Fu;
    a->sin_port = (USHORT)port_net;
}

/* Listener on an ephemeral loopback port; *addr receives the bound address. */
static SOCKET sb_listener(struct sockaddr_in *addr, int backlog)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int len = sizeof *addr;
    if (s == INVALID_SOCKET) return s;
    sb_loopback(addr, 0);
    if (bind(s, (struct sockaddr *)addr, sizeof *addr) || getsockname(s, (struct sockaddr *)addr, &len) ||
        listen(s, backlog)) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

/* Bound UDP socket on an ephemeral loopback port. */
static SOCKET sb_udp(struct sockaddr_in *addr)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int len = sizeof *addr;
    struct sockaddr_in a;
    if (s == INVALID_SOCKET) return s;
    sb_loopback(&a, 0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || getsockname(s, (struct sockaddr *)&a, &len)) {
        closesocket(s); return INVALID_SOCKET;
    }
    if (addr) *addr = a;
    return s;
}

/* Connected loopback TCP pair: *c client, *s accepted server side. Returns 1 on success. */
static int sb_pair(SOCKET *c, SOCKET *s)
{
    struct sockaddr_in a;
    SOCKET l = sb_listener(&a, 4);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*c != INVALID_SOCKET && connect(*c, (struct sockaddr *)&a, sizeof a) == 0)
        *s = accept(l, NULL, NULL);
    closesocket(l);
    if (*s == INVALID_SOCKET) { if (*c != INVALID_SOCKET) closesocket(*c); *c = INVALID_SOCKET; return 0; }
    return 1;
}
#define NEED_PAIR(c, s) do { if (!sb_pair(&(c), &(s))) { t_skip("cannot build loopback pair"); sb_end(); return; } } while (0)

static void sb_close2(SOCKET a, SOCKET b)
{
    if (a != INVALID_SOCKET) closesocket(a);
    if (b != INVALID_SOCKET) closesocket(b);
}

/* readiness by select with a bounded timeout: 1 readable, 0 not */
static int sb_readable(SOCKET s, int ms)
{
    fd_set r; struct timeval tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &r, NULL, NULL, &tv) == 1;
}

/* Receive exactly n bytes (blocking, bounded by SO_RCVTIMEO set by caller or data arrival). */
static int sb_recv_n(SOCKET s, char *b, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, b + got, n - got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

static void sb_rcvtimeo(SOCKET s, int ms)
{
    DWORD v = ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof v);
}

/* deterministic byte stream: xorshift64 */
typedef struct { unsigned long long x; unsigned long long hash; unsigned long long count; } sb_stream;
static void sb_stream_init(sb_stream *g, unsigned long long seed)
{ g->x = seed ? seed : 88172645463325252ULL; g->hash = 1469598103934665603ULL; g->count = 0; }
static void sb_stream_fill(sb_stream *g, unsigned char *p, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        g->x ^= g->x << 13; g->x ^= g->x >> 7; g->x ^= g->x << 17;
        p[i] = (unsigned char)(g->x >> 24);
        g->hash = (g->hash ^ p[i]) * 1099511628211ULL;
    }
    g->count += n;
}
static void sb_stream_eat(sb_stream *g, const unsigned char *p, int n)
{
    int i;
    for (i = 0; i < n; i++) g->hash = (g->hash ^ p[i]) * 1099511628211ULL;
    g->count += n;
}

static DWORD sb_handle_count(void)
{
    DWORD n = 0;
    GetProcessHandleCount(GetCurrentProcess(), &n);
    return n;
}
#endif
