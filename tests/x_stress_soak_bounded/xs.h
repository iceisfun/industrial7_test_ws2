/* Shared helpers for the x_stress_soak_bounded area: bounded soak loops, thread fan-out and exact accounting
 * over loopback sockets. ws2_32.dll and mswsock.dll are never linked: every Winsock call is resolved with
 * LoadLibrary/GetProcAddress (pinned to ws2_32.dll). The SDK headers supply types and constants only.
 * Every test brackets itself with XS_BEGIN()/xs_end() so the WSAStartup count is balanced. Nothing printed
 * by this area depends on ports, handles, timing or process ids. */
#ifndef XS_H
#define XS_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define W(name) UIN("ws2_32.dll", name)
#define WSAStartup(...)        W(WSAStartup)(__VA_ARGS__)
#define WSACleanup()           W(WSACleanup)()
#define WSAGetLastError()      W(WSAGetLastError)()
#define WSASetLastError(...)   W(WSASetLastError)(__VA_ARGS__)
#define socket(...)            W(socket)(__VA_ARGS__)
#define closesocket(...)       W(closesocket)(__VA_ARGS__)
#define bind(...)              W(bind)(__VA_ARGS__)
#define listen(...)            W(listen)(__VA_ARGS__)
#define accept(...)            W(accept)(__VA_ARGS__)
#define connect(...)           W(connect)(__VA_ARGS__)
#define send(...)              W(send)(__VA_ARGS__)
#define recv(...)              W(recv)(__VA_ARGS__)
#define sendto(...)            W(sendto)(__VA_ARGS__)
#define recvfrom(...)          W(recvfrom)(__VA_ARGS__)
#define shutdown(...)          W(shutdown)(__VA_ARGS__)
#define getsockname(...)       W(getsockname)(__VA_ARGS__)
#define getsockopt(...)        W(getsockopt)(__VA_ARGS__)
#define setsockopt(...)        W(setsockopt)(__VA_ARGS__)
#define ioctlsocket(...)       W(ioctlsocket)(__VA_ARGS__)
#define select(...)            W(select)(__VA_ARGS__)
#define WSAPoll(...)           W(WSAPoll)(__VA_ARGS__)
#define WSARecv(...)           W(WSARecv)(__VA_ARGS__)
#define WSASend(...)           W(WSASend)(__VA_ARGS__)
#define WSAIoctl(...)          W(WSAIoctl)(__VA_ARGS__)
#define WSASocketW(...)        W(WSASocketW)(__VA_ARGS__)
#define WSAEventSelect(...)    W(WSAEventSelect)(__VA_ARGS__)
#define WSACreateEvent()       W(WSACreateEvent)()
#define WSACloseEvent(...)     W(WSACloseEvent)(__VA_ARGS__)
#define WSAGetOverlappedResult(...) W(WSAGetOverlappedResult)(__VA_ARGS__)

/* The harness macro evaluates its operands twice; calls with side effects need single evaluation. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR xa_ = (ULONG_PTR)(a), xb_ = (ULONG_PTR)(b); \
    t_check(xa_ == xb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)xa_, (unsigned long long)xb_); } while (0)

#define XS_WAIT_MS 8000

static int xs_begin(void)
{
    WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export: WSAStartup"); return 0; }
    if (WSAStartup(MAKEWORD(2, 2), &d) != 0) { t_skip("WSAStartup failed"); return 0; }
    return 1;
}
#define XS_BEGIN() do { if (!xs_begin()) return; } while (0)
static void xs_end(void) { WSACleanup(); }

static void xs_lo4(struct sockaddr_in *a, unsigned port_net)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007Fu;
    a->sin_port = (USHORT)port_net;
}

/* TCP listener on an ephemeral loopback port; *addr receives the bound address. */
static SOCKET xs_listener(struct sockaddr_in *addr, int backlog)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int len = sizeof *addr;
    if (s == INVALID_SOCKET) return s;
    xs_lo4(addr, 0);
    if (bind(s, (struct sockaddr *)addr, sizeof *addr) || getsockname(s, (struct sockaddr *)addr, &len) ||
        listen(s, backlog)) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

/* Bound UDP socket on an ephemeral loopback port. */
static SOCKET xs_udp(struct sockaddr_in *addr)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int len = sizeof *addr;
    struct sockaddr_in a;
    if (s == INVALID_SOCKET) return s;
    xs_lo4(&a, 0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || getsockname(s, (struct sockaddr *)&a, &len)) {
        closesocket(s); return INVALID_SOCKET;
    }
    if (addr) *addr = a;
    return s;
}

/* Connected loopback TCP pair; flags go to WSASocketW for the client (0 = plain socket()). */
static int xs_pair_ex(SOCKET *c, SOCKET *s, DWORD flags)
{
    struct sockaddr_in a;
    SOCKET l = xs_listener(&a, 4);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = flags ? WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags)
               : socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*c != INVALID_SOCKET && connect(*c, (struct sockaddr *)&a, sizeof a) == 0)
        *s = accept(l, NULL, NULL);
    closesocket(l);
    if (*s == INVALID_SOCKET) { if (*c != INVALID_SOCKET) closesocket(*c); *c = INVALID_SOCKET; return 0; }
    return 1;
}
static int xs_pair(SOCKET *c, SOCKET *s) { return xs_pair_ex(c, s, 0); }

static void xs_rcvtimeo(SOCKET s, int ms)
{
    DWORD v = ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof v);
}
static void xs_sndtimeo(SOCKET s, int ms)
{
    DWORD v = ms;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&v, sizeof v);
}

static int xs_recv_n(SOCKET s, char *b, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, b + got, n - got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}
static int xs_send_n(SOCKET s, const char *b, int n)
{
    int sent = 0;
    while (sent < n) {
        int r = send(s, b + sent, n - sent, 0);
        if (r <= 0) break;
        sent += r;
    }
    return sent;
}

/* xorshift64 byte generator with an FNV-1a running digest, for transfers checked by checksum. */
typedef struct { unsigned long long x, hash, count; } xs_gen;
static void xs_gen_init(xs_gen *g, unsigned long long seed)
{ g->x = seed ? seed : 88172645463325252ULL; g->hash = 1469598103934665603ULL; g->count = 0; }
static void xs_gen_fill(xs_gen *g, unsigned char *p, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        g->x ^= g->x << 13; g->x ^= g->x >> 7; g->x ^= g->x << 17;
        p[i] = (unsigned char)(g->x >> 24);
        g->hash = (g->hash ^ p[i]) * 1099511628211ULL;
    }
    g->count += n;
}
static void xs_gen_eat(xs_gen *g, const unsigned char *p, int n)
{
    int i;
    for (i = 0; i < n; i++) g->hash = (g->hash ^ p[i]) * 1099511628211ULL;
    g->count += n;
}

static DWORD xs_handles(void)
{
    DWORD n = 0;
    GetProcessHandleCount(GetCurrentProcess(), &n);
    return n;
}

/* Run n threads of fn(arg+i*stride); returns how many finished within the bound. Handles are closed. */
typedef struct { void *arg; HANDLE h; DWORD result; } xs_thr;
static DWORD WINAPI xs_thr_tramp(void *p);
typedef DWORD (*xs_thr_fn)(void *);
typedef struct { xs_thr_fn fn; void *arg; } xs_thr_start;
static DWORD WINAPI xs_thr_tramp(void *p)
{
    xs_thr_start *s = (xs_thr_start *)p;
    return s->fn(s->arg);
}
static int xs_run_threads(int n, xs_thr_fn fn, void *args, size_t stride, DWORD ms, DWORD *results)
{
    HANDLE h[64]; xs_thr_start st[64];
    int i, done = 0;
    if (n > 64) n = 64;
    for (i = 0; i < n; i++) {
        st[i].fn = fn; st[i].arg = (char *)args + i * stride;
        h[i] = CreateThread(NULL, 0, xs_thr_tramp, &st[i], 0, NULL);
    }
    for (i = 0; i < n; i++) {
        if (!h[i]) continue;
        if (WaitForSingleObject(h[i], ms) == WAIT_OBJECT_0) {
            done++;
            if (results) GetExitCodeThread(h[i], &results[i]);
        } else {
            TerminateThread(h[i], 0xDEAD);
        }
        CloseHandle(h[i]);
    }
    return done;
}
#endif
