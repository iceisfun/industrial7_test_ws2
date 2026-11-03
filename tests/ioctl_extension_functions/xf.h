/* Shared helpers for the ioctl_extension_functions area.
 *
 * ws2_32.dll and mswsock.dll are never linked. Every Winsock entry used below is a macro that resolves the
 * export with LoadLibrary/GetProcAddress (pinned to ws2_32.dll) and calls through the pointer; the SDK headers
 * are included only for types and constants. Extension functions are obtained the way applications do it, with
 * WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) on a live socket. */
#ifndef XF_H
#define XF_H
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
#define WSASocketW(...)             W(WSASocketW)(__VA_ARGS__)
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
#define getpeername(...)            W(getpeername)(__VA_ARGS__)
#define setsockopt(...)             W(setsockopt)(__VA_ARGS__)
#define getsockopt(...)             W(getsockopt)(__VA_ARGS__)
#define ioctlsocket(...)            W(ioctlsocket)(__VA_ARGS__)
#define select(...)                 W(select)(__VA_ARGS__)
#define WSAIoctl(...)               W(WSAIoctl)(__VA_ARGS__)
#define WSARecv(...)                W(WSARecv)(__VA_ARGS__)
#define WSASend(...)                W(WSASend)(__VA_ARGS__)
#define WSAGetOverlappedResult(...) W(WSAGetOverlappedResult)(__VA_ARGS__)
#define WSACreateEvent()            W(WSACreateEvent)()
#define WSACloseEvent(...)          W(WSACloseEvent)(__VA_ARGS__)
#define WSAResetEvent(...)          W(WSAResetEvent)(__VA_ARGS__)

#undef EXPECT_EQ   /* the harness macro evaluates operands twice; calls with side effects need one evaluation */
#define EXPECT_EQ(a, b) do { ULONG_PTR xa_ = (ULONG_PTR)(a), xb_ = (ULONG_PTR)(b); \
    t_check(xa_ == xb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)xa_, (unsigned long long)xb_); } while (0)

#define XF_POISON   0xdeadbeefUL
#define XF_LOOPBACK 0x0100007FUL   /* 127.0.0.1 in network order on a little-endian host */

static int xf_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        state = (W(WSAStartup) && WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED_NET() do { if (!xf_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

static void xf_loop4(struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = XF_LOOPBACK;
}

/* Socket kinds the lookup is repeated on. */
struct xf_kind { const char *name; int af, type, proto; };
static const struct xf_kind XF_KINDS[] = {
    {"tcp4", AF_INET,  SOCK_STREAM, IPPROTO_TCP},
    {"udp4", AF_INET,  SOCK_DGRAM,  IPPROTO_UDP},
    {"tcp6", AF_INET6, SOCK_STREAM, IPPROTO_TCP},
    {"udp6", AF_INET6, SOCK_DGRAM,  IPPROTO_UDP},
};
#define XF_NKINDS (sizeof XF_KINDS / sizeof XF_KINDS[0])

/* The extension-function GUIDs this area knows about. */
struct xf_guid { const char *name; GUID g; int documented; };
static const struct xf_guid XF_GUIDS[] = {
    {"AcceptEx",             WSAID_ACCEPTEX, 1},
    {"GetAcceptExSockaddrs", WSAID_GETACCEPTEXSOCKADDRS, 1},
    {"TransmitFile",         WSAID_TRANSMITFILE, 1},
    {"TransmitPackets",      WSAID_TRANSMITPACKETS, 1},
    {"ConnectEx",            WSAID_CONNECTEX, 1},
    {"DisconnectEx",         WSAID_DISCONNECTEX, 1},
    {"WSARecvMsg",           WSAID_WSARECVMSG, 1},
    {"WSASendMsg",           WSAID_WSASENDMSG, 1},
};
#define XF_NGUIDS (sizeof XF_GUIDS / sizeof XF_GUIDS[0])
#define XF_NCORE 7   /* the first seven entries are served by the base provider's own table */

/* Raw lookup. Returns the WSAIoctl result. */
static int xf_lookup(SOCKET s, const GUID *g, void **out, DWORD *bytes)
{
    DWORD n = (DWORD)XF_POISON;
    void *p = NULL;
    int r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)g, sizeof *g, &p, sizeof p, &n, NULL, NULL);
    if (out) *out = p;
    if (bytes) *bytes = n;
    return r;
}

/* Cached per-process lookup on a throwaway TCP socket; NULL when unavailable. */
static void *xf_fn(const GUID *g)
{
    SOCKET s;
    void *p = NULL;
    if (!xf_up()) return NULL;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return NULL;
    if (xf_lookup(s, g, &p, NULL) != 0) p = NULL;
    closesocket(s);
    return p;
}
static void *xf_fn_udp(const GUID *g)
{
    SOCKET s;
    void *p = NULL;
    if (!xf_up()) return NULL;
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return NULL;
    if (xf_lookup(s, g, &p, NULL) != 0) p = NULL;
    closesocket(s);
    return p;
}

static SOCKET xf_listener(struct sockaddr_in *addr, int backlog)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int len = sizeof *addr;
    xf_loop4(addr);
    if (s == INVALID_SOCKET) return s;
    if (bind(s, (struct sockaddr *)addr, sizeof *addr) || getsockname(s, (struct sockaddr *)addr, &len) ||
        listen(s, backlog)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static int xf_readable(SOCKET s, int ms)
{
    fd_set fds; struct timeval tv;
    FD_ZERO(&fds); FD_SET(s, &fds);
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &fds, NULL, NULL, &tv) > 0;
}

/* The test cannot continue meaningfully (and the next call would block) when nothing arrives. */
#define WAIT_READABLE(s) do { if (!xf_readable((s), 4000)) { t_check(0, __FILE__, __LINE__, "data arrives", "nothing readable within 4 s"); return; } } while (0)

/* recv() that cannot hang the run: -2 when nothing becomes readable in time. */
static int xf_recv(SOCKET s, void *buf, int len, int flags)
{
    if (!xf_readable(s, 4000)) return -2;
    return recv(s, (char *)buf, len, flags);
}

/* accept() that cannot hang the run. */
static SOCKET xf_accept(SOCKET l)
{
    if (!xf_readable(l, 4000)) return INVALID_SOCKET;
    return accept(l, NULL, NULL);
}

/* Reads up to len bytes, waiting (bounded) for each chunk. Returns the count; short on EOF/timeout. */
static int xf_read_all(SOCKET s, void *buf, int len)
{
    int got = 0;
    while (got < len) {
        int r;
        if (!xf_readable(s, 4000)) break;
        r = recv(s, (char *)buf + got, len - got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

/* A connected loopback TCP pair: cli (connecting side), srv (accepted side). */
struct xf_pair { SOCKET lst, cli, srv; struct sockaddr_in addr; };
static int xf_pair_open(struct xf_pair *p)
{
    p->lst = p->cli = p->srv = INVALID_SOCKET;
    if (!xf_up()) return 0;
    p->lst = xf_listener(&p->addr, 4);
    p->cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (p->lst == INVALID_SOCKET || p->cli == INVALID_SOCKET) return 0;
    if (connect(p->cli, (struct sockaddr *)&p->addr, sizeof p->addr)) return 0;
    p->srv = xf_accept(p->lst);
    return p->srv != INVALID_SOCKET;
}
static void xf_pair_close(struct xf_pair *p)
{
    if (p->cli != INVALID_SOCKET) closesocket(p->cli);
    if (p->srv != INVALID_SOCKET) closesocket(p->srv);
    if (p->lst != INVALID_SOCKET) closesocket(p->lst);
    p->lst = p->cli = p->srv = INVALID_SOCKET;
}
#define PAIR(p) struct xf_pair p; do { if (!xf_pair_open(&p)) { xf_pair_close(&p); t_skip("loopback pair unavailable"); return; } } while (0)

/* Overlapped helper: waits (bounded) for the event of an OVERLAPPED and reports the result. */
static BOOL xf_ov_wait(SOCKET s, WSAOVERLAPPED *ov, DWORD *n, DWORD *flags, DWORD ms)
{
    if (WaitForSingleObject(ov->hEvent, ms) != WAIT_OBJECT_0) return FALSE;
    *n = 0; *flags = 0;
    return WSAGetOverlappedResult(s, ov, n, FALSE, flags);
}

static int xf_ipv6_ok(void)
{
    static int state;
    if (!state) {
        SOCKET s = xf_up() ? socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) : INVALID_SOCKET;
        state = s == INVALID_SOCKET ? -1 : 1;
        if (s != INVALID_SOCKET) closesocket(s);
    }
    return state > 0;
}
#endif
