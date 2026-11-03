/* Shared helpers for the lift_09 area: connection teardown, extension-function calls,
 * overlapped completion and completion-port behaviour on loopback TCP/UDP sockets.
 *
 * ws2_32.dll is never linked. Every Winsock entry used below is a macro that resolves the export
 * with LoadLibrary/GetProcAddress (pinned to ws2_32.dll) and calls through the pointer. The SDK headers
 * are included only for type and constant definitions. */
#ifndef H9_H
#define H9_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define W(name) UIN("ws2_32.dll", name)
#define WSAStartup(...)             W(WSAStartup)(__VA_ARGS__)
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
#define getpeername(...)            W(getpeername)(__VA_ARGS__)
#define setsockopt(...)             W(setsockopt)(__VA_ARGS__)
#define ioctlsocket(...)            W(ioctlsocket)(__VA_ARGS__)
#define select(...)                 W(select)(__VA_ARGS__)
#define WSAIoctl(...)               W(WSAIoctl)(__VA_ARGS__)
#define WSARecv(...)                W(WSARecv)(__VA_ARGS__)
#define WSASend(...)                W(WSASend)(__VA_ARGS__)
#define WSASocketW(...)             W(WSASocketW)(__VA_ARGS__)
#define WSASocketA(...)             W(WSASocketA)(__VA_ARGS__)
#define WSADuplicateSocketA(...)    W(WSADuplicateSocketA)(__VA_ARGS__)
#define WSAGetOverlappedResult(...) W(WSAGetOverlappedResult)(__VA_ARGS__)
#define WSAEventSelect(...)         W(WSAEventSelect)(__VA_ARGS__)
#define WSACreateEvent()            W(WSACreateEvent)()
#define WSACloseEvent(...)          W(WSACloseEvent)(__VA_ARGS__)

/* The harness EXPECT_EQ evaluates its operands twice; calls with side effects need a single evaluation. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR h9a_ = (ULONG_PTR)(a), h9b_ = (ULONG_PTR)(b); \
    t_check(h9a_ == h9b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)h9a_, (unsigned long long)h9b_); } while (0)

#define NT_SUCCESS_STATUS   ((ULONG)0x00000000)
#define NT_CANCELLED        ((ULONG)0xC0000120)
#define NT_CONN_ABORTED     ((ULONG)0xC0000241)
#define LOOPBACK_ADDR       0x0100007FUL    /* 127.0.0.1 in network byte order on a little-endian host */
#define POISON              0xdeadbeef

/* Starts Winsock once; every test begins with NEED_NET(). */
static int h9_up(void)
{
    static int state;                    /* 0 untried, 1 up, -1 failed */
    if (!state) {
        WSADATA d;
        state = (W(WSAStartup) && WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED_NET() do { if (!h9_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

static unsigned short h9_port(const struct sockaddr_in *a) { return (unsigned short)((a->sin_port >> 8) | (a->sin_port << 8)); }

static void h9_loop_addr(struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = LOOPBACK_ADDR;
}

static int h9_nonblock(SOCKET s, int nonblocking)
{
    u_long v = nonblocking ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &v);
}

/* True if the last-error is either untouched (poison) or zero: a successful call may do either. */
static int h9_err_clean(void)
{
    int e = WSAGetLastError();
    return e == 0 || (DWORD)e == POISON;
}

/* A bound-and-listening loopback TCP socket on an ephemeral port; its address is returned in *addr. */
static SOCKET h9_listener(struct sockaddr_in *addr, int backlog, int type)
{
    SOCKET s = socket(AF_INET, type, 0);
    int len = sizeof *addr;
    h9_loop_addr(addr);
    if (s == INVALID_SOCKET) return s;
    if (bind(s, (struct sockaddr *)addr, sizeof *addr) || getsockname(s, (struct sockaddr *)addr, &len)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (type == SOCK_STREAM && backlog > 0 && listen(s, backlog)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/* Waits up to ms for s to be readable (data, EOF, reset or a pending connection). */
static int h9_readable(SOCKET s, int ms)
{
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &fds, NULL, NULL, &tv) > 0;
}

/* recv() that waits (bounded) for readiness first so a regression cannot hang the run.
 * Returns -2 if nothing became readable in time. */
static int h9_recv(SOCKET s, void *buf, int len)
{
    if (!h9_readable(s, 4000)) return -2;
    return recv(s, (char *)buf, len, 0);
}

/* Reads exactly len bytes (or fewer on EOF/timeout/error); returns the count read, or -1 if the
 * first receive failed. */
static int h9_recv_all(SOCKET s, void *buf, int len)
{
    int got = 0;
    while (got < len) {
        int r = h9_recv(s, (char *)buf + got, len - got);
        if (r <= 0) return got ? got : (r < 0 ? -1 : 0);
        got += r;
    }
    return got;
}

static SOCKET h9_accept(SOCKET lst)
{
    if (!h9_readable(lst, 4000)) return INVALID_SOCKET;
    return accept(lst, NULL, NULL);
}

/* Connected loopback TCP pair; both ends are overlapped-capable (WSA_FLAG_OVERLAPPED). */
static int h9_pair_flags(SOCKET *c, SOCKET *s, DWORD flags)
{
    struct sockaddr_in a;
    SOCKET l = h9_listener(&a, 1, SOCK_STREAM);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    if (*c != INVALID_SOCKET && connect(*c, (struct sockaddr *)&a, sizeof a) == 0)
        *s = h9_accept(l);
    closesocket(l);
    if (*s == INVALID_SOCKET) {
        if (*c != INVALID_SOCKET) closesocket(*c);
        *c = INVALID_SOCKET;
        return 0;
    }
    return 1;
}
static int h9_pair(SOCKET *c, SOCKET *s) { return h9_pair_flags(c, s, WSA_FLAG_OVERLAPPED); }

/* Connected pair plus the listener's address (listener closed). */
#define NEED_PAIR(c, s) do { if (!h9_pair(&(c), &(s))) { t_skip("could not build a loopback TCP pair"); return; } } while (0)

/* Zero-timeout linger then close: the stack aborts the connection (RST) instead of a graceful FIN. */
static void h9_rst_close(SOCKET s)
{
    struct linger lg;
    lg.l_onoff = 1;
    lg.l_linger = 0;
    setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
    closesocket(s);
}

/* Extension function lookup through SIO_GET_EXTENSION_FUNCTION_POINTER. */
static void *h9_ext(SOCKET s, GUID guid)
{
    void *fn = NULL;
    DWORD n = 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof guid, &fn, sizeof fn, &n, NULL, NULL))
        return NULL;
    return fn;
}

/* Completion-port dequeue wrapper: reports the result, last error and the three out values. */
struct h9_dq { BOOL ok; DWORD err; DWORD bytes; ULONG_PTR key; OVERLAPPED *ov; };
static void h9_dequeue(HANDLE port, DWORD ms, struct h9_dq *r)
{
    SetLastError(POISON);
    r->key = POISON;
    r->bytes = POISON;
    r->ov = (OVERLAPPED *)(ULONG_PTR)POISON;
    r->ok = GetQueuedCompletionStatus(port, &r->bytes, &r->key, &r->ov, ms);
    r->err = GetLastError();
}
/* The queue must now be empty: timeout, out values untouched. */
#define CHECK_QUEUE_EMPTY(port) do { struct h9_dq q_; h9_dequeue((port), 200, &q_); \
    CHECK(!q_.ok); CHECK(q_.err == WAIT_TIMEOUT); CHECK(q_.key == POISON); \
    CHECK(q_.bytes == POISON); CHECK(q_.ov == NULL); } while (0)

/* APC bookkeeping for alertable completion routines. */
static DWORD h9_apc_error, h9_apc_size, h9_apc_flags;
static OVERLAPPED *h9_apc_ov;
static unsigned h9_apc_count;
static void WINAPI h9_apc(DWORD error, DWORD size, OVERLAPPED *ov, DWORD flags)
{
    h9_apc_count++;
    h9_apc_error = error;
    h9_apc_size = size;
    h9_apc_ov = ov;
    h9_apc_flags = flags;
}
#endif
