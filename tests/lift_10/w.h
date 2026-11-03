/* Shared helpers for the lift_10 area: Winsock completion-port behaviour, extension functions, IOCTLs, bind rules.
 * Every ws2_32 entry point is resolved once through LoadLibrary/GetProcAddress (U) into the p_<name> pointers
 * below; the DLL is never linked.  Kernel32 services (completion ports, events, threads, windows) are called
 * directly: they are not under test.
 */
#ifndef LIFT10_W_H
#define LIFT10_W_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <ntstatus.h>

#define W_FUNCS(X) \
    X(WSAStartup) X(socket) X(closesocket) X(bind) X(listen) X(accept) X(connect) \
    X(getsockname) X(getpeername) X(send) X(recv) X(shutdown) X(select) X(ioctlsocket) \
    X(WSAIoctl) X(WSAGetLastError) X(WSASetLastError) X(WSAAsyncSelect) X(WSARecv) \
    X(WSASendDisconnect) X(WSARecvDisconnect) X(WSAGetOverlappedResult) X(WSASocketW)

#define W_DECL(n) static __typeof__(&n) p_##n;
W_FUNCS(W_DECL)
#undef W_DECL

static int w_state;   /* 0 = not tried, 1 = ready, 2 = unavailable */

static int w_ready(void)
{
    if (w_state) return w_state == 1;
    w_state = 2;
#define W_LOAD(n) if (!(p_##n = U(n))) return 0;
    W_FUNCS(W_LOAD)
#undef W_LOAD
    WSADATA wd;
    if (p_WSAStartup(MAKEWORD(2, 2), &wd)) return 0;
    w_state = 1;
    return 1;
}
#define W_BEGIN() do { if (!w_ready()) { t_skip("winsock entry points unavailable"); return; } } while (0)

#define WM_SOCKET (WM_USER + 100)
#define W_FD_ALL (FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE)

static inline u_long w_swap32(u_long v) { return __builtin_bswap32(v); }

static struct sockaddr_in w_loop(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = w_swap32(0x7f000001);
    return a;
}

static void w_set_blocking(SOCKET s, int blocking)
{
    u_long mode = blocking ? 0 : 1;
    p_ioctlsocket(s, FIONBIO, &mode);
}

/* Listener on 127.0.0.1, ephemeral port; *dest receives the connectable address. */
static SOCKET w_listener(struct sockaddr_in *dest, int backlog)
{
    struct sockaddr_in a = w_loop();
    SOCKET l = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int len = sizeof a;
    if (l == INVALID_SOCKET) return l;
    if (p_bind(l, (struct sockaddr *)&a, sizeof a) || p_getsockname(l, (struct sockaddr *)dest, &len)
        || p_listen(l, backlog)) {
        p_closesocket(l);
        return INVALID_SOCKET;
    }
    return l;
}

/* accept() that cannot hang the run: waits at most `ms` for a pending connection. */
static SOCKET w_accept(SOCKET l, DWORD ms)
{
    fd_set rd;
    struct timeval tv;
    FD_ZERO(&rd);
    FD_SET(l, &rd);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (p_select(0, &rd, NULL, NULL, &tv) != 1) return INVALID_SOCKET;
    return p_accept(l, NULL, NULL);
}

/* Connected loopback pair; both ends overlapped-capable (plain socket()). */
static int w_pair(SOCKET *a, SOCKET *b)
{
    struct sockaddr_in dest;
    SOCKET l = w_listener(&dest, 1);
    *a = *b = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *a = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*a != INVALID_SOCKET && !p_connect(*a, (struct sockaddr *)&dest, sizeof dest))
        *b = w_accept(l, 3000);
    p_closesocket(l);
    if (*b == INVALID_SOCKET) {
        if (*a != INVALID_SOCKET) p_closesocket(*a);
        *a = INVALID_SOCKET;
        return 0;
    }
    return 1;
}

static void *w_ext(SOCKET s, GUID guid)
{
    void *fn = NULL;
    DWORD n = 0;
    if (p_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof guid, &fn, sizeof fn, &n, NULL, NULL))
        return NULL;
    return fn;
}
static LPFN_CONNECTEX w_connectex(SOCKET s)       { return (LPFN_CONNECTEX)w_ext(s, (GUID)WSAID_CONNECTEX); }
static LPFN_DISCONNECTEX w_disconnectex(SOCKET s) { return (LPFN_DISCONNECTEX)w_ext(s, (GUID)WSAID_DISCONNECTEX); }

/* One dequeue from a completion port, with sentinels so "untouched" is observable. */
#define W_SENT 0xdeadbeef
struct w_cp { BOOL ret; DWORD err; DWORD bytes; ULONG_PTR key; OVERLAPPED *ov; };
static struct w_cp w_dequeue(HANDLE port, DWORD ms)
{
    struct w_cp r;
    r.bytes = W_SENT;
    r.key = W_SENT;
    r.ov = (OVERLAPPED *)(ULONG_PTR)W_SENT;
    SetLastError(W_SENT);
    r.ret = GetQueuedCompletionStatus(port, &r.bytes, &r.key, &r.ov, ms);
    r.err = GetLastError();
    return r;
}
/* The port holds nothing: the call times out and leaves every output alone. */
static void w_expect_empty(HANDLE port, DWORD ms)
{
    struct w_cp r = w_dequeue(port, ms);
    CHECK(!r.ret);
    EXPECT_EQ(r.err, WAIT_TIMEOUT);
    EXPECT_EQ(r.bytes, W_SENT);
    EXPECT_EQ(r.key, W_SENT);
    CHECK(r.ov == NULL);
}

/* Alertable-completion bookkeeping shared by the APC tests. */
static unsigned w_apc_count;
static DWORD w_apc_error, w_apc_size;
static OVERLAPPED *w_apc_ov;
static void CALLBACK w_socket_apc(DWORD err, DWORD size, OVERLAPPED *ov, DWORD flags)
{
    ++w_apc_count;
    w_apc_error = err;
    w_apc_size = size;
    w_apc_ov = ov;
}
static void w_apc_reset(void) { w_apc_count = 0; w_apc_error = W_SENT; w_apc_size = W_SENT; w_apc_ov = NULL; }

static HANDLE w_port_for(SOCKET s, ULONG_PTR key) { return CreateIoCompletionPort((HANDLE)s, NULL, key, 0); }

#endif
