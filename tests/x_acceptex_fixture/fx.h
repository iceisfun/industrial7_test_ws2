/* Shared helpers for the x_acceptex_fixture area.
 *
 * ws2_32.dll and mswsock.dll are never linked.  Winsock calls go through fx_<name>() wrappers that resolve the
 * export from ws2_32.dll at call time; the SDK headers supply types and constants only.  AcceptEx,
 * GetAcceptExSockaddrs and DisconnectEx are obtained the way applications do it: WSAIoctl with
 * SIO_GET_EXTENSION_FUNCTION_POINTER on a socket of the family under test.  Discovery and operation are
 * separate steps so a missing pointer and a failing call are never confused.
 */
#ifndef FX_H
#define FX_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define FXW(ret, name, params, args) static ret fx_##name params { return UIN("ws2_32.dll", name) args; }
FXW(int,    WSAStartup, (WORD v, LPWSADATA d), (v, d))
FXW(int,    WSAGetLastError, (void), ())
FXW(void,   WSASetLastError, (int e), (e))
FXW(SOCKET, socket, (int a, int t, int p), (a, t, p))
FXW(SOCKET, WSASocketW, (int a, int t, int p, LPWSAPROTOCOL_INFOW i, GROUP g, DWORD f), (a, t, p, i, g, f))
FXW(int,    closesocket, (SOCKET s), (s))
FXW(int,    bind, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
FXW(int,    listen, (SOCKET s, int b), (s, b))
FXW(int,    connect, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
FXW(SOCKET, accept, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
FXW(int,    getsockname, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
FXW(int,    getpeername, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
FXW(int,    getsockopt, (SOCKET s, int lv, int n, char *v, int *l), (s, lv, n, v, l))
FXW(int,    setsockopt, (SOCKET s, int lv, int n, const char *v, int l), (s, lv, n, v, l))
FXW(int,    ioctlsocket, (SOCKET s, long c, u_long *a), (s, c, a))
FXW(int,    send, (SOCKET s, const char *b, int l, int f), (s, b, l, f))
FXW(int,    recv, (SOCKET s, char *b, int l, int f), (s, b, l, f))
FXW(int,    shutdown, (SOCKET s, int h), (s, h))
FXW(int,    select, (int n, fd_set *r, fd_set *w, fd_set *e, const struct timeval *t), (n, r, w, e, t))
FXW(int,    WSAIoctl, (SOCKET s, DWORD c, LPVOID i, DWORD il, LPVOID o, DWORD ol, LPDWORD r, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, c, i, il, o, ol, r, ov, cr))
FXW(BOOL,   WSAGetOverlappedResult, (SOCKET s, LPWSAOVERLAPPED ov, LPDWORD len, BOOL wait, LPDWORD fl), (s, ov, len, wait, fl))

#define FX_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)a_, (unsigned long long)b_); } while (0)

#define FX_STATUS_PENDING   0x00000103UL
#define FX_STATUS_CANCELLED 0xC0000120UL

static inline int fx_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        state = (UIN("ws2_32.dll", WSAStartup) && fx_WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}

/* ---- one fixture per address family ------------------------------------------------------------------- */
typedef union { struct sockaddr sa; struct sockaddr_in a4; struct sockaddr_in6 a6; struct sockaddr_storage ss; } fx_addr;

struct fx {
    int af;
    int alen;                    /* sizeof(sockaddr_in) or sizeof(sockaddr_in6) */
    DWORD slot;                  /* alen + 16, the documented per-address reservation */
    LPFN_ACCEPTEX acceptex;
    LPFN_GETACCEPTEXSOCKADDRS gaes;
    LPFN_DISCONNECTEX disconnectex;
    SOCKET lst;
    fx_addr addr;                /* listener address after bind to port 0 */
};

static inline SOCKET fx_stream(int af) { return fx_socket(af, SOCK_STREAM, IPPROTO_TCP); }

static inline void fx_loopback(int af, fx_addr *a)
{
    memset(a, 0, sizeof *a);
    a->sa.sa_family = (ADDRESS_FAMILY)af;
    if (af == AF_INET) a->a4.sin_addr.s_addr = 0x0100007f;
    else a->a6.sin6_addr.u.Byte[15] = 1;
}

static inline void *fx_lookup(SOCKET s, GUID g)
{
    void *fn = NULL;
    DWORD n = 0;
    if (fx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL)) return NULL;
    return fn;
}

/* Discovery only: the three pointers via a throw-away socket of the family. 1 when AcceptEx was offered. */
static inline int fx_discover(struct fx *f, int af)
{
    GUID ga = WSAID_ACCEPTEX, gs = WSAID_GETACCEPTEXSOCKADDRS, gd = WSAID_DISCONNECTEX;
    SOCKET s;
    memset(f, 0, sizeof *f);
    f->lst = INVALID_SOCKET;
    f->af = af;
    f->alen = af == AF_INET ? (int)sizeof(struct sockaddr_in) : (int)sizeof(struct sockaddr_in6);
    f->slot = f->alen + 16;
    s = fx_stream(af);
    if (s == INVALID_SOCKET) return 0;
    f->acceptex = (LPFN_ACCEPTEX)fx_lookup(s, ga);
    f->gaes = (LPFN_GETACCEPTEXSOCKADDRS)fx_lookup(s, gs);
    f->disconnectex = (LPFN_DISCONNECTEX)fx_lookup(s, gd);
    fx_closesocket(s);
    return f->acceptex != NULL;
}

static inline SOCKET fx_listener_on(int af, fx_addr *out, int backlog)
{
    int len = af == AF_INET ? (int)sizeof(struct sockaddr_in) : (int)sizeof(struct sockaddr_in6);
    SOCKET s = fx_stream(af);
    if (s == INVALID_SOCKET) return s;
    fx_loopback(af, out);
    if (fx_bind(s, &out->sa, len) || fx_getsockname(s, &out->sa, &len) || fx_listen(s, backlog)) {
        fx_closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/* Full fixture: discovery plus a listening loopback socket. 0 when the environment cannot provide it. */
static inline int fx_open(struct fx *f, int af)
{
    if (!fx_up()) return 0;
    if (!fx_discover(f, af)) return 0;
    f->lst = fx_listener_on(af, &f->addr, 8);
    return f->lst != INVALID_SOCKET;
}

static inline void fx_shut(struct fx *f)
{
    if (f->lst != INVALID_SOCKET) fx_closesocket(f->lst);
    f->lst = INVALID_SOCKET;
}

#define FX_OPEN(f, af) struct fx f; \
    do { if (!fx_up()) { t_skip("winsock unavailable"); return; } \
         if ((af) == AF_INET6) { SOCKET p_ = fx_stream(AF_INET6); if (p_ == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; } fx_closesocket(p_); } \
         if (!fx_open(&(f), (af))) { fx_shut(&(f)); t_skip("AcceptEx fixture unavailable"); return; } } while (0)

/* ---- clients ----------------------------------------------------------------------------------------- */
static inline SOCKET fx_client(struct fx *f)
{
    SOCKET c = fx_stream(f->af);
    if (c == INVALID_SOCKET) return c;
    if (fx_connect(c, &f->addr.sa, f->alen)) { fx_closesocket(c); return INVALID_SOCKET; }
    return c;
}

/* ---- overlapped plumbing ------------------------------------------------------------------------------ */
static inline HANDLE fx_event(void) { return CreateEventA(NULL, TRUE, FALSE, NULL); }

/* Bounded poll of the OVERLAPPED state itself (no event, no wait on the call under test). */
static inline int fx_done_within(OVERLAPPED *ov, int ms)
{
    int i;
    for (i = 0; i <= ms / 10; i++) {
        if (HasOverlappedIoCompleted(ov)) return 1;
        Sleep(10);
    }
    return HasOverlappedIoCompleted(ov) != 0;
}

/* Post AcceptEx. Returns 0 when it completed synchronously (TRUE), else the WSA error. *n receives the initial
 * output DWORD exactly as the call left it. */
static inline int fx_post(struct fx *f, SOCKET acc, void *buf, DWORD rl, DWORD ll, DWORD rr, DWORD *n, OVERLAPPED *ov)
{
    BOOL r;
    fx_WSASetLastError(0);
    r = f->acceptex(f->lst, acc, buf, rl, ll, rr, n, ov);
    return r ? 0 : fx_WSAGetLastError();
}

/* Wait for the request and fetch its result by WSAGetOverlappedResult. Returns 1 on success; *err is 0 or the
 * WSA error, WAIT_TIMEOUT when the request never completed. */
static inline int fx_result(SOCKET s, OVERLAPPED *ov, DWORD *bytes, DWORD ms, DWORD *err)
{
    DWORD fl = 0, n = 0;
    BOOL ok;
    if (WaitForSingleObject(ov->hEvent, ms) != WAIT_OBJECT_0) { if (err) *err = WAIT_TIMEOUT; return 0; }
    ok = fx_WSAGetOverlappedResult(s, (LPWSAOVERLAPPED)ov, &n, FALSE, &fl);
    if (bytes) *bytes = n;
    if (err) *err = ok ? 0 : (DWORD)fx_WSAGetLastError();
    return ok;
}

/* Cancel what is outstanding on the listener and wait for the request to leave the kernel. */
static inline void fx_drain(struct fx *f, OVERLAPPED *ov)
{
    if (f->lst != INVALID_SOCKET) { CancelIoEx((HANDLE)f->lst, NULL); }
    if (ov && ov->hEvent) WaitForSingleObject(ov->hEvent, 2000);
}

static inline int fx_readable(SOCKET s, int ms)
{
    fd_set r;
    struct timeval tv;
    FD_ZERO(&r);
    FD_SET(s, &r);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return fx_select(0, &r, NULL, NULL, &tv) == 1;
}

/* Receive up to len bytes with bounded waits; returns bytes got, -1 on error (error left in WSAGetLastError). */
static inline int fx_recv_n(SOCKET s, void *buf, int len, int ms)
{
    int got = 0;
    while (got < len) {
        int r;
        if (!fx_readable(s, ms)) break;
        r = fx_recv(s, (char *)buf + got, len - got, 0);
        if (r < 0) return -1;
        if (r == 0) break;
        got += r;
    }
    return got;
}

/* 1 when s reports orderly end of stream within ms (readable and recv returns 0). */
static inline int fx_at_eof(SOCKET s, int ms)
{
    char ch;
    if (!fx_readable(s, ms)) return 0;
    return fx_recv(s, &ch, 1, 0) == 0;
}

/* Completion port helper. */
static inline HANDLE fx_port(void) { return CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); }
static inline int fx_assoc(HANDLE port, SOCKET s, ULONG_PTR key) { return CreateIoCompletionPort((HANDLE)s, port, key, 0) == port; }

/* Dequeue one packet. Returns 1 when a packet arrived (ok = result of the call), 0 on timeout. */
static inline int fx_dequeue(HANDLE port, DWORD ms, BOOL *ok, DWORD *bytes, ULONG_PTR *key, OVERLAPPED **pov, DWORD *err)
{
    *pov = NULL; *bytes = 0; *key = 0;
    *ok = GetQueuedCompletionStatus(port, bytes, key, pov, ms);
    *err = *ok ? 0 : GetLastError();
    return *pov != NULL;
}

/* Poison pattern for output DWORDs and canary bytes. */
#define FX_POISON 0xA5A5A5A5UL
/* ---- per-test context: fixture + OVERLAPPED + a buffer with canaries after the used region ---------------- */
#define FXC_BUF 640
struct fxc {
    struct fx f;
    OVERLAPPED ov;
    DWORD n;                          /* the "initial output DWORD" handed to AcceptEx */
    unsigned char buf[FXC_BUF];
};

static inline int fxc_open(struct fxc *c, int af)
{
    memset(c, 0, sizeof *c);
    if (!fx_open(&c->f, af)) return 0;
    c->ov.hEvent = fx_event();
    memset(c->buf, 0xCC, sizeof c->buf);
    return c->ov.hEvent != NULL;
}
static inline void fxc_close(struct fxc *c)
{
    fx_drain(&c->f, &c->ov);
    fx_shut(&c->f);
    if (c->ov.hEvent) CloseHandle(c->ov.hEvent);
    c->ov.hEvent = NULL;
}
/* Post with both address slots at the documented minimum; resets the OVERLAPPED status and the output DWORD. */
static inline int fxc_post(struct fxc *c, SOCKET acc, DWORD rl)
{
    c->n = FX_POISON;
    c->ov.Internal = 0; c->ov.InternalHigh = 0;
    ResetEvent(c->ov.hEvent);
    return fx_post(&c->f, acc, c->buf, rl, c->f.slot, c->f.slot, &c->n, &c->ov);
}

#define FXC_OPEN(c, af) struct fxc c; \
    do { if (!fx_up()) { t_skip("winsock unavailable"); return; } \
         if ((af) == AF_INET6) { SOCKET p_ = fx_stream(AF_INET6); if (p_ == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; } fx_closesocket(p_); } \
         if (!fxc_open(&(c), (af))) { fxc_close(&(c)); t_skip("AcceptEx fixture unavailable"); return; } } while (0)

/* One scenario body, instantiated for both address families. */
#define FX_BOTH(name) static void name##_run(int af); \
    TEST(name##_v4) { name##_run(AF_INET); } \
    TEST(name##_v6) { name##_run(AF_INET6); } \
    static void name##_run(int af)

static inline void fx_close_all(SOCKET a, SOCKET b, SOCKET c3)
{
    if (a != INVALID_SOCKET) fx_closesocket(a);
    if (b != INVALID_SOCKET) fx_closesocket(b);
    if (c3 != INVALID_SOCKET) fx_closesocket(c3);
}
#endif
