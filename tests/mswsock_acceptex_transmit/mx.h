/* Shared helpers for the mswsock_acceptex_transmit area.
 *
 * ws2_32.dll and mswsock.dll are never linked. Core Winsock calls go through mx_<name>() wrappers that resolve the
 * export from ws2_32.dll with LoadLibrary/GetProcAddress at call time; the SDK headers supply types and constants
 * only. The extension functions (AcceptEx, ConnectEx, DisconnectEx, TransmitFile, TransmitPackets and
 * GetAcceptExSockaddrs) are obtained the way applications do it, with SIO_GET_EXTENSION_FUNCTION_POINTER, and the
 * exported entry points of mswsock.dll are resolved separately so both routes can be compared.
 */
#ifndef MX_H
#define MX_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define MXW(ret, name, params, args) static ret mx_##name params { return UIN("ws2_32.dll", name) args; }

MXW(int,    WSAStartup, (WORD v, LPWSADATA d), (v, d))
MXW(int,    WSAGetLastError, (void), ())
MXW(void,   WSASetLastError, (int e), (e))
MXW(SOCKET, socket, (int a, int t, int p), (a, t, p))
MXW(SOCKET, WSASocketW, (int a, int t, int p, LPWSAPROTOCOL_INFOW i, GROUP g, DWORD f), (a, t, p, i, g, f))
MXW(int,    closesocket, (SOCKET s), (s))
MXW(int,    bind, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
MXW(int,    listen, (SOCKET s, int b), (s, b))
MXW(int,    connect, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
MXW(SOCKET, accept, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
MXW(int,    getsockname, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
MXW(int,    getpeername, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
MXW(int,    getsockopt, (SOCKET s, int lv, int n, char *v, int *l), (s, lv, n, v, l))
MXW(int,    setsockopt, (SOCKET s, int lv, int n, const char *v, int l), (s, lv, n, v, l))
MXW(int,    ioctlsocket, (SOCKET s, long c, u_long *a), (s, c, a))
MXW(int,    send, (SOCKET s, const char *b, int l, int f), (s, b, l, f))
MXW(int,    recv, (SOCKET s, char *b, int l, int f), (s, b, l, f))
MXW(int,    recvfrom, (SOCKET s, char *b, int l, int f, struct sockaddr *a, int *al), (s, b, l, f, a, al))
MXW(int,    sendto, (SOCKET s, const char *b, int l, int f, const struct sockaddr *a, int al), (s, b, l, f, a, al))
MXW(int,    shutdown, (SOCKET s, int h), (s, h))
MXW(int,    select, (int n, fd_set *r, fd_set *w, fd_set *e, const struct timeval *t), (n, r, w, e, t))
MXW(int,    WSAIoctl, (SOCKET s, DWORD c, LPVOID i, DWORD il, LPVOID o, DWORD ol, LPDWORD r, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, c, i, il, o, ol, r, ov, cr))
MXW(BOOL,   WSAGetOverlappedResult, (SOCKET s, LPWSAOVERLAPPED ov, LPDWORD len, BOOL wait, LPDWORD fl), (s, ov, len, wait, fl))
MXW(int,    WSAPoll, (LPWSAPOLLFD f, ULONG n, INT to), (f, n, to))
MXW(int,    WSARecv, (SOCKET s, LPWSABUF b, DWORD n, LPDWORD got, LPDWORD f, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, b, n, got, f, ov, cr))

/* Single-evaluation equality check (the harness macro evaluates operands twice). */
#define MX_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)a_, (unsigned long long)b_); } while (0)

#define MX_STATUS_PENDING 0x00000103UL
#define MX_POISON         0xdeadbeefUL

static inline int mx_up(void)
{
    static int state;   /* 0 unknown, 1 up, -1 failed */
    if (!state) {
        WSADATA d;
        state = (UIN("ws2_32.dll", WSAStartup) && mx_WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED_NET() do { if (!mx_up()) { t_skip("winsock unavailable"); return; } } while (0)

/* ---- extension functions ------------------------------------------------ */
struct mx_ext {
    LPFN_ACCEPTEX acceptex;
    LPFN_GETACCEPTEXSOCKADDRS gaes;
    LPFN_CONNECTEX connectex;
    LPFN_DISCONNECTEX disconnectex;
    LPFN_TRANSMITFILE transmitfile;
    LPFN_TRANSMITPACKETS transmitpackets;
};

static inline void *mx_ext_lookup(SOCKET s, GUID g)
{
    void *fn = NULL;
    DWORD n = 0;
    if (mx_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL))
        return NULL;
    return fn;
}

/* Resolve the pointers through a throw-away TCP socket; returns 1 when the five core ones were offered. */
static inline int mx_load_ext(struct mx_ext *e)
{
    GUID ga = WSAID_ACCEPTEX, gs = WSAID_GETACCEPTEXSOCKADDRS, gc = WSAID_CONNECTEX,
         gd = WSAID_DISCONNECTEX, gt = WSAID_TRANSMITFILE, gp = WSAID_TRANSMITPACKETS;
    SOCKET s = mx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(e, 0, sizeof *e);
    if (s == INVALID_SOCKET) return 0;
    e->acceptex = (LPFN_ACCEPTEX)mx_ext_lookup(s, ga);
    e->gaes = (LPFN_GETACCEPTEXSOCKADDRS)mx_ext_lookup(s, gs);
    e->connectex = (LPFN_CONNECTEX)mx_ext_lookup(s, gc);
    e->disconnectex = (LPFN_DISCONNECTEX)mx_ext_lookup(s, gd);
    e->transmitfile = (LPFN_TRANSMITFILE)mx_ext_lookup(s, gt);
    e->transmitpackets = (LPFN_TRANSMITPACKETS)mx_ext_lookup(s, gp);
    mx_closesocket(s);
    return e->acceptex && e->gaes && e->connectex && e->disconnectex && e->transmitfile;   /* TransmitPackets is checked by its own tests */
}

#define MX_EXT(x) struct mx_ext x; \
    do { NEED_NET(); if (!mx_load_ext(&(x))) { t_skip("extension functions not offered"); return; } } while (0)

/* ---- addresses and sockets ---------------------------------------------- */
static inline struct sockaddr_in mx_lo4(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;   /* 127.0.0.1, network order */
    return a;
}

static inline SOCKET mx_tcp(void) { return mx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); }

/* Loopback TCP socket bound to an ephemeral port; *addr receives the real address. */
static inline SOCKET mx_bound(struct sockaddr_in *addr)
{
    int len = sizeof *addr;
    SOCKET s = mx_tcp();
    *addr = mx_lo4();
    if (s == INVALID_SOCKET) return s;
    if (mx_bind(s, (struct sockaddr *)addr, sizeof *addr) || mx_getsockname(s, (struct sockaddr *)addr, &len)) {
        mx_closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static inline SOCKET mx_listener(struct sockaddr_in *addr, int backlog)
{
    SOCKET s = mx_bound(addr);
    if (s != INVALID_SOCKET && mx_listen(s, backlog)) { mx_closesocket(s); return INVALID_SOCKET; }
    return s;
}

/* Wait until s is readable (or has a pending connection) for at most ms; 1 when ready. */
static inline int mx_readable(SOCKET s, int ms)
{
    fd_set r;
    struct timeval tv;
    FD_ZERO(&r);
    FD_SET(s, &r);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return mx_select(0, &r, NULL, NULL, &tv) == 1;
}

/* Accept with a bounded wait so a failed connect cannot hang the run. */
static inline SOCKET mx_accept_wait(SOCKET lst)
{
    if (!mx_readable(lst, 5000)) return INVALID_SOCKET;
    return mx_accept(lst, NULL, NULL);
}

/* Connected stream pair over loopback: *c is the connecting side, *a the accepted side. */
static inline int mx_pair(SOCKET *c, SOCKET *a)
{
    struct sockaddr_in addr;
    SOCKET l = mx_listener(&addr, 4);
    *c = *a = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = mx_tcp();
    if (*c == INVALID_SOCKET || mx_connect(*c, (struct sockaddr *)&addr, sizeof addr)) goto fail;
    *a = mx_accept_wait(l);
    if (*a == INVALID_SOCKET) goto fail;
    mx_closesocket(l);
    return 1;
fail:
    if (*c != INVALID_SOCKET) mx_closesocket(*c);
    mx_closesocket(l);
    *c = *a = INVALID_SOCKET;
    return 0;
}
#define MX_PAIR(c, a) SOCKET c, a; do { NEED_NET(); if (!mx_pair(&(c), &(a))) { t_skip("loopback pair unavailable"); return; } } while (0)

/* Receive exactly len bytes (bounded waits); returns the number actually received, -1 on a socket error. */
static inline int mx_recv_all(SOCKET s, void *buf, int len, int ms)
{
    int got = 0;
    while (got < len) {
        int r;
        if (!mx_readable(s, ms)) break;
        r = mx_recv(s, (char *)buf + got, len - got, 0);
        if (r < 0) return -1;
        if (r == 0) break;
        got += r;
    }
    return got;
}

/* 1 when the peer has closed its sending side and recv reports end of stream. */
static inline int mx_at_eof(SOCKET s, int ms)
{
    char c;
    if (!mx_readable(s, ms)) return 0;
    return mx_recv(s, &c, 1, 0) == 0;
}

/* 1 when nothing becomes readable within ms (a short bounded wait, not a timing assertion on the call under test). */
static inline int mx_quiet(SOCKET s, int ms) { return !mx_readable(s, ms); }

/* The next len bytes on s must equal want. */
static inline void mx_expect_bytes(SOCKET s, const void *want, int len)
{
    char *buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    int got = mx_recv_all(s, buf, len, 5000);
    MX_EQ(got, len);
    CHECK(got == len && !memcmp(buf, want, len));
    HeapFree(GetProcessHeap(), 0, buf);
}

/* ---- overlapped helpers -------------------------------------------------- */
static inline HANDLE mx_event(void) { return CreateEventA(NULL, TRUE, FALSE, NULL); }

/* Wait for an overlapped socket operation and fetch its result; *err gets the error of a failed result.
 * Returns 1 on success, 0 on failure or timeout (*err == WAIT_TIMEOUT for the latter). */
static inline int mx_ov_done(SOCKET s, OVERLAPPED *ov, DWORD *bytes, DWORD ms, DWORD *err)
{
    DWORD fl = 0, n = 0;
    BOOL ok;
    if (WaitForSingleObject(ov->hEvent, ms) != WAIT_OBJECT_0) { if (err) *err = WAIT_TIMEOUT; return 0; }
    ok = mx_WSAGetOverlappedResult(s, (LPWSAOVERLAPPED)ov, &n, FALSE, &fl);
    if (bytes) *bytes = n;
    if (err) *err = ok ? 0 : (DWORD)mx_WSAGetLastError();
    return ok ? 1 : 0;
}

/* Stop whatever is outstanding on s, close it and give the kernel a moment to finish with the OVERLAPPED. */
static inline void mx_abort(SOCKET s, OVERLAPPED *ov)
{
    if (s != INVALID_SOCKET) {
        CancelIo((HANDLE)s);
        mx_closesocket(s);
    }
    if (ov && ov->hEvent) WaitForSingleObject(ov->hEvent, 1000);
}

/* A reuse disconnect completes only once the connection has fully closed, which needs the peer's FIN too, so it
 * must never be issued synchronously while the peer stays open. This runs DisconnectEx(TF_REUSE_SOCKET) with an
 * OVERLAPPED, lets the peer observe end of stream and answer with its own shutdown, and waits for completion.
 * Returns 1 when the disconnect completed successfully. peer may be INVALID_SOCKET if it is already gone. */
static inline int mx_reuse_disconnect(LPFN_DISCONNECTEX fn, SOCKET s, SOCKET peer)
{
    OVERLAPPED ov;
    DWORD n = 0, err = 0;
    int ok, e;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    e = fn(s, &ov, TF_REUSE_SOCKET, 0) ? 0 : mx_WSAGetLastError();
    if (e != 0 && e != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); return 0; }
    if (peer != INVALID_SOCKET) {
        if (!mx_at_eof(peer, 5000)) { mx_abort(s, &ov); CloseHandle(ov.hEvent); return 0; }
        mx_shutdown(peer, SD_SEND);
    }
    ok = mx_ov_done(s, &ov, &n, 8000, &err);
    CloseHandle(ov.hEvent);
    return ok;
}

/* ---- file helpers --------------------------------------------------------- */
static inline unsigned char mx_pat(DWORD i, unsigned seed) { return (unsigned char)(i * 31u + i / 251u + seed); }

static inline void mx_fill(unsigned char *p, DWORD len, unsigned seed, DWORD base)
{
    DWORD i;
    for (i = 0; i < len; i++) p[i] = mx_pat(base + i, seed);
}

/* Create a scratch file holding len bytes of the pattern; the file pointer is left at the start. */
static inline HANDLE mx_make_file(const char *leaf, DWORD len, unsigned seed, DWORD access, DWORD flags)
{
    char path[MAX_PATH];
    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, len ? len : 1);
    HANDLE h;
    DWORD n = 0;
    t_tmpfile(path, sizeof path, leaf);
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                    flags, NULL);
    if (h == INVALID_HANDLE_VALUE) { HeapFree(GetProcessHeap(), 0, buf); return h; }
    mx_fill(buf, len, seed, 0);
    if (len && (!WriteFile(h, buf, len, &n, NULL) || n != len)) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    HeapFree(GetProcessHeap(), 0, buf);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        if (access != (GENERIC_READ | GENERIC_WRITE)) {   /* reopen with the narrower access, same file */
            CloseHandle(h);
            h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, flags, NULL);
        }
    }
    return h;
}

/* Expected stream for a file slice: bytes [off, off+len) of the pattern. */
static inline void mx_expect_slice(SOCKET s, unsigned seed, DWORD off, DWORD len)
{
    unsigned char *want = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, len ? len : 1);
    mx_fill(want, len, seed, off);
    mx_expect_bytes(s, want, (int)len);
    HeapFree(GetProcessHeap(), 0, want);
}

/* ---- background receiver (for payloads larger than the socket buffers) ---- */
struct mx_sink {
    SOCKET s;
    unsigned char *buf;
    int cap;
    volatile int got;
    HANDLE th;
};

static DWORD WINAPI mx_sink_main(LPVOID p)
{
    struct mx_sink *k = (struct mx_sink *)p;
    while (k->got < k->cap) {
        int r;
        if (!mx_readable(k->s, 8000)) break;
        r = mx_recv(k->s, (char *)k->buf + k->got, k->cap - k->got, 0);
        if (r <= 0) break;
        k->got += r;
    }
    return 0;
}

static inline void mx_sink_start(struct mx_sink *k, SOCKET s, int cap)
{
    k->s = s;
    k->cap = cap;
    k->got = 0;
    k->buf = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap ? cap : 1);
    k->th = CreateThread(NULL, 0, mx_sink_main, k, 0, NULL);
}

static inline int mx_sink_join(struct mx_sink *k)
{
    if (k->th) { WaitForSingleObject(k->th, 20000); CloseHandle(k->th); }
    k->th = NULL;
    return k->got;
}

static inline void mx_sink_free(struct mx_sink *k) { HeapFree(GetProcessHeap(), 0, k->buf); k->buf = NULL; }
#endif
