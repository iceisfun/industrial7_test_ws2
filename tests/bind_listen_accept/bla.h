/* Shared helpers for the bind_listen_accept area.
 *
 * Every Winsock entry point is resolved with LoadLibrary/GetProcAddress through U(); nothing here links
 * the library under test.  All endpoints are loopback with ephemeral ports.  No test prints a port,
 * an address chosen by the system, or a handle.
 */
#ifndef BLA_H
#define BLA_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef SO_CONDITIONAL_ACCEPT
#define SO_CONDITIONAL_ACCEPT 0x3002
#endif
#ifndef SOMAXCONN_HINT
#define SOMAXCONN_HINT(b) (-(b))
#endif

/* ---- start-up: one WSAStartup per process, never balanced ---- */
static int bla_up(void)
{
    static int done;
    if (!done) {
        WSADATA d;
        if (!U(WSAStartup) || U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 0;
        done = 1;
    }
    return 1;
}
#define NEED() do { if (!bla_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

/* ---- thin call wrappers ---- */
static int    werr(void)                { return U(WSAGetLastError)(); }
static void   wset(int e)               { U(WSASetLastError)(e); }
static SOCKET tcp(void) { bla_up(); return U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
static SOCKET udp(void) { bla_up(); return U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
static SOCKET tcp6(void) { bla_up(); return U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP); }
static SOCKET udp6(void) { bla_up(); return U(socket)(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); }
static int    cls(SOCKET s)             { return U(closesocket)(s); }
static int    bnd(SOCKET s, const void *a, int n)   { return U(bind)(s, (const struct sockaddr *)a, n); }
static int    lsn(SOCKET s, int b)      { return U(listen)(s, b); }
static int    con(SOCKET s, const void *a, int n)   { return U(connect)(s, (const struct sockaddr *)a, n); }
static SOCKET acc(SOCKET s, void *a, int *n)        { return U(accept)(s, (struct sockaddr *)a, n); }
static int    gsn(SOCKET s, void *a, int *n)        { return U(getsockname)(s, (struct sockaddr *)a, n); }
static int    gpn(SOCKET s, void *a, int *n)        { return U(getpeername)(s, (struct sockaddr *)a, n); }
static int    gso(SOCKET s, int lvl, int opt, void *v, int *n) { return U(getsockopt)(s, lvl, opt, (char *)v, n); }
static int    sso(SOCKET s, int lvl, int opt, const void *v, int n) { return U(setsockopt)(s, lvl, opt, (const char *)v, n); }
static int    snd(SOCKET s, const void *b, int n)   { return U(send)(s, (const char *)b, n, 0); }
static int    rcv(SOCKET s, void *b, int n)         { return U(recv)(s, (char *)b, n, 0); }
static int    nbio(SOCKET s, int on)    { u_long v = on ? 1 : 0; return U(ioctlsocket)(s, FIONBIO, &v); }

typedef SOCKET (WINAPI *wsaaccept_pfn)(SOCKET, struct sockaddr *, LPINT, LPCONDITIONPROC, DWORD_PTR);
static SOCKET wacc(SOCKET s, void *a, int *n, LPCONDITIONPROC cf, DWORD_PTR data)
{
    return ((wsaaccept_pfn)t_proc("WSAAccept"))(s, (struct sockaddr *)a, n, cf, data);
}

/* ---- addresses ---- */
static struct sockaddr_in lo4(unsigned port_host)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;                         /* 127.0.0.1 */
    a.sin_port = (u_short)(((port_host & 0xff) << 8) | ((port_host >> 8) & 0xff));
    return a;
}
static struct sockaddr_in any4(unsigned port_host)
{
    struct sockaddr_in a = lo4(port_host);
    a.sin_addr.s_addr = 0;
    return a;
}
static struct sockaddr_in6 lo6(unsigned port_host)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr.u.Byte[15] = 1;
    a.sin6_port = (u_short)(((port_host & 0xff) << 8) | ((port_host >> 8) & 0xff));
    return a;
}
static struct sockaddr_in6 any6(unsigned port_host)
{
    struct sockaddr_in6 a = lo6(port_host);
    a.sin6_addr.u.Byte[15] = 0;
    return a;
}
static int is_lo4(const struct sockaddr_in *a) { return a->sin_family == AF_INET && a->sin_addr.s_addr == 0x0100007f; }
static int is_any4(const struct sockaddr_in *a) { return a->sin_family == AF_INET && a->sin_addr.s_addr == 0; }

/* Bind to loopback port 0 and read back the full name. */
static int bind_lo(SOCKET s, struct sockaddr_in *out)
{
    struct sockaddr_in a = lo4(0);
    int n;
    if (bnd(s, &a, sizeof a) != 0) return -1;
    if (out) { n = sizeof *out; if (gsn(s, out, &n) != 0) return -1; }
    return 0;
}
/* Listening TCP socket on an ephemeral loopback port; *addr receives its name. */
static SOCKET listener(struct sockaddr_in *addr, int backlog)
{
    SOCKET s = tcp();
    struct sockaddr_in tmp;
    if (s == INVALID_SOCKET) return s;
    if (!addr) addr = &tmp;
    if (bind_lo(s, addr) != 0 || lsn(s, backlog) != 0) { cls(s); return INVALID_SOCKET; }
    return s;
}
/* Blocking connect to a listener that already queues; returns INVALID_SOCKET on failure. */
static SOCKET dial(const struct sockaddr_in *a)
{
    SOCKET c = tcp();
    if (c == INVALID_SOCKET) return c;
    if (con(c, a, sizeof *a) != 0) { cls(c); return INVALID_SOCKET; }
    return c;
}
/* A loopback TCP port with no listener at this moment: bind, read, close. */
static struct sockaddr_in dead_port(void)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s = tcp();
    if (s != INVALID_SOCKET) {
        struct sockaddr_in o;
        if (bind_lo(s, &o) == 0) a = o;
        cls(s);
    }
    return a;
}

/* ---- bounded waiting ---- */
static int readable(SOCKET s, int ms)
{
    fd_set r;
    struct timeval tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
static int writable(SOCKET s, int ms)
{
    fd_set w;
    struct timeval tv;
    w.fd_count = 1; w.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, NULL, &w, NULL, &tv) == 1;
}
/* accept() only once the listener is readable, so a missing connection cannot hang the run. */
static SOCKET acc_wait(SOCKET l, void *a, int *n, int ms)
{
    if (!readable(l, ms)) return INVALID_SOCKET;
    return acc(l, a, n);
}
static void rcvto(SOCKET s, int ms) { DWORD v = ms; sso(s, SOL_SOCKET, SO_RCVTIMEO, &v, sizeof v); }

static int join(HANDLE h, DWORD ms)
{
    int ok = WaitForSingleObject(h, ms) == WAIT_OBJECT_0;
    if (!ok) TerminateThread(h, 0);
    CloseHandle(h);
    return ok;
}

/* Background connector: connects once and keeps the socket open until the owner closes it. */
struct cth {
    struct sockaddr_in addr;
    SOCKET s;
    int rc, err;
    HANDLE th;
};
static DWORD WINAPI cth_main(void *p)
{
    struct cth *c = (struct cth *)p;
    c->s = tcp();
    c->rc = con(c->s, &c->addr, sizeof c->addr);
    c->err = werr();
    return 0;
}
static void cth_start(struct cth *c, const struct sockaddr_in *a)
{
    memset(c, 0, sizeof *c);
    c->addr = *a;
    c->s = INVALID_SOCKET;
    c->rc = -2;
    c->th = CreateThread(NULL, 0, cth_main, c, 0, NULL);
}
static int cth_finish(struct cth *c, DWORD ms)
{
    int ok = c->th ? join(c->th, ms) : 0;
    c->th = NULL;
    return ok;
}

/* IPv6 loopback usable? (cached) */
static int v6ok(void)
{
    static int st = -1;
    if (st < 0) {
        SOCKET s = tcp6();
        st = 0;
        if (s != INVALID_SOCKET) {
            struct sockaddr_in6 a = lo6(0);
            st = bnd(s, &a, sizeof a) == 0;
            cls(s);
        }
    }
    return st;
}
#define NEED6() do { if (!v6ok()) { t_skip("IPv6 loopback unusable"); return; } } while (0)

/* Single-evaluation checks. */
#define EQ(a, b) do { long long v_ = (long long)(a), w_ = (long long)(b); \
    t_check(v_ == w_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", v_, w_); } while (0)
/* The call must return -1 / INVALID_SOCKET and leave the given Winsock error. */
#define FAILS(call, err) do { wset(0x5a5a); long long r_ = (long long)(call); \
    int e_ = werr(); \
    t_check(r_ == -1, __FILE__, __LINE__, #call, "unexpected success"); \
    t_check(e_ == (err), __FILE__, __LINE__, #err, "WSAGetLastError got %d want %d", e_, (int)(err)); } while (0)
/* The call must fail; the exact error is only recorded. */
static const char *werr_class(int e)
{
    return e == WSAEAFNOSUPPORT ? "AFNOSUPPORT" : e == WSAEFAULT ? "FAULT" : e == WSAEADDRNOTAVAIL ? "ADDRNOTAVAIL" :
           e == WSAEINVAL ? "INVAL" : e == WSAEOPNOTSUPP ? "OPNOTSUPP" : e == WSAEPROTONOSUPPORT ? "PROTONOSUPPORT" : "other";
}
#define FAILS_NOTE(call, what) do { wset(0x5a5a); long long r_ = (long long)(call); \
    int e_ = werr(); \
    t_check(r_ == -1, __FILE__, __LINE__, #call, "unexpected success"); \
    t_note("%s -> %s", what, werr_class(e_)); } while (0)
#endif
