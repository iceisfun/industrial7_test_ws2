/* Shared helpers for the lift_06 area: thin wrappers that resolve every Winsock call through
 * LoadLibrary/GetProcAddress (U()), plus loopback socket plumbing. Nothing here links ws2_32. */
#ifndef L6_H
#define L6_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010
#endif

/* ---- start-up: one WSAStartup for the whole process, never balanced (the process exits) ---- */
static int w_up(void)
{
    static int done = 0;
    if (!done) {
        WSADATA d;
        if (!U(WSAStartup)) return 0;
        if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 0;
        done = 1;
    }
    return 1;
}
#define NEED_WS() do { if (!w_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

/* ---- wrappers (all calls resolved dynamically) ---- */
static int  w_err(void)              { return U(WSAGetLastError)(); }
static void w_seterr(int e)          { U(WSASetLastError)(e); }
static SOCKET w_socket(int af, int ty, int pr) { return U(socket)(af, ty, pr); }
static int  w_close(SOCKET s)        { return U(closesocket)(s); }
static int  w_bind(SOCKET s, const void *a, int n)    { return U(bind)(s, (const struct sockaddr *)a, n); }
static int  w_listen(SOCKET s, int b)                 { return U(listen)(s, b); }
static int  w_connect(SOCKET s, const void *a, int n) { return U(connect)(s, (const struct sockaddr *)a, n); }
static SOCKET w_accept(SOCKET s, void *a, int *n)     { return U(accept)(s, (struct sockaddr *)a, n); }
static int  w_getsockname(SOCKET s, void *a, int *n)  { return U(getsockname)(s, (struct sockaddr *)a, n); }
static int  w_getpeername(SOCKET s, void *a, int *n)  { return U(getpeername)(s, (struct sockaddr *)a, n); }
static int  w_getsockopt(SOCKET s, int lvl, int opt, void *v, int *n) { return U(getsockopt)(s, lvl, opt, (char *)v, n); }
static int  w_setsockopt(SOCKET s, int lvl, int opt, const void *v, int n) { return U(setsockopt)(s, lvl, opt, (const char *)v, n); }
static int  w_send(SOCKET s, const void *b, int n, int f)  { return U(send)(s, (const char *)b, n, f); }
static int  w_recv(SOCKET s, void *b, int n, int f)        { return U(recv)(s, (char *)b, n, f); }
static int  w_select(int n, fd_set *r, fd_set *w, fd_set *x, const struct timeval *t) { return U(select)(n, r, w, x, t); }
static int  w_ioctl(SOCKET s, long cmd, u_long *arg)       { return U(ioctlsocket)(s, cmd, arg); }
static int  w_nonblock(SOCKET s, int on) { u_long v = on ? 1 : 0; return w_ioctl(s, FIONBIO, &v); }

/* ---- fd_set helpers that do not depend on header macros needing imports ---- */
static void fs_zero(fd_set *s) { s->fd_count = 0; }
static void fs_add(fd_set *s, SOCKET k)
{
    u_int i;
    for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == k) return;
    if (s->fd_count < FD_SETSIZE) s->fd_array[s->fd_count++] = k;
}
static int fs_has(const fd_set *s, SOCKET k)
{
    u_int i;
    for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == k) return 1;
    return 0;
}
static void tv_set(struct timeval *t, long sec, long usec) { t->tv_sec = sec; t->tv_usec = usec; }

/* ---- loopback plumbing ---- */
static struct sockaddr_in lo_addr(unsigned short port_host)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;                       /* 127.0.0.1, network order on little endian */
    a.sin_port = (unsigned short)((port_host << 8) | (port_host >> 8));
    return a;
}
static int sa_port_nonzero(const struct sockaddr_in *a) { return a->sin_port != 0; }

/* TCP listener on an ephemeral loopback port; *addr receives the bound address. */
static SOCKET lo_listener(struct sockaddr_in *addr, int backlog)
{
    int n = sizeof *addr;
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return s;
    *addr = lo_addr(0);
    if (w_bind(s, addr, n) || w_getsockname(s, addr, &n) || w_listen(s, backlog)) { w_close(s); return INVALID_SOCKET; }
    return s;
}
/* Connected TCP pair over loopback; a = client end, b = accepted end. Returns 1 on success. */
static int lo_pair(SOCKET *a, SOCKET *b)
{
    struct sockaddr_in ad;
    SOCKET l = lo_listener(&ad, 1), c, s;
    *a = *b = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    c = w_socket(AF_INET, SOCK_STREAM, 0);
    if (c == INVALID_SOCKET || w_connect(c, &ad, sizeof ad)) { if (c != INVALID_SOCKET) w_close(c); w_close(l); return 0; }
    s = w_accept(l, NULL, NULL);
    w_close(l);
    if (s == INVALID_SOCKET) { w_close(c); return 0; }
    *a = c; *b = s;
    return 1;
}
/* A loopback TCP port that currently has no listener: bind, read the port, close. */
static struct sockaddr_in lo_dead_addr(void)
{
    struct sockaddr_in a = lo_addr(0);
    int n = sizeof a;
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) {
        if (w_bind(s, &a, n) || w_getsockname(s, &a, &n)) a = lo_addr(1);
        w_close(s);
    } else a = lo_addr(1);
    return a;
}
/* Receive timeout so a broken implementation fails a check instead of hanging the run. */
static void w_rcvtimeo(SOCKET s, int ms) { DWORD v = ms; w_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &v, sizeof v); }
static int w_so_error(SOCKET s) { DWORD v = 0xdeadbeef; int n = sizeof v; if (w_getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &n)) return -1; return (int)v; }

/* Join helper: wait a bounded time, then forcibly end a thread that never finished (reported by caller). */
static int join_thread(HANDLE h, DWORD ms)
{
    int ok = WaitForSingleObject(h, ms) == WAIT_OBJECT_0;
    if (!ok) TerminateThread(h, 0);
    CloseHandle(h);
    return ok;
}
/* Single-evaluation equality check (EXPECT_EQ evaluates its arguments twice, which breaks on calls). */
#define EQ(a, b) do { long long v_ = (long long)(a), w_ = (long long)(b); \
    t_check(v_ == w_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", v_, w_); } while (0)
#endif
