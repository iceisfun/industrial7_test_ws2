/* Shared plumbing for the select_poll area: select(), __WSAFDIsSet and WSAPoll.
 *
 * Every Winsock entry point is resolved through U() (LoadLibrary + GetProcAddress); nothing here links
 * ws2_32. Sockets are always loopback, listeners always bind port 0, every wait is bounded, and a
 * readiness check that must observe "ready" first waits (bounded) for the condition with a generous
 * timeout, so the assertion proper can then use a zero timeout without racing the loopback stack.
 */
#ifndef SP_H
#define SP_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <limits.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

/* single-evaluation equality check on any integer-ish value */
#define SPEQ(a, b) do { long long v_ = (long long)(a), w_ = (long long)(b); \
    t_check(v_ == w_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", v_, w_); } while (0)

/* ---- start-up: one WSAStartup for the whole process ---- */
static int sp_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        state = (U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED_WS() do { if (!sp_up()) { t_skip("WSAStartup unavailable"); return; } \
                       if (!U(select) || !U(socket) || !U(closesocket)) { t_skip("core exports missing"); return; } } while (0)
#define NEED_POLL() do { NEED_WS(); if (!U(WSAPoll)) { t_skip("WSAPoll missing"); return; } } while (0)

/* ---- thin wrappers ---- */
static int  sp_err(void)                 { return U(WSAGetLastError)(); }
static void sp_seterr(int e)             { U(WSASetLastError)(e); }
static SOCKET sp_sock(int af, int ty, int pr) { return U(socket)(af, ty, pr); }
static void sp_close(SOCKET s)           { if (s != INVALID_SOCKET) U(closesocket)(s); }
static int  sp_bind(SOCKET s, const void *a, int n) { return U(bind)(s, (const struct sockaddr *)a, n); }
static int  sp_listen(SOCKET s, int b)   { return U(listen)(s, b); }
static int  sp_connect(SOCKET s, const void *a, int n) { return U(connect)(s, (const struct sockaddr *)a, n); }
static SOCKET sp_accept(SOCKET s)        { return U(accept)(s, NULL, NULL); }
static int  sp_getsockname(SOCKET s, void *a, int *n) { return U(getsockname)(s, (struct sockaddr *)a, n); }
static int  sp_send(SOCKET s, const void *b, int n, int f) { return U(send)(s, (const char *)b, n, f); }
static int  sp_recv(SOCKET s, void *b, int n, int f)       { return U(recv)(s, (char *)b, n, f); }
static int  sp_sendto(SOCKET s, const void *b, int n, const void *a, int al)
{ return U(sendto)(s, (const char *)b, n, 0, (const struct sockaddr *)a, al); }
static int  sp_recvfrom(SOCKET s, void *b, int n, int f) { return U(recvfrom)(s, (char *)b, n, f, NULL, NULL); }
static int  sp_nonblock(SOCKET s, int on) { u_long v = on ? 1 : 0; return U(ioctlsocket)(s, FIONBIO, &v); }
static int  sp_setopt(SOCKET s, int lvl, int opt, const void *v, int n) { return U(setsockopt)(s, lvl, opt, (const char *)v, n); }
static int  sp_getopt_int(SOCKET s, int lvl, int opt) { int v = -12345, n = sizeof v; if (U(getsockopt)(s, lvl, opt, (char *)&v, &n)) return -999; return v; }
static void sp_linger0(SOCKET s) { struct linger l = { 1, 0 }; sp_setopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l); }

/* ---- addresses ---- */
static struct sockaddr_in sp_lo4(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007f;   /* 127.0.0.1 in network order */
    return a;
}
static struct sockaddr_in6 sp_lo6(void)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr.s6_addr[15] = 1;      /* ::1 */
    return a;
}
typedef union { struct sockaddr_in a4; struct sockaddr_in6 a6; } sp_addr;
static int sp_alen(int af) { return af == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in); }
static void sp_loaddr(int af, sp_addr *a) { memset(a, 0, sizeof *a); if (af == AF_INET6) a->a6 = sp_lo6(); else a->a4 = sp_lo4(); }

/* IPv6 loopback available? (bind a throw-away socket) */
static int sp_have_v6(void)
{
    static int st;
    if (!st) {
        SOCKET s = sp_sock(AF_INET6, SOCK_STREAM, 0);
        st = -1;
        if (s != INVALID_SOCKET) {
            struct sockaddr_in6 a = sp_lo6();
            if (sp_bind(s, &a, sizeof a) == 0) st = 1;
            sp_close(s);
        }
    }
    return st > 0;
}

/* TCP listener on an ephemeral loopback port. */
static SOCKET sp_listener(int af, sp_addr *out, int backlog)
{
    sp_addr a;
    int n = sp_alen(af);
    SOCKET s = sp_sock(af, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return s;
    sp_loaddr(af, &a);
    if (sp_bind(s, &a, n) || sp_getsockname(s, &a, &n) || sp_listen(s, backlog)) { sp_close(s); return INVALID_SOCKET; }
    if (out) *out = a;
    return s;
}
/* Connected blocking TCP pair; *c is the connecting end, *s the accepted end. */
static int sp_pair_af(int af, SOCKET *c, SOCKET *s)
{
    sp_addr a;
    SOCKET l = sp_listener(af, &a, 4), cc;
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    cc = sp_sock(af, SOCK_STREAM, 0);
    if (cc == INVALID_SOCKET || sp_connect(cc, &a, sp_alen(af))) { sp_close(cc); sp_close(l); return 0; }
    *s = sp_accept(l);
    sp_close(l);
    if (*s == INVALID_SOCKET) { sp_close(cc); return 0; }
    *c = cc;
    return 1;
}
static int sp_pair(SOCKET *c, SOCKET *s) { return sp_pair_af(AF_INET, c, s); }

/* UDP socket bound to an ephemeral loopback port; *out receives the address. */
static SOCKET sp_udp(int af, sp_addr *out)
{
    sp_addr a;
    int n = sp_alen(af);
    SOCKET s = sp_sock(af, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return s;
    sp_loaddr(af, &a);
    if (sp_bind(s, &a, n) || sp_getsockname(s, &a, &n)) { sp_close(s); return INVALID_SOCKET; }
    if (out) *out = a;
    return s;
}
/* Loopback TCP address that currently has no listener (bound then released). */
static sp_addr sp_dead(int af)
{
    sp_addr a;
    SOCKET s = sp_listener(af, &a, 0);
    if (s == INVALID_SOCKET) sp_loaddr(af, &a);
    sp_close(s);
    return a;
}
/* A closed-then-released datagram port. */
static sp_addr sp_dead_udp(int af)
{
    sp_addr a;
    SOCKET s = sp_udp(af, &a);
    if (s == INVALID_SOCKET) sp_loaddr(af, &a);
    sp_close(s);
    return a;
}

/* ---- fd_set helpers (no FD_SETSIZE limit; capacity is the caller's business) ---- */
static fd_set *sp_newset(unsigned cap)
{
    fd_set *s = (fd_set *)calloc(1, offsetof(fd_set, fd_array) + (cap ? cap : 1) * sizeof(SOCKET));
    return s;
}
static void sp_zero(fd_set *s)  { s->fd_count = 0; }
static void sp_put(fd_set *s, SOCKET k)   { s->fd_array[s->fd_count++] = k; }   /* raw append, duplicates allowed */
static void sp_add(fd_set *s, SOCKET k)   /* append unless present */
{
    u_int i;
    for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == k) return;
    s->fd_array[s->fd_count++] = k;
}
static int sp_has(const fd_set *s, SOCKET k)
{
    u_int i;
    for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == k) return 1;
    return 0;
}
static int sp_idx(const fd_set *s, SOCKET k)
{
    u_int i;
    for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == k) return (int)i;
    return -1;
}
/* Stack set of at most FD_SETSIZE sockets. */
typedef fd_set sp_set;
static void sp_set1(fd_set *s, SOCKET a) { sp_zero(s); sp_put(s, a); }

/* select with a millisecond timeout (negative = NULL timeout = wait forever). */
static int sp_sel(fd_set *r, fd_set *w, fd_set *x, int ms)
{
    struct timeval tv;
    if (ms >= 0) { tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000; }
    return U(select)(0, r, w, x, ms >= 0 ? &tv : NULL);
}
/* one-socket probes: 1 when ready within ms, 0 when not, -1 on error */
static int sp_readable(SOCKET s, int ms)  { fd_set f; sp_set1(&f, s); return sp_sel(&f, NULL, NULL, ms); }
static int sp_writable(SOCKET s, int ms)  { fd_set f; sp_set1(&f, s); return sp_sel(NULL, &f, NULL, ms); }
static int sp_excepted(SOCKET s, int ms)  { fd_set f; sp_set1(&f, s); return sp_sel(NULL, NULL, &f, ms); }
/* wait (bounded, generous) until readable; the caller then asserts with a zero timeout */
static int sp_wait_readable(SOCKET s) { return sp_readable(s, 4000) == 1; }
static int sp_wait_excepted(SOCKET s) { return sp_excepted(s, 4000) == 1; }

/* ---- WSAPoll helpers ---- */
static int sp_poll(SOCKET s, short events, int ms, short *revents)
{
    WSAPOLLFD p;
    int r;
    p.fd = s; p.events = events; p.revents = (short)0x7ead;
    r = U(WSAPoll)(&p, 1, ms);
    if (revents) *revents = p.revents;
    return r;
}
/* revents of a zero-timeout poll; -1 if the call failed */
static int sp_rev(SOCKET s, short events)
{
    short rv = 0;
    if (sp_poll(s, events, 0, &rv) < 0) return -1;
    return (unsigned short)rv;
}
/* wait (bounded) until revents has at least `bits` for events, then return the settled revents */
static int sp_poll_settle(SOCKET s, short events, short bits)
{
    short rv = 0;
    int i;
    for (i = 0; i < 40; i++) {
        if (sp_poll(s, events, 100, &rv) > 0 && (rv & bits) == bits) return (unsigned short)rv;
    }
    return (unsigned short)rv;
}
#define PEQ(sock, ev, want) do { int r_ = sp_rev((sock), (short)(ev)); \
    t_check(r_ == (int)(unsigned short)(want), __FILE__, __LINE__, "poll(" #sock "," #ev ") == " #want, "got 0x%x want 0x%x", r_, (unsigned)(unsigned short)(want)); } while (0)

/* ---- threads ---- */
typedef struct { DWORD delay_ms; void (*fn)(void *); void *arg; } sp_job;
static DWORD WINAPI sp_job_main(void *p)
{
    sp_job j = *(sp_job *)p;
    free(p);
    Sleep(j.delay_ms);
    j.fn(j.arg);
    return 0;
}
/* run fn(arg) on a new thread after delay_ms */
static HANDLE sp_after(DWORD delay_ms, void (*fn)(void *), void *arg)
{
    sp_job *j = (sp_job *)malloc(sizeof *j);
    HANDLE h;
    j->delay_ms = delay_ms; j->fn = fn; j->arg = arg;
    h = CreateThread(NULL, 0, sp_job_main, j, 0, NULL);
    if (!h) free(j);
    return h;
}
static int sp_join(HANDLE h, DWORD ms)
{
    int ok;
    if (!h) return 0;
    ok = WaitForSingleObject(h, ms) == WAIT_OBJECT_0;
    if (!ok) TerminateThread(h, 0);
    CloseHandle(h);
    return ok;
}
static void sp_job_send1(void *p)  { sp_send((SOCKET)(ULONG_PTR)p, "x", 1, 0); }
static void sp_job_close(void *p)  { sp_close((SOCKET)(ULONG_PTR)p); }
static void sp_job_shutsend(void *p) { U(shutdown)((SOCKET)(ULONG_PTR)p, SD_SEND); }
typedef struct { SOCKET s; const sp_addr *to; int af; } sp_conn_arg;
static void sp_job_connect(void *p)
{
    sp_conn_arg *c = (sp_conn_arg *)p;
    SOCKET s = sp_sock(c->af, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) { sp_connect(s, c->to, sp_alen(c->af)); c->s = s; }
}

/* APC counter for alertable-wait checks */
static volatile LONG sp_apc_hits;
static VOID CALLBACK sp_apc(ULONG_PTR p) { InterlockedIncrement(&sp_apc_hits); }

/* Deterministic pseudo-random generator for model-based tests. */
static unsigned sp_rng(unsigned *st) { *st = *st * 1664525u + 1013904223u; return *st >> 8; }

/* Instantiate a test body once per address family; the v6 variant skips when ::1 is unusable. */
#define FAMILY_TEST(name) \
    static void name##_body(int af); \
    TEST(name##_v4) { NEED_WS(); name##_body(AF_INET); } \
    TEST(name##_v6) { NEED_WS(); if (!sp_have_v6()) { t_skip("no IPv6 loopback"); return; } name##_body(AF_INET6); } \
    static void name##_body(int af)

#endif
