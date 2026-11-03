/* Shared helpers for the lift_04 area: Winsock option/startup/echo-scenario tests.
 * ws2_32.dll is never linked. Every Winsock call below is resolved with GetProcAddress through U(). */
#ifndef L4_H
#define L4_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>

#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 3
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 16
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 17
#endif
#ifndef SO_BSP_STATE
#define SO_BSP_STATE 0x1009
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif
#ifndef IP_DONTFRAGMENT
#define IP_DONTFRAGMENT 14
#endif

/* Single-evaluation comparisons (the harness EXPECT_EQ evaluates its arguments twice, which would
 * repeat any call with side effects). */
#define EQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define NE(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ != b_, __FILE__, __LINE__, #a " != " #b, "got 0x%llx", a_); } while (0)
#define NELEM(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* ---- trivial wrappers over the dynamically resolved entry points ---- */
static int  lerr(void)               { return U(WSAGetLastError)(); }
static void lset(int e)              { U(WSASetLastError)(e); }
static SOCKET sk(int af, int type, int proto) { return U(socket)(af, type, proto); }
static int  cl(SOCKET s)             { return U(closesocket)(s); }
static int  sso(SOCKET s, int lvl, int opt, const void *v, int len) { return U(setsockopt)(s, lvl, opt, (const char *)v, len); }
static int  gso(SOCKET s, int lvl, int opt, void *v, int *len)      { return U(getsockopt)(s, lvl, opt, (char *)v, len); }
static int  nonblock(SOCKET s, int on) { u_long v = on ? 1 : 0; return U(ioctlsocket)(s, FIONBIO, &v); }

static unsigned short be16(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }
static void lo4(struct sockaddr_in *a, unsigned short port_be)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007f;      /* 127.0.0.1 in network order */
    a->sin_port = port_be;
}

/* WSAStartup(2.2) for tests that need the stack; always pair with ws_down(). */
static int ws_up(void)
{
    WSADATA d;
    int r = U(WSAStartup)(MAKEWORD(2, 2), &d);
    if (r) { t_skip("WSAStartup failed: %d", r); return 0; }
    return 1;
}
static void ws_down(void) { U(WSACleanup)(); }

/* Wait (bounded) for a socket to become readable; 1 = readable, 0 = timeout. */
static int wait_readable(SOCKET s, int ms)
{
    WSAPOLLFD p;
    p.fd = s; p.events = POLLRDNORM; p.revents = 0;
    return U(WSAPoll)(&p, 1, ms) > 0 && (p.revents & (POLLRDNORM | POLLHUP | POLLERR));
}

/* recv on a non-blocking socket that retries WSAEWOULDBLOCK for a bounded time. */
static int sync_recv(SOCKET s, void *buf, int len, int flags)
{
    int i, r = SOCKET_ERROR;
    for (i = 0; i < 50; i++) {
        r = U(recv)(s, (char *)buf, len, flags);
        if (r != SOCKET_ERROR || lerr() != WSAEWOULDBLOCK) return r;
        wait_readable(s, 100);
    }
    return r;
}

/* Cap blocking operations on a socket so a misbehaving stack cannot hang the run. */
static void bound_socket(SOCKET s)
{
    DWORD ms = 10000;
    sso(s, SOL_SOCKET, SO_RCVTIMEO, &ms, sizeof ms);
    sso(s, SOL_SOCKET, SO_SNDTIMEO, &ms, sizeof ms);
}

/* Listener on 127.0.0.1:0. Returns INVALID_SOCKET on failure; *addr gets the bound address. */
static SOCKET make_listener(DWORD wsa_flags, struct sockaddr_in *addr)
{
    int len = sizeof *addr;
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, wsa_flags);
    if (s == INVALID_SOCKET) return s;
    lo4(addr, 0);
    if (U(bind)(s, (struct sockaddr *)addr, sizeof *addr) ||
        U(getsockname)(s, (struct sockaddr *)addr, &len) ||
        U(listen)(s, 8)) { cl(s); return INVALID_SOCKET; }
    return s;
}

/* Connected loopback TCP pair; returns 1 on success. */
static int make_pair(SOCKET *a, SOCKET *b, DWORD wsa_flags)
{
    struct sockaddr_in addr;
    int len = sizeof addr;
    SOCKET l = make_listener(wsa_flags, &addr);
    *a = *b = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *a = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, wsa_flags);
    if (*a == INVALID_SOCKET || U(connect)(*a, (struct sockaddr *)&addr, sizeof addr)) goto fail;
    bound_socket(l);
    *b = U(accept)(l, (struct sockaddr *)&addr, &len);
    if (*b == INVALID_SOCKET) goto fail;
    cl(l);
    bound_socket(*a); bound_socket(*b);
    return 1;
fail:
    if (*a != INVALID_SOCKET) cl(*a);
    cl(l);
    *a = *b = INVALID_SOCKET;
    return 0;
}

/* fd_set membership without the __WSAFDIsSet import. */
static int fd_has(const fd_set *set, SOCKET s)
{
    u_int i;
    for (i = 0; i < set->fd_count; i++) if (set->fd_array[i] == s) return 1;
    return 0;
}
static void fd_clr(fd_set *set, SOCKET s)
{
    u_int i;
    for (i = 0; i < set->fd_count; i++)
        if (set->fd_array[i] == s) { set->fd_array[i] = set->fd_array[--set->fd_count]; return; }
}
static void fd_add(fd_set *set, SOCKET s) { if (set->fd_count < FD_SETSIZE && !fd_has(set, s)) set->fd_array[set->fd_count++] = s; }

#endif
