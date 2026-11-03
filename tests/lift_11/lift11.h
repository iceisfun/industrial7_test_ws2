/* Shared helpers for the lift_11 area: lazy WSAStartup, loopback TCP pairs on
 * ephemeral ports, blocking-mode switch, poll probe, RST-style close.
 * Every Winsock call goes through U(); nothing here links the DLL under test. */
#ifndef LIFT11_H
#define LIFT11_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>

#ifndef POLLRDNORM
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLWRNORM 0x0010
#define POLLERR 0x0001
#define POLLHUP 0x0002
#endif

/* Start Winsock once per process; skip the calling test when that fails. */
/* EXPECT_EQ evaluates its arguments twice; this one does not, so calls can sit inside it. */
#define L_EQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)

static int l11_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        __typeof__(&WSAStartup) f = U(WSAStartup);
        state = (f && f(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (state < 0) t_skip("WSAStartup unavailable");
    return state > 0;
}
#define UP() do { if (!l11_up()) return; } while (0)

/* Byte-order helpers (the harness never imports from the DLL under test). */
#define l11_h16(x) ((unsigned short)__builtin_bswap16((unsigned short)(x)))
#define l11_h32(x) ((unsigned)__builtin_bswap32((unsigned)(x)))

static void l11_loopback(struct sockaddr_in *a)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007f; /* 127.0.0.1, network order */
}

/* Connected loopback TCP pair; the listener is closed again. flags are WSASocket flags. */
static int l11_pair_flags(SOCKET *cli, SOCKET *srv, DWORD flags)
{
    struct sockaddr_in a;
    int len = sizeof(a), ok = 1;
    SOCKET lis, c;
    l11_loopback(&a);
    lis = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    c = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    *cli = *srv = INVALID_SOCKET;
    if (lis == INVALID_SOCKET || c == INVALID_SOCKET) ok = 0;
    if (ok && (U(bind)(lis, (struct sockaddr *)&a, sizeof(a)) ||
               U(getsockname)(lis, (struct sockaddr *)&a, &len) ||
               U(listen)(lis, 1) ||
               U(connect)(c, (struct sockaddr *)&a, sizeof(a)))) ok = 0;
    if (ok) {
        fd_set r;
        struct timeval tv = {5, 0};
        FD_ZERO(&r); FD_SET(lis, &r);
        if (U(select)(0, &r, NULL, NULL, &tv) == 1) {
            len = sizeof(a);
            *srv = U(accept)(lis, (struct sockaddr *)&a, &len);
        }
    }
    if (lis != INVALID_SOCKET) U(closesocket)(lis);
    if (*srv == INVALID_SOCKET) {
        if (c != INVALID_SOCKET) U(closesocket)(c);
        t_skip("could not build a loopback TCP pair");
        return 0;
    }
    *cli = c;
    return 1;
}
static int l11_pair(SOCKET *cli, SOCKET *srv) { return l11_pair_flags(cli, srv, WSA_FLAG_OVERLAPPED); }
#define PAIR(c, s) do { if (!l11_pair(c, s)) return; } while (0)
#define PAIRF(c, s, f) do { if (!l11_pair_flags(c, s, f)) return; } while (0)

static int l11_blocking(SOCKET s, BOOL blocking)
{
    u_long v = !blocking;
    return U(ioctlsocket)(s, FIONBIO, &v);
}

/* WSAPoll with a short wait; returns revents (0 when nothing reported) and flags a
 * mismatch between the return count and the reported events. */
static short l11_poll(SOCKET s, short events, int *count_ok)
{
    WSAPOLLFD p;
    int r;
    p.fd = s; p.events = events; p.revents = 0;
    r = U(WSAPoll)(&p, 1, 1000);
    if (count_ok) *count_ok = (r == (p.revents ? 1 : 0));
    return p.revents;
}

/* Abortive close: zero linger makes the peer see a reset. */
static void l11_close_rst(SOCKET s)
{
    struct linger lg = {1, 0};
    U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof(lg));
    U(closesocket)(s);
}

/* FD_ISSET would import __WSAFDIsSet; scan the array instead. */
static int l11_isset(SOCKET s, const fd_set *f)
{
    u_int i;
    for (i = 0; i < f->fd_count; i++) if (f->fd_array[i] == s) return 1;
    return 0;
}

static int l11_err(void) { return U(WSAGetLastError)(); }
static void l11_seterr(int e) { U(WSASetLastError)(e); }

/* Receive timeout so an unexpected absence of data cannot hang a test. */
static void l11_rcvtimeo(SOCKET s, DWORD ms)
{
    U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
}
#endif
