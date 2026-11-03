/* Shared helpers for the af_unix area: lazy WSAStartup, SOCKADDR_UN construction, scratch socket paths,
 * a connected AF_UNIX stream trio (listener / client / accepted), bounded waits.
 * Every Winsock call goes through U(); nothing here links the DLL under test.
 * Observed-but-unverified behaviour is reported with AU_OBS (a note, never a failure). */
#ifndef AU_H
#define AU_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <afunix.h>

#ifndef POLLRDNORM
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLWRNORM 0x0010
#define POLLERR 0x0001
#define POLLHUP 0x0002
#define POLLNVAL 0x0004
#endif
#ifndef SO_BSP_STATE
#define SO_BSP_STATE 0x1009
#endif
#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME 0x700C
#endif

/* EXPECT_EQ evaluates its arguments twice; this one does not, so calls can sit inside it. */
#define AU_EQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define AU_OBS(what, ...) do { char o_[160]; snprintf(o_, sizeof o_, __VA_ARGS__); t_note("%s: %s", what, o_); } while (0)

static int au_up(void)
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
#define UP() do { if (!au_up()) return; } while (0)

/* FD_ISSET would import from the library under test; scan the array instead. */
static int au_isset(SOCKET s, const fd_set *f)
{
    u_int i;
    for (i = 0; i < f->fd_count; i++) if (f->fd_array[i] == s) return 1;
    return 0;
}
static int au_err(void) { return U(WSAGetLastError)(); }
static void au_seterr(int e) { U(WSASetLastError)(e); }
#define AU_POISON 0x5a5a

/* AF_UNIX stream socket, or skip the calling test when the family is not offered. */
static SOCKET au_sock_flags(DWORD flags)
{
    SOCKET s;
    if (!au_up()) return INVALID_SOCKET;
    s = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, flags);
    if (s == INVALID_SOCKET && au_err() == WSAEAFNOSUPPORT) t_skip("AF_UNIX not supported");
    return s;
}
static SOCKET au_sock(void) { return au_sock_flags(WSA_FLAG_OVERLAPPED); }
#define SOCK_OR_RETURN(v) SOCKET v = au_sock(); if (v == INVALID_SOCKET) return

/* Address with the given path (at most 107 characters plus terminator). */
static void au_addr(SOCKADDR_UN *a, const char *path)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    strncpy(a->sun_path, path, sizeof(a->sun_path) - 1);
}
/* Absolute path of a leaf file in the scratch directory. */
static const char *au_path(const char *leaf)
{
    static char ring[8][MAX_PATH];
    static int n;
    char *p = ring[n++ & 7];
    t_tmpfile(p, MAX_PATH, leaf);
    return p;
}
static void au_addr_leaf(SOCKADDR_UN *a, const char *leaf) { au_addr(a, au_path(leaf)); }

static int au_bind_to(SOCKET s, const SOCKADDR_UN *a) { return U(bind)(s, (const struct sockaddr *)a, sizeof(*a)); }
static int au_bind_leaf(SOCKET s, const char *leaf, SOCKADDR_UN *out)
{
    SOCKADDR_UN a;
    au_addr_leaf(&a, leaf);
    if (out) *out = a;
    return au_bind_to(s, &a);
}

static int au_blocking(SOCKET s, BOOL blocking)
{
    u_long v = !blocking;
    return U(ioctlsocket)(s, FIONBIO, &v);
}
static void au_rcvtimeo(SOCKET s, DWORD ms) { U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms)); }
static void au_sndtimeo(SOCKET s, DWORD ms) { U(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms)); }

/* select() based bounded waits; return 1 when ready. */
static int au_wait(SOCKET s, int want_write, int ms)
{
    fd_set f, e;
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    FD_ZERO(&f); FD_SET(s, &f);
    FD_ZERO(&e); FD_SET(s, &e);
    return U(select)(0, want_write ? NULL : &f, want_write ? &f : NULL, &e, &tv) > 0;
}
static int au_readable(SOCKET s, int ms) { return au_wait(s, 0, ms); }
static int au_writable(SOCKET s, int ms) { return au_wait(s, 1, ms); }

static SOCKET au_accept_bounded(SOCKET lis)
{
    if (!au_readable(lis, 3000)) return INVALID_SOCKET;
    return U(accept)(lis, NULL, NULL);
}

/* Connect cli to a through a non-blocking connect; accept on lis; restore blocking mode on cli. */
static SOCKET au_connect_accept(SOCKET lis, SOCKET cli, const SOCKADDR_UN *a)
{
    SOCKET srv;
    int r;
    au_blocking(cli, FALSE);
    r = U(connect)(cli, (const struct sockaddr *)a, sizeof(*a));
    CHECKF(r == 0 || au_err() == WSAEWOULDBLOCK, "connect ret %d err %d", r, au_err());
    srv = au_accept_bounded(lis);
    CHECK(srv != INVALID_SOCKET);
    au_blocking(cli, TRUE);
    return srv;
}

struct au_trio { SOCKET lis, cli, srv; SOCKADDR_UN addr; char path[MAX_PATH]; };

/* Listener bound to a scratch leaf, a connected client and the accepted socket. Returns 0 and skips on failure. */
static int au_trio_open(struct au_trio *t, const char *leaf)
{
    t->lis = t->cli = t->srv = INVALID_SOCKET;
    t->lis = au_sock();
    if (t->lis == INVALID_SOCKET) return 0;
    t->cli = au_sock();
    au_addr_leaf(&t->addr, leaf);
    strcpy(t->path, t->addr.sun_path);
    if (t->cli == INVALID_SOCKET || au_bind_to(t->lis, &t->addr) || U(listen)(t->lis, 4)) {
        t_skip("cannot create AF_UNIX listener");
        if (t->cli != INVALID_SOCKET) U(closesocket)(t->cli);
        U(closesocket)(t->lis);
        DeleteFileA(t->path);
        t->lis = t->cli = INVALID_SOCKET;
        return 0;
    }
    t->srv = au_connect_accept(t->lis, t->cli, &t->addr);
    if (t->srv == INVALID_SOCKET) {
        t_skip("cannot connect AF_UNIX pair");
        U(closesocket)(t->cli); U(closesocket)(t->lis);
        DeleteFileA(t->path);
        t->lis = t->cli = INVALID_SOCKET;
        return 0;
    }
    au_rcvtimeo(t->cli, 3000); au_rcvtimeo(t->srv, 3000);
    au_sndtimeo(t->cli, 3000); au_sndtimeo(t->srv, 3000);
    return 1;
}
static void au_trio_close(struct au_trio *t)
{
    if (t->srv != INVALID_SOCKET) U(closesocket)(t->srv);
    if (t->cli != INVALID_SOCKET) U(closesocket)(t->cli);
    if (t->lis != INVALID_SOCKET) U(closesocket)(t->lis);
    DeleteFileA(t->path);
    t->srv = t->cli = t->lis = INVALID_SOCKET;
}
#define TRIO(t, leaf) struct au_trio t; if (!au_trio_open(&t, leaf)) return

/* Remove a scratch socket file (the file outlives the socket on Windows). */
static void au_unlink_leaf(const char *leaf) { DeleteFileA(au_path(leaf)); }

static int au_send_all(SOCKET s, const char *p, int n)
{
    int off = 0;
    while (off < n) {
        int r = U(send)(s, p + off, n - off, 0);
        if (r <= 0) return -1;
        off += r;
    }
    return off;
}
static int au_recv_n(SOCKET s, char *p, int n)
{
    int off = 0;
    while (off < n) {
        int r = U(recv)(s, p + off, n - off, 0);
        if (r <= 0) return off ? off : r;
        off += r;
    }
    return off;
}
static short au_poll1(SOCKET s, short events, int ms)
{
    WSAPOLLFD p;
    p.fd = s; p.events = events; p.revents = 0;
    U(WSAPoll)(&p, 1, ms);
    return p.revents;
}
#endif
