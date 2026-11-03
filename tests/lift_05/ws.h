/* Shared helpers for the lift_05 area: thin wrappers that call Winsock only through
 * GetProcAddress-resolved pointers (never linked), plus small address/byte-order helpers
 * written locally so that no import from the DLL under test is needed. */
#ifndef LIFT05_WS_H
#define LIFT05_WS_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <ws2bth.h>
#include <wsnwlink.h>
#ifndef NSPROTO_IPX
#define NSPROTO_IPX 1000
#endif
#ifndef AF_IPX
#define AF_IPX 6
#endif

#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 21
#endif
#ifndef IPV6_TCLASS
#define IPV6_TCLASS 39
#endif
#ifndef IPV6_RECVTCLASS
#define IPV6_RECVTCLASS 40
#endif

/* ---- byte order, no import needed ---- */
static inline unsigned short h16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }
static inline unsigned int h32(unsigned int v) {
    return (v << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
}

/* ---- wrappers (all calls go through resolved pointers) ---- */
static inline int w_err(void) { return U(WSAGetLastError)(); }
static inline void w_seterr(int e) { U(WSASetLastError)(e); }
static inline SOCKET w_socket(int af, int ty, int pr) { return U(socket)(af, ty, pr); }
static inline int w_closesocket(SOCKET s) { return U(closesocket)(s); }
static inline void w_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static inline int w_bind(SOCKET s, const void *a, int l) { return U(bind)(s, (const struct sockaddr *)a, l); }
static inline int w_connect(SOCKET s, const void *a, int l) { return U(connect)(s, (const struct sockaddr *)a, l); }
static inline int w_listen(SOCKET s, int b) { return U(listen)(s, b); }
static inline SOCKET w_accept(SOCKET s, void *a, int *l) { return U(accept)(s, (struct sockaddr *)a, l); }
static inline int w_shutdown(SOCKET s, int how) { return U(shutdown)(s, how); }
static inline int w_setsockopt(SOCKET s, int lv, int nm, const void *v, int l) { return U(setsockopt)(s, lv, nm, (const char *)v, l); }
static inline int w_getsockopt(SOCKET s, int lv, int nm, void *v, int *l) { return U(getsockopt)(s, lv, nm, (char *)v, l); }
static inline int w_getsockname(SOCKET s, void *a, int *l) { return U(getsockname)(s, (struct sockaddr *)a, l); }
static inline int w_send(SOCKET s, const void *b, int n, int f) { return U(send)(s, (const char *)b, n, f); }
static inline int w_recv(SOCKET s, void *b, int n, int f) { return U(recv)(s, (char *)b, n, f); }
static inline int w_sendto(SOCKET s, const void *b, int n, int f, const void *a, int l) {
    return U(sendto)(s, (const char *)b, n, f, (const struct sockaddr *)a, l);
}
static inline int w_recvfrom(SOCKET s, void *b, int n, int f, void *a, int *l) {
    return U(recvfrom)(s, (char *)b, n, f, (struct sockaddr *)a, l);
}
static inline int w_ioctlsocket(SOCKET s, long cmd, unsigned long *arg) { return U(ioctlsocket)(s, cmd, arg); }

/* fd_set helpers that do not need __WSAFDIsSet */
static inline void fds_one(fd_set *f, SOCKET s) { f->fd_count = 1; f->fd_array[0] = s; }
static inline int fds_has(const fd_set *f, SOCKET s) {
    for (u_int i = 0; i < f->fd_count; i++) if (f->fd_array[i] == s) return 1;
    return 0;
}
static inline void fds_add(fd_set *f, SOCKET s) { if (f->fd_count < FD_SETSIZE && !fds_has(f, s)) f->fd_array[f->fd_count++] = s; }
static inline void fds_del(fd_set *f, SOCKET s) {
    for (u_int i = 0; i < f->fd_count; i++)
        if (f->fd_array[i] == s) { f->fd_array[i] = f->fd_array[--f->fd_count]; return; }
}
/* select with a bounded wait (ms); returns select()'s result */
static inline int w_select(fd_set *r, fd_set *w, fd_set *x, int ms) {
    TIMEVAL tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, r, w, x, &tv);
}
/* 1 when the socket is readable (or a listener has a pending connection) within ms */
static inline int w_readable(SOCKET s, int ms) {
    fd_set r; fds_one(&r, s);
    return w_select(&r, NULL, NULL, ms) == 1;
}
/* accept with a bounded wait so a mis-delivered connection cannot hang the test */
static inline SOCKET w_accept_to(SOCKET l, int ms) {
    if (!w_readable(l, ms)) return INVALID_SOCKET;
    return w_accept(l, NULL, NULL);
}
static inline int w_set_rcvtimeo(SOCKET s, int ms) {
    DWORD v = (DWORD)ms; return w_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &v, sizeof v);
}
static inline int w_nonblock(SOCKET s, int on) { unsigned long v = on; return w_ioctlsocket(s, FIONBIO, &v); }

/* Resolve ws2_32 once and start Winsock 2.2; returns 0 (and skips) if the stack is missing. */
static inline int ws_up(void) {
    static int state;                         /* 0 unknown, 1 up, -1 unavailable */
    if (state == 0) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || !t_proc_in("ws2_32.dll", "socket")) state = -1;
        else state = (U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (state < 0) { t_skip("ws2_32 unavailable"); return 0; }
    return 1;
}

/* ---- loopback address builders (network-order ports) ---- */
enum { A_ANY, A_LOOP, A_MAPPED_ANY, A_MAPPED_LOOP };
/* Fills ss for family af (AF_INET / AF_INET6); returns length. */
static inline int mk_addr(struct sockaddr_storage *ss, int af, int kind, unsigned short port_net) {
    memset(ss, 0, sizeof *ss);
    if (af == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET; a->sin_port = port_net;
        a->sin_addr.s_addr = (kind == A_LOOP) ? h32(0x7f000001u) : 0;
        return sizeof *a;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6; a->sin6_port = port_net;
        if (kind == A_LOOP) a->sin6_addr.u.Byte[15] = 1;
        else if (kind == A_MAPPED_ANY || kind == A_MAPPED_LOOP) {
            a->sin6_addr.u.Byte[10] = 0xff; a->sin6_addr.u.Byte[11] = 0xff;
            if (kind == A_MAPPED_LOOP) { a->sin6_addr.u.Byte[12] = 127; a->sin6_addr.u.Byte[15] = 1; }
        }
        return sizeof *a;
    }
}
static inline unsigned short addr_port(const struct sockaddr_storage *ss) {
    return ((const struct sockaddr_in *)ss)->sin_port;     /* same offset for v4 and v6 */
}

/* 1 when IPv6 loopback can be bound on this machine (cached). */
static inline int v6_usable(void) {
    static int st;
    if (!st) {
        SOCKET s = w_socket(AF_INET6, SOCK_DGRAM, 0);
        struct sockaddr_storage a; int l = mk_addr(&a, AF_INET6, A_LOOP, 0);
        st = (s != INVALID_SOCKET && w_bind(s, &a, l) == 0) ? 1 : -1;
        w_close(s);
    }
    return st > 0;
}
/* Picks a currently free TCP/UDP port (network order) usable on both stacks when v6 works. */
static inline unsigned short free_port(int type) {
    struct sockaddr_storage a; int l, af = v6_usable() ? AF_INET6 : AF_INET;
    SOCKET s = w_socket(af, type, 0);
    unsigned short p = 0; int n = sizeof a;
    if (s == INVALID_SOCKET) return 0;
    if (af == AF_INET6) { DWORD off = 0; w_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off); }
    l = mk_addr(&a, af, A_ANY, 0);
    if (w_bind(s, &a, l) == 0 && w_getsockname(s, &a, &n) == 0) p = addr_port(&a);
    w_close(s);
    return p;
}
#endif
