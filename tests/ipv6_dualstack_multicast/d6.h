/* Shared helpers for the ipv6_dualstack_multicast area.  Every Winsock call goes through a pointer
 * resolved with GetProcAddress (U/UIN); nothing from the DLL under test is linked. */
#ifndef D6_H
#define D6_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 21
#endif
#ifndef IPV6_RECVTCLASS
#define IPV6_RECVTCLASS 40
#endif
#ifndef IPV6_TCLASS
#define IPV6_TCLASS 39
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 14
#endif

#define SZ_SA6 ((int)sizeof(struct sockaddr_in6))
#define SZ_SA4 ((int)sizeof(struct sockaddr_in))

/* EXPECT_EQ evaluates its arguments twice; never put a call with side effects in it. */
#define EQC(call, want) do { long long r_ = (long long)(call); EXPECT_EQ(r_, (want)); } while (0)

/* ---- thin call wrappers ---------------------------------------------------- */
static inline int d_err(void) { return U(WSAGetLastError)(); }
static inline void d_seterr(int e) { U(WSASetLastError)(e); }
/* Every socket gets a receive timeout so a datagram that never arrives fails a check instead of hanging. */
static inline SOCKET d_sock(int af, int ty) {
    SOCKET s = U(socket)(af, ty, 0);
    if (s != INVALID_SOCKET) { DWORD ms = 4000; U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms); }
    return s;
}
static inline void d_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static inline int d_bind(SOCKET s, const void *a, int l) { return U(bind)(s, (const struct sockaddr *)a, l); }
static inline int d_connect(SOCKET s, const void *a, int l) { return U(connect)(s, (const struct sockaddr *)a, l); }
static inline int d_listen(SOCKET s, int b) { return U(listen)(s, b); }
static inline SOCKET d_accept(SOCKET s, void *a, int *l) { return U(accept)(s, (struct sockaddr *)a, l); }
static inline int d_sso(SOCKET s, int lv, int nm, const void *v, int l) { return U(setsockopt)(s, lv, nm, (const char *)v, l); }
static inline int d_gso(SOCKET s, int lv, int nm, void *v, int *l) { return U(getsockopt)(s, lv, nm, (char *)v, l); }
static inline int d_name(SOCKET s, void *a, int *l) { return U(getsockname)(s, (struct sockaddr *)a, l); }
static inline int d_peer(SOCKET s, void *a, int *l) { return U(getpeername)(s, (struct sockaddr *)a, l); }
static inline int d_send(SOCKET s, const void *b, int n) { return U(send)(s, (const char *)b, n, 0); }
static inline int d_recv(SOCKET s, void *b, int n) { return U(recv)(s, (char *)b, n, 0); }
static inline int d_sendto(SOCKET s, const void *b, int n, const void *a, int l) {
    return U(sendto)(s, (const char *)b, n, 0, (const struct sockaddr *)a, l);
}
static inline int d_recvfrom(SOCKET s, void *b, int n, void *a, int *l) {
    return U(recvfrom)(s, (char *)b, n, 0, (struct sockaddr *)a, l);
}

static inline unsigned short d_h16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }
static inline unsigned int d_h32(unsigned int v) {
    return (v << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
}

/* Start Winsock 2.2 once; skip the test when the stack is not usable. */
static inline int d_up(void) {
    static int st;
    if (!st) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || !t_proc_in("ws2_32.dll", "socket")) st = -1;
        else st = U(WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1;
    }
    if (st < 0) { t_skip("winsock unavailable"); return 0; }
    return 1;
}

/* ---- address builders (ports in network order) ------------------------------ */
enum { K_ANY, K_LOOP, K_MAP_ANY, K_MAP_LOOP };
static inline void mk6(struct sockaddr_in6 *a, int kind, unsigned short port_net) {
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6; a->sin6_port = port_net;
    if (kind == K_LOOP) a->sin6_addr.u.Byte[15] = 1;
    if (kind == K_MAP_ANY || kind == K_MAP_LOOP) {
        a->sin6_addr.u.Byte[10] = 0xff; a->sin6_addr.u.Byte[11] = 0xff;
        if (kind == K_MAP_LOOP) { a->sin6_addr.u.Byte[12] = 127; a->sin6_addr.u.Byte[15] = 1; }
    }
}
static inline void mk4(struct sockaddr_in *a, int loop, unsigned short port_net) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET; a->sin_port = port_net;
    a->sin_addr.s_addr = loop ? d_h32(0x7f000001u) : 0;
}
static inline int is_mapped_loop(const struct sockaddr_in6 *a) {
    static const unsigned char want[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1};
    return a->sin6_family == AF_INET6 && !memcmp(a->sin6_addr.u.Byte, want, 16);
}
static inline int is_v6_loop(const struct sockaddr_in6 *a) {
    static const unsigned char want[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return a->sin6_family == AF_INET6 && !memcmp(a->sin6_addr.u.Byte, want, 16);
}

/* ---- readiness ------------------------------------------------------------- */
static inline int d_readable(SOCKET s, int ms) {
    fd_set r; TIMEVAL tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
static inline int d_writable_or_failed(SOCKET s, int ms, int *failed) {
    fd_set w, x; TIMEVAL tv;
    w.fd_count = 1; w.fd_array[0] = s; x.fd_count = 1; x.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    int n = U(select)(0, NULL, &w, &x, &tv);
    *failed = (x.fd_count == 1);
    return n > 0;
}
static inline SOCKET d_accept_to(SOCKET l, int ms, void *a, int *len) {
    if (!d_readable(l, ms)) return INVALID_SOCKET;
    return d_accept(l, a, len);
}
static inline int d_recv_to(SOCKET s, void *b, int n, int ms) {
    if (!d_readable(s, ms)) return -2;
    return d_recv(s, b, n);
}
static inline int d_rcvtimeo(SOCKET s, int ms) { DWORD v = ms; return d_sso(s, SOL_SOCKET, SO_RCVTIMEO, &v, sizeof v); }
static inline int d_setint(SOCKET s, int lv, int nm, int v) { return d_sso(s, lv, nm, &v, sizeof v); }
static inline int d_getint(SOCKET s, int lv, int nm, int *v) { int l = sizeof *v; *v = 0; return d_gso(s, lv, nm, v, &l); }

/* ---- usability probes (cached) -------------------------------------------- */
static inline int d_v6_ok(void) {
    static int st;
    if (!st) {
        SOCKET s = d_sock(AF_INET6, SOCK_DGRAM);
        struct sockaddr_in6 a; mk6(&a, K_LOOP, 0);
        st = (s != INVALID_SOCKET && d_bind(s, &a, sizeof a) == 0) ? 1 : -1;
        d_close(s);
    }
    return st > 0;
}
#define NEED_V6() do { if (!d_up()) return; if (!d_v6_ok()) { t_skip("IPv6 loopback unavailable"); return; } } while (0)

/* A TCP listener on loopback with an ephemeral port.  fam is AF_INET or AF_INET6; for AF_INET6,
 * v6only is applied first (-1 leaves the default) and kind chooses the bind address. */
typedef struct { SOCKET s; unsigned short port; } lsn;
static inline int lsn_open6(lsn *l, int kind, int v6only) {
    struct sockaddr_in6 a; int n = sizeof a;
    memset(l, 0, sizeof *l);
    l->s = d_sock(AF_INET6, SOCK_STREAM);
    if (l->s == INVALID_SOCKET) return 0;
    if (v6only >= 0) d_setint(l->s, IPPROTO_IPV6, IPV6_V6ONLY, v6only);
    mk6(&a, kind, 0);
    if (d_bind(l->s, &a, sizeof a) || d_listen(l->s, 4) || d_name(l->s, &a, &n)) return 0;
    l->port = a.sin6_port;
    return 1;
}
static inline int lsn_open4(lsn *l) {
    struct sockaddr_in a; int n = sizeof a;
    memset(l, 0, sizeof *l);
    l->s = d_sock(AF_INET, SOCK_STREAM);
    if (l->s == INVALID_SOCKET) return 0;
    mk4(&a, 1, 0);
    if (d_bind(l->s, &a, sizeof a) || d_listen(l->s, 4) || d_name(l->s, &a, &n)) return 0;
    l->port = a.sin_port;
    return 1;
}

/* A UDP socket bound to an address on an ephemeral port. */
typedef struct { SOCKET s; unsigned short port; } usk;
static inline int usk_open6(usk *u, int kind, int v6only) {
    struct sockaddr_in6 a; int n = sizeof a;
    memset(u, 0, sizeof *u);
    u->s = d_sock(AF_INET6, SOCK_DGRAM);
    if (u->s == INVALID_SOCKET) return 0;
    if (v6only >= 0) d_setint(u->s, IPPROTO_IPV6, IPV6_V6ONLY, v6only);
    mk6(&a, kind, 0);
    if (d_bind(u->s, &a, sizeof a) || d_name(u->s, &a, &n)) return 0;
    u->port = a.sin6_port;
    return 1;
}
static inline int usk_open4(usk *u, int loop) {
    struct sockaddr_in a; int n = sizeof a;
    memset(u, 0, sizeof *u);
    u->s = d_sock(AF_INET, SOCK_DGRAM);
    if (u->s == INVALID_SOCKET) return 0;
    mk4(&a, loop, 0);
    if (d_bind(u->s, &a, sizeof a) || d_name(u->s, &a, &n)) return 0;
    u->port = a.sin_port;
    return 1;
}

/* WSARecvMsg / WSASendMsg via the extension-function ioctl. */
static inline LPFN_WSARECVMSG d_get_recvmsg(SOCKET s) {
    GUID g = WSAID_WSARECVMSG; LPFN_WSARECVMSG f = NULL; DWORD got = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &got, NULL, NULL)) return NULL;
    return f;
}
static inline LPFN_WSASENDMSG d_get_sendmsg(SOCKET s) {
    GUID g = WSAID_WSASENDMSG; LPFN_WSASENDMSG f = NULL; DWORD got = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &got, NULL, NULL)) return NULL;
    return f;
}

/* Control-message walker using the documented WSACMSGHDR layout (header padded to pointer size,
 * data aligned to pointer size), independent of the SDK macros. */
#define D_ALIGN(n) (((n) + 7u) & ~(size_t)7u)
#define D_CMSG_HDR ((size_t)sizeof(WSACMSGHDR))
static inline WSACMSGHDR *d_cmsg_first(const WSAMSG *m) {
    if (m->Control.len < D_CMSG_HDR) return NULL;
    return (WSACMSGHDR *)m->Control.buf;
}
static inline WSACMSGHDR *d_cmsg_next(const WSAMSG *m, const WSACMSGHDR *c) {
    char *n = (char *)c + D_ALIGN(c->cmsg_len);
    if (c->cmsg_len < D_CMSG_HDR) return NULL;
    if (n + D_CMSG_HDR > m->Control.buf + m->Control.len) return NULL;
    return (WSACMSGHDR *)n;
}
static inline WSACMSGHDR *d_cmsg_find(const WSAMSG *m, int level, int type) {
    for (WSACMSGHDR *c = d_cmsg_first(m); c; c = d_cmsg_next(m, c))
        if (c->cmsg_level == level && c->cmsg_type == type) return c;
    return NULL;
}
static inline void *d_cmsg_data(WSACMSGHDR *c) { return (char *)c + D_CMSG_HDR; }

/* One received datagram with control data. */
typedef struct {
    char data[256];
    WSABUF buf;
    char ctl[512] __attribute__((aligned(8)));
    struct sockaddr_storage from;
    WSAMSG m;
    DWORD got;
} rmsg;
static inline void rmsg_init(rmsg *r) {
    memset(r, 0, sizeof *r);
    r->buf.buf = r->data; r->buf.len = sizeof r->data;
    r->m.name = (LPSOCKADDR)&r->from; r->m.namelen = sizeof r->from;
    r->m.lpBuffers = &r->buf; r->m.dwBufferCount = 1;
    r->m.Control.buf = r->ctl; r->m.Control.len = sizeof r->ctl;
}
#endif
