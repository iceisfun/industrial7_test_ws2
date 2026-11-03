/* Shared helpers for the udp_datagram_io area. Winsock is reached only through
 * GetProcAddress-resolved pointers (U(Name)); nothing from the DLL under test is linked.
 * All sockets are bound to loopback on an OS-chosen port, all waits are bounded. */
#ifndef UD_H
#define UD_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET  _WSAIOW(IOC_VENDOR, 12)
#endif
#ifndef SIO_UDP_NETRESET
#define SIO_UDP_NETRESET   _WSAIOW(IOC_VENDOR, 15)
#endif

/* ---- tiny wrappers ---- */
static inline int  ud_err(void) { return U(WSAGetLastError)(); }
static inline void ud_seterr(int e) { U(WSASetLastError)(e); }
static inline void ud_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static inline unsigned short ud_ntohs(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }

static inline int ud_up(void) {
    static int st;
    if (!st) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || !t_proc_in("ws2_32.dll", "socket")) st = -1;
        else st = (U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (st < 0) { t_skip("ws2_32 unavailable"); return 0; }
    return 1;
}
#define UP() do { if (!ud_up()) return; } while (0)

static inline void ud_lo4(struct sockaddr_in *a, unsigned short port_net) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET; a->sin_port = port_net;
    a->sin_addr.s_addr = 0x0100007fu;          /* 127.0.0.1 in memory order */
}
static inline void ud_lo6(struct sockaddr_in6 *a, unsigned short port_net) {
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6; a->sin6_port = port_net;
    a->sin6_addr.u.Byte[15] = 1;
}

/* A bound loopback UDP endpoint. */
typedef struct { SOCKET s; int af; struct sockaddr_storage sa; int len; } ud_ep;

static inline int ud_open(ud_ep *e, int af) {
    int n;
    memset(e, 0, sizeof *e);
    e->af = af;
    e->s = U(socket)(af, SOCK_DGRAM, IPPROTO_UDP);
    if (e->s == INVALID_SOCKET) return 0;
    if (af == AF_INET) { ud_lo4((struct sockaddr_in *)&e->sa, 0); e->len = sizeof(struct sockaddr_in); }
    else               { ud_lo6((struct sockaddr_in6 *)&e->sa, 0); e->len = sizeof(struct sockaddr_in6); }
    if (U(bind)(e->s, (struct sockaddr *)&e->sa, e->len) != 0) { ud_close(e->s); e->s = INVALID_SOCKET; return 0; }
    n = (int)sizeof e->sa;
    if (U(getsockname)(e->s, (struct sockaddr *)&e->sa, &n) != 0) { ud_close(e->s); e->s = INVALID_SOCKET; return 0; }
    e->len = n;
    return 1;
}
static inline void ud_free(ud_ep *e) { ud_close(e->s); e->s = INVALID_SOCKET; }

/* Opens two bound endpoints; skips the test and returns 0 when that is not possible. */
static inline int ud_pair(ud_ep *a, ud_ep *b, int af) {
    if (!ud_open(a, af)) { t_skip("udp endpoint unavailable"); return 0; }
    if (!ud_open(b, af)) { ud_free(a); t_skip("udp endpoint unavailable"); return 0; }
    return 1;
}
static inline int ud_v6_ok(void) {
    static int st;
    if (!st) { ud_ep e; st = ud_open(&e, AF_INET6) ? 1 : -1; if (st > 0) ud_free(&e); }
    return st > 0;
}

static inline int ud_sendto(const ud_ep *from, const ud_ep *to, const void *b, int n) {
    return U(sendto)(from->s, (const char *)b, n, 0, (const struct sockaddr *)&to->sa, to->len);
}
static inline int ud_ready(SOCKET s, int ms) {
    fd_set r; TIMEVAL tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
/* receive one datagram with a bounded wait; -2 on timeout, otherwise recvfrom's result.
 * from/fromlen may be NULL. */
static inline int ud_recv_to(SOCKET s, void *b, int n, int flags, void *from, int *fromlen, int ms) {
    if (!ud_ready(s, ms)) return -2;
    return U(recvfrom)(s, (char *)b, n, flags, (struct sockaddr *)from, fromlen);
}
static inline int ud_nonblock(SOCKET s, int on) { u_long v = on; return U(ioctlsocket)(s, FIONBIO, &v); }
static inline int ud_setint(SOCKET s, int lvl, int opt, int v) {
    return U(setsockopt)(s, lvl, opt, (const char *)&v, sizeof v);
}
static inline int ud_getint(SOCKET s, int lvl, int opt, int *v) {
    int l = sizeof *v; return U(getsockopt)(s, lvl, opt, (char *)v, &l);
}
/* drain whatever is queued (bounded), returns number of datagrams removed */
static inline int ud_drain(SOCKET s, int ms) {
    char tmp[2048]; int n = 0;
    while (ud_ready(s, ms)) {
        if (U(recvfrom)(s, tmp, sizeof tmp, 0, NULL, NULL) == SOCKET_ERROR && ud_err() != WSAEMSGSIZE) break;
        n++;
        if (n > 4096) break;
    }
    return n;
}
static inline void ud_fill(unsigned char *b, int n, int seed) {
    int i; for (i = 0; i < n; i++) b[i] = (unsigned char)(seed + i * 7 + (i >> 8));
}
static inline int ud_same(const unsigned char *b, int n, int seed) {
    int i; for (i = 0; i < n; i++) if (b[i] != (unsigned char)(seed + i * 7 + (i >> 8))) return 0;
    return 1;
}
static inline int ud_sameaddr(const ud_ep *e, const struct sockaddr_storage *got, int gotlen) {
    if (gotlen != e->len || got->ss_family != e->sa.ss_family) return 0;
    if (e->af == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)&e->sa, *b = (const struct sockaddr_in *)got;
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&e->sa, *b = (const struct sockaddr_in6 *)got;
        return a->sin6_port == b->sin6_port && !memcmp(&a->sin6_addr, &b->sin6_addr, 16);
    }
}
#endif
