/* Shared helpers for the x_udp_coalescing_msg area: UDP message-oriented I/O (WSASendMsg / WSARecvMsg with
 * control data), UDP-level socket options and the datagram ioctls, all on loopback with OS-chosen ports.
 * Winsock is reached only through GetProcAddress-resolved pointers; nothing from the DLL under test is linked.
 * The control-message macros are re-implemented here (they are header macros, not exports). */
#ifndef XU_H
#define XU_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#define XU_SIO_UDP_NETRESET _WSAIOW(IOC_VENDOR, 15)
#define XU_UDP_NOCHECKSUM 1
#define XU_UDP_SEND_MSG_SIZE 2
#define XU_UDP_RECV_MAX_COALESCED_SIZE 3
#define XU_UDP_COALESCED_INFO 3
#define XU_UDP_CHECKSUM_COVERAGE 20
#define XU_IP_TOS 3
#define XU_IP_TTL 4
#define XU_IP_DONTFRAGMENT 14
#define XU_IP_PKTINFO 19
#define XU_IP_RECVTTL 21
#define XU_IP_RECVTOS 40
#define XU_IP_ECN 50
#define XU_IP_MTU_DISCOVER 71
#define XU_IPV6_PKTINFO 19
#define XU_IPV6_HOPLIMIT 21
#define XU_IPV6_UNICAST_HOPS 4
#define XU_IPV6_DONTFRAG 14
#define XU_IPV6_TCLASS 39
#define XU_IPV6_RECVTCLASS 40
#define XU_IPV6_ECN 50
#define XU_IPV6_V6ONLY 27
#define XU_MSG_TRUNC 0x0100
#define XU_MSG_CTRUNC 0x0200
#define XU_MSG_BCAST 0x0400
#define XU_MSG_MCAST 0x0800

typedef INT (WINAPI *xu_recvmsg_fn)(SOCKET, LPWSAMSG, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef INT (WINAPI *xu_sendmsg_fn)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static xu_recvmsg_fn xu_rm;
static xu_sendmsg_fn xu_sm;
static int xu_state;

static inline int xu_err(void) { return U(WSAGetLastError)(); }
static inline void xu_seterr(int e) { U(WSASetLastError)(e); }
static inline void xu_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }

/* Start Winsock once and resolve the two message functions through the extension-function ioctl. */
static inline int xu_up(void) {
    if (!xu_state) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) xu_state = -1;
        else {
            SOCKET s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            GUID gr = WSAID_WSARECVMSG, gs = WSAID_WSASENDMSG; DWORD got = 0;
            xu_state = -1;
            if (s != INVALID_SOCKET) {
                if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &gr, sizeof gr, &xu_rm, sizeof xu_rm, &got, NULL, NULL) == 0 &&
                    U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &gs, sizeof gs, &xu_sm, sizeof xu_sm, &got, NULL, NULL) == 0 &&
                    xu_rm && xu_sm) xu_state = 1;
                U(closesocket)(s);
            }
        }
    }
    if (xu_state < 0) { t_skip("winsock or message functions unavailable"); return 0; }
    return 1;
}
#define UP() do { if (!xu_up()) return; } while (0)

static inline int xu_v6_ok(void) {
    static int st;
    if (!st) {
        SOCKET s = U(socket)(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
        st = (s != INVALID_SOCKET && U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0) ? 1 : -1;
        xu_close(s);
    }
    return st > 0;
}
#define UP6() do { UP(); if (!xu_v6_ok()) { t_skip("ipv6 loopback unavailable"); return; } } while (0)

/* A bound loopback datagram endpoint. */
typedef struct { SOCKET s; int af; struct sockaddr_storage sa; int len; } xu_ep;

static inline int xu_open(xu_ep *e, int af) {
    int n;
    memset(e, 0, sizeof *e);
    e->af = af;
    e->s = U(socket)(af, SOCK_DGRAM, IPPROTO_UDP);
    if (e->s == INVALID_SOCKET) return 0;
    if (af == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&e->sa;
        a->sin_family = AF_INET; a->sin_addr.s_addr = 0x0100007fu; e->len = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&e->sa;
        a->sin6_family = AF_INET6; a->sin6_addr.u.Byte[15] = 1; e->len = sizeof *a;
    }
    if (U(bind)(e->s, (struct sockaddr *)&e->sa, e->len) != 0) { xu_close(e->s); e->s = INVALID_SOCKET; return 0; }
    n = (int)sizeof e->sa;
    if (U(getsockname)(e->s, (struct sockaddr *)&e->sa, &n) != 0) { xu_close(e->s); e->s = INVALID_SOCKET; return 0; }
    e->len = n;
    return 1;
}
static inline void xu_free(xu_ep *e) { xu_close(e->s); e->s = INVALID_SOCKET; }
static inline int xu_pair(xu_ep *a, xu_ep *b, int af) {
    if (!xu_open(a, af)) { t_skip("udp endpoint unavailable"); return 0; }
    if (!xu_open(b, af)) { xu_free(a); t_skip("udp endpoint unavailable"); return 0; }
    return 1;
}

static inline int xu_setint(SOCKET s, int lvl, int opt, int v) {
    return U(setsockopt)(s, lvl, opt, (const char *)&v, sizeof v);
}
static inline int xu_getint(SOCKET s, int lvl, int opt, int *v) {
    int l = sizeof *v; return U(getsockopt)(s, lvl, opt, (char *)v, &l);
}
static inline int xu_ready(SOCKET s, int ms) {
    fd_set r; TIMEVAL tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
static inline int xu_nonblock(SOCKET s, int on) { u_long v = on; return U(ioctlsocket)(s, FIONBIO, &v); }
static inline int xu_drain(SOCKET s, int ms) {
    char tmp[4096]; int n = 0;
    while (xu_ready(s, ms)) {
        if (U(recvfrom)(s, tmp, sizeof tmp, 0, NULL, NULL) == SOCKET_ERROR && xu_err() != WSAEMSGSIZE) break;
        if (++n > 4096) break;
    }
    return n;
}
static inline void xu_fill(unsigned char *b, int n, int seed) {
    int i; for (i = 0; i < n; i++) b[i] = (unsigned char)(seed + i * 7 + (i >> 8));
}
static inline int xu_same(const unsigned char *b, int n, int seed) {
    int i; for (i = 0; i < n; i++) if (b[i] != (unsigned char)(seed + i * 7 + (i >> 8))) return 0;
    return 1;
}

/* ---- control-message layout, implemented locally ---- */
#define XU_ALIGN(n)      (((n) + sizeof(SIZE_T) - 1) & ~(sizeof(SIZE_T) - 1))
#define XU_HDR           XU_ALIGN(sizeof(WSACMSGHDR))
#define XU_CMSG_LEN(n)   (XU_HDR + (n))              /* value stored in cmsg_len */
#define XU_CMSG_SPACE(n) (XU_HDR + XU_ALIGN(n))      /* bytes the message occupies */

/* Append one control message at *off in buf; returns the new offset. */
static inline size_t xu_cmsg_put(unsigned char *buf, size_t off, int level, int type, const void *data, size_t n) {
    WSACMSGHDR *h = (WSACMSGHDR *)(buf + off);
    memset(buf + off, 0, XU_CMSG_SPACE(n));
    h->cmsg_len = XU_CMSG_LEN(n); h->cmsg_level = level; h->cmsg_type = type;
    if (n) memcpy(buf + off + XU_HDR, data, n);
    return off + XU_CMSG_SPACE(n);
}
/* Find the first control message (level, type) in a received control area; returns data pointer or NULL. */
static inline const unsigned char *xu_cmsg_find(const unsigned char *ctl, size_t len, int level, int type, size_t *datalen) {
    size_t off = 0;
    while (off + sizeof(WSACMSGHDR) <= len) {
        const WSACMSGHDR *h = (const WSACMSGHDR *)(ctl + off);
        if (h->cmsg_len < sizeof(WSACMSGHDR) || off + h->cmsg_len > len) break;
        if (h->cmsg_level == level && h->cmsg_type == type) {
            if (datalen) *datalen = h->cmsg_len - XU_HDR;
            return ctl + off + XU_HDR;
        }
        off += XU_ALIGN(h->cmsg_len);
    }
    return NULL;
}
static inline int xu_cmsg_count(const unsigned char *ctl, size_t len) {
    size_t off = 0; int n = 0;
    while (off + sizeof(WSACMSGHDR) <= len) {
        const WSACMSGHDR *h = (const WSACMSGHDR *)(ctl + off);
        if (h->cmsg_len < sizeof(WSACMSGHDR) || off + h->cmsg_len > len) break;
        n++; off += XU_ALIGN(h->cmsg_len);
    }
    return n;
}

/* One receive through WSARecvMsg with a single data buffer and optional control buffer. */
typedef struct {
    int r, err; DWORD got; DWORD flags; ULONG ctllen; int namelen;
    unsigned char ctl[1024] __attribute__((aligned(8)));
    unsigned char data[70000];
    struct sockaddr_storage from;
} xu_rx;
static inline void xu_recv(SOCKET s, xu_rx *o, DWORD datacap, ULONG ctlcap, int withname, DWORD inflags) {
    WSAMSG m; WSABUF b;
    memset(o->ctl, 0xEE, sizeof o->ctl);
    memset(&o->from, 0, sizeof o->from);
    b.buf = (CHAR *)o->data; b.len = datacap;
    memset(&m, 0, sizeof m);
    if (withname) { m.name = (LPSOCKADDR)&o->from; m.namelen = sizeof o->from; }
    m.lpBuffers = &b; m.dwBufferCount = 1;
    m.Control.buf = ctlcap ? (CHAR *)o->ctl : NULL; m.Control.len = ctlcap;
    m.dwFlags = inflags;
    o->got = 0xFFFFFFFF;
    xu_seterr(0);
    o->r = xu_rm(s, &m, &o->got, NULL, NULL);
    o->err = o->r ? xu_err() : 0;
    o->flags = m.dwFlags; o->ctllen = m.Control.len; o->namelen = m.namelen;
}
/* Bounded wait, then receive; on timeout records a failed check and returns a timeout-shaped result instead of blocking. */
static inline void xu_recvw(SOCKET s, xu_rx *o, DWORD datacap, ULONG ctlcap, int withname, DWORD inflags) {
    if (!xu_ready(s, 3000)) {
        t_check(0, __FILE__, __LINE__, "datagram arrived within the wait", "timed out");
        o->r = SOCKET_ERROR; o->err = WSAETIMEDOUT; o->got = 0; o->flags = 0; o->ctllen = 0; o->namelen = 0;
        memset(o->ctl, 0xEE, sizeof o->ctl);
        return;
    }
    xu_recv(s, o, datacap, ctlcap, withname, inflags);
}
/* Send one buffer via WSASendMsg (control optional, destination optional). */
static inline int xu_send(SOCKET s, const xu_ep *to, const void *data, DWORD n, const void *ctl, ULONG ctllen, DWORD flags, DWORD *sent) {
    WSAMSG m; WSABUF b; DWORD sn = 0;
    int r;
    b.buf = (CHAR *)data; b.len = n;
    memset(&m, 0, sizeof m);
    if (to) { m.name = (LPSOCKADDR)&to->sa; m.namelen = to->len; }
    m.lpBuffers = &b; m.dwBufferCount = n || data ? 1 : 0;
    m.Control.buf = (CHAR *)ctl; m.Control.len = ctllen;
    xu_seterr(0);
    r = xu_sm(s, &m, flags, &sn, NULL, NULL);
    if (sent) *sent = sn;
    return r;
}
#endif
