/* x_raw_icmp_elevated: shared helpers. Every Winsock call goes through a pointer resolved with
 * LoadLibrary/GetProcAddress (U/UIN); nothing from the DLL under test is linked. */
#ifndef RAWH_H
#define RAWH_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 2
#endif
#ifndef IPV6_CHECKSUM
#define IPV6_CHECKSUM 26
#endif
#ifndef IP_OPTIONS
#define IP_OPTIONS 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* byte-order helpers without importing from the DLL under test */
#undef htons
#undef ntohs
#undef htonl
#undef ntohl
#define htons(x) ((unsigned short)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#define ntohs(x) htons(x)
#define htonl(x) ((unsigned)((((x) & 0xffu) << 24) | (((x) & 0xff00u) << 8) | (((x) >> 8) & 0xff00u) | (((x) >> 24) & 0xffu)))
#define ntohl(x) htonl(x)

#define RW_EQ(e, w) do { long long v_ = (long long)(e); long long w_ = (long long)(w); \
    t_check(v_ == w_, __FILE__, __LINE__, #e " == " #w, "got %lld (0x%llx) want %lld (0x%llx)", v_, v_, w_, w_); } while (0)

static inline int  rw_err(void) { return U(WSAGetLastError)(); }
static inline void rw_seterr(int e) { U(WSASetLastError)(e); }

/* True when the process token is an elevated administrator token. */
static inline int rw_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD n = 0; int r = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) r = el.TokenIsElevated != 0;
    CloseHandle(tok);
    return r;
}
static inline int rw_up(void)
{
    static int state;
    if (!state) { WSADATA d; state = U(WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1; }
    return state == 1;
}
#define RW_UP() do { if (!rw_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define RW_NEED_ADM() do { RW_UP(); if (!rw_elevated()) { t_skip("needs an elevated token"); return; } } while (0)
#define RW_NEED_STD() do { RW_UP(); if (rw_elevated()) { t_skip("needs a non-elevated token"); return; } } while (0)

static inline void rw_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static inline SOCKET rw_raw(int af, int proto) { return U(socket)(af, SOCK_RAW, proto); }
static inline SOCKET rw_udp(void) { return U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }

static inline void rw_lo4(struct sockaddr_in *a, unsigned short port)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET; a->sin_port = port; a->sin_addr.s_addr = 0x0100007fu;
}
static inline void rw_lo4b(struct sockaddr_in *a, unsigned char last, unsigned short port)
{
    rw_lo4(a, port); a->sin_addr.s_addr = (unsigned)127 | ((unsigned)last << 24);
}
static inline void rw_lo6(struct sockaddr_in6 *a, unsigned short port)
{
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6; a->sin6_port = port; a->sin6_addr.u.Byte[15] = 1;
}
static inline int rw_bind4(SOCKET s, unsigned short *port_out)
{
    struct sockaddr_in a; int n = sizeof a;
    rw_lo4(&a, 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return -1;
    if (port_out) { if (U(getsockname)(s, (struct sockaddr *)&a, &n)) return -1; *port_out = a.sin_port; }
    return 0;
}
static inline void rw_rcvtimeo(SOCKET s, DWORD ms) { U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof ms); }

/* One's-complement 16-bit checksum over len bytes (network order result stored as in the packet). */
static inline unsigned short rw_cksum(const void *p, int len)
{
    const unsigned char *b = p; unsigned long sum = 0;
    while (len > 1) { sum += (unsigned)(b[0] << 8 | b[1]); b += 2; len -= 2; }
    if (len) sum += (unsigned)(b[0] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;
    return (unsigned short)(((sum & 0xff) << 8) | (sum >> 8));  /* byte-swapped so a memcpy puts it in wire order */
}
/* ICMPv4 echo request: type 8, code 0, checksum, id, seq, payload. Returns total length. */
static inline int rw_echo4(unsigned char *p, unsigned short id, unsigned short seq, const void *data, int dlen)
{
    p[0] = 8; p[1] = 0; p[2] = p[3] = 0;
    p[4] = (unsigned char)(id >> 8); p[5] = (unsigned char)id;
    p[6] = (unsigned char)(seq >> 8); p[7] = (unsigned char)seq;
    if (dlen) memcpy(p + 8, data, dlen);
    unsigned short c = rw_cksum(p, 8 + dlen);
    memcpy(p + 2, &c, 2);
    return 8 + dlen;
}
/* Minimal IPv4 header (20 bytes, no options) into p; src/dst are network-order values. checksum filled. */
static inline int rw_iphdr(unsigned char *p, int total, int proto, unsigned src, unsigned dst, int ttl, unsigned short id)
{
    memset(p, 0, 20);
    p[0] = 0x45; p[2] = (unsigned char)(total >> 8); p[3] = (unsigned char)total;
    p[4] = (unsigned char)(id >> 8); p[5] = (unsigned char)id;
    p[8] = (unsigned char)ttl; p[9] = (unsigned char)proto;
    memcpy(p + 12, &src, 4); memcpy(p + 16, &dst, 4);
    unsigned short c = rw_cksum(p, 20);
    memcpy(p + 10, &c, 2);
    return 20;
}
/* UDP header + payload into p (checksum 0 = none, legal over IPv4). Returns udp length. */
static inline int rw_udp_pkt(unsigned char *p, unsigned short sport, unsigned short dport_net, const void *data, int dlen)
{
    int len = 8 + dlen;
    memcpy(p, &sport, 2); memcpy(p + 2, &dport_net, 2);
    p[4] = (unsigned char)(len >> 8); p[5] = (unsigned char)len; p[6] = p[7] = 0;
    if (dlen) memcpy(p + 8, data, dlen);
    return len;
}
/* recv with a bounded wait through select; returns bytes, 0 on timeout (distinct from the socket's own 0), -1 on error. */
static inline int rw_recv_wait(SOCKET s, void *buf, int cap, int ms)
{
    fd_set fs; struct timeval tv;
    FD_ZERO(&fs); FD_SET(s, &fs);
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    int r = U(select)(0, &fs, NULL, NULL, &tv);
    if (r <= 0) return r == 0 ? -2 : -1;      /* -2 = nothing arrived */
    return U(recv)(s, buf, cap, 0);
}
/* ---- bounded collection of datagrams ------------------------------------------------------------------ */
#define RW_PKTCAP 2048
typedef struct { int n; unsigned char b[RW_PKTCAP]; } rw_pkt;
static inline int rw_find(const unsigned char *h, int hn, const void *nd, int nn)
{
    int i;
    if (nn <= 0) return 1;
    for (i = 0; i + nn <= hn; i++) if (!memcmp(h + i, nd, nn)) return 1;
    return 0;
}
/* Receive datagrams until one contains the marker "stop" (or ms elapse). Every datagram, the marker one
 * included, is stored in p[0..return). *found says whether the marker arrived. */
static inline int rw_collect(SOCKET s, rw_pkt *p, int max, const void *stop, int stoplen, int ms, int *found)
{
    DWORD t0 = GetTickCount(); int k = 0;
    if (found) *found = 0;
    for (;;) {
        int left = ms - (int)(GetTickCount() - t0), n;
        if (left <= 0 || k >= max) break;
        n = rw_recv_wait(s, p[k].b, RW_PKTCAP, left);
        if (n == -2) break;
        if (n < 0) { p[k].n = n; k++; break; }
        p[k].n = n; k++;
        if (stop && rw_find(p[k - 1].b, n, stop, stoplen)) { if (found) *found = 1; break; }
    }
    return k;
}
/* number of collected packets (before the last, marker) containing needle */
static inline int rw_count_with(const rw_pkt *p, int k, const void *nd, int nn)
{
    int i, c = 0;
    for (i = 0; i < k; i++) if (p[i].n > 0 && rw_find(p[i].b, p[i].n, nd, nn)) c++;
    return c;
}
/* IPv4 header accessors on a received raw packet */
static inline int rw_ihl(const unsigned char *b) { return (b[0] & 15) * 4; }
static inline unsigned rw_src(const unsigned char *b) { unsigned v; memcpy(&v, b + 12, 4); return v; }
static inline unsigned rw_dst(const unsigned char *b) { unsigned v; memcpy(&v, b + 16, 4); return v; }
static inline int rw_totlen(const unsigned char *b) { return b[2] << 8 | b[3]; }
#define RW_LO4 0x0100007fu

/* Send one ICMPv4 echo request carrying data to dst; returns the sendto result. */
static inline int rw_ping4(SOCKET s, const struct sockaddr_in *dst, unsigned short id, unsigned short seq, const void *data, int dlen)
{
    unsigned char pk[2048]; int n = rw_echo4(pk, id, seq, data, dlen);
    return U(sendto)(s, (const char *)pk, n, 0, (const struct sockaddr *)dst, sizeof *dst);
}
/* Wait for the echo reply (type 0) for id/seq on a raw ICMPv4 socket; fills *out; *saw_req counts type-8 packets seen. */
static inline int rw_wait_reply4(SOCKET s, unsigned short id, unsigned short seq, rw_pkt *out, int ms, int *saw_req)
{
    DWORD t0 = GetTickCount();
    if (saw_req) *saw_req = 0;
    for (;;) {
        rw_pkt p; int left = ms - (int)(GetTickCount() - t0), n, ih;
        if (left <= 0) return 0;
        n = rw_recv_wait(s, p.b, RW_PKTCAP, left);
        if (n == -2) return 0;
        if (n < 20) return 0;
        p.n = n; ih = rw_ihl(p.b);
        if (p.b[9] != 1 || n < ih + 8) continue;
        if (p.b[ih] == 8 && saw_req) (*saw_req)++;
        if (p.b[ih] == 0 && p.b[ih + 4] == (id >> 8) && p.b[ih + 5] == (id & 255) && p.b[ih + 6] == (seq >> 8) && p.b[ih + 7] == (seq & 255)) { *out = p; return 1; }
    }
}
#endif
