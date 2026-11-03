/* Shared helpers for the sockopt_protocol_level area: protocol-level (IPPROTO_TCP, IPPROTO_IP, IPPROTO_IPV6,
 * IPPROTO_UDP) socket option behaviour.  Winsock is never linked; every entry point is resolved with
 * LoadLibrary/GetProcAddress through U() and wrapped in a small spl_* forwarder. */
#ifndef SPL_H
#define SPL_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

/* Option numbers that older SDK headers may lack. Values are the documented ones. */
#ifndef TCP_NODELAY
#define TCP_NODELAY 1

#endif
#define SPL_TCP_EXPEDITED_1122 2
#define SPL_TCP_KEEPALIVE      3
#define SPL_TCP_MAXSEG         4
#define SPL_TCP_MAXRT          5
#define SPL_TCP_STDURG         6
#define SPL_TCP_NOURG          7
#define SPL_TCP_ATMARK         8
#define SPL_TCP_NOSYNRETRIES   9
#define SPL_TCP_TIMESTAMPS     10
#define SPL_TCP_OFFLOAD_PREF   11
#define SPL_TCP_CONGESTION     12
#define SPL_TCP_DELAY_FIN_ACK  13
#define SPL_TCP_MAXRTMS        14
#define SPL_TCP_FASTOPEN       15
#define SPL_TCP_KEEPCNT        16
#define SPL_TCP_KEEPIDLE       3
#define SPL_TCP_KEEPINTVL      17
#define SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR 18
#define SPL_TCP_ICMP_ERROR_INFO 19

#define SPL_IP_OPTIONS         1
#define SPL_IP_HDRINCL         2
#define SPL_IP_TOS             3
#define SPL_IP_TTL             4
#define SPL_IP_MULTICAST_IF    9
#define SPL_IP_MULTICAST_TTL   10
#define SPL_IP_MULTICAST_LOOP  11
#define SPL_IP_ADD_MEMBERSHIP  12
#define SPL_IP_DROP_MEMBERSHIP 13
#define SPL_IP_DONTFRAGMENT    14
#define SPL_IP_PKTINFO         19
#define SPL_IP_RECVTTL         21
#define SPL_IP_RECEIVE_BROADCAST 22
#define SPL_IP_RECVIF          24
#define SPL_IP_RECVDSTADDR     25
#define SPL_IP_IFLIST          28
#define SPL_IP_UNICAST_IF      31
#define SPL_IP_RTHDR           32
#define SPL_IP_RECVRTHDR       38
#define SPL_IP_TCLASS          39
#define SPL_IP_RECVTOS         40
#define SPL_IP_ORIGINAL_ARRIVAL_IF 47
#define SPL_IP_MTU_DISCOVER    71
#define SPL_IP_MTU             73

#define SPL_IPV6_HDRINCL       2
#define SPL_IPV6_UNICAST_HOPS  4
#define SPL_IPV6_MULTICAST_IF  9
#define SPL_IPV6_MULTICAST_HOPS 10
#define SPL_IPV6_MULTICAST_LOOP 11
#define SPL_IPV6_ADD_MEMBERSHIP 12
#define SPL_IPV6_DROP_MEMBERSHIP 13
#define SPL_IPV6_DONTFRAG      14
#define SPL_IPV6_PKTINFO       19
#define SPL_IPV6_HOPLIMIT      21
#define SPL_IPV6_PROTECTION_LEVEL 23
#define SPL_IPV6_RECVIF        24
#define SPL_IPV6_RECVDSTADDR   25
#define SPL_IPV6_V6ONLY        27
#define SPL_IPV6_UNICAST_IF    31
#define SPL_IPV6_RTHDR         32
#define SPL_IPV6_RECVRTHDR     38
#define SPL_IPV6_TCLASS        39
#define SPL_IPV6_RECVTCLASS    40
#define SPL_IPV6_MTU_DISCOVER  71
#define SPL_IPV6_MTU           72

#define SPL_UDP_NOCHECKSUM     1
#define SPL_UDP_SEND_MSG_SIZE  2
#define SPL_UDP_RECV_MAX_COALESCED_SIZE 3

#define SPL_LVL_IP   0   /* IPPROTO_IP   */
#define SPL_LVL_TCP  6   /* IPPROTO_TCP  */
#define SPL_LVL_UDP  17  /* IPPROTO_UDP  */
#define SPL_LVL_IPV6 41  /* IPPROTO_IPV6 */

#define DEFW(ret, name, params, args) static ret spl_##name params { return U(name) args; }
DEFW(int,    WSAStartup, (WORD v, LPWSADATA d), (v, d))
DEFW(int,    WSAGetLastError, (void), ())
DEFW(void,   WSASetLastError, (int e), (e))
DEFW(SOCKET, socket, (int a, int t, int p), (a, t, p))
DEFW(int,    closesocket, (SOCKET s), (s))
DEFW(int,    bind, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
DEFW(int,    listen, (SOCKET s, int b), (s, b))
DEFW(int,    connect, (SOCKET s, const struct sockaddr *a, int l), (s, a, l))
DEFW(SOCKET, accept, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
DEFW(int,    getsockname, (SOCKET s, struct sockaddr *a, int *l), (s, a, l))
DEFW(int,    getsockopt, (SOCKET s, int lv, int n, char *v, int *l), (s, lv, n, v, l))
DEFW(int,    setsockopt, (SOCKET s, int lv, int n, const char *v, int l), (s, lv, n, v, l))
DEFW(int,    shutdown, (SOCKET s, int h), (s, h))
DEFW(int,    send, (SOCKET s, const char *b, int l, int f), (s, b, l, f))
DEFW(int,    recv, (SOCKET s, char *b, int l, int f), (s, b, l, f))
DEFW(int,    sendto, (SOCKET s, const char *b, int l, int f, const struct sockaddr *a, int al), (s, b, l, f, a, al))
DEFW(int,    recvfrom, (SOCKET s, char *b, int l, int f, struct sockaddr *a, int *al), (s, b, l, f, a, al))
DEFW(int,    ioctlsocket, (SOCKET s, long c, u_long *a), (s, c, a))
DEFW(int,    select, (int n, fd_set *r, fd_set *w, fd_set *e, const struct timeval *t), (n, r, w, e, t))

/* Equality check evaluating its arguments once. */
#define SEQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)

/* WSAStartup once per process; skips the calling test when the stack is unavailable. */
static inline int spl_up(void)
{
    static int done;
    if (!done) {
        WSADATA d;
        int r = spl_WSAStartup(MAKEWORD(2, 2), &d);
        if (r) { t_skip("WSAStartup failed: %d", r); return 0; }
        done = 1;
    }
    return 1;
}

/* Typed accessors: return the Winsock result, last error in *err (0 on success). */
static inline int spl_set(SOCKET s, int lv, int opt, const void *v, int len, int *err)
{
    int r;
    spl_WSASetLastError(0);
    r = spl_setsockopt(s, lv, opt, (const char *)v, len);
    *err = r ? spl_WSAGetLastError() : 0;
    return r;
}
static inline int spl_get(SOCKET s, int lv, int opt, void *v, int *len, int *err)
{
    int r;
    spl_WSASetLastError(0);
    r = spl_getsockopt(s, lv, opt, (char *)v, len);
    *err = r ? spl_WSAGetLastError() : 0;
    return r;
}
/* Set a 32-bit integer option; returns 0 / SOCKET_ERROR, *err filled. */
static inline int spl_seti(SOCKET s, int lv, int opt, int val, int *err) { return spl_set(s, lv, opt, &val, sizeof val, err); }
/* Read a 32-bit integer option into *out (pre-filled with a sentinel); returns result, *len = returned length. */
static inline int spl_geti(SOCKET s, int lv, int opt, int *out, int *err)
{
    int len = sizeof *out;
    *out = (int)0xA5A5A5A5;
    return spl_get(s, lv, opt, out, &len, err);
}
/* Set + read-back convenience for tests that only need the integer. Returns the read value, or 0xA5A5A5A5 on failure. */
static inline int spl_rb(SOCKET s, int lv, int opt)
{
    int v, e;
    if (spl_geti(s, lv, opt, &v, &e)) return (int)0xA5A5A5A5;
    return v;
}
#define SPL_BAD ((int)0xA5A5A5A5)

static inline void spl_loop4(struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007f; /* 127.0.0.1 */
}
static inline void spl_loop6(struct sockaddr_in6 *a)
{
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6;
    a->sin6_addr.s6_addr[15] = 1;
}
static inline SOCKET spl_tcp4(void) { return spl_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
static inline SOCKET spl_udp4(void) { return spl_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
static inline SOCKET spl_tcp6(void) { return spl_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); }
static inline SOCKET spl_udp6(void) { return spl_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); }
static inline void spl_close(SOCKET s) { if (s != INVALID_SOCKET) spl_closesocket(s); }

/* Bind to loopback with an ephemeral port; port is returned in network order through *port (may be NULL). */
static inline int spl_bind4(SOCKET s, u_short *port)
{
    struct sockaddr_in a; int l = sizeof a;
    spl_loop4(&a);
    if (spl_bind(s, (struct sockaddr *)&a, sizeof a)) return -1;
    if (spl_getsockname(s, (struct sockaddr *)&a, &l)) return -1;
    if (port) *port = a.sin_port;
    return 0;
}
static inline int spl_bind6(SOCKET s, u_short *port)
{
    struct sockaddr_in6 a; int l = sizeof a;
    spl_loop6(&a);
    if (spl_bind(s, (struct sockaddr *)&a, sizeof a)) return -1;
    if (spl_getsockname(s, (struct sockaddr *)&a, &l)) return -1;
    if (port) *port = a.sin6_port;
    return 0;
}

/* Connected loopback TCP pair (IPv4 when v6==0). On success returns 1 and fills c (client) and a (accepted). */
static inline int spl_pair(int v6, SOCKET *c, SOCKET *a, SOCKET *l)
{
    SOCKET ls = v6 ? spl_tcp6() : spl_tcp4(), cs = v6 ? spl_tcp6() : spl_tcp4();
    u_short port = 0;
    *c = *a = INVALID_SOCKET; if (l) *l = INVALID_SOCKET;
    if (ls == INVALID_SOCKET || cs == INVALID_SOCKET) goto fail;
    if (v6 ? spl_bind6(ls, &port) : spl_bind4(ls, &port)) goto fail;
    if (spl_listen(ls, 2)) goto fail;
    if (v6) { struct sockaddr_in6 d; spl_loop6(&d); d.sin6_port = port; if (spl_connect(cs, (struct sockaddr *)&d, sizeof d)) goto fail; }
    else    { struct sockaddr_in d;  spl_loop4(&d); d.sin_port = port;  if (spl_connect(cs, (struct sockaddr *)&d, sizeof d)) goto fail; }
    *a = spl_accept(ls, NULL, NULL);
    if (*a == INVALID_SOCKET) goto fail;
    *c = cs;
    if (l) *l = ls; else spl_close(ls);
    return 1;
fail:
    spl_close(ls); spl_close(cs); spl_close(*a); *a = INVALID_SOCKET;
    return 0;
}
/* IPv6 availability probe: skips the test when no IPv6 loopback stack is present. */
static inline int spl_have6(void)
{
    SOCKET s = spl_udp6();
    if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return 0; }
    spl_close(s);
    return 1;
}

/* ---- table driven value checks ---------------------------------------------------------------
 * One row: set `val` as a 32-bit integer; `err` is the expected Winsock error (0 = success).
 * After a success the option is read back (32-bit buffer) and masked with `mask`; it must equal `rb`.
 * After a failure the read-back must still equal the last value that was accepted (the failing
 * set must not change anything). */
struct spl_row { int val; int err; int rb; };
#define SPL_ANY ((int)0x7e57ab1e)
static inline void spl_run_rows(SOCKET s, int lv, int opt, unsigned mask, const struct spl_row *rows, int n, int have_last, int last)
{
    int i;
    for (i = 0; i < n; i++) {
        int e = -1, r = spl_seti(s, lv, opt, rows[i].val, &e), got, ge;
        if (rows[i].err == 0) {
            t_check(r == 0 && e == 0, __FILE__, __LINE__, "set accepted", "lv %d opt %d val 0x%x: rc %d err %d", lv, opt, rows[i].val, r, e);
            if (spl_geti(s, lv, opt, &got, &ge) == 0) {
                t_check(((unsigned)got & mask) == ((unsigned)rows[i].rb & mask), __FILE__, __LINE__, "read-back",
                        "lv %d opt %d val 0x%x: got 0x%x want 0x%x", lv, opt, rows[i].val, (unsigned)got & mask, (unsigned)rows[i].rb & mask);
                last = rows[i].rb; have_last = 1;
            } else t_check(0, __FILE__, __LINE__, "read-back call", "lv %d opt %d get failed err %d", lv, opt, ge);
        } else {
            t_check(r == SOCKET_ERROR && e == rows[i].err, __FILE__, __LINE__, "set refused", "lv %d opt %d val 0x%x: rc %d err %d want %d", lv, opt, rows[i].val, r, e, rows[i].err);
            if (have_last && spl_geti(s, lv, opt, &got, &ge) == 0)
                t_check(((unsigned)got & mask) == ((unsigned)last & mask), __FILE__, __LINE__, "unchanged after refusal",
                        "lv %d opt %d val 0x%x: got 0x%x want 0x%x", lv, opt, rows[i].val, (unsigned)got & mask, (unsigned)last & mask);
        }
    }
}
#define SPL_ROWS(s, lv, opt, mask, rows, have, last) spl_run_rows(s, lv, opt, mask, rows, (int)(sizeof(rows)/sizeof((rows)[0])), have, last)

/* Expect one call to fail with a given error. */
#define SPL_FAILS(call, want) do { int e_ = -1; int r_ = (call); (void)e_; \
    t_check(r_ == SOCKET_ERROR && spl_WSAGetLastError() == (want), __FILE__, __LINE__, #call, "rc %d err %d want %d", r_, spl_WSAGetLastError(), (want)); } while (0)

/* Option lengths: set `val` with each optlen in [0..8]; first_ok is the smallest optlen that succeeds, shorter ones
 * must fail with `short_err`. Uses a throw-away read afterwards to confirm the bytes consumed. */
static inline void spl_len_protocol(SOCKET s, int lv, int opt, int val, int first_ok, int short_err)
{
    int l, e;
    for (l = 0; l <= 8; l++) {
        int r = spl_set(s, lv, opt, &val, l, &e);
        if (l < first_ok) t_check(r == SOCKET_ERROR && e == short_err, __FILE__, __LINE__, "short optlen refused", "lv %d opt %d len %d: rc %d err %d want %d", lv, opt, l, r, e, short_err);
        else t_check(r == 0, __FILE__, __LINE__, "optlen accepted", "lv %d opt %d len %d: rc %d err %d", lv, opt, l, r, e);
    }
}
/* getsockopt buffer sizes: for buffer length bl the call must fail with short_err when bl < first_ok,
 * otherwise succeed with *optlen == (bl >= wide_from ? wide : narrow). */
static inline void spl_get_protocol(SOCKET s, int lv, int opt, int first_ok, int short_err, int narrow, int wide_from, int wide)
{
    int bl;
    for (bl = 0; bl <= 8; bl++) {
        unsigned char buf[16]; int len = bl, e, r;
        memset(buf, 0, sizeof buf);
        r = spl_get(s, lv, opt, buf, &len, &e);
        if (bl < first_ok) t_check(r == SOCKET_ERROR && e == short_err, __FILE__, __LINE__, "short buffer refused", "lv %d opt %d buf %d: rc %d err %d want %d", lv, opt, bl, r, e, short_err);
        else t_check(r == 0 && len == (bl >= wide_from ? wide : narrow), __FILE__, __LINE__, "returned length", "lv %d opt %d buf %d: rc %d err %d len %d", lv, opt, bl, r, e, len);
    }
}

/* One TEST per option: fresh socket from `mk`, run the row table. */
#define SPL_ROWTEST(tname, mk, lv, opt, mask, rows) \
    TEST(tname) { SOCKET s_; if (!spl_up()) return; s_ = mk(); \
        if (s_ == INVALID_SOCKET) { t_skip("socket creation failed: %d", spl_WSAGetLastError()); return; } \
        SPL_ROWS(s_, lv, opt, mask, rows, 0, 0); spl_close(s_); }
/* Expected default value of an integer option on a fresh socket (mask applied). */
#define SPL_DEFTEST(tname, mk, lv, opt, mask, want) \
    TEST(tname) { SOCKET s_; int v_ = 0, e_ = 0, r_; if (!spl_up()) return; s_ = mk(); \
        if (s_ == INVALID_SOCKET) { t_skip("socket creation failed: %d", spl_WSAGetLastError()); return; } \
        r_ = spl_geti(s_, lv, opt, &v_, &e_); \
        t_check(r_ == 0, __FILE__, __LINE__, "get succeeds", "lv %d opt %d: err %d", lv, opt, e_); \
        t_check(((unsigned)v_ & (mask)) == (unsigned)(want), __FILE__, __LINE__, "default value", "lv %d opt %d: got 0x%x want 0x%x", lv, opt, (unsigned)v_ & (mask), (unsigned)(want)); \
        spl_close(s_); }
/* A get/set pair that must both fail with `err` on a fresh socket. */
#define SPL_REFUSETEST(tname, mk, lv, opt, err) \
    TEST(tname) { SOCKET s_; int v_ = 0, e_ = 0, l_ = 4; if (!spl_up()) return; s_ = mk(); \
        if (s_ == INVALID_SOCKET) { t_skip("socket creation failed: %d", spl_WSAGetLastError()); return; } \
        t_check(spl_get(s_, lv, opt, &v_, &l_, &e_) == SOCKET_ERROR && e_ == (err), __FILE__, __LINE__, "get refused", "lv %d opt %d: err %d want %d", lv, opt, e_, (int)(err)); \
        v_ = 1; t_check(spl_set(s_, lv, opt, &v_, 4, &e_) == SOCKET_ERROR && e_ == (err), __FILE__, __LINE__, "set refused", "lv %d opt %d: err %d want %d", lv, opt, e_, (int)(err)); \
        spl_close(s_); }

/* ---- control-message receive helper (WSARecvMsg is an extension function obtained through WSAIoctl) ------- */
DEFW(int, WSAIoctl, (SOCKET s, DWORD c, LPVOID i, DWORD il, LPVOID o, DWORD ol, LPDWORD r, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr), (s, c, i, il, o, ol, r, ov, cr))
static inline LPFN_WSARECVMSG spl_get_recvmsg(SOCKET s)
{
    GUID g = WSAID_WSARECVMSG; LPFN_WSARECVMSG f = NULL; DWORD n;
    if (spl_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &n, NULL, NULL)) return NULL;
    return f;
}
/* Receive one datagram with WSARecvMsg and pull the first control message of (level,type) into *out (an int).
 * Returns 0 found, -2 no such control message, -1 receive failed (the caller sets SO_RCVTIMEO first). *got = payload bytes. */
static inline int spl_recv_cmsg(SOCKET s, LPFN_WSARECVMSG f, int lvl, int type, int *out, int *got)
{
    char buf[64], ctl[128]; WSABUF b; WSAMSG m; DWORD n = 0; WSACMSGHDR *c; struct sockaddr_storage ss;
    b.buf = buf; b.len = sizeof buf;
    memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&ss; m.namelen = sizeof ss; m.lpBuffers = &b; m.dwBufferCount = 1;
    m.Control.buf = ctl; m.Control.len = sizeof ctl;
    if (f(s, &m, &n, NULL, NULL)) return -1;
    *got = (int)n;
    for (c = WSA_CMSG_FIRSTHDR(&m); c; c = WSA_CMSG_NXTHDR(&m, c))
        if (c->cmsg_level == lvl && c->cmsg_type == type) { *out = *(int *)WSA_CMSG_DATA(c); return 0; }
    return -2;
}
static inline void spl_rcvtimeo(SOCKET s, DWORD ms) { spl_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms); }

/* Whether the process token is elevated. Raw sockets for protocols other than ICMP/ICMPv6, and the
 * IP_HDRINCL / IPV6_HDRINCL options, are refused with WSAEACCES to a token that is not. */
static inline int spl_elevated(void) {
    HANDLE tok; TOKEN_ELEVATION te; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n)) r = te.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}
#endif
