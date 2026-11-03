/* Shared helpers for the event_select_enum area: WSAEventSelect / WSAEnumNetworkEvents and the WSA event
 * object API (WSACreateEvent, WSACloseEvent, WSASetEvent, WSAResetEvent, WSAWaitForMultipleEvents).
 * Everything in ws2_32 is reached through U(); the SDK headers supply types and constants only. */
#ifndef ESE_H
#define ESE_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define ES_LOOP_BE   0x0100007Fu      /* 127.0.0.1, network order on a little-endian host */
/* Single-evaluation equality check (the harness macro evaluates its arguments twice). */
#define ES_EQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define ES_PAT       0xCCCCCCCCu
#define ES_ERR_HANDLE 6               /* WSA_INVALID_HANDLE == ERROR_INVALID_HANDLE */
#define ES_ERR_PARAM  87              /* WSA_INVALID_PARAMETER == ERROR_INVALID_PARAMETER */

static int es_init(void)
{
    static int done = -1;
    WSADATA d;
    if (done < 0) done = (U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : 0;
    return done;
}
#define ESTEST(n) \
    static void esbody_##n(void); \
    TEST(n) { if (!es_init()) { t_skip("WSAStartup failed"); return; } esbody_##n(); } \
    static void esbody_##n(void)

static int es_err(void) { return U(WSAGetLastError)(); }
static SOCKET es_sock(int type) { return U(socket)(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP); }
static void es_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static HANDLE es_ev(void) { return U(WSACreateEvent)(); }
static BOOL es_signalled(HANDLE ev) { return WaitForSingleObject(ev, 0) == WAIT_OBJECT_0; }
static BOOL es_wait(HANDLE ev, DWORD ms) { return WaitForSingleObject(ev, ms) == WAIT_OBJECT_0; }

static void es_addr(struct sockaddr_in *a, unsigned short port_be)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = ES_LOOP_BE;
    a->sin_port = port_be;
}
static SOCKET es_listener(struct sockaddr_in *out, int backlog)
{
    struct sockaddr_in a; int len = sizeof(a);
    SOCKET s = es_sock(SOCK_STREAM);
    if (s == INVALID_SOCKET) return s;
    es_addr(&a, 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof(a)) || U(getsockname)(s, (struct sockaddr *)&a, &len) ||
        U(listen)(s, backlog)) { es_close(s); return INVALID_SOCKET; }
    if (out) *out = a;
    return s;
}
static BOOL es_pair(SOCKET *cli, SOCKET *srv)
{
    struct sockaddr_in a;
    SOCKET l = es_listener(&a, 1);
    *cli = *srv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return FALSE;
    *cli = es_sock(SOCK_STREAM);
    if (*cli != INVALID_SOCKET && U(connect)(*cli, (struct sockaddr *)&a, sizeof(a)) == 0)
        *srv = U(accept)(l, NULL, NULL);
    es_close(l);
    if (*srv == INVALID_SOCKET) { es_close(*cli); *cli = INVALID_SOCKET; return FALSE; }
    return TRUE;
}
#define ES_PAIR(c, s) SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET; \
    if (!es_pair(&c, &s)) { t_skip("could not build a loopback connection"); return; }
/* Bound loopback UDP socket on an ephemeral port. */
static SOCKET es_udp(struct sockaddr_in *out)
{
    struct sockaddr_in a; int len = sizeof(a);
    SOCKET s = es_sock(SOCK_DGRAM);
    if (s == INVALID_SOCKET) return s;
    es_addr(&a, 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof(a)) || U(getsockname)(s, (struct sockaddr *)&a, &len)) {
        es_close(s); return INVALID_SOCKET;
    }
    if (out) *out = a;
    return s;
}
static void es_nonblock(SOCKET s, int on) { u_long v = on; U(ioctlsocket)(s, FIONBIO, &v); }

/* WSAEnumNetworkEvents with the structure pre-filled with a pattern. */
static int es_enum(SOCKET s, HANDLE ev, WSANETWORKEVENTS *ne)
{
    memset(ne, 0xCC, sizeof(*ne));
    return U(WSAEnumNetworkEvents)(s, ev, ne);
}
/* Enumerate and return the event mask (-1 on API failure); also verifies every reported slot has error 0. */
static LONG es_mask(SOCKET s, HANDLE ev)
{
    WSANETWORKEVENTS ne; int i;
    if (es_enum(s, ev, &ne)) return -1;
    for (i = 0; i < FD_MAX_EVENTS; ++i)
        if ((ne.lNetworkEvents & (1 << i)) && ne.iErrorCode[i]) return -2;
    return ne.lNetworkEvents;
}
/* What a one-byte recv does on an empty socket given a short receive timeout: the error code seen.
 * Non-blocking mode -> WSAEWOULDBLOCK at once; blocking mode -> WSAETIMEDOUT after the timeout. */
static int es_empty_recv_error(SOCKET s)
{
    DWORD to = 150; char b; int r, e;
    U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    U(WSASetLastError)(0);
    r = U(recv)(s, &b, 1, 0);
    e = es_err();
    return r == SOCKET_ERROR ? e : 0;
}
static int es_send_all(SOCKET s, const char *p, int n) { return U(send)(s, p, n, 0); }
static int es_udp_send(SOCKET from, const struct sockaddr_in *to, const char *p, int n)
{
    return U(sendto)(from, p, n, 0, (const struct sockaddr *)to, sizeof(*to));
}
/* Fill the send path until it would block (bounded). */
static void es_fill_send(SOCKET s)
{
    static char blk[8192]; int i, r;
    es_nonblock(s, 1);
    for (i = 0; i < 4096; ++i) {
        r = U(send)(s, blk, sizeof(blk), 0);
        if (r == SOCKET_ERROR) return;
    }
}
static void es_drain(SOCKET s)
{
    static char blk[16384]; int i, r;
    es_nonblock(s, 1);
    for (i = 0; i < 4096; ++i) { r = U(recv)(s, blk, sizeof(blk), 0); if (r <= 0) return; }
}
#endif
