/* Shared helpers for the ioctl_basic area: socket construction, a thin WSAIoctl wrapper that records the
 * outcome of one call as a small value, and the control-code constants this area exercises.
 * Everything in ws2_32 is reached through U(); the SDK headers supply types and constants only. */
#ifndef IB_H
#define IB_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

/* Control codes spelled out so that the numeric values are part of the measurement. */
#define IB_FIONBIO              0x8004667eu
#define IB_FIONREAD             0x4004667fu
#define IB_SIOCATMARK           0x40047307u
#define IB_FIOASYNC             0x8004667du
#define IB_ASSOCIATE_HANDLE     0x88000001u
#define IB_ENABLE_CIRCQ         0x28000002u
#define IB_FIND_ROUTE           0x48000003u
#define IB_FLUSH                0x28000004u
#define IB_GET_BCAST            0x48000005u
#define IB_GET_EXT_FN           0xC8000006u
#define IB_GET_QOS              0xC8000007u
#define IB_GET_GROUP_QOS        0xC8000008u
#define IB_MP_LOOPBACK          0x88000009u
#define IB_MC_SCOPE             0x8800000Au
#define IB_SET_QOS              0x8800000Bu
#define IB_SET_GROUP_QOS        0x8800000Cu
#define IB_TRANSLATE_HANDLE     0xC800000Du
#define IB_ROUTING_QUERY        0xC8000014u
#define IB_ROUTING_CHANGE       0x88000015u
#define IB_ADDRLIST_QUERY       0x48000016u
#define IB_ADDRLIST_CHANGE      0x28000017u
#define IB_QUERY_PNP            0x48000018u
#define IB_ADDRLIST_SORT        0xC8000019u
#define IB_NSP_NOTIFY           0x88000019u
#define IB_BSP_HANDLE           0x4800001bu
#define IB_BSP_HANDLE_SELECT    0x4800001cu
#define IB_BSP_HANDLE_POLL      0x4800001du
#define IB_BASE_HANDLE          0x48000022u
#define IB_RCVALL               0x98000001u
#define IB_RCVALL_MCAST         0x98000002u
#define IB_RCVALL_IGMP          0x98000003u
#define IB_KEEPALIVE            0x98000004u
#define IB_ABSORB_RTRALERT      0x98000005u
#define IB_UCAST_IF             0x98000006u
#define IB_LIMIT_BCAST          0x98000007u
#define IB_UDP_CONNRESET        0x9800000Cu
#define IB_UDP_NETRESET         0x9800000Fu
#define IB_LOOPBACK_FAST        0x98000010u
#define IB_TCP_INITIAL_RTO      0x98000011u
#define IB_APPLY_TRANSPORT      0x98000013u
#define IB_QUERY_TRANSPORT      0x98000014u
#define IB_RSS_INFO             0x58000025u
#define IB_COMPAT_MODE          0x9800012cu
#define IB_GET_IFLIST           0x4004747fu
#define IB_GET_IFLIST_EX        0x4800001eu

#define IB_UNSET 0xdeadbeefu

static int ib_up(void)
{
    static int done = -1;
    WSADATA d;
    if (done < 0) done = (U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : 0;
    return done;
}
#define IBTEST(n) \
    static void ibbody_##n(void); \
    TEST(n) { if (!ib_up()) { t_skip("WSAStartup failed"); return; } ibbody_##n(); } \
    static void ibbody_##n(void)

static int  ib_err(void)       { return U(WSAGetLastError)(); }
static void ib_seterr(int e)   { U(WSASetLastError)(e); }
static int  ib_close(SOCKET s) { return U(closesocket)(s); }

enum { K_TCP4, K_UDP4, K_TCP6, K_UDP6, K_UNIX, K_LISTEN4, K_CONN4, K_RAW4 };

static void ib_loop4(struct sockaddr_in *a, unsigned short port_be)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007fu;
    a->sin_port = port_be;
}

/* Fresh overlapped-capable socket of one of the kinds above; INVALID_SOCKET if the stack lacks it. */
static SOCKET ib_mk(int kind)
{
    struct sockaddr_in a, b;
    int len = sizeof a;
    SOCKET s = INVALID_SOCKET, l, c;
    DWORD fl = WSA_FLAG_OVERLAPPED;
    switch (kind) {
    case K_TCP4: return U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, fl);
    case K_UDP4: return U(WSASocketW)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, fl);
    case K_TCP6: return U(WSASocketW)(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, fl);
    case K_UDP6: return U(WSASocketW)(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, fl);
    case K_UNIX: return U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, fl);
    case K_RAW4: return U(WSASocketW)(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, fl);
    case K_LISTEN4:
        s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, fl);
        if (s == INVALID_SOCKET) return s;
        ib_loop4(&a, 0);
        if (U(bind)(s, (struct sockaddr *)&a, sizeof a) || U(listen)(s, 2)) { ib_close(s); return INVALID_SOCKET; }
        return s;
    case K_CONN4:
        l = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, fl);
        if (l == INVALID_SOCKET) return l;
        ib_loop4(&a, 0);
        if (U(bind)(l, (struct sockaddr *)&a, sizeof a) || U(listen)(l, 1) ||
            U(getsockname)(l, (struct sockaddr *)&b, &len)) { ib_close(l); return INVALID_SOCKET; }
        s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, fl);
        if (s != INVALID_SOCKET && U(connect)(s, (struct sockaddr *)&b, sizeof b) == 0) {
            c = U(accept)(l, NULL, NULL);
            if (c != INVALID_SOCKET) ib_close(c);   /* peer gone: s is connected, then closed by the peer */
        } else if (s != INVALID_SOCKET) { ib_close(s); s = INVALID_SOCKET; }
        ib_close(l);
        return s;
    }
    return s;
}
#define IB_SOCK(var, kind) SOCKET var = ib_mk(kind); \
    if (var == INVALID_SOCKET) { t_skip("socket kind %d unavailable (%d)", kind, ib_err()); return; }

/* A connected loopback TCP pair; both ends stay open (client c, server-side accepted s). */
static BOOL ib_pair(SOCKET *c, SOCKET *sv)
{
    struct sockaddr_in a;
    int len = sizeof a;
    SOCKET l = ib_mk(K_LISTEN4);
    *c = *sv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return FALSE;
    if (U(getsockname)(l, (struct sockaddr *)&a, &len) == 0) {
        *c = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (*c != INVALID_SOCKET && U(connect)(*c, (struct sockaddr *)&a, sizeof a) == 0)
            *sv = U(accept)(l, NULL, NULL);
    }
    ib_close(l);
    if (*sv == INVALID_SOCKET) {
        if (*c != INVALID_SOCKET) ib_close(*c);
        *c = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}
#define IB_PAIR(c, s) SOCKET c, s; \
    if (!ib_pair(&c, &s)) { t_skip("could not build a loopback connection"); return; }

/* Outcome of one synchronous WSAIoctl: return value, WSAGetLastError, bytes-returned (IB_UNSET if untouched). */
typedef struct { int r; int err; DWORD n; } ib_res;
static ib_res ib_io(SOCKET s, DWORD code, void *in, DWORD inl, void *out, DWORD outl, int with_n)
{
    ib_res x;
    DWORD n = IB_UNSET;
    ib_seterr((int)IB_UNSET);
    x.r = U(WSAIoctl)(s, code, in, inl, out, outl, with_n ? &n : NULL, NULL, NULL);
    x.err = ib_err();
    x.n = with_n ? n : IB_UNSET;
    return x;
}
#define IB_FAILS(x, e)  ((x).r == SOCKET_ERROR && (x).err == (e))
#define IB_OK(x)        ((x).r == 0)

/* Overlapped call with an event, bounded wait: returns the immediate result and, when pending, the final
 * outcome in *done_err (0 = success) and *done_n.  *pending is set when the call returned WSA_IO_PENDING. */
static ib_res ib_io_ov(SOCKET s, DWORD code, void *in, DWORD inl, void *out, DWORD outl,
                       int *pending, DWORD *done_err, DWORD *done_n, DWORD wait_ms)
{
    ib_res x;
    WSAOVERLAPPED ov;
    DWORD n = IB_UNSET, t = 0, fl = 0;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ib_seterr((int)IB_UNSET);
    x.r = U(WSAIoctl)(s, code, in, inl, out, outl, &n, &ov, NULL);
    x.err = ib_err();
    x.n = n;
    *pending = 0; *done_err = 0; *done_n = 0;
    if (x.r == SOCKET_ERROR && x.err == WSA_IO_PENDING) {
        *pending = 1;
        if (WaitForSingleObject(ov.hEvent, wait_ms) == WAIT_OBJECT_0) {
            if (U(WSAGetOverlappedResult)(s, &ov, &t, FALSE, &fl)) *done_err = 0;
            else *done_err = (DWORD)ib_err();
            *done_n = t;
        } else {
            *done_err = 0xffffffffu;       /* still pending after the wait */
            CancelIoEx((HANDLE)s, (LPOVERLAPPED)&ov);
            WaitForSingleObject(ov.hEvent, 2000);
        }
    }
    CloseHandle(ov.hEvent);
    return x;
}
#endif
