/* Shared helpers for the x_tcp_info_fastopen area: loopback TCP socket construction, a WSAIoctl wrapper that
 * records one call's outcome, and the control codes and option numbers this area measures. Everything in
 * ws2_32 is reached through U(); the SDK headers supply types and constants only. */
#ifndef XT_H
#define XT_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>

#define XT_SIO_TCP_INFO        0xD8000027u
#define XT_SIO_ACK_FREQ        0x98000017u
#define XT_SIO_INITIAL_RTO     0x98000011u
#define XT_SIO_LOOPBACK_FAST   0x98000010u
#define XT_SIO_SET_ICW         0x98000016u

#define XT_TCP_NODELAY         0x0001
#define XT_TCP_EXPEDITED_1122  0x0002
#define XT_TCP_KEEPALIVE       0x0003
#define XT_TCP_MAXSEG          0x0004
#define XT_TCP_MAXRT           0x0005
#define XT_TCP_STDURG          0x0006
#define XT_TCP_NOURG           0x0007
#define XT_TCP_ATMARK          0x0008
#define XT_TCP_NOSYNRETRIES    0x0009
#define XT_TCP_TIMESTAMPS      0x000A
#define XT_TCP_OFFLOAD_PREF    0x000B
#define XT_TCP_CONGESTION      0x000C
#define XT_TCP_DELAY_FIN_ACK   0x000D
#define XT_TCP_MAXRTMS         0x000E
#define XT_TCP_FASTOPEN        0x000F
#define XT_TCP_KEEPCNT         0x0010
#define XT_TCP_KEEPINTVL       0x0011
#define XT_TCP_FAIL_CONNECT    0x0012

#define XT_SO_RANDOMIZE_PORT   0x3005
#define XT_SO_PORT_SCALABILITY 0x3006
#define XT_SO_REUSE_UNICASTPORT 0x3007

/* TCP_INFO field layout, written out so the tests do not depend on SDK version guards */
typedef struct {
    DWORD State, Mss; ULONG64 ConnectionTimeMs; BYTE Timestamps; DWORD RttUs, MinRttUs, BytesInFlight, Cwnd,
        SndWnd, RcvWnd, RcvBuf; ULONG64 BytesOut, BytesIn; DWORD BytesReordered, BytesRetrans, FastRetrans,
        DupAcksIn, TimeoutEpisodes; BYTE SynRetrans;
} xt_info0;
typedef struct {
    xt_info0 b;
    DWORD SndLimTransRwin, SndLimTimeRwin; ULONG64 SndLimBytesRwin; DWORD SndLimTransCwnd, SndLimTimeCwnd;
    ULONG64 SndLimBytesCwnd; DWORD SndLimTransSnd, SndLimTimeSnd; ULONG64 SndLimBytesSnd;
} xt_info1;

/* outcome of one WSAIoctl / setsockopt / getsockopt call */
typedef struct { int rc; int err; DWORD ret; } xt_res;

int      xt_up(void);                      /* WSAStartup once; 0 on failure */
SOCKET   xt_tcp(void);
SOCKET   xt_udp(void);
void     xt_close(SOCKET s);
int      xt_bind_lo(SOCKET s, u_short *port);              /* bind 127.0.0.1:port (0 = ephemeral), port returned */
int      xt_listen_lo(SOCKET *l, u_short *port, int backlog); /* new bound+listening socket */
int      xt_connect_lo(SOCKET c, u_short port);
SOCKET   xt_accept(SOCKET l);                   /* accept once a connection is queued (bounded wait), else INVALID_SOCKET */
int      xt_pair(SOCKET *c, SOCKET *a, SOCKET *l);          /* connected loopback pair + listener */
int      xt_send(SOCKET s, const void *p, int n);
int      xt_recv_all(SOCKET s, void *p, int n, int timeout_ms); /* bytes read until n or timeout/close */
xt_res   xt_io(SOCKET s, DWORD code, const void *in, DWORD inlen, void *out, DWORD outlen);
xt_res   xt_so(SOCKET s, int level, int opt, const void *v, int len);  /* setsockopt */
xt_res   xt_go(SOCKET s, int level, int opt, void *v, int *len);       /* getsockopt (rc, err; ret = len) */
int      xt_geti(SOCKET s, int level, int opt, long long *v);          /* 4-byte get; 0 ok else WSA err */
int      xt_seti(SOCKET s, int level, int opt, int v);                 /* 4-byte set; 0 ok else WSA err */
int      xt_wsaerr(void);
int      xt_wait_state(SOCKET s, DWORD want, int timeout_ms);          /* poll TCP_INFO state */
int      xt_readable(SOCKET s, int timeout_ms);                         /* select read */
int      xt_elevated(void);

/* socket states used by the tables */
enum { XS_FRESH, XS_BOUND, XS_LISTEN, XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_UDP, XS_ACC_PEER_CLOSED, XS_COUNT };
extern const char *const xt_state_name[XS_COUNT];
typedef struct { SOCKET s, keep[2]; } xt_st;
int      xt_mkstate(int kind, xt_st *st);   /* 1 on success; st->s is the socket in the wanted state */
void     xt_rmstate(xt_st *st);
int      xt_is_connected_kind(int kind);

/* single-evaluation equality check (the arguments may be calls with side effects) */
#define EQ(a, b)  do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got %lld want %lld", a_, b_); } while (0)
#define NEED()    do { if (!xt_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#endif
