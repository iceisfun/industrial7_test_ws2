/* Shared helpers for the wsock32 compatibility-layer area.
 *
 * Everything under test is reached through GetProcAddress: WS(name) resolves in wsock32.dll (the module
 * under test), W2(name) resolves the same-named export of ws2_32.dll, MS(name) in mswsock.dll. The signatures
 * are declared here as plain function-pointer types so that nothing is ever linked. */
#ifndef WF_H
#define WF_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <nspapi.h>

#define WS(name) ((p_##name)t_proc_in("wsock32.dll", #name))
#define W2(name) ((p_##name)t_proc_in("ws2_32.dll", #name))
#define MS(name) ((p_##name)t_proc_in("mswsock.dll", #name))

typedef int    (WSAAPI *p_WSAStartup)(WORD, LPWSADATA);
typedef int    (WSAAPI *p_WSACleanup)(void);
typedef int    (WSAAPI *p_WSAGetLastError)(void);
typedef void   (WSAAPI *p_WSASetLastError)(int);
typedef SOCKET (WSAAPI *p_socket)(int, int, int);
typedef int    (WSAAPI *p_closesocket)(SOCKET);
typedef int    (WSAAPI *p_bind)(SOCKET, const struct sockaddr *, int);
typedef int    (WSAAPI *p_listen)(SOCKET, int);
typedef SOCKET (WSAAPI *p_accept)(SOCKET, struct sockaddr *, int *);
typedef int    (WSAAPI *p_connect)(SOCKET, const struct sockaddr *, int);
typedef int    (WSAAPI *p_getsockname)(SOCKET, struct sockaddr *, int *);
typedef int    (WSAAPI *p_getpeername)(SOCKET, struct sockaddr *, int *);
typedef int    (WSAAPI *p_send)(SOCKET, const char *, int, int);
typedef int    (WSAAPI *p_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
typedef int    (WSAAPI *p_recv)(SOCKET, char *, int, int);
typedef int    (WSAAPI *p_recvfrom)(SOCKET, char *, int, int, struct sockaddr *, int *);
typedef int    (WSAAPI *p_getsockopt)(SOCKET, int, int, char *, int *);
typedef int    (WSAAPI *p_setsockopt)(SOCKET, int, int, const char *, int);
typedef int    (WSAAPI *p_ioctlsocket)(SOCKET, long, u_long *);
typedef int    (WSAAPI *p_shutdown)(SOCKET, int);
typedef int    (WSAAPI *p_select)(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
typedef int    (WSAAPI *p___WSAFDIsSet)(SOCKET, fd_set *);
typedef int    (WSAAPI *p_WSARecvEx)(SOCKET, char *, int, int *);
typedef u_long (WSAAPI *p_htonl)(u_long);
typedef u_long (WSAAPI *p_ntohl)(u_long);
typedef u_short(WSAAPI *p_htons)(u_short);
typedef u_short(WSAAPI *p_ntohs)(u_short);
typedef unsigned long (WSAAPI *p_inet_addr)(const char *);
typedef char * (WSAAPI *p_inet_ntoa)(struct in_addr);
typedef struct servent *(WSAAPI *p_getservbyname)(const char *, const char *);
typedef struct servent *(WSAAPI *p_getservbyport)(int, const char *);
typedef INT    (WSAAPI *p_EnumProtocolsA)(LPINT, LPVOID, LPDWORD);
typedef INT    (WSAAPI *p_EnumProtocolsW)(LPINT, LPVOID, LPDWORD);
typedef INT    (WSAAPI *p_GetTypeByNameA)(LPSTR, LPGUID);
typedef INT    (WSAAPI *p_GetTypeByNameW)(LPWSTR, LPGUID);
typedef INT    (WSAAPI *p_GetNameByTypeA)(LPGUID, LPSTR, DWORD);
typedef INT    (WSAAPI *p_GetNameByTypeW)(LPGUID, LPWSTR, DWORD);
typedef INT    (WSAAPI *p_GetAddressByNameA)(DWORD, LPGUID, LPSTR, LPINT, DWORD, LPSERVICE_ASYNC_INFO, LPVOID, LPDWORD, LPSTR, LPDWORD);
typedef INT    (WSAAPI *p_GetAddressByNameW)(DWORD, LPGUID, LPWSTR, LPINT, DWORD, LPSERVICE_ASYNC_INFO, LPVOID, LPDWORD, LPWSTR, LPDWORD);
typedef INT    (WSAAPI *p_GetServiceA)(DWORD, LPGUID, LPSTR, DWORD, LPVOID, LPDWORD, LPSERVICE_ASYNC_INFO);
typedef INT    (WSAAPI *p_GetServiceW)(DWORD, LPGUID, LPWSTR, DWORD, LPVOID, LPDWORD, LPSERVICE_ASYNC_INFO);
typedef INT    (WSAAPI *p_SetServiceA)(DWORD, DWORD, DWORD, LPSERVICE_INFOA, LPSERVICE_ASYNC_INFO, LPDWORD);
typedef INT    (WSAAPI *p_SetServiceW)(DWORD, DWORD, DWORD, LPSERVICE_INFOW, LPSERVICE_ASYNC_INFO, LPDWORD);
typedef int    (WSAAPI *p_NPLoadNameSpaces)(LPDWORD, void *, LPDWORD);
typedef int    (WSAAPI *p_dn_expand)(const unsigned char *, const unsigned char *, const unsigned char *, unsigned char *, int);
typedef void   (WSAAPI *p_s_perror)(const char *, int);
typedef void * (WSAAPI *p_getnetbyname)(const char *);
typedef INT_PTR(WSAAPI *p_rcmd)(char **, unsigned short, const char *, const char *, const char *, int *);
typedef INT_PTR(WSAAPI *p_rexec)(char **, int, const char *, const char *, const char *, int *);
typedef INT_PTR(WSAAPI *p_rresvport)(int *);
typedef int    (WSAAPI *p_sethostname)(const char *, int);
typedef int    (WSAAPI *p_WSApSetPostRoutine)(void *);
typedef int    (WSAAPI *p_WSAAsyncSelect)(SOCKET, HWND, unsigned int, long);
typedef int    (WSAAPI *p_WSACancelAsyncRequest)(HANDLE);
typedef BOOL   (WSAAPI *p_AcceptEx)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
typedef VOID   (WSAAPI *p_GetAcceptExSockaddrs)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);
typedef BOOL   (WSAAPI *p_TransmitFile)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
typedef int    (WSAAPI *p_WEP)(void);
typedef int    (WSAAPI *p_gethostname)(char *, int);
typedef struct hostent *(WSAAPI *p_gethostbyname)(const char *);

#define WSA_NOTINIT  10093
#define WSA_ERR_VERNOTSUPPORTED 10092

static inline unsigned short wf_sw16(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }
static inline unsigned long wf_sw32(unsigned long v) {
    return ((v & 0xffUL) << 24) | ((v & 0xff00UL) << 8) | ((v >> 8) & 0xff00UL) | ((v >> 24) & 0xffUL);
}

/* Winsock lifetime: every test that needs the stack brackets its work with wf_up()/wf_down(). */
static inline int wf_up(void) {
    WSADATA d;
    if (!W2(WSAStartup) || !W2(WSACleanup)) { t_skip("ws2_32 start/cleanup missing"); return 0; }
    if (W2(WSAStartup)(0x0202, &d) != 0) { t_skip("WSAStartup(2.2) failed"); return 0; }
    return 1;
}
static inline void wf_down(void) { W2(WSACleanup)(); }
#define WF_UP() do { if (!wf_up()) return; } while (0)

static inline int wf_err(void) { return W2(WSAGetLastError)(); }
static inline void wf_seterr(int e) { W2(WSASetLastError)(e); }

static inline struct sockaddr_in wf_lo(unsigned short port_net) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = (u_long)(0x0100007fUL);   /* 127.0.0.1 in network byte order on a little-endian host */
    a.sin_port = port_net;
    return a;
}

/* Receive timeout (ms) on a socket so that no wait can hang the run. */
static inline void wf_rcvtimeo(SOCKET s, DWORD ms) {
    W2(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
}

/* A UDP socket bound to loopback:ephemeral; local address returned in *out. */
static inline SOCKET wf_udp(struct sockaddr_in *out) {
    SOCKET s = W2(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in a = wf_lo(0);
    int n = sizeof a;
    if (s == INVALID_SOCKET) return s;
    if (W2(bind)(s, (struct sockaddr *)&a, sizeof a) != 0 || W2(getsockname)(s, (struct sockaddr *)&a, &n) != 0) {
        W2(closesocket)(s); return INVALID_SOCKET;
    }
    wf_rcvtimeo(s, 3000);
    if (out) *out = a;
    return s;
}

/* A connected loopback TCP pair; *l receives the listener when non-NULL (otherwise it is closed). */
static inline int wf_tcp_pair(SOCKET *c, SOCKET *a, SOCKET *l) {
    struct sockaddr_in sa = wf_lo(0);
    int n = sizeof sa;
    SOCKET ls = W2(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP), cs, as;
    *c = *a = INVALID_SOCKET;
    if (ls == INVALID_SOCKET) return 0;
    if (W2(bind)(ls, (struct sockaddr *)&sa, sizeof sa) || W2(listen)(ls, 4) || W2(getsockname)(ls, (struct sockaddr *)&sa, &n)) {
        W2(closesocket)(ls); return 0;
    }
    cs = W2(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cs == INVALID_SOCKET || W2(connect)(cs, (struct sockaddr *)&sa, sizeof sa) != 0) {
        if (cs != INVALID_SOCKET) W2(closesocket)(cs);
        W2(closesocket)(ls); return 0;
    }
    as = W2(accept)(ls, NULL, NULL);
    if (as == INVALID_SOCKET) { W2(closesocket)(cs); W2(closesocket)(ls); return 0; }
    wf_rcvtimeo(cs, 3000); wf_rcvtimeo(as, 3000);
    *c = cs; *a = as;
    if (l) *l = ls; else W2(closesocket)(ls);
    return 1;
}

static inline void wf_nonblock(SOCKET s, u_long on) { W2(ioctlsocket)(s, FIONBIO, &on); }

/* Spawn this exe as a child with a mode name and arguments; true when the child exits 0. */
#define WF_RUN_CHILD(name, args) EXPECT_EQ(t_run_child(name, args, 30000), 0)

/* Single-evaluation equality (the harness macro evaluates its first operand twice, which matters for I/O calls). */
#define WEQ(a, b) do { long long wq_ = (long long)(a); \
    t_check(wq_ == (long long)(b), __FILE__, __LINE__, #a " == " #b, "got %lld want %lld", wq_, (long long)(b)); } while (0)

#endif
