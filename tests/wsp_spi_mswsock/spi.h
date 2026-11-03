/* Shared helpers for the wsp_spi_mswsock area.
 *
 * The base provider (mswsock.dll) is driven directly through its service provider interface: the only
 * export that is resolved by name is WSPStartup, everything else is reached through the WSPPROC_TABLE that
 * WSPStartup fills in.  The tests supply their own upcall table (WPU* thunks) and count what the provider
 * does with it.  Nothing here links the DLLs under test; ws2_32 is only used (loaded dynamically) to read
 * the protocol catalog so that real WSAPROTOCOL_INFOW entries can be handed to WSPSocket.
 */
#ifndef SPI_H
#define SPI_H
#include "t.h"
#include <winsock2.h>
#include <ws2spi.h>
#include <ws2tcpip.h>

/* The harness macro evaluates its arguments twice; most expressions in this area are provider calls with
 * side effects, so equality is re-defined here to evaluate each side exactly once. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR ea_ = (ULONG_PTR)(a), eb_ = (ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)ea_, (unsigned long long)eb_); } while (0)

/* ---- error numbers used by name in checks (kept local so the checks read plainly) ---- */
#define SE_FAULT        10014
#define SE_INVAL        10022
#define SE_NOTSOCK      10038
#define SE_NOTINIT      10093
#define SE_VERNOTSUP    10092
#define SE_OPNOTSUPP    10045
#define SE_ISCONN       10056
#define SE_NOTCONN      10057
#define SE_AFNOSUPPORT  10047
#define SE_SOCKTNOSUP   10044
#define SE_PROTONOSUP   10043
#define SE_PROTOTYPE    10041
#define SE_IOINCOMPLETE 996
#define SE_IOPENDING    997
#define SE_WOULDBLOCK   10035
#define SE_MSGSIZE      10040

#define MS_TCP_PROVIDER_ID_D1 0xE70F1AA0u
#define MS_TCP6_PROVIDER_ID_D1 0xF9EAB0C0u

/* ---- loopback helpers (byte order done by hand: no import needed) ---- */
static unsigned short sp_swap16(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }
static void sp_v4(struct sockaddr_in *a, unsigned short port_host)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_port = sp_swap16(port_host);
    a->sin_addr.s_addr = 0x0100007Fu;   /* 127.0.0.1 in network order on a little-endian host */
}
static void sp_v6(struct sockaddr_in6 *a, unsigned short port_host)
{
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6;
    a->sin6_port = sp_swap16(port_host);
    a->sin6_addr.s6_addr[15] = 1;
}

/* ---- the upcall table the tests hand to the provider ---- */
#define UP_CLOSEEVENT 0
#define UP_CLOSESOCKETHANDLE 1
#define UP_CREATEEVENT 2
#define UP_CREATESOCKETHANDLE 3
#define UP_FDISSET 4
#define UP_GETPROVIDERPATH 5
#define UP_MODIFYIFSHANDLE 6
#define UP_POSTMESSAGE 7
#define UP_QUERYBLOCKINGCALLBACK 8
#define UP_QUERYSOCKETHANDLECONTEXT 9
#define UP_QUEUEAPC 10
#define UP_RESETEVENT 11
#define UP_SETEVENT 12
#define UP_COMPLETEOVERLAPPED 13
#define UP_OPENCURRENTTHREAD 14
#define UP_CLOSETHREAD 15
#define UP_COUNT 16

typedef struct { volatile LONG n[UP_COUNT]; volatile LONG cat; volatile LONG_PTR handle; } sp_ups_t;
static sp_ups_t sp_upA, sp_upB;     /* two independent counters: table A and table B */

#define SP_THUNKS(T, C) \
static BOOL WSPAPI T##_CloseEvent(WSAEVENT h, LPINT e) { InterlockedIncrement(&C.n[UP_CLOSEEVENT]); *e = 0; return CloseHandle(h); } \
static int WSPAPI T##_CloseSocketHandle(SOCKET s, LPINT e) { InterlockedIncrement(&C.n[UP_CLOSESOCKETHANDLE]); *e = 0; return 0; } \
static WSAEVENT WSPAPI T##_CreateEvent(LPINT e) { InterlockedIncrement(&C.n[UP_CREATEEVENT]); *e = 0; return CreateEventW(NULL, TRUE, FALSE, NULL); } \
static SOCKET WSPAPI T##_CreateSocketHandle(DWORD c, DWORD_PTR ctx, LPINT e) { InterlockedIncrement(&C.n[UP_CREATESOCKETHANDLE]); *e = WSAEACCES; return INVALID_SOCKET; } \
static int WSPAPI T##_FDIsSet(SOCKET s, fd_set *set) { u_int i; InterlockedIncrement(&C.n[UP_FDISSET]); for (i = 0; i < set->fd_count; i++) if (set->fd_array[i] == s) return 1; return 0; } \
static int WSPAPI T##_GetProviderPath(LPGUID g, WCHAR *p, LPINT l, LPINT e) { InterlockedIncrement(&C.n[UP_GETPROVIDERPATH]); *e = WSAEINVAL; return SOCKET_ERROR; } \
static SOCKET WSPAPI T##_ModifyIFSHandle(DWORD cat, SOCKET h, LPINT e) { InterlockedIncrement(&C.n[UP_MODIFYIFSHANDLE]); C.cat = (LONG)cat; C.handle = (LONG_PTR)h; *e = 0; return h; } \
static BOOL WSPAPI T##_PostMessage(HWND w, UINT m, WPARAM wp, LPARAM lp) { InterlockedIncrement(&C.n[UP_POSTMESSAGE]); return TRUE; } \
static int WSPAPI T##_QueryBlockingCallback(DWORD cat, LPBLOCKINGCALLBACK *cb, PDWORD_PTR ctx, LPINT e) { InterlockedIncrement(&C.n[UP_QUERYBLOCKINGCALLBACK]); *cb = NULL; *ctx = 0; *e = 0; return 0; } \
static int WSPAPI T##_QuerySocketHandleContext(SOCKET s, PDWORD_PTR ctx, LPINT e) { InterlockedIncrement(&C.n[UP_QUERYSOCKETHANDLECONTEXT]); *e = WSAENOTSOCK; return SOCKET_ERROR; } \
static int WSPAPI T##_QueueApc(LPWSATHREADID t, LPWSAUSERAPC f, DWORD_PTR c, LPINT e) { InterlockedIncrement(&C.n[UP_QUEUEAPC]); *e = 0; return 0; } \
static BOOL WSPAPI T##_ResetEvent(WSAEVENT h, LPINT e) { InterlockedIncrement(&C.n[UP_RESETEVENT]); *e = 0; return ResetEvent(h); } \
static BOOL WSPAPI T##_SetEvent(WSAEVENT h, LPINT e) { InterlockedIncrement(&C.n[UP_SETEVENT]); *e = 0; return SetEvent(h); } \
static int WSPAPI T##_CompleteOverlapped(SOCKET s, LPWSAOVERLAPPED o, DWORD er, DWORD cb, LPINT e) { InterlockedIncrement(&C.n[UP_COMPLETEOVERLAPPED]); *e = 0; return 0; } \
static int WSPAPI T##_OpenCurrentThread(LPWSATHREADID t, LPINT e) { InterlockedIncrement(&C.n[UP_OPENCURRENTTHREAD]); *e = 0; return 0; } \
static int WSPAPI T##_CloseThread(LPWSATHREADID t, LPINT e) { InterlockedIncrement(&C.n[UP_CLOSETHREAD]); *e = 0; return 0; } \
static void T##_fill(WSPUPCALLTABLE *u) { \
    u->lpWPUCloseEvent = T##_CloseEvent; u->lpWPUCloseSocketHandle = T##_CloseSocketHandle; \
    u->lpWPUCreateEvent = T##_CreateEvent; u->lpWPUCreateSocketHandle = T##_CreateSocketHandle; \
    u->lpWPUFDIsSet = T##_FDIsSet; u->lpWPUGetProviderPath = T##_GetProviderPath; \
    u->lpWPUModifyIFSHandle = T##_ModifyIFSHandle; u->lpWPUPostMessage = T##_PostMessage; \
    u->lpWPUQueryBlockingCallback = T##_QueryBlockingCallback; \
    u->lpWPUQuerySocketHandleContext = T##_QuerySocketHandleContext; u->lpWPUQueueApc = T##_QueueApc; \
    u->lpWPUResetEvent = T##_ResetEvent; u->lpWPUSetEvent = T##_SetEvent; \
    u->lpWPUOpenCurrentThread = T##_OpenCurrentThread; u->lpWPUCloseThread = T##_CloseThread; }

SP_THUNKS(spA, sp_upA)
SP_THUNKS(spB, sp_upB)

static void sp_up_reset(sp_ups_t *c) { memset((void *)c, 0, sizeof *c); }
static LONG sp_up_total(const sp_ups_t *c) { LONG t = 0; int i; for (i = 0; i < UP_COUNT; i++) t += c->n[i]; return t; }

/* ---- protocol info: real catalog entries when ws2_32 can enumerate them, hand built otherwise ---- */
static const GUID sp_guid_v4 = { 0xE70F1AA0, 0xAB8B, 0x11CF, { 0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92 } };
static const GUID sp_guid_v6 = { 0xF9EAB0C0, 0x26D4, 0x11D0, { 0xBB, 0xBF, 0x00, 0xAA, 0x00, 0x6C, 0x34, 0xE4 } };

static void sp_hand_pi(WSAPROTOCOL_INFOW *pi, int af, int ty, int pr)
{
    memset(pi, 0, sizeof *pi);
    if (ty == SOCK_STREAM) pi->dwServiceFlags1 = XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE | XP1_EXPEDITED_DATA | XP1_IFS_HANDLES;
    else pi->dwServiceFlags1 = XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED | XP1_SUPPORT_BROADCAST | XP1_SUPPORT_MULTIPOINT | XP1_IFS_HANDLES;
    pi->ProviderId = af == AF_INET6 ? sp_guid_v6 : sp_guid_v4;
    pi->dwCatalogEntryId = 1001 + ty + (af == AF_INET6 ? 100 : 0);
    pi->ProtocolChain.ChainLen = 1;
    pi->iVersion = 2;
    pi->iAddressFamily = af;
    pi->iMaxSockAddr = af == AF_INET6 ? 28 : 16;
    pi->iMinSockAddr = af == AF_INET6 ? 28 : 16;
    pi->iSocketType = ty;
    pi->iProtocol = pr;
    pi->iProtocolMaxOffset = ty == SOCK_RAW ? 255 : 0;
    pi->dwMessageSize = ty == SOCK_STREAM ? 0 : 0xFFBB;
}

static WSAPROTOCOL_INFOW sp_cat[64];
static int sp_cat_n = -1;
static void sp_load_catalog(void)
{
    WSADATA d; DWORD len = 0; static WSAPROTOCOL_INFOW buf[96];
    sp_cat_n = 0;
    if (!U(WSAStartup) || !U(WSAEnumProtocolsW)) return;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return;
    len = sizeof buf;
    int n = U(WSAEnumProtocolsW)(NULL, buf, &len);
    if (n <= 0) return;
    for (int i = 0; i < n && sp_cat_n < 64; i++) {
        if (buf[i].ProtocolChain.ChainLen != 1) continue;
        if (buf[i].ProviderId.Data1 != MS_TCP_PROVIDER_ID_D1 && buf[i].ProviderId.Data1 != MS_TCP6_PROVIDER_ID_D1) continue;
        sp_cat[sp_cat_n++] = buf[i];
    }
}
static WSAPROTOCOL_INFOW sp_hand_store[8];
static int sp_hand_n;
/* Entry for (af, type, proto): the catalog's when found, else a hand-built look-alike. */
static const WSAPROTOCOL_INFOW *sp_pi(int af, int ty, int pr)
{
    int i;
    if (sp_cat_n < 0) sp_load_catalog();
    for (i = 0; i < sp_cat_n; i++)
        if (sp_cat[i].iAddressFamily == af && sp_cat[i].iSocketType == ty && sp_cat[i].iProtocol == pr) return &sp_cat[i];
    for (i = 0; i < sp_hand_n; i++)
        if (sp_hand_store[i].iAddressFamily == af && sp_hand_store[i].iSocketType == ty && sp_hand_store[i].iProtocol == pr) return &sp_hand_store[i];
    if (sp_hand_n < 8) { sp_hand_pi(&sp_hand_store[sp_hand_n], af, ty, pr); return &sp_hand_store[sp_hand_n++]; }
    return &sp_hand_store[0];
}

/* ---- provider start-up (once per process, never balanced: the table stays valid) ---- */
static WSPPROC_TABLE P;
static WSPDATA sp_data;
static int sp_state;    /* 0 untried, 1 running, -1 unavailable */
static int sp_up(void)
{
    if (!sp_state) {
        WSPUPCALLTABLE u;
        int (WSPAPI *st)(WORD, LPWSPDATA, LPWSAPROTOCOL_INFOW, WSPUPCALLTABLE, LPWSPPROC_TABLE) = (void *)UIN("mswsock.dll", WSPStartup);
        sp_state = -1;
        if (!st || t_is_wine()) return 0;   /* the emulator's stub for this entry aborts the process */
        spA_fill(&u);
        memset(&P, 0, sizeof P);
        if (st(MAKEWORD(2, 2), &sp_data, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &P) == 0 && P.lpWSPSocket) sp_state = 1;
    }
    return sp_state == 1;
}
#define SP_NEED() do { if (!sp_up()) { t_skip("provider start-up unavailable"); return; } } while (0)

/* ---- socket plumbing through the table ---- */
static SOCKET sp_sock_flags(int af, int ty, int pr, DWORD flags, int *e)
{
    *e = 0;
    return P.lpWSPSocket(af, ty, pr, (LPWSAPROTOCOL_INFOW)sp_pi(af, ty, pr), 0, flags, e);
}
static SOCKET sp_sock(int af, int ty, int pr, int *e) { return sp_sock_flags(af, ty, pr, WSA_FLAG_OVERLAPPED, e); }
static SOCKET sp_tcp(void) { int e; return sp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, &e); }
static SOCKET sp_udp(void) { int e; return sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &e); }
static void sp_close(SOCKET s) { int e; if (s != INVALID_SOCKET && s != 0) P.lpWSPCloseSocket(s, &e); }

static int sp_bind_lo(SOCKET s)
{
    struct sockaddr_in a; int e = 0;
    sp_v4(&a, 0);
    return P.lpWSPBind(s, (struct sockaddr *)&a, sizeof a, &e);
}
static int sp_name(SOCKET s, struct sockaddr_in *a)
{
    int e = 0, l = sizeof *a;
    memset(a, 0, sizeof *a);
    return P.lpWSPGetSockName(s, (struct sockaddr *)a, &l, &e);
}
/* Readable within ms? returns the select count. */
static int sp_readable(SOCKET s, int ms)
{
    fd_set r; struct timeval tv; int e = 0;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e);
}
static int sp_writable(SOCKET s, int ms)
{
    fd_set w; struct timeval tv; int e = 0;
    w.fd_count = 1; w.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return P.lpWSPSelect(0, NULL, &w, NULL, &tv, &e);
}
/* Listening TCP socket on an ephemeral loopback port. */
static SOCKET sp_listener(struct sockaddr_in *addr)
{
    int e = 0; SOCKET l = sp_tcp();
    if (l == INVALID_SOCKET) return l;
    if (sp_bind_lo(l) != 0 || P.lpWSPListen(l, 4, &e) != 0 || sp_name(l, addr) != 0) { sp_close(l); return INVALID_SOCKET; }
    return l;
}
/* A connected TCP pair (client c, accepted server side a). */
static int sp_pair(SOCKET *c, SOCKET *a)
{
    struct sockaddr_in la; int e = 0;
    SOCKET l = sp_listener(&la), k, s;
    *c = *a = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    k = sp_tcp();
    if (k == INVALID_SOCKET || P.lpWSPConnect(k, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e) != 0) { sp_close(k); sp_close(l); return 0; }
    if (sp_readable(l, 5000) != 1) { sp_close(k); sp_close(l); return 0; }
    s = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
    sp_close(l);
    if (s == INVALID_SOCKET) { sp_close(k); return 0; }
    *c = k; *a = s;
    return 1;
}
#define SP_PAIR(c, a) SOCKET c, a; do { if (!sp_pair(&c, &a)) { t_skip("loopback pair unavailable"); return; } } while (0)

static int sp_send_all(SOCKET s, const void *b, int n)
{
    WSABUF w; DWORD sent = 0; int e = 0;
    w.buf = (CHAR *)b; w.len = n;
    return P.lpWSPSend(s, &w, 1, &sent, 0, NULL, NULL, NULL, &e) == 0 && (int)sent == n;
}
static int sp_recv_some(SOCKET s, void *b, int n, int *err)
{
    WSABUF w; DWORD got = 0, fl = 0; int e = 0, r;
    w.buf = (CHAR *)b; w.len = n;
    r = P.lpWSPRecv(s, &w, 1, &got, &fl, NULL, NULL, NULL, &e);
    if (err) *err = e;
    return r == 0 ? (int)got : -1;
}

/* ---- child-process check counter: children report mismatches through their exit code ---- */
static int ck_bad;
#define CB() do { ck_bad = 0; sp_cat_n = 0; } while (0)   /* children never touch the catalog (no ws2_32 start-up) */
#define CK(c) do { if (!(c)) { ck_bad++; printf("  CHILD FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CK_EQ(a, b) do { if ((ULONG_PTR)(a) != (ULONG_PTR)(b)) { ck_bad++; printf("  CHILD FAIL %s:%d %s == %s (got 0x%llx want 0x%llx)\n", __FILE__, __LINE__, #a, #b, (unsigned long long)(ULONG_PTR)(a), (unsigned long long)(ULONG_PTR)(b)); } } while (0)

/* Raw WSPStartup for children (and the version tests): pure pass-through. */
typedef int (WSPAPI *sp_startup_fn)(WORD, LPWSPDATA, LPWSAPROTOCOL_INFOW, WSPUPCALLTABLE, LPWSPPROC_TABLE);
static sp_startup_fn sp_startup_ptr(void) { return (sp_startup_fn)UIN("mswsock.dll", WSPStartup); }
#endif
