/* Shared helpers for the x_registered_io area (Registered I/O).
 *
 * ws2_32.dll and mswsock.dll are never linked. Winsock entries are macros that resolve through
 * LoadLibrary/GetProcAddress (pinned to ws2_32.dll). The RIO entry points are obtained the way applications
 * do it: WSAIoctl(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, WSAID_MULTIPLE_RIO) on a live socket.
 * The MinGW headers lack the RIO types, so they are declared here from the documented layouts. */
#ifndef RIO_H
#define RIO_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define W(name) UIN("ws2_32.dll", name)
#define WSAStartup(...)             W(WSAStartup)(__VA_ARGS__)
#define WSACleanup()                W(WSACleanup)()
#define WSAGetLastError()           W(WSAGetLastError)()
#define WSASetLastError(...)        W(WSASetLastError)(__VA_ARGS__)
#define socket(...)                 W(socket)(__VA_ARGS__)
#define WSASocketW(...)             W(WSASocketW)(__VA_ARGS__)
#define closesocket(...)            W(closesocket)(__VA_ARGS__)
#define bind(...)                   W(bind)(__VA_ARGS__)
#define listen(...)                 W(listen)(__VA_ARGS__)
#define accept(...)                 W(accept)(__VA_ARGS__)
#define connect(...)                W(connect)(__VA_ARGS__)
#define send(...)                   W(send)(__VA_ARGS__)
#define recv(...)                   W(recv)(__VA_ARGS__)
#define sendto(...)                 W(sendto)(__VA_ARGS__)
#define recvfrom(...)               W(recvfrom)(__VA_ARGS__)
#define shutdown(...)               W(shutdown)(__VA_ARGS__)
#define getsockname(...)            W(getsockname)(__VA_ARGS__)
#define setsockopt(...)             W(setsockopt)(__VA_ARGS__)
#define getsockopt(...)             W(getsockopt)(__VA_ARGS__)
#define ioctlsocket(...)            W(ioctlsocket)(__VA_ARGS__)
#define WSAIoctl(...)               W(WSAIoctl)(__VA_ARGS__)
#define WSARecv(...)                W(WSARecv)(__VA_ARGS__)
#define WSASend(...)                W(WSASend)(__VA_ARGS__)

#undef EXPECT_EQ   /* the harness macro evaluates operands twice */
#define EXPECT_EQ(a, b) do { ULONG_PTR xa_ = (ULONG_PTR)(a), xb_ = (ULONG_PTR)(b); \
    t_check(xa_ == xb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)xa_, (unsigned long long)xb_); } while (0)

#ifndef WSA_FLAG_REGISTERED_IO
#define WSA_FLAG_REGISTERED_IO 0x100
#endif
#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER 0xC8000024
#endif

typedef struct rio_bufid_ *RIO_BUFFERID;
typedef struct rio_cq_ *RIO_CQ;
typedef struct rio_rq_ *RIO_RQ;
#define RIO_INVALID_BUFFERID ((RIO_BUFFERID)(ULONG_PTR)0xFFFFFFFF)
#define RIO_CORRUPT_CQ ((ULONG)0xFFFFFFFF)
#define RIO_MSG_DONT_NOTIFY 0x1
#define RIO_MSG_DEFER       0x2
#define RIO_MSG_WAITALL     0x4
#define RIO_MSG_COMMIT_ONLY 0x8
#define RIO_EVENT_COMPLETION 1
#define RIO_IOCP_COMPLETION  2

typedef struct { RIO_BUFFERID BufferId; ULONG Offset; ULONG Length; } RIO_BUF;
typedef struct { LONG Status; ULONG BytesTransferred; ULONGLONG SocketContext; ULONGLONG RequestContext; } RIORES;
typedef struct {
    int Type;
    union {
        struct { HANDLE EventHandle; BOOL NotifyReset; } Event;
        struct { HANDLE IocpHandle; PVOID CompletionKey; PVOID Overlapped; } Iocp;
    } u;
} RIO_NOTIF;

typedef BOOL (WINAPI *rio_recv_fn)(RIO_RQ, RIO_BUF *, ULONG, DWORD, PVOID);
typedef BOOL (WINAPI *rio_recvex_fn)(RIO_RQ, RIO_BUF *, ULONG, RIO_BUF *, RIO_BUF *, RIO_BUF *, RIO_BUF *, DWORD, PVOID);
typedef BOOL (WINAPI *rio_send_fn)(RIO_RQ, RIO_BUF *, ULONG, DWORD, PVOID);
typedef BOOL (WINAPI *rio_sendex_fn)(RIO_RQ, RIO_BUF *, ULONG, RIO_BUF *, RIO_BUF *, RIO_BUF *, RIO_BUF *, DWORD, PVOID);
typedef void (WINAPI *rio_closecq_fn)(RIO_CQ);
typedef RIO_CQ (WINAPI *rio_createcq_fn)(DWORD, RIO_NOTIF *);
typedef RIO_RQ (WINAPI *rio_createrq_fn)(SOCKET, ULONG, ULONG, ULONG, ULONG, RIO_CQ, RIO_CQ, PVOID);
typedef ULONG (WINAPI *rio_dequeue_fn)(RIO_CQ, RIORES *, ULONG);
typedef void (WINAPI *rio_dereg_fn)(RIO_BUFFERID);
typedef int (WINAPI *rio_notify_fn)(RIO_CQ);
typedef RIO_BUFFERID (WINAPI *rio_reg_fn)(PCHAR, DWORD);
typedef BOOL (WINAPI *rio_resizecq_fn)(RIO_CQ, DWORD);
typedef BOOL (WINAPI *rio_resizerq_fn)(RIO_RQ, ULONG, ULONG);

/* RIO_EXTENSION_FUNCTION_TABLE, in the documented field order. */
typedef struct {
    DWORD cbSize;
    rio_recv_fn Receive; rio_recvex_fn ReceiveEx; rio_send_fn Send; rio_sendex_fn SendEx;
    rio_closecq_fn CloseCompletionQueue; rio_createcq_fn CreateCompletionQueue; rio_createrq_fn CreateRequestQueue;
    rio_dequeue_fn DequeueCompletion; rio_dereg_fn DeregisterBuffer; rio_notify_fn Notify;
    rio_reg_fn RegisterBuffer; rio_resizecq_fn ResizeCompletionQueue; rio_resizerq_fn ResizeRequestQueue;
} RIO_TABLE;

#define RIO_LOOPBACK 0x0100007FUL

static int rio_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        state = (W(WSAStartup) && WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED_NET() do { if (!rio_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

static void rio_loop4(struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = RIO_LOOPBACK;
}

static SOCKET rio_sock(int af, int type, int proto, DWORD flags)
{
    return WSASocketW(af, type, proto, NULL, 0, flags);
}
#define RIO_FL (WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO)

static const GUID RIO_GUID = {0x8509e081, 0x96dd, 0x4005, {0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f}};

/* The table, fetched once on a throw-away RIO UDP socket. NULL when unavailable. */
static RIO_TABLE *rio_tbl(void)
{
    static RIO_TABLE t; static int state;
    if (!state) {
        SOCKET s; DWORD n = 0; GUID g = RIO_GUID;
        state = -1;
        if (rio_up() && (s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL)) != INVALID_SOCKET) {
            memset(&t, 0, sizeof t);
            t.cbSize = sizeof t;
            if (WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &t, sizeof t, &n, NULL, NULL) == 0)
                state = 1;
            closesocket(s);
        }
    }
    return state > 0 ? &t : NULL;
}
#define NEED_RIO(t) RIO_TABLE *t; NEED_NET(); t = rio_tbl(); if (!t) { t_skip("RIO unavailable"); return; }


/* 64-bit contexts exercise the full width of the RIORESULT fields. */
#define CTX_A 0xA1A1A1A1A1A1A1A1ULL
#define CTX_B 0xB2B2B2B2B2B2B2B2ULL
#define RQC(n) ((PVOID)(ULONG_PTR)(0x1100000000ULL + (n)))   /* request contexts: 0x11_0000_0000 + n */
#define RQV(n) (0x1100000000ULL + (n))

/* Bounded wait for completions: polls the queue until `want` entries were collected or ~5 s passed. */
static ULONG rio_wait(RIO_TABLE *t, RIO_CQ cq, RIORES *out, ULONG max, ULONG want)
{
    ULONG got = 0; int i;
    for (i = 0; i < 1000 && got < want; i++) {
        ULONG d = t->DequeueCompletion(cq, out + got, max - got);
        if (d == RIO_CORRUPT_CQ) return d;
        got += d;
        if (got < want) Sleep(5);
    }
    return got;
}
/* Short settle used before asserting that nothing happened. */
static void rio_settle(void) { Sleep(150); }

static SOCKET rio_ubind(struct sockaddr_in *out)
{
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    struct sockaddr_in a; int l = sizeof a;
    if (s == INVALID_SOCKET) return s;
    rio_loop4(&a);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || getsockname(s, (struct sockaddr *)&a, &l)) { closesocket(s); return INVALID_SOCKET; }
    if (out) *out = a;
    return s;
}

/* Fixture: two bound loopback RIO UDP sockets a and b, each with its own completion queue (polling) and a request
 * queue of depth 4/4, plus one registered 128 KiB region. Offsets inside the region:
 *   0x0000..0x7fff payload area for sends     0x8000..0xffff payload area for receives
 *   0x10100  SOCKADDR_INET holding b's address   0x10180  holding a's address
 *   0x10200  local-address out area    0x10300  remote-address out area */
#define PR_SEND 0x0000
#define PR_RECV 0x8000
#define PR_TOB  0x10100
#define PR_TOA  0x10180
#define PR_LOC  0x10200
#define PR_REM  0x10300
typedef struct {
    RIO_TABLE *t; SOCKET a, b; struct sockaddr_in aa, ba; RIO_CQ cqa, cqb; RIO_RQ ra, rb;
    char *mem; RIO_BUFFERID id;
} PAIR;
static int pair_open2(PAIR *p, RIO_TABLE *t, ULONG depth, int with_rb)
{
    memset(p, 0, sizeof *p); p->t = t;
    p->a = rio_ubind(&p->aa); p->b = rio_ubind(&p->ba);
    p->cqa = t->CreateCompletionQueue(depth * 4, NULL); p->cqb = t->CreateCompletionQueue(depth * 4, NULL);
    if (p->a == INVALID_SOCKET || p->b == INVALID_SOCKET || !p->cqa || !p->cqb) return 0;
    p->ra = t->CreateRequestQueue(p->a, depth, 1, depth, 1, p->cqa, p->cqa, (PVOID)(ULONG_PTR)CTX_A);
    if (with_rb) p->rb = t->CreateRequestQueue(p->b, depth, 1, depth, 1, p->cqb, p->cqb, (PVOID)(ULONG_PTR)CTX_B);
    p->mem = VirtualAlloc(NULL, 0x20000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p->ra || (with_rb && !p->rb) || !p->mem) return 0;
    p->id = t->RegisterBuffer(p->mem, 0x20000);
    if (p->id == RIO_INVALID_BUFFERID) return 0;
    memcpy(p->mem + PR_TOB, &p->ba, sizeof p->ba);
    memcpy(p->mem + PR_TOA, &p->aa, sizeof p->aa);
    return 1;
}
static int pair_open(PAIR *p, RIO_TABLE *t, ULONG depth) { return pair_open2(p, t, depth, 1); }
static void pair_close(PAIR *p)
{
    RIO_TABLE *t = p->t;
    if (p->a != INVALID_SOCKET) closesocket(p->a);
    if (p->b != INVALID_SOCKET) closesocket(p->b);
    if (p->id && p->id != RIO_INVALID_BUFFERID) t->DeregisterBuffer(p->id);
    if (p->cqa) t->CloseCompletionQueue(p->cqa);
    if (p->cqb) t->CloseCompletionQueue(p->cqb);
    if (p->mem) VirtualFree(p->mem, 0, MEM_RELEASE);
}
#define NEED_PAIR(p, t, depth) PAIR p; RIO_TABLE *t; NEED_NET(); t = rio_tbl(); if (!t) { t_skip("RIO unavailable"); return; } \
    if (!pair_open(&p, t, depth)) { pair_close(&p); t_skip("loopback RIO pair unavailable"); return; }
/* a -> b datagram from the send area. */
static BOOL pair_send(PAIR *p, ULONG off, ULONG len, ULONGLONG ctx, DWORD flags)
{
    RIO_BUF d = {p->id, off, len}, to = {p->id, PR_TOB, sizeof(SOCKADDR_INET)};
    return p->t->SendEx(p->ra, &d, 1, NULL, &to, NULL, NULL, flags, (PVOID)(ULONG_PTR)ctx);
}
static BOOL pair_recv(PAIR *p, ULONG off, ULONG len, ULONGLONG ctx, DWORD flags)
{
    RIO_BUF d = {p->id, off, len};
    return p->t->Receive(p->rb, &d, 1, flags, (PVOID)(ULONG_PTR)ctx);
}
#endif
