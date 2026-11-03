/* Engine for the x_overlapped_matrix area.
 *
 * One "case" is (operation, completion style, socket created with or without WSA_FLAG_OVERLAPPED, ready or
 * pending, how a pending request is finished).  run_case() builds the sockets, issues the request and renders
 * everything observable about it as a line of "name=value" tokens: the call's return value and error, the
 * OVERLAPPED internal fields, whether the event is signalled, whether (and what) completion packets were queued,
 * what a completion routine received, and what GetOverlappedResult / WSAGetOverlappedResult report afterwards.
 * The tests compare that line with the table in expect.inc, one CHECK per token.
 *
 * ws2_32 and mswsock are never linked: every entry point is resolved with LoadLibrary/GetProcAddress, and the
 * extension functions are obtained with SIO_GET_EXTENSION_FUNCTION_POINTER. Only plain kernel32 services
 * (events, completion ports, files) are used as scaffolding.
 */
#ifndef XOM_H
#define XOM_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef SIO_ADDRESS_LIST_CHANGE
#define SIO_ADDRESS_LIST_CHANGE _WSAIO(IOC_WS2, 23)
#endif
#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#endif
#ifndef FILE_SKIP_SET_EVENT_ON_HANDLE
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

enum { OP_SEND, OP_RECV, OP_SENDTO, OP_RECVFROM, OP_SENDMSG, OP_RECVMSG, OP_ALC, OP_EXT, OP_ALQ,
       OP_ACCEPTEX, OP_CONNECTEX, OP_DISCONNECTEX, OP_TRANSMIT, OP_READFILE, OP_WRITEFILE, OP_READFILEEX, OP_WRITEFILEEX, OP_COUNT };
static const char *const xom_opname[OP_COUNT] = {
    "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg", "ioctl_addrchange", "ioctl_extptr", "ioctl_addrquery",
    "acceptex", "connectex", "disconnectex", "transmitfile", "readfile", "writefile", "readfileex", "writefileex" };

enum { ST_EV, ST_EVLOW, ST_RT, ST_RTPORT, ST_IOCP, ST_IOCPEV, ST_SKIPOK, ST_SKIPOKNUL, ST_SKIPEVT, ST_SKIPEVTNUL,
       ST_SKIPBOTH, ST_COUNT };
static const char *const xom_stname[ST_COUNT] = {
    "event", "event_lowbit_port", "routine", "routine_port", "iocp_noevent", "iocp_event", "skipok_event",
    "skipok_noevent", "skipevt_event", "skipevt_noevent", "skip_both" };

enum { FIN_COMPLETE, FIN_CANCEL, FIN_CLOSE };
static const char *const xom_finname[] = { "done", "cancelex", "close" };

static int xom_has_port(int st) { return st == ST_EVLOW || st >= ST_RTPORT; }
static int xom_is_rt(int st) { return st == ST_RT || st == ST_RTPORT; }
static int xom_has_event(int st) { return st == ST_EV || st == ST_EVLOW || st == ST_IOCPEV || st == ST_SKIPOK || st == ST_SKIPEVT || st == ST_SKIPBOTH; }
static int xom_skipflags(int st)
{
    switch (st) {
    case ST_SKIPOK: case ST_SKIPOKNUL: return FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
    case ST_SKIPEVT: case ST_SKIPEVTNUL: return FILE_SKIP_SET_EVENT_ON_HANDLE;
    case ST_SKIPBOTH: return FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE;
    }
    return 0;
}
/* Does the operation accept a completion routine? */
static int xom_op_has_rt(int op) { return op <= OP_ALQ; }
static int xom_op_fileex(int op) { return op == OP_READFILEEX || op == OP_WRITEFILEEX; }
/* Is the operation TCP? (otherwise UDP, unconnected-socket ioctls, listeners) */
static int xom_op_udp(int op) { return op == OP_SENDTO || op == OP_RECVFROM || op == OP_SENDMSG || op == OP_RECVMSG; }

#define XOM_KEY 0x5151u
#define XOM_NOISE 0xFFFFFFFFu
#define XOM_SENTINEL ((ULONG_PTR)0x5A5A5A5A5A5Aull)

typedef struct {
    SOCKET s, p, l, a;      /* subject, peer, listener, AcceptEx accept socket */
    SOCKET fill[4];         /* ConnectEx backlog fillers */
    HANDLE port, ev, file;
    OVERLAPPED ov;
    WSABUF wb;
    WSAMSG msg;
    struct sockaddr_in sa, pa, la, from;
    int fromlen;
    DWORD n, fl;
    char sbuf[64], rbuf[256], abuf[128], alq[4096];
    void *fp;
    char tmp[MAX_PATH];
    int op, st, sflag, errmode;
} xom_ctx;
static xom_ctx g;

static volatile LONG rt_n;
static DWORD rt_err, rt_cb, rt_fl;
static int rt_ovmatch;
static void CALLBACK xom_rt(DWORD err, DWORD cb, LPWSAOVERLAPPED ov, DWORD fl)
{
    rt_err = err; rt_cb = cb; rt_fl = fl; rt_ovmatch = (ov == (LPWSAOVERLAPPED)&g.ov);
    InterlockedIncrement(&rt_n);
}

static int xom_ws_up(void)
{
    static int st;
    if (!st) { WSADATA d; st = (U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : -1; }
    return st > 0;
}
#define XOM_UP() do { if (!xom_ws_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

static SOCKET xom_sock(int type, DWORD flags) { return U(WSASocketW)(AF_INET, type, 0, NULL, 0, flags); }
static int xom_bind_lo(SOCKET s, struct sockaddr_in *out)
{
    struct sockaddr_in a; int l = sizeof a;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007f;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return 0;
    if (U(getsockname)(s, (struct sockaddr *)&a, &l)) return 0;
    if (out) *out = a;
    return 1;
}
static int xom_readable(SOCKET s, int ms)
{
    fd_set r; struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    FD_ZERO(&r); FD_SET(s, &r);
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
static void *xom_ext(SOCKET s, GUID id)
{
    void *fp = NULL; DWORD got = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &fp, sizeof fp, &got, NULL, NULL)) return NULL;
    return fp;
}

/* ---- observation string ------------------------------------------------ */
static char *xom_out; static size_t xom_cap;
static void T(const char *fmt, ...)
{
    size_t l = strlen(xom_out); va_list a;
    if (l + 2 >= xom_cap) return;
    if (l) xom_out[l++] = ' ';
    va_start(a, fmt); vsnprintf(xom_out + l, xom_cap - l, fmt, a); va_end(a);
}

static void xom_free(void)
{
    if (g.s != INVALID_SOCKET && g.s) U(closesocket)(g.s);
    if (g.p != INVALID_SOCKET && g.p) U(closesocket)(g.p);
    if (g.l != INVALID_SOCKET && g.l) U(closesocket)(g.l);
    if (g.a != INVALID_SOCKET && g.a) U(closesocket)(g.a);
    { int i; for (i = 0; i < 4; i++) if (g.fill[i] && g.fill[i] != INVALID_SOCKET) U(closesocket)(g.fill[i]); }
    if (g.file && g.file != INVALID_HANDLE_VALUE) CloseHandle(g.file);
    if (g.tmp[0]) DeleteFileA(g.tmp);
    if (g.port) CloseHandle(g.port);
    if (g.ev) CloseHandle(g.ev);
    memset(&g, 0, sizeof g);
}

static int xom_tcp_pair(DWORD sflags)
{
    struct sockaddr_in a; int l = sizeof a;
    SOCKET lis = xom_sock(SOCK_STREAM, WSA_FLAG_OVERLAPPED);
    if (lis == INVALID_SOCKET) return 0;
    g.s = xom_sock(SOCK_STREAM, sflags);
    if (g.s == INVALID_SOCKET || !xom_bind_lo(lis, &a) || U(listen)(lis, 4) || U(connect)(g.s, (struct sockaddr *)&a, sizeof a)) { U(closesocket)(lis); return 0; }
    if (!xom_readable(lis, 3000)) { U(closesocket)(lis); return 0; }
    g.p = U(accept)(lis, (struct sockaddr *)&a, &l);
    U(closesocket)(lis);
    return g.p != INVALID_SOCKET;
}
static int xom_udp_pair(DWORD sflags)
{
    g.s = xom_sock(SOCK_DGRAM, sflags);
    g.p = xom_sock(SOCK_DGRAM, WSA_FLAG_OVERLAPPED);
    if (g.s == INVALID_SOCKET || g.p == INVALID_SOCKET) return 0;
    return xom_bind_lo(g.s, &g.sa) && xom_bind_lo(g.p, &g.pa);
}

/* Fill the send path until a further send cannot be accepted immediately. */
static int xom_fill_send(void)
{
    static char blk[65536]; u_long nb = 1; int i, filled = 0;
    U(ioctlsocket)(g.s, FIONBIO, &nb);
    for (i = 0; i < 4096; i++) {
        int r = U(send)(g.s, blk, sizeof blk, 0);
        if (r == SOCKET_ERROR) { filled = (U(WSAGetLastError)() == WSAEWOULDBLOCK); break; }
    }
    nb = 0; U(ioctlsocket)(g.s, FIONBIO, &nb);
    return filled;
}

/* ---- setup ------------------------------------------------------------- */
static int xom_setup(int op, int st, int sflag, int mode)
{
    int ready = (mode == 1), err = (mode == 2);
    DWORD sf = sflag ? WSA_FLAG_OVERLAPPED : 0;
    memset(&g, 0, sizeof g);
    g.s = g.p = g.l = g.a = INVALID_SOCKET;
    g.op = op; g.st = st; g.sflag = sflag; g.errmode = (mode == 2);
    memcpy(g.sbuf, "0123456789abcdef", 16);
    switch (op) {
    case OP_SEND: case OP_WRITEFILE: case OP_RECV: case OP_READFILE: case OP_DISCONNECTEX: case OP_TRANSMIT: case OP_READFILEEX: case OP_WRITEFILEEX:
        if (err) { g.s = xom_sock(SOCK_STREAM, sf); if (g.s == INVALID_SOCKET) return 0; }
        else if (!xom_tcp_pair(sf)) return 0;
        if ((op == OP_RECV || op == OP_READFILE || op == OP_READFILEEX) && ready) {
            if (U(send)(g.p, "hello", 5, 0) != 5 || !xom_readable(g.s, 3000)) return 0;
        }
        if ((op == OP_SEND || op == OP_WRITEFILE || op == OP_WRITEFILEEX) && mode == 0) { if (!xom_fill_send()) return 0; }
        if (op == OP_TRANSMIT) {
            DWORD w, i, blocks = (mode == 0) ? 4096 : 1; char blk[4096];
            t_tmpfile(g.tmp, sizeof g.tmp, "xom_tf.bin");
            g.file = CreateFileA(g.tmp, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (g.file == INVALID_HANDLE_VALUE) return 0;
            memset(blk, 'T', sizeof blk);
            for (i = 0; i < blocks; i++) if (!WriteFile(g.file, blk, sizeof blk, &w, NULL)) return 0;
        }
        if (op == OP_DISCONNECTEX) g.fp = xom_ext(g.s, (GUID)WSAID_DISCONNECTEX);
        if (op == OP_TRANSMIT) g.fp = xom_ext(g.s, (GUID)WSAID_TRANSMITFILE);
        if ((op == OP_DISCONNECTEX || op == OP_TRANSMIT) && !g.fp) return 0;
        break;
    case OP_SENDTO: case OP_RECVFROM: case OP_SENDMSG: case OP_RECVMSG:
        if (!xom_udp_pair(sf)) return 0;
        if (err && (op == OP_RECVFROM || op == OP_RECVMSG)) {   /* an unbound datagram socket cannot receive */
            U(closesocket)(g.s); g.s = xom_sock(SOCK_DGRAM, sf);
            if (g.s == INVALID_SOCKET) return 0;
        }
        if (op == OP_SENDMSG) g.fp = xom_ext(g.s, (GUID)WSAID_WSASENDMSG);
        if (op == OP_RECVMSG) g.fp = xom_ext(g.s, (GUID)WSAID_WSARECVMSG);
        if ((op == OP_SENDMSG || op == OP_RECVMSG) && !g.fp) return 0;
        if ((op == OP_RECVFROM || op == OP_RECVMSG) && ready) {
            if (U(sendto)(g.p, "hello", 5, 0, (struct sockaddr *)&g.sa, sizeof g.sa) != 5 || !xom_readable(g.s, 3000)) return 0;
        }
        break;
    case OP_ALC: case OP_EXT: case OP_ALQ:
        g.s = xom_sock(SOCK_STREAM, sf);
        if (g.s == INVALID_SOCKET) return 0;
        break;
    case OP_ACCEPTEX:
        g.l = xom_sock(SOCK_STREAM, sf);
        g.a = xom_sock(SOCK_STREAM, WSA_FLAG_OVERLAPPED);
        if (g.l == INVALID_SOCKET || g.a == INVALID_SOCKET) return 0;
        if (!xom_bind_lo(g.l, &g.la) || (!err && U(listen)(g.l, 4))) return 0;
        g.s = g.l; g.l = INVALID_SOCKET;
        g.fp = xom_ext(g.s, (GUID)WSAID_ACCEPTEX);
        if (!g.fp) return 0;
        if (ready) {
            g.p = xom_sock(SOCK_STREAM, WSA_FLAG_OVERLAPPED);
            if (g.p == INVALID_SOCKET || U(connect)(g.p, (struct sockaddr *)&g.la, sizeof g.la)) return 0;
        }
        break;
    case OP_CONNECTEX:
        g.l = xom_sock(SOCK_STREAM, WSA_FLAG_OVERLAPPED);
        g.s = xom_sock(SOCK_STREAM, sf);
        if (g.l == INVALID_SOCKET || g.s == INVALID_SOCKET) return 0;
        if (!xom_bind_lo(g.l, &g.la) || U(listen)(g.l, ready ? 4 : 1) || (!err && !xom_bind_lo(g.s, NULL))) return 0;
        if (mode == 0) {   /* exhaust the accept backlog so that the subject connect cannot finish */
            int i; u_long nb = 1;
            for (i = 0; i < 4; i++) {
                g.fill[i] = xom_sock(SOCK_STREAM, WSA_FLAG_OVERLAPPED);
                if (g.fill[i] == INVALID_SOCKET) return 0;
                U(ioctlsocket)(g.fill[i], FIONBIO, &nb);
                U(connect)(g.fill[i], (struct sockaddr *)&g.la, sizeof g.la);
                Sleep(50);
            }
        }
        g.fp = xom_ext(g.s, (GUID)WSAID_CONNECTEX);
        if (!g.fp) return 0;
        break;
    }
    /* completion style */
    if (xom_has_port(st)) {
        g.port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
        if (!g.port) return 0;
        if (CreateIoCompletionPort((HANDLE)g.s, g.port, XOM_KEY, 0) != g.port) return 0;
        if (xom_skipflags(st) && !SetFileCompletionNotificationModes((HANDLE)g.s, (UCHAR)xom_skipflags(st))) return 0;
    }
    g.ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g.ev) return 0;
    return 1;
}

/* ---- issue ------------------------------------------------------------- */
static int xom_issue(void)
{
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr = (xom_is_rt(g.st) && xom_op_has_rt(g.op)) ? xom_rt : NULL;
    LPWSAOVERLAPPED o = (LPWSAOVERLAPPED)&g.ov;
    int ok = 0;
    memset(&g.ov, 0, sizeof g.ov);
    g.ov.InternalHigh = XOM_SENTINEL;
    if (xom_has_event(g.st)) g.ov.hEvent = (g.st == ST_EVLOW) ? (HANDLE)((ULONG_PTR)g.ev | 1) : g.ev;
    g.n = XOM_NOISE; g.fl = 0;
    g.wb.buf = g.sbuf; g.wb.len = 16;
    g.fromlen = sizeof g.from;
    if (g.errmode && (g.op == OP_SENDTO || g.op == OP_SENDMSG)) { static char big[70000]; g.wb.buf = big; g.wb.len = sizeof big; }   /* larger than any datagram */
    SetLastError(0); U(WSASetLastError)(0);
    switch (g.op) {
    case OP_SEND: ok = U(WSASend)(g.s, &g.wb, 1, &g.n, 0, o, cr) == 0; break;
    case OP_RECV: g.wb.buf = g.rbuf; g.wb.len = 64; ok = U(WSARecv)(g.s, &g.wb, 1, &g.n, &g.fl, o, cr) == 0; break;
    case OP_SENDTO: ok = U(WSASendTo)(g.s, &g.wb, 1, &g.n, 0, (struct sockaddr *)&g.pa, sizeof g.pa, o, cr) == 0; break;
    case OP_RECVFROM: g.wb.buf = g.rbuf; g.wb.len = 64;
        ok = U(WSARecvFrom)(g.s, &g.wb, 1, &g.n, &g.fl, (struct sockaddr *)&g.from, &g.fromlen, o, cr) == 0; break;
    case OP_SENDMSG:
        memset(&g.msg, 0, sizeof g.msg);
        g.msg.name = (LPSOCKADDR)&g.pa; g.msg.namelen = sizeof g.pa; g.msg.lpBuffers = &g.wb; g.msg.dwBufferCount = 1;
        ok = ((LPFN_WSASENDMSG)g.fp)(g.s, &g.msg, 0, &g.n, o, cr) == 0; break;
    case OP_RECVMSG:
        memset(&g.msg, 0, sizeof g.msg); g.wb.buf = g.rbuf; g.wb.len = 64;
        g.msg.name = (LPSOCKADDR)&g.from; g.msg.namelen = sizeof g.from; g.msg.lpBuffers = &g.wb; g.msg.dwBufferCount = 1;
        ok = ((LPFN_WSARECVMSG)g.fp)(g.s, &g.msg, &g.n, o, cr) == 0; break;
    case OP_ALC:
        ok = U(WSAIoctl)(g.s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &g.n, o, cr) == 0; break;
    case OP_EXT: {
        GUID id = WSAID_CONNECTEX; static void *out;
        if (g.errmode) id.Data1 ^= 0x55555555;
        ok = U(WSAIoctl)(g.s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &out, sizeof out, &g.n, o, cr) == 0; break; }
    case OP_ALQ:
        ok = U(WSAIoctl)(g.s, SIO_ADDRESS_LIST_QUERY, NULL, 0, g.alq, g.errmode ? 1 : sizeof g.alq, &g.n, o, cr) == 0; break;
    case OP_ACCEPTEX:
        ok = ((LPFN_ACCEPTEX)g.fp)(g.s, g.a, g.abuf, 0, 32, 32, &g.n, &g.ov) != 0; break;
    case OP_CONNECTEX:
        ok = ((LPFN_CONNECTEX)g.fp)(g.s, (struct sockaddr *)&g.la, sizeof g.la, NULL, 0, &g.n, &g.ov) != 0; break;
    case OP_DISCONNECTEX:
        ok = ((LPFN_DISCONNECTEX)g.fp)(g.s, &g.ov, 0, 0) != 0; break;
    case OP_TRANSMIT:
        ok = ((LPFN_TRANSMITFILE)g.fp)(g.s, g.file, 0, 0, &g.ov, NULL, 0) != 0; break;
    case OP_READFILE:
        ok = ReadFile((HANDLE)g.s, g.rbuf, 64, &g.n, &g.ov) != 0; break;
    case OP_WRITEFILE:
        ok = WriteFile((HANDLE)g.s, g.sbuf, 16, &g.n, &g.ov) != 0; break;
    case OP_READFILEEX:
        ok = ReadFileEx((HANDLE)g.s, g.rbuf, 64, &g.ov, (LPOVERLAPPED_COMPLETION_ROUTINE)xom_rt) != 0; break;
    case OP_WRITEFILEEX:
        ok = WriteFileEx((HANDLE)g.s, g.sbuf, 16, &g.ov, (LPOVERLAPPED_COMPLETION_ROUTINE)xom_rt) != 0; break;
    }
    return ok;
}

/* HasOverlappedIoCompleted, except that the *Ex file calls leave Internal at zero while queued. */
static int xom_done(void)
{
    if (xom_op_fileex(g.op)) return g.ov.InternalHigh != XOM_SENTINEL;
    return g.ov.Internal != 0x103;
}

/* ---- observation helpers ----------------------------------------------- */
static void xom_pkt_desc(char *d, size_t cap, BOOL ok, DWORD bytes, ULONG_PTR key, LPOVERLAPPED po, DWORD err)
{
    if (ok) snprintf(d, cap, "ok,b=%lu,k=%d,o=%d", bytes, key == XOM_KEY, po == &g.ov);
    else snprintf(d, cap, "fail%lu,b=%lu,k=%d,o=%d", err, bytes, key == XOM_KEY, po == &g.ov);
}
/* Poll the port; returns number of packets seen (max 4), description of the first in d. */
static int xom_poll_pkts(DWORD ms, char *d, size_t cap)
{
    int cnt = 0;
    d[0] = 0;
    if (!g.port) return 0;
    for (;;) {
        DWORD b = 0, e; ULONG_PTR key = 0; LPOVERLAPPED po = NULL; BOOL ok;
        SetLastError(0);
        ok = GetQueuedCompletionStatus(g.port, &b, &key, &po, cnt ? 0 : ms);
        e = GetLastError();
        if (!po) break;
        if (!cnt) xom_pkt_desc(d, cap, ok, b, key, po, e);
        if (++cnt >= 4) break;
    }
    return cnt;
}
static int xom_ev_set(void) { return g.ev && WaitForSingleObject(g.ev, 0) == WAIT_OBJECT_0; }
static const char *xom_ft(unsigned long long v, char *b, size_t c) { snprintf(b, c, "%llx", v); return b; }

static void xom_obs_fields(const char *tag, int rtwait)
{
    char b1[32], b2[32];
    T("i%s=%s", tag, xom_ft((ULONG)g.ov.Internal, b1, sizeof b1));
    if (g.ov.InternalHigh == XOM_SENTINEL) T("ih%s=untouched", tag);
    else T("ih%s=%s", tag, xom_ft((unsigned long long)g.ov.InternalHigh, b2, sizeof b2));
}

static void xom_rt_fields(void)
{
    if (!xom_is_rt(g.st)) return;
    T("rt=%ld", rt_n);
    if (rt_n) T("rt_err=%lu rt_cb=%lu rt_ov=%d", rt_err, rt_cb, rt_ovmatch);
}

static void xom_gor_fields(void)
{
    DWORD b = XOM_NOISE, fl = XOM_NOISE, e;
    BOOL ok;
    SetLastError(0);
    ok = GetOverlappedResult((HANDLE)g.s, &g.ov, &b, FALSE);
    e = GetLastError();
    if (ok) T("gor=ok,%lu", b); else T("gor=fail%lu,%lu", e, b);
    b = XOM_NOISE; fl = XOM_NOISE;
    U(WSASetLastError)(0);
    ok = U(WSAGetOverlappedResult)(g.s, (LPWSAOVERLAPPED)&g.ov, &b, FALSE, &fl);
    e = U(WSAGetLastError)();
    if (ok) T("wgor=ok,%lu,%lx", b, fl); else T("wgor=fail%lu,%lu,%lx", e, b, fl);
}

/* ---- the case ------------------------------------------------------------ */
static void xom_drive(int op)
{
    DWORD t0 = GetTickCount();
    switch (op) {
    case OP_RECV: case OP_READFILE: case OP_READFILEEX: U(send)(g.p, "hello", 5, 0); break;
    case OP_RECVFROM: case OP_RECVMSG: U(sendto)(g.p, "hello", 5, 0, (struct sockaddr *)&g.sa, sizeof g.sa); break;
    case OP_ACCEPTEX:
        g.p = xom_sock(SOCK_STREAM, WSA_FLAG_OVERLAPPED);
        if (g.p != INVALID_SOCKET) U(connect)(g.p, (struct sockaddr *)&g.la, sizeof g.la);
        break;
    case OP_SEND: case OP_WRITEFILE: case OP_WRITEFILEEX: case OP_TRANSMIT: case OP_DISCONNECTEX:
        while (!xom_done() && GetTickCount() - t0 < 8000) {
            if (xom_readable(g.p, 5)) { static char sink[65536]; U(recv)(g.p, sink, sizeof sink, 0); }
        }
        break;
    }
}

static void run_case(int op, int st, int sflag, int mode, int fin, char *out, size_t cap)
{
    int ready = (mode == 1);
    char pk[96], pk2[96];
    int ok, pending, n;
    xom_out = out; xom_cap = cap; out[0] = 0;
    SleepEx(0, TRUE);   /* let stray routines of an earlier case run before the counters are reset */
    rt_n = 0; rt_err = rt_cb = rt_fl = 0; rt_ovmatch = 0;
    if (!xom_setup(op, st, sflag, mode)) { T("setup=fail"); xom_free(); return; }
    ok = xom_issue();
    {
        int e = U(WSAGetLastError)();
        pending = !ok && (e == ERROR_IO_PENDING);
        if (xom_op_fileex(op) && ok && g.ov.InternalHigh == XOM_SENTINEL) pending = 1;   /* the *Ex file calls report success for a queued request */
        if (ok) T("r=ok"); else T("r=fail%d", e);
    }
    if (ok) { if (g.n == XOM_NOISE) T("n0=unset"); else T("n0=%lu", g.n); }
    if (pending && (ready || mode == 2)) goto wait_phase;   /* completion may already have happened: do not disturb it */
    {
        char b1[32];
        T("i0=%s", xom_ft((ULONG)g.ov.Internal, b1, sizeof b1));
        if (g.ov.InternalHigh == XOM_SENTINEL) T("ih0=untouched"); else T("ih0=%s", xom_ft((unsigned long long)g.ov.InternalHigh, b1, sizeof b1));
    }
    if (!pending) {
        if (g.ev) T("ev0=%d", xom_ev_set());
        if (xom_is_rt(st)) { DWORD r = SleepEx(0, TRUE); T("alert=%d", r == WAIT_IO_COMPLETION); xom_rt_fields(); }
        n = xom_poll_pkts(0, pk, sizeof pk);
        T("pk0=%d", n); if (n) T("pk0d=%s", pk);
        if (!(st == ST_EV || st == ST_RT)) {}
        xom_gor_fields();
        xom_free();
        return;
    }
    /* pending */
    if (g.ev) T("ev0=%d", xom_ev_set());
    n = xom_poll_pkts(0, pk, sizeof pk);
    T("pk0=%d", n);
wait_phase:
    if (fin == FIN_COMPLETE) {
        xom_drive(op);
    } else if (fin == FIN_CANCEL) {
        SetLastError(0);
        if (CancelIoEx((HANDLE)g.s, &g.ov)) T("cx=ok"); else T("cx=fail%lu", GetLastError());
    } else {
        T("cl=%d", U(closesocket)(g.s) == 0);
        g.s = INVALID_SOCKET;
    }
    {
        char first[96];
        int got = 0;
        first[0] = 0;
        if (xom_is_rt(st)) {
            DWORD r = SleepEx(3000, TRUE);
            T("c=%d", r == WAIT_IO_COMPLETION);
        } else if (xom_has_event(st)) {
            T("c=%d", WaitForSingleObject(g.ev, 3000) == WAIT_OBJECT_0);
        } else {
            got = xom_poll_pkts(3000, first, sizeof first);
            T("c=%d", got > 0);
            if (got) T("pkp=%s", first);
        }
        if (g.ev) T("ev1=%d", xom_ev_set());
        xom_obs_fields("1", 0);
        xom_rt_fields();
        n = xom_poll_pkts(40, pk2, sizeof pk2);
        T("pk1=%d", n); if (n) T("pk1d=%s", pk2);
        if (fin != FIN_CLOSE) xom_gor_fields();
    }
    {   /* make sure nothing is left in flight before the buffers go away */
        DWORD t0 = GetTickCount();
        if (g.s != INVALID_SOCKET && !xom_done()) CancelIoEx((HANDLE)g.s, &g.ov);
        while (!xom_done() && GetTickCount() - t0 < 2000) SleepEx(5, TRUE);
    }
    xom_free();
}

/* ---- case validity ------------------------------------------------------- */
/* Which ready values exist for the operation: bit0 = ready (completes inline), bit1 = pending. */
static int xom_mode_mask(int op)
{
    switch (op) {
    case OP_SEND: case OP_RECV: case OP_RECVFROM: case OP_RECVMSG: case OP_ACCEPTEX: case OP_READFILE: case OP_WRITEFILE:
    case OP_READFILEEX: case OP_WRITEFILEEX: case OP_CONNECTEX: return 1 | 2 | 4;
    case OP_DISCONNECTEX: case OP_TRANSMIT: return 2 | 4;
    case OP_ALC: return 1;
    default: return 2 | 4;
    }
}
static int xom_case_valid(int op, int st, int sflag)
{
    if (xom_op_fileex(op)) return (st == ST_RT || st == ST_RTPORT) && (sflag || st == ST_RT);
    if (!xom_op_has_rt(op) && xom_is_rt(st)) return 0;
    if (!sflag && xom_has_port(st)) return 0;   /* plain sockets cannot be associated with a port */
    return 1;
}

/* ---- expected table ---------------------------------------------------- */
#include "xom_types.h"

static const char *xom_lookup(const char *key)
{
    unsigned i;
    for (i = 0; i < xom_table_n; i++) if (!strcmp(xom_table[i].key, key)) return xom_table[i].val;
    return NULL;
}

static int xom_tok(const char **p, char *name, size_t nc, char *val, size_t vc)
{
    const char *s = *p; size_t i = 0;
    while (*s == ' ') s++;
    if (!*s) return 0;
    while (*s && *s != '=' && *s != ' ') { if (i + 1 < nc) name[i++] = *s; s++; }
    name[i] = 0; i = 0;
    if (*s == '=') s++;
    while (*s && *s != ' ') { if (i + 1 < vc) val[i++] = *s; s++; }
    val[i] = 0; *p = s;
    return 1;
}
/* '?' matches anything, 'a|b' is a set of acceptable values. */
static int xom_val_match(const char *want, const char *got)
{
    const char *p = want;
    if (!strcmp(want, "?")) return 1;
    while (*p) {
        const char *q = strchr(p, '|'); size_t l = q ? (size_t)(q - p) : strlen(p);
        if (strlen(got) == l && !strncmp(got, p, l)) return 1;
        if (!q) break;
        p = q + 1;
    }
    return 0;
}

static void xom_compare(const char *key, const char *obs)
{
#ifdef XOM_PROBE
    t_note("OBS %s => %s", key, obs);
#else
    const char *want = xom_lookup(key), *pw, *po;
    char wn[64], wv[128], on[64], ov_[128];
    if (!want) { t_check(0, __FILE__, __LINE__, "table entry present", "no expectation for %s (got: %s)", key, obs); return; }
    pw = want; po = obs;
    for (;;) {
        int a = xom_tok(&pw, wn, sizeof wn, wv, sizeof wv), b = xom_tok(&po, on, sizeof on, ov_, sizeof ov_);
        if (!a && !b) break;
        if (!a || !b || strcmp(wn, on)) {
            t_check(0, __FILE__, __LINE__, "observation shape", "%s: want [%s] got [%s]", key, want, obs);
            break;
        }
        t_check(xom_val_match(wv, ov_), __FILE__, __LINE__, "observation token", "%s: %s want %s got %s", key, wn, wv, ov_);
    }
#endif
}

/* mode: 0 = request left pending, 1 = request that can be satisfied, 2 = request that fails at once. */
static void xom_grid(int op, int mode, int fin, int sflag)
{
    static const char *const mname[3] = { "pend", "ready", "error" };
    int st;
    XOM_UP();
    if (!(xom_mode_mask(op) & (1 << mode))) { t_skip("combination does not exist"); return; }
    if (!sflag && mode != 1) { t_skip("only completable requests are issued on a non-overlapped socket"); return; }
    if (mode != 0 && fin != FIN_COMPLETE) { t_skip("nothing pending to finish"); return; }
    for (st = 0; st < ST_COUNT; st++) {
        char key[128], obs[512];
        if (!xom_case_valid(op, st, sflag)) continue;
        run_case(op, st, sflag, mode, fin, obs, sizeof obs);
        snprintf(key, sizeof key, "%s/%s/%s/%s/%s", xom_opname[op], xom_stname[st], sflag ? "ovl" : "plain", mname[mode], xom_finname[fin]);
        xom_compare(key, obs);
    }
}
#endif
