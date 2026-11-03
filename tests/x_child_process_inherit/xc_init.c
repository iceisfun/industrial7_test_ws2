/* x_child_process_inherit / init: a child process that inherited sockets but has not called WSAStartup. A table of
 * calls is run once before any startup (each must fail with WSANOTINITIALISED, or must keep working when it needs
 * no library state) and once after WSAStartup in the same child (each must work on the inherited handles). The child
 * reports one byte per call through a pipe: 0 for success, otherwise the error number minus 10000. */
#include "xc.h"

enum { OP_SOCKET, OP_WSASOCKET, OP_CLOSE, OP_SEND, OP_RECV, OP_GETSOCKNAME, OP_GETPEERNAME, OP_GETSOCKOPT, OP_SETSOCKOPT,
       OP_IOCTL, OP_SHUTDOWN, OP_SELECT, OP_EVENTSELECT, OP_CREATEEVENT, OP_WSAIOCTL, OP_WSARECV, OP_GETHOSTNAME,
       OP_GETADDRINFO, OP_ENUMPROTO, OP_DUPSOCKET, OP_CLEANUP, OP_LISTEN, OP_BIND, OP_CONNECT, OP_ACCEPT, OP_GETOVERLAPPED,
       OP_GETHOSTBYNAME, OP_GETSERVBYNAME, OP_HTONS, OP_NTOHL, OP_INETADDR, OP_LASTERROR, OP_COUNT };
static const char *op_names[OP_COUNT] = {
    "socket", "WSASocketW", "closesocket", "send", "recv", "getsockname", "getpeername", "getsockopt", "setsockopt",
    "ioctlsocket", "shutdown", "select", "WSAEventSelect", "WSACreateEvent", "WSAIoctl", "WSARecv", "gethostname",
    "getaddrinfo", "WSAEnumProtocolsW", "WSADuplicateSocketW", "WSACleanup", "listen", "bind", "connect", "accept",
    "WSAGetOverlappedResult", "gethostbyname", "getservbyname", "htons", "ntohl", "inet_addr", "WSAGetLastError" };

/* Run one call; returns 0 on success else error-10000 (clamped). s: connected stream, l: listener, u: datagram. */
static unsigned run_op(int op, SOCKET s, SOCKET l, SOCKET u)
{
    struct sockaddr_in a; int al = sizeof a, i = 0, il = sizeof i, r = 0; char buf[8]; u_long v = 0; DWORD n = 0; fd_set f; struct timeval tv = { 0, 0 };
    WSABUF wb; WSAOVERLAPPED ov; DWORD fl = 0; WSAPROTOCOL_INFOW pi; struct addrinfo *res = NULL, hint; DWORD cb = 0; WSAEVENT ev; char hn[256];
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007fu;
    xc_setwerr(0);
    switch (op) {
    case OP_SOCKET: { SOCKET x = U(socket)(AF_INET, SOCK_DGRAM, 0); if (x == INVALID_SOCKET) break; U(closesocket)(x); return 0; }
    case OP_WSASOCKET: { SOCKET x = U(WSASocketW)(AF_INET, SOCK_DGRAM, 0, NULL, 0, OVLD); if (x == INVALID_SOCKET) break; U(closesocket)(x); return 0; }
    case OP_CLOSE: if (U(closesocket)(s) == 0) return 0; break;
    case OP_SEND: if (U(send)(s, "q", 1, 0) == 1) return 0; break;
    case OP_RECV: if (U(recv)(s, buf, 1, MSG_PEEK) >= 0) return 0; break;
    case OP_GETSOCKNAME: if (U(getsockname)(s, (struct sockaddr *)&a, &al) == 0) return 0; break;
    case OP_GETPEERNAME: if (U(getpeername)(s, (struct sockaddr *)&a, &al) == 0) return 0; break;
    case OP_GETSOCKOPT: if (U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&i, &il) == 0) return 0; break;
    case OP_SETSOCKOPT: i = 1; if (U(setsockopt)(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&i, sizeof i) == 0) return 0; break;
    case OP_IOCTL: if (U(ioctlsocket)(s, FIONREAD, &v) == 0) return 0; break;
    case OP_SHUTDOWN: if (U(shutdown)(s, SD_BOTH) == 0) return 0; break;
    case OP_SELECT: f.fd_count = 1; f.fd_array[0] = s; if (U(select)(0, &f, NULL, NULL, &tv) >= 0) return 0; break;
    case OP_EVENTSELECT: ev = CreateEventA(NULL, FALSE, FALSE, NULL); r = U(WSAEventSelect)(s, ev, 0); CloseHandle(ev); if (r == 0) return 0; break;
    case OP_CREATEEVENT: ev = U(WSACreateEvent)(); if (ev != WSA_INVALID_EVENT) { CloseHandle(ev); return 0; } break;
    case OP_WSAIOCTL: if (U(WSAIoctl)(s, FIONREAD, NULL, 0, &v, sizeof v, &n, NULL, NULL) == 0) return 0; break;
    case OP_WSARECV: memset(&ov, 0, sizeof ov); wb.buf = buf; wb.len = 1; fl = MSG_PEEK; if (U(WSARecv)(s, &wb, 1, &n, &fl, NULL, NULL) == 0) return 0; break;
    case OP_GETHOSTNAME: if (U(gethostname)(hn, sizeof hn) == 0) return 0; break;
    case OP_GETADDRINFO: memset(&hint, 0, sizeof hint); hint.ai_flags = AI_NUMERICHOST; hint.ai_family = AF_INET; if (U(getaddrinfo)("127.0.0.1", NULL, &hint, &res) == 0) { U(freeaddrinfo)(res); return 0; } r = U(getaddrinfo)("127.0.0.1", NULL, &hint, &res); xc_setwerr(r); break;
    case OP_ENUMPROTO: cb = 0; U(WSAEnumProtocolsW)(NULL, NULL, &cb); if (xc_werr() == WSAENOBUFS) return 0; break;
    case OP_DUPSOCKET: if (U(WSADuplicateSocketW)(s, GetCurrentProcessId(), &pi) == 0) return 0; break;
    case OP_CLEANUP: if (U(WSACleanup)() == 0) return 0; break;
    case OP_LISTEN: if (U(listen)(u, 1) == 0) return 0; break;
    case OP_BIND: if (U(bind)(u, (struct sockaddr *)&a, sizeof a) == 0) return 0; break;
    case OP_CONNECT: if (U(connect)(u, (struct sockaddr *)&a, sizeof a) == 0) return 0; break;
    case OP_ACCEPT: { SOCKET x = U(accept)(l, NULL, NULL); if (x != INVALID_SOCKET) { U(closesocket)(x); return 0; } break; }
    case OP_GETOVERLAPPED: memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, TRUE, NULL); if (U(WSAGetOverlappedResult)(s, &ov, &n, FALSE, &fl)) { CloseHandle(ov.hEvent); return 0; } CloseHandle(ov.hEvent); break;
    case OP_GETHOSTBYNAME: if (U(gethostbyname)("localhost") != NULL) return 0; break;
    case OP_GETSERVBYNAME: if (U(getservbyname)("http", "tcp") != NULL) return 0; break;
    case OP_HTONS: return U(htons)(0x1234) == 0x3412 ? 0 : 1;
    case OP_NTOHL: return U(ntohl)(0x01020304u) == 0x04030201u ? 0 : 1;
    case OP_INETADDR: return U(inet_addr)("127.0.0.1") == 0x0100007fu ? 0 : 1;
    case OP_LASTERROR: SetLastError(1234); return U(WSAGetLastError)() == 1234 ? 0 : 1;
    }
    return xc_e8(xc_werr());
}
/* Ops that only observe and are safe to repeat after startup (no consumption of data, no state change). */
static int op_safe_after(int op)
{
    switch (op) { case OP_CLOSE: case OP_SHUTDOWN: case OP_CLEANUP: case OP_ACCEPT: case OP_LISTEN: case OP_BIND: case OP_CONNECT: case OP_SEND: return 0; }
    return 1;
}
CHILD(nostart_matrix)
{
    HANDLE pipe = (HANDLE)(ULONG_PTR)_strtoui64(argv[1], NULL, 10); SOCKET s = xc_arg_sock(argv, 2), l = xc_arg_sock(argv, 3), u = xc_arg_sock(argv, 4);
    unsigned char res[2 * OP_COUNT]; DWORD n; int op;
    memset(res, 0xee, sizeof res);
    for (op = 0; op < OP_COUNT; op++) res[op] = (unsigned char)run_op(op, s, l, u);
    xc_child_up();
    for (op = 0; op < OP_COUNT; op++) res[OP_COUNT + op] = op_safe_after(op) ? (unsigned char)run_op(op, s, l, u) : 0xee;
    WriteFile(pipe, res, sizeof res, &n, NULL);
    return 0;
}
static unsigned char g_res[2 * OP_COUNT];
static int g_matrix_state;   /* 0 not run, 1 results valid, -1 failed once (not repeated) */
static int run_matrix(void)
{
    if (g_matrix_state) return g_matrix_state > 0;
    g_matrix_state = -1;
    SOCKET c, srv, l, u; HANDLE rd, wr, list[4], p; SECURITY_ATTRIBUTES sa; char a[160]; DWORD n = 0, got = 0; unsigned char *dst = g_res;
    if (!xc_pair(OVLD, &c, &srv)) { t_skip("loopback pair unavailable"); return 0; }
    l = xc_listener(OVLD, NULL); u = xc_bound(SOCK_DGRAM, OVLD, NULL);
    if (l == INVALID_SOCKET || u == INVALID_SOCKET) { t_skip("setup"); return 0; }
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 4096)) { t_skip("pipe"); return 0; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    XEQ(xc_send(srv, "d", 1), 1);                    /* one byte for the peeking calls */
    list[0] = wr; list[1] = H(c); list[2] = H(l); list[3] = H(u);
    p = xc_spawn("nostart_matrix", XARGS(a, "%llu %llu %llu %llu", (unsigned long long)(ULONG_PTR)wr, xc_u(c), xc_u(l), xc_u(u)), list, 4, NULL);
    CloseHandle(wr);
    CHECK(p != NULL);
    memset(g_res, 0xee, sizeof g_res);
    if (p) {
        DWORD code = xc_wait(p, XC_CHILD_TIMEOUT);     /* the results sit in the pipe buffer until read */
        XEQ(code, 0);
        if (code == 0) ReadFile(rd, g_res, sizeof g_res, &got, NULL);
    }
    CloseHandle(rd);
    XEQ(got, sizeof g_res);
    xc_close(c); xc_close(srv); xc_close(l); xc_close(u);
    if (got == sizeof g_res) g_matrix_state = 1;
    return got == sizeof g_res;
}
#define WNI 93   /* WSANOTINITIALISED - 10000 */
/* Calls that need library state fail without startup; one test per call so a failure names the call. */
#define NOSTART_TEST(opn, tag) \
    TEST(init_nostart_##tag) { UP(); if (run_matrix()) { XEQ(g_res[opn], WNI); } }
NOSTART_TEST(OP_SOCKET, socket)
NOSTART_TEST(OP_WSASOCKET, wsasocketw)
NOSTART_TEST(OP_CLOSE, closesocket_inherited)
NOSTART_TEST(OP_SEND, send_inherited)
NOSTART_TEST(OP_RECV, recv_inherited)
NOSTART_TEST(OP_GETSOCKNAME, getsockname_inherited)
NOSTART_TEST(OP_GETPEERNAME, getpeername_inherited)
NOSTART_TEST(OP_GETSOCKOPT, getsockopt_inherited)
NOSTART_TEST(OP_SETSOCKOPT, setsockopt_inherited)
NOSTART_TEST(OP_IOCTL, ioctlsocket_inherited)
NOSTART_TEST(OP_SELECT, select_inherited)
NOSTART_TEST(OP_EVENTSELECT, wsaeventselect_inherited)
NOSTART_TEST(OP_WSAIOCTL, wsaioctl_inherited)
NOSTART_TEST(OP_WSARECV, wsarecv_inherited)
NOSTART_TEST(OP_GETHOSTNAME, gethostname)
NOSTART_TEST(OP_GETADDRINFO, getaddrinfo)
NOSTART_TEST(OP_ENUMPROTO, wsaenumprotocols)
NOSTART_TEST(OP_DUPSOCKET, wsaduplicatesocket)
NOSTART_TEST(OP_CLEANUP, wsacleanup)
NOSTART_TEST(OP_LISTEN, listen_inherited)
NOSTART_TEST(OP_BIND, bind_inherited)
NOSTART_TEST(OP_CONNECT, connect_inherited)
NOSTART_TEST(OP_ACCEPT, accept_inherited)
NOSTART_TEST(OP_GETOVERLAPPED, wsagetoverlappedresult)
NOSTART_TEST(OP_GETHOSTBYNAME, gethostbyname)
NOSTART_TEST(OP_GETSERVBYNAME, getservbyname)
NOSTART_TEST(OP_SHUTDOWN, shutdown_inherited)
/* Pure functions need no startup. */
TEST(init_nostart_pure_functions_work)
{
    UP();
    if (run_matrix()) {
        XEQ(g_res[OP_CREATEEVENT], 0); XEQ(g_res[OP_HTONS], 0); XEQ(g_res[OP_NTOHL], 0); XEQ(g_res[OP_INETADDR], 0); XEQ(g_res[OP_LASTERROR], 0);
    }
}
/* Once started, the same inherited handles work in that child. */
#define AFTER_TEST(opn, tag) \
    TEST(init_started_##tag) { UP(); if (run_matrix()) { XEQ(g_res[OP_COUNT + opn], 0); } }
AFTER_TEST(OP_SOCKET, socket)
AFTER_TEST(OP_WSASOCKET, wsasocketw)
AFTER_TEST(OP_RECV, recv_inherited)
AFTER_TEST(OP_GETSOCKNAME, getsockname_inherited)
AFTER_TEST(OP_GETPEERNAME, getpeername_inherited)
AFTER_TEST(OP_GETSOCKOPT, getsockopt_inherited)
AFTER_TEST(OP_SETSOCKOPT, setsockopt_inherited)
AFTER_TEST(OP_IOCTL, ioctlsocket_inherited)
AFTER_TEST(OP_SELECT, select_inherited)
AFTER_TEST(OP_EVENTSELECT, wsaeventselect_inherited)
AFTER_TEST(OP_CREATEEVENT, wsacreateevent)
AFTER_TEST(OP_WSAIOCTL, wsaioctl_inherited)
AFTER_TEST(OP_GETHOSTNAME, gethostname)
AFTER_TEST(OP_GETADDRINFO, getaddrinfo)
AFTER_TEST(OP_ENUMPROTO, wsaenumprotocols)
AFTER_TEST(OP_DUPSOCKET, wsaduplicatesocket)
AFTER_TEST(OP_GETOVERLAPPED, wsagetoverlappedresult)

/* Child WSAStartup/WSACleanup pairing is per process: a child's extra cleanup fails, the parent keeps working. */
CHILD(startup_pairs)
{
    WSADATA d; unsigned fails = 0;
    STEP(0, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0 && d.wVersion == MAKEWORD(2, 2));
    STEP(1, U(WSAStartup)(MAKEWORD(1, 1), &d) == 0 && d.wVersion == MAKEWORD(1, 1));
    STEP(2, U(WSACleanup)() == 0);
    STEP(3, U(WSACleanup)() == 0);
    STEP(4, U(WSACleanup)() == SOCKET_ERROR && xc_werr() == WSANOTINITIALISED);
    return (int)fails;
}
TEST(init_child_startup_cleanup_pairs_are_per_process)
{
    SOCKET c, s; char b;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(xc_run("startup_pairs", "", NULL, 0), 0);
    XEQ(xc_send(c, "x", 1), 1);                       /* the parent's startup is untouched */
    XEQ(xc_recv_n(s, &b, 1), 1);
    xc_close(c); xc_close(s);
}
