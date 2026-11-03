/* x_child_process_inherit / state: calls a child makes on inherited sockets whose state it has never seen (wrong-state
 * negatives answered by the shared endpoint), port ownership while only a child holds a socket, process-local
 * options, and overlapped operations a child leaves outstanding when it exits. */
#include "xc.h"

/* ---------------- wrong-state calls from the child ---------------- */
enum { S_BIND_BOUND, S_CONNECT_CONNECTED, S_LISTEN_CONNECTED, S_ACCEPT_CONNECTED, S_CONNECT_LISTENER, S_RECV_LISTENER,
       S_SEND_LISTENER, S_BIND_LISTENER, S_LISTEN_LISTENER, S_GETPEER_LISTENER, S_SHUTDOWN_LISTENER, S_COUNT };
static const char *s_names[S_COUNT] = { "bind_bound", "connect_connected", "listen_connected", "accept_connected", "connect_listener",
    "recv_listener", "send_listener", "bind_listener", "listen_listener", "getpeername_listener", "shutdown_listener" };
/* Each result byte: 0 success, else the error number minus 10000. Arguments: pipe, connected socket, listener, listener port. */
CHILD(state_table)
{
    HANDLE pipe = (HANDLE)(ULONG_PTR)_strtoui64(argv[1], NULL, 10); SOCKET c = xc_arg_sock(argv, 2), l = xc_arg_sock(argv, 3);
    struct sockaddr_in a = xc_lo(0), t = xc_lo((unsigned short)xc_arg_int(argv, 4)); int al = sizeof a; unsigned char r[S_COUNT]; char b[4]; DWORD n; int k, rc;
    xc_child_up();
    for (k = 0; k < S_COUNT; k++) {
        xc_setwerr(0); rc = 0;
        switch (k) {
        case S_BIND_BOUND:        rc = U(bind)(c, (struct sockaddr *)&a, sizeof a); break;
        case S_CONNECT_CONNECTED: rc = U(connect)(c, (struct sockaddr *)&t, sizeof t); break;
        case S_LISTEN_CONNECTED:  rc = U(listen)(c, 1); break;
        case S_ACCEPT_CONNECTED:  rc = U(accept)(c, NULL, NULL) == INVALID_SOCKET ? -1 : 0; break;
        case S_CONNECT_LISTENER:  rc = U(connect)(l, (struct sockaddr *)&t, sizeof t); break;
        case S_RECV_LISTENER:     rc = U(recv)(l, b, 1, 0) < 0 ? -1 : 0; break;
        case S_SEND_LISTENER:     rc = U(send)(l, "x", 1, 0) < 0 ? -1 : 0; break;
        case S_BIND_LISTENER:     rc = U(bind)(l, (struct sockaddr *)&a, sizeof a); break;
        case S_LISTEN_LISTENER:   rc = U(listen)(l, 2); break;
        case S_GETPEER_LISTENER:  rc = U(getpeername)(l, (struct sockaddr *)&a, &al); break;
        case S_SHUTDOWN_LISTENER: rc = U(shutdown)(l, SD_BOTH); break;
        }
        r[k] = (unsigned char)(rc == 0 ? 0 : xc_e8(xc_werr()));
    }
    WriteFile(pipe, r, sizeof r, &n, NULL);
    return 0;
}
static unsigned char g_st[S_COUNT]; static int g_st_state;
static int run_state(void)
{
    SOCKET c, s, l; struct sockaddr_in la; HANDLE rd, wr, h[3], p; SECURITY_ATTRIBUTES sa; char a[160]; DWORD got = 0;
    if (g_st_state) return g_st_state > 0;
    g_st_state = -1;
    if (!xc_pair(OVLD, &c, &s)) { t_skip("loopback pair unavailable"); return 0; }
    l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return 0; }
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 4096)) { t_skip("pipe"); return 0; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    h[0] = wr; h[1] = H(c); h[2] = H(l);
    p = xc_spawn("state_table", XARGS(a, "%llu %llu %llu %d", (unsigned long long)(ULONG_PTR)wr, xc_u(c), xc_u(l), xc_port_of(&la)), h, 3, NULL);
    CloseHandle(wr);
    CHECK(p != NULL);
    memset(g_st, 0xee, sizeof g_st);
    if (p) { DWORD code = xc_wait(p, XC_CHILD_TIMEOUT); XEQ(code, 0); if (code == 0) ReadFile(rd, g_st, sizeof g_st, &got, NULL); }
    CloseHandle(rd);
    XEQ(got, sizeof g_st);
    xc_close(c); xc_close(s); xc_close(l);
    if (got == sizeof g_st) g_st_state = 1;
    return got == sizeof g_st;
}
#define STATE_TEST(tag, k, want) TEST(state_##tag) { UP(); if (run_state()) XEQ(g_st[k], want); }
STATE_TEST(child_bind_on_bound_socket_einval,          S_BIND_BOUND, 22)
STATE_TEST(child_connect_on_connected_socket_eisconn,  S_CONNECT_CONNECTED, 56)
STATE_TEST(child_listen_on_connected_socket_eisconn,   S_LISTEN_CONNECTED, 56)
STATE_TEST(child_accept_on_connected_socket_einval,    S_ACCEPT_CONNECTED, 22)
STATE_TEST(child_connect_on_listener_einval,           S_CONNECT_LISTENER, 22)
STATE_TEST(child_recv_on_listener_enotconn,            S_RECV_LISTENER, 57)
STATE_TEST(child_send_on_listener_enotconn,            S_SEND_LISTENER, 57)
STATE_TEST(child_bind_on_listener_einval,              S_BIND_LISTENER, 22)
STATE_TEST(child_listen_again_on_listener_succeeds,    S_LISTEN_LISTENER, 0)
STATE_TEST(child_getpeername_on_listener_enotconn,     S_GETPEER_LISTENER, 57)
STATE_TEST(child_shutdown_on_listener_enotconn,        S_SHUTDOWN_LISTENER, 57)

/* ---------------- port ownership ---------------- */
CHILD(hold_forever) { Sleep(XC_CHILD_TIMEOUT); return 0; }
static void port_case(int type)
{
    SOCKET b, x; struct sockaddr_in a; char arg[64]; HANDLE h[1], p; int rc, e, tries;
    UP(); b = type == SOCK_STREAM ? xc_listener(OVLD, &a) : xc_bound(type, OVLD, &a);
    if (b == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(b);
    p = xc_spawn("hold_forever", XARGS(arg, "%llu", xc_u(b)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(b);                                           /* only the child owns the port now */
    x = xc_make(AF_INET, type, OVLD);
    xc_setwerr(0);
    rc = U(bind)(x, (struct sockaddr *)&a, sizeof a); e = xc_werr();
    XEQ(rc, SOCKET_ERROR);
    XEQ(e, WSAEADDRINUSE);
    xc_close(x);
    xc_kill(p);                                            /* the port is released with the last handle */
    for (tries = 0; tries < 20; tries++) {
        x = xc_make(AF_INET, type, OVLD);
        rc = U(bind)(x, (struct sockaddr *)&a, sizeof a);
        xc_close(x);
        if (rc == 0) break;
        Sleep(100);
    }
    XEQ(rc, 0);
}
TEST(port_listener_held_by_child_blocks_bind_until_it_dies) { port_case(SOCK_STREAM); }
TEST(port_datagram_held_by_child_blocks_bind_until_it_dies) { port_case(SOCK_DGRAM); }

/* The receive timeout set in the parent is held with the endpoint: the child reads the same value. */
CHILD(rcvtimeo_view)
{
    SOCKET s = xc_arg_sock(argv, 1); int v = -1, vl = sizeof v;
    xc_child_up();
    if (U(getsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, &vl)) return 2;
    return v == xc_arg_int(argv, 2) ? 0 : 1;
}
TEST(opt_rcvtimeo_set_in_parent_seen_by_child)
{
    SOCKET s; int v = 1234, got = 0, gl = sizeof got; char arg[64]; HANDLE h[1];
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, sizeof v), 0);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&got, &gl), 0);
    XEQ(got, 1234);
    h[0] = H(s);
    XEQ(xc_run("rcvtimeo_view", XARGS(arg, "%llu %d", xc_u(s), v), h, 1), 0);
    xc_close(s);
}

/* ---------------- operations a child leaves outstanding ---------------- */
CHILD(pend_acceptex)
{
    SOCKET l = xc_arg_sock(argv, 1), a; LPFN_ACCEPTEX fn = NULL; GUID g = WSAID_ACCEPTEX; DWORD n = 0, got = 0; char buf[64]; OVERLAPPED ov;
    xc_child_up();
    a = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (U(WSAIoctl)(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL) || !fn) return 1;
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (fn(l, a, buf, 0, 32, 32, &got, &ov) || xc_werr() != ERROR_IO_PENDING) return 2;
    ExitProcess(0);
    return 3;
}
TEST(pending_acceptex_left_by_exiting_child_does_not_take_connection)
{
    SOCKET l, c, s; struct sockaddr_in la; char arg[64], b; HANDLE h[1]; DWORD code;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(l);
    code = xc_run("pend_acceptex", XARGS(arg, "%llu", xc_u(l)), h, 1);
    XEQ(code, 0);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    s = xc_accept(l, XC_WAIT);                             /* the child's cancelled AcceptEx did not consume it */
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) { xc_rcvtimeo(s, XC_WAIT); XEQ(xc_send(c, "z", 1), 1); XEQ(xc_recv_n(s, &b, 1), 1); }
    xc_close(s); xc_close(c); xc_close(l);
}
CHILD(pend_recvfrom)
{
    SOCKET u = xc_arg_sock(argv, 1); WSABUF wb; char buf[8]; DWORD got = 0, fl = 0; WSAOVERLAPPED ov; struct sockaddr_in f; int fl2 = sizeof f;
    xc_child_up();
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = sizeof buf;
    if (U(WSARecvFrom)(u, &wb, 1, &got, &fl, (struct sockaddr *)&f, &fl2, &ov, NULL) == 0 || xc_werr() != WSA_IO_PENDING) return 2;
    ExitProcess(0);
    return 3;
}
TEST(pending_recvfrom_left_by_exiting_child_does_not_take_datagram)
{
    SOCKET u, tx; struct sockaddr_in ua, ta; char arg[64], b[8] = {0}; HANDLE h[1]; DWORD code;
    UP(); u = xc_bound(SOCK_DGRAM, OVLD, &ua); tx = xc_bound(SOCK_DGRAM, PLAIN, &ta);
    if (u == INVALID_SOCKET || tx == INVALID_SOCKET) { t_skip("setup"); return; }
    xc_rcvtimeo(u, XC_WAIT);
    h[0] = H(u);
    code = xc_run("pend_recvfrom", XARGS(arg, "%llu", xc_u(u)), h, 1);
    XEQ(code, 0);
    XEQ(U(sendto)(tx, "after", 5, 0, (struct sockaddr *)&ua, sizeof ua), 5);
    XEQ(U(recv)(u, b, sizeof b, 0), 5);
    CHECK(!memcmp(b, "after", 5));
    xc_close(u); xc_close(tx);
}
