/* x_child_process_inherit / close: lifetime of a shared endpoint. Which close the peer can see while another
 * process still holds a handle, shutdown issued from either side, what a process leaves behind when it exits or is
 * terminated (graceful close versus reset), pending overlapped receives in a process that exits or in a process whose
 * partner consumes the data, and the effect of WSACleanup in a process that inherited a socket. */
#include "xc.h"

/* ---- child: signal ready, wait for go, send X, then leave by the requested route ---- */
CHILD(hold)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; char g = 0; const char *how = argv[2];
    xc_child_up(); xc_rcvtimeo(s, XC_WAIT);
    STEP(0, xc_send(s, "R", 1) == 1);
    if (!strcmp(how, "hold") || !strcmp(how, "holdclose")) {   /* wait for the go byte, answer, then leave */
        STEP(1, U(recv)(s, &g, 1, 0) == 1 && g == 'G');
        STEP(2, xc_send(s, "X", 1) == 1);
        if (!strcmp(how, "holdclose")) STEP(3, U(closesocket)(s) == 0);
    } else if (!strcmp(how, "close")) {               /* close the child's copy, then idle until told */
        STEP(1, U(closesocket)(s) == 0);
        Sleep(0);
    }
    return (int)fails;
}
static void parent_close_case(const char *how, int want_recv, int want_err)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("hold", XARGS(a, "%llu %s", xc_u(c), how), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    xc_close(c);
    CHECK(!xc_readable(s, 200));                      /* no FIN: the connection is still owned by the child */
    XEQ(xc_send(s, "G", 1), 1);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'X');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_setwerr(0);
    XEQ(U(recv)(s, &b, 1, 0), want_recv);
    if (want_err) XEQ(xc_werr(), want_err);
    xc_close(s);
}
/* The last handle closed by closesocket ends the stream in order; the same handle released by process exit resets it. */
TEST(close_parent_close_keeps_connection_while_child_holds_then_closes) { parent_close_case("holdclose", 0, 0); }
TEST(close_parent_close_keeps_connection_while_child_holds_then_exits)  { parent_close_case("hold", SOCKET_ERROR, WSAECONNRESET); }
TEST(close_child_exit_with_parent_holding_leaves_connection_open)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("hold", XARGS(a, "%llu close", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    CHECK(!xc_readable(s, 200));
    XEQ(xc_send(c, "p", 1), 1);                       /* the parent's handle is untouched */
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'p');
    xc_close(c);
    XEQ(U(recv)(s, &b, 1, 0), 0);
    xc_close(s);
}
TEST(close_last_handle_in_parent_after_child_exit_ends_connection)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("hold", XARGS(a, "%llu close", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    XEQ(U(recv)(s, &b, 1, 0), 0);
    xc_close(s);
}

/* ---- shutdown acts on the shared endpoint ---- */
CHILD(shut_send)
{
    SOCKET s = xc_arg_sock(argv, 1);
    xc_child_up();
    return U(shutdown)(s, SD_SEND) == 0 ? 0 : 1;
}
TEST(close_child_shutdown_send_is_visible_to_parent_handle)
{
    SOCKET c, s; char a[64], b; HANDLE h[1]; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    code = xc_run("shut_send", XARGS(a, "%llu", xc_u(c)), h, 1);
    XEQ(code, 0);
    XEQ(U(recv)(s, &b, 1, 0), 0);                     /* FIN reached the peer while the parent still has a handle */
    XEQ(xc_send(c, "x", 1), SOCKET_ERROR);            /* the parent's own send side is shut down too */
    XEQ(xc_werr(), WSAESHUTDOWN);
    XEQ(xc_send(s, "y", 1), 1);                       /* the other direction is still open */
    XEQ(xc_recv_n(c, &b, 1), 1); XEQ(b, 'y');
    xc_close(c); xc_close(s);
}
CHILD(shut_recv)
{
    SOCKET s = xc_arg_sock(argv, 1);
    xc_child_up();
    return U(shutdown)(s, SD_RECEIVE) == 0 ? 0 : 1;
}
TEST(close_child_shutdown_receive_is_visible_to_parent_handle)
{
    SOCKET c, s; char a[64], b; HANDLE h[1]; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    code = xc_run("shut_recv", XARGS(a, "%llu", xc_u(c)), h, 1);
    XEQ(code, 0);
    xc_setwerr(0);
    XEQ(U(recv)(c, &b, 1, 0), SOCKET_ERROR);          /* the parent's receive side is shut down as well */
    XEQ(xc_werr(), WSAESHUTDOWN);
    XEQ(xc_send(c, "x", 1), 1);                       /* sending is unaffected */
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'x');
    xc_close(c); xc_close(s);
}
TEST(close_parent_shutdown_then_child_send_fails)
{
    SOCKET c, s; char a[64]; HANDLE h[1], p; DWORD code; char b;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(U(shutdown)(c, SD_SEND), 0);
    h[0] = H(c);
    p = xc_spawn("send_after_shutdown", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, WSAESHUTDOWN);
    XEQ(U(recv)(s, &b, 1, 0), 0);
    xc_close(c); xc_close(s);
}
CHILD(send_after_shutdown)
{
    SOCKET s = xc_arg_sock(argv, 1);
    xc_child_up();
    if (xc_send(s, "x", 1) != SOCKET_ERROR) return 0;
    return xc_werr();
}

/* ---- exit routes: unread data, linger, terminate ---- */
CHILD(hold_exit)
{
    SOCKET s = xc_arg_sock(argv, 1); const char *how = argv[2]; char b;
    xc_child_up(); xc_rcvtimeo(s, XC_WAIT);
    if (!strcmp(how, "linger0")) { struct linger l = { 1, 0 }; U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l); }
    xc_send(s, "R", 1);
    if (!strcmp(how, "closeexit")) { U(closesocket)(s); return 0; }
    if (!strcmp(how, "unread") || !strcmp(how, "unread_term")) {
        /* wait for the peer's byte to be queued, but never read it */
        xc_readable(s, XC_WAIT);
    }
    if (!strcmp(how, "wait_term") || !strcmp(how, "unread_term")) { Sleep(XC_CHILD_TIMEOUT); return 99; }
    (void)b;
    return 0;
}
static void exit_route(const char *how, int peer_sends, int want_recv, int want_err)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("hold_exit", XARGS(a, "%llu %s", xc_u(c), how), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(c);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    if (peer_sends) XEQ(xc_send(s, "u", 1), 1);
    if (strstr(how, "term")) {
        if (peer_sends) Sleep(200);                   /* let the byte be queued before the kill */
        xc_kill(p); p = NULL;
    } else {
        code = xc_wait(p, XC_CHILD_TIMEOUT);
        XEQ(code, 0);
    }
    xc_setwerr(0);
    XEQ(U(recv)(s, &b, 1, 0), want_recv);
    if (want_err) XEQ(xc_werr(), want_err);
    xc_close(s);
}
TEST(close_exit_after_closesocket_is_orderly)            { exit_route("closeexit", 0, 0, 0); }
TEST(close_exit_without_closesocket_resets_peer)         { exit_route("quiet", 0, SOCKET_ERROR, WSAECONNRESET); }
TEST(close_terminate_without_closesocket_resets_peer)    { exit_route("wait_term", 0, SOCKET_ERROR, WSAECONNRESET); }
TEST(close_exit_with_unread_data_resets_peer)            { exit_route("unread", 1, SOCKET_ERROR, WSAECONNRESET); }
TEST(close_terminate_with_unread_data_resets_peer)       { exit_route("unread_term", 1, SOCKET_ERROR, WSAECONNRESET); }
TEST(close_exit_with_linger_zero_resets_peer)            { exit_route("linger0", 0, SOCKET_ERROR, WSAECONNRESET); }

/* Once reset, the peer's later calls report the reset too (sticky). */
TEST(close_reset_is_sticky_for_peer_send)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("hold_exit", XARGS(a, "%llu linger0", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(c);
    XEQ(xc_recv_n(s, &b, 1), 1);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);
    XEQ(xc_werr(), WSAECONNRESET);
    XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);
    XEQ(xc_werr(), WSAECONNRESET);
    XEQ(xc_send(s, "z", 1), SOCKET_ERROR);
    t_note("send after reset error class: %s", xc_werr() == WSAECONNRESET ? "WSAECONNRESET" : xc_werr() == WSAECONNABORTED ? "WSAECONNABORTED" : "other");
    xc_close(s);
}

/* ---- pending overlapped receives ---- */
CHILD(pending_recv_exit)
{
    SOCKET s = xc_arg_sock(argv, 1); WSABUF wb; char buf[8]; DWORD got = 0, fl = 0; WSAOVERLAPPED ov; int r;
    xc_child_up();
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL);
    if (r == 0 || xc_werr() != WSA_IO_PENDING) return 2;
    if (xc_send(s, "R", 1) != 1) return 3;
    ExitProcess(0);                                   /* with the receive still outstanding */
    return 4;
}
TEST(close_child_exit_with_pending_recv_resets_peer)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("pending_recv_exit", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(c);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);
    XEQ(xc_werr(), WSAECONNRESET);
    xc_close(s);
}
CHILD(pending_recv_take)
{
    SOCKET s = xc_arg_sock(argv, 1); WSABUF wb; char buf[8] = {0}; DWORD got = 0, fl = 0; WSAOVERLAPPED ov; int r; unsigned fails = 0;
    xc_child_up();
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL);
    STEP(0, r == SOCKET_ERROR && xc_werr() == WSA_IO_PENDING);
    STEP(1, xc_send(s, "R", 1) == 1);
    STEP(2, WaitForSingleObject(ov.hEvent, XC_WAIT) == WAIT_OBJECT_0);
    STEP(3, U(WSAGetOverlappedResult)(s, &ov, &got, FALSE, &fl) && got == 1 && buf[0] == 'A');
    CloseHandle(ov.hEvent);
    return (int)fails;
}
TEST(close_child_pending_recv_takes_peer_data_not_parent)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("pending_recv_take", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    XEQ(xc_send(s, "A", 1), 1);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    CHECK(!xc_readable(c, 0));
    xc_close(c); xc_close(s);
}

/* Pending receive owned by the parent while the child holds the other handle. */
TEST(close_parent_pending_recv_survives_parent_close_while_child_holds)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p; DWORD got = 0, fl = 0, w; WSABUF wb; char buf[8] = {0}; WSAOVERLAPPED ov; int r;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("hold", XARGS(a, "%llu hold", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = sizeof buf;
    r = U(WSARecv)(c, &wb, 1, &got, &fl, &ov, NULL);
    XEQ(r, SOCKET_ERROR); XEQ(xc_werr(), WSA_IO_PENDING);
    xc_close(c);                                      /* the child's handle keeps the endpoint, so nothing is cancelled */
    w = WaitForSingleObject(ov.hEvent, 300);
    XEQ(w, WAIT_TIMEOUT);
    xc_kill(p);                                       /* the endpoint goes away with the last handle */
    w = WaitForSingleObject(ov.hEvent, XC_WAIT);
    XEQ(w, WAIT_OBJECT_0);
    { DWORD x = 0, f2 = 0; BOOL ok = U(WSAGetOverlappedResult)(c, &ov, &x, FALSE, &f2); XEQ(ok, 0); XEQ(xc_werr(), WSAENOTSOCK); }   /* the parent closed its handle: the lookup fails */
    CloseHandle(ov.hEvent);
    xc_close(s);
}

/* ---- WSACleanup in the child ---- */
CHILD(cleanup_then_idle)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; WSADATA d;
    STEP(0, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(1, xc_send(s, "R", 1) == 1);
    STEP(2, U(WSACleanup)() == 0);
    STEP(3, U(WSACleanup)() == SOCKET_ERROR && xc_werr() == WSANOTINITIALISED);
    return (int)fails;
}
TEST(close_child_wsacleanup_aborts_shared_connection)
{
    SOCKET c, s; char a[64], b; HANDLE h[1]; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    code = xc_run("cleanup_then_idle", XARGS(a, "%llu", xc_u(c)), h, 1);
    XEQ(code, 0);
    xc_setwerr(0);
    XEQ(xc_recv_n(s, &b, 1), SOCKET_ERROR);           /* the last cleanup in the child aborts the connection... */
    XEQ(xc_werr(), WSAECONNRESET);
    xc_setwerr(0);
    XEQ(xc_send(c, "p", 1), SOCKET_ERROR);            /* ...even though the parent still holds a handle */
    XEQ(xc_werr(), WSAECONNABORTED);
    xc_close(c); xc_close(s);
}
