/* WSAAsyncSelect notification flow: what is posted for which socket state, the message layout
 * (wParam socket, lParam low word event / high word error), exactly-once delivery until the matching
 * call re-enables the event, the calls that do and do not re-enable, ordering inside one socket, many
 * sockets sharing a window, datagram and IPv6 sockets, and posting versus sending.
 * All traffic is IPv4/IPv6 loopback with kernel-chosen ports. */
#include "asm.h"

#define SETUP(ev) \
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); \
    NEED(w && a_pair(&c, &v)); \
    EQ(a_select(v, w, ASM_WM, (ev)), 0)

#define SOCKFAIL(call, werr) do { \
        int r_; int e_; U(WSASetLastError)(0); r_ = (call); e_ = a_err(); \
        CHECKF(r_ == SOCKET_ERROR, "%s returned %d", #call, r_); \
        CHECKF(e_ == (werr), "%s error %d want %d", #call, e_, (int)(werr)); } while (0)

/* ---- FD_WRITE -------------------------------------------------------------------------------- */

ATEST(asm_ev_write_initial_single_message)
{
    LPARAM lp = 99;
    SETUP(FD_WRITE);
    CHECK(a_take(v, ASM_WM, FD_WRITE, 3000, &lp));
    EQ(lp, FD_WRITE);
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_write_reselect_reposts)
{
    int i;
    SETUP(FD_WRITE);
    for (i = 0; i < 3; ++i) {
        CHECKF(a_take(v, ASM_WM, FD_WRITE, 3000, NULL), "round %d", i);
        EQ(a_quiet(100), 0);
        EQ(a_select(v, w, ASM_WM, FD_WRITE), 0);
    }
    CHECK(a_take(v, ASM_WM, FD_WRITE, 3000, NULL));
}

/* A connected stream socket with every event selected only reports it can be written. */
ATEST(asm_ev_all_events_connected_reports_write_only)
{
    SETUP(FD_ALL_EVENTS);
    CHECK(a_take(v, ASM_WM, FD_WRITE, 3000, NULL));
    EQ(a_quiet(300), 0);
}

ATEST(asm_ev_write_not_posted_without_selection)
{
    SETUP(FD_READ | FD_CLOSE);
    EQ(a_quiet(300), 0);
}

/* The selection state decides: a socket that is not connected has nothing to report. */
ATEST(asm_ev_unconnected_stream_reports_nothing)
{
    SOCKET s = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(s, w, ASM_WM, FD_READ | FD_WRITE | FD_CLOSE | FD_OOB), 0);
    EQ(a_quiet(300), 0);
}

ATEST(asm_ev_bound_unconnected_stream_reports_nothing)
{
    SOCKET s = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP); HWND w = a_win(ASM_WIN_MSGONLY);
    struct sockaddr_in a;
    NEED(w);
    a_loop_addr(&a, 0);
    EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), 0);
    EQ(a_select(s, w, ASM_WM, FD_READ | FD_WRITE | FD_CLOSE), 0);
    EQ(a_quiet(300), 0);
}

/* ---- message layout -------------------------------------------------------------------------- */

ATEST(asm_ev_message_fields_read)
{
    asm_rec r;
    SETUP(FD_READ);
    CHECK(a_send(c, 5) == 5);
    a_pump(300);
    CHECK(a_find_rec(v, ASM_WM, FD_READ, &r));
    if (!a_find_rec(v, ASM_WM, FD_READ, &r)) return;
    EQ(r.hwnd, w);
    EQ(r.wp, v);
    EQ(r.msg, ASM_WM);
    EQ(r.lp, FD_READ);          /* error word zero */
    EQ(r.tid, GetCurrentThreadId());
}

ATEST(asm_ev_message_fields_write)
{
    asm_rec r;
    SETUP(FD_WRITE);
    a_pump(300);
    CHECK(a_find_rec(v, ASM_WM, FD_WRITE, &r));
    if (!a_find_rec(v, ASM_WM, FD_WRITE, &r)) return;
    EQ(r.hwnd, w);
    EQ(r.wp, v);
    EQ(r.lp, FD_WRITE);
}

ATEST(asm_ev_message_fields_close)
{
    asm_rec r;
    SETUP(FD_CLOSE);
    a_close(c);
    a_pump(500);
    CHECK(a_find_rec(v, ASM_WM, FD_CLOSE, &r));
    if (!a_find_rec(v, ASM_WM, FD_CLOSE, &r)) return;
    EQ(r.hwnd, w);
    EQ(r.wp, v);
    EQ(r.lp, FD_CLOSE);        /* graceful close carries no error */
}

ATEST(asm_ev_message_fields_accept)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4), cl = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    HWND w = a_win(ASM_WIN_MSGONLY); asm_rec r;
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
    EQ(U(connect)(cl, (struct sockaddr *)&a, sizeof a), 0);
    a_pump(500);
    CHECK(a_find_rec(l, ASM_WM, FD_ACCEPT, &r));
    if (!a_find_rec(l, ASM_WM, FD_ACCEPT, &r)) return;
    EQ(r.hwnd, w);
    EQ(r.wp, l);
    EQ(r.lp, FD_ACCEPT);
}

ATEST(asm_ev_message_fields_connect)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4), cl = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    HWND w = a_win(ASM_WIN_MSGONLY); asm_rec r;
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(cl, w, ASM_WM, FD_CONNECT), 0);
    SOCKFAIL(U(connect)(cl, (struct sockaddr *)&a, sizeof a), WSAEWOULDBLOCK);
    a_pump(500);
    CHECK(a_find_rec(cl, ASM_WM, FD_CONNECT, &r));
    if (!a_find_rec(cl, ASM_WM, FD_CONNECT, &r)) return;
    EQ(r.hwnd, w);
    EQ(r.wp, cl);
    EQ(r.lp, FD_CONNECT);
}

/* ---- FD_READ re-enabling ----------------------------------------------------------------------- */

ATEST(asm_ev_read_three_arrivals_one_message)
{
    int i;
    SETUP(FD_READ);
    for (i = 0; i < 3; ++i) { CHECK(a_send(c, 2) == 2); a_pump(80); }
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_read_partial_recv_repeats_while_data_remains)
{
    SETUP(FD_READ);
    CHECK(a_send(c, 6) == 6);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_recv(v, 2), 2);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));       /* 4 bytes still queued */
    EQ(a_recv(v, 4), 4);
    EQ(a_quiet(250), 0);                                  /* drained: nothing more */
}

ATEST(asm_ev_read_failed_recv_on_empty_queue_is_silent)
{
    SETUP(FD_READ);
    SOCKFAIL(a_recv(v, 4), WSAEWOULDBLOCK);
    EQ(a_quiet(250), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

/* Only the receive calls re-enable: asking how much is queued does not. */
ATEST(asm_ev_read_fionread_does_not_rearm)
{
    u_long n = 0;
    SETUP(FD_READ);
    CHECK(a_send(c, 4) == 4);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(U(ioctlsocket)(v, FIONREAD, &n), 0);
    EQ(n, 4);
    EQ(a_quiet(250), 0);
    EQ(a_recv(v, 1), 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_ev_read_select_call_does_not_rearm)
{
    fd_set rd; struct timeval tv = {0, 0};
    SETUP(FD_READ);
    CHECK(a_send(c, 4) == 4);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    FD_ZERO(&rd); FD_SET(v, &rd);
    EQ(U(select)(0, &rd, NULL, NULL, &tv), 1);
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_read_getsockopt_does_not_rearm)
{
    int err = 0, len = sizeof err;
    SETUP(FD_READ);
    CHECK(a_send(c, 4) == 4);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(U(getsockopt)(v, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_read_send_does_not_rearm_read)
{
    SETUP(FD_READ);
    CHECK(a_send(c, 4) == 4);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    CHECK(a_send(v, 3) == 3);                             /* local send on the same socket */
    EQ(a_quiet(250), 0);
}

static int read_via(int how, SOCKET s)
{
    char buf[16];
    switch (how) {
    case 0: return U(recv)(s, buf, 2, 0);
    case 1: return U(recvfrom)(s, buf, 2, 0, NULL, NULL);
    case 2: {
        WSABUF b; DWORD got = 0, fl = 0;
        b.buf = buf; b.len = 2;
        return U(WSARecv)(s, &b, 1, &got, &fl, NULL, NULL) == 0 ? (int)got : -1;
    }
    case 3: {
        WSABUF b; DWORD got = 0, fl = 0;
        b.buf = buf; b.len = 2;
        return U(WSARecvFrom)(s, &b, 1, &got, &fl, NULL, NULL, NULL, NULL) == 0 ? (int)got : -1;
    }
    }
    return -1;
}

/* Each receive API named by the contract re-enables FD_READ; two bytes remain so a new message follows. */
ATEST(asm_ev_read_rearmed_by_each_receive_api)
{
    static const char *names[] = { "recv", "recvfrom", "WSARecv", "WSARecvFrom" };
    int how;
    SETUP(FD_READ);
    for (how = 0; how < 4; ++how) {
        CHECKF(a_send(c, 4) == 4, "%s send", names[how]);
        CHECKF(a_take(v, ASM_WM, FD_READ, 3000, NULL), "%s first message", names[how]);
        CHECKF(read_via(how, v) == 2, "%s receive", names[how]);
        CHECKF(a_take(v, ASM_WM, FD_READ, 3000, NULL), "%s re-enabled message", names[how]);
        CHECKF(a_recv(v, 16) == 2, "%s drain", names[how]);
        CHECKF(a_quiet(120) == 0, "%s quiet", names[how]);
    }
}

ATEST(asm_ev_read_select_again_reposts_pending_data)
{
    SETUP(FD_READ);
    CHECK(a_send(c, 4) == 4);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_quiet(200), 0);
}

ATEST(asm_ev_read_existing_data_reported_on_select)
{
    SOCKET cl, sv; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&cl, &sv));
    CHECK(a_send(cl, 9) == 9);
    EQ(a_select(sv, w, ASM_WM, FD_READ), 0);
    CHECK(a_take(sv, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_ev_read_independent_per_socket)
{
    SOCKET c1, v1, c2, v2; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c1, &v1) && a_pair(&c2, &v2));
    EQ(a_select(v1, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v2, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c1, 1) == 1);
    CHECK(a_take(v1, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_quiet_for(v2, ASM_WM, 200), 0);
    CHECK(a_send(c2, 1) == 1);
    CHECK(a_take(v2, ASM_WM, FD_READ, 3000, NULL));
}

/* ---- datagram sockets ------------------------------------------------------------------------- */

ATEST(asm_ev_udp_read_on_arrival)
{
    SOCKET a, b; struct sockaddr_in aa, ba; HWND w = a_win(ASM_WIN_MSGONLY); char buf[32];
    NEED(w && a_udp_pair(&a, &b, &aa, &ba));
    EQ(a_select(b, w, ASM_WM, FD_READ), 0);
    EQ(a_quiet(150), 0);
    EQ(U(sendto)(a, "ping", 4, 0, (struct sockaddr *)&ba, sizeof ba), 4);
    CHECK(a_take(b, ASM_WM, FD_READ, 3000, NULL));
    EQ(U(recvfrom)(b, buf, sizeof buf, 0, NULL, NULL), 4);
    EQ(a_quiet(200), 0);
}

ATEST(asm_ev_udp_second_datagram_rearms_after_first_read)
{
    SOCKET a, b; struct sockaddr_in aa, ba; HWND w = a_win(ASM_WIN_MSGONLY); char buf[32];
    NEED(w && a_udp_pair(&a, &b, &aa, &ba));
    EQ(a_select(b, w, ASM_WM, FD_READ), 0);
    EQ(U(sendto)(a, "one", 3, 0, (struct sockaddr *)&ba, sizeof ba), 3);
    EQ(U(sendto)(a, "two!", 4, 0, (struct sockaddr *)&ba, sizeof ba), 4);
    CHECK(a_take(b, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_quiet(200), 0);                                   /* one message for two datagrams */
    EQ(U(recvfrom)(b, buf, sizeof buf, 0, NULL, NULL), 3);
    CHECK(a_take(b, ASM_WM, FD_READ, 3000, NULL));         /* second datagram is still queued */
    EQ(U(recvfrom)(b, buf, sizeof buf, 0, NULL, NULL), 4);
    EQ(a_quiet(200), 0);
}

ATEST(asm_ev_udp_unbound_socket_reports_nothing_to_read)
{
    SOCKET s = a_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(s, w, ASM_WM, FD_READ | FD_CLOSE), 0);
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_udp_select_after_arrival_reports_read)
{
    SOCKET a, b; struct sockaddr_in aa, ba; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_udp_pair(&a, &b, &aa, &ba));
    EQ(U(sendto)(a, "late", 4, 0, (struct sockaddr *)&ba, sizeof ba), 4);
    a_pump(100);
    EQ(a_select(b, w, ASM_WM, FD_READ), 0);
    CHECK(a_take(b, ASM_WM, FD_READ, 3000, NULL));
}

/* Writability of a bound datagram socket is reported on selection; recorded, not asserted. */
ATEST(asm_ev_udp_write_on_selection_observed)
{
    SOCKET a, b; struct sockaddr_in aa, ba; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_udp_pair(&a, &b, &aa, &ba));
    EQ(a_select(a, w, ASM_WM, FD_WRITE), 0);
    t_note("bound UDP socket FD_WRITE on selection: %s", a_take(a, ASM_WM, FD_WRITE, 1500, NULL) ? "posted" : "not posted");
}

/* ---- listening and connecting sockets ------------------------------------------------------- */

ATEST(asm_ev_listener_unselected_events_stay_quiet)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4), cl = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(l, w, ASM_WM, FD_READ | FD_WRITE | FD_CLOSE | FD_OOB | FD_CONNECT), 0);
    EQ(U(connect)(cl, (struct sockaddr *)&a, sizeof a), 0);
    EQ(a_quiet(300), 0);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);                 /* still pending: reported on selection */
    CHECK(a_take(l, ASM_WM, FD_ACCEPT, 3000, NULL));
}

ATEST(asm_ev_accept_quiet_before_any_connection)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
    EQ(a_quiet(250), 0);
}

static SOCKET accept_via(int how, SOCKET l)
{
    SOCKET s = how == 0 ? U(accept)(l, NULL, NULL) : U(WSAAccept)(l, NULL, NULL, NULL, 0);
    return s;
}

ATEST(asm_ev_accept_rearmed_by_accept_and_wsaaccept)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 8), cl[6]; HWND w = a_win(ASM_WIN_MSGONLY);
    int how, i;
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
    for (how = 0; how < 2; ++how) {
        SOCKET s;
        for (i = 0; i < 2; ++i) {
            cl[how * 2 + i] = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            EQ(U(connect)(cl[how * 2 + i], (struct sockaddr *)&a, sizeof a), 0);
        }
        CHECKF(a_take(l, ASM_WM, FD_ACCEPT, 3000, NULL), "first message, api %d", how);
        EQ(a_quiet(150), 0);                                  /* two pending, one message */
        s = accept_via(how, l);
        CHECKF(s != INVALID_SOCKET, "accept api %d (err %d)", how, a_err());
        CHECKF(a_take(l, ASM_WM, FD_ACCEPT, 3000, NULL), "re-enabled message, api %d", how);
        if (s != INVALID_SOCKET) U(closesocket)(s);
        s = accept_via(how, l);
        if (s != INVALID_SOCKET) U(closesocket)(s);
        CHECKF(a_quiet(150) == 0, "quiet after last accept, api %d", how);
    }
}

ATEST(asm_ev_accept_failed_would_block_is_silent)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
    SOCKFAIL((int)U(accept)(l, NULL, NULL), WSAEWOULDBLOCK);
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_connect_then_write_in_order)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4), cl = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    HWND w = a_win(ASM_WIN_MSGONLY); LONG sc, sw;
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(cl, w, ASM_WM, FD_CONNECT | FD_WRITE), 0);
    SOCKFAIL(U(connect)(cl, (struct sockaddr *)&a, sizeof a), WSAEWOULDBLOCK);
    CHECK(a_quiet(500) >= 2);
    sc = a_seq_of(cl, ASM_WM, FD_CONNECT);
    sw = a_seq_of(cl, ASM_WM, FD_WRITE);
    CHECK(sc > 0 && sw > 0);
    CHECK(sc < sw);
    EQ(a_count(cl, ASM_WM), 2);
}

ATEST(asm_ev_connect_posts_once_per_connect)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4), cl = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && l != INVALID_SOCKET);
    EQ(a_select(cl, w, ASM_WM, FD_CONNECT), 0);
    SOCKFAIL(U(connect)(cl, (struct sockaddr *)&a, sizeof a), WSAEWOULDBLOCK);
    CHECK(a_take(cl, ASM_WM, FD_CONNECT, 3000, NULL));
    EQ(a_quiet(250), 0);
}

ATEST(asm_ev_connect_on_connected_socket_fails_without_message)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); struct sockaddr_in a; int len = sizeof a;
    NEED(w && a_pair(&c, &v));
    EQ(U(getpeername)(c, (struct sockaddr *)&a, &len), 0);
    EQ(a_select(c, w, ASM_WM, FD_CONNECT), 0);
    SOCKFAIL(U(connect)(c, (struct sockaddr *)&a, sizeof a), WSAEISCONN);
    EQ(a_quiet(250), 0);
}

/* ---- FD_CLOSE --------------------------------------------------------------------------------- */

ATEST(asm_ev_close_posted_once)
{
    SETUP(FD_CLOSE | FD_READ);
    a_close(c);
    CHECK(a_take(v, ASM_WM, FD_CLOSE, 3000, NULL));
    EQ(a_recv(v, 8), 0);
    EQ(a_recv(v, 8), 0);
    EQ(a_quiet(300), 0);
}

ATEST(asm_ev_close_no_repeat_after_recv)
{
    SETUP(FD_CLOSE);
    a_close(c);
    CHECK(a_take(v, ASM_WM, FD_CLOSE, 3000, NULL));
    EQ(a_recv(v, 8), 0);
    EQ(a_quiet(300), 0);
}

ATEST(asm_ev_close_after_cancel_is_silent)
{
    SETUP(FD_CLOSE);
    EQ(a_select(v, w, 0, 0), 0);
    a_drain(50);
    a_close(c);
    EQ(a_quiet(300), 0);
}

ATEST(asm_ev_close_read_precedes_close)
{
    LONG sr, sc;
    SETUP(FD_READ | FD_CLOSE);
    CHECK(a_send(c, 5) == 5);
    a_close(c);
    a_pump(600);
    sr = a_seq_of(v, ASM_WM, FD_READ);
    sc = a_seq_of(v, ASM_WM, FD_CLOSE);
    CHECK(sr > 0);
    if (sc > 0) CHECK(sr < sc);
    EQ(a_recv(v, 16), 5);
    CHECK(a_take(v, ASM_WM, FD_CLOSE, 3000, NULL));
    EQ(a_recv(v, 16), 0);
}

/* ---- many sockets, one window -------------------------------------------------------------------- */

ATEST(asm_ev_many_sockets_distinct_wparam)
{
    enum { N = 24 };
    SOCKET cl[N], sv[N]; HWND w = a_win(ASM_WIN_MSGONLY); int i, got = 0;
    NEED(w);
    for (i = 0; i < N; ++i) {
        NEED(a_pair(&cl[i], &sv[i]));
        EQ(a_select(sv[i], w, ASM_WM, FD_READ), 0);
    }
    for (i = 0; i < N; ++i) CHECK(a_send(cl[i], 1) == 1);
    for (i = 0; i < N; ++i) got += a_take(sv[i], ASM_WM, FD_READ, 3000, NULL);
    EQ(got, N);
    EQ(a_quiet(200), 0);
}

ATEST(asm_ev_two_message_ids_on_one_window)
{
    SOCKET c1, v1, c2, v2; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c1, &v1) && a_pair(&c2, &v2));
    EQ(a_select(v1, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v2, w, ASM_WM2, FD_READ), 0);
    CHECK(a_send(c1, 1) == 1);
    CHECK(a_send(c2, 1) == 1);
    CHECK(a_take(v1, ASM_WM, FD_READ, 3000, NULL));
    CHECK(a_take(v2, ASM_WM2, FD_READ, 3000, NULL));
    EQ(a_count(v1, ASM_WM2), 0);
    EQ(a_count(v2, ASM_WM), 0);
}

ATEST(asm_ev_same_socket_value_identifies_socket_not_peer)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(c, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_quiet(200), 0);
    CHECK(a_send(v, 1) == 1);
    CHECK(a_take(c, ASM_WM, FD_READ, 3000, NULL));
}

/* ---- posted, not sent --------------------------------------------------------------------------- */

ATEST(asm_ev_message_is_posted_not_sent)
{
    MSG m;
    SETUP(FD_READ);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
    EQ(a_total(), 0);                          /* the window procedure has not run: nothing dispatched yet */
    EQ(m.hwnd, w);
    EQ(m.message, ASM_WM);
    EQ(m.wParam, v);
    EQ(m.lParam, FD_READ);
    a_pump(50);
    EQ(a_count(v, ASM_WM), 1);
}

ATEST(asm_ev_message_filter_range_excludes_other_ids)
{
    MSG m;
    SETUP(FD_READ);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
    CHECK(!UU(PeekMessageA)(&m, w, ASM_WM2, ASM_WM2, PM_NOREMOVE));
    CHECK(!UU(PeekMessageA)(&m, w, ASM_WM + 1, ASM_WM + 60, PM_NOREMOVE) || ASM_WM2 <= ASM_WM + 60);
    CHECK(UU(PeekMessageA)(&m, w, ASM_WM, ASM_WM, PM_REMOVE));
    CHECK(!UU(PeekMessageA)(&m, w, ASM_WM, ASM_WM, PM_NOREMOVE));
}

ATEST(asm_ev_queue_status_shows_posted_message)
{
    MSG m;
    SETUP(FD_READ);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
    CHECK((HIWORD(UU(GetQueueStatus)(QS_POSTMESSAGE)) & QS_POSTMESSAGE) != 0);
    a_drain(50);
}

ATEST(asm_ev_removed_message_is_not_reposted)
{
    MSG m;
    SETUP(FD_READ);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
    CHECK(UU(PeekMessageA)(&m, w, ASM_WM, ASM_WM, PM_REMOVE));
    EQ(a_quiet(250), 0);
}

/* ---- message numbers -------------------------------------------------------------------------- */

ATEST(asm_ev_message_number_table)
{
    static const UINT ids[] = { WM_USER, WM_USER + 1, WM_USER + 0x1ff, 0x7FFF, WM_APP, WM_APP + 1, 0xBFFE, 0xBFFF, 0xC000, 0xC001, 0xFFFE, 0xFFFF };
    size_t i;
    for (i = 0; i < sizeof ids / sizeof ids[0]; ++i) {
        SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
        NEED(w && a_pair(&c, &v));
        EQ(a_select(v, w, ids[i], FD_WRITE), 0);
        CHECKF(a_take(v, ids[i], FD_WRITE, 3000, NULL), "message 0x%x", ids[i]);
        a_close(c); a_close(v);
        a_destroy(w);
        a_log_reset();
    }
}

ATEST(asm_ev_registered_message_number)
{
    UINT id = UU(RegisterWindowMessageA)("asm_sock_notify_probe");
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && id >= 0xC000 && a_pair(&c, &v));
    EQ(a_select(v, w, id, FD_WRITE), 0);
    CHECK(a_take(v, id, FD_WRITE, 3000, NULL));
}

/* ---- IPv6 -------------------------------------------------------------------------------------- */

ATEST(asm_ev_ipv6_read_and_close)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    if (!a_pair6(&c, &v)) { t_skip("no IPv6 loopback"); return; }
    EQ(a_select(v, w, ASM_WM, FD_READ | FD_CLOSE), 0);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_recv(v, 8), 3);
    a_close(c);
    CHECK(a_take(v, ASM_WM, FD_CLOSE, 3000, NULL));
}

ATEST(asm_ev_ipv6_accept_connect_write)
{
    struct sockaddr_in6 a; SOCKET l, cl; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    l = a_listener6(&a, 4);
    if (l == INVALID_SOCKET) { t_skip("no IPv6 loopback"); return; }
    cl = a_sock(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
    EQ(a_select(cl, w, ASM_WM, FD_CONNECT | FD_WRITE), 0);
    SOCKFAIL(U(connect)(cl, (struct sockaddr *)&a, sizeof a), WSAEWOULDBLOCK);
    CHECK(a_take(cl, ASM_WM, FD_CONNECT, 3000, NULL));
    CHECK(a_take(cl, ASM_WM, FD_WRITE, 3000, NULL));
    CHECK(a_take(l, ASM_WM, FD_ACCEPT, 3000, NULL));
}

/* ---- selecting from another thread ---------------------------------------------------------- */

static DWORD WINAPI select_and_exit(LPVOID p)
{
    struct { SOCKET s; HWND w; int r; } *a = p;
    a->r = U(WSAAsyncSelect)(a->s, a->w, ASM_WM, FD_READ);
    return 0;
}

ATEST(asm_ev_selecting_thread_may_exit)
{
    struct { SOCKET s; HWND w; int r; } arg;
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); HANDLE th;
    NEED(w && a_pair(&c, &v));
    arg.s = v; arg.w = w; arg.r = -2;
    th = CreateThread(NULL, 0, select_and_exit, &arg, 0, NULL);
    NEED(th);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    EQ(arg.r, 0);
    CHECK(a_send(c, 2) == 2);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}
