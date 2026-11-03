/* WSAAsyncSelect argument validation and its immediate side effects: which window handles, event masks
 * and sockets are accepted, the error reported for each rejection and the order in which the checks
 * apply, the forced non-blocking mode, cancellation with an empty event mask, replacing an earlier
 * selection (window, message number, event set, WSAEventSelect), and behaviour before WSAStartup.
 * Message flow itself is measured in select_events.c / select_windows.c. */
#include "asm.h"

#define SOCKFAIL(call, werr) do { \
        int r_; int e_; U(WSASetLastError)(0); r_ = (call); e_ = a_err(); \
        CHECKF(r_ == SOCKET_ERROR, "%s returned %d", #call, r_); \
        CHECKF(e_ == (werr), "%s error %d want %d", #call, e_, (int)(werr)); } while (0)

static SOCKET tcp(void) { return a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP); }

/* ---- accepted and rejected window handles -------------------------------------------------- */

ATEST(asm_sel_accepts_message_only_window)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(s, w, ASM_WM, FD_READ), 0);
}

ATEST(asm_sel_accepts_hidden_toplevel_window)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_POPUP);
    NEED(w);
    EQ(a_select(s, w, ASM_WM, FD_READ), 0);
}

ATEST(asm_sel_accepts_child_window)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_CHILD);
    NEED(w);
    EQ(a_select(s, w, ASM_WM, FD_READ), 0);
}

ATEST(asm_sel_null_window_rejected)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, NULL, ASM_WM, FD_READ), WSAEINVAL);
}

/* Cancelling needs a live window handle too: the handle is validated before the event mask is looked at. */
ATEST(asm_sel_null_window_with_zero_events_rejected)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, NULL, 0, 0), WSAEINVAL);
}

ATEST(asm_sel_small_integer_window_rejected)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, (HWND)(ULONG_PTR)1, ASM_WM, FD_READ), WSAEINVAL);
}

ATEST(asm_sel_stale_window_handle_rejected)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    a_destroy(w);
    SOCKFAIL(a_select(s, w, ASM_WM, FD_READ), WSAEINVAL);
}

ATEST(asm_sel_broadcast_handle_rejected)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, HWND_BROADCAST, ASM_WM, FD_READ), WSAEINVAL);
}

ATEST(asm_sel_message_parent_handle_rejected)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, HWND_MESSAGE, ASM_WM, FD_READ), WSAEINVAL);
}

ATEST(asm_sel_topmost_pseudo_handle_rejected)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, HWND_TOPMOST, ASM_WM, FD_READ), WSAEINVAL);
}

/* ---- event masks ----------------------------------------------------------------------------- */

static const struct { long ev; const char *name; } k_valid_masks[] = {
    { FD_READ, "FD_READ" }, { FD_WRITE, "FD_WRITE" }, { FD_OOB, "FD_OOB" }, { FD_ACCEPT, "FD_ACCEPT" },
    { FD_CONNECT, "FD_CONNECT" }, { FD_CLOSE, "FD_CLOSE" }, { FD_QOS, "FD_QOS" }, { FD_GROUP_QOS, "FD_GROUP_QOS" },
    { FD_ROUTING_INTERFACE_CHANGE, "FD_ROUTING_INTERFACE_CHANGE" }, { FD_ADDRESS_LIST_CHANGE, "FD_ADDRESS_LIST_CHANGE" },
    { FD_ALL_EVENTS, "FD_ALL_EVENTS" }, { FD_READ | FD_WRITE | FD_CLOSE, "READ|WRITE|CLOSE" },
    { FD_ACCEPT | FD_CLOSE, "ACCEPT|CLOSE" }, { FD_CONNECT | FD_WRITE, "CONNECT|WRITE" }, { 0, "none" },
};

/* The accepted event mask is the ten defined FD_* bits (0x3ff); each one alone is valid on a stream socket. */
ATEST(asm_sel_valid_event_masks_table)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    size_t i;
    NEED(w);
    for (i = 0; i < sizeof k_valid_masks / sizeof k_valid_masks[0]; ++i) {
        SOCKET s = tcp();
        int r = a_select(s, w, ASM_WM, k_valid_masks[i].ev);
        CHECKF(r == 0, "mask %s returned %d (err %d)", k_valid_masks[i].name, r, a_err());
        a_close(s);
    }
}

static const long k_bad_masks[] = {
    0x400, 0x800, 0x1000, 0x8000, 0x10000, 0x100000, 0x40000000, (long)0x80000000, -1, 0x3ff | 0x400, FD_READ | 0x2000,
};

ATEST(asm_sel_undefined_event_bits_rejected_table)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    size_t i;
    NEED(w);
    for (i = 0; i < sizeof k_bad_masks / sizeof k_bad_masks[0]; ++i) {
        SOCKET s = tcp();
        int r, e;
        U(WSASetLastError)(0);
        r = a_select(s, w, ASM_WM, k_bad_masks[i]);
        e = a_err();
        CHECKF(r == SOCKET_ERROR && e == WSAEINVAL, "mask 0x%lx returned %d err %d", (unsigned long)k_bad_masks[i], r, e);
        a_close(s);
    }
}

/* A rejected call changes nothing: the socket is still blocking (FIONBIO 0 is accepted). */
ATEST(asm_sel_rejected_mask_leaves_socket_blocking)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_MSGONLY); u_long z = 0;
    NEED(w);
    SOCKFAIL(a_select(s, w, ASM_WM, 0x400), WSAEINVAL);
    EQ(U(ioctlsocket)(s, FIONBIO, &z), 0);
}

ATEST(asm_sel_rejected_window_leaves_socket_blocking)
{
    SOCKET s = tcp(); u_long z = 0;
    SOCKFAIL(a_select(s, NULL, ASM_WM, FD_READ), WSAEINVAL);
    EQ(U(ioctlsocket)(s, FIONBIO, &z), 0);
}

/* ---- sockets ---------------------------------------------------------------------------------- */

ATEST(asm_sel_invalid_socket_value)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    SOCKFAIL(a_select(INVALID_SOCKET, w, ASM_WM, FD_READ), WSAENOTSOCK);
}

ATEST(asm_sel_closed_socket)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    a_close(s);
    SOCKFAIL(a_select(s, w, ASM_WM, FD_READ), WSAENOTSOCK);
}

ATEST(asm_sel_event_handle_is_not_a_socket)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    NEED(w);
    SOCKFAIL(a_select((SOCKET)ev, w, ASM_WM, FD_READ), WSAENOTSOCK);
    CloseHandle(ev);
}

ATEST(asm_sel_socket_checked_before_window)
{
    SOCKFAIL(a_select(INVALID_SOCKET, NULL, ASM_WM, FD_READ), WSAENOTSOCK);
}

ATEST(asm_sel_socket_checked_before_mask)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    SOCKFAIL(a_select(INVALID_SOCKET, w, ASM_WM, -1), WSAENOTSOCK);
}

ATEST(asm_sel_window_and_mask_both_bad_report_invalid)
{
    SOCKET s = tcp();
    SOCKFAIL(a_select(s, NULL, ASM_WM, -1), WSAEINVAL);
}

ATEST(asm_sel_accepts_datagram_socket)
{
    SOCKET s = a_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(s, w, ASM_WM, FD_READ | FD_WRITE | FD_CLOSE), 0);
}

ATEST(asm_sel_accepts_ipv6_stream_socket)
{
    SOCKET s = a_sock(AF_INET6, SOCK_STREAM, IPPROTO_TCP); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    if (s == INVALID_SOCKET) { t_skip("no IPv6 stream sockets"); return; }
    EQ(a_select(s, w, ASM_WM, FD_READ | FD_CLOSE), 0);
}

ATEST(asm_sel_accepts_wsasocket_overlapped_socket)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    SOCKET s;
    NEED(U(WSASocketW) && w);
    s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;
    EQ(a_select(s, w, ASM_WM, FD_READ), 0);
    U(closesocket)(s);
}

ATEST(asm_sel_accepts_listening_socket)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
}

ATEST(asm_sel_repeat_calls_all_succeed)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_MSGONLY); int i;
    NEED(w);
    for (i = 0; i < 20; ++i) EQ(a_select(s, w, ASM_WM, (i & 1) ? FD_READ : FD_READ | FD_CLOSE), 0);
}

/* ---- the socket becomes non-blocking ----------------------------------------------------------- */

ATEST(asm_sel_forces_nonblocking_recv_wouldblock)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int e = 0, r;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    r = a_recv_bounded(v, 16, &e, 2000);
    CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "recv r=%d err=%d", r, e);
}

ATEST(asm_sel_forces_nonblocking_even_with_empty_mask)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int e = 0, r;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, 0, 0), 0);
    r = a_recv_bounded(v, 16, &e, 2000);
    CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "recv r=%d err=%d", r, e);
}

ATEST(asm_sel_blocking_fionbio_refused)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); u_long z = 0;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    SOCKFAIL(U(ioctlsocket)(v, FIONBIO, &z), WSAEINVAL);
}

ATEST(asm_sel_nonblocking_fionbio_one_accepted)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); u_long o = 1;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(U(ioctlsocket)(v, FIONBIO, &o), 0);
}

/* The documented way back to blocking mode: cancel the selection, then clear FIONBIO. */
ATEST(asm_sel_cancel_then_fionbio_zero_succeeds)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); u_long z = 0;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, 0, 0), 0);
    EQ(U(ioctlsocket)(v, FIONBIO, &z), 0);
}

/* Cancelling does not by itself restore blocking mode. */
ATEST(asm_sel_cancel_keeps_socket_nonblocking)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int e = 0, r;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, 0, 0), 0);
    r = a_recv_bounded(v, 16, &e, 2000);
    CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "recv r=%d err=%d", r, e);
}

/* After cancel + FIONBIO 0 the socket really blocks again: data sent from another thread's perspective
 * is simply received; here the data is already queued so recv returns it. */
ATEST(asm_sel_blocking_restored_receives_queued_data)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); u_long z = 0; int e = 0, r;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, 0, 0), 0);
    EQ(U(ioctlsocket)(v, FIONBIO, &z), 0);
    CHECK(a_send(c, 7) == 7);
    r = a_recv_bounded(v, 16, &e, 2000);
    CHECKF(r == 7, "recv r=%d err=%d", r, e);
}

ATEST(asm_sel_recv_wouldblock_then_data_after_send)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    SOCKFAIL(a_recv(v, 8), WSAEWOULDBLOCK);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(a_recv(v, 8), 3);
}

ATEST(asm_sel_accept_on_nonblocking_listener_wouldblock)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(l, w, ASM_WM, FD_ACCEPT), 0);
    U(WSASetLastError)(0);
    CHECK(U(accept)(l, NULL, NULL) == INVALID_SOCKET);
    EQ(a_err(), WSAEWOULDBLOCK);
}

ATEST(asm_sel_connect_becomes_nonblocking)
{
    struct sockaddr_in a; SOCKET l = a_listener(&a, 4), c = tcp(); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(c, w, ASM_WM, FD_CONNECT), 0);
    U(WSASetLastError)(0);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    EQ(a_err(), WSAEWOULDBLOCK);
    CHECK(a_take(c, ASM_WM, FD_CONNECT, 3000, NULL));
}

/* ---- replacing a selection ------------------------------------------------------------------- */

ATEST(asm_sel_reselect_new_window_redirects)
{
    SOCKET c, v; HWND w1 = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_POPUP); asm_rec r;
    NEED(w1 && w2 && a_pair(&c, &v));
    EQ(a_select(v, w1, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w2, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 2) == 2);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    a_pump(100);
    /* the one FD_READ went to the second window only */
    CHECK(a_total() == 0);
    EQ(a_recv(v, 8), 2);
    CHECK(a_send(c, 2) == 2);
    CHECK(a_find_rec(v, ASM_WM, FD_READ, &r) == 0);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_sel_reselect_target_window_is_the_new_one)
{
    SOCKET c, v; HWND w1 = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_POPUP); asm_rec r;
    NEED(w1 && w2 && a_pair(&c, &v));
    EQ(a_select(v, w1, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w2, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL) == 1);
    /* re-run to look at the window recorded for the delivery */
    EQ(a_recv(v, 8), 1);
    CHECK(a_send(c, 1) == 1);
    a_pump(300);
    CHECK(a_find_rec(v, ASM_WM, FD_READ, &r));
    if (a_find_rec(v, ASM_WM, FD_READ, &r)) EQ(r.hwnd, w2);
}

ATEST(asm_sel_reselect_new_message_id_replaces_old)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, ASM_WM2, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM2, FD_READ, 3000, NULL));
    a_pump(100);
    EQ(a_count(v, ASM_WM), 0);
}

ATEST(asm_sel_reselect_event_set_replaces_old)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ | FD_WRITE), 0);
    EQ(a_select(v, w, ASM_WM, FD_WRITE), 0);
    CHECK(a_take(v, ASM_WM, FD_WRITE, 3000, NULL));
    a_drain(50);
    CHECK(a_send(c, 1) == 1);
    EQ(a_quiet_for(v, ASM_WM, 300), 0);
}

ATEST(asm_sel_cancel_stops_new_messages)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, 0, 0), 0);
    a_drain(50);
    CHECK(a_send(c, 4) == 4);
    EQ(a_quiet(300), 0);
}

/* A cancel does not retract a message that was already posted; the application must expect one. */
ATEST(asm_sel_cancel_leaves_already_posted_message)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); MSG m;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 4) == 4);
    CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
    EQ(a_select(v, w, 0, 0), 0);
    CHECK(a_take(v, ASM_WM, FD_READ, 1000, NULL));
}

ATEST(asm_sel_cancel_with_nonzero_message_still_cancels)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(a_select(v, w, ASM_WM, 0), 0);
    a_drain(50);
    CHECK(a_send(c, 4) == 4);
    EQ(a_quiet(300), 0);
}

ATEST(asm_sel_cancel_on_never_selected_socket)
{
    SOCKET s = tcp(); HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w);
    EQ(a_select(s, w, 0, 0), 0);
}

ATEST(asm_sel_reselect_after_cancel_reports_pending_data)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, 0, 0), 0);
    CHECK(a_send(c, 5) == 5);
    a_pump(100);
    EQ(a_total(), 0);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

/* ---- interplay with WSAEventSelect ---------------------------------------------------------- */

ATEST(asm_sel_event_select_replaces_async_select)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); HANDLE ev;
    NEED(U(WSAEventSelect) && U(WSACreateEvent) && w && a_pair(&c, &v));
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(U(WSAEventSelect)(v, ev, FD_READ), 0);
    CHECK(a_send(c, 3) == 3);
    EQ(WaitForSingleObject(ev, 3000), WAIT_OBJECT_0);
    EQ(a_quiet_for(v, ASM_WM, 200), 0);
    CloseHandle(ev);
}

ATEST(asm_sel_async_select_replaces_event_select)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); HANDLE ev;
    NEED(U(WSAEventSelect) && w && a_pair(&c, &v));
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    EQ(U(WSAEventSelect)(v, ev, FD_READ), 0);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 3) == 3);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
    EQ(WaitForSingleObject(ev, 200), WAIT_TIMEOUT);
    CloseHandle(ev);
}

/* Event selection after a window selection takes the socket back: no further messages. */
ATEST(asm_sel_event_select_zero_mask_also_cancels_messages)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); HANDLE ev;
    NEED(U(WSAEventSelect) && w && a_pair(&c, &v));
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    EQ(U(WSAEventSelect)(v, ev, 0), 0);
    a_drain(50);
    CHECK(a_send(c, 3) == 3);
    EQ(a_quiet(300), 0);
    CloseHandle(ev);
}

/* ---- other close paths ------------------------------------------------------------------------ */

ATEST(asm_sel_local_closesocket_posts_nothing)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ | FD_CLOSE), 0);
    a_close(v);
    EQ(a_quiet(300), 0);
}

ATEST(asm_sel_destroyed_window_socket_stays_usable)
{
    SOCKET c, v; HWND w1 = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_MSGONLY);
    NEED(w1 && w2 && a_pair(&c, &v));
    EQ(a_select(v, w1, ASM_WM, FD_READ | FD_CLOSE), 0);
    a_destroy(w1);
    CHECK(a_send(c, 6) == 6);
    a_pump(200);
    EQ(a_total(), 0);
    EQ(a_recv(v, 16), 6);
    EQ(a_select(v, w2, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 2) == 2);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_sel_destroyed_window_with_pending_events_does_not_break_close)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ | FD_WRITE | FD_CLOSE), 0);
    a_destroy(w);
    a_close(c);
    EQ(U(closesocket)(v) , 0);
    /* closed by hand: make the tracker forget it */
    a_close(INVALID_SOCKET);
}

/* ---- before WSAStartup / after WSACleanup -------------------------------------------------- */

static int probe_uninitialised(void)
{
    int r, e;
    HANDLE h;
    U(WSASetLastError)(0);
    r = U(WSAAsyncSelect)(INVALID_SOCKET, NULL, ASM_WM, FD_READ); e = a_err();
    if (r != SOCKET_ERROR || e != WSANOTINITIALISED) return 1;
    U(WSASetLastError)(0);
    r = U(WSACancelAsyncRequest)((HANDLE)(ULONG_PTR)4); e = a_err();
    if (r != SOCKET_ERROR || e != WSANOTINITIALISED) return 2;
    U(WSASetLastError)(0);
    h = U(WSAAsyncGetHostByName)(NULL, ASM_WM, "x", NULL, 0); e = a_err();
    if (h != NULL || e != WSANOTINITIALISED) return 3;
    U(WSASetLastError)(0);
    h = U(WSAAsyncGetProtoByName)(NULL, ASM_WM, "tcp", NULL, 0); e = a_err();
    if (h != NULL || e != WSANOTINITIALISED) return 4;
    U(WSASetLastError)(0);
    h = U(WSAAsyncGetProtoByNumber)(NULL, ASM_WM, 6, NULL, 0); e = a_err();
    if (h != NULL || e != WSANOTINITIALISED) return 5;
    U(WSASetLastError)(0);
    h = U(WSAAsyncGetServByName)(NULL, ASM_WM, "http", NULL, NULL, 0); e = a_err();
    if (h != NULL || e != WSANOTINITIALISED) return 6;
    U(WSASetLastError)(0);
    h = U(WSAAsyncGetServByPort)(NULL, ASM_WM, 80, NULL, NULL, 0); e = a_err();
    if (h != NULL || e != WSANOTINITIALISED) return 7;
    U(WSASetLastError)(0);
    {
        char a[4] = {127, 0, 0, 1};
        h = U(WSAAsyncGetHostByAddr)(NULL, ASM_WM, a, 4, AF_INET, NULL, 0); e = a_err();
        if (h != NULL || e != WSANOTINITIALISED) return 8;
    }
    return 0;
}

/* Fresh process, WSAStartup never called: every entry point of this family reports WSANOTINITIALISED. */
CHILD(asm_uninit_fresh)
{
    return probe_uninitialised();
}

/* Started and cleaned up again: back to the same state. */
CHILD(asm_uninit_after_cleanup)
{
    WSADATA d;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 50;
    if (U(WSACleanup)() != 0) return 51;
    return probe_uninitialised();
}

TEST(asm_uninit_fresh_process_all_entry_points)
{
    NEED(U(WSAAsyncSelect));
    EQ(t_run_child("asm_uninit_fresh", "", 20000), 0);
}

TEST(asm_uninit_after_cleanup_all_entry_points)
{
    NEED(U(WSAAsyncSelect));
    EQ(t_run_child("asm_uninit_after_cleanup", "", 20000), 0);
}
