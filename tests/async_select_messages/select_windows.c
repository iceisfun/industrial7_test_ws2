/* WSAAsyncSelect and the window that receives the notifications: the same events for every kind of
 * window, a window owned by another thread, messages that wait in the queue of a thread that is not
 * pumping, ordering across sockets, windows destroyed while events are in flight, and repeated
 * select/cancel/destroy cycles. No input is injected; windows are never shown. */
#include "asm.h"

static const int k_kinds[] = { ASM_WIN_MSGONLY, ASM_WIN_POPUP, ASM_WIN_OVERLAP, ASM_WIN_CHILD };
static const char *k_kind_names[] = { "message-only", "popup", "overlapped", "child" };

/* Every window kind gets the same initial FD_WRITE and a later FD_READ with identical layout. */
ATEST(asm_win_every_kind_receives_write_and_read)
{
    size_t i; int tested = 0;
    for (i = 0; i < sizeof k_kinds / sizeof k_kinds[0]; ++i) {
        SOCKET c, v; HWND w = a_win(k_kinds[i]); asm_rec r; LPARAM lp;
        if (!w) { t_note("%s window unavailable", k_kind_names[i]); continue; }
        NEED(a_pair(&c, &v));
        EQ(a_select(v, w, ASM_WM, FD_READ | FD_WRITE), 0);
        CHECKF(a_take(v, ASM_WM, FD_WRITE, 3000, &lp) && lp == FD_WRITE, "%s: write", k_kind_names[i]);
        CHECKF(a_send(c, 2) == 2, "%s: send", k_kind_names[i]);
        CHECKF(a_take(v, ASM_WM, FD_READ, 3000, &lp) && lp == FD_READ, "%s: read", k_kind_names[i]);
        a_close(c); a_close(v);
        a_log_reset();
        ++tested;
    }
    CHECK(tested >= 1);
}

ATEST(asm_win_record_names_target_window)
{
    size_t i;
    for (i = 0; i < sizeof k_kinds / sizeof k_kinds[0]; ++i) {
        SOCKET c, v; HWND w = a_win(k_kinds[i]); asm_rec r;
        if (!w) continue;
        NEED(a_pair(&c, &v));
        EQ(a_select(v, w, ASM_WM, FD_WRITE), 0);
        CHECKF(a_take(v, ASM_WM, FD_WRITE, 3000, NULL), "%s", k_kind_names[i]);
        a_close(c); a_close(v);
        a_log_reset();
    }
}

/* Only the selected window sees the message, even with other windows of the same class alive. */
ATEST(asm_win_other_windows_see_nothing)
{
    SOCKET c, v; HWND w1 = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_MSGONLY), w3 = a_win(ASM_WIN_MSGONLY); asm_rec r;
    NEED(w1 && w2 && w3 && a_pair(&c, &v));
    EQ(a_select(v, w2, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    a_pump(500);
    CHECK(a_find_rec(v, ASM_WM, FD_READ, &r));
    if (a_find_rec(v, ASM_WM, FD_READ, &r)) EQ(r.hwnd, w2);
    EQ(a_total(), 1);
}

/* ---- a window owned by another thread ---------------------------------------------------------- */

ATEST(asm_win_other_thread_receives_on_its_own_thread)
{
    SOCKET c, v; asm_wthread t; asm_rec r; DWORD t0;
    NEED(a_pair(&c, &v));
    NEED(a_wthread_start(&t, ASM_WIN_MSGONLY));
    EQ(a_select(v, t.hwnd, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 2) == 2);
    t0 = GetTickCount();
    while (!a_find_rec(v, ASM_WM, FD_READ, &r) && GetTickCount() - t0 < 5000) Sleep(10);
    CHECK(a_find_rec(v, ASM_WM, FD_READ, &r));
    if (a_find_rec(v, ASM_WM, FD_READ, &r)) { EQ(r.tid, t.tid); EQ(r.hwnd, t.hwnd); CHECK(r.tid != GetCurrentThreadId()); }
    a_wthread_stop(&t);
}

ATEST(asm_win_other_thread_full_exchange)
{
    SOCKET c, v; asm_wthread t; int i;
    NEED(a_pair(&c, &v));
    NEED(a_wthread_start(&t, ASM_WIN_MSGONLY));
    EQ(a_select(v, t.hwnd, ASM_WM, FD_READ | FD_CLOSE), 0);
    for (i = 0; i < 5; ++i) {
        CHECK(a_send(c, 3) == 3);
        CHECKF(a_take(v, ASM_WM, FD_READ, 5000, NULL), "round %d", i);
        EQ(a_recv(v, 8), 3);
    }
    a_close(c);
    CHECK(a_take(v, ASM_WM, FD_CLOSE, 5000, NULL));
    a_wthread_stop(&t);
}

/* The window's thread ends (window destroyed) while the selection is still in place. */
ATEST(asm_win_owner_thread_exit_leaves_socket_usable)
{
    SOCKET c, v; asm_wthread t; char buf[8];
    NEED(a_pair(&c, &v));
    NEED(a_wthread_start(&t, ASM_WIN_MSGONLY));
    EQ(a_select(v, t.hwnd, ASM_WM, FD_READ | FD_CLOSE), 0);
    a_wthread_stop(&t);
    CHECK(a_send(c, 4) == 4);
    a_pump(300);
    EQ(a_total(), 0);
    Sleep(50);
    EQ(a_recv(v, 8), 4);
    CHECK(a_send(v, 2) == 2);
    EQ(U(recv)(c, buf, sizeof buf, 0), 2);
}

ATEST(asm_win_owner_thread_exit_then_reselect_on_main_window)
{
    SOCKET c, v; asm_wthread t; HWND w = a_win(ASM_WIN_MSGONLY);
    NEED(w && a_pair(&c, &v));
    NEED(a_wthread_start(&t, ASM_WIN_MSGONLY));
    EQ(a_select(v, t.hwnd, ASM_WM, FD_READ), 0);
    a_wthread_stop(&t);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_win_two_threads_two_windows_one_socket_pair)
{
    SOCKET c, v; asm_wthread t1, t2;
    NEED(a_pair(&c, &v));
    NEED(a_wthread_start(&t1, ASM_WIN_MSGONLY));
    if (!a_wthread_start(&t2, ASM_WIN_MSGONLY)) { a_wthread_stop(&t1); t_skip("second window thread"); return; }
    EQ(a_select(c, t1.hwnd, ASM_WM, FD_READ), 0);
    EQ(a_select(v, t2.hwnd, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 5000, NULL));
    CHECK(a_send(v, 1) == 1);
    CHECK(a_take(c, ASM_WM, FD_READ, 5000, NULL));
    a_wthread_stop(&t1);
    a_wthread_stop(&t2);
}

/* ---- queued while nobody pumps ---------------------------------------------------------------- */

/* Re-armed events post a new message each time; none is merged with an earlier one still in the queue. */
ATEST(asm_win_unpumped_messages_accumulate)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); MSG m; int i;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    for (i = 0; i < 3; ++i) {
        CHECK(a_send(c, 2) == 2);
        Sleep(150);                                 /* let the notification be posted */
        CHECK(UU(PeekMessageA)(&m, w, ASM_WM, ASM_WM, PM_NOREMOVE));
        EQ(a_recv(v, 8), 2);                        /* re-enable without pumping */
    }
    a_pump(300);
    EQ(a_count(v, ASM_WM), 3);
}

ATEST(asm_win_queued_messages_keep_event_order)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); LONG sr, sc;
    NEED(w && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ | FD_CLOSE), 0);
    CHECK(a_send(c, 2) == 2);
    Sleep(200);
    a_close(c);
    Sleep(200);
    a_pump(300);
    sr = a_seq_of(v, ASM_WM, FD_READ);
    sc = a_seq_of(v, ASM_WM, FD_CLOSE);
    CHECK(sr > 0);
    if (sc > 0) CHECK(sr < sc);
}

/* Notifications from different sockets are posted in the order the events happened. */
ATEST(asm_win_cross_socket_order_follows_events)
{
    enum { N = 6 };
    SOCKET cl[N], sv[N]; HWND w = a_win(ASM_WIN_MSGONLY); int i; LONG prev = 0;
    NEED(w);
    for (i = 0; i < N; ++i) { NEED(a_pair(&cl[i], &sv[i])); EQ(a_select(sv[i], w, ASM_WM, FD_READ), 0); }
    for (i = N - 1; i >= 0; --i) {                    /* trigger in reverse socket order */
        MSG m;
        CHECK(a_send(cl[i], 1) == 1);
        CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
        CHECK(m.wParam == sv[i]);
        UU(PeekMessageA)(&m, w, ASM_WM, ASM_WM, PM_REMOVE);   /* leave the queue for the next trigger */
        UU(DispatchMessageA)(&m);
    }
    for (i = N - 1; i >= 0; --i) {
        LONG s = a_seq_of(sv[i], ASM_WM, FD_READ);
        CHECKF(s > prev, "socket %d delivered out of order", i);
        prev = s;
    }
}

/* ---- destruction races ------------------------------------------------------------------------ */

ATEST(asm_win_destroy_immediately_after_select_cycles)
{
    int i;
    for (i = 0; i < 40; ++i) {
        SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY);
        NEED(w && a_pair(&c, &v));
        EQ(a_select(v, w, ASM_WM, FD_READ | FD_WRITE | FD_CLOSE), 0);
        if (i & 1) CHECK(a_send(c, 1) == 1);
        a_destroy(w);
        a_close(c);
        a_close(v);
    }
    a_drain(200);
}

ATEST(asm_win_destroy_between_trigger_and_pump)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_MSGONLY); MSG m;
    NEED(w && w2 && a_pair(&c, &v));
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_peek_posted(w, ASM_WM, 3000, &m));
    a_destroy(w);                                      /* the posted message dies with the window */
    a_pump(200);
    EQ(a_total(), 0);
    EQ(a_select(v, w2, ASM_WM, FD_READ), 0);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_win_select_cancel_cycles_end_in_selected_state)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int i;
    NEED(w && a_pair(&c, &v));
    for (i = 0; i < 100; ++i) {
        EQ(a_select(v, w, ASM_WM, FD_READ | FD_WRITE), 0);
        EQ(a_select(v, w, 0, 0), 0);
    }
    a_drain(200);
    EQ(a_select(v, w, ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    CHECK(a_take(v, ASM_WM, FD_READ, 3000, NULL));
}

ATEST(asm_win_many_windows_one_socket_last_selection_wins)
{
    enum { N = 12 };
    SOCKET c, v; HWND ws[N]; int i;
    NEED(a_pair(&c, &v));
    for (i = 0; i < N; ++i) { ws[i] = a_win(ASM_WIN_MSGONLY); NEED(ws[i]); }
    for (i = 0; i < N; ++i) EQ(a_select(v, ws[i], ASM_WM, FD_READ), 0);
    CHECK(a_send(c, 1) == 1);
    a_pump(600);
    {
        asm_rec r;
        EQ(a_total(), 1);
        CHECK(a_find_rec(v, ASM_WM, FD_READ, &r));
        if (a_find_rec(v, ASM_WM, FD_READ, &r)) EQ(r.hwnd, ws[N - 1]);
    }
}

ATEST(asm_win_many_sockets_one_window_independent_cancel)
{
    enum { N = 10 };
    SOCKET cl[N], sv[N]; HWND w = a_win(ASM_WIN_MSGONLY); int i, got = 0;
    NEED(w);
    for (i = 0; i < N; ++i) { NEED(a_pair(&cl[i], &sv[i])); EQ(a_select(sv[i], w, ASM_WM, FD_READ), 0); }
    for (i = 0; i < N; i += 2) EQ(a_select(sv[i], w, 0, 0), 0);        /* cancel the even ones */
    a_drain(100);
    for (i = 0; i < N; ++i) CHECK(a_send(cl[i], 1) == 1);
    for (i = 1; i < N; i += 2) got += a_take(sv[i], ASM_WM, FD_READ, 3000, NULL);
    EQ(got, N / 2);
    for (i = 0; i < N; i += 2) EQ(a_count(sv[i], ASM_WM), 0);
}

/* ---- the desktop window --------------------------------------------------------------------- */

ATEST(asm_win_desktop_window_is_accepted_and_cancellable)
{
    SOCKET s = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP); HWND d = UU(GetDesktopWindow)();
    NEED(d);
    EQ(a_select(s, d, ASM_WM, FD_READ), 0);
    EQ(a_select(s, d, 0, 0), 0);
}

ATEST(asm_win_visibility_is_irrelevant)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_POPUP);
    NEED(w && a_pair(&c, &v));
    CHECK(!UU(IsWindowVisible)(w));
    EQ(a_select(v, w, ASM_WM, FD_WRITE), 0);
    CHECK(a_take(v, ASM_WM, FD_WRITE, 3000, NULL));
}

ATEST(asm_win_disabled_window_still_receives)
{
    SOCKET c, v; HWND w = a_win(ASM_WIN_POPUP);
    NEED(w && a_pair(&c, &v));
    UU(EnableWindow)(w, FALSE);
    EQ(a_select(v, w, ASM_WM, FD_WRITE), 0);
    CHECK(a_take(v, ASM_WM, FD_WRITE, 3000, NULL));
}
