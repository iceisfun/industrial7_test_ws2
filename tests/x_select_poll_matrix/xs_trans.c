/* State transitions on one socket: every step is followed by a snapshot through select, WSAPoll and the
 * AFD poll request (rows keyed by test name and step), plus edge-versus-level checks for the event
 * based interfaces. */
#include "xs.h"

static int build(const char *name, xs_st *st)
{
    int i;
    memset(st, 0, sizeof(*st));
    st->s = st->peer = st->lst = st->aux = INVALID_SOCKET;
    for (i = 0; i < xs_nstates; i++) if (!strcmp(xs_states[i].name, name)) return xs_states[i].build(st);
    return 0;
}
#define NEED(st, name) xs_st st; \
    if (!xs_init()) { t_skip("winsock, poll or ntdll entry points missing"); return; } \
    if (!build(name, &st)) { xs_teardown(&st); t_skip("could not reach state " name); return; }
#define SNAP(grp, step, sock) do { char b_[512]; xs_snap(sock, b_, sizeof(b_)); xs_row_check(grp, step, b_); } while (0)
#define VAL(grp, step, ...) do { char b_[256]; snprintf(b_, sizeof(b_), __VA_ARGS__); xs_row_check(grp, step, b_); } while (0)

static int rd(SOCKET s, int n, int flags) { char b[256]; int r; xs_nb(s, 1); r = U(recv)(s, b, n, flags); return r < 0 ? -xs_err() : r; }

TEST(tr_data_cycle)
{
    NEED(st, "tcp_conn_client");
    SNAP("tr_data_cycle", "idle", st.s);
    xs_send_n(st.peer, 5, 0); xs_wait(st.s, 'r', 3000);
    SNAP("tr_data_cycle", "sent5", st.s);
    VAL("tr_data_cycle", "recv2", "%d", rd(st.s, 2, 0));
    SNAP("tr_data_cycle", "after_recv2", st.s);
    VAL("tr_data_cycle", "recv_rest", "%d", rd(st.s, 100, 0));
    SNAP("tr_data_cycle", "after_rest", st.s);
    VAL("tr_data_cycle", "recv_empty", "%d", rd(st.s, 100, 0));
    xs_send_n(st.peer, 1, 0); xs_wait(st.s, 'r', 3000);
    SNAP("tr_data_cycle", "sent1_more", st.s);
    SNAP("tr_data_cycle", "peer_side", st.peer);
    xs_teardown(&st);
}

TEST(tr_peek_does_not_consume)
{
    NEED(st, "tcp_data_client");
    VAL("tr_peek", "peek", "%d", rd(st.s, 100, MSG_PEEK));
    SNAP("tr_peek", "after_peek", st.s);
    VAL("tr_peek", "recv", "%d", rd(st.s, 100, 0));
    SNAP("tr_peek", "after_recv", st.s);
    xs_teardown(&st);
}

TEST(tr_fin_cycle)
{
    NEED(st, "tcp_conn_client");
    SNAP("tr_fin_cycle", "idle", st.s);
    U(shutdown)(st.peer, SD_SEND); xs_wait(st.s, 'r', 3000);
    SNAP("tr_fin_cycle", "peer_fin", st.s);
    VAL("tr_fin_cycle", "recv", "%d", rd(st.s, 10, 0));
    SNAP("tr_fin_cycle", "after_zero_read", st.s);
    VAL("tr_fin_cycle", "recv_again", "%d", rd(st.s, 10, 0));
    U(shutdown)(st.s, SD_SEND); xs_wait(st.peer, 'r', 3000);
    SNAP("tr_fin_cycle", "local_fin_too", st.s);
    SNAP("tr_fin_cycle", "peer_side", st.peer);
    xs_teardown(&st);
}

TEST(tr_fin_then_close_local)
{
    NEED(st, "tcp_peer_fin");
    VAL("tr_fin_close", "send_after_peer_fin", "%d", xs_send_n(st.s, 3, 0));
    xs_settle(100);
    SNAP("tr_fin_close", "after_send", st.s);
    SNAP("tr_fin_close", "peer_side", st.peer);
    xs_teardown(&st);
}

TEST(tr_listener_cycle)
{
    NEED(st, "tcp_listen_pending");
    {
        struct sockaddr_in a; int l = sizeof(a); SOCKET c2, a1, a2;
        SNAP("tr_listener", "one_queued", st.s);
        U(getsockname)(st.s, (struct sockaddr *)&a, &l);
        c2 = xs_sock(AF_INET, SOCK_STREAM);
        VAL("tr_listener", "second_connect", "%d", U(connect)(c2, (struct sockaddr *)&a, l));
        SNAP("tr_listener", "two_queued", st.s);
        a1 = U(accept)(st.s, NULL, NULL);
        xs_wait(st.s, 'r', 1000);   /* the remaining queued connection becomes visible again; bounded */
        SNAP("tr_listener", "after_accept1", st.s);
        a2 = U(accept)(st.s, NULL, NULL);
        SNAP("tr_listener", "after_accept2", st.s);
        SNAP("tr_listener", "accepted_socket", a1);
        xs_close(a1); xs_close(a2); xs_close(c2);
    }
    xs_teardown(&st);
}

TEST(tr_listener_nonblocking_accept_empty)
{
    NEED(st, "tcp_listen_idle");
    xs_nb(st.s, 1);
    VAL("tr_listener_empty", "accept", "%d", U(accept)(st.s, NULL, NULL) == INVALID_SOCKET ? xs_err() : 0);
    SNAP("tr_listener_empty", "after", st.s);
    xs_teardown(&st);
}

TEST(tr_oob_cycle)
{
    NEED(st, "tcp_conn_client");
    char b[8];
    xs_send_n(st.peer, 4, 0); xs_send_n(st.peer, 1, MSG_OOB); xs_wait(st.s, 'x', 3000);
    SNAP("tr_oob_cycle", "data_and_oob", st.s);
    {
        u_long at = 7; U(ioctlsocket)(st.s, SIOCATMARK, &at);
        VAL("tr_oob_cycle", "atmark_before", "%lu", at);
    }
    VAL("tr_oob_cycle", "recv_normal", "%d", rd(st.s, 100, 0));
    SNAP("tr_oob_cycle", "after_normal", st.s);
    VAL("tr_oob_cycle", "recv_oob", "%d", rd(st.s, 100, MSG_OOB));
    SNAP("tr_oob_cycle", "after_oob", st.s);
    VAL("tr_oob_cycle", "recv_oob_again", "%d", rd(st.s, 100, MSG_OOB));
    (void)b;
    xs_teardown(&st);
}

TEST(tr_oob_inline_cycle)
{
    NEED(st, "tcp_oob_inline");
    u_long at = 7;
    SNAP("tr_oob_inline", "pending", st.s);
    U(ioctlsocket)(st.s, SIOCATMARK, &at);
    VAL("tr_oob_inline", "atmark", "%lu", at);
    VAL("tr_oob_inline", "recv_oob_flag", "%d", rd(st.s, 100, MSG_OOB));
    VAL("tr_oob_inline", "recv_plain", "%d", rd(st.s, 100, 0));
    SNAP("tr_oob_inline", "after", st.s);
    xs_teardown(&st);
}

TEST(tr_send_buffer_cycle)
{
    NEED(st, "tcp_send_buffer_full");
    DWORD t0 = GetTickCount(); int w;
    xs_nb(st.peer, 1);
    SNAP("tr_sendbuf", "full", st.s);
    while ((int)(GetTickCount() - t0) < 8000) {
        char b[65536]; int n = U(recv)(st.peer, b, sizeof(b), 0);
        if (n <= 0) { if (xs_wait(st.s, 'w', 20)) break; Sleep(5); }
    }
    w = xs_wait(st.s, 'w', 3000);
    VAL("tr_sendbuf", "writable_again", "%d", w);
    SNAP("tr_sendbuf", "drained", st.s);
    xs_teardown(&st);
}

TEST(tr_udp_cycle)
{
    NEED(st, "udp_bound");
    struct sockaddr_in a; int l = sizeof(a); SOCKET p = xs_sock(AF_INET, SOCK_DGRAM); char b[4];
    U(getsockname)(st.s, (struct sockaddr *)&a, &l);
    SNAP("tr_udp_cycle", "idle", st.s);
    U(sendto)(p, "0123456789", 10, 0, (struct sockaddr *)&a, l); xs_wait(st.s, 'r', 3000);
    SNAP("tr_udp_cycle", "datagram", st.s);
    VAL("tr_udp_cycle", "recv_short", "%d", rd(st.s, 4, 0));
    SNAP("tr_udp_cycle", "after_truncated_recv", st.s);
    U(sendto)(p, "ab", 2, 0, (struct sockaddr *)&a, l); U(sendto)(p, "cd", 2, 0, (struct sockaddr *)&a, l); xs_wait(st.s, 'r', 3000); xs_settle(50);
    VAL("tr_udp_cycle", "recv_one", "%d", rd(st.s, 100, 0));
    SNAP("tr_udp_cycle", "one_of_two_left", st.s);
    VAL("tr_udp_cycle", "recv_two", "%d", rd(st.s, 100, 0));
    SNAP("tr_udp_cycle", "empty_again", st.s);
    (void)b;
    xs_close(p); xs_teardown(&st);
}

TEST(tr_udp_icmp_cycle)
{
    NEED(st, "udp_icmp_error");
    SNAP("tr_udp_icmp", "error_pending", st.s);
    VAL("tr_udp_icmp", "recv_reports", "%d", rd(st.s, 10, 0));
    SNAP("tr_udp_icmp", "after_report", st.s);
    VAL("tr_udp_icmp", "recv_nonblocking_after", "%d", (xs_nb(st.s, 1), rd(st.s, 10, 0)));
    xs_teardown(&st);
}

TEST(tr_reset_cycle)
{
    NEED(st, "tcp_peer_reset");
    SNAP("tr_reset", "pending", st.s);
    VAL("tr_reset", "send", "%d", xs_send_n(st.s, 2, 0) < 0 ? -xs_err() : 0);
    SNAP("tr_reset", "after_send", st.s);
    VAL("tr_reset", "recv", "%d", rd(st.s, 10, 0));
    SNAP("tr_reset", "after_recv", st.s);
    VAL("tr_reset", "recv_again", "%d", rd(st.s, 10, 0));
    xs_teardown(&st);
}

TEST(tr_refused_connect_cycle)
{
    NEED(st, "tcp_connect_refused_nb");
    int e = -1, l = sizeof(e);
    SNAP("tr_refused", "pending_error", st.s);
    U(getsockopt)(st.s, SOL_SOCKET, SO_ERROR, (char *)&e, &l);
    VAL("tr_refused", "so_error", "%d", e);
    SNAP("tr_refused", "after_so_error", st.s);
    e = -1; U(getsockopt)(st.s, SOL_SOCKET, SO_ERROR, (char *)&e, &l);
    VAL("tr_refused", "so_error_again", "%d", e);
    xs_teardown(&st);
}

TEST(tr_closed_by_peer_then_local_close_read)
{
    NEED(st, "tcp_peer_close_data");
    VAL("tr_close_data", "recv", "%d", rd(st.s, 100, 0));
    SNAP("tr_close_data", "after_data", st.s);
    VAL("tr_close_data", "recv_zero", "%d", rd(st.s, 100, 0));
    SNAP("tr_close_data", "after_zero", st.s);
    xs_teardown(&st);
}

/* ---- edge versus level ----------------------------------------------------- */
static void enum_str(SOCKET s, char *out, size_t cap)
{
    WSANETWORKEVENTS ne; char nm[120], tail[160]; int i, sig = WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0;
    tail[0] = 0; memset(&ne, 0x55, sizeof(ne));
    if (U(WSAEnumNetworkEvents)(s, xs_event(), &ne)) { snprintf(out, cap, "sig=%d err=%d", sig, xs_err()); return; }
    for (i = 0; i < 10; i++)
        if ((ne.lNetworkEvents & (1 << i)) && ne.iErrorCode[i]) { char t[40]; snprintf(t, sizeof(t), " %s=%d", xs_fd_name(1u << i, nm, sizeof(nm)), ne.iErrorCode[i]); strncat(tail, t, sizeof(tail) - strlen(tail) - 1); }
    snprintf(out, cap, "sig=%d %s%s", sig, xs_fd_name(ne.lNetworkEvents, nm, sizeof(nm)), tail);
}
#define ENUM(grp, step, s) do { char b_[256]; enum_str(s, b_, sizeof(b_)); xs_row_check(grp, step, b_); } while (0)

TEST(tr_event_select_edge_read)
{
    NEED(st, "tcp_data_client");
    ResetEvent(xs_event());
    U(WSAEventSelect)(st.s, xs_event(), FD_READ | FD_WRITE | FD_CLOSE);
    ENUM("tr_evsel_edge", "first_enum", st.s);
    ENUM("tr_evsel_edge", "second_enum", st.s);
    SNAP("tr_evsel_edge", "level_view_unchanged", st.s);
    VAL("tr_evsel_edge", "recv2", "%d", rd(st.s, 2, 0));
    ENUM("tr_evsel_edge", "after_partial_recv", st.s);
    VAL("tr_evsel_edge", "recv_rest", "%d", rd(st.s, 100, 0));
    ENUM("tr_evsel_edge", "after_full_recv", st.s);
    xs_send_n(st.peer, 1, 0); xs_wait(st.s, 'r', 3000);
    WaitForSingleObject(xs_event(), 1000);
    ENUM("tr_evsel_edge", "new_data", st.s);
    U(WSAEventSelect)(st.s, NULL, 0);
    xs_teardown(&st);
}

TEST(tr_event_select_write_rearm)
{
    NEED(st, "tcp_conn_client");
    ResetEvent(xs_event());
    U(WSAEventSelect)(st.s, xs_event(), FD_READ | FD_WRITE | FD_CLOSE);
    ENUM("tr_evsel_write", "first", st.s);
    ENUM("tr_evsel_write", "second", st.s);
    VAL("tr_evsel_write", "send", "%d", xs_send_n(st.s, 4, 0));
    ENUM("tr_evsel_write", "after_send", st.s);
    U(WSAEventSelect)(st.s, NULL, 0);
    xs_teardown(&st);
}

TEST(tr_event_select_mask_filters)
{
    NEED(st, "tcp_peer_fin_data");
    const long masks[] = { FD_READ, FD_WRITE, FD_CLOSE, FD_OOB, FD_READ | FD_CLOSE, 0 };
    size_t i;
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        char step[24];
        snprintf(step, sizeof(step), "mask_%ld", masks[i]);
        ResetEvent(xs_event());
        U(WSAEventSelect)(st.s, xs_event(), masks[i]);
        ENUM("tr_evsel_mask", step, st.s);
        U(WSAEventSelect)(st.s, NULL, 0);
    }
    xs_teardown(&st);
}

TEST(tr_async_edge_read)
{
    NEED(st, "tcp_data_client");
    char out[128];
    xs_async_begin(st.s, FD_READ | FD_WRITE | FD_CLOSE);
    xs_async_pump(out, sizeof(out), 300); xs_row_check("tr_async_edge", "first", out);
    xs_async_pump(out, sizeof(out), 150); xs_row_check("tr_async_edge", "second", out);
    VAL("tr_async_edge", "recv2", "%d", rd(st.s, 2, 0));
    xs_async_pump(out, sizeof(out), 300); xs_row_check("tr_async_edge", "after_partial_recv", out);
    VAL("tr_async_edge", "recv_rest", "%d", rd(st.s, 100, 0));
    xs_async_pump(out, sizeof(out), 150); xs_row_check("tr_async_edge", "after_full_recv", out);
    xs_async_end(st.s);
    xs_teardown(&st);
}

TEST(tr_async_select_makes_socket_nonblocking)
{
    NEED(st, "tcp_conn_client");
    char out[64]; char b[8]; int r;
    xs_async_begin(st.s, FD_READ);
    r = U(recv)(st.s, b, sizeof(b), 0);
    VAL("tr_async_nb", "recv_empty", "%d", r < 0 ? xs_err() : r);
    xs_async_end(st.s);
    r = U(recv)(st.s, b, sizeof(b), 0);   /* still nonblocking after the association was removed */
    VAL("tr_async_nb", "recv_after_cancel", "%d", r < 0 ? xs_err() : r);
    (void)out;
    xs_teardown(&st);
}

TEST(tr_event_select_makes_socket_nonblocking)
{
    NEED(st, "tcp_conn_client");
    char b[8]; int r;
    U(WSAEventSelect)(st.s, xs_event(), FD_READ);
    r = U(recv)(st.s, b, sizeof(b), 0);
    VAL("tr_evsel_nb", "recv_empty", "%d", r < 0 ? xs_err() : r);
    U(WSAEventSelect)(st.s, NULL, 0);
    r = U(recv)(st.s, b, sizeof(b), 0);
    VAL("tr_evsel_nb", "recv_after_cancel", "%d", r < 0 ? xs_err() : r);
    xs_teardown(&st);
}

/* ---- sets mixing several sockets ----------------------------------------- */
TEST(tr_mixed_poll_array)
{
    xs_st a, b, c;
    if (!xs_init()) { t_skip("missing entry points"); return; }
    if (!build("tcp_data_client", &a) || !build("tcp_conn_client", &b) || !build("tcp_peer_reset", &c)) { t_skip("states unreachable"); return; }
    {
        WSAPOLLFD f[4]; int n, i; char nm[80], out[256];
        f[0].fd = a.s; f[1].fd = b.s; f[2].fd = c.s; f[3].fd = INVALID_SOCKET;
        for (i = 0; i < 4; i++) { f[i].events = POLLRDNORM | POLLWRNORM; f[i].revents = (short)0x7777; }
        n = U(WSAPoll)(f, 4, 0);
        out[0] = 0;
        for (i = 0; i < 4; i++) { char t[64]; snprintf(t, sizeof(t), "%s[%s]", i ? " " : "", xs_poll_name((unsigned short)f[i].revents, nm, sizeof(nm))); strncat(out, t, sizeof(out) - strlen(out) - 1); }
        VAL("tr_mixed_poll", "array4", "n=%d %s", n, out);
    }
    xs_teardown(&a); xs_teardown(&b); xs_teardown(&c);
}

TEST(tr_mixed_select_sets)
{
    xs_st a, b;
    if (!xs_init()) { t_skip("missing entry points"); return; }
    if (!build("tcp_data_client", &a) || !build("tcp_oob_pending", &b)) { t_skip("states unreachable"); return; }
    {
        fd_set r, w, x; struct timeval tv = { 0, 0 }; int n;
        FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
        r.fd_array[0] = a.s; r.fd_array[1] = b.s; r.fd_count = 2;
        w.fd_array[0] = a.s; w.fd_count = 1;
        x.fd_array[0] = a.s; x.fd_array[1] = b.s; x.fd_count = 2;
        n = U(select)(0, &r, &w, &x, &tv);
        VAL("tr_mixed_select", "sets", "n=%d r=%u w=%u x=%u r0is_a=%d x0is_b=%d", n, r.fd_count, w.fd_count, x.fd_count,
            r.fd_count && r.fd_array[0] == a.s, x.fd_count && x.fd_array[0] == b.s);
    }
    xs_teardown(&a); xs_teardown(&b);
}
