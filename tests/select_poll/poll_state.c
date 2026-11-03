/* WSAPoll: what the revents field reports for each connection state, and how it depends on the
 * requested events. The provider registers read interest as "data or pending accept", write interest as
 * "send possible or connect failure", and always registers disconnect and abort; the disconnect bit
 * comes back as POLLHUP and an abort or connect failure as POLLERR|POLLHUP whatever was requested.
 * Also cross-checks against select() for the same states and tests wake-ups from other threads.
 */
#include "sp.h"

static int has(int rev, int bits) { return (rev & bits) == bits; }

/* ---------------------------------------------------------------- idle states */
FAMILY_TEST(sp_pol_idle_pair_reports_write_only)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    PEQ(a, POLLRDNORM, 0);
    PEQ(a, POLLRDBAND, 0);
    PEQ(a, POLLWRNORM, POLLWRNORM);
    PEQ(a, POLLIN, 0);
    PEQ(a, POLLOUT, POLLWRNORM);
    PEQ(a, POLLIN | POLLOUT, POLLWRNORM);
    PEQ(b, POLLWRNORM | POLLRDNORM, POLLWRNORM);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_pol_data_reports_rdnorm_and_a_following_recv_does_not_block)
{
    SOCKET a, b;
    char buf[8];
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "poll", 4, 0), 4);
    CHECK(has(sp_poll_settle(b, POLLRDNORM, POLLRDNORM), POLLRDNORM));
    PEQ(b, POLLRDNORM, POLLRDNORM);
    PEQ(b, POLLRDBAND, 0);
    PEQ(b, POLLRDNORM | POLLWRNORM, POLLRDNORM | POLLWRNORM);
    PEQ(b, POLLWRNORM, POLLWRNORM);
    PEQ(a, POLLRDNORM, 0);
    SPEQ(sp_recv(b, buf, sizeof buf, 0), 4);
    PEQ(b, POLLRDNORM, 0);
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_pol_partial_read_keeps_rdnorm)
{
    SOCKET a, b;
    char buf[8];
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "0123456789", 10, 0), 10);
    CHECK(has(sp_poll_settle(b, POLLRDNORM, POLLRDNORM), POLLRDNORM));
    SPEQ(sp_recv(b, buf, 3, 0), 3);
    PEQ(b, POLLRDNORM, POLLRDNORM);
    SPEQ(sp_recv(b, buf, 7, 0), 7);
    PEQ(b, POLLRDNORM, 0);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- orderly close */
FAMILY_TEST(sp_pol_peer_fin_reports_hup_for_every_requested_mask)
{
    static const struct { short ev; int want; } t[] = {
        { 0, POLLHUP },
        { POLLRDNORM, POLLHUP },
        { POLLRDBAND, POLLHUP },
        { POLLRDNORM | POLLRDBAND, POLLHUP },
        { POLLWRNORM, POLLHUP | POLLWRNORM },
        { POLLRDNORM | POLLWRNORM, POLLHUP | POLLWRNORM },
        { POLLRDNORM | POLLRDBAND | POLLWRNORM, POLLHUP | POLLWRNORM },
    };
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        SOCKET a, b;
        int got;
        CHECK(sp_pair_af(af, &a, &b));
        SPEQ(U(shutdown)(a, SD_SEND), 0);
        got = sp_poll_settle(b, t[i].ev, POLLHUP);
        CHECKF(got == t[i].want, "events 0x%x: revents 0x%x want 0x%x", (unsigned short)t[i].ev, got, t[i].want);
        sp_close(a); sp_close(b);
    }
}
FAMILY_TEST(sp_pol_peer_fin_with_unread_data_reports_each_requested_part)
{
    static const struct { short ev; int want; } t[] = {
        { 0, POLLHUP },
        { POLLRDNORM, POLLHUP | POLLRDNORM },
        { POLLRDBAND, POLLHUP },
        { POLLWRNORM, POLLHUP | POLLWRNORM },
        { POLLRDNORM | POLLWRNORM, POLLHUP | POLLRDNORM | POLLWRNORM },
    };
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        SOCKET a, b;
        int got;
        CHECK(sp_pair_af(af, &a, &b));
        SPEQ(sp_send(a, "last", 4, 0), 4);
        SPEQ(U(shutdown)(a, SD_SEND), 0);
        got = sp_poll_settle(b, t[i].ev, POLLHUP);
        CHECKF(got == t[i].want, "events 0x%x: revents 0x%x want 0x%x", (unsigned short)t[i].ev, got, t[i].want);
        sp_close(a); sp_close(b);
    }
}
FAMILY_TEST(sp_pol_closing_peer_gives_hup_and_data_stays_readable)
{
    SOCKET a, b;
    char buf[8];
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(sp_send(a, "bye", 3, 0), 3);
    sp_close(a);
    CHECK(has(sp_poll_settle(b, POLLRDNORM | POLLWRNORM, POLLHUP), POLLHUP));
    SPEQ(sp_recv(b, buf, sizeof buf, 0), 3);
    SPEQ(sp_recv(b, buf, sizeof buf, 0), 0);
    CHECK(has(sp_rev(b, POLLRDNORM | POLLWRNORM), POLLHUP));   /* the hang-up persists after EOF */
    sp_close(b);
}
FAMILY_TEST(sp_pol_both_sides_shutdown_send_both_see_hup)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(U(shutdown)(a, SD_SEND), 0);
    SPEQ(U(shutdown)(b, SD_SEND), 0);
    CHECK(has(sp_poll_settle(a, POLLWRNORM, POLLHUP), POLLHUP));
    CHECK(has(sp_poll_settle(b, POLLWRNORM, POLLHUP), POLLHUP));
    sp_close(a); sp_close(b);
}
FAMILY_TEST(sp_pol_local_shutdown_send_alone_is_not_hup)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    SPEQ(U(shutdown)(a, SD_SEND), 0);
    PEQ(a, POLLRDNORM | POLLWRNORM, POLLWRNORM);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- abortive close */
FAMILY_TEST(sp_pol_reset_reports_err_and_hup_for_every_requested_mask)
{
    static const short ev[] = { 0, POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLRDNORM | POLLWRNORM };
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof ev / sizeof ev[0]; i++) {
        SOCKET a, b;
        int got;
        CHECK(sp_pair_af(af, &a, &b));
        sp_linger0(a);
        sp_close(a);
        got = sp_poll_settle(b, ev[i], POLLERR | POLLHUP);
        CHECKF(has(got, POLLERR | POLLHUP), "events 0x%x: revents 0x%x lacks ERR|HUP", (unsigned short)ev[i], got);
        CHECKF((got & POLLNVAL) == 0, "events 0x%x: revents 0x%x has NVAL", (unsigned short)ev[i], got);
        t_note("reset, events 0x%x -> revents 0x%x", (unsigned short)ev[i], got);
        sp_close(b);
    }
}
FAMILY_TEST(sp_pol_reset_counts_as_ready_even_with_no_events_requested)
{
    SOCKET a, b;
    short rv = 0;
    int r = 0, i;
    NEED_POLL();
    CHECK(sp_pair_af(af, &a, &b));
    sp_linger0(a);
    sp_close(a);
    for (i = 0; i < 40 && r != 1; i++) r = sp_poll(b, 0, 100, &rv);
    SPEQ(r, 1);
    CHECK(has(rv, POLLERR | POLLHUP));
    sp_close(b);
}

/* ---------------------------------------------------------------- out-of-band */
TEST(sp_pol_oob_with_ordinary_data_reports_both_bands)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "plain", 5, 0), 5);
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(has(sp_poll_settle(b, POLLRDNORM | POLLRDBAND, POLLRDBAND), POLLRDBAND));
    CHECK(has(sp_poll_settle(b, POLLRDNORM | POLLRDBAND, POLLRDNORM), POLLRDNORM));
    PEQ(b, POLLRDNORM | POLLRDBAND | POLLWRNORM, POLLRDNORM | POLLRDBAND | POLLWRNORM);
    PEQ(b, POLLRDBAND, POLLRDBAND);
    PEQ(b, POLLRDNORM, POLLRDNORM);
    sp_close(a); sp_close(b);
}
TEST(sp_pol_oob_not_requested_is_not_reported)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_excepted(b));
    PEQ(b, POLLRDNORM, 0);
    PEQ(b, POLLWRNORM, POLLWRNORM);
    PEQ(b, 0, 0);
    PEQ(b, POLLRDBAND, POLLRDBAND);
    sp_close(a); sp_close(b);
}
TEST(sp_pol_oob_inline_never_reports_rdband)
{
    SOCKET a, b;
    int on = 1;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_setopt(b, SOL_SOCKET, SO_OOBINLINE, &on, sizeof on), 0);
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_readable(b));
    PEQ(b, POLLRDBAND, 0);
    PEQ(b, POLLRDNORM | POLLRDBAND, POLLRDNORM);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- listeners */
FAMILY_TEST(sp_pol_listener_pending_connection_rdnorm_only_when_requested)
{
    sp_addr ad;
    SOCKET l, c, s;
    NEED_POLL();
    l = sp_listener(af, &ad, 4);
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_connect(c, &ad, sp_alen(af)), 0);
    CHECK(sp_wait_readable(l));
    PEQ(l, POLLRDNORM, POLLRDNORM);
    PEQ(l, POLLIN, POLLRDNORM);
    PEQ(l, POLLRDBAND, 0);
    PEQ(l, POLLWRNORM, 0);
    PEQ(l, 0, 0);                    /* pending accept is part of read interest only */
    s = sp_accept(l);
    CHECK(s != INVALID_SOCKET);
    PEQ(l, POLLRDNORM, 0);
    sp_close(c); sp_close(s); sp_close(l);
}
FAMILY_TEST(sp_pol_listener_with_backlog_of_three_drains_one_by_one)
{
    sp_addr ad;
    SOCKET l, c[3], s;
    int i;
    NEED_POLL();
    l = sp_listener(af, &ad, 8);
    for (i = 0; i < 3; i++) { c[i] = sp_sock(af, SOCK_STREAM, 0); SPEQ(sp_connect(c[i], &ad, sp_alen(af)), 0); }
    CHECK(sp_wait_readable(l));
    for (i = 0; i < 3; i++) {
        PEQ(l, POLLRDNORM, POLLRDNORM);
        s = sp_accept(l);
        CHECK(s != INVALID_SOCKET);
        sp_close(s);
    }
    PEQ(l, POLLRDNORM, 0);
    for (i = 0; i < 3; i++) sp_close(c[i]);
    sp_close(l);
}
FAMILY_TEST(sp_pol_idle_listener_never_reports_hup_or_write)
{
    sp_addr ad;
    SOCKET l;
    NEED_POLL();
    l = sp_listener(af, &ad, 2);
    PEQ(l, POLLRDNORM | POLLRDBAND | POLLWRNORM, 0);
    PEQ(l, 0, 0);
    sp_close(l);
}
TEST(sp_pol_bound_unconnected_stream_socket_is_quiet)
{
    SOCKET s;
    sp_addr a;
    NEED_POLL();
    s = sp_sock(AF_INET, SOCK_STREAM, 0);
    sp_loaddr(AF_INET, &a);
    SPEQ(sp_bind(s, &a, sizeof a.a4), 0);
    PEQ(s, POLLRDNORM | POLLWRNORM, 0);
    sp_close(s);
}

/* ---------------------------------------------------------------- connect */
FAMILY_TEST(sp_pol_nonblocking_connect_success_is_write_ready_not_error)
{
    sp_addr ad;
    SOCKET l, c;
    NEED_POLL();
    l = sp_listener(af, &ad, 4);
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_nonblock(c, 1), 0);
    sp_connect(c, &ad, sp_alen(af));
    SPEQ(sp_poll_settle(c, POLLWRNORM, POLLWRNORM), POLLWRNORM);
    PEQ(c, POLLRDNORM, 0);
    SPEQ(sp_getopt_int(c, SOL_SOCKET, SO_ERROR), 0);
    sp_close(c); sp_close(l);
}
FAMILY_TEST(sp_pol_refused_connect_flags_by_requested_mask)
{
    sp_addr dead = sp_dead(af);
    SOCKET c;
    NEED_POLL();
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_nonblock(c, 1), 0);
    SPEQ(sp_connect(c, &dead, sp_alen(af)), SOCKET_ERROR);
    SPEQ(sp_err(), WSAEWOULDBLOCK);
    if (!sp_wait_excepted(c)) { t_skip("refusal not reported within the bound"); sp_close(c); return; }
    /* write interest carries the connect-failure registration */
    PEQ(c, POLLWRNORM, POLLWRNORM | POLLHUP | POLLERR);
    PEQ(c, POLLRDNORM | POLLWRNORM, POLLWRNORM | POLLHUP | POLLERR);
    PEQ(c, POLLRDNORM | POLLRDBAND | POLLWRNORM, POLLWRNORM | POLLHUP | POLLERR);
    /* without write interest the failure is not reported */
    PEQ(c, POLLRDNORM, 0);
    PEQ(c, POLLRDBAND, 0);
    PEQ(c, 0, 0);
    sp_close(c);
}
FAMILY_TEST(sp_pol_refused_connect_is_seen_by_select_as_except_only)
{
    sp_addr dead = sp_dead(af);
    SOCKET c;
    fd_set r, w, x;
    NEED_POLL();
    c = sp_sock(af, SOCK_STREAM, 0);
    SPEQ(sp_nonblock(c, 1), 0);
    sp_connect(c, &dead, sp_alen(af));
    sp_set1(&r, c); sp_set1(&w, c); sp_set1(&x, c);
    if (sp_sel(&r, &w, &x, 8000) != 1) { t_skip("refusal not reported within the bound"); sp_close(c); return; }
    SPEQ(x.fd_count, 1);
    SPEQ(r.fd_count, 0);
    SPEQ(w.fd_count, 0);
    SPEQ(sp_getopt_int(c, SOL_SOCKET, SO_ERROR), WSAECONNREFUSED);
    sp_close(c);
}
TEST(sp_pol_blocking_connect_refused_leaves_poll_view_stable)
{
    sp_addr dead = sp_dead(AF_INET);
    SOCKET c;
    int first, second;
    NEED_POLL();
    c = sp_sock(AF_INET, SOCK_STREAM, 0);
    SPEQ(sp_connect(c, &dead, sizeof dead.a4), SOCKET_ERROR);
    SPEQ(sp_err(), WSAECONNREFUSED);
    first = sp_rev(c, POLLWRNORM);
    second = sp_rev(c, POLLWRNORM);
    SPEQ(first, second);
    CHECK(has(first, POLLHUP | POLLERR));
    sp_close(c);
}

/* ---------------------------------------------------------------- datagram */
FAMILY_TEST(sp_pol_udp_states)
{
    sp_addr ad;
    SOCKET rx, tx;
    char buf[8];
    NEED_POLL();
    rx = sp_udp(af, &ad);
    tx = sp_sock(af, SOCK_DGRAM, IPPROTO_UDP);
    PEQ(rx, POLLRDNORM | POLLWRNORM, POLLWRNORM);
    SPEQ(sp_sendto(tx, "udp", 3, &ad, sp_alen(af)), 3);
    CHECK(sp_wait_readable(rx));
    PEQ(rx, POLLRDNORM, POLLRDNORM);
    PEQ(rx, POLLRDNORM | POLLWRNORM, POLLRDNORM | POLLWRNORM);
    PEQ(rx, POLLRDBAND, 0);
    PEQ(tx, POLLRDNORM | POLLWRNORM, POLLWRNORM);
    SPEQ(sp_recvfrom(rx, buf, sizeof buf, 0), 3);
    PEQ(rx, POLLRDNORM, 0);
    sp_close(rx); sp_close(tx);
}
TEST(sp_pol_udp_icmp_unreachable_observed)
{
    sp_addr dead = sp_dead_udp(AF_INET);
    SOCKET u;
    int rv;
    NEED_POLL();
    u = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(sp_connect(u, &dead, sizeof dead.a4), 0);
    SPEQ(sp_send(u, "ping", 4, 0), 4);
    if (sp_readable(u, 3000) != 1) { t_skip("no ICMP port-unreachable delivered"); sp_close(u); return; }
    rv = sp_rev(u, POLLRDNORM | POLLWRNORM);
    SPEQ(rv, POLLRDNORM | POLLWRNORM);
    sp_close(u);
}
TEST(sp_pol_udp_peer_close_has_no_effect_on_unconnected_socket)
{
    sp_addr a1;
    SOCKET s1, s2;
    sp_addr a2;
    NEED_POLL();
    s1 = sp_udp(AF_INET, &a1);
    s2 = sp_udp(AF_INET, &a2);
    sp_close(s2);
    PEQ(s1, POLLRDNORM | POLLWRNORM, POLLWRNORM);
    sp_close(s1);
}

/* ---------------------------------------------------------------- send buffer pressure */
TEST(sp_pol_full_send_buffer_drops_wrnorm_and_it_returns_after_drain)
{
    SOCKET a, b;
    static char blk[8192];
    int i, full = 0, sz = 4096;
    char sink[8192];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    sp_setopt(a, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    sp_setopt(b, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    SPEQ(sp_nonblock(a, 1), 0);
    for (i = 0; i < 6000; i++) {
        if (sp_send(a, blk, sizeof blk, 0) == SOCKET_ERROR && sp_err() == WSAEWOULDBLOCK) { full = 1; break; }
    }
    if (!full) { t_skip("send buffer never filled within the bound"); sp_close(a); sp_close(b); return; }
    PEQ(a, POLLWRNORM, 0);
    PEQ(a, POLLRDNORM | POLLWRNORM, 0);
    SPEQ(sp_nonblock(b, 1), 0);
    for (i = 0; i < 20000; i++) {
        int r = sp_recv(b, sink, sizeof sink, 0);
        if (r <= 0) break;
    }
    CHECK(has(sp_poll_settle(a, POLLWRNORM, POLLWRNORM), POLLWRNORM));
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- cross-check with select */
static void cross(SOCKET s, int sel_read, int sel_write, int poll_rd, int poll_wr)
{
    SPEQ(sp_readable(s, 0), sel_read);
    SPEQ(sp_writable(s, 0), sel_write);
    PEQ(s, POLLRDNORM, poll_rd ? POLLRDNORM : 0);
    PEQ(s, POLLWRNORM, poll_wr ? POLLWRNORM : 0);
}
TEST(sp_pol_cross_idle_stream)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    cross(a, 0, 1, 0, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_pol_cross_stream_with_data)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "d", 1, 0), 1);
    CHECK(sp_wait_readable(b));
    cross(b, 1, 1, 1, 1);
    cross(a, 0, 1, 0, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_pol_cross_listener_pending)
{
    sp_addr ad;
    SOCKET l, c;
    NEED_POLL();
    l = sp_listener(AF_INET, &ad, 4);
    cross(l, 0, 0, 0, 0);
    c = sp_sock(AF_INET, SOCK_STREAM, 0);
    SPEQ(sp_connect(c, &ad, sizeof ad.a4), 0);
    CHECK(sp_wait_readable(l));
    cross(l, 1, 0, 1, 0);
    sp_close(c); sp_close(l);
}
TEST(sp_pol_cross_udp)
{
    sp_addr ad;
    SOCKET rx, tx;
    NEED_POLL();
    rx = sp_udp(AF_INET, &ad);
    tx = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    cross(rx, 0, 1, 0, 1);
    SPEQ(sp_sendto(tx, "u", 1, &ad, sizeof ad.a4), 1);
    CHECK(sp_wait_readable(rx));
    cross(rx, 1, 1, 1, 1);
    sp_close(rx); sp_close(tx);
}
TEST(sp_pol_fin_is_readable_to_select_but_hup_only_to_poll)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(U(shutdown)(a, SD_SEND), 0);
    CHECK(sp_wait_readable(b));
    SPEQ(sp_readable(b, 0), 1);                          /* EOF counts as readable for select */
    CHECK(has(sp_poll_settle(b, POLLRDNORM, POLLHUP), POLLHUP));
    PEQ(b, POLLRDNORM, POLLHUP);                          /* but not as normal data for poll */
    sp_close(a); sp_close(b);
}
TEST(sp_pol_reset_is_readable_to_select_and_err_hup_to_poll)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    sp_linger0(a);
    sp_close(a);
    CHECK(sp_wait_readable(b));
    CHECK(has(sp_poll_settle(b, POLLRDNORM, POLLERR | POLLHUP), POLLERR | POLLHUP));
    sp_close(b);
}
TEST(sp_pol_oob_is_except_to_select_and_rdband_to_poll)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "!", 1, MSG_OOB), 1);
    CHECK(sp_wait_excepted(b));
    SPEQ(sp_excepted(b, 0), 1);
    PEQ(b, POLLRDBAND, POLLRDBAND);
    sp_close(a); sp_close(b);
}

/* ---------------------------------------------------------------- wake-ups */
TEST(sp_pol_blocked_poll_wakes_for_incoming_connection)
{
    sp_addr ad;
    SOCKET l;
    HANDLE h;
    sp_conn_arg ca;
    short rv = 0;
    NEED_POLL();
    l = sp_listener(AF_INET, &ad, 4);
    ca.s = INVALID_SOCKET; ca.to = &ad; ca.af = AF_INET;
    h = sp_after(150, sp_job_connect, &ca);
    SPEQ(sp_poll(l, POLLRDNORM, 5000, &rv), 1);
    SPEQ(rv, POLLRDNORM);
    CHECK(sp_join(h, 4000));
    sp_close(ca.s); sp_close(l);
}
TEST(sp_pol_blocked_poll_wakes_for_peer_fin)
{
    SOCKET a, b;
    HANDLE h;
    short rv = 0;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, sp_job_shutsend, (void *)(ULONG_PTR)a);
    SPEQ(sp_poll(b, POLLRDNORM, 5000, &rv), 1);
    SPEQ(rv, POLLHUP);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b);
}
static void job_oob(void *p) { sp_send((SOCKET)(ULONG_PTR)p, "!", 1, MSG_OOB); }
TEST(sp_pol_blocked_poll_wakes_for_oob)
{
    SOCKET a, b;
    HANDLE h;
    short rv = 0;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, job_oob, (void *)(ULONG_PTR)a);
    SPEQ(sp_poll(b, POLLRDBAND, 5000, &rv), 1);
    SPEQ(rv, POLLRDBAND);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b);
}
TEST(sp_pol_blocked_poll_wakes_for_nonblocking_connect_completion)
{
    sp_addr ad;
    SOCKET l, c;
    short rv = 0;
    NEED_POLL();
    l = sp_listener(AF_INET, &ad, 4);
    c = sp_sock(AF_INET, SOCK_STREAM, 0);
    SPEQ(sp_nonblock(c, 1), 0);
    sp_connect(c, &ad, sizeof ad.a4);
    SPEQ(sp_poll(c, POLLWRNORM, 5000, &rv), 1);
    SPEQ(rv, POLLWRNORM);
    sp_close(c); sp_close(l);
}
TEST(sp_pol_poll_on_two_sockets_wakes_for_whichever_fires)
{
    SOCKET a, b, c, d;
    WSAPOLLFD p[2];
    HANDLE h;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    CHECK(sp_pair(&c, &d));
    h = sp_after(150, sp_job_send1, (void *)(ULONG_PTR)c);
    p[0].fd = b; p[0].events = POLLRDNORM; p[0].revents = 0;
    p[1].fd = d; p[1].events = POLLRDNORM; p[1].revents = 0;
    SPEQ(U(WSAPoll)(p, 2, 5000), 1);
    SPEQ(p[0].revents, 0);
    SPEQ(p[1].revents, POLLRDNORM);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b); sp_close(c); sp_close(d);
}
typedef struct { SOCKET s; int ret; short rv; } pol_thr;
static DWORD WINAPI pol_reader(void *p)
{
    pol_thr *t = (pol_thr *)p;
    t->ret = sp_poll(t->s, POLLRDNORM, 6000, &t->rv);
    return 0;
}
TEST(sp_pol_two_threads_poll_the_same_socket)
{
    SOCKET a, b;
    pol_thr t1, t2;
    HANDLE h1, h2;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    t1.s = t2.s = b; t1.ret = t2.ret = -7;
    h1 = CreateThread(NULL, 0, pol_reader, &t1, 0, NULL);
    h2 = CreateThread(NULL, 0, pol_reader, &t2, 0, NULL);
    Sleep(200);
    SPEQ(sp_send(a, "w", 1, 0), 1);
    CHECK(sp_join(h1, 8000));
    CHECK(sp_join(h2, 8000));
    SPEQ(t1.ret, 1); SPEQ(t1.rv, POLLRDNORM);
    SPEQ(t2.ret, 1); SPEQ(t2.rv, POLLRDNORM);
    sp_close(a); sp_close(b);
}
TEST(sp_pol_poll_and_select_waiters_coexist)
{
    SOCKET a, b;
    pol_thr t1;
    {
        HANDLE h1;
        fd_set r;
        NEED_POLL();
        CHECK(sp_pair(&a, &b));
        t1.s = b; t1.ret = -7;
        h1 = CreateThread(NULL, 0, pol_reader, &t1, 0, NULL);
        Sleep(150);
        SPEQ(sp_send(a, "w", 1, 0), 1);
        sp_set1(&r, b);
        SPEQ(sp_sel(&r, NULL, NULL, 5000), 1);
        CHECK(sp_join(h1, 8000));
        SPEQ(t1.ret, 1);
        sp_close(a); sp_close(b);
    }
}

/* ---------------------------------------------------------------- inherited / duplicated */
TEST(sp_pol_duplicated_handle_observed)
{
    SOCKET a, b;
    HANDLE dup = NULL;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "k", 1, 0), 1);
    CHECK(sp_wait_readable(b));
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)b, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK(dup != NULL && (SOCKET)dup != b);
    if (dup) {
        PEQ((SOCKET)dup, POLLRDNORM | POLLWRNORM, POLLRDNORM | POLLWRNORM);
        CloseHandle(dup);
    }
    sp_close(a); sp_close(b);
}
