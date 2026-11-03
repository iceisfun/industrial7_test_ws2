/* WSAPoll: argument validation and array handling. The accepted event bits (exhaustively over all
 * 65536 values), the precedence between a bad descriptor and a bad event mask, the NVAL rules, the
 * return value (number of ready descriptors, not counting invalid ones), repeated descriptors in one
 * array, timeout conventions (zero, positive, any negative = wait), and large arrays.
 * Event semantics of connection states are in poll_state.c.
 */
#include "sp.h"

#define EV_VALID_MASK ((short)(POLLRDNORM | POLLRDBAND | POLLWRNORM))

/* ---- the whole event-mask space ---- */
TEST(sp_poll_event_mask_validity_over_all_65536_values)
{
    sp_addr ad;
    SOCKET l;
    unsigned ev, bad = 0;
    NEED_POLL();
    l = sp_listener(AF_INET, &ad, 2);
    CHECK(l != INVALID_SOCKET);
    for (ev = 0; ev < 65536; ev++) {
        WSAPOLLFD p;
        int r, want_valid = ((ev & ~(unsigned)(0x10 | 0x100 | 0x200)) & 0xffff) == 0;
        p.fd = l; p.events = (short)ev; p.revents = 0x5555;
        sp_seterr(0);
        r = U(WSAPoll)(&p, 1, 0);
        if (want_valid) { if (r != 0 || p.revents != 0) bad++; }          /* idle listener: nothing ready */
        else if (r != SOCKET_ERROR || sp_err() != WSAEINVAL) bad++;
    }
    CHECKF(bad == 0, "%u event masks classified differently from the rule (valid iff only RDNORM/RDBAND/WRNORM)", bad);
    sp_close(l);
}
TEST(sp_poll_each_single_event_bit_classified)
{
    static const struct { short bit; int valid; } bits[] = {
        { 0x0001, 0 }, { 0x0002, 0 }, { 0x0004, 0 }, { 0x0008, 0 }, { 0x0010, 1 }, { 0x0020, 0 },
        { 0x0040, 0 }, { 0x0080, 0 }, { 0x0100, 1 }, { 0x0200, 1 }, { 0x0400, 0 }, { 0x0800, 0 },
        { 0x1000, 0 }, { 0x2000, 0 }, { 0x4000, 0 }, { (short)0x8000, 0 },
    };
    SOCKET a, b;
    unsigned i;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    for (i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        WSAPOLLFD p;
        int r;
        p.fd = a; p.events = bits[i].bit; p.revents = 0;
        sp_seterr(0);
        r = U(WSAPoll)(&p, 1, 0);
        if (bits[i].valid) CHECKF(r >= 0, "bit 0x%x rejected (%d, err %d)", (unsigned short)bits[i].bit, r, sp_err());
        else { CHECKF(r == SOCKET_ERROR, "bit 0x%x accepted", (unsigned short)bits[i].bit); SPEQ(sp_err(), WSAEINVAL); }
    }
    sp_close(a); sp_close(b);
}
TEST(sp_poll_valid_event_combinations_on_a_connected_socket)
{
    /* idle connected stream: writable only, so every combination containing WRNORM reports it */
    static const short ev[] = {
        0, POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLRDNORM | POLLRDBAND, POLLRDNORM | POLLWRNORM,
        POLLRDBAND | POLLWRNORM, POLLRDNORM | POLLRDBAND | POLLWRNORM, POLLIN, POLLOUT, POLLIN | POLLOUT,
    };
    SOCKET a, b;
    unsigned i;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    for (i = 0; i < sizeof ev / sizeof ev[0]; i++) {
        int want = (ev[i] & POLLWRNORM) ? POLLWRNORM : 0;
        int got = sp_rev(a, ev[i]);
        CHECKF(got == want, "events 0x%x: revents 0x%x want 0x%x", (unsigned short)ev[i], got, want);
    }
    sp_close(a); sp_close(b);
}
TEST(sp_poll_events_zero_on_idle_socket_reports_nothing)
{
    SOCKET a, b;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    PEQ(a, 0, 0);
    PEQ(b, 0, 0);
    sp_close(a); sp_close(b);
}
TEST(sp_poll_pollpri_is_rejected_on_every_socket_kind)
{
    SOCKET a, b, u;
    sp_addr ad;
    SOCKET l;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    u = sp_udp(AF_INET, NULL);
    l = sp_listener(AF_INET, &ad, 1);
    {
        const SOCKET all[] = { a, u, l };
        unsigned i;
        for (i = 0; i < 3; i++) {
            WSAPOLLFD p = { all[i], POLLPRI, 0 };
            sp_seterr(0);
            SPEQ(U(WSAPoll)(&p, 1, 0), SOCKET_ERROR);
            SPEQ(sp_err(), WSAEINVAL);
        }
    }
    sp_close(a); sp_close(b); sp_close(u); sp_close(l);
}

/* ---- bad event bits versus bad descriptors ---- */
TEST(sp_poll_bad_events_on_minus_one_fd_are_ignored)
{
    /* The -1 sentinel is flagged NVAL before its events are looked at, so garbage events there are harmless. */
    sp_addr ad;
    SOCKET l = sp_listener(AF_INET, &ad, 1);
    static const short junk[] = { POLLERR, POLLHUP, POLLNVAL, POLLPRI, POLLWRBAND, (short)0xffff, (short)0x8000 };
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof junk / sizeof junk[0]; i++) {
        WSAPOLLFD p[2];
        p[0].fd = l; p[0].events = 0; p[0].revents = 0x77;
        p[1].fd = INVALID_SOCKET; p[1].events = junk[i]; p[1].revents = 0x77;
        sp_seterr(0);
        SPEQ(U(WSAPoll)(p, 2, 0), 0);
        SPEQ(p[0].revents, 0);
        SPEQ(p[1].revents, POLLNVAL);
    }
    sp_close(l);
}
TEST(sp_poll_bad_events_on_other_bogus_fd_fail_the_call)
{
    /* Any other handle value that is not a socket gets its events checked first, so the mask is
     * rejected with WSAEINVAL instead of being reported as NVAL. */
    static const SOCKET bogus[] = { 0, 4, 0x0abcdef4, (SOCKET)-2, (SOCKET)0x7fffffffffffffffULL };
    sp_addr ad;
    SOCKET l = sp_listener(AF_INET, &ad, 1);
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof bogus / sizeof bogus[0]; i++) {
        WSAPOLLFD p[2];
        p[0].fd = l; p[0].events = POLLRDNORM; p[0].revents = 0x77;
        p[1].fd = bogus[i]; p[1].events = POLLERR; p[1].revents = 0x77;
        sp_seterr(0);
        SPEQ(U(WSAPoll)(p, 2, 0), SOCKET_ERROR);
        SPEQ(sp_err(), WSAEINVAL);
    }
    sp_close(l);
}
TEST(sp_poll_bad_events_on_valid_second_entry_fail_the_call)
{
    SOCKET a, b;
    WSAPOLLFD p[2];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    p[0].fd = a; p[0].events = POLLWRNORM; p[0].revents = 0x77;
    p[1].fd = b; p[1].events = POLLWRBAND; p[1].revents = 0x77;
    sp_seterr(0);
    SPEQ(U(WSAPoll)(p, 2, 0), SOCKET_ERROR);
    SPEQ(sp_err(), WSAEINVAL);
    sp_close(a); sp_close(b);
}

/* ---- NVAL handling ---- */
TEST(sp_poll_invalid_descriptor_values_report_nval_beside_a_valid_one)
{
    static const SOCKET bad[] = { INVALID_SOCKET, (SOCKET)-2, (SOCKET)0x8000000000000000ULL, 0, 4, 0x0abcdef4, 0xabacab };
    sp_addr ad;
    SOCKET l = sp_listener(AF_INET, &ad, 1);
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        WSAPOLLFD p[2];
        p[0].fd = bad[i]; p[0].events = POLLRDNORM; p[0].revents = 0x77;
        p[1].fd = l; p[1].events = POLLRDNORM; p[1].revents = 0x77;
        sp_seterr(0xbad);
        SPEQ(U(WSAPoll)(p, 2, 0), 0);
        SPEQ(sp_err(), 0);            /* a successful poll resets the last-error value */
        SPEQ(p[0].revents, POLLNVAL);
        SPEQ(p[1].revents, 0);
    }
    sp_close(l);
}
TEST(sp_poll_closed_socket_handle_is_nval)
{
    sp_addr ad;
    SOCKET l = sp_listener(AF_INET, &ad, 1), dead;
    WSAPOLLFD p[2];
    NEED_POLL();
    dead = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sp_close(dead);
    p[0].fd = dead; p[0].events = POLLWRNORM; p[0].revents = 0x77;
    p[1].fd = l; p[1].events = POLLRDNORM; p[1].revents = 0x77;
    SPEQ(U(WSAPoll)(p, 2, 0), 0);
    SPEQ(p[0].revents, POLLNVAL);
    sp_close(l);
}
TEST(sp_poll_only_closed_socket_fails_notsock)
{
    SOCKET dead;
    WSAPOLLFD p;
    NEED_POLL();
    dead = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sp_close(dead);
    p.fd = dead; p.events = POLLWRNORM; p.revents = 0x77;
    sp_seterr(0);
    SPEQ(U(WSAPoll)(&p, 1, 0), SOCKET_ERROR);
    SPEQ(sp_err(), WSAENOTSOCK);
    SPEQ(p.revents, POLLNVAL);
}
TEST(sp_poll_all_entries_invalid_is_notsock_for_each_sentinel)
{
    static const SOCKET bad[] = { INVALID_SOCKET, 0, 4, 0xabacab };
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        WSAPOLLFD p;
        p.fd = bad[i]; p.events = POLLWRNORM; p.revents = 0x77;
        sp_seterr(0);
        SPEQ(U(WSAPoll)(&p, 1, 0), SOCKET_ERROR);
        SPEQ(sp_err(), WSAENOTSOCK);
        SPEQ(p.revents, POLLNVAL);
    }
}
TEST(sp_poll_nval_entries_are_not_counted_in_the_result)
{
    SOCKET a, b;
    WSAPOLLFD p[3];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    p[0].fd = INVALID_SOCKET; p[0].events = POLLWRNORM; p[0].revents = 0;
    p[1].fd = a; p[1].events = POLLWRNORM; p[1].revents = 0;
    p[2].fd = (SOCKET)0xabacab; p[2].events = POLLWRNORM; p[2].revents = 0;
    SPEQ(U(WSAPoll)(p, 3, 0), 1);
    SPEQ(p[0].revents, POLLNVAL);
    SPEQ(p[1].revents, POLLWRNORM);
    SPEQ(p[2].revents, POLLNVAL);
    sp_close(a); sp_close(b);
}
TEST(sp_poll_invalid_entries_do_not_disturb_neighbours_events)
{
    SOCKET a, b;
    WSAPOLLFD p[4];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(a, "xyz", 3, 0), 3);
    CHECK(sp_wait_readable(b));
    p[0].fd = a; p[0].events = POLLRDNORM | POLLWRNORM; p[0].revents = 0;
    p[1].fd = INVALID_SOCKET; p[1].events = POLLRDNORM; p[1].revents = 0;
    p[2].fd = b; p[2].events = POLLRDNORM | POLLWRNORM; p[2].revents = 0;
    p[3].fd = 7; p[3].events = POLLWRNORM; p[3].revents = 0;
    SPEQ(U(WSAPoll)(p, 4, 0), 2);
    SPEQ(p[0].revents, POLLWRNORM);
    SPEQ(p[1].revents, POLLNVAL);
    SPEQ(p[2].revents, POLLRDNORM | POLLWRNORM);
    SPEQ(p[3].revents, POLLNVAL);
    sp_close(a); sp_close(b);
}

/* ---- revents handling ---- */
TEST(sp_poll_revents_is_overwritten_not_accumulated)
{
    SOCKET a, b;
    WSAPOLLFD p;
    int i;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    for (i = 0; i < 3; i++) {
        static const short junk[] = { (short)0xffff, 0x0100, 0x0010 };
        p.fd = a; p.events = POLLWRNORM; p.revents = junk[i];
        SPEQ(U(WSAPoll)(&p, 1, 0), 1);
        SPEQ(p.revents, POLLWRNORM);
    }
    p.fd = a; p.events = POLLRDNORM; p.revents = (short)0xffff;
    SPEQ(U(WSAPoll)(&p, 1, 0), 0);
    SPEQ(p.revents, 0);
    sp_close(a); sp_close(b);
}
TEST(sp_poll_fd_and_events_fields_are_left_unchanged)
{
    SOCKET a, b;
    WSAPOLLFD p;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    p.fd = a; p.events = POLLRDNORM | POLLWRNORM; p.revents = 0;
    SPEQ(U(WSAPoll)(&p, 1, 0), 1);
    SPEQ(p.fd, a);
    SPEQ(p.events, POLLRDNORM | POLLWRNORM);
    sp_close(a); sp_close(b);
}
TEST(sp_poll_idle_call_zeroes_revents_of_every_entry)
{
    sp_addr ad;
    SOCKET l1 = sp_listener(AF_INET, &ad, 1), l2 = sp_listener(AF_INET, &ad, 1);
    WSAPOLLFD p[2];
    NEED_POLL();
    p[0].fd = l1; p[0].events = POLLRDNORM; p[0].revents = (short)0xffff;
    p[1].fd = l2; p[1].events = POLLRDNORM | POLLRDBAND; p[1].revents = (short)0xaaaa;
    SPEQ(U(WSAPoll)(p, 2, 0), 0);
    SPEQ(p[0].revents, 0);
    SPEQ(p[1].revents, 0);
    sp_close(l1); sp_close(l2);
}

/* ---- count parameter ---- */
TEST(sp_poll_zero_count_is_einval_for_any_pointer_and_timeout)
{
    static const int ms[] = { 0, 1, -1, 100 };
    WSAPOLLFD p;
    unsigned i;
    NEED_POLL();
    p.fd = INVALID_SOCKET; p.events = POLLRDNORM; p.revents = 0;
    for (i = 0; i < 4; i++) {
        sp_seterr(0);
        SPEQ(U(WSAPoll)(&p, 0, ms[i]), SOCKET_ERROR);
        SPEQ(sp_err(), WSAEINVAL);
        sp_seterr(0);
        SPEQ(U(WSAPoll)(NULL, 0, ms[i]), SOCKET_ERROR);
        SPEQ(sp_err(), WSAEINVAL);
    }
}
TEST(sp_poll_count_smaller_than_array_ignores_the_tail)
{
    SOCKET a, b;
    WSAPOLLFD p[3];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    p[0].fd = a; p[0].events = POLLWRNORM; p[0].revents = 0;
    p[1].fd = b; p[1].events = POLLWRNORM; p[1].revents = 0x1234;
    p[2].fd = INVALID_SOCKET; p[2].events = POLLERR; p[2].revents = 0x4321;
    SPEQ(U(WSAPoll)(p, 1, 0), 1);
    SPEQ(p[0].revents, POLLWRNORM);
    SPEQ(p[1].revents, 0x1234);
    SPEQ(p[2].revents, 0x4321);
    sp_close(a); sp_close(b);
}
TEST(sp_poll_single_entry_array_many_sockets_sizes)
{
    static const unsigned sizes[] = { 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100 };
    unsigned si, i;
    NEED_POLL();
    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        unsigned n = sizes[si];
        WSAPOLLFD *p = (WSAPOLLFD *)calloc(n, sizeof *p);
        SOCKET *so = (SOCKET *)calloc(n, sizeof *so);
        for (i = 0; i < n; i++) { so[i] = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP); p[i].fd = so[i]; p[i].events = POLLWRNORM; p[i].revents = 0x55; }
        SPEQ(U(WSAPoll)(p, n, 0), n);
        for (i = 0; i < n; i++) SPEQ(p[i].revents, POLLWRNORM);
        for (i = 0; i < n; i++) sp_close(so[i]);
        free(p); free(so);
    }
}
TEST(sp_poll_large_array_with_partial_readiness)
{
    enum { N = 200 };
    SOCKET rx[N], tx;
    sp_addr ad[N];
    WSAPOLLFD *p = (WSAPOLLFD *)calloc(N, sizeof *p);
    int i, ready = 0;
    NEED_POLL();
    tx = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < N; i++) { rx[i] = sp_udp(AF_INET, &ad[i]); p[i].fd = rx[i]; p[i].events = POLLRDNORM; }
    for (i = 0; i < N; i += 3) { sp_sendto(tx, "d", 1, &ad[i], sizeof ad[i].a4); ready++; }
    for (i = 0; i < N; i += 3) CHECK(sp_wait_readable(rx[i]));
    SPEQ(U(WSAPoll)(p, N, 0), ready);
    for (i = 0; i < N; i++) SPEQ(p[i].revents, i % 3 == 0 ? POLLRDNORM : 0);
    for (i = 0; i < N; i++) sp_close(rx[i]);
    sp_close(tx);
    free(p);
}
TEST(sp_poll_large_array_all_idle_returns_zero)
{
    enum { N = 150 };
    SOCKET rx[N];
    WSAPOLLFD *p = (WSAPOLLFD *)calloc(N, sizeof *p);
    int i;
    NEED_POLL();
    for (i = 0; i < N; i++) { rx[i] = sp_udp(AF_INET, NULL); p[i].fd = rx[i]; p[i].events = POLLRDNORM | POLLRDBAND; p[i].revents = 0x5a5a; }
    SPEQ(U(WSAPoll)(p, N, 20), 0);
    for (i = 0; i < N; i++) SPEQ(p[i].revents, 0);
    for (i = 0; i < N; i++) sp_close(rx[i]);
    free(p);
}
TEST(sp_poll_array_positions_are_independent_of_socket_order)
{
    SOCKET a, b, c, d;
    WSAPOLLFD p[4];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    CHECK(sp_pair(&c, &d));
    SPEQ(sp_send(a, "1", 1, 0), 1);
    SPEQ(sp_send(d, "2", 1, 0), 1);
    CHECK(sp_wait_readable(b));
    CHECK(sp_wait_readable(c));
    p[0].fd = d; p[1].fd = c; p[2].fd = b; p[3].fd = a;
    { int i; for (i = 0; i < 4; i++) { p[i].events = POLLRDNORM; p[i].revents = 0; } }
    SPEQ(U(WSAPoll)(p, 4, 0), 2);
    SPEQ(p[0].revents, 0);
    SPEQ(p[1].revents, POLLRDNORM);
    SPEQ(p[2].revents, POLLRDNORM);
    SPEQ(p[3].revents, 0);
    sp_close(a); sp_close(b); sp_close(c); sp_close(d);
}

/* ---- repeated descriptors ---- */
TEST(sp_poll_same_socket_twice_each_entry_gets_its_own_events)
{
    SOCKET a, b;
    WSAPOLLFD p[2];
    int r;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));              /* a: writable, nothing to read */
    p[0].fd = a; p[0].events = POLLRDNORM; p[0].revents = 0x77;
    p[1].fd = a; p[1].events = POLLWRNORM; p[1].revents = 0x77;
    r = U(WSAPoll)(p, 2, 0);
    SPEQ(p[0].revents, 0);
    SPEQ(p[1].revents, POLLWRNORM);
    SPEQ(r, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_poll_same_socket_twice_identical_requests_both_report)
{
    SOCKET a, b;
    WSAPOLLFD p[2];
    int r;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    p[0].fd = a; p[0].events = POLLWRNORM; p[0].revents = 0;
    p[1].fd = a; p[1].events = POLLWRNORM; p[1].revents = 0;
    r = U(WSAPoll)(p, 2, 0);
    SPEQ(p[0].revents, POLLWRNORM);
    SPEQ(p[1].revents, POLLWRNORM);
    SPEQ(r, 1);   /* the count is per socket handle, not per array entry */
    sp_close(a); sp_close(b);
}
TEST(sp_poll_same_socket_three_times_with_split_events)
{
    SOCKET a, b;
    WSAPOLLFD p[3];
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(b, "d", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    p[0].fd = a; p[0].events = POLLRDNORM; p[0].revents = 0;
    p[1].fd = a; p[1].events = POLLWRNORM; p[1].revents = 0;
    p[2].fd = a; p[2].events = POLLRDBAND; p[2].revents = 0;
    CHECK(U(WSAPoll)(p, 3, 0) >= 1);
    SPEQ(p[0].revents, POLLRDNORM);
    SPEQ(p[1].revents, POLLWRNORM);
    SPEQ(p[2].revents, 0);
    sp_close(a); sp_close(b);
}

/* ---- timeouts ---- */
TEST(sp_poll_zero_timeout_never_waits)
{
    SOCKET u;
    WSAPOLLFD p;
    DWORD t0;
    NEED_POLL();
    u = sp_udp(AF_INET, NULL);
    p.fd = u; p.events = POLLRDNORM; p.revents = 0;
    t0 = GetTickCount();
    SPEQ(U(WSAPoll)(&p, 1, 0), 0);
    CHECKF(GetTickCount() - t0 < 1500, "zero timeout took %lu ms", GetTickCount() - t0);
    sp_close(u);
}
TEST(sp_poll_positive_timeout_waits_then_returns_zero)
{
    SOCKET u;
    WSAPOLLFD p;
    DWORD t0, el;
    NEED_POLL();
    u = sp_udp(AF_INET, NULL);
    p.fd = u; p.events = POLLRDNORM; p.revents = 0x1111;
    t0 = GetTickCount();
    SPEQ(U(WSAPoll)(&p, 1, 300), 0);
    el = GetTickCount() - t0;
    CHECKF(el >= 150, "300 ms timeout returned after %lu ms", el);
    SPEQ(p.revents, 0);
    sp_close(u);
}
TEST(sp_poll_ready_socket_ignores_the_timeout_value)
{
    static const int ms[] = { 0, 1, 1000, INT_MAX, -1, -2, INT_MIN };
    SOCKET a, b;
    unsigned i;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    for (i = 0; i < sizeof ms / sizeof ms[0]; i++) {
        WSAPOLLFD p = { a, POLLWRNORM, 0 };
        SPEQ(U(WSAPoll)(&p, 1, ms[i]), 1);
        SPEQ(p.revents, POLLWRNORM);
    }
    sp_close(a); sp_close(b);
}
TEST(sp_poll_every_negative_timeout_means_wait_for_an_event)
{
    /* The wait is only released by the delayed sender; a negative value must not behave like zero. */
    static const int ms[] = { -1, -2, -1000, INT_MIN };
    unsigned i;
    NEED_POLL();
    for (i = 0; i < sizeof ms / sizeof ms[0]; i++) {
        SOCKET a, b;
        WSAPOLLFD p;
        HANDLE h;
        CHECK(sp_pair(&a, &b));
        h = sp_after(200, sp_job_send1, (void *)(ULONG_PTR)a);
        p.fd = b; p.events = POLLRDNORM; p.revents = 0;
        SPEQ(U(WSAPoll)(&p, 1, ms[i]), 1);
        SPEQ(p.revents, POLLRDNORM);
        CHECK(sp_join(h, 4000));
        sp_close(a); sp_close(b);
    }
}
TEST(sp_poll_large_positive_timeout_is_released_by_event)
{
    SOCKET a, b;
    WSAPOLLFD p;
    HANDLE h;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    h = sp_after(150, sp_job_send1, (void *)(ULONG_PTR)a);
    p.fd = b; p.events = POLLRDNORM; p.revents = 0;
    SPEQ(U(WSAPoll)(&p, 1, INT_MAX), 1);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b);
}
TEST(sp_poll_blocked_poll_is_alertable_for_apcs)
{
    SOCKET u;
    WSAPOLLFD p;
    NEED_POLL();
    u = sp_udp(AF_INET, NULL);
    sp_apc_hits = 0;
    CHECK(QueueUserAPC(sp_apc, GetCurrentThread(), 0));
    p.fd = u; p.events = POLLRDNORM; p.revents = 0;
    /* A pending APC runs while the call waits; afterwards the wait either resumes to its timeout or
     * returns early. The APC must have run exactly once and the socket must not be reported ready. */
    {
        int r = U(WSAPoll)(&p, 1, 300);
        CHECKF(r == 0 || r == SOCKET_ERROR, "poll returned %d", r);
        t_note("poll interrupted by APC returned %d (error %d)", r, r == SOCKET_ERROR ? sp_err() : 0);
    }
    SleepEx(0, TRUE);
    SPEQ(sp_apc_hits, 1);
    sp_close(u);
}

/* ---- the poll wait versus a concurrent close ---- */
TEST(sp_poll_other_socket_closed_does_not_disturb_the_wait)
{
    SOCKET a, b, c, d;
    WSAPOLLFD p;
    HANDLE h;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    CHECK(sp_pair(&c, &d));
    h = sp_after(100, sp_job_close, (void *)(ULONG_PTR)c);     /* unrelated socket */
    p.fd = b; p.events = POLLRDNORM; p.revents = 0;
    SPEQ(U(WSAPoll)(&p, 1, 400), 0);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(b); sp_close(d);
}
TEST(sp_poll_polled_socket_closed_in_the_middle_reports_nval_and_counts)
{
    SOCKET a, b, c, d;
    WSAPOLLFD p[2];
    HANDLE h;
    NEED_POLL();
    CHECK(sp_pair(&a, &b));
    CHECK(sp_pair(&c, &d));
    h = sp_after(150, sp_job_close, (void *)(ULONG_PTR)b);
    p[0].fd = b; p[0].events = POLLRDNORM; p[0].revents = 0;
    p[1].fd = d; p[1].events = POLLRDNORM; p[1].revents = 0;
    SPEQ(U(WSAPoll)(p, 2, 4000), 1);
    SPEQ(p[0].revents, POLLNVAL);
    SPEQ(p[1].revents, 0);
    CHECK(sp_join(h, 4000));
    sp_close(a); sp_close(c); sp_close(d);
}
