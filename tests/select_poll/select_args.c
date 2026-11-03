/* select(): argument handling and result-set bookkeeping. Start-up state, the nfds and timeout
 * parameters, NULL / empty set combinations, which fd decides the dispatch, duplicate and ordering rules
 * for the returned sets, counting of memberships, the fd_count ceiling, and sets larger than FD_SETSIZE.
 * Readiness semantics of individual socket states are in select_state.c.
 */
#include "sp.h"

/* ---- before WSAStartup / after the last WSACleanup (fresh process) ---- */
CHILD(sp_select_nostartup)
{
    SOCKET fake = 0x1234;
    fd_set r;
    struct timeval tv = { 0, 1000 };
    int (WSAAPI *sel)(int, fd_set *, fd_set *, fd_set *, const struct timeval *) =
        (int (WSAAPI *)(int, fd_set *, fd_set *, fd_set *, const struct timeval *))t_proc_in("ws2_32.dll", "select");
    int (WSAAPI *gle)(void) = (int (WSAAPI *)(void))t_proc_in("ws2_32.dll", "WSAGetLastError");
    if (!sel || !gle) return 90;
    r.fd_count = 1; r.fd_array[0] = fake;
    if (sel(0, &r, NULL, NULL, &tv) != SOCKET_ERROR) return 91;
    if (gle() != WSANOTINITIALISED) return 92;
    if (r.fd_count != 1 || r.fd_array[0] != fake) return 93;      /* set untouched on failure */
    /* an empty request fails the start-up check first as well */
    r.fd_count = 0;
    if (sel(0, &r, NULL, NULL, &tv) != SOCKET_ERROR || gle() != WSANOTINITIALISED) return 94;
    return 0;
}
TEST(sp_select_before_wsastartup_fails_notinitialised)
{
    REQUIRE(U(select));
    SPEQ(t_run_child("sp_select_nostartup", "", 20000), 0);
}
CHILD(sp_select_after_cleanup)
{
    WSADATA d;
    fd_set w;
    SOCKET s;
    struct timeval tv = { 0, 1000 };
    int (WSAAPI *sel)(int, fd_set *, fd_set *, fd_set *, const struct timeval *) =
        (int (WSAAPI *)(int, fd_set *, fd_set *, fd_set *, const struct timeval *))t_proc_in("ws2_32.dll", "select");
    int (WSAAPI *gle)(void) = (int (WSAAPI *)(void))t_proc_in("ws2_32.dll", "WSAGetLastError");
    int (WSAAPI *up)(WORD, LPWSADATA) = (int (WSAAPI *)(WORD, LPWSADATA))t_proc_in("ws2_32.dll", "WSAStartup");
    int (WSAAPI *down)(void) = (int (WSAAPI *)(void))t_proc_in("ws2_32.dll", "WSACleanup");
    SOCKET (WSAAPI *mk)(int, int, int) = (SOCKET (WSAAPI *)(int, int, int))t_proc_in("ws2_32.dll", "socket");
    if (!sel || !gle || !up || !down || !mk) return 90;
    if (up(MAKEWORD(2, 2), &d)) return 91;
    s = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 92;
    w.fd_count = 1; w.fd_array[0] = s;
    if (sel(0, NULL, &w, NULL, &tv) != 1) return 93;
    if (down()) return 94;
    w.fd_count = 1; w.fd_array[0] = s;
    if (sel(0, NULL, &w, NULL, &tv) != SOCKET_ERROR) return 95;
    if (gle() != WSANOTINITIALISED) return 96;
    return 0;
}
TEST(sp_select_after_last_wsacleanup_fails_notinitialised)
{
    REQUIRE(U(select));
    SPEQ(t_run_child("sp_select_after_cleanup", "", 20000), 0);
}
CHILD(sp_wsapoll_nostartup)
{
    WSAPOLLFD p;
    int (WSAAPI *poll)(LPWSAPOLLFD, ULONG, INT) = (int (WSAAPI *)(LPWSAPOLLFD, ULONG, INT))t_proc_in("ws2_32.dll", "WSAPoll");
    int (WSAAPI *gle)(void) = (int (WSAAPI *)(void))t_proc_in("ws2_32.dll", "WSAGetLastError");
    if (!poll || !gle) return 90;
    p.fd = 0x1234; p.events = POLLRDNORM; p.revents = 0x55;
    if (poll(&p, 1, 0) != SOCKET_ERROR) return 91;
    if (gle() != WSANOTINITIALISED) return 92;
    return 0;
}
TEST(sp_wsapoll_before_wsastartup_fails_notinitialised)
{
    REQUIRE(U(WSAPoll));
    SPEQ(t_run_child("sp_wsapoll_nostartup", "", 20000), 0);
}
TEST(sp_select_survives_balanced_extra_startup_cleanup)
{
    WSADATA d;
    SOCKET s;
    fd_set w;
    NEED_WS();
    s = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SPEQ(U(WSAStartup)(MAKEWORD(2, 2), &d), 0);
    SPEQ(U(WSACleanup)(), 0);     /* the process-wide reference from sp_up() remains */
    sp_set1(&w, s);
    SPEQ(sp_sel(NULL, &w, NULL, 100), 1);
    sp_close(s);
}

/* ---- nfds is ignored ---- */
TEST(sp_select_nfds_is_ignored)
{
    static const int nfds[] = { 0, 1, 2, 5, 64, 1000, INT_MAX, -1, INT_MIN };
    SOCKET a, b;
    unsigned i;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(b, "x", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    for (i = 0; i < sizeof nfds / sizeof nfds[0]; i++) {
        fd_set r;
        struct timeval tv = { 0, 0 };
        sp_set1(&r, a);
        SPEQ(U(select)(nfds[i], &r, NULL, NULL, &tv), 1);
        SPEQ(r.fd_count, 1);
        SPEQ(r.fd_array[0], a);
    }
    sp_close(a); sp_close(b);
}
TEST(sp_select_nfds_ignored_for_error_cases_too)
{
    static const int nfds[] = { 0, 7, INT_MAX, -1 };
    struct timeval tv = { 0, 1000 };
    unsigned i;
    NEED_WS();
    for (i = 0; i < sizeof nfds / sizeof nfds[0]; i++) {
        sp_seterr(0);
        SPEQ(U(select)(nfds[i], NULL, NULL, NULL, &tv), SOCKET_ERROR);
        SPEQ(sp_err(), WSAEINVAL);
    }
}

/* ---- timeouts ---- */
TEST(sp_select_null_timeout_with_ready_socket_returns)
{
    SOCKET a, b;
    fd_set w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&w, a);
    SPEQ(U(select)(0, NULL, &w, NULL, NULL), 1);   /* a writable socket never blocks the call */
    SPEQ(w.fd_count, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_select_timeout_struct_not_modified)
{
    SOCKET a, b;
    fd_set r;
    struct timeval tv;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&r, a);
    tv.tv_sec = 0; tv.tv_usec = 120000;
    SPEQ(U(select)(0, &r, NULL, NULL, &tv), 0);
    SPEQ(tv.tv_sec, 0);
    SPEQ(tv.tv_usec, 120000);
    tv.tv_sec = 5; tv.tv_usec = 777;
    sp_set1(&r, b);
    SPEQ(U(select)(0, NULL, &r, NULL, &tv), 1);
    SPEQ(tv.tv_sec, 5);
    SPEQ(tv.tv_usec, 777);
    sp_close(a); sp_close(b);
}
TEST(sp_select_zero_timeout_idle_clears_all_sets)
{
    SOCKET a, b;
    fd_set r, w, x;
    struct timeval tv = { 0, 0 };
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&r, a); sp_set1(&x, a); sp_zero(&w);
    sp_put(&w, a);
    /* fill the write set with something that is not writable: an unconnected stream socket */
    {
        SOCKET u = sp_sock(AF_INET, SOCK_STREAM, 0);
        sp_zero(&w); sp_put(&w, u);
        SPEQ(U(select)(0, &r, &w, &x, &tv), 0);
        SPEQ(r.fd_count, 0);
        SPEQ(w.fd_count, 0);
        SPEQ(x.fd_count, 0);
        sp_close(u);
    }
    sp_close(a); sp_close(b);
}
TEST(sp_select_timeout_expiry_waits_roughly_that_long)
{
    SOCKET u;
    fd_set r;
    DWORD t0, el;
    NEED_WS();
    u = sp_udp(AF_INET, NULL);
    sp_set1(&r, u);
    t0 = GetTickCount();
    SPEQ(sp_sel(&r, NULL, NULL, 300), 0);
    el = GetTickCount() - t0;
    CHECKF(el >= 150, "returned after only %lu ms for a 300 ms timeout", el);
    sp_close(u);
}
TEST(sp_select_timeout_larger_than_one_second_in_usec_is_accepted)
{
    /* tv_usec is not normalised or range-checked; with a ready socket the call simply succeeds. */
    SOCKET a, b;
    fd_set w;
    struct timeval tv;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    tv.tv_sec = 0; tv.tv_usec = 2500000;
    sp_set1(&w, a);
    SPEQ(U(select)(0, NULL, &w, NULL, &tv), 1);
    sp_close(a); sp_close(b);
}
TEST(sp_select_unusual_timeouts_do_not_fail_ready_socket)
{
    static const struct { long s, us; } tvs[] = {
        { 0, -1 }, { -1, 0 }, { -5, -5 }, { 0x7fffffff, 0 }, { 0, 0x7fffffff }, { 100000, 999999 },
    };
    SOCKET a, b;
    unsigned i;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    for (i = 0; i < sizeof tvs / sizeof tvs[0]; i++) {
        fd_set w;
        struct timeval tv;
        tv.tv_sec = tvs[i].s; tv.tv_usec = tvs[i].us;
        sp_set1(&w, a);
        SPEQ(U(select)(0, NULL, &w, NULL, &tv), 1);
    }
    sp_close(a); sp_close(b);
}
TEST(sp_select_idle_sets_cleared_even_when_only_one_set_given)
{
    SOCKET u;
    fd_set x;
    NEED_WS();
    u = sp_sock(AF_INET, SOCK_STREAM, 0);
    sp_set1(&x, u);
    SPEQ(sp_sel(NULL, NULL, &x, 0), 0);
    SPEQ(x.fd_count, 0);
    sp_close(u);
}

/* ---- NULL / empty set combinations ---- */
TEST(sp_select_all_null_any_timeout_is_einval)
{
    static const int ms[] = { 0, 1, 50 };
    unsigned i;
    NEED_WS();
    for (i = 0; i < 3; i++) {
        sp_seterr(0);
        SPEQ(sp_sel(NULL, NULL, NULL, ms[i]), SOCKET_ERROR);
        SPEQ(sp_err(), WSAEINVAL);
    }
}
TEST(sp_select_empty_set_combinations_are_einval)
{
    /* bit0 = read set present-but-empty, bit1 = write, bit2 = except; the others are NULL */
    unsigned m;
    NEED_WS();
    for (m = 1; m < 8; m++) {
        fd_set r, w, x;
        sp_zero(&r); sp_zero(&w); sp_zero(&x);
        sp_seterr(0);
        SPEQ(sp_sel(m & 1 ? &r : NULL, m & 2 ? &w : NULL, m & 4 ? &x : NULL, 20), SOCKET_ERROR);
        SPEQ(sp_err(), WSAEINVAL);
        SPEQ(r.fd_count, 0);
        SPEQ(w.fd_count, 0);
        SPEQ(x.fd_count, 0);
    }
}
TEST(sp_select_einval_returns_without_waiting_for_timeout)
{
    fd_set r;
    DWORD t0, el;
    NEED_WS();
    sp_zero(&r);
    t0 = GetTickCount();
    SPEQ(sp_sel(&r, NULL, NULL, 2000), SOCKET_ERROR);
    el = GetTickCount() - t0;
    CHECKF(el < 1500, "empty request waited %lu ms", el);
}
TEST(sp_select_empty_read_set_with_live_write_set_works)
{
    SOCKET a, b;
    fd_set r, w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_zero(&r);
    sp_set1(&w, a);
    SPEQ(sp_sel(&r, &w, NULL, 100), 1);
    SPEQ(r.fd_count, 0);
    SPEQ(w.fd_count, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_select_null_read_set_with_live_except_set_idle)
{
    SOCKET a, b;
    fd_set x;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&x, a);
    SPEQ(sp_sel(NULL, NULL, &x, 20), 0);
    SPEQ(x.fd_count, 0);
    sp_close(a); sp_close(b);
}
TEST(sp_select_each_set_alone_reports_its_own_condition)
{
    SOCKET a, b;
    fd_set s;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(b, "z", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    sp_set1(&s, a); SPEQ(sp_sel(&s, NULL, NULL, 0), 1);
    sp_set1(&s, a); SPEQ(sp_sel(NULL, &s, NULL, 0), 1);
    sp_set1(&s, a); SPEQ(sp_sel(NULL, NULL, &s, 0), 0);
    sp_close(a); sp_close(b);
}

/* ---- which fd selects the dispatch ---- */
TEST(sp_select_invalid_first_read_fd_fails_even_with_valid_write_fd)
{
    /* The first fd of the first non-empty set picks the provider; if that handle is not a socket
     * the whole call fails with WSAENOTSOCK before anything is polled. */
    SOCKET a, b;
    fd_set r, w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&r, INVALID_SOCKET);
    sp_set1(&w, a);
    sp_seterr(0);
    SPEQ(sp_sel(&r, &w, NULL, 50), SOCKET_ERROR);
    SPEQ(sp_err(), WSAENOTSOCK);
    SPEQ(r.fd_count, 1);
    SPEQ(w.fd_count, 1);
    SPEQ(w.fd_array[0], a);
    sp_close(a); sp_close(b);
}
TEST(sp_select_invalid_first_fd_in_write_set_with_empty_read_set)
{
    SOCKET a, b;
    fd_set r, w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_zero(&r);
    sp_set1(&w, (SOCKET)0x7ff0);
    sp_seterr(0);
    SPEQ(sp_sel(&r, &w, NULL, 50), SOCKET_ERROR);
    SPEQ(sp_err(), WSAENOTSOCK);
    SPEQ(w.fd_count, 1);
    sp_close(a); sp_close(b);
}
TEST(sp_select_bogus_handle_values_are_notsock)
{
    static const SOCKET bogus[] = { 0, 4, 0x0abcdef4, 0xabacab, (SOCKET)-2, (SOCKET)0x8000000000000000ULL };
    unsigned i;
    NEED_WS();
    for (i = 0; i < sizeof bogus / sizeof bogus[0]; i++) {
        fd_set r;
        sp_set1(&r, bogus[i]);
        sp_seterr(0);
        SPEQ(sp_sel(&r, NULL, NULL, 10), SOCKET_ERROR);
        SPEQ(sp_err(), WSAENOTSOCK);
        SPEQ(r.fd_count, 1);
        SPEQ(r.fd_array[0], bogus[i]);
    }
}
TEST(sp_select_closed_socket_is_notsock_and_set_kept)
{
    SOCKET s;
    fd_set w;
    NEED_WS();
    s = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sp_close(s);
    sp_set1(&w, s);
    sp_seterr(0);
    SPEQ(sp_sel(NULL, &w, NULL, 10), SOCKET_ERROR);
    SPEQ(sp_err(), WSAENOTSOCK);
    SPEQ(w.fd_count, 1);
    SPEQ(w.fd_array[0], s);
}

/* ---- duplicates, order and compaction of the returned sets ---- */
TEST(sp_select_duplicate_patterns_collapse_to_unique_ready_sockets)
{
    static const struct { int n; int idx[6]; int unique; } pat[] = {
        { 3, { 0, 1, 0 }, 2 },
        { 4, { 0, 0, 1, 1 }, 2 },
        { 5, { 0, 1, 0, 1, 0 }, 2 },
        { 6, { 2, 2, 2, 2, 2, 2 }, 1 },
        { 4, { 0, 1, 2, 0 }, 3 },
    };
    SOCKET so[3];
    unsigned p;
    int i;
    NEED_WS();
    for (i = 0; i < 3; i++) so[i] = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);   /* always writable */
    for (p = 0; p < sizeof pat / sizeof pat[0]; p++) {
        fd_set w;
        int j, first[3] = { -1, -1, -1 }, order = 0;
        sp_zero(&w);
        for (j = 0; j < pat[p].n; j++) sp_put(&w, so[pat[p].idx[j]]);
        SPEQ(sp_sel(NULL, &w, NULL, 100), pat[p].unique);
        SPEQ(w.fd_count, pat[p].unique);
        /* the survivors appear in order of first occurrence */
        for (j = 0; j < pat[p].n; j++) if (first[pat[p].idx[j]] < 0) first[pat[p].idx[j]] = order++;
        for (i = 0; i < 3; i++) if (first[i] >= 0) SPEQ(sp_idx(&w, so[i]), first[i]);
    }
    for (i = 0; i < 3; i++) sp_close(so[i]);
}
TEST(sp_select_result_order_follows_input_order)
{
    enum { N = 6 };
    SOCKET so[N];
    fd_set w;
    int i;
    NEED_WS();
    for (i = 0; i < N; i++) so[i] = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sp_zero(&w);
    for (i = N - 1; i >= 0; i--) sp_put(&w, so[i]);          /* reversed */
    SPEQ(sp_sel(NULL, &w, NULL, 100), N);
    for (i = 0; i < N; i++) SPEQ(w.fd_array[i], so[N - 1 - i]);
    for (i = 0; i < N; i++) sp_close(so[i]);
}
TEST(sp_select_not_ready_entries_are_removed_and_ready_ones_compacted)
{
    SOCKET rx[4], tx;
    sp_addr ad[4];
    fd_set r;
    int i;
    NEED_WS();
    tx = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < 4; i++) rx[i] = sp_udp(AF_INET, &ad[i]);
    sp_zero(&r);
    for (i = 0; i < 4; i++) sp_put(&r, rx[i]);
    SPEQ(sp_sendto(tx, "a", 1, &ad[1], sizeof ad[1].a4), 1);
    SPEQ(sp_sendto(tx, "b", 1, &ad[3], sizeof ad[3].a4), 1);
    CHECK(sp_wait_readable(rx[1]));
    CHECK(sp_wait_readable(rx[3]));
    SPEQ(sp_sel(&r, NULL, NULL, 0), 2);
    SPEQ(r.fd_count, 2);
    SPEQ(r.fd_array[0], rx[1]);
    SPEQ(r.fd_array[1], rx[3]);
    for (i = 0; i < 4; i++) sp_close(rx[i]);
    sp_close(tx);
}
TEST(sp_select_nothing_ready_yields_zero_count_in_every_set)
{
    SOCKET u1, u2;
    fd_set r, x;
    NEED_WS();
    u1 = sp_udp(AF_INET, NULL); u2 = sp_udp(AF_INET, NULL);
    sp_zero(&r); sp_put(&r, u1); sp_put(&r, u2);
    sp_zero(&x); sp_put(&x, u1);
    SPEQ(sp_sel(&r, NULL, &x, 30), 0);
    SPEQ(r.fd_count, 0);
    SPEQ(x.fd_count, 0);
    sp_close(u1); sp_close(u2);
}
TEST(sp_select_slots_after_count_are_not_scrubbed)
{
    SOCKET u1, u2, u3;
    fd_set w;
    NEED_WS();
    u1 = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    u2 = sp_sock(AF_INET, SOCK_STREAM, 0);   /* unconnected stream: never writable */
    u3 = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sp_zero(&w); sp_put(&w, u1); sp_put(&w, u2); sp_put(&w, u3);
    SPEQ(sp_sel(NULL, &w, NULL, 50), 2);
    SPEQ(w.fd_count, 2);
    SPEQ(w.fd_array[0], u1);
    SPEQ(w.fd_array[1], u3);
    SPEQ(w.fd_array[2], u3);       /* the stale tail keeps its old value */
    sp_close(u1); sp_close(u2); sp_close(u3);
}

/* ---- counting memberships ---- */
TEST(sp_select_return_counts_set_memberships_not_sockets)
{
    SOCKET a, b;
    fd_set r, w, x;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(b, "k", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    sp_set1(&r, a); sp_set1(&w, a); sp_zero(&x); sp_put(&x, a);
    SPEQ(sp_sel(&r, &w, &x, 0), 2);        /* readable + writable, not exceptional */
    SPEQ(r.fd_count, 1);
    SPEQ(w.fd_count, 1);
    SPEQ(x.fd_count, 0);
    sp_close(a); sp_close(b);
}
TEST(sp_select_two_sockets_three_conditions)
{
    SOCKET a, b;
    fd_set r, w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(b, "k", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    sp_zero(&r); sp_put(&r, a); sp_put(&r, b);
    sp_zero(&w); sp_put(&w, a); sp_put(&w, b);
    SPEQ(sp_sel(&r, &w, NULL, 0), 3);      /* a readable, a writable, b writable */
    SPEQ(r.fd_count, 1);
    SPEQ(r.fd_array[0], a);
    SPEQ(w.fd_count, 2);
    sp_close(a); sp_close(b);
}
TEST(sp_select_same_set_pointer_for_all_three_args)
{
    SOCKET a, b;
    fd_set s;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&s, a);
    /* read (idle), write (ready) and except (idle) sets alias: the socket is reported once */
    SPEQ(sp_sel(&s, &s, &s, 100), 1);
    SPEQ(s.fd_count, 1);
    SPEQ(s.fd_array[0], a);
    sp_close(a); sp_close(b);
}
TEST(sp_select_untouched_socket_conditions_do_not_leak_between_sets)
{
    SOCKET a, b;
    fd_set r, w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    sp_set1(&r, a);     /* a is writable but nothing to read */
    sp_set1(&w, b);
    SPEQ(sp_sel(&r, &w, NULL, 20), 1);
    SPEQ(r.fd_count, 0);
    SPEQ(w.fd_count, 1);
    SPEQ(w.fd_array[0], b);
    sp_close(a); sp_close(b);
}

/* ---- set size limits ---- */
TEST(sp_select_exactly_fd_setsize_sockets)
{
    SOCKET so[FD_SETSIZE];
    fd_set w;
    int i;
    NEED_WS();
    sp_zero(&w);
    for (i = 0; i < FD_SETSIZE; i++) { so[i] = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP); sp_put(&w, so[i]); }
    SPEQ(sp_sel(NULL, &w, NULL, 200), FD_SETSIZE);
    SPEQ(w.fd_count, FD_SETSIZE);
    for (i = 0; i < FD_SETSIZE; i++) SPEQ(w.fd_array[i], so[i]);
    for (i = 0; i < FD_SETSIZE; i++) sp_close(so[i]);
}
TEST(sp_select_custom_set_beyond_fd_setsize)
{
    enum { N = FD_SETSIZE + 37 };
    SOCKET so[N];
    fd_set *w = sp_newset(N);
    int i;
    NEED_WS();
    for (i = 0; i < N; i++) { so[i] = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP); sp_put(w, so[i]); }
    SPEQ(sp_sel(NULL, w, NULL, 200), N);
    SPEQ(w->fd_count, N);
    for (i = 0; i < N; i++) SPEQ(w->fd_array[i], so[i]);
    for (i = 0; i < N; i++) sp_close(so[i]);
    free(w);
}
TEST(sp_select_large_read_set_with_partial_readiness)
{
    enum { N = 130 };
    SOCKET rx[N], tx;
    sp_addr ad[N];
    fd_set *r = sp_newset(N);
    int i, ready = 0, k;
    NEED_WS();
    tx = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < N; i++) { rx[i] = sp_udp(AF_INET, &ad[i]); sp_put(r, rx[i]); }
    for (i = 1; i < N; i += 2) { sp_sendto(tx, "d", 1, &ad[i], sizeof ad[i].a4); ready++; }
    for (i = 1; i < N; i += 2) CHECK(sp_wait_readable(rx[i]));
    SPEQ(sp_sel(r, NULL, NULL, 0), ready);
    SPEQ(r->fd_count, ready);
    for (k = 0, i = 1; i < N; i += 2, k++) SPEQ(r->fd_array[k], rx[i]);
    for (i = 0; i < N; i++) sp_close(rx[i]);
    sp_close(tx);
    free(r);
}
TEST(sp_select_large_read_set_all_idle)
{
    enum { N = 150 };
    SOCKET rx[N];
    fd_set *r = sp_newset(N);
    int i;
    NEED_WS();
    for (i = 0; i < N; i++) { rx[i] = sp_udp(AF_INET, NULL); sp_put(r, rx[i]); }
    SPEQ(sp_sel(r, NULL, NULL, 20), 0);
    SPEQ(r->fd_count, 0);
    for (i = 0; i < N; i++) sp_close(rx[i]);
    free(r);
}
TEST(sp_select_set_with_more_than_65535_entries_is_enobufs)
{
    /* The provider refuses any set whose count does not fit 16 bits, before looking at the sockets. */
    SOCKET u;
    fd_set *w = sp_newset(65536);
    unsigned i;
    NEED_WS();
    u = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < 65536; i++) sp_put(w, u);
    sp_seterr(0);
    SPEQ(sp_sel(NULL, w, NULL, 10), SOCKET_ERROR);
    SPEQ(sp_err(), WSAENOBUFS);
    SPEQ(w->fd_count, 65536);     /* untouched */
    sp_close(u);
    free(w);
}
TEST(sp_select_oversized_read_set_is_enobufs_even_if_write_set_is_small)
{
    SOCKET u;
    fd_set *r = sp_newset(65536), w;
    unsigned i;
    NEED_WS();
    u = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < 65536; i++) sp_put(r, u);
    sp_set1(&w, u);
    sp_seterr(0);
    SPEQ(sp_sel(r, &w, NULL, 10), SOCKET_ERROR);
    SPEQ(sp_err(), WSAENOBUFS);
    sp_close(u);
    free(r);
}

/* ---- mixed socket kinds in one call ---- */
TEST(sp_select_mixed_tcp_udp_in_one_write_set)
{
    SOCKET a, b, u;
    fd_set w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    u = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sp_zero(&w); sp_put(&w, a); sp_put(&w, u); sp_put(&w, b);
    SPEQ(sp_sel(NULL, &w, NULL, 100), 3);
    sp_close(a); sp_close(b); sp_close(u);
}
TEST(sp_select_mixed_v4_and_v6_in_one_call)
{
    SOCKET a, b, c, d;
    fd_set r, w;
    NEED_WS();
    if (!sp_have_v6()) { t_skip("no IPv6 loopback"); return; }
    CHECK(sp_pair_af(AF_INET, &a, &b));
    CHECK(sp_pair_af(AF_INET6, &c, &d));
    SPEQ(sp_send(d, "6", 1, 0), 1);
    CHECK(sp_wait_readable(c));
    sp_zero(&r); sp_put(&r, a); sp_put(&r, c);
    sp_zero(&w); sp_put(&w, b); sp_put(&w, d);
    SPEQ(sp_sel(&r, &w, NULL, 0), 3);
    SPEQ(r.fd_count, 1);
    SPEQ(r.fd_array[0], c);
    SPEQ(w.fd_count, 2);
    sp_close(a); sp_close(b); sp_close(c); sp_close(d);
}
TEST(sp_select_blocking_and_nonblocking_sockets_report_alike)
{
    SOCKET a, b;
    fd_set r, w;
    NEED_WS();
    CHECK(sp_pair(&a, &b));
    SPEQ(sp_send(b, "n", 1, 0), 1);
    CHECK(sp_wait_readable(a));
    SPEQ(sp_nonblock(a, 1), 0);
    sp_set1(&r, a); sp_set1(&w, a);
    SPEQ(sp_sel(&r, &w, NULL, 0), 2);
    SPEQ(sp_nonblock(a, 0), 0);
    sp_set1(&r, a); sp_set1(&w, a);
    SPEQ(sp_sel(&r, &w, NULL, 0), 2);
    sp_close(a); sp_close(b);
}

/* ---- the event bookkeeping of WSAEventSelect is not disturbed by select ---- */
TEST(sp_select_does_not_rearm_wsaeventselect_event)
{
    SOCKET a, b;
    HANDLE ev;
    fd_set r;
    NEED_WS();
    REQUIRE(U(WSAEventSelect));
    CHECK(sp_pair(&a, &b));
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    SPEQ(U(WSAEventSelect)(a, (WSAEVENT)ev, FD_READ), 0);
    SPEQ(sp_send(b, "data", 4, 0), 4);
    SPEQ(WaitForSingleObject(ev, 4000), WAIT_OBJECT_0);
    sp_set1(&r, a);
    SPEQ(sp_sel(&r, NULL, NULL, 0), 1);
    SPEQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);   /* select consumed nothing and signalled nothing */
    U(WSAEventSelect)(a, NULL, 0);
    CloseHandle(ev);
    sp_close(a); sp_close(b);
}
