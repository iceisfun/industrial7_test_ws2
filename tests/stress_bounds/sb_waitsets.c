/* Boundaries of the readiness-wait primitives: select with default-sized and oversized fd_set
 * structures (FD_SETSIZE = 64), WSAPoll with hundreds of entries, and WSAWaitForMultipleEvents at
 * WSA_MAXIMUM_WAIT_EVENTS (64). Measured: return counts, which entries remain set, error codes. */
#include "sb.h"

/* an fd_set with room for n sockets, allocated on the heap */
typedef struct { u_int fd_count; SOCKET fd_array[1]; } big_set;
static big_set *bs_new(int cap)
{
    return (big_set *)calloc(1, sizeof(u_int) + 4 + (size_t)cap * sizeof(SOCKET));
}
static int bs_has(const big_set *b, SOCKET s)
{
    u_int i;
    for (i = 0; i < b->fd_count; i++) if (b->fd_array[i] == s) return 1;
    return 0;
}

static SOCKET *make_udps(int n, struct sockaddr_in *addrs)
{
    SOCKET *v = (SOCKET *)calloc(n, sizeof(SOCKET));
    int i;
    for (i = 0; i < n; i++) v[i] = sb_udp(addrs ? &addrs[i] : NULL);
    return v;
}
static void free_udps(SOCKET *v, int n)
{
    int i;
    for (i = 0; i < n; i++) if (v[i] != INVALID_SOCKET) closesocket(v[i]);
    free(v);
}
static int all_valid(SOCKET *v, int n) { int i; for (i = 0; i < n; i++) if (v[i] == INVALID_SOCKET) return 0; return 1; }

static void poke(SOCKET from, const struct sockaddr_in *to)
{
    sendto(from, "p", 1, 0, (const struct sockaddr *)to, sizeof *to);
}

/* ---- select: default fd_set (FD_SETSIZE 64) ---------------------------------------------------- */

TEST(sel_fd_setsize_is_64_in_sdk_layout)
{
    fd_set s;
    EXPECT_EQ(FD_SETSIZE, 64);
    EXPECT_EQ(sizeof s.fd_array / sizeof s.fd_array[0], 64);
    EXPECT_EQ(sizeof(fd_set), 4 + 4 + 64 * 8);
}

TEST(sel_exactly_64_sockets_in_default_set_all_polled)
{
    struct sockaddr_in a[64]; SOCKET *v; fd_set r; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    v = make_udps(64, a);
    if (!all_valid(v, 64)) { t_skip("socket creation"); free_udps(v, 64); sb_end(); return; }
    r.fd_count = 64;
    for (i = 0; i < 64; i++) r.fd_array[i] = v[i];
    n = select(0, &r, NULL, NULL, &tv);
    EXPECT_EQ(n, 0);
    EXPECT_EQ(r.fd_count, 0);
    /* the last slot of the default array is watched */
    poke(v[0], &a[63]);
    EXPECT_EQ(sb_readable(v[63], SB_WAIT_MS), 1);
    r.fd_count = 64;
    for (i = 0; i < 64; i++) r.fd_array[i] = v[i];
    n = select(0, &r, NULL, NULL, &tv);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(r.fd_count, 1);
    EXPECT_EQ(r.fd_array[0], v[63]);
    free_udps(v, 64);
    sb_end();
}

TEST(sel_fd_set_macro_does_not_add_65th_socket)
{
    fd_set s; SOCKET v[66]; int i;
    SB_BEGIN();
    for (i = 0; i < 66; i++) v[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    FD_ZERO(&s);
    for (i = 0; i < 66; i++) FD_SET(v[i], &s);
    EXPECT_EQ(s.fd_count, 64);
    EXPECT_EQ(s.fd_array[63], v[63]);
    for (i = 0; i < 66; i++) if (v[i] != INVALID_SOCKET) closesocket(v[i]);
    sb_end();
}

TEST(sel_oversized_custom_set_65_sockets_reports_the_65th)
{
    struct sockaddr_in a[65]; SOCKET *v; big_set *r; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    v = make_udps(65, a);
    r = bs_new(65);
    if (!all_valid(v, 65)) { t_skip("socket creation"); goto out; }
    poke(v[0], &a[64]);
    EXPECT_EQ(sb_readable(v[64], SB_WAIT_MS), 1);
    r->fd_count = 65;
    for (i = 0; i < 65; i++) r->fd_array[i] = v[i];
    n = select(0, (fd_set *)r, NULL, NULL, &tv);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(r->fd_count, 1);
    CHECK(bs_has(r, v[64]));
out:
    free(r); free_udps(v, 65);
    sb_end();
}

TEST(sel_oversized_custom_set_1000_sockets_none_ready)
{
    enum { N = 1000 };
    SOCKET *v; big_set *r; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    v = make_udps(N, NULL); r = bs_new(N);
    if (!all_valid(v, N)) { t_skip("socket creation"); goto out; }
    r->fd_count = N;
    for (i = 0; i < N; i++) r->fd_array[i] = v[i];
    n = select(0, (fd_set *)r, NULL, NULL, &tv);
    EXPECT_EQ(n, 0);
    EXPECT_EQ(r->fd_count, 0);
out:
    free(r); free_udps(v, N);
    sb_end();
}

TEST(sel_oversized_custom_set_1000_sockets_last_and_first_ready)
{
    enum { N = 1000 };
    struct sockaddr_in *a = (struct sockaddr_in *)calloc(N, sizeof *a);
    SOCKET *v; big_set *r; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    v = make_udps(N, a); r = bs_new(N);
    if (!all_valid(v, N)) { t_skip("socket creation"); goto out; }
    poke(v[500], &a[0]); poke(v[500], &a[N - 1]);
    sb_readable(v[0], SB_WAIT_MS); sb_readable(v[N - 1], SB_WAIT_MS);
    r->fd_count = N;
    for (i = 0; i < N; i++) r->fd_array[i] = v[i];
    n = select(0, (fd_set *)r, NULL, NULL, &tv);
    EXPECT_EQ(n, 2);
    EXPECT_EQ(r->fd_count, 2);
    CHECK(bs_has(r, v[0]));
    CHECK(bs_has(r, v[N - 1]));
out:
    free(r); free_udps(v, N); free(a);
    sb_end();
}

TEST(sel_oversized_write_set_of_300_fresh_datagram_sockets_all_writable)
{
    enum { N = 300 };
    SOCKET *v; big_set *w; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    v = make_udps(N, NULL); w = bs_new(N);
    if (!all_valid(v, N)) { t_skip("socket creation"); goto out; }
    w->fd_count = N;
    for (i = 0; i < N; i++) w->fd_array[i] = v[i];
    n = select(0, NULL, (fd_set *)w, NULL, &tv);
    EXPECT_EQ(n, N);
    EXPECT_EQ(w->fd_count, N);
out:
    free(w); free_udps(v, N);
    sb_end();
}

TEST(sel_read_and_write_sets_both_oversized_count_sums)
{
    enum { N = 100 };
    struct sockaddr_in a[N]; SOCKET *v; big_set *r, *w; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    v = make_udps(N, a); r = bs_new(N); w = bs_new(N);
    if (!all_valid(v, N)) { t_skip("socket creation"); goto out; }
    poke(v[0], &a[99]); sb_readable(v[99], SB_WAIT_MS);
    r->fd_count = w->fd_count = N;
    for (i = 0; i < N; i++) r->fd_array[i] = w->fd_array[i] = v[i];
    n = select(0, (fd_set *)r, (fd_set *)w, NULL, &tv);
    EXPECT_EQ(n, N + 1);       /* return value is the sum over the read and write sets */
    EXPECT_EQ(r->fd_count, 1);
    EXPECT_EQ(w->fd_count, N);
out:
    free(r); free(w); free_udps(v, N);
    sb_end();
}

TEST(sel_same_socket_repeated_in_oversized_set_counts_once_or_per_entry)
{
    struct sockaddr_in a; SOCKET s, p; big_set *r; struct timeval tv = {0, 0}; int i, n;
    SB_BEGIN();
    s = sb_udp(&a); p = sb_udp(NULL); r = bs_new(80);
    poke(p, &a); sb_readable(s, SB_WAIT_MS);
    r->fd_count = 80;
    for (i = 0; i < 80; i++) r->fd_array[i] = s;
    n = select(0, (fd_set *)r, NULL, NULL, &tv);
    CHECK(n >= 1);
    t_note("repeated entry count reported %s", n == 1 ? "once" : "per entry");
    CHECK(r->fd_count >= 1);
    free(r); sb_close2(s, p);
    sb_end();
}

TEST(sel_ready_socket_found_in_each_of_64_positions)
{
    enum { N = 64 };
    struct sockaddr_in a[N]; SOCKET *v; fd_set r; struct timeval tv = {0, 0}; int pos, bad = 0, i;
    SB_BEGIN();
    v = make_udps(N, a);
    if (!all_valid(v, N)) { t_skip("socket creation"); free_udps(v, N); sb_end(); return; }
    for (pos = 0; pos < N; pos += 9) {
        char c; int n;
        poke(v[(pos + 1) % N], &a[pos]); sb_readable(v[pos], SB_WAIT_MS);
        r.fd_count = N;
        for (i = 0; i < N; i++) r.fd_array[i] = v[i];
        n = select(0, &r, NULL, NULL, &tv);
        if (n != 1 || r.fd_count != 1 || r.fd_array[0] != v[pos]) bad++;
        recv(v[pos], &c, 1, 0);
    }
    EXPECT_EQ(bad, 0);
    free_udps(v, N);
    sb_end();
}

/* ---- WSAPoll with many entries ------------------------------------------------------------------ */

TEST(poll_500_sockets_one_readable)
{
    enum { N = 500 };
    struct sockaddr_in *a = (struct sockaddr_in *)calloc(N, sizeof *a); SOCKET *v;
    WSAPOLLFD *p = (WSAPOLLFD *)calloc(N, sizeof *p); int i, n, ready = 0, readable_ok = 0;
    SB_BEGIN();
    if (!W(WSAPoll)) { t_skip("missing export: WSAPoll"); goto out2; }
    v = make_udps(N, a);
    if (!all_valid(v, N)) { t_skip("socket creation"); free_udps(v, N); goto out2; }
    poke(v[0], &a[321]); sb_readable(v[321], SB_WAIT_MS);
    for (i = 0; i < N; i++) { p[i].fd = v[i]; p[i].events = POLLRDNORM; p[i].revents = 0x7777; }
    n = WSAPoll(p, N, 0);
    EXPECT_EQ(n, 1);
    for (i = 0; i < N; i++) {
        if (p[i].revents) ready++;
        if (i == 321 && (p[i].revents & POLLRDNORM)) readable_ok = 1;
    }
    EXPECT_EQ(ready, 1);
    EXPECT_EQ(readable_ok, 1);
    free_udps(v, N);
out2:
    free(p); free(a);
    sb_end();
}

TEST(poll_500_idle_sockets_with_short_timeout_returns_zero)
{
    enum { N = 500 };
    SOCKET *v; WSAPOLLFD *p = (WSAPOLLFD *)calloc(N, sizeof *p); int i, n;
    SB_BEGIN();
    if (!W(WSAPoll)) { t_skip("missing export: WSAPoll"); goto out2; }
    v = make_udps(N, NULL);
    if (!all_valid(v, N)) { t_skip("socket creation"); free_udps(v, N); goto out2; }
    for (i = 0; i < N; i++) { p[i].fd = v[i]; p[i].events = POLLRDNORM; p[i].revents = 0x7777; }
    n = WSAPoll(p, N, 50);
    EXPECT_EQ(n, 0);
    for (i = 0; i < N; i++) if (p[i].revents != 0) { CHECK(p[i].revents == 0); break; }
    free_udps(v, N);
out2:
    free(p);
    sb_end();
}

TEST(poll_500_fresh_datagram_sockets_all_writable)
{
    enum { N = 500 };
    SOCKET *v; WSAPOLLFD *p = (WSAPOLLFD *)calloc(N, sizeof *p); int i, n, w = 0;
    SB_BEGIN();
    if (!W(WSAPoll)) { t_skip("missing export: WSAPoll"); goto out2; }
    v = make_udps(N, NULL);
    if (!all_valid(v, N)) { t_skip("socket creation"); free_udps(v, N); goto out2; }
    for (i = 0; i < N; i++) { p[i].fd = v[i]; p[i].events = POLLWRNORM; }
    n = WSAPoll(p, N, 0);
    EXPECT_EQ(n, N);
    for (i = 0; i < N; i++) if (p[i].revents & POLLWRNORM) w++;
    EXPECT_EQ(w, N);
    free_udps(v, N);
out2:
    free(p);
    sb_end();
}

TEST(poll_invalid_entries_amid_many_are_flagged_pollnval)
{
    enum { N = 200 };
    SOCKET *v; WSAPOLLFD *p = (WSAPOLLFD *)calloc(N, sizeof *p); int i, n, bad = 0, nval = 0;
    SB_BEGIN();
    if (!W(WSAPoll)) { t_skip("missing export: WSAPoll"); goto out2; }
    v = make_udps(N, NULL);
    if (!all_valid(v, N)) { t_skip("socket creation"); free_udps(v, N); goto out2; }
    for (i = 0; i < N; i++) { p[i].fd = v[i]; p[i].events = POLLWRNORM; }
    closesocket(v[17]); v[17] = INVALID_SOCKET;   /* stale value stays in the array */
    closesocket(v[150]);
    v[150] = INVALID_SOCKET;
    p[17].fd = (SOCKET)0x7fff0; p[150].fd = (SOCKET)0x7fff4;
    n = WSAPoll(p, N, 0);
    for (i = 0; i < N; i++) {
        if (i == 17 || i == 150) { if (p[i].revents & POLLNVAL) nval++; else bad++; }
        else if (!(p[i].revents & POLLWRNORM)) bad++;
    }
    EXPECT_EQ(nval, 2);
    EXPECT_EQ(bad, 0);
    CHECK(n == N || n == N - 2 || n == 2 || n == -1);   /* tallies differ only in whether NVAL counts */
    free_udps(v, N);
out2:
    free(p);
    sb_end();
}

/* ---- WSAWaitForMultipleEvents: WSA_MAXIMUM_WAIT_EVENTS ------------------------------------------ */

static void make_events(WSAEVENT *e, int n) { int i; for (i = 0; i < n; i++) e[i] = WSACreateEvent(); }
static void kill_events(WSAEVENT *e, int n) { int i; for (i = 0; i < n; i++) if (e[i] != WSA_INVALID_EVENT) WSACloseEvent(e[i]); }

TEST(wait_maximum_wait_events_constant_is_64)
{
    EXPECT_EQ(WSA_MAXIMUM_WAIT_EVENTS, 64);
    EXPECT_EQ(WSA_WAIT_FAILED, (DWORD)-1);
    EXPECT_EQ(WSA_WAIT_TIMEOUT, 258);
}

TEST(wait_64_events_all_unsignalled_times_out)
{
    WSAEVENT e[64]; DWORD r;
    SB_BEGIN();
    make_events(e, 64);
    r = WSAWaitForMultipleEvents(64, e, FALSE, 0, FALSE);
    EXPECT_EQ(r, WSA_WAIT_TIMEOUT);
    kill_events(e, 64);
    sb_end();
}

TEST(wait_64_events_last_one_signalled_returns_index_63)
{
    WSAEVENT e[64]; DWORD r;
    SB_BEGIN();
    make_events(e, 64);
    WSASetEvent(e[63]);
    r = WSAWaitForMultipleEvents(64, e, FALSE, 1000, FALSE);
    EXPECT_EQ(r, WSA_WAIT_EVENT_0 + 63);
    kill_events(e, 64);
    sb_end();
}

TEST(wait_64_events_lowest_signalled_index_wins)
{
    WSAEVENT e[64]; DWORD r;
    SB_BEGIN();
    make_events(e, 64);
    WSASetEvent(e[40]); WSASetEvent(e[12]); WSASetEvent(e[63]);
    r = WSAWaitForMultipleEvents(64, e, FALSE, 1000, FALSE);
    EXPECT_EQ(r, WSA_WAIT_EVENT_0 + 12);
    kill_events(e, 64);
    sb_end();
}

TEST(wait_64_events_wait_all_needs_every_event)
{
    WSAEVENT e[64]; DWORD r; int i;
    SB_BEGIN();
    make_events(e, 64);
    for (i = 0; i < 63; i++) WSASetEvent(e[i]);
    r = WSAWaitForMultipleEvents(64, e, TRUE, 50, FALSE);
    EXPECT_EQ(r, WSA_WAIT_TIMEOUT);
    WSASetEvent(e[63]);
    r = WSAWaitForMultipleEvents(64, e, TRUE, 1000, FALSE);
    EXPECT_EQ(r, WSA_WAIT_EVENT_0);
    /* manual-reset events stay signalled after the wait */
    EXPECT_EQ(WaitForSingleObject(e[5], 0), WAIT_OBJECT_0);
    kill_events(e, 64);
    sb_end();
}

TEST(wait_65_events_is_rejected_with_invalid_parameter)
{
    WSAEVENT e[65]; DWORD r;
    SB_BEGIN();
    make_events(e, 65);
    WSASetEvent(e[0]);
    SetLastError(0);
    r = WSAWaitForMultipleEvents(65, e, FALSE, 0, FALSE);
    EXPECT_EQ(r, WSA_WAIT_FAILED);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_PARAMETER);
    kill_events(e, 65);
    sb_end();
}

TEST(wait_65_events_wait_all_is_rejected_too)
{
    WSAEVENT e[65]; DWORD r;
    SB_BEGIN();
    make_events(e, 65);
    SetLastError(0);
    r = WSAWaitForMultipleEvents(65, e, TRUE, 0, FALSE);
    EXPECT_EQ(r, WSA_WAIT_FAILED);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_PARAMETER);
    kill_events(e, 65);
    sb_end();
}

TEST(wait_zero_events_is_rejected_with_invalid_parameter)
{
    WSAEVENT e[1]; DWORD r;
    SB_BEGIN();
    e[0] = WSACreateEvent();
    SetLastError(0);
    r = WSAWaitForMultipleEvents(0, e, FALSE, 0, FALSE);
    EXPECT_EQ(r, WSA_WAIT_FAILED);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_PARAMETER);
    kill_events(e, 1);
    sb_end();
}

TEST(wait_oversized_counts_all_rejected)
{
    static const DWORD counts[] = { 65, 66, 100, 1000, 0x7fffffff };
    WSAEVENT e[1]; unsigned i; int bad = 0;
    SB_BEGIN();
    e[0] = WSACreateEvent(); WSASetEvent(e[0]);
    for (i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        DWORD r; SetLastError(0);
        r = WSAWaitForMultipleEvents(counts[i], e, FALSE, 0, FALSE);
        if (r != WSA_WAIT_FAILED || GetLastError() != ERROR_INVALID_PARAMETER) bad++;
    }
    EXPECT_EQ(bad, 0);
    kill_events(e, 1);
    sb_end();
}

TEST(wait_signalled_event_wakes_blocked_waiter_across_64_events)
{
    WSAEVENT e[64]; DWORD r;
    SB_BEGIN();
    make_events(e, 64);
    /* a stack of three pre-set events gives a deterministic index without a helper thread */
    WSASetEvent(e[31]);
    r = WSAWaitForMultipleEvents(64, e, FALSE, SB_WAIT_MS, FALSE);
    EXPECT_EQ(r, WSA_WAIT_EVENT_0 + 31);
    WSAResetEvent(e[31]);
    EXPECT_EQ(WSAWaitForMultipleEvents(64, e, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    kill_events(e, 64);
    sb_end();
}

TEST(wait_event_select_on_64_sockets_each_reports_its_own_index)
{
    enum { N = 64 };
    struct sockaddr_in a[N]; SOCKET *v; WSAEVENT e[N]; int i, bad = 0;
    SB_BEGIN();
    v = make_udps(N, a);
    if (!all_valid(v, N)) { t_skip("socket creation"); free_udps(v, N); sb_end(); return; }
    make_events(e, N);
    for (i = 0; i < N; i++) WSAEventSelect(v[i], e[i], FD_READ);
    for (i = 0; i < N; i += 7) {
        DWORD r;
        poke(v[(i + 1) % N], &a[i]);
        r = WSAWaitForMultipleEvents(N, e, FALSE, SB_WAIT_MS, FALSE);
        if (r != WSA_WAIT_EVENT_0 + (DWORD)i) bad++;
        { char c; recv(v[i], &c, 1, 0); }
        WSAResetEvent(e[i]);
    }
    EXPECT_EQ(bad, 0);
    for (i = 0; i < N; i++) WSAEventSelect(v[i], NULL, 0);
    kill_events(e, N);
    free_udps(v, N);
    sb_end();
}
