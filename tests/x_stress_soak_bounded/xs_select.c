/* select() over 63, 64 and 65 sockets with the SDK default FD_SETSIZE of 64: the 65-entry sets use the
 * fd_set layout with a larger array, which select() honours through fd_count. Positions, partial readiness,
 * write sets, mixed read/write sums, level-triggered repeats, stream EOF readiness and WSAENOTSOCK are
 * asserted from exact counts and exact membership. */
#include "xs_selbody.h"

TEST(select_sdk_fd_setsize_is_64) { CHECK(FD_SETSIZE == 64); EXPECT_EQ(sizeof(fd_set), sizeof(u_int) + 64 * sizeof(SOCKET) + 4); }

#define ONE(n, p, id) TEST(select_##n##_one_ready_at_##id) { body_one_ready(n, p); }
ONE(63, 0, first)  ONE(63, 31, middle)  ONE(63, 62, last)
ONE(64, 0, first)  ONE(64, 32, middle)  ONE(64, 63, last)
ONE(65, 0, first)  ONE(65, 32, middle)  ONE(65, 63, index63)  ONE(65, 64, last)
TEST(select_63_all_ready) { body_all_ready(63); }
TEST(select_64_all_ready) { body_all_ready(64); }
TEST(select_65_all_ready) { body_all_ready(65); }
TEST(select_63_none_ready) { body_none_ready(63); }
TEST(select_64_none_ready) { body_none_ready(64); }
TEST(select_65_none_ready) { body_none_ready(65); }
TEST(select_63_every_2nd) { body_every_kth(63, 2); }
TEST(select_64_every_3rd) { body_every_kth(64, 3); }
TEST(select_65_every_2nd) { body_every_kth(65, 2); }
TEST(select_65_every_7th) { body_every_kth(65, 7); }
TEST(select_63_all_writable) { body_all_writable(63); }
TEST(select_64_all_writable) { body_all_writable(64); }
TEST(select_65_all_writable) { body_all_writable(65); }
TEST(select_63_read_and_write_sum) { body_read_and_write_sum(63); }
TEST(select_64_read_and_write_sum) { body_read_and_write_sum(64); }
TEST(select_65_read_and_write_sum) { body_read_and_write_sum(65); }
TEST(select_63_level_triggered_20_repeats) { body_level_triggered(63); }
TEST(select_64_level_triggered_20_repeats) { body_level_triggered(64); }
TEST(select_65_level_triggered_20_repeats) { body_level_triggered(65); }
TEST(select_63_tcp_data_and_eof) { body_tcp_pairs(63); }
TEST(select_64_tcp_data_and_eof) { body_tcp_pairs(64); }
TEST(select_65_tcp_data_and_eof) { body_tcp_pairs(65); }
TEST(select_64_closed_member_is_notsock) { body_closed_member(64); }
TEST(select_65_closed_member_is_notsock) { body_closed_member(65); }

/* The SDK macros stop at 64 entries: the 65th FD_SET is silently ignored and FD_ISSET sees only 64. */
TEST(select_fd_set_macro_stops_at_64)
{
    udpset *u = calloc(1, sizeof *u); fd_set s; int i, in = 0;
    XS_BEGIN();
    if (!udpset_make(u, 65)) { t_skip("cannot create 65 sockets"); udpset_free(u); free(u); xs_end(); return; }
    FD_ZERO(&s);
    for (i = 0; i < 65; i++) FD_SET(u->s[i], &s);
    EXPECT_EQ(s.fd_count, 64);
    for (i = 0; i < 65; i++) if (xs_isset(&s, u->s[i])) in++;
    EXPECT_EQ(in, 64);
    FD_CLR(u->s[0], &s);
    EXPECT_EQ(s.fd_count, 63);
    FD_SET(u->s[0], &s); FD_SET(u->s[0], &s);
    EXPECT_EQ(s.fd_count, 64);   /* duplicates are not added twice */
    udpset_free(u); free(u); xs_end();
}

/* All three sets empty is an invalid request. */
TEST(select_all_sets_empty_is_einval)
{
    struct timeval tv = { 0, 10000 }; fd_set r;
    XS_BEGIN();
    FD_ZERO(&r);
    WSASetLastError(0);
    EXPECT_EQ(select(0, &r, NULL, NULL, &tv), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0);
    EXPECT_EQ(select(0, NULL, NULL, NULL, &tv), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xs_end();
}

/* WSAPoll over 63/64/65 entries reports the same readiness as select for the same traffic. */
static void poll_vs_select(int n)
{
    udpset *u = calloc(1, sizeof *u); WSAPOLLFD *p = calloc(n, sizeof *p); bigset r; int i, pr, mism = 0, ready_poll = 0;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d sockets", n); udpset_free(u); free(u); free(p); xs_end(); return; }
    for (i = 0; i < n; i += 4) udpset_feed(u, i);
    Sleep(50);
    for (i = 0; i < n; i++) { p[i].fd = u->s[i]; p[i].events = POLLRDNORM; p[i].revents = 0; }
    pr = WSAPoll(p, n, 3000);
    bigset_fill(&r, u->s, n);
    EXPECT_EQ(do_select(&r, NULL, NULL, 3000), (n + 3) / 4);
    for (i = 0; i < n; i++) {
        int pol = (p[i].revents & POLLRDNORM) != 0;
        if (pol) ready_poll++;
        if (pol != bigset_has(&r, u->s[i])) mism++;
    }
    EXPECT_EQ(pr, (n + 3) / 4);
    EXPECT_EQ(ready_poll, (n + 3) / 4);
    EXPECT_EQ(mism, 0);
    udpset_free(u); free(u); free(p); xs_end();
}
TEST(select_poll_agree_63) { poll_vs_select(63); }
TEST(select_poll_agree_64) { poll_vs_select(64); }
TEST(select_poll_agree_65) { poll_vs_select(65); }

/* 1000 back-to-back selects on a 64-socket set with a moving single ready socket always name that socket. */
TEST(select_1000_repeats_moving_ready_socket)
{
    udpset *u = calloc(1, sizeof *u); bigset r; int i, bad = 0;
    XS_BEGIN();
    if (!udpset_make(u, 64)) { t_skip("cannot create 64 sockets"); udpset_free(u); free(u); xs_end(); return; }
    for (i = 0; i < 1000; i++) {
        int pos = (i * 37) % 64;
        udpset_feed(u, pos);
        bigset_fill(&r, u->s, 64);
        if (do_select(&r, NULL, NULL, 3000) != 1 || r.fd_count != 1 || r.fd_array[0] != u->s[pos]) bad++;
        udpset_drain(u, pos);
    }
    EXPECT_EQ(bad, 0);
    udpset_free(u); free(u); xs_end();
}

/* 8 threads each select on a private 64-socket set at the same time; each sees exactly its own ready socket. */
typedef struct { int id, ok; } sel_thr;
static DWORD sel_thread(void *p)
{
    sel_thr *t = (sel_thr *)p; udpset *u = calloc(1, sizeof *u); bigset r; int i, good = 0;
    if (u && udpset_make(u, 64)) {
        for (i = 0; i < 50; i++) {
            int pos = (t->id * 5 + i) % 64;
            udpset_feed(u, pos);
            bigset_fill(&r, u->s, 64);
            if (do_select(&r, NULL, NULL, 3000) == 1 && r.fd_array[0] == u->s[pos]) good++;
            udpset_drain(u, pos);
        }
    }
    if (u) { udpset_free(u); free(u); }
    t->ok = good == 50;
    return 0;
}
TEST(select_8_threads_private_64_socket_sets)
{
    sel_thr t[8]; int i, ok = 0;
    XS_BEGIN();
    for (i = 0; i < 8; i++) { t[i].id = i; t[i].ok = 0; }
    EXPECT_EQ(xs_run_threads(8, sel_thread, t, sizeof t[0], 25000, NULL), 8);
    for (i = 0; i < 8; i++) ok += t[i].ok;
    EXPECT_EQ(ok, 8);
    xs_end();
}
