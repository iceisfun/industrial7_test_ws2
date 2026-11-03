/* select() with a custom FD_SETSIZE of 512 (defined before the Winsock headers): the SDK macros then admit
 * 512 sockets, and sets around the boundary (511, 512, 513 sockets) return exact counts and membership. */
#define FD_SETSIZE 512
#include "xs_selbody.h"

TEST(bigselect_fd_setsize_is_512) { CHECK(FD_SETSIZE == 512); EXPECT_EQ(sizeof(fd_set), sizeof(u_int) + 512 * sizeof(SOCKET) + 4); }

#define ONE(n, p, id) TEST(bigselect_##n##_one_ready_at_##id) { body_one_ready(n, p); }
ONE(511, 0, first) ONE(511, 255, middle) ONE(511, 510, last)
ONE(512, 0, first) ONE(512, 256, middle) ONE(512, 511, last)
ONE(513, 0, first) ONE(513, 256, middle) ONE(513, 511, index511) ONE(513, 512, last)
TEST(bigselect_511_all_ready) { body_all_ready(511); }
TEST(bigselect_512_all_ready) { body_all_ready(512); }
TEST(bigselect_513_all_ready) { body_all_ready(513); }
TEST(bigselect_512_none_ready) { body_none_ready(512); }
TEST(bigselect_513_none_ready) { body_none_ready(513); }
TEST(bigselect_511_every_5th) { body_every_kth(511, 5); }
TEST(bigselect_512_every_2nd) { body_every_kth(512, 2); }
TEST(bigselect_513_every_11th) { body_every_kth(513, 11); }
TEST(bigselect_512_all_writable) { body_all_writable(512); }
TEST(bigselect_513_all_writable) { body_all_writable(513); }
TEST(bigselect_512_read_and_write_sum) { body_read_and_write_sum(512); }
TEST(bigselect_513_read_and_write_sum) { body_read_and_write_sum(513); }
TEST(bigselect_513_level_triggered) { body_level_triggered(513); }
TEST(bigselect_513_closed_member_is_notsock) { body_closed_member(513); }

TEST(bigselect_fd_set_macro_stops_at_512)
{
    udpset *u = calloc(1, sizeof *u); fd_set *s = calloc(1, sizeof(fd_set)); int i, in = 0;
    XS_BEGIN();
    if (!udpset_make(u, 513)) { t_skip("cannot create 513 sockets"); udpset_free(u); free(u); free(s); xs_end(); return; }
    FD_ZERO(s);
    for (i = 0; i < 513; i++) FD_SET(u->s[i], s);
    EXPECT_EQ(s->fd_count, 512);
    for (i = 0; i < 513; i++) if (xs_isset(s, u->s[i])) in++;
    EXPECT_EQ(in, 512);
    udpset_free(u); free(u); free(s); xs_end();
}

/* A set built with the SDK-sized macro and select on it with all 512 entries ready. */
TEST(bigselect_macro_built_512_set_all_ready)
{
    udpset *u = calloc(1, sizeof *u); fd_set *s = calloc(1, sizeof(fd_set)); int i; struct timeval tv = { 3, 0 };
    XS_BEGIN();
    if (!udpset_make(u, 512)) { t_skip("cannot create 512 sockets"); udpset_free(u); free(u); free(s); xs_end(); return; }
    for (i = 0; i < 512; i++) { udpset_feed(u, i); FD_SET(u->s[i], s); }
    Sleep(60);
    EXPECT_EQ(select(0, s, NULL, NULL, &tv), 512);
    EXPECT_EQ(s->fd_count, 512);
    udpset_free(u); free(u); free(s); xs_end();
}

/* TCP pairs at the 65 boundary inside the enlarged TU stay correct (set larger than the SDK default). */
TEST(bigselect_100_tcp_data_and_eof) { body_tcp_pairs(100); }
