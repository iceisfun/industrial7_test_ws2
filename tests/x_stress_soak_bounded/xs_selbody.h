/* Shared select() scenario helpers for the default and the enlarged FD_SETSIZE translation units.
 * A "bigset" has the fd_set layout (count then socket array) with room for far more than FD_SETSIZE sockets;
 * it is passed to select() through a cast, which is the documented way to wait on more sockets than the SDK
 * array holds. */
#ifndef XS_SELBODY_H
#define XS_SELBODY_H
#include "xs.h"

#define BIG_MAX 1200
typedef struct { u_int fd_count; SOCKET fd_array[BIG_MAX]; } bigset;

typedef struct { SOCKET s[BIG_MAX]; struct sockaddr_in a[BIG_MAX]; SOCKET feeder; int n; } udpset;

static int udpset_make(udpset *u, int n)
{
    int i;
    memset(u, 0, sizeof *u);
    u->n = n;
    u->feeder = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < n; i++) {
        u->s[i] = xs_udp(&u->a[i]);
        if (u->s[i] == INVALID_SOCKET) { u->n = i; return 0; }
    }
    return u->feeder != INVALID_SOCKET;
}
static void udpset_free(udpset *u)
{
    int i;
    for (i = 0; i < u->n; i++) if (u->s[i] != INVALID_SOCKET) closesocket(u->s[i]);
    if (u->feeder != INVALID_SOCKET) closesocket(u->feeder);
}
static void udpset_feed(udpset *u, int i)
{
    sendto(u->feeder, "z", 1, 0, (struct sockaddr *)&u->a[i], sizeof u->a[i]);
}
static void udpset_drain(udpset *u, int i)
{
    char b[8]; xs_rcvtimeo(u->s[i], 1000); recv(u->s[i], b, sizeof b, 0);
}
static void bigset_fill(bigset *b, const SOCKET *s, int n)
{
    int i; b->fd_count = n; for (i = 0; i < n; i++) b->fd_array[i] = s[i];
}
static int bigset_has(const bigset *b, SOCKET s)
{
    u_int i; for (i = 0; i < b->fd_count; i++) if (b->fd_array[i] == s) return 1;
    return 0;
}
/* FD_ISSET would call into ws2_32 at link time; membership is checked by hand on the documented layout. */
static int xs_isset(const fd_set *s, SOCKET x)
{
    u_int i; for (i = 0; i < s->fd_count; i++) if (s->fd_array[i] == x) return 1;
    return 0;
}
static int do_select(bigset *r, bigset *w, bigset *e, int ms)
{
    struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return select(0, (fd_set *)r, (fd_set *)w, (fd_set *)e, &tv);
}

/* exactly one ready socket at position pos among n */
static void body_one_ready(int n, int pos)
{
    udpset *u = calloc(1, sizeof *u); bigset r;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    udpset_feed(u, pos);
    bigset_fill(&r, u->s, n);
    EXPECT_EQ(do_select(&r, NULL, NULL, 3000), 1);
    EXPECT_EQ(r.fd_count, 1);
    CHECK(bigset_has(&r, u->s[pos]));
    udpset_free(u); free(u); xs_end();
}
static void body_all_ready(int n)
{
    udpset *u = calloc(1, sizeof *u); bigset r; int i, miss = 0;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    for (i = 0; i < n; i++) udpset_feed(u, i);
    Sleep(50);
    bigset_fill(&r, u->s, n);
    EXPECT_EQ(do_select(&r, NULL, NULL, 3000), n);
    EXPECT_EQ(r.fd_count, n);
    for (i = 0; i < n; i++) if (!bigset_has(&r, u->s[i])) miss++;
    EXPECT_EQ(miss, 0);
    udpset_free(u); free(u); xs_end();
}
static void body_none_ready(int n)
{
    udpset *u = calloc(1, sizeof *u); bigset r;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    bigset_fill(&r, u->s, n);
    EXPECT_EQ(do_select(&r, NULL, NULL, 30), 0);
    EXPECT_EQ(r.fd_count, 0);
    udpset_free(u); free(u); xs_end();
}
static void body_every_kth(int n, int k)
{
    udpset *u = calloc(1, sizeof *u); bigset r; int i, want = 0, wrong = 0;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    for (i = 0; i < n; i += k) { udpset_feed(u, i); want++; }
    Sleep(50);
    bigset_fill(&r, u->s, n);
    EXPECT_EQ(do_select(&r, NULL, NULL, 3000), want);
    EXPECT_EQ(r.fd_count, want);
    for (i = 0; i < n; i++) if (bigset_has(&r, u->s[i]) != (i % k == 0)) wrong++;
    EXPECT_EQ(wrong, 0);
    udpset_free(u); free(u); xs_end();
}
static void body_all_writable(int n)
{
    udpset *u = calloc(1, sizeof *u); bigset w; int i, miss = 0;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    bigset_fill(&w, u->s, n);
    EXPECT_EQ(do_select(NULL, &w, NULL, 3000), n);
    EXPECT_EQ(w.fd_count, n);
    for (i = 0; i < n; i++) if (!bigset_has(&w, u->s[i])) miss++;
    EXPECT_EQ(miss, 0);
    udpset_free(u); free(u); xs_end();
}
/* read set and write set over the same n sockets, only the last one readable: total = 1 + n */
static void body_read_and_write_sum(int n)
{
    udpset *u = calloc(1, sizeof *u); bigset r, w;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    udpset_feed(u, n - 1);
    Sleep(30);
    bigset_fill(&r, u->s, n); bigset_fill(&w, u->s, n);
    EXPECT_EQ(do_select(&r, &w, NULL, 3000), n + 1);
    EXPECT_EQ(r.fd_count, 1);
    EXPECT_EQ(w.fd_count, n);
    udpset_free(u); free(u); xs_end();
}
/* a ready socket is reported again by the next call until its data is consumed; then it drops out */
static void body_level_triggered(int n)
{
    udpset *u = calloc(1, sizeof *u); bigset r; int i, again = 0;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    udpset_feed(u, n / 2);
    for (i = 0; i < 20; i++) {
        bigset_fill(&r, u->s, n);
        if (do_select(&r, NULL, NULL, 3000) == 1 && r.fd_count == 1 && r.fd_array[0] == u->s[n / 2]) again++;
    }
    EXPECT_EQ(again, 20);
    udpset_drain(u, n / 2);
    bigset_fill(&r, u->s, n);
    EXPECT_EQ(do_select(&r, NULL, NULL, 30), 0);
    udpset_free(u); free(u); xs_end();
}
/* connected stream sockets: peer data and peer shutdown both read as ready; unconnected-yet-quiet ones do not */
static void body_tcp_pairs(int n)
{
    SOCKET *c = calloc(n, sizeof(SOCKET)), *s = calloc(n, sizeof(SOCKET)); bigset r; int i, made = 0, wrong = 0, want = 0;
    XS_BEGIN();
    for (i = 0; i < n; i++) {
        LINGER lg = { 1, 0 };
        if (xs_pair(&c[i], &s[i])) { made++; setsockopt(c[i], SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
                                     setsockopt(s[i], SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg); }
    }
    if (made != n) { t_skip("only %d of %d pairs", made, n); }
    else {
        for (i = 0; i < n; i++) {
            if (i % 3 == 0) { send(c[i], "q", 1, 0); want++; }
            else if (i % 3 == 1) { shutdown(c[i], SD_SEND); want++; }
        }
        Sleep(50);
        bigset_fill(&r, s, n);
        EXPECT_EQ(do_select(&r, NULL, NULL, 3000), want);
        for (i = 0; i < n; i++) if (bigset_has(&r, s[i]) != (i % 3 != 2)) wrong++;
        EXPECT_EQ(wrong, 0);
    }
    for (i = 0; i < n; i++) { if (c[i] != INVALID_SOCKET && c[i]) closesocket(c[i]); if (s[i] != INVALID_SOCKET && s[i]) closesocket(s[i]); }
    free(c); free(s); xs_end();
}
/* sets that contain an invalid socket value: select fails with WSAENOTSOCK and reports -1 */
static void body_closed_member(int n)
{
    udpset *u = calloc(1, sizeof *u); bigset r; SOCKET victim;
    XS_BEGIN();
    if (!udpset_make(u, n)) { t_skip("cannot create %d datagram sockets", n); udpset_free(u); free(u); xs_end(); return; }
    victim = u->s[n - 1]; closesocket(victim);
    bigset_fill(&r, u->s, n);
    WSASetLastError(0);
    EXPECT_EQ(do_select(&r, NULL, NULL, 30), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    u->s[n - 1] = INVALID_SOCKET;
    udpset_free(u); free(u); xs_end();
}
#endif
