/* Bulk transfers: 32 MB over TCP in several I/O styles checked by an exact byte count and a digest computed
 * independently by sender and receiver; 100000 small datagrams over UDP where only relations are asserted
 * (received <= sent, no datagram twice, none corrupted, per-sender order preserved, every sendto accepted). */
#include "xs.h"

#define MB (1024 * 1024)
#define TOTAL (32LL * MB)

enum { S_BLOCK, S_NONBLOCK, S_OVERLAPPED };

typedef struct {
    SOCKET s; int style; long long total; int chunk; unsigned long long seed;
    xs_gen g; long long moved; int fail;
} xfer_t;

static int wait_ready(SOCKET s, int write)
{
    fd_set f; struct timeval tv = { XS_WAIT_MS / 1000, 0 };
    f.fd_count = 1; f.fd_array[0] = s;
    return select(0, write ? NULL : &f, write ? &f : NULL, NULL, &tv) == 1;
}

static int io_send(int style, SOCKET s, const char *b, int n)
{
    if (style == S_OVERLAPPED) {
        WSAOVERLAPPED ov; WSABUF wb = { n, (char *)b }; DWORD got = 0, fl = 0; int r;
        memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
        r = WSASend(s, &wb, 1, &got, 0, &ov, NULL);
        if (r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, XS_WAIT_MS * 2) != WAIT_OBJECT_0) { CancelIoEx((HANDLE)s, &ov); WaitForSingleObject(ov.hEvent, XS_WAIT_MS); WSACloseEvent(ov.hEvent); return -1; }
            r = WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl) ? 0 : -1;
        }
        WSACloseEvent(ov.hEvent);
        return r == 0 ? (int)got : -1;
    }
    for (;;) {
        int r = send(s, b, n, 0);
        if (r >= 0) return r;
        if (style == S_NONBLOCK && WSAGetLastError() == WSAEWOULDBLOCK) { if (!wait_ready(s, 1)) return -1; continue; }
        return -1;
    }
}
static int io_recv(int style, SOCKET s, char *b, int n)
{
    if (style == S_OVERLAPPED) {
        WSAOVERLAPPED ov; WSABUF wb = { n, b }; DWORD got = 0, fl = 0; int r;
        memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
        r = WSARecv(s, &wb, 1, &got, &fl, &ov, NULL);
        if (r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, XS_WAIT_MS * 2) != WAIT_OBJECT_0) { CancelIoEx((HANDLE)s, &ov); WaitForSingleObject(ov.hEvent, XS_WAIT_MS); WSACloseEvent(ov.hEvent); return -1; }
            r = WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl) ? 0 : -1;
        }
        WSACloseEvent(ov.hEvent);
        return r == 0 ? (int)got : -1;
    }
    for (;;) {
        int r = recv(s, b, n, 0);
        if (r >= 0) return r;
        if (style == S_NONBLOCK && WSAGetLastError() == WSAEWOULDBLOCK) { if (!wait_ready(s, 0)) return -1; continue; }
        return -1;
    }
}

static DWORD WINAPI tx_main(void *p)
{
    xfer_t *x = (xfer_t *)p;
    unsigned char *buf = malloc(x->chunk);
    long long left = x->total; int step = 0;
    xs_gen_init(&x->g, x->seed);
    while (left > 0) {
        int n = x->chunk; int sent = 0;
        if (x->chunk > 1 && (step++ & 3) == 3) n = x->chunk / 2 + 1;     /* mix sizes: odd, shorter sends */
        if (n > left) n = (int)left;
        xs_gen_fill(&x->g, buf, n);
        while (sent < n) {
            int r = io_send(x->style, x->s, (char *)buf + sent, n - sent);
            if (r <= 0) { x->fail = 1; free(buf); return 1; }
            sent += r;
        }
        x->moved += n; left -= n;
    }
    shutdown(x->s, SD_SEND);
    free(buf);
    return 0;
}
static DWORD WINAPI rx_main(void *p)
{
    xfer_t *x = (xfer_t *)p;
    char *buf = malloc(x->chunk);
    xs_gen_init(&x->g, x->seed);
    for (;;) {
        int r = io_recv(x->style, x->s, buf, x->chunk);
        if (r < 0) { x->fail = 1; break; }
        if (r == 0) break;
        xs_gen_eat(&x->g, (unsigned char *)buf, r);
        x->moved += r;
    }
    free(buf);
    return 0;
}

/* one direction: sender thread on client socket, receiver thread on accepted socket (swap: reversed roles) */
static void tcp_one_way(int tx_style, int rx_style, int tx_chunk, int rx_chunk, long long total, int nodelay, int rcvbuf, int swap)
{
    SOCKET c, s; xfer_t t, r; HANDLE th[2];
    XS_BEGIN();
    if (!xs_pair(&c, &s)) { t_skip("no pair"); xs_end(); return; }
    if (nodelay) { int one = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one); }
    if (rcvbuf) setsockopt(swap ? c : s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof rcvbuf);
    if (tx_style == S_NONBLOCK || rx_style == S_NONBLOCK) {
        u_long nb = 1;
        if (tx_style == S_NONBLOCK) ioctlsocket(swap ? s : c, FIONBIO, &nb);
        if (rx_style == S_NONBLOCK) ioctlsocket(swap ? c : s, FIONBIO, &nb);
    }
    memset(&t, 0, sizeof t); memset(&r, 0, sizeof r);
    t.s = swap ? s : c; t.style = tx_style; t.total = total; t.chunk = tx_chunk; t.seed = 0x1234567;
    r.s = swap ? c : s; r.style = rx_style; r.total = total; r.chunk = rx_chunk; r.seed = 0x1234567;
    th[0] = CreateThread(NULL, 0, rx_main, &r, 0, NULL);
    th[1] = CreateThread(NULL, 0, tx_main, &t, 0, NULL);
    EXPECT_EQ(WaitForSingleObject(th[1], 28000), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(th[0], 28000), WAIT_OBJECT_0);
    CloseHandle(th[0]); CloseHandle(th[1]);
    EXPECT_EQ(t.fail, 0);
    EXPECT_EQ(r.fail, 0);
    CHECKF(t.moved == total, "sent %lld", t.moved);
    CHECKF(r.moved == total, "received %lld", r.moved);
    CHECK(t.g.hash == r.g.hash);
    CHECK(t.g.count == r.g.count);
    closesocket(c); closesocket(s);
    xs_end();
}
TEST(bulk_tcp_32mb_blocking_64k)                 { tcp_one_way(S_BLOCK, S_BLOCK, 65536, 65536, TOTAL, 0, 0, 0); }
TEST(bulk_tcp_32mb_blocking_1mb_sends_tiny_reads){ tcp_one_way(S_BLOCK, S_BLOCK, MB, 1500, TOTAL / 4, 0, 0, 0); }
TEST(bulk_tcp_32mb_blocking_tiny_sends_big_reads){ tcp_one_way(S_BLOCK, S_BLOCK, 777, MB, TOTAL / 8, 1, 0, 0); }
TEST(bulk_tcp_32mb_odd_total_and_chunks)         { tcp_one_way(S_BLOCK, S_BLOCK, 40009, 7001, TOTAL + 5, 0, 0, 0); }
TEST(bulk_tcp_32mb_nonblocking_select_both_sides){ tcp_one_way(S_NONBLOCK, S_NONBLOCK, 32768, 32768, TOTAL, 0, 0, 0); }
TEST(bulk_tcp_32mb_overlapped_event_both_sides)  { tcp_one_way(S_OVERLAPPED, S_OVERLAPPED, 65536, 65536, TOTAL, 0, 0, 0); }
TEST(bulk_tcp_32mb_overlapped_send_blocking_recv){ tcp_one_way(S_OVERLAPPED, S_BLOCK, 131072, 8192, TOTAL, 0, 0, 0); }
TEST(bulk_tcp_32mb_blocking_send_overlapped_recv){ tcp_one_way(S_BLOCK, S_OVERLAPPED, 8192, 131072, TOTAL, 0, 0, 0); }
TEST(bulk_tcp_32mb_small_receive_buffer)         { tcp_one_way(S_BLOCK, S_BLOCK, 65536, 65536, TOTAL, 0, 4096, 0); }
TEST(bulk_tcp_32mb_roles_swapped)                { tcp_one_way(S_BLOCK, S_BLOCK, 65536, 65536, TOTAL, 0, 0, 1); }
TEST(bulk_tcp_8mb_one_byte_receive_calls_sampled)
{
    /* receiver reads 1 byte at a time for the first 64 KB only, then switches to big reads: totals still exact */
    SOCKET c, s; xfer_t t; xs_gen g; long long got = 0; char *buf = malloc(MB); HANDLE th;
    long long total = 8LL * MB; int r;
    XS_BEGIN();
    if (!xs_pair(&c, &s)) { t_skip("no pair"); xs_end(); return; }
    memset(&t, 0, sizeof t);
    t.s = c; t.style = S_BLOCK; t.total = total; t.chunk = 65536; t.seed = 99;
    xs_gen_init(&g, 99);
    xs_rcvtimeo(s, XS_WAIT_MS);
    th = CreateThread(NULL, 0, tx_main, &t, 0, NULL);
    while (got < total) {
        int want = got < 65536 ? 1 : MB;
        r = recv(s, buf, want, 0);
        if (r <= 0) break;
        xs_gen_eat(&g, (unsigned char *)buf, r); got += r;
    }
    WaitForSingleObject(th, 20000); CloseHandle(th);
    CHECKF(got == total, "got %lld", got);
    CHECK(g.hash == t.g.hash);
    EXPECT_EQ(recv(s, buf, 8, 0), 0);
    closesocket(c); closesocket(s); free(buf);
    xs_end();
}

/* Both directions at once on one connection: 4 threads, 16 MB each way. */
TEST(bulk_tcp_16mb_each_way_simultaneously)
{
    SOCKET c, s; xfer_t tc, ts, rc, rs; HANDLE th[4]; long long total = 16LL * MB;
    XS_BEGIN();
    if (!xs_pair(&c, &s)) { t_skip("no pair"); xs_end(); return; }
    memset(&tc, 0, sizeof tc); memset(&ts, 0, sizeof ts); memset(&rc, 0, sizeof rc); memset(&rs, 0, sizeof rs);
    tc.s = c; tc.total = total; tc.chunk = 32768; tc.seed = 5;
    ts.s = s; ts.total = total; ts.chunk = 50000; ts.seed = 6;
    rc.s = c; rc.total = total; rc.chunk = 65536; rc.seed = 6;      /* c receives what s sends */
    rs.s = s; rs.total = total; rs.chunk = 16384; rs.seed = 5;
    th[0] = CreateThread(NULL, 0, rx_main, &rc, 0, NULL);
    th[1] = CreateThread(NULL, 0, rx_main, &rs, 0, NULL);
    th[2] = CreateThread(NULL, 0, tx_main, &tc, 0, NULL);
    th[3] = CreateThread(NULL, 0, tx_main, &ts, 0, NULL);
    { int i; for (i = 0; i < 4; i++) { EXPECT_EQ(WaitForSingleObject(th[i], 28000), WAIT_OBJECT_0); CloseHandle(th[i]); } }
    CHECKF(rc.moved == total && rs.moved == total && tc.moved == total && ts.moved == total, "moved %lld %lld %lld %lld", tc.moved, ts.moved, rc.moved, rs.moved);
    CHECK(tc.g.hash == rs.g.hash);
    CHECK(ts.g.hash == rc.g.hash);
    EXPECT_EQ(tc.fail + ts.fail + rc.fail + rs.fail, 0);
    closesocket(c); closesocket(s);
    xs_end();
}

/* Four parallel connections of 8 MB each = 32 MB total. */
TEST(bulk_tcp_four_connections_8mb_each)
{
    SOCKET c[4], s[4]; xfer_t t[4], r[4]; HANDLE th[8]; int i, bad = 0; long long sum = 0;
    XS_BEGIN();
    for (i = 0; i < 4; i++) if (!xs_pair(&c[i], &s[i])) { t_skip("no pair"); xs_end(); return; }
    for (i = 0; i < 4; i++) {
        memset(&t[i], 0, sizeof t[i]); memset(&r[i], 0, sizeof r[i]);
        t[i].s = c[i]; t[i].total = 8LL * MB; t[i].chunk = 16384 + i * 1000; t[i].seed = 100 + i;
        r[i].s = s[i]; r[i].total = 8LL * MB; r[i].chunk = 65536 - i * 3000; r[i].seed = 100 + i;
        th[i] = CreateThread(NULL, 0, rx_main, &r[i], 0, NULL);
        th[4 + i] = CreateThread(NULL, 0, tx_main, &t[i], 0, NULL);
    }
    for (i = 0; i < 8; i++) { EXPECT_EQ(WaitForSingleObject(th[i], 28000), WAIT_OBJECT_0); CloseHandle(th[i]); }
    for (i = 0; i < 4; i++) { if (t[i].g.hash != r[i].g.hash || r[i].moved != 8LL * MB || t[i].fail || r[i].fail) bad++; sum += r[i].moved; }
    EXPECT_EQ(bad, 0);
    CHECKF(sum == TOTAL, "sum %lld", sum);
    for (i = 0; i < 4; i++) { closesocket(c[i]); closesocket(s[i]); }
    xs_end();
}

/* After a 32 MB transfer the connection is still usable for a small echo and ends cleanly. */
TEST(bulk_tcp_connection_usable_after_large_transfer)
{
    SOCKET c, s; xfer_t t, r; HANDLE th[2]; char b[8] = { 0 };
    XS_BEGIN();
    if (!xs_pair(&c, &s)) { t_skip("no pair"); xs_end(); return; }
    memset(&t, 0, sizeof t); memset(&r, 0, sizeof r);
    t.s = c; t.total = 16LL * MB; t.chunk = 65536; t.seed = 3; r.s = s; r.total = t.total; r.chunk = 65536; r.seed = 3;
    th[0] = CreateThread(NULL, 0, rx_main, &r, 0, NULL); th[1] = CreateThread(NULL, 0, tx_main, &t, 0, NULL);
    WaitForSingleObject(th[1], 28000); WaitForSingleObject(th[0], 28000); CloseHandle(th[0]); CloseHandle(th[1]);
    CHECK(r.moved == t.total && r.g.hash == t.g.hash);
    /* the send side was shut down; the reverse direction still works */
    xs_rcvtimeo(c, XS_WAIT_MS);
    EXPECT_EQ(send(s, "pong", 4, 0), 4);
    EXPECT_EQ(recv(c, b, 8, 0), 4);
    EXPECT_EQ(memcmp(b, "pong", 4), 0);
    WSASetLastError(0);
    EXPECT_EQ(send(c, "x", 1, 0), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    closesocket(c); closesocket(s);
    xs_end();
}

/* ---- UDP: 100000 small datagrams -------------------------------------------------------------------------- */
typedef struct { int sender, seq, check, pad[5]; } dgram;   /* 32 bytes */

typedef struct {
    SOCKET rx; volatile LONG received, corrupt, dup, reordered, stop, send_fail;
    int nsenders, per_sender; int last[8]; unsigned char *seen;    /* seen[sender*per_sender+seq] */
    int expect_size;
} udp_t;
static udp_t *ug;

static DWORD WINAPI udp_receiver(void *p)
{
    udp_t *u = (udp_t *)p; dgram d;
    for (;;) {
        int r = recv(u->rx, (char *)&d, sizeof d, 0);
        if (r < 0) { if (WSAGetLastError() == WSAETIMEDOUT) { if (u->stop) break; continue; } break; }
        if (r != sizeof d || d.sender < 0 || d.sender >= u->nsenders || d.seq < 0 || d.seq >= u->per_sender ||
            d.check != (d.sender * 1000003 ^ d.seq * 31 ^ 0x5a5a)) { InterlockedIncrement(&u->corrupt); continue; }
        if (u->seen[d.sender * u->per_sender + d.seq]++) InterlockedIncrement(&u->dup);
        if (d.seq < u->last[d.sender]) InterlockedIncrement(&u->reordered); else u->last[d.sender] = d.seq;
        InterlockedIncrement(&u->received);
    }
    return 0;
}
typedef struct { udp_t *u; SOCKET s; int id; struct sockaddr_in to; int connected; int sent; } usend_t;
static DWORD WINAPI udp_sender(void *p)
{
    usend_t *a = (usend_t *)p; int k;
    for (k = 0; k < a->u->per_sender; k++) {
        dgram d; int r, spins = 0;
        memset(&d, 0, sizeof d);
        d.sender = a->id; d.seq = k; d.check = a->id * 1000003 ^ k * 31 ^ 0x5a5a;
        /* flow control: do not run more than 3000 datagrams per sender ahead of the receiver */
        while ((long)(a->sent * a->u->nsenders) - (long)a->u->received > 3000 && spins++ < 2000) Sleep(0);
        for (;;) {
            r = a->connected ? send(a->s, (const char *)&d, sizeof d, 0)
                             : sendto(a->s, (const char *)&d, sizeof d, 0, (struct sockaddr *)&a->to, sizeof a->to);
            if (r == sizeof d) { a->sent++; break; }
            if (WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEWOULDBLOCK) { Sleep(1); continue; }
            InterlockedIncrement(&a->u->send_fail); break;
        }
    }
    return 0;
}

static void udp_soak(int nsenders, int connected)
{
    udp_t *u = calloc(1, sizeof *u); usend_t sa[8]; HANDLE th[9]; struct sockaddr_in ra;
    int i, sent = 0, bufsz = 8 * MB, per = 100000 / nsenders;
    XS_BEGIN();
    u->nsenders = nsenders; u->per_sender = per;
    u->seen = calloc((size_t)nsenders * per, 1);
    u->rx = xs_udp(&ra);
    if (u->rx == INVALID_SOCKET) { t_skip("no receiver"); free(u->seen); free(u); xs_end(); return; }
    setsockopt(u->rx, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof bufsz);
    xs_rcvtimeo(u->rx, 700);
    th[8] = CreateThread(NULL, 0, udp_receiver, u, 0, NULL);
    for (i = 0; i < nsenders; i++) {
        memset(&sa[i], 0, sizeof sa[i]);
        sa[i].u = u; sa[i].id = i; sa[i].to = ra; sa[i].connected = connected;
        sa[i].s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (connected) connect(sa[i].s, (struct sockaddr *)&ra, sizeof ra);
        th[i] = CreateThread(NULL, 0, udp_sender, &sa[i], 0, NULL);
    }
    for (i = 0; i < nsenders; i++) { EXPECT_EQ(WaitForSingleObject(th[i], 28000), WAIT_OBJECT_0); CloseHandle(th[i]); sent += sa[i].sent; }
    Sleep(300);
    u->stop = 1;
    EXPECT_EQ(WaitForSingleObject(th[8], 8000), WAIT_OBJECT_0);
    CloseHandle(th[8]);
    EXPECT_EQ(u->send_fail, 0);
    EXPECT_EQ(sent, per * nsenders);
    CHECKF(u->received <= sent, "received %ld of %d", (long)u->received, sent);
    CHECKF(u->received > 0, "nothing received");
    EXPECT_EQ(u->corrupt, 0);
    EXPECT_EQ(u->dup, 0);
    EXPECT_EQ(u->reordered, 0);
    t_note("udp %d senders connected=%d: loss accounted as sent-received only", nsenders, connected);
    for (i = 0; i < nsenders; i++) closesocket(sa[i].s);
    closesocket(u->rx); free(u->seen); free(u);
    xs_end();
}
TEST(bulk_udp_100k_one_sender_sendto)            { udp_soak(1, 0); }
TEST(bulk_udp_100k_one_sender_connected_send)    { udp_soak(1, 1); }
TEST(bulk_udp_100k_four_senders_sendto)          { udp_soak(4, 0); }
TEST(bulk_udp_100k_eight_senders_connected)      { udp_soak(8, 1); }

/* 100k datagrams round-robin over 50 receiver sockets: per-socket counts never exceed what was sent to it. */
TEST(bulk_udp_100k_round_robin_over_50_receivers)
{
    enum { R = 50, N = 100000 };
    SOCKET rs[R], tx; struct sockaddr_in ad[R]; fd_set f; int i, sent_to[R] = { 0 }, got_to[R] = { 0 }, total_got = 0, bad = 0, idle = 0;
    int bufsz = 4 * MB;
    XS_BEGIN();
    tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < R; i++) { rs[i] = xs_udp(&ad[i]); setsockopt(rs[i], SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof bufsz); }
    for (i = 0; i < N; i++) {
        int t = i % R; dgram d; int r;
        memset(&d, 0, sizeof d); d.sender = t; d.seq = i; d.check = t * 1000003 ^ i * 31 ^ 0x5a5a;
        for (;;) {
            r = sendto(tx, (const char *)&d, sizeof d, 0, (struct sockaddr *)&ad[t], sizeof ad[t]);
            if (r == sizeof d) { sent_to[t]++; break; }
            if (WSAGetLastError() == WSAENOBUFS) { Sleep(1); continue; }
            bad++; break;
        }
        if ((i % 1000) == 999) {   /* drain periodically so the sockets do not overflow */
            int k;
            for (k = 0; k < R; k++) {
                for (;;) {
                    dgram e; struct timeval tv = { 0, 0 };
                    f.fd_count = 1; f.fd_array[0] = rs[k];
                    if (select(0, &f, NULL, NULL, &tv) != 1) break;
                    if (recv(rs[k], (char *)&e, sizeof e, 0) == sizeof e) {
                        if (e.sender != k || e.check != (e.sender * 1000003 ^ e.seq * 31 ^ 0x5a5a)) bad++;
                        got_to[k]++; total_got++;
                    } else break;
                }
            }
        }
    }
    for (;;) {   /* final drain: stop after a quiet period */
        int k, any = 0;
        for (k = 0; k < R; k++) {
            dgram e; struct timeval tv = { 0, 20000 };
            f.fd_count = 1; f.fd_array[0] = rs[k];
            while (select(0, &f, NULL, NULL, &tv) == 1 && recv(rs[k], (char *)&e, sizeof e, 0) == sizeof e) {
                if (e.sender != k || e.check != (e.sender * 1000003 ^ e.seq * 31 ^ 0x5a5a)) bad++;
                got_to[k]++; total_got++; any = 1; f.fd_count = 1; f.fd_array[0] = rs[k];
            }
        }
        if (!any && ++idle >= 2) break;
    }
    EXPECT_EQ(bad, 0);
    { int over = 0, sumsent = 0; for (i = 0; i < R; i++) { if (got_to[i] > sent_to[i]) over++; sumsent += sent_to[i]; }
      EXPECT_EQ(over, 0); EXPECT_EQ(sumsent, N); CHECKF(total_got <= N && total_got > 0, "got %d", total_got); }
    for (i = 0; i < R; i++) closesocket(rs[i]);
    closesocket(tx);
    xs_end();
}

/* Receiver buffer smaller than the datagram: each recv fails with WSAEMSGSIZE and consumes exactly one datagram.
 * Failures counted <= sent; a following full-size recv finds nothing left once all are consumed. */
TEST(bulk_udp_20k_truncated_receives_consume_one_datagram_each)
{
    enum { N = 20000 };
    struct sockaddr_in ra; SOCKET rx_s, tx;
    int i, sent = 0, trunc = 0, other = 0; int bufsz = 8 * MB; dgram d; char small[8];
    XS_BEGIN();
    rx_s = xs_udp(&ra); tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(rx_s, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof bufsz);
    xs_rcvtimeo(rx_s, 300);
    memset(&d, 0, sizeof d);
    for (i = 0; i < N; i++) {
        d.seq = i;
        if (sendto(tx, (const char *)&d, sizeof d, 0, (struct sockaddr *)&ra, sizeof ra) == sizeof d) sent++;
        if ((i % 500) == 499) Sleep(1);
    }
    for (;;) {
        int r = recv(rx_s, small, sizeof small, 0);
        if (r == SOCKET_ERROR && WSAGetLastError() == WSAEMSGSIZE) { trunc++; continue; }
        if (r == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT) break;
        other++; break;
    }
    EXPECT_EQ(sent, N);
    EXPECT_EQ(other, 0);
    CHECKF(trunc <= sent && trunc > 0, "truncated %d of %d", trunc, sent);
    closesocket(rx_s); closesocket(tx);
    xs_end();
}

/* Zero-length datagrams: 50000 sent; each received one returns 0 bytes without error; count <= sent. */
TEST(bulk_udp_50k_zero_length_datagrams)
{
    struct sockaddr_in ra; SOCKET rx_s, tx;
    int i, sent = 0, got = 0, bad = 0; int bufsz = 8 * MB; char b[4];
    XS_BEGIN();
    rx_s = xs_udp(&ra); tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(rx_s, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof bufsz);
    xs_rcvtimeo(rx_s, 300);
    for (i = 0; i < 50000; i++) {
        if (sendto(tx, b, 0, 0, (struct sockaddr *)&ra, sizeof ra) == 0) sent++;
        if ((i % 500) == 499) Sleep(1);
    }
    for (;;) {
        int r = recv(rx_s, b, sizeof b, 0);
        if (r == 0) { got++; continue; }
        if (r == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT) break;
        bad++; break;
    }
    EXPECT_EQ(sent, 50000);
    EXPECT_EQ(bad, 0);
    CHECKF(got <= sent && got > 0, "got %d of %d", got, sent);
    closesocket(rx_s); closesocket(tx);
    xs_end();
}
