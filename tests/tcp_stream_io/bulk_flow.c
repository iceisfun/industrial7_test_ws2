/* Bulk transfer and flow control on TCP loopback pairs: multi-megabyte transfers in both directions,
 * non-blocking send back-pressure (WSAEWOULDBLOCK), recovery once the peer drains, buffer-size options as
 * relations only, concurrent senders and receivers, and many sequential connections. Measured: byte counts,
 * content integrity, return values and error codes. */
#include "ts.h"

#define MB (1 << 20)

static void run_transfer(long long total, int wchunk, int rchunk, int rdelay, unsigned seed)
{
    SOCKET c, s; ts_job wj = { 0 }, rj = { 0 }; HANDLE tw, tr;
    NEED_PAIR(c, s);
    wj.s = c; wj.seed = seed; wj.total = total; wj.chunk = wchunk;
    rj.s = s; rj.seed = seed; rj.chunk = rchunk; rj.delay_ms = rdelay;
    tr = ts_start(ts_reader, &rj);
    tw = ts_start(ts_writer, &wj);
    CHECK(ts_join(tw, 40000));
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    CHECK(ts_join(tr, 40000));
    EXPECT_EQ(wj.total, total);
    EXPECT_EQ(rj.total, total);
    CHECK(wj.ok);
    CHECK(rj.ok);
    EXPECT_EQ(rj.final_ret, 0);
    ts_close2(c, s);
}

TEST(bulk_transfer_1mb_default_chunks)       { run_transfer(1 * MB, 4096, 4096, 0, 1); }
TEST(bulk_transfer_2mb_large_send_calls)     { run_transfer(2 * MB, 256 * 1024, 4096, 0, 2); }
TEST(bulk_transfer_2mb_large_recv_calls)     { run_transfer(2 * MB, 1000, 256 * 1024, 0, 3); }
TEST(bulk_transfer_3mb_odd_chunk_sizes)      { run_transfer(3 * MB + 17, 7919, 6007, 0, 4); }
TEST(bulk_transfer_1mb_one_kib_chunks)       { run_transfer(1 * MB, 1024, 1024, 0, 5); }
TEST(bulk_transfer_256kb_slow_reader)        { run_transfer(256 * 1024, 4096, 2048, 1, 6); }
TEST(bulk_transfer_4mb_single_send_call)     { run_transfer(4 * MB, 4 * MB, 65536, 0, 7); }
TEST(bulk_transfer_single_byte_total)        { run_transfer(1, 1, 16, 0, 8); }
TEST(bulk_transfer_zero_bytes_is_just_eof)   { run_transfer(0, 100, 100, 0, 9); }

TEST(bulk_full_duplex_transfer)
{
    SOCKET c, s; ts_job w1 = { 0 }, r1 = { 0 }, w2 = { 0 }, r2 = { 0 }; HANDLE h[4];
    NEED_PAIR(c, s);
    w1.s = c; w1.seed = 51; w1.total = 1500000; w1.chunk = 8000;
    r1.s = s; r1.seed = 51; r1.chunk = 5000;
    w2.s = s; w2.seed = 52; w2.total = 1200000; w2.chunk = 6000;
    r2.s = c; r2.seed = 52; r2.chunk = 9000;
    h[0] = ts_start(ts_reader, &r1); h[1] = ts_start(ts_reader, &r2);
    h[2] = ts_start(ts_writer, &w1); h[3] = ts_start(ts_writer, &w2);
    CHECK(ts_join(h[2], 40000)); CHECK(ts_join(h[3], 40000));
    shutdown(c, SD_SEND); shutdown(s, SD_SEND);
    CHECK(ts_join(h[0], 40000)); CHECK(ts_join(h[1], 40000));
    EXPECT_EQ(r1.total, 1500000);
    EXPECT_EQ(r2.total, 1200000);
    CHECK(r1.ok && r2.ok && w1.ok && w2.ok);
    ts_close2(c, s);
}

TEST(bulk_blocking_send_of_one_megabyte_returns_full_count)
{
    SOCKET c, s; ts_job rj = { 0 }; HANDLE th; char *buf = malloc(MB); int r;
    NEED_PAIR(c, s);
    rj.s = s; rj.seed = 61; rj.chunk = 16384;
    th = ts_start(ts_reader, &rj);
    ts_fill(buf, MB, 61, 0);
    r = send(c, buf, MB, 0);
    EXPECT_EQ(r, MB);                  /* a blocking stream send completes the whole request */
    shutdown(c, SD_SEND);
    CHECK(ts_join(th, 30000));
    EXPECT_EQ(rj.total, MB);
    CHECK(rj.ok);
    free(buf);
    ts_close2(c, s);
}

/* ---- non-blocking back-pressure --------------------------------------------- */

/* Fills the send path of c (non-blocking) until it refuses; returns the byte count accepted, or -1 if
 * the cap was reached without back-pressure. *err gets the error that ended the fill. */
static long long fill_until_blocked(SOCKET c, long long cap, int *err, int chunk)
{
    char *buf = malloc(chunk); long long total = 0;
    ts_nonblock(c, 1);
    *err = 0;
    for (;;) {
        int r;
        ts_fill(buf, chunk, 71, (unsigned long long)total);
        r = send(c, buf, chunk, 0);
        if (r < 0) { *err = WSAGetLastError(); break; }
        total += r;
        if (total >= cap) { free(buf); return -1; }
    }
    free(buf);
    return total;
}

TEST(bulk_nonblocking_send_eventually_wouldblock)
{
    SOCKET c, s; int err; long long n;
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); ts_close2(c, s); return; }
    EXPECT_EQ(err, WSAEWOULDBLOCK);
    CHECK(n > 0);
    ts_close2(c, s);
}

TEST(bulk_nonblocking_send_wouldblock_repeats_while_full)
{
    SOCKET c, s; int err; long long n;
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); ts_close2(c, s); return; }
    for (int i = 0; i < 3; i++) {
        WSASetLastError(0);
        EXPECT_EQ(send(c, "x", 1, 0), -1);
        EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    }
    ts_close2(c, s);
}

TEST(bulk_nonblocking_full_socket_is_not_writable_until_drained)
{
    SOCKET c, s; int err; long long n; char *b = malloc(65536);
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); free(b); ts_close2(c, s); return; }
    EXPECT_EQ(ts_writable(c, 100), 0);
    for (long long got = 0; got < n; ) { int r = recv(s, b, 65536, 0); if (r <= 0) break; got += r; }
    CHECK(ts_writable(c, TS_WAIT_MS));
    free(b);
    ts_close2(c, s);
}

TEST(bulk_nonblocking_everything_accepted_is_delivered_intact)
{
    SOCKET c, s; int err; long long n, got = 0; char *b = malloc(65536); int ok = 1;
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); free(b); ts_close2(c, s); return; }
    shutdown(c, SD_SEND);
    while (got < n) {
        int r = recv(s, b, 65536, 0);
        if (r <= 0) break;
        if (!ts_verify(b, r, 71, (unsigned long long)got)) ok = 0;
        got += r;
    }
    EXPECT_EQ(got, n);
    CHECK(ok);
    EXPECT_EQ(recv(s, b, 1, 0), 0);
    free(b);
    ts_close2(c, s);
}

TEST(bulk_nonblocking_send_resumes_after_drain)
{
    SOCKET c, s; int err; long long n, drained = 0; char *b = malloc(65536); int r;
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); free(b); ts_close2(c, s); return; }
    while (drained < n) { r = recv(s, b, 65536, 0); if (r <= 0) break; drained += r; }
    EXPECT_EQ(drained, n);
    CHECK(ts_writable(c, TS_WAIT_MS));
    EXPECT_EQ(send(c, "again", 5, 0), 5);
    EXPECT_EQ(ts_recv_n(s, b, 5), 5);
    CHECK(!memcmp(b, "again", 5));
    free(b);
    ts_close2(c, s);
}

TEST(bulk_nonblocking_large_single_send_is_partial_or_full)
{
    SOCKET c, s; char *buf = malloc(16 * MB); int r;
    NEED_PAIR(c, s);
    ts_nonblock(c, 1);
    memset(buf, 1, 16 * MB);
    WSASetLastError(0);
    r = send(c, buf, 16 * MB, 0);
    if (r < 0) {
        EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    } else {
        CHECK(r > 0 && r <= 16 * MB);
    }
    t_note("one non-blocking 16 MiB send: %s", r == 16 * MB ? "accepted whole" : r > 0 ? "accepted partly" : "refused");
    free(buf);
    ts_close2(c, s);
}

TEST(bulk_nonblocking_wsasend_full_is_wouldblock)
{
    SOCKET c, s; int err; long long n; WSABUF w; DWORD sent = 0xdead; char x = 'x';
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); ts_close2(c, s); return; }
    w.buf = &x; w.len = 1;
    WSASetLastError(0);
    EXPECT_EQ(WSASend(c, &w, 1, &sent, 0, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    ts_close2(c, s);
}

TEST(bulk_nonblocking_full_then_peer_reset_reports_reset)
{
    SOCKET c, s; int err; long long n;
    NEED_PAIR(c, s);
    n = fill_until_blocked(c, 256LL * MB, &err, 16384);
    if (n < 0) { t_skip("no back-pressure within the cap"); ts_close2(c, s); return; }
    ts_rst_close(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(send(c, "x", 1, 0), -1);
    CHECK(WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAECONNABORTED);
    closesocket(c);
}

TEST(bulk_blocking_send_unblocks_when_peer_drains)
{
    SOCKET c, s; ts_job rj = { 0 }; HANDLE th; char *buf = malloc(8 * MB); int r;
    NEED_PAIR(c, s);
    ts_fill(buf, 8 * MB, 81, 0);
    rj.s = s; rj.seed = 81; rj.chunk = 65536; rj.delay_ms = 0;
    th = ts_start(ts_reader, &rj);
    r = send(c, buf, 8 * MB, 0);
    EXPECT_EQ(r, 8 * MB);
    shutdown(c, SD_SEND);
    CHECK(ts_join(th, 40000));
    EXPECT_EQ(rj.total, 8 * MB);
    CHECK(rj.ok);
    free(buf);
    ts_close2(c, s);
}

/* ---- buffer options as relations ---------------------------------------------- */

TEST(bulk_sndbuf_rcvbuf_default_values_are_positive)
{
    SOCKET c, s; int v = 0, len = sizeof v;
    NEED_PAIR(c, s);
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&v, &len), 0);
    CHECK(v > 0);
    v = 0; len = sizeof v;
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_RCVBUF, (char *)&v, &len), 0);
    CHECK(v > 0);
    ts_close2(c, s);
}

TEST(bulk_sndbuf_set_then_get_is_not_smaller)
{
    SOCKET c, s; int v = 0, len = sizeof v;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(c, SOL_SOCKET, SO_SNDBUF, 256 * 1024), 0);
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&v, &len), 0);
    CHECK(v >= 256 * 1024);
    ts_close2(c, s);
}

TEST(bulk_rcvbuf_set_then_get_is_not_smaller)
{
    SOCKET c, s; int v = 0, len = sizeof v;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_RCVBUF, 128 * 1024), 0);
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, &len), 0);
    CHECK(v >= 128 * 1024);
    ts_close2(c, s);
}

TEST(bulk_buffer_option_changes_do_not_disturb_the_stream)
{
    SOCKET c, s; ts_job rj = { 0 }; HANDLE th; char *buf = malloc(500000);
    NEED_PAIR(c, s);
    rj.s = s; rj.seed = 91; rj.chunk = 8192;
    th = ts_start(ts_reader, &rj);
    ts_fill(buf, 500000, 91, 0);
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(ts_send_all(c, buf + i * 100000, 100000), 100000);
        ts_set_int(c, SOL_SOCKET, SO_SNDBUF, (i + 1) * 32 * 1024);
        ts_set_int(s, SOL_SOCKET, SO_RCVBUF, (i + 1) * 16 * 1024);
    }
    shutdown(c, SD_SEND);
    CHECK(ts_join(th, 20000));
    EXPECT_EQ(rj.total, 500000);
    CHECK(rj.ok);
    free(buf);
    ts_close2(c, s);
}

TEST(bulk_tiny_receive_buffer_still_transfers_everything)
{
    SOCKET c, s; ts_job wj = { 0 }, rj = { 0 }; HANDLE tw, tr;
    NEED_PAIR(c, s);
    ts_set_int(s, SOL_SOCKET, SO_RCVBUF, 4096);
    wj.s = c; wj.seed = 92; wj.total = 300000; wj.chunk = 10000;
    rj.s = s; rj.seed = 92; rj.chunk = 3000;
    tr = ts_start(ts_reader, &rj);
    tw = ts_start(ts_writer, &wj);
    CHECK(ts_join(tw, 40000));
    shutdown(c, SD_SEND);
    CHECK(ts_join(tr, 40000));
    EXPECT_EQ(rj.total, 300000);
    CHECK(rj.ok);
    ts_close2(c, s);
}

TEST(bulk_larger_send_buffer_accepts_not_less_before_blocking)
{
    SOCKET c1, s1, c2, s2; int err; long long small_n, big_n;
    NEED_NET();
    if (!ts_pair(&c1, &s1)) { t_skip("pair"); return; }
    if (!ts_pair(&c2, &s2)) { ts_close2(c1, s1); t_skip("pair"); return; }
    ts_set_int(c1, SOL_SOCKET, SO_SNDBUF, 8 * 1024);
    ts_set_int(c2, SOL_SOCKET, SO_SNDBUF, 512 * 1024);
    small_n = fill_until_blocked(c1, 256LL * MB, &err, 4096);
    big_n = fill_until_blocked(c2, 256LL * MB, &err, 4096);
    if (small_n < 0 || big_n < 0) t_skip("no back-pressure within the cap");
    else { t_note("send buffer relation holds: %d", big_n >= small_n); CHECK(big_n >= small_n); }
    ts_close2(c1, s1);
    ts_close2(c2, s2);
}

/* ---- concurrency and repetition ------------------------------------------------- */

typedef struct { SOCKET s; int count; int len; int ok; } burst;
static DWORD WINAPI burst_thread(LPVOID a)
{
    burst *b = a; char buf[256];
    b->ok = 1;
    for (int i = 0; i < b->count; i++) {
        memset(buf, 'A' + (int)(i % 26), b->len);
        if (send(b->s, buf, b->len, 0) != b->len) { b->ok = 0; break; }
    }
    return 0;
}

TEST(bulk_concurrent_senders_on_separate_connections)
{
    enum { N = 4 };
    SOCKET c[N], s[N]; burst bu[N]; HANDLE th[N]; ts_job rj[N]; HANDLE tr[N]; NEED_NET();
    for (int i = 0; i < N; i++) {
        if (!ts_pair(&c[i], &s[i])) { t_skip("pair"); for (int k = 0; k < i; k++) ts_close2(c[k], s[k]); return; }
    }
    for (int i = 0; i < N; i++) {
        memset(&rj[i], 0, sizeof rj[i]);
        rj[i].s = s[i]; rj[i].chunk = 1000; rj[i].seed = 0;
        bu[i].s = c[i]; bu[i].count = 500; bu[i].len = 100 + i;
    }
    for (int i = 0; i < N; i++) {
        /* readers only count bytes: the pattern check is not used for these streams */
        tr[i] = CreateThread(NULL, 0, ts_reader, &rj[i], 0, NULL);
        th[i] = CreateThread(NULL, 0, burst_thread, &bu[i], 0, NULL);
    }
    for (int i = 0; i < N; i++) { CHECK(ts_join(th[i], 30000)); shutdown(c[i], SD_SEND); }
    for (int i = 0; i < N; i++) {
        CHECK(ts_join(tr[i], 30000));
        EXPECT_EQ(rj[i].total, 500LL * (100 + i));
        CHECK(bu[i].ok);
    }
    for (int i = 0; i < N; i++) ts_close2(c[i], s[i]);
}

TEST(bulk_two_threads_send_on_one_socket_totals_match)
{
    SOCKET c, s; burst b1, b2; HANDLE t1, t2; ts_job rj = { 0 }; HANDLE tr;
    NEED_PAIR(c, s);
    rj.s = s; rj.chunk = 2000;
    tr = CreateThread(NULL, 0, ts_reader, &rj, 0, NULL);
    b1.s = c; b1.count = 1000; b1.len = 50; b1.ok = 0;
    b2.s = c; b2.count = 1000; b2.len = 70; b2.ok = 0;
    t1 = CreateThread(NULL, 0, burst_thread, &b1, 0, NULL);
    t2 = CreateThread(NULL, 0, burst_thread, &b2, 0, NULL);
    CHECK(ts_join(t1, 30000)); CHECK(ts_join(t2, 30000));
    shutdown(c, SD_SEND);
    CHECK(ts_join(tr, 30000));
    EXPECT_EQ(rj.total, 1000LL * 50 + 1000LL * 70);
    CHECK(b1.ok && b2.ok);
    ts_close2(c, s);
}

TEST(bulk_sequential_connections_reuse_cleanly)
{
    NEED_NET();
    for (int i = 0; i < 60; i++) {
        SOCKET c, s; char m[40], b[40]; int n = 1 + (i % 37);
        if (!ts_pair(&c, &s)) { CHECK(0); return; }
        ts_fill(m, n, 100 + i, 0);
        EXPECT_EQ(send(c, m, n, 0), n);
        EXPECT_EQ(ts_recv_n(s, b, n), n);
        CHECK(!memcmp(m, b, n));
        ts_close2(c, s);
    }
}

static DWORD WINAPI echo_thread(LPVOID a)
{
    SOCKET s = (SOCKET)(ULONG_PTR)a; char *b = malloc(65536);
    for (;;) {
        int r = recv(s, b, 65536, 0);
        if (r <= 0) break;
        if (ts_send_all(s, b, r) != r) break;
    }
    free(b);
    return 0;
}

TEST(bulk_echo_server_thread_round_trips_growing_sizes)
{
    SOCKET c, s; HANDLE th; char *buf = malloc(70000), *back = malloc(70000);
    static const int sizes[] = { 1, 2, 10, 100, 1000, 4096, 10000, 65535 };
    NEED_PAIR(c, s);
    th = CreateThread(NULL, 0, echo_thread, (LPVOID)(ULONG_PTR)s, 0, NULL);
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        int n = sizes[i];
        ts_fill(buf, n, 120 + i, 0);
        /* sender and receiver are the same thread: keep each request below what the stack will queue
           in both directions, so the echo cannot deadlock against our own unread data */
        EXPECT_EQ(ts_send_all(c, buf, n), n);
        EXPECT_EQ(ts_recv_n(c, back, n), n);
        CHECK(!memcmp(buf, back, n));
    }
    shutdown(c, SD_SEND);
    CHECK(ts_join(th, 10000));
    free(buf); free(back);
    ts_close2(c, s);
}
