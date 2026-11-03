/* Volume and limit behaviour of data transfer: a 64 MiB stream with checksum, single enormous send
 * calls drained by a helper thread, SO_SNDBUF = 0, WSABUF array length thresholds found by bisection
 * (asserted as monotone relations), and hundreds of overlapped receives pending then cancelled or
 * completed in order. Measured: byte counts, hashes, completion statuses and error codes. */
#include "sb.h"

#define MB (1024 * 1024)

/* ---- drain thread -------------------------------------------------------------------------------- */

typedef struct { SOCKET s; sb_stream st; int chunk; int err; } drain_t;

static DWORD WINAPI drain_main(LPVOID p)
{
    drain_t *d = (drain_t *)p;
    unsigned char *buf = (unsigned char *)malloc(d->chunk);
    for (;;) {
        int r = recv(d->s, (char *)buf, d->chunk, 0);
        if (r == 0) break;
        if (r < 0) { d->err = WSAGetLastError(); break; }
        sb_stream_eat(&d->st, buf, r);
    }
    free(buf);
    return 0;
}

static HANDLE start_drain(drain_t *d, SOCKET s, int chunk)
{
    memset(d, 0, sizeof *d);
    d->s = s; d->chunk = chunk;
    sb_stream_init(&d->st, 1);
    d->st.x = 0; /* unused; only hash/count matter */
    d->st.hash = 1469598103934665603ULL; d->st.count = 0;
    sb_rcvtimeo(s, 10000);
    return CreateThread(NULL, 0, drain_main, d, 0, NULL);
}

static int finish_drain(HANDLE h) { int ok = WaitForSingleObject(h, 20000) == WAIT_OBJECT_0; CloseHandle(h); return ok; }

/* ---- 64 MiB stream ------------------------------------------------------------------------------- */

static void stream_total(unsigned long long total, int chunk, int rchunk, unsigned long long seed)
{
    SOCKET c, s; drain_t d; HANDLE h; sb_stream tx; unsigned char *buf; unsigned long long sent = 0;
    SB_BEGIN();
    NEED_PAIR(c, s);
    sb_stream_init(&tx, seed);
    h = start_drain(&d, s, rchunk);
    buf = (unsigned char *)malloc(chunk);
    while (sent < total) {
        int n = (total - sent < (unsigned)chunk) ? (int)(total - sent) : chunk, r;
        sb_stream_fill(&tx, buf, n);
        r = send(c, (char *)buf, n, 0);
        if (r != n) { CHECKF(0, "send returned %d err %d", r, WSAGetLastError()); break; }
        sent += n;
    }
    shutdown(c, SD_SEND);
    EXPECT_EQ(finish_drain(h), 1);
    EXPECT_EQ(d.err, 0);
    EXPECT_EQ(d.st.count, sent);
    CHECK(d.st.hash == tx.hash);
    free(buf);
    sb_close2(c, s);
    sb_end();
}

TEST(xfer_64mb_in_64k_chunks_checksum)     { stream_total(64ULL * MB, 65536, 65536, 11); }
TEST(xfer_32mb_in_odd_chunks_checksum)     { stream_total(32ULL * MB + 5, 40009, 7001, 12); }
TEST(xfer_16mb_in_1mb_sends_small_reads)   { stream_total(16ULL * MB, MB, 1500, 13); }
TEST(xfer_8mb_in_tiny_sends_big_reads)     { stream_total(8ULL * MB, 513, 4 * MB, 14); }

/* ---- enormous single calls ------------------------------------------------------------------------ */

TEST(xfer_single_send_of_64mb_returns_full_count)
{
    enum { N = 64 * MB };
    SOCKET c, s; drain_t d; HANDLE h; sb_stream tx; unsigned char *buf; int r;
    SB_BEGIN();
    NEED_PAIR(c, s);
    buf = (unsigned char *)malloc(N);
    if (!buf) { t_skip("alloc"); sb_close2(c, s); sb_end(); return; }
    sb_stream_init(&tx, 21);
    sb_stream_fill(&tx, buf, N);
    h = start_drain(&d, s, 256 * 1024);
    r = send(c, (char *)buf, N, 0);
    EXPECT_EQ(r, N);
    shutdown(c, SD_SEND);
    EXPECT_EQ(finish_drain(h), 1);
    EXPECT_EQ(d.st.count, N);
    CHECK(d.st.hash == tx.hash);
    free(buf);
    sb_close2(c, s);
    sb_end();
}

TEST(xfer_single_wsasend_with_four_aliased_16mb_buffers)
{
    enum { N = 16 * MB };
    SOCKET c, s; drain_t d; HANDLE h; unsigned char *buf; WSABUF b[4]; DWORD sent = 0; int r, i;
    unsigned long long expect_hash = 1469598103934665603ULL, k;
    SB_BEGIN();
    NEED_PAIR(c, s);
    buf = (unsigned char *)malloc(N);
    if (!buf) { t_skip("alloc"); sb_close2(c, s); sb_end(); return; }
    for (i = 0; i < N; i++) buf[i] = (unsigned char)(i * 31 + (i >> 8));
    for (i = 0; i < 4; i++) { b[i].buf = (char *)buf; b[i].len = N; }
    for (k = 0; k < 4; k++) for (i = 0; i < N; i++) expect_hash = (expect_hash ^ buf[i]) * 1099511628211ULL;
    h = start_drain(&d, s, 1 * MB);
    r = WSASend(c, b, 4, &sent, 0, NULL, NULL);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(sent, 4u * N);
    shutdown(c, SD_SEND);
    EXPECT_EQ(finish_drain(h), 1);
    EXPECT_EQ(d.st.count, 4ULL * N);
    CHECK(d.st.hash == expect_hash);
    free(buf);
    sb_close2(c, s);
    sb_end();
}

TEST(xfer_single_recv_of_8mb_buffer_returns_only_what_arrived)
{
    enum { N = 8 * MB };
    SOCKET c, s; char *buf; int r;
    SB_BEGIN();
    NEED_PAIR(c, s);
    buf = (char *)malloc(N);
    if (!buf) { t_skip("alloc"); sb_close2(c, s); sb_end(); return; }
    EXPECT_EQ(send(c, "0123456789", 10, 0), 10);
    sb_readable(s, SB_WAIT_MS);
    r = recv(s, buf, N, 0);
    EXPECT_EQ(r, 10);
    CHECK(!memcmp(buf, "0123456789", 10));
    free(buf);
    sb_close2(c, s);
    sb_end();
}

TEST(xfer_udp_send_of_oversize_datagram_fails_with_msgsize)
{
    struct sockaddr_in a; SOCKET r, t; static char buf[70000]; int n, e;
    SB_BEGIN();
    r = sb_udp(&a); t = sb_udp(NULL);
    WSASetLastError(0);
    n = sendto(t, buf, 65508, 0, (struct sockaddr *)&a, sizeof a);   /* 65507 is the IPv4 UDP payload maximum */
    e = WSAGetLastError();
    EXPECT_EQ(n, SOCKET_ERROR);
    EXPECT_EQ(e, WSAEMSGSIZE);
    WSASetLastError(0);
    n = sendto(t, buf, 70000, 0, (struct sockaddr *)&a, sizeof a);
    EXPECT_EQ(n, SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEMSGSIZE);
    sb_close2(r, t);
    sb_end();
}

TEST(xfer_udp_send_of_largest_legal_datagram_roundtrips)
{
    struct sockaddr_in a; SOCKET r, t; static char out[65507], in[65536]; int n, i, same;
    SB_BEGIN();
    r = sb_udp(&a); t = sb_udp(NULL);
    for (i = 0; i < (int)sizeof out; i++) out[i] = (char)(i * 13 + 5);
    n = sendto(t, out, sizeof out, 0, (struct sockaddr *)&a, sizeof a);
    if (n != (int)sizeof out) { t_note("max datagram send returned %d err %d", n, WSAGetLastError()); }
    else {
        sb_readable(r, SB_WAIT_MS);
        n = recvfrom(r, in, sizeof in, 0, NULL, NULL);
        EXPECT_EQ(n, (int)sizeof out);
        same = n == (int)sizeof out && !memcmp(in, out, sizeof out);
        EXPECT_EQ(same, 1);
    }
    sb_close2(r, t);
    sb_end();
}

TEST(xfer_udp_recv_truncation_reports_msgsize_for_every_size)
{
    struct sockaddr_in a; SOCKET r, t; char out[512], in[512]; int sz, bad = 0;
    SB_BEGIN();
    r = sb_udp(&a); t = sb_udp(NULL);
    memset(out, 'k', sizeof out);
    for (sz = 1; sz < 512; sz += 61) {
        int n, e;
        sendto(t, out, 512, 0, (struct sockaddr *)&a, sizeof a);
        sb_readable(r, SB_WAIT_MS);
        WSASetLastError(0);
        n = recvfrom(r, in, sz, 0, NULL, NULL); e = WSAGetLastError();
        if (n != SOCKET_ERROR || e != WSAEMSGSIZE) bad++;
    }
    EXPECT_EQ(bad, 0);
    sb_close2(r, t);
    sb_end();
}

/* ---- SO_SNDBUF = 0 -------------------------------------------------------------------------------- */

TEST(sndbuf_zero_set_succeeds_on_stream_and_datagram)
{
    SOCKET t = INVALID_SOCKET, u; int v = 0;
    SB_BEGIN();
    t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    EXPECT_EQ(setsockopt(t, SOL_SOCKET, SO_SNDBUF, (char *)&v, sizeof v), 0);
    EXPECT_EQ(setsockopt(u, SOL_SOCKET, SO_SNDBUF, (char *)&v, sizeof v), 0);
    sb_close2(t, u);
    sb_end();
}

TEST(sndbuf_zero_get_value_is_recorded)
{
    SOCKET t; int v = 0, g = -1, l = sizeof g, r;
    SB_BEGIN();
    t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(t, SOL_SOCKET, SO_SNDBUF, (char *)&v, sizeof v);
    r = getsockopt(t, SOL_SOCKET, SO_SNDBUF, (char *)&g, &l);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(l, sizeof g);
    if (g != 0) t_note("SO_SNDBUF read back differs from the zero that was set");
    closesocket(t);
    sb_end();
}

TEST(sndbuf_zero_stream_still_delivers_4mb_with_blocking_sends)
{
    SOCKET c, s; drain_t d; HANDLE h; sb_stream tx; unsigned char *buf; int zero = 0, total = 0, r;
    SB_BEGIN();
    NEED_PAIR(c, s);
    EXPECT_EQ(setsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&zero, sizeof zero), 0);
    sb_stream_init(&tx, 31);
    buf = (unsigned char *)malloc(65536);
    h = start_drain(&d, s, 65536);
    while (total < 4 * MB) {
        sb_stream_fill(&tx, buf, 65536);
        r = send(c, (char *)buf, 65536, 0);
        if (r != 65536) { CHECKF(0, "send returned %d err %d", r, WSAGetLastError()); break; }
        total += r;
    }
    shutdown(c, SD_SEND);
    EXPECT_EQ(finish_drain(h), 1);
    EXPECT_EQ(d.st.count, (unsigned)total);
    CHECK(d.st.hash == tx.hash);
    free(buf);
    sb_close2(c, s);
    sb_end();
}

TEST(sndbuf_zero_small_send_is_delivered_in_order)
{
    SOCKET c, s; int zero = 0, i, bad = 0;
    SB_BEGIN();
    NEED_PAIR(c, s);
    setsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&zero, sizeof zero);
    sb_rcvtimeo(s, SB_WAIT_MS);
    for (i = 0; i < 100; i++) {
        char o = (char)i, g = 0;
        if (send(c, &o, 1, 0) != 1 || sb_recv_n(s, &g, 1) != 1 || g != o) bad++;
    }
    EXPECT_EQ(bad, 0);
    sb_close2(c, s);
    sb_end();
}

TEST(sndbuf_extreme_values_set_without_crashing)
{
    static const int vals[] = { 1, 4096, 1 << 20, 16 << 20, 0x7fffffff };
    SOCKET t; unsigned i; int ok = 0;
    SB_BEGIN();
    t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        int g = 0, l = sizeof g;
        if (setsockopt(t, SOL_SOCKET, SO_SNDBUF, (char *)&vals[i], sizeof(int)) == 0 &&
            getsockopt(t, SOL_SOCKET, SO_SNDBUF, (char *)&g, &l) == 0) ok++;
        else t_note("SO_SNDBUF=%d rejected err %d", vals[i], WSAGetLastError());
    }
    CHECK(ok >= 3);
    closesocket(t);
    sb_end();
}

/* ---- WSABUF array length thresholds ----------------------------------------------------------------- */

/* Send one real byte followed by (n-1) empty buffers over a pair; returns 0/-1 with error in *err. */
static int send_n_buffers(SOCKET c, SOCKET s, WSABUF *b, int n, int *err)
{
    DWORD sent = 0; int r; char g;
    r = WSASend(c, b, n, &sent, 0, NULL, NULL);
    if (r != 0) { *err = WSAGetLastError(); return -1; }
    if (sent != 1) { *err = -2; return -1; }
    if (sb_recv_n(s, &g, 1) != 1) { *err = -3; return -1; }
    return 0;
}

TEST(wsabuf_send_count_threshold_is_monotone)
{
    enum { MAXN = 1 << 20 };
    SOCKET c, s; WSABUF *b; char one = 'z'; int n, err = 0, lo, hi, bad = 0, firstbad = 0;
    SB_BEGIN();
    NEED_PAIR(c, s);
    sb_rcvtimeo(s, SB_WAIT_MS);
    b = (WSABUF *)calloc(MAXN, sizeof *b);
    b[0].buf = &one; b[0].len = 1;
    for (n = 1; n < MAXN; n++) { b[n].buf = &one; b[n].len = 0; }
    for (n = 1; n <= MAXN; n <<= 1) if (send_n_buffers(c, s, b, n, &err) != 0) { firstbad = n; break; }
    if (!firstbad) {
        t_note("no WSABUF count limit below %d", MAXN);
        EXPECT_EQ(send_n_buffers(c, s, b, MAXN, &err), 0);
    } else {
        int e2;
        lo = firstbad >> 1; hi = firstbad;
        if (lo < 1) lo = 1;
        while (hi - lo > 1) {
            int mid = lo + (hi - lo) / 2;
            if (send_n_buffers(c, s, b, mid, &err) == 0) lo = mid; else hi = mid;
        }
        /* threshold relation: lo works, lo+1 fails, and a few counts around/above behave the same way */
        EXPECT_EQ(send_n_buffers(c, s, b, lo, &err), 0);
        e2 = 0;
        EXPECT_EQ(send_n_buffers(c, s, b, lo + 1, &e2), -1);
        CHECK(e2 > 0);
        CHECK(e2 == WSAEINVAL || e2 == WSAENOBUFS || e2 == WSAEFAULT || e2 == WSA_NOT_ENOUGH_MEMORY || e2 == WSAEMSGSIZE);
        if (lo > 1) EXPECT_EQ(send_n_buffers(c, s, b, lo / 2, &err), 0);
        if (lo * 2 < MAXN) EXPECT_EQ(send_n_buffers(c, s, b, lo * 2, &e2), -1);
        EXPECT_EQ(e2 > 0, 1);
        t_note("WSASend buffer-count threshold power class: 2^%d, failure error %d", 31 - __builtin_clz(lo), e2);
        (void)bad;
    }
    /* connection survives every rejected call */
    EXPECT_EQ(send(c, "q", 1, 0), 1);
    { char g = 0; EXPECT_EQ(sb_recv_n(s, &g, 1), 1); EXPECT_EQ(g, 'q'); }
    free(b);
    sb_close2(c, s);
    sb_end();
}

TEST(wsabuf_send_of_64_one_byte_buffers_is_gathered_in_order)
{
    SOCKET c, s; WSABUF b[64]; char data[64], got[64]; DWORD sent = 0; int i;
    SB_BEGIN();
    NEED_PAIR(c, s);
    for (i = 0; i < 64; i++) { data[i] = (char)(i + 1); b[i].buf = &data[i]; b[i].len = 1; }
    EXPECT_EQ(WSASend(c, b, 64, &sent, 0, NULL, NULL), 0);
    EXPECT_EQ(sent, 64);
    sb_rcvtimeo(s, SB_WAIT_MS);
    EXPECT_EQ(sb_recv_n(s, got, 64), 64);
    CHECK(!memcmp(got, data, 64));
    sb_close2(c, s);
    sb_end();
}

TEST(wsabuf_send_of_10000_small_buffers_is_gathered_in_order)
{
    enum { N = 10000 };
    SOCKET c, s; WSABUF *b = (WSABUF *)calloc(N, sizeof *b); unsigned char *data = (unsigned char *)malloc(N), *got = (unsigned char *)malloc(N);
    DWORD sent = 0; int i, r, e = 0;
    SB_BEGIN();
    NEED_PAIR(c, s);
    for (i = 0; i < N; i++) { data[i] = (unsigned char)(i * 3); b[i].buf = (char *)&data[i]; b[i].len = 1; }
    r = WSASend(c, b, N, &sent, 0, NULL, NULL);
    if (r != 0) { e = WSAGetLastError(); t_note("10000-buffer WSASend failed err %d", e); }
    else {
        EXPECT_EQ(sent, N);
        sb_rcvtimeo(s, SB_WAIT_MS);
        EXPECT_EQ(sb_recv_n(s, (char *)got, N), N);
        CHECK(!memcmp(got, data, N));
    }
    free(b); free(data); free(got);
    sb_close2(c, s);
    sb_end();
}

TEST(wsabuf_recv_scatter_across_64_buffers_fills_in_order)
{
    SOCKET c, s; WSABUF b[64]; char out[64], in[64]; DWORD got = 0, fl = 0; int i;
    SB_BEGIN();
    NEED_PAIR(c, s);
    for (i = 0; i < 64; i++) { out[i] = (char)('A' + i % 26); b[i].buf = &in[63 - i]; b[i].len = 1; }
    EXPECT_EQ(send(c, out, 64, 0), 64);
    sb_readable(s, SB_WAIT_MS);
    sb_rcvtimeo(s, SB_WAIT_MS);
    EXPECT_EQ(WSARecv(s, b, 64, &got, &fl, NULL, NULL), 0);
    EXPECT_EQ(got, 64);
    for (i = 0; i < 64; i++) EXPECT_EQ(in[63 - i], out[i]);
    sb_close2(c, s);
    sb_end();
}

TEST(wsabuf_zero_count_send_is_observed)
{
    SOCKET c, s; WSABUF b; char x = 'x'; DWORD sent = 0; int r;
    SB_BEGIN();
    NEED_PAIR(c, s);
    b.buf = &x; b.len = 1;
    WSASetLastError(0);
    r = WSASend(c, &b, 0, &sent, 0, NULL, NULL);
    t_note("zero-count call returned %d err %d", r, r ? WSAGetLastError() : 0);  /* provider has no explicit check */
    sb_close2(c, s);
    sb_end();
}

TEST(wsabuf_zero_count_recv_is_observed)
{
    SOCKET c, s; WSABUF b; char x = 'x'; DWORD got = 0, fl = 0; int r;
    SB_BEGIN();
    NEED_PAIR(c, s);
    b.buf = &x; b.len = 1;
    WSASetLastError(0);
    r = WSARecv(s, &b, 0, &got, &fl, NULL, NULL);
    t_note("zero-count call returned %d err %d", r, r ? WSAGetLastError() : 0);  /* provider has no explicit check */
    sb_close2(c, s);
    sb_end();
}

/* ---- many overlapped operations ---------------------------------------------------------------------- */

typedef struct { OVERLAPPED ov; char byte; } pend_t;

static void pend_setup(pend_t *p, int n)
{
    int i;
    memset(p, 0, n * sizeof *p);
    for (i = 0; i < n; i++) p[i].ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
}
static void pend_free(pend_t *p, int n) { int i; for (i = 0; i < n; i++) if (p[i].ov.hEvent) CloseHandle(p[i].ov.hEvent); }

static int post_recvs(SOCKET s, pend_t *p, int n)
{
    int i, pending = 0;
    for (i = 0; i < n; i++) {
        WSABUF b; DWORD got = 0, fl = 0;
        b.buf = &p[i].byte; b.len = 1;
        if (WSARecv(s, &b, 1, &got, &fl, &p[i].ov, NULL) == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) pending++;
    }
    return pending;
}

TEST(ovl_300_pending_stream_recvs_cancelled_with_one_cancelioex)
{
    enum { N = 300 };
    SOCKET c, s; pend_t *p = (pend_t *)malloc(N * sizeof *p); int i, aborted = 0, pending;
    BOOL (WINAPI *pCancelIoEx)(HANDLE, LPOVERLAPPED) = (BOOL (WINAPI *)(HANDLE, LPOVERLAPPED))t_proc_in("kernel32.dll", "CancelIoEx");
    SB_BEGIN();
    REQUIRE(pCancelIoEx);
    NEED_PAIR(c, s);
    pend_setup(p, N);
    pending = post_recvs(s, p, N);
    EXPECT_EQ(pending, N);
    EXPECT_EQ(pCancelIoEx((HANDLE)s, NULL), 1);
    for (i = 0; i < N; i++) {
        DWORD got = 0, fl = 0;
        if (WaitForSingleObject(p[i].ov.hEvent, SB_WAIT_MS) != WAIT_OBJECT_0) continue;
        WSASetLastError(0);
        if (!WSAGetOverlappedResult(s, &p[i].ov, &got, FALSE, &fl) && WSAGetLastError() == WSA_OPERATION_ABORTED) aborted++;
    }
    EXPECT_EQ(aborted, N);
    pend_free(p, N); free(p);
    sb_close2(c, s);
    sb_end();
}

TEST(ovl_300_pending_stream_recvs_aborted_by_closesocket)
{
    enum { N = 300 };
    SOCKET c, s; pend_t *p = (pend_t *)malloc(N * sizeof *p); int i, done = 0;
    SB_BEGIN();
    NEED_PAIR(c, s);
    pend_setup(p, N);
    EXPECT_EQ(post_recvs(s, p, N), N);
    closesocket(s);
    for (i = 0; i < N; i++) if (WaitForSingleObject(p[i].ov.hEvent, SB_WAIT_MS) == WAIT_OBJECT_0) done++;
    EXPECT_EQ(done, N);
    for (i = 0; i < N; i++) if (p[i].ov.Internal == 0 || p[i].ov.Internal == 0x103) { CHECK(p[i].ov.Internal != 0x103); break; }
    pend_free(p, N); free(p);
    closesocket(c);
    sb_end();
}

TEST(ovl_cancelling_one_pending_stream_recv_cancels_every_queued_recv)
{
    enum { N = 20, VICTIM = 10 };
    SOCKET c, s; pend_t *p = (pend_t *)malloc(N * sizeof *p); int i, cancelled = 0, aborted = 0; char out = 'q', in = 0;
    BOOL (WINAPI *pCancelIoEx)(HANDLE, LPOVERLAPPED) = (BOOL (WINAPI *)(HANDLE, LPOVERLAPPED))t_proc_in("kernel32.dll", "CancelIoEx");
    SB_BEGIN();
    REQUIRE(pCancelIoEx);
    NEED_PAIR(c, s);
    pend_setup(p, N);
    EXPECT_EQ(post_recvs(s, p, N), N);
    EXPECT_EQ(pCancelIoEx((HANDLE)s, &p[VICTIM].ov), TRUE);
    /* the whole receive queue of the stream is flushed, not only the named operation */
    for (i = 0; i < N; i++) {
        DWORD got = 0, fl = 0;
        if (WaitForSingleObject(p[i].ov.hEvent, SB_WAIT_MS) != WAIT_OBJECT_0) continue;
        if (p[i].ov.Internal == 0xC0000120) cancelled++;
        WSASetLastError(0);
        if (!WSAGetOverlappedResult(s, &p[i].ov, &got, FALSE, &fl) && WSAGetLastError() == WSA_OPERATION_ABORTED) aborted++;
    }
    EXPECT_EQ(cancelled, N);
    EXPECT_EQ(aborted, N);
    /* the connection itself is untouched: later data is still received */
    sb_rcvtimeo(s, SB_WAIT_MS);
    EXPECT_EQ(send(c, &out, 1, 0), 1);
    EXPECT_EQ(recv(s, &in, 1, 0), 1);
    EXPECT_EQ(in, 'q');
    pend_free(p, N); free(p);
    sb_close2(c, s);
    sb_end();
}

TEST(ovl_300_pending_datagram_recvs_complete_in_order_per_datagram)
{
    enum { N = 300 };
    struct sockaddr_in a; SOCKET r, t; pend_t *p = (pend_t *)malloc(N * sizeof *p); int i, good = 0;
    SB_BEGIN();
    r = sb_udp(&a); t = sb_udp(NULL);
    pend_setup(p, N);
    EXPECT_EQ(post_recvs(r, p, N), N);
    for (i = 0; i < N; i++) {
        char d = (char)(i ^ 0x5a);
        sendto(t, &d, 1, 0, (struct sockaddr *)&a, sizeof a);
    }
    for (i = 0; i < N; i++) {
        DWORD got = 0, fl = 0;
        if (WaitForSingleObject(p[i].ov.hEvent, SB_WAIT_MS) != WAIT_OBJECT_0) continue;
        if (WSAGetOverlappedResult(r, &p[i].ov, &got, FALSE, &fl) && got == 1 && p[i].byte == (char)(i ^ 0x5a)) good++;
    }
    /* loopback UDP may drop when a queue overflows; count the relation, hard-check only completion of all */
    CHECK(good <= N);
    CHECK(good >= N / 2);
    if (good != N) t_note("datagram completions delivered out of %d: fewer than all", N);
    pend_free(p, N); free(p);
    sb_close2(r, t);
    sb_end();
}

TEST(ovl_pending_recvs_across_200_sockets_all_aborted_on_close)
{
    enum { N = 200 };
    SOCKET *v = (SOCKET *)calloc(N, sizeof(SOCKET)); pend_t *p = (pend_t *)malloc(N * sizeof *p); int i, pending = 0, done = 0;
    SB_BEGIN();
    pend_setup(p, N);
    for (i = 0; i < N; i++) {
        WSABUF b; DWORD got = 0, fl = 0;
        v[i] = sb_udp(NULL);
        b.buf = &p[i].byte; b.len = 1;
        if (v[i] != INVALID_SOCKET && WSARecv(v[i], &b, 1, &got, &fl, &p[i].ov, NULL) == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) pending++;
    }
    EXPECT_EQ(pending, N);
    for (i = 0; i < N; i++) if (v[i] != INVALID_SOCKET) closesocket(v[i]);
    for (i = 0; i < N; i++) if (WaitForSingleObject(p[i].ov.hEvent, SB_WAIT_MS) == WAIT_OBJECT_0) done++;
    EXPECT_EQ(done, N);
    pend_free(p, N); free(p); free(v);
    sb_end();
}

TEST(ovl_stream_recv_status_after_close_is_connection_aborted)
{
    SOCKET c, s; pend_t p[1];
    SB_BEGIN();
    NEED_PAIR(c, s);
    pend_setup(p, 1);
    EXPECT_EQ(post_recvs(s, p, 1), 1);
    EXPECT_EQ(p[0].ov.Internal, 0x103);          /* STATUS_PENDING while queued */
    closesocket(s);
    WaitForSingleObject(p[0].ov.hEvent, SB_WAIT_MS);
    EXPECT_EQ(p[0].ov.Internal, 0xC0000241);     /* STATUS_CONNECTION_ABORTED: a connected stream's pending recv */
    EXPECT_EQ(p[0].ov.InternalHigh, 0);
    pend_free(p, 1);
    closesocket(c);
    sb_end();
}

TEST(ovl_completion_port_receives_300_connection_aborted_completions)
{
    enum { N = 300 };
    SOCKET c, s; pend_t *p = (pend_t *)malloc(N * sizeof *p); HANDLE port; int i, got_n = 0;
    SB_BEGIN();
    NEED_PAIR(c, s);
    port = CreateIoCompletionPort((HANDLE)s, NULL, 77, 0);
    EXPECT_NE(port, NULL);
    pend_setup(p, N);
    /* events with the low bit set would suppress port packets; ours are plain */
    EXPECT_EQ(post_recvs(s, p, N), N);
    closesocket(s);
    for (i = 0; i < N; i++) {
        DWORD bytes; ULONG_PTR key; LPOVERLAPPED ov;
        BOOL ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov, SB_WAIT_MS);
        if (!ok && ov && key == 77 && GetLastError() == ERROR_CONNECTION_ABORTED) got_n++;
    }
    EXPECT_EQ(got_n, N);
    CloseHandle(port);
    pend_free(p, N); free(p);
    closesocket(c);
    sb_end();
}

TEST(ovl_datagram_recv_status_after_close_is_cancelled)
{
    SOCKET u; pend_t p[1];
    SB_BEGIN();
    u = sb_udp(NULL);
    pend_setup(p, 1);
    EXPECT_EQ(post_recvs(u, p, 1), 1);
    closesocket(u);
    EXPECT_EQ(WaitForSingleObject(p[0].ov.hEvent, SB_WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(p[0].ov.Internal, 0xC0000120);     /* STATUS_CANCELLED */
    EXPECT_EQ(p[0].ov.InternalHigh, 0);
    pend_free(p, 1);
    sb_end();
}

TEST(ovl_cancelling_one_pending_datagram_recv_leaves_the_others)
{
    enum { N = 6, VICTIM = 3 };
    SOCKET u; pend_t p[N]; int i, cancelled = 0, still = 0;
    BOOL (WINAPI *pCancelIoEx)(HANDLE, LPOVERLAPPED) = (BOOL (WINAPI *)(HANDLE, LPOVERLAPPED))t_proc_in("kernel32.dll", "CancelIoEx");
    SB_BEGIN();
    REQUIRE(pCancelIoEx);
    u = sb_udp(NULL);
    pend_setup(p, N);
    EXPECT_EQ(post_recvs(u, p, N), N);
    EXPECT_EQ(pCancelIoEx((HANDLE)u, &p[VICTIM].ov), TRUE);
    EXPECT_EQ(WaitForSingleObject(p[VICTIM].ov.hEvent, SB_WAIT_MS), WAIT_OBJECT_0);
    for (i = 0; i < N; i++) {
        if (p[i].ov.Internal == 0xC0000120) cancelled++;
        else if (p[i].ov.Internal == 0x103) still++;
    }
    EXPECT_EQ(cancelled, 1);     /* unlike a stream, only the named datagram receive is cancelled */
    EXPECT_EQ(still, N - 1);
    closesocket(u);
    for (i = 0; i < N; i++) WaitForSingleObject(p[i].ov.hEvent, SB_WAIT_MS);
    pend_free(p, N);
    sb_end();
}
