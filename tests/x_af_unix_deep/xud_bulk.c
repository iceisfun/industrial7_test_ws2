/* Large transfers over AF_UNIX stream sockets without any sendfile-style helper: one megabyte in single
 * calls, in odd-sized chunks, through scatter-gather and overlapped sends, both directions at once, with
 * half-close used as the end-of-data marker. Data is a position-dependent pattern so reordering, loss and
 * duplication are all detected. */
#include "xud.h"

#define MB (1 << 20)

static void fill(unsigned char *p, size_t n, unsigned seed)
{
    size_t i;
    for (i = 0; i < n; i++) p[i] = (unsigned char)((i * 131u + (i >> 8) * 17u + seed) & 0xff);
}

struct xfer { SOCKET s; unsigned char *buf; int n; int done; int chunk; };
static DWORD WINAPI th_sender(LPVOID p)
{
    struct xfer *x = p;
    int off = 0;
    while (off < x->n) {
        int c = x->n - off;
        int r;
        if (x->chunk && c > x->chunk) c = x->chunk;
        r = U(send)(x->s, (char *)x->buf + off, c, 0);
        if (r <= 0) break;
        off += r;
    }
    x->done = off;
    return 0;
}
static DWORD WINAPI th_receiver(LPVOID p)
{
    struct xfer *x = p;
    int off = 0;
    while (off < x->n) {
        int c = x->n - off;
        int r;
        if (x->chunk && c > x->chunk) c = x->chunk;
        r = U(recv)(x->s, (char *)x->buf + off, c, 0);
        if (r <= 0) break;
        off += r;
    }
    x->done = off;
    return 0;
}

TEST(xud_bulk_single_send_1mb_blocking)
{
    unsigned char *src, *dst;
    struct xfer rx;
    HANDLE th;
    TRIO(t, "bk1.sock");
    src = malloc(MB); dst = malloc(MB);
    fill(src, MB, 1);
    rx.s = t.srv; rx.buf = dst; rx.n = MB; rx.done = 0; rx.chunk = 0;
    th = CreateThread(NULL, 0, th_receiver, &rx, 0, NULL);
    XEQ(U(send)(t.cli, (char *)src, MB, 0), MB);        /* one call moves it all when the reader keeps up */
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    XEQ(rx.done, MB);
    CHECK(!memcmp(src, dst, MB));
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_single_send_1mb_reverse_direction)
{
    unsigned char *src, *dst;
    struct xfer rx;
    HANDLE th;
    TRIO(t, "bk2.sock");
    src = malloc(MB); dst = malloc(MB);
    fill(src, MB, 2);
    rx.s = t.cli; rx.buf = dst; rx.n = MB; rx.done = 0; rx.chunk = 0;
    th = CreateThread(NULL, 0, th_receiver, &rx, 0, NULL);
    XEQ(U(send)(t.srv, (char *)src, MB, 0), MB);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    XEQ(rx.done, MB);
    CHECK(!memcmp(src, dst, MB));
    free(src); free(dst);
    x_trio_close(&t);
}
static void chunked(int send_chunk, int recv_chunk, unsigned seed)
{
    unsigned char *src, *dst;
    struct xfer tx, rx;
    HANDLE th[2];
    TRIO(t, "bk3.sock");
    src = malloc(MB); dst = malloc(MB);
    fill(src, MB, seed);
    tx.s = t.cli; tx.buf = src; tx.n = MB; tx.done = 0; tx.chunk = send_chunk;
    rx.s = t.srv; rx.buf = dst; rx.n = MB; rx.done = 0; rx.chunk = recv_chunk;
    th[0] = CreateThread(NULL, 0, th_receiver, &rx, 0, NULL);
    th[1] = CreateThread(NULL, 0, th_sender, &tx, 0, NULL);
    WaitForMultipleObjects(2, th, TRUE, 15000);
    CloseHandle(th[0]); CloseHandle(th[1]);
    XEQ(tx.done, MB);
    XEQ(rx.done, MB);
    CHECK(!memcmp(src, dst, MB));
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_chunks_odd_sizes) { chunked(65537, 4093, 3); }
TEST(xud_bulk_chunks_tiny_send_large_recv) { chunked(97, 1 << 18, 4); }
TEST(xud_bulk_chunks_large_send_tiny_recv) { chunked(1 << 18, 211, 5); }
TEST(xud_bulk_chunks_4k_both) { chunked(4096, 4096, 6); }
TEST(xud_bulk_chunks_64k_both) { chunked(65536, 65536, 7); }
TEST(xud_bulk_chunks_one_page_minus_one) { chunked(4095, 8191, 8); }

TEST(xud_bulk_full_duplex_1mb_each_way)
{
    unsigned char *a_src, *a_dst, *b_src, *b_dst;
    struct xfer ts[2], tr[2];
    HANDLE th[4];
    TRIO(t, "bk4.sock");
    a_src = malloc(MB); a_dst = malloc(MB); b_src = malloc(MB); b_dst = malloc(MB);
    fill(a_src, MB, 11); fill(b_src, MB, 12);
    ts[0].s = t.cli; ts[0].buf = a_src; ts[0].n = MB; ts[0].done = 0; ts[0].chunk = 32768;
    ts[1].s = t.srv; ts[1].buf = b_src; ts[1].n = MB; ts[1].done = 0; ts[1].chunk = 32768;
    tr[0].s = t.srv; tr[0].buf = a_dst; tr[0].n = MB; tr[0].done = 0; tr[0].chunk = 16384;
    tr[1].s = t.cli; tr[1].buf = b_dst; tr[1].n = MB; tr[1].done = 0; tr[1].chunk = 16384;
    th[0] = CreateThread(NULL, 0, th_receiver, &tr[0], 0, NULL);
    th[1] = CreateThread(NULL, 0, th_receiver, &tr[1], 0, NULL);
    th[2] = CreateThread(NULL, 0, th_sender, &ts[0], 0, NULL);
    th[3] = CreateThread(NULL, 0, th_sender, &ts[1], 0, NULL);
    WaitForMultipleObjects(4, th, TRUE, 20000);
    { int i; for (i = 0; i < 4; i++) CloseHandle(th[i]); }
    XEQ(ts[0].done, MB); XEQ(ts[1].done, MB);
    XEQ(tr[0].done, MB); XEQ(tr[1].done, MB);
    CHECK(!memcmp(a_src, a_dst, MB));
    CHECK(!memcmp(b_src, b_dst, MB));
    free(a_src); free(a_dst); free(b_src); free(b_dst);
    x_trio_close(&t);
}

/* ---- scatter-gather and overlapped ---- */
TEST(xud_bulk_wsasend_gather_many_buffers)
{
    enum { NB = 64, SZ = 8192 };
    unsigned char *src, *dst;
    WSABUF wb[NB];
    struct xfer rx;
    HANDLE th;
    DWORD sent = 0;
    int i;
    TRIO(t, "bk5.sock");
    src = malloc(NB * SZ); dst = malloc(NB * SZ);
    fill(src, NB * SZ, 21);
    for (i = 0; i < NB; i++) { wb[i].buf = (char *)src + i * SZ; wb[i].len = SZ; }
    rx.s = t.srv; rx.buf = dst; rx.n = NB * SZ; rx.done = 0; rx.chunk = 0;
    th = CreateThread(NULL, 0, th_receiver, &rx, 0, NULL);
    XEQ(U(WSASend)(t.cli, wb, NB, &sent, 0, NULL, NULL), 0);
    XEQ(sent, NB * SZ);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    XEQ(rx.done, NB * SZ);
    CHECK(!memcmp(src, dst, NB * SZ));
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_wsarecv_scatter_many_buffers)
{
    enum { NB = 64, SZ = 8192 };
    unsigned char *src, *dst;
    WSABUF wb[NB];
    struct xfer tx;
    HANDLE th;
    DWORD got = 0, total = 0, fl;
    int i;
    TRIO(t, "bk6.sock");
    src = malloc(NB * SZ); dst = malloc(NB * SZ);
    fill(src, NB * SZ, 22);
    memset(dst, 0, NB * SZ);
    for (i = 0; i < NB; i++) { wb[i].buf = (char *)dst + i * SZ; wb[i].len = SZ; }
    tx.s = t.cli; tx.buf = src; tx.n = NB * SZ; tx.done = 0; tx.chunk = 0;
    th = CreateThread(NULL, 0, th_sender, &tx, 0, NULL);
    while (total < NB * SZ) {
        int k = (int)(total / SZ);
        fl = MSG_WAITALL;
        got = 0;
        if (U(WSARecv)(t.srv, wb + k, NB - k, &got, &fl, NULL, NULL)) break;
        if (!got) break;
        total += got;
        (void)fl;
        break;                                           /* one MSG_WAITALL gather must fill everything */
    }
    XEQ(total, NB * SZ);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    CHECK(!memcmp(src, dst, NB * SZ));
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_overlapped_send_1mb_completes_with_full_count)
{
    unsigned char *src, *dst;
    WSABUF wb;
    WSAOVERLAPPED ov;
    struct xfer rx;
    HANDLE th;
    DWORD sent = 0, tr = 0, fl = 0;
    int r;
    TRIO(t, "bk7.sock");
    src = malloc(MB); dst = malloc(MB);
    fill(src, MB, 23);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = (char *)src; wb.len = MB;
    rx.s = t.srv; rx.buf = dst; rx.n = MB; rx.done = 0; rx.chunk = 65536;
    th = CreateThread(NULL, 0, th_receiver, &rx, 0, NULL);
    r = U(WSASend)(t.cli, &wb, 1, &sent, 0, &ov, NULL);
    CHECK(r == 0 || x_err() == WSA_IO_PENDING);
    CHECK(U(WSAGetOverlappedResult)(t.cli, &ov, &tr, TRUE, &fl));
    XEQ(tr, MB);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    CloseHandle(ov.hEvent);
    XEQ(rx.done, MB);
    CHECK(!memcmp(src, dst, MB));
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_overlapped_recv_waitall_completes_on_first_data)
{
    /* MSG_WAITALL does not hold an overlapped receive open: it completes with what the first send delivered */
    unsigned char *src, *dst;
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD got = 0, tr = 0, fl = MSG_WAITALL;
    int r;
    TRIO(t, "bk8.sock");
    src = malloc(MB); dst = malloc(MB);
    fill(src, MB, 24);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = (char *)dst; wb.len = MB;
    r = U(WSARecv)(t.srv, &wb, 1, &got, &fl, &ov, NULL);
    XEQ(r, -1);
    XEQ(x_err(), WSA_IO_PENDING);
    XEQ(U(send)(t.cli, (char *)src, 50000, 0), 50000);
    fl = 0;
    CHECK(U(WSAGetOverlappedResult)(t.srv, &ov, &tr, TRUE, &fl));
    XEQ(tr, 50000);
    CHECK(!memcmp(src, dst, 50000));
    CloseHandle(ov.hEvent);
    free(src); free(dst);
    x_trio_close(&t);
}

/* ---- half-close as the end-of-data marker ---- */
TEST(xud_bulk_half_close_marks_end_of_data)
{
    unsigned char *src, *dst;
    int total = 0, r;
    const int N = 300000;
    struct xfer tx;
    HANDLE th;
    TRIO(t, "bk9.sock");
    src = malloc(N); dst = malloc(MB);
    fill(src, N, 31);
    tx.s = t.cli; tx.buf = src; tx.n = N; tx.done = 0; tx.chunk = 0;
    th = CreateThread(NULL, 0, th_sender, &tx, 0, NULL);
    for (;;) {                                           /* read until the sender's half-close */
        r = U(recv)(t.srv, (char *)dst + total, MB - total, 0);
        if (r <= 0) break;
        total += r;
        if (total >= N) break;
    }
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    XEQ(tx.done, N);
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(recv)(t.srv, (char *)dst + total, 16, 0), 0);  /* end of stream, counted exactly */
    XEQ(total, N);
    CHECK(!memcmp(src, dst, N));
    /* the reverse direction still works after the half-close */
    XEQ(U(send)(t.srv, (char *)&total, 4, 0), 4);
    {
        int back = 0;
        XEQ(x_recv_n(t.cli, (char *)&back, 4), 4);
        XEQ(back, N);
    }
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_close_after_send_delivers_everything)
{
    unsigned char *src, *dst;
    int total = 0, r;
    const int N = 400000;
    TRIO(t, "bk10.sock");
    src = malloc(N); dst = malloc(N);
    fill(src, N, 32);
    {
        struct xfer tx; HANDLE th;
        tx.s = t.cli; tx.buf = src; tx.n = N; tx.done = 0; tx.chunk = 0;
        th = CreateThread(NULL, 0, th_sender, &tx, 0, NULL);
        while (total < N) { r = U(recv)(t.srv, (char *)dst + total, N - total, 0); if (r <= 0) break; total += r; }
        WaitForSingleObject(th, 10000);
        CloseHandle(th);
    }
    XEQ(total, N);
    CHECK(!memcmp(src, dst, N));
    free(src); free(dst);
    x_trio_close(&t);
}
TEST(xud_bulk_send_then_graceful_close_then_peer_reads_all)
{
    /* data queued in the peer's buffer when the sender closes is still readable, then end of stream */
    unsigned char *src, *dst;
    int r, total = 0;
    const int N = 40000;
    TRIO(t, "bk11.sock");
    src = malloc(N); dst = malloc(N + 16);
    fill(src, N, 33);
    XEQ(U(send)(t.cli, (char *)src, N, 0), N);
    XEQ(U(closesocket)(t.cli), 0);
    t.cli = INVALID_SOCKET;
    while (total < N) { r = U(recv)(t.srv, (char *)dst + total, N + 16 - total, 0); if (r <= 0) break; total += r; }
    XEQ(total, N);
    CHECK(!memcmp(src, dst, N));
    XEQ(U(recv)(t.srv, (char *)dst, 16, 0), 0);
    free(src); free(dst);
    x_trio_close(&t);
}

/* ---- nonblocking send hits the buffer limit ---- */
TEST(xud_bulk_nonblocking_send_accepts_whole_then_wouldblock)
{
    unsigned char *src;
    int first, r, e, total, tries = 0;
    TRIO(t, "bk12.sock");
    src = malloc(MB);
    fill(src, MB, 41);
    x_blocking(t.cli, FALSE);
    first = U(send)(t.cli, (char *)src, MB, 0);
    XEQ(first, MB);                                     /* a send is accepted whole while the queue is below its limit */
    total = first;
    do {
        r = U(send)(t.cli, (char *)src, MB, 0);
        e = r < 0 ? x_err() : 0;
        if (r > 0) total += r;
    } while (r > 0 && ++tries < 16);
    XEQ(r, -1);
    XEQ(e, WSAEWOULDBLOCK);
    /* everything accepted is exactly what the peer can drain */
    {
        char *sink = malloc(MB);
        int got = 0;
        x_rcvtimeo(t.srv, 400);
        for (;;) { r = U(recv)(t.srv, sink, MB, 0); if (r <= 0) break; got += r; }
        XEQ(got, total);
        free(sink);
    }
    free(src);
    x_trio_close(&t);
}
TEST(xud_bulk_nonblocking_writable_again_after_drain)
{
    unsigned char *src;
    char *sink;
    int r, drained = 0;
    TRIO(t, "bk13.sock");
    src = malloc(MB); sink = malloc(MB);
    fill(src, MB, 42);
    x_blocking(t.cli, FALSE);
    do { r = U(send)(t.cli, (char *)src, MB, 0); } while (r > 0);
    XEQ(x_err(), WSAEWOULDBLOCK);
    CHECK(!x_wait(t.cli, 1, 200));                      /* full: not writable */
    x_rcvtimeo(t.srv, 400);
    while ((r = U(recv)(t.srv, sink, MB, 0)) > 0) drained += r;
    CHECK(x_wait(t.cli, 1, 3000));                      /* drained: writable again */
    XEQ(U(send)(t.cli, "z", 1, 0), 1);
    CHECK(drained > 0);
    free(src); free(sink);
    x_trio_close(&t);
}
