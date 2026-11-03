/* Completion-port soaks: 8 (or 1, or 3) worker threads drain the completions of 200 connected sockets, re-arming
 * one overlapped receive per socket. Bytes received per socket and in total are asserted exactly, with a
 * running digest per socket against the sender's digest. The echo variants add a second hop through the same
 * port (receive on one end, WSASend back, receive at the other end). */
#include "xs.h"

#define NPAIR 200
enum { K_RECV_A = 1, K_RECV_B, K_SEND_B };

typedef struct conn conn;
typedef struct { OVERLAPPED ov; int kind; conn *c; WSABUF wb; char *buf; } op_t;
struct conn {
    int id;
    SOCKET a, b;
    long long got_a, got_b, want;
    xs_gen dig_a, dig_b, dig_send;
    op_t ra, rb;
    int finished_a;
};

typedef struct {
    HANDLE port;
    int echo, recvbuf, nworkers;
    conn *c;
    volatile LONG total_a, total_b, finished, errors, completions, sends_done;
    long long want_each;
} ctx_t;

static ctx_t *g;

static int arm(conn *c, op_t *o, SOCKET s, int kind, int bufsz)
{
    DWORD got = 0, fl = 0;
    memset(&o->ov, 0, sizeof o->ov);
    o->kind = kind; o->c = c; o->wb.buf = o->buf; o->wb.len = bufsz;
    if (WSARecv(s, &o->wb, 1, &got, &fl, &o->ov, NULL) == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) return 0;
    return 1;
}

static DWORD WINAPI worker(void *p)
{
    ctx_t *x = g; (void)p;
    for (;;) {
        DWORD n = 0; ULONG_PTR key = 0; OVERLAPPED *ov = NULL;
        BOOL ok = GetQueuedCompletionStatus(x->port, &n, &key, &ov, 20000);
        op_t *o; conn *c;
        if (!ov) { if (key != (ULONG_PTR)-1) InterlockedIncrement(&x->errors); return 0; }
        o = (op_t *)ov; c = o->c;
        InterlockedIncrement(&x->completions);
        if (o->kind == K_SEND_B) {
            if (!ok || (int)n != o->wb.len) InterlockedIncrement(&x->errors);
            InterlockedIncrement(&x->sends_done);
            free(o->buf); free(o);
            continue;
        }
        if (!ok || n == 0) {
            InterlockedIncrement(&x->errors);
            if (o->kind == K_RECV_A) InterlockedIncrement(&x->finished);
            continue;
        }
        if (o->kind == K_RECV_A) {
            xs_gen_eat(&c->dig_a, (unsigned char *)o->buf, n);
            c->got_a += n; InterlockedExchangeAdd(&x->total_a, n);
            if (c->got_a < c->want) { if (!arm(c, o, c->a, K_RECV_A, x->recvbuf)) { InterlockedIncrement(&x->errors); InterlockedIncrement(&x->finished); } }
            else InterlockedIncrement(&x->finished);
        } else { /* K_RECV_B: echo hop */
            op_t *so = calloc(1, sizeof *so);
            DWORD sent = 0;
            xs_gen_eat(&c->dig_b, (unsigned char *)o->buf, n);
            c->got_b += n; InterlockedExchangeAdd(&x->total_b, n);
            so->kind = K_SEND_B; so->c = c; so->buf = malloc(n); memcpy(so->buf, o->buf, n);
            so->wb.buf = so->buf; so->wb.len = n;
            if (W(WSASend)(c->b, &so->wb, 1, &sent, 0, &so->ov, NULL) == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
                InterlockedIncrement(&x->errors); free(so->buf); free(so);
            }
            if (c->got_b < c->want) { if (!arm(c, o, c->b, K_RECV_B, x->recvbuf)) InterlockedIncrement(&x->errors); }
        }
    }
}

typedef struct { int first, count, chunk; } sender_arg;
static DWORD WINAPI sender(void *p)
{
    sender_arg *a = (sender_arg *)p; int i;
    unsigned char *buf = malloc(a->chunk);
    for (i = a->first; i < a->first + a->count; i++) {
        conn *c = &g->c[i];
        long long left = c->want;
        SOCKET s = g->echo ? c->a : c->b;
        while (left > 0) {
            int n = (int)(left < a->chunk ? left : a->chunk);
            xs_gen_fill(&c->dig_send, buf, n);
            if (xs_send_n(s, (char *)buf, n) != n) { InterlockedIncrement(&g->errors); break; }
            left -= n;
        }
    }
    free(buf);
    return 0;
}

static void run_iocp(int nworkers, int echo, long long per_sock, int chunk, int recvbuf)
{
    ctx_t *x = calloc(1, sizeof *x); int i, made = 0;
    HANDLE wth[16], sth[4]; sender_arg sa[4];
    int nsend = 4, arm_fail = 0, mismatch = 0, a_bad = 0, b_bad = 0;
    long long want_total = per_sock * NPAIR;
    DWORD t0;
    XS_BEGIN();
    g = x;
    x->echo = echo; x->recvbuf = recvbuf; x->nworkers = nworkers;
    x->c = calloc(NPAIR, sizeof(conn));
    x->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    for (i = 0; i < NPAIR; i++) {
        conn *c = &x->c[i];
        c->id = i; c->want = per_sock;
        xs_gen_init(&c->dig_a, 1); xs_gen_init(&c->dig_b, 1); xs_gen_init(&c->dig_send, (unsigned long long)i * 2654435761ULL + 12345);
        c->dig_a.hash = c->dig_b.hash = c->dig_send.hash;   /* all digests start from the same offset basis */
        c->dig_a.hash = c->dig_b.hash = c->dig_send.hash = 1469598103934665603ULL;
        c->ra.buf = malloc(recvbuf); c->rb.buf = malloc(recvbuf);
        if (!xs_pair(&c->a, &c->b)) continue;
        { LINGER lg = { 1, 0 }; setsockopt(c->a, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
          setsockopt(c->b, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg); }
        CreateIoCompletionPort((HANDLE)c->a, x->port, 1, 0);
        CreateIoCompletionPort((HANDLE)c->b, x->port, 2, 0);
        made++;
    }
    EXPECT_EQ(made, NPAIR);
    for (i = 0; i < nworkers; i++) wth[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    for (i = 0; i < NPAIR; i++) {
        conn *c = &x->c[i];
        if (!arm(c, &c->ra, c->a, K_RECV_A, recvbuf)) arm_fail++;
        if (echo && !arm(c, &c->rb, c->b, K_RECV_B, recvbuf)) arm_fail++;
    }
    EXPECT_EQ(arm_fail, 0);
    for (i = 0; i < nsend; i++) {
        sa[i].first = i * (NPAIR / nsend); sa[i].count = NPAIR / nsend; sa[i].chunk = chunk;
        sth[i] = CreateThread(NULL, 0, sender, &sa[i], 0, NULL);
    }
    for (i = 0; i < nsend; i++) { WaitForSingleObject(sth[i], 60000); CloseHandle(sth[i]); }
    t0 = GetTickCount();
    while (x->finished < NPAIR && GetTickCount() - t0 < 20000) Sleep(5);
    for (i = 0; i < nworkers; i++) PostQueuedCompletionStatus(x->port, 0, (ULONG_PTR)-1, NULL);
    for (i = 0; i < nworkers; i++) { WaitForSingleObject(wth[i], 25000); CloseHandle(wth[i]); }
    EXPECT_EQ(x->finished, NPAIR);
    EXPECT_EQ(x->errors, 0);
    CHECKF((long long)x->total_a == want_total, "total_a %lld want %lld", (long long)x->total_a, want_total);
    if (echo) {
        CHECKF((long long)x->total_b == want_total, "total_b %lld want %lld", (long long)x->total_b, want_total);
        CHECK(x->sends_done > 0);
    }
    for (i = 0; i < NPAIR; i++) {
        conn *c = &x->c[i];
        if (c->got_a != per_sock) a_bad++;
        if (c->dig_a.hash != c->dig_send.hash) mismatch++;
        if (echo && (c->got_b != per_sock || c->dig_b.hash != c->dig_send.hash)) b_bad++;
    }
    EXPECT_EQ(a_bad, 0);
    EXPECT_EQ(mismatch, 0);
    EXPECT_EQ(b_bad, 0);
    for (i = 0; i < NPAIR; i++) {
        conn *c = &x->c[i];
        if (c->a) closesocket(c->a);
        if (c->b) closesocket(c->b);
        /* Pending (never-completed) receives from close are drained below before freeing buffers. */
    }
    {   /* drain any aborted receives so no kernel write can land in freed memory */
        int drained = 0; DWORD n; ULONG_PTR k; OVERLAPPED *ov = NULL;
        while (drained < 5000) {
            ov = NULL;
            GetQueuedCompletionStatus(x->port, &n, &k, &ov, 300);
            if (!ov) break;
            drained++;
        }
    }
    for (i = 0; i < NPAIR; i++) { free(x->c[i].ra.buf); free(x->c[i].rb.buf); }
    CloseHandle(x->port);
    free(x->c); free(x); g = NULL;
    xs_end();
}

TEST(iocp_8_workers_200_sockets_32k_each_chunk_1000)   { run_iocp(8, 0, 32768, 1000, 4096); }
TEST(iocp_8_workers_200_sockets_32k_each_chunk_8192)   { run_iocp(8, 0, 32768, 8192, 4096); }
TEST(iocp_8_workers_200_sockets_4k_each_chunk_64)      { run_iocp(8, 0, 4096, 64, 4096); }
TEST(iocp_8_workers_200_sockets_16k_each_100byte_recv) { run_iocp(8, 0, 16384, 1024, 100); }
TEST(iocp_1_worker_200_sockets_32k_each)               { run_iocp(1, 0, 32768, 4096, 4096); }
TEST(iocp_3_workers_200_sockets_32k_each_odd_chunks)   { run_iocp(3, 0, 32768 + 11, 777, 1500); }
TEST(iocp_8_workers_200_sockets_echo_16k_each)         { run_iocp(8, 1, 16384, 2048, 4096); }
TEST(iocp_8_workers_200_sockets_echo_small_buffers)    { run_iocp(8, 1, 8192, 500, 256); }

/* Pure completion-port accounting: 10000 posted packets with distinct keys all arrive exactly once. */
static volatile LONG g_pk_count; static volatile LONG64 g_pk_sum; static HANDLE g_pk_port;
static DWORD WINAPI pk_worker(void *p)
{
    (void)p;
    for (;;) {
        DWORD n; ULONG_PTR k; OVERLAPPED *ov;
        if (!GetQueuedCompletionStatus(g_pk_port, &n, &k, &ov, 15000)) return 1;
        if (ov == (OVERLAPPED *)1) return 0;
        InterlockedIncrement(&g_pk_count); InterlockedAdd64(&g_pk_sum, (LONG64)k + n);
    }
}
TEST(iocp_8_workers_10000_posted_packets_counted_exactly)
{
    HANDLE th[8]; int i; LONG64 want = 0; DWORD res[8];
    g_pk_count = 0; g_pk_sum = 0;
    g_pk_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    for (i = 0; i < 8; i++) th[i] = CreateThread(NULL, 0, pk_worker, NULL, 0, NULL);
    for (i = 0; i < 10000; i++) { PostQueuedCompletionStatus(g_pk_port, i & 7, (ULONG_PTR)i + 1, (OVERLAPPED *)(ULONG_PTR)(0x100 + i)); want += i + 1 + (i & 7); }
    for (i = 0; i < 8; i++) PostQueuedCompletionStatus(g_pk_port, 0, 0, (OVERLAPPED *)1);
    for (i = 0; i < 8; i++) { WaitForSingleObject(th[i], 20000); GetExitCodeThread(th[i], &res[i]); CloseHandle(th[i]); EXPECT_EQ(res[i], 0); }
    EXPECT_EQ(g_pk_count, 10000);
    CHECKF(g_pk_sum == want, "sum %lld want %lld", (long long)g_pk_sum, (long long)want);
    CloseHandle(g_pk_port);
}

/* 200 UDP sockets on the port, 8 workers re-arming receives; senders send 30 numbered datagrams each, paced.
 * Relations: received <= sent, no datagram twice, no corrupted datagram, bytes = 16 * datagrams. */
typedef struct { OVERLAPPED ov; int idx; SOCKET s; int msg[4]; WSABUF wb; } uop;
static volatile LONG u_recv, u_bad, u_dup, u_err; static volatile LONG u_seen[200][32]; static HANDLE u_port; static int u_stop;
static DWORD WINAPI uworker(void *p)
{
    (void)p;
    for (;;) {
        DWORD n; ULONG_PTR k; OVERLAPPED *ov = NULL; DWORD fl = 0, got = 0;
        BOOL ok = GetQueuedCompletionStatus(u_port, &n, &k, &ov, 15000);
        uop *o;
        if (!ov) return 0;
        o = (uop *)ov;
        if (!ok) { if (!u_stop) InterlockedIncrement(&u_err); continue; }
        if (n != 16 || o->msg[0] != o->idx || o->msg[1] < 0 || o->msg[1] >= 30 || o->msg[2] != ~(o->msg[0] ^ o->msg[1])) InterlockedIncrement(&u_bad);
        else if (InterlockedIncrement(&u_seen[o->idx][o->msg[1]]) > 1) InterlockedIncrement(&u_dup);
        InterlockedIncrement(&u_recv);
        memset(&o->ov, 0, sizeof o->ov);
        W(WSARecv)(o->s, &o->wb, 1, &got, &fl, &o->ov, NULL);
    }
}
TEST(iocp_8_workers_200_udp_sockets_relations_only)
{
    enum { N = 200 };
    static uop ops[N]; SOCKET rs[N], tx; struct sockaddr_in ad[N]; HANDLE th[8]; int i, k, sent = 0, bufsz = 1 << 20;
    XS_BEGIN();
    memset((void *)u_seen, 0, sizeof u_seen); u_recv = u_bad = u_dup = u_err = 0; u_stop = 0;
    u_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for (i = 0; i < N; i++) {
        DWORD got = 0, fl = 0;
        rs[i] = xs_udp(&ad[i]);
        setsockopt(rs[i], SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof bufsz);
        CreateIoCompletionPort((HANDLE)rs[i], u_port, 0, 0);
        memset(&ops[i], 0, sizeof ops[i]);
        ops[i].idx = i; ops[i].s = rs[i]; ops[i].wb.buf = (char *)ops[i].msg; ops[i].wb.len = sizeof ops[i].msg;
        WSARecv(rs[i], &ops[i].wb, 1, &got, &fl, &ops[i].ov, NULL);
    }
    for (i = 0; i < 8; i++) th[i] = CreateThread(NULL, 0, uworker, NULL, 0, NULL);
    for (k = 0; k < 30; k++) {
        for (i = 0; i < N; i++) {
            int m[4] = { i, k, ~(i ^ k), 0 };
            if (sendto(tx, (const char *)m, sizeof m, 0, (struct sockaddr *)&ad[i], sizeof ad[i]) == sizeof m) sent++;
        }
        Sleep(2);
    }
    EXPECT_EQ(sent, N * 30);
    Sleep(500);
    u_stop = 1;
    for (i = 0; i < N; i++) closesocket(rs[i]);
    for (i = 0; i < 8; i++) PostQueuedCompletionStatus(u_port, 0, 0, NULL);
    for (i = 0; i < 8; i++) { WaitForSingleObject(th[i], 20000); CloseHandle(th[i]); }
    CHECKF(u_recv <= sent && u_recv > 0, "received %ld of %d", (long)u_recv, sent);
    EXPECT_EQ(u_bad, 0);
    EXPECT_EQ(u_dup, 0);
    closesocket(tx); CloseHandle(u_port);
    xs_end();
}
