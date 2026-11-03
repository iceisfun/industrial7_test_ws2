/* Close/cancel racing against overlapped receives on many sockets at once. Every issued overlapped operation
 * must complete exactly once (one completion packet, or one event signal, or one completion-routine call) with
 * either success or an aborted-class status; bytes reported by successful completions never exceed the bytes
 * sent by the feeder. The closers run on several threads while a feeder thread sends to some peers. */
#include "xs.h"

#define MAXSOCK 128
#define MAXOPS 4

typedef struct { OVERLAPPED ov; int sock, k; char buf[64]; } op_t;

enum { C_CLOSE, C_CANCEL_THEN_CLOSE, C_SHUTDOWN_THEN_CLOSE, C_CANCEL_ONLY_THEN_LATE_CLOSE, C_PEER_CLOSE };

typedef struct {
    int udp, nsock, kops, closers, mode, feeder;
    SOCKET rx[MAXSOCK], peer[MAXSOCK];
    op_t *ops;
    volatile LONG sent_bytes;
    int tidx;
} race_t;

static race_t *g_r;

static DWORD WINAPI closer_main(void *p)
{
    int t = (int)(INT_PTR)p, i;
    race_t *r = g_r;
    for (i = t; i < r->nsock; i += r->closers) {
        switch (r->mode) {
        case C_CLOSE: closesocket(r->rx[i]); break;
        case C_CANCEL_THEN_CLOSE: CancelIoEx((HANDLE)r->rx[i], NULL); closesocket(r->rx[i]); break;
        case C_SHUTDOWN_THEN_CLOSE: shutdown(r->rx[i], SD_RECEIVE); closesocket(r->rx[i]); break;
        case C_CANCEL_ONLY_THEN_LATE_CLOSE: CancelIoEx((HANDLE)r->rx[i], NULL); break;
        case C_PEER_CLOSE: closesocket(r->peer[i]); r->peer[i] = INVALID_SOCKET; break;
        }
    }
    return 0;
}

static DWORD WINAPI feeder_main(void *p)
{
    race_t *r = g_r; int round, i;
    (void)p;
    for (round = 0; round < 2; round++)
        for (i = 0; i < r->nsock; i += 2) {
            if (r->peer[i] == INVALID_SOCKET) continue;
            if (send(r->peer[i], "12345678", 8, 0) == 8) InterlockedAdd(&r->sent_bytes, 8);
        }
    return 0;
}

typedef struct { int ok, aborted_class, other, dup, bad_key; unsigned long long bytes_ok; DWORD codes[8]; int ncodes; } tally_t;

static void note_code(tally_t *t, DWORD c)
{
    int i; for (i = 0; i < t->ncodes; i++) if (t->codes[i] == c) return;
    if (t->ncodes < 8) t->codes[t->ncodes++] = c;
}

static void race_run(int udp, int nsock, int kops, int closers, int mode, int feeder, tally_t *t, int *issued_out)
{
    race_t *r = calloc(1, sizeof *r);
    HANDLE port, ct[16], fh = NULL;
    int i, k, issued = 0, completed = 0, made = 0;
    memset(t, 0, sizeof *t);
    r->udp = udp; r->nsock = nsock; r->kops = kops; r->closers = closers; r->mode = mode; r->feeder = feeder;
    r->ops = calloc(nsock * kops, sizeof(op_t));
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    for (i = 0; i < nsock; i++) {
        r->rx[i] = r->peer[i] = INVALID_SOCKET;
        if (udp) {
            struct sockaddr_in ra, pa;
            r->rx[i] = xs_udp(&ra);
            r->peer[i] = xs_udp(&pa);
            if (r->rx[i] == INVALID_SOCKET || r->peer[i] == INVALID_SOCKET || connect(r->peer[i], (struct sockaddr *)&ra, sizeof ra))
                continue;
        } else if (!xs_pair(&r->rx[i], &r->peer[i])) continue;
        if (!udp) { LINGER lg = { 1, 0 }; setsockopt(r->peer[i], SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg); }
        CreateIoCompletionPort((HANDLE)r->rx[i], port, (ULONG_PTR)i, 0);
        made++;
        for (k = 0; k < kops; k++) {
            op_t *o = &r->ops[i * kops + k];
            WSABUF wb = { sizeof o->buf, o->buf }; DWORD got = 0, fl = 0;
            int rc;
            o->sock = i; o->k = k;
            rc = WSARecv(r->rx[i], &wb, 1, &got, &fl, &o->ov, NULL);
            if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING) issued++;
        }
    }
    EXPECT_EQ(made, nsock);
    g_r = r;
    if (feeder) fh = CreateThread(NULL, 0, feeder_main, NULL, 0, NULL);
    for (i = 0; i < closers; i++) ct[i] = CreateThread(NULL, 0, closer_main, (void *)(INT_PTR)i, 0, NULL);
    for (i = 0; i < closers; i++) { WaitForSingleObject(ct[i], 20000); CloseHandle(ct[i]); }
    if (fh) { WaitForSingleObject(fh, 20000); CloseHandle(fh); }
    if (mode == C_CANCEL_ONLY_THEN_LATE_CLOSE || mode == C_PEER_CLOSE) {
        /* collect what cancelled/peer-close produced, then close everything */
    }
    {
        unsigned char *seen = calloc(nsock * kops, 1);
        for (; completed < issued;) {
            DWORD b = 0; ULONG_PTR key = 0; OVERLAPPED *ov = NULL; DWORD err = 0; BOOL ok;
            SetLastError(0);
            ok = GetQueuedCompletionStatus(port, &b, &key, &ov, mode == C_PEER_CLOSE || mode == C_CANCEL_ONLY_THEN_LATE_CLOSE ? 3000 : XS_WAIT_MS);
            if (!ov) {
                if (mode == C_PEER_CLOSE || mode == C_CANCEL_ONLY_THEN_LATE_CLOSE) {
                    /* ops that no event completed yet: close the receivers now to flush the rest */
                    for (i = 0; i < nsock; i++) if (r->rx[i] != INVALID_SOCKET) { closesocket(r->rx[i]); r->rx[i] = INVALID_SOCKET; }
                    mode = -1;
                    continue;
                }
                break;
            }
            err = ok ? 0 : GetLastError();
            {
                int idx = (int)(((op_t *)ov) - r->ops);
                if (idx < 0 || idx >= nsock * kops || seen[idx]) { t->dup++; completed++; continue; }
                seen[idx] = 1;
                if (key != (ULONG_PTR)r->ops[idx].sock) t->bad_key++;
            }
            completed++;
            if (ok) { t->ok++; t->bytes_ok += b; }
            else if (err == ERROR_OPERATION_ABORTED ||
                     (!udp && (err == ERROR_NETNAME_DELETED || err == ERROR_CONNECTION_ABORTED))) t->aborted_class++;
            else t->other++;
            note_code(t, err);
        }
        free(seen);
        /* nothing more may arrive */
        {
            DWORD b; ULONG_PTR key; OVERLAPPED *ov = NULL;
            GetQueuedCompletionStatus(port, &b, &key, &ov, 150);
            if (ov) t->dup++;
        }
    }
    for (i = 0; i < nsock; i++) {
        if (r->rx[i] != INVALID_SOCKET && mode != C_CLOSE && mode != C_CANCEL_THEN_CLOSE && mode != C_SHUTDOWN_THEN_CLOSE) closesocket(r->rx[i]);
        if (r->peer[i] != INVALID_SOCKET) closesocket(r->peer[i]);
    }
    CloseHandle(port);
    *issued_out = issued;
    if (completed != issued) t->other += 1000;
    t->bytes_ok = t->bytes_ok;
    CHECKF(t->bytes_ok <= (unsigned long long)r->sent_bytes, "bytes %llu sent %ld", t->bytes_ok, (long)r->sent_bytes);
    free(r->ops); free(r); g_r = NULL;
}

static void race_test(int udp, int nsock, int kops, int closers, int mode, int feeder, int rounds)
{
    int rd;
    XS_BEGIN();
    for (rd = 0; rd < rounds; rd++) {
        tally_t t; int issued = 0, i;
        race_run(udp, nsock, kops, closers, mode, feeder, &t, &issued);
        EXPECT_EQ(issued, nsock * kops);
        EXPECT_EQ(t.ok + t.aborted_class + t.other, issued);
        EXPECT_EQ(t.other, 0);
        EXPECT_EQ(t.dup, 0);
        EXPECT_EQ(t.bad_key, 0);
    }
    xs_end();
}

#define RACE(name, udp, ns, ko, cl, mode, fe, rounds) \
    TEST(race_##name) { race_test(udp, ns, ko, cl, mode, fe, rounds); }
RACE(tcp_close_100x2_1closer,         0, 100, 2, 1, C_CLOSE, 0, 1)
RACE(tcp_close_100x2_4closers,        0, 100, 2, 4, C_CLOSE, 0, 1)
RACE(tcp_close_100x3_8closers_feeder, 0, 100, 3, 8, C_CLOSE, 1, 1)
RACE(tcp_close_30x4_5_rounds,         0, 30,  4, 3, C_CLOSE, 1, 5)
RACE(tcp_cancel_then_close_100x2,     0, 100, 2, 4, C_CANCEL_THEN_CLOSE, 1, 1)
RACE(tcp_shutdown_recv_then_close,    0, 100, 2, 4, C_SHUTDOWN_THEN_CLOSE, 1, 1)
RACE(tcp_cancel_only_then_late_close, 0, 100, 2, 4, C_CANCEL_ONLY_THEN_LATE_CLOSE, 0, 1)
RACE(tcp_peer_closes_gracefully,      0, 100, 2, 4, C_PEER_CLOSE, 0, 1)
RACE(udp_close_100x2_1closer,         1, 100, 2, 1, C_CLOSE, 0, 1)
RACE(udp_close_100x2_4closers,        1, 100, 2, 4, C_CLOSE, 0, 1)
RACE(udp_close_100x3_8closers_feeder, 1, 100, 3, 8, C_CLOSE, 1, 1)
RACE(udp_close_30x4_5_rounds,         1, 30,  4, 3, C_CLOSE, 1, 5)
RACE(udp_cancel_then_close_100x2,     1, 100, 2, 4, C_CANCEL_THEN_CLOSE, 1, 1)
RACE(udp_cancel_only_then_late_close, 1, 100, 2, 4, C_CANCEL_ONLY_THEN_LATE_CLOSE, 0, 1)

typedef ULONG (WINAPI *rtl2dos_pfn)(LONG);
static DWORD rtl2dos(LONG st)
{
    rtl2dos_pfn f = (rtl2dos_pfn)t_proc_in("ntdll.dll", "RtlNtStatusToDosError");
    return f ? f(st) : 0xFFFFFFFF;
}

/* Event-based accounting: each op has its own event; after the race every event is signalled exactly once and
 * WSAGetOverlappedResult reports success or an aborted-class error. */
static void event_race(int udp)
{
    enum { N = 60, K = 2 };
    SOCKET rx_s[N], peer[N]; static WSAOVERLAPPED ov[N * K]; static char buf[N * K][32];
    int i, k, issued = 0, signalled = 0, success = 0, aborted = 0, other = 0;
    XS_BEGIN();
    memset(ov, 0, sizeof ov);
    for (i = 0; i < N; i++) {
        rx_s[i] = peer[i] = INVALID_SOCKET;
        if (udp) rx_s[i] = xs_udp(NULL); else xs_pair(&rx_s[i], &peer[i]);
        for (k = 0; k < K; k++) {
            WSABUF wb = { sizeof buf[0], buf[i * K + k] }; DWORD got = 0, fl = 0;
            ov[i * K + k].hEvent = WSACreateEvent();
            if (WSARecv(rx_s[i], &wb, 1, &got, &fl, &ov[i * K + k], NULL) == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) issued++;
        }
    }
    EXPECT_EQ(issued, N * K);
    for (i = 0; i < N; i++) closesocket(rx_s[i]);
    for (i = 0; i < N * K; i++) {
        if (WaitForSingleObject(ov[i].hEvent, XS_WAIT_MS) != WAIT_OBJECT_0) continue;
        signalled++;
        /* the socket is closed, so read the final status straight from the request block */
        if ((LONG)ov[i].Internal == 0) success++;
        else {
            DWORD e = rtl2dos((LONG)ov[i].Internal);
            if (e == ERROR_OPERATION_ABORTED || (!udp && (e == ERROR_NETNAME_DELETED || e == ERROR_CONNECTION_ABORTED))) aborted++;
            else other++;
        }
    }
    EXPECT_EQ(signalled, N * K);
    EXPECT_EQ(other, 0);
    EXPECT_EQ(success + aborted, N * K);
    for (i = 0; i < N * K; i++) WSACloseEvent(ov[i].hEvent);
    for (i = 0; i < N; i++) if (peer[i] != INVALID_SOCKET) closesocket(peer[i]);
    xs_end();
}
TEST(race_event_accounting_tcp) { event_race(0); }
TEST(race_event_accounting_udp) { event_race(1); }

/* Completion routines: close all sockets from the issuing thread, then wait alertably; the routine runs
 * exactly once per operation with an aborted-class error and zero bytes. */
typedef struct { volatile LONG calls; volatile LONG zero_bytes; volatile LONG ok_err; volatile LONG dups; } cr_stat;
static cr_stat g_cr;
static volatile LONG g_cr_seen[256];
static void CALLBACK cr_routine(DWORD err, DWORD n, LPWSAOVERLAPPED ov, DWORD fl)
{
    int idx = (int)(INT_PTR)ov->hEvent;   /* index stashed by the issuer (hEvent is unused for routines) */
    InterlockedIncrement(&g_cr.calls);
    if (n == 0) InterlockedIncrement(&g_cr.zero_bytes);
    if (err == WSA_OPERATION_ABORTED || err == WSAECONNABORTED || err == WSAECONNRESET) InterlockedIncrement(&g_cr.ok_err);
    if (InterlockedIncrement(&g_cr_seen[idx]) != 1) InterlockedIncrement(&g_cr.dups);
}
static void routine_race(int udp)
{
    enum { N = 100 };
    SOCKET rx_s[N], peer[N]; static WSAOVERLAPPED ov[N]; static char buf[N][32];
    int i, issued = 0;
    DWORD t0;
    XS_BEGIN();
    memset(&g_cr, 0, sizeof g_cr); memset((void *)g_cr_seen, 0, sizeof g_cr_seen); memset(ov, 0, sizeof ov);
    for (i = 0; i < N; i++) {
        peer[i] = INVALID_SOCKET;
        if (udp) rx_s[i] = xs_udp(NULL); else xs_pair(&rx_s[i], &peer[i]);
        { WSABUF wb = { sizeof buf[0], buf[i] }; DWORD got = 0, fl = 0;
          ov[i].hEvent = (HANDLE)(INT_PTR)i;
          if (WSARecv(rx_s[i], &wb, 1, &got, &fl, &ov[i], cr_routine) == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) issued++; }
    }
    EXPECT_EQ(issued, N);
    for (i = 0; i < N; i++) closesocket(rx_s[i]);
    t0 = GetTickCount();
    while (g_cr.calls < N && GetTickCount() - t0 < XS_WAIT_MS) SleepEx(20, TRUE);
    SleepEx(100, TRUE);
    EXPECT_EQ(g_cr.calls, N);
    EXPECT_EQ(g_cr.zero_bytes, N);
    EXPECT_EQ(g_cr.ok_err, N);
    EXPECT_EQ(g_cr.dups, 0);
    for (i = 0; i < N; i++) if (peer[i] != INVALID_SOCKET) closesocket(peer[i]);
    xs_end();
}
TEST(race_completion_routines_tcp) { routine_race(0); }
TEST(race_completion_routines_udp) { routine_race(1); }

/* Many threads each closing the same socket value concurrently: exactly one closesocket succeeds per socket,
 * the rest fail with WSAENOTSOCK (or succeed only if the value was reused, which is not asserted). */
typedef struct { SOCKET *socks; int n; volatile LONG ok; volatile LONG notsock; volatile LONG other; } dc_t;
static dc_t g_dc;
static DWORD WINAPI dc_thread(void *p)
{
    int i; (void)p;
    for (i = 0; i < g_dc.n; i++) {
        if (closesocket(g_dc.socks[i]) == 0) InterlockedIncrement(&g_dc.ok);
        else if (WSAGetLastError() == WSAENOTSOCK) InterlockedIncrement(&g_dc.notsock);
        else InterlockedIncrement(&g_dc.other);
    }
    return 0;
}
TEST(race_concurrent_double_close_one_winner_per_socket)
{
    enum { N = 200, T = 4 };
    SOCKET s[N]; HANDLE th[T]; int i;
    XS_BEGIN();
    for (i = 0; i < N; i++) s[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&g_dc, 0, sizeof g_dc); g_dc.socks = s; g_dc.n = N;
    for (i = 0; i < T; i++) th[i] = CreateThread(NULL, 0, dc_thread, NULL, 0, NULL);
    for (i = 0; i < T; i++) { WaitForSingleObject(th[i], 20000); CloseHandle(th[i]); }
    /* Values can be reissued only by socket(); none is created while the closers run, so the win count is exact. */
    EXPECT_EQ(g_dc.ok, N);
    EXPECT_EQ(g_dc.notsock, N * (T - 1));
    EXPECT_EQ(g_dc.other, 0);
    xs_end();
}
