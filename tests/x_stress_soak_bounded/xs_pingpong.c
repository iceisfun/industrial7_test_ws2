/* 50 concurrent send/receive ping-pong conversations, each on a private loopback pair, in several I/O styles
 * (blocking, nonblocking+select, overlapped+event) over TCP and UDP. Every round sends a message whose length and
 * bytes derive from (conversation id, round); the echo must come back byte-exact. The total number of verified
 * round trips and echoed bytes is asserted exactly; all sockets are closed and all threads joined. */
#include "xs.h"

#define NPAIRS 50

enum { M_BLOCK, M_NONBLOCK, M_OVERLAPPED };

typedef struct {
    int id, style, udp, rounds, maxlen, nodelay, swap;
    SOCKET a, b;                 /* a initiates, b echoes (or swapped roles) */
    volatile LONG bad;           /* mismatching or failed rounds */
    long long echoed;            /* verified bytes returned to the initiator */
    int done_rounds;
} pp_t;

static int wait_readable(SOCKET s)
{
    fd_set r; struct timeval tv = { XS_WAIT_MS / 1000, 0 };
    r.fd_count = 1; r.fd_array[0] = s;
    return select(0, &r, NULL, NULL, &tv) == 1;
}

/* receive up to n bytes (one call's worth), returns count, 0 on orderly close, -1 on failure */
static int rx(int style, SOCKET s, char *b, int n)
{
    if (style == M_OVERLAPPED) {
        WSAOVERLAPPED ov; WSABUF wb; DWORD got = 0, fl = 0; int r;
        memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
        wb.buf = b; wb.len = n;
        r = WSARecv(s, &wb, 1, &got, &fl, &ov, NULL);
        if (r == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) { WSACloseEvent(ov.hEvent); return -1; }
            if (WaitForSingleObject(ov.hEvent, XS_WAIT_MS) != WAIT_OBJECT_0) {
                CancelIoEx((HANDLE)s, &ov); WaitForSingleObject(ov.hEvent, XS_WAIT_MS);
                WSACloseEvent(ov.hEvent); return -1;
            }
            if (!WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl)) { WSACloseEvent(ov.hEvent); return -1; }
        }
        WSACloseEvent(ov.hEvent);
        return (int)got;
    }
    for (;;) {
        int r = recv(s, b, n, 0);
        if (r >= 0) return r;
        if (style == M_NONBLOCK && WSAGetLastError() == WSAEWOULDBLOCK) { if (!wait_readable(s)) return -1; continue; }
        return -1;
    }
}

static int tx_all(int style, SOCKET s, const char *b, int n)
{
    int sent = 0;
    while (sent < n) {
        int r;
        if (style == M_OVERLAPPED) {
            WSAOVERLAPPED ov; WSABUF wb; DWORD got = 0;
            memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
            wb.buf = (char *)b + sent; wb.len = n - sent;
            r = W(WSASend)(s, &wb, 1, &got, 0, &ov, NULL);
            if (r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) {
                DWORD fl = 0;
                if (WaitForSingleObject(ov.hEvent, XS_WAIT_MS) == WAIT_OBJECT_0 && WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl)) r = 0;
            }
            WSACloseEvent(ov.hEvent);
            if (r != 0) return sent;
            sent += (int)got;
        } else {
            r = send(s, b + sent, n - sent, 0);
            if (r < 0 && style == M_NONBLOCK && WSAGetLastError() == WSAEWOULDBLOCK) { Sleep(1); continue; }
            if (r <= 0) return sent;
            sent += r;
        }
    }
    return sent;
}

static void fill_msg(char *m, int id, int round, int len)
{
    int i;
    for (i = 0; i < len; i++) m[i] = (char)(id * 7 + round * 13 + i * 3 + (i >> 8));
}
static int msg_len(const pp_t *p, int round) { return 1 + (p->id * 31 + round * 17) % p->maxlen; }

static DWORD echo_side(void *arg)
{
    pp_t *p = (pp_t *)arg;
    SOCKET s = p->swap ? p->a : p->b;
    char *buf = malloc(p->maxlen + 1);
    int r;
    if (!buf) return 1;
    for (r = 0; r < p->rounds || !p->udp; r++) {
        int n = rx(p->style, s, buf, p->maxlen);
        if (n <= 0) { if (p->udp || n < 0) { if (r < p->rounds) InterlockedIncrement(&p->bad); } break; }
        if (tx_all(p->style, s, buf, n) != n) { InterlockedIncrement(&p->bad); break; }
        if (p->udp && r + 1 == p->rounds) break;
    }
    free(buf);
    return 0;
}

static DWORD init_side(void *arg)
{
    pp_t *p = (pp_t *)arg;
    SOCKET s = p->swap ? p->b : p->a;
    char *out = malloc(p->maxlen + 1), *in = malloc(p->maxlen + 1);
    int r;
    if (!out || !in) { free(out); free(in); return 1; }
    for (r = 0; r < p->rounds; r++) {
        int len = msg_len(p, r), got = 0;
        fill_msg(out, p->id, r, len);
        if (tx_all(p->style, s, out, len) != len) { InterlockedIncrement(&p->bad); break; }
        while (got < len) {
            int n = rx(p->style, s, in + got, len - got);
            if (n <= 0) break;
            got += n;
            if (p->udp) break;
        }
        if (got != len || memcmp(in, out, len)) { InterlockedIncrement(&p->bad); break; }
        p->echoed += len; p->done_rounds++;
    }
    if (!p->udp) shutdown(s, SD_SEND);
    free(out); free(in);
    return 0;
}

static DWORD WINAPI th_echo(void *a) { return echo_side(a); }
static DWORD WINAPI th_init(void *a) { return init_side(a); }

static int make_udp_pair(pp_t *p)
{
    struct sockaddr_in aa, ba;
    p->a = xs_udp(&aa); p->b = xs_udp(&ba);
    if (p->a == INVALID_SOCKET || p->b == INVALID_SOCKET) return 0;
    return connect(p->a, (struct sockaddr *)&ba, sizeof ba) == 0 && connect(p->b, (struct sockaddr *)&aa, sizeof aa) == 0;
}

static void run_pingpong(int style, int udp, int rounds, int maxlen, int nodelay, int swap)
{
    static pp_t pp[NPAIRS];
    HANDLE th[NPAIRS * 2]; int i, made = 0, finished = 0, bad = 0, total_rounds = 0; long long total = 0, expect = 0;
    XS_BEGIN();
    memset(pp, 0, sizeof pp);
    for (i = 0; i < NPAIRS; i++) {
        pp[i].id = i; pp[i].style = style; pp[i].udp = udp; pp[i].rounds = rounds; pp[i].maxlen = maxlen;
        pp[i].nodelay = nodelay; pp[i].swap = swap;
        if (udp ? make_udp_pair(&pp[i]) : xs_pair(&pp[i].a, &pp[i].b)) {
            LINGER lg = { 1, 0 };
            made++;
            xs_rcvtimeo(pp[i].a, XS_WAIT_MS); xs_rcvtimeo(pp[i].b, XS_WAIT_MS);
            if (!udp) {
                setsockopt(pp[i].a, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
                setsockopt(pp[i].b, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
                if (nodelay) { int one = 1; setsockopt(pp[i].a, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
                               setsockopt(pp[i].b, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one); }
            }
            if (style == M_NONBLOCK) { u_long nb = 1; ioctlsocket(pp[i].a, FIONBIO, &nb); ioctlsocket(pp[i].b, FIONBIO, &nb); }
        }
        { int r; for (r = 0; r < rounds; r++) expect += msg_len(&pp[i], r); }
    }
    EXPECT_EQ(made, NPAIRS);
    for (i = 0; i < NPAIRS; i++) {
        th[i * 2] = CreateThread(NULL, 0, th_echo, &pp[i], 0, NULL);
        th[i * 2 + 1] = CreateThread(NULL, 0, th_init, &pp[i], 0, NULL);
    }
    for (i = 0; i < NPAIRS * 2; i++) {
        if (!th[i]) continue;
        if (WaitForSingleObject(th[i], 25000) == WAIT_OBJECT_0) finished++; else TerminateThread(th[i], 1);
        CloseHandle(th[i]);
    }
    for (i = 0; i < NPAIRS; i++) {
        bad += pp[i].bad; total += pp[i].echoed; total_rounds += pp[i].done_rounds;
        if (pp[i].a != INVALID_SOCKET) closesocket(pp[i].a);
        if (pp[i].b != INVALID_SOCKET) closesocket(pp[i].b);
    }
    EXPECT_EQ(finished, NPAIRS * 2);
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(total_rounds, NPAIRS * rounds);
    CHECKF(total == expect, "echoed %lld expected %lld", total, expect);
    xs_end();
}

TEST(pingpong_50_tcp_blocking_200_rounds_small)       { run_pingpong(M_BLOCK, 0, 200, 64, 0, 0); }
TEST(pingpong_50_tcp_blocking_200_rounds_1500)        { run_pingpong(M_BLOCK, 0, 200, 1500, 0, 0); }
TEST(pingpong_50_tcp_blocking_100_rounds_20000)       { run_pingpong(M_BLOCK, 0, 100, 20000, 0, 0); }
TEST(pingpong_50_tcp_blocking_nodelay)                { run_pingpong(M_BLOCK, 0, 200, 200, 1, 0); }
TEST(pingpong_50_tcp_blocking_roles_swapped)          { run_pingpong(M_BLOCK, 0, 150, 700, 0, 1); }
TEST(pingpong_50_tcp_nonblocking_select)              { run_pingpong(M_NONBLOCK, 0, 150, 900, 0, 0); }
TEST(pingpong_50_tcp_overlapped_event)                { run_pingpong(M_OVERLAPPED, 0, 150, 900, 0, 0); }
TEST(pingpong_50_tcp_overlapped_event_large)          { run_pingpong(M_OVERLAPPED, 0, 60, 30000, 0, 0); }
TEST(pingpong_50_udp_connected_blocking)              { run_pingpong(M_BLOCK, 1, 200, 1200, 0, 0); }
TEST(pingpong_50_udp_connected_nonblocking_select)    { run_pingpong(M_NONBLOCK, 1, 150, 1200, 0, 0); }
TEST(pingpong_50_udp_connected_overlapped_event)      { run_pingpong(M_OVERLAPPED, 1, 150, 1200, 0, 0); }
TEST(pingpong_50_udp_one_byte_messages)               { run_pingpong(M_BLOCK, 1, 300, 1, 0, 0); }

/* Every conversation thread runs its own WSAStartup/WSACleanup pair around its socket work. */
typedef struct { int id, ok; } own_t;
static DWORD own_thread(void *p)
{
    own_t *o = (own_t *)p;
    WSADATA d; SOCKET c, s; int r, good = 1;
    if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return 1;
    if (!xs_pair(&c, &s)) { WSACleanup(); return 1; }
    xs_rcvtimeo(c, XS_WAIT_MS); xs_rcvtimeo(s, XS_WAIT_MS);
    for (r = 0; r < 100; r++) {
        char m[16], e[16]; int len = 1 + (o->id + r) % 16;
        fill_msg(m, o->id, r, len);
        if (send(c, m, len, 0) != len || xs_recv_n(s, e, len) != len || memcmp(m, e, len)) good = 0;
        if (send(s, e, len, 0) != len || xs_recv_n(c, m, len) != len || memcmp(m, e, len)) good = 0;
    }
    { LINGER lg = { 1, 0 }; setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
      setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg); }
    closesocket(c); closesocket(s);
    WSACleanup();
    o->ok = good;
    return 0;
}
TEST(pingpong_50_threads_each_with_own_startup_cleanup)
{
    own_t o[NPAIRS]; DWORD res[NPAIRS]; int i, ok = 0, fin;
    XS_BEGIN();
    for (i = 0; i < NPAIRS; i++) { o[i].id = i; o[i].ok = 0; res[i] = 99; }
    fin = xs_run_threads(NPAIRS, own_thread, o, sizeof o[0], 25000, res);
    EXPECT_EQ(fin, NPAIRS);
    for (i = 0; i < NPAIRS; i++) { ok += o[i].ok; }
    EXPECT_EQ(ok, NPAIRS);
    xs_end();
}

/* One shared datagram socket pair used by 50 sender threads concurrently: each message carries sender id and
 * sequence; the receiver sees every datagram exactly once (loopback with a big receive buffer). */
typedef struct { SOCKET s; int id; int count; } shared_snd;
static DWORD shared_sender(void *p)
{
    shared_snd *a = (shared_snd *)p;
    int k, sent = 0;
    for (k = 0; k < a->count; k++) {
        int m[3] = { a->id, k, ~(a->id ^ k) };
        for (;;) {
            int r = send(a->s, (const char *)m, sizeof m, 0);
            if (r == sizeof m) { sent++; break; }
            if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAENOBUFS) { Sleep(1); continue; }
            break;
        }
        if ((k & 15) == 15) Sleep(1);   /* let the receiver drain; keeps loss out of the picture */
    }
    return sent;
}
TEST(pingpong_50_threads_share_one_udp_sender_socket_no_dup_no_corruption)
{
    static unsigned char seen[NPAIRS][40];
    struct sockaddr_in ra; SOCKET rx_s, tx_s; shared_snd a[NPAIRS]; DWORD res[NPAIRS]; int i, got = 0, dup = 0, corrupt = 0, fin;
    int bufsz = 4 * 1024 * 1024;
    XS_BEGIN();
    memset(seen, 0, sizeof seen);
    rx_s = xs_udp(&ra);
    tx_s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (rx_s == INVALID_SOCKET || tx_s == INVALID_SOCKET || connect(tx_s, (struct sockaddr *)&ra, sizeof ra)) {
        t_skip("no datagram pair"); xs_end(); return;
    }
    setsockopt(rx_s, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof bufsz);
    xs_rcvtimeo(rx_s, 1500);
    for (i = 0; i < NPAIRS; i++) { a[i].s = tx_s; a[i].id = i; a[i].count = 40; res[i] = 0; }
    {
        HANDLE th[NPAIRS];
        for (i = 0; i < NPAIRS; i++) {
            struct { shared_snd *s; } unused; (void)unused;
            th[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shared_sender, &a[i], 0, NULL);
        }
        for (;;) {
            int m[3];
            int r = recv(rx_s, (char *)m, sizeof m, 0);
            if (r != sizeof m) break;
            got++;
            if (m[2] != ~(m[0] ^ m[1]) || m[0] < 0 || m[0] >= NPAIRS || m[1] < 0 || m[1] >= 40) { corrupt++; continue; }
            if (seen[m[0]][m[1]]++) dup++;
        }
        fin = 0;
        for (i = 0; i < NPAIRS; i++) {
            if (WaitForSingleObject(th[i], 10000) == WAIT_OBJECT_0) { fin++; GetExitCodeThread(th[i], &res[i]); }
            CloseHandle(th[i]);
        }
    }
    EXPECT_EQ(fin, NPAIRS);
    EXPECT_EQ(dup, 0);
    EXPECT_EQ(corrupt, 0);
    { int sent = 0; for (i = 0; i < NPAIRS; i++) sent += (int)res[i];
      EXPECT_EQ(sent, NPAIRS * 40);
      CHECKF(got <= sent && got > 0, "received %d of %d", got, sent); }
    closesocket(rx_s); closesocket(tx_s);
    xs_end();
}
