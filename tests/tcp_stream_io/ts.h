/* Shared helpers for the tcp_stream_io area: loopback TCP pairs, bounded waits, deterministic payloads,
 * reader/writer threads.
 *
 * ws2_32.dll is never linked. Every Winsock entry used below is a macro that resolves the export with
 * LoadLibrary/GetProcAddress (pinned to ws2_32.dll) and calls through the pointer. The SDK headers are
 * included for type and constant definitions only. */
#ifndef TS_H
#define TS_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define W(name) UIN("ws2_32.dll", name)
#define WSAStartup(...)             W(WSAStartup)(__VA_ARGS__)
#define WSACleanup()                W(WSACleanup)()
#define WSAGetLastError()           W(WSAGetLastError)()
#define WSASetLastError(...)        W(WSASetLastError)(__VA_ARGS__)
#define socket(...)                 W(socket)(__VA_ARGS__)
#define closesocket(...)            W(closesocket)(__VA_ARGS__)
#define bind(...)                   W(bind)(__VA_ARGS__)
#define listen(...)                 W(listen)(__VA_ARGS__)
#define accept(...)                 W(accept)(__VA_ARGS__)
#define connect(...)                W(connect)(__VA_ARGS__)
#define send(...)                   W(send)(__VA_ARGS__)
#define recv(...)                   W(recv)(__VA_ARGS__)
#define sendto(...)                 W(sendto)(__VA_ARGS__)
#define shutdown(...)               W(shutdown)(__VA_ARGS__)
#define getsockname(...)            W(getsockname)(__VA_ARGS__)
#define getsockopt(...)             W(getsockopt)(__VA_ARGS__)
#define setsockopt(...)             W(setsockopt)(__VA_ARGS__)
#define ioctlsocket(...)            W(ioctlsocket)(__VA_ARGS__)
#define select(...)                 W(select)(__VA_ARGS__)
#define WSAIoctl(...)               W(WSAIoctl)(__VA_ARGS__)
#define WSARecv(...)                W(WSARecv)(__VA_ARGS__)
#define WSASend(...)                W(WSASend)(__VA_ARGS__)

/* The harness EXPECT_EQ evaluates its operands twice; calls with side effects need a single evaluation. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR tsa_ = (ULONG_PTR)(a), tsb_ = (ULONG_PTR)(b); \
    t_check(tsa_ == tsb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", \
            (unsigned long long)tsa_, (unsigned long long)tsb_); } while (0)

#define TS_POISON 0xdeadbeef
#define TS_WAIT_MS 5000            /* upper bound for every wait; tests never rely on it elapsing */

static int ts_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        state = (W(WSAStartup) && WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}
#define NEED_NET() do { if (!ts_up()) { t_skip("WSAStartup unavailable"); return; } } while (0)

static void ts_loop(struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007FUL;
}

static void ts_timeouts(SOCKET s, int ms)
{
    DWORD v = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof v);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&v, sizeof v);
}

static void ts_nonblock(SOCKET s, int on)
{
    u_long v = on ? 1 : 0;
    ioctlsocket(s, FIONBIO, &v);
}

static int ts_set_int(SOCKET s, int level, int opt, int v)
{
    return setsockopt(s, level, opt, (const char *)&v, sizeof v);
}

/* Listener on an ephemeral loopback port. */
static SOCKET ts_listener(struct sockaddr_in *addr)
{
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int len = sizeof *addr;
    ts_loop(addr);
    if (l == INVALID_SOCKET) return l;
    if (bind(l, (struct sockaddr *)addr, sizeof *addr) || getsockname(l, (struct sockaddr *)addr, &len) || listen(l, 4)) {
        closesocket(l);
        return INVALID_SOCKET;
    }
    return l;
}

/* A connected loopback pair; all waits on both ends are bounded by TS_WAIT_MS. */
static int ts_pair(SOCKET *cli, SOCKET *srv)
{
    struct sockaddr_in a;
    SOCKET l = ts_listener(&a), c, s;
    *cli = *srv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET) { closesocket(l); return 0; }
    if (connect(c, (struct sockaddr *)&a, sizeof a)) { closesocket(c); closesocket(l); return 0; }
    s = accept(l, NULL, NULL);
    closesocket(l);
    if (s == INVALID_SOCKET) { closesocket(c); return 0; }
    ts_timeouts(c, TS_WAIT_MS + 3000);
    ts_timeouts(s, TS_WAIT_MS + 3000);
    *cli = c;
    *srv = s;
    return 1;
}
#define NEED_PAIR(c, s) do { NEED_NET(); if (!ts_pair(&(c), &(s))) { t_skip("loopback pair unavailable"); return; } } while (0)
static void ts_close2(SOCKET a, SOCKET b)
{
    if (a != INVALID_SOCKET) closesocket(a);
    if (b != INVALID_SOCKET) closesocket(b);
}

/* Abortive close: SO_LINGER {on, 0} then closesocket, which sends a reset. */
static void ts_rst_close(SOCKET s)
{
    struct linger l = { 1, 0 };
    setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l);
    closesocket(s);
}

static int ts_readable(SOCKET s, int ms)
{
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &fds, NULL, NULL, &tv) > 0;
}

static int ts_writable(SOCKET s, int ms)
{
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, NULL, &fds, NULL, &tv) > 0;
}

static int ts_except(SOCKET s, int ms)
{
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, NULL, NULL, &fds, &tv) > 0;
}

static int ts_fionread(SOCKET s)
{
    u_long n = 0xffffffff;
    if (ioctlsocket(s, FIONREAD, &n)) return -1;
    return (int)n;
}

static int ts_atmark(SOCKET s)
{
    u_long v = 0xdead;
    if (ioctlsocket(s, SIOCATMARK, &v)) return -1;
    return v ? 1 : 0;
}

/* Waits (bounded) until at least n bytes are queued for reading on s. Returns the queued count. */
static int ts_wait_queued(SOCKET s, int n, int ms)
{
    DWORD t0 = GetTickCount();
    int q = ts_fionread(s);
    while (q >= 0 && q < n && (int)(GetTickCount() - t0) < ms) {
        Sleep(5);
        q = ts_fionread(s);
    }
    return q;
}

/* Blocking send of the whole buffer, looping over short sends. Returns bytes sent (< n on error). */
static int ts_send_all(SOCKET s, const char *p, int n)
{
    int done = 0;
    while (done < n) {
        int r = send(s, p + done, n - done, 0);
        if (r <= 0) break;
        done += r;
    }
    return done;
}

/* Blocking recv of exactly n bytes with plain recv (no MSG_WAITALL), looping. Returns bytes read. */
static int ts_recv_n(SOCKET s, char *p, int n)
{
    int done = 0;
    while (done < n) {
        int r = recv(s, p + done, n - done, 0);
        if (r <= 0) break;
        done += r;
    }
    return done;
}

/* Deterministic payload: byte i of a stream seeded with `seed`. */
static unsigned char ts_pat(unsigned seed, unsigned long long i)
{
    return (unsigned char)((i * 131u + (i >> 8) * 7u + seed * 37u) & 0xff);
}
static void ts_fill(char *p, int n, unsigned seed, unsigned long long off)
{
    for (int i = 0; i < n; i++) p[i] = (char)ts_pat(seed, off + (unsigned)i);
}
static int ts_verify(const char *p, int n, unsigned seed, unsigned long long off)
{
    for (int i = 0; i < n; i++) if ((unsigned char)p[i] != ts_pat(seed, off + (unsigned)i)) return 0;
    return 1;
}

/* ---- threads ------------------------------------------------------------ */
typedef struct {
    SOCKET s;
    unsigned seed;
    long long total;        /* writer: bytes to send; reader: out, bytes received */
    int chunk;              /* chunk size for send/recv calls */
    int delay_ms;           /* reader: sleep between recvs (0 = none) */
    int ok;                 /* out: payload verified / all bytes accepted */
    int err;                /* out: last Winsock error when the loop ended abnormally */
    int final_ret;          /* reader: last recv return value */
} ts_job;

/* Reads until EOF or error, verifying the deterministic pattern. */
static DWORD WINAPI ts_reader(LPVOID arg)
{
    ts_job *j = arg;
    char *buf = malloc(j->chunk > 0 ? j->chunk : 4096);
    int chunk = j->chunk > 0 ? j->chunk : 4096;
    long long got = 0;
    j->ok = 1;
    for (;;) {
        int r = recv(j->s, buf, chunk, 0);
        j->final_ret = r;
        if (r <= 0) { if (r < 0) j->err = WSAGetLastError(); break; }
        if (!ts_verify(buf, r, j->seed, (unsigned long long)got)) j->ok = 0;
        got += r;
        if (j->delay_ms) Sleep(j->delay_ms);
    }
    j->total = got;
    free(buf);
    return 0;
}

/* Sends j->total bytes of the pattern in j->chunk sized calls, then (if ok) leaves the socket open. */
static DWORD WINAPI ts_writer(LPVOID arg)
{
    ts_job *j = arg;
    int chunk = j->chunk > 0 ? j->chunk : 4096;
    char *buf = malloc(chunk);
    long long sent = 0;
    j->ok = 1;
    while (sent < j->total) {
        int n = (j->total - sent < chunk) ? (int)(j->total - sent) : chunk;
        int r;
        ts_fill(buf, n, j->seed, (unsigned long long)sent);
        r = ts_send_all(j->s, buf, n);
        if (r != n) { j->ok = 0; j->err = WSAGetLastError(); sent += r; break; }
        sent += r;
    }
    j->total = sent;
    free(buf);
    return 0;
}

static HANDLE ts_start(LPTHREAD_START_ROUTINE fn, ts_job *j)
{
    return CreateThread(NULL, 0, fn, j, 0, NULL);
}
static int ts_join(HANDLE h, DWORD ms)
{
    if (!h) return 0;
    if (WaitForSingleObject(h, ms) != WAIT_OBJECT_0) return 0;   /* leaked on purpose: a hung thread must not be closed */
    CloseHandle(h);
    return 1;
}
#endif
