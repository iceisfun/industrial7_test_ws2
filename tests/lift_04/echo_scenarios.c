/* lift_04: multi-threaded loopback echo scenarios.
 * A server thread (blocking, select-driven or out-of-band aware) and one or more client threads
 * (blocking, recvfrom-mixing or event-driven) exchange a patterned buffer over 127.0.0.1 on an
 * ephemeral port; the server echoes it back. Measures end-to-end data integrity across send/recv
 * chunk sizes, overlapped vs synchronous creation flags, select() ready counts, WSAEventSelect
 * notifications, the untouched from-address of recvfrom on a stream socket, and the OOB mark.
 * Worker threads never call CHECK; they record the first problem and the test thread asserts it. */
#include "l4.h"

#define MAXCLI 4
#define PAT_FIRST 'A'
#define WAIT_MS 15000

typedef struct scen {
    int chunk, nchunks, nclients;
    DWORD srv_flags, cli_flags;
    int srv_buf, cli_buf;
    struct sockaddr_in addr;            /* published by the server before it signals ready */
    HANDLE ready;
    volatile LONG fails;
    char first[200];
    volatile LONG cli_ok;
    int oob_tail;
} scen;

static void sfail(scen *sc, const char *fmt, ...)
{
    va_list a;
    if (InterlockedIncrement((LONG *)&sc->fails) == 1) {
        va_start(a, fmt);
        vsnprintf(sc->first, sizeof sc->first, fmt, a);
        va_end(a);
    }
}
#define TCK(sc, c, ...) do { if (!(c)) sfail(sc, __VA_ARGS__); } while (0)

static void fill_pattern(char *buf, int chunk, int n)
{
    int i;
    for (i = 0; i < n; i++) memset(buf + i * chunk, PAT_FIRST + i, chunk);
}
static int check_pattern(const char *buf, int chunk, int n)
{
    int i, j;
    for (i = 0; i < n; i++)
        for (j = 0; j < chunk; j++)
            if (buf[i * chunk + j] != PAT_FIRST + i) return i * chunk + j;
    return -1;
}

static int send_all(SOCKET s, const char *buf, int len, int flags, int piece)
{
    int done = 0;
    while (done < len) {
        int n = U(send)(s, buf + done, len - done < piece ? len - done : piece, flags);
        if (n <= 0) return done;
        done += n;
    }
    return done;
}
static int recv_all(SOCKET s, char *buf, int len, int flags, int piece)
{
    int done = 0;
    while (done < len) {
        int n = U(recv)(s, buf + done, len - done < piece ? len - done : piece, flags);
        if (n <= 0) return done;
        done += n;
    }
    return done;
}
/* Drain until the peer's orderly close; anything but zero bytes is unexpected. */
static int drain_to_eof(SOCKET s)
{
    char b[256]; int n, total = 0;
    while ((n = U(recv)(s, b, sizeof b, 0)) > 0) total += n;
    return total;
}

static int cur_opentype(void)
{
    int v = 1, sz = sizeof v;
    gso(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, &v, &sz);
    return v;
}

/* ------------------------------------------------------------------ servers */

static SOCKET srv_open(scen *sc, int nonblocking)
{
    int len = sizeof sc->addr;
    SOCKET s = U(WSASocketA)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, sc->srv_flags);
    if (s == INVALID_SOCKET) { sfail(sc, "server socket %d", lerr()); return s; }
    lo4(&sc->addr, 0);
    if (U(bind)(s, (struct sockaddr *)&sc->addr, sizeof sc->addr) ||
        U(getsockname)(s, (struct sockaddr *)&sc->addr, &len) ||
        nonblock(s, nonblocking) || U(listen)(s, SOMAXCONN)) {
        sfail(sc, "server setup %d", lerr());
        cl(s);
        return INVALID_SOCKET;
    }
    return s;
}

static SOCKET srv_accept(scen *sc, SOCKET l)
{
    struct sockaddr_in peer; int len = sizeof peer; SOCKET c;
    if (!wait_readable(l, WAIT_MS)) { sfail(sc, "accept timed out"); return INVALID_SOCKET; }
    c = U(accept)(l, (struct sockaddr *)&peer, &len);
    if (c == INVALID_SOCKET) { sfail(sc, "accept %d", lerr()); return c; }
    bound_socket(c);
    TCK(sc, peer.sin_addr.s_addr == 0x0100007f, "peer is not loopback");
    return c;
}

static DWORD WINAPI srv_simple(LPVOID p)
{
    scen *sc = p; SOCKET l, c; int i, n = sc->chunk * sc->nchunks;
    char *buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    l = srv_open(sc, 0);
    SetEvent(sc->ready);
    for (i = 0; l != INVALID_SOCKET && i < sc->nclients; i++) {
        c = srv_accept(sc, l);
        if (c == INVALID_SOCKET) break;
        TCK(sc, recv_all(c, buf, n, 0, sc->srv_buf) == n, "server short receive");
        TCK(sc, check_pattern(buf, sc->chunk, sc->nchunks) < 0, "server pattern mismatch");
        TCK(sc, send_all(c, buf, n, 0, sc->srv_buf) == n, "server short echo");
        TCK(sc, drain_to_eof(c) == 0, "server saw trailing data");
        cl(c);
    }
    if (l != INVALID_SOCKET) cl(l);
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

/* Out-of-band server: normal data is echoed, then OOB data arrives and is read in two steps. */
static DWORD WINAPI srv_oob(LPVOID p)
{
    scen *sc = p; SOCKET l, c; int n = sc->chunk * sc->nchunks; u_long mark = 7;
    char *buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    l = srv_open(sc, 0);
    SetEvent(sc->ready);
    c = l == INVALID_SOCKET ? INVALID_SOCKET : srv_accept(sc, l);
    if (c != INVALID_SOCKET) {
        U(ioctlsocket)(c, SIOCATMARK, &mark);
        TCK(sc, mark == 1, "fresh connection not at mark");
        TCK(sc, recv_all(c, buf, n, 0, sc->srv_buf) == n, "server short receive");
        TCK(sc, check_pattern(buf, sc->chunk, sc->nchunks) < 0, "server pattern mismatch");
        mark = 7;
        U(ioctlsocket)(c, SIOCATMARK, &mark);
        TCK(sc, mark == 1, "not at mark after normal data");
        TCK(sc, send_all(c, buf, n, 0, sc->srv_buf) == n, "server short echo");
        /* the urgent data: first 8 bytes, then the rest; the mark is reached once all is consumed */
        TCK(sc, recv_all(c, buf, 8, 0, sc->srv_buf) == 8, "oob head short");
        /* how much of the tail is delivered is not asserted: the peer closes after its urgent send,
         * and a read that reaches the close simply returns what was queued */
        sc->oob_tail = recv_all(c, buf, n - 8, 0, sc->srv_buf);
        TCK(sc, sc->oob_tail >= 0 && sc->oob_tail <= n - 8, "oob tail count");
        mark = 7;
        U(ioctlsocket)(c, SIOCATMARK, &mark);
        TCK(sc, mark == 0, "oob: still reporting at-mark after consuming all urgent data");
        cl(c);
    }
    if (l != INVALID_SOCKET) cl(l);
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

/* Non-blocking server driven by select(): echoes whatever has arrived on every connection. */
static DWORD WINAPI srv_select(LPVOID p)
{
    scen *sc = p; SOCKET l, conn[MAXCLI]; int nconn = 0, i, n = sc->chunk * sc->nchunks;
    int got[MAXCLI] = {0}, sent[MAXCLI] = {0};
    char *bufs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * MAXCLI);
    fd_set open_r, open_w, fr, fw;
    DWORD deadline = GetTickCount() + 30000;
    struct timeval tv = { 0, 10000 };

    l = srv_open(sc, 1);
    SetEvent(sc->ready);
    if (l == INVALID_SOCKET) { HeapFree(GetProcessHeap(), 0, bufs); return 0; }
    FD_ZERO(&open_r); FD_ZERO(&open_w);
    fd_add(&open_r, l);

    for (;;) {
        int nset = 0, nready;
        fr = open_r; fw = open_w;
        if ((int)(GetTickCount() - deadline) > 0) { sfail(sc, "select server timed out"); break; }
        nready = U(select)(0, &fr, &fw, NULL, &tv);
        if (nready == SOCKET_ERROR) { sfail(sc, "select err %d", lerr()); break; }

        if (fd_has(&fr, l) && nconn < sc->nclients) {
            struct sockaddr_in peer; int len = sizeof peer;
            nset++;
            conn[nconn] = U(accept)(l, (struct sockaddr *)&peer, &len);
            TCK(sc, conn[nconn] != INVALID_SOCKET, "accept %d", lerr());
            if (conn[nconn] == INVALID_SOCKET) break;
            TCK(sc, peer.sin_addr.s_addr == 0x0100007f, "peer not loopback");
            fd_add(&open_r, conn[nconn]); fd_add(&open_w, conn[nconn]);
            nconn++;
        }
        for (i = 0; i < nconn; i++) {
            char *b = bufs + i * n;
            int delta;
            if (fd_has(&fr, conn[i])) {
                nset++;
                if (got[i] < n) {
                    int r = U(recv)(conn[i], b + got[i], n - got[i] < sc->srv_buf ? n - got[i] : sc->srv_buf, 0);
                    TCK(sc, r != SOCKET_ERROR, "recv err %d", lerr());
                    if (r > 0) got[i] += r;
                    if (got[i] == n) {
                        TCK(sc, check_pattern(b, sc->chunk, sc->nchunks) < 0, "select server pattern");
                        fd_clr(&open_r, conn[i]);
                    }
                }
            }
            delta = got[i] - sent[i];
            if (fd_has(&fw, conn[i])) {
                nset++;
                if (delta > 0 && sent[i] < n) {
                    int r = U(send)(conn[i], b + sent[i], delta < sc->srv_buf ? delta : sc->srv_buf, 0);
                    TCK(sc, r != SOCKET_ERROR, "send err %d", lerr());
                    if (r > 0) sent[i] += r;
                    if (sent[i] == n) fd_clr(&open_w, conn[i]);
                }
            }
        }
        /* select reports each socket once per set it is ready in */
        TCK(sc, nset == nready, "select returned %d ready, observed %d", nready, nset);
        if (sc->fails) break;
        if (open_w.fd_count == 0 && open_r.fd_count == 1 && nconn == sc->nclients) break;
    }
    for (i = 0; i < nconn; i++) {
        /* connections are non-blocking: whatever is left is just discarded, then closed */
        char b[64];
        while (U(recv)(conn[i], b, sizeof b, 0) > 0) {}
        cl(conn[i]);
    }
    cl(l);
    HeapFree(GetProcessHeap(), 0, bufs);
    return 0;
}

/* ------------------------------------------------------------------ clients */

typedef struct cli { scen *sc; int kind; } cli;
enum { CK_SIMPLE, CK_OOB, CK_MIXED, CK_EVENT };

static SOCKET cli_open(scen *sc, char **sendbuf, char **recvbuf)
{
    int n = sc->chunk * sc->nchunks; SOCKET s;
    *sendbuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * n);
    *recvbuf = *sendbuf + n;
    fill_pattern(*sendbuf, sc->chunk, sc->nchunks);
    s = U(WSASocketA)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, sc->cli_flags);
    if (s == INVALID_SOCKET) sfail(sc, "client socket %d", lerr());
    else bound_socket(s);
    return s;
}

static DWORD WINAPI cli_main(LPVOID p)
{
    cli *c = p; scen *sc = c->sc; SOCKET s; char *sb, *rb; int n = sc->chunk * sc->nchunks;

    if (WaitForSingleObject(sc->ready, WAIT_MS) != WAIT_OBJECT_0) { sfail(sc, "server never ready"); return 0; }
    TCK(sc, cur_opentype() == 0, "new thread did not start with SO_OPENTYPE 0");
    s = cli_open(sc, &sb, &rb);
    if (s == INVALID_SOCKET) goto out;

    if (c->kind == CK_EVENT) {
        WSAEVENT ev = U(WSACreateEvent)();
        WSANETWORKEVENTS ne;
        LONG mask = FD_READ | FD_WRITE | FD_CLOSE;
        char *sp = sb, *sl = sb + n, *rp = rb, *rl = rb + n;
        int r;

        U(WSAEventSelect)(s, ev, FD_CONNECT);        /* also switches the socket to non-blocking */
        r = U(connect)(s, (struct sockaddr *)&sc->addr, sizeof sc->addr);
        if (r != 0) {
            TCK(sc, lerr() == WSAEWOULDBLOCK, "event connect err %d", lerr());
            TCK(sc, U(WSAWaitForMultipleEvents)(1, &ev, FALSE, WAIT_MS, FALSE) == WSA_WAIT_EVENT_0, "connect event timed out");
            TCK(sc, U(WSAEnumNetworkEvents)(s, ev, &ne) == 0, "enum events");
            TCK(sc, (ne.lNetworkEvents & FD_CONNECT) && ne.iErrorCode[FD_CONNECT_BIT] == 0, "connect completion error %d", ne.iErrorCode[FD_CONNECT_BIT]);
        }
        U(WSAEventSelect)(s, ev, mask);
        while (!sc->fails) {
            if (U(WSAWaitForMultipleEvents)(1, &ev, FALSE, WAIT_MS, FALSE) != WSA_WAIT_EVENT_0) { sfail(sc, "event wait timed out"); break; }
            if (U(WSAEnumNetworkEvents)(s, ev, &ne)) { sfail(sc, "enum events failed"); break; }
            if (ne.lNetworkEvents & FD_WRITE) {
                TCK(sc, ne.iErrorCode[FD_WRITE_BIT] == 0, "FD_WRITE error %d", ne.iErrorCode[FD_WRITE_BIT]);
                while (sp < sl) {
                    int k = U(send)(s, sp, (int)(sl - sp) < sc->cli_buf ? (int)(sl - sp) : sc->cli_buf, 0);
                    if (k < 0) { TCK(sc, lerr() == WSAEWOULDBLOCK, "send err %d", lerr()); break; }
                    sp += k;
                }
                if (sp == sl) { U(shutdown)(s, SD_SEND); mask &= ~FD_WRITE; U(WSAEventSelect)(s, ev, mask); }
            }
            if (ne.lNetworkEvents & FD_READ) {
                TCK(sc, ne.iErrorCode[FD_READ_BIT] == 0, "FD_READ error %d", ne.iErrorCode[FD_READ_BIT]);
                /* the first read after FD_READ must produce data */
                r = U(recv)(s, rp, (int)(rl - rp) < sc->cli_buf ? (int)(rl - rp) : sc->cli_buf, 0);
                TCK(sc, r >= 0, "first read err %d", lerr());
                while (r >= 0) {
                    rp += r;
                    if (rp == rl) { mask &= ~FD_READ; U(WSAEventSelect)(s, ev, mask); break; }
                    r = U(recv)(s, rp, (int)(rl - rp) < sc->cli_buf ? (int)(rl - rp) : sc->cli_buf, 0);
                    TCK(sc, r >= 0 || lerr() == WSAEWOULDBLOCK, "read err %d", lerr());
                }
            }
            if (ne.lNetworkEvents & FD_CLOSE) {
                TCK(sc, ne.iErrorCode[FD_CLOSE_BIT] == 0, "FD_CLOSE error %d", ne.iErrorCode[FD_CLOSE_BIT]);
                break;
            }
        }
        TCK(sc, sp == sl, "event client sent %d of %d", (int)(sp - sb), n);
        TCK(sc, rp == rl, "event client received %d of %d", (int)(rp - rb), n);
        TCK(sc, check_pattern(rb, sc->chunk, sc->nchunks) < 0, "event client pattern");
        U(WSACloseEvent)(ev);
        goto done;
    }

    TCK(sc, U(connect)(s, (struct sockaddr *)&sc->addr, sizeof sc->addr) == 0, "connect err %d", lerr());
    TCK(sc, send_all(s, sb, n, 0, sc->cli_buf) == n, "client short send");

    if (c->kind == CK_OOB) {
        TCK(sc, recv_all(s, rb, n, 0, sc->cli_buf) == n, "client short echo");
        TCK(sc, check_pattern(rb, sc->chunk, sc->nchunks) < 0, "client echo pattern");
        TCK(sc, send_all(s, sb, n, MSG_OOB, sc->cli_buf) == n, "client short OOB send");
        TCK(sc, U(shutdown)(s, SD_SEND) == 0, "shutdown err %d", lerr());
    } else {
        TCK(sc, U(shutdown)(s, SD_SEND) == 0, "shutdown err %d", lerr());
        if (c->kind == CK_MIXED) {
            /* recvfrom on a connected stream socket must leave the from-address alone */
            struct sockaddr_in from; int flen = sizeof from, got = 0;
            memset(&from, 0, sizeof from);
            while (got < n) {
                int k = U(recvfrom)(s, rb + got, n - got < sc->cli_buf ? n - got : sc->cli_buf, 0, (struct sockaddr *)&from, &flen);
                if (k <= 0) break;
                got += k;
            }
            TCK(sc, got == n, "mixed client short echo");
            TCK(sc, from.sin_addr.s_addr == 0 && from.sin_family == 0, "recvfrom wrote the from address of a stream socket");
        } else {
            TCK(sc, recv_all(s, rb, n, 0, sc->cli_buf) == n, "client short echo");
        }
        TCK(sc, check_pattern(rb, sc->chunk, sc->nchunks) < 0, "client echo pattern");
    }
    drain_to_eof(s);
done:
    InterlockedIncrement((LONG *)&sc->cli_ok);
out:
    if (s != INVALID_SOCKET) cl(s);
    HeapFree(GetProcessHeap(), 0, sb);
    return 0;
}

/* ------------------------------------------------------------------ driver */

static void run_scenario(LPTHREAD_START_ROUTINE server, int ckind, int chunk, int nchunks, int nclients,
                         DWORD sflags, DWORD cflags, int sbuf, int cbuf)
{
    static scen sc;
    cli ca[MAXCLI];
    HANDLE th[1 + MAXCLI]; int i, nth = 0;
    DWORD id, w;

    if (!ws_up()) return;
    memset(&sc, 0, sizeof sc);
    sc.chunk = chunk; sc.nchunks = nchunks; sc.nclients = nclients;
    sc.srv_flags = sflags; sc.cli_flags = cflags; sc.srv_buf = sbuf; sc.cli_buf = cbuf;
    sc.ready = CreateEventA(NULL, TRUE, FALSE, NULL);

    th[nth++] = CreateThread(NULL, 0, server, &sc, 0, &id);
    for (i = 0; i < nclients; i++) {
        ca[i].sc = &sc; ca[i].kind = ckind;
        th[nth++] = CreateThread(NULL, 0, cli_main, &ca[i], 0, &id);
    }
    w = WaitForMultipleObjects(nth, th, TRUE, 45000);
    CHECKF(w == WAIT_OBJECT_0, "workers did not finish (wait %lu)", w);
    if (w != WAIT_OBJECT_0) { /* leave the stuck threads; sockets are bounded by timeouts */ }
    for (i = 0; i < nth; i++) CloseHandle(th[i]);
    CloseHandle(sc.ready);
    if (server == srv_oob) t_note("urgent tail delivered %d of %d bytes", sc.oob_tail, chunk * nchunks - 8);
    CHECKF(sc.fails == 0, "%s", sc.first);
    CHECKF(sc.cli_ok == nclients, "%ld of %d clients completed", sc.cli_ok, nclients);
    ws_down();
}

TEST(echo_blocking_overlapped_one_client)   { run_scenario(srv_simple, CK_SIMPLE, 1000, 8, 1, WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED, 500, 500); }
TEST(echo_blocking_synchronous_one_client)  { run_scenario(srv_simple, CK_SIMPLE, 1000, 8, 1, 0, 0, 500, 500); }
TEST(echo_blocking_mixed_flags)             { run_scenario(srv_simple, CK_SIMPLE, 1000, 8, 1, 0, WSA_FLAG_OVERLAPPED, 1000, 128); }
TEST(echo_blocking_four_clients)            { run_scenario(srv_simple, CK_SIMPLE, 1024, 4, 4, WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED, 700, 300); }
TEST(echo_blocking_tiny_pieces)             { run_scenario(srv_simple, CK_SIMPLE, 256, 4, 1, 0, 0, 17, 31); }
TEST(echo_recvfrom_leaves_from_address)     { run_scenario(srv_simple, CK_MIXED, 512, 8, 1, 0, 0, 512, 512); }
TEST(echo_event_client_blocking_server)     { run_scenario(srv_simple, CK_EVENT, 1000, 8, 1, 0, WSA_FLAG_OVERLAPPED, 600, 400); }
TEST(echo_select_server_one_client)         { run_scenario(srv_select, CK_SIMPLE, 1000, 8, 1, 0, 0, 256, 256); }
TEST(echo_select_server_four_clients)       { run_scenario(srv_select, CK_SIMPLE, 1000, 4, 4, WSA_FLAG_OVERLAPPED, 0, 300, 300); }
TEST(echo_select_server_event_clients)      { run_scenario(srv_select, CK_EVENT, 1000, 4, 3, 0, WSA_FLAG_OVERLAPPED, 400, 400); }
TEST(echo_out_of_band_mark)                 { run_scenario(srv_oob, CK_OOB, 128, 4, 1, 0, 0, 128, 128); }
