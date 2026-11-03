/* TCP echo scenarios over loopback with different I/O styles on each side: blocking client/server,
 * WSAEventSelect-driven client, non-blocking select()-driven server (including the exact count that
 * select() returns), out-of-band data with SIOCATMARK, and a client that reads with recvfrom() on a
 * connected stream socket (the address argument must be left alone). Two clients run concurrently
 * where the scenario has more than one. Worker threads only record failures; the test thread
 * reports them. Every wait is bounded. */
#include "ws.h"

enum { SRV_SYNC, SRV_SELECT, SRV_OOB };
enum { CLI_SYNC, CLI_EVENT, CLI_OOB, CLI_MIXED };

typedef struct {
    int srv_mode, cli_mode;
    int chunk, nchunks, nclients;
    int srv_piece, cli_piece;
    SOCKET listener;
    unsigned short port;                 /* network order */
    volatile LONG bad;
    char msg[160];
} scen;

#define FAILT(sc, ...) do { if (InterlockedIncrement(&(sc)->bad) == 1) snprintf((sc)->msg, sizeof (sc)->msg, __VA_ARGS__); } while (0)
#define TOTAL(sc) ((sc)->chunk * (sc)->nchunks)
#define MAXBUF 40000

static void fill(unsigned char *b, int n) { int i; for (i = 0; i < n; i++) b[i] = (unsigned char)(i * 31 + i / 7); }
static int pattern_ok(const unsigned char *b, int n) {
    int i; for (i = 0; i < n; i++) if (b[i] != (unsigned char)(i * 31 + i / 7)) return 0;
    return 1;
}
static int send_all(SOCKET s, const char *b, int n, int flags, int piece) {
    int done = 0;
    while (done < n) {
        int k = w_send(s, b + done, n - done < piece ? n - done : piece, flags);
        if (k <= 0) return -1;
        done += k;
    }
    return done;
}
static int recv_all(SOCKET s, char *b, int n, int piece) {
    int done = 0;
    while (done < n) {
        int k = w_recv(s, b + done, n - done < piece ? n - done : piece, 0);
        if (k < 0) return -1;
        if (k == 0) break;
        done += k;
    }
    return done;
}
/* after the peer shut down its send side the next read must report a clean end of stream */
static int expect_eof(SOCKET s) { char c; return w_recv(s, &c, 1, 0) == 0; }

/* ---- servers ---- */
static DWORD WINAPI srv_sync(void *arg) {
    scen *sc = arg; int c, n = TOTAL(sc);
    static unsigned char buf[MAXBUF];
    for (c = 0; c < sc->nclients; c++) {
        SOCKET s = w_accept_to(sc->listener, 15000);
        if (s == INVALID_SOCKET) { FAILT(sc, "accept timed out"); return 0; }
        w_set_rcvtimeo(s, 10000);
        if (recv_all(s, (char *)buf, n, sc->srv_piece) != n) FAILT(sc, "server short receive");
        else if (!pattern_ok(buf, n)) FAILT(sc, "server pattern mismatch");
        if (send_all(s, (char *)buf, n, 0, sc->srv_piece) != n) FAILT(sc, "server short echo");
        if (!expect_eof(s)) FAILT(sc, "server expected end of stream");
        w_close(s);
    }
    return 0;
}

static DWORD WINAPI srv_oob(void *arg) {
    scen *sc = arg; int n = TOTAL(sc), got;
    static unsigned char buf[MAXBUF];
    unsigned long mark = 0;
    SOCKET s = w_accept_to(sc->listener, 15000);
    if (s == INVALID_SOCKET) { FAILT(sc, "accept timed out"); return 0; }
    w_set_rcvtimeo(s, 10000);
    mark = 0; w_ioctlsocket(s, SIOCATMARK, &mark);
    if (mark != 1) FAILT(sc, "initial atmark %lu", mark);
    if (recv_all(s, (char *)buf, n, sc->srv_piece) != n) FAILT(sc, "server short receive");
    else if (!pattern_ok(buf, n)) FAILT(sc, "server pattern mismatch");
    mark = 0; w_ioctlsocket(s, SIOCATMARK, &mark);
    if (mark != 1) FAILT(sc, "atmark after plain data %lu", mark);
    if (send_all(s, (char *)buf, n, 0, sc->srv_piece) != n) FAILT(sc, "server short echo");
    /* consume the out-of-band burst: 8 bytes first, then everything that follows */
    got = recv_all(s, (char *)buf, 8, sc->srv_piece);
    if (got != 8) FAILT(sc, "first oob read %d", got);
    got = recv_all(s, (char *)buf, n - 8, sc->srv_piece);
    /* every out-of-band send leaves exactly one byte in the urgent queue, outside the normal stream */
    if (got != n - 8 - sc->nchunks) FAILT(sc, "normal bytes after oob %d", got);
    mark = 1; w_ioctlsocket(s, SIOCATMARK, &mark);
    if (mark != 0) FAILT(sc, "atmark after oob consumed %lu", mark);
    { int k, tot = 0; char c1; for (;;) { k = w_recv(s, &c1, 1, MSG_OOB); if (k <= 0) break; tot += k; }
      if (tot != sc->nchunks) FAILT(sc, "urgent bytes drained %d", tot); }
    w_close(s);
    return 0;
}

typedef struct { SOCKET s; int nrecv, nsend; } conn;

static DWORD WINAPI srv_select(void *arg) {
    scen *sc = arg; int n = TOTAL(sc), nconn = 0, i;
    static unsigned char bufs[8][MAXBUF];
    conn cn[8]; fd_set open_r, open_w, r, w;
    DWORD deadline = GetTickCount() + 30000;
    memset(cn, 0, sizeof cn);
    w_nonblock(sc->listener, 1);
    open_r.fd_count = open_w.fd_count = 0;
    fds_add(&open_r, sc->listener);
    for (;;) {
        int ready, nset = 0;
        if ((LONG)(GetTickCount() - deadline) > 0) { FAILT(sc, "select server deadline"); break; }
        r = open_r; w = open_w;
        ready = w_select(&r, &w, NULL, 10);
        if (ready == SOCKET_ERROR) { FAILT(sc, "select error %d", w_err()); break; }
        if (fds_has(&r, sc->listener)) {
            SOCKET a;
            nset++;
            a = w_accept(sc->listener, NULL, NULL);
            if (a == INVALID_SOCKET || nconn >= 8) { FAILT(sc, "accept failed %d", w_err()); break; }
            cn[nconn].s = a; fds_add(&open_r, a); fds_add(&open_w, a); nconn++;
        }
        for (i = 0; i < nconn; i++) {
            int delta;
            if (fds_has(&r, cn[i].s)) {
                nset++;
                if (cn[i].nrecv < n) {
                    int k = w_recv(cn[i].s, (char *)bufs[i] + cn[i].nrecv,
                                   n - cn[i].nrecv < sc->srv_piece ? n - cn[i].nrecv : sc->srv_piece, 0);
                    if (k == SOCKET_ERROR) { FAILT(sc, "recv error %d", w_err()); k = 0; }
                    cn[i].nrecv += k;
                    if (cn[i].nrecv == n) {
                        if (!pattern_ok(bufs[i], n)) FAILT(sc, "pattern mismatch");
                        fds_del(&open_r, cn[i].s);
                    }
                }
            }
            delta = cn[i].nrecv - cn[i].nsend;
            if (fds_has(&w, cn[i].s)) {
                nset++;
                if (delta > 0 && cn[i].nsend < n) {
                    int k = w_send(cn[i].s, (char *)bufs[i] + cn[i].nsend, delta < sc->srv_piece ? delta : sc->srv_piece, 0);
                    if (k == SOCKET_ERROR) { FAILT(sc, "send error %d", w_err()); k = 0; }
                    cn[i].nsend += k;
                    if (cn[i].nsend == n) fds_del(&open_w, cn[i].s);
                }
            }
        }
        if (nset != ready) { FAILT(sc, "select returned %d, %d sockets flagged", ready, nset); break; }
        if (open_w.fd_count == 0 && open_r.fd_count == 1 && nconn == sc->nclients) break;
        if (sc->bad) break;
    }
    for (i = 0; i < nconn; i++) w_close(cn[i].s);
    return 0;
}

/* ---- clients ---- */
static void connect_to(scen *sc, SOCKET s) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = sc->port; a.sin_addr.s_addr = h32(0x7f000001u);
    if (w_connect(s, &a, sizeof a) != 0) FAILT(sc, "connect error %d", w_err());
}

static void cli_sync(scen *sc, int mixed, int oob) {
    int n = TOTAL(sc);
    unsigned char sb[MAXBUF], rb[MAXBUF];
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in from; int fromlen = sizeof from, got = 0;
    fill(sb, n);
    connect_to(sc, s);
    w_set_rcvtimeo(s, 10000);
    if (send_all(s, (char *)sb, n, 0, sc->cli_piece) != n) FAILT(sc, "client short send");
    if (mixed) {
        w_shutdown(s, SD_SEND);
        memset(&from, 0, sizeof from);                    /* family 0, address 0.0.0.0 */
        while (got < n) {
            int k = w_recvfrom(s, rb + got, n - got < sc->cli_piece ? n - got : sc->cli_piece, 0, &from, &fromlen);
            if (k <= 0) break;
            got += k;
        }
        if (got != n) FAILT(sc, "client short receive");
        /* connection-oriented sockets never fill in the source address */
        if (from.sin_addr.s_addr != 0 || from.sin_family != 0) FAILT(sc, "recvfrom wrote the address");
    } else {
        got = recv_all(s, (char *)rb, n, sc->cli_piece);
        if (got != n) FAILT(sc, "client short receive");
    }
    if (got == n && !pattern_ok(rb, n)) FAILT(sc, "client pattern mismatch");
    if (oob) {
        if (send_all(s, (char *)sb, n, MSG_OOB, sc->cli_piece) != n) FAILT(sc, "client short oob send");
        w_shutdown(s, SD_SEND);
    } else if (!mixed) {
        w_shutdown(s, SD_SEND);
    }
    { char c; int k = w_recv(s, &c, 1, 0); if (k != 0) FAILT(sc, "client expected end of stream (rc=%d err=%d oob=%d)", k, w_err(), oob); }
    w_close(s);
}

static void cli_event(scen *sc) {
    int n = TOTAL(sc), err, k;
    unsigned char sb[MAXBUF], rb[MAXBUF];
    char *sp = (char *)sb, *rp = (char *)rb, *se = (char *)sb + n, *re = (char *)rb + n;
    SOCKET s = w_socket(AF_INET, SOCK_STREAM, 0);
    HANDLE ev = U(WSACreateEvent)();
    WSANETWORKEVENTS ne; long mask = FD_READ | FD_WRITE | FD_CLOSE;
    struct sockaddr_in a; DWORD deadline = GetTickCount() + 30000;
    fill(sb, n);
    U(WSAEventSelect)(s, ev, FD_CONNECT);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = sc->port; a.sin_addr.s_addr = h32(0x7f000001u);
    if (w_connect(s, &a, sizeof a) != 0) {
        if (w_err() != WSAEWOULDBLOCK) FAILT(sc, "connect error %d", w_err());
        if (WaitForSingleObject(ev, 10000) != WAIT_OBJECT_0) { FAILT(sc, "no connect event"); goto out; }
        if (U(WSAEnumNetworkEvents)(s, ev, &ne) != 0) { FAILT(sc, "enum events failed"); goto out; }
        if (!(ne.lNetworkEvents & FD_CONNECT) || ne.iErrorCode[FD_CONNECT_BIT] != 0) { FAILT(sc, "connect event bad"); goto out; }
    }
    U(WSAEventSelect)(s, ev, mask);
    for (;;) {
        if ((LONG)(GetTickCount() - deadline) > 0) { FAILT(sc, "event client deadline"); break; }
        if (WaitForSingleObject(ev, 10000) != WAIT_OBJECT_0) { FAILT(sc, "event wait timed out"); break; }
        if (U(WSAEnumNetworkEvents)(s, ev, &ne) != 0) { FAILT(sc, "enum events failed"); break; }
        if (ne.lNetworkEvents & FD_WRITE) {
            if (ne.iErrorCode[FD_WRITE_BIT]) FAILT(sc, "FD_WRITE error %d", ne.iErrorCode[FD_WRITE_BIT]);
            else do {
                int want = (int)(se - sp); if (want > sc->cli_piece) want = sc->cli_piece;
                k = w_send(s, sp, want, 0);
                if (k < 0) { err = w_err(); if (err != WSAEWOULDBLOCK) FAILT(sc, "send error %d", err); }
                else sp += k;
            } while (k >= 0 && sp < se);
            if (sp == se) { w_shutdown(s, SD_SEND); mask &= ~FD_WRITE; U(WSAEventSelect)(s, ev, mask); }
        }
        if (ne.lNetworkEvents & FD_READ) {
            if (ne.iErrorCode[FD_READ_BIT]) { FAILT(sc, "FD_READ error %d", ne.iErrorCode[FD_READ_BIT]); break; }
            do {
                int want = (int)(re - rp); if (want > sc->cli_piece) want = sc->cli_piece;
                k = w_recv(s, rp, want, 0);
                if (k < 0) { if (w_err() != WSAEWOULDBLOCK) FAILT(sc, "recv error %d", w_err()); break; }
                rp += k;
                if (rp == re) { mask &= ~FD_READ; U(WSAEventSelect)(s, ev, mask); break; }
            } while (k > 0);
        }
        if (ne.lNetworkEvents & FD_CLOSE) {
            if (ne.iErrorCode[FD_CLOSE_BIT]) FAILT(sc, "FD_CLOSE error %d", ne.iErrorCode[FD_CLOSE_BIT]);
            break;
        }
    }
    if (sp != se) FAILT(sc, "event client sent %d of %d", (int)(sp - (char *)sb), n);
    if (rp != re) FAILT(sc, "event client received %d of %d", (int)(rp - (char *)rb), n);
    else if (!pattern_ok(rb, n)) FAILT(sc, "event client pattern mismatch");
out:
    U(WSAEventSelect)(s, ev, 0);
    U(WSACloseEvent)(ev);
    w_close(s);
}

static DWORD WINAPI cli_thread(void *arg) {
    scen *sc = arg;
    switch (sc->cli_mode) {
    case CLI_SYNC:  cli_sync(sc, 0, 0); break;
    case CLI_MIXED: cli_sync(sc, 1, 0); break;
    case CLI_OOB:   cli_sync(sc, 0, 1); break;
    case CLI_EVENT: cli_event(sc); break;
    }
    return 0;
}

static void run_scen(scen *sc) {
    struct sockaddr_in a; int n = sizeof a, i;
    HANDLE th[8]; HANDLE srv;
    if (!ws_up()) return;
    sc->bad = 0; sc->msg[0] = 0;
    sc->listener = w_socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = h32(0x7f000001u);
    CHECK(w_bind(sc->listener, &a, sizeof a) == 0);
    CHECK(w_listen(sc->listener, SOMAXCONN) == 0);
    CHECK(w_getsockname(sc->listener, &a, &n) == 0);
    sc->port = a.sin_port;
    srv = CreateThread(NULL, 0, sc->srv_mode == SRV_SYNC ? srv_sync : sc->srv_mode == SRV_OOB ? srv_oob : srv_select, sc, 0, NULL);
    for (i = 0; i < sc->nclients; i++) th[i] = CreateThread(NULL, 0, cli_thread, sc, 0, NULL);
    for (i = 0; i < sc->nclients; i++) { CHECK(WaitForSingleObject(th[i], 60000) == WAIT_OBJECT_0); CloseHandle(th[i]); }
    CHECK(WaitForSingleObject(srv, 60000) == WAIT_OBJECT_0);
    CloseHandle(srv);
    w_close(sc->listener);
    CHECKF(sc->bad == 0, "%s", sc->msg);
}

TEST(l5_echo_sync_server_sync_client) {
    scen sc = {SRV_SYNC, CLI_SYNC, 2048, 16, 2, 64, 128};
    run_scen(&sc);
}
TEST(l5_echo_sync_server_event_client) {
    scen sc = {SRV_SYNC, CLI_EVENT, 2048, 16, 2, 64, 128};
    run_scen(&sc);
}
TEST(l5_echo_select_server_sync_client) {
    scen sc = {SRV_SELECT, CLI_SYNC, 2048, 16, 2, 64, 128};
    run_scen(&sc);
}
TEST(l5_echo_out_of_band_atmark) {
    scen sc = {SRV_OOB, CLI_OOB, 128, 16, 1, 128, 128};
    run_scen(&sc);
}
TEST(l5_echo_sync_server_recvfrom_client_address_untouched) {
    scen sc = {SRV_SYNC, CLI_MIXED, 2048, 16, 2, 64, 128};
    run_scen(&sc);
}
