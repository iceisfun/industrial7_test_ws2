/* 200-connection accept soaks: connector threads open loopback connections to an ephemeral listener while the
 * main thread accepts them with accept() (blocking and select-driven) or with AcceptEx (event, completion port,
 * with and without an initial receive). The number of connections accepted is asserted exactly, every accepted
 * peer must carry the distinct id its client sent, and cleanup leaves no pending request behind. */
#include "xs.h"

#define NCONN 200

typedef struct {
    struct sockaddr_in addr;
    int first, count;      /* ids first .. first+count-1 */
    SOCKET *out;           /* client sockets, indexed by id */
    int connected, sent;
} conn_job;

static DWORD conn_thread(void *p)
{
    conn_job *j = (conn_job *)p;
    int k;
    for (k = 0; k < j->count; k++) {
        int id = j->first + k;
        SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        LINGER lg = { 1, 0 };
        j->out[id] = INVALID_SOCKET;
        if (c == INVALID_SOCKET) continue;
        setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        if (connect(c, (struct sockaddr *)&j->addr, sizeof j->addr) != 0) { closesocket(c); continue; }
        j->connected++;
        if (send(c, (const char *)&id, sizeof id, 0) == sizeof id) j->sent++;
        j->out[id] = c;
    }
    return 0;
}

typedef struct { conn_job job[16]; HANDLE th[16]; int n; SOCKET clients[NCONN + 64]; } conn_pool;

static DWORD WINAPI conn_tramp(void *p) { return conn_thread(p); }

static void pool_start(conn_pool *cp, const struct sockaddr_in *a, int total, int nthreads, int first_id)
{
    int i, per = total / nthreads, id = first_id;
    memset(cp->th, 0, sizeof cp->th);
    cp->n = nthreads;
    for (i = 0; i < nthreads; i++) {
        conn_job *j = &cp->job[i];
        memset(j, 0, sizeof *j);
        j->addr = *a; j->first = id; j->count = (i == nthreads - 1) ? total - per * (nthreads - 1) : per;
        j->out = cp->clients;
        id += j->count;
        cp->th[i] = CreateThread(NULL, 0, conn_tramp, j, 0, NULL);
    }
}
/* returns total connected; sets *sent */
static int pool_join(conn_pool *cp, int *sent)
{
    int i, c = 0, s = 0;
    for (i = 0; i < cp->n; i++) {
        if (cp->th[i]) {
            if (WaitForSingleObject(cp->th[i], 30000) != WAIT_OBJECT_0) TerminateThread(cp->th[i], 1);
            CloseHandle(cp->th[i]);
        }
        c += cp->job[i].connected; s += cp->job[i].sent;
    }
    if (sent) *sent = s;
    return c;
}
static void pool_close_clients(conn_pool *cp, int n)
{
    int i;
    for (i = 0; i < n; i++) if (cp->clients[i] != 0 && cp->clients[i] != INVALID_SOCKET) closesocket(cp->clients[i]);
}

/* Accept `want` connections with plain accept(); each carries a distinct id. Returns how many were accepted. */
static int drain_accept(SOCKET l, int want, unsigned char *seen, int *id_bad, int *addr_bad, const struct sockaddr_in *la)
{
    int got = 0;
    while (got < want) {
        struct sockaddr_in pa; int pl = sizeof pa;
        SOCKET s;
        int id = -1;
        { /* a listener ignores SO_RCVTIMEO, so bound the wait with select instead of a blocking accept */
          fd_set rs; struct timeval tv = { XS_WAIT_MS / 1000, 0 };
          rs.fd_count = 1; rs.fd_array[0] = l;
          if (select(0, &rs, NULL, NULL, &tv) != 1) break; }
        s = accept(l, (struct sockaddr *)&pa, &pl);
        if (s == INVALID_SOCKET) break;
        if (pl != sizeof pa || pa.sin_family != AF_INET || pa.sin_addr.s_addr != 0x0100007Fu) (*addr_bad)++;
        xs_rcvtimeo(s, XS_WAIT_MS);
        if (xs_recv_n(s, (char *)&id, sizeof id) != sizeof id || id < 0 || id >= want || seen[id]) (*id_bad)++;
        else seen[id] = 1;
        { LINGER lg = { 1, 0 }; setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg); }
        closesocket(s);
        got++;
    }
    return got;
}

/* Accept everything currently queued on a nonblocking listener; returns the number accepted. */
static int drain_accept_nb(SOCKET l, unsigned char *seen, int *id_bad, int *addr_bad)
{
    int n = 0;
    for (;;) {
        struct sockaddr_in pa; int pl = sizeof pa, id = -1;
        SOCKET s = accept(l, (struct sockaddr *)&pa, &pl);
        if (s == INVALID_SOCKET) break;
        if (pa.sin_addr.s_addr != 0x0100007Fu) (*addr_bad)++;
        { u_long nb = 0; ioctlsocket(s, FIONBIO, &nb); }
        xs_rcvtimeo(s, XS_WAIT_MS);
        if (xs_recv_n(s, (char *)&id, sizeof id) != sizeof id || id < 0 || id >= NCONN || seen[id]) (*id_bad)++;
        else seen[id] = 1;
        closesocket(s); n++;
    }
    return n;
}

static void accept_blocking(int nthreads)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; unsigned char seen[NCONN] = { 0 };
    int got, id_bad = 0, addr_bad = 0, conn, sent;
    XS_BEGIN();
    cp = calloc(1, sizeof *cp);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !cp) { t_skip("no listener"); xs_end(); return; }
    xs_rcvtimeo(l, XS_WAIT_MS);
    pool_start(cp, &a, NCONN, nthreads, 0);
    got = drain_accept(l, NCONN, seen, &id_bad, &addr_bad, &a);
    conn = pool_join(cp, &sent);
    EXPECT_EQ(conn, NCONN);
    EXPECT_EQ(sent, NCONN);
    EXPECT_EQ(got, NCONN);
    EXPECT_EQ(id_bad, 0);
    EXPECT_EQ(addr_bad, 0);
    pool_close_clients(cp, NCONN);
    closesocket(l);
    free(cp);
    xs_end();
}
TEST(accept_200_blocking_1_connector_thread)  { accept_blocking(1); }
TEST(accept_200_blocking_4_connector_threads) { accept_blocking(4); }
TEST(accept_200_blocking_10_connector_threads){ accept_blocking(10); }

/* With nothing left in the queue and a nonblocking listener accept fails with WSAEWOULDBLOCK, each time. */
TEST(accept_empty_queue_nonblocking_200_polls_wouldblock)
{
    struct sockaddr_in a; SOCKET l; int i, bad = 0;
    XS_BEGIN();
    l = xs_listener(&a, 4);
    if (l == INVALID_SOCKET) { t_skip("no listener"); xs_end(); return; }
    { u_long nb = 1; ioctlsocket(l, FIONBIO, &nb); }
    for (i = 0; i < 200; i++) {
        WSASetLastError(0);
        if (accept(l, NULL, NULL) != INVALID_SOCKET || WSAGetLastError() != WSAEWOULDBLOCK) bad++;
    }
    EXPECT_EQ(bad, 0);
    closesocket(l);
    xs_end();
}

/* Nonblocking listener driven by select(): the listener reads ready once per pending connection batch and the
 * total accepted equals the total connected. */
TEST(accept_200_select_driven_nonblocking)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; int got = 0, spins = 0, conn, sent;
    unsigned char seen[NCONN] = { 0 }; int id_bad = 0;
    XS_BEGIN();
    cp = calloc(1, sizeof *cp);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !cp) { t_skip("no listener"); xs_end(); return; }
    { u_long nb = 1; ioctlsocket(l, FIONBIO, &nb); }
    pool_start(cp, &a, NCONN, 5, 0);
    while (got < NCONN && spins < 400) {
        fd_set r; struct timeval tv = { 0, 100000 };
        r.fd_count = 1; r.fd_array[0] = l; spins++;
        if (select(0, &r, NULL, NULL, &tv) < 1) continue;
        for (;;) {
            SOCKET s = accept(l, NULL, NULL);
            int id = -1;
            if (s == INVALID_SOCKET) break;
            { u_long nb = 0; ioctlsocket(s, FIONBIO, &nb); }
            xs_rcvtimeo(s, XS_WAIT_MS);
            if (xs_recv_n(s, (char *)&id, sizeof id) != sizeof id || id < 0 || id >= NCONN || seen[id]) id_bad++;
            else seen[id] = 1;
            closesocket(s); got++;
        }
    }
    conn = pool_join(cp, &sent);
    EXPECT_EQ(conn, NCONN);
    EXPECT_EQ(got, NCONN);
    EXPECT_EQ(id_bad, 0);
    pool_close_clients(cp, NCONN);
    closesocket(l);
    free(cp);
    xs_end();
}

/* Listener whose connections are all established before the first accept: backlog large enough, exact drain,
 * then one more accept on a nonblocking listener says would-block. Connects are issued with nonblocking
 * sockets and completion is observed with select on the write set. */
TEST(accept_200_prequeued_then_drained_exactly)
{
    struct sockaddr_in a; SOCKET l; SOCKET cs[NCONN]; int i, ok = 0, got = 0;
    unsigned char seen[NCONN] = { 0 }; int id_bad = 0, addr_bad = 0;
    XS_BEGIN();
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET) { t_skip("no listener"); xs_end(); return; }
    for (i = 0; i < NCONN; i++) {
        LINGER lg = { 1, 0 };
        cs[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        setsockopt(cs[i], SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        if (connect(cs[i], (struct sockaddr *)&a, sizeof a) == 0) {
            if (send(cs[i], (const char *)&i, sizeof i, 0) == sizeof i) ok++;
        }
    }
    if (ok != NCONN) t_note("only %d of %d connections queued before accept", ok, NCONN);
    { u_long nb = 1; ioctlsocket(l, FIONBIO, &nb); }
    {
        int spins = 0;
        while (got < ok && spins++ < 400) {
            fd_set r; struct timeval tv = { 0, 50000 };
            r.fd_count = 1; r.fd_array[0] = l;
            if (select(0, &r, NULL, NULL, &tv) < 1) continue;
            got += drain_accept_nb(l, seen, &id_bad, &addr_bad);
        }
    }
    EXPECT_EQ(ok, NCONN);
    EXPECT_EQ(got, ok);
    EXPECT_EQ(id_bad, 0);
    WSASetLastError(0);
    EXPECT_EQ(accept(l, NULL, NULL), INVALID_SOCKET);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    for (i = 0; i < NCONN; i++) if (cs[i] != INVALID_SOCKET) closesocket(cs[i]);
    closesocket(l);
    xs_end();
}

/* ---- AcceptEx ---------------------------------------------------------------------------------------------- */
#define ADDRLEN (sizeof(struct sockaddr_in) + 16)
#define ABUF (2 * ADDRLEN + 16)

static LPFN_ACCEPTEX pAcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS pGetAddrs;

static int load_acceptex(SOCKET s)
{
    GUID g1 = WSAID_ACCEPTEX, g2 = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD n = 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g1, sizeof g1, &pAcceptEx, sizeof pAcceptEx, &n, NULL, NULL)) return 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g2, sizeof g2, &pGetAddrs, sizeof pGetAddrs, &n, NULL, NULL)) return 0;
    return 1;
}

typedef struct { WSAOVERLAPPED ov; SOCKET s; char buf[ABUF]; } post_t;

static int post_accept(SOCKET l, post_t *p, DWORD recvlen, HANDLE ev)
{
    DWORD got = 0;
    memset(&p->ov, 0, sizeof p->ov);
    p->ov.hEvent = ev;
    p->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (p->s == INVALID_SOCKET) return 0;
    if (pAcceptEx(l, p->s, p->buf, recvlen, ADDRLEN, ADDRLEN, &got, &p->ov)) return 1;
    return WSAGetLastError() == ERROR_IO_PENDING;
}

static void ctx_and_check_id(SOCKET l, post_t *p, int *id_bad, unsigned char *seen)
{
    int id = -1;
    setsockopt(p->s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&l, sizeof l);
    xs_rcvtimeo(p->s, XS_WAIT_MS);
    if (xs_recv_n(p->s, (char *)&id, sizeof id) != sizeof id || id < 0 || id >= NCONN || seen[id]) (*id_bad)++;
    else seen[id] = 1;
}

/* 200 posted AcceptEx with one event each, 200 connectors; wait for each in turn. */
TEST(acceptex_200_event_completions_exact)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; post_t *p; int i, ok = 0, id_bad = 0, conn, sent, posted = 0;
    unsigned char seen[NCONN] = { 0 };
    XS_BEGIN();
    cp = calloc(1, sizeof *cp); p = calloc(NCONN, sizeof *p);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    for (i = 0; i < NCONN; i++) posted += post_accept(l, &p[i], 0, WSACreateEvent());
    EXPECT_EQ(posted, NCONN);
    pool_start(cp, &a, NCONN, 5, 0);
    for (i = 0; i < NCONN; i++) {
        DWORD bytes = 99, fl = 0;
        if (WSAGetOverlappedResult(p[i].s, &p[i].ov, &bytes, FALSE, &fl) == FALSE &&
            WaitForSingleObject(p[i].ov.hEvent, XS_WAIT_MS) != WAIT_OBJECT_0) continue;
        if (WSAGetOverlappedResult(p[i].s, &p[i].ov, &bytes, FALSE, &fl) && bytes == 0) {
            ok++;
            ctx_and_check_id(l, &p[i], &id_bad, seen);
        }
    }
    conn = pool_join(cp, &sent);
    EXPECT_EQ(conn, NCONN);
    EXPECT_EQ(ok, NCONN);
    EXPECT_EQ(id_bad, 0);
    for (i = 0; i < NCONN; i++) { if (p[i].s != INVALID_SOCKET) closesocket(p[i].s); WSACloseEvent(p[i].ov.hEvent); }
    pool_close_clients(cp, NCONN);
    closesocket(l); free(cp); free(p);
    xs_end();
}

/* The accepted socket after SO_UPDATE_ACCEPT_CONTEXT reports the listener's local port and a loopback peer. */
TEST(acceptex_200_context_update_gives_peer_and_local_names)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; post_t *p; int i, name_bad = 0, parsed_bad = 0, ok = 0;
    XS_BEGIN();
    cp = calloc(1, sizeof *cp); p = calloc(NCONN, sizeof *p);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    for (i = 0; i < NCONN; i++) post_accept(l, &p[i], 0, WSACreateEvent());
    pool_start(cp, &a, NCONN, 4, 0);
    for (i = 0; i < NCONN; i++) {
        struct sockaddr_in ln, pn, *lp = NULL, *pp = NULL; int ll = sizeof ln, pl = sizeof pn, lpl = 0, ppl = 0;
        if (WaitForSingleObject(p[i].ov.hEvent, XS_WAIT_MS) != WAIT_OBJECT_0) continue;
        ok++;
        setsockopt(p[i].s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&l, sizeof l);
        if (getsockname(p[i].s, (struct sockaddr *)&ln, &ll) != 0 || ln.sin_port != a.sin_port ||
            ln.sin_addr.s_addr != 0x0100007Fu) name_bad++;
        if (W(getpeername)(p[i].s, (struct sockaddr *)&pn, &pl) != 0 || pn.sin_addr.s_addr != 0x0100007Fu ||
            pn.sin_port == a.sin_port) name_bad++;
        pGetAddrs(p[i].buf, 0, ADDRLEN, ADDRLEN, (struct sockaddr **)&lp, &lpl, (struct sockaddr **)&pp, &ppl);
        if (!lp || !pp || lp->sin_port != a.sin_port || pp->sin_port != pn.sin_port || lpl != sizeof ln || ppl != sizeof pn)
            parsed_bad++;
    }
    pool_join(cp, NULL);
    EXPECT_EQ(ok, NCONN);
    EXPECT_EQ(name_bad, 0);
    EXPECT_EQ(parsed_bad, 0);
    for (i = 0; i < NCONN; i++) { closesocket(p[i].s); WSACloseEvent(p[i].ov.hEvent); }
    pool_close_clients(cp, NCONN);
    closesocket(l); free(cp); free(p);
    xs_end();
}

/* Completion-port variant: one packet per posted AcceptEx, key and overlapped pointer round-trip. */
TEST(acceptex_200_completion_port_one_packet_each)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; post_t *p; HANDLE port; int i, got = 0, wrong_key = 0, bad_status = 0, dup = 0;
    unsigned char seen[NCONN] = { 0 };
    XS_BEGIN();
    cp = calloc(1, sizeof *cp); p = calloc(NCONN, sizeof *p);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    port = CreateIoCompletionPort((HANDLE)l, NULL, 0x1234, 0);
    CHECK(port != NULL);
    for (i = 0; i < NCONN; i++) post_accept(l, &p[i], 0, NULL);
    pool_start(cp, &a, NCONN, 8, 0);
    while (got < NCONN) {
        DWORD bytes = 0; ULONG_PTR key = 0; OVERLAPPED *ov = NULL;
        BOOL r = GetQueuedCompletionStatus(port, &bytes, &key, &ov, XS_WAIT_MS);
        int idx;
        if (!ov) break;
        if (!r) bad_status++;
        if (key != 0x1234) wrong_key++;
        idx = (int)(((post_t *)ov) - p);
        if (idx < 0 || idx >= NCONN || seen[idx]) dup++; else seen[idx] = 1;
        got++;
    }
    pool_join(cp, NULL);
    EXPECT_EQ(got, NCONN);
    EXPECT_EQ(bad_status, 0);
    EXPECT_EQ(wrong_key, 0);
    EXPECT_EQ(dup, 0);
    { DWORD b; ULONG_PTR k; OVERLAPPED *o = NULL;
      BOOL r = GetQueuedCompletionStatus(port, &b, &k, &o, 200);
      CHECK(!r && o == NULL); }
    for (i = 0; i < NCONN; i++) closesocket(p[i].s);
    pool_close_clients(cp, NCONN);
    closesocket(l); CloseHandle(port); free(cp); free(p);
    xs_end();
}

/* AcceptEx with a 4-byte initial receive completes only once the client's id arrived; bytes == 4 and the
 * buffer starts with the id. */
TEST(acceptex_200_with_initial_receive_delivers_id)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; post_t *p; int i, ok = 0, wrong_len = 0, id_bad = 0;
    unsigned char seen[NCONN] = { 0 };
    XS_BEGIN();
    cp = calloc(1, sizeof *cp); p = calloc(NCONN, sizeof *p);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    for (i = 0; i < NCONN; i++) post_accept(l, &p[i], 4, WSACreateEvent());
    pool_start(cp, &a, NCONN, 5, 0);
    for (i = 0; i < NCONN; i++) {
        DWORD bytes = 0, fl = 0; int id;
        if (WaitForSingleObject(p[i].ov.hEvent, XS_WAIT_MS) != WAIT_OBJECT_0) continue;
        if (!WSAGetOverlappedResult(p[i].s, &p[i].ov, &bytes, FALSE, &fl)) continue;
        ok++;
        if (bytes != 4) wrong_len++;
        memcpy(&id, p[i].buf, 4);
        if (id < 0 || id >= NCONN || seen[id]) id_bad++; else seen[id] = 1;
    }
    pool_join(cp, NULL);
    EXPECT_EQ(ok, NCONN);
    EXPECT_EQ(wrong_len, 0);
    EXPECT_EQ(id_bad, 0);
    for (i = 0; i < NCONN; i++) { closesocket(p[i].s); WSACloseEvent(p[i].ov.hEvent); }
    pool_close_clients(cp, NCONN);
    closesocket(l); free(cp); free(p);
    xs_end();
}

/* With an initial receive length and no data sent, the request stays pending: after connecting 20 silent
 * clients no completion is signalled; sending the byte completes them. */
TEST(acceptex_initial_receive_stays_pending_until_data_arrives)
{
    struct sockaddr_in a; SOCKET l; post_t *p; SOCKET c[20]; int i, early = 0, late = 0;
    XS_BEGIN();
    p = calloc(20, sizeof *p);
    l = xs_listener(&a, 32);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    for (i = 0; i < 20; i++) post_accept(l, &p[i], 4, WSACreateEvent());
    for (i = 0; i < 20; i++) { c[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); connect(c[i], (struct sockaddr *)&a, sizeof a); }
    Sleep(150);
    for (i = 0; i < 20; i++) if (WaitForSingleObject(p[i].ov.hEvent, 0) == WAIT_OBJECT_0) early++;
    for (i = 0; i < 20; i++) send(c[i], "abcd", 4, 0);
    for (i = 0; i < 20; i++) if (WaitForSingleObject(p[i].ov.hEvent, XS_WAIT_MS) == WAIT_OBJECT_0) late++;
    EXPECT_EQ(early, 0);
    EXPECT_EQ(late, 20);
    for (i = 0; i < 20; i++) { closesocket(c[i]); closesocket(p[i].s); WSACloseEvent(p[i].ov.hEvent); }
    closesocket(l); free(p);
    xs_end();
}

/* Only 100 requests posted for 200 connectors: exactly 100 complete; posting 100 more completes the rest. */
TEST(acceptex_posted_in_two_waves_accepts_exactly_200)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; post_t *p; int i, first = 0, second = 0, queued_before;
    XS_BEGIN();
    cp = calloc(1, sizeof *cp); p = calloc(NCONN, sizeof *p);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    for (i = 0; i < 100; i++) post_accept(l, &p[i], 0, WSACreateEvent());
    pool_start(cp, &a, NCONN, 5, 0);
    Sleep(300);
    for (i = 0; i < 100; i++) if (WaitForSingleObject(p[i].ov.hEvent, XS_WAIT_MS) == WAIT_OBJECT_0) first++;
    EXPECT_EQ(first, 100);
    for (i = 100; i < NCONN; i++) post_accept(l, &p[i], 0, WSACreateEvent());
    for (i = 100; i < NCONN; i++) if (WaitForSingleObject(p[i].ov.hEvent, XS_WAIT_MS) == WAIT_OBJECT_0) second++;
    EXPECT_EQ(second, 100);
    EXPECT_EQ(pool_join(cp, NULL), NCONN);
    for (i = 0; i < NCONN; i++) { closesocket(p[i].s); WSACloseEvent(p[i].ov.hEvent); }
    pool_close_clients(cp, NCONN);
    closesocket(l); free(cp); free(p);
    xs_end();
}

/* A re-arming accept loop on a completion port keeping 16 requests outstanding accepts exactly 200. */
TEST(acceptex_rearming_loop_with_16_outstanding_accepts_exactly_200)
{
    struct sockaddr_in a; SOCKET l; conn_pool *cp; post_t *p; HANDLE port; int i, done = 0, posted = 0, bad = 0;
    XS_BEGIN();
    cp = calloc(1, sizeof *cp); p = calloc(NCONN + 16, sizeof *p);
    l = xs_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    port = CreateIoCompletionPort((HANDLE)l, NULL, 7, 0);
    for (i = 0; i < 16; i++) { post_accept(l, &p[posted], 0, NULL); posted++; }
    pool_start(cp, &a, NCONN, 6, 0);
    while (done < NCONN) {
        DWORD b; ULONG_PTR k; OVERLAPPED *ov = NULL;
        BOOL r = GetQueuedCompletionStatus(port, &b, &k, &ov, XS_WAIT_MS);
        if (!ov) break;
        if (!r) bad++;
        done++;
        if (posted < NCONN) { post_accept(l, &p[posted], 0, NULL); posted++; }
    }
    pool_join(cp, NULL);
    EXPECT_EQ(done, NCONN);
    EXPECT_EQ(posted, NCONN);
    EXPECT_EQ(bad, 0);
    for (i = 0; i < NCONN; i++) closesocket(p[i].s);
    pool_close_clients(cp, NCONN);
    closesocket(l); CloseHandle(port); free(cp); free(p);
    xs_end();
}

/* Closing the listener with 200 AcceptEx requests pending completes every one of them exactly once, none
 * successfully. The status set is recorded for the report. */
TEST(acceptex_listener_close_completes_all_200_pending_once)
{
    struct sockaddr_in a; SOCKET l; post_t *p; HANDLE port; int i, got = 0, success = 0, dup = 0;
    unsigned char seen[NCONN] = { 0 };
    DWORD firsterr = 0; int same = 1;
    XS_BEGIN();
    p = calloc(NCONN, sizeof *p);
    l = xs_listener(&a, 8);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    port = CreateIoCompletionPort((HANDLE)l, NULL, 5, 0);
    for (i = 0; i < NCONN; i++) post_accept(l, &p[i], 0, NULL);
    closesocket(l);
    while (got < NCONN) {
        DWORD b; ULONG_PTR k; OVERLAPPED *ov = NULL; DWORD err;
        BOOL r;
        SetLastError(0);
        r = GetQueuedCompletionStatus(port, &b, &k, &ov, XS_WAIT_MS);
        err = r ? 0 : GetLastError();
        if (!ov) break;
        if (r) success++;
        if (got == 0) firsterr = err; else if (err != firsterr) same = 0;
        { int idx = (int)(((post_t *)ov) - p); if (idx < 0 || idx >= NCONN || seen[idx]) dup++; else seen[idx] = 1; }
        got++;
    }
    EXPECT_EQ(got, NCONN);
    EXPECT_EQ(success, 0);
    EXPECT_EQ(dup, 0);
    EXPECT_EQ(same, 1);
    EXPECT_EQ(firsterr, ERROR_OPERATION_ABORTED);
    for (i = 0; i < NCONN; i++) closesocket(p[i].s);
    CloseHandle(port); free(p);
    xs_end();
}

/* One AcceptEx call with the given shape; a request that pends is cancelled and drained so nothing outlives
 * the call. Returns 1 if accepted as pending/complete, 0 if refused, with the WSA error in *err. */
static int try_acceptex(SOCKET l, SOCKET acc, DWORD rlen, DWORD llen, DWORD remlen, int *err)
{
    static WSAOVERLAPPED ov; static char buf[256];
    DWORD got = 0, fl = 0;
    BOOL r;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = WSACreateEvent();
    WSASetLastError(0);
    r = pAcceptEx(l, acc, buf, rlen, llen, remlen, &got, &ov);
    *err = r ? 0 : WSAGetLastError();
    if (!r && *err == ERROR_IO_PENDING) {
        CancelIoEx((HANDLE)l, &ov);
        WaitForSingleObject(ov.hEvent, XS_WAIT_MS);
        WSACloseEvent(ov.hEvent);
        return 1;
    }
    WSACloseEvent(ov.hEvent);
    return r ? 1 : 0;
}

/* AcceptEx negative shapes, one request each. */
TEST(acceptex_negative_shapes)
{
    struct sockaddr_in a; SOCKET l, s, plain; int err;
    XS_BEGIN();
    l = xs_listener(&a, 4);
    if (l == INVALID_SOCKET || !load_acceptex(l)) { t_skip("no AcceptEx"); xs_end(); return; }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    plain = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    /* undersized or zero address lengths: the request is accepted as pending when the buffer pointer is
     * valid and the length is nonzero; a zero length is refused with WSAEFAULT. */
    EXPECT_EQ(try_acceptex(plain, s, 0, ADDRLEN, ADDRLEN, &err), 0); EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(try_acceptex(l, s, 0, 8, ADDRLEN, &err), 1);   EXPECT_EQ(err, WSA_IO_PENDING);
    EXPECT_EQ(try_acceptex(l, s, 0, ADDRLEN, 8, &err), 1);   EXPECT_EQ(err, WSA_IO_PENDING);
    EXPECT_EQ(try_acceptex(l, s, 0, 0, 0, &err), 0);         EXPECT_EQ(err, WSAEFAULT);
    EXPECT_EQ(try_acceptex(l, s, 0, 15, 15, &err), 1);       EXPECT_EQ(err, WSA_IO_PENDING);
    EXPECT_EQ(try_acceptex(l, s, 0, 16, 16, &err), 1);       EXPECT_EQ(err, WSA_IO_PENDING);
    EXPECT_EQ(try_acceptex(l, s, 0, 32, 32, &err), 1);       EXPECT_EQ(err, WSA_IO_PENDING);
    closesocket(s); closesocket(plain);
    { SOCKET c, srv;
      if (xs_pair(&c, &srv)) {
          EXPECT_EQ(try_acceptex(l, c, 0, ADDRLEN, ADDRLEN, &err), 0); EXPECT_EQ(err, WSAEINVAL);
          closesocket(c); closesocket(srv);
      } }
    { SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      EXPECT_EQ(try_acceptex(l, u, 0, ADDRLEN, ADDRLEN, &err), 0); EXPECT_EQ(err, WSAEINVAL);
      closesocket(u); }
    { SOCKET d = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      SOCKET acc = socket(AF_INET, SOCK_STREAM, 0);
      EXPECT_EQ(try_acceptex(d, acc, 0, ADDRLEN, ADDRLEN, &err), 0); EXPECT_EQ(err, WSAEINVAL);
      closesocket(acc); closesocket(d); }
    closesocket(l);
    xs_end();
}
