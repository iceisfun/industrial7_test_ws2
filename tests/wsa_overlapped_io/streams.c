/* wsa_overlapped_io / streams: socket-creation flavour vs overlapped behaviour, long ordered sequences and
 * integrity of data moved through chains of overlapped requests (events, routines and a port). */
#include "oio.h"

/* socket() (no flags) yields an overlapped-capable socket on this platform: a receive pends. */
TEST(oio_stream_socket_call_creates_overlapped_socket)
{
    struct sockaddr_in a = oio_lo(); int len = sizeof a; WSAOVERLAPPED o; char buf[4]; DWORD fl; HANDLE ev = oio_event();
    SOCKET lis, c, s = INVALID_SOCKET;
    UP();
    lis = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP); c = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(lis != INVALID_SOCKET && c != INVALID_SOCKET);
    U(bind)(lis, (struct sockaddr *)&a, sizeof a); U(getsockname)(lis, (struct sockaddr *)&a, &len); U(listen)(lis, 1);
    OEQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    s = U(accept)(lis, NULL, NULL);
    REQUIRE(s != INVALID_SOCKET);
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "k", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    U(closesocket)(lis); oio_close2(c, s); CloseHandle(ev);
}

/* An accepted socket inherits the overlapped attribute of its listener. */
TEST(oio_stream_accepted_socket_inherits_overlapped_attribute)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl; HANDLE ev = oio_event();
    UP(); PAIR(c, s);                       /* overlapped listener */
    oio_ovl(&o, ev);
    OEQ(oio_post_recv(s, buf, sizeof buf, &o, &fl), SOCKET_ERROR);   /* s came from accept() */
    OEQ(WERR(), WSA_IO_PENDING);
    CancelIoEx((HANDLE)s, &o); oio_wait(ev, OIO_WAIT);
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_stream_accepted_from_plain_listener_is_plain)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD nb = 0, fl = 0; HANDLE ev = oio_event();
    UP(); PAIR_PLAIN(c, s);
    oio_send(c, "p", 1); Sleep(50);
    oio_ovl(&o, ev);
    WSABUF b = {sizeof buf, buf};
    OEQ(U(WSARecv)(s, &b, 1, &nb, &fl, &o, NULL), 0);   /* data was ready: synchronous */
    OEQ(nb, 1);
    oio_close2(c, s); CloseHandle(ev);
}

/* 500 one-byte overlapped sends are received in order. */
TEST(oio_stream_many_small_sends_in_order)
{
    enum { N = 500 };
    SOCKET c, s; static WSAOVERLAPPED o[N]; static char tx[N], rx[N]; HANDLE ev = oio_event(); int got = 0;
    UP(); PAIR(c, s);
    for (int i = 0; i < N; i++) {
        tx[i] = (char)(i * 5 + 1);
        oio_ovl(&o[i], ev);
        WSABUF b = {1, &tx[i]};
        int rc = U(WSASend)(c, &b, 1, NULL, 0, &o[i], NULL);
        CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    }
    while (got < N) {
        fd_set r; struct timeval tv = {5, 0}; FD_ZERO(&r); FD_SET(s, &r);
        if (U(select)(0, &r, NULL, NULL, &tv) != 1) break;
        int k = U(recv)(s, rx + got, N - got, 0);
        if (k <= 0) break;
        got += k;
    }
    OEQ(got, N);
    CHECK(!memcmp(tx, rx, N));
    for (int i = 0; i < N; i++) {
        DWORD bytes = 0, f2;
        for (int w = 0; w < 500 && o[i].Internal == OIO_STATUS_PENDING; w++) Sleep(5);
        CHECK(U(WSAGetOverlappedResult)(c, &o[i], &bytes, FALSE, &f2) && bytes == 1);
    }
    oio_close2(c, s); CloseHandle(ev);
}

/* A sequence of receive requests through a port moves 64 KiB intact, whatever the segmentation. */
TEST(oio_stream_port_receive_chain_integrity)
{
    enum { N = 65536, CH = 1024 };
    SOCKET c, s; static char tx[N], rx[N]; WSAOVERLAPPED o; DWORD fl; int got = 0;
    UP(); PAIR(c, s);
    HANDLE port = CreateIoCompletionPort((HANDLE)c, NULL, 4, 0); REQUIRE(port);
    for (int i = 0; i < N; i++) tx[i] = (char)(i ^ (i >> 8));
    int sent = 0;
    while (got < N) {
        if (sent < N) { int k = U(send)(s, tx + sent, N - sent > 8192 ? 8192 : N - sent, 0); if (k > 0) sent += k; }
        oio_ovl(&o, NULL);
        int want = N - got < CH ? N - got : CH;
        int rc = oio_post_recv(c, rx + got, want, &o, &fl);
        CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
        DWORD bytes = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
        if (!GetQueuedCompletionStatus(port, &bytes, &key, &ov, OIO_WAIT)) break;
        OEQ(ov, &o); OEQ(key, 4);
        if (bytes == 0) break;
        got += bytes;
    }
    OEQ(got, N);
    CHECK(!memcmp(tx, rx, N));
    CloseHandle(port); oio_close2(c, s);
}

/* The same chain through completion routines, one request at a time. */
TEST(oio_stream_routine_receive_chain_integrity)
{
    enum { N = 20000, CH = 700 };
    SOCKET c, s; static char tx[N], rx[N]; WSAOVERLAPPED o; DWORD fl; int got = 0, sent = 0;
    UP(); PAIR(c, s);
    for (int i = 0; i < N; i++) tx[i] = (char)(i * 3);
    while (got < N) {
        if (sent < N) { int k = U(send)(s, tx + sent, N - sent > 4096 ? 4096 : N - sent, 0); if (k > 0) sent += k; }
        oio_cr_reset(); oio_ovl(&o, NULL);
        WSABUF b = {N - got < CH ? N - got : CH, rx + got};
        fl = 0;
        int rc = U(WSARecv)(c, &b, 1, NULL, &fl, &o, oio_cr);
        CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
        if (SleepEx(OIO_WAIT, TRUE) != WAIT_IO_COMPLETION) break;
        OEQ(g_cr.err, 0);
        if (g_cr.bytes == 0) break;
        got += g_cr.bytes;
    }
    OEQ(got, N);
    CHECK(!memcmp(tx, rx, N));
    oio_close2(c, s);
}

/* Exactly one packet per request: 50 sends, 50 packets, nothing extra. */
TEST(oio_stream_port_one_packet_per_send)
{
    enum { N = 50 };
    SOCKET c, s; static WSAOVERLAPPED o[N]; char rx[N], tx[N]; int seen[N] = {0}; int extra = 0;
    UP(); PAIR(c, s);
    HANDLE port = CreateIoCompletionPort((HANDLE)c, NULL, 8, 0); REQUIRE(port);
    for (int i = 0; i < N; i++) {
        tx[i] = (char)i; oio_ovl(&o[i], NULL);
        WSABUF b = {1, &tx[i]};
        int rc = U(WSASend)(c, &b, 1, NULL, 0, &o[i], NULL);
        CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    }
    for (int i = 0; i < N; i++) {
        DWORD bytes; ULONG_PTR key; LPOVERLAPPED ov;
        if (!GetQueuedCompletionStatus(port, &bytes, &key, &ov, OIO_WAIT)) { CHECK(0); break; }
        OEQ(bytes, 1);
        long idx = (long)(ov - (LPOVERLAPPED)o);
        if (idx >= 0 && idx < N) seen[idx]++; else extra++;
    }
    for (int i = 0; i < N; i++) OEQ(seen[i], 1);
    OEQ(extra, 0);
    DWORD bytes; ULONG_PTR key; LPOVERLAPPED ov;
    CHECK(!GetQueuedCompletionStatus(port, &bytes, &key, &ov, 150));
    int got = 0;
    while (got < N) { int k = U(recv)(s, rx + got, N - got, 0); if (k <= 0) break; got += k; }
    OEQ(got, N);
    CloseHandle(port); oio_close2(c, s);
}

/* A worker thread blocks in GetQueuedCompletionStatus while the main thread submits and finishes. */
static void thr_gqcs(void *p)
{
    void **a = (void **)p; DWORD bytes = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    BOOL ok = GetQueuedCompletionStatus((HANDLE)a[0], &bytes, &key, &ov, OIO_WAIT);
    *(ULONG_PTR *)a[1] = ok ? (ULONG_PTR)ov : 0;
    *(DWORD *)a[2] = bytes;
}
TEST(oio_stream_worker_thread_dequeues_completion)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 0; ULONG_PTR ovp = 0; oio_thr t; void *a[3];
    UP(); PAIR(c, s);
    HANDLE port = CreateIoCompletionPort((HANDLE)c, NULL, 2, 0); REQUIRE(port);
    a[0] = port; a[1] = &ovp; a[2] = &bytes;
    HANDLE th = oio_spawn(&t, thr_gqcs, a);
    oio_ovl(&o, NULL);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    Sleep(50);
    oio_send(s, "wk", 2);
    oio_join(th);
    OEQ(ovp, &o); OEQ(bytes, 2);
    CloseHandle(port); oio_close2(c, s);
}

/* Completion routines on two threads: each routine runs on the thread that issued its request. */
static volatile DWORD g_thr_tid_a, g_thr_tid_b;
static void CALLBACK thr_cr_a(DWORD e, DWORD b, LPWSAOVERLAPPED o, DWORD f) { g_thr_tid_a = GetCurrentThreadId(); }
static void thr_issue_and_wait(void *p)
{
    void **a = (void **)p; SOCKET sock = *(SOCKET *)a[0]; WSAOVERLAPPED *o = (WSAOVERLAPPED *)a[1]; DWORD fl = 0;
    WSABUF b = {4, (CHAR *)a[2]};
    memset(o, 0, sizeof *o);
    U(WSARecv)(sock, &b, 1, NULL, &fl, o, thr_cr_a);
    *(DWORD *)a[3] = GetCurrentThreadId();
    SleepEx(OIO_WAIT, TRUE);
}
TEST(oio_stream_routine_runs_on_issuing_worker_thread)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD tid = 0; oio_thr t; void *a[4];
    UP(); PAIR(c, s);
    g_thr_tid_a = 0;
    a[0] = &c; a[1] = &o; a[2] = buf; a[3] = &tid;
    HANDLE th = oio_spawn(&t, thr_issue_and_wait, a);
    Sleep(150);
    oio_send(s, "t", 1);
    oio_join(th);
    CHECK(tid != 0 && tid != GetCurrentThreadId());
    OEQ(g_thr_tid_a, tid);
    oio_close2(c, s);
}
