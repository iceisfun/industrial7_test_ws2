/* socket_handle_semantics / extra: further interactions of file-style I/O with socket state (shutdown,
 * concurrent close, ordering of overlapped requests, large transfers through completion ports) and sockets
 * handed to children for accept / datagram use. */
#include "sh.h"

/* ---------------- file I/O versus shutdown ---------------- */

TEST(shs_shut_writefile_after_local_send_shutdown)
{
    SOCKET c, s; DWORD n = 77;
    UP(); PAIR(c, s, SYNC);
    EQ(U(shutdown)(c, SD_SEND), 0);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)c, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_PIPE_NOT_CONNECTED);
    sh_closes(c); sh_closes(s);
}
TEST(shs_shut_send_after_local_send_shutdown_is_eshutdown)
{
    SOCKET c, s;
    UP(); PAIR(c, s, SYNC);
    EQ(U(shutdown)(c, SD_SEND), 0);
    sh_setwerr(0);
    EQ(sh_send(c, "q", 1), SOCKET_ERROR);
    EQ(sh_werr(), WSAESHUTDOWN);
    sh_closes(c); sh_closes(s);
}
TEST(shs_shut_readfile_after_local_receive_shutdown)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[4];
    UP(); PAIR(c, s, SYNC);
    EQ(U(shutdown)(s, SD_RECEIVE), 0);
    sh_send(c, "q", 1);
    BOOL r = sh_readfile((HANDLE)s, b, sizeof b, &n, &e);
    CHECK(!r);
    EQ(e, ERROR_NETNAME_DELETED);
    sh_closes(c); sh_closes(s);
}
TEST(shs_shut_readfile_sees_eof_after_both_directions_closed_by_peer)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[4];
    UP(); PAIR(c, s, SYNC);
    U(shutdown)(c, SD_BOTH);
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 0);
    sh_closes(c); sh_closes(s);
}

/* ---------------- closing while another thread is in ReadFile ---------------- */

typedef struct { HANDLE h; BOOL ret; DWORD err, got; char buf[8]; SOCKET peer; } rjob;
static DWORD WINAPI rjob_thread(LPVOID p)
{
    rjob *j = (rjob *)p;
    j->ret = ReadFile(j->h, j->buf, sizeof j->buf, &j->got, NULL);
    j->err = GetLastError();
    return 0;
}
static DWORD WINAPI delayed_sender(LPVOID p)
{
    rjob *j = (rjob *)p;
    Sleep(1000);
    sh_send(j->peer, "late", 4);
    return 0;
}
/* closesocket on a synchronous handle waits for the synchronous read that is in flight on the same file
 * object (it does not abort it); a helper delivers data so the sequence cannot hang. */
TEST(shs_close_waits_for_sync_readfile_in_other_thread)
{
    SOCKET c, s; rjob j; HANDLE t, snd; int rc;
    UP(); PAIR(c, s, SYNC);
    memset(&j, 0, sizeof j); j.h = (HANDLE)s; j.peer = c;
    t = CreateThread(NULL, 0, rjob_thread, &j, 0, NULL);
    snd = CreateThread(NULL, 0, delayed_sender, &j, 0, NULL);
    Sleep(300);
    rc = sh_closes(s);
    EQ(rc, 0);
    CHECK(WaitForSingleObject(t, SH_WAIT) == WAIT_OBJECT_0);
    CHECK(j.ret);                          /* the read was not aborted: it returned the late data */
    EQ(j.got, 4);
    WaitForSingleObject(snd, SH_WAIT);
    CloseHandle(t); CloseHandle(snd); sh_closes(c);
}

/* ---------------- ordering and volume of overlapped requests ---------------- */

/* Several reads posted on one socket complete in the order they were posted. */
TEST(shs_order_overlapped_reads_complete_in_post_order)
{
    enum { N = 4 };
    SOCKET c, s; OVERLAPPED o[N]; HANDLE ev[N]; char b[N][4]; DWORD n; int i;
    UP(); PAIR(c, s, PLAIN);
    for (i = 0; i < N; i++) {
        ev[i] = sh_event(); sh_ovl(&o[i], ev[i]); memset(b[i], 0, 4);
        SET_ERR(0);
        CHECK(!sh_rf((HANDLE)s, b[i], 2, &n, &o[i]));
        EXPECT_ERR(ERROR_IO_PENDING);
    }
    sh_send(c, "AABBCCDD", 8);
    for (i = 0; i < N; i++) {
        EQ(sh_wait(ev[i]), WAIT_OBJECT_0);
        CHECK(GetOverlappedResult((HANDLE)s, &o[i], &n, FALSE));
        EQ(n, 2);
    }
    CHECK(!memcmp(b[0], "AA", 2) && !memcmp(b[1], "BB", 2) && !memcmp(b[2], "CC", 2) && !memcmp(b[3], "DD", 2));
    for (i = 0; i < N; i++) CloseHandle(ev[i]);
    sh_closes(c); sh_closes(s);
}

/* A queue of overlapped WriteFile requests delivers every byte in order. */
TEST(shs_order_overlapped_writes_deliver_in_order)
{
    enum { N = 16, L = 1000 };
    static char tx[N][L], rx[N * L];
    SOCKET c, s; OVERLAPPED o[N]; HANDLE ev[N]; int i, got;
    UP(); PAIR(c, s, PLAIN);
    for (i = 0; i < N; i++) {
        DWORD n;
        memset(tx[i], 'a' + i, L);
        ev[i] = sh_event(); sh_ovl(&o[i], ev[i]);
        CHECK(sh_wf((HANDLE)c, tx[i], L, &n, &o[i]) || GetLastError() == ERROR_IO_PENDING);
    }
    got = sh_recv_all(s, rx, N * L);
    EQ(got, N * L);
    for (i = 0; i < N; i++) CHECK(rx[i * L] == 'a' + i && rx[i * L + L - 1] == 'a' + i);
    for (i = 0; i < N; i++) { DWORD n; CHECK(GetOverlappedResult((HANDLE)c, &o[i], &n, TRUE)); EQ(n, L); CloseHandle(ev[i]); }
    sh_closes(c); sh_closes(s);
}

/* Completion through a port reports the number of bytes and the key given at association. */
TEST(shs_iocpx_read_packet_fields)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n = 0; ULONG_PTR key = 0; LPOVERLAPPED got = NULL; char b[8];
    UP(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(CreateIoCompletionPort((HANDLE)s, p, 0x55, 0) == p);
    sh_ovl(&o, NULL);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    EXPECT_ERR(ERROR_IO_PENDING);
    sh_send(c, "pkt", 3);
    CHECK(GetQueuedCompletionStatus(p, &n, &key, &got, SH_WAIT));
    CHECK(got == &o);
    EQ(n, 3);
    EQ(key, 0x55);
    CloseHandle(p); sh_closes(c); sh_closes(s);
}
TEST(shs_iocpx_cancelled_read_posts_aborted_packet)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n = 0; ULONG_PTR key = 0; LPOVERLAPPED got = NULL; char b[8];
    UP(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CreateIoCompletionPort((HANDLE)s, p, 0x66, 0);
    sh_ovl(&o, NULL);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    CHECK(CancelIoEx((HANDLE)s, &o));
    SET_ERR(0);
    CHECK(!GetQueuedCompletionStatus(p, &n, &key, &got, SH_WAIT));
    CHECK(got == &o);
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    EQ(key, 0x66);
    CloseHandle(p); sh_closes(c); sh_closes(s);
}
TEST(shs_iocpx_eof_read_packet_has_zero_bytes)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n = 77; ULONG_PTR key = 0; LPOVERLAPPED got = NULL; char b[8];
    UP(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CreateIoCompletionPort((HANDLE)s, p, 0x77, 0);
    sh_ovl(&o, NULL);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    sh_closes(c);
    CHECK(GetQueuedCompletionStatus(p, &n, &key, &got, SH_WAIT));
    CHECK(got == &o);
    EQ(n, 0);
    CloseHandle(p); sh_closes(s);
}
/* A packet that was queued survives closing the socket. */
TEST(shs_iocpx_packet_survives_socket_close)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n = 0; ULONG_PTR key = 0; LPOVERLAPPED got = NULL;
    UP(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CreateIoCompletionPort((HANDLE)c, p, 0x88, 0);
    sh_ovl(&o, NULL);
    CHECK(sh_wf((HANDLE)c, "w", 1, &n, &o));
    sh_closes(c);
    CHECK(GetQueuedCompletionStatus(p, &n, &key, &got, SH_WAIT));
    EQ(key, 0x88);
    CloseHandle(p); sh_closes(s);
}

/* ---------------- duplicates and select ---------------- */

TEST(shs_dupx_select_on_duplicate_handle)
{
    SOCKET c, s; HANDLE d;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    sh_send(c, "x", 1);
    t_note("select over a duplicated handle sees data: %d", sh_readable((SOCKET)d, SH_WAIT));
    CloseHandle(d); sh_closes(c); sh_closes(s);
}
TEST(shs_dupx_shutdown_through_duplicate)
{
    SOCKET c, s; HANDLE d; char b[2];
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ(U(shutdown)((SOCKET)d, SD_SEND), 0);
    EQ(sh_recv(s, b, 1), 0);                 /* the peer sees the half-close while both handles stay open */
    sh_closes(c); CloseHandle(d); sh_closes(s);
}
/* The duplicate and the original share one options store: an option set through one reads back through the other. */
TEST(shs_dupx_options_shared)
{
    SOCKET c, s; HANDLE d; int v = 12345, g = 0, gl = sizeof g;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ(U(setsockopt)((SOCKET)d, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof v), 0);
    EQ(U(getsockopt)(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&g, &gl), 0);
    t_note("SO_RCVTIMEO set through a duplicate reads back through the original as %d", g);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}
TEST(shs_dupx_nonblocking_mode_shared_with_duplicate)
{
    SOCKET c, s; HANDLE d; u_long nb = 1; char b[2];
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ(U(ioctlsocket)((SOCKET)d, FIONBIO, &nb), 0);
    sh_setwerr(0);
    int rc = U(recv)(c, b, 1, 0);
    t_note("recv on the original after FIONBIO through a duplicate: %d (werr %d)", rc, sh_werr());
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* ---------------- listener and datagram socket inherited by a child ---------------- */

static SOCKET argsock(char **argv, int i) { return (SOCKET)(ULONG_PTR)_strtoui64(argv[i], NULL, 10); }
CHILD(accept_inherited)
{
    SOCKET l = argsock(argv, 1), a; WSADATA d; char b[8] = {0}; unsigned fails = 0;
    U(WSAStartup)(MAKEWORD(2, 2), &d);
    a = U(accept)(l, NULL, NULL);
    if (a == INVALID_SOCKET) return 1;
    if (!(sh_recv_all(a, b, 4) == 4 && !memcmp(b, "ping", 4))) fails |= 2;
    if (sh_send(a, "pong", 4) != 4) fails |= 4;
    sh_closes(a);
    sh_closes(l);
    return (int)fails;
}
TEST(shs_inheritx_listener_accepted_by_child)
{
    SOCKET l, c; struct sockaddr_in a; char arg[32], b[8] = {0}; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead;
    UP(); l = sh_listener(PLAIN, &a);
    REQUIRE(l != INVALID_SOCKET);
    sprintf(arg, "%llu", (unsigned long long)l);
    h = t_spawn_child("accept_inherited", arg, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    c = sh_make(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    sh_rcvtimeo(c, SH_WAIT);
    sh_send(c, "ping", 4);
    EQ(sh_recv_all(c, b, 4), 4);
    CHECK(!memcmp(b, "pong", 4));
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(c); sh_closes(l);
}

CHILD(recvfrom_inherited)
{
    SOCKET u = argsock(argv, 1); WSADATA d; char b[16] = {0}; struct sockaddr_in from; int fl = sizeof from;
    U(WSAStartup)(MAKEWORD(2, 2), &d);
    if (!sh_readable(u, SH_WAIT)) return 1;
    if (U(recvfrom)(u, b, sizeof b, 0, (struct sockaddr *)&from, &fl) != 5) return 2;
    return memcmp(b, "hello", 5) ? 3 : 0;
}
TEST(shs_inheritx_bound_udp_receives_in_child)
{
    SOCKET u, tx; struct sockaddr_in a = sh_lo(0); int n = sizeof a; char arg[32]; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead;
    UP();
    u = sh_make(SOCK_DGRAM, PLAIN); tx = sh_make(SOCK_DGRAM, WSA_FLAG_NO_HANDLE_INHERIT);
    EQ(U(bind)(u, (struct sockaddr *)&a, sizeof a), 0);
    EQ(U(getsockname)(u, (struct sockaddr *)&a, &n), 0);
    sprintf(arg, "%llu", (unsigned long long)u);
    h = t_spawn_child("recvfrom_inherited", arg, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    EQ(U(sendto)(tx, "hello", 5, 0, (struct sockaddr *)&a, n), 5);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(u); sh_closes(tx);
}

/* A socket that is connected only in the child: the child connects an inherited unconnected socket and the
 * parent sees the state change through its own handle. */
CHILD(connect_inherited)
{
    SOCKET s = argsock(argv, 1); WSADATA d; struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007fu;
    a.sin_port = (unsigned short)atoi(argv[2]);
    U(WSAStartup)(MAKEWORD(2, 2), &d);
    return U(connect)(s, (struct sockaddr *)&a, sizeof a) == 0 ? 0 : 1;
}
TEST(shs_inheritx_connect_in_child_visible_to_parent)
{
    SOCKET l, c, s; struct sockaddr_in a, peer; int pl = sizeof peer; char arg[48]; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead;
    UP(); l = sh_listener(PLAIN, &a);
    c = sh_make(SOCK_STREAM, PLAIN);
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET);
    sprintf(arg, "%llu %u", (unsigned long long)c, (unsigned)a.sin_port);
    h = t_spawn_child("connect_inherited", arg, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    s = U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    /* The connected state lives in each process's Winsock layer: the parent's view of this socket is stale. */
    sh_setwerr(0);
    int prc = U(getpeername)(c, (struct sockaddr *)&peer, &pl);
    CHECK(prc == SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTCONN);
    sh_send(c, "z", 1);
    sh_rcvtimeo(s, SH_WAIT);
    char b[2]; EQ(sh_recv(s, b, 1), 1);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(c); sh_closes(s); sh_closes(l);
}
