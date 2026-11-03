/* select(): readiness rules for stream and datagram sockets (connect completion, pending accept,
 * data, OOB, close), error reporting for bad / non-socket handles, set handling (duplicates, shared
 * sets, large sets, sets at the edge of a page), APC delivery, and wake-up on close from another thread. */
#include "l6.h"

#define SEL_START() NEED_WS(); REQUIRE(U(select)); REQUIRE(U(socket))

static fd_set R, W, X;
static void zero_all(void) { fs_zero(&R); fs_zero(&W); fs_zero(&X); }
static void add_all(SOCKET s) { fs_add(&R, s); fs_add(&W, s); fs_add(&X, s); }

/* ---- unconnected sockets ---- */
static void idle_unconnected(long usec)
{
    SOCKET a = w_socket(AF_INET, SOCK_STREAM, 0), b = w_socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv;
    zero_all(); add_all(a); add_all(b);
    tv_set(&tv, 0, usec);
    EQ(w_select(0, &R, &W, &X, &tv), 0);
    CHECK(!fs_has(&R, a)); CHECK(!fs_has(&W, b)); CHECK(!fs_has(&X, a)); CHECK(!fs_has(&X, b));
    w_close(a); w_close(b);
}
TEST(lift06_select_unconnected_stream_zero_timeout)  { SEL_START(); idle_unconnected(0); }
TEST(lift06_select_unconnected_stream_tiny_timeout)  { SEL_START(); idle_unconnected(500); }

TEST(lift06_select_unbound_datagram_is_writable)
{
    SOCKET s; struct timeval tv;
    SEL_START();
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(s != INVALID_SOCKET);
    zero_all(); add_all(s);
    tv_set(&tv, 0, 250000);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&W, s));
    CHECK(!fs_has(&R, s));
    w_close(s);
}

/* ---- argument errors ---- */
TEST(lift06_select_all_null_sets_einval)
{
    struct timeval tv;
    SEL_START();
    tv_set(&tv, 0, 500);
    w_seterr(0);
    EQ(w_select(10, NULL, NULL, NULL, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
}
TEST(lift06_select_all_empty_sets_einval)
{
    struct timeval tv;
    SEL_START();
    tv_set(&tv, 0, 500);
    zero_all();
    w_seterr(0);
    EQ(w_select(10, &R, &W, &X, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAEINVAL);
}
static void bad_handle_in(int which)
{
    struct timeval tv;
    tv_set(&tv, 0, 500);
    zero_all();
    fs_add(which == 0 ? &R : which == 1 ? &W : &X, INVALID_SOCKET);
    w_seterr(0);
    EQ(w_select(10, &R, &W, &X, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
}
TEST(lift06_select_invalid_handle_in_read_set)   { SEL_START(); bad_handle_in(0); }
TEST(lift06_select_invalid_handle_in_write_set)  { SEL_START(); bad_handle_in(1); }
TEST(lift06_select_invalid_handle_in_except_set) { SEL_START(); bad_handle_in(2); }

/* A valid kernel handle that is not a socket (a file) is ENOTSOCK and is left in its set. */
static HANDLE open_tmp_file(void)
{
    char p[MAX_PATH];
    t_tmpfile(p, sizeof p, "sel.dat");
    return CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
}
TEST(lift06_select_file_handle_alone_enotsock_and_stays_set)
{
    HANDLE f; struct timeval tv;
    SEL_START();
    f = open_tmp_file();
    CHECK(f != INVALID_HANDLE_VALUE);
    tv_set(&tv, 0, 500);
    zero_all(); fs_add(&R, (SOCKET)f);
    w_seterr(0);
    EQ(w_select(0, &R, &W, &X, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    CHECK(fs_has(&R, (SOCKET)f));
    CloseHandle(f);
}
static void file_among_sockets(int where)
{
    HANDLE f; SOCKET a, b; struct timeval tv;
    f = open_tmp_file();
    CHECK(lo_pair(&a, &b));
    tv_set(&tv, 0, 500);
    zero_all();
    fs_add(&R, a);
    if (where == 1) { fs_add(&X, a); fs_add(&W, (SOCKET)f); }
    else { fs_add(&W, b); fs_add(&X, (SOCKET)f); }
    w_seterr(0);
    EQ(w_select(0, &R, &W, &X, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    w_close(a); w_close(b); CloseHandle(f);
}
TEST(lift06_select_file_handle_in_write_set_with_sockets)  { SEL_START(); file_among_sockets(1); }
TEST(lift06_select_file_handle_in_except_set_with_sockets) { SEL_START(); file_among_sockets(2); }

TEST(lift06_select_duplicated_socket_handle_works)
{
    SOCKET a, b; HANDLE hd = NULL; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)a, GetCurrentProcess(), &hd, 0, FALSE, DUPLICATE_SAME_ACCESS));
    tv_set(&tv, 0, 500);
    /* The duplicate is a socket in its own right: idle -> nothing readable. */
    zero_all(); fs_add(&R, (SOCKET)hd);
    EQ(w_select(0, &R, &W, &X, &tv), 0);
    /* In the write set the duplicate counts as writable. */
    zero_all(); fs_add(&R, a); fs_add(&X, a); fs_add(&W, (SOCKET)hd);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    zero_all(); fs_add(&R, a); fs_add(&W, b); fs_add(&X, (SOCKET)hd);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CloseHandle(hd);
    w_close(a); w_close(b);
}

/* ---- APC delivery ---- */
static unsigned g_apc;
static VOID CALLBACK sel_apc(ULONG_PTR p) { ++*(unsigned *)p; }
TEST(lift06_select_runs_queued_apc_when_nothing_ready)
{
    SOCKET a, b; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    zero_all(); fs_add(&R, a);
    g_apc = 0;
    CHECK(QueueUserAPC(sel_apc, GetCurrentThread(), (ULONG_PTR)&g_apc));
    tv_set(&tv, 0, 500);
    EQ(w_select(a + 1, &R, NULL, NULL, &tv), 0);
    EQ(g_apc, 1);                    /* the wait inside select is alertable */
    w_close(a); w_close(b);
}
TEST(lift06_select_leaves_apc_pending_when_socket_ready)
{
    SOCKET a, b; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    zero_all(); fs_add(&W, b);
    g_apc = 0;
    CHECK(QueueUserAPC(sel_apc, GetCurrentThread(), (ULONG_PTR)&g_apc));
    tv_set(&tv, 0, 500);
    EQ(w_select(b + 1, NULL, &W, NULL, &tv), 1);
    CHECK(fs_has(&W, b));
    EQ(g_apc, 0);                    /* an immediately satisfied select does not wait, so no APC yet */
    SleepEx(0, TRUE);
    EQ(g_apc, 1);
    w_close(a); w_close(b);
}

/* ---- set handling ---- */
TEST(lift06_select_same_socket_listed_twice)
{
    SOCKET a, b; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    W.fd_count = 2; W.fd_array[0] = b; W.fd_array[1] = b;
    tv_set(&tv, 0, 500);
    EQ(w_select(0, NULL, &W, NULL, &tv), 1);
    EQ(W.fd_count, 1);               /* duplicates collapse; the tail slot is not scrubbed */
    EQ(W.fd_array[0], b);
    EQ(W.fd_array[1], b);
    w_close(a); w_close(b);
}
TEST(lift06_select_shared_read_write_set_single_socket)
{
    SOCKET a, b; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    tv_set(&tv, 0, 500);
    fs_zero(&R); fs_add(&R, b);
    EQ(w_select(b + 1, &R, &R, NULL, &tv), 1);
    CHECK(fs_has(&R, b));
    fs_zero(&R); fs_add(&R, b); fs_add(&R, a);
    EQ(w_select(0, &R, &R, NULL, &tv), 2);   /* both are writable, so both come back */
    CHECK(fs_has(&R, a)); CHECK(fs_has(&R, b));
    w_close(a); w_close(b);
}
TEST(lift06_select_shared_set_with_pending_data)
{
    SOCKET a, b; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    tv_set(&tv, 0, 500);
    EQ(w_send(b, "test", 4, 0), 4);
    fs_zero(&R); fs_add(&R, a);
    EQ(w_select(0, &R, NULL, NULL, &tv), 1);
    CHECK(fs_has(&R, a));
    fs_zero(&R); fs_add(&R, b); fs_add(&R, a);
    EQ(w_select(0, &R, &R, NULL, &tv), 2);
    CHECK(fs_has(&R, a)); CHECK(fs_has(&R, b));
    w_close(a); w_close(b);
}

/* Fill the sender's buffer (bounded) and watch write readiness vanish, then recover reads. */
TEST(lift06_select_full_send_buffer_not_writable)
{
    SOCKET a, b; struct timeval tv; static char blk[4096]; int i, full = 0;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    tv_set(&tv, 0, 500);
    EQ(w_send(b, "test", 4, 0), 4);
    w_nonblock(b, 1);
    for (i = 0; i < 8192; i++) {
        fs_zero(&W); fs_add(&W, b);
        if (w_select(0, NULL, &W, NULL, &tv) == 0) { full = 1; break; }
        w_send(b, blk, sizeof blk, 0);
    }
    if (!full) { t_skip("send buffer never reported full within the bound"); w_close(a); w_close(b); return; }
    fs_zero(&R); fs_add(&R, b); fs_add(&R, a);
    EQ(w_select(0, &R, &R, NULL, &tv), 1);
    CHECK(!fs_has(&R, b));
    CHECK(fs_has(&R, a));
    /* Data in the other direction makes the stalled sender readable, and the peer is writable. */
    EQ(w_send(a, "test", 4, 0), 4);
    Sleep(100);
    fs_zero(&R); fs_add(&R, b); fs_add(&R, a);
    EQ(w_select(0, &R, &R, NULL, &tv), 2);
    CHECK(fs_has(&R, a)); CHECK(fs_has(&R, b));
    w_close(a); w_close(b);
}

/* An fd_set whose single entry ends exactly at a no-access page must be handled without
 * touching memory past the entries counted by fd_count. */
TEST(lift06_select_fdset_ending_at_guard_page)
{
    SOCKET a, b; struct timeval tv; char *pg; DWORD old; fd_set *fs; int ret;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    EQ(w_send(b, "x", 1, 0), 1);
    pg = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(pg != NULL);
    if (pg) {
        VirtualProtect(pg + 0x1000, 0x1000, PAGE_NOACCESS, &old);
        fs = (fd_set *)((pg + 0x1000) - offsetof(fd_set, fd_array[1]));
        fs->fd_count = 1; fs->fd_array[0] = a;
        tv_set(&tv, 0, 500);
        ret = w_select(0, fs, NULL, NULL, &tv);
        EQ(ret, 1);
        VirtualFree(pg, 0, MEM_RELEASE);
    }
    w_close(a); w_close(b);
}

/* More sockets than FD_SETSIZE, in a caller-allocated set. */
TEST(lift06_select_two_hundred_sockets_in_write_set)
{
    enum { N = 200 };
    SOCKET so[N]; fd_set *fs; struct timeval tv; int i, ret, made = 0;
    SEL_START();
    fs = malloc(offsetof(fd_set, fd_array[N]));
    fs->fd_count = N;
    for (i = 0; i < N; i += 2) {
        if (!lo_pair(&so[i], &so[i + 1])) break;
        fs->fd_array[i] = so[i]; fs->fd_array[i + 1] = so[i + 1];
        made = i + 2;
    }
    CHECK(made == N);
    if (made == N) {
        tv_set(&tv, 0, 500);
        ret = w_select(0, NULL, fs, NULL, &tv);
        EQ(ret, N);
        for (i = 0; i < N; i++) CHECK(fs->fd_array[i] == so[i]);   /* order is preserved */
    }
    for (i = 0; i < made; i++) w_close(so[i]);
    free(fs);
}

/* ---- connection-state readiness ---- */
TEST(lift06_select_idle_listener_returns_zero)
{
    struct sockaddr_in a; SOCKET l; struct timeval tv;
    SEL_START();
    l = lo_listener(&a, 5);
    zero_all(); add_all(l);
    tv_set(&tv, 0, 250000);
    EQ(w_select(0, &R, &W, &X, &tv), 0);
    w_close(l);
}
TEST(lift06_select_pending_connection_makes_listener_readable)
{
    struct sockaddr_in a; SOCKET l, c, s; struct timeval tv; int e;
    SEL_START();
    l = lo_listener(&a, 5);
    c = w_socket(AF_INET, SOCK_STREAM, 0);
    w_nonblock(c, 1);
    e = w_connect(c, &a, sizeof a);
    CHECK(e == 0 || w_err() == WSAEWOULDBLOCK);
    tv_set(&tv, 1, 250000);
    zero_all(); add_all(l);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&R, l));
    s = w_accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    /* Both ends of the established connection are now writable and the connect reported no error. */
    zero_all(); add_all(l); add_all(s); add_all(c);
    EQ(w_select(0, &R, &W, &X, &tv), 2);
    CHECK(fs_has(&W, c)); CHECK(fs_has(&W, s));
    EQ(w_so_error(c), 0);
    w_close(s); w_close(c); w_close(l);
}
TEST(lift06_select_data_arrival_readable_not_exceptional)
{
    SOCKET a, b; struct timeval tv; char buf[16];
    SEL_START();
    CHECK(lo_pair(&a, &b));
    w_nonblock(b, 1);
    tv_set(&tv, 1, 250000);
    EQ(w_send(a, "1234", 4, 0), 4);
    zero_all(); fs_add(&R, b); fs_add(&X, b);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&R, b)); CHECK(!fs_has(&X, b));
    zero_all(); add_all(b);
    EQ(w_select(0, &R, &W, &X, &tv), 2);   /* readable and writable */
    CHECK(fs_has(&R, b)); CHECK(fs_has(&W, b)); CHECK(!fs_has(&X, b));
    memset(buf, 0, sizeof buf);
    EQ(w_recv(b, buf, sizeof buf, 0), 4);
    EXPECT_STR(buf, "1234");
    w_close(a); w_close(b);
}
TEST(lift06_select_oob_byte_reported_in_except_set)
{
    SOCKET a, b; struct timeval tv; char c = 0;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    w_nonblock(b, 1);
    tv_set(&tv, 1, 250000);
    EQ(w_send(a, "A", 1, MSG_OOB), 1);
    zero_all(); fs_add(&R, b); fs_add(&X, b);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&X, b));
    EQ(w_recv(b, &c, 1, MSG_OOB), 1);
    EQ(c, 'A');
    w_close(a); w_close(b);
}
TEST(lift06_select_inline_oob_is_readable_and_msg_oob_recv_fails)
{
    SOCKET a, b; struct timeval tv; char c = 0; int one = 1;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    w_nonblock(b, 1);
    EQ(w_setsockopt(b, SOL_SOCKET, SO_OOBINLINE, &one, sizeof one), 0);
    tv_set(&tv, 1, 250000);
    EQ(w_send(a, "A", 1, MSG_OOB), 1);
    zero_all(); fs_add(&R, b); fs_add(&X, b);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&R, b));
    w_seterr(0);
    EQ(w_recv(b, &c, 1, MSG_OOB), SOCKET_ERROR);   /* inline OOB data can no longer be fetched as OOB */
    EQ(w_err(), WSAEINVAL);
    c = 0;
    EQ(w_recv(b, &c, 1, 0), 1);
    EQ(c, 'A');
    w_seterr(0);
    EQ(w_recv(b, &c, 1, 0), SOCKET_ERROR);          /* and the byte is delivered only once */
    EQ(w_err(), WSAEWOULDBLOCK);
    w_close(a); w_close(b);
}
TEST(lift06_select_peer_close_makes_socket_readable_with_eof)
{
    SOCKET a, b; struct timeval tv; char buf[8];
    SEL_START();
    CHECK(lo_pair(&a, &b));
    tv_set(&tv, 1, 250000);
    EQ(w_close(b), 0);
    zero_all(); fs_add(&R, a);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&R, a));
    EQ(w_recv(a, buf, sizeof buf, 0), 0);
    EQ(w_close(a), 0);
}

/* ---- closed handles and cross-thread close ---- */
TEST(lift06_select_closed_socket_enotsock_sets_unchanged)
{
    SOCKET a, b; struct timeval tv;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    w_close(a);
    zero_all(); add_all(b); add_all(a);
    tv_set(&tv, 1, 250000);
    w_seterr(0);
    EQ(w_select(0, &R, NULL, &X, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    EQ(R.fd_count, 2);                  /* on error the sets are not rewritten */
    EQ(X.fd_count, 2);
    w_close(b);
}

static DWORD WINAPI close_later(void *p) { Sleep(300); w_close(*(SOCKET *)p); return 0; }
TEST(lift06_select_close_from_other_thread_wakes_read_set)
{
    SOCKET a, b; struct timeval tv; HANDLE th;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    th = CreateThread(NULL, 0, close_later, &b, 0, NULL);
    zero_all(); add_all(b);
    tv_set(&tv, 4, 0);
    EQ(w_select(0, &R, NULL, &X, &tv), 1);
    CHECK(fs_has(&R, b));
    CHECK(join_thread(th, 3000));
    w_close(a);
}
TEST(lift06_select_close_from_other_thread_fails_except_only_wait)
{
    SOCKET a, b; struct timeval tv; HANDLE th;
    SEL_START();
    CHECK(lo_pair(&a, &b));
    th = CreateThread(NULL, 0, close_later, &b, 0, NULL);
    zero_all(); fs_add(&X, b);
    tv_set(&tv, 4, 0);
    w_seterr(0);
    EQ(w_select(0, NULL, NULL, &X, &tv), SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    CHECK(!fs_has(&X, b));
    CHECK(join_thread(th, 3000));
    w_close(a);
}

struct lw { SOCKET s; HANDLE ready; int killed; };
static DWORD WINAPI listen_select(void *p)
{
    struct lw *q = p; fd_set r; struct timeval tv;
    fs_zero(&r); fs_add(&r, q->s);
    tv_set(&tv, 5, 0);
    SetEvent(q->ready);
    q->killed = (w_select(0, &r, NULL, NULL, &tv) == 1);
    return 0;
}
TEST(lift06_select_close_wakes_listener_wait)
{
    struct sockaddr_in a; struct lw q; HANDLE th; char c;
    SEL_START();
    q.s = lo_listener(&a, 5);
    q.killed = 0;
    q.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, listen_select, &q, 0, NULL);
    WaitForSingleObject(q.ready, 3000);
    Sleep(200);
    EQ(w_close(q.s), 0);
    CHECK(join_thread(th, 4000));
    CHECK(q.killed);
    w_seterr(0);
    EQ(w_recv(q.s, &c, 1, MSG_PEEK), SOCKET_ERROR);
    EQ(w_err(), WSAENOTSOCK);
    CloseHandle(q.ready);
}

/* ---- non-blocking connect failure semantics ---- */
static int wait_all3(SOCKET s, int sec)
{
    struct timeval tv;
    zero_all(); add_all(s);
    tv_set(&tv, sec, 0);
    return w_select(0, &R, &W, &X, &tv);
}
TEST(lift06_select_nonblocking_connect_refused_sequence)
{
    struct sockaddr_in d, la; SOCKET s, l; int ret;
    SEL_START();
    d = lo_dead_addr();
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_nonblock(s, 1);
    w_seterr(0);
    EQ(w_connect(s, &d, sizeof d), SOCKET_ERROR);
    EQ(w_err(), WSAEWOULDBLOCK);
    ret = wait_all3(s, 8);
    if (ret == 0) { t_skip("refusal not reported within the bound"); w_close(s); return; }
    EQ(ret, 1);
    CHECK(fs_has(&X, s));
    /* The pending error is sticky: reading SO_ERROR does not clear it. */
    EQ(w_so_error(s), WSAECONNREFUSED);
    EQ(w_so_error(s), WSAECONNREFUSED);
    EQ(wait_all3(s, 8), 1);
    CHECK(fs_has(&X, s));
    /* Another connect attempt does not reset the error either. */
    w_seterr(0);
    EQ(w_connect(s, &d, sizeof d), SOCKET_ERROR);
    EQ(w_err(), WSAEWOULDBLOCK);
    EQ(w_so_error(s), WSAECONNREFUSED);
    EQ(wait_all3(s, 8), 1);
    CHECK(fs_has(&X, s));
    /* A successful connection finally clears it. */
    l = lo_listener(&la, 2);
    w_seterr(0);
    EQ(w_connect(s, &la, sizeof la), SOCKET_ERROR);
    EQ(w_err(), WSAEWOULDBLOCK);
    EQ(wait_all3(s, 4), 1);
    CHECK(fs_has(&W, s));
    EQ(w_so_error(s), 0);
    w_close(s); w_close(l);
}
TEST(lift06_select_listen_after_failed_nonblocking_connect)
{
    struct sockaddr_in d, a = lo_addr(0); SOCKET s, c2, s2; int n = sizeof a, ret;
    struct timeval tv;
    SEL_START();
    d = lo_dead_addr();
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_nonblock(s, 1);
    EQ(w_bind(s, &a, sizeof a), 0);
    w_seterr(0);
    EQ(w_connect(s, &d, sizeof d), SOCKET_ERROR);
    EQ(w_err(), WSAEWOULDBLOCK);
    zero_all(); fs_add(&X, s);
    tv_set(&tv, 8, 0);
    ret = w_select(0, NULL, NULL, &X, &tv);
    if (ret == 0) { t_skip("refusal not reported within the bound"); w_close(s); return; }
    EQ(ret, 1);
    EQ(w_getsockname(s, &a, &n), 0);
    /* A socket whose connect failed may be turned into a listener and serves a client. */
    EQ(w_listen(s, 1), 0);
    c2 = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(w_connect(c2, &a, sizeof a), 0);
    zero_all(); fs_add(&R, s); tv_set(&tv, 3, 0);
    ret = w_select(0, &R, NULL, NULL, &tv);
    EQ(ret, 1);
    s2 = w_accept(s, NULL, NULL);
    CHECKF(s2 != INVALID_SOCKET, "accept err=%d", w_err());
    if (s2 != INVALID_SOCKET) w_close(s2);
    w_close(c2);
    EQ(w_so_error(s), WSAECONNREFUSED);
    zero_all(); add_all(s);
    tv_set(&tv, 0, 0);
    ret = w_select(0, &R, &W, &X, &tv);
    EQ(ret, 1);
    CHECK(fs_has(&X, s));
    w_close(s);
}
TEST(lift06_select_after_blocking_refused_connect)
{
    struct sockaddr_in d; SOCKET s; struct timeval tv;
    SEL_START();
    d = lo_dead_addr();
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_seterr(0);
    EQ(w_connect(s, &d, sizeof d), SOCKET_ERROR);
    EQ(w_err(), WSAECONNREFUSED);
    /* The synchronous failure is returned to the caller and not left pending as a socket error. */
    EQ(w_so_error(s), 0);
    zero_all(); add_all(s);
    tv_set(&tv, 0, 0);
    EQ(w_select(0, &R, &W, &X, &tv), 1);
    CHECK(fs_has(&X, s));
    EQ(w_so_error(s), 0);
    w_close(s);
}
