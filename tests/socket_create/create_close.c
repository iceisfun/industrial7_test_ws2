/* socket_create: closesocket semantics, INVALID_SOCKET, and the numeric properties of socket handles.
 *
 * Observed contract: a socket is an NT handle to a \Device\Afd endpoint. closesocket() on a live socket
 * returns 0 and closes that handle; on anything that is not a socket known to the provider layer
 * (including 0, INVALID_SOCKET, handles of other object types and sockets already closed) it returns
 * SOCKET_ERROR with WSAENOTSOCK and leaves foreign handles alone. A closesocket() issued from another
 * thread while one is blocked inside accept()/recv() on the same socket wakes it with WSAEINTR.
 * A socket handle is a multiple of 4, non-zero, and fits in 32 bits. DuplicateHandle copies keep the
 * endpoint alive and remain usable as sockets after the original is closed. */
#include "sc.h"

static SOCKET make_kind(int i, DWORD fl) {
    switch (i) {
    case 0: return sc_make(AF_INET, SOCK_STREAM, 0, fl);
    case 1: return sc_make(AF_INET, SOCK_DGRAM, 0, fl);
    case 2: return sc_make(AF_INET6, SOCK_STREAM, 0, fl);
    case 3: return sc_make(AF_INET6, SOCK_DGRAM, 0, fl);
    default: return sc_make(AF_UNIX, SOCK_STREAM, 0, fl);
    }
}
static const char *kind_name[] = {"tcp4", "udp4", "tcp6", "udp6", "unix"};
#define NKINDS 5

/* ---- normal close ---- */
TEST(sockcreate_close_live_socket_returns_zero_for_every_kind) {
    int i;
    SC_UP();
    for (i = 0; i < NKINDS; i++) {
        SOCKET s = make_kind(i, WSA_FLAG_OVERLAPPED);
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "creation", "%s", kind_name[i]);
        if (s == INVALID_SOCKET) continue;
        sc_seterr(0);
        t_check(U(closesocket)(s) == 0, __FILE__, __LINE__, "closesocket", "%s error %d", kind_name[i], sc_err());
    }
}
TEST(sockcreate_close_synchronous_and_noinherit_sockets) {
    static const DWORD fl[] = {0, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_REGISTERED_IO, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_STREAM, 0, fl[i]);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(U(closesocket)(s), 0);
    }
}
TEST(sockcreate_close_releases_the_nt_handle) {
    int i;
    SC_UP();
    for (i = 0; i < NKINDS; i++) {
        SOCKET s = make_kind(i, 1);
        DWORD f;
        if (s == INVALID_SOCKET) { t_check(0, __FILE__, __LINE__, "creation", "%s", kind_name[i]); continue; }
        CHECK(GetHandleInformation((HANDLE)s, &f));
        SC_EQ(U(closesocket)(s), 0);
        SetLastError(0);
        t_check(!GetHandleInformation((HANDLE)s, &f), __FILE__, __LINE__, "handle gone", "%s", kind_name[i]);
        EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
}
TEST(sockcreate_close_unbound_unconnected_socket_has_no_side_effects) {
    SOCKET a, b;
    SC_UP();
    a = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    b = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET);
    SC_EQ(U(closesocket)(a), 0);
    SC_EQ(sc_sotype(b), SOCK_STREAM);                /* the sibling is untouched */
    SC_EQ(U(closesocket)(b), 0);
}

/* ---- closing something that is not (or no longer) a socket ---- */
static void expect_notsock(SOCKET s, const char *what) {
    int r;
    sc_seterr(0);
    r = U(closesocket)(s);
    t_check(r == SOCKET_ERROR, __FILE__, __LINE__, "closesocket fails", "%s returned %d", what, r);
    t_check(sc_err() == WSAENOTSOCK, __FILE__, __LINE__, "WSAENOTSOCK", "%s got %d", what, sc_err());
}
TEST(sockcreate_close_twice_is_enotsock) {
    int i;
    SC_UP();
    for (i = 0; i < NKINDS; i++) {
        SOCKET s = make_kind(i, 1);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(U(closesocket)(s), 0);
        expect_notsock(s, kind_name[i]);
        expect_notsock(s, "third close");
    }
}
TEST(sockcreate_close_invalid_socket_is_enotsock) {
    SC_UP();
    expect_notsock(INVALID_SOCKET, "INVALID_SOCKET");
}
TEST(sockcreate_close_zero_and_small_values_are_enotsock) {
    SOCKET v;
    SC_UP();
    for (v = 0; v <= 16; v += 4) expect_notsock(v, "small value");
    expect_notsock(1, "1");
    expect_notsock(3, "3");
}
TEST(sockcreate_close_pseudo_handles_are_enotsock) {
    SC_UP();
    expect_notsock((SOCKET)GetCurrentProcess(), "process pseudo handle");     /* same bits as INVALID_SOCKET */
    expect_notsock((SOCKET)GetCurrentThread(), "thread pseudo handle");
}
TEST(sockcreate_close_event_handle_is_enotsock_and_survives) {
    HANDLE e = CreateEventW(NULL, FALSE, FALSE, NULL);
    SC_UP();
    CHECK(e != NULL);
    expect_notsock((SOCKET)e, "event");
    CHECK(SetEvent(e));                                  /* still a valid handle */
    CloseHandle(e);
}
TEST(sockcreate_close_other_object_types_are_enotsock_and_survive) {
    HANDLE h[4];
    DWORD f;
    int i;
    SC_UP();
    h[0] = CreateMutexW(NULL, FALSE, NULL);
    h[1] = CreateSemaphoreW(NULL, 0, 1, NULL);
    h[2] = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    h[3] = GetCurrentProcess();
    for (i = 0; i < 3; i++) {
        CHECK(h[i] != NULL && h[i] != INVALID_HANDLE_VALUE);
        expect_notsock((SOCKET)h[i], "foreign object");
        CHECK(GetHandleInformation(h[i], &f));
        CloseHandle(h[i]);
    }
}
TEST(sockcreate_close_never_issued_handle_values_are_enotsock) {
    static const SOCKET v[] = {0x7ffffffc, 0xfffffffc, 0x100000000ull, 0x123456780ull, 0x8000000000000000ull};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof v / sizeof *v; i++) expect_notsock(v[i], "arbitrary value");
}
TEST(sockcreate_close_failure_keeps_win32_and_wsa_error_equal) {
    SC_UP();
    SetLastError(0);
    CHECK(U(closesocket)(INVALID_SOCKET) == SOCKET_ERROR);
    SC_EQ(GetLastError(), WSAENOTSOCK);
    SC_EQ(sc_err(), WSAENOTSOCK);
}
TEST(sockcreate_close_return_value_is_minus_one_exactly) {
    SOCKET s;
    int r;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    U(closesocket)(s);
    r = U(closesocket)(s);
    SC_EQ(r, -1);
    CHECK(SOCKET_ERROR == -1);
    CHECK(INVALID_SOCKET == (SOCKET)~(ULONG_PTR)0);
}

/* ---- every operation on a closed socket reports WSAENOTSOCK ---- */
TEST(sockcreate_close_operations_on_closed_socket_report_enotsock) {
    SOCKET s;
    struct sockaddr_in a;
    int len = sizeof a, one = 1, v, vl = sizeof v, rc;
    u_long nb = 1;
    char buf[4] = {0};
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(s != INVALID_SOCKET);
    sc_close(s);
    sc_loop4(&a);
#define NOTSOCK(call) do { sc_seterr(0); rc = (call); t_check(rc == SOCKET_ERROR, __FILE__, __LINE__, #call, "returned %d", rc); \
                           t_check(sc_err() == WSAENOTSOCK, __FILE__, __LINE__, #call, "error %d", sc_err()); } while (0)
    NOTSOCK(U(bind)(s, (struct sockaddr *)&a, sizeof a));
    NOTSOCK(U(listen)(s, 1));
    NOTSOCK(U(connect)(s, (struct sockaddr *)&a, sizeof a));
    NOTSOCK(U(shutdown)(s, SD_BOTH));
    NOTSOCK(U(getsockname)(s, (struct sockaddr *)&a, &len));
    NOTSOCK(U(getpeername)(s, (struct sockaddr *)&a, &len));
    NOTSOCK(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&v, &vl));
    NOTSOCK(U(setsockopt)(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one));
    NOTSOCK(U(ioctlsocket)(s, FIONBIO, &nb));
    NOTSOCK(U(send)(s, buf, 1, 0));
    NOTSOCK(U(recv)(s, buf, 1, 0));
    NOTSOCK(U(sendto)(s, buf, 1, 0, (struct sockaddr *)&a, sizeof a));
    NOTSOCK(U(recvfrom)(s, buf, 1, 0, NULL, NULL));
#undef NOTSOCK
    sc_seterr(0);
    CHECK(U(accept)(s, NULL, NULL) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAENOTSOCK);
}

/* ---- DuplicateHandle copies ---- */
TEST(sockcreate_close_duplicated_handle_is_still_a_socket) {
    SOCKET s;
    HANDLE d = NULL;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    CHECK(s != INVALID_SOCKET);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK(d != NULL && (SOCKET)d != s);
    SC_EQ(sc_sotype((SOCKET)d), SOCK_DGRAM);
    SC_EQ(U(closesocket)(s), 0);
    SC_EQ(sc_sotype((SOCKET)d), SOCK_DGRAM);        /* the endpoint lives as long as one handle does */
    SC_EQ(U(closesocket)((SOCKET)d), 0);
    expect_notsock((SOCKET)d, "closed duplicate");
}
TEST(sockcreate_close_duplicate_closed_first) {
    SOCKET s;
    HANDLE d = NULL;
    SC_UP();
    s = sc_make(AF_INET6, SOCK_STREAM, 0, 1);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    SC_EQ(U(closesocket)((SOCKET)d), 0);
    SC_EQ(sc_sotype(s), SOCK_STREAM);
    SC_EQ(U(closesocket)(s), 0);
}
TEST(sockcreate_close_duplicate_in_same_process_with_inherit_flag) {
    SOCKET s;
    HANDLE d = NULL;
    DWORD f = 0;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, TRUE, DUPLICATE_SAME_ACCESS));
    CHECK(GetHandleInformation(d, &f));
    CHECK(f & HANDLE_FLAG_INHERIT);                      /* the copy takes the flag asked of DuplicateHandle */
    SC_EQ(sc_sotype((SOCKET)d), SOCK_STREAM);
    sc_close(s);
    sc_close((SOCKET)d);
}

/* ---- closing from a second thread wakes a blocked caller ---- */
/* A helper thread closes the socket after a delay; a watchdog thread sends one datagram / connects to the
 * socket's own (loopback) address after a few seconds so that a stack which fails to wake the blocked call
 * cannot hang the run. If the closer lost the race and ran before the call blocked, the call reports
 * WSAENOTSOCK instead; that outcome is recorded, not asserted. */
typedef struct { SOCKET s; struct sockaddr_in addr; int stream; volatile LONG done; } wake_t;
static DWORD WINAPI close_later(LPVOID p) {
    wake_t *w = (wake_t *)p;
    Sleep(700);
    U(closesocket)(w->s);
    return 0;
}
static DWORD WINAPI watchdog(LPVOID p) {
    wake_t *w = (wake_t *)p;
    int i;
    for (i = 0; i < 60 && !w->done; i++) Sleep(100);
    if (!w->done) {
        SOCKET c = sc_make(AF_INET, w->stream ? SOCK_STREAM : SOCK_DGRAM, 0, 1);
        if (c != INVALID_SOCKET) {
            if (w->stream) U(connect)(c, (struct sockaddr *)&w->addr, sizeof w->addr);
            else U(sendto)(c, "x", 1, 0, (struct sockaddr *)&w->addr, sizeof w->addr);
            Sleep(300);
            sc_close(c);
        }
    }
    return 0;
}
static void wake_run(int stream) {
    wake_t w;
    struct sockaddr_in a;
    HANDLE th, wd;
    char b[4];
    int l = sizeof a, r, e;
    SOCKET got = INVALID_SOCKET;
    memset(&w, 0, sizeof w);
    w.stream = stream;
    w.s = sc_make(AF_INET, stream ? SOCK_STREAM : SOCK_DGRAM, 0, 1);
    CHECK(w.s != INVALID_SOCKET);
    if (w.s == INVALID_SOCKET) return;
    sc_loop4(&a);
    CHECK(U(bind)(w.s, (struct sockaddr *)&a, sizeof a) == 0);
    if (stream) CHECK(U(listen)(w.s, 1) == 0);
    CHECK(U(getsockname)(w.s, (struct sockaddr *)&w.addr, &l) == 0);
    th = CreateThread(NULL, 0, close_later, &w, 0, NULL);
    wd = CreateThread(NULL, 0, watchdog, &w, 0, NULL);
    CHECK(th != NULL && wd != NULL);
    sc_seterr(0);
    if (stream) { got = U(accept)(w.s, NULL, NULL); r = (got == INVALID_SOCKET) ? SOCKET_ERROR : 0; }
    else r = U(recv)(w.s, b, sizeof b, 0);
    e = sc_err();
    InterlockedExchange(&w.done, 1);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    if (wd) { WaitForSingleObject(wd, 5000); CloseHandle(wd); }
    sc_close(got);
    CHECK(r == SOCKET_ERROR);
    if (r == SOCKET_ERROR && e == WSAENOTSOCK) { t_note("the closer ran before the call blocked"); return; }
    SC_EQ(e, WSAEINTR);
    sc_seterr(0);
    SC_EQ(U(closesocket)(w.s), SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTSOCK);
}
TEST(sockcreate_close_wakes_blocked_accept_with_eintr) { SC_UP(); wake_run(1); }
TEST(sockcreate_close_wakes_blocked_recv_with_eintr)   { SC_UP(); wake_run(0); }
/* ---- numeric properties of socket handles ---- */
TEST(sockcreate_handle_is_multiple_of_four_for_every_kind_and_flag) {
    static const DWORD fl[] = {0, 1, 0x80, 0x81, 0x100};
    int i;
    unsigned j;
    SC_UP();
    for (i = 0; i < NKINDS; i++)
        for (j = 0; j < sizeof fl / sizeof *fl; j++) {
            SOCKET s = make_kind(i, fl[j]);
            if (s == INVALID_SOCKET) continue;          /* AF_UNIX refuses 0x100 */
            t_check((s & 3) == 0, __FILE__, __LINE__, "multiple of 4", "%s flags %#lx", kind_name[i], fl[j]);
            t_check(s != 0, __FILE__, __LINE__, "non-zero", "%s", kind_name[i]);
            t_check((s >> 32) == 0, __FILE__, __LINE__, "fits in 32 bits", "%s", kind_name[i]);
            sc_close(s);
        }
}
TEST(sockcreate_handle_values_are_distinct_while_open) {
    SOCKET ss[96];
    int i, j, n = 0, dup = 0;
    SC_UP();
    for (i = 0; i < 96; i++) {
        ss[i] = make_kind(i % NKINDS, 1);
        if (ss[i] == INVALID_SOCKET) break;
        n++;
        for (j = 0; j < i; j++) if (ss[j] == ss[i]) dup++;
    }
    SC_EQ(n, 96);
    SC_EQ(dup, 0);
    for (i = 0; i < n; i++) sc_close(ss[i]);
}
TEST(sockcreate_handle_all_open_sockets_are_valid_nt_handles) {
    SOCKET ss[32];
    int i;
    SC_UP();
    for (i = 0; i < 32; i++) ss[i] = sc_make(AF_INET, SOCK_DGRAM, 0, i & 1 ? 1 : 0);
    for (i = 0; i < 32; i++) {
        DWORD f;
        CHECK(ss[i] != INVALID_SOCKET);
        if (ss[i] != INVALID_SOCKET) CHECK(GetHandleInformation((HANDLE)ss[i], &f));
    }
    for (i = 0; i < 32; i++) sc_close(ss[i]);
}
TEST(sockcreate_handle_reuse_after_close_yields_a_working_socket) {
    int i;
    SC_UP();
    for (i = 0; i < 20; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(sc_sotype(s), SOCK_STREAM);
        SC_EQ(U(closesocket)(s), 0);
    }
}
TEST(sockcreate_handle_no_leak_over_many_create_close_cycles) {
    DWORD before = 0, after = 0;
    int i;
    SC_UP();
    for (i = 0; i < 4; i++) sc_close(make_kind(i, 1));         /* warm up lazily created provider state */
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
    for (i = 0; i < 300; i++) {
        SOCKET s = make_kind(i % NKINDS, i & 1);
        if (s == INVALID_SOCKET) { t_check(0, __FILE__, __LINE__, "creation", "iteration %d error %d", i, sc_err()); break; }
        sc_close(s);
    }
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &after));
    CHECK(after < before + 16);
}
TEST(sockcreate_handle_stays_valid_across_failed_creations) {
    SOCKET s;
    int i;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    for (i = 0; i < 20; i++) {
        CHECK(U(socket)(AF_INET, SOCK_SEQPACKET, 0) == INVALID_SOCKET);
        CHECK(U(socket)(SC_BAD, SOCK_STREAM, 0) == INVALID_SOCKET);
    }
    SC_EQ(sc_sotype(s), SOCK_STREAM);
    sc_close(s);
}
