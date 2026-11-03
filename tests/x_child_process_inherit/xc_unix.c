/* x_child_process_inherit / unix: the AF_UNIX stream family across processes. Inherited connected pairs, listeners
 * accepting in a child, name identity (the bound path is the same endpoint), protocol-info duplicates, the
 * inheritable bit, closing semantics when a child leaves, and a bind/listen performed by a child. Skipped as a whole
 * where the family is unavailable. */
#include "xc.h"

static int xu_family_ok(void)
{
    SOCKET s;
    if (!xc_up()) return 0;
    s = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
    if (s == INVALID_SOCKET) { t_skip("AF_UNIX unavailable (%d)", xc_werr()); return 0; }
    xc_close(s);
    return 1;
}
#define XU() do { if (!xu_family_ok()) return; } while (0)
static void xu_addr(SOCKADDR_UN *a, const char *leaf)
{
    char p[MAX_PATH];
    memset(a, 0, sizeof *a); a->sun_family = AF_UNIX;
    t_tmpfile(p, sizeof p, leaf);
    strncpy(a->sun_path, p, sizeof a->sun_path - 1);
}
/* Listener / client / accepted trio on a scratch path. */
static int xu_trio(const char *leaf, int flags, SOCKET *l, SOCKET *c, SOCKET *s, SOCKADDR_UN *addr)
{
    SOCKADDR_UN a; xu_addr(&a, leaf);
    *l = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, flags); *c = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, flags); *s = INVALID_SOCKET;
    if (*l == INVALID_SOCKET || *c == INVALID_SOCKET) return 0;
    if (U(bind)(*l, (struct sockaddr *)&a, sizeof a) || U(listen)(*l, 4)) return 0;
    if (U(connect)(*c, (struct sockaddr *)&a, sizeof a)) return 0;
    *s = xc_accept(*l, XC_WAIT);
    xc_rcvtimeo(*c, XC_WAIT);
    if (*s != INVALID_SOCKET) xc_rcvtimeo(*s, XC_WAIT);
    if (addr) *addr = a;
    return *s != INVALID_SOCKET;
}
#define TRIO_OR_SKIP(leaf, flags) SOCKET l, c, s; SOCKADDR_UN ad; \
    if (!xu_trio(leaf, flags, &l, &c, &s, &ad)) { t_skip("AF_UNIX loopback unavailable"); xc_close(l); xc_close(c); return; }
static const char *leaf_of(const SOCKADDR_UN *a) { const char *p = strrchr(a->sun_path, '\\'); return p ? p + 1 : a->sun_path; }

CHILD(u_exchange)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; SOCKADDR_UN n; int nl = sizeof n; char b[4] = {0};
    xc_child_up(); xc_rcvtimeo(s, XC_WAIT);
    STEP(0, xc_type_of(s) == SOCK_STREAM);
    memset(&n, 0, sizeof n);
    if (argv[3][0] == 'p') STEP(1, U(getpeername)(s, (struct sockaddr *)&n, &nl) == 0 && n.sun_family == AF_UNIX && !strcmp(leaf_of(&n), argv[2]));
    STEP(2, xc_send(s, "kid", 3) == 3);
    STEP(3, xc_recv_n(s, b, 3) == 3 && !memcmp(b, "par", 3));
    return (int)fails;
}
static void unix_exchange(int use_client, int flags, const char *leaf)
{
    TRIO_OR_SKIP(leaf, flags);
    {
        /* use_client: the child holds the client end (its peer name is the listener's path); otherwise the accepted end (unnamed peer) */
        SOCKET mine = use_client ? c : s, other = use_client ? s : c; char a[128]; HANDLE h[1], p;
        h[0] = H(mine);
        p = xc_spawn("u_exchange", XARGS(a, "%llu %s %c", xc_u(mine), leaf_of(&ad), use_client ? 'p' : 'n'), h, 1, NULL);
        CHECK(p != NULL);
        CHECK(xc_expect(other, "kid"));
        XEQ(xc_send(other, "par", 3), 3);
        XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
    }
    xc_close(l); xc_close(c); xc_close(s);
}
TEST(unix_inherit_client_end_exchange)       { XU(); unix_exchange(1, OVLD, "xcx1a.sock"); }
TEST(unix_inherit_client_end_sync)           { XU(); unix_exchange(1, SYNC, "xcx1b.sock"); }
TEST(unix_inherit_accepted_end_exchange)     { XU(); unix_exchange(0, OVLD, "xcx1c.sock"); }

/* ---- listener in the child ---- */
CHILD(u_accept)
{
    SOCKET l = xc_arg_sock(argv, 1), a; unsigned fails = 0; char b[3] = {0};
    xc_child_up();
    a = xc_accept(l, XC_WAIT);
    STEP(0, a != INVALID_SOCKET);
    if (a == INVALID_SOCKET) return (int)fails;
    xc_rcvtimeo(a, XC_WAIT);
    STEP(1, xc_recv_n(a, b, 2) == 2 && !memcmp(b, "hi", 2));
    STEP(2, xc_send(a, "ok", 2) == 2);
    U(closesocket)(a);
    return (int)fails;
}
TEST(unix_inherited_listener_accepts_in_child)
{
    SOCKADDR_UN a; SOCKET l, c; char arg[64]; HANDLE h[1], p;
    XU(); xu_addr(&a, "xcx2.sock");
    l = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
    if (l == INVALID_SOCKET || U(bind)(l, (struct sockaddr *)&a, sizeof a) || U(listen)(l, 4)) { t_skip("setup"); xc_close(l); return; }
    h[0] = H(l);
    p = xc_spawn("u_accept", XARGS(arg, "%llu", xc_u(l)), h, 1, NULL);
    CHECK(p != NULL);
    c = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    XEQ(xc_send(c, "hi", 2), 2);
    CHECK(xc_expect(c, "ok"));
    XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
    xc_close(c); xc_close(l);
}
TEST(unix_listener_queue_split_parent_child_in_order)
{
    SOCKADDR_UN a; SOCKET l, cl[4]; char arg[64]; HANDLE h[1]; DWORD code; int i;
    XU(); xu_addr(&a, "xcx3.sock");
    l = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
    if (l == INVALID_SOCKET || U(bind)(l, (struct sockaddr *)&a, sizeof a) || U(listen)(l, 8)) { t_skip("setup"); xc_close(l); return; }
    for (i = 0; i < 2; i++) {
        char id = (char)i;
        cl[i] = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
        XEQ(U(connect)(cl[i], (struct sockaddr *)&a, sizeof a), 0);
        xc_send(cl[i], &id, 1);
    }
    h[0] = H(l);
    code = xc_run("acc_n_unix", XARGS(arg, "%llu 2", xc_u(l)), h, 1);
    XEQ(code, 0 | (1 << 3));
    for (i = 2; i < 4; i++) {
        char id = (char)i;
        cl[i] = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
        XEQ(U(connect)(cl[i], (struct sockaddr *)&a, sizeof a), 0);
        xc_send(cl[i], &id, 1);
    }
    for (i = 2; i < 4; i++) {
        SOCKET x = xc_accept(l, XC_WAIT); char id = -1;
        CHECK(x != INVALID_SOCKET);
        if (x != INVALID_SOCKET) { xc_rcvtimeo(x, XC_WAIT); U(recv)(x, &id, 1, 0); XEQ(id, i); xc_close(x); }
    }
    for (i = 0; i < 4; i++) xc_close(cl[i]);
    xc_close(l);
}
CHILD(acc_n_unix)
{
    SOCKET l = xc_arg_sock(argv, 1); int n = xc_arg_int(argv, 2), i; DWORD code = 0; char id;
    xc_child_up();
    for (i = 0; i < n; i++) {
        SOCKET a = xc_accept(l, XC_WAIT);
        if (a == INVALID_SOCKET) return 0x80000000u | code;
        xc_rcvtimeo(a, XC_WAIT);
        if (U(recv)(a, &id, 1, 0) != 1) { U(closesocket)(a); return 0x40000000u | code; }
        code |= (DWORD)(id & 7) << (3 * i);
        U(closesocket)(a);
    }
    return code;
}

/* ---- protocol-info duplicates ---- */
CHILD(u_from_info)
{
    WSAPROTOCOL_INFOW pi; SOCKET s; unsigned fails = 0; SOCKADDR_UN n; int nl = sizeof n; char b[4] = {0};
    xc_child_up();
    STEP(0, xc_read_blob(argv, 1, &pi));
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, OVLD);
    STEP(1, s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return (int)fails;
    xc_rcvtimeo(s, XC_WAIT);
    STEP(2, pi.iAddressFamily == AF_UNIX && xc_type_of(s) == SOCK_STREAM);
    memset(&n, 0, sizeof n);
    STEP(3, U(getpeername)(s, (struct sockaddr *)&n, &nl) == 0 && n.sun_family == AF_UNIX && !strcmp(leaf_of(&n), argv[2]));
    STEP(4, xc_recv_n(s, b, 3) == 3 && !memcmp(b, "abc", 3));
    STEP(5, xc_send(s, "z", 1) == 1);
    return (int)fails;
}
TEST(unix_duplicate_to_child_shares_connection)
{
    TRIO_OR_SKIP("xcx4.sock", OVLD);
    {
        char a[96], b; int rc, e; HANDLE p;
        p = xc_spawn_blob("u_from_info", leaf_of(&ad), c, NULL, 0, &rc, &e);
        CHECK(p != NULL); XEQ(rc, 0);
        XEQ(xc_send(s, "abc", 3), 3);
        XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'z');
        XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
    }
    xc_close(l); xc_close(c); xc_close(s);
}
TEST(unix_duplicate_blob_fields)
{
    TRIO_OR_SKIP("xcx5.sock", OVLD);
    {
        WSAPROTOCOL_INFOW pi, o; int ol = sizeof o; HANDLE p = xc_idle();
        XEQ(U(WSADuplicateSocketW)(c, GetProcessId(p), &pi), 0);
        XEQ(pi.iAddressFamily, AF_UNIX);
        XEQ(pi.iSocketType, SOCK_STREAM);
        XEQ(U(getsockopt)(c, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&o, &ol), 0);
        XEQ(o.dwCatalogEntryId, pi.dwCatalogEntryId);
        xc_kill(p);
    }
    xc_close(l); xc_close(c); xc_close(s);
}

/* ---- inheritable bit and handle lists ---- */
TEST(unix_socket_flag_matrix)
{
    static const struct { int flags; DWORD want; } t[] = { { SYNC, HANDLE_FLAG_INHERIT }, { OVLD, HANDLE_FLAG_INHERIT }, { NOINH, 0 }, { OVLD | NOINH, 0 } };
    unsigned i; XU();
    for (i = 0; i < 4; i++) {
        SOCKET x = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, t[i].flags);
        CHECK(x != INVALID_SOCKET);
        XEQ(xc_hflags(H(x)), t[i].want);
        xc_close(x);
    }
}
TEST(unix_handle_list_noinherit_socket_refused)
{
    SOCKET x; HANDLE h[1], p; DWORD err = 0;
    XU(); x = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD | NOINH);
    h[0] = H(x);
    p = xc_spawn("exit0", "", h, 1, &err);
    CHECK(p == NULL); XEQ(err, ERROR_INVALID_PARAMETER);
    if (p) xc_kill(p);
    xc_close(x);
}
CHILD(u_absent)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; DWORD f;
    xc_child_up();
    xc_setwerr(0);
    STEP(0, !xc_is_socket(s) && xc_werr() == WSAENOTSOCK);
    STEP(1, !GetHandleInformation(H(s), &f));
    return (int)fails;
}
TEST(unix_noinherit_socket_absent_in_child_with_inherit_all)
{
    TRIO_OR_SKIP("xcx6.sock", OVLD | NOINH);
    {
        char a[64]; STARTUPINFOA si; PROCESS_INFORMATION pi; char cmd[1024]; DWORD code = 0xDEAD0000;
        memset(&si, 0, sizeof si); si.cb = sizeof si;
        snprintf(cmd, sizeof cmd, "\"%s\" --child u_absent %llu", t_self_path(), xc_u(c));
        if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) { CloseHandle(pi.hThread); code = xc_wait(pi.hProcess, XC_CHILD_TIMEOUT); }
        XEQ(code, 0);
    }
    xc_close(l); xc_close(c); xc_close(s);
}

/* ---- closing ---- */
CHILD(u_hold)
{
    SOCKET s = xc_arg_sock(argv, 1);
    xc_child_up();
    xc_send(s, "R", 1);
    return 0;
}
TEST(unix_child_exit_after_parent_close_resets_stream)
{
    TRIO_OR_SKIP("xcx7.sock", OVLD);
    {
        char a[64], b; HANDLE h[1], p;
        h[0] = H(c);
        p = xc_spawn("u_hold", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
        CHECK(p != NULL);
        xc_close(c);
        XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
        XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
        xc_setwerr(0);
        XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);       /* a handle released by process exit resets the stream */
        XEQ(xc_werr(), WSAECONNRESET);
    }
    xc_close(l); xc_close(s);
}
TEST(unix_parent_close_while_child_alive_keeps_stream)
{
    TRIO_OR_SKIP("xcx8.sock", OVLD);
    {
        char a[64], b; HANDLE h[1], p;
        h[0] = H(c);
        p = xc_spawn("u_wait_go", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
        CHECK(p != NULL);
        XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
        xc_close(c);
        CHECK(!xc_readable(s, 200));
        XEQ(xc_send(s, "G", 1), 1);
        XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'X');
        XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
        xc_setwerr(0);
        XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);       /* a handle released by process exit resets the stream */
        XEQ(xc_werr(), WSAECONNRESET);
    }
    xc_close(l); xc_close(s);
}
CHILD(u_wait_go)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; char g = 0;
    xc_child_up(); xc_rcvtimeo(s, XC_WAIT);
    STEP(0, xc_send(s, "R", 1) == 1);
    STEP(1, U(recv)(s, &g, 1, 0) == 1 && g == 'G');
    STEP(2, xc_send(s, "X", 1) == 1);
    return (int)fails;
}
TEST(unix_child_exit_with_unread_data_resets_stream)
{
    TRIO_OR_SKIP("xcx9.sock", OVLD);
    {
        char a[64], b; HANDLE h[1], p; int r;
        h[0] = H(c);
        p = xc_spawn("u_unread", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
        CHECK(p != NULL);
        xc_close(c);
        XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
        XEQ(xc_send(s, "u", 1), 1);
        XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
        xc_setwerr(0);
        r = U(recv)(s, &b, 1, 0);
        XEQ(r, SOCKET_ERROR); XEQ(xc_werr(), WSAECONNRESET);
    }
    xc_close(l); xc_close(s);
}
CHILD(u_unread)
{
    SOCKET s = xc_arg_sock(argv, 1);
    xc_child_up();
    xc_send(s, "R", 1);
    xc_readable(s, XC_WAIT);
    return 0;
}

/* ---- state set by a child ---- */
CHILD(u_bind_listen)
{
    SOCKET s = xc_arg_sock(argv, 1); SOCKADDR_UN a; xu_addr(&a, argv[2]);
    xc_child_up();
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return (int)xc_e8(xc_werr());
    if (U(listen)(s, 2)) return (int)xc_e8(xc_werr()) + 100;
    return 0;
}
TEST(unix_bind_and_listen_in_child_parent_view_unchanged)
{
    SOCKET x, c2; char a[96]; HANDLE h[1]; SOCKADDR_UN n, want; int nl = sizeof n, i = 0, il = sizeof i;
    XU(); x = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
    h[0] = H(x);
    XEQ(xc_run("u_bind_listen", XARGS(a, "%llu xcxa.sock", xc_u(x)), h, 1), 0);
    memset(&n, 0, sizeof n);
    xu_addr(&want, "xcxa.sock");
    xc_setwerr(0);
    XEQ(U(getsockname)(x, (struct sockaddr *)&n, &nl), SOCKET_ERROR);
    XEQ(xc_werr(), WSAEINVAL);
    XEQ(U(getsockopt)(x, SOL_SOCKET, SO_ACCEPTCONN, (char *)&i, &il), 0);
    XEQ(i, 0);
    c2 = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, OVLD);
    xc_setwerr(0);
    XEQ(U(connect)(c2, (struct sockaddr *)&want, sizeof want), SOCKET_ERROR);   /* a path-based listener needs the binder's own context */
    XEQ(xc_werr(), WSAECONNREFUSED);
    xc_close(c2); xc_close(x);
}
