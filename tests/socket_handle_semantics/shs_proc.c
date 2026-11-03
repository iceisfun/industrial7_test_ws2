/* socket_handle_semantics / proc: sockets crossing process boundaries. Inheritance through CreateProcess
 * (handle value passed on the command line), standard-handle redirection to a socket, WSADuplicateSocketA/W
 * followed by WSASocket(FROM_PROTOCOL_INFO) in the target (also after the source closed), and handles pushed
 * into a child with DuplicateHandle. Children report through their exit code: 0 means every step held, otherwise
 * a bitmask of the failed steps. */
#include "sh.h"

static void child_start(void)
{
    WSADATA d;
    U(WSAStartup)(MAKEWORD(2, 2), &d);
}
static SOCKET arg_socket(char **argv, int i) { return (SOCKET)(ULONG_PTR)_strtoui64(argv[i], NULL, 10); }
#define STEP(bit, cond) do { if (!(cond)) fails |= (1u << (bit)); } while (0)

/* Sockets in tests that spawn children with bInheritHandles must not leak into them. */
static void noinh2(SOCKET a, SOCKET b)
{
    SetHandleInformation((HANDLE)a, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation((HANDLE)b, HANDLE_FLAG_INHERIT, 0);
}

static DWORD run_child(const char *name, const char *args, BOOL inherit, HANDLE hin, HANDLE hout, SOCKET peer, int (*peer_script)(SOCKET), DWORD timeout)
{
    PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xDEAD0000;
    h = t_spawn_child(name, args, 0, hin, hout, NULL, inherit, NULL, &pi);
    if (!h) return 0xDEAD0000;
    if (peer_script) peer_script(peer);
    if (WaitForSingleObject(h, timeout) != WAIT_OBJECT_0) { TerminateProcess(h, 1); WaitForSingleObject(h, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(h, &code);
    CloseHandle(pi.hThread); CloseHandle(h);
    return code;
}

/* ---------------- inheritance through CreateProcess ---------------- */

/* Child uses an inherited socket: handle properties, send, receive, option query, close. */
CHILD(inherit_user)
{
    SOCKET s = arg_socket(argv, 1); unsigned fails = 0; DWORD f = 0xdead, n = 0; char b[8] = {0}; int ty = 0, tl = sizeof ty;
    child_start();
    STEP(0, GetHandleInformation((HANDLE)s, &f) && f == HANDLE_FLAG_INHERIT);
    STEP(1, GetFileType((HANDLE)s) == FILE_TYPE_PIPE);
    STEP(2, sh_send(s, "kid", 3) == 3);
    STEP(3, sh_recv_all(s, b, 3) == 3 && !memcmp(b, "par", 3));
    STEP(4, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl) == 0 && ty == SOCK_STREAM);
    /* ReadFile/WriteFile obey the same overlapped rule in the child */
    if (argc > 2 && !strcmp(argv[2], "sync")) STEP(5, sh_wf((HANDLE)s, "x", 1, &n, NULL) && n == 1);
    else STEP(5, !sh_wf((HANDLE)s, "x", 1, &n, NULL) && GetLastError() == ERROR_INVALID_PARAMETER);
    STEP(6, sh_closes(s) == 0);
    STEP(7, !GetHandleInformation((HANDLE)s, &f));
    return (int)fails;
}
static int script_inherit(SOCKET s)
{
    char b[8] = {0};
    int ok = sh_recv_all(s, b, 3) == 3 && !memcmp(b, "kid", 3);
    sh_send(s, "par", 3);
    return ok;
}
static void run_inherit(int flags, BOOL clear_after, const char *name, DWORD want)
{
    SOCKET c, s; char arg[48]; DWORD code;
    UP(); PAIR(c, s, flags);
    if (clear_after) SetHandleInformation((HANDLE)c, HANDLE_FLAG_INHERIT, 0);
    sprintf(arg, "%llu %s", (unsigned long long)c, (flags == SYNC || (flags & WSA_FLAG_NO_HANDLE_INHERIT && !(flags & OVLD))) ? "sync" : "ovl");
    code = run_child(name, arg, TRUE, NULL, NULL, s, script_inherit, 20000);
    EQ(code, want);
    sh_closes(c); sh_closes(s);
}
TEST(shs_inherit_default_socket_usable_in_child)       { run_inherit(PLAIN, FALSE, "inherit_user", 0); }
TEST(shs_inherit_sync_socket_usable_in_child)          { run_inherit(SYNC, FALSE, "inherit_user", 0); }
TEST(shs_inherit_overlapped_socket_usable_in_child)    { run_inherit(OVLD, FALSE, "inherit_user", 0); }

/* The same handle value is valid in the child (inheritance preserves the value). */
CHILD(inherit_same_value)
{
    SOCKET s = arg_socket(argv, 1); unsigned fails = 0; int rc, ty = 0, tl = sizeof ty;
    child_start();
    STEP(0, GetFileType((HANDLE)s) == FILE_TYPE_PIPE);
    rc = U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl);
    STEP(1, rc == 0 && ty == SOCK_DGRAM);
    return (int)fails;
}
TEST(shs_inherit_udp_socket_same_value)
{
    SOCKET u; char arg[32]; DWORD code;
    UP(); u = sh_make(SOCK_DGRAM, PLAIN);
    sprintf(arg, "%llu", (unsigned long long)u);
    code = run_child("inherit_same_value", arg, TRUE, NULL, NULL, 0, NULL, 20000);
    EQ(code, 0);
    sh_closes(u);
}

/* Not inherited: bInheritHandles FALSE, WSA_FLAG_NO_HANDLE_INHERIT, or the flag cleared afterwards. */
CHILD(inherit_absent)
{
    SOCKET s = arg_socket(argv, 1); unsigned fails = 0; DWORD f = 0xdead; int rc;
    child_start();
    SET_ERR(0);
    STEP(0, !GetHandleInformation((HANDLE)s, &f) && GetLastError() == ERROR_INVALID_HANDLE);
    STEP(1, GetFileType((HANDLE)s) == FILE_TYPE_UNKNOWN);
    sh_setwerr(0);
    rc = sh_send(s, "x", 1);
    STEP(2, rc == SOCKET_ERROR && sh_werr() == WSAENOTSOCK);
    sh_setwerr(0);
    rc = sh_closes(s);
    STEP(3, rc == SOCKET_ERROR && sh_werr() == WSAENOTSOCK);
    return (int)fails;
}
static int script_none(SOCKET s) { return 0; }
TEST(shs_inherit_noinherit_flag_not_inherited)         { run_inherit(WSA_FLAG_NO_HANDLE_INHERIT, FALSE, "inherit_absent", 0); }
TEST(shs_inherit_noinherit_overlapped_not_inherited)   { run_inherit(OVLD | WSA_FLAG_NO_HANDLE_INHERIT, FALSE, "inherit_absent", 0); }
TEST(shs_inherit_cleared_flag_not_inherited)           { run_inherit(PLAIN, TRUE, "inherit_absent", 0); }
TEST(shs_inherit_bInheritHandles_false)
{
    SOCKET c, s; char arg[32]; DWORD code;
    UP(); PAIR(c, s, PLAIN);
    sprintf(arg, "%llu", (unsigned long long)c);
    code = run_child("inherit_absent", arg, FALSE, NULL, NULL, s, NULL, 20000);
    EQ(code, 0);
    sh_closes(c); sh_closes(s);
}
/* Restoring the flag restores inheritance. */
TEST(shs_inherit_flag_restored_is_inherited)
{
    SOCKET c, s; char arg[32]; DWORD code;
    UP(); PAIR(c, s, WSA_FLAG_NO_HANDLE_INHERIT);
    SetHandleInformation((HANDLE)c, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    sprintf(arg, "%llu sync", (unsigned long long)c);
    code = run_child("inherit_user", arg, TRUE, NULL, NULL, s, script_inherit, 20000);
    EQ(code, 0);
    sh_closes(c); sh_closes(s);
}

/* The child closing its copy does not disturb the parent's: the stream stays open until the last handle goes. */
CHILD(inherit_close_only)
{
    SOCKET s = arg_socket(argv, 1);
    child_start();
    return sh_closes(s) == 0 ? 0 : 1;
}
TEST(shs_inherit_child_close_keeps_stream_alive)
{
    SOCKET c, s; char arg[32], b[4]; DWORD code;
    UP(); PAIR(c, s, PLAIN);
    sprintf(arg, "%llu", (unsigned long long)c);
    code = run_child("inherit_close_only", arg, TRUE, NULL, NULL, 0, NULL, 20000);
    EQ(code, 0);
    EQ(sh_send(c, "ok", 2), 2);
    EQ(sh_recv_all(s, b, 2), 2);
    CHECK(!sh_readable(s, 200));              /* no close notification from the child's exit */
    sh_closes(c);
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}
/* A child that exits without closing releases its copy: the parent closing last ends the stream. */
CHILD(inherit_hold) { child_start(); Sleep(200); return 0; }
TEST(shs_inherit_child_exit_releases_reference)
{
    SOCKET c, s; char arg[32], b[4]; DWORD code;
    UP(); PAIR(c, s, PLAIN);
    sprintf(arg, "%llu", (unsigned long long)c);
    code = run_child("inherit_hold", arg, TRUE, NULL, NULL, 0, NULL, 20000);
    EQ(code, 0);
    sh_closes(c);
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}
/* While the child lives and holds the inherited handle, the parent's close does not end the stream. */
CHILD(inherit_wait_for_byte)
{
    SOCKET s = arg_socket(argv, 1); char b[4] = {0}; unsigned fails = 0;
    child_start();
    STEP(0, sh_recv_all(s, b, 1) == 1 && b[0] == 'G');
    STEP(1, sh_send(s, "R", 1) == 1);
    return (int)fails;
}
static int script_parent_closes_first(SOCKET peer)
{
    char b[4];
    sh_send(peer, "G", 1);
    return sh_recv_all(peer, b, 1) == 1;
}
TEST(shs_inherit_child_keeps_stream_after_parent_close)
{
    SOCKET c, s; char arg[32]; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead; char b[4] = {0};
    UP(); PAIR(c, s, PLAIN);
    sprintf(arg, "%llu", (unsigned long long)c);
    h = t_spawn_child("inherit_wait_for_byte", arg, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    sh_closes(c);                              /* parent drops its handle; the child still holds one */
    CHECK(!sh_readable(s, 300));
    sh_send(s, "G", 1);
    EQ(sh_recv_all(s, b, 1), 1);
    EQ(b[0], 'R');
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(s);
}

/* A child that never calls WSAStartup and uses an inherited handle: recorded. */
CHILD(inherit_no_startup)
{
    SOCKET s = arg_socket(argv, 1); int rc;
    sh_setwerr(0);
    rc = sh_send(s, "x", 1);
    return rc == SOCKET_ERROR ? 100 + (sh_werr() & 0xff) : 0;
}
TEST(shs_inherit_without_wsastartup_in_child)
{
    SOCKET c, s; char arg[32]; DWORD code;
    UP(); PAIR(c, s, PLAIN);
    sprintf(arg, "%llu", (unsigned long long)c);
    code = run_child("inherit_no_startup", arg, TRUE, NULL, NULL, 0, NULL, 20000);
    t_note("send on an inherited socket before WSAStartup in the child: exit %lu (WSANOTINITIALISED low byte is %d)", code, WSANOTINITIALISED & 0xff);
    CHECK(code == 100 + (WSANOTINITIALISED & 0xff));
    sh_closes(c); sh_closes(s);
}

/* ---------------- standard handles redirected to a socket ---------------- */

CHILD(stdout_writer)
{
    DWORD n = 0;
    BOOL r = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "from-child", 10, &n, NULL);
    return r && n == 10 ? 0 : 100 + (int)GetLastError();
}
static void std_out_case(int flags, DWORD want_exit, int want_data)
{
    SOCKET c, s; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead; char b[16] = {0}; int got = 0;
    UP(); PAIR(c, s, flags);
    h = t_spawn_child("stdout_writer", "", 0, NULL, (HANDLE)c, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, want_exit);
    if (sh_readable(s, want_data ? SH_WAIT : 300)) got = sh_recv(s, b, 10);
    if (want_data) { EQ(got, 10); EQ(memcmp(b, "from-child", 10), 0); }
    else CHECK(got <= 0 || !sh_readable(s, 0) == 0);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(c); sh_closes(s);
}
/* A synchronous socket works as a child's standard output; an overlapped one is refused with
 * ERROR_INVALID_PARAMETER by the child's WriteFile (the classic reason redirected sockets must be non-overlapped). */
TEST(shs_stdout_sync_socket_receives_child_output)   { std_out_case(SYNC, 0, 1); }
TEST(shs_stdout_overlapped_socket_write_refused)
{
    SOCKET c, s; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead;
    UP(); PAIR(c, s, PLAIN);
    h = t_spawn_child("stdout_writer", "", 0, NULL, (HANDLE)c, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 100 + ERROR_INVALID_PARAMETER);
    CHECK(!sh_readable(s, 300));
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(c); sh_closes(s);
}

CHILD(stdin_reader)
{
    char b[8] = {0}; DWORD n = 0;
    BOOL r = ReadFile(GetStdHandle(STD_INPUT_HANDLE), b, 5, &n, NULL);
    return r && n == 5 && !memcmp(b, "stdin", 5) ? 0 : 1;
}
TEST(shs_stdin_sync_socket_feeds_child)
{
    SOCKET c, s; PROCESS_INFORMATION pi; HANDLE h; DWORD code = 0xdead;
    UP(); PAIR(c, s, SYNC);
    sh_send(s, "stdin", 5);
    h = t_spawn_child("stdin_reader", "", 0, (HANDLE)c, NULL, NULL, TRUE, NULL, &pi);
    REQUIRE(h);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(c); sh_closes(s);
}

/* ---------------- WSADuplicateSocket -> WSASocket(FROM_PROTOCOL_INFO) in another process ---------------- */

static int read_exact(HANDLE h, void *p, DWORD n)
{
    DWORD got = 0, k;
    while (got < n) { if (!ReadFile(h, (char *)p + got, n - got, &k, NULL) || !k) return 0; got += k; }
    return 1;
}
/* argv[1]: 1 = WSAPROTOCOL_INFOW, 0 = WSAPROTOCOL_INFOA; argv[2]: role (stream, dgram, listen). The info arrives on stdin. */
CHILD(dup_user)
{
    WSAPROTOCOL_INFOW pw; WSAPROTOCOL_INFOA pa; int w = atoi(argv[1]); const char *role = argv[2];
    SOCKET s; unsigned fails = 0; DWORD f = 0xdead; char b[16] = {0};
    child_start();
    if (w) { if (!read_exact(GetStdHandle(STD_INPUT_HANDLE), &pw, sizeof pw)) return 0x8000; }
    else   { if (!read_exact(GetStdHandle(STD_INPUT_HANDLE), &pa, sizeof pa)) return 0x8000; }
    s = w ? U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pw, 0, 0)
          : U(WSASocketA)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pa, 0, 0);
    STEP(0, s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return (int)fails;
    STEP(1, GetFileType((HANDLE)s) == FILE_TYPE_PIPE);
    STEP(2, GetHandleInformation((HANDLE)s, &f));
    if (!strcmp(role, "stream")) {
        STEP(3, sh_recv_all(s, b, 3) == 3 && !memcmp(b, "abc", 3));
        STEP(4, sh_send(s, "kid", 3) == 3);
    } else if (!strcmp(role, "dgram")) {
        struct sockaddr_in from; int fl = sizeof from;
        STEP(3, sh_readable(s, SH_WAIT) && U(recvfrom)(s, b, sizeof b, 0, (struct sockaddr *)&from, &fl) == 4 && !memcmp(b, "dgrm", 4));
    } else if (!strcmp(role, "listen")) {
        SOCKET a = U(accept)(s, NULL, NULL);
        STEP(3, a != INVALID_SOCKET);
        if (a != INVALID_SOCKET) {
            STEP(4, sh_recv_all(a, b, 4) == 4 && !memcmp(b, "conn", 4));
            sh_send(a, "ack", 3);
            sh_closes(a);
        }
    }
    STEP(5, sh_closes(s) == 0);
    return (int)fails;
}
/* Runs a child, ships it the protocol info for `src` over its stdin pipe. */
typedef struct { PROCESS_INFORMATION pi; HANDLE h, wr; WSAPROTOCOL_INFOW w; WSAPROTOCOL_INFOA a; int useW; int rc; int werr; } dupctx;
static int dup_start(dupctx *x, SOCKET src, const char *role, int useW, int close_src_before_send)
{
    HANDLE rd; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; char args[32]; DWORD n;
    x->useW = useW;
    CreatePipe(&rd, &x->wr, &sa, 0);
    SetHandleInformation(x->wr, HANDLE_FLAG_INHERIT, 0);
    sprintf(args, "%d %s", useW, role);
    x->h = t_spawn_child("dup_user", args, 0, rd, NULL, NULL, TRUE, NULL, &x->pi);
    CloseHandle(rd);
    if (!x->h) return 0;
    x->rc = useW ? U(WSADuplicateSocketW)(src, x->pi.dwProcessId, &x->w) : U(WSADuplicateSocketA)(src, x->pi.dwProcessId, &x->a);
    x->werr = x->rc ? sh_werr() : 0;
    if (close_src_before_send) sh_closes(src);
    WriteFile(x->wr, useW ? (void *)&x->w : (void *)&x->a, useW ? sizeof x->w : sizeof x->a, &n, NULL);
    return 1;
}
static DWORD dup_finish(dupctx *x)
{
    DWORD code = 0xDEAD0001;
    if (WaitForSingleObject(x->h, 15000) != WAIT_OBJECT_0) TerminateProcess(x->h, 1);
    else GetExitCodeProcess(x->h, &code);
    CloseHandle(x->h); CloseHandle(x->pi.hThread); CloseHandle(x->wr);
    return code;
}

static void dup_stream_case(int flags, int useW, int close_first)
{
    SOCKET c, s; dupctx x; char b[8] = {0}; DWORD code;
    UP(); PAIR(c, s, flags);
    noinh2(c, s);
    REQUIRE(dup_start(&x, c, "stream", useW, close_first));
    EQ(x.rc, 0);
    sh_send(s, "abc", 3);
    EQ(sh_recv_all(s, b, 3), 3);
    EQ(memcmp(b, "kid", 3), 0);
    code = dup_finish(&x);
    EQ(code, 0);
    if (!close_first) sh_closes(c);
    /* both handles are gone now: the peer sees the orderly close */
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}
TEST(shs_wsadup_w_noinherit_socket)                 { dup_stream_case(WSA_FLAG_NO_HANDLE_INHERIT, 1, 0); }
TEST(shs_wsadup_a_noinherit_socket)                 { dup_stream_case(WSA_FLAG_NO_HANDLE_INHERIT, 0, 0); }
TEST(shs_wsadup_w_overlapped_socket)                { dup_stream_case(OVLD, 1, 0); }
TEST(shs_wsadup_w_sync_socket)                      { dup_stream_case(SYNC, 1, 0); }
TEST(shs_wsadup_w_plain_socket)                     { dup_stream_case(PLAIN, 1, 0); }
TEST(shs_wsadup_a_plain_socket)                     { dup_stream_case(PLAIN, 0, 0); }
/* The parent may close its handle after WSADuplicateSocket: the target already holds its own. */
TEST(shs_wsadup_w_parent_closed_before_use)         { dup_stream_case(WSA_FLAG_NO_HANDLE_INHERIT, 1, 1); }
TEST(shs_wsadup_a_parent_closed_before_use)         { dup_stream_case(WSA_FLAG_NO_HANDLE_INHERIT, 0, 1); }
TEST(shs_wsadup_w_plain_parent_closed_before_use)   { dup_stream_case(PLAIN, 1, 1); }

/* A datagram socket bound before duplication is shared. */
TEST(shs_wsadup_dgram_bound_before_dup_shared)
{
    SOCKET d, tx; dupctx x; struct sockaddr_in a = sh_lo(0); int n = sizeof a; DWORD code;
    UP();
    d = sh_make(SOCK_DGRAM, WSA_FLAG_NO_HANDLE_INHERIT); tx = sh_make(SOCK_DGRAM, PLAIN);
    EQ(U(bind)(d, (struct sockaddr *)&a, sizeof a), 0);
    EQ(U(getsockname)(d, (struct sockaddr *)&a, &n), 0);
    REQUIRE(dup_start(&x, d, "dgram", 1, 0));
    EQ(x.rc, 0);
    Sleep(300);
    EQ(U(sendto)(tx, "dgrm", 4, 0, (struct sockaddr *)&a, n), 4);
    code = dup_finish(&x);
    EQ(code, 0);
    sh_closes(d); sh_closes(tx);
}
/* A listening socket can be accepted on from another process. */
TEST(shs_wsadup_listener_accepts_in_target)
{
    SOCKET l, c; dupctx x; struct sockaddr_in a; char b[8] = {0}; DWORD code;
    UP();
    l = sh_listener(WSA_FLAG_NO_HANDLE_INHERIT, &a);
    REQUIRE(l != INVALID_SOCKET);
    REQUIRE(dup_start(&x, l, "listen", 1, 0));
    EQ(x.rc, 0);
    c = sh_make(SOCK_STREAM, PLAIN);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    sh_send(c, "conn", 4);
    sh_rcvtimeo(c, SH_WAIT);
    EQ(sh_recv_all(c, b, 3), 3);
    EQ(memcmp(b, "ack", 3), 0);
    code = dup_finish(&x);
    EQ(code, 0);
    sh_closes(c); sh_closes(l);
}

/* A/W variants produce equivalent descriptions of the socket. */
TEST(shs_wsadup_info_a_and_w_agree)
{
    SOCKET s; WSAPROTOCOL_INFOA a; WSAPROTOCOL_INFOW w; DWORD pid = GetCurrentProcessId();
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(&a, 0, sizeof a); memset(&w, 0, sizeof w);
    EQ(U(WSADuplicateSocketA)(s, pid, &a), 0);
    EQ(U(WSADuplicateSocketW)(s, pid, &w), 0);
    EQ(a.iAddressFamily, w.iAddressFamily);
    EQ(a.iSocketType, w.iSocketType);
    EQ(a.iProtocol, w.iProtocol);
    EQ(a.dwServiceFlags1, w.dwServiceFlags1);
    EQ(a.dwProviderFlags, w.dwProviderFlags);
    CHECK(!memcmp(&a.ProviderId, &w.ProviderId, sizeof(GUID)));
    EQ(a.iSocketType, SOCK_STREAM);
    sh_closes(s);
}
/* The info is for one target: it is not accepted in place of a protocol request in the source process
 * unless the pid matches the one it was made for. */
TEST(shs_wsadup_to_exited_process_fails)
{
    SOCKET c, s; PROCESS_INFORMATION pi; HANDLE h; WSAPROTOCOL_INFOW w;
    UP(); PAIR(c, s, PLAIN);
    h = t_spawn_child("exit_now", "", 0, NULL, NULL, NULL, FALSE, NULL, &pi);
    REQUIRE(h);
    WaitForSingleObject(h, SH_WAIT);
    sh_setwerr(0);
    /* the process object is still open here, so the pid cannot be recycled */
    EQ(U(WSADuplicateSocketW)(c, pi.dwProcessId, &w), SOCKET_ERROR);
    EQ(sh_werr(), WSAEMFILE);
    CloseHandle(h); CloseHandle(pi.hThread); sh_closes(c); sh_closes(s);
}
CHILD(exit_now) { return 0; }

/* In the target, the second WSASocket from the same info returns the same descriptor, and closing either
 * invalidates the other. */
CHILD(dup_twice)
{
    WSAPROTOCOL_INFOW pw; SOCKET s1, s2; unsigned fails = 0; int rc;
    child_start();
    if (!read_exact(GetStdHandle(STD_INPUT_HANDLE), &pw, sizeof pw)) return 0x8000;
    s1 = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pw, 0, 0);
    s2 = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pw, 0, 0);
    STEP(0, s1 != INVALID_SOCKET && s2 != INVALID_SOCKET);
    STEP(1, s1 == s2);
    STEP(2, sh_closes(s2) == 0);
    sh_setwerr(0);
    rc = sh_send(s1, "x", 1);
    STEP(3, rc == SOCKET_ERROR && sh_werr() == WSAENOTSOCK);
    return (int)fails;
}
TEST(shs_wsadup_same_info_twice_in_target)
{
    SOCKET c, s; HANDLE rd, wr; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; PROCESS_INFORMATION pi; HANDLE h;
    WSAPROTOCOL_INFOW w; DWORD n, code = 0xdead;
    UP(); PAIR(c, s, WSA_FLAG_NO_HANDLE_INHERIT);
    CreatePipe(&rd, &wr, &sa, 0); SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0);
    h = t_spawn_child("dup_twice", "", 0, rd, NULL, NULL, TRUE, NULL, &pi);
    CloseHandle(rd);
    REQUIRE(h);
    EQ(U(WSADuplicateSocketW)(c, pi.dwProcessId, &w), 0);
    WriteFile(wr, &w, sizeof w, &n, NULL);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    CloseHandle(h); CloseHandle(pi.hThread); CloseHandle(wr); sh_closes(c); sh_closes(s);
}

/* ---------------- DuplicateHandle into another process ---------------- */

/* The child reads a decimal handle value from stdin (a value valid in its own table) and uses it. */
CHILD(pushed_user)
{
    char line[32] = {0}; DWORD n = 0; SOCKET s; unsigned fails = 0; char b[8] = {0}; int ty = 0, tl = sizeof ty;
    child_start();
    ReadFile(GetStdHandle(STD_INPUT_HANDLE), line, sizeof line - 1, &n, NULL);
    s = (SOCKET)(ULONG_PTR)_strtoui64(line, NULL, 10);
    STEP(0, GetFileType((HANDLE)s) == FILE_TYPE_PIPE);
    STEP(1, sh_recv_all(s, b, 3) == 3 && !memcmp(b, "abc", 3));
    STEP(2, sh_send(s, "kid", 3) == 3);
    STEP(3, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl) == 0 && ty == SOCK_STREAM);
    STEP(4, sh_closes(s) == 0);
    return (int)fails;
}
static void pushed_case(int flags, int inherit_arg)
{
    SOCKET c, s; HANDLE rd, wr, remote = NULL; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; PROCESS_INFORMATION pi; HANDLE h;
    char line[32], b[8] = {0}; DWORD n, code = 0xdead;
    UP(); PAIR(c, s, flags);
    noinh2(c, s);
    CreatePipe(&rd, &wr, &sa, 0); SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0);
    h = t_spawn_child("pushed_user", "", 0, rd, NULL, NULL, TRUE, NULL, &pi);
    CloseHandle(rd);
    REQUIRE(h);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, h, &remote, 0, inherit_arg, DUPLICATE_SAME_ACCESS));
    sprintf(line, "%llu", (unsigned long long)(ULONG_PTR)remote);
    WriteFile(wr, line, (DWORD)strlen(line), &n, NULL);
    sh_send(s, "abc", 3);
    EQ(sh_recv_all(s, b, 3), 3);
    EQ(memcmp(b, "kid", 3), 0);
    WaitForSingleObject(h, SH_WAIT);
    GetExitCodeProcess(h, &code);
    EQ(code, 0);
    CloseHandle(h); CloseHandle(pi.hThread); CloseHandle(wr);
    sh_closes(c);
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}
TEST(shs_push_duplicate_into_child_plain)          { pushed_case(PLAIN, FALSE); }
TEST(shs_push_duplicate_into_child_sync)           { pushed_case(SYNC, FALSE); }
TEST(shs_push_duplicate_into_child_noinherit)      { pushed_case(WSA_FLAG_NO_HANDLE_INHERIT, FALSE); }
TEST(shs_push_duplicate_into_child_inheritable)    { pushed_case(PLAIN, TRUE); }

/* The child's copy can be pulled back with DUPLICATE_CLOSE_SOURCE: the parent then owns the last reference. */
CHILD(push_hold)
{
    char line[32] = {0}; DWORD n = 0; char b[4];
    child_start();
    ReadFile(GetStdHandle(STD_INPUT_HANDLE), line, sizeof line - 1, &n, NULL);     /* handle value (unused) */
    ReadFile(GetStdHandle(STD_INPUT_HANDLE), b, 1, &n, NULL);                      /* wait for release */
    return 0;
}
TEST(shs_push_pull_back_with_close_source)
{
    SOCKET c, s; HANDLE rd, wr, remote = NULL, back = NULL; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; PROCESS_INFORMATION pi; HANDLE h;
    char b[8] = {0}; DWORD n;
    UP(); PAIR(c, s, PLAIN);
    noinh2(c, s);
    CreatePipe(&rd, &wr, &sa, 0); SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0);
    h = t_spawn_child("push_hold", "", 0, rd, NULL, NULL, TRUE, NULL, &pi);
    CloseHandle(rd);
    REQUIRE(h);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, h, &remote, 0, FALSE, DUPLICATE_SAME_ACCESS));
    sh_closes(c);
    CHECK(!sh_readable(s, 300));                       /* the child's copy keeps the stream open */
    CHECK(DuplicateHandle(h, remote, GetCurrentProcess(), &back, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE));
    CHECK(back != NULL);
    EQ(sh_send((SOCKET)back, "bk", 2), 2);
    EQ(sh_recv_all(s, b, 2), 2);
    CHECK(!sh_readable(s, 200));
    sh_closes((SOCKET)back);
    EQ(sh_recv(s, b, 1), 0);
    WriteFile(wr, "X", 1, &n, NULL);
    WriteFile(wr, "Y", 1, &n, NULL);
    WaitForSingleObject(h, SH_WAIT);
    CloseHandle(h); CloseHandle(pi.hThread); CloseHandle(wr); sh_closes(s);
}
