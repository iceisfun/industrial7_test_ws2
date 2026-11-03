/* socket_create: the dwFlags argument of WSASocket and the per-thread SO_OPENTYPE default that socket() uses.
 *
 * What a flag decides is visible on the kernel object behind the socket handle:
 *  - overlapped sockets are opened asynchronous (FileModeInformation == 0); without WSA_FLAG_OVERLAPPED the
 *    endpoint is opened FILE_SYNCHRONOUS_IO_NONALERT (0x20) and cannot be attached to a completion port;
 *  - handles are inheritable unless WSA_FLAG_NO_HANDLE_INHERIT is given (REGISTERED_IO sockets are not either);
 *  - unknown bits are refused; the error depends on the socket: stream sockets created with protocol 0 report
 *    WSAEPROTOTYPE (10041), datagram sockets and explicit-protocol requests report WSAEINVAL (10022), AF_UNIX
 *    reports WSAEINVAL;
 *  - multipoint flags: stream sockets refuse all of them (10041); datagram sockets accept the two leaf flags and
 *    refuse the two root flags (10022).
 * socket() is WSASocketW with WSA_FLAG_OVERLAPPED unless the calling thread's SO_OPENTYPE is non-zero. */
#include "sc.h"

static LONG nt_mode(SOCKET s, ULONG *mode) {
    sc_NtQueryInformationFile_t q = (sc_NtQueryInformationFile_t)t_proc_in("ntdll.dll", "NtQueryInformationFile");
    ULONG_PTR iosb[2] = {0, 0};
    *mode = 0xffffffff;
    if (!q) return (LONG)0xC0000002;
    return q((HANDLE)s, iosb, mode, sizeof *mode, 16 /* FileModeInformation */);
}
static int is_inheritable(SOCKET s) {
    DWORD f = 0;
    CHECK(GetHandleInformation((HANDLE)s, &f));
    return (f & HANDLE_FLAG_INHERIT) != 0;
}
static int set_opentype(int v) { return sc_sso(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, &v, sizeof v); }

/* ---- table: accepted flag combinations ---- */
struct fl_row { DWORD flags; int sync_mode; int inherit; };
static const struct fl_row ok_flags[] = {
    {0,                                              1, 1},
    {WSA_FLAG_OVERLAPPED,                            0, 1},
    {WSA_FLAG_NO_HANDLE_INHERIT,                     1, 0},
    {WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT, 0, 0},
};
static void ok_flags_for(int af, int ty) {
    unsigned i;
    for (i = 0; i < sizeof ok_flags / sizeof *ok_flags; i++) {
        SOCKET s;
        ULONG mode;
        sc_seterr(0);
        s = sc_make(af, ty, 0, ok_flags[i].flags);
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "creation", "af=%d flags=%#lx error %d", af, ok_flags[i].flags, sc_err());
        if (s == INVALID_SOCKET) continue;
        t_check(nt_mode(s, &mode) == 0, __FILE__, __LINE__, "FileModeInformation", NULL);
        t_check(mode == (ok_flags[i].sync_mode ? FILE_SYNCHRONOUS_IO_NONALERT : 0), __FILE__, __LINE__, "mode",
                "af=%d flags=%#lx mode %#lx", af, ok_flags[i].flags, mode);
        t_check(is_inheritable(s) == ok_flags[i].inherit, __FILE__, __LINE__, "inherit", "af=%d flags=%#lx", af, ok_flags[i].flags);
        sc_close(s);
    }
}
TEST(sockcreate_flags_accepted_tcp4)   { SC_UP(); ok_flags_for(AF_INET, SOCK_STREAM); }
TEST(sockcreate_flags_accepted_udp4)   { SC_UP(); ok_flags_for(AF_INET, SOCK_DGRAM); }
TEST(sockcreate_flags_accepted_tcp6)   { SC_UP(); ok_flags_for(AF_INET6, SOCK_STREAM); }
TEST(sockcreate_flags_accepted_udp6)   { SC_UP(); ok_flags_for(AF_INET6, SOCK_DGRAM); }
TEST(sockcreate_flags_accepted_unix)   { SC_UP(); ok_flags_for(AF_UNIX, SOCK_STREAM); }

/* ---- no flags: synchronous, inheritable ---- */
TEST(sockcreate_flags_zero_is_synchronous_nonalert) {
    SOCKET s; ULONG mode;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 0);
    CHECK(s != INVALID_SOCKET);
    SC_EQ(nt_mode(s, &mode), 0);
    SC_EQ(mode, FILE_SYNCHRONOUS_IO_NONALERT);
    sc_close(s);
}
TEST(sockcreate_flags_overlapped_is_asynchronous) {
    SOCKET s; ULONG mode;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    SC_EQ(nt_mode(s, &mode), 0);
    SC_EQ(mode, 0);
    sc_close(s);
}

/* ---- REGISTERED_IO: always asynchronous and never inheritable ---- */
TEST(sockcreate_flags_registered_io_forces_async_and_noinherit) {
    static const DWORD fl[] = {WSA_FLAG_REGISTERED_IO, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED,
                               WSA_FLAG_REGISTERED_IO | WSA_FLAG_NO_HANDLE_INHERIT,
                               WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof fl / sizeof *fl; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_STREAM, 0, fl[i]);
        ULONG mode;
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "creation", "flags=%#lx error %d", fl[i], sc_err());
        if (s == INVALID_SOCKET) continue;
        t_check(nt_mode(s, &mode) == 0 && mode == 0, __FILE__, __LINE__, "async", "flags=%#lx mode %#lx", fl[i], mode);
        t_check(!is_inheritable(s), __FILE__, __LINE__, "not inheritable", "flags=%#lx", fl[i]);
        sc_close(s);
    }
}
TEST(sockcreate_flags_registered_io_works_for_dgram_and_v6) {
    SOCKET a, b;
    SC_UP();
    a = sc_make(AF_INET, SOCK_DGRAM, 0, WSA_FLAG_REGISTERED_IO);
    b = sc_make(AF_INET6, SOCK_STREAM, 0, WSA_FLAG_REGISTERED_IO);
    CHECK(a != INVALID_SOCKET);
    CHECK(b != INVALID_SOCKET);
    SC_EQ(sc_sotype(a), SOCK_DGRAM);
    SC_EQ(sc_sotype(b), SOCK_STREAM);
    sc_close(a); sc_close(b);
}
TEST(sockcreate_flags_registered_io_refused_for_unix) {
    SC_UP();
    sc_seterr(0);
    CHECK(sc_make(AF_UNIX, SOCK_STREAM, 0, WSA_FLAG_REGISTERED_IO) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEINVAL);
    sc_seterr(0);
    CHECK(sc_make(AF_UNIX, SOCK_STREAM, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEINVAL);
}

/* ---- refused flag bits ---- */
static const DWORD refused_bits[] = {0x200, 0x400, 0x800, 0x1000, 0x2000, 0x10000, 0x100000, 0x1000000,
                                     0x40000000, 0x80000000u, 0xffffffffu, 0xfffffffeu, 0x83, 0x103};
static const DWORD multipoint_bits[] = {2, 4, 8, 0x10, 0x3, 0x5, 0x9, 0x11};
static void refused_for(int af, int ty, int err, const DWORD *fl, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++) {
        SOCKET s;
        sc_seterr(0);
        s = sc_make(af, ty, 0, fl[i]);
        t_check(s == INVALID_SOCKET, __FILE__, __LINE__, "refused", "af=%d flags=%#lx", af, fl[i]);
        t_check(sc_err() == err, __FILE__, __LINE__, "error", "af=%d flags=%#lx got %d want %d", af, fl[i], sc_err(), err);
        sc_close(s);
    }
}
#define NBITS(a) (unsigned)(sizeof(a) / sizeof((a)[0]))
TEST(sockcreate_flags_refused_bits_tcp4)  { SC_UP(); refused_for(AF_INET, SOCK_STREAM, WSAEPROTOTYPE, refused_bits, NBITS(refused_bits)); }
TEST(sockcreate_flags_refused_bits_tcp6)  { SC_UP(); refused_for(AF_INET6, SOCK_STREAM, WSAEPROTOTYPE, refused_bits, NBITS(refused_bits)); }
TEST(sockcreate_flags_refused_bits_udp4)  { SC_UP(); refused_for(AF_INET, SOCK_DGRAM, WSAEINVAL, refused_bits, NBITS(refused_bits)); }
TEST(sockcreate_flags_refused_bits_udp6)  { SC_UP(); refused_for(AF_INET6, SOCK_DGRAM, WSAEINVAL, refused_bits, NBITS(refused_bits)); }
TEST(sockcreate_flags_refused_bits_unix)  { SC_UP(); refused_for(AF_UNIX, SOCK_STREAM, WSAEINVAL, refused_bits, NBITS(refused_bits)); }
TEST(sockcreate_flags_multipoint_refused_by_stream_sockets) {
    SC_UP();
    refused_for(AF_INET, SOCK_STREAM, WSAEPROTOTYPE, multipoint_bits, NBITS(multipoint_bits));
    refused_for(AF_INET6, SOCK_STREAM, WSAEPROTOTYPE, multipoint_bits, NBITS(multipoint_bits));
}
TEST(sockcreate_flags_multipoint_refused_by_unix) {
    SC_UP();
    refused_for(AF_UNIX, SOCK_STREAM, WSAEINVAL, multipoint_bits, NBITS(multipoint_bits));
}
TEST(sockcreate_flags_multipoint_root_refused_by_datagram) {
    static const DWORD roots[] = {WSA_FLAG_MULTIPOINT_C_ROOT, WSA_FLAG_MULTIPOINT_D_ROOT, 3, 9, 0x83};
    SC_UP();
    refused_for(AF_INET, SOCK_DGRAM, WSAEINVAL, roots, NBITS(roots));
    refused_for(AF_INET6, SOCK_DGRAM, WSAEINVAL, roots, NBITS(roots));
}
TEST(sockcreate_flags_multipoint_leaf_accepted_by_datagram) {
    static const DWORD leaves[] = {WSA_FLAG_MULTIPOINT_C_LEAF, WSA_FLAG_MULTIPOINT_D_LEAF, WSA_FLAG_MULTIPOINT_C_LEAF | WSA_FLAG_OVERLAPPED,
                                   WSA_FLAG_MULTIPOINT_C_LEAF | WSA_FLAG_MULTIPOINT_D_LEAF};
    unsigned i;
    SC_UP();
    for (i = 0; i < NBITS(leaves); i++) {
        SOCKET s = sc_make(AF_INET, SOCK_DGRAM, 0, leaves[i]);
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "leaf datagram socket", "flags %#lx error %d", leaves[i], sc_err());
        if (s != INVALID_SOCKET) SC_EQ(sc_sotype(s), SOCK_DGRAM);
        sc_close(s);
    }
}
/* with an explicit protocol the unknown-bit refusal is WSAEINVAL even for streams */
TEST(sockcreate_flags_refused_with_explicit_protocol_is_einval) {
    SC_UP();
    sc_seterr(0); CHECK(sc_make(AF_INET, 0, IPPROTO_TCP, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEINVAL);
    sc_seterr(0); CHECK(sc_make(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEINVAL);
    sc_seterr(0); CHECK(sc_make(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEINVAL);
    sc_seterr(0); CHECK(sc_make(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEINVAL);
    sc_seterr(0); CHECK(sc_make(AF_INET6, SOCK_STREAM, IPPROTO_TCP, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEINVAL);
}
/* with protocol 0 (or IPPROTO_IP) a stream request reports WSAEPROTOTYPE */
TEST(sockcreate_flags_refused_with_zero_protocol_is_eprototype) {
    SC_UP();
    sc_seterr(0); CHECK(sc_make(AF_INET, SOCK_STREAM, IPPROTO_IP, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEPROTOTYPE);
    sc_seterr(0); CHECK(sc_make(AF_INET, 0, 0, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEPROTOTYPE);
}
/* a request that fails in the catalog stage reports that error, never the flag error */
TEST(sockcreate_flags_catalog_error_precedes_flag_error) {
    SC_UP();
    sc_seterr(0); CHECK(sc_make(AF_INET, SOCK_SEQPACKET, 0, 0x200) == INVALID_SOCKET); SC_EQ(sc_err(), WSAESOCKTNOSUPPORT);
    sc_seterr(0); CHECK(sc_make(SC_BAD, SOCK_STREAM, 0, 0xffffffffu) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEAFNOSUPPORT);
    sc_seterr(0); CHECK(sc_make(AF_INET, SOCK_STREAM, SC_BAD, 0x10) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEPROTONOSUPPORT);
    sc_seterr(0); CHECK(sc_make(AF_UNSPEC, 0, 0, 0x10) == INVALID_SOCKET); SC_EQ(sc_err(), WSAEINVAL);
}
TEST(sockcreate_flags_access_system_security_is_recorded) {
    SOCKET s;
    SC_UP();
    sc_seterr(0);
    s = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_ACCESS_SYSTEM_SECURITY);     /* needs SeSecurityPrivilege in the token */
    t_note("access-system-security create -> %s error %d", s == INVALID_SOCKET ? "failed" : "ok", s == INVALID_SOCKET ? sc_err() : 0);
    sc_close(s);
}

/* ---- the A entry point takes the same flags ---- */
TEST(sockcreate_flags_wsasocketa_honours_flags) {
    static const DWORD fl[] = {0, WSA_FLAG_OVERLAPPED, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = U(WSASocketA)(AF_INET, SOCK_STREAM, 0, NULL, 0, fl[i]);
        ULONG mode;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        CHECK(nt_mode(s, &mode) == 0);
        SC_EQ(mode, (fl[i] & WSA_FLAG_OVERLAPPED) ? 0 : FILE_SYNCHRONOUS_IO_NONALERT);
        SC_EQ(is_inheritable(s), (fl[i] & WSA_FLAG_NO_HANDLE_INHERIT) ? 0 : 1);
        sc_close(s);
    }
    sc_seterr(0);
    CHECK(U(WSASocketA)(AF_INET, SOCK_STREAM, 0, NULL, 0, 0x200) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEPROTOTYPE);
}

/* ---- socket() and SO_OPENTYPE ---- */
TEST(sockcreate_flags_socket_is_overlapped_by_default) {
    SOCKET s; ULONG mode;
    SC_UP();
    set_opentype(0);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    SC_EQ(nt_mode(s, &mode), 0);
    SC_EQ(mode, 0);
    CHECK(is_inheritable(s));
    sc_close(s);
}
TEST(sockcreate_flags_opentype_makes_socket_synchronous) {
    static const int vals[] = {SO_SYNCHRONOUS_NONALERT, SO_SYNCHRONOUS_ALERT, 1, 0x30, 0x7fffffff, -1};
    unsigned i;
    SC_UP();
    for (i = 0; i < sizeof vals / sizeof *vals; i++) {
        SOCKET s; ULONG mode;
        SC_EQ(set_opentype(vals[i]), 0);
        s = U(socket)(AF_INET, SOCK_DGRAM, 0);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(nt_mode(s, &mode), 0);
        t_check(mode == FILE_SYNCHRONOUS_IO_NONALERT, __FILE__, __LINE__, "synchronous", "opentype=%#x mode %#lx", vals[i], mode);
        sc_close(s);
    }
    set_opentype(0);
}
TEST(sockcreate_flags_opentype_zero_restores_overlapped) {
    SOCKET s; ULONG mode;
    SC_UP();
    set_opentype(SO_SYNCHRONOUS_NONALERT);
    set_opentype(0);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    SC_EQ(nt_mode(s, &mode), 0);
    SC_EQ(mode, 0);
    sc_close(s);
}
/* an explicit dwFlags always wins over the thread default, in both directions */
TEST(sockcreate_flags_explicit_flags_override_opentype) {
    SOCKET s; ULONG mode;
    SC_UP();
    set_opentype(SO_SYNCHRONOUS_NONALERT);
    s = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    SC_EQ(nt_mode(s, &mode), 0);
    SC_EQ(mode, 0);
    sc_close(s);
    set_opentype(0);
    s = sc_make(AF_INET, SOCK_STREAM, 0, 0);
    CHECK(s != INVALID_SOCKET);
    SC_EQ(nt_mode(s, &mode), 0);
    SC_EQ(mode, FILE_SYNCHRONOUS_IO_NONALERT);
    sc_close(s);
}
TEST(sockcreate_flags_creating_socket_leaves_opentype_untouched) {
    int v = -1, n = sizeof v;
    SOCKET s;
    SC_UP();
    set_opentype(SO_SYNCHRONOUS_ALERT);
    s = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_OVERLAPPED);
    sc_close(s);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    sc_close(s);
    CHECK(sc_gso(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, &v, &n) == 0);
    SC_EQ(v, SO_SYNCHRONOUS_ALERT);
    set_opentype(0);
}
TEST(sockcreate_flags_opentype_applies_to_unix_and_v6) {
    SOCKET a, b; ULONG ma, mb;
    SC_UP();
    set_opentype(SO_SYNCHRONOUS_NONALERT);
    a = U(socket)(AF_INET6, SOCK_STREAM, 0);
    b = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET);
    SC_EQ(nt_mode(a, &ma), 0);
    SC_EQ(nt_mode(b, &mb), 0);
    SC_EQ(ma, FILE_SYNCHRONOUS_IO_NONALERT);
    SC_EQ(mb, FILE_SYNCHRONOUS_IO_NONALERT);
    sc_close(a); sc_close(b);
    set_opentype(0);
}
static DWORD WINAPI opentype_thread(LPVOID p) {
    ULONG mode = 0xff;
    SOCKET s;
    int v = 55, n = sizeof v;
    if (!sc_up()) return 100;
    if (sc_gso(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, &v, &n) || v != 0) return 101;       /* a new thread starts at 0 */
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 102;
    if (nt_mode(s, &mode) || mode != 0) { sc_close(s); return 103; }
    sc_close(s);
    return 0;
}
TEST(sockcreate_flags_opentype_is_per_thread) {
    HANDLE th; DWORD rc = 99;
    SC_UP();
    set_opentype(SO_SYNCHRONOUS_NONALERT);
    th = CreateThread(NULL, 0, opentype_thread, NULL, 0, NULL);
    CHECK(th != NULL);
    if (th) { CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0); GetExitCodeThread(th, &rc); CloseHandle(th); }
    SC_EQ(rc, 0);
    set_opentype(0);
}

/* ---- completion port association follows the mode ---- */
TEST(sockcreate_flags_synchronous_socket_cannot_join_completion_port) {
    SOCKET s; HANDLE port;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 0);
    CHECK(s != INVALID_SOCKET);
    SetLastError(0);
    port = CreateIoCompletionPort((HANDLE)s, NULL, 1, 0);
    CHECK(port == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (port) CloseHandle(port);
    sc_close(s);
}
TEST(sockcreate_flags_overlapped_socket_joins_completion_port) {
    static const DWORD fl[] = {WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_REGISTERED_IO};
    unsigned i;
    SC_UP();
    for (i = 0; i < 3; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_DGRAM, 0, fl[i]);
        HANDLE port;
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        port = CreateIoCompletionPort((HANDLE)s, NULL, 1, 0);
        t_check(port != NULL, __FILE__, __LINE__, "association", "flags=%#lx GLE %lu", fl[i], GetLastError());
        if (port) CloseHandle(port);
        sc_close(s);
    }
}
TEST(sockcreate_flags_socket_default_joins_completion_port) {
    SOCKET s; HANDLE port;
    SC_UP();
    set_opentype(0);
    s = U(socket)(AF_INET6, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    port = CreateIoCompletionPort((HANDLE)s, NULL, 1, 0);
    CHECK(port != NULL);
    if (port) CloseHandle(port);
    sc_close(s);
}
TEST(sockcreate_flags_opentype_socket_cannot_join_completion_port) {
    SOCKET s; HANDLE port;
    SC_UP();
    set_opentype(SO_SYNCHRONOUS_NONALERT);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    set_opentype(0);
    CHECK(s != INVALID_SOCKET);
    SetLastError(0);
    port = CreateIoCompletionPort((HANDLE)s, NULL, 1, 0);
    CHECK(port == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (port) CloseHandle(port);
    sc_close(s);
}

/* ---- handle inheritance across CreateProcess ---- */
CHILD(sockcreate_probe_inherited) {
    WSADATA d;
    SOCKET s;
    int t;
    if (argc < 2) return 9;
    U(WSAStartup)(MAKEWORD(2, 2), &d);
    s = (SOCKET)(ULONG_PTR)strtoull(argv[1], NULL, 10);
    t = sc_sotype(s);
    if (t == SOCK_STREAM || t == SOCK_DGRAM) return 0;
    return sc_err() == WSAENOTSOCK ? 2 : 3;
}
static DWORD run_inherit_child(SOCKET s, BOOL inherit) {
    char arg[40];
    PROCESS_INFORMATION pi;
    HANDLE h;
    DWORD code = 0xDEAD0000;
    snprintf(arg, sizeof arg, "%llu", (unsigned long long)s);
    h = t_spawn_child("sockcreate_probe_inherited", arg, 0, NULL, NULL, NULL, inherit, NULL, &pi);
    if (!h) return 0xDEAD0000;
    if (WaitForSingleObject(h, 20000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); code = 0xDEAD0001; }
    else GetExitCodeProcess(h, &code);
    CloseHandle(pi.hThread); CloseHandle(h);
    return code;
}
TEST(sockcreate_flags_inheritable_socket_reaches_child) {
    static const DWORD fl[] = {0, WSA_FLAG_OVERLAPPED};
    unsigned i;
    SC_UP();
    for (i = 0; i < 2; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_STREAM, 0, fl[i]);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(run_inherit_child(s, TRUE), 0);            /* the same handle value names the same socket in the child */
        SC_EQ(run_inherit_child(s, FALSE), 2);           /* without bInheritHandles it is not a socket there */
        sc_close(s);
    }
}
TEST(sockcreate_flags_noinherit_socket_stays_home) {
    static const DWORD fl[] = {WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED, WSA_FLAG_REGISTERED_IO};
    unsigned i;
    SC_UP();
    for (i = 0; i < 3; i++) {
        SOCKET s = sc_make(AF_INET, SOCK_STREAM, 0, fl[i]);
        CHECK(s != INVALID_SOCKET);
        SC_EQ(run_inherit_child(s, TRUE), 2);
        sc_close(s);
    }
}
TEST(sockcreate_flags_inherit_bit_is_switchable_after_creation) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    CHECK(is_inheritable(s));
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0));
    CHECK(!is_inheritable(s));
    SC_EQ(run_inherit_child(s, TRUE), 2);
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    CHECK(is_inheritable(s));
    SC_EQ(run_inherit_child(s, TRUE), 0);
    sc_close(s);
}
TEST(sockcreate_flags_noinherit_socket_can_be_made_inheritable) {
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    CHECK(!is_inheritable(s));
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    SC_EQ(run_inherit_child(s, TRUE), 0);
    sc_close(s);
}

/* ---- the same flags never change what the socket reports about itself ---- */
TEST(sockcreate_flags_do_not_change_protocol_info) {
    static const DWORD fl[] = {0, 1, 0x80, 0x81, 0x100};
    WSAPROTOCOL_INFOW base, cur;
    unsigned i;
    SOCKET s;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    CHECK(sc_getinfo(s, &base) == 0);
    sc_close(s);
    for (i = 0; i < sizeof fl / sizeof *fl; i++) {
        s = sc_make(AF_INET, SOCK_DGRAM, 0, fl[i]);
        CHECK(s != INVALID_SOCKET);
        CHECK(sc_getinfo(s, &cur) == 0);
        t_check(!memcmp(&base, &cur, sizeof base), __FILE__, __LINE__, "info identical", "flags=%#lx", fl[i]);
        sc_close(s);
    }
}

/* ---- a pending overlapped receive is cancelled by closesocket ---- */
static SOCKET bound_udp(DWORD fl) {
    struct sockaddr_in a;
    SOCKET s = sc_make(AF_INET, SOCK_DGRAM, 0, fl);
    if (s == INVALID_SOCKET) return s;
    sc_loop4(&a);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) { sc_close(s); return INVALID_SOCKET; }
    return s;
}
TEST(sockcreate_flags_overlapped_recv_pending_then_cancelled_by_close) {
    SOCKET s;
    char buf[16];
    WSABUF wb = {sizeof buf, buf};
    DWORD got = 0, fl = 0;
    WSAOVERLAPPED ov;
    int r;
    SC_UP();
    s = bound_udp(WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    r = U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL);
    CHECK(r == SOCKET_ERROR);
    SC_EQ(sc_err(), WSA_IO_PENDING);
    CHECK(U(closesocket)(s) == 0);
    SC_EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
    SC_EQ(ov.Internal, 0xC0000120);                 /* STATUS_CANCELLED */
    CloseHandle(ov.hEvent);
}
TEST(sockcreate_flags_overlapped_recv_cancelled_result_after_close) {
    SOCKET s;
    char buf[8];
    WSABUF wb = {sizeof buf, buf};
    DWORD got = 77, fl = 0;
    WSAOVERLAPPED ov;
    SC_UP();
    s = bound_udp(WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSA_IO_PENDING);
    sc_close(s);
    CHECK(WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
    SC_EQ(ov.InternalHigh, 0);                      /* nothing was transferred */
    CloseHandle(ov.hEvent);
}
