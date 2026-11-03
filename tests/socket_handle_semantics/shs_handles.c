/* socket_handle_semantics / handles: handle flags (inherit, protect-from-close), WSA_FLAG_NO_HANDLE_INHERIT,
 * DuplicateHandle of a socket inside one process, closesocket versus CloseHandle versus NtClose, handle value
 * behaviour, and the identity of GetLastError and WSAGetLastError. */
#include "sh.h"

/* ---------------- GetHandleInformation: inherit flag per creation path ---------------- */

static DWORD hflags(SOCKET s)
{
    DWORD f = 0xdead;
    if (!GetHandleInformation((HANDLE)s, &f)) return 0xdeadbeef;
    return f;
}

/* Documented: sockets are inheritable unless created with WSA_FLAG_NO_HANDLE_INHERIT. */
static void inherit_flag_for(int type, int flags, DWORD want)
{
    SOCKET s;
    UP();
    s = sh_make(type, flags);
    CHECK(s != INVALID_SOCKET);
    EQ(hflags(s), want);
    sh_closes(s);
}
TEST(shs_hinfo_tcp_plain_inheritable)        { inherit_flag_for(SOCK_STREAM, PLAIN, HANDLE_FLAG_INHERIT); }
TEST(shs_hinfo_tcp_sync_inheritable)         { inherit_flag_for(SOCK_STREAM, SYNC, HANDLE_FLAG_INHERIT); }
TEST(shs_hinfo_tcp_overlapped_inheritable)   { inherit_flag_for(SOCK_STREAM, OVLD, HANDLE_FLAG_INHERIT); }
TEST(shs_hinfo_udp_plain_inheritable)        { inherit_flag_for(SOCK_DGRAM, PLAIN, HANDLE_FLAG_INHERIT); }
TEST(shs_hinfo_tcp_noinherit)                { inherit_flag_for(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT, 0); }
TEST(shs_hinfo_tcp_noinherit_overlapped)     { inherit_flag_for(SOCK_STREAM, OVLD | WSA_FLAG_NO_HANDLE_INHERIT, 0); }
TEST(shs_hinfo_udp_noinherit)                { inherit_flag_for(SOCK_DGRAM, WSA_FLAG_NO_HANDLE_INHERIT, 0); }

/* An accepted socket takes the inherit property of its listener. */
static void accepted_flag(int flags, DWORD want)
{
    SOCKET c, s;
    UP(); PAIR(c, s, flags);
    EQ(hflags(c), want);
    EQ(hflags(s), want);
    sh_closes(c); sh_closes(s);
}
TEST(shs_hinfo_accepted_follows_listener_default)   { accepted_flag(PLAIN, HANDLE_FLAG_INHERIT); }
TEST(shs_hinfo_accepted_follows_listener_noinherit) { accepted_flag(WSA_FLAG_NO_HANDLE_INHERIT, 0); }
TEST(shs_hinfo_accepted_follows_listener_noinherit_ovl) { accepted_flag(OVLD | WSA_FLAG_NO_HANDLE_INHERIT, 0); }

/* A mixed pair: an inheritable listener hands out inheritable sockets regardless of the client's flags. */
TEST(shs_hinfo_accepted_independent_of_client)
{
    struct sockaddr_in a; SOCKET l, c, s;
    UP();
    l = sh_listener(PLAIN, &a);
    c = sh_make(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT);
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    s = U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    EQ(hflags(c), 0);
    EQ(hflags(s), HANDLE_FLAG_INHERIT);
    sh_closes(c); sh_closes(s); sh_closes(l);
}

/* ---------------- SetHandleInformation ---------------- */

TEST(shs_hinfo_clear_and_set_inherit)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0));
    EQ(hflags(s), 0);
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    EQ(hflags(s), HANDLE_FLAG_INHERIT);
    sh_closes(s);
}

TEST(shs_hinfo_set_inherit_on_noinherit_socket)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT);
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    EQ(hflags(s), HANDLE_FLAG_INHERIT);
    sh_closes(s);
}

/* The mask selects which bits change; bits outside the mask are left alone. */
TEST(shs_hinfo_mask_zero_changes_nothing)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(SetHandleInformation((HANDLE)s, 0, 0));
    EQ(hflags(s), HANDLE_FLAG_INHERIT);
    CHECK(SetHandleInformation((HANDLE)s, 0, HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE));
    EQ(hflags(s), HANDLE_FLAG_INHERIT);
    sh_closes(s);
}

TEST(shs_hinfo_protect_flag_roundtrip)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE));
    EQ(hflags(s), HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE);
    CHECK(SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0));
    EQ(hflags(s), HANDLE_FLAG_INHERIT);
    sh_closes(s);
}

/* Flag changes are visible through the object-level queries too. */
TEST(shs_hinfo_matches_object_attributes)
{
    SOCKET s; sh_objbasic ob; sh_NtQueryObject_t q;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    q = NTFN(sh_NtQueryObject_t, "NtQueryObject");
    REQUIRE(q);
    memset(&ob, 0, sizeof ob);
    EQ(q((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.Attributes & OBJ_INHERIT, OBJ_INHERIT);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    EQ(q((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.Attributes & OBJ_INHERIT, 0);
    sh_closes(s);
}

TEST(shs_hinfo_invalid_handles)
{
    static const ULONG_PTR bad[] = { 0, 0x7ffffffc, 0x4444 };
    for (int i = 0; i < 3; i++) {
        DWORD f = 0;
        SET_ERR(0);
        CHECK(!GetHandleInformation((HANDLE)bad[i], &f));
        EXPECT_ERR(ERROR_INVALID_HANDLE);
        SET_ERR(0);
        CHECK(!SetHandleInformation((HANDLE)bad[i], HANDLE_FLAG_INHERIT, 0));
        EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
}

TEST(shs_hinfo_after_close_fails)
{
    SOCKET s; DWORD f;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(s);
    SET_ERR(0);
    CHECK(!GetHandleInformation((HANDLE)s, &f));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    SET_ERR(0);
    CHECK(!SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

/* ---------------- protect-from-close ---------------- */

/* A protected handle cannot be closed: CloseHandle fails, and closesocket reports success without actually
 * releasing the kernel handle. Once the protection is lifted closesocket closes it. */
TEST(shs_protect_closehandle_fails)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    SET_ERR(0);
    CHECK(!CloseHandle((HANDLE)s));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    EQ(hflags(s), HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    sh_closes(s);
}

TEST(shs_protect_closesocket_keeps_handle)
{
    SOCKET s; int rc; char name[32];
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    sh_setwerr(0);
    rc = sh_closes(s);
    EQ(rc, 0);
    /* the object is still there */
    EQ(sh_type_name((HANDLE)s, name, sizeof name), 0);
    EXPECT_STR(name, "File");
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    EQ(sh_closes(s), 0);
    CHECK(!GetHandleInformation((HANDLE)s, &(DWORD){0}));
}

TEST(shs_protect_ntclose_not_closable)
{
    SOCKET s; sh_NtClose_t nc;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    nc = NTFN(sh_NtClose_t, "NtClose");
    REQUIRE(nc);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    EQ32(nc((HANDLE)s), ST_HANDLE_NOT_CLOSABLE);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    EQ32(nc((HANDLE)s), 0);
    EQ32(nc((HANDLE)s), ST_INVALID_HANDLE);
}

/* ---------------- DuplicateHandle inside the process ---------------- */

TEST(shs_dup_distinct_value_and_usable)
{
    SOCKET c, s; HANDLE d; char b[8] = {0};
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CHECK(d != NULL);
    if (!d) { sh_closes(c); sh_closes(s); return; }
    CHECK(d != (HANDLE)c);
    EQ(sh_send((SOCKET)d, "dup", 3), 3);
    EQ(sh_recv_all(s, b, 3), 3);
    EXPECT_STR(b, "dup");
    EQ(sh_send(s, "back", 4), 4);
    memset(b, 0, sizeof b);
    EQ(sh_recv_all((SOCKET)d, b, 4), 4);
    EXPECT_STR(b, "back");
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* The duplicate is a full Winsock handle: option queries, name queries and ioctls work on it. */
TEST(shs_dup_winsock_calls_work)
{
    SOCKET c, s; HANDLE d; int ty = 0, tl = sizeof ty, al; struct sockaddr_in a; u_long nb = 1;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ(U(getsockopt)((SOCKET)d, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl), 0);
    EQ(ty, SOCK_STREAM);
    al = sizeof a;
    EQ(U(getsockname)((SOCKET)d, (struct sockaddr *)&a, &al), 0);
    al = sizeof a;
    EQ(U(getpeername)((SOCKET)d, (struct sockaddr *)&a, &al), 0);
    EQ(U(ioctlsocket)((SOCKET)d, FIONBIO, &nb), 0);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* The duplicate shares the one endpoint: closing the original does not disturb the stream. */
TEST(shs_dup_survives_original_close)
{
    SOCKET c, s; HANDLE d; char b[8] = {0};
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ(sh_closes(c), 0);
    EQ(sh_send((SOCKET)d, "xy", 2), 2);
    EQ(sh_recv_all(s, b, 2), 2);
    EXPECT_STR(b, "xy");
    /* no end of file yet: the endpoint is still referenced */
    CHECK(!sh_readable(s, 200));
    EQ(sh_closes((SOCKET)d), 0);
    EQ(sh_recv(s, b, 1), 0);       /* now the peer sees the orderly close */
    sh_closes(s);
}

TEST(shs_dup_survives_original_close_via_closehandle)
{
    SOCKET c, s; HANDLE d; char b[8] = {0};
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    CHECK(CloseHandle((HANDLE)c));
    EQ(sh_send((SOCKET)d, "q", 1), 1);
    EQ(sh_recv(s, b, 1), 1);
    CHECK(CloseHandle(d));
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}

/* Last handle closed through CloseHandle: the peer sees the close just like closesocket. */
TEST(shs_dup_two_duplicates_last_close_ends_stream)
{
    SOCKET c, s; HANDLE d1, d2; char b[4];
    UP(); PAIR(c, s, PLAIN);
    d1 = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    d2 = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d1 && d2);
    sh_closes(c); CloseHandle(d1);
    CHECK(!sh_readable(s, 200));
    CloseHandle(d2);
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}

TEST(shs_dup_inherit_argument)
{
    SOCKET c, s; HANDLE d1, d2;
    UP(); PAIR(c, s, PLAIN);
    d1 = sh_dup((HANDLE)c, 0, TRUE, DUPLICATE_SAME_ACCESS);
    d2 = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d1 && d2);
    EQ(hflags((SOCKET)d1), HANDLE_FLAG_INHERIT);
    EQ(hflags((SOCKET)d2), 0);
    /* the original is untouched by duplicating */
    EQ(hflags(c), HANDLE_FLAG_INHERIT);
    CloseHandle(d1); CloseHandle(d2); sh_closes(c); sh_closes(s);
}

TEST(shs_dup_of_noinherit_socket_can_be_inheritable)
{
    SOCKET c, s; HANDLE d;
    UP(); PAIR(c, s, WSA_FLAG_NO_HANDLE_INHERIT);
    d = sh_dup((HANDLE)c, 0, TRUE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ(hflags(c), 0);
    EQ(hflags((SOCKET)d), HANDLE_FLAG_INHERIT);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* DUPLICATE_SAME_ACCESS copies the granted mask; an explicit smaller mask is honoured. */
TEST(shs_dup_access_same)
{
    SOCKET c, s; HANDLE d; sh_objbasic a, b;
    sh_NtQueryObject_t q = NTFN(sh_NtQueryObject_t, "NtQueryObject");
    UP(); REQUIRE(q); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    EQ(q((HANDLE)c, 0, &a, sizeof a, NULL), 0);
    EQ(q(d, 0, &b, sizeof b, NULL), 0);
    EQ(b.GrantedAccess, a.GrantedAccess);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

TEST(shs_dup_access_reduced_mask)
{
    SOCKET c, s; HANDLE d; sh_objbasic b;
    sh_NtQueryObject_t q = NTFN(sh_NtQueryObject_t, "NtQueryObject");
    UP(); REQUIRE(q); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, FILE_READ_DATA | SYNCHRONIZE, FALSE, 0);
    REQUIRE(d);
    memset(&b, 0, sizeof b);
    EQ(q(d, 0, &b, sizeof b, NULL), 0);
    EQ(b.GrantedAccess, FILE_READ_DATA | SYNCHRONIZE);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* A handle without FILE_WRITE_DATA cannot be written with WriteFile; the access check is the file system layer's. */
TEST(shs_dup_read_only_handle_writefile_denied)
{
    SOCKET c, s; HANDLE d; DWORD n = 77; OVERLAPPED o; HANDLE ev = sh_event();
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, FILE_READ_DATA | SYNCHRONIZE, FALSE, 0);
    REQUIRE(d);
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(!sh_wf(d, "q", 1, &n, &o));
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    CHECK(!sh_readable(s, 200));
    CloseHandle(ev); CloseHandle(d); sh_closes(c); sh_closes(s);
}

TEST(shs_dup_write_only_handle_readfile_denied)
{
    SOCKET c, s; HANDLE d; DWORD n = 77; OVERLAPPED o; HANDLE ev = sh_event(); char b[4];
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, FILE_WRITE_DATA | SYNCHRONIZE, FALSE, 0);
    REQUIRE(d);
    sh_send(s, "k", 1);
    CHECK(sh_readable(c, SH_WAIT));
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(!sh_rf(d, b, 1, &n, &o));
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    CloseHandle(ev); CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* Winsock data-path calls do not need FILE_WRITE_DATA: send over a read-only duplicate still works. */
TEST(shs_dup_read_only_handle_send_still_works)
{
    SOCKET c, s; HANDLE d; char b[4];
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, FILE_READ_DATA | SYNCHRONIZE, FALSE, 0);
    REQUIRE(d);
    EQ(sh_send((SOCKET)d, "q", 1), 1);
    EQ(sh_recv(s, b, 1), 1);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* WriteFile through a duplicate obeys the same overlapped rule as through the original. */
TEST(shs_dup_writefile_needs_overlapped)
{
    SOCKET c, s; HANDLE d; DWORD n = 77;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    SET_ERR(0);
    CHECK(!sh_wf(d, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CloseHandle(d); sh_closes(c); sh_closes(s);
}

/* In-process DUPLICATE_CLOSE_SOURCE: the original handle is consumed. */
TEST(shs_dup_close_source)
{
    SOCKET c, s; HANDLE d; char b[4];
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    REQUIRE(d);
    t_note("close-source duplicate reuses the source handle value: %d", d == (HANDLE)c);
    EQ(sh_send((SOCKET)d, "w", 1), 1);
    EQ(sh_recv(s, b, 1), 1);
    sh_closes((SOCKET)d);
    CHECK(!GetHandleInformation(d, &(DWORD){0}));
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}

/* ---------------- closesocket / CloseHandle / NtClose ---------------- */

TEST(shs_close_closehandle_ends_stream)
{
    SOCKET c, s; char b[4];
    UP(); PAIR(c, s, PLAIN);
    CHECK(CloseHandle((HANDLE)c));
    EQ(sh_recv(s, b, 1), 0);
    sh_closes(s);
}

TEST(shs_close_closehandle_twice_invalid)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(CloseHandle((HANDLE)s));
    SET_ERR(0);
    CHECK(!CloseHandle((HANDLE)s));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

/* After CloseHandle the Winsock layer still has the descriptor: the first closesocket succeeds, the second is
 * WSAENOTSOCK. */
TEST(shs_close_closesocket_after_closehandle)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(CloseHandle((HANDLE)s));
    sh_setwerr(0);
    EQ(sh_closes(s), 0);
    sh_setwerr(0);
    EQ(sh_closes(s), SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTSOCK);
}

TEST(shs_close_closesocket_after_ntclose)
{
    SOCKET s; sh_NtClose_t nc;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    nc = NTFN(sh_NtClose_t, "NtClose");
    REQUIRE(nc);
    EQ32(nc((HANDLE)s), 0);
    /* the descriptor is gone for data calls */
    sh_setwerr(0);
    EQ(sh_send(s, "x", 1), SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTSOCK);
    EQ(sh_closes(s), 0);
}

TEST(shs_close_closesocket_twice)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ(sh_closes(s), 0);
    sh_setwerr(0);
    EQ(sh_closes(s), SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTSOCK);
    SET_ERR(0);
    EQ(sh_closes(s), SOCKET_ERROR);
    EXPECT_ERR(WSAENOTSOCK);
}

TEST(shs_close_use_after_close_is_notsock)
{
    SOCKET s; char b[2]; int v, n = sizeof v;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(s);
    sh_setwerr(0); EQ(U(recv)(s, b, 1, 0), SOCKET_ERROR); EQ(sh_werr(), WSAENOTSOCK);
    sh_setwerr(0); EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&v, &n), SOCKET_ERROR); EQ(sh_werr(), WSAENOTSOCK);
    sh_setwerr(0); EQ(U(shutdown)(s, SD_BOTH), SOCKET_ERROR); EQ(sh_werr(), WSAENOTSOCK);
}

/* closesocket on a handle that is not a socket: WSAENOTSOCK, and the foreign handle is left open. */
TEST(shs_close_closesocket_on_event_handle)
{
    HANDLE ev; DWORD f;
    UP(); ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    sh_setwerr(0);
    EQ(sh_closes((SOCKET)ev), SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTSOCK);
    CHECK(GetHandleInformation(ev, &f));
    CloseHandle(ev);
}
TEST(shs_close_closesocket_on_file_handle)
{
    HANDLE fh; DWORD f; char path[MAX_PATH];
    UP();
    t_tmpfile(path, sizeof path, "plain.bin");
    fh = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(fh != INVALID_HANDLE_VALUE);
    sh_setwerr(0);
    EQ(sh_closes((SOCKET)fh), SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTSOCK);
    CHECK(GetHandleInformation(fh, &f));
    CloseHandle(fh);
}
TEST(shs_close_winsock_calls_on_event_handle)
{
    HANDLE ev;
    UP(); ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    sh_setwerr(0);
    EQ(sh_send((SOCKET)ev, "x", 1), SOCKET_ERROR);
    EQ(sh_werr(), WSAENOTSOCK);
    CloseHandle(ev);
}

/* ---------------- handle values ---------------- */

TEST(shs_value_multiple_of_four_and_distinct)
{
    SOCKET a[8]; int i, j;
    UP();
    for (i = 0; i < 8; i++) { a[i] = sh_make(SOCK_STREAM, PLAIN); CHECK(a[i] != INVALID_SOCKET); CHECK(a[i] != 0); EQ(a[i] & 3, 0); }
    for (i = 0; i < 8; i++) for (j = i + 1; j < 8; j++) CHECK(a[i] != a[j]);
    for (i = 0; i < 8; i++) sh_closes(a[i]);
}

TEST(shs_value_stale_handle_invalid_until_reused)
{
    SOCKET s; DWORD f;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(s);
    CHECK(!GetHandleInformation((HANDLE)s, &f));
    EQ(GetFileType((HANDLE)s), FILE_TYPE_UNKNOWN);
}

TEST(shs_value_reuse_recorded)
{
    SOCKET a, b; HANDLE ev;
    UP(); a = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(a);
    b = sh_make(SOCK_STREAM, PLAIN);
    t_note("a freed socket handle value is handed out again to the next socket: %d", a == b);
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    sh_closes(b);
    CloseHandle(ev);
}

/* A reused value is a fresh object: state of the dead socket does not leak into it. */
TEST(shs_value_reused_handle_is_fresh_socket)
{
    SOCKET a, b; struct sockaddr_in x = sh_lo(0); int n = sizeof x, v = 0, vl = sizeof v;
    UP();
    a = sh_make(SOCK_STREAM, PLAIN);
    U(bind)(a, (struct sockaddr *)&x, sizeof x);
    U(listen)(a, 1);
    sh_closes(a);
    b = sh_make(SOCK_STREAM, PLAIN);
    EQ(U(getsockopt)(b, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &vl), 0);
    EQ(v, 0);
    sh_setwerr(0);
    EQ(U(getsockname)(b, (struct sockaddr *)&x, &n), SOCKET_ERROR);   /* unbound */
    EQ(sh_werr(), WSAEINVAL);
    sh_closes(b);
}

TEST(shs_value_many_sockets_all_close)
{
    enum { N = 64 };
    SOCKET a[N]; int i, ok = 0;
    UP();
    for (i = 0; i < N; i++) a[i] = sh_make(i & 1 ? SOCK_DGRAM : SOCK_STREAM, PLAIN);
    for (i = 0; i < N; i++) if (a[i] != INVALID_SOCKET) ok++;
    EQ(ok, N);
    for (i = 0; i < N; i++) if (a[i] != INVALID_SOCKET) EQ(sh_closes(a[i]), 0);
    for (i = 0; i < N; i++) CHECK(!GetHandleInformation((HANDLE)a[i], &(DWORD){0}));
}

/* ---------------- GetLastError and WSAGetLastError are one value ---------------- */

TEST(shs_err_set_win32_read_winsock)
{
    UP();
    SET_ERR(1234);
    EQ(sh_werr(), 1234);
    SET_ERR(0);
    EQ(sh_werr(), 0);
    SET_ERR(WSAECONNRESET);
    EQ(sh_werr(), WSAECONNRESET);
}
TEST(shs_err_set_winsock_read_win32)
{
    UP();
    sh_setwerr(4321);
    EQ(GetLastError(), 4321);
    sh_setwerr(0);
    EQ(GetLastError(), 0);
    sh_setwerr(WSAEWOULDBLOCK);
    EQ(GetLastError(), WSAEWOULDBLOCK);
}
TEST(shs_err_read_does_not_clear)
{
    UP();
    sh_setwerr(777);
    (void)sh_werr(); (void)sh_werr();
    EQ(GetLastError(), 777);
    EQ(sh_werr(), 777);
}
TEST(shs_err_failed_call_sets_both)
{
    SOCKET s; char b[2];
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    SET_ERR(0);
    EQ(U(recv)(s, b, 1, 0), SOCKET_ERROR);
    EQ(GetLastError(), WSAENOTCONN);
    EQ(sh_werr(), WSAENOTCONN);
    sh_closes(s);
}
TEST(shs_err_successful_calls_clear_error)
{
    SOCKET c, s; u_long nb = 0;
    UP(); PAIR(c, s, PLAIN);
    sh_setwerr(999);
    EQ(sh_send(c, "x", 1), 1);
    EQ(sh_werr(), 0);
    EQ(GetLastError(), 0);
    sh_setwerr(999);
    EQ(U(ioctlsocket)(c, FIONBIO, &nb), 0);
    EQ(sh_werr(), 0);
    sh_closes(c); sh_closes(s);
}
TEST(shs_err_kernel32_error_visible_after_winsock_failure)
{
    UP();
    sh_setwerr(0);
    EQ(U(select)(0, NULL, NULL, NULL, NULL), SOCKET_ERROR);
    EQ(GetLastError(), WSAEINVAL);
    EQ(sh_werr(), WSAEINVAL);
}
/* ReadFile failing in the file layer: the Win32 mapping, not a WSA code, and WSAGetLastError sees the same value. */
TEST(shs_err_readfile_error_seen_by_winsock)
{
    SOCKET s; DWORD n;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    SET_ERR(0);
    CHECK(!sh_rf((HANDLE)s, &n, 1, &n, NULL));
    EQ(sh_werr(), ERROR_INVALID_PARAMETER);
    sh_closes(s);
}
TEST(shs_err_notsock_codes_are_same_number)
{
    CHECK(ERROR_INVALID_HANDLE == 6);
    EQ(WSAENOTSOCK, 10038);
    EQ(WSA_INVALID_HANDLE, 6);
}

static DWORD g_thr_seen;
static DWORD WINAPI err_thread(LPVOID p)
{
    SOCKET s = *(SOCKET *)p; char b[2];
    g_thr_seen = (DWORD)sh_werr();             /* fresh thread: no error yet */
    U(recv)(s, b, 1, 0);                        /* fails with WSAENOTCONN in this thread */
    return (DWORD)sh_werr();
}
/* The error value is per thread. */
TEST(shs_err_is_per_thread)
{
    SOCKET s; HANDLE t; DWORD code = 0;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_setwerr(31337);
    t = CreateThread(NULL, 0, err_thread, &s, 0, NULL);
    WaitForSingleObject(t, SH_WAIT);
    GetExitCodeThread(t, &code);
    CloseHandle(t);
    t_note("last error in a fresh thread: %lu", g_thr_seen);
    EQ(code, WSAENOTCONN);
    EQ(sh_werr(), 31337);
    sh_closes(s);
}
