/* WSPStartup / WSPCleanup of the base provider, driven directly.
 *
 * Measures: the version contract (only 2.2 is accepted, the error is the return value, not lpErrno), the
 * WSPDATA the provider writes, the 30-entry procedure table, the reference count that gates every other entry
 * point (ERROR code 10093 before the first start and after the last cleanup), which upcalls the provider does
 * and does not make while starting, and the rule that the upcall table is only captured by the first start.
 * Anything that depends on the process-wide start-up count runs in a freshly launched child process so the
 * count is known to be zero.
 */
#include "spi.h"

/* ---- export presence ---- */
TEST(startup_export_only_in_mswsock)
{
    CHECK(t_proc_in("mswsock.dll", "WSPStartup") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "WSPStartup") == NULL);
    CHECK(t_proc_in("wsock32.dll", "WSPStartup") == NULL);
}
TEST(startup_only_wspstartup_is_named_export)
{
    /* The rest of the SPI is reached through the table only. */
    static const char *const n[] = { "WSPSocket", "WSPBind", "WSPListen", "WSPAccept", "WSPConnect", "WSPCleanup",
                                     "WSPCloseSocket", "WSPSend", "WSPRecv", "WSPSelect", "WSPIoctl", "WSPShutdown" };
    for (size_t i = 0; i < sizeof n / sizeof n[0]; i++) {
        FARPROC p = t_proc_in("mswsock.dll", n[i]);
        CHECKF(p == NULL, "%s unexpectedly exported", n[i]);
    }
}

/* ---- basic start-up in this process ---- */
TEST(startup_runs_and_fills_table)
{
    SP_NEED();
    CHECK(P.lpWSPSocket != NULL);
}
TEST(startup_wspdata_versions)
{
    SP_NEED();
    EXPECT_EQ(sp_data.wVersion, 0x0202);
    EXPECT_EQ(sp_data.wHighVersion, 0x0202);
}
TEST(startup_wspdata_description)
{
    SP_NEED();
    EXPECT_WSTR(sp_data.szDescription, L"Microsoft Windows Sockets Version 2.");
}
TEST(startup_wspdata_description_length)
{
    SP_NEED();
    EXPECT_EQ(lstrlenW(sp_data.szDescription), 36);
}

/* ---- the 30-entry table ---- */
static void **tab(WSPPROC_TABLE *t) { return (void **)t; }
TEST(proctable_size_is_thirty_pointers)
{
    EXPECT_EQ(sizeof(WSPPROC_TABLE), 30 * sizeof(void *));
}
TEST(proctable_all_entries_non_null)
{
    int i;
    SP_NEED();
    for (i = 0; i < 30; i++) CHECKF(tab(&P)[i] != NULL, "entry %d is NULL", i);
}
TEST(proctable_entries_are_distinct)
{
    int i, j;
    SP_NEED();
    for (i = 0; i < 30; i++)
        for (j = i + 1; j < 30; j++)
            CHECKF(tab(&P)[i] != tab(&P)[j], "entries %d and %d share a pointer", i, j);
}
TEST(proctable_entries_live_in_the_provider_image)
{
    HMODULE ms = t_module("mswsock.dll");
    int i;
    SP_NEED();
    for (i = 0; i < 30; i++) {
        HMODULE h = NULL;
        BOOL ok = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)tab(&P)[i], &h);
        CHECKF(ok && h == ms, "entry %d is outside mswsock", i);
    }
}
TEST(proctable_entries_are_executable_code)
{
    MEMORY_BASIC_INFORMATION mbi;
    int i;
    SP_NEED();
    for (i = 0; i < 30; i++) {
        memset(&mbi, 0, sizeof mbi);
        CHECK(VirtualQuery(tab(&P)[i], &mbi, sizeof mbi) == sizeof mbi);
        CHECKF((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0, "entry %d not executable", i);
    }
}
TEST(proctable_stable_across_second_start)
{
    WSPPROC_TABLE t2; WSPDATA d2; WSPUPCALLTABLE u; int r, e, i;
    SP_NEED();
    spA_fill(&u);
    memset(&t2, 0, sizeof t2);
    r = sp_startup_ptr()(MAKEWORD(2, 2), &d2, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t2);
    EXPECT_EQ(r, 0);
    for (i = 0; i < 30; i++) CHECKF(tab(&t2)[i] == tab(&P)[i], "entry %d changed", i);
    EXPECT_EQ(d2.wVersion, 0x0202);
    EXPECT_EQ(P.lpWSPCleanup(&e), 0);   /* balance the extra start */
}
TEST(proctable_cleanup_pointer_matches_table)
{
    /* The table entry is directly callable and balances a start made on purpose. */
    WSPPROC_TABLE t2; WSPDATA d2; WSPUPCALLTABLE u; int e = 0;
    SP_NEED();
    spA_fill(&u);
    EXPECT_EQ(sp_startup_ptr()(MAKEWORD(2, 2), &d2, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t2), 0);
    EXPECT_EQ(t2.lpWSPCleanup(&e), 0);
}

/* ---- upcalls made (or not made) by start-up and by plain socket traffic ---- */
TEST(startup_makes_no_upcalls)
{
    WSPPROC_TABLE t2; WSPDATA d2; WSPUPCALLTABLE u; int e = 0;
    SP_NEED();
    sp_up_reset(&sp_upB);
    spB_fill(&u);
    EXPECT_EQ(sp_startup_ptr()(MAKEWORD(2, 2), &d2, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t2), 0);
    EXPECT_EQ(sp_up_total(&sp_upB), 0);
    EXPECT_EQ(P.lpWSPCleanup(&e), 0);
}
TEST(startup_second_table_is_ignored_while_running)
{
    /* Provider keeps the table it saw on the 0 -> 1 transition; a different table on a later start is never used. */
    WSPPROC_TABLE t2; WSPDATA d2; WSPUPCALLTABLE u; int e = 0; SOCKET s;
    SP_NEED();
    sp_up_reset(&sp_upA); sp_up_reset(&sp_upB);
    spB_fill(&u);
    EXPECT_EQ(sp_startup_ptr()(MAKEWORD(2, 2), &d2, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t2), 0);
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sp_upB.n[UP_MODIFYIFSHANDLE], 0);
    CHECK(sp_upA.n[UP_MODIFYIFSHANDLE] >= 1);
    sp_close(s);
    EXPECT_EQ(P.lpWSPCleanup(&e), 0);
}
TEST(socket_makes_one_modify_ifs_upcall)
{
    SOCKET s;
    SP_NEED();
    sp_up_reset(&sp_upA);
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sp_upA.n[UP_MODIFYIFSHANDLE], 1);
    sp_close(s);
}
TEST(socket_does_not_create_a_socket_handle_through_the_host)
{
    SOCKET s;
    SP_NEED();
    sp_up_reset(&sp_upA);
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(sp_upA.n[UP_CREATESOCKETHANDLE], 0);
    sp_close(s);
}
TEST(socket_modify_ifs_receives_the_catalog_id)
{
    SOCKET s; const WSAPROTOCOL_INFOW *pi;
    SP_NEED();
    pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sp_up_reset(&sp_upA);
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ((DWORD)sp_upA.cat, pi->dwCatalogEntryId);
    sp_close(s);
}
TEST(socket_returned_value_is_the_value_the_host_returned)
{
    SOCKET s;
    SP_NEED();
    sp_up_reset(&sp_upA);
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ((LONG_PTR)s, sp_upA.handle);
    sp_close(s);
}
TEST(socket_close_makes_no_host_upcalls)
{
    SOCKET s; int e = 0;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    sp_up_reset(&sp_upA);
    EXPECT_EQ(P.lpWSPCloseSocket(s, &e), 0);
    EXPECT_EQ(sp_up_total(&sp_upA), 0);
}
TEST(accept_makes_one_modify_ifs_upcall)
{
    struct sockaddr_in la; SOCKET l, c, a; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    CHECK(l != INVALID_SOCKET);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    sp_up_reset(&sp_upA);
    a = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(sp_upA.n[UP_MODIFYIFSHANDLE], 1);
    EXPECT_EQ(sp_upA.n[UP_CREATESOCKETHANDLE], 0);
    sp_close(a); sp_close(c); sp_close(l);
}
TEST(accept_modify_ifs_catalog_id_is_the_listeners)
{
    struct sockaddr_in la; SOCKET l, c, a; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    CHECK(l != INVALID_SOCKET);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    sp_up_reset(&sp_upA);
    a = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
    EXPECT_EQ((DWORD)sp_upA.cat, sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP)->dwCatalogEntryId);
    sp_close(a); sp_close(c); sp_close(l);
}
TEST(select_and_getsockname_make_no_upcalls)
{
    SOCKET s; struct sockaddr_in a;
    SP_NEED();
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    CHECK(sp_bind_lo(s) == 0);
    sp_up_reset(&sp_upA);
    CHECK(sp_name(s, &a) == 0);
    (void)sp_writable(s, 0);
    EXPECT_EQ(sp_up_total(&sp_upA), 0);
    sp_close(s);
}

/* ---- version negotiation (children: the count must start at zero) ---- */
#define VER_CHILD(nm, ver) \
CHILD(nm) { \
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int r, e = 0; \
    CB(); spA_fill(&u); memset(&t, 0, sizeof t); memset(&d, 0, sizeof d); \
    r = sp_startup_ptr()((WORD)(ver), &d, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t); \
    CK_EQ(r, SE_VERNOTSUP); \
    CK(t.lpWSPSocket == NULL); \
    return ck_bad; \
}
VER_CHILD(ver_0000, 0x0000)
VER_CHILD(ver_0001, 0x0001)
VER_CHILD(ver_0002, 0x0002)
VER_CHILD(ver_0101, 0x0101)
VER_CHILD(ver_0102, 0x0102)
VER_CHILD(ver_0201, 0x0201)
VER_CHILD(ver_0203, 0x0203)
VER_CHILD(ver_0302, 0x0302)
VER_CHILD(ver_0a0a, 0x0A0A)
VER_CHILD(ver_ffff, 0xFFFF)
VER_CHILD(ver_0200, 0x0200)
VER_CHILD(ver_0100, 0x0100)

#define VER_TEST(nm) TEST(startup_bad_version_##nm) { SP_NEED(); EXPECT_EQ(t_run_child("ver_" #nm, "", 30000), 0); }
VER_TEST(0000) VER_TEST(0001) VER_TEST(0002) VER_TEST(0101) VER_TEST(0102) VER_TEST(0201)
VER_TEST(0203) VER_TEST(0302) VER_TEST(0a0a) VER_TEST(ffff) VER_TEST(0200) VER_TEST(0100)

CHILD(ver_failure_leaves_count_zero)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int r, e = 0;
    CB(); spA_fill(&u);
    r = sp_startup_ptr()(0x0101, &d, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t);
    CK_EQ(r, SE_VERNOTSUP);
    /* A rejected version must not have been counted: a good start followed by one cleanup reaches zero. */
    r = sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t);
    CK_EQ(r, 0);
    CK_EQ(t.lpWSPCleanup(&e), 0);
    e = 0;
    CK_EQ(t.lpWSPCleanup(&e), (ULONG_PTR)(LONG_PTR)-1);
    CK_EQ(e, SE_NOTINIT);
    return ck_bad;
}
TEST(startup_rejected_version_is_not_counted) { SP_NEED(); EXPECT_EQ(t_run_child("ver_failure_leaves_count_zero", "", 30000), 0); }

CHILD(ver_error_is_return_value_only)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int r;
    CB(); spA_fill(&u);
    U(WSASetLastError)(0x1234);
    r = sp_startup_ptr()(0x0101, &d, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t);
    CK_EQ(r, SE_VERNOTSUP);
    return ck_bad;
}
TEST(startup_version_error_returned_directly) { SP_NEED(); EXPECT_EQ(t_run_child("ver_error_is_return_value_only", "", 30000), 0); }

/* ---- reference counting (children) ---- */
CHILD(rc_cleanup_before_start)
{
    /* Obtain a table, balance it, then every further cleanup has nothing to release. */
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e = 0;
    CB(); spA_fill(&u);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t), 0);
    CK_EQ(t.lpWSPCleanup(&e), 0);
    e = 0;
    CK_EQ(t.lpWSPCleanup(&e), (ULONG_PTR)(LONG_PTR)-1);
    CK_EQ(e, SE_NOTINIT);
    e = 0;
    CK_EQ(t.lpWSPCleanup(&e), (ULONG_PTR)(LONG_PTR)-1);
    CK_EQ(e, SE_NOTINIT);
    return ck_bad;
}
TEST(cleanup_with_nothing_started) { SP_NEED(); EXPECT_EQ(t_run_child("rc_cleanup_before_start", "", 30000), 0); }

CHILD(rc_three_deep)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e = 0, i;
    CB(); spA_fill(&u);
    for (i = 0; i < 3; i++) CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), u, &t), 0);
    for (i = 0; i < 3; i++) { e = -1; CK_EQ(t.lpWSPCleanup(&e), 0); }
    e = 0;
    CK_EQ(t.lpWSPCleanup(&e), (ULONG_PTR)(LONG_PTR)-1);
    CK_EQ(e, SE_NOTINIT);
    return ck_bad;
}
TEST(cleanup_balances_three_starts) { SP_NEED(); EXPECT_EQ(t_run_child("rc_three_deep", "", 30000), 0); }

CHILD(rc_socket_survives_inner_cleanup)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e = 0; SOCKET s;
    const WSAPROTOCOL_INFOW *pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CB(); spA_fill(&u);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, u, &t), 0);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, u, &t), 0);
    s = t.lpWSPSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (LPWSAPROTOCOL_INFOW)pi, 0, WSA_FLAG_OVERLAPPED, &e);
    CK(s != INVALID_SOCKET);
    CK_EQ(t.lpWSPCleanup(&e), 0);               /* 2 -> 1: socket must still be usable */
    { int type = 0, len = sizeof type; e = 0;
      CK_EQ(t.lpWSPGetSockOpt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len, &e), 0);
      CK_EQ(type, SOCK_STREAM); }
    CK_EQ(t.lpWSPCloseSocket(s, &e), 0);
    CK_EQ(t.lpWSPCleanup(&e), 0);
    return ck_bad;
}
TEST(cleanup_inner_keeps_sockets_alive) { SP_NEED(); EXPECT_EQ(t_run_child("rc_socket_survives_inner_cleanup", "", 30000), 0); }

CHILD(rc_final_cleanup_closes_sockets)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e = 0; SOCKET s; DWORD fl;
    const WSAPROTOCOL_INFOW *pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CB(); spA_fill(&u);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, u, &t), 0);
    s = t.lpWSPSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (LPWSAPROTOCOL_INFOW)pi, 0, WSA_FLAG_OVERLAPPED, &e);
    CK(s != INVALID_SOCKET);
    CK(GetHandleInformation((HANDLE)s, &fl));
    CK_EQ(t.lpWSPCleanup(&e), 0);               /* last release: the provider closes what it still owns */
    CK(!GetHandleInformation((HANDLE)s, &fl));
    return ck_bad;
}
TEST(cleanup_final_release_closes_open_sockets) { SP_NEED(); EXPECT_EQ(t_run_child("rc_final_cleanup_closes_sockets", "", 30000), 0); }

CHILD(rc_restart_after_cleanup)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e = 0, round; SOCKET s;
    const WSAPROTOCOL_INFOW *pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CB(); spA_fill(&u);
    for (round = 0; round < 3; round++) {
        CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, u, &t), 0);
        s = t.lpWSPSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (LPWSAPROTOCOL_INFOW)pi, 0, WSA_FLAG_OVERLAPPED, &e);
        CK(s != INVALID_SOCKET);
        CK_EQ(t.lpWSPCloseSocket(s, &e), 0);
        CK_EQ(t.lpWSPCleanup(&e), 0);
    }
    return ck_bad;
}
TEST(startup_cleanup_cycles) { SP_NEED(); EXPECT_EQ(t_run_child("rc_restart_after_cleanup", "", 60000), 0); }

CHILD(rc_new_table_used_after_full_cycle)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE ua, ub; int e = 0; SOCKET s;
    const WSAPROTOCOL_INFOW *pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CB(); spA_fill(&ua); spB_fill(&ub);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, ua, &t), 0);
    CK_EQ(t.lpWSPCleanup(&e), 0);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, ub, &t), 0);
    s = t.lpWSPSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (LPWSAPROTOCOL_INFOW)pi, 0, WSA_FLAG_OVERLAPPED, &e);
    CK(s != INVALID_SOCKET);
    CK_EQ(sp_upB.n[UP_MODIFYIFSHANDLE], 1);
    CK_EQ(sp_upA.n[UP_MODIFYIFSHANDLE], 0);
    t.lpWSPCloseSocket(s, &e);
    t.lpWSPCleanup(&e);
    return ck_bad;
}
TEST(startup_after_full_cleanup_takes_new_upcall_table) { SP_NEED(); EXPECT_EQ(t_run_child("rc_new_table_used_after_full_cycle", "", 30000), 0); }

/* ---- every entry that needs a running provider fails with 10093 when none is running ---- */
CHILD(rc_all_entries_gated)
{
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e, r; SOCKET s;
    const WSAPROTOCOL_INFOW *pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a; int al = sizeof a; char cb[16]; int cl = sizeof(int);
    fd_set fs; struct timeval tv; WSABUF wb; DWORD n = 0, fl = 0; WSANETWORKEVENTS ne; WSAPROTOCOL_INFOW out;
    CB(); spA_fill(&u); memset(&a, 0, sizeof a); memset(&cb, 0, sizeof cb);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, u, &t), 0);
    CK_EQ(t.lpWSPCleanup(&e), 0);
    wb.buf = cb; wb.len = 1; fs.fd_count = 0; tv.tv_sec = 0; tv.tv_usec = 0;
#define GATED(expr, bad) do { e = 0; r = (int)(LONG_PTR)(expr); CK_EQ(r, (bad)); CK_EQ(e, SE_NOTINIT); } while (0)
    s = (SOCKET)0x4;
    GATED(t.lpWSPSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (LPWSAPROTOCOL_INFOW)pi, 0, 1, &e), -1);
    GATED(t.lpWSPCloseSocket(s, &e), -1);
    GATED(t.lpWSPBind(s, (struct sockaddr *)&a, sizeof a, &e), -1);
    GATED(t.lpWSPListen(s, 1, &e), -1);
    GATED(t.lpWSPAccept(s, NULL, NULL, NULL, 0, &e), -1);
    GATED(t.lpWSPConnect(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, &e), -1);
    GATED(t.lpWSPGetSockName(s, (struct sockaddr *)&a, &al, &e), -1);
    GATED(t.lpWSPGetPeerName(s, (struct sockaddr *)&a, &al, &e), -1);
    GATED(t.lpWSPGetSockOpt(s, SOL_SOCKET, SO_TYPE, cb, &cl, &e), -1);
    GATED(t.lpWSPSetSockOpt(s, SOL_SOCKET, SO_REUSEADDR, cb, 4, &e), -1);
    GATED(t.lpWSPSend(s, &wb, 1, &n, 0, NULL, NULL, NULL, &e), -1);
    GATED(t.lpWSPRecv(s, &wb, 1, &n, &fl, NULL, NULL, NULL, &e), -1);
    GATED(t.lpWSPSendTo(s, &wb, 1, &n, 0, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, &e), -1);
    GATED(t.lpWSPRecvFrom(s, &wb, 1, &n, &fl, (struct sockaddr *)&a, &al, NULL, NULL, NULL, &e), -1);
    GATED(t.lpWSPShutdown(s, SD_BOTH, &e), -1);
    GATED(t.lpWSPSendDisconnect(s, NULL, &e), -1);
    GATED(t.lpWSPRecvDisconnect(s, NULL, &e), -1);
    GATED(t.lpWSPEnumNetworkEvents(s, NULL, &ne, &e), -1);
    GATED(t.lpWSPEventSelect(s, NULL, 0, &e), -1);
    GATED(t.lpWSPAsyncSelect(s, NULL, 0, 0, &e), -1);
    GATED(t.lpWSPDuplicateSocket(s, GetCurrentProcessId(), &out, &e), -1);
    GATED(t.lpWSPCancelBlockingCall(&e), -1);
    GATED(t.lpWSPGetOverlappedResult(s, NULL, &n, FALSE, &fl, &e), 0);   /* BOOL result */
    GATED(t.lpWSPGetQOSByName(s, &wb, NULL, &e), 0);                      /* BOOL result */
    GATED(t.lpWSPSelect(0, &fs, NULL, NULL, &tv, &e), -1);
    GATED(t.lpWSPIoctl(s, FIONREAD, NULL, 0, cb, 4, &n, NULL, NULL, NULL, &e), -1);
    GATED(t.lpWSPJoinLeaf(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, 0, &e), -1);
    GATED(t.lpWSPCleanup(&e), -1);
    return ck_bad;
}
TEST(all_entries_report_not_initialised_when_stopped) { SP_NEED(); EXPECT_EQ(t_run_child("rc_all_entries_gated", "", 60000), 0); }

CHILD(rc_addr_conversion_needs_no_start)
{
    /* The two string conversion entries do not consult the start-up count. */
    WSPPROC_TABLE t; WSPDATA d; WSPUPCALLTABLE u; int e = 0, r;
    const WSAPROTOCOL_INFOW *pi = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a; DWORD l; WCHAR buf[64];
    CB(); spA_fill(&u);
    CK_EQ(sp_startup_ptr()(0x0202, &d, (LPWSAPROTOCOL_INFOW)pi, u, &t), 0);
    CK_EQ(t.lpWSPCleanup(&e), 0);
    sp_v4(&a, 80); l = 64; e = -1;
    r = t.lpWSPAddressToString((LPSOCKADDR)&a, sizeof a, (LPWSAPROTOCOL_INFOW)pi, buf, &l, &e);
    if (r == 0) CK(!lstrcmpW(buf, L"127.0.0.1:80"));
    else CK(e != SE_NOTINIT);
    return ck_bad;
}
TEST(address_string_entries_not_gated_by_start_count) { SP_NEED(); EXPECT_EQ(t_run_child("rc_addr_conversion_needs_no_start", "", 30000), 0); }

/* ---- threads: a thread that never called into the provider can use it ---- */
static DWORD WINAPI thr_socket(LPVOID p)
{
    int e = 0; SOCKET s = sp_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &e);
    int ok = 0;
    if (s != INVALID_SOCKET) { ok = P.lpWSPCloseSocket(s, &e) == 0; }
    return ok ? 1 : 0;
}
TEST(thread_without_prior_use_can_create_sockets)
{
    HANDLE h; DWORD code = 0;
    SP_NEED();
    h = CreateThread(NULL, 0, thr_socket, NULL, 0, NULL);
    CHECK(h != NULL);
    if (!h) return;
    EXPECT_EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0);
    GetExitCodeThread(h, &code);
    EXPECT_EQ(code, 1);
    CloseHandle(h);
}
static DWORD WINAPI thr_use_handle(LPVOID p)
{
    int e = 0, type = 0, len = sizeof type;
    SOCKET s = (SOCKET)p;
    if (P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len, &e) != 0) return 0;
    return type == SOCK_DGRAM;
}
TEST(socket_handle_usable_from_another_thread)
{
    SOCKET s; HANDLE h; DWORD code = 0;
    SP_NEED();
    s = sp_udp();
    CHECK(s != INVALID_SOCKET);
    h = CreateThread(NULL, 0, thr_use_handle, (LPVOID)s, 0, NULL);
    CHECK(h != NULL);
    if (h) { WaitForSingleObject(h, 10000); GetExitCodeThread(h, &code); EXPECT_EQ(code, 1); CloseHandle(h); }
    sp_close(s);
}
