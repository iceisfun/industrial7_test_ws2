/* Leftover ws2_32 surface: multipoint join on unicast sockets, name-space ioctl handles, provider
 * (de)advertisement and async-call completion, no-op exports, the fd_set membership helper, address-info
 * release functions, and the error-slot mapping between Win32 and Winsock errors.
 *
 * Observed contract, by group:
 *   WSAJoinLeaf        : a unicast socket (stream or datagram, in any state) can never join; the call returns
 *                        INVALID_SOCKET and WSAEINVAL. A bad socket is WSAENOTSOCK, a missing stack WSANOTINITIALISED.
 *   WSANSPIoctl        : needs a started stack; a NULL byte counter is WSAEINVAL and is checked before the handle;
 *                        a NULL or closed lookup handle is ERROR_INVALID_HANDLE.
 *   WSAAdvertiseProvider / WSAUnadvertiseProvider : need no stack; a NULL id or an incomplete routine table is
 *                        WSAEINVAL (the HRESULT E_INVALIDARG maps to it).
 *   WSAProviderCompleteAsyncCall : an unknown async-call handle fails with -1.
 *   WEP                : a do-nothing export, callable and returning to the caller.
 *   freeaddrinfo family: NULL is accepted silently; the narrow and wide names are one function.
 *   __WSAFDIsSet       : a plain linear scan of fd_count entries, no clamping to FD_SETSIZE, no stack needed.
 *   error slot         : Win32 failures and Winsock failures share one per-thread slot. */
#include "qm.h"

UDECL(int, WSANSPIoctl, (HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, void *));
UDECL(int, WSAAdvertiseProvider, (const GUID *, const void *));
UDECL(int, WSAUnadvertiseProvider, (const GUID *));
UDECL(int, WSAProviderCompleteAsyncCall, (HANDLE, HRESULT));
UDECL(int, WEP, (void));
/* WEP is an unimplemented stub that aborts the process in the emulated stack. */
#define REQ_WEP() do { if (t_is_wine()) { t_skip("WEP is a stub in the emulated stack"); return; } if (!UN(WEP)) { t_skip("missing export: WEP"); return; } } while (0)

static int setup_listener(SOCKET *l, struct sockaddr_in *a)
{
    qm_lo4(a);
    *l = qm_sock(SOCK_STREAM);
    if (*l == INVALID_SOCKET) return 0;
    if (U(bind)(*l, (struct sockaddr *)a, sizeof *a) != 0 || U(listen)(*l, 4) != 0) { qm_close(*l); return 0; }
    int n = sizeof *a;
    return U(getsockname)(*l, (struct sockaddr *)a, &n) == 0;
}

/* ---- WSAJoinLeaf -------------------------------------------------------------------------------------- */

static SOCKET join(SOCKET s, const struct sockaddr_in *a, int len, DWORD flags)
{
    return U(WSAJoinLeaf)(s, (const struct sockaddr *)a, len, NULL, NULL, NULL, NULL, flags);
}

TEST(join_tcp_fresh_socket_is_einval)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_STREAM); struct sockaddr_in a; qm_lo4(&a); a.sin_port = U(htons)(9);
    SETWSAERR(0);
    SOCKET r = join(s, &a, sizeof a, JL_BOTH);
    EXPECT_EQ(r, INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    qm_close(s);
}
TEST(join_udp_fresh_socket_is_einval)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM); struct sockaddr_in a; qm_lo4(&a); a.sin_port = U(htons)(9);
    EXPECT_EQ(join(s, &a, sizeof a, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    qm_close(s);
}
TEST(join_every_flag_value_is_einval_on_unicast)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    static const DWORD flags[] = { 0, JL_SENDER_ONLY, JL_RECEIVER_ONLY, JL_BOTH, 8, 0x80, 0xFFFFFFFFu };
    SOCKET s = qm_sock(SOCK_DGRAM); struct sockaddr_in a; qm_lo4(&a); a.sin_port = U(htons)(9);
    for (int i = 0; i < QM_N(flags); i++) {
        SETWSAERR(0);
        SOCKET r = join(s, &a, sizeof a, flags[i]);
        t_check(r == INVALID_SOCKET && WSAERR() == WSAEINVAL, __FILE__, __LINE__, "join(flags)", "flags 0x%lx ret 0x%llx err %d", flags[i], (unsigned long long)r, WSAERR());
    }
    qm_close(s);
}
TEST(join_bound_udp_is_einval)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM); struct sockaddr_in a; qm_lo4(&a);
    CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0);
    EXPECT_EQ(join(s, &a, sizeof a, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    qm_close(s);
}
TEST(join_bound_wildcard_udp_is_einval)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM); struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET;
    CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0);
    struct sockaddr_in g; qm_lo4(&g); g.sin_addr.s_addr = U(inet_addr)("224.0.0.251"); g.sin_port = U(htons)(5353);
    EXPECT_EQ(join(s, &g, sizeof g, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    qm_close(s);
}
TEST(join_listening_tcp_is_einval)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET l; struct sockaddr_in a;
    if (!setup_listener(&l, &a)) { t_skip("no loopback listener"); return; }
    EXPECT_EQ(join(l, &a, sizeof a, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    qm_close(l);
}
TEST(join_connected_tcp_is_einval)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET l; struct sockaddr_in a;
    if (!setup_listener(&l, &a)) { t_skip("no loopback listener"); return; }
    SOCKET c = qm_sock(SOCK_STREAM);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == 0);
    EXPECT_EQ(join(c, &a, sizeof a, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    qm_close(c); qm_close(l);
}
TEST(join_failure_leaves_the_socket_usable)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM); struct sockaddr_in a; qm_lo4(&a); a.sin_port = U(htons)(9);
    join(s, &a, sizeof a, JL_BOTH);
    CHECK(U(bind)(s, (struct sockaddr *)&(struct sockaddr_in){ .sin_family = AF_INET, .sin_addr.s_addr = a.sin_addr.s_addr }, sizeof a) == 0);
    int t = 0, n = sizeof t;
    EXPECT_EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&t, &n), 0);
    EXPECT_EQ(t, SOCK_DGRAM);
    qm_close(s);
}
TEST(join_invalid_socket_is_enotsock)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    struct sockaddr_in a; qm_lo4(&a);
    SOCKET bad[] = { INVALID_SOCKET, 0, QM_BOGUS_SOCKET };
    for (int i = 0; i < 3; i++) {
        SETWSAERR(0);
        SOCKET r = join(bad[i], &a, sizeof a, JL_BOTH);
        t_check(r == INVALID_SOCKET && WSAERR() == WSAENOTSOCK, __FILE__, __LINE__, "join(bad socket)", "row %d ret 0x%llx err %d", i, (unsigned long long)r, WSAERR());
    }
}
TEST(join_closed_socket_is_enotsock)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_DGRAM); struct sockaddr_in a; qm_lo4(&a);
    qm_close(s);
    EXPECT_EQ(join(s, &a, sizeof a, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
}
TEST(join_non_socket_handle_is_enotsock)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL); struct sockaddr_in a; qm_lo4(&a);
    EXPECT_EQ(join((SOCKET)e, &a, sizeof a, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    CloseHandle(e);
}
TEST(join_bad_socket_error_wins_over_bad_address)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    EXPECT_EQ(U(WSAJoinLeaf)(QM_BOGUS_SOCKET, NULL, 0, NULL, NULL, NULL, NULL, JL_BOTH), INVALID_SOCKET);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
}
TEST(join_null_address_on_fresh_socket_fails)
{
    /* Fresh TCP socket: the address is looked at before the multipoint capability. Both outcomes are a
     * failure; the code is WSAEFAULT when the address check comes first. */
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_STREAM);
    EXPECT_EQ(U(WSAJoinLeaf)(s, NULL, sizeof(struct sockaddr_in), NULL, NULL, NULL, NULL, JL_BOTH), INVALID_SOCKET);
    int e = WSAERR();
    CHECK(e == WSAEFAULT || e == WSAEINVAL);
    if (e != WSAEFAULT) t_note("NULL address on a fresh socket gave %d", e);
    qm_close(s);
}
TEST(join_short_address_length_on_fresh_socket_fails)
{
    REQUIRE(U(WSAJoinLeaf)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_STREAM); struct sockaddr_in a; qm_lo4(&a);
    EXPECT_EQ(join(s, &a, 4, JL_BOTH), INVALID_SOCKET);
    int e = WSAERR();
    CHECK(e == WSAEFAULT || e == WSAEINVAL);
    if (e != WSAEFAULT) t_note("short address length on a fresh socket gave %d", e);
    qm_close(s);
}
CHILD(join_before_startup)
{
    struct sockaddr_in a; qm_lo4(&a);
    STEP(1, U(WSAJoinLeaf) != NULL);
    SOCKET r = U(WSAJoinLeaf)(QM_BOGUS_SOCKET, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, JL_BOTH);
    STEP(2, r == INVALID_SOCKET);
    STEP(3, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(join_before_startup_is_notinitialised)
{
    REQUIRE(U(WSAJoinLeaf));
    RUN_CHILD("join_before_startup", "", 20000);
}
TEST(join_after_last_cleanup_is_notinitialised)
{
    REQUIRE(U(WSAJoinLeaf));
    RUN_CHILD("join_after_cleanup", "", 20000);
}
CHILD(join_after_cleanup)
{
    struct sockaddr_in a; qm_lo4(&a);
    STEP(1, qm_up() == 0);
    STEP(2, U(WSACleanup)() == 0);
    SOCKET r = U(WSAJoinLeaf)(QM_BOGUS_SOCKET, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL, JL_BOTH);
    STEP(3, r == INVALID_SOCKET);
    STEP(4, WSAERR() == WSANOTINITIALISED);
    return 0;
}

/* ---- WSANSPIoctl --------------------------------------------------------------------------------------- */

static HANDLE open_lookup(void)
{
    static const GUID svc = { 0x0002a803, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };   /* host address by name */
    WSAQUERYSETW q; GUID g = svc; HANDLE h = NULL;
    memset(&q, 0, sizeof q);
    q.dwSize = sizeof q; q.lpszServiceInstanceName = (LPWSTR)L"localhost"; q.lpServiceClassId = &g; q.dwNameSpace = NS_ALL;
    if (U(WSALookupServiceBeginW)(&q, LUP_RETURN_NAME, &h) != 0) return NULL;
    return h;
}
CHILD(nspioctl_before_startup)
{
    DWORD got = 0;
    STEP(1, UN(WSANSPIoctl) != NULL);
    STEP(2, UN(WSANSPIoctl)(NULL, 0, NULL, 0, NULL, 0, &got, NULL) == -1);
    STEP(3, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(nspioctl_before_startup_is_notinitialised)
{
    REQUIRE(UN(WSANSPIoctl));
    RUN_CHILD("nspioctl_before_startup", "", 20000);
}
TEST(nspioctl_null_byte_counter_is_einval)
{
    REQUIRE(UN(WSANSPIoctl)); QM_NEED_WSA();
    SETWSAERR(0);
    EXPECT_EQ(UN(WSANSPIoctl)(NULL, 0, NULL, 0, NULL, 0, NULL, NULL), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
}
TEST(nspioctl_null_byte_counter_is_checked_before_handle)
{
    REQUIRE(UN(WSANSPIoctl)); REQUIRE(U(WSALookupServiceEnd)); QM_NEED_WSA();
    HANDLE h = open_lookup(); if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(UN(WSANSPIoctl)(h, 0, NULL, 0, NULL, 0, NULL, NULL), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
    U(WSALookupServiceEnd)(h);
}
TEST(nspioctl_null_handle_is_invalid_handle)
{
    REQUIRE(UN(WSANSPIoctl)); QM_NEED_WSA();
    DWORD got = 0xABCD;
    SETWSAERR(0);
    EXPECT_EQ(UN(WSANSPIoctl)(NULL, 0, NULL, 0, NULL, 0, &got, NULL), -1);
    EXPECT_EQ(WSAERR(), ERROR_INVALID_HANDLE);
    EXPECT_EQ(got, 0xABCD);
}
TEST(nspioctl_ended_lookup_handle_is_invalid_handle)
{
    REQUIRE(UN(WSANSPIoctl)); REQUIRE(U(WSALookupServiceEnd)); QM_NEED_WSA();
    HANDLE h = open_lookup(); if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(U(WSALookupServiceEnd)(h), 0);
    DWORD got = 0;
    SETWSAERR(0);
    EXPECT_EQ(UN(WSANSPIoctl)(h, 0, NULL, 0, NULL, 0, &got, NULL), -1);
    EXPECT_EQ(WSAERR(), ERROR_INVALID_HANDLE);
}
TEST(nspioctl_live_dns_handle_unknown_code_is_opnotsupp)
{
    /* The name-space provider decides what an unknown control code means; the call must at least return
     * and leave the handle usable for the normal end-of-lookup call. The DNS provider has no control codes:
     * the answer is -1 / WSAEOPNOTSUPP. */
    REQUIRE(UN(WSANSPIoctl)); REQUIRE(U(WSALookupServiceEnd)); QM_NEED_WSA();
    HANDLE h = open_lookup(); if (!h) { t_skip("no lookup handle"); return; }
    DWORD got = 0;
    SETWSAERR(0);
    int r = UN(WSANSPIoctl)(h, 0x88000FFFu, NULL, 0, NULL, 0, &got, NULL);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(WSAERR(), WSAEOPNOTSUPP);
    EXPECT_EQ(U(WSALookupServiceEnd)(h), 0);
}
/* ---- provider advertisement (name-space v2) ------------------------------------------------------------ */

TEST(advertise_null_id_is_einval)
{
    REQUIRE(UN(WSAAdvertiseProvider));
    unsigned char tbl[0x80]; memset(tbl, 0, sizeof tbl);
    SETWSAERR(0);
    EXPECT_EQ(UN(WSAAdvertiseProvider)(NULL, tbl), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
}
TEST(advertise_null_routine_table_is_einval)
{
    REQUIRE(UN(WSAAdvertiseProvider));
    SETWSAERR(0);
    EXPECT_EQ(UN(WSAAdvertiseProvider)(&qm_guid_a, NULL), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
}
TEST(advertise_both_null_is_einval)
{
    REQUIRE(UN(WSAAdvertiseProvider));
    SETWSAERR(0);
    EXPECT_EQ(UN(WSAAdvertiseProvider)(NULL, NULL), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
}
TEST(advertise_empty_routine_table_is_einval)
{
    /* A table whose entry points are all NULL cannot be published. */
    REQUIRE(UN(WSAAdvertiseProvider));
    unsigned char tbl[0x80]; memset(tbl, 0, sizeof tbl);
    *(DWORD *)tbl = 0x58;                               /* cbSize filled in, pointers left NULL */
    SETWSAERR(0);
    EXPECT_EQ(UN(WSAAdvertiseProvider)(&qm_guid_a, tbl), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
}
TEST(advertise_needs_no_startup)
{
    REQUIRE(UN(WSAAdvertiseProvider));
    RUN_CHILD("advertise_no_startup", "", 20000);
}
CHILD(advertise_no_startup)
{
    STEP(1, UN(WSAAdvertiseProvider) != NULL);
    SETWSAERR(0);
    STEP(2, UN(WSAAdvertiseProvider)(NULL, NULL) == -1);
    STEP(3, WSAERR() == WSAEINVAL);                    /* argument error, not WSANOTINITIALISED */
    STEP(4, UN(WSAUnadvertiseProvider)(NULL) == -1);
    STEP(5, WSAERR() == WSAEINVAL);
    return 0;
}
TEST(unadvertise_null_id_is_einval)
{
    REQUIRE(UN(WSAUnadvertiseProvider));
    SETWSAERR(0);
    EXPECT_EQ(UN(WSAUnadvertiseProvider)(NULL), -1);
    EXPECT_EQ(WSAERR(), WSAEINVAL);
}
TEST(unadvertise_unknown_id_is_service_not_found)
{
    /* The id was never published. The outcome depends on the provider-stub service; record it. */
    REQUIRE(UN(WSAUnadvertiseProvider));
    SETWSAERR(0);
    int r = UN(WSAUnadvertiseProvider)(&qm_guid_a);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(WSAERR(), WSASERVICE_NOT_FOUND);
}
TEST(provider_complete_async_call_unknown_handle_fails)
{
    REQUIRE(UN(WSAProviderCompleteAsyncCall));
    static const ULONG_PTR hs[] = { 0, 1, 0x1234, (ULONG_PTR)-1 };
    for (int i = 0; i < QM_N(hs); i++) {
        SETWSAERR(0);
        int r = UN(WSAProviderCompleteAsyncCall)((HANDLE)hs[i], 0);
        t_check(r == -1, __FILE__, __LINE__, "complete(unknown handle)", "handle 0x%llx ret %d", (unsigned long long)hs[i], r);
        if (r == -1 && WSAERR() == 0) t_note("no error code recorded for handle 0x%llx", (unsigned long long)hs[i]);
    }
}

/* ---- no-op and alias exports -------------------------------------------------------------------------- */

TEST(wep_export_is_callable)
{
    /* A leftover 16-bit era export: it does nothing and returns to the caller. The returned value is not
     * part of the contract. */
    REQ_WEP();
    UN(WEP)();
    CHECK(1);
}
TEST(wep_export_lives_in_ws2_32)
{
    REQ_WEP();
    HMODULE m = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)UN(WEP), &m);
    CHECK(m == t_module("ws2_32.dll"));
}
TEST(wep_leaves_last_error_alone)
{
    REQ_WEP();
    SET_ERR(0x2468);
    UN(WEP)();
    EXPECT_EQ(GetLastError(), 0x2468);
}
TEST(freeaddrinfo_null_is_a_noop)
{
    REQUIRE(U(freeaddrinfo));
    SET_ERR(0x1357);
    U(freeaddrinfo)(NULL);
    EXPECT_EQ(GetLastError(), 0x1357);
}
TEST(freeaddrinfow_null_is_a_noop)
{
    FARPROC f = t_proc_in("ws2_32.dll", "FreeAddrInfoW");
    REQUIRE(f);
    SET_ERR(0x1357);
    ((void (WINAPI *)(void *))f)(NULL);
    EXPECT_EQ(GetLastError(), 0x1357);
}
TEST(freeaddrinfoex_null_is_a_noop)
{
    FARPROC f = t_proc_in("ws2_32.dll", "FreeAddrInfoEx"), w = t_proc_in("ws2_32.dll", "FreeAddrInfoExW");
    REQUIRE(f); REQUIRE(w);
    SET_ERR(0x1357);
    ((void (WINAPI *)(void *))f)(NULL);
    ((void (WINAPI *)(void *))w)(NULL);
    EXPECT_EQ(GetLastError(), 0x1357);
}
TEST(freeaddrinfo_null_needs_no_startup)
{
    REQUIRE(U(freeaddrinfo));
    RUN_CHILD("freeaddrinfo_no_startup", "", 20000);
}
CHILD(freeaddrinfo_no_startup)
{
    STEP(1, U(freeaddrinfo) != NULL);
    U(freeaddrinfo)(NULL);
    FARPROC w = t_proc_in("ws2_32.dll", "FreeAddrInfoW");
    STEP(2, w != NULL);
    ((void (WINAPI *)(void *))w)(NULL);
    return 0;
}
TEST(freeaddrinfo_narrow_and_wide_are_one_function)
{
    FARPROC n = t_proc_in("ws2_32.dll", "freeaddrinfo"), w = t_proc_in("ws2_32.dll", "FreeAddrInfoW");
    REQUIRE(n); REQUIRE(w);
    CHECK(n == w);
}
TEST(freeaddrinfoex_and_exw_are_one_function)
{
    FARPROC a = t_proc_in("ws2_32.dll", "FreeAddrInfoEx"), b = t_proc_in("ws2_32.dll", "FreeAddrInfoExW");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
TEST(freeaddrinfo_releases_a_real_chain)
{
    REQUIRE(U(getaddrinfo)); REQUIRE(U(freeaddrinfo)); QM_NEED_WSA();
    struct addrinfo h, *res = NULL; memset(&h, 0, sizeof h);
    h.ai_family = AF_INET; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_NUMERICHOST;
    EXPECT_EQ(U(getaddrinfo)("127.0.0.1", "80", &h, &res), 0);
    CHECK(res != NULL);
    U(freeaddrinfo)(res);
}

/* ---- __WSAFDIsSet --------------------------------------------------------------------------------------- */

typedef struct { u_int fd_count; SOCKET fd_array[512]; } bigset_t;

TEST(fdisset_empty_set_is_zero)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; memset(&s, 0, sizeof s);
    EXPECT_EQ(U(__WSAFDIsSet)(5, &s), 0);
    EXPECT_EQ(U(__WSAFDIsSet)(0, &s), 0);
}
TEST(fdisset_member_is_one_nonmember_is_zero)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; memset(&s, 0, sizeof s);
    s.fd_count = 3; s.fd_array[0] = 10; s.fd_array[1] = 20; s.fd_array[2] = 30;
    EXPECT_EQ(U(__WSAFDIsSet)(10, &s), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(20, &s), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(30, &s), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(15, &s), 0);
    EXPECT_EQ(U(__WSAFDIsSet)(0, &s), 0);
}
TEST(fdisset_entries_past_the_count_are_ignored)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; memset(&s, 0, sizeof s);
    s.fd_count = 1; s.fd_array[0] = 10; s.fd_array[1] = 99;
    EXPECT_EQ(U(__WSAFDIsSet)(99, &s), 0);
}
TEST(fdisset_duplicate_members_still_report_one)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; memset(&s, 0, sizeof s);
    s.fd_count = 3; s.fd_array[0] = 7; s.fd_array[1] = 7; s.fd_array[2] = 7;
    EXPECT_EQ(U(__WSAFDIsSet)(7, &s), 1);
}
TEST(fdisset_scans_beyond_the_default_set_size)
{
    /* No clamp to FD_SETSIZE: a caller that built a larger set (FD_SETSIZE redefined) is honoured. */
    REQUIRE(U(__WSAFDIsSet));
    bigset_t b; memset(&b, 0, sizeof b);
    b.fd_count = 300;
    for (u_int i = 0; i < 300; i++) b.fd_array[i] = 1000 + i;
    EXPECT_EQ(U(__WSAFDIsSet)(1000 + 299, (fd_set *)&b), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(1000 + 64, (fd_set *)&b), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(1000 + 300, (fd_set *)&b), 0);
}
TEST(fdisset_matches_the_last_entry_and_the_first)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; memset(&s, 0, sizeof s);
    s.fd_count = FD_SETSIZE;
    for (u_int i = 0; i < FD_SETSIZE; i++) s.fd_array[i] = 100 + i;
    EXPECT_EQ(U(__WSAFDIsSet)(100, &s), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(100 + FD_SETSIZE - 1, &s), 1);
    EXPECT_EQ(U(__WSAFDIsSet)(100 + FD_SETSIZE, &s), 0);
}
TEST(fdisset_compares_full_socket_width)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; memset(&s, 0, sizeof s);
    s.fd_count = 1; s.fd_array[0] = (SOCKET)0x100000005ULL;
    EXPECT_EQ(U(__WSAFDIsSet)((SOCKET)0x100000005ULL, &s), 1);
    EXPECT_EQ(U(__WSAFDIsSet)((SOCKET)5, &s), 0);
}
TEST(fdisset_needs_no_startup_and_keeps_error_slot)
{
    REQUIRE(U(__WSAFDIsSet));
    RUN_CHILD("fdisset_no_startup", "", 20000);
}
CHILD(fdisset_no_startup)
{
    fd_set s; memset(&s, 0, sizeof s); s.fd_count = 1; s.fd_array[0] = 3;
    STEP(1, U(__WSAFDIsSet) != NULL);
    SET_ERR(0x777);
    STEP(2, U(__WSAFDIsSet)(3, &s) == 1);
    STEP(3, U(__WSAFDIsSet)(4, &s) == 0);
    STEP(4, GetLastError() == 0x777);
    return 0;
}
TEST(fd_macros_agree_with_the_helper)
{
    REQUIRE(U(__WSAFDIsSet));
    fd_set s; FD_ZERO(&s);
    FD_SET(11, &s); FD_SET(12, &s); FD_SET(11, &s);       /* duplicate add is ignored by the macro */
    EXPECT_EQ(s.fd_count, 2);
    EXPECT_EQ(U(__WSAFDIsSet)(11, &s), 1);
    FD_CLR(11, &s);
    EXPECT_EQ(U(__WSAFDIsSet)(11, &s), 0);
    EXPECT_EQ(U(__WSAFDIsSet)(12, &s), 1);
}

/* ---- WSAEnumNetworkEvents on things that are not sockets --------------------------------------------- */

TEST(enumevents_non_socket_handles_are_enotsock)
{
    REQUIRE(U(WSAEnumNetworkEvents)); QM_NEED_WSA();
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE mtx = CreateMutexA(NULL, FALSE, NULL);
    char tmp[MAX_PATH]; t_tmpfile(tmp, sizeof tmp, "qm_enum.bin");
    HANDLE f = CreateFileA(tmp, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE rows[] = { ev, mtx, f, GetCurrentProcess(), GetCurrentThread() };
    for (int i = 0; i < QM_N(rows); i++) {
        WSANETWORKEVENTS ne; memset(&ne, 0x5A, sizeof ne);
        SETWSAERR(0);
        int r = U(WSAEnumNetworkEvents)((SOCKET)rows[i], NULL, &ne);
        t_check(r == SOCKET_ERROR && WSAERR() == WSAENOTSOCK, __FILE__, __LINE__, "enum(non-socket)", "row %d ret %d err %d", i, r, WSAERR());
        t_check(ne.lNetworkEvents == 0x5A5A5A5A, __FILE__, __LINE__, "enum(non-socket) output untouched", "row %d", i);
    }
    CloseHandle(f); CloseHandle(mtx); CloseHandle(ev);
}
TEST(enumevents_with_event_argument_on_non_socket_is_enotsock)
{
    REQUIRE(U(WSAEnumNetworkEvents)); QM_NEED_WSA();
    HANDLE ev = CreateEventA(NULL, TRUE, TRUE, NULL);
    WSANETWORKEVENTS ne;
    EXPECT_EQ(U(WSAEnumNetworkEvents)((SOCKET)ev, ev, &ne), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);       /* a rejected call does not reset the event */
    CloseHandle(ev);
}
TEST(enumevents_invalid_values_are_enotsock)
{
    REQUIRE(U(WSAEnumNetworkEvents)); QM_NEED_WSA();
    SOCKET rows[] = { INVALID_SOCKET, 0, QM_BOGUS_SOCKET };
    for (int i = 0; i < 3; i++) {
        WSANETWORKEVENTS ne;
        SETWSAERR(0);
        int r = U(WSAEnumNetworkEvents)(rows[i], NULL, &ne);
        t_check(r == SOCKET_ERROR && WSAERR() == WSAENOTSOCK, __FILE__, __LINE__, "enum(bad socket)", "row %d ret %d err %d", i, r, WSAERR());
    }
}
TEST(enumevents_closed_socket_is_enotsock)
{
    REQUIRE(U(WSAEnumNetworkEvents)); QM_NEED_WSA();
    SOCKET s = qm_sock(SOCK_STREAM); qm_close(s);
    WSANETWORKEVENTS ne;
    EXPECT_EQ(U(WSAEnumNetworkEvents)(s, NULL, &ne), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
}
CHILD(enumevents_before_startup)
{
    WSANETWORKEVENTS ne;
    STEP(1, U(WSAEnumNetworkEvents) != NULL);
    STEP(2, U(WSAEnumNetworkEvents)(QM_BOGUS_SOCKET, NULL, &ne) == SOCKET_ERROR);
    STEP(3, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(enumevents_before_startup_is_notinitialised)
{
    REQUIRE(U(WSAEnumNetworkEvents));
    RUN_CHILD("enumevents_before_startup", "", 20000);
}

/* ---- Win32 and Winsock errors share one slot ----------------------------------------------------------- */

TEST(errslot_win32_failure_is_visible_to_wsagetlasterror)
{
    REQUIRE(U(WSAGetLastError));
    SET_ERR(0);
    CHECK(!CloseHandle((HANDLE)(ULONG_PTR)0x7FFC));
    EXPECT_EQ(WSAERR(), ERROR_INVALID_HANDLE);
    EXPECT_EQ(WSA_INVALID_HANDLE, ERROR_INVALID_HANDLE);
}
TEST(errslot_winsock_failure_is_visible_to_getlasterror)
{
    REQUIRE(U(closesocket)); QM_NEED_WSA();
    SET_ERR(0);
    EXPECT_EQ(U(closesocket)(QM_BOGUS_SOCKET), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAENOTSOCK);
}
TEST(errslot_invalid_handle_versus_notsock)
{
    /* The same bad value is a bad handle to the event API and a non-socket to the socket API. */
    REQUIRE(U(WSACloseEvent)); REQUIRE(U(closesocket)); QM_NEED_WSA();
    HANDLE bad = (HANDLE)(ULONG_PTR)QM_BOGUS_SOCKET;
    SETWSAERR(0);
    EXPECT_EQ(U(WSACloseEvent)(bad), FALSE);
    EXPECT_EQ(WSAERR(), WSA_INVALID_HANDLE);
    SETWSAERR(0);
    EXPECT_EQ(U(closesocket)((SOCKET)bad), SOCKET_ERROR);
    EXPECT_EQ(WSAERR(), WSAENOTSOCK);
}
TEST(errslot_event_failure_does_not_need_startup)
{
    REQUIRE(U(WSACloseEvent));
    RUN_CHILD("errslot_event_no_startup", "", 20000);
}
CHILD(errslot_event_no_startup)
{
    STEP(1, U(WSACloseEvent) != NULL && U(WSASetEvent) != NULL && U(WSAResetEvent) != NULL);
    SET_ERR(0);
    STEP(2, U(WSACloseEvent)(NULL) == FALSE);
    STEP(3, GetLastError() == WSA_INVALID_HANDLE);
    SET_ERR(0);
    STEP(4, U(WSASetEvent)(NULL) == FALSE);
    STEP(5, GetLastError() == ERROR_INVALID_HANDLE);
    SET_ERR(0);
    STEP(6, U(WSAResetEvent)(NULL) == FALSE);
    STEP(7, GetLastError() == ERROR_INVALID_HANDLE);
    HANDLE e = U(WSACreateEvent)();
    STEP(8, e != WSA_INVALID_EVENT);
    STEP(9, U(WSACloseEvent)(e) == TRUE);
    return 0;
}
TEST(errslot_wait_for_multiple_events_bad_count_is_invalid_parameter)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); QM_NEED_WSA();
    HANDLE e = U(WSACreateEvent)();
    SETWSAERR(0);
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(0, &e, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    EXPECT_EQ(WSAERR(), WSA_INVALID_PARAMETER);
    HANDLE many[WSA_MAXIMUM_WAIT_EVENTS + 1];
    for (int i = 0; i < WSA_MAXIMUM_WAIT_EVENTS + 1; i++) many[i] = e;
    SETWSAERR(0);
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(WSA_MAXIMUM_WAIT_EVENTS + 1, many, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    EXPECT_EQ(WSAERR(), WSA_INVALID_PARAMETER);
    U(WSACloseEvent)(e);
}
TEST(errslot_wait_for_multiple_events_bad_handle_is_invalid_handle)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); QM_NEED_WSA();
    HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL); CloseHandle(e);
    SETWSAERR(0);
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE), WSA_WAIT_FAILED);
    EXPECT_EQ(WSAERR(), WSA_INVALID_HANDLE);
}
TEST(errslot_wait_timeout_does_not_touch_the_slot)
{
    REQUIRE(U(WSAWaitForMultipleEvents)); QM_NEED_WSA();
    HANDLE e = U(WSACreateEvent)();
    SETWSAERR(WSAEMFILE);
    EXPECT_EQ(U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    EXPECT_EQ(WSAERR(), WSAEMFILE);
    U(WSACloseEvent)(e);
}
TEST(errslot_cancel_async_request_unknown_handles)
{
    REQUIRE(U(WSACancelAsyncRequest)); QM_NEED_WSA();
    /* handle 0 is left out: it equals the "no current task" marker once an async worker exists */
    static const ULONG_PTR hs[] = { 1, 0x1234, 0xFFFFFFFFu, (ULONG_PTR)-1 };
    for (int i = 0; i < QM_N(hs); i++) {
        SETWSAERR(0);
        int r = U(WSACancelAsyncRequest)((HANDLE)hs[i]);
        t_check(r == SOCKET_ERROR && WSAERR() == WSAEINVAL, __FILE__, __LINE__, "cancel(unknown)", "handle 0x%llx ret %d err %d", (unsigned long long)hs[i], r, WSAERR());
    }
}
CHILD(cancel_async_before_startup)
{
    STEP(1, U(WSACancelAsyncRequest) != NULL);
    STEP(2, U(WSACancelAsyncRequest)((HANDLE)(ULONG_PTR)1) == SOCKET_ERROR);
    STEP(3, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(errslot_cancel_async_request_before_startup_is_notinitialised)
{
    REQUIRE(U(WSACancelAsyncRequest));
    RUN_CHILD("cancel_async_before_startup", "", 20000);
}
TEST(errslot_isblocking_is_false_and_clears_the_slot)
{
    /* With a started stack the per-thread lookup inside the call is a TLS read, which resets the thread's
     * error slot to 0 as a side effect: the previous value does not survive. */
    REQUIRE(U(WSAIsBlocking)); QM_NEED_WSA();
    SETWSAERR(WSAECONNRESET);
    EXPECT_EQ(U(WSAIsBlocking)(), FALSE);
    EXPECT_EQ(WSAERR(), 0);
}

/* ---- the event objects behind WSACreateEvent --------------------------------------------------------- */

typedef struct { ULONG Attributes; ACCESS_MASK GrantedAccess; ULONG HandleCount; ULONG PointerCount; ULONG Reserved[10]; } basic_info_t;
typedef LONG (NTAPI *NtQueryObject_t)(HANDLE, int, PVOID, ULONG, PULONG);

TEST(event_object_has_full_access)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    NtQueryObject_t q = (NtQueryObject_t)t_proc_in("ntdll.dll", "NtQueryObject");
    REQUIRE(q);
    HANDLE e = U(WSACreateEvent)();
    basic_info_t bi; ULONG got = 0; memset(&bi, 0, sizeof bi);
    LONG st = q(e, 0, &bi, sizeof bi, &got);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(bi.GrantedAccess, 0x1F0003);               /* EVENT_ALL_ACCESS */
    EXPECT_EQ(bi.HandleCount, 1);
    EXPECT_EQ(bi.Attributes & 2, 0);                     /* not inheritable */
    U(WSACloseEvent)(e);
}
TEST(event_object_type_is_event)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    NtQueryObject_t q = (NtQueryObject_t)t_proc_in("ntdll.dll", "NtQueryObject");
    REQUIRE(q);
    HANDLE e = U(WSACreateEvent)();
    unsigned char buf[256]; ULONG got = 0; memset(buf, 0, sizeof buf);
    LONG st = q(e, 2, buf, sizeof buf, &got);            /* ObjectTypeInformation */
    EXPECT_EQ(st, 0);
    if (st == 0) {
        UNICODE_STRING *u = (UNICODE_STRING *)buf;
        CHECK(u->Length == 10 && !wcsncmp(u->Buffer, L"Event", 5));
    }
    U(WSACloseEvent)(e);
}
TEST(event_object_is_unnamed)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent));
    NtQueryObject_t q = (NtQueryObject_t)t_proc_in("ntdll.dll", "NtQueryObject");
    REQUIRE(q);
    HANDLE e = U(WSACreateEvent)();
    unsigned char buf[512]; ULONG got = 0; memset(buf, 0xAA, sizeof buf);
    LONG st = q(e, 1, buf, sizeof buf, &got);            /* ObjectNameInformation */
    EXPECT_EQ(st, 0);
    if (st == 0) EXPECT_EQ(((UNICODE_STRING *)buf)->Length, 0);
    U(WSACloseEvent)(e);
}
TEST(event_handles_from_wsa_and_kernel_are_interchangeable)
{
    REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSACloseEvent)); REQUIRE(U(WSASetEvent));
    HANDLE e = U(WSACreateEvent)();
    CHECK(SetEvent(e));
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);        /* manual reset: still signalled */
    CHECK(ResetEvent(e));
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_TIMEOUT);
    CHECK(U(WSASetEvent)(e));
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);
    CHECK(CloseHandle(e));                                       /* closed through the Win32 call */
    SET_ERR(0);
    CHECK(!U(WSACloseEvent)(e));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(event_close_of_a_mutex_and_a_file_works_like_closehandle)
{
    REQUIRE(U(WSACloseEvent));
    HANDLE m = CreateMutexA(NULL, FALSE, NULL);
    CHECK(U(WSACloseEvent)(m));
    DWORD fl;
    CHECK(!GetHandleInformation(m, &fl));
}
