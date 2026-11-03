/* IPv6 and dual-stack behaviour of the address-list query, protocol-info reporting, AcceptEx / ConnectEx,
 * WSAConnect / WSAAccept, and readiness reporting (select, WSAPoll, WSAEventSelect) on IPv6 sockets.
 * Measures: shape of SIO_ADDRESS_LIST_QUERY output for IPv6 and IPv4 sockets (family, sockaddr length,
 * scope identifiers of link-local entries, size protocol); the provider description of IPv6 sockets;
 * the address-buffer size rule of AcceptEx for IPv6; how a dual-stack listener reports v4-mapped peers
 * through GetAcceptExSockaddrs; ConnectEx binding rules; readable/writable reporting for connects and
 * accepts.  Loopback only, bounded waits. */
#include "d6.h"

/* ---- SIO_ADDRESS_LIST_QUERY ----------------------------------------------------------------- */
static int addr_list(SOCKET s, char *buf, DWORD cap, DWORD *got) {
    *got = 0;
    return U(WSAIoctl)(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, cap, got, NULL, NULL);
}
#define ALHDR ((DWORD)offsetof(SOCKET_ADDRESS_LIST, Address))

TEST(ds6_addrlist_v6_size_query_reports_efault_with_size) {
    SOCKET s; DWORD got = 0; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    d_seterr(0);
    rc = U(WSAIoctl)(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0, &got, NULL, NULL);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEFAULT);
    CHECK(got >= ALHDR);
    d_close(s);
}

TEST(ds6_addrlist_v6_entries_are_ipv6_sockaddrs) {
    SOCKET s; static char buf[8192]; DWORD got; SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)buf; LONG i;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(addr_list(s, buf, sizeof buf, &got) == 0);
    CHECK(l->iAddressCount >= 0);
    CHECK(got >= ALHDR + (DWORD)l->iAddressCount * sizeof(SOCKET_ADDRESS));
    for (i = 0; i < l->iAddressCount; i++) {
        SOCKET_ADDRESS *a = &l->Address[i];
        EXPECT_EQ(a->iSockaddrLength, SZ_SA6);
        CHECK((char *)a->lpSockaddr >= buf && (char *)a->lpSockaddr + a->iSockaddrLength <= buf + got);   /* inside the returned block */
        EXPECT_EQ(a->lpSockaddr->sa_family, AF_INET6);
    }
    d_close(s);
}

TEST(ds6_addrlist_v4_entries_are_ipv4_sockaddrs) {
    SOCKET s; static char buf[8192]; DWORD got; SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)buf; LONG i;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_DGRAM);
    CHECK(addr_list(s, buf, sizeof buf, &got) == 0);
    for (i = 0; i < l->iAddressCount; i++) {
        EXPECT_EQ(l->Address[i].iSockaddrLength, SZ_SA4);
        EXPECT_EQ(l->Address[i].lpSockaddr->sa_family, AF_INET);
    }
    d_close(s);
}

TEST(ds6_addrlist_v6_link_local_entries_carry_scope) {
    SOCKET s; static char buf[8192]; DWORD got; SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)buf; LONG i; int ll = 0;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(addr_list(s, buf, sizeof buf, &got) == 0);
    for (i = 0; i < l->iAddressCount; i++) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)l->Address[i].lpSockaddr;
        if (a->sin6_addr.u.Byte[0] == 0xfe && (a->sin6_addr.u.Byte[1] & 0xc0) == 0x80) {
            ll++;
            CHECK(a->sin6_scope_id != 0);    /* a link-local address is meaningless without its zone */
        }
        EXPECT_EQ(a->sin6_port, 0);
    }
    t_note("link-local entries in the IPv6 address list: %s", ll ? "present" : "none");
    d_close(s);
}

TEST(ds6_addrlist_v6_contains_loopback_note) {
    SOCKET s; static char buf[8192]; DWORD got; SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)buf; LONG i; int found = 0;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(addr_list(s, buf, sizeof buf, &got) == 0);
    for (i = 0; i < l->iAddressCount; i++)
        if (is_v6_loop((struct sockaddr_in6 *)l->Address[i].lpSockaddr)) found = 1;
    t_note("::1 in the IPv6 address list: %s", found ? "yes" : "no");
    d_close(s);
}

TEST(ds6_addrlist_tcp_and_udp_v6_sockets_agree) {
    SOCKET a, b; static char b1[8192], b2[8192]; DWORD g1, g2;
    NEED_V6();
    a = d_sock(AF_INET6, SOCK_STREAM); b = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(addr_list(a, b1, sizeof b1, &g1) == 0);
    CHECK(addr_list(b, b2, sizeof b2, &g2) == 0);
    EXPECT_EQ(((SOCKET_ADDRESS_LIST *)b1)->iAddressCount, ((SOCKET_ADDRESS_LIST *)b2)->iAddressCount);
    d_close(a); d_close(b);
}

TEST(ds6_addrlist_v6_small_buffer_reports_needed_size) {
    SOCKET s; static char buf[8192]; DWORD full, got = 0; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(addr_list(s, buf, sizeof buf, &full) == 0);
    if (((SOCKET_ADDRESS_LIST *)buf)->iAddressCount == 0) { d_close(s); t_skip("no IPv6 addresses to size"); return; }
    d_seterr(0);
    rc = U(WSAIoctl)(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, full - 1, &got, NULL, NULL);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEFAULT);
    EXPECT_EQ(got, full);
    d_close(s);
}

/* ---- provider description ------------------------------------------------------------------ */
static int proto_info(SOCKET s, WSAPROTOCOL_INFOW *pi) {
    int l = sizeof *pi; memset(pi, 0, sizeof *pi);
    return d_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, pi, &l);
}

TEST(ds6_protoinfo_tcp_v6) {
    SOCKET s; WSAPROTOCOL_INFOW pi;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(proto_info(s, &pi) == 0);
    EXPECT_EQ(pi.iAddressFamily, AF_INET6);
    EXPECT_EQ(pi.iSocketType, SOCK_STREAM);
    EXPECT_EQ(pi.iProtocol, IPPROTO_TCP);
    EXPECT_EQ(pi.iMaxSockAddr, SZ_SA6);
    EXPECT_EQ(pi.iMinSockAddr, SZ_SA6);
    CHECK(!lstrcmpW(pi.szProtocol, L"MSAFD Tcpip [TCP/IPv6]"));
    d_close(s);
}

TEST(ds6_protoinfo_udp_v6) {
    SOCKET s; WSAPROTOCOL_INFOW pi;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(proto_info(s, &pi) == 0);
    EXPECT_EQ(pi.iAddressFamily, AF_INET6);
    EXPECT_EQ(pi.iSocketType, SOCK_DGRAM);
    EXPECT_EQ(pi.iProtocol, IPPROTO_UDP);
    EXPECT_EQ(pi.iMaxSockAddr, SZ_SA6);
    CHECK(!lstrcmpW(pi.szProtocol, L"MSAFD Tcpip [UDP/IPv6]"));
    CHECK((pi.dwServiceFlags1 & XP1_CONNECTIONLESS) != 0);
    CHECK((pi.dwServiceFlags1 & XP1_MESSAGE_ORIENTED) != 0);
    d_close(s);
}

TEST(ds6_protoinfo_v4_for_contrast) {
    SOCKET s; WSAPROTOCOL_INFOW pi;
    if (!d_up()) return;
    s = d_sock(AF_INET, SOCK_STREAM);
    CHECK(proto_info(s, &pi) == 0);
    EXPECT_EQ(pi.iAddressFamily, AF_INET);
    EXPECT_EQ(pi.iMaxSockAddr, SZ_SA4);
    CHECK(!lstrcmpW(pi.szProtocol, L"MSAFD Tcpip [TCP/IP]"));
    d_close(s);
}

TEST(ds6_protoinfo_dualstack_switch_does_not_change_family) {
    SOCKET s; WSAPROTOCOL_INFOW pi;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    CHECK(proto_info(s, &pi) == 0);
    EXPECT_EQ(pi.iAddressFamily, AF_INET6);
    CHECK(!lstrcmpW(pi.szProtocol, L"MSAFD Tcpip [TCP/IPv6]"));
    d_close(s);
}

TEST(ds6_sockopt_max_msg_size_v6_udp_note) {
    SOCKET s4, s6; int v4 = 0, v6 = 0;
    NEED_V6();
    s4 = d_sock(AF_INET, SOCK_DGRAM); s6 = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_getint(s4, SOL_SOCKET, SO_MAX_MSG_SIZE, &v4) == 0);
    CHECK(d_getint(s6, SOL_SOCKET, SO_MAX_MSG_SIZE, &v6) == 0);
    CHECK(v4 > 0 && v6 > 0);
    t_note("SO_MAX_MSG_SIZE v6 %s v4", v6 > v4 ? "exceeds" : v6 == v4 ? "equals" : "is below");
    d_close(s4); d_close(s6);
}

/* ---- WSAConnect / WSAAccept -------------------------------------------------------------------- */
TEST(ds6_wsaconnect_and_wsaaccept_on_dualstack) {
    lsn l; SOCKET c, a; struct sockaddr_in6 to, from; int n = sizeof from;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    c = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(d_setint(c, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    mk6(&to, K_MAP_LOOP, l.port);
    CHECK(U(WSAConnect)(c, (struct sockaddr *)&to, sizeof to, NULL, NULL, NULL, NULL) == 0);
    CHECK(d_readable(l.s, 3000));
    a = U(WSAAccept)(l.s, (struct sockaddr *)&from, &n, NULL, 0);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(n, SZ_SA6);
    CHECK(is_mapped_loop(&from));            /* the dual-stack client travels over IPv4 */
    d_close(a); d_close(c); d_close(l.s);
}

static int cond_calls;
static int CALLBACK cond_refuse(LPWSABUF caller, LPWSABUF callee, LPQOS a, LPQOS b, LPWSABUF cid, LPWSABUF cd, GROUP *g, DWORD_PTR ud) {
    struct sockaddr_in6 *sa = (struct sockaddr_in6 *)caller->buf;
    cond_calls++;
    *(int *)ud = (caller->len == (ULONG)SZ_SA6 && sa->sin6_family == AF_INET6);
    return CF_REJECT;
}
TEST(ds6_wsaaccept_condition_sees_ipv6_caller_address) {
    lsn l; SOCKET c, a; struct sockaddr_in6 to; int seen = 0;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&to, K_LOOP, l.port);
    cond_calls = 0;
    {
        unsigned long nb = 1; U(ioctlsocket)(c, FIONBIO, &nb);
        d_connect(c, &to, sizeof to);
    }
    CHECK(d_readable(l.s, 3000));
    d_seterr(0);
    a = U(WSAAccept)(l.s, NULL, NULL, cond_refuse, (DWORD_PTR)&seen);
    CHECK(a == INVALID_SOCKET);
    EXPECT_EQ(d_err(), WSAECONNREFUSED);
    EXPECT_EQ(cond_calls, 1);
    EXPECT_EQ(seen, 1);
    d_close(c); d_close(l.s);
}

/* ---- AcceptEx / ConnectEx ---------------------------------------------------------------------- */
static LPFN_ACCEPTEX get_acceptex(SOCKET s) {
    GUID g = WSAID_ACCEPTEX; LPFN_ACCEPTEX f = NULL; DWORD got;
    U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &got, NULL, NULL);
    return f;
}
static LPFN_GETACCEPTEXSOCKADDRS get_addrs(SOCKET s) {
    GUID g = WSAID_GETACCEPTEXSOCKADDRS; LPFN_GETACCEPTEXSOCKADDRS f = NULL; DWORD got;
    U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &got, NULL, NULL);
    return f;
}
static LPFN_CONNECTEX get_connectex(SOCKET s) {
    GUID g = WSAID_CONNECTEX; LPFN_CONNECTEX f = NULL; DWORD got;
    U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &got, NULL, NULL);
    return f;
}
#define AEX_ADDR (SZ_SA6 + 16)

TEST(ds6_acceptex_undersized_address_space_is_accepted_as_pending) {
    lsn l; SOCKET a, b2; static OVERLAPPED ov2; LPFN_ACCEPTEX ax; static char buf[256]; DWORD got = 0; static OVERLAPPED ov; BOOL ok;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    ax = get_acceptex(l.s);
    if (!ax) { t_skip("AcceptEx unavailable"); d_close(l.s); return; }
    a = d_sock(AF_INET6, SOCK_STREAM);
    memset(&ov, 0, sizeof ov);
    d_seterr(0);
    ok = ax(l.s, a, buf, 0, SZ_SA6 + 15, AEX_ADDR, &got, &ov);
    CHECK(!ok);
    EXPECT_EQ(d_err(), WSA_IO_PENDING);                  /* the local length is only checked when a connection arrives */
    b2 = d_sock(AF_INET6, SOCK_STREAM);                  /* a fresh accept socket: the first one now has an accept pending */
    memset(&ov2, 0, sizeof ov2);
    d_seterr(0);
    ok = ax(l.s, b2, buf, 0, AEX_ADDR, SZ_SA6 + 15, &got, &ov2);
    CHECK(!ok);
    EXPECT_EQ(d_err(), WSA_IO_PENDING);                  /* nor is the remote length checked up front */
    d_close(b2); d_close(a); d_close(l.s);
}

TEST(ds6_acceptex_v4_sized_address_space_on_v6_listener_is_accepted_as_pending) {
    lsn l; SOCKET a; LPFN_ACCEPTEX ax; static char buf[256]; DWORD got = 0; static OVERLAPPED ov; BOOL ok;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    ax = get_acceptex(l.s);
    if (!ax) { t_skip("AcceptEx unavailable"); d_close(l.s); return; }
    a = d_sock(AF_INET6, SOCK_STREAM);
    memset(&ov, 0, sizeof ov);
    d_seterr(0);
    ok = ax(l.s, a, buf, 0, SZ_SA4 + 16, SZ_SA4 + 16, &got, &ov);
    CHECK(!ok);
    EXPECT_EQ(d_err(), WSA_IO_PENDING);                  /* accepted as pending: nothing rejects the sizes up front */
    d_close(a); d_close(l.s);
}

/* returns 1 and fills buf when an overlapped AcceptEx completed with a connection from `client` */
static int acceptex_round(lsn *l, SOCKET acc, char *buf, DWORD buflen, LPFN_ACCEPTEX ax, SOCKET client, const void *to, int tolen) {
    OVERLAPPED ov; DWORD got = 0, flags = 0; BOOL ok;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ok = ax(l->s, acc, buf, 0, AEX_ADDR, AEX_ADDR, &got, &ov);
    if (!ok && d_err() != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); return 0; }
    if (d_connect(client, to, tolen)) { CloseHandle(ov.hEvent); return 0; }
    if (WaitForSingleObject(ov.hEvent, 3000) != WAIT_OBJECT_0) { CancelIo((HANDLE)l->s); CloseHandle(ov.hEvent); return 0; }
    ok = U(WSAGetOverlappedResult)(l->s, &ov, &got, FALSE, &flags);
    CloseHandle(ov.hEvent);
    return ok ? 1 : 0;
}

TEST(ds6_acceptex_reports_v6_remote_and_local_addresses) {
    lsn l; SOCKET a, c; LPFN_ACCEPTEX ax; LPFN_GETACCEPTEXSOCKADDRS ga; static char buf[256];
    struct sockaddr *lp = NULL, *rp = NULL; INT ll = 0, rl = 0; struct sockaddr_in6 to;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    ax = get_acceptex(l.s); ga = get_addrs(l.s);
    if (!ax || !ga) { t_skip("AcceptEx unavailable"); d_close(l.s); return; }
    a = d_sock(AF_INET6, SOCK_STREAM); c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&to, K_LOOP, l.port);
    CHECK(acceptex_round(&l, a, buf, sizeof buf, ax, c, &to, sizeof to));
    ga(buf, 0, AEX_ADDR, AEX_ADDR, &lp, &ll, &rp, &rl);
    EXPECT_EQ(ll, SZ_SA6);
    EXPECT_EQ(rl, SZ_SA6);
    CHECK(lp && is_v6_loop((struct sockaddr_in6 *)lp));
    CHECK(rp && is_v6_loop((struct sockaddr_in6 *)rp));
    if (lp) EXPECT_EQ(((struct sockaddr_in6 *)lp)->sin6_port, l.port);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_acceptex_dualstack_reports_mapped_remote_for_v4_client) {
    lsn l; SOCKET a, c; LPFN_ACCEPTEX ax; LPFN_GETACCEPTEXSOCKADDRS ga; static char buf[256];
    struct sockaddr *lp = NULL, *rp = NULL; INT ll = 0, rl = 0; struct sockaddr_in to;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    ax = get_acceptex(l.s); ga = get_addrs(l.s);
    if (!ax || !ga) { t_skip("AcceptEx unavailable"); d_close(l.s); return; }
    a = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(d_setint(a, IPPROTO_IPV6, IPV6_V6ONLY, 0) == 0);
    c = d_sock(AF_INET, SOCK_STREAM);
    mk4(&to, 1, l.port);
    CHECK(acceptex_round(&l, a, buf, sizeof buf, ax, c, &to, sizeof to));
    ga(buf, 0, AEX_ADDR, AEX_ADDR, &lp, &ll, &rp, &rl);
    EXPECT_EQ(rl, SZ_SA6);
    CHECK(rp && is_mapped_loop((struct sockaddr_in6 *)rp));
    CHECK(lp && is_mapped_loop((struct sockaddr_in6 *)lp));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_acceptex_accepted_socket_needs_update_context_for_names) {
    lsn l; SOCKET a, c; LPFN_ACCEPTEX ax; static char buf[256]; struct sockaddr_in6 to, nm; int n = sizeof nm;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    ax = get_acceptex(l.s);
    if (!ax) { t_skip("AcceptEx unavailable"); d_close(l.s); return; }
    a = d_sock(AF_INET6, SOCK_STREAM); c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&to, K_LOOP, l.port);
    CHECK(acceptex_round(&l, a, buf, sizeof buf, ax, c, &to, sizeof to));
    d_seterr(0);
    EQC(d_peer(a, &nm, &n), SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENOTCONN);
    CHECK(d_sso(a, SOL_SOCKET, 0x700B /* SO_UPDATE_ACCEPT_CONTEXT */, &l.s, sizeof l.s) == 0);
    n = sizeof nm;
    CHECK(d_peer(a, &nm, &n) == 0);
    CHECK(is_v6_loop(&nm));
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_connectex_requires_bound_socket) {
    lsn l; SOCKET c; LPFN_CONNECTEX cx; struct sockaddr_in6 to; OVERLAPPED ov; BOOL ok;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    cx = get_connectex(c);
    if (!cx) { t_skip("ConnectEx unavailable"); d_close(c); d_close(l.s); return; }
    mk6(&to, K_LOOP, l.port);
    memset(&ov, 0, sizeof ov);
    d_seterr(0);
    ok = cx(c, (struct sockaddr *)&to, sizeof to, NULL, 0, NULL, &ov);
    CHECK(!ok);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(c); d_close(l.s);
}

TEST(ds6_connectex_to_v6_loopback_completes) {
    lsn l; SOCKET c, a; LPFN_CONNECTEX cx; struct sockaddr_in6 to, any; OVERLAPPED ov; BOOL ok; DWORD got = 0, fl = 0, sent = 0;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    cx = get_connectex(c);
    if (!cx) { t_skip("ConnectEx unavailable"); d_close(c); d_close(l.s); return; }
    mk6(&any, K_ANY, 0);
    CHECK(d_bind(c, &any, sizeof any) == 0);
    mk6(&to, K_LOOP, l.port);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ok = cx(c, (struct sockaddr *)&to, sizeof to, (PVOID)"hi", 2, &sent, &ov);
    if (!ok) EXPECT_EQ(d_err(), ERROR_IO_PENDING);
    CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
    CHECK(U(WSAGetOverlappedResult)(c, &ov, &got, FALSE, &fl));
    a = d_accept_to(l.s, 3000, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    if (a != INVALID_SOCKET) {
        char b[8];
        EQC(d_recv_to(a, b, sizeof b, 3000), 2);
        CHECK(!memcmp(b, "hi", 2));
    }
    CloseHandle(ov.hEvent);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_connectex_closed_port_completes_with_refused) {
    lsn l; SOCKET c; LPFN_CONNECTEX cx; struct sockaddr_in6 to, any; OVERLAPPED ov; BOOL ok; DWORD got = 0, fl = 0; unsigned short p;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    p = l.port; d_close(l.s);
    c = d_sock(AF_INET6, SOCK_STREAM);
    cx = get_connectex(c);
    if (!cx) { t_skip("ConnectEx unavailable"); d_close(c); return; }
    mk6(&any, K_ANY, 0);
    CHECK(d_bind(c, &any, sizeof any) == 0);
    mk6(&to, K_LOOP, p);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ok = cx(c, (struct sockaddr *)&to, sizeof to, NULL, 0, NULL, &ov);
    if (!ok && d_err() != ERROR_IO_PENDING) { EXPECT_EQ(d_err(), WSAECONNREFUSED); }
    else {
        CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
        d_seterr(0);
        CHECK(!U(WSAGetOverlappedResult)(c, &ov, &got, FALSE, &fl));
        EXPECT_EQ(d_err(), WSAECONNREFUSED);
    }
    CloseHandle(ov.hEvent);
    d_close(c);
}

/* ---- readiness -------------------------------------------------------------------------------- */
TEST(ds6_select_listener_readable_on_pending_v6_connection) {
    lsn l; SOCKET c; struct sockaddr_in6 to;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    CHECK(!d_readable(l.s, 100));            /* nothing pending yet */
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&to, K_LOOP, l.port);
    CHECK(d_connect(c, &to, sizeof to) == 0);
    CHECK(d_readable(l.s, 3000));
    d_close(c); d_close(l.s);
}

TEST(ds6_select_refused_v6_connect_reports_exception) {
    lsn l; SOCKET c; struct sockaddr_in6 to; unsigned short p; unsigned long nb = 1; fd_set w, x; TIMEVAL tv = {3, 0}; int n, e = 0, l2 = sizeof e;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    p = l.port; d_close(l.s);
    c = d_sock(AF_INET6, SOCK_STREAM);
    U(ioctlsocket)(c, FIONBIO, &nb);
    mk6(&to, K_LOOP, p);
    d_seterr(0);
    if (d_connect(c, &to, sizeof to) == 0) { d_close(c); return; }
    CHECK(d_err() == WSAEWOULDBLOCK || d_err() == WSAECONNREFUSED);
    w.fd_count = 1; w.fd_array[0] = c; x.fd_count = 1; x.fd_array[0] = c;
    n = U(select)(0, NULL, &w, &x, &tv);
    CHECK(n >= 1);
    CHECK(x.fd_count == 1);                  /* failure surfaces in the exception set, not the write set */
    CHECK(d_gso(c, SOL_SOCKET, SO_ERROR, &e, &l2) == 0);
    EXPECT_EQ(e, WSAECONNREFUSED);
    d_close(c);
}

TEST(ds6_wsapoll_reports_v6_accept_and_data) {
    lsn l; SOCKET c, a; struct sockaddr_in6 to; WSAPOLLFD fd; int n;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&to, K_LOOP, l.port);
    CHECK(d_connect(c, &to, sizeof to) == 0);
    fd.fd = l.s; fd.events = POLLRDNORM; fd.revents = 0;
    n = U(WSAPoll)(&fd, 1, 3000);
    EXPECT_EQ(n, 1);
    CHECK((fd.revents & POLLRDNORM) != 0);
    a = d_accept(l.s, NULL, NULL);
    fd.fd = a; fd.events = POLLRDNORM; fd.revents = 0;
    EQC(U(WSAPoll)(&fd, 1, 100), 0);
    CHECK(d_send(c, "x", 1) == 1);
    EQC(U(WSAPoll)(&fd, 1, 3000), 1);
    CHECK((fd.revents & POLLRDNORM) != 0);
    d_close(a); d_close(c); d_close(l.s);
}

TEST(ds6_eventselect_accept_and_connect_on_v6) {
    lsn l; SOCKET c; struct sockaddr_in6 to; HANDLE ec, el; WSANETWORKEVENTS ne; unsigned long nb = 1;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    el = U(WSACreateEvent)(); ec = U(WSACreateEvent)();
    CHECK(U(WSAEventSelect)(l.s, el, FD_ACCEPT) == 0);
    c = d_sock(AF_INET6, SOCK_STREAM);
    CHECK(U(WSAEventSelect)(c, ec, FD_CONNECT) == 0);
    mk6(&to, K_LOOP, l.port);
    d_connect(c, &to, sizeof to);
    CHECK(U(WSAWaitForMultipleEvents)(1, &el, FALSE, 3000, FALSE) == WSA_WAIT_EVENT_0);
    memset(&ne, 0xff, sizeof ne);
    CHECK(U(WSAEnumNetworkEvents)(l.s, el, &ne) == 0);
    CHECK((ne.lNetworkEvents & FD_ACCEPT) != 0);
    EXPECT_EQ(ne.iErrorCode[FD_ACCEPT_BIT], 0);
    CHECK(U(WSAWaitForMultipleEvents)(1, &ec, FALSE, 3000, FALSE) == WSA_WAIT_EVENT_0);
    memset(&ne, 0xff, sizeof ne);
    CHECK(U(WSAEnumNetworkEvents)(c, ec, &ne) == 0);
    CHECK((ne.lNetworkEvents & FD_CONNECT) != 0);
    EXPECT_EQ(ne.iErrorCode[FD_CONNECT_BIT], 0);
    (void)nb;
    U(WSACloseEvent)(el); U(WSACloseEvent)(ec);
    d_close(c); d_close(l.s);
}

TEST(ds6_dualstack_listener_backlog_serves_mixed_families) {
    lsn l; SOCKET c[4], a[4]; struct sockaddr_in a4; struct sockaddr_in6 a6; int i, mapped = 0, plain = 0, n;
    NEED_V6();
    CHECK(lsn_open6(&l, K_ANY, 0));
    mk4(&a4, 1, l.port); mk6(&a6, K_LOOP, l.port);
    for (i = 0; i < 4; i++) {
        c[i] = d_sock(i & 1 ? AF_INET6 : AF_INET, SOCK_STREAM);
        CHECK(i & 1 ? d_connect(c[i], &a6, sizeof a6) == 0 : d_connect(c[i], &a4, sizeof a4) == 0);
    }
    for (i = 0; i < 4; i++) {
        struct sockaddr_in6 pn; n = sizeof pn;
        a[i] = d_accept_to(l.s, 3000, &pn, &n);
        CHECK(a[i] != INVALID_SOCKET);
        if (is_mapped_loop(&pn)) mapped++; else if (is_v6_loop(&pn)) plain++;
    }
    EXPECT_EQ(mapped, 2);
    EXPECT_EQ(plain, 2);
    for (i = 0; i < 4; i++) { d_close(c[i]); d_close(a[i]); }
    d_close(l.s);
}
