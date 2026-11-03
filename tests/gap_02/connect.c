/* Connection helpers: WSAConnectByList, WSAConnectByNameW, WSAConnect and AcceptEx, restricted to the
 * rows that depend on the socket's family and state or on the numeric value of the socket handle.
 * Measures: the sockets the by-list and by-name helpers accept (only IPv4 and IPv6), how a list is
 * filtered for the socket's family and IPv6-only setting, the reserved handle values 0 and -1, what a
 * negative address count means, and the errors AcceptEx gives for listeners and accept sockets in the
 * wrong state. All peers are loopback listeners created here on ephemeral ports. */
#include "g2.h"

/* One-entry list helper. */
typedef struct { SOCKET_ADDRESS_LIST *l; } list1;
static SOCKET_ADDRESS_LIST *mk_list(int n, SOCKADDR **sa, const int *len) {
    SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                  sizeof(SOCKET_ADDRESS_LIST) + (n > 0 ? n : 1) * sizeof(SOCKET_ADDRESS));
    int i;
    l->iAddressCount = n;
    for (i = 0; i < n; i++) { l->Address[i].lpSockaddr = sa[i]; l->Address[i].iSockaddrLength = len[i]; }
    return l;
}
static void free_list(SOCKET_ADDRESS_LIST *l) { HeapFree(GetProcessHeap(), 0, l); }

#define BYLIST(s, l) WS(WSAConnectByList)((s), (l), NULL, NULL, NULL, NULL, NULL, NULL)

/* ---- WSAConnectByList ---- */

TEST(gap2_conn_list_unix_socket_is_invalid) {
    SOCKET s, lst; unsigned short port; struct sockaddr_in a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = WS(socket)(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { t_skip("no AF_UNIX sockets"); return; }
    lst = g2_listen4(&port);
    g2_loop4(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    W_SETERR(0);
    r = BYLIST(s, l);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    free_list(l); g2_close(s); g2_close(lst);
}

TEST(gap2_conn_list_negative_count_is_invalid) {
    SOCKET s, lst; unsigned short port; struct sockaddr_in a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = g2_tcp4(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no sockets"); return; }
    g2_loop4(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    l->iAddressCount = -1;
    W_SETERR(0);
    r = BYLIST(s, l);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    free_list(l); g2_close(s); g2_close(lst);
}

TEST(gap2_conn_list_zero_socket_value_is_not_a_socket) {
    SOCKET lst; unsigned short port; struct sockaddr_in a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    lst = g2_listen4(&port);
    g2_loop4(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    W_SETERR(0);
    r = BYLIST((SOCKET)0, l);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_NOTSOCK);
    free_list(l); g2_close(lst);
}

static int v6only(SOCKET s, int on) {
    return WS(setsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on, sizeof on);
}
static void mapped_loop(struct sockaddr_in6 *a, unsigned short port_be) {
    memset(a, 0, sizeof *a);
    a->sin6_family = AF_INET6; a->sin6_port = port_be;
    a->sin6_addr.u.Byte[10] = 0xff; a->sin6_addr.u.Byte[11] = 0xff;
    a->sin6_addr.u.Byte[12] = 127; a->sin6_addr.u.Byte[15] = 1;
}

/* A V6ONLY socket drops IPv4-mapped entries from the candidate list; with nothing left the call is invalid. */
TEST(gap2_conn_list_v6only_socket_ignores_mapped_entries) {
    SOCKET s, lst; unsigned short port; struct sockaddr_in6 a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = g2_tcp6(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no IPv6 sockets"); g2_close(s); g2_close(lst); return; }
    if (v6only(s, 1) != 0) { t_skip("cannot set IPV6_V6ONLY"); g2_close(s); g2_close(lst); return; }
    mapped_loop(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    W_SETERR(0);
    r = BYLIST(s, l);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    free_list(l); g2_close(s); g2_close(lst);
}

TEST(gap2_conn_list_dual_stack_socket_with_mapped_entry) {
    SOCKET s, lst, acc; unsigned short port; struct sockaddr_in6 a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = g2_tcp6(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no IPv6 sockets"); g2_close(s); g2_close(lst); return; }
    v6only(s, 0);
    mapped_loop(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    W_SETERR(0);
    r = BYLIST(s, l);
    EXPECT_EQ(r, TRUE);
    if (r) {
        fd_set rd; struct timeval tv = { 3, 0 };
        FD_ZERO(&rd); FD_SET(lst, &rd);
        if (WS(select)(0, &rd, NULL, NULL, &tv) == 1) { acc = WS(accept)(lst, NULL, NULL); g2_close(acc); }
    }
    free_list(l); g2_close(s); g2_close(lst);
}

TEST(gap2_conn_list_entries_of_other_family_are_not_candidates) {
    SOCKET s, lst; unsigned short port; struct sockaddr_in a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = g2_tcp6(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no IPv6 sockets"); g2_close(s); g2_close(lst); return; }
    g2_loop4(&a, port);                       /* a plain IPv4 entry offered to an IPv6 socket */
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    W_SETERR(0);
    r = BYLIST(s, l);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    free_list(l); g2_close(s); g2_close(lst);
}

TEST(gap2_conn_list_datagram_socket_note) {
    SOCKET s, lst; unsigned short port; struct sockaddr_in a; SOCKADDR *sa[1]; int len[1]; SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = g2_udp4(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no sockets"); g2_close(s); g2_close(lst); return; }
    g2_loop4(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    W_SETERR(0);
    r = BYLIST(s, l);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    free_list(l); g2_close(s); g2_close(lst);
}

TEST(gap2_conn_list_success_needs_context_update_for_peer_name) {
    SOCKET s, lst, acc; unsigned short port; struct sockaddr_in a, peer; int plen = sizeof peer; SOCKADDR *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *l; BOOL r;
    G2_NEED();
    s = g2_tcp4(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no sockets"); g2_close(s); g2_close(lst); return; }
    g2_loop4(&a, port);
    sa[0] = (SOCKADDR *)&a; len[0] = sizeof a;
    l = mk_list(1, sa, len);
    r = BYLIST(s, l);
    EXPECT_EQ(r, TRUE);
    if (r) {
        /* The connection exists but the socket's name cache is not refreshed until the update option is set. */
        W_SETERR(0);
        EXPECT_EQ(WS(getpeername)(s, (SOCKADDR *)&peer, &plen), SOCKET_ERROR);
        EXPECT_EQ(W_ERR(), 10057);
        EXPECT_EQ(WS(setsockopt)(s, SOL_SOCKET, 0x7010, NULL, 0), 0);
        plen = sizeof peer;
        EXPECT_EQ(WS(getpeername)(s, (SOCKADDR *)&peer, &plen), 0);
        EXPECT_EQ(peer.sin_port, port);
        {
            fd_set rd; struct timeval tv = { 3, 0 };
            FD_ZERO(&rd); FD_SET(lst, &rd);
            if (WS(select)(0, &rd, NULL, NULL, &tv) == 1) { acc = WS(accept)(lst, NULL, NULL); g2_close(acc); }
        }
    }
    free_list(l); g2_close(s); g2_close(lst);
}

/* ---- WSAConnectByNameW ---- */

TEST(gap2_conn_name_zero_socket_value_is_not_a_socket) {
    BOOL r;
    G2_NEED();
    W_SETERR(0);
    r = WS(WSAConnectByNameW)((SOCKET)0, (LPWSTR)L"127.0.0.1", (LPWSTR)L"80", NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_NOTSOCK);
}

TEST(gap2_conn_name_unix_socket_is_unsupported_family) {
    SOCKET s; BOOL r;
    G2_NEED();
    s = WS(socket)(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { t_skip("no AF_UNIX sockets"); return; }
    W_SETERR(0);
    r = WS(WSAConnectByNameW)(s, (LPWSTR)L"127.0.0.1", (LPWSTR)L"9", NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_AFNOSUPPORT);
    g2_close(s);
}

TEST(gap2_conn_name_ipv6_literal_on_ipv4_socket_is_host_not_found) {
    SOCKET s; BOOL r;
    G2_NEED();
    s = g2_tcp4();
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    W_SETERR(0);
    r = WS(WSAConnectByNameW)(s, (LPWSTR)L"::1", (LPWSTR)L"9", NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), 11001);   /* WSAHOST_NOT_FOUND */
    g2_close(s);
}

TEST(gap2_conn_name_service_out_of_range_note) {
    SOCKET s; BOOL r;
    G2_NEED();
    s = g2_tcp4();
    if (s == INVALID_SOCKET) { t_skip("no socket"); return; }
    W_SETERR(0);
    r = WS(WSAConnectByNameW)(s, (LPWSTR)L"127.0.0.1", (LPWSTR)L"99999", NULL, NULL, NULL, NULL, NULL, NULL);
    t_note("service 99999: error class %s", W_ERR() == 10061 ? "refused" : "other");
    CHECK(r == FALSE);
    g2_close(s);
}

TEST(gap2_conn_name_datagram_socket_is_invalid) {
    SOCKET s, lst; unsigned short port; WCHAR svc[8]; BOOL r;
    G2_NEED();
    s = g2_udp4(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no sockets"); g2_close(s); g2_close(lst); return; }
    swprintf(svc, 8, L"%u", (unsigned)((port >> 8) | ((port & 0xff) << 8)));
    W_SETERR(0);
    r = WS(WSAConnectByNameW)(s, (LPWSTR)L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    g2_close(s); g2_close(lst);
}

TEST(gap2_conn_name_success_needs_context_update_for_peer_name) {
    SOCKET s, lst, acc; unsigned short port; WCHAR svc[8]; struct sockaddr_in peer; int plen = sizeof peer; BOOL r;
    G2_NEED();
    s = g2_tcp4(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no sockets"); g2_close(s); g2_close(lst); return; }
    swprintf(svc, 8, L"%u", (unsigned)((port >> 8) | ((port & 0xff) << 8)));
    r = WS(WSAConnectByNameW)(s, (LPWSTR)L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, TRUE);
    if (r) {
        W_SETERR(0);
        EXPECT_EQ(WS(getpeername)(s, (SOCKADDR *)&peer, &plen), SOCKET_ERROR);
        EXPECT_EQ(W_ERR(), 10057);
        EXPECT_EQ(WS(setsockopt)(s, SOL_SOCKET, 0x7010, NULL, 0), 0);
        plen = sizeof peer;
        EXPECT_EQ(WS(getpeername)(s, (SOCKADDR *)&peer, &plen), 0);
        EXPECT_EQ(peer.sin_port, port);
        {
            fd_set rd; struct timeval tv = { 3, 0 };
            FD_ZERO(&rd); FD_SET(lst, &rd);
            if (WS(select)(0, &rd, NULL, NULL, &tv) == 1) { acc = WS(accept)(lst, NULL, NULL); g2_close(acc); }
        }
    }
    g2_close(s); g2_close(lst);
}

TEST(gap2_conn_name_short_remote_length_is_fault) {
    SOCKET s, lst, acc; unsigned short port; WCHAR svc[8]; BYTE out[64]; DWORD olen = 4; BOOL r;
    G2_NEED();
    s = g2_tcp4(); lst = g2_listen4(&port);
    if (s == INVALID_SOCKET || lst == INVALID_SOCKET) { t_skip("no sockets"); g2_close(s); g2_close(lst); return; }
    swprintf(svc, 8, L"%u", (unsigned)((port >> 8) | ((port & 0xff) << 8)));
    memset(out, 0xCD, sizeof out);
    W_SETERR(0);
    r = WS(WSAConnectByNameW)(s, (LPWSTR)L"127.0.0.1", svc, NULL, NULL, &olen, (LPSOCKADDR)out, NULL, NULL);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(W_ERR(), GE_FAULT);
    if (r) { fd_set rd; struct timeval tv = { 3, 0 }; FD_ZERO(&rd); FD_SET(lst, &rd); if (WS(select)(0, &rd, NULL, NULL, &tv) == 1) { acc = WS(accept)(lst, NULL, NULL); g2_close(acc); } }
    g2_close(s); g2_close(lst);
}

/* ---- WSAConnect ---- */

TEST(gap2_conn_wsaconnect_zero_socket_value_is_not_a_socket) {
    struct sockaddr_in a; int r;
    G2_NEED();
    g2_loop4(&a, 0x5000);
    W_SETERR(0);
    r = WS(WSAConnect)((SOCKET)0, (SOCKADDR *)&a, sizeof a, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_NOTSOCK);
}

/* ---- AcceptEx: listeners and accept sockets in the wrong state ---- */

typedef struct { SOCKET lst, acc; BYTE buf[256]; OVERLAPPED ov; } acc_ctx;

static BOOL do_acceptex(acc_ctx *c, DWORD *got) {
    memset(&c->ov, 0, sizeof c->ov);
    c->ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    *got = 0;
    return MS(AcceptEx)(c->lst, c->acc, c->buf, 0, 32, 32, got, &c->ov);
}
static void finish_acceptex(acc_ctx *c, BOOL r, int err) {
    if (!r && err == ERROR_IO_PENDING) { WS(closesocket)(c->lst); c->lst = INVALID_SOCKET; WaitForSingleObject(c->ov.hEvent, 3000); }
    CloseHandle(c->ov.hEvent);
}

TEST(gap2_conn_acceptex_listener_never_listened_is_invalid) {
    acc_ctx c; DWORD got; BOOL r; int e;
    G2_NEED();
    c.lst = g2_tcp4(); c.acc = g2_tcp4();
    if (c.lst == INVALID_SOCKET || c.acc == INVALID_SOCKET) { t_skip("no sockets"); return; }
    g2_bind_any4(c.lst);
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_INVAL);
    finish_acceptex(&c, r, e);
    g2_close(c.lst); g2_close(c.acc);
}

TEST(gap2_conn_acceptex_unbound_listener_is_invalid) {
    acc_ctx c; DWORD got; BOOL r; int e;
    G2_NEED();
    c.lst = g2_tcp4(); c.acc = g2_tcp4();
    if (c.lst == INVALID_SOCKET || c.acc == INVALID_SOCKET) { t_skip("no sockets"); return; }
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_INVAL);
    finish_acceptex(&c, r, e);
    g2_close(c.lst); g2_close(c.acc);
}

TEST(gap2_conn_acceptex_datagram_listener_is_invalid) {
    acc_ctx c; DWORD got; BOOL r; int e;
    G2_NEED();
    c.lst = g2_udp4(); c.acc = g2_tcp4();
    if (c.lst == INVALID_SOCKET || c.acc == INVALID_SOCKET) { t_skip("no sockets"); return; }
    g2_bind_any4(c.lst);
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_INVAL);
    finish_acceptex(&c, r, e);
    g2_close(c.lst); g2_close(c.acc);
}

TEST(gap2_conn_acceptex_datagram_accept_socket_is_invalid) {
    acc_ctx c; DWORD got; BOOL r; int e; unsigned short port;
    G2_NEED();
    c.lst = g2_listen4(&port); c.acc = g2_udp4();
    if (c.lst == INVALID_SOCKET || c.acc == INVALID_SOCKET) { t_skip("no sockets"); return; }
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_INVAL);
    finish_acceptex(&c, r, e);
    g2_close(c.lst); g2_close(c.acc);
}

TEST(gap2_conn_acceptex_bound_accept_socket_is_invalid) {
    acc_ctx c; DWORD got; BOOL r; int e; unsigned short port;
    G2_NEED();
    c.lst = g2_listen4(&port); c.acc = g2_tcp4();
    if (c.lst == INVALID_SOCKET || c.acc == INVALID_SOCKET) { t_skip("no sockets"); return; }
    g2_bind_any4(c.acc);
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_INVAL);
    finish_acceptex(&c, r, e);
    g2_close(c.lst); g2_close(c.acc);
}

TEST(gap2_conn_acceptex_listener_as_its_own_accept_socket_is_invalid) {
    acc_ctx c; DWORD got; BOOL r; int e; unsigned short port;
    G2_NEED();
    c.lst = g2_listen4(&port); c.acc = c.lst;
    if (c.lst == INVALID_SOCKET) { t_skip("no sockets"); return; }
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_INVAL);
    finish_acceptex(&c, r, e);
    g2_close(c.lst);
}

TEST(gap2_conn_acceptex_accept_socket_zero_value_is_not_a_socket) {
    acc_ctx c; DWORD got; BOOL r; int e; unsigned short port;
    G2_NEED();
    c.lst = g2_listen4(&port); c.acc = 0;
    if (c.lst == INVALID_SOCKET) { t_skip("no sockets"); return; }
    W_SETERR(0);
    r = do_acceptex(&c, &got); e = W_ERR();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, GE_NOTSOCK);
    finish_acceptex(&c, r, e);
    g2_close(c.lst);
}
