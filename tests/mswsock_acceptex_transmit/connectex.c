/* ConnectEx: completion through a completion port, the byte count for initial data, connection context
 * (SO_UPDATE_CONNECT_CONTEXT) and what Winsock knows about the socket without it, SO_CONNECT_TIME, the exact
 * address the peer sees from a pre-bound client, concurrent connects, reconnect after a failed attempt and after
 * DisconnectEx(TF_REUSE_SOCKET).  The basic argument errors (unbound socket, NULL overlapped, short name,
 * connected / listening / datagram sockets) are asserted in other areas and are not repeated. */
#include "mx.h"

struct cx {
    struct mx_ext x;
    SOCKET lst, c;
    struct sockaddr_in addr;     /* listener */
    struct sockaddr_in cbound;   /* client's own bound address */
    OVERLAPPED ov;
};

static int cx_open(struct cx *k)
{
    int len;
    memset(k, 0, sizeof *k);
    k->lst = k->c = INVALID_SOCKET;
    if (!mx_up() || !mx_load_ext(&k->x)) return 0;
    k->lst = mx_listener(&k->addr, 8);
    k->c = mx_bound(&k->cbound);
    len = sizeof k->cbound;
    (void)len;
    k->ov.hEvent = mx_event();
    return k->lst != INVALID_SOCKET && k->c != INVALID_SOCKET && k->ov.hEvent;
}

static void cx_close(struct cx *k)
{
    if (k->c != INVALID_SOCKET) mx_abort(k->c, &k->ov);
    if (k->lst != INVALID_SOCKET) mx_closesocket(k->lst);
    if (k->ov.hEvent) CloseHandle(k->ov.hEvent);
}

#define CX(k) \
    do { if (!cx_open(&(k))) { cx_close(&(k)); t_skip("ConnectEx fixture unavailable"); return; } } while (0)

/* Issue ConnectEx on s toward the listener; returns 0 for synchronous success, else the error. */
static int cx_go(struct cx *k, SOCKET s, const void *data, DWORD len, DWORD *sent)
{
    BOOL r;
    ResetEvent(k->ov.hEvent);
    r = k->x.connectex(s, (struct sockaddr *)&k->addr, sizeof k->addr, (PVOID)data, len, sent, &k->ov);
    return r ? 0 : mx_WSAGetLastError();
}

static int cx_update(SOCKET s) { return mx_setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0); }

TEST(connectex_pointer_is_identical_across_sockets)
{
    SOCKET s1, s2;
    GUID g = WSAID_CONNECTEX;
    NEED_NET();
    s1 = mx_tcp(); s2 = mx_tcp();
    CHECK(mx_ext_lookup(s1, g) != NULL);
    CHECK(mx_ext_lookup(s1, g) == mx_ext_lookup(s2, g));
    mx_closesocket(s1); mx_closesocket(s2);
}

/* The accepted side sees exactly the address the client socket was bound to before ConnectEx. */
TEST(connectex_peer_sees_the_prebound_address)
{
    struct cx k;
    SOCKET srv;
    struct sockaddr_in seen;
    int len = sizeof seen;
    DWORD n = 0, err = 0;
    CX(k);
    MX_EQ(cx_go(&k, k.c, NULL, 0, NULL), ERROR_IO_PENDING);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    CHECK(srv != INVALID_SOCKET);
    MX_EQ(mx_getpeername(srv, (struct sockaddr *)&seen, &len), 0);
    MX_EQ(seen.sin_port, k.cbound.sin_port);
    MX_EQ(seen.sin_addr.s_addr, k.cbound.sin_addr.s_addr);
    mx_closesocket(srv);
    cx_close(&k);
}

TEST(connectex_completion_port_packet_reports_initial_data_length)
{
    struct cx k;
    HANDLE port;
    SOCKET srv;
    DWORD got = MX_POISON;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    CX(k);
    port = CreateIoCompletionPort((HANDLE)k.c, NULL, 0x77, 0);
    CHECK(port != NULL);
    {
        int e = cx_go(&k, k.c, "12345", 5, NULL);
        t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "ConnectEx posts", "error %d", e);
    }
    CHECK(GetQueuedCompletionStatus(port, &got, &key, &pov, 5000));
    MX_EQ(key, 0x77);
    CHECK(pov == &k.ov);
    MX_EQ(got, 5);
    srv = mx_accept_wait(k.lst);
    CHECK(srv != INVALID_SOCKET);
    mx_expect_bytes(srv, "12345", 5);
    mx_closesocket(srv);
    cx_close(&k);
    CloseHandle(port);
}

TEST(connectex_overlapped_result_counts_initial_data)
{
    struct cx k;
    SOCKET srv;
    DWORD n = MX_POISON, err = 0;
    CX(k);
    cx_go(&k, k.c, "abcdefgh", 8, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    MX_EQ(n, 8);
    srv = mx_accept_wait(k.lst);
    CHECK(srv != INVALID_SOCKET);
    mx_expect_bytes(srv, "abcdefgh", 8);
    mx_closesocket(srv);
    cx_close(&k);
}

/* Without the context update Winsock does not treat the socket as connected for name queries and shutdown. */
TEST(connectex_names_and_shutdown_without_context_update_are_notconn)
{
    struct cx k;
    SOCKET srv;
    struct sockaddr_in a;
    int len = sizeof a;
    DWORD n = 0, err = 0;
    CX(k);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    MX_EQ(mx_getpeername(k.c, (struct sockaddr *)&a, &len), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    MX_EQ(mx_shutdown(k.c, SD_SEND), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    cx_close(&k);
}

TEST(connectex_context_update_makes_peer_name_and_shutdown_work)
{
    struct cx k;
    SOCKET srv;
    struct sockaddr_in a;
    int len = sizeof a;
    DWORD n = 0, err = 0;
    CX(k);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    CHECK(srv != INVALID_SOCKET);
    MX_EQ(cx_update(k.c), 0);
    MX_EQ(mx_getpeername(k.c, (struct sockaddr *)&a, &len), 0);
    MX_EQ(a.sin_port, k.addr.sin_port);
    MX_EQ(a.sin_addr.s_addr, k.addr.sin_addr.s_addr);
    MX_EQ(mx_shutdown(k.c, SD_SEND), 0);
    CHECK(mx_at_eof(srv, 5000));
    mx_closesocket(srv);
    cx_close(&k);
}

/* The local address is available from the moment of the bind and does not change across the connect. */
TEST(connectex_local_name_matches_the_prebound_address)
{
    struct cx k;
    SOCKET srv;
    struct sockaddr_in a;
    int len = sizeof a;
    DWORD n = 0, err = 0;
    CX(k);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    MX_EQ(mx_getsockname(k.c, (struct sockaddr *)&a, &len), 0);
    MX_EQ(a.sin_port, k.cbound.sin_port);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    cx_close(&k);
}

TEST(connectex_connect_time_is_unset_before_and_set_after)
{
    struct cx k;
    SOCKET srv;
    DWORD t = 0, n = 0, err = 0;
    int len = sizeof t;
    CX(k);
    MX_EQ(mx_getsockopt(k.c, SOL_SOCKET, SO_CONNECT_TIME, (char *)&t, &len), 0);
    MX_EQ(t, 0xFFFFFFFFUL);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    t = 0xFFFFFFFFUL; len = sizeof t;
    MX_EQ(mx_getsockopt(k.c, SOL_SOCKET, SO_CONNECT_TIME, (char *)&t, &len), 0);
    CHECK(t != 0xFFFFFFFFUL && t < 60);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    cx_close(&k);
}

/* Winsock only learns that the socket is connected from the context update; until then a plain connect on the
 * socket is rejected as an invalid operation, not as "already connected". */
TEST(connectex_then_connect_without_context_update_is_einval)
{
    struct cx k;
    SOCKET srv;
    DWORD n = 0, err = 0;
    CX(k);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    MX_EQ(mx_connect(k.c, (struct sockaddr *)&k.addr, sizeof k.addr), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAEINVAL);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    cx_close(&k);
}

TEST(connectex_then_connect_after_context_update_recorded)
{
    struct cx k;
    SOCKET srv;
    DWORD n = 0, err = 0;
    CX(k);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    MX_EQ(cx_update(k.c), 0);
    MX_EQ(mx_connect(k.c, (struct sockaddr *)&k.addr, sizeof k.addr), SOCKET_ERROR);
    t_note("connect after ConnectEx and SO_UPDATE_CONNECT_CONTEXT: error %d", mx_WSAGetLastError());
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    cx_close(&k);
}

TEST(connectex_concurrent_sockets_each_connect_and_carry_their_own_data)
{
    struct cx k;
    SOCKET c2, s1, s2;
    struct sockaddr_in b2;
    OVERLAPPED ov2;
    DWORD n = 0, err = 0;
    char buf[4];
    CX(k);
    c2 = mx_bound(&b2);
    memset(&ov2, 0, sizeof ov2);
    ov2.hEvent = mx_event();
    cx_go(&k, k.c, "AAA", 3, NULL);
    k.x.connectex(c2, (struct sockaddr *)&k.addr, sizeof k.addr, "BBB", 3, NULL, &ov2);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    CHECK(mx_ov_done(c2, &ov2, &n, 5000, &err));
    s1 = mx_accept_wait(k.lst);
    s2 = mx_accept_wait(k.lst);
    CHECK(s1 != INVALID_SOCKET && s2 != INVALID_SOCKET);
    /* Whichever accepted socket carries which client, each must carry exactly its client's three bytes. */
    {
        int got1 = mx_recv_all(s1, buf, 3, 5000);
        int first_is_a = got1 == 3 && !memcmp(buf, "AAA", 3);
        int first_is_b = got1 == 3 && !memcmp(buf, "BBB", 3);
        CHECK(first_is_a || first_is_b);
        MX_EQ(mx_recv_all(s2, buf, 3, 5000), 3);
        CHECK(!memcmp(buf, first_is_a ? "BBB" : "AAA", 3));
    }
    if (s1 != INVALID_SOCKET) mx_closesocket(s1);
    if (s2 != INVALID_SOCKET) mx_closesocket(s2);
    mx_abort(c2, &ov2);
    CloseHandle(ov2.hEvent);
    cx_close(&k);
}

/* IPv6 loopback ConnectEx with initial data. */
TEST(connectex_ipv6_loopback_with_initial_data)
{
    struct cx k;
    SOCKET l6, c6, srv;
    struct sockaddr_in6 sa, ca;
    int len = sizeof sa;
    DWORD n = 0, err = 0;
    CX(k);
    l6 = mx_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    c6 = mx_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.u.Byte[15] = 1;
    ca = sa;
    if (l6 == INVALID_SOCKET || c6 == INVALID_SOCKET || mx_bind(l6, (struct sockaddr *)&sa, sizeof sa) ||
        mx_listen(l6, 2) || mx_getsockname(l6, (struct sockaddr *)&sa, &len) || mx_bind(c6, (struct sockaddr *)&ca, sizeof ca)) {
        if (l6 != INVALID_SOCKET) mx_closesocket(l6);
        if (c6 != INVALID_SOCKET) mx_closesocket(c6);
        cx_close(&k);
        t_skip("IPv6 loopback unavailable");
        return;
    }
    ResetEvent(k.ov.hEvent);
    k.x.connectex(c6, (struct sockaddr *)&sa, sizeof sa, "v6!", 3, NULL, &k.ov);
    CHECK(mx_ov_done(c6, &k.ov, &n, 5000, &err));
    MX_EQ(n, 3);
    srv = mx_accept_wait(l6);
    CHECK(srv != INVALID_SOCKET);
    mx_expect_bytes(srv, "v6!", 3);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    mx_closesocket(c6);
    mx_closesocket(l6);
    cx_close(&k);
}

/* ---- failure then retry; reuse -------------------------------------------------------------------------- */

TEST(connectex_retry_after_refusal_on_the_same_socket_succeeds)
{
    struct cx k;
    struct sockaddr_in dead;
    SOCKET d;
    DWORD n = 0, err = 0, err2 = 0;
    int e;
    CX(k);
    d = mx_listener(&dead, 1);
    mx_closesocket(d);   /* nothing listens here any more */
    ResetEvent(k.ov.hEvent);
    e = k.x.connectex(k.c, (struct sockaddr *)&dead, sizeof dead, NULL, 0, NULL, &k.ov) ? 0 : mx_WSAGetLastError();
    t_check(e == ERROR_IO_PENDING || e == WSAECONNREFUSED, __FILE__, __LINE__, "refused attempt posts", "error %d", e);
    if (e == ERROR_IO_PENDING) {
        MX_EQ(mx_ov_done(k.c, &k.ov, &n, 5000, &err), 0);
        MX_EQ(err, WSAECONNREFUSED);
    }
    e = cx_go(&k, k.c, NULL, 0, NULL);
    t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "second ConnectEx posts", "error %d", e);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err2));
    {
        SOCKET s = mx_accept_wait(k.lst);
        CHECK(s != INVALID_SOCKET);
        if (s != INVALID_SOCKET) mx_closesocket(s);
    }
    cx_close(&k);
}

/* A reused client socket connects again. The next peer is a fresh listener so the new connection has a different
 * remote port from the old one (the old four-tuple may still be winding down). */
TEST(connectex_after_disconnectex_reuse_connects_again)
{
    struct cx k;
    struct sockaddr_in addr2;
    SOCKET srv, l2, srv2;
    DWORD n = 0, err = 0;
    int e;
    CX(k);
    cx_go(&k, k.c, NULL, 0, NULL);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    CHECK(mx_reuse_disconnect(k.x.disconnectex, k.c, srv));
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    l2 = mx_listener(&addr2, 2);
    ResetEvent(k.ov.hEvent);
    e = k.x.connectex(k.c, (struct sockaddr *)&addr2, sizeof addr2, "again", 5, NULL, &k.ov) ? 0 : mx_WSAGetLastError();
    if (e == WSAEINVAL) {
        /* The socket came back unbound: bind it again, as the documentation allows for. */
        struct sockaddr_in any = mx_lo4();
        t_note("socket was unbound by TF_REUSE_SOCKET; rebinding before the second ConnectEx");
        MX_EQ(mx_bind(k.c, (struct sockaddr *)&any, sizeof any), 0);
        ResetEvent(k.ov.hEvent);
        e = k.x.connectex(k.c, (struct sockaddr *)&addr2, sizeof addr2, "again", 5, NULL, &k.ov) ? 0 : mx_WSAGetLastError();
    }
    t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "second ConnectEx", "error %d", e);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv2 = mx_accept_wait(l2);
    CHECK(srv2 != INVALID_SOCKET);
    mx_expect_bytes(srv2, "again", 5);
    if (srv2 != INVALID_SOCKET) mx_closesocket(srv2);
    mx_closesocket(l2);
    cx_close(&k);
}

/* ---- destinations Windows refuses, observed rather than assumed -------------------------------------------- */

/* The final outcome of a ConnectEx toward `to`: the immediate error, or the completion's error when it pends. */
static int cx_outcome(struct cx *k, const struct sockaddr_in *to, DWORD *how)
{
    DWORD n = 0, err = 0;
    int e;
    ResetEvent(k->ov.hEvent);
    e = k->x.connectex(k->c, (const struct sockaddr *)to, sizeof *to, NULL, 0, NULL, &k->ov) ? 0 : mx_WSAGetLastError();
    *how = e == ERROR_IO_PENDING;
    if (e != ERROR_IO_PENDING) return e;
    mx_ov_done(k->c, &k->ov, &n, 5000, &err);
    return (int)err;
}

TEST(connectex_to_port_zero_is_addrnotavail)
{
    struct cx k;
    struct sockaddr_in z;
    DWORD how;
    CX(k);
    z = k.addr;
    z.sin_port = 0;
    MX_EQ(cx_outcome(&k, &z, &how), WSAEADDRNOTAVAIL);
    cx_close(&k);
}

TEST(connectex_to_the_unspecified_address_is_addrnotavail)
{
    struct cx k;
    struct sockaddr_in z;
    DWORD how;
    CX(k);
    z = k.addr;
    z.sin_addr.s_addr = 0;
    MX_EQ(cx_outcome(&k, &z, &how), WSAEADDRNOTAVAIL);
    cx_close(&k);
}

TEST(connectex_name_longer_than_sockaddr_in_is_accepted)
{
    struct cx k;
    unsigned char big[64];
    SOCKET srv;
    DWORD n = 0, err = 0;
    int e;
    CX(k);
    memset(big, 0, sizeof big);
    memcpy(big, &k.addr, sizeof k.addr);
    ResetEvent(k.ov.hEvent);
    e = k.x.connectex(k.c, (struct sockaddr *)big, sizeof big, NULL, 0, NULL, &k.ov) ? 0 : mx_WSAGetLastError();
    t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", e);
    CHECK(mx_ov_done(k.c, &k.ov, &n, 5000, &err));
    srv = mx_accept_wait(k.lst);
    CHECK(srv != INVALID_SOCKET);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    cx_close(&k);
}
