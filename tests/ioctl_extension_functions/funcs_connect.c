/* ConnectEx, DisconnectEx and a few AcceptEx details reached through the looked-up pointers: the order of the
 * parameter checks, the connect-context life cycle, flag validation, and socket reuse.
 *
 * Order of checks in ConnectEx: a missing OVERLAPPED is ERROR_INVALID_PARAMETER first; then a name length below
 * two is WSAEFAULT (the name pointer is not dereferenced for it); only then does the socket get looked at.
 * DisconnectEx: flag bits other than TF_REUSE_SOCKET, or a non-zero reserved argument, are WSAEINVAL before the
 * socket is looked at. */
#include "xf.h"

typedef BOOL (WINAPI *connectex_fn)(SOCKET, const struct sockaddr *, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *disconnectex_fn)(SOCKET, LPOVERLAPPED, DWORD, DWORD);
typedef BOOL (WINAPI *acceptex_fn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);

static connectex_fn    get_cx(void) { GUID g = WSAID_CONNECTEX;    return (connectex_fn)xf_fn(&g); }
static disconnectex_fn get_dx(void) { GUID g = WSAID_DISCONNECTEX; return (disconnectex_fn)xf_fn(&g); }
static acceptex_fn     get_ax(void) { GUID g = WSAID_ACCEPTEX;     return (acceptex_fn)xf_fn(&g); }
#define NEED_CX(f) connectex_fn f = get_cx(); do { if (!f) { t_skip("ConnectEx unavailable"); return; } } while (0)
#define NEED_DX(f) disconnectex_fn f = get_dx(); do { if (!f) { t_skip("DisconnectEx unavailable"); return; } } while (0)
#define NEED_AX(f) acceptex_fn f = get_ax(); do { if (!f) { t_skip("AcceptEx unavailable"); return; } } while (0)

static SOCKET bound_tcp(void)
{
    struct sockaddr_in a; SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    xf_loop4(&a);
    if (s != INVALID_SOCKET && bind(s, (struct sockaddr *)&a, sizeof a)) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

/* Overlapped state with an event; finish() waits (bounded) and returns the transferred byte count or -1. */
struct op { WSAOVERLAPPED ov; };
static void op_init(struct op *o) { memset(o, 0, sizeof *o); o->ov.hEvent = WSACreateEvent(); }
static void op_done(struct op *o) { if (o->ov.hEvent) WSACloseEvent(o->ov.hEvent); }
/* After a call that returned FALSE: expects ERROR_IO_PENDING, waits, then returns the result (or -1 on failure,
 * storing the error in *err). */
static long op_finish(SOCKET s, struct op *o, DWORD *err)
{
    DWORD n = 0, fl = 0;
    if (WSAGetLastError() != ERROR_IO_PENDING) { *err = WSAGetLastError(); return -1; }
    if (WaitForSingleObject(o->ov.hEvent, 8000) != WAIT_OBJECT_0) { *err = WAIT_TIMEOUT; return -1; }
    if (!WSAGetOverlappedResult(s, &o->ov, &n, FALSE, &fl)) { *err = WSAGetLastError(); return -1; }
    *err = 0;
    return (long)n;
}

/* ---- ConnectEx: parameter-check order -------------------------------------------------------------------- */

TEST(xf_connectex_missing_overlapped_wins_over_everything)
{
    struct sockaddr_in a; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    xf_loop4(&a);
    WSASetLastError(0);
    CHECK(!cx(INVALID_SOCKET, (struct sockaddr *)&a, 0, NULL, 0, &n, NULL));
    EXPECT_EQ(WSAGetLastError(), ERROR_INVALID_PARAMETER);
}
TEST(xf_connectex_missing_overlapped_with_short_name)
{
    struct sockaddr_in a; DWORD n = 0; SOCKET s;
    NEED_NET(); NEED_CX(cx);
    s = bound_tcp();
    REQUIRE(s != INVALID_SOCKET);
    xf_loop4(&a);
    WSASetLastError(0);
    CHECK(!cx(s, (struct sockaddr *)&a, 1, NULL, 0, &n, NULL));
    EXPECT_EQ(WSAGetLastError(), ERROR_INVALID_PARAMETER);
    closesocket(s);
}
TEST(xf_connectex_name_length_below_two_is_efault_before_socket_lookup)
{
    static const int lens[] = {1, 0, -1, -100, (int)0x80000000};
    unsigned i; struct sockaddr_in a; struct op o;
    NEED_NET(); NEED_CX(cx);
    xf_loop4(&a); op_init(&o);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        DWORD n = 0;
        WSASetLastError(0);
        CHECK(!cx(INVALID_SOCKET, (struct sockaddr *)&a, lens[i], NULL, 0, &n, &o.ov));
        CHECKF(WSAGetLastError() == WSAEFAULT, "namelen %d: error %d", lens[i], WSAGetLastError());
    }
    op_done(&o);
}
TEST(xf_connectex_name_length_below_two_on_real_socket)
{
    struct sockaddr_in a; struct op o; SOCKET s; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    s = bound_tcp();
    REQUIRE(s != INVALID_SOCKET);
    xf_loop4(&a); op_init(&o);
    WSASetLastError(0);
    CHECK(!cx(s, (struct sockaddr *)&a, 0, NULL, 0, &n, &o.ov));
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    op_done(&o);
    closesocket(s);
}
TEST(xf_connectex_name_length_below_two_does_not_read_the_name)
{
    struct op o; DWORD n = 0; SOCKET s;
    NEED_NET(); NEED_CX(cx);
    s = bound_tcp();
    REQUIRE(s != INVALID_SOCKET);
    op_init(&o);
    WSASetLastError(0);
    CHECK(!cx(s, NULL, 1, NULL, 0, &n, &o.ov));       /* the pointer is never dereferenced for this failure */
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    op_done(&o);
    closesocket(s);
}
TEST(xf_connectex_failed_check_leaves_overlapped_untouched)
{
    struct sockaddr_in a; struct op o; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    xf_loop4(&a); op_init(&o);
    o.ov.Internal = 0x1234; o.ov.InternalHigh = 0x5678;
    CHECK(!cx(INVALID_SOCKET, (struct sockaddr *)&a, 1, NULL, 0, &n, &o.ov));
    EXPECT_EQ(o.ov.Internal, 0x1234);
    EXPECT_EQ(o.ov.InternalHigh, 0x5678);
    op_done(&o);
}

/* ---- ConnectEx: connect context life cycle ----------------------------------------------------------------- */

static int connect_ex_pair(SOCKET *cli, SOCKET *srv, SOCKET *lst, struct sockaddr_in *addr, const char *init, DWORD initlen, long *sent)
{
    connectex_fn cx = get_cx(); struct op o; DWORD n = 0, err; long r;
    *lst = xf_listener(addr, 2);
    *cli = bound_tcp();
    *srv = INVALID_SOCKET;
    if (!cx || *lst == INVALID_SOCKET || *cli == INVALID_SOCKET) return 0;
    op_init(&o);
    if (!cx(*cli, (struct sockaddr *)addr, sizeof *addr, (PVOID)init, initlen, &n, &o.ov)) {
        r = op_finish(*cli, &o, &err);
        if (r < 0) { op_done(&o); return 0; }
        if (sent) *sent = r;
    } else if (sent) *sent = n;
    op_done(&o);
    *srv = xf_accept(*lst);
    return *srv != INVALID_SOCKET;
}

#define CXPAIR(c, s, l, a) SOCKET c, s, l; struct sockaddr_in a; \
    do { NEED_NET(); if (!connect_ex_pair(&c, &s, &l, &a, NULL, 0, NULL)) { \
        if (c != INVALID_SOCKET) { closesocket(c); } \
        if (s != INVALID_SOCKET) { closesocket(s); } \
        if (l != INVALID_SOCKET) { closesocket(l); } \
        t_skip("ConnectEx pair unavailable"); return; } } while (0)
#define CXCLOSE(c, s, l) do { closesocket(c); closesocket(s); closesocket(l); } while (0)

TEST(xf_connectex_data_flows_both_ways_without_context_update)
{
    char b[8];
    CXPAIR(c, s, l, a);
    CHECK(send(c, "ping", 4, 0) == 4);
    memset(b, 0, sizeof b);
    EXPECT_EQ(xf_read_all(s, b, 4), 4);
    CHECK(!memcmp(b, "ping", 4));
    CHECK(send(s, "pong", 4, 0) == 4);
    memset(b, 0, sizeof b);
    EXPECT_EQ(xf_read_all(c, b, 4), 4);
    CHECK(!memcmp(b, "pong", 4));
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_peer_name_after_context_update_matches_listener)
{
    struct sockaddr_in peer; int len = sizeof peer;
    CXPAIR(c, s, l, a);
    CHECK(setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0);
    memset(&peer, 0, sizeof peer);
    CHECK(getpeername(c, (struct sockaddr *)&peer, &len) == 0);
    EXPECT_EQ(peer.sin_port, a.sin_port);
    EXPECT_EQ(peer.sin_addr.s_addr, a.sin_addr.s_addr);
    EXPECT_EQ(len, sizeof peer);
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_peer_name_before_context_update_is_enotconn)
{
    struct sockaddr_in peer; int len = sizeof peer, r;
    CXPAIR(c, s, l, a);
    memset(&peer, 0, sizeof peer);
    WSASetLastError(0);
    r = getpeername(c, (struct sockaddr *)&peer, &len);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_sockname_before_context_update_recorded)
{
    struct sockaddr_in me; int len = sizeof me, r;
    CXPAIR(c, s, l, a);
    memset(&me, 0, sizeof me);
    r = getsockname(c, (struct sockaddr *)&me, &len);
    CHECK(r == 0);     /* bound before the connect, so the local name is always known */
    EXPECT_EQ(me.sin_addr.s_addr, XF_LOOPBACK);
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_context_update_with_wrong_length_or_data_recorded)
{
    int one = 1, r;
    CXPAIR(c, s, l, a);
    WSASetLastError(0);
    r = setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, (char *)&one, sizeof one);
    t_note("SO_UPDATE_CONNECT_CONTEXT with 4 bytes of data: %s (error %d)", r == 0 ? "accepted" : "rejected", r ? WSAGetLastError() : 0);
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_context_update_on_never_connected_socket_is_enotconn)
{
    SOCKET x; int r;
    NEED_NET();
    x = bound_tcp();
    REQUIRE(x != INVALID_SOCKET);
    WSASetLastError(0);
    r = setsockopt(x, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(x);
}
TEST(xf_connectex_shutdown_needs_the_context_update)
{
    char b[4]; int r;
    CXPAIR(c, s, l, a);
    WSASetLastError(0);
    r = shutdown(c, SD_SEND);
    CHECK(r == SOCKET_ERROR);
    t_note("shutdown before SO_UPDATE_CONNECT_CONTEXT: error %d", WSAGetLastError());
    CHECK(setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0);
    CHECK(shutdown(c, SD_SEND) == 0);
    WAIT_READABLE(s);
    EXPECT_EQ(xf_recv(s, b, sizeof b, 0), 0);
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_initial_data_is_sent_and_counted)
{
    SOCKET c, s, l; struct sockaddr_in a; long sent = -1; char b[16];
    NEED_NET();
    CHECK(connect_ex_pair(&c, &s, &l, &a, "0123456789", 10, &sent));
    if (s == INVALID_SOCKET) { closesocket(c); closesocket(l); return; }
    EXPECT_EQ(sent, 10);
    memset(b, 0, sizeof b);
    EXPECT_EQ(xf_read_all(s, b, 10), 10);
    CHECK(!memcmp(b, "0123456789", 10));
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_zero_length_initial_data_with_buffer_pointer)
{
    SOCKET c, s, l; struct sockaddr_in a; long sent = -1;
    NEED_NET();
    CHECK(connect_ex_pair(&c, &s, &l, &a, "ignored", 0, &sent));
    if (s == INVALID_SOCKET) { closesocket(c); closesocket(l); return; }
    EXPECT_EQ(sent, 0);
    CHECK(!xf_readable(s, 200));
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_large_initial_data_arrives_intact)
{
    enum { N = 60000 };
    static char out[N], in[N];
    SOCKET c, s, l; struct sockaddr_in a; long sent = -1; int i;
    NEED_NET();
    for (i = 0; i < N; i++) out[i] = (char)(i * 31 + i / 256);
    CHECK(connect_ex_pair(&c, &s, &l, &a, out, N, &sent));
    if (s == INVALID_SOCKET) { closesocket(c); closesocket(l); return; }
    EXPECT_EQ(sent, N);
    EXPECT_EQ(xf_read_all(s, in, N), N);
    CHECK(!memcmp(in, out, N));
    CXCLOSE(c, s, l);
}

TEST(xf_connectex_refused_error_is_econnrefused_through_overlapped_result)
{
    struct sockaddr_in a; SOCKET lst, s; struct op o; DWORD n = 0, err = 0; long r;
    NEED_NET(); NEED_CX(cx);
    lst = xf_listener(&a, 1);
    REQUIRE(lst != INVALID_SOCKET);
    closesocket(lst);                    /* the port is now closed: nothing listens there */
    s = bound_tcp();
    REQUIRE(s != INVALID_SOCKET);
    op_init(&o);
    if (!cx(s, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov)) {
        r = op_finish(s, &o, &err);
        CHECK(r < 0);
        CHECKF(err == WSAECONNREFUSED || err == ERROR_CONNECTION_REFUSED, "error %lu", err);
    } else CHECKF(0, "refused connection reported success");
    op_done(&o);
    closesocket(s);
}
TEST(xf_connectex_on_connected_socket_is_eisconn_with_overlapped_untouched)
{
    struct op o; DWORD n = 0;
    CXPAIR(c, s, l, a);
    {
        connectex_fn cx = get_cx();
        op_init(&o);
        WSASetLastError(0);
        CHECK(!cx(c, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov));
        EXPECT_EQ(WSAGetLastError(), WSAEISCONN);
        op_done(&o);
    }
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_on_accepted_socket_is_eisconn)
{
    struct op o; DWORD n = 0;
    CXPAIR(c, s, l, a);
    {
        connectex_fn cx = get_cx();
        op_init(&o);
        WSASetLastError(0);
        CHECK(!cx(s, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov));
        EXPECT_EQ(WSAGetLastError(), WSAEISCONN);
        op_done(&o);
    }
    CXCLOSE(c, s, l);
}
TEST(xf_connectex_on_datagram_socket_is_einval)
{
    SOCKET u; struct sockaddr_in a, ua; struct op o; DWORD n = 0; SOCKET l; int r; long res;
    NEED_NET(); NEED_CX(cx);
    l = xf_listener(&a, 1);
    REQUIRE(l != INVALID_SOCKET);
    u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(u != INVALID_SOCKET);
    xf_loop4(&ua);
    CHECK(bind(u, (struct sockaddr *)&ua, sizeof ua) == 0);
    op_init(&o);
    WSASetLastError(0);
    r = cx(u, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    op_done(&o);
    closesocket(u); closesocket(l);
}
TEST(xf_connectex_on_listening_socket_is_einval)
{
    struct sockaddr_in a; SOCKET l; struct op o; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    l = xf_listener(&a, 1);
    REQUIRE(l != INVALID_SOCKET);
    op_init(&o);
    WSASetLastError(0);
    CHECK(!cx(l, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov));
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    op_done(&o);
    closesocket(l);
}
TEST(xf_connectex_address_family_mismatch_recorded)
{
    struct sockaddr_in6 a6; SOCKET s; struct op o; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    s = bound_tcp();
    REQUIRE(s != INVALID_SOCKET);
    memset(&a6, 0, sizeof a6);
    a6.sin6_family = AF_INET6; a6.sin6_addr.u.Byte[15] = 1; a6.sin6_port = 0x0900;   /* port 9, network order */
    op_init(&o);
    WSASetLastError(0);
    CHECK(!cx(s, (struct sockaddr *)&a6, sizeof a6, NULL, 0, &n, &o.ov));
    if (WSAGetLastError() == ERROR_IO_PENDING) {
        DWORD err = 0; long rr = op_finish(s, &o, &err);
        t_note("ConnectEx v6 name on a v4 socket: pends, then %s (error %lu)", rr < 0 ? "fails" : "completes", err);
    } else t_note("ConnectEx v6 name on a v4 socket: error %d", WSAGetLastError());
    op_done(&o);
    closesocket(s);
}
TEST(xf_connectex_short_inet_name_is_eaddrnotavail)
{
    struct sockaddr_in a; SOCKET s; struct op o; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    s = bound_tcp();
    REQUIRE(s != INVALID_SOCKET);
    xf_loop4(&a);
    op_init(&o);
    WSASetLastError(0);
    CHECK(!cx(s, (struct sockaddr *)&a, 8, NULL, 0, &n, &o.ov));
    EXPECT_EQ(WSAGetLastError(), WSAEADDRNOTAVAIL);
    op_done(&o);
    closesocket(s);
}
TEST(xf_connectex_unbound_socket_is_einval)
{
    struct sockaddr_in a; SOCKET lst, s; struct op o; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    lst = xf_listener(&a, 1);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(lst != INVALID_SOCKET && s != INVALID_SOCKET);
    op_init(&o);
    WSASetLastError(0);
    CHECK(!cx(s, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov));
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    op_done(&o);
    closesocket(s); closesocket(lst);
}
TEST(xf_connectex_to_port_zero_is_eaddrnotavail)
{
    struct sockaddr_in a; SOCKET lst, s; struct op o; DWORD n = 0;
    NEED_NET(); NEED_CX(cx);
    lst = xf_listener(&a, 1);
    s = bound_tcp();
    REQUIRE(lst != INVALID_SOCKET && s != INVALID_SOCKET);
    a.sin_port = 0;
    op_init(&o);
    WSASetLastError(0);
    if (!cx(s, (struct sockaddr *)&a, sizeof a, NULL, 0, &n, &o.ov)) {
        DWORD err = 0; long r = op_finish(s, &o, &err);
        CHECK(r < 0);
        EXPECT_EQ(err, WSAEADDRNOTAVAIL);
    }
    op_done(&o);
    closesocket(s); closesocket(lst);
}

/* ---- DisconnectEx ------------------------------------------------------------------------------------------- */

TEST(xf_disconnectex_flag_bits_other_than_reuse_are_einval)
{
    static const DWORD flags[] = {1, 3, 4, 8, 0x10, 0x20, 0x100, 0x80000000, 0xFFFFFFFD, 0xFFFFFFFF};
    unsigned i;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
            WSASetLastError(0);
            CHECKF(!dx(p.cli, NULL, flags[i], 0), "flags 0x%lx accepted", flags[i]);
            CHECKF(WSAGetLastError() == WSAEINVAL, "flags 0x%lx: error %d", flags[i], WSAGetLastError());
        }
        /* a rejected call leaves the connection intact */
        CHECK(send(p.cli, "x", 1, 0) == 1);
    }
    xf_pair_close(&p);
}
TEST(xf_disconnectex_nonzero_reserved_is_einval)
{
    static const DWORD res[] = {1, 2, 0x100, 0x80000000, 0xFFFFFFFF};
    unsigned i;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        for (i = 0; i < sizeof res / sizeof res[0]; i++) {
            WSASetLastError(0);
            CHECK(!dx(p.cli, NULL, 0, res[i]));
            CHECKF(WSAGetLastError() == WSAEINVAL, "reserved 0x%lx: error %d", res[i], WSAGetLastError());
        }
    }
    xf_pair_close(&p);
}
TEST(xf_disconnectex_flag_check_precedes_socket_lookup)
{
    NEED_NET(); NEED_DX(dx);
    WSASetLastError(0);
    CHECK(!dx(INVALID_SOCKET, NULL, 1, 0));
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0);
    CHECK(!dx(INVALID_SOCKET, NULL, 0, 7));
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
}
TEST(xf_disconnectex_valid_flags_on_invalid_socket_is_notsock)
{
    NEED_NET(); NEED_DX(dx);
    WSASetLastError(0);
    CHECK(!dx(INVALID_SOCKET, NULL, TF_REUSE_SOCKET, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0);
    CHECK(!dx(INVALID_SOCKET, NULL, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_disconnectex_closed_socket_is_notsock)
{
    SOCKET s;
    NEED_NET(); NEED_DX(dx);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    closesocket(s);
    WSASetLastError(0);
    CHECK(!dx(s, NULL, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
/* The synchronous call is issued from a helper thread so that a call that waits for the peer cannot hang the run. */
struct dxarg { disconnectex_fn dx; SOCKET s; DWORD flags; volatile LONG done; BOOL ok; int err; };
static DWORD WINAPI dx_thread(LPVOID a)
{
    struct dxarg *d = (struct dxarg *)a;
    WSASetLastError(0);
    d->ok = d->dx(d->s, NULL, d->flags, 0);
    d->err = d->ok ? 0 : WSAGetLastError();
    InterlockedExchange(&d->done, 1);
    return 0;
}
TEST(xf_disconnectex_reuse_flag_sync_call_completion)
{
    static struct dxarg a;
    HANDLE h;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        memset(&a, 0, sizeof a);
        a.dx = dx; a.s = p.cli; a.flags = TF_REUSE_SOCKET;
        h = CreateThread(NULL, 0, dx_thread, &a, 0, NULL);
        REQUIRE(h);
        if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) {
            t_note("synchronous DisconnectEx(TF_REUSE_SOCKET) still blocked after 8 s while the peer holds its end open");
            closesocket(p.srv); p.srv = INVALID_SOCKET;
            if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) {
                CHECKF(0, "DisconnectEx did not return even after the peer closed");
                return;
            }
            t_note("it returned once the peer closed its end");
        } else t_note("synchronous DisconnectEx(TF_REUSE_SOCKET) returned without the peer closing");
        CloseHandle(h);
        t_note("result: %s error %d", a.ok ? "success" : "failure", a.err);
    }
    xf_pair_close(&p);
}
TEST(xf_disconnectex_reuse_flag_overlapped_completes_only_after_peer_closes)
{
    /* With TF_REUSE_SOCKET the request waits for the close handshake to finish: the peer sees the end of stream at
     * once, but the completion arrives only after the peer has closed its own end too. */
    struct op o; DWORD n = 0, fl = 0; char b[4]; int r;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        op_init(&o);
        WSASetLastError(0);
        r = dx(p.cli, &o.ov, TF_REUSE_SOCKET, 0);
        CHECK(!r);
        EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
        WAIT_READABLE(p.srv);
        EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);
        closesocket(p.srv); p.srv = INVALID_SOCKET;
        CHECKF(xf_ov_wait(p.cli, &o.ov, &n, &fl, 8000), "completion error %d", WSAGetLastError());
        EXPECT_EQ(n, 0);
        op_done(&o);
    }
    xf_pair_close(&p);
}
TEST(xf_disconnectex_peer_sees_end_of_stream_after_queued_data)
{
    char b[8];
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        CHECK(send(p.cli, "tail", 4, 0) == 4);
        CHECKF(dx(p.cli, NULL, 0, 0), "error %d", WSAGetLastError());
        EXPECT_EQ(xf_read_all(p.srv, b, 4), 4);
        CHECK(!memcmp(b, "tail", 4));
        WAIT_READABLE(p.srv);
        EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);
    }
    xf_pair_close(&p);
}
TEST(xf_disconnectex_unconnected_with_reuse_flag_is_enotconn)
{
    SOCKET s;
    NEED_NET(); NEED_DX(dx);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(0);
    CHECK(!dx(s, NULL, TF_REUSE_SOCKET, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}
TEST(xf_disconnectex_listening_socket_is_enotconn)
{
    struct sockaddr_in a; SOCKET l;
    NEED_NET(); NEED_DX(dx);
    l = xf_listener(&a, 1);
    REQUIRE(l != INVALID_SOCKET);
    WSASetLastError(0);
    CHECK(!dx(l, NULL, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(l);
}
TEST(xf_disconnectex_unconnected_datagram_socket_is_enotconn)
{
    SOCKET u;
    NEED_NET(); NEED_DX(dx);
    u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(u != INVALID_SOCKET);
    WSASetLastError(0);
    CHECK(!dx(u, NULL, 0, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(u);
}
TEST(xf_disconnectex_second_call_after_disconnect_recorded)
{
    int r2;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        CHECK(dx(p.cli, NULL, 0, 0));
        WSASetLastError(0);
        r2 = dx(p.cli, NULL, 0, 0);
        t_note("second DisconnectEx on the same socket: %s (error %d)", r2 ? "succeeds" : "fails", r2 ? 0 : WSAGetLastError());
    }
    xf_pair_close(&p);
}
TEST(xf_disconnectex_overlapped_requires_no_byte_count_and_leaves_pending_error_code)
{
    struct op o; DWORD err = 0;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx();
        REQUIRE(dx);
        op_init(&o);
        WSASetLastError(0);
        if (!dx(p.cli, &o.ov, 0, 0)) {
            long r = op_finish(p.cli, &o, &err);
            CHECKF(r == 0, "completion: %ld err=%lu", r, err);
        }
        op_done(&o);
    }
    xf_pair_close(&p);
}

/* Reuse of a disconnected socket as the connecting side of a new ConnectEx. The documented use of the reuse flag. */
TEST(xf_disconnectex_reuse_then_connectex_again_recorded)
{
    struct sockaddr_in a2, any; SOCKET l2; struct op o; DWORD n = 0, err = 0, fl = 0; int r;
    PAIR(p);
    {
        disconnectex_fn dx = get_dx(); connectex_fn cx = get_cx();
        REQUIRE(dx && cx);
        op_init(&o);
        r = dx(p.cli, &o.ov, TF_REUSE_SOCKET, 0);
        CHECK(!r && WSAGetLastError() == WSA_IO_PENDING);
        closesocket(p.srv); p.srv = INVALID_SOCKET;
        CHECKF(xf_ov_wait(p.cli, &o.ov, &n, &fl, 8000), "completion error %d", WSAGetLastError());
        l2 = xf_listener(&a2, 1);
        REQUIRE(l2 != INVALID_SOCKET);
        WSAResetEvent(o.ov.hEvent);
        memset(&o.ov.Internal, 0, sizeof(o.ov) - offsetof(WSAOVERLAPPED, Internal) - sizeof(HANDLE));
        WSASetLastError(0);
        if (cx(p.cli, (struct sockaddr *)&a2, sizeof a2, NULL, 0, &n, &o.ov)) t_note("ConnectEx on the reused socket as it is: completes inline");
        else {
            long rr = op_finish(p.cli, &o, &err);
            t_note("ConnectEx on the reused socket as it is: %s error %lu", rr < 0 ? "fails" : "completes", err);
            if (rr < 0) {
                /* bind it again and retry */
                xf_loop4(&any);
                WSASetLastError(0);
                r = bind(p.cli, (struct sockaddr *)&any, sizeof any);
                t_note("bind of the reused socket: %s (error %d)", r == 0 ? "ok" : "fails", r ? WSAGetLastError() : 0);
                if (r == 0) {
                    WSAResetEvent(o.ov.hEvent);
                    memset(&o.ov.Internal, 0, sizeof(o.ov) - offsetof(WSAOVERLAPPED, Internal) - sizeof(HANDLE));
                    WSASetLastError(0);
                    if (!cx(p.cli, (struct sockaddr *)&a2, sizeof a2, NULL, 0, &n, &o.ov)) {
                        rr = op_finish(p.cli, &o, &err);
                        t_note("ConnectEx after re-binding: %s error %lu", rr < 0 ? "fails" : "completes", err);
                    } else t_note("ConnectEx after re-binding: completes inline");
                }
            }
        }
        op_done(&o);
        closesocket(l2);
    }
    xf_pair_close(&p);
}

/* ---- AcceptEx: details beyond argument validation ------------------------------------------------------------- */

TEST(xf_acceptex_accept_context_update_makes_peer_name_available)
{
    SOCKET acc, c2; BYTE buf[64]; DWORD got = 0, n, fl; struct op o; struct sockaddr_in me, peer, cli; int len = sizeof me;
    struct sockaddr_in a; SOCKET l;
    NEED_NET(); NEED_AX(ax);
    l = xf_listener(&a, 2);
    acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(l != INVALID_SOCKET && acc != INVALID_SOCKET && c2 != INVALID_SOCKET);
    op_init(&o);
    if (!ax(l, acc, buf, 0, 32, 32, &got, &o.ov) && WSAGetLastError() != ERROR_IO_PENDING) CHECKF(0, "AcceptEx error %d", WSAGetLastError());
    CHECK(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(xf_ov_wait(l, &o.ov, &n, &fl, 5000));
    memset(&cli, 0, sizeof cli);
    len = sizeof cli;
    CHECK(getsockname(c2, (struct sockaddr *)&cli, &len) == 0);
    CHECK(setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof l) == 0);
    len = sizeof peer; memset(&peer, 0, sizeof peer);
    CHECK(getpeername(acc, (struct sockaddr *)&peer, &len) == 0);
    EXPECT_EQ(peer.sin_port, cli.sin_port);
    len = sizeof me; memset(&me, 0, sizeof me);
    CHECK(getsockname(acc, (struct sockaddr *)&me, &len) == 0);
    EXPECT_EQ(me.sin_port, a.sin_port);
    op_done(&o);
    closesocket(c2); closesocket(acc); closesocket(l);
}
TEST(xf_acceptex_accept_context_update_with_wrong_length_is_rejected)
{
    SOCKET acc, c2; BYTE buf[64]; DWORD got = 0, n, fl; struct op o; struct sockaddr_in a; SOCKET l; int r;
    NEED_NET(); NEED_AX(ax);
    l = xf_listener(&a, 2);
    acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(l != INVALID_SOCKET && acc != INVALID_SOCKET && c2 != INVALID_SOCKET);
    op_init(&o);
    ax(l, acc, buf, 0, 32, 32, &got, &o.ov);
    CHECK(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(xf_ov_wait(l, &o.ov, &n, &fl, 5000));
    WSASetLastError(0);
    r = setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, 4);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    op_done(&o);
    closesocket(c2); closesocket(acc); closesocket(l);
}
TEST(xf_acceptex_accepted_socket_carries_data_without_context_update)
{
    SOCKET acc, c2; BYTE buf[64]; DWORD got = 0, n, fl; struct op o; struct sockaddr_in a; SOCKET l; char r[4];
    NEED_NET(); NEED_AX(ax);
    l = xf_listener(&a, 2);
    acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(l != INVALID_SOCKET && acc != INVALID_SOCKET && c2 != INVALID_SOCKET);
    op_init(&o);
    ax(l, acc, buf, 0, 32, 32, &got, &o.ov);
    CHECK(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(xf_ov_wait(l, &o.ov, &n, &fl, 5000));
    CHECK(send(c2, "abcd", 4, 0) == 4);
    EXPECT_EQ(xf_read_all(acc, r, 4), 4);
    CHECK(!memcmp(r, "abcd", 4));
    op_done(&o);
    closesocket(c2); closesocket(acc); closesocket(l);
}
TEST(xf_acceptex_receive_length_zero_does_not_wait_for_data)
{
    SOCKET acc, c2; BYTE buf[64]; DWORD got = 0xdeadbeef, n, fl; struct op o; struct sockaddr_in a; SOCKET l;
    NEED_NET(); NEED_AX(ax);
    l = xf_listener(&a, 2);
    acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(l != INVALID_SOCKET && acc != INVALID_SOCKET && c2 != INVALID_SOCKET);
    op_init(&o);
    ax(l, acc, buf, 0, 32, 32, &got, &o.ov);
    CHECK(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(xf_ov_wait(l, &o.ov, &n, &fl, 5000));      /* completes on connection alone */
    EXPECT_EQ(n, 0);
    op_done(&o);
    closesocket(c2); closesocket(acc); closesocket(l);
}
TEST(xf_acceptex_accept_socket_reusable_after_disconnectex)
{
    SOCKET acc, c2; BYTE buf[64]; DWORD got = 0, n, fl; struct op o, o2; struct sockaddr_in a; SOCKET l; int r;
    NEED_NET(); NEED_AX(ax); NEED_DX(dx);
    l = xf_listener(&a, 2);
    acc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(l != INVALID_SOCKET && acc != INVALID_SOCKET && c2 != INVALID_SOCKET);
    op_init(&o); op_init(&o2);
    ax(l, acc, buf, 0, 32, 32, &got, &o.ov);
    CHECK(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(xf_ov_wait(l, &o.ov, &n, &fl, 5000));
    r = dx(acc, &o2.ov, TF_REUSE_SOCKET, 0);
    CHECK(!r && WSAGetLastError() == WSA_IO_PENDING);
    closesocket(c2);                                  /* the peer's close lets the reuse request finish */
    CHECKF(xf_ov_wait(acc, &o2.ov, &n, &fl, 8000), "DisconnectEx completion error %d", WSAGetLastError());
    c2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    WSAResetEvent(o.ov.hEvent);
    memset(&o.ov.Internal, 0, sizeof(o.ov) - offsetof(WSAOVERLAPPED, Internal) - sizeof(HANDLE));
    WSASetLastError(0);
    if (!ax(l, acc, buf, 0, 32, 32, &got, &o.ov) && WSAGetLastError() != ERROR_IO_PENDING)
        t_note("AcceptEx on a reused accept socket: error %d", WSAGetLastError());
    else {
        CHECK(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
        CHECKF(xf_ov_wait(l, &o.ov, &n, &fl, 5000), "AcceptEx on the reused socket did not complete: %d", WSAGetLastError());
    }
    op_done(&o); op_done(&o2);
    closesocket(c2); closesocket(acc); closesocket(l);
}
