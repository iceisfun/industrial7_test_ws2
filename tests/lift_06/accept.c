/* accept / WSAAccept: alertable wait, condition-function deferral, wake-up on close, address and
 * length out-parameter protocol, and which option state an accepted socket inherits from its listener. */
#include "l6.h"

typedef SOCKET (WINAPI *wsaaccept_fn)(SOCKET, struct sockaddr *, LPINT, LPCONDITIONPROC, DWORD_PTR);
#define WSAACC(s, a, n, cf) (((wsaaccept_fn)t_proc("WSAAccept"))((s), (struct sockaddr *)(a), (n), (cf), 0))

static int CALLBACK defer_all(LPWSABUF a, LPWSABUF b, LPQOS c, LPQOS d, LPWSABUF e, LPWSABUF f, GROUP *g, DWORD_PTR h) { return CF_DEFER; }

struct apc_ctx { HANDLE ev; struct sockaddr_in addr; SOCKET conn; unsigned apc; };
static DWORD WINAPI connect_when_signalled(void *p)
{
    struct apc_ctx *c = p;
    WaitForSingleObject(c->ev, 5000);
    c->conn = w_socket(AF_INET, SOCK_STREAM, 0);
    if (w_connect(c->conn, &c->addr, sizeof c->addr)) { w_close(c->conn); c->conn = INVALID_SOCKET; }
    return 0;
}
static VOID CALLBACK signal_apc(ULONG_PTR p) { struct apc_ctx *c = (struct apc_ctx *)p; c->apc++; SetEvent(c->ev); }

TEST(lift06_accept_is_alertable)
{
    struct sockaddr_in a; SOCKET l, acc; struct apc_ctx c; HANDLE th;
    NEED_WS(); REQUIRE(U(accept));
    l = lo_listener(&a, 5);
    memset(&c, 0, sizeof c);
    c.ev = CreateEventW(NULL, FALSE, FALSE, NULL); c.addr = a; c.conn = INVALID_SOCKET;
    th = CreateThread(NULL, 0, connect_when_signalled, &c, 0, NULL);
    CHECK(QueueUserAPC(signal_apc, GetCurrentThread(), (ULONG_PTR)&c));
    /* The APC runs inside the blocking accept; only then does the helper thread connect. */
    acc = w_accept(l, NULL, NULL);
    CHECK(acc != INVALID_SOCKET);
    EQ(c.apc, 1);
    CHECK(join_thread(th, 5000));
    if (acc != INVALID_SOCKET) w_close(acc);
    if (c.conn != INVALID_SOCKET) w_close(c.conn);
    CloseHandle(c.ev); w_close(l);
}

static SOCKET conn_to(const struct sockaddr_in *a)
{
    SOCKET c = w_socket(AF_INET, SOCK_STREAM, 0);
    if (w_connect(c, a, sizeof *a)) { w_close(c); return INVALID_SOCKET; }
    return c;
}

TEST(lift06_wsaaccept_defer_returns_try_again_and_keeps_connection)
{
    struct sockaddr_in a; SOCKET l, c, acc;
    NEED_WS(); REQUIRE(U(WSAAccept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    CHECK(c != INVALID_SOCKET);
    w_seterr(0);
    acc = WSAACC(l, NULL, NULL, defer_all);
    CHECK(acc == INVALID_SOCKET);
    EQ(w_err(), WSATRY_AGAIN);
    /* The deferred connection is still queued. */
    acc = w_accept(l, NULL, NULL);
    CHECK(acc != INVALID_SOCKET);
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}

struct kill { SOCKET s; HANDLE ready; int killed; };
static DWORD WINAPI accept_blocked(void *p)
{
    struct kill *k = p; SOCKET s;
    SetEvent(k->ready);
    s = w_accept(k->s, NULL, NULL);
    if (s != INVALID_SOCKET) w_close(s);
    k->killed = (s == INVALID_SOCKET);
    return 0;
}
TEST(lift06_accept_blocked_call_fails_when_listener_closed)
{
    struct sockaddr_in a; struct kill k; HANDLE th;
    NEED_WS(); REQUIRE(U(accept));
    k.s = lo_listener(&a, 5); k.killed = 0;
    k.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, accept_blocked, &k, 0, NULL);
    WaitForSingleObject(k.ready, 3000);
    Sleep(200);
    EQ(w_close(k.s), 0);
    CHECK(join_thread(th, 4000));
    CHECK(k.killed);
    CloseHandle(k.ready);
}

TEST(lift06_wsaaccept_zero_length_with_address_is_efault)
{
    struct sockaddr_in a; SOCKET l, c, acc; SOCKADDR_STORAGE ss; int n = 0;
    NEED_WS(); REQUIRE(U(WSAAccept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    w_seterr(0);
    acc = WSAACC(l, &ss, &n, NULL);
    CHECK(acc == INVALID_SOCKET);
    EQ(w_err(), WSAEFAULT);
    EQ(n, 0);
    w_close(c); w_close(l);
}
TEST(lift06_wsaaccept_no_address_ok)
{
    struct sockaddr_in a; SOCKET l, c, acc;
    NEED_WS(); REQUIRE(U(WSAAccept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    acc = WSAACC(l, NULL, NULL, NULL);
    CHECK(acc != INVALID_SOCKET);
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}
TEST(lift06_wsaaccept_storage_sized_buffer_gets_family_and_shorter_length)
{
    struct sockaddr_in a; SOCKET l, c, acc; SOCKADDR_STORAGE ss; int n = sizeof ss;
    NEED_WS(); REQUIRE(U(WSAAccept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    memset(&ss, 0, sizeof ss);
    acc = WSAACC(l, &ss, &n, NULL);
    CHECK(acc != INVALID_SOCKET);
    CHECK(n != (int)sizeof ss);
    EQ(n, sizeof(struct sockaddr_in));
    CHECK(ss.ss_family == AF_INET);
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}
TEST(lift06_accept_zero_length_with_address_is_efault)
{
    struct sockaddr_in a; SOCKET l, c, acc; SOCKADDR_STORAGE ss; int n = 0;
    NEED_WS(); REQUIRE(U(accept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    w_seterr(0);
    acc = w_accept(l, &ss, &n);
    CHECK(acc == INVALID_SOCKET);
    EQ(w_err(), WSAEFAULT);
    EQ(n, 0);
    w_close(c); w_close(l);
}
TEST(lift06_accept_no_address_ok)
{
    struct sockaddr_in a; SOCKET l, c, acc;
    NEED_WS(); REQUIRE(U(accept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    acc = w_accept(l, NULL, NULL);
    CHECK(acc != INVALID_SOCKET);
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}
TEST(lift06_accept_storage_sized_buffer_gets_family_and_shorter_length)
{
    struct sockaddr_in a; SOCKET l, c, acc; SOCKADDR_STORAGE ss; int n = sizeof ss;
    NEED_WS(); REQUIRE(U(accept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    memset(&ss, 0, sizeof ss);
    acc = w_accept(l, &ss, &n);
    CHECK(acc != INVALID_SOCKET);
    EQ(n, sizeof(struct sockaddr_in));
    CHECK(ss.ss_family == AF_INET);
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}
TEST(lift06_accept_address_without_length_leaves_buffer_alone)
{
    struct sockaddr_in a; SOCKET l, c, acc; SOCKADDR_STORAGE ss, zero;
    NEED_WS(); REQUIRE(U(accept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    memset(&ss, 0, sizeof ss); memset(&zero, 0, sizeof zero);
    acc = w_accept(l, &ss, NULL);
    CHECK(acc != INVALID_SOCKET);
    CHECK(!memcmp(&ss, &zero, sizeof ss));
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}
TEST(lift06_accept_reports_peer_address_matching_getpeername)
{
    struct sockaddr_in a, from, pn; SOCKET l, c, acc; int n = sizeof from, pl = sizeof pn;
    NEED_WS(); REQUIRE(U(accept));
    l = lo_listener(&a, 5); c = conn_to(&a);
    acc = w_accept(l, &from, &n);
    CHECK(acc != INVALID_SOCKET);
    EQ(w_getsockname(c, &pn, &pl), 0);
    CHECK(from.sin_addr.s_addr == pn.sin_addr.s_addr);
    CHECK(from.sin_port == pn.sin_port);
    if (acc != INVALID_SOCKET) w_close(acc);
    w_close(c); w_close(l);
}

/* ---- option inheritance ---- */
static void inherit_int(int level, int opt, int val)
{
    struct sockaddr_in a = lo_addr(0), d; SOCKET l, c, s; int got = 0, n = sizeof got, dn = sizeof d;
    l = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(w_setsockopt(l, level, opt, &val, sizeof val), 0);
    EQ(w_bind(l, &a, sizeof a), 0);
    EQ(w_getsockname(l, &d, &dn), 0);
    EQ(w_listen(l, 1), 0);
    c = conn_to(&d);
    s = w_accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        EQ(w_getsockopt(s, level, opt, &got, &n), 0);
        EQ(got, val);
        w_close(s);
    }
    w_close(c); w_close(l);
}
#define INHERIT(nm, lvl, opt, v) TEST(lift06_accept_inherits_##nm) { NEED_WS(); REQUIRE(U(accept)); inherit_int(lvl, opt, v); }
INHERIT(reuseaddr,  SOL_SOCKET, SO_REUSEADDR, 1)
INHERIT(keepalive,  SOL_SOCKET, SO_KEEPALIVE, 1)
INHERIT(oobinline,  SOL_SOCKET, SO_OOBINLINE, 1)
INHERIT(sndbuf,     SOL_SOCKET, SO_SNDBUF, 0x123)
INHERIT(rcvbuf,     SOL_SOCKET, SO_RCVBUF, 0x123)
INHERIT(sndtimeo,   SOL_SOCKET, SO_SNDTIMEO, 0x123)
INHERIT(rcvtimeo,   SOL_SOCKET, SO_RCVTIMEO, 0x123)
INHERIT(nodelay,    IPPROTO_TCP, TCP_NODELAY, 1)

TEST(lift06_accept_inherits_linger)
{
    struct sockaddr_in a = lo_addr(0), d; SOCKET l, c, s; struct linger lg = { 1, 555 }; int n = sizeof lg, dn = sizeof d;
    NEED_WS(); REQUIRE(U(accept));
    l = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(w_setsockopt(l, SOL_SOCKET, SO_LINGER, &lg, sizeof lg), 0);
    EQ(w_bind(l, &a, sizeof a), 0);
    EQ(w_getsockname(l, &d, &dn), 0);
    EQ(w_listen(l, 1), 0);
    c = conn_to(&d);
    s = w_accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        memset(&lg, 0, sizeof lg);
        EQ(w_getsockopt(s, SOL_SOCKET, SO_LINGER, &lg, &n), 0);
        EQ(lg.l_onoff, 1);
        EQ(lg.l_linger, 555);
        w_close(s);
    }
    w_close(c); w_close(l);
}
