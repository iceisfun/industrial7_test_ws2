/* WSAConnectByNameA: parameter validation, address / length out-parameter protocol, socket-type
 * restriction. Only numeric loopback node names and a local listener are used, so no resolver is needed. */
#include "l6.h"

typedef BOOL (WINAPI *cbn_fn)(SOCKET, LPSTR, LPSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval *, LPWSAOVERLAPPED);

static char g_svc[16];
static SOCKET setup(struct sockaddr_in *la)
{
    SOCKET l = lo_listener(la, 4);
    if (l != INVALID_SOCKET) {
        unsigned p = (unsigned)(((la->sin_port & 0xff) << 8) | (la->sin_port >> 8));
        snprintf(g_svc, sizeof g_svc, "%u", p);
    }
    return l;
}
#define CBN(s, node, svc, ll, la, rl, ra, ov) \
    ((cbn_fn)t_proc("WSAConnectByNameA"))((s), (LPSTR)(node), (LPSTR)(svc), (ll), (la), (rl), (ra), NULL, (ov))

TEST(lift06_cbn_fills_all_outputs)
{
    SOCKET l, s; struct sockaddr_in la, loc, rem, sn, pn;
    DWORD ll = sizeof loc, rl = sizeof rem, ctx = TRUE; int snl = sizeof sn, pnl = sizeof pn;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la); CHECK(l != INVALID_SOCKET);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&loc, 0, sizeof loc); memset(&rem, 0, sizeof rem);
    CHECK(CBN(s, "127.0.0.1", g_svc, &ll, (LPSOCKADDR)&loc, &rl, (LPSOCKADDR)&rem, NULL));
    w_setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, &ctx, sizeof ctx);
    EQ(w_getsockname(s, &sn, &snl), 0);
    EQ(w_getpeername(s, &pn, &pnl), 0);
    EQ(snl, sizeof sn);
    EQ(pnl, sizeof pn);
    EQ(ll, sizeof loc);
    EQ(rl, sizeof rem);
    /* The local address output carries the host address but a zero port; the remote one is the peer. */
    EQ(loc.sin_port, 0);
    CHECK(loc.sin_addr.s_addr == sn.sin_addr.s_addr);
    CHECK(!memcmp(&rem, &pn, sizeof rem));
    w_close(s); w_close(l);
}

TEST(lift06_cbn_null_lengths_leave_addresses_untouched)
{
    SOCKET l, s; struct sockaddr_in la, loc, rem, sn, pn; int snl = sizeof sn, pnl = sizeof pn; DWORD ctx = TRUE;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&loc, 0, sizeof loc); memset(&rem, 0, sizeof rem);
    CHECK(CBN(s, "127.0.0.1", g_svc, NULL, (LPSOCKADDR)&loc, NULL, (LPSOCKADDR)&rem, NULL));
    w_setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, &ctx, sizeof ctx);
    EQ(w_getsockname(s, &sn, &snl), 0);
    EQ(w_getpeername(s, &pn, &pnl), 0);
    EQ(snl, sizeof sn);
    EQ(pnl, sizeof pn);
    EQ(loc.sin_family, 0);
    EQ(rem.sin_family, 0);
    w_close(s); w_close(l);
}

TEST(lift06_cbn_null_node_is_einval)
{
    SOCKET s;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_seterr(0);
    CHECK(!CBN(s, NULL, "80", NULL, NULL, NULL, NULL, NULL));
    EQ(w_err(), WSAEINVAL);
    w_close(s);
}

TEST(lift06_cbn_null_service_is_einval_even_on_closed_socket)
{
    SOCKET s;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_close(s);
    /* The name arguments are validated before the socket handle is touched. */
    w_seterr(0);
    CHECK(!CBN(s, "127.0.0.1", NULL, NULL, NULL, NULL, NULL, NULL));
    EQ(w_err(), WSAEINVAL);
}

TEST(lift06_cbn_null_addresses_and_lengths_ok)
{
    SOCKET l, s; struct sockaddr_in la;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(CBN(s, "127.0.0.1", g_svc, NULL, NULL, NULL, NULL, NULL));
    w_close(s); w_close(l);
}

TEST(lift06_cbn_lengths_without_addresses_are_reported)
{
    SOCKET l, s; struct sockaddr_in la; DWORD ll = sizeof(struct sockaddr_in), rl = sizeof(struct sockaddr_in);
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(CBN(s, "127.0.0.1", g_svc, &ll, NULL, &rl, NULL, NULL));
    EQ(ll, sizeof(struct sockaddr_in));
    EQ(rl, sizeof(struct sockaddr_in));
    w_close(s); w_close(l);
}

TEST(lift06_cbn_short_lengths_are_efault)
{
    SOCKET l, s; struct sockaddr_in la, loc, rem; DWORD ll = 3, rl = 3;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_seterr(0);
    CHECK(!CBN(s, "127.0.0.1", g_svc, &ll, (LPSOCKADDR)&loc, &rl, (LPSOCKADDR)&rem, NULL));
    EQ(w_err(), WSAEFAULT);
    EQ(ll, 3);
    EQ(rl, 3);
    w_close(s); w_close(l);
}

TEST(lift06_cbn_long_lengths_are_trimmed_to_sockaddr_in)
{
    SOCKET l, s; struct sockaddr_in la; char loc[64], rem[64]; DWORD ll = 50, rl = 50;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(CBN(s, "127.0.0.1", g_svc, &ll, (LPSOCKADDR)loc, &rl, (LPSOCKADDR)rem, NULL));
    EQ(ll, sizeof(struct sockaddr_in));
    EQ(rl, sizeof(struct sockaddr_in));
    w_close(s); w_close(l);
}

TEST(lift06_cbn_unknown_service_is_type_not_found)
{
    SOCKET s;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    w_seterr(0);
    CHECK(!CBN(s, "127.0.0.1", "nonexistentservice", NULL, NULL, NULL, NULL, NULL));
    EQ(w_err(), WSATYPE_NOT_FOUND);
    w_close(s);
}

TEST(lift06_cbn_datagram_socket_rejected)
{
    SOCKET l, s; struct sockaddr_in la; int e;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    w_seterr(0);
    CHECK(!CBN(s, "127.0.0.1", g_svc, NULL, NULL, NULL, NULL, NULL));
    e = w_err();
    /* Which of the three errors appears depends on the Windows 10 build (EOPNOTSUPP on early builds). */
    CHECKF(e == WSAEINVAL || e == WSAEFAULT || e == WSAEOPNOTSUPP, "err %d", e);
    t_note("datagram socket error class: %s", e == WSAEINVAL ? "EINVAL" : e == WSAEFAULT ? "EFAULT" : e == WSAEOPNOTSUPP ? "EOPNOTSUPP" : "other");
    w_close(s); w_close(l);
}

TEST(lift06_cbn_reserved_pointer_must_be_null)
{
    SOCKET l, s; struct sockaddr_in la; WSAOVERLAPPED ov;
    REQUIRE(U(WSAConnectByNameA)); NEED_WS();
    l = setup(&la);
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&ov, 0, sizeof ov);
    w_seterr(0);
    CHECK(!CBN(s, "127.0.0.1", g_svc, NULL, NULL, NULL, NULL, &ov));
    EQ(w_err(), WSAEINVAL);
    w_close(s); w_close(l);
}
