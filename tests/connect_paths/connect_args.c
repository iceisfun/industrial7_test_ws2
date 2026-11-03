/* connect() / WSAConnect(): argument validation and the order in which the checks fire.
 *
 * Measures, against loopback listeners only:
 *   - socket-handle validation (invalid, zero, non-socket handle, closed socket) -> WSAENOTSOCK
 *   - address-length rules (too short -> WSAEFAULT, longer than the family needs -> accepted and trimmed)
 *   - address-family mismatch -> WSAEAFNOSUPPORT
 *   - precedence between those checks and the socket state checks (connected, listening)
 *   - failed attempts leave the socket unbound and unconnected
 *   - INADDR_ANY / in6addr_any / port 0 destinations -> WSAEADDRNOTAVAIL
 *   - the loopback /8 range, wildcard-bound sockets, IPv6 and dual-stack destinations
 * The same property is usually asserted through connect() and WSAConnect().
 */
#include "cp.h"
#include <limits.h>

/* Scratch sockaddr big enough for any family, zero filled. */
typedef union {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    char raw[128];
} anyaddr;

static void any_from4(anyaddr *u, const struct sockaddr_in *a)
{
    memset(u, 0, sizeof *u);
    u->in = *a;
}
static void any_from6(anyaddr *u, const struct sockaddr_in6 *a)
{
    memset(u, 0, sizeof *u);
    u->in6 = *a;
}

static int try_connect(SOCKET s, const void *a, int len, int use_wsa)
{
    return use_wsa ? cp_WSAConnect(s, (const struct sockaddr *)a, len, NULL, NULL, NULL, NULL)
                   : cp_connect(s, (const struct sockaddr *)a, len);
}

#define KIND_NAME(w) ((w) ? "WSAConnect" : "connect")

/* ---- socket handle validation ------------------------------------------------------------ */

TEST(cpa_connect_invalid_socket)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(connect)); NEED();
    CP_FAILS(cp_connect(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a), WSAENOTSOCK);
}

TEST(cpa_wsaconnect_invalid_socket)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(WSAConnect)); NEED();
    CP_FAILS(cp_WSAConnect(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL), WSAENOTSOCK);
}

TEST(cpa_connect_zero_socket)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(connect)); NEED();
    CP_FAILS(cp_connect(0, (struct sockaddr *)&a, sizeof a), WSAENOTSOCK);
    CP_FAILS(cp_WSAConnect(0, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL), WSAENOTSOCK);
}

TEST(cpa_connect_event_handle_is_not_a_socket)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    HANDLE h;
    REQUIRE(U(connect)); NEED();
    h = CreateEventA(NULL, FALSE, FALSE, NULL);
    CHECK(h != NULL);
    CP_FAILS(cp_connect((SOCKET)h, (struct sockaddr *)&a, sizeof a), WSAENOTSOCK);
    CloseHandle(h);
}

TEST(cpa_connect_closed_socket)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    CP_EQ(cp_closesocket(s), 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a, sizeof a), WSAENOTSOCK);
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL), WSAENOTSOCK);
}

TEST(cpa_invalid_socket_is_checked_before_the_length)
{
    /* The handle lookup happens in the dispatcher, before the provider ever sees the length. */
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(connect)); NEED();
    CP_FAILS(cp_connect(INVALID_SOCKET, (struct sockaddr *)&a, 0), WSAENOTSOCK);
    if (!t_is_wine()) CP_FAILS(cp_connect(INVALID_SOCKET, (struct sockaddr *)&a, -1), WSAENOTSOCK);
}

/* ---- address length ----------------------------------------------------------------------- */

static const int g_short_lens[] = { 0, 1, 2, 3, 4, 8, 12, 15, -1, -16, INT_MIN };

/* A length below the family's minimum (16 for AF_INET) is rejected by the provider before the
 * destination is looked at; the buffer itself is large and valid so only the length is wrong. */
static void short_len_table(int type, int use_wsa)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 4), s;
    anyaddr u;
    size_t i;
    CHECK(l != INVALID_SOCKET);
    any_from4(&u, &la);
    for (i = 0; i < sizeof g_short_lens / sizeof g_short_lens[0]; i++) {
        if (g_short_lens[i] < 0 && t_is_wine()) continue;   /* negative lengths are not meaningful on an emulated stack */
        s = cp_socket(AF_INET, type, 0);
        CHECK(s != INVALID_SOCKET);
        cp_WSASetLastError(0);
        int r = try_connect(s, &u, g_short_lens[i], use_wsa);
        int e = cp_WSAGetLastError();
        t_check(r == SOCKET_ERROR && e == WSAEFAULT, __FILE__, __LINE__, "short length rejected",
                "%s len %d: ret %d err %d", KIND_NAME(use_wsa), g_short_lens[i], r, e);
        cp_closesocket(s);
    }
    CP_EQ(cp_wait(l, CP_R, 200), 0);   /* nothing reached the listener */
    cp_closesocket(l);
}

TEST(cpa_connect_short_length_table_tcp)  { REQUIRE(U(connect)); NEED(); short_len_table(SOCK_STREAM, 0); }
TEST(cpa_connect_short_length_table_udp)  { REQUIRE(U(connect)); NEED(); short_len_table(SOCK_DGRAM, 0); }
TEST(cpa_wsaconnect_short_length_table_tcp) { REQUIRE(U(WSAConnect)); NEED(); short_len_table(SOCK_STREAM, 1); }
TEST(cpa_wsaconnect_short_length_table_udp) { REQUIRE(U(WSAConnect)); NEED(); short_len_table(SOCK_DGRAM, 1); }

TEST(cpa_short_length_leaves_socket_unbound_and_unconnected)
{
    struct sockaddr_in la, n;
    SOCKET l, s;
    int nl = sizeof n;
    anyaddr u;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    any_from4(&u, &la);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&u, 8), WSAEFAULT);
    /* The implicit bind happens only after the length and family checks, so the socket is still unbound. */
    CP_FAILS(cp_getsockname(s, (struct sockaddr *)&n, &nl), WSAEINVAL);
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    /* ... and is still usable for a correct attempt. */
    CP_EQ(cp_connect(s, (struct sockaddr *)&u, sizeof(struct sockaddr_in)), 0);
    CHECK(cp_peer_is(s, &la));
    cp_closesocket(s); cp_closesocket(l);
}

static const int g_long_lens[] = { 16, 17, 20, 24, 28, 32, 64, 100, 128 };

/* Longer than the family needs: the provider trims the length to the family's maximum (16 for AF_INET). */
static void long_len_table(int use_wsa)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 16), s, a;
    anyaddr u;
    size_t i;
    CHECK(l != INVALID_SOCKET);
    any_from4(&u, &la);
    for (i = 0; i < sizeof g_long_lens / sizeof g_long_lens[0]; i++) {
        s = cp_socket(AF_INET, SOCK_STREAM, 0);
        cp_WSASetLastError(0);
        int r = try_connect(s, &u, g_long_lens[i], use_wsa);
        int e = cp_WSAGetLastError();
        t_check(r == 0, __FILE__, __LINE__, "long length accepted", "%s len %d: ret %d err %d",
                KIND_NAME(use_wsa), g_long_lens[i], r, e);
        if (r == 0) {
            CHECK(cp_peer_is(s, &la));
            if (cp_accept_one(l, &a, 2000)) cp_closesocket(a);
        }
        cp_closesocket(s);
    }
    cp_closesocket(l);
}

TEST(cpa_connect_long_length_table)     { REQUIRE(U(connect)); NEED(); long_len_table(0); }
TEST(cpa_wsaconnect_long_length_table)  { REQUIRE(U(WSAConnect)); NEED(); long_len_table(1); }

TEST(cpa_long_length_peer_name_is_trimmed)
{
    /* getpeername reports the 16-byte AF_INET form even when connect() was handed 128 bytes. */
    struct sockaddr_in la, p;
    SOCKET l, s;
    anyaddr u;
    int pl = sizeof p;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    any_from4(&u, &la);
    memset(u.raw + 16, 0xA5, sizeof u.raw - 16);   /* trailing junk must be ignored */
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(s, (struct sockaddr *)&u, 128), 0);
    CP_EQ(cp_getpeername(s, (struct sockaddr *)&p, &pl), 0);
    CP_EQ(pl, sizeof p);
    CHECK(cp_same_addr(&p, &la));
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_sin_zero_bytes_are_ignored)
{
    struct sockaddr_in la, p;
    SOCKET l, s, a;
    int pl = sizeof p;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    memset(la.sin_zero, 0xFF, sizeof la.sin_zero);
    CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    CP_EQ(cp_getpeername(s, (struct sockaddr *)&p, &pl), 0);
    CP_EQ(p.sin_port, la.sin_port);
    CP_EQ(p.sin_addr.s_addr, la.sin_addr.s_addr);
    if (cp_accept_one(l, &a, 2000)) cp_closesocket(a);
    cp_closesocket(s); cp_closesocket(l);
}

/* ---- address family ----------------------------------------------------------------------- */

static const struct { int family; const char *name; } g_bad_fams[] = {
    { AF_UNSPEC, "AF_UNSPEC" }, { AF_UNIX, "AF_UNIX" }, { AF_IPX, "AF_IPX" }, { AF_NETBIOS, "AF_NETBIOS" },
    { AF_INET6, "AF_INET6" }, { 3, "3" }, { 0x7fff, "0x7fff" }, { 0xffff, "0xffff" },
};

static void bad_family_table(int type, int use_wsa)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 4), s;
    anyaddr u;
    size_t i;
    CHECK(l != INVALID_SOCKET);
    for (i = 0; i < sizeof g_bad_fams / sizeof g_bad_fams[0]; i++) {
        any_from4(&u, &la);
        u.in.sin_family = (ADDRESS_FAMILY)g_bad_fams[i].family;
        s = cp_socket(AF_INET, type, 0);
        cp_WSASetLastError(0);
        int r = try_connect(s, &u, sizeof(struct sockaddr_in), use_wsa);
        int e = cp_WSAGetLastError();
        t_check(r == SOCKET_ERROR && e == WSAEAFNOSUPPORT, __FILE__, __LINE__, "wrong family rejected",
                "%s family %s: ret %d err %d", KIND_NAME(use_wsa), g_bad_fams[i].name, r, e);
        cp_closesocket(s);
    }
    CP_EQ(cp_wait(l, CP_R, 200), 0);
    cp_closesocket(l);
}

TEST(cpa_connect_wrong_family_table_tcp)    { REQUIRE(U(connect)); NEED(); bad_family_table(SOCK_STREAM, 0); }
TEST(cpa_connect_wrong_family_table_udp)    { REQUIRE(U(connect)); NEED(); bad_family_table(SOCK_DGRAM, 0); }
TEST(cpa_wsaconnect_wrong_family_table_tcp) { REQUIRE(U(WSAConnect)); NEED(); bad_family_table(SOCK_STREAM, 1); }
TEST(cpa_wsaconnect_wrong_family_table_udp) { REQUIRE(U(WSAConnect)); NEED(); bad_family_table(SOCK_DGRAM, 1); }

TEST(cpa_v6_sockaddr_on_v4_socket_with_full_v6_length)
{
    struct sockaddr_in6 a6 = cp_lo6(cp_ns(9));
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a6, sizeof a6), WSAEAFNOSUPPORT);
    cp_closesocket(s);
}

TEST(cpa_unspec_on_unconnected_datagram_socket_is_not_a_disconnect)
{
    /* AF_UNSPEC with an all-zero body only means "disconnect" on a socket that is connected;
     * on a fresh one it is just a wrong family. */
    struct sockaddr_in z;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    memset(&z, 0, sizeof z);
    s = cp_socket(AF_INET, SOCK_DGRAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&z, sizeof z), WSAEAFNOSUPPORT);
    cp_closesocket(s);
}

TEST(cpa_length_is_checked_before_family)
{
    struct sockaddr_in6 a6 = cp_lo6(cp_ns(9));
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a6, 8), WSAEFAULT);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a6, 15), WSAEFAULT);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a6, 16), WSAEAFNOSUPPORT);
    cp_closesocket(s);
}

TEST(cpa_wrong_family_leaves_socket_unbound)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9)), n;
    SOCKET s;
    int nl = sizeof n;
    REQUIRE(U(connect)); NEED();
    a.sin_family = AF_UNIX;
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a, sizeof a), WSAEAFNOSUPPORT);
    CP_FAILS(cp_getsockname(s, (struct sockaddr *)&n, &nl), WSAEINVAL);
    cp_closesocket(s);
}

/* ---- precedence against the socket state -------------------------------------------------- */

TEST(cpa_listening_socket_checks_length_and_family_before_state)
{
    struct sockaddr_in la, other;
    SOCKET l = cp_listener(&la, 1), l2 = cp_listener(&other, 1);
    anyaddr u;
    REQUIRE(U(connect)); NEED();
    any_from4(&u, &other);
    CP_FAILS(cp_connect(l, (struct sockaddr *)&u, sizeof other), WSAEINVAL);
    CP_FAILS(cp_connect(l, (struct sockaddr *)&u, 0), WSAEFAULT);
    CP_FAILS(cp_WSAConnect(l, (struct sockaddr *)&u, 4, NULL, NULL, NULL, NULL), WSAEFAULT);
    u.in.sin_family = AF_UNIX;
    CP_FAILS(cp_connect(l, (struct sockaddr *)&u, sizeof other), WSAEAFNOSUPPORT);
    CP_FAILS(cp_WSAConnect(l, (struct sockaddr *)&u, sizeof other, NULL, NULL, NULL, NULL), WSAEAFNOSUPPORT);
    cp_closesocket(l); cp_closesocket(l2);
}

TEST(cpa_listening_socket_stays_a_listener_after_failed_connect)
{
    struct sockaddr_in la, other;
    SOCKET l = cp_listener(&la, 2), l2 = cp_listener(&other, 2), c, a = INVALID_SOCKET;
    int acc = 0, n = sizeof acc;
    REQUIRE(U(connect)); NEED();
    CP_FAILS(cp_connect(l, (struct sockaddr *)&other, sizeof other), WSAEINVAL);
    CP_EQ(cp_getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, (char *)&acc, &n), 0);
    CP_EQ(acc, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(cp_accept_one(l, &a, 3000));
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l); cp_closesocket(l2);
}

TEST(cpa_connected_socket_reports_eisconn_before_length_and_family)
{
    SOCKET c, s;
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(connect)); NEED();
    CHECK(cp_pair(&c, &s));
    CP_FAILS(cp_connect(c, (struct sockaddr *)&a, 0), WSAEISCONN);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&a, 4), WSAEISCONN);
    a.sin_family = AF_UNIX;
    CP_FAILS(cp_connect(c, (struct sockaddr *)&a, sizeof a), WSAEISCONN);
    CP_FAILS(cp_WSAConnect(c, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL), WSAEISCONN);
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpa_accepted_socket_reports_eisconn)
{
    SOCKET c, s;
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(connect)); NEED();
    CHECK(cp_pair(&c, &s));
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a, sizeof a), WSAEISCONN);
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL), WSAEISCONN);
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpa_eisconn_does_not_disturb_the_connection)
{
    SOCKET c, s;
    char b[4] = {0};
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    REQUIRE(U(connect)); NEED();
    CHECK(cp_pair(&c, &s));
    CP_FAILS(cp_connect(c, (struct sockaddr *)&a, sizeof a), WSAEISCONN);
    CP_EQ(cp_send(c, "ping", 4, 0), 4);
    CHECK(cp_wait(s, CP_R, 3000) & CP_R);
    CP_EQ(cp_recv(s, b, 4, 0), 4);
    CHECK(!memcmp(b, "ping", 4));
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpa_connect_to_same_listener_twice_is_eisconn)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 4), c, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEISCONN);
    CP_FAILS(cp_WSAConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL), WSAEISCONN);
    /* Only one connection was ever made. */
    CHECK(cp_accept_one(l, &a, 3000));
    cp_closesocket(a);
    CP_EQ(cp_wait(l, CP_R, 200), 0);
    cp_closesocket(c); cp_closesocket(l);
}

/* ---- INADDR_ANY and port 0 ---------------------------------------------------------------- */

TEST(cpa_tcp_connect_to_inaddr_any_is_addrnotavail)
{
    struct sockaddr_in la, any;
    SOCKET l = cp_listener(&la, 1), s;
    REQUIRE(U(connect)); NEED();
    any = cp_lo4(la.sin_port);
    any.sin_addr.s_addr = cp_htonl(INADDR_ANY);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&any, sizeof any), WSAEADDRNOTAVAIL);
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&any, sizeof any, NULL, NULL, NULL, NULL), WSAEADDRNOTAVAIL);
    CP_EQ(cp_wait(l, CP_R, 200), 0);   /* no connection attempt was made */
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_tcp_connect_to_inaddr_any_port_zero_is_addrnotavail)
{
    struct sockaddr_in any = cp_lo4(0);
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    any.sin_addr.s_addr = cp_htonl(INADDR_ANY);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&any, sizeof any), WSAEADDRNOTAVAIL);
    cp_closesocket(s);
}

TEST(cpa_tcp_connect_to_port_zero_is_addrnotavail)
{
    struct sockaddr_in a = cp_lo4(0);
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&a, sizeof a), WSAEADDRNOTAVAIL);
    CP_FAILS(cp_WSAConnect(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL), WSAEADDRNOTAVAIL);
    cp_closesocket(s);
}

TEST(cpa_tcp_connect_failure_leaves_socket_usable)
{
    struct sockaddr_in la, any = cp_lo4(0);
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&any, sizeof any), WSAEADDRNOTAVAIL);
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(cp_accept_one(l, &a, 3000));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_udp_connect_to_inaddr_any_or_port_zero_note)
{
    /* Datagram sockets may treat these differently from TCP; record without asserting. */
    struct sockaddr_in z = cp_lo4(0), p0 = cp_lo4(0);
    SOCKET s;
    int r;
    REQUIRE(U(connect)); NEED();
    z.sin_addr.s_addr = cp_htonl(INADDR_ANY);
    z.sin_port = cp_ns(7);
    s = cp_socket(AF_INET, SOCK_DGRAM, 0);
    cp_WSASetLastError(0);
    r = cp_connect(s, (struct sockaddr *)&z, sizeof z);
    t_note("UDP connect to INADDR_ANY:port -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    cp_closesocket(s);
    s = cp_socket(AF_INET, SOCK_DGRAM, 0);
    cp_WSASetLastError(0);
    r = cp_connect(s, (struct sockaddr *)&p0, sizeof p0);
    t_note("UDP connect to loopback:0 -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    cp_closesocket(s);
}

/* ---- local address selection --------------------------------------------------------------- */

TEST(cpa_connect_assigns_loopback_local_address)
{
    struct sockaddr_in la, n;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    int nl = sizeof n;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    CP_EQ(cp_getsockname(s, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(nl, sizeof n);
    CP_EQ(n.sin_family, AF_INET);
    CP_EQ(n.sin_addr.s_addr, cp_htonl(INADDR_LOOPBACK));
    CP_NE(n.sin_port, 0);
    CP_NE(n.sin_port, la.sin_port);
    if (cp_accept_one(l, &a, 3000)) {
        struct sockaddr_in p; int pl = sizeof p;
        CP_EQ(cp_getpeername(a, (struct sockaddr *)&p, &pl), 0);
        CHECK(cp_same_addr(&p, &n));   /* the acceptor's peer is the connector's local name */
        cp_closesocket(a);
    }
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_connect_keeps_explicit_bind_port)
{
    struct sockaddr_in la, b = cp_lo4(0), n;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    int nl = sizeof n;
    u_short port;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_bind(s, (struct sockaddr *)&b, sizeof b), 0);
    CP_EQ(cp_getsockname(s, (struct sockaddr *)&n, &nl), 0);
    port = n.sin_port;
    CP_NE(port, 0);
    CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    nl = sizeof n;
    CP_EQ(cp_getsockname(s, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(n.sin_port, port);
    if (cp_accept_one(l, &a, 3000)) cp_closesocket(a);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_wildcard_bound_socket_reports_concrete_address_after_connect)
{
    struct sockaddr_in la, w = cp_lo4(0), n;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    int nl = sizeof n;
    REQUIRE(U(connect)); NEED();
    w.sin_addr.s_addr = cp_htonl(INADDR_ANY);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_bind(s, (struct sockaddr *)&w, sizeof w), 0);
    CP_EQ(cp_getsockname(s, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(n.sin_addr.s_addr, cp_htonl(INADDR_ANY));
    CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    nl = sizeof n;
    CP_EQ(cp_getsockname(s, (struct sockaddr *)&n, &nl), 0);
    CP_EQ(n.sin_addr.s_addr, cp_htonl(INADDR_LOOPBACK));
    if (cp_accept_one(l, &a, 3000)) cp_closesocket(a);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_loopback_range_destination_reaches_wildcard_listener)
{
    /* A listener bound to INADDR_ANY accepts a connection aimed at any 127.x.y.z address. */
    struct sockaddr_in w = cp_lo4(0), d;
    SOCKET l, s, a = INVALID_SOCKET;
    int nl = sizeof w;
    REQUIRE(U(connect)); NEED();
    w.sin_addr.s_addr = cp_htonl(INADDR_ANY);
    l = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_bind(l, (struct sockaddr *)&w, sizeof w), 0);
    CP_EQ(cp_getsockname(l, (struct sockaddr *)&w, &nl), 0);
    CP_EQ(cp_listen(l, 2), 0);
    d = cp_lo4(w.sin_port);
    d.sin_addr.s_addr = cp_htonl(0x7F000002);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(s, (struct sockaddr *)&d, sizeof d), 0);
    CHECK(cp_peer_is(s, &d));
    if (cp_accept_one(l, &a, 3000)) {
        struct sockaddr_in n; int k = sizeof n;
        CP_EQ(cp_getsockname(a, (struct sockaddr *)&n, &k), 0);
        CP_EQ(n.sin_addr.s_addr, d.sin_addr.s_addr);   /* the accepted socket carries the address that was dialled */
        cp_closesocket(a);
    }
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_loopback_listener_is_not_reachable_through_other_loopback_address)
{
    /* A listener bound to 127.0.0.1 only does not accept connections to 127.0.0.2. */
    struct sockaddr_in la, d;
    SOCKET l = cp_listener(&la, 1), s;
    REQUIRE(U(connect)); NEED();
    d = la;
    d.sin_addr.s_addr = cp_htonl(0x7F000002);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    CP_EQ(cp_wait(l, CP_R, 200), 0);
    cp_closesocket(s); cp_closesocket(l);
}

/* ---- forwarders ---------------------------------------------------------------------------- */

TEST(cpa_wsock32_connect_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "connect"), b = t_proc_in("wsock32.dll", "connect");
    if (!a || !b) { t_skip("export missing"); return; }
    CHECK(a == b);
}

TEST(cpa_wsock32_connect_works_through_the_forwarder)
{
    struct sockaddr_in la;
    SOCKET l, s, a = INVALID_SOCKET;
    int (WSAAPI *wconnect)(SOCKET, const struct sockaddr *, int);
    REQUIRE(U(connect)); NEED();
    wconnect = (void *)t_proc_in("wsock32.dll", "connect");
    REQUIRE(wconnect);
    l = cp_listener(&la, 1);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(wconnect(s, (struct sockaddr *)&la, sizeof la), 0);
    CP_FAILS(wconnect(s, (struct sockaddr *)&la, sizeof la), WSAEISCONN);
    if (cp_accept_one(l, &a, 3000)) cp_closesocket(a);
    cp_closesocket(s); cp_closesocket(l);
}

/* ---- IPv6 ---------------------------------------------------------------------------------- */

#define NEED6(l6, la6) do { (l6) = cp_listener6(&(la6), 4); if ((l6) == INVALID_SOCKET) { t_skip("IPv6 loopback unavailable"); return; } } while (0)

TEST(cpa_v6_connect_to_loopback_listener)
{
    struct sockaddr_in6 la, p;
    SOCKET l, s, a = INVALID_SOCKET;
    int pl = sizeof p;
    REQUIRE(U(connect)); NEED();
    NEED6(l, la);
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    CP_EQ(cp_connect(s, (struct sockaddr *)&la, sizeof la), 0);
    CP_EQ(cp_getpeername(s, (struct sockaddr *)&p, &pl), 0);
    CP_EQ(pl, sizeof p);
    CP_EQ(p.sin6_port, la.sin6_port);
    CHECK(!memcmp(&p.sin6_addr, &la.sin6_addr, 16));
    CP_FAILS(cp_connect(s, (struct sockaddr *)&la, sizeof la), WSAEISCONN);
    if (cp_accept_one(l, &a, 3000)) cp_closesocket(a);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_v6_short_length_is_efault)
{
    static const int lens[] = { 0, 1, 4, 8, 16, 20, -1 };
    struct sockaddr_in6 la;
    SOCKET l, s;
    anyaddr u;
    size_t i;
    REQUIRE(U(connect)); NEED();
    NEED6(l, la);
    any_from6(&u, &la);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        if (lens[i] < 0 && t_is_wine()) continue;
        s = cp_socket(AF_INET6, SOCK_STREAM, 0);
        cp_WSASetLastError(0);
        int r = cp_connect(s, (struct sockaddr *)&u, lens[i]);
        int e = cp_WSAGetLastError();
        t_check(r == SOCKET_ERROR && e == WSAEFAULT, __FILE__, __LINE__, "v6 short length", "len %d ret %d err %d", lens[i], r, e);
        cp_closesocket(s);
    }
    cp_closesocket(l);
}

TEST(cpa_v6_length_28_and_longer_are_accepted)
{
    static const int lens[] = { 28, 29, 32, 64, 128 };
    struct sockaddr_in6 la;
    SOCKET l, s, a;
    anyaddr u;
    size_t i;
    REQUIRE(U(connect)); NEED();
    NEED6(l, la);
    any_from6(&u, &la);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        s = cp_socket(AF_INET6, SOCK_STREAM, 0);
        cp_WSASetLastError(0);
        int r = cp_connect(s, (struct sockaddr *)&u, lens[i]);
        int e = cp_WSAGetLastError();
        t_check(r == 0, __FILE__, __LINE__, "v6 long length", "len %d ret %d err %d", lens[i], r, e);
        if (r == 0 && cp_accept_one(l, &a, 2000)) cp_closesocket(a);
        cp_closesocket(s);
    }
    cp_closesocket(l);
}

TEST(cpa_v6_length_24_note)
{
    /* sockaddr_in6 without scope id (the pre-scope layout): record whether it is accepted. */
    struct sockaddr_in6 la;
    SOCKET l, s, a;
    int r;
    REQUIRE(U(connect)); NEED();
    NEED6(l, la);
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    r = cp_connect(s, (struct sockaddr *)&la, 24);
    t_note("AF_INET6 connect with length 24 -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    if (r == 0 && cp_accept_one(l, &a, 2000)) cp_closesocket(a);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_v6_socket_with_v4_sockaddr_is_afnosupport)
{
    struct sockaddr_in6 la;
    SOCKET l, s;
    anyaddr u;
    REQUIRE(U(connect)); NEED();
    NEED6(l, la);
    memset(&u, 0, sizeof u);
    u.in = cp_lo4(cp_ns(9));
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&u, 28), WSAEAFNOSUPPORT);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&u, 16), WSAEFAULT);   /* too short for AF_INET6 */
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_v6_any_and_port_zero_are_addrnotavail)
{
    struct sockaddr_in6 la, any, p0;
    SOCKET l, s;
    REQUIRE(U(connect)); NEED();
    NEED6(l, la);
    any = cp_lo6(la.sin6_port);
    memset(&any.sin6_addr, 0, 16);
    p0 = cp_lo6(0);
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&any, sizeof any), WSAEADDRNOTAVAIL);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&p0, sizeof p0), WSAEADDRNOTAVAIL);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_v6_dual_stack_socket_reaches_v4_listener_via_mapped_address)
{
    struct sockaddr_in la;
    struct sockaddr_in6 m;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    DWORD off = 0;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { cp_closesocket(l); t_skip("IPv6 unavailable"); return; }
    if (cp_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof off)) {
        t_note("IPV6_V6ONLY clear failed: %d", cp_WSAGetLastError());
        cp_closesocket(s); cp_closesocket(l);
        return;
    }
    memset(&m, 0, sizeof m);
    m.sin6_family = AF_INET6;
    m.sin6_port = la.sin_port;
    m.sin6_addr.u.Byte[10] = 0xFF; m.sin6_addr.u.Byte[11] = 0xFF;
    m.sin6_addr.u.Byte[12] = 127; m.sin6_addr.u.Byte[15] = 1;
    CP_EQ(cp_connect(s, (struct sockaddr *)&m, sizeof m), 0);
    CHECK(cp_accept_one(l, &a, 3000));
    if (a != INVALID_SOCKET) {
        struct sockaddr_in p; int pl = sizeof p;
        CP_EQ(cp_getpeername(a, (struct sockaddr *)&p, &pl), 0);
        CP_EQ(p.sin_family, AF_INET);   /* the listener sees a plain IPv4 peer */
        CP_EQ(p.sin_addr.s_addr, cp_htonl(INADDR_LOOPBACK));
        cp_closesocket(a);
    }
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_v6_only_socket_with_mapped_address_note)
{
    struct sockaddr_in la;
    struct sockaddr_in6 m;
    SOCKET l = cp_listener(&la, 1), s;
    DWORD on = 1;
    int r;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { cp_closesocket(l); t_skip("IPv6 unavailable"); return; }
    cp_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof on);
    memset(&m, 0, sizeof m);
    m.sin6_family = AF_INET6;
    m.sin6_port = la.sin_port;
    m.sin6_addr.u.Byte[10] = 0xFF; m.sin6_addr.u.Byte[11] = 0xFF;
    m.sin6_addr.u.Byte[12] = 127; m.sin6_addr.u.Byte[15] = 1;
    cp_nb(s, 1);
    cp_WSASetLastError(0);
    r = cp_connect(s, (struct sockaddr *)&m, sizeof m);
    t_note("v6-only connect to mapped address -> %d (err %d)", r, r ? cp_WSAGetLastError() : 0);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpa_v6_loopback_dead_port_is_refused)
{
    struct sockaddr_in6 d;
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    if (!cp_dead_port6(&d)) { t_skip("IPv6 loopback unavailable"); return; }
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, (struct sockaddr *)&d, sizeof d), WSAECONNREFUSED);
    cp_closesocket(s);
}
