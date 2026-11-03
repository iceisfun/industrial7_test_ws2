/* connect() corner cases that cut across the other connect_paths files:
 *   - a second connect while the first one is still completing on a non-blocking socket
 *   - a connection made with ConnectEx is not yet "connected" for plain connect() until the
 *     connect context has been updated
 *   - closing a socket whose non-blocking connect has not been observed yet
 *   - a NULL name with a zero length, and connect on sockets that are already part of a connection
 *   - many sequential connections to one listener
 * Loopback listeners on ephemeral ports only; all waits are bounded.
 */
#include "cp.h"

#define WAIT_MS 5000

TEST(cpx_nb_second_connect_is_already_or_isconn)
{
    /* Right after WSAEWOULDBLOCK the attempt is either still in flight (WSAEALREADY) or has just
     * completed (WSAEISCONN); nothing else is acceptable. */
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    int r, e;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    cp_WSASetLastError(0);
    r = cp_connect(c, (struct sockaddr *)&la, sizeof la);
    e = cp_WSAGetLastError();
    t_check(r == SOCKET_ERROR && (e == WSAEALREADY || e == WSAEISCONN), __FILE__, __LINE__,
            "second connect refused", "ret %d err %d", r, e);
    t_note("second connect while completing -> %s", e == WSAEALREADY ? "WSAEALREADY" : e == WSAEISCONN ? "WSAEISCONN" : "other");
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    CHECK(cp_peer_is(c, &la));
    if (cp_accept_one(l, &a, WAIT_MS)) cp_closesocket(a);
    cp_closesocket(c); cp_closesocket(l);
}

TEST(cpx_nb_second_wsaconnect_is_already_or_isconn)
{
    struct sockaddr_in la;
    SOCKET l, c, a = INVALID_SOCKET;
    int r, e;
    REQUIRE(U(WSAConnect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_WSAConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL), WSAEWOULDBLOCK);
    cp_WSASetLastError(0);
    r = cp_WSAConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL);
    e = cp_WSAGetLastError();
    t_check(r == SOCKET_ERROR && (e == WSAEALREADY || e == WSAEISCONN), __FILE__, __LINE__,
            "second WSAConnect refused", "ret %d err %d", r, e);
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    if (cp_accept_one(l, &a, WAIT_MS)) cp_closesocket(a);
    cp_closesocket(c); cp_closesocket(l);
}

TEST(cpx_nb_connect_to_other_listener_while_completing_fails)
{
    /* A different destination while the first attempt is in flight cannot start a second attempt. */
    struct sockaddr_in la, lb;
    SOCKET l1, l2, c, a = INVALID_SOCKET;
    int r, e;
    REQUIRE(U(connect)); NEED();
    l1 = cp_listener(&la, 1);
    l2 = cp_listener(&lb, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    cp_WSASetLastError(0);
    r = cp_connect(c, (struct sockaddr *)&lb, sizeof lb);
    e = cp_WSAGetLastError();
    t_check(r == SOCKET_ERROR && (e == WSAEALREADY || e == WSAEISCONN), __FILE__, __LINE__,
            "other destination refused", "ret %d err %d", r, e);
    CHECK(cp_wait(c, CP_W, WAIT_MS) & CP_W);
    CHECK(cp_peer_is(c, &la));                      /* still the first peer */
    CP_EQ(cp_wait(l2, CP_R, 200), 0);               /* the second listener never saw anything */
    if (cp_accept_one(l1, &a, WAIT_MS)) cp_closesocket(a);
    cp_closesocket(c); cp_closesocket(l1); cp_closesocket(l2);
}

TEST(cpx_connectex_socket_needs_context_update_for_plain_connect)
{
    struct sockaddr_in la, any = cp_lo4(0);
    GUID g = WSAID_CONNECTEX;
    LPFN_CONNECTEX pCx = NULL;
    OVERLAPPED ov;
    DWORD got = 0, sent = 0;
    SOCKET l, c, a = INVALID_SOCKET;
    int r, e;
    REQUIRE(U(WSAIoctl)); REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cp_WSAIoctl(c, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &pCx, sizeof pCx, &got, NULL, NULL) || !pCx) {
        t_skip("ConnectEx not available");
        cp_closesocket(c); cp_closesocket(l);
        return;
    }
    CP_EQ(cp_bind(c, (struct sockaddr *)&any, sizeof any), 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    r = pCx(c, (struct sockaddr *)&la, sizeof la, NULL, 0, &sent, &ov);
    if (!r) CP_EQ(cp_WSAGetLastError(), ERROR_IO_PENDING);
    CP_EQ(WaitForSingleObject(ov.hEvent, WAIT_MS), WAIT_OBJECT_0);
    CHECK(cp_accept_one(l, &a, WAIT_MS));

    /* Winsock has not been told the socket is connected yet: plain connect() reports WSAEINVAL. */
    cp_WSASetLastError(0);
    r = cp_connect(c, (struct sockaddr *)&la, sizeof la);
    e = cp_WSAGetLastError();
    t_check(r == SOCKET_ERROR && e == WSAEINVAL, __FILE__, __LINE__, "connect before context update",
            "ret %d err %d", r, e);

    CP_EQ(cp_setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), 0);
    cp_WSASetLastError(0);
    r = cp_connect(c, (struct sockaddr *)&la, sizeof la);
    e = cp_WSAGetLastError();
    CP_EQ(r, SOCKET_ERROR);
    t_note("connect after SO_UPDATE_CONNECT_CONTEXT -> err %s", e == WSAEISCONN ? "WSAEISCONN" : "other");
    CHECK(cp_peer_is(c, &la));
    CloseHandle(ov.hEvent);
    if (a != INVALID_SOCKET) cp_closesocket(a);
    cp_closesocket(c); cp_closesocket(l);
}

TEST(cpx_close_right_after_wouldblock_leaves_listener_usable)
{
    struct sockaddr_in la;
    SOCKET l, c, c2, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 4);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_nb(c, 1);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, sizeof la), WSAEWOULDBLOCK);
    CP_EQ(cp_closesocket(c), 0);
    /* The abandoned attempt may or may not be queued; drain whatever is there. */
    while (cp_accept_one(l, &a, 300)) { cp_closesocket(a); a = INVALID_SOCKET; }
    /* The listener still works. */
    c2 = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c2, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    if (a != INVALID_SOCKET) cp_closesocket(a);
    cp_closesocket(c2); cp_closesocket(l);
}

TEST(cpx_null_name_with_zero_length_is_efault)
{
    SOCKET s;
    REQUIRE(U(connect)); NEED();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_FAILS(cp_connect(s, NULL, 0), WSAEFAULT);
    CP_FAILS(cp_WSAConnect(s, NULL, 0, NULL, NULL, NULL, NULL), WSAEFAULT);
    cp_closesocket(s);
    s = cp_socket(AF_INET, SOCK_DGRAM, 0);
    CP_FAILS(cp_connect(s, NULL, 0), WSAEFAULT);
    cp_closesocket(s);
}

TEST(cpx_connect_on_accepted_socket_is_eisconn)
{
    struct sockaddr_in la, other;
    SOCKET l, o, c, a = INVALID_SOCKET;
    REQUIRE(U(connect)); NEED();
    l = cp_listener(&la, 1);
    o = cp_listener(&other, 1);
    c = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(cp_connect(c, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    CP_FAILS(cp_connect(a, (struct sockaddr *)&other, sizeof other), WSAEISCONN);
    CP_FAILS(cp_connect(a, (struct sockaddr *)&la, sizeof la), WSAEISCONN);
    CP_FAILS(cp_WSAConnect(a, (struct sockaddr *)&other, sizeof other, NULL, NULL, NULL, NULL), WSAEISCONN);
    CP_EQ(cp_wait(o, CP_R, 200), 0);
    cp_closesocket(a); cp_closesocket(c); cp_closesocket(l); cp_closesocket(o);
}

TEST(cpx_connected_state_beats_bad_length_and_family)
{
    /* On a connected stream socket the state check comes before the length and family checks. */
    struct sockaddr_in la, bad;
    SOCKET c, a;
    REQUIRE(U(connect)); NEED();
    CHECK(cp_pair(&c, &a));
    la = cp_lo4(cp_ns(9));
    bad = la;
    bad.sin_family = AF_UNIX;
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, 4), WSAEISCONN);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&bad, sizeof bad), WSAEISCONN);
    CP_FAILS(cp_connect(c, (struct sockaddr *)&la, 0), WSAEISCONN);
    cp_closesocket(a); cp_closesocket(c);
}

TEST(cpx_sequential_connections_get_distinct_local_ports)
{
    enum { N = 12 };
    struct sockaddr_in la, n;
    SOCKET l = cp_listener(&la, N), c[N], a;
    unsigned short ports[N];
    int i, j, nl, dup = 0, ok = 0;
    REQUIRE(U(connect)); NEED();
    for (i = 0; i < N; i++) {
        c[i] = cp_socket(AF_INET, SOCK_STREAM, 0);
        if (cp_connect(c[i], (struct sockaddr *)&la, sizeof la) == 0) {
            ok++;
            nl = sizeof n;
            ports[i] = cp_getsockname(c[i], (struct sockaddr *)&n, &nl) == 0 ? n.sin_port : 0;
        } else ports[i] = 0;
    }
    CHECK(l != INVALID_SOCKET);
    CP_EQ(ok, N);
    for (i = 0; i < N; i++) {
        CHECK(ports[i] != 0);
        for (j = i + 1; j < N; j++) if (ports[i] == ports[j]) dup++;
    }
    CP_EQ(dup, 0);
    for (i = 0; i < N; i++) if (cp_accept_one(l, &a, WAIT_MS)) cp_closesocket(a);
    for (i = 0; i < N; i++) cp_closesocket(c[i]);
    cp_closesocket(l);
}
