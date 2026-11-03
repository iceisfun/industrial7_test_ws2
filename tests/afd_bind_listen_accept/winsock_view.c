/* What the Winsock layer shows for endpoints that were set up (or only partly set up) through the raw
 * requests, and what the raw requests show for endpoints set up through Winsock.
 *
 * The Winsock layer keeps a user-mode record per socket (bound, listening, connected, local name). The
 * driver knows nothing about that record, and the record is only updated by Winsock's own calls, so a
 * socket driven through the raw requests keeps a Winsock-level state that disagrees with the driver's.
 */
#include "abl.h"

static int acceptconn(SOCKET s) {
    int v = -1, len = sizeof v;
    CHECK(W.getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &len) == 0);
    return v;
}

TEST(ablv_winsock_listen_marks_acceptconn) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    CHECK(acceptconn(s) == 0);
    CHECK(W.listen(s, 3) == 0);
    CHECK(acceptconn(s) != 0);
    abl_close(s);
}
TEST(ablv_raw_listen_not_visible_as_acceptconn) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    CHECK_NS(abl_raw_listen(s, 3, 0), NS_SUCCESS);
    CHECK(acceptconn(s) == 0);
    abl_close(s);
}
TEST(ablv_winsock_listen_after_raw_listen_fails) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    CHECK_NS(abl_raw_listen(s, 3, 0), NS_SUCCESS);
    SET_ERR(0);
    CHECK(W.listen(s, 3) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(s);
}
TEST(ablv_raw_listen_after_winsock_listen_fails) {
    ABL_BEGIN();
    SOCKET s = abl_listener(NULL);
    CHECK_NS(abl_raw_listen(s, 3, 0), NS_INVALID_PARAMETER);
    CHECK(acceptconn(s) != 0);                      /* still listening, unchanged */
    abl_close(s);
}
TEST(ablv_winsock_accept_on_raw_listener_fails) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET s = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(abl_raw_listen(s, 3, 0), NS_SUCCESS);
    SOCKET c = abl_tcp();
    CHECK(abl_connect(c, &a) == 0);
    SET_ERR(0);
    SOCKET t = W.accept(s, NULL, NULL);
    CHECK(t == INVALID_SOCKET);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(c); abl_close(s);
}
TEST(ablv_winsock_connect_reaches_raw_listener) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET s = abl_bound(SOCK_STREAM, &a);
    CHECK_NS(abl_raw_listen(s, 3, 0), NS_SUCCESS);
    SOCKET c = abl_tcp(); struct sockaddr_in p; int len = sizeof p;
    CHECK(abl_connect(c, &a) == 0);
    CHECK(W.getpeername(c, (struct sockaddr *)&p, &len) == 0);
    CHECK(!memcmp(&p, &a, sizeof p));
    abl_close(c); abl_close(s);
}
TEST(ablv_getsockname_on_raw_bound_socket_fails) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o, n; int len = sizeof n;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    SET_ERR(0);
    CHECK(W.getsockname(s, (struct sockaddr *)&n, &len) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(s);
}
TEST(ablv_winsock_listen_on_raw_bound_socket_fails) {
    ABL_BEGIN();
    SOCKET s = abl_tcp(); struct sockaddr_in o;
    CHECK_NS(abl_raw_bind4(s, 0, LO4, 0, &o), NS_SUCCESS);
    SET_ERR(0);
    CHECK(W.listen(s, 3) == SOCKET_ERROR);
    CHECK(W.WSAGetLastError() == WSAEINVAL);
    abl_close(s);
}
TEST(ablv_winsock_listener_serves_raw_wait_and_accept) {
    /* a Winsock-created listener is a plain driver listener: the raw wait/accept pair works on it */
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    SOCKET c = abl_client_to(&a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    BYTE out[64]; IO_STATUS_BLOCK io; ABL_ACCEPT aa;
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io, NULL), NS_SUCCESS);
    SOCKET t = abl_tcp();
    memset(&aa, 0, sizeof aa); aa.sequence = *(ULONG *)out; aa.accept_handle = (HANDLE)t;
    CHECK_NS(abl_ctl(l, IO_ACCEPT, &aa, sizeof aa, NULL, 0, &io, NULL), NS_SUCCESS);
    CHECK(abl_wait_writable(c, WAIT_MS));
    abl_nonblock(c, 0);
    CHECK(W.send(c, "k", 1, 0) == 1);
    char b = 0;
    CHECK(abl_wait_readable(t, WAIT_MS));
    CHECK(W.recv(t, &b, 1, 0) == 1 && b == 'k');
    abl_close(t); abl_close(c); abl_close(l);
}
TEST(ablv_winsock_accept_consumes_what_wait_would_report) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    SOCKET c = abl_tcp();
    CHECK(abl_connect(c, &a) == 0);
    CHECK(abl_wait_readable(l, WAIT_MS));
    SOCKET t = W.accept(l, NULL, NULL);
    CHECK(t != INVALID_SOCKET);
    /* nothing is left waiting: a raw wait on the same listener stays pending */
    BYTE out[64]; IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK_NS(abl_submit(l, ev, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io), NS_PENDING);
    CHECK(abl_wait(l, ev, &io, 300) == WAIT_TIMEOUT);
    CHECK_NS(io.Status, NS_CANCELLED);
    CloseHandle(ev); abl_close(t); abl_close(c); abl_close(l);
}
TEST(ablv_raw_name_equals_winsock_name_for_every_bound_kind) {
    ABL_BEGIN();
    for (int k = 0; k < 3; k++) {
        struct sockaddr_in a, q, n; int len = sizeof q; IO_STATUS_BLOCK io;
        SOCKET s = k == 0 ? abl_bound(SOCK_STREAM, &a) : k == 1 ? abl_bound(SOCK_DGRAM, &a) : abl_listener(&a);
        CHECK(W.getsockname(s, (struct sockaddr *)&q, &len) == 0);
        CHECK_NS(abl_raw_name(s, &n, sizeof n, &io), NS_SUCCESS);
        CHECK(!memcmp(&q, &n, sizeof n));
        CHECK(!memcmp(&a, &n, sizeof n));
        abl_close(s);
    }
}
