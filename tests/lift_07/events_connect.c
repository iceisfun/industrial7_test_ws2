/* Measures FD_CONNECT / FD_WRITE notification around connection establishment through WSAEventSelect and
 * WSAAsyncSelect: non-blocking connects, selecting after the connection exists, selecting a subset first,
 * connected UDP sockets and the error code reported for a refused connection. */
#include "lift07.h"

#define CN_ALL (FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE)

static int cn_connect_ok(SOCKET s, const struct sockaddr_in *a)
{
    int r = U(connect)(s, (const struct sockaddr *)a, sizeof(*a));
    return r == 0 || l7_err() == WSAEWOULDBLOCK;
}

L7EVTEST(l07_connect_nonblocking_events)
{
    struct sockaddr_in a; SOCKET l = l7_listener(&a, 2), cl, sv;
    if (l == INVALID_SOCKET) { t_skip("no listener"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l7_select(c, cl, CN_ALL);
    L7_NONE(c);
    CHECK(cn_connect_ok(cl, &a));
    l7_expect(c, FD_CONNECT, FD_WRITE, 1000);
    L7_NONE(c);
    l7_select(c, cl, 0);
    l7_select(c, cl, CN_ALL);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);

    sv = U(accept)(l, NULL, NULL);
    CHECK(sv != INVALID_SOCKET);
    l7_select(c, sv, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    l7_expect(c, FD_WRITE, 0, 1000);
    l7_close(cl); l7_close(sv); l7_close(l);
}

L7EVTEST(l07_connect_then_select)
{
    /* Select after the connection is already up: an event object also reports FD_CONNECT, window messages
     * only FD_WRITE. */
    struct sockaddr_in a; SOCKET l = l7_listener(&a, 2), cl, sv;
    if (l == INVALID_SOCKET) { t_skip("no listener"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(U(connect)(cl, (struct sockaddr *)&a, sizeof(a)) == 0);
    sv = U(accept)(l, NULL, NULL);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_select(c, cl, CN_ALL);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    else               l7_expect(c, FD_CONNECT, FD_WRITE, 1000);
    l7_close(cl); l7_close(sv); l7_close(l);
}

L7EVTEST(l07_connect_select_subset_without_connect_first)
{
    struct sockaddr_in a; SOCKET l = l7_listener(&a, 2), cl, sv;
    if (l == INVALID_SOCKET) { t_skip("no listener"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l7_select(c, cl, FD_ACCEPT | FD_CLOSE | FD_OOB | FD_READ | FD_WRITE);
    CHECK(cn_connect_ok(cl, &a));
    sv = U(accept)(l, NULL, NULL);
    CHECK(sv != INVALID_SOCKET);
    l7_expect(c, FD_WRITE, 0, 1000);
    l7_select(c, cl, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    else               l7_expect(c, FD_CONNECT, 0, 1000);
    l7_close(cl); l7_close(sv); l7_close(l);
}

L7EVTEST(l07_connect_udp_unconnected_quiet)
{
    /* A fresh datagram socket is writable at once (messages) or silent (event objects). */
    SOCKET cl = l7_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(cl != INVALID_SOCKET);
    l7_select(c, cl, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_close(cl);
}

L7EVTEST(l07_connect_udp_connect_reports_connect_and_write)
{
    struct sockaddr_in a; int len = sizeof(a);
    SOCKET cl = l7_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP), sv = l7_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(cl != INVALID_SOCKET && sv != INVALID_SOCKET);
    l7_select(c, cl, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_loop_addr(&a, 0);
    CHECK(U(bind)(sv, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(U(getsockname)(sv, (struct sockaddr *)&a, &len) == 0);
    CHECK(U(connect)(cl, (struct sockaddr *)&a, sizeof(a)) == 0);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    else               l7_expect(c, FD_CONNECT, FD_WRITE, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

/* Address of a loopback port nobody listens on (a listener was just closed there). */
static BOOL cn_dead_port(struct sockaddr_in *a)
{
    SOCKET l = l7_listener(a, 1);
    if (l == INVALID_SOCKET) return FALSE;
    l7_close(l);
    return TRUE;
}
#define CN_REFUSED MAKELONG(FD_CONNECT, WSAECONNREFUSED)

L7EVTEST(l07_connect_refused_reports_error_code)
{
    /* Loopback refusals can take a few seconds to be reported; wait generously and skip when the
     * report does not arrive in time. */
    struct sockaddr_in dead; int r; SOCKET cl;
    if (!cn_dead_port(&dead)) { t_skip("no port"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l7_select(c, cl, CN_ALL);
    L7_NONE(c);
    r = U(connect)(cl, (struct sockaddr *)&dead, sizeof(dead));
    CHECK(r == SOCKET_ERROR);
    if (!l7_notified(c, 8000)) { l7_close(cl); t_skip("refusal not reported in time"); return; }
    l7_expect(c, CN_REFUSED, 0, 0);
    L7_NONE(c);

    /* the same again on the same socket behaves identically */
    r = U(connect)(cl, (struct sockaddr *)&dead, sizeof(dead));
    CHECK(r == SOCKET_ERROR);
    if (!l7_notified(c, 8000)) { l7_close(cl); t_skip("second refusal not reported in time"); return; }
    l7_expect(c, CN_REFUSED, 0, 0);
    L7_NONE(c);
    l7_close(cl);
}

L7EVTEST(l07_connect_refused_then_bad_length_connect)
{
    struct sockaddr_in dead; int r; SOCKET cl;
    if (!cn_dead_port(&dead)) { t_skip("no port"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l7_select(c, cl, CN_ALL);
    r = U(connect)(cl, (struct sockaddr *)&dead, sizeof(dead));
    CHECK(r == SOCKET_ERROR);
    r = U(connect)(cl, (struct sockaddr *)&dead, 1);          /* invalid length while the first is in flight */
    CHECK(r == SOCKET_ERROR);
    if (!l7_notified(c, 8000)) { l7_close(cl); t_skip("refusal not reported in time"); return; }
    l7_expect(c, CN_REFUSED, 0, 0);
    L7_NONE(c);
    l7_close(cl);
}

L7EVTEST(l07_connect_refused_then_bad_family_connect)
{
    struct sockaddr_in dead, bad; int r; SOCKET cl;
    if (!cn_dead_port(&dead)) { t_skip("no port"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l7_select(c, cl, CN_ALL);
    r = U(connect)(cl, (struct sockaddr *)&dead, sizeof(dead));
    CHECK(r == SOCKET_ERROR);
    bad = dead; bad.sin_family = 0xf1;
    r = U(connect)(cl, (struct sockaddr *)&bad, sizeof(bad));
    CHECK(r == SOCKET_ERROR);
    if (!l7_notified(c, 8000)) { l7_close(cl); t_skip("refusal not reported in time"); return; }
    l7_expect(c, CN_REFUSED, 0, 0);
    L7_NONE(c);
    l7_close(cl);
}

L7EVTEST(l07_connect_refused_then_successful_connect)
{
    /* Event objects only: after a refusal, a connect to a live listener is reported as FD_CONNECT|FD_WRITE
     * and the socket polls writable; right after the refused attempt nothing is pollable yet. */
    struct sockaddr_in dead, live; SOCKET l, cl; int r;
    if (c->is_message) { t_skip("event-object mode only"); return; }
    if (!cn_dead_port(&dead)) { t_skip("no port"); return; }
    l = l7_listener(&live, 2);
    if (l == INVALID_SOCKET) { t_skip("no listener"); return; }
    cl = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l7_select(c, cl, CN_ALL);
    L7_NONE(c);
    r = U(connect)(cl, (struct sockaddr *)&dead, sizeof(dead));
    CHECK(r == SOCKET_ERROR);
    CHECKF(l7_poll(cl, POLLRDNORM | POLLRDBAND | POLLWRNORM) == 0, "pollable right after refused connect");
    if (!l7_notified(c, 8000)) { l7_close(cl); l7_close(l); t_skip("refusal not reported in time"); return; }
    Sleep(500);
    r = U(connect)(cl, (struct sockaddr *)&live, sizeof(live));
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAEWOULDBLOCK, "r=%d err=%d", r, l7_err());
    CHECKF(l7_poll(cl, POLLRDNORM | POLLRDBAND | POLLWRNORM) == POLLWRNORM, "not writable");
    l7_expect(c, FD_CONNECT | FD_WRITE, 0, 4000);
    L7_NONE(c);
    l7_close(cl); l7_close(l);
}
