/* WSAPoll: parameter validation, handling of invalid descriptors, the event masks reported for
 * listening, connected, out-of-band, half-closed, reset, refused and UDP sockets, and closing a
 * socket while it is being polled.  Loopback only; every poll has a bounded timeout.
 */
#include "l8.h"

static const short invalid_event_bits[] = {
    POLLERR, POLLHUP, POLLNVAL, 0x8, POLLWRBAND, 0x40, 0x80, POLLPRI, 0x800, 0x1000, 0x2000, 0x4000, (short)0x8000,
};

#define POLL_IN_BITS (POLLRDNORM | POLLRDBAND)

/* Connect a nonblocking client to the listener and accept it; both ends end up nonblocking. */
static void connect_trio(SOCKET listener, const struct sockaddr_in *addr, SOCKET *client, SOCKET *server)
{
    WSAPOLLFD p;
    *client = w_socket(AF_INET, SOCK_STREAM, 0);
    l8_nonblocking(*client, TRUE);
    CHECK(w_connect(*client, (const struct sockaddr *)addr, sizeof *addr) == 0 || w_WSAGetLastError() == WSAEWOULDBLOCK);
    p.fd = listener; p.events = POLLRDNORM; p.revents = 0;
    CHECK(w_WSAPoll(&p, 1, 3000) == 1);
    *server = w_accept(listener, NULL, NULL);
    CHECK(*server != INVALID_SOCKET);
    l8_nonblocking(*server, TRUE);
}

TEST(l8_wsapoll_bad_parameters)
{
    NEED_WS();
    w_WSASetLastError(0);
    L8_EQ(w_WSAPoll(NULL, 0, 0), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    w_WSASetLastError(0);
    L8_EQ(w_WSAPoll(NULL, 0, 1), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
}

TEST(l8_wsapoll_invalid_event_bits_on_listener)
{
    struct sockaddr_in a;
    SOCKET l;
    unsigned i;
    NEED_WS();
    l = l8_listener(&a, 5);
    for (i = 0; i < sizeof invalid_event_bits / sizeof invalid_event_bits[0]; i++) {
        WSAPOLLFD p = { l, invalid_event_bits[i], (short)0xdead };
        w_WSASetLastError(0);
        L8_EQ(w_WSAPoll(&p, 1, 0), SOCKET_ERROR);
        L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    }
    w_closesocket(l);
}

TEST(l8_wsapoll_invalid_event_bits_on_connected_socket)
{
    SOCKET c, s;
    unsigned i;
    NEED_WS();
    l8_pair(&c, &s, 0);
    for (i = 0; i < sizeof invalid_event_bits / sizeof invalid_event_bits[0]; i++) {
        WSAPOLLFD p = { s, invalid_event_bits[i], (short)0xdead };
        w_WSASetLastError(0);
        L8_EQ(w_WSAPoll(&p, 1, 0), SOCKET_ERROR);
        L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    }
    w_closesocket(c);
    w_closesocket(s);
}

TEST(l8_wsapoll_idle_listener_reports_nothing)
{
    struct sockaddr_in a;
    SOCKET l;
    WSAPOLLFD p;
    NEED_WS();
    l = l8_listener(&a, 5);
    p.fd = l; p.events = POLLRDNORM | POLLRDBAND | POLLWRNORM; p.revents = (short)0xdead;
    L8_EQ(w_WSAPoll(&p, 1, 0), 0);
    L8_EQ(p.revents, 0);
    w_closesocket(l);
}

TEST(l8_wsapoll_invalid_descriptor_first_is_nval)
{
    struct sockaddr_in a;
    SOCKET l;
    WSAPOLLFD p[2];
    NEED_WS();
    l = l8_listener(&a, 5);
    p[0].fd = INVALID_SOCKET; p[0].events = POLLERR; p[0].revents = (short)0xdead;
    p[1].fd = l; p[1].events = POLLIN; p[1].revents = (short)0xdead;
    w_WSASetLastError(0xdeadbeef);
    /* An invalid descriptor is reported through revents; it does not fail the call or count as ready. */
    L8_EQ(w_WSAPoll(p, 2, 0), 0);
    L8_EQ(w_WSAGetLastError(), 0);
    L8_EQ(p[0].revents, POLLNVAL);
    L8_EQ(p[1].revents, 0);
    w_closesocket(l);
}

TEST(l8_wsapoll_bogus_handle_second_is_nval)
{
    struct sockaddr_in a;
    SOCKET l;
    WSAPOLLFD p[2];
    NEED_WS();
    l = l8_listener(&a, 5);
    p[0].fd = l; p[0].events = POLLIN; p[0].revents = (short)0xdead;
    p[1].fd = (SOCKET)0xabacab; p[1].events = POLLIN; p[1].revents = (short)0xdead;
    w_WSASetLastError(0xdeadbeef);
    L8_EQ(w_WSAPoll(p, 2, 0), 0);
    L8_EQ(w_WSAGetLastError(), 0);
    L8_EQ(p[0].revents, 0);
    L8_EQ(p[1].revents, POLLNVAL);
    w_closesocket(l);
}

TEST(l8_wsapoll_error_event_request_fails_whole_call)
{
    struct sockaddr_in a;
    SOCKET l;
    WSAPOLLFD p[2];
    NEED_WS();
    l = l8_listener(&a, 5);
    p[0].fd = l; p[0].events = POLLIN; p[0].revents = (short)0xdead;
    p[1].fd = (SOCKET)0xabacab; p[1].events = POLLERR; p[1].revents = (short)0xdead;
    w_WSASetLastError(0xdeadbeef);
    L8_EQ(w_WSAPoll(p, 2, 0), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    L8_EQ(p[0].revents, 0);
    L8_EQ(p[1].revents, 0);
    w_closesocket(l);
}

TEST(l8_wsapoll_only_invalid_descriptors_fail_notsock)
{
    WSAPOLLFD p[2];
    NEED_WS();
    p[0].fd = INVALID_SOCKET; p[0].events = POLLERR; p[0].revents = (short)0xdead;
    p[1].fd = (SOCKET)0xabacab; p[1].events = POLLERR; p[1].revents = (short)0xdead;
    w_WSASetLastError(0xdeadbeef);
    L8_EQ(w_WSAPoll(p, 2, 0), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAENOTSOCK);
    L8_EQ(p[0].revents, POLLNVAL);
    L8_EQ(p[1].revents, POLLNVAL);
}

TEST(l8_wsapoll_listener_pending_connection)
{
    struct sockaddr_in a;
    SOCKET l, c;
    WSAPOLLFD p;
    NEED_WS();
    l = l8_listener(&a, 5);
    c = w_socket(AF_INET, SOCK_STREAM, 0);
    l8_nonblocking(c, TRUE);
    w_connect(c, (struct sockaddr *)&a, sizeof a);

    p.fd = l; p.events = POLLIN; p.revents = (short)0xdead;
    L8_EQ(w_WSAPoll(&p, 1, 3000), 1);
    L8_EQ(p.revents, POLLRDNORM);
    p.revents = (short)0xdead;
    L8_EQ(w_WSAPoll(&p, 1, 0), 1);
    L8_EQ(p.revents, POLLRDNORM);
    /* Asking only for events the listener never produces reports nothing. */
    p.events = POLLRDBAND | POLLWRNORM; p.revents = (short)0xdead;
    L8_EQ(w_WSAPoll(&p, 1, 0), 0);
    L8_EQ(p.revents, 0);
    w_closesocket(c);
    w_closesocket(l);
}

TEST(l8_wsapoll_connected_sockets_are_writable)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    WSAPOLLFD p[3];
    int i;
    NEED_WS();
    l = l8_listener(&a, 5);
    connect_trio(l, &a, &c, &s);
    SOCKET set[3] = { l, s, c };
    for (i = 0; i < 3; i++) { p[i].fd = set[i]; p[i].events = POLLRDNORM | POLLRDBAND | POLLWRNORM; p[i].revents = (short)0xdead; }
    L8_EQ(w_WSAPoll(p, 3, 0), 2);
    L8_EQ(p[0].revents, 0);
    L8_EQ(p[1].revents, POLLWRNORM);
    L8_EQ(p[2].revents, POLLWRNORM);
    w_closesocket(c); w_closesocket(s); w_closesocket(l);
}

TEST(l8_wsapoll_data_arrival_and_drain)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    char buf[6];
    NEED_WS();
    l = l8_listener(&a, 5);
    connect_trio(l, &a, &c, &s);
    L8_EQ(w_send(s, "1234", 4, 0), 4);
    POLL_MASK_IS(c, POLL_IN_BITS, POLLRDNORM);
    POLL_IS(c, POLLRDNORM | POLLWRNORM);
    POLL_IS(s, POLLWRNORM);
    L8_EQ(l8_wait_recv(c, buf, sizeof buf), 4);
    POLL_IS(c, POLLWRNORM);
    POLL_IS(s, POLLWRNORM);
    w_closesocket(c); w_closesocket(s); w_closesocket(l);
}

TEST(l8_wsapoll_out_of_band_data)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    char b = 0;
    NEED_WS();
    l = l8_listener(&a, 5);
    connect_trio(l, &a, &c, &s);
    L8_EQ(w_send(c, "A", 1, MSG_OOB), 1);
    POLL_IS(c, POLLWRNORM);
    POLL_MASK_IS(s, POLL_IN_BITS, POLLRDBAND);   /* urgent data is band data, not normal data */
    POLL_IS(s, POLLWRNORM | POLLRDBAND);
    L8_EQ(w_recv(s, &b, 1, MSG_OOB), 1);
    L8_EQ(b, 'A');
    POLL_IS(c, POLLWRNORM);
    POLL_IS(s, POLLWRNORM);
    w_closesocket(c); w_closesocket(s); w_closesocket(l);
}

TEST(l8_wsapoll_out_of_band_inline_is_normal_data)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    char b = 0;
    int on = 1;
    NEED_WS();
    l = l8_listener(&a, 5);
    connect_trio(l, &a, &c, &s);
    L8_EQ(w_setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (const char *)&on, sizeof on), 0);
    L8_EQ(w_send(c, "A", 1, MSG_OOB), 1);
    POLL_IS(c, POLLWRNORM);
    POLL_MASK_IS(s, POLL_IN_BITS, POLLRDNORM);
    POLL_IS(s, POLLWRNORM | POLLRDNORM);
    L8_EQ(w_recv(s, &b, 1, 0), 1);
    L8_EQ(b, 'A');
    POLL_IS(c, POLLWRNORM);
    POLL_IS(s, POLLWRNORM);
    w_closesocket(c); w_closesocket(s); w_closesocket(l);
}

TEST(l8_wsapoll_half_close_reports_hangup)
{
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED_WS();
    l = l8_listener(&a, 5);
    connect_trio(l, &a, &c, &s);
    /* Shutting down our receive side tells the peer nothing. */
    L8_EQ(w_shutdown(c, SD_RECEIVE), 0);
    POLL_IS(c, POLLWRNORM);
    POLL_IS(s, POLLWRNORM);
    /* Shutting down the send side delivers a FIN: the peer sees a hang-up, still writable. */
    L8_EQ(w_shutdown(c, SD_SEND), 0);
    POLL_IS(c, POLLWRNORM);
    POLL_MASK_IS(s, 0, POLLHUP);
    POLL_IS(s, POLLWRNORM | POLLHUP);
    w_closesocket(c); w_closesocket(s); w_closesocket(l);
}

TEST(l8_wsapoll_peer_close_reports_hangup)
{
    SOCKET c, s;
    NEED_WS();
    l8_pair(&c, &s, 0);
    w_closesocket(c);
    POLL_MASK_IS(s, 0, POLLHUP);
    POLL_IS(s, POLLWRNORM | POLLHUP);
    w_closesocket(s);
}

TEST(l8_wsapoll_half_close_with_data_pending)
{
    SOCKET c, s;
    NEED_WS();
    l8_pair(&c, &s, 0);
    L8_EQ(w_send(c, "data", 5, 0), 5);
    POLL_IS(c, POLLWRNORM);
    POLL_MASK_IS(s, POLL_IN_BITS, POLLRDNORM);
    POLL_IS(s, POLLWRNORM | POLLRDNORM);
    w_shutdown(c, SD_SEND);
    POLL_IS(c, POLLWRNORM);
    POLL_MASK_IS(s, 0, POLLHUP);
    POLL_IS(s, POLLWRNORM | POLLRDNORM | POLLHUP);
    w_closesocket(c); w_closesocket(s);
}

static DWORD WINAPI close_later(void *p)
{
    SOCKET s = *(SOCKET *)p;
    Sleep(500);
    w_closesocket(s);
    return 0;
}

TEST(l8_wsapoll_socket_closed_while_polling)
{
    SOCKET c, s;
    WSAPOLLFD p;
    HANDLE th;
    volatile unsigned apcs = 0;
    NEED_WS();
    l8_pair(&c, &s, 0);
    th = CreateThread(NULL, 0, close_later, &c, 0, NULL);
    p.fd = c; p.events = POLLRDNORM | POLLRDBAND; p.revents = (short)0xdead;
    CHECK(QueueUserAPC(l8_apc_count, GetCurrentThread(), (ULONG_PTR)&apcs));
    t_note("closed-while-polling: ret=%d revents=%#x apcs=%u", w_WSAPoll(&p, 1, 3000), (unsigned)(unsigned short)p.revents, (unsigned)apcs);
    L8_EQ(WaitForSingleObject(th, 3000), WAIT_OBJECT_0);
    CloseHandle(th);
    w_closesocket(s);
}

TEST(l8_wsapoll_refused_connect_nonblocking)
{
    struct sockaddr_in dead = l8_dead_port();
    SOCKET c;
    WSAPOLLFD p;
    int err, len = sizeof err;
    NEED_WS();
    c = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    l8_nonblocking(c, TRUE);
    L8_EQ(w_connect(c, (struct sockaddr *)&dead, sizeof dead), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEWOULDBLOCK);

    /* The refusal can take a couple of seconds to be reported. */
    p.fd = c; p.events = POLLRDNORM | POLLRDBAND | POLLWRNORM; p.revents = (short)0xdead;
    L8_EQ(w_WSAPoll(&p, 1, 10000), 1);
    L8_EQ(p.revents, POLLWRNORM | POLLHUP | POLLERR);

    err = -1;
    L8_EQ(w_getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    L8_EQ(err, WSAECONNREFUSED);
    err = -1; len = sizeof err;
    L8_EQ(w_getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    L8_EQ(err, WSAECONNREFUSED);   /* reading SO_ERROR does not clear it here */
    POLL_IS(c, POLLWRNORM | POLLHUP | POLLERR);
    w_closesocket(c);
}

TEST(l8_wsapoll_refused_connect_blocking)
{
    struct sockaddr_in dead = l8_dead_port();
    SOCKET c;
    int err, len = sizeof err;
    NEED_WS();
    c = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(w_connect(c, (struct sockaddr *)&dead, sizeof dead), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAECONNREFUSED);
    POLL_IS(c, POLLWRNORM | POLLHUP | POLLERR);
    err = -1;
    L8_EQ(w_getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    L8_EQ(err, 0);   /* a synchronous failure was already returned to the caller */
    w_closesocket(c);
}

TEST(l8_wsapoll_udp_sockets)
{
    SOCKET rx, tx;
    struct sockaddr_in a = l8_lo4();
    int len = sizeof a;
    NEED_WS();
    rx = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    tx = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    POLL_IS(rx, POLLWRNORM);
    POLL_IS(tx, POLLWRNORM);
    L8_EQ(w_bind(rx, (struct sockaddr *)&a, sizeof a), 0);
    L8_EQ(w_getsockname(rx, (struct sockaddr *)&a, &len), 0);
    POLL_IS(rx, POLLWRNORM);
    POLL_IS(tx, POLLWRNORM);
    L8_EQ(w_sendto(tx, "data", 5, 0, (struct sockaddr *)&a, sizeof a), 5);
    POLL_MASK_IS(rx, POLL_IN_BITS, POLLRDNORM);
    POLL_IS(rx, POLLWRNORM | POLLRDNORM);
    POLL_IS(tx, POLLWRNORM);
    w_closesocket(rx);
    w_closesocket(tx);
}
