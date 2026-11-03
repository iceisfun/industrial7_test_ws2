/* WSARecvEx (the MSG_PARTIAL receive) and WSAPoll readiness of sockets produced by the extension functions:
 * accepted by AcceptEx, connected by ConnectEx, fed by TransmitFile, and closed by DisconnectEx.  WSARecvEx
 * is exported by mswsock.dll and forwarded by wsock32.dll; both routes are exercised. */
#include "mx.h"

typedef int (WINAPI *recvex_fn)(SOCKET, char *, int, int *);

static recvex_fn recvex(void) { return (recvex_fn)UIN("mswsock.dll", WSARecvEx); }

/* A bound UDP socket on loopback and a sender aimed at it. */
static int udp_pair(SOCKET *rx, SOCKET *tx, struct sockaddr_in *rxaddr)
{
    int len = sizeof *rxaddr;
    *rxaddr = mx_lo4();
    *rx = mx_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    *tx = mx_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*rx == INVALID_SOCKET || *tx == INVALID_SOCKET) return 0;
    if (mx_bind(*rx, (struct sockaddr *)rxaddr, sizeof *rxaddr) || mx_getsockname(*rx, (struct sockaddr *)rxaddr, &len)) return 0;
    return 1;
}

#define UDP(rx, tx, addr) SOCKET rx, tx; struct sockaddr_in addr; \
    do { NEED_NET(); if (!udp_pair(&(rx), &(tx), &(addr))) { t_skip("UDP loopback unavailable"); return; } } while (0)

/* ---- WSARecvEx --------------------------------------------------------------------------------------------- */

/* A datagram larger than the buffer: the buffer-sized prefix is returned, MSG_PARTIAL (0x8000) is the only flag
 * bit set, the last error is still WSAEMSGSIZE, and the rest of the datagram is gone. */
TEST(recvex_truncated_datagram_sets_exactly_msg_partial_and_keeps_emsgsize)
{
    recvex_fn fn = recvex();
    char buf[4];
    int flags = 0x55, r;
    UDP(rx, tx, addr);
    REQUIRE(fn);
    MX_EQ(mx_sendto(tx, "0123456789", 10, 0, (struct sockaddr *)&addr, sizeof addr), 10);
    CHECK(mx_readable(rx, 5000));
    mx_WSASetLastError(0);
    r = fn(rx, buf, 4, &flags);
    MX_EQ(r, 4);
    MX_EQ(flags, 0x8000);
    MX_EQ(mx_WSAGetLastError(), WSAEMSGSIZE);
    CHECK(!memcmp(buf, "0123", 4));
    {
        u_long nb = 1;
        char more[8];
        mx_ioctlsocket(rx, FIONBIO, &nb);
        MX_EQ(mx_recv(rx, more, 8, 0), SOCKET_ERROR);
        MX_EQ(mx_WSAGetLastError(), WSAEWOULDBLOCK);
    }
    mx_closesocket(rx); mx_closesocket(tx);
}

TEST(recvex_datagram_that_exactly_fits_is_not_partial)
{
    recvex_fn fn = recvex();
    char buf[10];
    int flags = 0x8000;
    UDP(rx, tx, addr);
    REQUIRE(fn);
    MX_EQ(mx_sendto(tx, "abcdefghij", 10, 0, (struct sockaddr *)&addr, sizeof addr), 10);
    CHECK(mx_readable(rx, 5000));
    MX_EQ(fn(rx, buf, 10, &flags), 10);
    MX_EQ(flags, 0);
    CHECK(!memcmp(buf, "abcdefghij", 10));
    mx_closesocket(rx); mx_closesocket(tx);
}

TEST(recvex_zero_length_datagram_returns_zero_without_partial)
{
    recvex_fn fn = recvex();
    char buf[4];
    int flags = 0x1;
    UDP(rx, tx, addr);
    REQUIRE(fn);
    MX_EQ(mx_sendto(tx, "", 0, 0, (struct sockaddr *)&addr, sizeof addr), 0);
    CHECK(mx_readable(rx, 5000));
    MX_EQ(fn(rx, buf, 4, &flags), 0);
    MX_EQ(flags, 0);
    mx_closesocket(rx); mx_closesocket(tx);
}

/* Datagram boundaries are preserved: two datagrams come out one per call, the truncated one flagged. */
TEST(recvex_consecutive_datagrams_each_report_their_own_partial_state)
{
    recvex_fn fn = recvex();
    char buf[5];
    int flags;
    UDP(rx, tx, addr);
    REQUIRE(fn);
    MX_EQ(mx_sendto(tx, "longer-than-five", 16, 0, (struct sockaddr *)&addr, sizeof addr), 16);
    MX_EQ(mx_sendto(tx, "short", 5, 0, (struct sockaddr *)&addr, sizeof addr), 5);
    CHECK(mx_readable(rx, 5000));
    flags = 0;
    MX_EQ(fn(rx, buf, 5, &flags), 5);
    MX_EQ(flags, 0x8000);
    CHECK(mx_readable(rx, 5000));
    flags = 0x8000;
    MX_EQ(fn(rx, buf, 5, &flags), 5);
    MX_EQ(flags, 0);
    CHECK(!memcmp(buf, "short", 5));
    mx_closesocket(rx); mx_closesocket(tx);
}

/* On a stream socket a short buffer is not an error: bytes are simply left for the next call. */
TEST(recvex_stream_slices_never_set_partial)
{
    recvex_fn fn = recvex();
    char buf[4];
    int flags, i, total = 0;
    MX_PAIR(c, a);
    REQUIRE(fn);
    MX_EQ(mx_send(c, "0123456789", 10, 0), 10);
    for (i = 0; i < 10 && total < 10; i++) {
        int r;
        if (!mx_readable(a, 5000)) break;
        flags = 0x8000;
        r = fn(a, buf, 3, &flags);
        t_check(r > 0 && r <= 3 && flags == 0, __FILE__, __LINE__, "stream slice", "ret %d flags 0x%x", r, flags);
        if (r <= 0) break;
        total += r;
    }
    MX_EQ(total, 10);
    mx_closesocket(c); mx_closesocket(a);
}

TEST(recvex_reset_connection_reports_connreset_and_clears_flags)
{
    recvex_fn fn = recvex();
    LINGER lg;
    char buf[4];
    int flags = 0x40;
    MX_PAIR(c, a);
    REQUIRE(fn);
    lg.l_onoff = 1; lg.l_linger = 0;
    MX_EQ(mx_setsockopt(c, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg), 0);
    mx_closesocket(c);          /* abortive close: the peer receives a reset */
    CHECK(mx_readable(a, 5000));
    MX_EQ(fn(a, buf, 4, &flags), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAECONNRESET);
    MX_EQ(flags, 0);
    mx_closesocket(a);
}

TEST(recvex_after_shutdown_receive_is_eshutdown)
{
    recvex_fn fn = recvex();
    char buf[4];
    int flags = 0, r;
    MX_PAIR(c, a);
    REQUIRE(fn);
    MX_EQ(mx_shutdown(a, SD_RECEIVE), 0);
    r = fn(a, buf, 4, &flags);
    MX_EQ(r, SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAESHUTDOWN);
    MX_EQ(flags, 0);
    mx_closesocket(c); mx_closesocket(a);
}

TEST(recvex_wsock32_forwarder_flags_a_truncated_datagram)
{
    recvex_fn fn = (recvex_fn)UIN("wsock32.dll", WSARecvEx);
    char buf[2];
    int flags = 0;
    UDP(rx, tx, addr);
    REQUIRE(fn);
    MX_EQ(mx_sendto(tx, "wxyz", 4, 0, (struct sockaddr *)&addr, sizeof addr), 4);
    CHECK(mx_readable(rx, 5000));
    MX_EQ(fn(rx, buf, 2, &flags), 2);
    MX_EQ(flags, 0x8000);
    mx_closesocket(rx); mx_closesocket(tx);
}

/* WSARecv reports the same truncation as an error with the byte count, and leaves the flags alone. */
TEST(recvex_and_wsarecv_agree_on_the_truncated_datagram)
{
    WSABUF wb;
    char buf[4];
    DWORD got = 0, fl = 0;
    int r;
    UDP(rx, tx, addr);
    MX_EQ(mx_sendto(tx, "ABCDEFGH", 8, 0, (struct sockaddr *)&addr, sizeof addr), 8);
    CHECK(mx_readable(rx, 5000));
    wb.buf = buf; wb.len = 4;
    r = mx_WSARecv(rx, &wb, 1, &got, &fl, NULL, NULL);
    MX_EQ(r, SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAEMSGSIZE);
    MX_EQ(got, 4);
    MX_EQ(fl, 0);
    CHECK(!memcmp(buf, "ABCD", 4));
    mx_closesocket(rx); mx_closesocket(tx);
}

/* ---- WSAPoll on extension-function sockets -------------------------------------------------------------------- */

static int poll_one(SOCKET s, short events, int to_ms, short *rev)
{
    WSAPOLLFD p;
    int r;
    p.fd = s; p.events = events; p.revents = 0x7777;
    r = mx_WSAPoll(&p, 1, to_ms);
    *rev = p.revents;
    return r;
}

TEST(wsapoll_acceptex_socket_is_writable_at_once_and_readable_after_data)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, acc, cli;
    OVERLAPPED ov;
    unsigned char buf[64];
    DWORD n = 0, err = 0;
    short rev;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 4);
    acc = mx_tcp();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    x.acceptex(lst, acc, buf, 0, 32, 32, &n, &ov);
    cli = mx_tcp();
    CHECK(mx_connect(cli, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(mx_ov_done(lst, &ov, &n, 5000, &err));
    MX_EQ(poll_one(acc, POLLWRNORM, 2000, &rev), 1);
    CHECK(rev & POLLWRNORM);
    MX_EQ(poll_one(acc, POLLRDNORM, 100, &rev), 0);
    MX_EQ(rev, 0);
    MX_EQ(mx_send(cli, "go", 2, 0), 2);
    MX_EQ(poll_one(acc, POLLRDNORM, 5000, &rev), 1);
    CHECK(rev & POLLRDNORM);
    CloseHandle(ov.hEvent);
    mx_closesocket(cli); mx_closesocket(acc); mx_closesocket(lst);
}

/* The listener never reports a pending connection for one the extended accept has already taken. */
TEST(wsapoll_listener_with_acceptex_pending_stays_quiet_after_the_connection_is_taken)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, acc, cli;
    OVERLAPPED ov;
    unsigned char buf[64];
    DWORD n = 0, err = 0;
    short rev;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 4);
    acc = mx_tcp();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    x.acceptex(lst, acc, buf, 0, 32, 32, &n, &ov);
    cli = mx_tcp();
    CHECK(mx_connect(cli, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(mx_ov_done(lst, &ov, &n, 5000, &err));
    MX_EQ(poll_one(lst, POLLRDNORM, 150, &rev), 0);
    MX_EQ(rev, 0);
    CloseHandle(ov.hEvent);
    mx_closesocket(cli); mx_closesocket(acc); mx_closesocket(lst);
}

TEST(wsapoll_connectex_socket_is_writable_after_completion)
{
    struct mx_ext x;
    struct sockaddr_in addr, bound;
    SOCKET lst, c, srv;
    OVERLAPPED ov;
    DWORD n = 0, err = 0;
    short rev;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 4);
    c = mx_bound(&bound);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    x.connectex(c, (struct sockaddr *)&addr, sizeof addr, NULL, 0, NULL, &ov);
    CHECK(mx_ov_done(c, &ov, &n, 5000, &err));
    srv = mx_accept_wait(lst);
    MX_EQ(poll_one(c, POLLWRNORM, 2000, &rev), 1);
    CHECK(rev & POLLWRNORM);
    MX_EQ(poll_one(c, POLLRDNORM, 100, &rev), 0);
    CloseHandle(ov.hEvent);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    mx_closesocket(c); mx_closesocket(lst);
}

TEST(wsapoll_peer_of_transmitfile_becomes_readable_and_drains)
{
    struct mx_ext x;
    HANDLE f;
    char buf[300];
    short rev;
    MX_PAIR(c, a);
    if (!mx_load_ext(&x)) { mx_closesocket(c); mx_closesocket(a); t_skip("extension functions not offered"); return; }
    f = mx_make_file("poll_tf.bin", 300, 3, GENERIC_READ | GENERIC_WRITE, 0);
    MX_EQ(poll_one(a, POLLRDNORM, 100, &rev), 0);
    CHECK(x.transmitfile(c, f, 0, 0, NULL, NULL, 0));
    MX_EQ(poll_one(a, POLLRDNORM, 5000, &rev), 1);
    CHECK(rev & POLLRDNORM);
    MX_EQ(mx_recv_all(a, buf, 300, 5000), 300);
    MX_EQ(poll_one(a, POLLRDNORM, 100, &rev), 0);
    CloseHandle(f);
    mx_closesocket(c); mx_closesocket(a);
}

TEST(wsapoll_peer_of_disconnectex_reports_hangup)
{
    struct mx_ext x;
    short rev;
    MX_PAIR(c, a);
    if (!mx_load_ext(&x)) { mx_closesocket(c); mx_closesocket(a); t_skip("extension functions not offered"); return; }
    CHECK(x.disconnectex(c, NULL, 0, 0));
    MX_EQ(poll_one(a, POLLRDNORM, 5000, &rev), 1);
    CHECK(rev & POLLHUP);
    mx_closesocket(c); mx_closesocket(a);
}

TEST(wsapoll_socket_after_disconnectex_reuse_records_its_state)
{
    struct mx_ext x;
    short rev;
    int r;
    MX_PAIR(c, a);
    if (!mx_load_ext(&x)) { mx_closesocket(c); mx_closesocket(a); t_skip("extension functions not offered"); return; }
    CHECK(mx_reuse_disconnect(x.disconnectex, c, a));
    r = poll_one(c, POLLRDNORM | POLLWRNORM, 100, &rev);
    t_note("poll of a reused (unconnected) socket: ret %d revents 0x%x", r, (unsigned)rev);
    mx_closesocket(c); mx_closesocket(a);
}

/* A single call polling sockets that came out of different extension paths reports each one correctly. */
TEST(wsapoll_mixed_extension_sockets_in_one_call)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, acc, cli, p1, p2;
    OVERLAPPED ov;
    unsigned char buf[64];
    DWORD n = 0, err = 0;
    WSAPOLLFD fds[3];
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 4);
    acc = mx_tcp();
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    x.acceptex(lst, acc, buf, 0, 32, 32, &n, &ov);
    cli = mx_tcp();
    CHECK(mx_connect(cli, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(mx_ov_done(lst, &ov, &n, 5000, &err));
    CHECK(mx_pair(&p1, &p2));
    MX_EQ(mx_send(p1, "d", 1, 0), 1);
    fds[0].fd = acc; fds[0].events = POLLRDNORM; fds[0].revents = 0;
    fds[1].fd = p2;  fds[1].events = POLLRDNORM; fds[1].revents = 0;
    fds[2].fd = cli; fds[2].events = POLLWRNORM; fds[2].revents = 0;
    CHECK(mx_readable(p2, 5000));
    MX_EQ(mx_WSAPoll(fds, 3, 2000), 2);
    MX_EQ(fds[0].revents, 0);
    CHECK(fds[1].revents & POLLRDNORM);
    CHECK(fds[2].revents & POLLWRNORM);
    CloseHandle(ov.hEvent);
    mx_closesocket(cli); mx_closesocket(acc); mx_closesocket(lst); mx_closesocket(p1); mx_closesocket(p2);
}
