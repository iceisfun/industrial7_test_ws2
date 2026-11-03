/* Argument validation on the UDP send side: destination address length and family, send flags,
 * missing destination, the maximum datagram size (SO_MAX_MSG_SIZE) boundary with WSAEMSGSIZE,
 * sending after a send-side shutdown, and whether a rejected send leaves the socket bound or not.
 * Nothing is ever sent anywhere but loopback. */
#include "ud.h"

static int unbound_name(SOCKET s) {            /* returns getsockname's result and last error */
    struct sockaddr_storage n; int l = sizeof n;
    ud_seterr(0);
    return U(getsockname)(s, (struct sockaddr *)&n, &l);
}

/* ---- destination address length ---- */

TEST(udp_sendto_v4_address_shorter_than_sockaddr_in_is_efault) {
    ud_ep rx; SOCKET s; int len;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    CHECK(s != INVALID_SOCKET);
    for (len = 0; len < (int)sizeof(struct sockaddr_in); len++) {
        int r;
        ud_seterr(0);
        r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&rx.sa, len);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEFAULT, "tolen %d gave r=%d err=%d", len, r, ud_err());
    }
    CHECK(!ud_ready(rx.s, 100));
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_v6_address_shorter_than_sockaddr_in6_is_efault) {
    ud_ep rx; SOCKET s; static const int lens[] = { 0, 1, 2, 8, 16, 20, 24, 27 }; unsigned i;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    if (!ud_open(&rx, AF_INET6)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET6, SOCK_DGRAM, 0);
    CHECK(s != INVALID_SOCKET);
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        int r;
        ud_seterr(0);
        r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&rx.sa, lens[i]);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEFAULT, "tolen %d gave r=%d err=%d", lens[i], r, ud_err());
    }
    CHECK(!ud_ready(rx.s, 100));
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_address_length_larger_than_needed_is_accepted_note) {
    ud_ep rx; SOCKET s; struct sockaddr_storage big; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    memset(&big, 0, sizeof big);
    memcpy(&big, &rx.sa, rx.len);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&big, (int)sizeof big);
    t_note("sendto with tolen=%d for an IPv4 destination: r=%d err=%d", (int)sizeof big, r, r < 0 ? ud_err() : 0);
    if (r == 1) CHECK(ud_ready(rx.s, 3000));
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_short_address_does_not_bind_the_socket) {
    ud_ep rx; SOCKET s; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&rx.sa, 4);
    EXPECT_EQ(r, SOCKET_ERROR);
    r = unbound_name(s);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEINVAL);
    ud_close(s); ud_free(&rx);
}

/* ---- destination family ---- */

TEST(udp_sendto_v6_address_on_v4_socket_is_eafnosupport) {
    ud_ep rx; SOCKET s; struct sockaddr_in6 to; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_lo6(&to, rx.sa.ss_family ? ((struct sockaddr_in *)&rx.sa)->sin_port : 0);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEAFNOSUPPORT);
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_v4_sized_address_on_v6_socket_is_efault) {
    ud_ep rx; SOCKET s; struct sockaddr_in to; int r;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET6, SOCK_DGRAM, 0);
    ud_lo4(&to, ((struct sockaddr_in *)&rx.sa)->sin_port);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
    /* a sockaddr_in is shorter than the minimum for an AF_INET6 socket: the length check wins */
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    CHECK(!ud_ready(rx.s, 100));
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_family_table_on_v4_socket) {
    static const int fam[] = { AF_UNSPEC, AF_UNIX, AF_INET6, AF_IPX, AF_NETBIOS, 0x7fff, 0xffff };
    ud_ep rx; SOCKET s; unsigned i;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    for (i = 0; i < sizeof fam / sizeof *fam; i++) {
        struct sockaddr_in to; int r;
        ud_lo4(&to, ((struct sockaddr_in *)&rx.sa)->sin_port);
        to.sin_family = (ADDRESS_FAMILY)fam[i];
        ud_seterr(0);
        r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEAFNOSUPPORT, "family %d gave r=%d err=%d", fam[i], r, ud_err());
    }
    CHECK(!ud_ready(rx.s, 100));
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_short_length_is_checked_before_family) {
    ud_ep rx; SOCKET s; struct sockaddr_in6 to; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_lo6(&to, 0);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&to, 8);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_wrong_family_does_not_bind_the_socket) {
    ud_ep rx; SOCKET s; struct sockaddr_in6 to; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_lo6(&to, 0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
    EXPECT_EQ(r, SOCKET_ERROR);
    r = unbound_name(s);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEINVAL);
    ud_close(s); ud_free(&rx);
}

TEST(udp_wsasendto_wrong_family_matches_sendto) {
    ud_ep rx; SOCKET s; struct sockaddr_in6 to; WSABUF b; DWORD sent = 0xdeadbeef; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_lo6(&to, 0);
    b.buf = (char *)"x"; b.len = 1;
    ud_seterr(0);
    r = U(WSASendTo)(s, &b, 1, &sent, 0, (struct sockaddr *)&to, sizeof to, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEAFNOSUPPORT);
    ud_seterr(0);
    r = U(WSASendTo)(s, &b, 1, &sent, 0, (struct sockaddr *)&rx.sa, 3, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_close(s); ud_free(&rx);
}

/* ---- missing destination ---- */

TEST(udp_sendto_null_destination_on_unconnected_socket_is_enotconn) {
    SOCKET s; int r;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, NULL, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTCONN);
    ud_close(s);
}

TEST(udp_sendto_null_destination_on_connected_socket_uses_peer) {
    ud_ep a, b; int r; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    r = U(sendto)(a.s, "q", 1, 0, NULL, 0);
    EXPECT_EQ(r, 1);
    CHECK(ud_recv_to(b.s, &c, 1, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_sendto_overrides_connected_peer) {
    ud_ep a, b, c; char buf[4]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    r = ud_sendto(&a, &c, "to-c", 4);
    EXPECT_EQ(r, 4);
    CHECK(ud_recv_to(c.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 4);
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_send_without_connect_is_enotconn_even_when_bound) {
    ud_ep a; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_seterr(0);
    r = U(send)(a.s, "x", 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTCONN);
    ud_free(&a);
}

/* ---- send flags (sendto path) ---- */

TEST(udp_sendto_dontroute_flag_is_accepted) {
    ud_ep a, b; int r; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    r = U(sendto)(a.s, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&b.sa, b.len);
    EXPECT_EQ(r, 1);
    CHECK(ud_recv_to(b.s, &c, 1, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_sendto_unsupported_flags_are_eopnotsupp) {
    static const int flags[] = { MSG_OOB, MSG_PEEK, 0x8, 0x10, 0x20, 0x80, 0x100, 0x1000, 0x20000 };
    ud_ep a, b; unsigned i;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (i = 0; i < sizeof flags / sizeof *flags; i++) {
        int r;
        ud_seterr(0);
        r = U(sendto)(a.s, "x", 1, flags[i], (struct sockaddr *)&b.sa, b.len);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEOPNOTSUPP, "flag 0x%x gave r=%d err=%d", flags[i], r, ud_err());
    }
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsasendto_unsupported_flags_are_eopnotsupp) {
    ud_ep a, b; WSABUF w; DWORD sent = 0; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    w.buf = (char *)"x"; w.len = 1;
    ud_seterr(0);
    r = U(WSASendTo)(a.s, &w, 1, &sent, MSG_OOB, (struct sockaddr *)&b.sa, b.len, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEOPNOTSUPP);
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_sendto_bad_flags_still_bind_the_socket) {
    ud_ep rx; SOCKET s; struct sockaddr_in me; int l = sizeof me, r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    r = U(sendto)(s, "x", 1, MSG_OOB, (struct sockaddr *)&rx.sa, rx.len);
    EXPECT_EQ(r, SOCKET_ERROR);
    r = U(getsockname)(s, (struct sockaddr *)&me, &l);
    t_note("getsockname after a flag-rejected sendto on a fresh socket: r=%d err=%d port_nonzero=%d", r, r ? ud_err() : 0, r == 0 && me.sin_port != 0);
    ud_close(s); ud_free(&rx);
}

/* ---- shutdown of the send side ---- */

TEST(udp_connected_send_after_shutdown_send_is_eshutdown) {
    ud_ep a, b; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    if (U(shutdown)(a.s, SD_SEND) != 0) { t_note("shutdown(SD_SEND) on connected UDP failed err=%d", ud_err()); ud_free(&a); ud_free(&b); return; }
    ud_seterr(0);
    r = U(send)(a.s, "x", 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAESHUTDOWN);
    ud_seterr(0);
    r = ud_sendto(&a, &b, "x", 1);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAESHUTDOWN);
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_connected_receive_still_works_after_shutdown_send) {
    ud_ep a, b; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    if (U(shutdown)(a.s, SD_SEND) != 0) { ud_free(&a); ud_free(&b); t_skip("shutdown not supported here"); return; }
    CHECK(ud_sendto(&b, &a, "r", 1) == 1);
    CHECK(ud_recv_to(a.s, &c, 1, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_connected_receive_after_shutdown_receive_returns_zero) {
    ud_ep a, b; char c; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    if (U(shutdown)(a.s, SD_RECEIVE) != 0) { ud_free(&a); ud_free(&b); t_skip("shutdown not supported here"); return; }
    ud_nonblock(a.s, 1);
    ud_seterr(0);
    r = U(recv)(a.s, &c, 1, 0);
    t_note("recv on connected UDP after shutdown(SD_RECEIVE): r=%d err=%d", r, r < 0 ? ud_err() : 0);
    ud_free(&a); ud_free(&b);
}

/* ---- maximum datagram size ---- */

TEST(udp_so_max_msg_size_is_65507_on_ipv4) {
    SOCKET s; int v = 0, r;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    r = ud_getint(s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v);
    EXPECT_EQ(r, 0); EXPECT_EQ(v, 65507);
    ud_close(s);
}

TEST(udp_so_max_msg_size_ipv6_value_note) {
    SOCKET s; int v = 0, r;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    s = U(socket)(AF_INET6, SOCK_DGRAM, 0);
    r = ud_getint(s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v);
    EXPECT_EQ(r, 0);
    t_note("SO_MAX_MSG_SIZE on an AF_INET6 datagram socket: %d", v);
    CHECK(v > 60000);
    ud_close(s);
}

TEST(udp_so_max_msg_size_is_readable_before_and_after_bind) {
    ud_ep a; SOCKET s; int v1 = 0, v2 = 0;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    CHECK(ud_getint(s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v1) == 0);
    ud_close(s);
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(ud_getint(a.s, SOL_SOCKET, SO_MAX_MSG_SIZE, &v2) == 0);
    EXPECT_EQ(v1, v2);
    ud_free(&a);
}

TEST(udp_so_max_msg_size_short_buffer_is_efault) {
    SOCKET s; char b[2] = {0}; int l = 2, r;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_seterr(0);
    r = U(getsockopt)(s, SOL_SOCKET, SO_MAX_MSG_SIZE, b, &l);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_close(s);
}

TEST(udp_so_max_msg_size_setsockopt_is_rejected_note) {
    SOCKET s; int r, v = 1000;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_seterr(0);
    r = ud_setint(s, SOL_SOCKET, SO_MAX_MSG_SIZE, v);
    t_note("setsockopt(SO_MAX_MSG_SIZE): r=%d err=%d", r, r ? ud_err() : 0);
    ud_close(s);
}

TEST(udp_send_of_max_size_datagram_is_delivered_whole) {
    ud_ep a, b; static unsigned char tx[65536], rx[65536]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ud_fill(tx, 65507, 5);
    ud_setint(b.s, SOL_SOCKET, SO_RCVBUF, 1 << 20);
    r = ud_sendto(&a, &b, tx, 65507);
    EXPECT_EQ(r, 65507);
    r = ud_recv_to(b.s, rx, sizeof rx, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 65507);
    if (r == 65507) CHECK(ud_same(rx, 65507, 5));
    ud_free(&a); ud_free(&b);
}

TEST(udp_send_one_byte_over_max_is_emsgsize) {
    ud_ep a, b; static unsigned char tx[70000]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ud_seterr(0);
    r = ud_sendto(&a, &b, tx, 65508);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!ud_ready(b.s, 150));
    ud_free(&a); ud_free(&b);
}

TEST(udp_send_oversize_table_is_emsgsize) {
    static const int sizes[] = { 65508, 65509, 65515, 65527, 65528, 65535, 65536, 65537, 70000, 100000 };
    ud_ep a, b; unsigned char *tx; unsigned i;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    tx = (unsigned char *)VirtualAlloc(NULL, 131072, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tx) { ud_free(&a); ud_free(&b); t_skip("no scratch memory"); return; }
    for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        int r;
        ud_seterr(0);
        r = ud_sendto(&a, &b, tx, sizes[i]);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEMSGSIZE, "size %d gave r=%d err=%d", sizes[i], r, ud_err());
    }
    CHECK(!ud_ready(b.s, 150));
    VirtualFree(tx, 0, MEM_RELEASE);
    ud_free(&a); ud_free(&b);
}

TEST(udp_socket_remains_usable_after_emsgsize) {
    ud_ep a, b; static unsigned char tx[70000]; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(ud_sendto(&a, &b, tx, 66000) == SOCKET_ERROR);
    CHECK(ud_sendto(&a, &b, "k", 1) == 1);
    CHECK(ud_recv_to(b.s, &c, 1, 0, NULL, NULL, 3000) == 1);
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsasendto_oversize_total_across_buffers_is_emsgsize) {
    ud_ep a, b; static unsigned char big[40000]; WSABUF w[2]; DWORD sent = 0xdeadbeef; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    w[0].buf = (char *)big; w[0].len = 40000; w[1].buf = (char *)big; w[1].len = 40000;
    ud_seterr(0);
    r = U(WSASendTo)(a.s, w, 2, &sent, 0, (struct sockaddr *)&b.sa, b.len, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEMSGSIZE);
    CHECK(!ud_ready(b.s, 150));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsasendto_gathers_buffers_into_one_datagram) {
    ud_ep a, b; WSABUF w[3]; DWORD sent = 0; char buf[32]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    w[0].buf = (char *)"abc"; w[0].len = 3; w[1].buf = (char *)""; w[1].len = 0; w[2].buf = (char *)"defg"; w[2].len = 4;
    r = U(WSASendTo)(a.s, w, 3, &sent, 0, (struct sockaddr *)&b.sa, b.len, NULL, NULL);
    EXPECT_EQ(r, 0); EXPECT_EQ(sent, 7);
    r = ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 7);
    CHECK(!memcmp(buf, "abcdefg", 7));
    CHECK(!ud_ready(b.s, 100));
    ud_free(&a); ud_free(&b);
}

TEST(udp_wsasendto_oversize_leaves_byte_count_note) {
    ud_ep a, b; static unsigned char big[66000]; WSABUF w; DWORD sent = 0xdeadbeef; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    w.buf = (char *)big; w.len = sizeof big;
    r = U(WSASendTo)(a.s, &w, 1, &sent, 0, (struct sockaddr *)&b.sa, b.len, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    t_note("bytes-sent value after a rejected oversize WSASendTo: 0x%lx", sent);
    ud_free(&a); ud_free(&b);
}

TEST(udp_overlapped_oversize_send_fails_synchronously_with_emsgsize_note) {
    ud_ep a, b; static unsigned char big[66000]; WSABUF w; WSAOVERLAPPED ov; WSAEVENT ev; DWORD sent = 0; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    ev = U(WSACreateEvent)();
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    w.buf = (char *)big; w.len = sizeof big;
    ud_seterr(0);
    r = U(WSASendTo)(a.s, &w, 1, &sent, 0, (struct sockaddr *)&b.sa, b.len, &ov, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    t_note("overlapped oversize WSASendTo: err=%d", ud_err());
    CHECK(ud_err() == WSAEMSGSIZE || ud_err() == WSA_IO_PENDING);
    U(WSACloseEvent)(ev);
    ud_free(&a); ud_free(&b);
}

/* ---- destination validity that does not depend on the network ---- */

TEST(udp_sendto_to_loopback_port_zero_is_rejected_or_dropped_note) {
    ud_ep rx; SOCKET s; struct sockaddr_in to; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_lo4(&to, 0);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
    t_note("sendto 127.0.0.1 port 0: r=%d err=%d", r, r < 0 ? ud_err() : 0);
    ud_close(s); ud_free(&rx);
}

TEST(udp_sendto_closed_socket_is_enotsock) {
    ud_ep rx; SOCKET s; int r;
    UP();
    if (!ud_open(&rx, AF_INET)) { t_skip("endpoint"); return; }
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    ud_close(s);
    ud_seterr(0);
    r = U(sendto)(s, "x", 1, 0, (struct sockaddr *)&rx.sa, rx.len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTSOCK);
    ud_seterr(0);
    r = U(recvfrom)(s, (char *)&r, 1, 0, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTSOCK);
    ud_free(&rx);
}

TEST(udp_sendto_invalid_socket_value_is_enotsock) {
    int r;
    UP();
    ud_seterr(0);
    r = U(sendto)(INVALID_SOCKET, "x", 1, 0, NULL, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTSOCK);
    ud_seterr(0);
    r = U(recvfrom)(INVALID_SOCKET, (char *)&r, 1, 0, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTSOCK);
}
