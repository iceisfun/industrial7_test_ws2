/* Connected-UDP semantics (peer filtering, reconnect, dissolve) and the ICMP port-unreachable
 * feedback path on loopback: WSAECONNRESET on a later receive, the SIO_UDP_CONNRESET switch and its
 * argument validation. The "closed port" is always a port that this process bound and then closed. */
#include "ud.h"

/* Address of a loopback UDP port with no socket behind it. */
static int closed_target(ud_ep *t, int af) {
    if (!ud_open(t, af)) return 0;
    ud_close(t->s);
    t->s = INVALID_SOCKET;
    return 1;
}
static int connreset_set(SOCKET s, BOOL on, DWORD *bytes) {
    DWORD b = 0xdeadbeef;
    int r = U(WSAIoctl)(s, SIO_UDP_CONNRESET, &on, sizeof on, NULL, 0, &b, NULL, NULL);
    if (bytes) *bytes = b;
    return r;
}
/* Waits (bounded) for a reset report. Returns 1 when the next receive fails with WSAECONNRESET. */
static int expect_reset(SOCKET s, int ms) {
    char c; int r;
    if (!ud_ready(s, ms)) return 0;
    ud_seterr(0);
    r = U(recv)(s, &c, 1, 0);
    return r == SOCKET_ERROR && ud_err() == WSAECONNRESET;
}

/* ---- peer filtering of a connected socket ---- */

TEST(udp_connected_socket_drops_datagrams_from_other_ports) {
    ud_ep a, b, c; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(ud_sendto(&c, &a, "stranger", 8) == 8);
    CHECK(ud_sendto(&b, &a, "peer", 4) == 4);
    r = ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 4);
    CHECK(!memcmp(buf, "peer", 4));
    CHECK(!ud_ready(a.s, 150));
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_connected_socket_only_stranger_data_is_never_readable) {
    ud_ep a, b, c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(ud_sendto(&c, &a, "s1", 2) == 2);
    CHECK(ud_sendto(&c, &a, "s2", 2) == 2);
    CHECK(!ud_ready(a.s, 300));
    {
        u_long n = 99;
        U(ioctlsocket)(a.s, FIONREAD, &n);
        EXPECT_EQ(n, 0);
    }
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_connected_recvfrom_reports_the_peer_address) {
    ud_ep a, b; struct sockaddr_storage from; int fl = sizeof from; char c;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(ud_sendto(&b, &a, "p", 1) == 1);
    CHECK(ud_recv_to(a.s, &c, 1, 0, &from, &fl, 3000) == 1);
    CHECK(ud_sameaddr(&b, &from, fl));
    ud_free(&a); ud_free(&b);
}

TEST(udp_reconnect_switches_the_accepted_peer) {
    ud_ep a, b, c; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(U(connect)(a.s, (struct sockaddr *)&c.sa, c.len) == 0);
    CHECK(ud_sendto(&b, &a, "old", 3) == 3);
    CHECK(ud_sendto(&c, &a, "new", 3) == 3);
    r = ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 3);
    CHECK(!memcmp(buf, "new", 3));
    CHECK(!ud_ready(a.s, 150));
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_reconnect_changes_destination_of_send) {
    ud_ep a, b, c; char buf[4];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(U(send)(a.s, "1", 1, 0) == 1);
    CHECK(U(connect)(a.s, (struct sockaddr *)&c.sa, c.len) == 0);
    CHECK(U(send)(a.s, "2", 1, 0) == 1);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 1 && buf[0] == '1');
    CHECK(ud_recv_to(c.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 1 && buf[0] == '2');
    CHECK(!ud_ready(b.s, 100)); CHECK(!ud_ready(c.s, 100));
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_dissolved_association_accepts_any_sender_again) {
    ud_ep a, b, c; struct sockaddr_in un; char buf[8]; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!ud_open(&c, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    memset(&un, 0, sizeof un);
    if (U(connect)(a.s, (struct sockaddr *)&un, sizeof un) != 0) {
        t_note("connect(AF_UNSPEC) on connected UDP failed err=%d", ud_err());
        ud_free(&a); ud_free(&b); ud_free(&c); return;
    }
    CHECK(ud_sendto(&c, &a, "any", 3) == 3);
    r = ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 3);
    ud_seterr(0);
    r = U(send)(a.s, "x", 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTCONN);
    ud_free(&a); ud_free(&b); ud_free(&c);
}

TEST(udp_mutually_connected_sockets_exchange_in_both_directions) {
    ud_ep a, b; int i, bad = 0; char buf[4];
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(U(connect)(b.s, (struct sockaddr *)&a.sa, a.len) == 0);
    for (i = 0; i < 10; i++) {
        buf[0] = (char)('A' + i);
        if (U(send)(a.s, buf, 1, 0) != 1) { bad++; break; }
        if (ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) != 1 || buf[0] != 'A' + i) { bad++; break; }
        buf[0] = (char)('a' + i);
        if (U(send)(b.s, buf, 1, 0) != 1) { bad++; break; }
        if (ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000) != 1 || buf[0] != 'a' + i) { bad++; break; }
    }
    EXPECT_EQ(bad, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_connected_zero_length_send_and_receive) {
    ud_ep a, b; char c; int r;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(U(connect)(b.s, (struct sockaddr *)&a.sa, a.len) == 0);
    r = U(send)(a.s, "", 0, 0);
    EXPECT_EQ(r, 0);
    r = ud_recv_to(b.s, &c, 1, 0, NULL, NULL, 3000);
    EXPECT_EQ(r, 0);
    ud_free(&a); ud_free(&b);
}

TEST(udp_connect_to_wrong_family_address_note) {
    ud_ep a; struct sockaddr_in6 to; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_lo6(&to, 0x3412);
    ud_seterr(0);
    r = U(connect)(a.s, (struct sockaddr *)&to, sizeof to);
    t_note("connect(IPv4 UDP socket, IPv6 address): r=%d err=%d", r, r ? ud_err() : 0);
    CHECK(r == SOCKET_ERROR);
    ud_free(&a);
}

TEST(udp_connect_short_address_is_efault) {
    ud_ep a, b; int r, len;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    for (len = 0; len < 16; len += 5) {
        ud_seterr(0);
        r = U(connect)(a.s, (struct sockaddr *)&b.sa, len);
        CHECKF(r == SOCKET_ERROR && ud_err() == WSAEFAULT, "len %d gave r=%d err=%d", len, r, ud_err());
    }
    ud_free(&a); ud_free(&b);
}

/* ---- ICMP port unreachable -> WSAECONNRESET ---- */

TEST(udp_send_to_closed_port_succeeds_then_receive_reports_connreset) {
    ud_ep a, t; int r;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    r = ud_sendto(&a, &t, "ping", 4);
    EXPECT_EQ(r, 4);
    CHECK(expect_reset(a.s, 3000));
    ud_free(&a);
}

TEST(udp_connreset_is_reported_once) {
    ud_ep a, t; char c; int r;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (!expect_reset(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); return; }
    ud_nonblock(a.s, 1);
    ud_seterr(0);
    r = U(recv)(a.s, &c, 1, 0);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEWOULDBLOCK);
    ud_free(&a);
}

TEST(udp_socket_is_usable_after_connreset) {
    ud_ep a, b, t; char buf[4];
    UP();
    if (!ud_pair(&a, &b, AF_INET) ) return;
    if (!closed_target(&t, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (!expect_reset(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); ud_free(&b); return; }
    CHECK(ud_sendto(&b, &a, "ok", 2) == 2);
    CHECK(ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 2);
    CHECK(ud_sendto(&a, &b, "ok", 2) == 2);
    CHECK(ud_recv_to(b.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 2);
    ud_free(&a); ud_free(&b);
}

TEST(udp_connreset_does_not_touch_other_sockets) {
    ud_ep a, o, t;
    UP();
    if (!ud_pair(&a, &o, AF_INET)) return;
    if (!closed_target(&t, AF_INET)) { ud_free(&a); ud_free(&o); t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (!expect_reset(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); ud_free(&o); return; }
    CHECK(!ud_ready(o.s, 100));
    ud_free(&a); ud_free(&o);
}

TEST(udp_connreset_makes_socket_readable_for_select) {
    ud_ep a, t;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(!ud_ready(a.s, 0));
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    CHECK(ud_ready(a.s, 3000));
    ud_free(&a);
}

TEST(udp_connreset_peek_note) {
    ud_ep a, t; char c; int r;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (!ud_ready(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); return; }
    ud_seterr(0);
    r = U(recv)(a.s, &c, 1, MSG_PEEK);
    t_note("MSG_PEEK receive with a pending reset: r=%d err=%d", r, r < 0 ? ud_err() : 0);
    ud_nonblock(a.s, 1);
    r = U(recv)(a.s, &c, 1, 0);
    t_note("following plain receive: r=%d err=%d", r, r < 0 ? ud_err() : 0);
    ud_free(&a);
}

TEST(udp_connreset_so_error_note) {
    ud_ep a, t; int e = -1;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (!ud_ready(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); return; }
    CHECK(ud_getint(a.s, SOL_SOCKET, SO_ERROR, &e) == 0);
    t_note("SO_ERROR with a pending reset: %d", e);
    ud_free(&a);
}

TEST(udp_connected_send_to_closed_port_then_receive_reports_connreset) {
    ud_ep a, t; int r;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&t.sa, t.len) == 0);
    r = U(send)(a.s, "ping", 4, 0);
    EXPECT_EQ(r, 4);
    CHECK(expect_reset(a.s, 3000));
    ud_free(&a);
}

TEST(udp_connected_send_after_connreset_note) {
    ud_ep a, t; int r;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(U(connect)(a.s, (struct sockaddr *)&t.sa, t.len) == 0);
    CHECK(U(send)(a.s, "ping", 4, 0) == 4);
    if (!ud_ready(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); return; }
    ud_seterr(0);
    r = U(send)(a.s, "ping", 4, 0);
    t_note("send after a pending reset on a connected socket: r=%d err=%d", r, r < 0 ? ud_err() : 0);
    ud_free(&a);
}

TEST(udp_connreset_ipv6_loopback) {
    ud_ep a, t;
    UP();
    if (!ud_v6_ok()) { t_skip("no IPv6 loopback"); return; }
    if (!ud_open(&a, AF_INET6) || !closed_target(&t, AF_INET6)) { t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    CHECK(expect_reset(a.s, 3000));
    ud_free(&a);
}

TEST(udp_connreset_wsarecvfrom_reports_connreset) {
    ud_ep a, t; WSABUF rb; DWORD got = 0, fl = 0; char c; int r;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (!ud_ready(a.s, 3000)) { t_note("no reset observed"); ud_free(&a); return; }
    rb.buf = &c; rb.len = 1;
    ud_seterr(0);
    r = U(WSARecvFrom)(a.s, &rb, 1, &got, &fl, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAECONNRESET);
    ud_free(&a);
}

TEST(udp_overlapped_receive_pending_gets_connreset) {
    ud_ep a, t; WSABUF rb; WSAOVERLAPPED ov; WSAEVENT ev; DWORD got = 0, fl = 0, x = 0, xf = 0; char c; int r, ok;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    ev = U(WSACreateEvent)();
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    rb.buf = &c; rb.len = 1;
    r = U(WSARecvFrom)(a.s, &rb, 1, &got, &fl, NULL, NULL, &ov, NULL);
    CHECK(r == SOCKET_ERROR && ud_err() == WSA_IO_PENDING);
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    if (U(WaitForSingleObject)(ev, 3000) != WAIT_OBJECT_0) {
        t_note("pending receive did not complete after the port-unreachable");
        ud_close(a.s); U(WaitForSingleObject)(ev, 2000); U(WSACloseEvent)(ev); return;
    }
    ud_seterr(0);
    ok = U(WSAGetOverlappedResult)(a.s, &ov, &x, FALSE, &xf);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(ud_err(), WSAECONNRESET);
    U(WSACloseEvent)(ev);
    ud_free(&a);
}

/* ---- SIO_UDP_CONNRESET ---- */

TEST(udp_connreset_disabled_suppresses_the_report) {
    ud_ep a, b, t; char buf[4]; DWORD n = 0xdeadbeef;
    UP();
    if (!ud_pair(&a, &b, AF_INET)) return;
    if (!closed_target(&t, AF_INET)) { ud_free(&a); ud_free(&b); t_skip("endpoint"); return; }
    EXPECT_EQ(connreset_set(a.s, FALSE, &n), 0);
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    CHECK(!ud_ready(a.s, 600));
    CHECK(ud_sendto(&b, &a, "ok", 2) == 2);
    CHECK(ud_recv_to(a.s, buf, sizeof buf, 0, NULL, NULL, 3000) == 2);
    ud_free(&a); ud_free(&b);
}

TEST(udp_connreset_disabled_then_enabled_again) {
    ud_ep a, t;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(connreset_set(a.s, FALSE, NULL) == 0);
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    CHECK(!ud_ready(a.s, 400));
    CHECK(connreset_set(a.s, TRUE, NULL) == 0);
    CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
    CHECK(expect_reset(a.s, 3000));
    ud_free(&a);
}

TEST(udp_connreset_disabled_on_connected_socket) {
    ud_ep a, t;
    UP();
    if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
    CHECK(connreset_set(a.s, FALSE, NULL) == 0);
    CHECK(U(connect)(a.s, (struct sockaddr *)&t.sa, t.len) == 0);
    CHECK(U(send)(a.s, "ping", 4, 0) == 4);
    CHECK(!ud_ready(a.s, 600));
    ud_free(&a);
}

TEST(udp_connreset_nonzero_input_values_all_mean_enabled) {
    static const DWORD vals[] = { 1, 2, 0x100, 0x01000000, 0xffffffff };
    unsigned i;
    UP();
    for (i = 0; i < sizeof vals / sizeof *vals; i++) {
        ud_ep a, t; DWORD v = vals[i]; DWORD n = 0; int r;
        if (!ud_open(&a, AF_INET) || !closed_target(&t, AF_INET)) { t_skip("endpoint"); return; }
        CHECK(connreset_set(a.s, FALSE, NULL) == 0);
        r = U(WSAIoctl)(a.s, SIO_UDP_CONNRESET, &v, sizeof v, NULL, 0, &n, NULL, NULL);
        CHECKF(r == 0, "value 0x%lx rejected err=%d", v, ud_err());
        CHECK(ud_sendto(&a, &t, "ping", 4) == 4);
        t_note("SIO_UDP_CONNRESET value 0x%lx: reset reported=%d", v, ud_ready(a.s, 1500));
        ud_free(&a);
    }
}

TEST(udp_connreset_ioctl_missing_input_is_efault) {
    ud_ep a; DWORD n = 0; BOOL on = FALSE; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_seterr(0);
    r = U(WSAIoctl)(a.s, SIO_UDP_CONNRESET, NULL, 0, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_seterr(0);
    r = U(WSAIoctl)(a.s, SIO_UDP_CONNRESET, &on, 0, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_seterr(0);
    r = U(WSAIoctl)(a.s, SIO_UDP_CONNRESET, NULL, sizeof on, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    ud_free(&a);
}

TEST(udp_connreset_ioctl_without_byte_count_is_efault) {
    ud_ep a; BOOL on = FALSE; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_seterr(0);
    r = U(WSAIoctl)(a.s, SIO_UDP_CONNRESET, &on, sizeof on, NULL, 0, NULL, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    ud_free(&a);
}

TEST(udp_connreset_ioctl_on_stream_socket_is_einval) {
    SOCKET s; BOOL on = FALSE; DWORD n = 0; int r;
    UP();
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    ud_seterr(0);
    r = U(WSAIoctl)(s, SIO_UDP_CONNRESET, &on, sizeof on, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEINVAL);
    ud_close(s);
}

TEST(udp_netreset_ioctl_validation) {
    ud_ep a; SOCKET s; BOOL on = FALSE; DWORD n = 0; int r;
    UP();
    if (!ud_open(&a, AF_INET)) { t_skip("endpoint"); return; }
    ud_seterr(0);
    r = U(WSAIoctl)(a.s, SIO_UDP_NETRESET, &on, sizeof on, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, 0);
    ud_seterr(0);
    r = U(WSAIoctl)(a.s, SIO_UDP_NETRESET, NULL, 0, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEFAULT);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    ud_seterr(0);
    r = U(WSAIoctl)(s, SIO_UDP_NETRESET, &on, sizeof on, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAEINVAL);
    ud_close(s);
    ud_free(&a);
}

TEST(udp_connreset_ioctl_on_unbound_socket_succeeds) {
    SOCKET s; int r;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    r = connreset_set(s, FALSE, NULL);
    EXPECT_EQ(r, 0);
    ud_close(s);
}

TEST(udp_connreset_ioctl_survives_bind_after_setting) {
    SOCKET s; struct sockaddr_in a, n; int l = sizeof n; ud_ep t;
    UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    CHECK(connreset_set(s, FALSE, NULL) == 0);
    ud_lo4(&a, 0);
    CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(U(getsockname)(s, (struct sockaddr *)&n, &l) == 0);
    if (!closed_target(&t, AF_INET)) { ud_close(s); t_skip("endpoint"); return; }
    CHECK(U(sendto)(s, "ping", 4, 0, (struct sockaddr *)&t.sa, t.len) == 4);
    CHECK(!ud_ready(s, 500));
    ud_close(s);
}

TEST(udp_connreset_ioctl_invalid_socket_is_enotsock) {
    BOOL on = FALSE; DWORD n = 0; int r;
    UP();
    ud_seterr(0);
    r = U(WSAIoctl)(INVALID_SOCKET, SIO_UDP_CONNRESET, &on, sizeof on, NULL, 0, &n, NULL, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(ud_err(), WSAENOTSOCK);
}
