/* IOCTL_AFD_CONNECT (0x12007) driven directly on the socket handle.
 *
 * The request is a 0x18-byte header (use-SAN flag, root handle, reserved word) followed by the raw socket
 * address; a shorter block is an invalid parameter and completes in the submit call. The address is validated
 * before any network activity: a family above the largest the driver knows, or fewer bytes than the family's
 * address size, is an invalid-address error (or an invalid parameter on the legacy endpoint flavour, so the
 * length-shape tests accept either and record which one this system produced). A good request on a stream
 * socket pends or completes immediately and ends with success and zero bytes; a closed port ends with the
 * connection-refused status. On a datagram socket the same request sets the default peer.
 */
#include "csr.h"

/* accept a queued connection with a bounded wait */
static SOCKET take(SOCKET l) { return cs_readable(l, CS_WAIT) ? X.accept(l, NULL, NULL) : INVALID_SOCKET; }

static void expect_bad_shape(SOCKET s, const void *sa, ULONG salen, const char *what) {
    UCHAR req[0x40]; memset(req, 0, sizeof req);
    memcpy(req + 0x18, sa, salen > 0x28 ? 0x28 : salen);
    CS_R r = cs_ioctl(s, CS_IOCTL_CONNECT, req, 0x18 + salen, NULL, 0);
    CHECKF((ULONG)r.first == CS_INVALID_ADDRESS || (ULONG)r.first == CS_INVALID_PARAMETER,
           "%s: submit status 0x%08lx", what, (unsigned long)r.first);
    CHECK_ST(r.final, r.first);
    t_note("connect %s -> %s", what, (ULONG)r.first == CS_INVALID_ADDRESS ? "INVALID_ADDRESS" : "other");
}

TEST(csrconn_stream_connect_to_listener) {
    CS_BEGIN();
    struct sockaddr_in la, ca, name, peer; int n = sizeof name;
    SOCKET l = cs_listener(&la);
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    cs_bind_lo(c, &ca);
    CS_R r = cs_connect(c, &la, sizeof la);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 0);
    SOCKET s = take(l);
    CHECK(s != INVALID_SOCKET);
    /* the accepted side names the connecting socket (the winsock layer's own cache of the raw-connected
       socket is not updated by a raw request, so only the accepted side is asked) */
    n = sizeof peer;
    CHECK(s != INVALID_SOCKET && X.getpeername(s, (struct sockaddr *)&peer, &n) == 0);
    CHECK(peer.sin_port == ca.sin_port && peer.sin_addr.s_addr == ca.sin_addr.s_addr);
    CHECK(X.send(c, "ping", 4, 0) == 4);
    char b[8] = {0};
    CHECK(s != INVALID_SOCKET && cs_readable(s, CS_WAIT) && X.recv(s, b, sizeof b, 0) == 4 && !memcmp(b, "ping", 4));
    cs_close(c); cs_close(s); cs_close(l);
}

TEST(csrconn_event_is_signalled_on_completion) {
    CS_BEGIN();
    struct sockaddr_in la;
    SOCKET l = cs_listener(&la), c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    CS_R r = cs_connect(c, &la, sizeof la);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(r.signalled);
    cs_close(take(l)); cs_close(c); cs_close(l);
}

TEST(csrconn_unbound_socket_note) {
    CS_BEGIN();
    struct sockaddr_in la, name; int n = sizeof name;
    SOCKET l = cs_listener(&la), c = cs_sock(AF_INET, SOCK_STREAM);
    CS_R r = cs_connect(c, &la, sizeof la);
    t_note("raw connect on an unbound socket: submit 0x%08lx final 0x%08lx", (unsigned long)r.first, (unsigned long)r.final);
    if ((ULONG)r.final == CS_SUCCESS) {
        int gn = X.getsockname(c, (struct sockaddr *)&name, &n);
        t_note("getsockname after an implicit bind by raw connect: %d", gn);
    }
    cs_close(take(l)); cs_close(c); cs_close(l);
}

TEST(csrconn_refused_port) {
    CS_BEGIN();
    struct sockaddr_in la;
    SOCKET l = cs_listener(&la);
    cs_close(l);                                  /* nothing listens on that port any more */
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    CS_R r = cs_connect_ms(c, &la, sizeof la, CS_REFUSE_WAIT);
    CHECK_ASYNC_OK(r);
    CHECK_ST(r.final, CS_CONNECTION_REFUSED);
    cs_close(c);
}

TEST(csrconn_refused_leaves_socket_reusable) {
    CS_BEGIN();
    struct sockaddr_in dead, la;
    SOCKET d = cs_listener(&dead); cs_close(d);
    SOCKET l = cs_listener(&la);
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    CS_R r = cs_connect_ms(c, &dead, sizeof dead, CS_REFUSE_WAIT);
    CHECK_ST(r.final, CS_CONNECTION_REFUSED);
    /* A refused attempt does not consume the endpoint's ability to try again (the winsock layer keeps the
       socket open for another connect). Record what the raw layer says. */
    r = cs_connect(c, &la, sizeof la);
    t_note("second raw connect after a refusal: 0x%08lx", (unsigned long)r.final);
    cs_close(take(l)); cs_close(c); cs_close(l);
}

/* ---- input length table: anything below the 0x18-byte header is rejected synchronously ---------------- */
static void short_header(ULONG len) {
    CS_BEGIN();
    struct sockaddr_in la;
    SOCKET l = cs_listener(&la), c = cs_sock(AF_INET, SOCK_STREAM);
    UCHAR req[0x40]; memset(req, 0, sizeof req);
    memcpy(req + 0x18, &la, sizeof la);
    CS_R r = cs_ioctl(c, CS_IOCTL_CONNECT, req, len, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(l);
}
TEST(csrconn_input_length_0) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    CS_R r = cs_ioctl(c, CS_IOCTL_CONNECT, NULL, 0, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c);
}
TEST(csrconn_input_length_1)    { short_header(1); }
TEST(csrconn_input_length_8)    { short_header(8); }
TEST(csrconn_input_length_0x10) { short_header(0x10); }
TEST(csrconn_input_length_0x17) { short_header(0x17); }

TEST(csrconn_header_without_address) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    UCHAR req[0x18]; memset(req, 0, sizeof req);
    CS_R r = cs_ioctl(c, CS_IOCTL_CONNECT, req, 0x18, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c);
}
TEST(csrconn_address_one_byte) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    UCHAR req[0x19]; memset(req, 0, sizeof req); req[0x18] = AF_INET;
    CS_R r = cs_ioctl(c, CS_IOCTL_CONNECT, req, 0x19, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c);
}

/* ---- address shape ------------------------------------------------------------------------------------ */
TEST(csrconn_inet_address_too_short) {
    CS_BEGIN();
    struct sockaddr_in la;
    SOCKET l = cs_listener(&la), c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    static const ULONG lens[] = { 2, 4, 8, 12, 15 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        char what[32]; sprintf(what, "AF_INET address of %lu bytes", lens[i]);
        expect_bad_shape(c, &la, lens[i], what);
    }
    cs_close(c); cs_close(l);
}
TEST(csrconn_family_above_known_range) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in a = cs_lo4(BE16(9)); a.sin_family = 0x23;
    expect_bad_shape(c, &a, sizeof a, "family 0x23");
    a.sin_family = 0x1000;
    expect_bad_shape(c, &a, sizeof a, "family 0x1000");
    a.sin_family = 0xffff;
    expect_bad_shape(c, &a, sizeof a, "family 0xffff");
    cs_close(c);
}
TEST(csrconn_inet6_address_too_short_on_v6_socket) {
    CS_BEGIN();
    if (!cs_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET c = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; a.sin6_port = BE16(9);
    expect_bad_shape(c, &a, 16, "AF_INET6 address of 16 bytes");
    expect_bad_shape(c, &a, 20, "AF_INET6 address of 20 bytes");
    cs_close(c);
}
TEST(csrconn_trailing_bytes_after_address_note) {
    CS_BEGIN();
    struct sockaddr_in la;
    SOCKET l = cs_listener(&la), c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    UCHAR a[24]; memset(a, 0, sizeof a); memcpy(a, &la, sizeof la);
    CS_R r = cs_connect(c, a, sizeof a);
    t_note("connect with 8 trailing address bytes: 0x%08lx", (unsigned long)r.final);
    cs_close(take(l)); cs_close(c); cs_close(l);
}
TEST(csrconn_port_zero_note) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    struct sockaddr_in a = cs_lo4(0);
    CS_R r = cs_connect(c, &a, sizeof a);
    CHECKF((ULONG)r.final != CS_SUCCESS && (ULONG)r.final != CS_PENDING, "connect to port 0 ended 0x%08lx", (unsigned long)r.final);
    t_note("connect to loopback port 0: 0x%08lx", (unsigned long)r.final);
    cs_close(c);
}
TEST(csrconn_inet6_destination_on_inet_socket_note) {
    CS_BEGIN();
    if (!cs_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in ca; cs_bind_lo(c, &ca);
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; a.sin6_port = BE16(9);
    CS_R r = cs_connect(c, &a, sizeof a);
    CHECKF((ULONG)r.final != CS_SUCCESS, "connect of an IPv4 socket to ::1 succeeded");
    t_note("AF_INET socket, AF_INET6 destination: 0x%08lx", (unsigned long)r.final);
    cs_close(c);
}

/* ---- state ---------------------------------------------------------------------------------------------- */
TEST(csrconn_second_connect_on_connected_socket_note) {
    CS_BEGIN();
    struct sockaddr_in la;
    SOCKET l = cs_listener(&la), c, s;
    cs_pair(&c, &s);
    CS_R r = cs_connect(c, &la, sizeof la);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "second connect left pending");
    t_note("connect on a connected stream socket: 0x%08lx", (unsigned long)r.final);
    cs_close(c); cs_close(s); cs_close(l);
}
TEST(csrconn_connect_on_listener_note) {
    CS_BEGIN();
    struct sockaddr_in la, lb;
    SOCKET l = cs_listener(&la), m = cs_listener(&lb);
    CS_R r = cs_connect(l, &lb, sizeof lb);
    CHECKF((ULONG)r.final != CS_SUCCESS, "a listening socket connected");
    t_note("connect on a listening socket: 0x%08lx", (unsigned long)r.final);
    cs_close(l); cs_close(m);
}
TEST(csrconn_connect_to_self_listener_port_is_refused_or_ok) {
    CS_BEGIN();
    struct sockaddr_in la, ca;
    SOCKET l = cs_listener(&la);
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    cs_bind_lo(c, &ca);
    CS_R r = cs_connect(c, &ca, sizeof ca);            /* its own, non-listening address */
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "connect to an own non-listening address hung");
    t_note("connect to own bound address: 0x%08lx", (unsigned long)r.final);
    cs_close(c); cs_close(l);
}

/* ---- datagram sockets --------------------------------------------------------------------------------- */
TEST(csrconn_udp_connect_sets_peer) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba, peer; int n = sizeof peer;
    cs_udp_pair(&a, &b, &aa, &ba);
    CS_R r = cs_connect(a, &ba, sizeof ba);
    CHECK_DONE(r, CS_SUCCESS, 0);
    /* the default peer is visible through its effect: only that peer's datagrams are delivered */
    SOCKET c = cs_sock(AF_INET, SOCK_DGRAM); struct sockaddr_in ca; cs_bind_lo(c, &ca);
    CHECK(X.sendto(c, "N", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    CHECK(X.sendto(b, "P", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    char got[4] = {0};
    CHECK(cs_readable(a, CS_WAIT) && X.recv(a, got, sizeof got, 0) == 1 && got[0] == 'P');
    cs_close(a); cs_close(b); cs_close(c);
}
TEST(csrconn_udp_connect_then_unaddressed_send) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CS_R sr = cs_send(a, "dgram", 5, 0, 0);                /* the raw connection-style send, no address */
    CHECK_DONE(sr, CS_SUCCESS, 5);
    char buf[16] = {0};
    CHECK(cs_readable(b, CS_WAIT) && X.recv(b, buf, sizeof buf, 0) == 5 && !memcmp(buf, "dgram", 5));
    cs_close(a); cs_close(b);
}
TEST(csrconn_udp_connect_filters_other_senders) {
    CS_BEGIN();
    SOCKET a, b, c; struct sockaddr_in aa, ba, ca;
    cs_udp_pair(&a, &b, &aa, &ba);
    c = cs_sock(AF_INET, SOCK_DGRAM); cs_bind_lo(c, &ca);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CHECK(X.sendto(c, "X", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);   /* not the connected peer: dropped */
    CHECK(X.sendto(b, "Y", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    char buf[4] = {0};
    CHECK(cs_readable(a, CS_WAIT) && X.recv(a, buf, sizeof buf, 0) == 1);
    CHECK(buf[0] == 'Y');
    cs_close(a); cs_close(b); cs_close(c);
}
TEST(csrconn_udp_reconnect_to_other_peer) {
    CS_BEGIN();
    SOCKET a, b, c; struct sockaddr_in aa, ba, ca, peer; int n = sizeof peer;
    cs_udp_pair(&a, &b, &aa, &ba);
    c = cs_sock(AF_INET, SOCK_DGRAM); cs_bind_lo(c, &ca);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CS_R r = cs_connect(a, &ca, sizeof ca);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(X.sendto(b, "O", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);   /* the old peer is now filtered */
    CHECK(X.sendto(c, "N", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    char got[4] = {0};
    CHECK(cs_readable(a, CS_WAIT) && X.recv(a, got, sizeof got, 0) == 1 && got[0] == 'N');
    cs_close(a); cs_close(b); cs_close(c);
}
TEST(csrconn_udp_connect_unbound_note) {
    CS_BEGIN();
    SOCKET a = cs_sock(AF_INET, SOCK_DGRAM), b = cs_sock(AF_INET, SOCK_DGRAM);
    struct sockaddr_in ba; cs_bind_lo(b, &ba);
    CS_R r = cs_connect(a, &ba, sizeof ba);
    t_note("raw connect on an unbound UDP socket: 0x%08lx", (unsigned long)r.final);
    cs_close(a); cs_close(b);
}
TEST(csrconn_udp_bad_address_shape) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    expect_bad_shape(a, &ba, 8, "UDP AF_INET address of 8 bytes");
    cs_close(a); cs_close(b);
}
TEST(csrconn_udp_short_header) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    UCHAR req[0x30]; memset(req, 0, sizeof req); memcpy(req + 0x18, &ba, sizeof ba);
    CS_R r = cs_ioctl(a, CS_IOCTL_CONNECT, req, 0x14, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(a); cs_close(b);
}

/* ---- v6 --------------------------------------------------------------------------------------------- */
TEST(csrconn_v6_loopback_connect) {
    CS_BEGIN();
    if (!cs_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET l = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    CHECK(X.bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    int n = sizeof a;
    CHECK(X.getsockname(l, (struct sockaddr *)&a, &n) == 0);
    CHECK(X.listen(l, 2) == 0);
    SOCKET c = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in6 b; memset(&b, 0, sizeof b);
    b.sin6_family = AF_INET6; b.sin6_addr.u.Byte[15] = 1;
    CHECK(X.bind(c, (struct sockaddr *)&b, sizeof b) == 0);
    CS_R r = cs_connect(c, &a, sizeof a);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 0);
    cs_close(take(l)); cs_close(c); cs_close(l);
}
TEST(csrconn_v6_refused) {
    CS_BEGIN();
    if (!cs_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET l = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    CHECK(X.bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    int n = sizeof a;
    CHECK(X.getsockname(l, (struct sockaddr *)&a, &n) == 0);
    cs_close(l);
    SOCKET c = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in6 b; memset(&b, 0, sizeof b);
    b.sin6_family = AF_INET6; b.sin6_addr.u.Byte[15] = 1;
    CHECK(X.bind(c, (struct sockaddr *)&b, sizeof b) == 0);
    CS_R r = cs_connect_ms(c, &a, sizeof a, CS_REFUSE_WAIT);
    CHECK_ST(r.final, CS_CONNECTION_REFUSED);
    cs_close(c);
}
