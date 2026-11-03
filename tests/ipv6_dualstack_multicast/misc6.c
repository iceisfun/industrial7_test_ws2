/* IPv6 socket-state rules and text/name conversion for IPv6 literals.
 * Measures: error codes for operations that are invalid for the socket's state or type (send before
 * connect, accept without listen, listen on a datagram socket), basic socket option reads on IPv6
 * sockets, FIONREAD on an IPv6 datagram socket, and numeric conversions (WSAStringToAddress,
 * WSAAddressToString, getaddrinfo, getnameinfo) that need no resolver.  Loopback only. */
#include "d6.h"

TEST(ds6_misc_tcp_send_before_connect_is_enotconn) {
    SOCKET s; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    d_seterr(0);
    rc = d_send(s, "x", 1);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENOTCONN);
    d_close(s);
}

TEST(ds6_misc_udp_send_without_peer_is_enotconn) {
    SOCKET s; int rc;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    d_seterr(0);
    rc = d_send(s, "x", 1);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENOTCONN);
    d_close(s);
}

TEST(ds6_misc_accept_without_listen_is_einval) {
    SOCKET s, a; struct sockaddr_in6 sa; int n = sizeof sa;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, 0);
    CHECK(d_bind(s, &sa, sizeof sa) == 0);
    d_seterr(0);
    a = d_accept(s, &sa, &n);
    EXPECT_EQ(a, INVALID_SOCKET);
    EXPECT_EQ(d_err(), WSAEINVAL);
    d_close(s);
}

TEST(ds6_misc_listen_on_datagram_socket_is_eopnotsupp) {
    SOCKET s; int rc; struct sockaddr_in6 sa;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&sa, K_LOOP, 0);
    CHECK(d_bind(s, &sa, sizeof sa) == 0);
    d_seterr(0);
    rc = d_listen(s, 1);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEOPNOTSUPP);
    d_close(s);
}

TEST(ds6_misc_accept_on_datagram_socket_is_eopnotsupp) {
    SOCKET s, a; struct sockaddr_in6 sa;
    NEED_V6();
    s = d_sock(AF_INET6, SOCK_DGRAM);
    mk6(&sa, K_LOOP, 0);
    CHECK(d_bind(s, &sa, sizeof sa) == 0);
    d_seterr(0);
    a = d_accept(s, NULL, NULL);
    EXPECT_EQ(a, INVALID_SOCKET);
    EXPECT_EQ(d_err(), WSAEOPNOTSUPP);
    d_close(s);
}

TEST(ds6_misc_so_type_and_acceptconn_on_v6_sockets) {
    lsn l; SOCKET u; int v;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    CHECK(d_getint(l.s, SOL_SOCKET, SO_TYPE, &v) == 0); EXPECT_EQ(v, SOCK_STREAM);
    CHECK(d_getint(l.s, SOL_SOCKET, SO_ACCEPTCONN, &v) == 0); EXPECT_EQ(v, 1);
    u = d_sock(AF_INET6, SOCK_DGRAM);
    CHECK(d_getint(u, SOL_SOCKET, SO_TYPE, &v) == 0); EXPECT_EQ(v, SOCK_DGRAM);
    d_seterr(0);
    CHECK(d_getint(u, SOL_SOCKET, SO_ACCEPTCONN, &v) != 0);      /* a datagram socket has no listening state */
    EXPECT_EQ(d_err(), WSAENOPROTOOPT);
    d_close(u); d_close(l.s);
}

TEST(ds6_misc_v6only_on_invalid_socket_is_enotsock) {
    int v = 1, rc;
    if (!d_up()) return;
    d_seterr(0);
    rc = d_sso(INVALID_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof v);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENOTSOCK);
    d_seterr(0);
    rc = d_getint(INVALID_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, &v);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAENOTSOCK);
}

TEST(ds6_misc_v6only_on_v4_socket_note) {
    SOCKET s; int v, rc;
    NEED_V6();
    s = d_sock(AF_INET, SOCK_STREAM);
    d_seterr(0);
    rc = d_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, &v);
    t_note("getsockopt IPV6_V6ONLY on an AF_INET socket: rc %d err %d", rc, rc ? d_err() : 0);
    d_seterr(0);
    rc = d_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    t_note("setsockopt IPV6_V6ONLY on an AF_INET socket: rc %d err %d", rc, rc ? d_err() : 0);
    d_close(s);
}

TEST(ds6_misc_udp_fionread_reports_datagram_size) {
    usk r, s; struct sockaddr_in6 to; unsigned long n = 0; char buf[32];
    NEED_V6();
    CHECK(usk_open6(&r, K_LOOP, -1)); CHECK(usk_open6(&s, K_LOOP, -1));
    mk6(&to, K_LOOP, r.port);
    CHECK(d_sendto(s.s, "0123456789", 10, &to, sizeof to) == 10);
    CHECK(d_readable(r.s, 3000));
    CHECK(U(ioctlsocket)(r.s, FIONREAD, &n) == 0);
    EXPECT_EQ(n, 10u);
    CHECK(d_recv(r.s, buf, sizeof buf) == 10);
    CHECK(U(ioctlsocket)(r.s, FIONREAD, &n) == 0);
    EXPECT_EQ(n, 0u);
    d_close(r.s); d_close(s.s);
}

TEST(ds6_misc_string_to_address_v6_literals) {
    struct sockaddr_in6 a; int len = sizeof a, rc;
    char s1[] = "[::1]:80", s2[] = "::1", s3[] = "[::ffff:127.0.0.1]:9";
    if (!d_up()) return;
    memset(&a, 0xAA, sizeof a);
    rc = U(WSAStringToAddressA)(s1, AF_INET6, NULL, (LPSOCKADDR)&a, &len);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(len, SZ_SA6);
    EXPECT_EQ(a.sin6_family, AF_INET6);
    EXPECT_EQ(a.sin6_port, d_h16(80));
    CHECK(is_v6_loop(&a));
    len = sizeof a; memset(&a, 0xAA, sizeof a);
    rc = U(WSAStringToAddressA)(s2, AF_INET6, NULL, (LPSOCKADDR)&a, &len);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(a.sin6_port, 0);
    CHECK(is_v6_loop(&a));
    len = sizeof a;
    rc = U(WSAStringToAddressA)(s3, AF_INET6, NULL, (LPSOCKADDR)&a, &len);
    EXPECT_EQ(rc, 0);
    CHECK(is_mapped_loop(&a));
    EXPECT_EQ(a.sin6_port, d_h16(9));
}

TEST(ds6_misc_string_to_address_v6_garbage_is_einval) {
    struct sockaddr_in6 a; int len = sizeof a, rc;
    char bad[] = "::1::2";
    if (!d_up()) return;
    d_seterr(0);
    rc = U(WSAStringToAddressA)(bad, AF_INET6, NULL, (LPSOCKADDR)&a, &len);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEINVAL);
}

TEST(ds6_misc_address_to_string_v6_loopback) {
    struct sockaddr_in6 a; char out[64]; DWORD n = sizeof out; int rc;
    if (!d_up()) return;
    mk6(&a, K_LOOP, d_h16(80));
    rc = U(WSAAddressToStringA)((LPSOCKADDR)&a, sizeof a, NULL, out, &n);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(strcmp(out, "[::1]:80"), 0);
    EXPECT_EQ(n, (DWORD)(strlen(out) + 1));
    mk6(&a, K_LOOP, 0);
    n = sizeof out;
    rc = U(WSAAddressToStringA)((LPSOCKADDR)&a, sizeof a, NULL, out, &n);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(strcmp(out, "::1"), 0);
}

TEST(ds6_misc_address_to_string_small_buffer_reports_size) {
    struct sockaddr_in6 a; char out[4]; DWORD n = sizeof out; int rc;
    if (!d_up()) return;
    mk6(&a, K_LOOP, d_h16(80));
    d_seterr(0);
    rc = U(WSAAddressToStringA)((LPSOCKADDR)&a, sizeof a, NULL, out, &n);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(d_err(), WSAEFAULT);
    EXPECT_EQ(n, (DWORD)strlen("[::1]:80") + 1);
}

TEST(ds6_misc_getaddrinfo_numeric_v6_literal) {
    ADDRINFOA hint, *res = NULL; int rc;
    if (!d_up()) return;
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_UNSPEC; hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    rc = U(getaddrinfo)("::1", "8080", &hint, &res);
    EXPECT_EQ(rc, 0);
    if (rc == 0 && res) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)res->ai_addr;
        EXPECT_EQ(res->ai_family, AF_INET6);
        EXPECT_EQ((int)res->ai_addrlen, SZ_SA6);
        EXPECT_EQ(res->ai_socktype, SOCK_STREAM);
        EXPECT_EQ(a->sin6_port, d_h16(8080));
        CHECK(is_v6_loop(a));
        U(freeaddrinfo)(res);
    }
}

TEST(ds6_misc_getaddrinfo_numeric_v6_literal_wrong_family_fails) {
    ADDRINFOA hint, *res = NULL; int rc;
    if (!d_up()) return;
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_INET; hint.ai_socktype = SOCK_STREAM; hint.ai_flags = AI_NUMERICHOST;
    rc = U(getaddrinfo)("::1", "80", &hint, &res);
    CHECK(rc != 0);
    if (rc == 0 && res) U(freeaddrinfo)(res);
}

TEST(ds6_misc_getnameinfo_numeric_v6) {
    struct sockaddr_in6 a; char host[64], serv[16]; int rc;
    if (!d_up()) return;
    mk6(&a, K_LOOP, d_h16(8080));
    rc = U(getnameinfo)((const struct sockaddr *)&a, sizeof a, host, sizeof host, serv, sizeof serv,
                        NI_NUMERICHOST | NI_NUMERICSERV);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(strcmp(host, "::1"), 0);
    EXPECT_EQ(strcmp(serv, "8080"), 0);
}

TEST(ds6_misc_getnameinfo_mapped_address_text) {
    struct sockaddr_in6 a; char host[64]; int rc;
    if (!d_up()) return;
    mk6(&a, K_MAP_LOOP, 0);
    rc = U(getnameinfo)((const struct sockaddr *)&a, sizeof a, host, sizeof host, NULL, 0, NI_NUMERICHOST);
    EXPECT_EQ(rc, 0);
    t_note("numeric text of a v4-mapped address: %s", host);
    CHECK(strstr(host, "127.0.0.1") != NULL);
}

TEST(ds6_misc_tcp_getsockopt_type_on_accepted_v6_socket) {
    lsn l; SOCKET c, a; struct sockaddr_in6 sa; int v;
    NEED_V6();
    CHECK(lsn_open6(&l, K_LOOP, -1));
    c = d_sock(AF_INET6, SOCK_STREAM);
    mk6(&sa, K_LOOP, l.port);
    CHECK(d_connect(c, &sa, sizeof sa) == 0);
    a = d_accept_to(l.s, 3000, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    if (a != INVALID_SOCKET) {
        CHECK(d_getint(a, SOL_SOCKET, SO_TYPE, &v) == 0); EXPECT_EQ(v, SOCK_STREAM);
        CHECK(d_getint(a, SOL_SOCKET, SO_ACCEPTCONN, &v) == 0); EXPECT_EQ(v, 0);
        d_close(a);
    }
    d_close(c); d_close(l.s);
}
