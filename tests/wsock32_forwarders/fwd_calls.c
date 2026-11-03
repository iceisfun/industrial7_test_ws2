/* Calls made purely through wsock32's forwarded exports.
 *
 * The forwarders carry no code of their own, so the contract is "wsock32.<name> behaves as ws2_32.<name>"
 * (or mswsock.<name>). This file drives complete scenarios with only wsock32 entry points (a TCP echo with
 * socket/bind/listen/connect/accept/send/recv/shutdown/closesocket/select/ioctlsocket, a datagram
 * exchange), the documented error results of the socket calls reached through wsock32, the not-initialised
 * result of each call that needs a running stack, WSAStartup through wsock32, the mswsock extension exports
 * (AcceptEx, GetAcceptExSockaddrs, TransmitFile) and the async-style compat calls with invalid arguments. */
#include "wf.h"

/* ---------------------------------------------------------------- byte order and address text */
TEST(fwd_htons_table) {
    static const unsigned short v[] = { 0, 1, 0x00ff, 0x0100, 0x1234, 0x8000, 0xabcd, 0xff00, 0xffff };
    p_htons f = WS(htons); unsigned i;
    REQUIRE(f);
    for (i = 0; i < sizeof v / sizeof v[0]; i++) CHECKF(f(v[i]) == wf_sw16(v[i]), "htons(%04x)", v[i]);
}
TEST(fwd_ntohs_table) {
    static const unsigned short v[] = { 0, 1, 0x00ff, 0x0100, 0x1234, 0x8000, 0xabcd, 0xff00, 0xffff };
    p_ntohs f = WS(ntohs); unsigned i;
    REQUIRE(f);
    for (i = 0; i < sizeof v / sizeof v[0]; i++) CHECKF(f(v[i]) == wf_sw16(v[i]), "ntohs(%04x)", v[i]);
}
TEST(fwd_htonl_table) {
    static const unsigned long v[] = { 0, 1, 0xff, 0x100, 0x12345678UL, 0x80000000UL, 0xdeadbeefUL, 0xff00ff00UL, 0xffffffffUL };
    p_htonl f = WS(htonl); unsigned i;
    REQUIRE(f);
    for (i = 0; i < sizeof v / sizeof v[0]; i++) CHECKF(f(v[i]) == wf_sw32(v[i]), "htonl(%08lx)", v[i]);
}
TEST(fwd_ntohl_table) {
    static const unsigned long v[] = { 0, 1, 0xff, 0x100, 0x12345678UL, 0x80000000UL, 0xdeadbeefUL, 0xff00ff00UL, 0xffffffffUL };
    p_ntohl f = WS(ntohl); unsigned i;
    REQUIRE(f);
    for (i = 0; i < sizeof v / sizeof v[0]; i++) CHECKF(f(v[i]) == wf_sw32(v[i]), "ntohl(%08lx)", v[i]);
}
TEST(fwd_byte_order_round_trip) {
    p_htonl h = WS(htonl); p_ntohl n = WS(ntohl); unsigned long x;
    REQUIRE(h); REQUIRE(n);
    for (x = 1; x < 0xffffffffUL / 3; x = x * 5 + 3) CHECK(n(h(x)) == x);
}
TEST(fwd_inet_addr_valid_forms) {
    p_inet_addr f = WS(inet_addr);
    REQUIRE(f);
    CHECK(f("127.0.0.1") == 0x0100007fUL);
    CHECK(f("0.0.0.0") == 0);
    CHECK(f("255.255.255.254") == 0xfeffffffUL);
    CHECK(f("10.20.30.40") == 0x281e140aUL);
    CHECK(f("1.2.3.4") == 0x04030201UL);
    CHECK(f("0x7f.1") == 0x0100007fUL);        /* classic shorthand forms are accepted */
    CHECK(f("127.1") == 0x0100007fUL);
}
TEST(fwd_inet_addr_invalid_forms_give_none) {
    p_inet_addr f = WS(inet_addr);
    static const char *bad[] = { "256.1.1.1", "1.2.3.4.5", "a.b.c.d", "1..2.3", ".1.2.3", "1.2.3.256" };
    unsigned i;
    REQUIRE(f);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECKF(f(bad[i]) == INADDR_NONE, "'%s'", bad[i]);
}
TEST(fwd_inet_addr_broadcast_text_is_ambiguous_with_none) {
    p_inet_addr f = WS(inet_addr);
    REQUIRE(f);
    CHECK(f("255.255.255.255") == INADDR_NONE);
}
TEST(fwd_inet_ntoa_text) {
    p_inet_ntoa f = WS(inet_ntoa); struct in_addr a; char *s;
    REQUIRE(f);
    WF_UP();
    a.s_addr = 0x0100007fUL; s = f(a);
    CHECK(s != NULL); if (s) EXPECT_STR(s, "127.0.0.1");
    a.s_addr = 0x04030201UL; s = f(a);
    CHECK(s != NULL); if (s) EXPECT_STR(s, "1.2.3.4");
    a.s_addr = 0; s = f(a);
    CHECK(s != NULL); if (s) EXPECT_STR(s, "0.0.0.0");
    a.s_addr = 0xffffffffUL; s = f(a);
    CHECK(s != NULL); if (s) EXPECT_STR(s, "255.255.255.255");
    wf_down();
}
TEST(fwd_inet_ntoa_reuses_one_buffer_per_thread) {
    p_inet_ntoa f = WS(inet_ntoa); struct in_addr a, b; char *s1, *s2;
    REQUIRE(f);
    WF_UP();
    a.s_addr = 0x0100007fUL; b.s_addr = 0x04030201UL;
    s1 = f(a); s2 = f(b);
    CHECK(s1 == s2);
    if (s2) EXPECT_STR(s2, "1.2.3.4");
    wf_down();
}
TEST(fwd_inet_addr_inet_ntoa_round_trip) {
    p_inet_addr fa = WS(inet_addr); p_inet_ntoa fn = WS(inet_ntoa); struct in_addr a; char *s;
    REQUIRE(fa); REQUIRE(fn);
    WF_UP();
    a.s_addr = fa("192.168.77.9");
    s = fn(a);
    CHECK(s != NULL); if (s) EXPECT_STR(s, "192.168.77.9");
    wf_down();
}

/* ---------------------------------------------------------------- startup through wsock32 */
TEST(fwd_wsastartup_1_1_request) {
    p_WSAStartup su = WS(WSAStartup); p_WSACleanup cl = WS(WSACleanup); WSADATA d;
    REQUIRE(su); REQUIRE(cl);
    memset(&d, 0xAA, sizeof d);
    WEQ(su(0x0101, &d), 0);
    WEQ(d.wVersion, 0x0101);
    WEQ(d.wHighVersion, 0x0202);
    WEQ(cl(), 0);
}
TEST(fwd_wsastartup_2_2_request) {
    p_WSAStartup su = WS(WSAStartup); p_WSACleanup cl = WS(WSACleanup); WSADATA d;
    REQUIRE(su); REQUIRE(cl);
    WEQ(su(0x0202, &d), 0);
    WEQ(d.wVersion, 0x0202);
    WEQ(d.wHighVersion, 0x0202);
    WEQ(cl(), 0);
}
TEST(fwd_wsastartup_1_0_request_echoed) {
    p_WSAStartup su = WS(WSAStartup); p_WSACleanup cl = WS(WSACleanup); WSADATA d;
    REQUIRE(su); REQUIRE(cl);
    WEQ(su(0x0001, &d), 0);
    WEQ(d.wVersion, 0x0001);
    WEQ(cl(), 0);
}
TEST(fwd_wsastartup_version_zero_refused) {
    p_WSAStartup su = WS(WSAStartup); WSADATA d;
    REQUIRE(su);
    WEQ(su(0x0000, &d), WSAVERNOTSUPPORTED);
}
TEST(fwd_wsastartup_description_and_status_filled) {
    p_WSAStartup su = WS(WSAStartup); p_WSACleanup cl = WS(WSACleanup); WSADATA d;
    REQUIRE(su); REQUIRE(cl);
    memset(&d, 0, sizeof d);
    WEQ(su(0x0101, &d), 0);
    CHECK(d.szDescription[0] != 0);
    EXPECT_STR(d.szSystemStatus, "Running");
    cl();
}
TEST(fwd_wsacleanup_without_startup_fails) {
    /* the count is process wide: balance whatever the other tests of this run left, then probe */
    p_WSACleanup cl = WS(WSACleanup); int guard = 0;
    REQUIRE(cl);
    while (cl() == 0 && guard++ < 64) {}
    wf_seterr(0);
    WEQ(cl(), SOCKET_ERROR);
    WEQ(wf_err(), WSANOTINITIALISED);
}
TEST(fwd_startup_then_ws2_32_socket_works) {
    p_WSAStartup su = WS(WSAStartup); p_WSACleanup cl = WS(WSACleanup); WSADATA d; SOCKET s;
    REQUIRE(su); REQUIRE(cl);
    WEQ(su(0x0101, &d), 0);
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) W2(closesocket)(s);
    WEQ(cl(), 0);
}
TEST(fwd_last_error_pair_shares_state) {
    p_WSASetLastError set = WS(WSASetLastError); p_WSAGetLastError get = WS(WSAGetLastError);
    REQUIRE(set); REQUIRE(get);
    set(10061);
    WEQ(get(), 10061);
    WEQ(W2(WSAGetLastError)(), 10061);
    WEQ(GetLastError(), 10061);
    set(0);
    WEQ(get(), 0);
}

/* ---------------------------------------------------------------- full scenarios with wsock32 entry points */
TEST(fwd_tcp_echo_roundtrip_all_wsock32) {
    p_socket sk = WS(socket); p_bind bd = WS(bind); p_listen ls = WS(listen); p_getsockname gn = WS(getsockname);
    p_connect cn = WS(connect); p_accept ac = WS(accept); p_send sd = WS(send); p_recv rc = WS(recv);
    p_getpeername gp = WS(getpeername); p_shutdown sh = WS(shutdown); p_closesocket cs = WS(closesocket);
    p_WSAStartup su = WS(WSAStartup); p_WSACleanup cl = WS(WSACleanup);
    SOCKET l, c, a; struct sockaddr_in sa = wf_lo(0), pa; int n = sizeof sa, pn = sizeof pa; char b[16]; WSADATA d; DWORD tmo = 3000;
    REQUIRE(sk); REQUIRE(bd); REQUIRE(ls); REQUIRE(gn); REQUIRE(cn); REQUIRE(ac); REQUIRE(sd); REQUIRE(rc);
    REQUIRE(gp); REQUIRE(sh); REQUIRE(cs); REQUIRE(su); REQUIRE(cl);
    WEQ(su(0x0101, &d), 0);
    l = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(l != INVALID_SOCKET);
    WEQ(bd(l, (struct sockaddr *)&sa, sizeof sa), 0);
    WEQ(ls(l, 1), 0);
    WEQ(gn(l, (struct sockaddr *)&sa, &n), 0);
    WEQ(n, sizeof sa);
    c = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    W2(setsockopt)(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    WEQ(cn(c, (struct sockaddr *)&sa, sizeof sa), 0);
    a = ac(l, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    W2(setsockopt)(a, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    WEQ(gp(c, (struct sockaddr *)&pa, &pn), 0);
    WEQ(pa.sin_port, sa.sin_port);
    WEQ(sd(c, "ping", 4, 0), 4);
    WEQ(rc(a, b, sizeof b, 0), 4);
    CHECK(!memcmp(b, "ping", 4));
    WEQ(sd(a, "pong!", 5, 0), 5);
    WEQ(rc(c, b, sizeof b, 0), 5);
    CHECK(!memcmp(b, "pong!", 5));
    WEQ(sh(c, SD_SEND), 0);
    WEQ(rc(a, b, sizeof b, 0), 0);
    WEQ(sh(a, SD_BOTH), 0);
    WEQ(cs(c), 0); WEQ(cs(a), 0); WEQ(cs(l), 0);
    WEQ(cl(), 0);
}
TEST(fwd_accept_returns_peer_address) {
    SOCKET c, a, l; struct sockaddr_in from, ca; int fl = sizeof from, cn = sizeof ca;
    p_accept ac = WS(accept);
    REQUIRE(ac);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, &l)) { wf_down(); t_skip("pair"); return; }
    W2(closesocket)(a);                         /* use the pair only to learn the listener */
    {
        struct sockaddr_in sa; int n = sizeof sa; SOCKET c2, a2;
        W2(getsockname)(l, (struct sockaddr *)&sa, &n);
        c2 = W2(socket)(AF_INET, SOCK_STREAM, 0);
        W2(connect)(c2, (struct sockaddr *)&sa, sizeof sa);
        W2(getsockname)(c2, (struct sockaddr *)&ca, &cn);
        memset(&from, 0, sizeof from);
        a2 = ac(l, (struct sockaddr *)&from, &fl);
        CHECK(a2 != INVALID_SOCKET);
        WEQ(fl, sizeof from);
        WEQ(from.sin_family, AF_INET);
        WEQ(from.sin_port, ca.sin_port);
        WEQ(from.sin_addr.s_addr, ca.sin_addr.s_addr);
        if (a2 != INVALID_SOCKET) W2(closesocket)(a2);
        W2(closesocket)(c2);
    }
    W2(closesocket)(c); W2(closesocket)(l);
    wf_down();
}
TEST(fwd_udp_exchange_all_wsock32) {
    p_socket sk = WS(socket); p_bind bd = WS(bind); p_getsockname gn = WS(getsockname); p_sendto st = WS(sendto);
    p_recvfrom rf = WS(recvfrom); p_closesocket cs = WS(closesocket);
    SOCKET a, b; struct sockaddr_in sa = wf_lo(0), sb = wf_lo(0), from; int na = sizeof sa, nb = sizeof sb, fl = sizeof from; char buf[16]; DWORD tmo = 3000;
    REQUIRE(sk); REQUIRE(bd); REQUIRE(gn); REQUIRE(st); REQUIRE(rf); REQUIRE(cs);
    WF_UP();
    a = sk(AF_INET, SOCK_DGRAM, IPPROTO_UDP); b = sk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET);
    WEQ(bd(a, (struct sockaddr *)&sa, sizeof sa), 0); WEQ(bd(b, (struct sockaddr *)&sb, sizeof sb), 0);
    WEQ(gn(a, (struct sockaddr *)&sa, &na), 0); WEQ(gn(b, (struct sockaddr *)&sb, &nb), 0);
    W2(setsockopt)(b, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    WEQ(st(a, "dgram", 5, 0, (struct sockaddr *)&sb, sizeof sb), 5);
    WEQ(rf(b, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl), 5);
    CHECK(!memcmp(buf, "dgram", 5));
    WEQ(from.sin_port, sa.sin_port);
    cs(a); cs(b);
    wf_down();
}
TEST(fwd_select_readability) {
    p_select sel = WS(select); SOCKET c, a; fd_set rd; struct timeval tv = { 0, 0 }; int r;
    REQUIRE(sel);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("pair"); return; }
    FD_ZERO(&rd); FD_SET(a, &rd);
    r = sel(0, &rd, NULL, NULL, &tv);
    WEQ(r, 0);
    WEQ(rd.fd_count, 0);                       /* the set is rewritten to the ready sockets */
    CHECK(W2(send)(c, "x", 1, 0) == 1);
    tv.tv_sec = 3;
    FD_ZERO(&rd); FD_SET(a, &rd);
    r = sel(0, &rd, NULL, NULL, &tv);
    WEQ(r, 1);
    WEQ(rd.fd_count, 1);
    WEQ(rd.fd_array[0], a);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(fwd_select_writability_of_connected_socket) {
    p_select sel = WS(select); SOCKET c, a; fd_set wr; struct timeval tv = { 3, 0 };
    REQUIRE(sel);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("pair"); return; }
    FD_ZERO(&wr); FD_SET(c, &wr);
    WEQ(sel(0, NULL, &wr, NULL, &tv), 1);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(fwd_select_empty_sets_is_inval) {
    p_select sel = WS(select); fd_set e; struct timeval tv = { 0, 0 };
    REQUIRE(sel);
    WF_UP();
    FD_ZERO(&e);
    wf_seterr(0);
    WEQ(sel(0, &e, &e, &e, &tv), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    wf_seterr(0);
    WEQ(sel(0, NULL, NULL, NULL, &tv), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    wf_down();
}
TEST(fwd_select_closed_socket_is_notsock) {
    p_select sel = WS(select); SOCKET s; fd_set rd; struct timeval tv = { 0, 0 };
    REQUIRE(sel);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    W2(closesocket)(s);
    FD_ZERO(&rd); FD_SET(s, &rd);
    wf_seterr(0);
    WEQ(sel(0, &rd, NULL, NULL, &tv), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(fwd_ioctlsocket_fionread_and_fionbio) {
    p_ioctlsocket io = WS(ioctlsocket); SOCKET c, a; u_long n = 99, on = 1;
    REQUIRE(io);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("pair"); return; }
    WEQ(io(a, FIONREAD, &n), 0);
    WEQ(n, 0);
    CHECK(W2(send)(c, "12345", 5, 0) == 5);
    Sleep(100);
    WEQ(io(a, FIONREAD, &n), 0);
    WEQ(n, 5);
    WEQ(io(a, FIONBIO, &on), 0);
    {
        char b[8];
        WEQ(W2(recv)(a, b, sizeof b, 0), 5);
        wf_seterr(0);
        WEQ(W2(recv)(a, b, sizeof b, 0), SOCKET_ERROR);
        WEQ(wf_err(), WSAEWOULDBLOCK);
    }
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(fwd_ioctlsocket_invalid_socket_is_notsock) {
    p_ioctlsocket io = WS(ioctlsocket); u_long n = 0;
    REQUIRE(io);
    WF_UP();
    wf_seterr(0);
    WEQ(io(INVALID_SOCKET, FIONREAD, &n), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}

/* ---------------------------------------------------------------- documented errors through wsock32 */
TEST(fwd_socket_unsupported_family) {
    p_socket sk = WS(socket);
    REQUIRE(sk);
    WF_UP();
    wf_seterr(0);
    CHECK(sk(0x7ff0, SOCK_STREAM, 0) == INVALID_SOCKET);
    WEQ(wf_err(), WSAEAFNOSUPPORT);
    wf_down();
}
TEST(fwd_socket_unsupported_type) {
    p_socket sk = WS(socket);
    REQUIRE(sk);
    WF_UP();
    wf_seterr(0);
    CHECK(sk(AF_INET, 0x7ff0, 0) == INVALID_SOCKET);
    WEQ(wf_err(), WSAESOCKTNOSUPPORT);
    wf_down();
}
TEST(fwd_bind_address_in_use) {
    p_bind bd = WS(bind); SOCKET a, b; struct sockaddr_in sa = wf_lo(0); int n = sizeof sa;
    REQUIRE(bd);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0); b = W2(socket)(AF_INET, SOCK_STREAM, 0);
    WEQ(bd(a, (struct sockaddr *)&sa, sizeof sa), 0);
    W2(getsockname)(a, (struct sockaddr *)&sa, &n);
    wf_seterr(0);
    WEQ(bd(b, (struct sockaddr *)&sa, sizeof sa), SOCKET_ERROR);
    WEQ(wf_err(), WSAEADDRINUSE);
    W2(closesocket)(a); W2(closesocket)(b);
    wf_down();
}
TEST(fwd_bind_twice_is_inval) {
    p_bind bd = WS(bind); SOCKET a; struct sockaddr_in sa = wf_lo(0);
    REQUIRE(bd);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(bd(a, (struct sockaddr *)&sa, sizeof sa), 0);
    wf_seterr(0);
    WEQ(bd(a, (struct sockaddr *)&sa, sizeof sa), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_bind_short_name_is_fault) {
    p_bind bd = WS(bind); SOCKET a; struct sockaddr_in sa = wf_lo(0);
    REQUIRE(bd);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_seterr(0);
    WEQ(bd(a, (struct sockaddr *)&sa, 4), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_connect_wrong_family_for_socket) {
    p_connect cn = WS(connect); SOCKET a; struct sockaddr_in6 s6;
    REQUIRE(cn);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    memset(&s6, 0, sizeof s6); s6.sin6_family = AF_INET6; s6.sin6_port = wf_sw16(9);
    wf_seterr(0);
    WEQ(cn(a, (struct sockaddr *)&s6, sizeof s6), SOCKET_ERROR);
    WEQ(wf_err(), WSAEAFNOSUPPORT);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_connect_short_name_is_fault) {
    p_connect cn = WS(connect); SOCKET a; struct sockaddr_in sa = wf_lo(wf_sw16(9));
    REQUIRE(cn);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_seterr(0);
    WEQ(cn(a, (struct sockaddr *)&sa, 8), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_listen_on_datagram_socket_is_opnotsupp) {
    p_listen ls = WS(listen); SOCKET a; struct sockaddr_in sa = wf_lo(0);
    REQUIRE(ls);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    W2(bind)(a, (struct sockaddr *)&sa, sizeof sa);
    wf_seterr(0);
    WEQ(ls(a, 1), SOCKET_ERROR);
    WEQ(wf_err(), WSAEOPNOTSUPP);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_listen_unbound_stream_is_inval) {
    p_listen ls = WS(listen); SOCKET a;
    REQUIRE(ls);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_seterr(0);
    WEQ(ls(a, 1), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_accept_on_non_listening_is_inval) {
    p_accept ac = WS(accept); SOCKET a; struct sockaddr_in sa = wf_lo(0);
    REQUIRE(ac);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    W2(bind)(a, (struct sockaddr *)&sa, sizeof sa);
    wf_seterr(0);
    CHECK(ac(a, NULL, NULL) == INVALID_SOCKET);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_accept_on_datagram_socket_is_opnotsupp) {
    p_accept ac = WS(accept); SOCKET a; struct sockaddr_in sa = wf_lo(0);
    REQUIRE(ac);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    W2(bind)(a, (struct sockaddr *)&sa, sizeof sa);
    wf_seterr(0);
    CHECK(ac(a, NULL, NULL) == INVALID_SOCKET);
    WEQ(wf_err(), WSAEOPNOTSUPP);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_accept_nonblocking_no_pending_would_block) {
    p_accept ac = WS(accept); SOCKET l; struct sockaddr_in sa = wf_lo(0);
    REQUIRE(ac);
    WF_UP();
    l = W2(socket)(AF_INET, SOCK_STREAM, 0);
    W2(bind)(l, (struct sockaddr *)&sa, sizeof sa);
    W2(listen)(l, 1);
    wf_nonblock(l, 1);
    wf_seterr(0);
    CHECK(ac(l, NULL, NULL) == INVALID_SOCKET);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(l);
    wf_down();
}
TEST(fwd_send_on_unconnected_stream_is_notconn) {
    p_send sd = WS(send); SOCKET a;
    REQUIRE(sd);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_seterr(0);
    WEQ(sd(a, "x", 1, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_send_on_unconnected_datagram_is_notconn) {
    p_send sd = WS(send); SOCKET a;
    REQUIRE(sd);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0);
    WEQ(sd(a, "x", 1, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);   /* an unconnected datagram socket reports not-connected, not destination-required */
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_send_after_shutdown_is_shutdown) {
    p_send sd = WS(send); SOCKET c, a;
    REQUIRE(sd);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("pair"); return; }
    W2(shutdown)(c, SD_SEND);
    wf_seterr(0);
    WEQ(sd(c, "x", 1, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAESHUTDOWN);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(fwd_sendto_short_address_is_fault) {
    p_sendto st = WS(sendto); SOCKET a; struct sockaddr_in sa = wf_lo(wf_sw16(9));
    REQUIRE(st);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0);
    WEQ(st(a, "x", 1, 0, (struct sockaddr *)&sa, 4), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_getpeername_unconnected_is_notconn) {
    p_getpeername gp = WS(getpeername); SOCKET a; struct sockaddr_in sa; int n = sizeof sa;
    REQUIRE(gp);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_seterr(0);
    WEQ(gp(a, (struct sockaddr *)&sa, &n), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_getsockname_small_buffer_is_fault) {
    p_getsockname gn = WS(getsockname); SOCKET a; struct sockaddr_in sa = wf_lo(0); char tiny[4]; int n = sizeof tiny;
    REQUIRE(gn);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    W2(bind)(a, (struct sockaddr *)&sa, sizeof sa);
    wf_seterr(0);
    WEQ(gn(a, (struct sockaddr *)tiny, &n), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_getsockname_bound_loopback) {
    p_getsockname gn = WS(getsockname); SOCKET a; struct sockaddr_in sa = wf_lo(0), got; int n = sizeof got;
    REQUIRE(gn);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    W2(bind)(a, (struct sockaddr *)&sa, sizeof sa);
    memset(&got, 0, sizeof got);
    WEQ(gn(a, (struct sockaddr *)&got, &n), 0);
    WEQ(n, sizeof got);
    WEQ(got.sin_family, AF_INET);
    WEQ(got.sin_addr.s_addr, sa.sin_addr.s_addr);
    CHECK(got.sin_port != 0);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_shutdown_invalid_how_is_inval) {
    p_shutdown sh = WS(shutdown); SOCKET c, a;
    REQUIRE(sh);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL)) { wf_down(); t_skip("pair"); return; }
    wf_seterr(0);
    WEQ(sh(c, 7), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    wf_seterr(0);
    WEQ(sh(c, -1), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(c); W2(closesocket)(a);
    wf_down();
}
TEST(fwd_shutdown_unconnected_stream_is_notconn) {
    p_shutdown sh = WS(shutdown); SOCKET a;
    REQUIRE(sh);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_STREAM, 0);
    wf_seterr(0);
    WEQ(sh(a, SD_BOTH), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTCONN);
    W2(closesocket)(a);
    wf_down();
}
TEST(fwd_closesocket_twice_is_notsock) {
    p_closesocket cs = WS(closesocket); SOCKET a;
    REQUIRE(cs);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    WEQ(cs(a), 0);
    wf_seterr(0);
    WEQ(cs(a), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(fwd_closesocket_invalid_socket_is_notsock) {
    p_closesocket cs = WS(closesocket);
    REQUIRE(cs);
    WF_UP();
    wf_seterr(0);
    WEQ(cs(INVALID_SOCKET), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}

/* ---------------------------------------------------------------- not initialised, per call */
CHILD(wf_nostartup_call) {
    HMODULE m = LoadLibraryA("wsock32.dll");
    int which = argc > 1 ? atoi(argv[1]) : -1, r = 12345;
    struct sockaddr_in sa; int n = sizeof sa; char b[8]; u_long ul = 0; fd_set fs; struct timeval tv = { 0, 0 };
    p_WSAGetLastError e;
    if (!m) return 1;
    e = (p_WSAGetLastError)GetProcAddress(m, "WSAGetLastError");
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET;
    FD_ZERO(&fs); FD_SET((SOCKET)1000, &fs);
#define P(nm) ((p_##nm)GetProcAddress(m, #nm))
    switch (which) {
    case 0:  r = P(socket)(AF_INET, SOCK_STREAM, 0) == INVALID_SOCKET ? -1 : 0; break;
    case 1:  r = P(bind)(INVALID_SOCKET, (struct sockaddr *)&sa, sizeof sa); break;
    case 2:  r = P(listen)(INVALID_SOCKET, 1); break;
    case 3:  r = P(connect)(INVALID_SOCKET, (struct sockaddr *)&sa, sizeof sa); break;
    case 4:  r = P(accept)(INVALID_SOCKET, NULL, NULL) == INVALID_SOCKET ? -1 : 0; break;
    case 5:  r = P(send)(INVALID_SOCKET, "x", 1, 0); break;
    case 6:  r = P(sendto)(INVALID_SOCKET, "x", 1, 0, (struct sockaddr *)&sa, sizeof sa); break;
    case 7:  r = P(getsockname)(INVALID_SOCKET, (struct sockaddr *)&sa, &n); break;
    case 8:  r = P(getpeername)(INVALID_SOCKET, (struct sockaddr *)&sa, &n); break;
    case 9:  r = P(shutdown)(INVALID_SOCKET, SD_BOTH); break;
    case 10: r = P(closesocket)(INVALID_SOCKET); break;
    case 11: r = P(ioctlsocket)(INVALID_SOCKET, FIONREAD, &ul); break;
    case 12: r = P(select)(0, &fs, NULL, NULL, &tv); break;
    case 13: r = P(gethostname)(b, sizeof b); break;
    case 14: r = P(gethostbyname)("localhost") ? 0 : -1; break;
    case 15: r = P(getservbyname)("http", "tcp") ? 0 : -1; break;
    case 16: r = P(WSAAsyncSelect)(INVALID_SOCKET, NULL, 0, 0); break;
    case 17: r = P(WSACancelAsyncRequest)((HANDLE)(ULONG_PTR)0x1234); break;
    }
#undef P
    if (r != -1) return 2;
    return e() == WSANOTINITIALISED ? 0 : 3;
}
#define NOSTART(nm, idx) TEST(fwd_notinitialised_##nm) { WF_RUN_CHILD("wf_nostartup_call", #idx); }
NOSTART(socket, 0)
NOSTART(bind, 1)
NOSTART(listen, 2)
NOSTART(connect, 3)
NOSTART(accept, 4)
NOSTART(send, 5)
NOSTART(sendto, 6)
NOSTART(getsockname, 7)
NOSTART(getpeername, 8)
NOSTART(shutdown, 9)
NOSTART(closesocket, 10)
NOSTART(ioctlsocket, 11)
NOSTART(select, 12)
NOSTART(gethostname, 13)
NOSTART(gethostbyname, 14)
NOSTART(getservbyname, 15)
NOSTART(WSAAsyncSelect, 16)
NOSTART(WSACancelAsyncRequest, 17)

/* ---------------------------------------------------------------- async-style compat calls */
TEST(fwd_asyncselect_invalid_socket_is_notsock) {
    p_WSAAsyncSelect f = WS(WSAAsyncSelect);
    REQUIRE(f);
    WF_UP();
    wf_seterr(0);
    WEQ(f(INVALID_SOCKET, GetDesktopWindow(), WM_USER + 1, FD_READ), SOCKET_ERROR);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(fwd_asyncselect_null_window_is_inval) {
    p_WSAAsyncSelect f = WS(WSAAsyncSelect); SOCKET s;
    REQUIRE(f);
    WF_UP();
    s = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    wf_seterr(0);
    WEQ(f(s, NULL, WM_USER + 1, FD_READ), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    W2(closesocket)(s);
    wf_down();
}
TEST(fwd_cancelasyncrequest_bogus_handle_is_inval) {
    p_WSACancelAsyncRequest f = WS(WSACancelAsyncRequest);
    REQUIRE(f);
    WF_UP();
    wf_seterr(0);
    WEQ(f((HANDLE)(ULONG_PTR)0x7e57), SOCKET_ERROR);
    WEQ(wf_err(), WSAEINVAL);
    wf_down();
}

/* ---------------------------------------------------------------- mswsock extension exports */
CHILD(wf_getacceptexsockaddrs_cold) {
    /* before any AcceptEx call in the process the outputs are cleared and nothing is parsed */
    HMODULE m = LoadLibraryA("wsock32.dll");
    p_GetAcceptExSockaddrs f;
    struct sockaddr *l = (struct sockaddr *)0x1, *r = (struct sockaddr *)0x2; int ll = 77, rl = 88; char buf[128];
    if (!m) return 1;
    f = (p_GetAcceptExSockaddrs)GetProcAddress(m, "GetAcceptExSockaddrs");
    if (!f) return 2;
    memset(buf, 0, sizeof buf);
    f(buf, 0, 32, 32, &l, &ll, &r, &rl);
    if (l != NULL || r != NULL) return 3;
    if (ll != 0 || rl != 0) return 4;
    return 0;
}
TEST(fwd_getacceptexsockaddrs_cold_start_clears_outputs) { WF_RUN_CHILD("wf_getacceptexsockaddrs_cold", ""); }

TEST(fwd_transmitfile_invalid_socket_is_notsock) {
    p_TransmitFile f = WS(TransmitFile);
    REQUIRE(f);
    WF_UP();
    wf_seterr(0);
    WEQ(f(INVALID_SOCKET, INVALID_HANDLE_VALUE, 0, 0, NULL, NULL, 0), FALSE);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}
TEST(fwd_acceptex_invalid_listen_socket_is_notsock) {
    p_AcceptEx f = WS(AcceptEx); char buf[64]; DWORD got = 0; OVERLAPPED ov;
    REQUIRE(f);
    WF_UP();
    memset(&ov, 0, sizeof ov);
    wf_seterr(0);
    WEQ(f(INVALID_SOCKET, INVALID_SOCKET, buf, 0, 32, 32, &got, &ov), FALSE);
    WEQ(wf_err(), WSAENOTSOCK);
    wf_down();
}

static int build_temp_file(char *path, int path_cap, int size) {
    HANDLE h; DWORD w; char *data; int i;
    t_tmpfile(path, (size_t)path_cap, "wf_tx.bin");
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    data = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size);
    for (i = 0; i < size; i++) data[i] = (char)('A' + (i % 26));
    WriteFile(h, data, (DWORD)size, &w, NULL);
    HeapFree(GetProcessHeap(), 0, data);
    CloseHandle(h);
    return (int)w == size;
}
TEST(fwd_transmitfile_sends_file_contents) {
    p_TransmitFile f = WS(TransmitFile); SOCKET c, a; char path[MAX_PATH]; HANDLE h; int got = 0, i, bad = 0; char buf[6000];
    REQUIRE(f);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL) || !build_temp_file(path, sizeof path, 5000)) { wf_down(); t_skip("setup"); return; }
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    WEQ(f(c, h, 0, 0, NULL, NULL, 0), TRUE);
    CloseHandle(h);
    while (got < 5000) { int n = W2(recv)(a, buf + got, (int)sizeof buf - got, 0); if (n <= 0) break; got += n; }
    WEQ(got, 5000);
    for (i = 0; i < got; i++) if (buf[i] != (char)('A' + (i % 26))) bad++;
    WEQ(bad, 0);
    W2(closesocket)(c); W2(closesocket)(a);
    DeleteFileA(path);
    wf_down();
}
TEST(fwd_transmitfile_head_and_tail_buffers_frame_the_file) {
    p_TransmitFile f = WS(TransmitFile); SOCKET c, a; char path[MAX_PATH]; HANDLE h; int got = 0; char buf[128];
    TRANSMIT_FILE_BUFFERS tb;
    REQUIRE(f);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL) || !build_temp_file(path, sizeof path, 10)) { wf_down(); t_skip("setup"); return; }
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    memset(&tb, 0, sizeof tb);
    tb.Head = (PVOID)"HEAD"; tb.HeadLength = 4; tb.Tail = (PVOID)"TAIL"; tb.TailLength = 4;
    WEQ(f(c, h, 0, 0, NULL, &tb, 0), TRUE);
    CloseHandle(h);
    while (got < 18) { int n = W2(recv)(a, buf + got, (int)sizeof buf - got, 0); if (n <= 0) break; got += n; }
    WEQ(got, 18);
    CHECK(!memcmp(buf, "HEAD", 4));
    CHECK(!memcmp(buf + 4, "ABCDEFGHIJ", 10));
    CHECK(!memcmp(buf + 14, "TAIL", 4));
    W2(closesocket)(c); W2(closesocket)(a);
    DeleteFileA(path);
    wf_down();
}
TEST(fwd_transmitfile_partial_length) {
    p_TransmitFile f = WS(TransmitFile); SOCKET c, a; char path[MAX_PATH]; HANDLE h; int got = 0; char buf[64];
    REQUIRE(f);
    WF_UP();
    if (!wf_tcp_pair(&c, &a, NULL) || !build_temp_file(path, sizeof path, 100)) { wf_down(); t_skip("setup"); return; }
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    WEQ(f(c, h, 30, 0, NULL, NULL, 0), TRUE);
    CloseHandle(h);
    while (got < 30) { int n = W2(recv)(a, buf + got, (int)sizeof buf - got, 0); if (n <= 0) break; got += n; }
    WEQ(got, 30);
    CHECK(!memcmp(buf, "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD", 30));
    wf_nonblock(a, 1);
    wf_seterr(0);
    WEQ(W2(recv)(a, buf, sizeof buf, 0), SOCKET_ERROR);
    WEQ(wf_err(), WSAEWOULDBLOCK);
    W2(closesocket)(c); W2(closesocket)(a);
    DeleteFileA(path);
    wf_down();
}
TEST(fwd_acceptex_accepts_and_parses_addresses) {
    p_AcceptEx ax = WS(AcceptEx); p_GetAcceptExSockaddrs ga = WS(GetAcceptExSockaddrs);
    SOCKET l, as, c; struct sockaddr_in sa = wf_lo(0), ca; int n = sizeof sa, cn = sizeof ca; char buf[2 * (sizeof(struct sockaddr_in) + 16) + 16];
    OVERLAPPED ov; DWORD got = 0, flags = 0; BOOL ok; struct sockaddr *la = NULL, *ra = NULL; int lal = 0, ral = 0;
    REQUIRE(ax); REQUIRE(ga);
    WF_UP();
    l = W2(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(W2(bind)(l, (struct sockaddr *)&sa, sizeof sa) == 0 && W2(listen)(l, 2) == 0);
    W2(getsockname)(l, (struct sockaddr *)&sa, &n);
    as = W2(socket)(AF_INET, SOCK_STREAM, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(buf, 0, sizeof buf);
    ok = ax(l, as, buf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &got, &ov);
    CHECK(ok || wf_err() == ERROR_IO_PENDING);
    c = W2(socket)(AF_INET, SOCK_STREAM, 0);
    CHECK(W2(connect)(c, (struct sockaddr *)&sa, sizeof sa) == 0);
    CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);
    W2(getsockname)(c, (struct sockaddr *)&ca, &cn);
    ga(buf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &la, &lal, &ra, &ral);
    CHECK(la != NULL && ra != NULL);
    if (la && ra) {
        WEQ(lal, sizeof(struct sockaddr_in));
        WEQ(ral, sizeof(struct sockaddr_in));
        WEQ(((struct sockaddr_in *)la)->sin_port, sa.sin_port);
        WEQ(((struct sockaddr_in *)ra)->sin_port, ca.sin_port);
        WEQ(((struct sockaddr_in *)ra)->sin_addr.s_addr, ca.sin_addr.s_addr);
        WEQ((char *)la, buf);                    /* with no receive data the local block starts the buffer */
    }
    (void)flags;
    CloseHandle(ov.hEvent);
    W2(closesocket)(c); W2(closesocket)(as); W2(closesocket)(l);
    wf_down();
}

/* ---------------------------------------------------------------- legacy name services through forwarders */
TEST(fwd_gethostname_matches_ws2_32) {
    p_gethostname a = WS(gethostname), b = W2(gethostname); char x[256], y[256];
    REQUIRE(a); REQUIRE(b);
    WF_UP();
    WEQ(a(x, sizeof x), 0);
    WEQ(b(y, sizeof y), 0);
    EXPECT_STR(x, y);
    wf_down();
}
TEST(fwd_gethostname_small_buffer_is_fault) {
    p_gethostname a = WS(gethostname); char x[1];
    REQUIRE(a);
    WF_UP();
    wf_seterr(0);
    WEQ(a(x, sizeof x), SOCKET_ERROR);
    WEQ(wf_err(), WSAEFAULT);
    wf_down();
}
TEST(fwd_getservbyname_http_tcp_80) {
    p_getservbyname f = WS(getservbyname); struct servent *se;
    REQUIRE(f);
    WF_UP();
    se = f("http", "tcp");
    if (!se) { wf_down(); t_skip("no http entry"); return; }
    WEQ(wf_sw16((unsigned short)se->s_port), 80);
    EXPECT_STR(se->s_proto, "tcp");
    wf_down();
}
TEST(fwd_getservbyport_80_is_http) {
    p_getservbyport f = WS(getservbyport); struct servent *se;
    REQUIRE(f);
    WF_UP();
    se = f(wf_sw16(80), "tcp");
    if (!se) { wf_down(); t_skip("no port-80 entry"); return; }
    EXPECT_STR(se->s_name, "http");
    wf_down();
}
TEST(fwd_getservbyname_unknown_is_null) {
    p_getservbyname f = WS(getservbyname);
    REQUIRE(f);
    WF_UP();
    wf_seterr(0);
    CHECK(f("no_such_service_zz", "tcp") == NULL);
    WEQ(wf_err(), WSANO_DATA);
    wf_down();
}
