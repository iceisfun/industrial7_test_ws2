/* Datagram and misc connection-state behaviour on loopback: connected-UDP semantics (send/recv/peer name,
 * re-connect, dissolving the association with AF_UNSPEC), address arguments ignored by TCP sendto and
 * recvfrom, WSAPoll not re-arming an event selected socket, and the SO_BROADCAST gate on sendto
 * (only the refusal paths are exercised, nothing is ever transmitted off the host). */
#include "lift11.h"

static SOCKET l11_udp(void)
{
    return U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

/* Bound UDP receiver on loopback plus a fresh client; both nonblocking. */
static int l11_udp_pair(SOCKET *cli, SOCKET *srv, struct sockaddr_in *srv_addr)
{
    int len = sizeof(*srv_addr);
    struct sockaddr_in b;
    *cli = l11_udp();
    *srv = l11_udp();
    if (*cli == INVALID_SOCKET || *srv == INVALID_SOCKET) { t_skip("udp sockets unavailable"); return 0; }
    l11_loopback(&b);
    if (U(bind)(*srv, (struct sockaddr *)&b, sizeof(b)) || U(getsockname)(*srv, (struct sockaddr *)srv_addr, &len)) {
        t_skip("udp bind failed"); return 0;
    }
    l11_blocking(*cli, FALSE);
    l11_blocking(*srv, FALSE);
    return 1;
}

TEST(udp_send_on_unconnected_socket_is_notconn)
{
    SOCKET c;
    UP();
    c = l11_udp();
    REQUIRE(c != INVALID_SOCKET);
    l11_blocking(c, FALSE);
    l11_seterr(0xdeadbeef);
    L_EQ(U(send)(c, "data", 4, 0), -1);
    L_EQ(l11_err(), WSAENOTCONN);
    U(closesocket)(c);
}

TEST(udp_recv_on_unbound_socket_is_einval)
{
    SOCKET c;
    char b[5];
    UP();
    c = l11_udp();
    REQUIRE(c != INVALID_SOCKET);
    l11_blocking(c, FALSE);
    l11_seterr(0xdeadbeef);
    L_EQ(U(recv)(c, b, sizeof(b), 0), -1);
    L_EQ(l11_err(), WSAEINVAL);
    U(closesocket)(c);
}

TEST(udp_recv_on_bound_empty_socket_wouldblock)
{
    SOCKET c, s;
    struct sockaddr_in a;
    char b[5];
    UP();
    if (!l11_udp_pair(&c, &s, &a)) return;
    l11_seterr(0xdeadbeef);
    L_EQ(U(recv)(s, b, sizeof(b), 0), -1);
    L_EQ(l11_err(), WSAEWOULDBLOCK);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(udp_connect_sets_peer_and_name)
{
    SOCKET c, s;
    struct sockaddr_in a, peer, me;
    int len;
    UP();
    if (!l11_udp_pair(&c, &s, &a)) return;
    L_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
    len = sizeof(peer);
    L_EQ(U(getpeername)(c, (struct sockaddr *)&peer, &len), 0);
    CHECK(!memcmp(&peer, &a, sizeof(a)));
    len = sizeof(me);
    L_EQ(U(getsockname)(c, (struct sockaddr *)&me, &len), 0);
    /* The receiver never connected, so it has no peer. */
    len = sizeof(peer);
    l11_seterr(0xdeadbeef);
    L_EQ(U(getpeername)(s, (struct sockaddr *)&peer, &len), -1);
    L_EQ(l11_err(), WSAENOTCONN);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(udp_connected_send_delivers_and_unconnected_peer_cannot_reply)
{
    SOCKET c, s;
    struct sockaddr_in a;
    char b[5];
    int r;
    UP();
    if (!l11_udp_pair(&c, &s, &a)) return;
    L_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
    L_EQ(U(send)(c, "data", 4, 0), 4);
    l11_rcvtimeo(s, 3000);
    l11_blocking(s, TRUE);
    memset(b, 0xcc, sizeof(b));
    r = U(recv)(s, b, sizeof(b), 0);
    L_EQ(r, 4);
    CHECK(!memcmp(b, "data", 4));
    l11_blocking(s, FALSE);
    l11_seterr(0xdeadbeef);
    L_EQ(U(recv)(s, b, sizeof(b), 0), -1);
    L_EQ(l11_err(), WSAEWOULDBLOCK);
    l11_seterr(0xdeadbeef);
    L_EQ(U(send)(s, "data", 4, 0), -1);
    L_EQ(l11_err(), WSAENOTCONN);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(udp_reconnect_and_unspec_disconnect)
{
    SOCKET c, s;
    struct sockaddr_in a, other, peer;
    int len = sizeof(peer);
    UP();
    if (!l11_udp_pair(&c, &s, &a)) return;
    L_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
    L_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
    other = a;
    other.sin_port ^= 0x0100;           /* a different port, still nobody there */
    L_EQ(U(connect)(c, (struct sockaddr *)&other, sizeof(other)), 0);
    memset(&other, 0, sizeof(other));
    other.sin_family = AF_UNSPEC;
    L_EQ(U(connect)(c, (struct sockaddr *)&other, sizeof(other)), 0);
    l11_seterr(0xdeadbeef);
    L_EQ(U(getpeername)(c, (struct sockaddr *)&peer, &len), -1);
    L_EQ(l11_err(), WSAENOTCONN);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(tcp_sendto_recvfrom_ignore_address_arguments)
{
    /* On a connected stream socket the address and length arguments of sendto / recvfrom are not
     * validated, not consumed and not written. */
    static const char msg[] = "ws2_32/TCP socket test";
    SOCKET c, s;
    SOCKADDR_IN bad, copy;
    char got[sizeof(msg)] = {0};
    int fromlen = 0x40ffee11;
    UP();
    PAIR(&c, &s);
    memset(&bad, 0xfe, sizeof(bad));
    copy = bad;
    L_EQ(U(sendto)(s, msg, sizeof(msg), 0, (SOCKADDR *)&bad, sizeof(bad)), (int)sizeof(msg));
    CHECK(!memcmp(&bad, &copy, sizeof(bad)));
    l11_rcvtimeo(c, 3000);
    L_EQ(U(recvfrom)(c, got, sizeof(got), 0, (SOCKADDR *)&bad, &fromlen), (int)sizeof(msg));
    CHECK(!memcmp(&bad, &copy, sizeof(bad)));
    L_EQ(fromlen, 0x40ffee11);
    CHECK(!memcmp(got, msg, sizeof(msg)));
    U(closesocket)(c); U(closesocket)(s);
}

TEST(eventselect_poll_does_not_rearm_event)
{
    SOCKET c, s;
    HANDLE ev;
    int cnt = 0;
    short r;
    UP();
    PAIR(&c, &s);
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    L_EQ(U(WSAEventSelect)(c, (WSAEVENT)ev, FD_READ), 0);
    L_EQ(U(send)(s, "data", 4, 0), 4);
    L_EQ(WaitForSingleObject(ev, 3000), WAIT_OBJECT_0);
    r = l11_poll(c, POLLRDNORM | POLLRDBAND | POLLWRNORM, &cnt);
    CHECK(cnt);
    L_EQ(r, POLLRDNORM | POLLWRNORM);
    L_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    CloseHandle(ev);
    U(closesocket)(s); U(closesocket)(c);
}

/* ---- broadcast gate (refusal paths only) -------------------------------- */

static void l11_bcast_addr(struct sockaddr_in *b)
{
    memset(b, 0, sizeof(*b));
    b->sin_family = AF_INET;
    b->sin_port = l11_h16(12345);
    b->sin_addr.s_addr = 0xffffffffu;
}

TEST(udp_sendto_broadcast_without_so_broadcast_is_eacces)
{
    SOCKET s;
    struct sockaddr_in b;
    UP();
    s = l11_udp();
    REQUIRE(s != INVALID_SOCKET);
    l11_bcast_addr(&b);
    l11_seterr(0xdeadbeef);
    L_EQ(U(sendto)(s, "test", 4, 0, (struct sockaddr *)&b, sizeof(b)), -1);
    L_EQ(l11_err(), WSAEACCES);
    U(closesocket)(s);
}

TEST(udp_so_broadcast_cleared_again_refuses_broadcast_send)
{
    SOCKET s;
    struct sockaddr_in b;
    int val = 1, len = sizeof(val);
    UP();
    s = l11_udp();
    REQUIRE(s != INVALID_SOCKET);
    l11_bcast_addr(&b);
    L_EQ(U(setsockopt)(s, SOL_SOCKET, SO_BROADCAST, (char *)&val, sizeof(val)), 0);
    val = 0xdead;
    L_EQ(U(getsockopt)(s, SOL_SOCKET, SO_BROADCAST, (char *)&val, &len), 0);
    CHECK(val != 0);
    val = 0;
    L_EQ(U(setsockopt)(s, SOL_SOCKET, SO_BROADCAST, (char *)&val, sizeof(val)), 0);
    l11_seterr(0xdeadbeef);
    L_EQ(U(sendto)(s, "test", 4, 0, (struct sockaddr *)&b, sizeof(b)), -1);
    L_EQ(l11_err(), WSAEACCES);
    U(closesocket)(s);
}

TEST(udp_connect_to_broadcast_leaves_so_broadcast_off)
{
    /* Connecting a datagram socket transmits nothing. Whether the route exists depends on the host's
     * interfaces, so only the follow-on state is checked when the connect itself succeeds. */
    SOCKET s;
    struct sockaddr_in b;
    int val = 1, len = sizeof(val);
    UP();
    s = l11_udp();
    REQUIRE(s != INVALID_SOCKET);
    l11_bcast_addr(&b);
    if (U(connect)(s, (struct sockaddr *)&b, sizeof(b)) != 0) {
        t_note("connect to the limited broadcast address failed, error %d", l11_err());
        U(closesocket)(s);
        return;
    }
    L_EQ(U(getsockopt)(s, SOL_SOCKET, SO_BROADCAST, (char *)&val, &len), 0);
    L_EQ(val, 0);
    L_EQ(U(sendto)(s, "test", 4, 0, (struct sockaddr *)&b, sizeof(b)), -1);
    U(closesocket)(s);
}
