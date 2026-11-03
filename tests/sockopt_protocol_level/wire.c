/* Options whose effect is visible on loopback: the hop limit a sender sets is what a receiver that asked for it
 * reads from the control data, UDP_SEND_MSG_SIZE cuts one large send into datagrams of that size, and an
 * oversized message size makes the send fail. */
#include "spl.h"

TEST(wire_ipv6_hop_limit_reaches_receiver)
{
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in6 d; LPFN_WSARECVMSG f; int i, e;
    static const int hops[] = {1, 2, 17, 64, 200, 255};
    if (!spl_up() || !spl_have6()) return;
    rx = spl_udp6(); tx = spl_udp6();
    spl_bind6(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    SEQ(spl_seti(rx, SPL_LVL_IPV6, SPL_IPV6_HOPLIMIT, 1, &e), 0);
    spl_loop6(&d); d.sin6_port = p;
    for (i = 0; i < 6; i++) {
        int v = -1, got = 0, r;
        SEQ(spl_seti(tx, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, hops[i], &e), 0);
        SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
        r = spl_recv_cmsg(rx, f, SPL_LVL_IPV6, SPL_IPV6_HOPLIMIT, &v, &got);
        CHECKF(r == 0 && v == hops[i] && got == 1, "hops %d: r %d v %d got %d", hops[i], r, v, got);
    }
    spl_close(rx); spl_close(tx);
}
TEST(wire_ipv4_ttl_reaches_receiver)
{
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in d; LPFN_WSARECVMSG f; int i, e;
    static const int ttls[] = {1, 2, 17, 64, 200, 255};
    if (!spl_up()) return;
    rx = spl_udp4(); tx = spl_udp4();
    spl_bind4(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    SEQ(spl_seti(rx, SPL_LVL_IP, SPL_IP_RECVTTL, 1, &e), 0);
    spl_loop4(&d); d.sin_port = p;
    for (i = 0; i < 6; i++) {
        int v = -1, got = 0, r;
        SEQ(spl_seti(tx, SPL_LVL_IP, SPL_IP_TTL, ttls[i], &e), 0);
        SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
        r = spl_recv_cmsg(rx, f, SPL_LVL_IP, SPL_IP_TTL, &v, &got);
        CHECKF(r == 0 && v == ttls[i] && got == 1, "ttl %d: r %d v %d got %d", ttls[i], r, v, got);
    }
    spl_close(rx); spl_close(tx);
}
TEST(wire_ipv4_ttl_through_ipv6_level_reaches_receiver)
{
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in d; LPFN_WSARECVMSG f; int e, v = -1, got = 0, r;
    if (!spl_up()) return;
    rx = spl_udp4(); tx = spl_udp4();
    spl_bind4(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    SEQ(spl_seti(rx, SPL_LVL_IP, SPL_IP_RECVTTL, 1, &e), 0);
    SEQ(spl_seti(tx, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 23, &e), 0);
    spl_loop4(&d); d.sin_port = p;
    SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
    r = spl_recv_cmsg(rx, f, SPL_LVL_IP, SPL_IP_TTL, &v, &got);
    CHECKF(r == 0 && v == 23, "r %d v %d", r, v);
    spl_close(rx); spl_close(tx);
}
TEST(wire_ipv4_tos_visible_to_receiver_note)
{
    /* Whether the stack applies a user-set type of service depends on system policy, so only observe it. */
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in d; LPFN_WSARECVMSG f; int e, v = -1, got = 0, r;
    if (!spl_up()) return;
    rx = spl_udp4(); tx = spl_udp4();
    spl_bind4(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    SEQ(spl_seti(rx, SPL_LVL_IP, SPL_IP_RECVTOS, 1, &e), 0);
    SEQ(spl_seti(tx, SPL_LVL_IP, SPL_IP_TOS, 0xb8, &e), 0);
    spl_loop4(&d); d.sin_port = p;
    SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
    r = spl_recv_cmsg(rx, f, SPL_LVL_IP, SPL_IP_TOS, &v, &got);
    CHECKF(r == 0 || r == -2, "receive failed: %d", r);
    t_note("TOS control data: r=%d v=%d", r, v);
    spl_close(rx); spl_close(tx);
}

/* ---- UDP_SEND_MSG_SIZE ---------------------------------------------------------------------------------------------- */
static SOCKET uso_pair(SOCKET *rx)
{
    SOCKET tx = spl_udp4(); u_short p = 0; struct sockaddr_in d;
    *rx = spl_udp4();
    spl_bind4(*rx, &p);
    spl_rcvtimeo(*rx, 1500);
    spl_loop4(&d); d.sin_port = p;
    if (spl_connect(tx, (struct sockaddr *)&d, sizeof d)) { spl_close(tx); spl_close(*rx); return INVALID_SOCKET; }
    return tx;
}
static int drain(SOCKET rx, int *sizes, int max)
{
    char buf[9000]; int n = 0;
    while (n < max) {
        int r = spl_recv(rx, buf, sizeof buf, 0);
        if (r < 0) break;
        sizes[n++] = r;
    }
    return n;
}
TEST(uso_send_msg_size_segments_a_large_send)
{
    SOCKET rx, tx; static char buf[9000]; int sizes[16], n, e;
    if (!spl_up()) return;
    tx = uso_pair(&rx); if (tx == INVALID_SOCKET) { t_skip("setup failed"); return; }
    memset(buf, 'a', sizeof buf);
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 1000, &e), 0);
    SEQ(spl_send(tx, buf, 3500, 0), 3500);
    n = drain(rx, sizes, 16);
    SEQ(n, 4);
    SEQ(sizes[0], 1000); SEQ(sizes[1], 1000); SEQ(sizes[2], 1000); SEQ(sizes[3], 500);
    spl_close(tx); spl_close(rx);
}
TEST(uso_send_msg_size_zero_sends_one_datagram)
{
    SOCKET rx, tx; static char buf[9000]; int sizes[16], n, e;
    if (!spl_up()) return;
    tx = uso_pair(&rx); if (tx == INVALID_SOCKET) { t_skip("setup failed"); return; }
    memset(buf, 'a', sizeof buf);
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 1000, &e), 0);
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 0, &e), 0);
    SEQ(spl_send(tx, buf, 3500, 0), 3500);
    n = drain(rx, sizes, 16);
    SEQ(n, 1); SEQ(sizes[0], 3500);
    spl_close(tx); spl_close(rx);
}
TEST(uso_send_smaller_than_message_size_is_unsplit)
{
    SOCKET rx, tx; static char buf[9000]; int sizes[16], n, e;
    if (!spl_up()) return;
    tx = uso_pair(&rx); if (tx == INVALID_SOCKET) { t_skip("setup failed"); return; }
    memset(buf, 'a', sizeof buf);
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 1000, &e), 0);
    SEQ(spl_send(tx, buf, 600, 0), 600);
    SEQ(spl_send(tx, buf, 1000, 0), 1000);
    n = drain(rx, sizes, 16);
    SEQ(n, 2); SEQ(sizes[0], 600); SEQ(sizes[1], 1000);
    spl_close(tx); spl_close(rx);
}
TEST(uso_message_size_of_one_byte)
{
    SOCKET rx, tx; static char buf[64]; int sizes[16], n, e, i;
    if (!spl_up()) return;
    tx = uso_pair(&rx); if (tx == INVALID_SOCKET) { t_skip("setup failed"); return; }
    memset(buf, 'a', sizeof buf);
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 1, &e), 0);
    SEQ(spl_send(tx, buf, 5, 0), 5);
    n = drain(rx, sizes, 16);
    SEQ(n, 5);
    for (i = 0; i < n; i++) SEQ(sizes[i], 1);
    spl_close(tx); spl_close(rx);
}
TEST(uso_message_size_above_datagram_limit_is_accepted_but_send_fails)
{
    SOCKET rx, tx; static char buf[4000]; int e;
    if (!spl_up()) return;
    tx = uso_pair(&rx); if (tx == INVALID_SOCKET) { t_skip("setup failed"); return; }
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 70000, &e), 0);
    SEQ(spl_rb(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE), 70000);
    SPL_FAILS(spl_send(tx, buf, 3500, 0), WSAEINVAL);
    SEQ(spl_seti(tx, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 0, &e), 0);
    SEQ(spl_send(tx, buf, 3500, 0), 3500);                 /* usable again once cleared */
    spl_close(tx); spl_close(rx);
}
