/* Dual-stack behaviour driven by IPV6_V6ONLY and the receive-side packet-info options observed over loopback:
 * a wildcard IPv6 listener with V6ONLY cleared also takes IPv4 peers (reported as mapped addresses), with V6ONLY
 * set it does not, and the packet-info control data names the loopback destination. */
#include "spl.h"

static int is_mapped_loop(const struct sockaddr_in6 *a)
{
    static const unsigned char want[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1};
    return memcmp(&a->sin6_addr, want, 16) == 0;
}
/* wildcard IPv6 listener with the given V6ONLY value; returns INVALID_SOCKET on setup failure */
static SOCKET any6_listener(int v6only, u_short *port)
{
    SOCKET s = spl_tcp6(); struct sockaddr_in6 a; int l = sizeof a, e;
    if (s == INVALID_SOCKET) return s;
    if (spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, v6only, &e)) { spl_close(s); return INVALID_SOCKET; }
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6;
    if (spl_bind(s, (struct sockaddr *)&a, sizeof a) || spl_getsockname(s, (struct sockaddr *)&a, &l) || spl_listen(s, 2)) {
        spl_close(s); return INVALID_SOCKET;
    }
    *port = a.sin6_port;
    return s;
}
TEST(dualstack_listener_accepts_ipv4_peer_as_mapped_address)
{
    SOCKET l, c, a; u_short p = 0; struct sockaddr_in d; struct sockaddr_in6 peer; int pl = sizeof peer;
    if (!spl_up() || !spl_have6()) return;
    l = any6_listener(0, &p);
    if (l == INVALID_SOCKET) { t_skip("dual-stack listener unavailable"); return; }
    SEQ(spl_rb(l, SPL_LVL_IPV6, SPL_IPV6_V6ONLY) & 0xff, 0);
    c = spl_tcp4(); spl_loop4(&d); d.sin_port = p;
    SEQ(spl_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    a = spl_accept(l, (struct sockaddr *)&peer, &pl);
    CHECKF(a != INVALID_SOCKET, "accept failed %d", spl_WSAGetLastError());
    if (a != INVALID_SOCKET) {
        SEQ(pl, sizeof peer);
        SEQ(peer.sin6_family, AF_INET6);
        CHECKF(is_mapped_loop(&peer), "peer not the mapped IPv4 loopback address");
    }
    spl_close(a); spl_close(c); spl_close(l);
}
TEST(v6only_listener_refuses_ipv4_peer)
{
    SOCKET l, c; u_short p = 0; struct sockaddr_in d; int r;
    if (!spl_up() || !spl_have6()) return;
    l = any6_listener(1, &p);
    if (l == INVALID_SOCKET) { t_skip("v6only listener unavailable"); return; }
    SEQ(spl_rb(l, SPL_LVL_IPV6, SPL_IPV6_V6ONLY) & 0xff, 1);
    c = spl_tcp4(); spl_loop4(&d); d.sin_port = p;
    r = spl_connect(c, (struct sockaddr *)&d, sizeof d);
    SEQ(r, SOCKET_ERROR);
    SEQ(spl_WSAGetLastError(), WSAECONNREFUSED);
    spl_close(c); spl_close(l);
}
TEST(v6only_listener_still_accepts_ipv6_peer)
{
    SOCKET l, c, a; u_short p = 0; struct sockaddr_in6 d;
    if (!spl_up() || !spl_have6()) return;
    l = any6_listener(1, &p);
    if (l == INVALID_SOCKET) { t_skip("v6only listener unavailable"); return; }
    c = spl_tcp6(); spl_loop6(&d); d.sin6_port = p;
    SEQ(spl_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    a = spl_accept(l, NULL, NULL);
    CHECKF(a != INVALID_SOCKET, "accept failed %d", spl_WSAGetLastError());
    spl_close(a); spl_close(c); spl_close(l);
}
TEST(v6only_cannot_change_after_bind)
{
    /* Once the socket is bound the flag is frozen: the set is refused as invalid and the value is unchanged. */
    SOCKET s; int e, r;
    if (!spl_up() || !spl_have6()) return;
    s = spl_tcp6();
    SEQ(spl_bind6(s, NULL), 0);
    r = spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_V6ONLY, 0, &e);
    SEQ(r, SOCKET_ERROR); SEQ(e, WSAEINVAL);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_V6ONLY) & 0xff, 1);
    spl_close(s);
}
TEST(wire_ipv4_pktinfo_names_loopback_destination)
{
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in d; LPFN_WSARECVMSG f; int e;
    char buf[16], ctl[128]; WSABUF b; WSAMSG m; DWORD n = 0; WSACMSGHDR *c; int seen = 0;
    if (!spl_up()) return;
    rx = spl_udp4(); tx = spl_udp4();
    spl_bind4(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    SEQ(spl_seti(rx, SPL_LVL_IP, SPL_IP_PKTINFO, 1, &e), 0);
    spl_loop4(&d); d.sin_port = p;
    SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
    b.buf = buf; b.len = sizeof buf;
    memset(&m, 0, sizeof m); m.lpBuffers = &b; m.dwBufferCount = 1; m.Control.buf = ctl; m.Control.len = sizeof ctl;
    SEQ(f(rx, &m, &n, NULL, NULL), 0);
    for (c = WSA_CMSG_FIRSTHDR(&m); c; c = WSA_CMSG_NXTHDR(&m, c))
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == SPL_IP_PKTINFO) {
            IN_PKTINFO *pi = (IN_PKTINFO *)WSA_CMSG_DATA(c);
            seen = 1;
            SEQ(c->cmsg_len, WSA_CMSG_LEN(sizeof(IN_PKTINFO)));
            SEQ(pi->ipi_addr.s_addr, 0x0100007fu);
        }
    SEQ(seen, 1);
    spl_close(rx); spl_close(tx);
}
TEST(wire_ipv6_pktinfo_names_loopback_destination)
{
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in6 d; LPFN_WSARECVMSG f; int e;
    char buf[16], ctl[128]; WSABUF b; WSAMSG m; DWORD n = 0; WSACMSGHDR *c; int seen = 0;
    if (!spl_up() || !spl_have6()) return;
    rx = spl_udp6(); tx = spl_udp6();
    spl_bind6(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    SEQ(spl_seti(rx, SPL_LVL_IPV6, SPL_IPV6_PKTINFO, 1, &e), 0);
    spl_loop6(&d); d.sin6_port = p;
    SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
    b.buf = buf; b.len = sizeof buf;
    memset(&m, 0, sizeof m); m.lpBuffers = &b; m.dwBufferCount = 1; m.Control.buf = ctl; m.Control.len = sizeof ctl;
    SEQ(f(rx, &m, &n, NULL, NULL), 0);
    for (c = WSA_CMSG_FIRSTHDR(&m); c; c = WSA_CMSG_NXTHDR(&m, c))
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == SPL_IPV6_PKTINFO) {
            IN6_PKTINFO *pi = (IN6_PKTINFO *)WSA_CMSG_DATA(c);
            seen = 1;
            SEQ(c->cmsg_len, WSA_CMSG_LEN(sizeof(IN6_PKTINFO)));
            { static const unsigned char lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}; CHECKF(memcmp(&pi->ipi6_addr, lo, 16) == 0, "destination is not ::1"); }
        }
    SEQ(seen, 1);
    spl_close(rx); spl_close(tx);
}
TEST(wire_pktinfo_absent_when_not_requested)
{
    SOCKET rx, tx; u_short p = 0; struct sockaddr_in d; LPFN_WSARECVMSG f;
    char buf[16], ctl[128]; WSABUF b; WSAMSG m; DWORD n = 0;
    if (!spl_up()) return;
    rx = spl_udp4(); tx = spl_udp4();
    spl_bind4(rx, &p);
    f = spl_get_recvmsg(rx);
    if (!f) { t_skip("no WSARecvMsg"); spl_close(rx); spl_close(tx); return; }
    spl_rcvtimeo(rx, 2000);
    spl_loop4(&d); d.sin_port = p;
    SEQ(spl_sendto(tx, "x", 1, 0, (struct sockaddr *)&d, sizeof d), 1);
    b.buf = buf; b.len = sizeof buf;
    memset(&m, 0, sizeof m); m.lpBuffers = &b; m.dwBufferCount = 1; m.Control.buf = ctl; m.Control.len = sizeof ctl;
    SEQ(f(rx, &m, &n, NULL, NULL), 0);
    SEQ(m.Control.len, 0);
    spl_close(rx); spl_close(tx);
}
