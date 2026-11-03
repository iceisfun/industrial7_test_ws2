/* x_raw_icmp_elevated / rcvall: SIO_RCVALL, SIO_RCVALL_IGMPMCAST and SIO_RCVALL_MCAST on loopback.
 *
 * A raw IPPROTO_IP socket (elevation required) bound to a local address and switched to receive-all gets a copy
 * of every IPv4 packet the stack processes for that interface, TCP and UDP included, each with its IPv4
 * header. On loopback a UDP datagram shows up exactly once; an ICMP echo shows up as request then reply.
 * Preconditions are enforced with WSAEINVAL: the socket must be bound (not to INADDR_ANY), the value must be
 * one of RCVALL_OFF/ON/SOCKETLEVELONLY/IPLEVEL (0..3), the input must be at least a DWORD, and only raw
 * sockets accept it. A missing bytes-returned pointer is WSAEFAULT. The standard token cannot even create the
 * IPPROTO_IP raw socket, so every row below is conditional on elevation; the refusal is one test. */
#include "rawh.h"

static SOCKET mk(unsigned char last) {
    SOCKET s = rw_raw(AF_INET, IPPROTO_IP); struct sockaddr_in a;
    if (s == INVALID_SOCKET) return s;
    rw_lo4b(&a, last, 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a) != 0) { rw_close(s); return INVALID_SOCKET; }
    return s;
}
static int rcvall(SOCKET s, DWORD code, int val) { DWORD v = val, ret = 0xdead; rw_seterr(0); return U(WSAIoctl)(s, code, &v, 4, NULL, 0, &ret, NULL, NULL); }
#define NEED_SOCK() SOCKET s; RW_NEED_ADM(); s = mk(1); if (s == INVALID_SOCKET) { t_skip("raw IP socket refused"); return; }

TEST(rawrcvall_standard_token_cannot_create_ip_socket) {
    SOCKET s; RW_NEED_STD(); rw_seterr(0); s = rw_raw(AF_INET, IPPROTO_IP);
    RW_EQ(s, INVALID_SOCKET); RW_EQ(rw_err(), WSAEACCES);
}
TEST(rawrcvall_requires_bound_socket) {
    SOCKET s; RW_NEED_ADM(); s = rw_raw(AF_INET, IPPROTO_IP); if (s == INVALID_SOCKET) { t_skip("refused"); return; }
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawrcvall_values) {
    static const struct { int v, err; } t[] = {{RCVALL_OFF, 0}, {RCVALL_ON, 0}, {RCVALL_SOCKETLEVELONLY, 0}, {RCVALL_IPLEVEL, 0}, {RCVALL_OFF, 0},
        {4, WSAEINVAL}, {5, WSAEINVAL}, {-1, WSAEINVAL}};
    size_t i; NEED_SOCK();
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        int r = rcvall(s, SIO_RCVALL, t[i].v), e = rw_err();
        t_check(t[i].err ? (r == -1 && e == t[i].err) : r == 0, __FILE__, __LINE__, "SIO_RCVALL value", "value %d r=%d err=%d", t[i].v, r, e);
    }
    rw_close(s);
}
TEST(rawrcvall_input_length) {
    DWORD v = RCVALL_ON, ret = 0xdead; char big[8] = {1, 0, 0, 0, 0, 0, 0, 0}; NEED_SOCK();
    rw_seterr(0); RW_EQ(U(WSAIoctl)(s, SIO_RCVALL, NULL, 0, NULL, 0, &ret, NULL, NULL), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); RW_EQ(U(WSAIoctl)(s, SIO_RCVALL, &v, 4, NULL, 0, &ret, NULL, NULL), 0); RW_EQ(ret, 0);
    rw_seterr(0); RW_EQ(U(WSAIoctl)(s, SIO_RCVALL, big, 8, NULL, 0, &ret, NULL, NULL), 0);
    t_note("SIO_RCVALL with a 3 byte input: %d", (rw_seterr(0), U(WSAIoctl)(s, SIO_RCVALL, &v, 3, NULL, 0, &ret, NULL, NULL)));
    rw_close(s);
}
TEST(rawrcvall_null_bytes_returned) {
    DWORD v = RCVALL_ON; NEED_SOCK();
    rw_seterr(0); RW_EQ(U(WSAIoctl)(s, SIO_RCVALL, &v, 4, NULL, 0, NULL, NULL, NULL), -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(s);
}
TEST(rawrcvall_any_bound_rejected) {
    SOCKET s; struct sockaddr_in a; RW_NEED_ADM(); s = rw_raw(AF_INET, IPPROTO_IP); if (s == INVALID_SOCKET) { t_skip("refused"); return; }
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; RW_EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), 0);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawrcvall_bound_127_0_0_2_accepted) {
    SOCKET s; RW_NEED_ADM(); s = mk(2); if (s == INVALID_SOCKET) { t_skip("refused"); return; }
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    rw_close(s);
}
TEST(rawrcvall_only_raw_sockets) {
    static const struct { int ty, pr; } k[] = {{SOCK_DGRAM, IPPROTO_UDP}, {SOCK_STREAM, IPPROTO_TCP}}; size_t i;
    RW_NEED_ADM();
    for (i = 0; i < 2; i++) {
        SOCKET s = U(socket)(AF_INET, k[i].ty, k[i].pr); struct sockaddr_in a; rw_lo4(&a, 0);
        U(bind)(s, (struct sockaddr *)&a, sizeof a);
        RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), -1); RW_EQ(rw_err(), WSAEINVAL);
        rw_close(s);
    }
}
TEST(rawrcvall_accepted_on_other_raw_protocols) {
    static const int pr[] = {IPPROTO_ICMP, IPPROTO_UDP}; size_t i; RW_NEED_ADM();
    for (i = 0; i < 2; i++) {
        SOCKET s = rw_raw(AF_INET, pr[i]); struct sockaddr_in a; rw_lo4(&a, 0);
        if (s == INVALID_SOCKET) continue;
        U(bind)(s, (struct sockaddr *)&a, sizeof a);
        { int r = rcvall(s, SIO_RCVALL, RCVALL_ON); t_check(r == 0, __FILE__, __LINE__, "RCVALL on raw protocol socket", "proto %d err %d", pr[i], rw_err()); }
        rw_close(s);
    }
}
/* ---- what is received ---- */
TEST(rawrcvall_sees_udp_datagram_once) {
    SOCKET u, c; unsigned short port, cport; struct sockaddr_in to, me; int ml = sizeof me, k, i, hits = 0; rw_pkt p[8]; int found; NEED_SOCK();
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_bind4(c, &cport); rw_lo4(&to, port); rw_rcvtimeo(u, 3000); (void)me; (void)ml;
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    RW_EQ(U(sendto)(c, "RCVALL-UDP", 10, 0, (struct sockaddr *)&to, sizeof to), 10);
    { char b[32]; RW_EQ(U(recv)(u, b, sizeof b, 0), 10); }
    U(sendto)(c, "RCVALL-END", 10, 0, (struct sockaddr *)&to, sizeof to);
    k = rw_collect(s, p, 8, "RCVALL-END", 10, 3000, &found); CHECK(found);
    for (i = 0; i < k; i++) if (rw_find(p[i].b, p[i].n, "RCVALL-UDP", 10)) {
        const unsigned char *b = p[i].b; hits++;
        RW_EQ(b[0], 0x45); RW_EQ(b[9], 17); RW_EQ(rw_src(b), RW_LO4); RW_EQ(rw_dst(b), RW_LO4);
        RW_EQ(p[i].n, 20 + 8 + 10); RW_EQ(rw_totlen(b), 38);
        RW_EQ(b[20] << 8 | b[21], ntohs(cport)); RW_EQ(b[22] << 8 | b[23], ntohs(port)); RW_EQ(b[24] << 8 | b[25], 18);
    }
    RW_EQ(hits, 1);
    rw_close(u); rw_close(c); rw_close(s);
}
TEST(rawrcvall_off_stops_udp) {
    SOCKET u, c, mark; unsigned short port; struct sockaddr_in to, lo; rw_pkt p[8]; int k, found; NEED_SOCK();
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_lo4(&to, port); rw_rcvtimeo(u, 3000); rw_lo4(&lo, 0);
    mark = rw_raw(AF_INET, 253); if (mark == INVALID_SOCKET) { t_skip("raw refused"); return; }
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_OFF), 0);
    U(sendto)(c, "OFF-UDP", 7, 0, (struct sockaddr *)&to, sizeof to);
    { char b[16]; RW_EQ(U(recv)(u, b, sizeof b, 0), 7); }
    RW_EQ(U(sendto)(mark, "OFF-END", 7, 0, (struct sockaddr *)&lo, sizeof lo), 7);
    /* the protocol-0 raw socket is selected by protocol, not by receive-all, so it still gets the marker */
    k = rw_collect(s, p, 8, "OFF-END", 7, 3000, &found); CHECK(found);
    RW_EQ(rw_count_with(p, k, "OFF-UDP", 7), 0);
    rw_close(u); rw_close(c); rw_close(mark); rw_close(s);
}
TEST(rawrcvall_sees_icmp_request_and_reply) {
    SOCKET ic; struct sockaddr_in lo; rw_pkt p[8]; int k, i, req = -1, rep = -1, found; unsigned char pk[32], tag[2]; NEED_SOCK();
    ic = rw_raw(AF_INET, IPPROTO_ICMP); rw_lo4(&lo, 0);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    { int n = rw_echo4(pk, 0x6a6a, 1, "RCVALL-ECHO", 11); tag[0] = 0; (void)tag; RW_EQ(U(sendto)(ic, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n); }
    /* ends at the reply, which carries the same data */
    for (k = 0, found = 0; !found;) {
        rw_pkt q; int n = rw_recv_wait(s, q.b, RW_PKTCAP, 3000); if (n < 0) break; q.n = n; if (k < 8) p[k++] = q;
        if (n > 28 && q.b[9] == 1 && q.b[20] == 0 && rw_find(q.b, n, "RCVALL-ECHO", 11)) found = 1;
    }
    CHECK(found);
    for (i = 0; i < k; i++) if (p[i].b[9] == 1 && rw_find(p[i].b, p[i].n, "RCVALL-ECHO", 11)) { if (p[i].b[20] == 8 && req < 0) req = i; if (p[i].b[20] == 0 && rep < 0) rep = i; }
    CHECK(req >= 0); CHECK(rep >= 0); CHECK(req < rep);
    rw_close(ic); rw_close(s);
}
TEST(rawrcvall_sees_tcp_syn) {
    SOCKET l, c; unsigned short port; struct sockaddr_in to; rw_pkt p[16]; int k, i, syn = 0; DWORD t0; NEED_SOCK();
    l = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP); c = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rw_bind4(l, &port); RW_EQ(U(listen)(l, 1), 0); rw_lo4(&to, port);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    RW_EQ(U(connect)(c, (struct sockaddr *)&to, sizeof to), 0);
    t0 = GetTickCount();
    while (!syn && GetTickCount() - t0 < 3000) {
        k = rw_collect(s, p, 16, NULL, 0, 300, NULL);
        for (i = 0; i < k; i++) if (p[i].n >= 40 && p[i].b[9] == 6 && (p[i].b[22] << 8 | p[i].b[23]) == ntohs(port) && (p[i].b[33] & 0x12) == 0x02) syn = 1;
    }
    CHECK(syn);
    rw_close(c); rw_close(l); rw_close(s);
}
TEST(rawrcvall_ip_level_value_receives_udp) {
    SOCKET u, c; unsigned short port; struct sockaddr_in to; rw_pkt p[8]; int k, found; NEED_SOCK();
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_lo4(&to, port);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_IPLEVEL), 0);
    U(sendto)(c, "IPLEVEL-U", 9, 0, (struct sockaddr *)&to, sizeof to);
    U(sendto)(c, "IPLEVEL-E", 9, 0, (struct sockaddr *)&to, sizeof to);
    k = rw_collect(s, p, 8, "IPLEVEL-E", 9, 3000, &found);
    CHECK(found); RW_EQ(rw_count_with(p, k, "IPLEVEL-U", 9), 1);
    rw_close(u); rw_close(c); rw_close(s);
}
TEST(rawrcvall_socketlevelonly_value) {
    SOCKET u, c; unsigned short port; struct sockaddr_in to; rw_pkt p[8]; int k, found; NEED_SOCK();
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_lo4(&to, port);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_SOCKETLEVELONLY), 0);
    U(sendto)(c, "SLO-U", 5, 0, (struct sockaddr *)&to, sizeof to);
    U(sendto)(c, "SLO-E", 5, 0, (struct sockaddr *)&to, sizeof to);
    k = rw_collect(s, p, 8, "SLO-E", 5, 3000, &found);
    /* socket-level only: traffic of other sockets is not delivered, not even the end marker */
    CHECK(!found); RW_EQ(rw_count_with(p, k, "SLO-U", 5), 0);
    rw_close(u); rw_close(c); rw_close(s);
}
TEST(rawrcvall_own_sent_packet_received) {
    SOCKET s, a; struct sockaddr_in lo; rw_pkt p[4]; int found;
    RW_NEED_ADM(); s = mk(1); a = rw_raw(AF_INET, 253); if (s == INVALID_SOCKET || a == INVALID_SOCKET) { t_skip("refused"); return; }
    rw_lo4(&lo, 0);
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    RW_EQ(U(sendto)(s, "OWN-SENT", 8, 0, (struct sockaddr *)&lo, sizeof lo), 8);
    (void)a;
    RW_EQ(rw_collect(s, p, 4, "OWN-SENT", 8, 3000, &found) >= 1, 1); CHECK(found);
    rw_close(a); rw_close(s);
}
/* ---- the two multicast flavours ---- */
TEST(rawrcvall_igmpmcast_values) {
    static const int v[] = {RCVALL_OFF, RCVALL_ON, 2, 3}; size_t i; NEED_SOCK();
    for (i = 0; i < 4; i++) { int r = rcvall(s, SIO_RCVALL_IGMPMCAST, v[i]), e = rw_err(); t_check(r == 0, __FILE__, __LINE__, "SIO_RCVALL_IGMPMCAST", "value %d r=%d err=%d", v[i], r, e); }
    rw_close(s);
}
TEST(rawrcvall_mcast_values) {
    static const int v[] = {RCVALL_OFF, RCVALL_ON, 2, 3}; size_t i; NEED_SOCK();
    for (i = 0; i < 4; i++) { int r = rcvall(s, SIO_RCVALL_MCAST, v[i]), e = rw_err(); t_check(r == 0, __FILE__, __LINE__, "SIO_RCVALL_MCAST", "value %d r=%d err=%d", v[i], r, e); }
    rw_close(s);
}
TEST(rawrcvall_multicast_flavours_on_unbound_socket) {
    SOCKET s; RW_NEED_ADM(); s = rw_raw(AF_INET, IPPROTO_IP); if (s == INVALID_SOCKET) { t_skip("refused"); return; }
    { int r = rcvall(s, SIO_RCVALL_IGMPMCAST, 1), e = rw_err(); RW_EQ(r, -1); RW_EQ(e, WSAEINVAL); }
    { int r = rcvall(s, SIO_RCVALL_MCAST, 1), e = rw_err(); RW_EQ(r, -1); RW_EQ(e, WSAEINVAL); }
    rw_close(s);
}
TEST(rawrcvall_multicast_flavours_dont_deliver_unicast) {
    SOCKET u, c; unsigned short port; struct sockaddr_in to; rw_pkt p[8]; int k, found; NEED_SOCK();
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_lo4(&to, port);
    RW_EQ(rcvall(s, SIO_RCVALL_IGMPMCAST, RCVALL_ON), 0); RW_EQ(rcvall(s, SIO_RCVALL_MCAST, RCVALL_ON), 0);
    U(sendto)(c, "MC-uni", 6, 0, (struct sockaddr *)&to, sizeof to);
    { SOCKET m = rw_raw(AF_INET, 253); struct sockaddr_in lo; rw_lo4(&lo, 0); if (m != INVALID_SOCKET) { U(sendto)(m, "MC-end", 6, 0, (struct sockaddr *)&lo, sizeof lo); rw_close(m); } }
    k = rw_collect(s, p, 8, "MC-end", 6, 3000, &found); CHECK(found);
    RW_EQ(rw_count_with(p, k, "MC-uni", 6), 0);
    rw_close(u); rw_close(c); rw_close(s);
}
TEST(rawrcvall_standard_token_icmp_socket_accepts_rcvall) {
    SOCKET s, u, c; struct sockaddr_in a, to; unsigned short port; rw_pkt p[8]; int k, found;
    RW_NEED_STD(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&a, 0); U(bind)(s, (struct sockaddr *)&a, sizeof a);
    /* the one receive-all path a standard user has: a bound raw ICMP socket accepts the ioctl */
    RW_EQ(rcvall(s, SIO_RCVALL, RCVALL_ON), 0);
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_lo4(&to, port);
    U(sendto)(c, "STD-UDP", 7, 0, (struct sockaddr *)&to, sizeof to);
    { unsigned char pk[16]; int n = rw_echo4(pk, 0x6b6b, 1, "STD-END", 7); U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&a, sizeof a); }
    k = rw_collect(s, p, 8, "STD-END", 7, 3000, &found);
    /* receive-all does not widen what a standard token sees: the echo reply arrives, the UDP datagram does not */
    CHECK(found); RW_EQ(rw_count_with(p, k, "STD-UDP", 7), 0);
    rw_close(u); rw_close(c); rw_close(s);
}
