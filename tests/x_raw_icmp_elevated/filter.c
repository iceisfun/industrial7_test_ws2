/* x_raw_icmp_elevated / filter: which raw sockets receive which IPv4 packets (loopback only).
 *
 * Experimental protocol numbers 253 and 254 are used so that no stack component consumes the traffic.
 * Observed on Windows 10 22H2: every raw socket whose protocol equals the packet's protocol gets its own copy
 * (the sender included), a protocol-0 socket gets every protocol except TCP and UDP, a socket bound to an
 * address only gets packets destined to that address, a connected raw socket only gets packets from its peer
 * (a peer that does not match yields nothing), and raw sockets of the other protocols get nothing. The
 * received packet includes the IPv4 header; the stack builds it from the socket options when IP_HDRINCL is off
 * (TTL, IP_OPTIONS applied, IP_TOS ignored). Needs an elevated token for protocols 253/254/0; a standard token
 * can only reach the ICMP rows, and the refusal is checked in rawfilter_standard_token_refused. */
#include "rawh.h"

#define PA 253
#define PB 254
static int bind4(SOCKET s, unsigned char last) { struct sockaddr_in a; rw_lo4b(&a, last, 0); return U(bind)(s, (struct sockaddr *)&a, sizeof a); }
static int bindany(SOCKET s) { struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; return U(bind)(s, (struct sockaddr *)&a, sizeof a); }
/* does the socket receive a datagram containing m within a moment? */
static int rcv_has(SOCKET s, const char *m, int ms) {
    rw_pkt p[8]; int found = 0; rw_collect(s, p, 8, m, (int)strlen(m), ms, &found); return found;
}
/* drain whatever is queued */
static void flush(SOCKET s) { rw_pkt p[8]; rw_collect(s, p, 8, NULL, 0, 100, NULL); }
static int sendp(SOCKET s, unsigned char dst_last, const char *m) {
    struct sockaddr_in to; rw_lo4b(&to, dst_last, 0); return U(sendto)(s, m, (int)strlen(m), 0, (struct sockaddr *)&to, sizeof to);
}
#define NEED() RW_NEED_ADM()

TEST(rawfilter_same_protocol_gets_copy_including_sender) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(a, 1); bind4(b, 1);
    RW_EQ(sendp(a, 1, "AA-copy"), 7);
    CHECK(rcv_has(b, "AA-copy", 3000)); CHECK(rcv_has(a, "AA-copy", 3000));
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_unbound_sender_also_receives_after_send) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA); if (a == INVALID_SOCKET) { t_skip("raw refused"); return; }
    RW_EQ(sendp(a, 1, "AU-self"), 7);
    CHECK(rcv_has(a, "AU-self", 3000));
    rw_close(a); }
}
TEST(rawfilter_other_protocol_gets_nothing) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PB), c = rw_raw(AF_INET, PA); if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(a, 1); bind4(b, 1); bind4(c, 1);
    RW_EQ(sendp(a, 1, "OP-first"), 8);
    CHECK(rcv_has(c, "OP-first", 3000));          /* same protocol: arrived */
    RW_EQ(sendp(a, 1, "OP-second"), 9);        /* sentinel for b: send on b's protocol */
    CHECK(rcv_has(c, "OP-second", 3000));
    { rw_pkt p[8]; int k = rw_collect(b, p, 8, NULL, 0, 300, NULL); RW_EQ(k, 0); }
    rw_close(a); rw_close(b); rw_close(c); }
}
TEST(rawfilter_header_protocol_field_selects_receiver) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PB); int one = 1; unsigned char pk[32]; struct sockaddr_in to;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); rw_lo4(&to, 0);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    memcpy(pk + 20, "HDR-254", 7); rw_iphdr(pk, 27, PB, RW_LO4, RW_LO4, 64, 0x91);
    RW_EQ(U(sendto)(a, (char *)pk, 27, 0, (struct sockaddr *)&to, sizeof to), 27);
    CHECK(rcv_has(b, "HDR-254", 3000));
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_protocol_zero_gets_all_non_tcp_udp) {
    NEED(); { SOCKET w = rw_raw(AF_INET, 0), a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PB); if (w == INVALID_SOCKET || a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(w, 1); bind4(a, 1);
    RW_EQ(sendp(a, 1, "W0-253"), 6); CHECK(rcv_has(w, "W0-253", 3000));
    RW_EQ(sendp(b, 1, "W0-254"), 6); CHECK(rcv_has(w, "W0-254", 3000));
    rw_close(w); rw_close(a); rw_close(b); }
}
TEST(rawfilter_protocol_255_gets_only_255) {
    NEED(); { SOCKET r = rw_raw(AF_INET, 255), a = rw_raw(AF_INET, PA); if (r == INVALID_SOCKET || a == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(r, 1); bind4(a, 1);
    RW_EQ(sendp(a, 1, "R255-no"), 7);
    CHECK(rcv_has(a, "R255-no", 3000));
    { rw_pkt p[8]; RW_EQ(rw_collect(r, p, 8, NULL, 0, 300, NULL), 0); }
    RW_EQ(sendp(r, 1, "R255-yes"), 8); CHECK(rcv_has(r, "R255-yes", 3000));
    rw_close(r); rw_close(a); }
}
TEST(rawfilter_bound_address_only_gets_its_destination) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b1 = rw_raw(AF_INET, PA), b2 = rw_raw(AF_INET, PA), any = rw_raw(AF_INET, PA);
    if (a == INVALID_SOCKET || b1 == INVALID_SOCKET || b2 == INVALID_SOCKET || any == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(a, 1); bind4(b1, 1); bind4(b2, 2); bindany(any);
    RW_EQ(sendp(a, 2, "ADDR-to-2"), 9);
    CHECK(rcv_has(b2, "ADDR-to-2", 3000)); CHECK(rcv_has(any, "ADDR-to-2", 3000));
    RW_EQ(sendp(a, 1, "ADDR-to-1"), 9);
    CHECK(rcv_has(b1, "ADDR-to-1", 3000)); CHECK(rcv_has(any, "ADDR-to-1", 3000));
    { rw_pkt p[8]; int k = rw_collect(b2, p, 8, NULL, 0, 300, NULL); RW_EQ(rw_count_with(p, k, "ADDR-to-1", 9), 0); }
    { rw_pkt p[8]; int k = rw_collect(b1, p, 8, NULL, 0, 100, NULL); RW_EQ(rw_count_with(p, k, "ADDR-to-2", 9), 0); }
    rw_close(a); rw_close(b1); rw_close(b2); rw_close(any); }
}
TEST(rawfilter_connected_peer_filter) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), q9 = rw_raw(AF_INET, PA), q1 = rw_raw(AF_INET, PA); struct sockaddr_in p9, p1;
    if (a == INVALID_SOCKET || q9 == INVALID_SOCKET || q1 == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(a, 1); rw_lo4b(&p9, 9, 0); rw_lo4(&p1, 0);
    RW_EQ(U(connect)(q9, (struct sockaddr *)&p9, sizeof p9), 0);
    RW_EQ(U(connect)(q1, (struct sockaddr *)&p1, sizeof p1), 0);
    RW_EQ(sendp(a, 1, "CONN-pkt"), 8);
    CHECK(rcv_has(q1, "CONN-pkt", 3000));
    { rw_pkt p[8]; RW_EQ(rw_collect(q9, p, 8, NULL, 0, 300, NULL), 0); }
    rw_close(a); rw_close(q9); rw_close(q1); }
}
TEST(rawfilter_ttl_and_default_header) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); rw_pkt p[4]; int found, ttl; static const int ttls[] = {7, 0, 1, 255};
    size_t i;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1);
    RW_EQ(sendp(a, 1, "HD-default"), 10);
    RW_EQ(rw_collect(b, p, 4, "HD-default", 10, 3000, &found), 1); CHECK(found);
    RW_EQ(p[0].b[0], 0x45); RW_EQ(p[0].b[1], 0); RW_EQ(p[0].b[8], 128); RW_EQ(p[0].b[9], PA);
    RW_EQ(rw_src(p[0].b), RW_LO4); RW_EQ(rw_dst(p[0].b), RW_LO4); RW_EQ(rw_totlen(p[0].b), 20 + 10); RW_EQ(p[0].n, 30);
    CHECK(!memcmp(p[0].b + 20, "HD-default", 10));
    for (i = 0; i < 4; i++) {
        ttl = ttls[i]; RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_TTL, (char *)&ttl, 4), 0);
        RW_EQ(sendp(a, 1, "HD-ttl"), 6);
        RW_EQ(rw_collect(b, p, 4, "HD-ttl", 6, 3000, &found), 1); CHECK(found); RW_EQ(p[0].b[8], ttl);
    }
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_ip_tos_option_not_applied) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); rw_pkt p[4]; int found, tos = 0x28;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_TOS, (char *)&tos, 4), 0);
    RW_EQ(sendp(a, 1, "TOS-test"), 8);
    RW_EQ(rw_collect(b, p, 4, "TOS-test", 8, 3000, &found), 1); CHECK(found); RW_EQ(p[0].b[1], 0);
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_ip_options_are_put_in_header) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); rw_pkt p[4]; int found; unsigned char o[4] = {1, 1, 1, 0};
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_OPTIONS, (char *)o, 4), 0);
    RW_EQ(sendp(a, 1, "OPT-test"), 8);
    RW_EQ(rw_collect(b, p, 4, "OPT-test", 8, 3000, &found), 1); CHECK(found);
    RW_EQ(p[0].b[0], 0x46); RW_EQ(p[0].n, 24 + 8); RW_EQ(rw_totlen(p[0].b), 32); CHECK(!memcmp(p[0].b + 20, o, 4)); CHECK(!memcmp(p[0].b + 24, "OPT-test", 8));
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_hdrincl_fields_preserved) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); rw_pkt p[4]; int found, one = 1; unsigned char pk[40]; struct sockaddr_in to;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); rw_lo4(&to, 0);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    memcpy(pk + 20, "FIELDS", 6); rw_iphdr(pk, 26, PA, RW_LO4, RW_LO4, 33, 0x1234); pk[1] = 0x28; pk[10] = pk[11] = 0; { unsigned short c = rw_cksum(pk, 20); memcpy(pk + 10, &c, 2); }
    RW_EQ(U(sendto)(a, (char *)pk, 26, 0, (struct sockaddr *)&to, sizeof to), 26);
    RW_EQ(rw_collect(b, p, 4, "FIELDS", 6, 3000, &found), 1); CHECK(found);
    RW_EQ(p[0].b[1], 0x28); RW_EQ(p[0].b[8], 33); RW_EQ(p[0].b[4] << 8 | p[0].b[5], 0x1234); RW_EQ(p[0].b[9], PA); RW_EQ(p[0].n, 26);
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_hdrincl_options_preserved) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); rw_pkt p[4]; int found, one = 1; unsigned char pk[40]; struct sockaddr_in to;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); rw_lo4(&to, 0);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    memset(pk, 0, sizeof pk); rw_iphdr(pk, 30, PA, RW_LO4, RW_LO4, 33, 0x4321); pk[0] = 0x46; pk[20] = pk[21] = pk[22] = 1; pk[23] = 0; memcpy(pk + 24, "OPTHDR", 6);
    pk[10] = pk[11] = 0; { unsigned short c = rw_cksum(pk, 24); memcpy(pk + 10, &c, 2); }
    RW_EQ(U(sendto)(a, (char *)pk, 30, 0, (struct sockaddr *)&to, sizeof to), 30);
    RW_EQ(rw_collect(b, p, 4, "OPTHDR", 6, 3000, &found), 1); CHECK(found);
    RW_EQ(p[0].b[0], 0x46); RW_EQ(p[0].n, 30); CHECK(!memcmp(p[0].b + 20, "\1\1\1\0", 4));
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_hdrincl_destination_in_header) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b1 = rw_raw(AF_INET, PA), b2 = rw_raw(AF_INET, PA); int one = 1; unsigned char pk[40]; struct sockaddr_in to2;
    if (a == INVALID_SOCKET || b1 == INVALID_SOCKET || b2 == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b1, 1); bind4(b2, 2); rw_lo4b(&to2, 2, 0);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    /* header says 127.0.0.1, sockaddr says 127.0.0.2: the header wins */
    memcpy(pk + 20, "HDST-1", 6); rw_iphdr(pk, 26, PA, RW_LO4, RW_LO4, 64, 0x51);
    RW_EQ(U(sendto)(a, (char *)pk, 26, 0, (struct sockaddr *)&to2, sizeof to2), 26);
    CHECK(rcv_has(b1, "HDST-1", 3000));
    /* header says 127.0.0.2 */
    memcpy(pk + 20, "HDST-2", 6); rw_iphdr(pk, 26, PA, RW_LO4, 0x0200007fu, 64, 0x52);
    RW_EQ(U(sendto)(a, (char *)pk, 26, 0, (struct sockaddr *)&to2, sizeof to2), 26);
    CHECK(rcv_has(b2, "HDST-2", 3000));
    { rw_pkt p[8]; int k = rw_collect(b1, p, 8, NULL, 0, 200, NULL); RW_EQ(rw_count_with(p, k, "HDST-2", 6), 0); }
    rw_close(a); rw_close(b1); rw_close(b2); }
}
TEST(rawfilter_hdrincl_foreign_source_dropped) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); int one = 1; unsigned char pk[40]; struct sockaddr_in to;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); rw_lo4(&to, 0);
    RW_EQ(U(setsockopt)(a, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    memcpy(pk + 20, "SRC-bad", 7); rw_iphdr(pk, 27, PA, 0x0900007fu, RW_LO4, 64, 0x53);
    RW_EQ(U(sendto)(a, (char *)pk, 27, 0, (struct sockaddr *)&to, sizeof to), 27);
    memcpy(pk + 20, "SRC-good", 8); rw_iphdr(pk, 28, PA, RW_LO4, RW_LO4, 64, 0x54);
    RW_EQ(U(sendto)(a, (char *)pk, 28, 0, (struct sockaddr *)&to, sizeof to), 28);
    { rw_pkt p[8]; int found, k = rw_collect(b, p, 8, "SRC-good", 8, 3000, &found); CHECK(found); RW_EQ(rw_count_with(p, k, "SRC-bad", 7), 0); }
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_recvfrom_source_address) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); struct sockaddr_in f; int fl = sizeof f; unsigned char buf[100]; int n;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); memset(&f, 0xcc, sizeof f);
    RW_EQ(sendp(a, 1, "FROM-test"), 9);
    { fd_set fs; struct timeval tv = {3, 0}; FD_ZERO(&fs); FD_SET(b, &fs); RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    n = U(recvfrom)(b, (char *)buf, sizeof buf, 0, (struct sockaddr *)&f, &fl);
    RW_EQ(n, 29); RW_EQ(fl, 16); RW_EQ(f.sin_family, AF_INET); RW_EQ(f.sin_port, 0); RW_EQ(f.sin_addr.s_addr, RW_LO4);
    rw_close(a); rw_close(b); }
}
TEST(rawfilter_sockaddr_port_is_not_the_protocol) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PB), c = rw_raw(AF_INET, PA); struct sockaddr_in to;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET || c == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); bind4(c, 1); rw_lo4(&to, htons(PB));
    RW_EQ(U(sendto)(a, "PORT-254", 8, 0, (struct sockaddr *)&to, sizeof to), 8);
    CHECK(rcv_has(c, "PORT-254", 3000));
    { rw_pkt p[8]; RW_EQ(rw_collect(b, p, 8, NULL, 0, 200, NULL), 0); }
    rw_close(a); rw_close(b); rw_close(c); }
}
TEST(rawfilter_closed_socket_stops_receiving) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA), c = rw_raw(AF_INET, PA);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET || c == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); bind4(c, 1); rw_close(b);
    RW_EQ(sendp(a, 1, "CLOSED-ok"), 9); CHECK(rcv_has(c, "CLOSED-ok", 3000));
    rw_close(a); rw_close(c); }
}
TEST(rawfilter_receive_queue_overflow_keeps_oldest) {
    NEED(); { SOCKET a = rw_raw(AF_INET, PA), b = rw_raw(AF_INET, PA); int i, v = 4096, got = 0; rw_pkt p[1]; (void)p;
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(b, 1); U(setsockopt)(b, SOL_SOCKET, SO_RCVBUF, (char *)&v, 4);
    for (i = 0; i < 200; i++) { char m[40]; int n = sprintf(m, "FLOOD-%03d-xxxxxxxxxxxxxxxxxxxxxxxx", i); U(sendto)(a, m, n, 0, (struct sockaddr *)&(struct sockaddr_in){2, 0, {{{0x7f, 0, 0, 1}}}}, 16); }
    for (;;) { unsigned char b2[100]; int n = rw_recv_wait(b, b2, sizeof b2, 300); if (n < 0) break; got++; }
    t_note("queued datagrams with a 4096 byte buffer after 200 sends: bounded=%d", got < 200);
    CHECK(got < 200); CHECK(got > 0);
    rw_close(a); rw_close(b); }
}
/* ICMP sockets: the standard token gets these too, so the rows run in both modes */
TEST(rawfilter_icmp_socket_ignores_udp) {
    SOCKET ic, u, c, a; struct sockaddr_in lo; unsigned short port; rw_pkt p[8]; int found; unsigned char pk[32]; struct sockaddr_in to;
    RW_UP(); ic = rw_raw(AF_INET, IPPROTO_ICMP); if (ic == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0); U(bind)(ic, (struct sockaddr *)&lo, sizeof lo);
    u = rw_udp(); c = rw_udp(); rw_bind4(u, &port); rw_lo4(&to, port);
    RW_EQ(U(sendto)(c, "UDP-not-icmp", 12, 0, (struct sockaddr *)&to, sizeof to), 12);
    { int n = rw_echo4(pk, 0x5a5a, 1, "E", 1); RW_EQ(U(sendto)(ic, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n); }
    { int k = rw_collect(ic, p, 8, "E", 1, 3000, &found); CHECK(found); RW_EQ(rw_count_with(p, k, "UDP-not-icmp", 12), 0); }
    a = INVALID_SOCKET; rw_close(ic); rw_close(u); rw_close(c);
}
TEST(rawfilter_raw_udp_socket_gets_no_udp) {
    NEED(); { SOCKET ru = rw_raw(AF_INET, IPPROTO_UDP), u = rw_udp(), c = rw_udp(); unsigned short port; struct sockaddr_in to; rw_pkt p[4]; int k;
    if (ru == INVALID_SOCKET) { t_skip("raw refused"); return; }
    bind4(ru, 1); rw_bind4(u, &port); rw_lo4(&to, port); rw_rcvtimeo(u, 3000);
    RW_EQ(U(sendto)(c, "UDP-to-raw?", 11, 0, (struct sockaddr *)&to, sizeof to), 11);
    { char b[32]; RW_EQ(U(recv)(u, b, sizeof b, 0), 11); }
    k = rw_collect(ru, p, 4, NULL, 0, 500, NULL); RW_EQ(k, 0);
    rw_close(ru); rw_close(u); rw_close(c); }
}
TEST(rawfilter_standard_token_refused) {
    RW_NEED_STD(); { SOCKET a = rw_raw(AF_INET, PA), w = rw_raw(AF_INET, 0), u = rw_raw(AF_INET, IPPROTO_UDP);
    CHECK(a == INVALID_SOCKET); CHECK(w == INVALID_SOCKET); CHECK(u == INVALID_SOCKET);
    rw_seterr(0); a = rw_raw(AF_INET, PB); RW_EQ(a, INVALID_SOCKET); RW_EQ(rw_err(), WSAEACCES);
    rw_close(a); rw_close(w); rw_close(u); }
}
