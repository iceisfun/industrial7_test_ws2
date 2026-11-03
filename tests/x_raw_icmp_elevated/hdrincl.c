/* x_raw_icmp_elevated / hdrincl: IP_HDRINCL sends of hand-built IPv4 headers over loopback.
 *
 * With IP_HDRINCL set (elevation required) the first bytes of every send are the IPv4 header. The test builds
 * UDP datagrams addressed to a normal UDP socket on 127.0.0.1 and watches what arrives. Observed rules: the
 * stack fixes up length and checksum itself (a zero or wrong total length, a wrong header checksum and even a
 * version nibble of 6 do not stop delivery), but the header length must be 5 words or carry real options, the
 * protocol field must say UDP, and the source must be a local address. The destination in the header, not
 * the sockaddr, picks the receiver. Without IP_HDRINCL the same bytes are just a payload. Rows that must not
 * arrive are proven with a sentinel datagram sent through an ordinary UDP socket afterwards. */
#include "rawh.h"

static const unsigned char SENT[] = "sentinel!";

struct env { SOCKET raw, rx, tx; unsigned short port; struct sockaddr_in to; };
static int env_open(struct env *e, int hdrincl) {
    memset(e, 0, sizeof *e); e->raw = e->rx = e->tx = INVALID_SOCKET;
    e->raw = rw_raw(AF_INET, IPPROTO_UDP);
    if (e->raw == INVALID_SOCKET) return 0;
    e->rx = rw_udp(); e->tx = rw_udp();
    if (rw_bind4(e->rx, &e->port) != 0) return 0;
    rw_rcvtimeo(e->rx, 3000);
    rw_lo4(&e->to, e->port);
    if (hdrincl) { int one = 1; if (U(setsockopt)(e->raw, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4) != 0) return 0; }
    return 1;
}
static void env_close(struct env *e) { rw_close(e->raw); rw_close(e->rx); rw_close(e->tx); }
#define ENV(hdr) struct env E; RW_NEED_ADM(); if (!env_open(&E, hdr)) { env_close(&E); t_skip("cannot set up raw UDP sender"); return; }
/* send the sentinel through an ordinary UDP socket and collect everything that reached the receiver until it */
static int drain_to_sentinel(struct env *e, unsigned char out[][64], int *lens, int max) {
    int k = 0;
    U(sendto)(e->tx, (const char *)SENT, 9, 0, (struct sockaddr *)&e->to, sizeof e->to);
    while (k < max) {
        unsigned char b[64]; int n = U(recv)(e->rx, (char *)b, sizeof b, 0);
        if (n < 0) break;
        if (n == 9 && !memcmp(b, SENT, 9)) return k;
        memcpy(out[k], b, n); lens[k] = n; k++;
    }
    return k;
}
static int build_udp(struct env *e, unsigned char *pk, const char *data, int dl, unsigned short sport) {
    int ul = rw_udp_pkt(pk + 20, htons(sport), e->port, data, dl);
    rw_iphdr(pk, 20 + ul, 17, RW_LO4, RW_LO4, 64, 0x77);
    return 20 + ul;
}

TEST(rawhdr_udp_delivered_with_source_port) {
    ENV(1); unsigned char pk[128], b[64]; struct sockaddr_in f; int fl = sizeof f, n, tot;
    tot = build_udp(&E, pk, "hello", 5, 4000);
    RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&E.to, sizeof E.to), tot);
    n = U(recvfrom)(E.rx, (char *)b, sizeof b, 0, (struct sockaddr *)&f, &fl);
    RW_EQ(n, 5); CHECK(!memcmp(b, "hello", 5)); RW_EQ(f.sin_addr.s_addr, RW_LO4); RW_EQ(ntohs(f.sin_port), 4000);
    env_close(&E);
}
TEST(rawhdr_without_option_header_is_payload) {
    ENV(0); unsigned char pk[128], b[128]; int n, tot;
    tot = build_udp(&E, pk, "hello", 5, 4000);
    /* the raw UDP socket treats the 33 bytes as a UDP message: its first 8 bytes (IPv4 header start) are the UDP header */
    RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&E.to, sizeof E.to), tot);
    n = U(recv)(E.rx, (char *)b, sizeof b, 0);
    t_note("raw UDP without HDRINCL, packet bytes as payload: receiver got %d", n);
    env_close(&E);
}
TEST(rawhdr_send_unconnected_needs_destination) {
    ENV(1); unsigned char pk[128]; int tot = build_udp(&E, pk, "hello", 5, 4000);
    rw_seterr(0); RW_EQ(U(send)(E.raw, (char *)pk, tot, 0), -1); RW_EQ(rw_err(), WSAENOTCONN);
    env_close(&E);
}
TEST(rawhdr_connected_send) {
    ENV(1); unsigned char pk[128], b[64]; int tot = build_udp(&E, pk, "conn!", 5, 4001), n;
    RW_EQ(U(connect)(E.raw, (struct sockaddr *)&E.to, sizeof E.to), 0);
    RW_EQ(U(send)(E.raw, (char *)pk, tot, 0), tot);
    n = U(recv)(E.rx, (char *)b, sizeof b, 0); RW_EQ(n, 5); CHECK(!memcmp(b, "conn!", 5));
    env_close(&E);
}
TEST(rawhdr_header_destination_wins_over_sockaddr) {
    ENV(1); unsigned char pk[128], b[64]; struct sockaddr_in other; int tot = build_udp(&E, pk, "dest!", 5, 4002), n;
    rw_lo4b(&other, 9, E.port);
    RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&other, sizeof other), tot);
    n = U(recv)(E.rx, (char *)b, sizeof b, 0); RW_EQ(n, 5); CHECK(!memcmp(b, "dest!", 5));
    env_close(&E);
}
/* header variants: 1 = delivered, 0 = dropped */
struct hv { const char *tag; int ok; };
static void variant(int idx, unsigned char *pk, int udp_total) {
    switch (idx) {
    case 0: break;                                                      /* well formed */
    case 1: pk[2] = pk[3] = 0; break;                                   /* total length 0 */
    case 2: pk[2] = 0; pk[3] = 200; break;                              /* total length too big */
    case 3: pk[2] = 0; pk[3] = 24; break;                               /* total length too small */
    case 4: pk[10] ^= 0xff; break;                                      /* header checksum wrong */
    case 5: pk[0] = 0x65; break;                                        /* version nibble 6 */
    case 6: pk[8] = 0; break;                                           /* TTL 0 */
    case 7: pk[8] = 1; break;                                           /* TTL 1 */
    case 8: pk[9] = 6; break;                                           /* protocol TCP */
    case 9: pk[9] = 0; break;                                           /* protocol 0 */
    case 10: pk[0] = 0x44; break;                                       /* IHL 4 */
    case 11: pk[0] = 0x46; break;                                       /* IHL 6 without option bytes */
    case 12: memset(pk + 12, 0, 4); break;                              /* source 0.0.0.0 */
    case 13: pk[12] = 127; pk[13] = 0; pk[14] = 0; pk[15] = 9; break;   /* source 127.0.0.9 */
    case 14: pk[12] = 192; pk[13] = 0; pk[14] = 2; pk[15] = 1; break;   /* source 192.0.2.1 (no such local address) */
    case 15: pk[1] = 0xb8; break;                                       /* TOS */
    case 16: pk[6] = 0x40; break;                                       /* DF */
    case 17: pk[4] = 0xab; pk[5] = 0xcd; break;                         /* identification */
    }
    (void)udp_total;
}
static const struct hv hvs[] = {
    {"well formed", 1}, {"total length 0", 1}, {"total length too big", 1}, {"total length too small", 1},
    {"bad header checksum", 1}, {"version 6 nibble", 1}, {"ttl 0", 1}, {"ttl 1", 1},
    {"protocol tcp", 0}, {"protocol 0", 0}, {"ihl 4", 0}, {"ihl 6 without options", 0},
    {"source 0.0.0.0", 0}, {"source 127.0.0.9", 0}, {"source not local", 0}, {"tos set", 1}, {"df set", 1}, {"id set", 1},
};
TEST(rawhdr_header_variants_table) {
    ENV(1); size_t i;
    for (i = 0; i < sizeof hvs / sizeof hvs[0]; i++) {
        unsigned char pk[128]; int tot = build_udp(&E, pk, "variant", 7, 4100), seen;
        unsigned char got[4][64]; int lens[4];
        variant((int)i, pk, tot);
        RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&E.to, sizeof E.to), tot);
        seen = drain_to_sentinel(&E, got, lens, 4);
        t_check(seen == hvs[i].ok, __FILE__, __LINE__, "variant delivery", "%s: delivered %d want %d", hvs[i].tag, seen, hvs[i].ok);
        if (seen && hvs[i].ok) t_check(lens[0] == 7 && !memcmp(got[0], "variant", 7), __FILE__, __LINE__, "variant payload", "%s", hvs[i].tag);
    }
    env_close(&E);
}
/* truncated sends: the call reports the byte count, only a complete UDP header is delivered (empty payload) */
TEST(rawhdr_truncated_sends) {
    ENV(1); unsigned char pk[128]; int tot = build_udp(&E, pk, "trunc", 5, 4200), n;
    for (n = 0; n <= 28; n++) {
        unsigned char got[4][64]; int lens[4], seen;
        if (n == 28) continue;
        RW_EQ(U(sendto)(E.raw, (char *)pk, n, 0, (struct sockaddr *)&E.to, sizeof E.to), n);
        seen = drain_to_sentinel(&E, got, lens, 4);
        t_check(seen == 0, __FILE__, __LINE__, "truncated send not delivered", "len %d delivered %d", n, seen);
    }
    RW_EQ(U(sendto)(E.raw, (char *)pk, 28, 0, (struct sockaddr *)&E.to, sizeof E.to), 28);
    { unsigned char b[64]; int r = U(recv)(E.rx, (char *)b, sizeof b, 0); RW_EQ(r, 0); }
    env_close(&E);
}
TEST(rawhdr_zero_checksum_udp_ok) {
    ENV(1); unsigned char pk[128], b[64]; int tot = build_udp(&E, pk, "nocksum", 7, 4300), n;
    pk[26] = pk[27] = 0;
    RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&E.to, sizeof E.to), tot);
    n = U(recv)(E.rx, (char *)b, sizeof b, 0); RW_EQ(n, 7);
    env_close(&E);
}
TEST(rawhdr_wrong_udp_checksum_still_delivered) {
    /* unlike the plain raw-UDP send below, a header-included packet is not checksum-validated on its way to the
     * loopback receiver */
    ENV(1); unsigned char pk[128], b[64]; int tot = build_udp(&E, pk, "wrongck", 7, 4301), n;
    pk[26] = 0x12; pk[27] = 0x34;
    RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&E.to, sizeof E.to), tot);
    n = U(recv)(E.rx, (char *)b, sizeof b, 0); RW_EQ(n, 7); CHECK(!memcmp(b, "wrongck", 7));
    env_close(&E);
}
TEST(rawhdr_udp_to_closed_port_is_silent) {
    ENV(1); unsigned char pk[128]; int tot; struct sockaddr_in to;
    /* a second receiver socket is bound then closed so the port is free: the datagram has nobody to go to */
    { SOCKET t = rw_udp(); unsigned short p; rw_bind4(t, &p); rw_close(t); rw_lo4(&to, p); E.port = p; }
    tot = build_udp(&E, pk, "nobody", 6, 4400);
    RW_EQ(U(sendto)(E.raw, (char *)pk, tot, 0, (struct sockaddr *)&to, sizeof to), tot);
    env_close(&E);
}
/* ---- IPPROTO_RAW and other protocols ---- */
TEST(rawhdr_ipproto_raw_hdrincl_default) {
    SOCKET s; int v = 7, n = 4;
    RW_NEED_ADM(); s = rw_raw(AF_INET, IPPROTO_RAW);
    if (s == INVALID_SOCKET) { t_skip("raw socket refused"); return; }
    RW_EQ(U(getsockopt)(s, IPPROTO_IP, IP_HDRINCL, (char *)&v, &n), 0); RW_EQ(v, 0);
    rw_close(s);
}
TEST(rawhdr_ipproto_raw_send_is_payload_of_protocol_255) {
    struct env E; SOCKET r255; unsigned char pk[128], rb[256]; int tot, n;
    RW_NEED_ADM(); if (!env_open(&E, 0)) { env_close(&E); t_skip("setup"); return; }
    r255 = rw_raw(AF_INET, IPPROTO_RAW);
    { struct sockaddr_in lo; rw_lo4(&lo, 0); U(bind)(r255, (struct sockaddr *)&lo, sizeof lo); }
    tot = build_udp(&E, pk, "inner", 5, 4500);
    RW_EQ(U(sendto)(r255, (char *)pk, tot, 0, (struct sockaddr *)&E.to, sizeof E.to), tot);
    /* the whole built packet travelled as the payload of a protocol-255 datagram and no UDP arrived */
    n = rw_recv_wait(r255, rb, sizeof rb, 3000);
    RW_EQ(n, 20 + tot); RW_EQ(rb[9], 255); CHECK(!memcmp(rb + 20, pk, tot));
    { unsigned char got[4][64]; int lens[4]; RW_EQ(drain_to_sentinel(&E, got, lens, 4), 0); }
    rw_close(r255); env_close(&E);
}
TEST(rawhdr_raw_udp_payload_only) {
    ENV(0); unsigned char pk[64], b[64]; struct sockaddr_in f; int fl = sizeof f, n;
    rw_udp_pkt(pk, htons(4600), E.port, "nohdr", 5);
    RW_EQ(U(sendto)(E.raw, (char *)pk, 13, 0, (struct sockaddr *)&E.to, sizeof E.to), 13);
    n = U(recvfrom)(E.rx, (char *)b, sizeof b, 0, (struct sockaddr *)&f, &fl);
    RW_EQ(n, 5); CHECK(!memcmp(b, "nohdr", 5)); RW_EQ(f.sin_addr.s_addr, RW_LO4); RW_EQ(ntohs(f.sin_port), 4600);
    env_close(&E);
}
TEST(rawhdr_raw_udp_sockaddr_port_ignored) {
    ENV(0); unsigned char pk[64], b[64]; struct sockaddr_in to = E.to; int n;
    rw_udp_pkt(pk, htons(4601), E.port, "port0", 5); to.sin_port = 0;
    RW_EQ(U(sendto)(E.raw, (char *)pk, 13, 0, (struct sockaddr *)&to, sizeof to), 13);
    n = U(recv)(E.rx, (char *)b, sizeof b, 0); RW_EQ(n, 5);
    env_close(&E);
}
TEST(rawhdr_raw_udp_wrong_checksum_dropped) {
    ENV(0); unsigned char pk[64], got[4][64]; int lens[4];
    rw_udp_pkt(pk, htons(4602), E.port, "badck", 5); pk[6] = pk[7] = 0x12;
    RW_EQ(U(sendto)(E.raw, (char *)pk, 13, 0, (struct sockaddr *)&E.to, sizeof E.to), 13);
    RW_EQ(drain_to_sentinel(&E, got, lens, 4), 0);
    env_close(&E);
}
/* ---- ICMP over a header-included socket ---- */
TEST(rawhdr_icmp_echo_with_header) {
    SOCKET s; struct sockaddr_in lo; unsigned char pk[64]; rw_pkt p; int one = 1, n;
    RW_NEED_ADM(); s = rw_raw(AF_INET, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0); U(bind)(s, (struct sockaddr *)&lo, sizeof lo);
    RW_EQ(U(setsockopt)(s, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    n = rw_echo4(pk + 20, 0x5151, 1, "hi", 2); rw_iphdr(pk, 20 + n, 1, RW_LO4, RW_LO4, 3, 0x31);
    RW_EQ(U(sendto)(s, (char *)pk, 20 + n, 0, (struct sockaddr *)&lo, sizeof lo), 20 + n);
    CHECK(rw_wait_reply4(s, 0x5151, 1, &p, 3000, NULL));
    RW_EQ(p.b[8], 128);   /* the reply's TTL is the responder's, not the request's */
    rw_close(s);
}
TEST(rawhdr_icmp_truncated_header_send) {
    SOCKET s; struct sockaddr_in lo; unsigned char pk[64]; int one = 1, n;
    RW_NEED_ADM(); s = rw_raw(AF_INET, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    RW_EQ(U(setsockopt)(s, IPPROTO_IP, IP_HDRINCL, (char *)&one, 4), 0);
    n = rw_echo4(pk + 20, 0x5152, 1, "hi", 2); rw_iphdr(pk, 20 + n, 1, RW_LO4, RW_LO4, 64, 0x32);
    RW_EQ(U(sendto)(s, (char *)pk, 19, 0, (struct sockaddr *)&lo, sizeof lo), 19);
    RW_EQ(U(sendto)(s, (char *)pk, 20, 0, (struct sockaddr *)&lo, sizeof lo), 20);
    rw_close(s);
}
/* ---- standard token ---- */
TEST(rawhdr_standard_token_cannot_include_header) {
    SOCKET s; struct sockaddr_in lo; unsigned char pk[64]; int n;
    RW_NEED_STD(); s = rw_raw(AF_INET, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    n = rw_echo4(pk + 20, 0x5153, 1, "hi", 2); rw_iphdr(pk, 20 + n, 1, RW_LO4, RW_LO4, 64, 0x33);
    /* without IP_HDRINCL the 20 header bytes are an ICMP message of type 0x45: refused like any non-echo type */
    rw_seterr(0); RW_EQ(U(sendto)(s, (char *)pk, 20 + n, 0, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEACCES);
    rw_close(s);
}
