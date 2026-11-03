/* x_raw_icmp_elevated / icmp4: ICMPv4 echo through a raw socket to 127.0.0.1.
 *
 * The test builds the ICMP header and checksum itself; the stack answers an echo request to a local address
 * with an echo reply (type 0, same id, sequence and data, TTL 128, valid checksum) and hands it to raw ICMP
 * sockets together with its 20-byte IPv4 header. The sender's own request is not looped back to raw ICMP
 * sockets. An echo request with a wrong checksum is silently dropped. A non-elevated token may send echo
 * requests only: any other type, a non-zero code or a message shorter than 8 bytes fails with WSAEACCES, while
 * an elevated token may send anything. Absence is proven with a sentinel (a second, valid request sent after
 * the one that must be ignored) instead of a bare timeout. */
#include "rawh.h"

static unsigned short g_id = 0x7100;
#define OPEN4() SOCKET s; RW_UP(); s = rw_raw(AF_INET, IPPROTO_ICMP); if (s == INVALID_SOCKET) { t_skip("raw ICMP socket refused (%d)", rw_err()); return; }
static SOCKET ready(void) { SOCKET s = rw_raw(AF_INET, IPPROTO_ICMP); if (s != INVALID_SOCKET) { struct sockaddr_in a; rw_lo4(&a, 0); U(bind)(s, (struct sockaddr *)&a, sizeof a); } return s; }

/* checks every property of a received echo reply for a loopback request */
static void check_reply(const rw_pkt *p, unsigned short id, unsigned short seq, const void *data, int dlen) {
    int ih = rw_ihl(p->b);
    RW_EQ(p->b[0] >> 4, 4); RW_EQ(ih, 20);
    RW_EQ(p->b[9], 1);
    RW_EQ(p->n, 20 + 8 + dlen); RW_EQ(rw_totlen(p->b), 20 + 8 + dlen);
    RW_EQ(rw_src(p->b), RW_LO4); RW_EQ(rw_dst(p->b), RW_LO4);
    RW_EQ(p->b[8], 128);
    RW_EQ(p->b[ih], 0); RW_EQ(p->b[ih + 1], 0);
    RW_EQ(p->b[ih + 4] << 8 | p->b[ih + 5], id); RW_EQ(p->b[ih + 6] << 8 | p->b[ih + 7], seq);
    CHECK(!memcmp(p->b + ih + 8, data, dlen));
    RW_EQ(rw_cksum(p->b + ih, p->n - ih), 0);
}

TEST(rawicmp_echo_reply_basic) {
    SOCKET s; struct sockaddr_in lo; rw_pkt p; int saw;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    RW_EQ(rw_ping4(s, &lo, ++g_id, 1, "abcdefgh", 8), 8 + 8);
    CHECK(rw_wait_reply4(s, g_id, 1, &p, 3000, &saw));
    check_reply(&p, g_id, 1, "abcdefgh", 8);
    RW_EQ(saw, 0);
    rw_close(s);
}
TEST(rawicmp_echo_reply_unbound_socket) {
    OPEN4(); struct sockaddr_in lo; rw_pkt p;
    rw_lo4(&lo, 0);
    RW_EQ(rw_ping4(s, &lo, ++g_id, 2, "unbound!", 8), 16);
    CHECK(rw_wait_reply4(s, g_id, 2, &p, 3000, NULL));
    check_reply(&p, g_id, 2, "unbound!", 8);
    rw_close(s);
}
TEST(rawicmp_echo_reply_connected_socket) {
    OPEN4(); struct sockaddr_in lo; rw_pkt p; unsigned char pk[32]; int n;
    rw_lo4(&lo, 0);
    RW_EQ(U(connect)(s, (struct sockaddr *)&lo, sizeof lo), 0);
    n = rw_echo4(pk, ++g_id, 3, "conn", 4);
    RW_EQ(U(send)(s, (char *)pk, n, 0), n);
    CHECK(rw_wait_reply4(s, g_id, 3, &p, 3000, NULL));
    check_reply(&p, g_id, 3, "conn", 4);
    rw_close(s);
}
TEST(rawicmp_echo_port_in_sockaddr_is_ignored) {
    OPEN4(); struct sockaddr_in lo; rw_pkt p;
    rw_lo4(&lo, htons(77));
    RW_EQ(rw_ping4(s, &lo, ++g_id, 4, "port", 4), 12);
    CHECK(rw_wait_reply4(s, g_id, 4, &p, 3000, NULL));
    check_reply(&p, g_id, 4, "port", 4);
    rw_close(s);
}
/* payload sizes: the reply carries exactly what was sent */
static void echo_size(int dlen) {
    SOCKET s; struct sockaddr_in lo; static unsigned char data[9000]; static unsigned char big[70000]; int i, n, ih, got = 0;
    DWORD t0;
    unsigned char *pk = malloc(dlen + 64);
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { free(pk); t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    for (i = 0; i < dlen; i++) data[i] = (unsigned char)(i * 7 + 3);
    n = rw_echo4(pk, ++g_id, 9, data, dlen);
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n);
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 4000 && !got) {
        int r = rw_recv_wait(s, big, sizeof big, 1000);
        if (r < 28) { if (r == -2) break; continue; }
        ih = rw_ihl(big);
        if (big[ih] == 0 && big[ih + 4] == (g_id >> 8) && big[ih + 5] == (g_id & 255)) {
            RW_EQ(r, 28 + dlen); CHECK(!memcmp(big + ih + 8, data, dlen)); RW_EQ(rw_cksum(big + ih, r - ih), 0); got = 1;
        }
    }
    t_check(got, __FILE__, __LINE__, "reply received", "payload %d", dlen);
    rw_close(s); free(pk);
}
TEST(rawicmp_echo_payload_0)    { echo_size(0); }
TEST(rawicmp_echo_payload_1)    { echo_size(1); }
TEST(rawicmp_echo_payload_2)    { echo_size(2); }
TEST(rawicmp_echo_payload_3)    { echo_size(3); }
TEST(rawicmp_echo_payload_32)   { echo_size(32); }
TEST(rawicmp_echo_payload_56)   { echo_size(56); }
TEST(rawicmp_echo_payload_1000) { echo_size(1000); }
TEST(rawicmp_echo_payload_1472) { echo_size(1472); }
TEST(rawicmp_echo_payload_1473) { echo_size(1473); }
TEST(rawicmp_echo_payload_8000) { echo_size(8000); }

/* several requests in flight, replies match id and sequence in order */
TEST(rawicmp_echo_sequence_in_order) {
    SOCKET s; struct sockaddr_in lo; int i; rw_pkt p; unsigned short id;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0); id = ++g_id;
    for (i = 1; i <= 5; i++) { char d[4]; memset(d, 'a' + i, 4); RW_EQ(rw_ping4(s, &lo, id, (unsigned short)i, d, 4), 12); }
    for (i = 1; i <= 5; i++) { char d[4]; memset(d, 'a' + i, 4); CHECK(rw_wait_reply4(s, id, (unsigned short)i, &p, 3000, NULL)); check_reply(&p, id, (unsigned short)i, d, 4); }
    rw_close(s);
}
/* the sender's own request is not looped back to raw ICMP sockets */
TEST(rawicmp_own_request_not_delivered) {
    SOCKET s; struct sockaddr_in lo; int saw = -1; rw_pkt p;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "x", 1);
    CHECK(rw_wait_reply4(s, g_id, 1, &p, 3000, &saw));
    RW_EQ(saw, 0);
    rw_close(s);
}
/* a second raw ICMP socket sees the reply too (each receiver gets its own copy) */
TEST(rawicmp_reply_copied_to_every_socket) {
    SOCKET a, b; struct sockaddr_in lo; rw_pkt p;
    RW_UP(); a = ready(); b = ready(); if (a == INVALID_SOCKET || b == INVALID_SOCKET) { rw_close(a); rw_close(b); t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(a, &lo, ++g_id, 1, "copy", 4);
    CHECK(rw_wait_reply4(a, g_id, 1, &p, 3000, NULL));
    CHECK(rw_wait_reply4(b, g_id, 1, &p, 3000, NULL));
    rw_close(a); rw_close(b);
}
/* wrong ICMP checksum on an echo request: dropped, the next valid request is answered first */
TEST(rawicmp_bad_checksum_request_dropped) {
    SOCKET s; struct sockaddr_in lo; rw_pkt p; unsigned char pk[32]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    n = rw_echo4(pk, ++g_id, 1, "bad!", 4); pk[2] ^= 0x5a;
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n);
    RW_EQ(rw_ping4(s, &lo, g_id, 2, "good", 4), 12);
    CHECK(rw_wait_reply4(s, g_id, 2, &p, 3000, NULL));
    { rw_pkt q; CHECK(!rw_wait_reply4(s, g_id, 1, &q, 300, NULL)); }
    rw_close(s);
}
TEST(rawicmp_zero_checksum_request_dropped) {
    SOCKET s; struct sockaddr_in lo; rw_pkt p; unsigned char pk[32]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    n = rw_echo4(pk, ++g_id, 1, "nock", 4); pk[2] = pk[3] = 0;
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n);
    RW_EQ(rw_ping4(s, &lo, g_id, 2, "good", 4), 12);
    CHECK(rw_wait_reply4(s, g_id, 2, &p, 3000, NULL));
    { rw_pkt q; CHECK(!rw_wait_reply4(s, g_id, 1, &q, 300, NULL)); }
    rw_close(s);
}
/* ---- who may send what ---- */
struct tyrow { int type; };
TEST(rawicmp_send_non_echo_types_by_token) {
    SOCKET s; struct sockaddr_in lo; int ty, adm; unsigned char pk[16];
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    adm = rw_elevated(); rw_lo4(&lo, 0);
    for (ty = 0; ty < 20; ty++) {
        int r, e;
        if (ty == 8) continue;
        memset(pk, 0, sizeof pk); pk[0] = (unsigned char)ty; pk[7] = 1; { unsigned short c = rw_cksum(pk, 16); memcpy(pk + 2, &c, 2); }
        rw_seterr(0); r = U(sendto)(s, (char *)pk, 16, 0, (struct sockaddr *)&lo, sizeof lo); e = rw_err();
        if (adm) t_check(r == 16, __FILE__, __LINE__, "elevated may send any type", "type %d r=%d err=%d", ty, r, e);
        else t_check(r == -1 && e == WSAEACCES, __FILE__, __LINE__, "standard token: only echo", "type %d r=%d err=%d", ty, r, e);
    }
    rw_close(s);
}
TEST(rawicmp_send_echo_code_by_token) {
    static const int codes[] = {1, 3, 128, 255}; SOCKET s; struct sockaddr_in lo; size_t i; int adm; unsigned char pk[16];
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    adm = rw_elevated(); rw_lo4(&lo, 0);
    for (i = 0; i < 4; i++) {
        int r, e; memset(pk, 0, 16); pk[0] = 8; pk[1] = (unsigned char)codes[i]; { unsigned short c = rw_cksum(pk, 16); memcpy(pk + 2, &c, 2); }
        rw_seterr(0); r = U(sendto)(s, (char *)pk, 16, 0, (struct sockaddr *)&lo, sizeof lo); e = rw_err();
        if (adm) t_check(r == 16, __FILE__, __LINE__, "elevated may send a coded echo", "code %d r=%d err=%d", codes[i], r, e);
        else t_check(r == -1 && e == WSAEACCES, __FILE__, __LINE__, "standard token: code must be 0", "code %d r=%d err=%d", codes[i], r, e);
    }
    rw_close(s);
}
TEST(rawicmp_send_short_message_by_token) {
    SOCKET s; struct sockaddr_in lo; int n, adm; unsigned char pk[16];
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    adm = rw_elevated(); rw_lo4(&lo, 0);
    memset(pk, 0, 16); pk[0] = 8;
    for (n = 0; n <= 8; n++) {
        int r, e; rw_seterr(0); r = U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo); e = rw_err();
        if (adm || n == 8) t_check(r == n, __FILE__, __LINE__, "send accepted", "len %d r=%d err=%d adm=%d", n, r, e, adm);
        else t_check(r == -1 && e == WSAEACCES, __FILE__, __LINE__, "standard token: header needs 8 bytes", "len %d r=%d err=%d", n, r, e);
    }
    rw_close(s);
}
/* ---- address and length errors (same for both tokens) ---- */
TEST(rawicmp_send_errors_destination) {
    OPEN4(); struct sockaddr_in lo, u; struct sockaddr_in6 l6; unsigned char pk[16]; int r;
    rw_lo4(&lo, 0); rw_lo6(&l6, 0); u = lo; u.sin_family = AF_UNSPEC;
    rw_echo4(pk, 1, 1, "12345678", 0);
    rw_seterr(0); r = U(send)(s, (char *)pk, 8, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOTCONN);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, NULL, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOTCONN);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&l6, sizeof l6); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEAFNOSUPPORT);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&u, sizeof u); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEAFNOSUPPORT);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&lo, 8); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&lo, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(s);
}
TEST(rawicmp_send_oob_flag_unconnected) {
    OPEN4(); unsigned char pk[16]; int r; rw_echo4(pk, 1, 1, NULL, 0);
    rw_seterr(0); r = U(send)(s, (char *)pk, 8, MSG_OOB); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOTCONN);
    rw_close(s);
}
TEST(rawicmp_send_max_message_size) {
    static unsigned char big[70000]; static unsigned char sink[70000]; SOCKET s; struct sockaddr_in lo; int adm, r;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    adm = rw_elevated(); (void)adm; rw_lo4(&lo, 0);
    /* an echo request of exactly the maximum (SO_MAX_MSG_SIZE = 65515) is accepted, one byte more is WSAEMSGSIZE */
    memset(big, 0, 65515); big[0] = 8; big[4] = (unsigned char)(++g_id >> 8); big[5] = (unsigned char)g_id; { unsigned short c = rw_cksum(big, 65515); memcpy(big + 2, &c, 2); }
    RW_EQ(U(sendto)(s, (char *)big, 65515, 0, (struct sockaddr *)&lo, sizeof lo), 65515);
    { DWORD t0 = GetTickCount(); while (GetTickCount() - t0 < 3000) { int n = rw_recv_wait(s, sink, sizeof sink, 500); if (n >= 28 && sink[rw_ihl(sink)] == 0) break; if (n == -2) break; } }
    rw_seterr(0); RW_EQ(U(sendto)(s, (char *)big, 65516, 0, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    rw_seterr(0); RW_EQ(U(sendto)(s, (char *)big, 65535, 0, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    rw_seterr(0); RW_EQ(U(sendto)(s, (char *)big, 70000, 0, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    rw_close(s);
}
/* ---- bind / name queries ---- */
TEST(rawicmp_bind_loopback_and_names) {
    OPEN4(); struct sockaddr_in lo, g; int gl = sizeof g;
    rw_lo4(&lo, 0); memset(&g, 0xcc, sizeof g);
    RW_EQ(U(bind)(s, (struct sockaddr *)&lo, sizeof lo), 0);
    RW_EQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);
    RW_EQ(gl, 16); RW_EQ(g.sin_family, AF_INET); RW_EQ(g.sin_port, 0); RW_EQ(g.sin_addr.s_addr, RW_LO4);
    rw_seterr(0); RW_EQ(U(getpeername)(s, (struct sockaddr *)&g, &gl), -1); RW_EQ(rw_err(), WSAENOTCONN);
    rw_close(s);
}
TEST(rawicmp_getsockname_unbound_is_einval) {
    OPEN4(); struct sockaddr_in g; int gl = sizeof g;
    rw_seterr(0); RW_EQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp_rebind_is_einval) {
    OPEN4(); struct sockaddr_in lo; rw_lo4(&lo, 0);
    RW_EQ(U(bind)(s, (struct sockaddr *)&lo, sizeof lo), 0);
    rw_seterr(0); RW_EQ(U(bind)(s, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp_send_implicitly_binds) {
    OPEN4(); struct sockaddr_in lo; rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "bind", 4);
    rw_seterr(0); RW_EQ(U(bind)(s, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp_bind_any_and_port) {
    OPEN4(); struct sockaddr_in a; SOCKET t;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET;
    RW_EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), 0);
    t = rw_raw(AF_INET, IPPROTO_ICMP); rw_lo4(&a, htons(5));
    RW_EQ(U(bind)(t, (struct sockaddr *)&a, sizeof a), 0);   /* the port of a raw bind is not used */
    rw_close(t); rw_close(s);
}
TEST(rawicmp_bind_127_0_0_2) {
    OPEN4(); struct sockaddr_in a; rw_lo4b(&a, 2, 0);
    RW_EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), 0);
    rw_close(s);
}
TEST(rawicmp_bind_two_sockets_same_address) {
    SOCKET a, b; struct sockaddr_in lo;
    RW_UP(); a = rw_raw(AF_INET, IPPROTO_ICMP); b = rw_raw(AF_INET, IPPROTO_ICMP);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { rw_close(a); rw_close(b); t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    RW_EQ(U(bind)(a, (struct sockaddr *)&lo, sizeof lo), 0); RW_EQ(U(bind)(b, (struct sockaddr *)&lo, sizeof lo), 0);
    rw_close(a); rw_close(b);
}
TEST(rawicmp_bind_errors) {
    OPEN4(); struct sockaddr_in a; struct sockaddr_in6 a6; SOCKET t;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x010200c0u;   /* 192.0.2.1: documentation range, never assigned */
    rw_seterr(0); RW_EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), -1); RW_EQ(rw_err(), WSAEADDRNOTAVAIL);
    t = rw_raw(AF_INET, IPPROTO_ICMP); rw_lo6(&a6, 0);
    rw_seterr(0); RW_EQ(U(bind)(t, (struct sockaddr *)&a6, sizeof a6), -1); RW_EQ(rw_err(), WSAEAFNOSUPPORT);
    rw_lo4(&a, 0);
    rw_seterr(0); RW_EQ(U(bind)(t, (struct sockaddr *)&a, 4), -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_seterr(0); RW_EQ(U(bind)(t, (struct sockaddr *)&a, 0), -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(t); rw_close(s);
}
TEST(rawicmp_connect_names_and_errors) {
    OPEN4(); struct sockaddr_in lo, g; struct sockaddr_in6 l6; int gl = sizeof g;
    rw_lo4(&lo, 0); rw_lo6(&l6, 0);
    rw_seterr(0); RW_EQ(U(connect)(s, (struct sockaddr *)&l6, sizeof l6), -1); RW_EQ(rw_err(), WSAEAFNOSUPPORT);
    rw_seterr(0); RW_EQ(U(connect)(s, (struct sockaddr *)&lo, 8), -1); RW_EQ(rw_err(), WSAEFAULT);
    RW_EQ(U(connect)(s, (struct sockaddr *)&lo, sizeof lo), 0);
    memset(&g, 0xcc, sizeof g);
    RW_EQ(U(getpeername)(s, (struct sockaddr *)&g, &gl), 0); RW_EQ(gl, 16); RW_EQ(g.sin_family, AF_INET); RW_EQ(g.sin_addr.s_addr, RW_LO4);
    RW_EQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0); RW_EQ(g.sin_addr.s_addr, RW_LO4);
    rw_close(s);
}
/* ---- receive semantics ---- */
static int waitq(SOCKET s) { u_long av = 0; DWORD t0 = GetTickCount(); while (GetTickCount() - t0 < 3000) { fd_set f; struct timeval tv = {0, 100000}; FD_ZERO(&f); FD_SET(s, &f); if (U(select)(0, &f, NULL, NULL, &tv) > 0) return 1; } return 0; }
TEST(rawicmp_fionread_reports_whole_datagram) {
    SOCKET s; struct sockaddr_in lo; u_long av = 0xdead; unsigned char b[200];
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16);
    CHECK(waitq(s));
    RW_EQ(U(ioctlsocket)(s, FIONREAD, &av), 0); RW_EQ(av, 20 + 8 + 16);
    RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), 44);
    rw_close(s);
}
TEST(rawicmp_recv_small_buffer_discards_datagram) {
    SOCKET s; struct sockaddr_in lo; unsigned char b[100]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16); CHECK(waitq(s));
    rw_seterr(0); n = U(recv)(s, (char *)b, 10, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    RW_EQ(rw_recv_wait(s, b, sizeof b, 300), -2);       /* the truncated datagram is gone */
    rw_close(s);
}
TEST(rawicmp_recv_peek_keeps_datagram) {
    SOCKET s; struct sockaddr_in lo; unsigned char b[100]; int n; u_long av = 0;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16); CHECK(waitq(s));
    n = U(recv)(s, (char *)b, sizeof b, MSG_PEEK); RW_EQ(n, 44);
    RW_EQ(U(ioctlsocket)(s, FIONREAD, &av), 0); RW_EQ(av, 44);
    n = U(recv)(s, (char *)b, sizeof b, 0); RW_EQ(n, 44);
    RW_EQ(rw_recv_wait(s, b, sizeof b, 200), -2);
    rw_close(s);
}
TEST(rawicmp_recv_peek_small_buffer_keeps_datagram) {
    SOCKET s; struct sockaddr_in lo; unsigned char b[100]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16); CHECK(waitq(s));
    rw_seterr(0); n = U(recv)(s, (char *)b, 10, MSG_PEEK); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    n = U(recv)(s, (char *)b, sizeof b, 0); RW_EQ(n, 44);
    rw_close(s);
}
TEST(rawicmp_recv_zero_length_buffer) {
    SOCKET s; struct sockaddr_in lo; unsigned char b[100]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16); CHECK(waitq(s));
    rw_seterr(0); n = U(recv)(s, (char *)b, 0, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    RW_EQ(rw_recv_wait(s, b, sizeof b, 200), -2);
    rw_close(s);
}
TEST(rawicmp_recvfrom_fills_source) {
    SOCKET s; struct sockaddr_in lo, f; unsigned char b[100]; int n, fl = sizeof f;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0); memset(&f, 0xcc, sizeof f);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16); CHECK(waitq(s));
    n = U(recvfrom)(s, (char *)b, sizeof b, 0, (struct sockaddr *)&f, &fl);
    RW_EQ(n, 44); RW_EQ(fl, 16); RW_EQ(f.sin_family, AF_INET); RW_EQ(f.sin_port, 0); RW_EQ(f.sin_addr.s_addr, RW_LO4);
    rw_close(s);
}
TEST(rawicmp_recvfrom_short_namelen_is_efault) {
    SOCKET s; struct sockaddr_in lo, f; unsigned char b[100]; int n, fl = 4;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    rw_ping4(s, &lo, ++g_id, 1, "0123456789abcdef", 16); CHECK(waitq(s));
    rw_seterr(0); n = U(recvfrom)(s, (char *)b, sizeof b, 0, (struct sockaddr *)&f, &fl); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(s);
}
TEST(rawicmp_recv_nonblocking_empty) {
    SOCKET s; u_long nb = 1; unsigned char b[100]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    RW_EQ(U(ioctlsocket)(s, FIONBIO, &nb), 0);
    rw_seterr(0); n = U(recv)(s, (char *)b, sizeof b, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEWOULDBLOCK);
    rw_close(s);
}
TEST(rawicmp_recv_timeout) {
    SOCKET s; unsigned char b[100]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_rcvtimeo(s, 200);
    rw_seterr(0); n = U(recv)(s, (char *)b, sizeof b, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAETIMEDOUT);
    rw_close(s);
}
TEST(rawicmp_recv_unbound_is_einval) {
    OPEN4(); unsigned char b[100]; int n;
    rw_rcvtimeo(s, 200);
    rw_seterr(0); n = U(recv)(s, (char *)b, sizeof b, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); n = U(recv)(s, (char *)b, sizeof b, MSG_OOB); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); n = U(recv)(s, (char *)b, sizeof b, MSG_WAITALL); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp_shutdown_receive) {
    SOCKET s; unsigned char b[100]; int n;
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    RW_EQ(U(shutdown)(s, SD_RECEIVE), 0);
    rw_seterr(0); n = U(recv)(s, (char *)b, sizeof b, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAESHUTDOWN);
    RW_EQ(U(shutdown)(s, SD_SEND), 0);
    rw_close(s);
}
TEST(rawicmp_listen_accept_unsupported) {
    OPEN4(); SOCKET a;
    rw_seterr(0); RW_EQ(U(listen)(s, 1), -1); RW_EQ(rw_err(), WSAEOPNOTSUPP);
    rw_seterr(0); a = U(accept)(s, NULL, NULL); CHECK(a == INVALID_SOCKET); RW_EQ(rw_err(), WSAEOPNOTSUPP);
    rw_close(s);
}
TEST(rawicmp_select_readable_after_reply) {
    SOCKET s; struct sockaddr_in lo; fd_set f; struct timeval tv = {3, 0};
    RW_UP(); s = ready(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused"); return; }
    rw_lo4(&lo, 0);
    { fd_set e; struct timeval z = {0, 0}; FD_ZERO(&e); FD_SET(s, &e); RW_EQ(U(select)(0, &e, NULL, NULL, &z), 0); }
    rw_ping4(s, &lo, ++g_id, 1, "sel", 3);
    FD_ZERO(&f); FD_SET(s, &f);
    RW_EQ(U(select)(0, &f, NULL, NULL, &tv), 1);
    rw_close(s);
}
TEST(rawicmp_writable_immediately) {
    OPEN4(); fd_set f; struct timeval z = {0, 0};
    FD_ZERO(&f); FD_SET(s, &f);
    RW_EQ(U(select)(0, NULL, &f, NULL, &z), 1);
    rw_close(s);
}
TEST(rawicmp_rcvbuf_small_value_roundtrip) {
    OPEN4(); int v = 4096, n = 4, r;
    RW_EQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, 4), 0);
    v = 0; r = U(getsockopt)(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, &n); RW_EQ(r, 0); RW_EQ(v, 4096);
    rw_close(s);
}
TEST(rawicmp_exclusiveaddruse_after_reuseaddr_rejected) {
    OPEN4(); int one = 1;
    RW_EQ(U(setsockopt)(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, 4), 0);
    rw_seterr(0); RW_EQ(U(setsockopt)(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&one, 4), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp_reuseaddr_after_exclusiveaddruse) {
    OPEN4(); int one = 1, r, e;
    RW_EQ(U(setsockopt)(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&one, 4), 0);
    rw_seterr(0); r = U(setsockopt)(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, 4); e = rw_err();
    RW_EQ(r, -1); RW_EQ(e, WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp_protocol_info_fields) {
    OPEN4(); WSAPROTOCOL_INFOW pi; int n = sizeof pi; WSAPROTOCOL_INFOA pa; int na = sizeof pa;
    memset(&pi, 0, sizeof pi);
    RW_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &n), 0);
    RW_EQ(pi.iAddressFamily, AF_INET); RW_EQ(pi.iSocketType, SOCK_RAW); RW_EQ(pi.iProtocol, 0); RW_EQ(pi.iMaxSockAddr, 16); RW_EQ(pi.iMinSockAddr, 16);
    EXPECT_WSTR(pi.szProtocol, L"MSAFD Tcpip [RAW/IP]");
    memset(&pa, 0, sizeof pa);
    RW_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&pa, &na), 0);
    EXPECT_STR(pa.szProtocol, "MSAFD Tcpip [RAW/IP]");
    rw_close(s);
}
