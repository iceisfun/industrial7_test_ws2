/* x_raw_icmp_elevated / icmp6: ICMPv6 echo through a raw AF_INET6 socket to ::1.
 *
 * Unlike IPv4, a raw IPv6 socket receives the ICMPv6 message without the IPv6 header, and the stack fills in
 * the ICMPv6 checksum (it needs the pseudo-header) whatever the sender put in the checksum field. The echo
 * request (128) is answered with a reply (129) carrying the same id, sequence and data. Token rules mirror
 * IPv4: a standard user may send echo requests of at least 8 bytes only (WSAEACCES otherwise), an elevated
 * token may send anything, IPV6_CHECKSUM does not exist on these sockets. */
#include "rawh.h"

static unsigned short g_id6 = 0x6100;
#define OPEN6() SOCKET s; RW_UP(); s = rw_raw(AF_INET6, IPPROTO_ICMPV6); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 socket refused (%d)", rw_err()); return; }

static int echo6(unsigned char *p, unsigned short id, unsigned short seq, const void *d, int dl) {
    memset(p, 0, 8); p[0] = 128; p[4] = (unsigned char)(id >> 8); p[5] = (unsigned char)id; p[6] = (unsigned char)(seq >> 8); p[7] = (unsigned char)seq;
    if (dl) memcpy(p + 8, d, dl);
    return 8 + dl;   /* checksum left 0: the stack computes it */
}
/* wait for the echo reply with id/seq; returns datagram length or 0 */
static int wait6(SOCKET s, unsigned short id, unsigned short seq, unsigned char *out, int cap, int ms, int *other) {
    DWORD t0 = GetTickCount(); if (other) *other = 0;
    for (;;) {
        int left = ms - (int)(GetTickCount() - t0), n;
        if (left <= 0) return 0;
        n = rw_recv_wait(s, out, cap, left);
        if (n == -2) return 0;
        if (n < 8) return 0;
        if (out[0] == 129 && out[4] == (id >> 8) && out[5] == (id & 255) && out[6] == (seq >> 8) && out[7] == (seq & 255)) return n;
        if (other) (*other)++;
    }
}
static SOCKET ready6(void) { SOCKET s = rw_raw(AF_INET6, IPPROTO_ICMPV6); if (s != INVALID_SOCKET) { struct sockaddr_in6 a; rw_lo6(&a, 0); U(bind)(s, (struct sockaddr *)&a, sizeof a); } return s; }

TEST(rawicmp6_echo_reply_basic) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[64], rb[200]; int n, other;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 1, "abcdefgh", 8);
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), 16);
    n = wait6(s, g_id6, 1, rb, sizeof rb, 3000, &other);
    RW_EQ(n, 16); RW_EQ(rb[0], 129); RW_EQ(rb[1], 0); CHECK(!memcmp(rb + 8, "abcdefgh", 8));
    RW_EQ(other, 0);
    rw_close(s);
}
TEST(rawicmp6_reply_has_no_ipv6_header_and_valid_checksum) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[64], rb[200]; int n; unsigned short ck;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 2, "pseudohd", 8);
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), 16);
    n = wait6(s, g_id6, 2, rb, sizeof rb, 3000, NULL);
    RW_EQ(n, 16);
    /* ICMPv6 checksum over the pseudo-header (::1 -> ::1, length, next header 58) and the message must verify */
    { unsigned char ps[40 + 16]; unsigned short v; memset(ps, 0, sizeof ps); ps[15] = 1; ps[31] = 1; ps[34] = 0; ps[35] = 16; ps[39] = 58; memcpy(ps + 40, rb, 16);
      v = rw_cksum(ps, 56); RW_EQ(v, 0); }
    ck = (unsigned short)(rb[2] << 8 | rb[3]); CHECK(ck != 0);
    rw_close(s);
}
TEST(rawicmp6_checksum_field_is_overwritten) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[64], rb[200]; int n;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 3, "garbage!", 8); pk[2] = 0xde; pk[3] = 0xad;
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), 16);
    n = wait6(s, g_id6, 3, rb, sizeof rb, 3000, NULL);
    RW_EQ(n, 16);    /* a bad value did not stop the request from being answered */
    rw_close(s);
}
static void echo6_size(int dl) {
    SOCKET s; struct sockaddr_in6 lo; static unsigned char pk[9000], rb[9000]; int n, i;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); for (i = 0; i < dl; i++) rb[i] = (unsigned char)(i * 5 + 1);
    n = echo6(pk, ++g_id6, 7, rb, dl);
    RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n);
    { static unsigned char out[9000]; int r = wait6(s, g_id6, 7, out, sizeof out, 4000, NULL);
      RW_EQ(r, 8 + dl); CHECK(!memcmp(out + 8, rb, dl)); }
    rw_close(s);
}
TEST(rawicmp6_echo_payload_0)    { echo6_size(0); }
TEST(rawicmp6_echo_payload_1)    { echo6_size(1); }
TEST(rawicmp6_echo_payload_32)   { echo6_size(32); }
TEST(rawicmp6_echo_payload_1232) { echo6_size(1232); }
TEST(rawicmp6_echo_payload_4000) { echo6_size(4000); }
TEST(rawicmp6_echo_sequence) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[32], rb[64]; int i; unsigned short id;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); id = ++g_id6;
    for (i = 1; i <= 4; i++) { int n = echo6(pk, id, (unsigned short)i, "seq!", 4); RW_EQ(U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo), n); }
    for (i = 1; i <= 4; i++) { int n = wait6(s, id, (unsigned short)i, rb, sizeof rb, 3000, NULL); RW_EQ(n, 12); }
    rw_close(s);
}
/* a request shorter than the 8 byte echo header is not answered; the next full request is */
TEST(rawicmp6_short_request_not_answered) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[32], rb[64]; int n, r;
    RW_NEED_ADM(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 1, NULL, 0);
    r = U(sendto)(s, (char *)pk, 5, 0, (struct sockaddr *)&lo, sizeof lo); RW_EQ(r, 5);
    n = echo6(pk, g_id6, 2, "full", 4);
    r = U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo); RW_EQ(r, n);
    n = wait6(s, g_id6, 2, rb, sizeof rb, 3000, NULL); RW_EQ(n, 12);
    CHECK(wait6(s, g_id6, 1, rb, sizeof rb, 300, NULL) == 0);
    rw_close(s);
}
/* ---- token rules ---- */
TEST(rawicmp6_send_types_by_token) {
    static const int ty[] = {1, 2, 3, 4, 129, 130, 133, 134, 135, 136, 137, 143, 255, 0};
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[16]; size_t i; int adm;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    adm = rw_elevated(); rw_lo6(&lo, 0);
    for (i = 0; i < sizeof ty / sizeof ty[0]; i++) {
        int r, e; memset(pk, 0, 16); pk[0] = (unsigned char)ty[i]; pk[7] = 1;
        rw_seterr(0); r = U(sendto)(s, (char *)pk, 16, 0, (struct sockaddr *)&lo, sizeof lo); e = rw_err();
        if (adm) t_check(r == 16, __FILE__, __LINE__, "elevated may send any type", "type %d r=%d err=%d", ty[i], r, e);
        else t_check(r == -1 && e == WSAEACCES, __FILE__, __LINE__, "standard token: echo request only", "type %d r=%d err=%d", ty[i], r, e);
    }
    rw_close(s);
}
TEST(rawicmp6_send_short_by_token) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[16]; int n, adm;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    adm = rw_elevated(); rw_lo6(&lo, 0); memset(pk, 0, 16); pk[0] = 128;
    for (n = 0; n <= 8; n++) {
        int r, e; rw_seterr(0); r = U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo); e = rw_err();
        if (adm || n == 8) t_check(r == n, __FILE__, __LINE__, "accepted", "len %d r=%d err=%d", n, r, e);
        else t_check(r == -1 && e == WSAEACCES, __FILE__, __LINE__, "standard token: 8 byte minimum", "len %d r=%d err=%d", n, r, e);
    }
    rw_close(s);
}
TEST(rawicmp6_send_code_by_token) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[16]; int adm, r, e;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    adm = rw_elevated(); rw_lo6(&lo, 0); memset(pk, 0, 16); pk[0] = 128; pk[1] = 7;
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 16, 0, (struct sockaddr *)&lo, sizeof lo); e = rw_err();
    if (adm) RW_EQ(r, 16); else { RW_EQ(r, -1); RW_EQ(e, WSAEACCES); }
    rw_close(s);
}
/* ---- address errors and bind ---- */
TEST(rawicmp6_send_errors) {
    OPEN6(); struct sockaddr_in6 lo; struct sockaddr_in a4; unsigned char pk[16]; int r;
    rw_lo6(&lo, 0); rw_lo4(&a4, 0); echo6(pk, 1, 1, NULL, 0);
    rw_seterr(0); r = U(send)(s, (char *)pk, 8, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOTCONN);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, NULL, 0); RW_EQ(r, -1); RW_EQ(rw_err(), WSAENOTCONN);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&a4, sizeof a4); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_seterr(0); r = U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&lo, 12); RW_EQ(r, -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_close(s);
}
TEST(rawicmp6_bind_loopback_and_names) {
    OPEN6(); struct sockaddr_in6 lo, g; int gl = sizeof g, r;
    rw_lo6(&lo, 0); memset(&g, 0xcc, sizeof g);
    r = U(bind)(s, (struct sockaddr *)&lo, sizeof lo); RW_EQ(r, 0);
    if (r == 0) {
        RW_EQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0); RW_EQ(gl, 28); RW_EQ(g.sin6_family, AF_INET6); RW_EQ(g.sin6_port, 0);
        CHECK(!memcmp(&g.sin6_addr, &lo.sin6_addr, 16));
    }
    rw_close(s);
}
TEST(rawicmp6_bind_errors) {
    OPEN6(); struct sockaddr_in6 a; struct sockaddr_in a4; SOCKET t;
    rw_lo6(&a, 0); a.sin6_addr.u.Byte[15] = 2;
    rw_seterr(0); RW_EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), -1); RW_EQ(rw_err(), WSAEADDRNOTAVAIL);
    rw_lo4(&a4, 0);
    rw_seterr(0); RW_EQ(U(bind)(s, (struct sockaddr *)&a4, sizeof a4), -1); RW_EQ(rw_err(), WSAEFAULT);
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6;
    t = rw_raw(AF_INET6, IPPROTO_ICMPV6);
    RW_EQ(U(bind)(t, (struct sockaddr *)&a, sizeof a), 0);
    rw_seterr(0); RW_EQ(U(bind)(t, (struct sockaddr *)&a, sizeof a), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(t); rw_close(s);
}
TEST(rawicmp6_send_implicitly_binds) {
    OPEN6(); struct sockaddr_in6 lo; unsigned char pk[16]; rw_lo6(&lo, 0); echo6(pk, ++g_id6, 1, NULL, 0);
    RW_EQ(U(sendto)(s, (char *)pk, 8, 0, (struct sockaddr *)&lo, sizeof lo), 8);
    rw_seterr(0); RW_EQ(U(bind)(s, (struct sockaddr *)&lo, sizeof lo), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp6_recv_unbound_is_einval) {
    OPEN6(); unsigned char b[64]; rw_rcvtimeo(s, 200);
    rw_seterr(0); RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_close(s);
}
TEST(rawicmp6_recv_small_buffer) {
    SOCKET s; struct sockaddr_in6 lo; unsigned char pk[32], b[64]; int n;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 1, "12345678", 8);
    U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo);
    { fd_set f; struct timeval tv = {3, 0}; FD_ZERO(&f); FD_SET(s, &f); RW_EQ(U(select)(0, &f, NULL, NULL, &tv), 1); }
    rw_seterr(0); n = U(recv)(s, (char *)b, 4, 0); RW_EQ(n, -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    RW_EQ(rw_recv_wait(s, b, sizeof b, 200), -2);
    rw_close(s);
}
TEST(rawicmp6_recvfrom_source) {
    SOCKET s; struct sockaddr_in6 lo, f; unsigned char pk[32], b[64]; int n, fl = sizeof f;
    RW_UP(); s = ready6(); if (s == INVALID_SOCKET) { t_skip("raw ICMPv6 refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 1, "12345678", 8); memset(&f, 0xcc, sizeof f);
    U(sendto)(s, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo);
    { fd_set fs; struct timeval tv = {3, 0}; FD_ZERO(&fs); FD_SET(s, &fs); RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    n = U(recvfrom)(s, (char *)b, sizeof b, 0, (struct sockaddr *)&f, &fl);
    RW_EQ(n, 16); RW_EQ(fl, 28); RW_EQ(f.sin6_family, AF_INET6); CHECK(!memcmp(&f.sin6_addr, &lo.sin6_addr, 16));
    rw_close(s);
}
TEST(rawicmp6_connect_and_send) {
    OPEN6(); struct sockaddr_in6 lo; unsigned char pk[32], rb[64]; int n;
    rw_lo6(&lo, 0);
    RW_EQ(U(connect)(s, (struct sockaddr *)&lo, sizeof lo), 0);
    n = echo6(pk, ++g_id6, 5, "conn", 4);
    RW_EQ(U(send)(s, (char *)pk, n, 0), n);
    n = wait6(s, g_id6, 5, rb, sizeof rb, 3000, NULL); RW_EQ(n, 12);
    rw_close(s);
}
TEST(rawicmp6_v4_socket_does_not_see_v6) {
    SOCKET a, b; struct sockaddr_in6 lo; unsigned char pk[32], rb[64]; int n;
    RW_UP(); a = ready6(); b = rw_raw(AF_INET, IPPROTO_ICMP); if (a == INVALID_SOCKET || b == INVALID_SOCKET) { rw_close(a); rw_close(b); t_skip("raw ICMP refused"); return; }
    rw_lo6(&lo, 0); n = echo6(pk, ++g_id6, 1, "v6!!", 4);
    U(sendto)(a, (char *)pk, n, 0, (struct sockaddr *)&lo, sizeof lo);
    n = wait6(a, g_id6, 1, rb, sizeof rb, 3000, NULL); RW_EQ(n, 12);
    RW_EQ(rw_recv_wait(b, rb, sizeof rb, 300), -2);
    rw_close(a); rw_close(b);
}
