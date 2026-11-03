/* IPV6_V6ONLY option semantics: default value, value normalisation, option-length rules for TCP (4-byte value)
 * and UDP (1-byte value), the option on an IPv4 socket, and the WSAEINVAL refusal once a socket is bound,
 * listening, connected or accepted.  No traffic beyond loopback connects. */
#include "sm.h"

static int rd_tcp(SOCKET s, int *v) { return s_getint(s, IPPROTO_IPV6, IPV6_V6ONLY, v); }
/* UDP reports a single byte: read it into a buffer with a sentinel next to it */
static int rd_udp(SOCKET s, int *v, int *outlen) {
    unsigned char b[4] = { 0x55, 0x55, 0x55, 0x55 }; int l = 4, rc = U(getsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)b, &l);
    *v = b[0]; *outlen = l;
    if (b[1] != 0x55) *v = -1;   /* more than one byte written */
    return rc;
}

TEST(dsm_v6only_tcp_default_is_on) {
    SOCKET s; int v;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_STREAM);
    CHECK(rd_tcp(s, &v) == 0); EXPECT_EQ(v, 1);
    s_close(s);
}
TEST(dsm_v6only_udp_default_is_on) {
    SOCKET s; int v, l;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_DGRAM);
    CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 1); EXPECT_EQ(l, 1);
    s_close(s);
}
TEST(dsm_v6only_tcp_value_normalised_to_bool) {
    static const int vals[] = { 0, 1, 2, 3, -1, 0x100, 0x7fffffff };
    SOCKET s; int v;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_STREAM);
    for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) {
        CHECK(s_v6only(s, vals[i]) == 0);
        CHECK(rd_tcp(s, &v) == 0);
        CHECKF(v == (vals[i] != 0), "set %d reads %d", vals[i], v);
    }
    s_close(s);
}
TEST(dsm_v6only_udp_value_normalised_to_bool) {
    SOCKET s; int v, l;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_DGRAM);
    CHECK(s_v6only(s, 0) == 0); CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 0);
    CHECK(s_v6only(s, 2) == 0); CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 1);
    CHECK(s_v6only(s, 0) == 0); CHECK(s_v6only(s, -1) == 0); CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 1);
    s_close(s);
}
TEST(dsm_v6only_tcp_set_length_rules) {
    SOCKET s; int v;
    if (!s_up()) return;
    for (int ol = 0; ol <= 8; ol++) {
        char b[16] = { 0 }; int rc;
        s = s_open(AF_INET6, SOCK_STREAM);
        rc = U(setsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, b, ol);   /* value 0 in the first four bytes */
        if (ol < 4) { CHECKF(rc != 0 && s_err() == WSAEFAULT, "len %d rc=%d err=%d", ol, rc, s_err()); CHECK(rd_tcp(s, &v) == 0); EXPECT_EQ(v, 1); }
        else { CHECKF(rc == 0, "len %d", ol); CHECK(rd_tcp(s, &v) == 0); EXPECT_EQ(v, 0); }
        s_close(s);
    }
}
TEST(dsm_v6only_udp_set_length_rules) {
    SOCKET s; int v, l;
    if (!s_up()) return;
    for (int ol = 0; ol <= 8; ol++) {
        char b[16] = { 0 }; int rc;
        s = s_open(AF_INET6, SOCK_DGRAM);
        rc = U(setsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, b, ol);
        if (ol < 1) { CHECKF(rc != 0 && s_err() == WSAEFAULT, "len %d rc=%d err=%d", ol, rc, s_err()); CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 1); }
        else { CHECKF(rc == 0, "len %d", ol); CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 0); }
        s_close(s);
    }
}
TEST(dsm_v6only_tcp_get_length_rules) {
    if (!s_up()) return;
    for (int gl = 0; gl <= 8; gl++) {
        unsigned char b[16]; int l = gl, rc; SOCKET s = s_open(AF_INET6, SOCK_STREAM);
        memset(b, 0x55, sizeof b);
        rc = U(getsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)b, &l);
        if (gl < 4) { CHECKF(rc != 0 && s_err() == WSAEFAULT, "len %d rc=%d err=%d", gl, rc, s_err()); CHECK(b[0] == 0x55); }
        else { CHECKF(rc == 0, "len %d", gl); EXPECT_EQ(l, 4); CHECK(b[0] == 1 && b[1] == 0 && b[2] == 0 && b[3] == 0); CHECK(b[4] == 0x55); }
        s_close(s);
    }
}
TEST(dsm_v6only_udp_get_length_rules) {
    if (!s_up()) return;
    for (int gl = 0; gl <= 8; gl++) {
        unsigned char b[16]; int l = gl, rc; SOCKET s = s_open(AF_INET6, SOCK_DGRAM);
        memset(b, 0x55, sizeof b);
        rc = U(getsockopt)(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)b, &l);
        if (gl < 1) { CHECKF(rc != 0 && s_err() == WSAEFAULT, "len %d rc=%d err=%d", gl, rc, s_err()); CHECK(b[0] == 0x55); }
        else { CHECKF(rc == 0, "len %d", gl); EXPECT_EQ(l, 1); CHECK(b[0] == 1); CHECK(b[1] == 0x55); }
        s_close(s);
    }
}
TEST(dsm_v6only_on_ipv4_tcp_socket_is_accepted) {
    SOCKET s; int v;
    if (!s_up()) return;
    s = s_open(AF_INET, SOCK_STREAM);
    CHECK(rd_tcp(s, &v) == 0); EXPECT_EQ(v, 1);
    CHECK(s_v6only(s, 1) == 0);
    s_close(s);
}
TEST(dsm_v6only_on_ipv4_udp_socket_is_accepted) {
    SOCKET s; int v, l;
    if (!s_up()) return;
    s = s_open(AF_INET, SOCK_DGRAM);
    CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, 1);
    CHECK(s_v6only(s, 1) == 0);
    s_close(s);
}

/* refusal once the socket has an endpoint: bound, listening, connected, accepted; even the value it already has */
static void tcp_state_case(int state, int to) {
    SOCKET s = s_open(AF_INET6, SOCK_STREAM), peer = INVALID_SOCKET, acc = INVALID_SOCKET, tgt = s; char a[32]; int v, before, rc;
    unsigned short p;
    s_v6only(s, 1 - to);
    s_mkaddr(a, AK_V6LOOP, 0); CHECK(U(bind)(s, (struct sockaddr *)a, SA6LEN) == 0);
    p = s_port(s);
    if (state >= 1) CHECK(U(listen)(s, 2) == 0);
    if (state >= 2) {
        peer = s_open(AF_INET6, SOCK_STREAM); s_mkaddr(a, AK_V6LOOP, p);
        CHECK(s_connect(peer, a, SA6LEN, 3000) == 0);
        if (state == 2) tgt = peer;
        else { CHECK(s_readable(s, 3000)); acc = U(accept)(s, NULL, NULL); tgt = acc; }
    }
    if (tgt != INVALID_SOCKET) {
        CHECK(rd_tcp(tgt, &before) == 0);
        rc = s_v6only(tgt, to);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "state %d to %d rc=%d err=%d", state, to, rc, s_err());
        CHECK(rd_tcp(tgt, &v) == 0);
        CHECKF(v == before, "state %d value changed %d -> %d", state, before, v);
    }
    s_close(acc); s_close(peer); s_close(s);
}
TEST(dsm_v6only_tcp_set_after_bind_is_einval)      { if (!s_up()) return; tcp_state_case(0, 0); tcp_state_case(0, 1); }
TEST(dsm_v6only_tcp_set_after_listen_is_einval)    { if (!s_up()) return; tcp_state_case(1, 0); tcp_state_case(1, 1); }
TEST(dsm_v6only_tcp_set_after_connect_is_einval)   { if (!s_up()) return; tcp_state_case(2, 0); tcp_state_case(2, 1); }
TEST(dsm_v6only_tcp_set_on_accepted_socket_is_einval) { if (!s_up()) return; tcp_state_case(3, 0); tcp_state_case(3, 1); }
TEST(dsm_v6only_udp_set_after_bind_is_einval) {
    if (!s_up()) return;
    for (int to = 0; to < 2; to++) {
        SOCKET s = s_open(AF_INET6, SOCK_DGRAM); char a[32]; int v, l, before, rc;
        s_v6only(s, 1 - to); s_mkaddr(a, AK_V6LOOP, 0);
        CHECK(U(bind)(s, (struct sockaddr *)a, SA6LEN) == 0);
        CHECK(rd_udp(s, &before, &l) == 0);
        rc = s_v6only(s, to);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "to %d rc=%d err=%d", to, rc, s_err());
        CHECK(rd_udp(s, &v, &l) == 0); EXPECT_EQ(v, before);
        s_close(s);
    }
}
TEST(dsm_v6only_set_to_current_value_after_bind_is_still_einval) {
    SOCKET s; char a[32]; int rc;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_STREAM); s_mkaddr(a, AK_V6ANY, 0);
    CHECK(U(bind)(s, (struct sockaddr *)a, SA6LEN) == 0);
    rc = s_v6only(s, 1);
    CHECK(rc != 0 && s_err() == WSAEINVAL);
    s_close(s);
}
TEST(dsm_v6only_set_twice_before_bind_is_fine) {
    SOCKET s; int v;
    if (!s_up()) return;
    s = s_open(AF_INET6, SOCK_STREAM);
    for (int i = 0; i < 4; i++) { CHECK(s_v6only(s, i & 1) == 0); CHECK(rd_tcp(s, &v) == 0); EXPECT_EQ(v, i & 1); }
    s_close(s);
}
TEST(dsm_v6only_accepted_socket_inherits_listener_value) {
    if (!s_up()) return;
    for (int val = 0; val < 2; val++) {
        SOCKET l = s_open(AF_INET6, SOCK_STREAM), c = s_open(AF_INET6, SOCK_STREAM), a; char ad[32]; int v;
        s_v6only(l, val); s_mkaddr(ad, AK_V6LOOP, 0);
        CHECK(U(bind)(l, (struct sockaddr *)ad, SA6LEN) == 0); CHECK(U(listen)(l, 2) == 0);
        s_mkaddr(ad, AK_V6LOOP, s_port(l));
        CHECK(s_connect(c, ad, SA6LEN, 3000) == 0);
        CHECK(s_readable(l, 3000));
        a = U(accept)(l, NULL, NULL);
        CHECK(a != INVALID_SOCKET);
        if (a != INVALID_SOCKET) { CHECK(rd_tcp(a, &v) == 0); CHECKF(v == val, "listener %d accepted %d", val, v); }
        s_close(a); s_close(c); s_close(l);
    }
}
TEST(dsm_v6only_value_decides_mapped_bind_and_v4_reach) {
    /* the option is what separates "bind to v4-mapped works" from WSAEADDRNOTAVAIL */
    if (!s_up()) return;
    for (int val = 0; val < 2; val++) {
        SOCKET s = s_open(AF_INET6, SOCK_STREAM); char a[32]; int rc;
        s_v6only(s, val); s_mkaddr(a, AK_MAPLOOP, 0);
        rc = U(bind)(s, (struct sockaddr *)a, SA6LEN);
        if (val) { CHECK(rc != 0); CHECK(s_err() == WSAEADDRNOTAVAIL); } else CHECK(rc == 0);
        s_close(s);
    }
}
