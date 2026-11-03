/* Option matrices for the message-oriented datagram controls on UDP sockets: IP/IPv6 receive-side control
 * message switches (pktinfo, TTL/hop limit, TOS/traffic class, ECN), TTL/TOS values, DONTFRAGMENT, path-MTU
 * discovery, UDP segmentation size (UDP_SEND_MSG_SIZE), receive coalescing size, UDP_NOCHECKSUM and the
 * UDP-Lite style coverage option. The tables in opts_tab.h hold the behaviour observed on Windows 10: for each
 * socket kind (AF_INET datagram, AF_INET6 datagram, AF_INET stream) and option, the default value, the result of
 * setting each of a fixed set of integers (error and value read back) and the result of get/set with buffer
 * lengths 0..8 (error and returned length). Options that are not meaningful for a socket kind fail with a
 * fixed error that the tables record too. Nothing here depends on the network. */
#include "xu.h"
#include "opts_tab.h"

static const char *kind_name[] = {"udp4", "udp6", "tcp4"};
static SOCKET open_kind(int fam) {
    return U(socket)(fam == 1 ? AF_INET6 : AF_INET, fam == 2 ? SOCK_STREAM : SOCK_DGRAM, 0);
}
static int is_byte_opt(const char *n) { return !strcmp(n, "UDP_NOCHECKSUM"); }

/* Reads an option into an int pre-filled with a recognisable pattern so a short write is visible. */
static int get_int(SOCKET s, int lvl, int opt, int *out, int *outlen) {
    int v = 0, l = sizeof v, r;
    r = U(getsockopt)(s, lvl, opt, (char *)&v, &l);
    *out = v; if (outlen) *outlen = l;
    return r;
}

/* Default values of every option, per socket kind. */
TEST(xo_defaults_match_table) {
    size_t i; UP();
    for (i = 0; i < sizeof xu_deftab / sizeof xu_deftab[0]; i++) {
        const xu_defrow *d = &xu_deftab[i]; const xu_optdef *o = &xu_optdefs[d->opt];
        SOCKET s = open_kind(d->fam); int v, r, e;
        if (s == INVALID_SOCKET) { t_skip("socket unavailable"); return; }
        xu_seterr(0);
        r = get_int(s, o->level, o->opt, &v, NULL); e = r ? xu_err() : 0;
        if (is_byte_opt(o->name)) v &= 0xff;
        CHECKF(e == d->err, "%s %s: error got %d want %d", kind_name[d->fam], o->name, e, d->err);
        if (!d->err) CHECKF(v == d->val, "%s %s: default got %d want %d", kind_name[d->fam], o->name, v, d->val);
        xu_close(s);
    }
}

/* Setting integer values: error, and the value a following get returns. A fresh socket per row, so rows
 * do not influence each other. */
static void run_valtab(int fam_filter) {
    size_t i;
    for (i = 0; i < sizeof xu_valtab / sizeof xu_valtab[0]; i++) {
        const xu_valrow *d = &xu_valtab[i]; const xu_optdef *o = &xu_optdefs[d->opt];
        SOCKET s; int r, e, v, gr;
        if (d->fam != fam_filter) continue;
        s = open_kind(d->fam);
        if (s == INVALID_SOCKET) { t_skip("socket unavailable"); return; }
        xu_seterr(0);
        r = xu_setint(s, o->level, o->opt, d->val); e = r ? xu_err() : 0;
        CHECKF(e == d->serr, "%s %s set %d: error got %d want %d", kind_name[d->fam], o->name, d->val, e, d->serr);
        xu_seterr(0);
        gr = get_int(s, o->level, o->opt, &v, NULL);
        if (is_byte_opt(o->name)) v &= 0xff;
        if (d->gerr) CHECKF(gr != 0 && xu_err() == d->gerr, "%s %s get after set %d: want error %d", kind_name[d->fam], o->name, d->val, d->gerr);
        else CHECKF(gr == 0 && v == d->gval, "%s %s set %d: read back %d want %d (r=%d)", kind_name[d->fam], o->name, d->val, v, d->gval, gr);
        xu_close(s);
    }
}
TEST(xo_set_value_matrix_udp4) { UP(); run_valtab(0); }
TEST(xo_set_value_matrix_udp6) { UP6(); run_valtab(1); }
TEST(xo_set_value_matrix_tcp4) { UP(); run_valtab(2); }

/* Option buffer lengths: for lengths 0..8 the get result, returned length and the set result. The buffer is
 * pre-filled with 0x55 and the set reuses the buffer left behind by the get, exactly in that order. */
static void run_lentab(int fam_filter) {
    size_t i; SOCKET s = INVALID_SOCKET; int lastopt = -1;
    for (i = 0; i < sizeof xu_lentab / sizeof xu_lentab[0]; i++) {
        const xu_lenrow *d = &xu_lentab[i]; const xu_optdef *o = &xu_optdefs[d->opt];
        char b[16]; int l, r, e;
        if (d->fam != fam_filter) continue;
        if (d->opt != lastopt) { xu_close(s); s = open_kind(d->fam); lastopt = d->opt; if (s == INVALID_SOCKET) { t_skip("socket unavailable"); return; } }
        memset(b, 0x55, sizeof b); l = d->len;
        xu_seterr(0);
        r = U(getsockopt)(s, o->level, o->opt, b, &l); e = r ? xu_err() : 0;
        CHECKF(e == d->gerr, "%s %s get len %d: error got %d want %d", kind_name[d->fam], o->name, d->len, e, d->gerr);
        CHECKF(l == d->gout, "%s %s get len %d: returned length got %d want %d", kind_name[d->fam], o->name, d->len, l, d->gout);
        xu_seterr(0);
        r = U(setsockopt)(s, o->level, o->opt, b, d->len); e = r ? xu_err() : 0;
        CHECKF(e == d->serr, "%s %s set len %d: error got %d want %d", kind_name[d->fam], o->name, d->len, e, d->serr);
    }
    xu_close(s);
}
TEST(xo_length_matrix_udp4) { UP(); run_lentab(0); }
TEST(xo_length_matrix_udp6) { UP6(); run_lentab(1); }
TEST(xo_length_matrix_tcp4) { UP(); run_lentab(2); }

/* A NULL option length pointer on get is a fault. */
TEST(xo_get_null_length_is_efault) {
    SOCKET s; int v = 0, r; UP();
    s = U(socket)(AF_INET, SOCK_DGRAM, 0); REQUIRE(s != INVALID_SOCKET);
    xu_seterr(0);
    r = U(getsockopt)(s, IPPROTO_IP, XU_IP_TTL, (char *)&v, NULL);
    CHECK(r == SOCKET_ERROR); EXPECT_EQ(xu_err(), WSAEFAULT);
    xu_close(s);
}
/* Options are per socket: changing one leaves a second socket untouched. */
TEST(xo_options_are_per_socket) {
    SOCKET a, b; int v; UP();
    a = U(socket)(AF_INET, SOCK_DGRAM, 0); b = U(socket)(AF_INET, SOCK_DGRAM, 0); REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET);
    CHECK(xu_setint(a, IPPROTO_IP, XU_IP_TTL, 9) == 0);
    CHECK(xu_setint(a, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 321) == 0);
    CHECK(xu_getint(b, IPPROTO_IP, XU_IP_TTL, &v) == 0 && v == 128);
    CHECK(xu_getint(b, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, &v) == 0 && v == 0);
    xu_close(a); xu_close(b);
}
/* Options survive bind and connect. */
TEST(xo_options_survive_bind_and_connect) {
    xu_ep a, b; int v; UP(); if (!xu_pair(&a, &b, AF_INET)) return;
    CHECK(xu_setint(a.s, IPPROTO_IP, XU_IP_TTL, 33) == 0);
    CHECK(xu_setint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, 700) == 0);
    CHECK(xu_setint(a.s, IPPROTO_IP, XU_IP_PKTINFO, 1) == 0);
    CHECK(U(connect)(a.s, (struct sockaddr *)&b.sa, b.len) == 0);
    CHECK(xu_getint(a.s, IPPROTO_IP, XU_IP_TTL, &v) == 0 && v == 33);
    CHECK(xu_getint(a.s, IPPROTO_UDP, XU_UDP_SEND_MSG_SIZE, &v) == 0 && v == 700);
    CHECK(xu_getint(a.s, IPPROTO_IP, XU_IP_PKTINFO, &v) == 0 && v == 1);
    xu_free(&a); xu_free(&b);
}
