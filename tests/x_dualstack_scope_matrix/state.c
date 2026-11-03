/* Calls whose result depends on socket state and family: name queries on unbound sockets, listen/accept/connect/bind
 * state errors for IPv4, dual-stack and V6ONLY TCP sockets, accept and getsockname name-buffer sizes for IPv4 and
 * IPv6 peers, UDP connect to mapped/IPv6/wildcard destinations, flow information on bind, and the V6ONLY option's
 * effect on connect after bind. Loopback only. */
#include "sm.h"

static const int KINDS[3] = { SK_V4, SK_V6D, SK_V6O };
static int ak_loop(int sk) { return sk == SK_V4 ? AK_V4LOOP : AK_V6LOOP; }

TEST(dsm_state_getsockname_unbound_is_einval) {
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) for (int ty = 0; ty < 2; ty++) {
        SOCKET s = s_mk(KINDS[k], ty ? SOCK_DGRAM : SOCK_STREAM); struct sockaddr_in6 n; int nl = sizeof n, rc;
        rc = U(getsockname)(s, (struct sockaddr *)&n, &nl);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "%s ty %d rc=%d err=%d", SK_NAME[KINDS[k]], ty, rc, s_err());
        s_close(s);
    }
}
TEST(dsm_state_getpeername_unconnected_is_enotconn) {
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) {
        SOCKET s = s_mk(KINDS[k], SOCK_STREAM); struct sockaddr_in6 n; int nl = sizeof n, rc;
        rc = U(getpeername)(s, (struct sockaddr *)&n, &nl);
        CHECKF(rc != 0 && s_err() == WSAENOTCONN, "%s rc=%d err=%d", SK_NAME[KINDS[k]], rc, s_err());
        s_close(s);
    }
}
TEST(dsm_state_listen_unbound_is_einval) {
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) {
        SOCKET s = s_mk(KINDS[k], SOCK_STREAM); int rc = U(listen)(s, 1);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "%s", SK_NAME[KINDS[k]]);
        s_close(s);
    }
}
TEST(dsm_state_bind_twice_is_einval) {
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) {
        SOCKET s = s_mk(KINDS[k], SOCK_STREAM); char a[32]; int l = s_mkaddr(a, ak_loop(KINDS[k]), 0), rc;
        CHECK(U(bind)(s, (struct sockaddr *)a, l) == 0);
        l = s_mkaddr(a, ak_loop(KINDS[k]), s_port(s));
        rc = U(bind)(s, (struct sockaddr *)a, l);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "%s rc=%d err=%d", SK_NAME[KINDS[k]], rc, s_err());
        s_close(s);
    }
}
TEST(dsm_state_listener_state_errors) {
    unsigned long on = 1;
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) {
        SOCKET s = s_mk(KINDS[k], SOCK_STREAM), a; char ad[32]; int l = s_mkaddr(ad, ak_loop(KINDS[k]), 0), rc, nl; struct sockaddr_in6 n;
        CHECK(U(bind)(s, (struct sockaddr *)ad, l) == 0);
        U(ioctlsocket)(s, FIONBIO, &on);
        nl = sizeof n; a = U(accept)(s, (struct sockaddr *)&n, &nl);
        CHECKF(a == INVALID_SOCKET && s_err() == WSAEINVAL, "%s accept before listen err %d", SK_NAME[KINDS[k]], s_err());
        s_close(a);
        CHECK(U(listen)(s, 1) == 0);
        CHECKF(U(listen)(s, 1) == 0, "listen twice");
        nl = sizeof n; a = U(accept)(s, (struct sockaddr *)&n, &nl);
        CHECKF(a == INVALID_SOCKET && s_err() == WSAEWOULDBLOCK, "%s accept with nothing pending err %d", SK_NAME[KINDS[k]], s_err());
        s_close(a);
        l = s_mkaddr(ad, ak_loop(KINDS[k]), s_port(s));
        rc = U(connect)(s, (struct sockaddr *)ad, l);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "%s connect on listener err %d", SK_NAME[KINDS[k]], s_err());
        rc = U(bind)(s, (struct sockaddr *)ad, l);
        CHECKF(rc != 0 && s_err() == WSAEINVAL, "%s bind on listener err %d", SK_NAME[KINDS[k]], s_err());
        s_close(s);
    }
}
/* accept(): the name buffer must hold the peer's name: 16 bytes for an IPv4 peer on an IPv4 listener, 28 on any IPv6 listener */
static void accept_sizes(int lsk) {
    static const int sizes[] = { 0, 4, 15, 16, 27, 28 };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        SOCKET l = s_mk(lsk, SOCK_STREAM), c, a; char ad[32], buf[64]; int len = s_mkaddr(ad, ak_loop(lsk), 0), nl, need = lsk == SK_V4 ? 16 : 28;
        CHECK(U(bind)(l, (struct sockaddr *)ad, len) == 0); CHECK(U(listen)(l, 2) == 0);
        s_mkaddr(ad, ak_loop(lsk), s_port(l));
        c = s_mk(lsk == SK_V4 ? SK_V4 : SK_V6D, SOCK_STREAM);
        CHECK(s_connect(c, ad, len, 3000) == 0);
        CHECK(s_readable(l, 3000));
        memset(buf, 0xcc, sizeof buf); nl = sizes[i];
        a = U(accept)(l, (struct sockaddr *)buf, &nl);
        if (sizes[i] >= need) { CHECKF(a != INVALID_SOCKET, "%s size %d", SK_NAME[lsk], sizes[i]); EXPECT_EQ(nl, need); }
        else { CHECKF(a == INVALID_SOCKET && s_err() == WSAEFAULT, "%s size %d err %d", SK_NAME[lsk], sizes[i], s_err()); EXPECT_EQ(nl, sizes[i]); }
        s_close(a); s_close(c); s_close(l);
    }
}
TEST(dsm_state_accept_name_sizes_v4_listener)   { accept_sizes(SK_V4); }
TEST(dsm_state_accept_name_sizes_dual_listener) { accept_sizes(SK_V6D); }
TEST(dsm_state_accept_name_sizes_v6only_listener) { accept_sizes(SK_V6O); }
TEST(dsm_state_getsockname_short_buffer) {
    static const int sizes[] = { 0, 8, 16, 27, 28, 40 };
    if (!s_up()) return;
    for (int k = 0; k < 3; k++) for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        SOCKET s = s_mk(KINDS[k], SOCK_STREAM); char ad[32], buf[64]; int len = s_mkaddr(ad, ak_loop(KINDS[k]), 0), nl = sizes[i], rc, need = KINDS[k] == SK_V4 ? 16 : 28;
        CHECK(U(bind)(s, (struct sockaddr *)ad, len) == 0);
        rc = U(getsockname)(s, (struct sockaddr *)buf, &nl);
        if (sizes[i] >= need) { CHECKF(rc == 0, "%s %d", SK_NAME[KINDS[k]], sizes[i]); EXPECT_EQ(nl, need); }
        else { CHECKF(rc != 0 && s_err() == WSAEFAULT, "%s %d err %d", SK_NAME[KINDS[k]], sizes[i], s_err()); EXPECT_EQ(nl, sizes[i]); }
        s_close(s);
    }
}
TEST(dsm_state_bind_ignores_flowinfo) {
    SOCKET s; char a[32]; struct sockaddr_in6 n; int nl = sizeof n;
    if (!s_up()) return;
    s = s_mk(SK_V6D, SOCK_STREAM); s_mkaddr(a, AK_V6LOOP, 0);
    ((struct sockaddr_in6 *)a)->sin6_flowinfo = 0x12345;
    CHECK(U(bind)(s, (struct sockaddr *)a, SA6LEN) == 0);
    CHECK(U(getsockname)(s, (struct sockaddr *)&n, &nl) == 0);
    EXPECT_EQ(n.sin6_flowinfo, 0);
    s_close(s);
}

struct uc { int sk, tak, err; const char *peer, *name; };
static const struct uc UC[] = {
    { SK_V6D, AK_MAPLOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28" },
    { SK_V6O, AK_MAPLOOP, 10049, "", "" },
    { SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28" },
    { SK_V4, AK_V4LOOP, 0, "v4:loop:len16", "v4:loop:len16" },
    { SK_V6D, AK_V4LOOP, 10014, "", "" },
    { SK_V4, AK_MAPLOOP, 10047, "", "" },
    { SK_V6D, AK_MAPANY, 10049, "", "" },
    { SK_V6D, AK_V6ANY, 10049, "", "" },
    { SK_V4, AK_V4ANY, 10049, "", "" },
};
TEST(dsm_state_udp_connect_matrix) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof UC / sizeof *UC; i++) {
        SOCKET s = s_mk(UC[i].sk, SOCK_DGRAM); char a[32], d[64]; int l = s_mkaddr(a, UC[i].tak, s_h16(9)), rc, e = 0;
        rc = U(connect)(s, (struct sockaddr *)a, l);
        if (rc) e = s_err();
        CHECKF(e == UC[i].err, "%s -> %s err %d want %d", SK_NAME[UC[i].sk], AK_NAME[UC[i].tak], e, UC[i].err);
        if (!UC[i].err) {
            struct sockaddr_in6 n; int nl = sizeof n;
            CHECK(U(getpeername)(s, (struct sockaddr *)&n, &nl) == 0); s_desc(&n, nl, d, sizeof d);
            CHECKF(!strcmp(d, UC[i].peer), "peer %s want %s", d, UC[i].peer);
            nl = sizeof n; CHECK(U(getsockname)(s, (struct sockaddr *)&n, &nl) == 0); s_desc(&n, nl, d, sizeof d);
            CHECKF(!strcmp(d, UC[i].name), "name %s want %s", d, UC[i].name);
        }
        s_close(s);
    }
}
TEST(dsm_state_v6only_reset_after_bind_does_not_change_mapped_reach) {
    SOCKET ls; char a[32]; unsigned short p;
    if (!s_up()) return;
    ls = s_mk(SK_V4, SOCK_STREAM); s_mkaddr(a, AK_V4LOOP, 0);
    CHECK(U(bind)(ls, (struct sockaddr *)a, SA4LEN) == 0); CHECK(U(listen)(ls, 2) == 0); p = s_port(ls);
    for (int v = 0; v < 2; v++) {
        SOCKET c = s_open(AF_INET6, SOCK_STREAM); int e;
        s_v6only(c, v); s_mkaddr(a, AK_V6ANY, 0);
        CHECK(U(bind)(c, (struct sockaddr *)a, SA6LEN) == 0);
        CHECK(s_v6only(c, 1 - v) != 0); CHECK(s_err() == WSAEINVAL);
        s_mkaddr(a, AK_MAPLOOP, p);
        e = s_connect(c, a, SA6LEN, 3000);
        CHECKF(e == (v ? WSAEADDRNOTAVAIL : 0), "V6ONLY %d connect-to-mapped err %d", v, e);
        s_close(c);
    }
    s_close(ls);
}
