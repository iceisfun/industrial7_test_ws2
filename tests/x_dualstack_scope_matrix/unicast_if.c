/* IP_UNICAST_IF / IPV6_UNICAST_IF (option 31 at IPPROTO_IP and IPPROTO_IPV6): argument forms, per-level byte
 * order, which socket families accept which level, option-length rules, read-back, and use on loopback
 * connections.  The loopback interface index is resolved at run time (never hard-coded). */
#include "sm.h"

enum { LV_IP, LV_IP6 };
static int level_of(int lv) { return lv == LV_IP ? IPPROTO_IP : IPPROTO_IPV6; }
static const char *const LVN[2] = { "ip", "ipv6" };

static int set_uif(SOCKET s, int lv, unsigned v) { return U(setsockopt)(s, level_of(lv), 31, (const char *)&v, 4); }
static int get_uif(SOCKET s, int lv, unsigned *v) { int l = 4; *v = 0xdeadbeef; return U(getsockopt)(s, level_of(lv), 31, (char *)v, &l); }

/* IPv4-style semantics: the 32-bit value is the interface index in network byte order; the read-back is host order.
 * Applies to IPv4 sockets at both levels and to dual-stack IPv6 sockets at the IP level. */
static void v4style(int sk, int ty, int lv) {
    SOCKET s; unsigned idx = s_loopidx(), v; int rc;
    if (!s_up()) return;
    if (!idx) { t_skip("no loopback interface index"); return; }
    s = s_mk(sk, ty);
    CHECK(get_uif(s, lv, &v) == 0); EXPECT_EQ(v, 0);
    CHECK(set_uif(s, lv, 0) == 0);
    rc = set_uif(s, lv, idx);                 /* host order index is read as a huge network-order number */
    if (idx != s_h32(idx)) { CHECK(rc != 0); CHECK(s_err() == WSAEADDRNOTAVAIL); }
    CHECK(get_uif(s, lv, &v) == 0); EXPECT_EQ(v, 0);
    CHECK(set_uif(s, lv, s_h32(idx)) == 0);
    CHECK(get_uif(s, lv, &v) == 0); EXPECT_EQ(v, idx);
    rc = set_uif(s, lv, 0x7777);
    CHECK(rc != 0); CHECK(s_err() == WSAEADDRNOTAVAIL);
    CHECK(get_uif(s, lv, &v) == 0); EXPECT_EQ(v, idx);   /* a refused value leaves the old one */
    CHECK(set_uif(s, lv, 0) == 0);
    CHECK(get_uif(s, lv, &v) == 0); EXPECT_EQ(v, 0);
    s_close(s);
}
/* IPv6 semantics: the value is the index in host order and must name an existing interface */
static void v6style(int sk, int ty) {
    SOCKET s; unsigned idx = s_loopidx(), v; int rc;
    if (!s_up()) return;
    if (!idx) { t_skip("no loopback interface index"); return; }
    s = s_mk(sk, ty);
    CHECK(get_uif(s, LV_IP6, &v) == 0); EXPECT_EQ(v, 0);
    CHECK(set_uif(s, LV_IP6, idx) == 0);
    CHECK(get_uif(s, LV_IP6, &v) == 0); EXPECT_EQ(v, idx);
    rc = set_uif(s, LV_IP6, 0x7777);
    CHECK(rc != 0); CHECK(s_err() == WSAEINVAL);
    rc = set_uif(s, LV_IP6, 0xffffffffu);
    CHECK(rc != 0); CHECK(s_err() == WSAEINVAL);
    if (idx != s_h32(idx)) { rc = set_uif(s, LV_IP6, s_h32(idx)); CHECK(rc != 0); CHECK(s_err() == WSAEINVAL); }
    CHECK(get_uif(s, LV_IP6, &v) == 0); EXPECT_EQ(v, idx);
    CHECK(set_uif(s, LV_IP6, 0) == 0);
    CHECK(get_uif(s, LV_IP6, &v) == 0); EXPECT_EQ(v, 0);
    s_close(s);
}
TEST(dsm_uif_v4_tcp_ip_level)            { v4style(SK_V4, SOCK_STREAM, LV_IP); }
TEST(dsm_uif_v4_udp_ip_level)            { v4style(SK_V4, SOCK_DGRAM, LV_IP); }
TEST(dsm_uif_v4_tcp_ipv6_level_is_ip_semantics) { v4style(SK_V4, SOCK_STREAM, LV_IP6); }
TEST(dsm_uif_v4_udp_ipv6_level_is_ip_semantics) { v4style(SK_V4, SOCK_DGRAM, LV_IP6); }
TEST(dsm_uif_dual_tcp_ip_level)          { v4style(SK_V6D, SOCK_STREAM, LV_IP); }
TEST(dsm_uif_dual_udp_ip_level)          { v4style(SK_V6D, SOCK_DGRAM, LV_IP); }
TEST(dsm_uif_dual_tcp_ipv6_level)        { v6style(SK_V6D, SOCK_STREAM); }
TEST(dsm_uif_dual_udp_ipv6_level)        { v6style(SK_V6D, SOCK_DGRAM); }
TEST(dsm_uif_v6only_tcp_ipv6_level)      { v6style(SK_V6O, SOCK_STREAM); }
TEST(dsm_uif_v6only_udp_ipv6_level)      { v6style(SK_V6O, SOCK_DGRAM); }

/* a V6ONLY socket has no IPv4 side: every set at the IP level is WSAEINVAL whatever the value or length, get reports 0 */
static void v6only_ip_level(int ty) {
    SOCKET s; unsigned v; static const unsigned vals[] = { 0, 1, 0x01000000u, 0x7777, 0xffffffffu };
    if (!s_up()) return;
    s = s_mk(SK_V6O, ty);
    CHECK(get_uif(s, LV_IP, &v) == 0); EXPECT_EQ(v, 0);
    for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) { CHECK(set_uif(s, LV_IP, vals[i]) != 0); CHECK(s_err() == WSAEINVAL); }
    for (int ol = 0; ol <= 8; ol += 2) { char b[8] = { 0 }; CHECK(U(setsockopt)(s, IPPROTO_IP, 31, b, ol) != 0); CHECK(s_err() == WSAEINVAL); }
    CHECK(get_uif(s, LV_IP, &v) == 0); EXPECT_EQ(v, 0);
    s_close(s);
}
TEST(dsm_uif_v6only_tcp_ip_level_refused) { v6only_ip_level(SOCK_STREAM); }
TEST(dsm_uif_v6only_udp_ip_level_refused) { v6only_ip_level(SOCK_DGRAM); }

/* option length: fewer than 4 bytes is WSAEFAULT where the level is usable, 4 or more is taken */
static void lens(int sk, int ty, int lv) {
    SOCKET s;
    if (!s_up()) return;
    s = s_mk(sk, ty);
    for (int ol = 0; ol <= 8; ol += 2) {
        char b[8] = { 0 }; int rc = U(setsockopt)(s, level_of(lv), 31, b, ol);
        if (ol < 4) { CHECKF(rc != 0 && s_err() == WSAEFAULT, "%s len %d rc=%d err=%d", LVN[lv], ol, rc, s_err()); }
        else CHECKF(rc == 0, "%s len %d rc=%d err=%d", LVN[lv], ol, rc, s_err());
    }
    s_close(s);
}
TEST(dsm_uif_option_length_v4_ip)        { lens(SK_V4, SOCK_STREAM, LV_IP); lens(SK_V4, SOCK_DGRAM, LV_IP); }
TEST(dsm_uif_option_length_v4_ipv6level) { lens(SK_V4, SOCK_STREAM, LV_IP6); }
TEST(dsm_uif_option_length_dual_ip)      { lens(SK_V6D, SOCK_STREAM, LV_IP); lens(SK_V6D, SOCK_DGRAM, LV_IP); }
TEST(dsm_uif_option_length_dual_ipv6)    { lens(SK_V6D, SOCK_STREAM, LV_IP6); lens(SK_V6D, SOCK_DGRAM, LV_IP6); }
TEST(dsm_uif_option_length_v6only_ipv6)  { lens(SK_V6O, SOCK_STREAM, LV_IP6); lens(SK_V6O, SOCK_DGRAM, LV_IP6); }

/* using the option: loopback connections stay possible with the loopback interface selected */
TEST(dsm_uif_v4_connect_with_loopback_selected) {
    SOCKET l, c; char a[32]; unsigned idx = s_loopidx();
    if (!s_up()) return;
    if (!idx) { t_skip("no loopback interface index"); return; }
    l = s_mk(SK_V4, SOCK_STREAM); s_mkaddr(a, AK_V4LOOP, 0);
    CHECK(U(bind)(l, (struct sockaddr *)a, SA4LEN) == 0); CHECK(U(listen)(l, 2) == 0);
    s_mkaddr(a, AK_V4LOOP, s_port(l));
    c = s_mk(SK_V4, SOCK_STREAM);
    CHECK(set_uif(c, LV_IP, s_h32(idx)) == 0);
    CHECK(s_connect(c, a, SA4LEN, 3000) == 0);
    CHECK(s_readable(l, 3000));
    s_close(c); s_close(l);
}
TEST(dsm_uif_v6_connect_with_loopback_selected) {
    SOCKET l, c; char a[32]; unsigned idx = s_loopidx();
    if (!s_up()) return;
    if (!idx) { t_skip("no loopback interface index"); return; }
    l = s_mk(SK_V6D, SOCK_STREAM); s_mkaddr(a, AK_V6LOOP, 0);
    CHECK(U(bind)(l, (struct sockaddr *)a, SA6LEN) == 0); CHECK(U(listen)(l, 2) == 0);
    s_mkaddr(a, AK_V6LOOP, s_port(l));
    c = s_mk(SK_V6D, SOCK_STREAM);
    CHECK(set_uif(c, LV_IP6, idx) == 0);
    CHECK(s_connect(c, a, SA6LEN, 3000) == 0);
    CHECK(s_readable(l, 3000));
    s_close(c); s_close(l);
}
TEST(dsm_uif_v4_connect_with_host_order_index_is_refused_at_set) {
    SOCKET c; unsigned idx = s_loopidx();
    if (!s_up()) return;
    if (!idx || idx == s_h32(idx)) { t_skip("index is its own byte swap"); return; }
    c = s_mk(SK_V4, SOCK_STREAM);
    CHECK(set_uif(c, LV_IP, idx) != 0); CHECK(s_err() == WSAEADDRNOTAVAIL);
    s_close(c);
}
