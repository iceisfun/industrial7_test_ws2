/* Interactions between protocol-level options and socket state: options a listener hands to the sockets it accepts,
 * options that exclude each other, levels that alias each other, and the keep-alive ioctl against the TCP keep-alive
 * options. Loopback only, every socket closed. */
#include "spl.h"

#define EINV WSAEINVAL
#define EFLT WSAEFAULT
#define ENOOPT WSAENOPROTOOPT

/* ---- inheritance by accepted sockets ------------------------------------------------------------------------ */
struct inh { int lv, opt, val, mask; };
static const struct inh inherit_tcp[] = {
    {SPL_LVL_TCP, TCP_NODELAY, 1, 0xff},
    {SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 600, -1},
    {SPL_LVL_TCP, SPL_TCP_KEEPCNT, 3, -1},
    {SPL_LVL_TCP, SPL_TCP_KEEPINTVL, 4, -1},
    {SPL_LVL_TCP, SPL_TCP_MAXRT, 9, -1},
    {SPL_LVL_TCP, SPL_TCP_STDURG, 1, 0xff},
    {SPL_LVL_TCP, SPL_TCP_NOURG, 1, 0xff},
    {SPL_LVL_TCP, SPL_TCP_NOSYNRETRIES, 1, 0xff},
    {SPL_LVL_TCP, SPL_TCP_DELAY_FIN_ACK, 1, 0xff},
    {SPL_LVL_IP, SPL_IP_TTL, 33, -1},
    {SPL_LVL_IP, SPL_IP_TOS, 40, -1},
    {SPL_LVL_IP, SPL_IP_DONTFRAGMENT, 0, -1},
};
static void inherit_run(int idx, int set_after_listen)
{
    SOCKET l, c, a; u_short p = 0; struct sockaddr_in d; int e;
    const struct inh *o = &inherit_tcp[idx];
    if (!spl_up()) return;
    l = spl_tcp4(); spl_bind4(l, &p);
    if (!set_after_listen) SEQ(spl_seti(l, o->lv, o->opt, o->val, &e), 0);
    SEQ(spl_listen(l, 2), 0);
    if (set_after_listen) SEQ(spl_seti(l, o->lv, o->opt, o->val, &e), 0);
    c = spl_tcp4(); spl_loop4(&d); d.sin_port = p;
    SEQ(spl_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    a = spl_accept(l, NULL, NULL);
    if (a == INVALID_SOCKET) { t_skip("accept failed"); spl_close(c); spl_close(l); return; }
    {
        int v = spl_rb(a, o->lv, o->opt);
        t_check(((unsigned)v & (unsigned)o->mask) == ((unsigned)o->val & (unsigned)o->mask), __FILE__, __LINE__, "accepted socket inherits",
                "lv %d opt %d: got %d want %d", o->lv, o->opt, v, o->val);
    }
    spl_close(a); spl_close(c); spl_close(l);
}
#define INH_TEST(n, i) TEST(inherit_before_listen_##n) { inherit_run(i, 0); } TEST(inherit_after_listen_##n) { inherit_run(i, 1); }
INH_TEST(nodelay, 0) INH_TEST(keepalive, 1) INH_TEST(keepcnt, 2) INH_TEST(keepintvl, 3) INH_TEST(maxrt, 4)
INH_TEST(stdurg, 5) INH_TEST(nourg, 6) INH_TEST(nosynretries, 7) INH_TEST(delay_fin_ack, 8)
INH_TEST(ttl, 9) INH_TEST(tos, 10) INH_TEST(dontfragment, 11)

TEST(inherit_changes_after_accept_do_not_reach_listener)
{
    SOCKET l, c, a; u_short p = 0; struct sockaddr_in d; int e;
    if (!spl_up()) return;
    l = spl_tcp4(); spl_bind4(l, &p); spl_listen(l, 2);
    c = spl_tcp4(); spl_loop4(&d); d.sin_port = p; spl_connect(c, (struct sockaddr *)&d, sizeof d);
    a = spl_accept(l, NULL, NULL);
    SEQ(spl_seti(a, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 2, &e), 0);
    SEQ(spl_seti(a, SPL_LVL_IP, SPL_IP_TTL, 9, &e), 0);
    SEQ(spl_rb(l, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 10);
    SEQ(spl_rb(l, SPL_LVL_IP, SPL_IP_TTL), 128);
    spl_close(a); spl_close(c); spl_close(l);
}
TEST(ipv6_inherit_hop_limit_and_keepcnt)
{
    SOCKET l, c, a; u_short p = 0; struct sockaddr_in6 d; int e;
    if (!spl_up() || !spl_have6()) return;
    l = spl_tcp6(); spl_bind6(l, &p);
    SEQ(spl_seti(l, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS, 44, &e), 0);
    SEQ(spl_seti(l, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 5, &e), 0);
    spl_listen(l, 2);
    c = spl_tcp6(); spl_loop6(&d); d.sin6_port = p; SEQ(spl_connect(c, (struct sockaddr *)&d, sizeof d), 0);
    a = spl_accept(l, NULL, NULL);
    SEQ(spl_rb(a, SPL_LVL_IPV6, SPL_IPV6_UNICAST_HOPS), 44);
    SEQ(spl_rb(a, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 5);
    spl_close(a); spl_close(c); spl_close(l);
}

/* ---- DONTFRAGMENT versus MTU_DISCOVER ------------------------------------------------------------------------- */
static SOCKET mk_udp4(void) { return spl_udp4(); }
static SOCKET mk_tcp4(void) { return spl_tcp4(); }
static SOCKET mk_udp6(void) { return spl_udp6(); }
static SOCKET mk_tcp6(void) { return spl_tcp6(); }

/* Either option is refused while the other is in force: IP_MTU_DISCOVER is refused (with every value, zero included)
 * once IP_DONTFRAGMENT has ever been written, and IP_DONTFRAGMENT is refused while a non-zero IP_MTU_DISCOVER mode is set. */
static void mtud_df_run(SOCKET (*mk)(void), int lv, int df, int mtud)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = mk();
    if (s == INVALID_SOCKET) { t_skip("socket creation failed: %d", spl_WSAGetLastError()); return; }
    /* Writing the don't-fragment flag first pins the path-MTU mode. */
    SEQ(spl_seti(s, lv, df, 1, &e), 0);
    SEQ(spl_seti(s, lv, mtud, 1, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_seti(s, lv, mtud, 0, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_seti(s, lv, df, 0, &e), 0);
    SEQ(spl_seti(s, lv, mtud, 2, &e), SOCKET_ERROR); SEQ(e, EINV);     /* still refused after clearing the flag */
    SEQ(spl_rb(s, lv, mtud), 0);
    spl_close(s);
    /* A non-zero path-MTU mode blocks the flag; returning to zero releases it. */
    s = mk();
    SEQ(spl_seti(s, lv, mtud, 2, &e), 0);
    SEQ(spl_seti(s, lv, df, 1, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_seti(s, lv, df, 0, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_rb(s, lv, df) & 1, 0);
    SEQ(spl_seti(s, lv, mtud, 0, &e), 0);
    SEQ(spl_seti(s, lv, df, 1, &e), 0);
    SEQ(spl_rb(s, lv, df), 1);
    spl_close(s);
    /* Setting the mode to zero never pins anything. */
    s = mk();
    SEQ(spl_seti(s, lv, mtud, 0, &e), 0);
    SEQ(spl_seti(s, lv, df, 1, &e), 0);
    SEQ(spl_seti(s, lv, df, 0, &e), 0);
    SEQ(spl_rb(s, lv, mtud), 0);
    spl_close(s);
}
TEST(dontfragment_and_mtu_discover_exclude_each_other_udp4) { mtud_df_run(mk_udp4, SPL_LVL_IP, SPL_IP_DONTFRAGMENT, SPL_IP_MTU_DISCOVER); }
TEST(dontfragment_and_mtu_discover_exclude_each_other_tcp4) { mtud_df_run(mk_tcp4, SPL_LVL_IP, SPL_IP_DONTFRAGMENT, SPL_IP_MTU_DISCOVER); }
TEST(dontfragment_and_mtu_discover_exclude_each_other_udp6) { mtud_df_run(mk_udp6, SPL_LVL_IPV6, SPL_IPV6_DONTFRAG, SPL_IPV6_MTU_DISCOVER); }
TEST(dontfragment_and_mtu_discover_exclude_each_other_tcp6) { mtud_df_run(mk_tcp6, SPL_LVL_IPV6, SPL_IPV6_DONTFRAG, SPL_IPV6_MTU_DISCOVER); }
TEST(dontfragment_and_mtu_discover_exclude_each_other_udp4_through_ipv6_level) { mtud_df_run(mk_udp4, SPL_LVL_IPV6, SPL_IPV6_DONTFRAG, SPL_IPV6_MTU_DISCOVER); }
TEST(ipv4_level_dontfragment_on_ipv6_socket_is_refused)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_udp6();
    if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; }
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_DONTFRAGMENT, 1, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_seti(s, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 2, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}
TEST(mtu_discover_refused_on_listener_after_dontfragment_but_accepted_socket_inherits_flag)
{
    SOCKET l, c, a; u_short p = 0; struct sockaddr_in d; int e;
    if (!spl_up()) return;
    l = spl_tcp4(); spl_bind4(l, &p);
    SEQ(spl_seti(l, SPL_LVL_IP, SPL_IP_DONTFRAGMENT, 0, &e), 0);
    SEQ(spl_seti(l, SPL_LVL_IP, SPL_IP_MTU_DISCOVER, 2, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_listen(l, 2);
    c = spl_tcp4(); spl_loop4(&d); d.sin_port = p; spl_connect(c, (struct sockaddr *)&d, sizeof d);
    a = spl_accept(l, NULL, NULL);
    SEQ(spl_rb(c, SPL_LVL_IP, SPL_IP_DONTFRAGMENT), 1);        /* TCP default */
    SEQ(spl_rb(a, SPL_LVL_IP, SPL_IP_DONTFRAGMENT), 0);        /* inherited from the listener */
    spl_close(a); spl_close(c); spl_close(l);
}

/* ---- the protection level is one option reachable through both levels ------------------------------------------ */
TEST(protection_level_shared_between_ip_and_ipv6_levels_on_ipv4_socket)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_rb(s, SPL_LVL_IP, 23), 10);
    SEQ(spl_rb(s, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL), 10);
    SEQ(spl_seti(s, SPL_LVL_IPV6, SPL_IPV6_PROTECTION_LEVEL, 20, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_IP, 23), 20);
    SEQ(spl_seti(s, SPL_LVL_IP, 23, 5, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}

/* ---- source-specific membership --------------------------------------------------------------------------------- */
TEST(ip_source_membership_add_and_drop)
{
    SOCKET s; struct ip_mreq_source m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    memset(&m, 0, sizeof m);
    m.imr_multiaddr.s_addr = 0xfb0000e0u; m.imr_interface.s_addr = 0x0100007f; m.imr_sourceaddr.s_addr = 0x0200007f;
    SEQ(spl_set(s, SPL_LVL_IP, 15, &m, sizeof m, &e), 0);        /* IP_ADD_SOURCE_MEMBERSHIP */
    SEQ(spl_set(s, SPL_LVL_IP, 16, &m, sizeof m, &e), 0);        /* IP_DROP_SOURCE_MEMBERSHIP */
    spl_close(s);
}
TEST(ip_source_filter_block_and_unblock_need_a_membership)
{
    SOCKET s; struct ip_mreq_source m; int e;
    if (!spl_up()) return;
    s = spl_udp4();
    memset(&m, 0, sizeof m);
    m.imr_multiaddr.s_addr = 0xfb0000e0u; m.imr_interface.s_addr = 0x0100007f; m.imr_sourceaddr.s_addr = 0x0200007f;
    SEQ(spl_set(s, SPL_LVL_IP, 17, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EINV);   /* IP_BLOCK_SOURCE */
    SEQ(spl_set(s, SPL_LVL_IP, 18, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EINV);   /* IP_UNBLOCK_SOURCE */
    spl_close(s);
}
TEST(ip_membership_refused_on_tcp_socket)
{
    SOCKET s; struct ip_mreq m; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    memset(&m, 0, sizeof m); m.imr_multiaddr.s_addr = 0xfb0000e0u; m.imr_interface.s_addr = 0x0100007f;
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_ADD_MEMBERSHIP, &m, sizeof m, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_set(s, SPL_LVL_IP, SPL_IP_MULTICAST_IF, &m.imr_interface, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}

/* ---- null and absurd arguments ------------------------------------------------------------------------------------- */
TEST(null_argument_pointers_are_faults)
{
    SOCKET s; int v = 0, l = 4;
    if (!spl_up()) return;
    s = spl_tcp4();
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, TCP_NODELAY, NULL, &l), EFLT);
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, TCP_NODELAY, (char *)&v, NULL), EFLT);
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, TCP_NODELAY, NULL, NULL), EFLT);
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_TCP, TCP_NODELAY, NULL, 4), EFLT);
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_TCP, TCP_NODELAY, NULL, 0), EFLT);
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_IP, SPL_IP_TTL, NULL, 4), EFLT);
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, NULL, 4), EFLT);   /* wrong level for TCP, but the pointer is judged first */
    SEQ(spl_rb(s, SPL_LVL_TCP, TCP_NODELAY) & 0xff, 0);
    spl_close(s);
}
TEST(negative_and_huge_option_lengths)
{
    SOCKET s; int v = 1, l;
    if (!spl_up()) return;
    s = spl_udp4();
    l = -1;
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_IP, SPL_IP_TTL, (char *)&v, &l), EFLT);
    l = 0x7fffffff;
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_IP, SPL_IP_TTL, (char *)&v, &l), EFLT);
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_IP, SPL_IP_TTL, (char *)&v, -1), WSAENOBUFS);
    SEQ(spl_rb(s, SPL_LVL_IP, SPL_IP_TTL), 128);
    spl_close(s);
}
TEST(invalid_socket_handles_report_notsock)
{
    SOCKET bad = (SOCKET)0x7ff0; int v = 1, l = 4;
    if (!spl_up()) return;
    SPL_FAILS(spl_getsockopt(bad, SPL_LVL_TCP, TCP_NODELAY, (char *)&v, &l), WSAENOTSOCK);
    SPL_FAILS(spl_setsockopt(bad, SPL_LVL_IP, SPL_IP_TTL, (char *)&v, 4), WSAENOTSOCK);
    SPL_FAILS(spl_getsockopt(INVALID_SOCKET, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, (char *)&v, &l), WSAENOTSOCK);
}
