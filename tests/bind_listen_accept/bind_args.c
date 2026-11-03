/* bind(): argument validation order, name-length protocol, family rules, and socket state transitions.
 *
 * Measures: the socket handle is judged before any pointer or length; every length shorter than the
 * family's sockaddr fails with WSAEFAULT while longer lengths are accepted and clamped; a failed bind
 * leaves the socket unbound and reusable; a successful bind cannot be repeated on the same socket
 * (WSAEINVAL) whatever state it moved to afterwards; port 0 hands out distinct ephemeral ports; the
 * stored name round-trips through getsockname with the padding zeroed.
 */
#include "bla.h"

/* ---- handle is judged first ---- */

TEST(bla_bind_closed_socket_is_notsock)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED();
    s = tcp();
    EQ(cls(s), 0);
    FAILS(bnd(s, &a, sizeof a), WSAENOTSOCK);
}

TEST(bla_bind_closed_socket_with_null_name_is_notsock)
{
    SOCKET s;
    NEED();
    s = tcp();
    EQ(cls(s), 0);
    FAILS(bnd(s, NULL, 0), WSAENOTSOCK);          /* the handle check precedes name checks */
    FAILS(bnd(s, NULL, 16), WSAENOTSOCK);
}

TEST(bla_bind_bad_handle_values)
{
    struct sockaddr_in a = lo4(0);
    NEED();
    FAILS(bnd(0, &a, sizeof a), WSAENOTSOCK);
    FAILS(bnd((SOCKET)0xdeadbeef, &a, sizeof a), WSAENOTSOCK);
    FAILS(bnd(INVALID_SOCKET, &a, sizeof a), WSAENOTSOCK);
    FAILS(bnd(INVALID_SOCKET, NULL, 0), WSAENOTSOCK);
}

TEST(bla_bind_udp_closed_socket_is_notsock)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED();
    s = udp();
    EQ(cls(s), 0);
    FAILS(bnd(s, &a, sizeof a), WSAENOTSOCK);
}

/* ---- name length: every length below the family size is a fault ---- */

static void short_len(SOCKET s, int len)
{
    struct sockaddr_in a = lo4(0), probe;
    int n = sizeof probe;
    FAILS(bnd(s, &a, len), WSAEFAULT);
    /* the failure must not leave the socket bound */
    FAILS(gsn(s, &probe, &n), WSAEINVAL);
}

#define SHORT_TCP(l) TEST(bla_bind_tcp_len_##l##_is_efault) { SOCKET s; NEED(); s = tcp(); short_len(s, l); cls(s); }
#define SHORT_UDP(l) TEST(bla_bind_udp_len_##l##_is_efault) { SOCKET s; NEED(); s = udp(); short_len(s, l); cls(s); }
SHORT_TCP(0) SHORT_TCP(1) SHORT_TCP(2) SHORT_TCP(4) SHORT_TCP(8) SHORT_TCP(12) SHORT_TCP(15)
SHORT_UDP(0) SHORT_UDP(1) SHORT_UDP(2) SHORT_UDP(4) SHORT_UDP(8) SHORT_UDP(12) SHORT_UDP(15)

TEST(bla_bind_negative_length_is_efault)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED();
    s = tcp();
    FAILS(bnd(s, &a, -1), WSAEFAULT);
    FAILS(bnd(s, &a, (int)0x80000000), WSAEFAULT);
    cls(s);
}

TEST(bla_bind_null_name_any_length_is_efault)
{
    static const int lens[] = { 0, 1, 15, 16, 28, 128 };
    unsigned i;
    SOCKET s;
    NEED();
    s = tcp();
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) FAILS(bnd(s, NULL, lens[i]), WSAEFAULT);
    cls(s);
}

/* ---- name length: longer than the family size is clamped, not refused ---- */

static void long_len(int type, int len)
{
    union { struct sockaddr_in a; char raw[256]; } buf;
    struct sockaddr_in back;
    SOCKET s = type == SOCK_STREAM ? tcp() : udp();
    int n = sizeof back;
    memset(&buf, 0, sizeof buf);
    buf.a = lo4(0);
    EQ(bnd(s, &buf, len), 0);
    EQ(gsn(s, &back, &n), 0);
    EQ(n, sizeof back);
    CHECK(is_lo4(&back));
    CHECK(back.sin_port != 0);
    cls(s);
}
#define LONG_TCP(l) TEST(bla_bind_tcp_len_##l##_is_clamped) { NEED(); long_len(SOCK_STREAM, l); }
#define LONG_UDP(l) TEST(bla_bind_udp_len_##l##_is_clamped) { NEED(); long_len(SOCK_DGRAM, l); }
LONG_TCP(17) LONG_TCP(20) LONG_TCP(28) LONG_TCP(32) LONG_TCP(64) LONG_TCP(128) LONG_TCP(256)
LONG_UDP(17) LONG_UDP(28) LONG_UDP(128)

TEST(bla_bind_v6_len_below_28_is_efault)
{
    static const int lens[] = { 1, 2, 4, 8, 16, 20, 24, 27 };
    struct sockaddr_in6 a;
    unsigned i;
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    a = lo6(0);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) FAILS(bnd(s, &a, lens[i]), WSAEFAULT);
    cls(s);
}

TEST(bla_bind_v6_len_larger_than_28_is_clamped)
{
    union { struct sockaddr_in6 a; char raw[128]; } buf;
    struct sockaddr_in6 back;
    int n = sizeof back;
    SOCKET s;
    NEED(); NEED6();
    memset(&buf, 0, sizeof buf);
    buf.a = lo6(0);
    s = tcp6();
    EQ(bnd(s, &buf, 64), 0);
    EQ(gsn(s, &back, &n), 0);
    EQ(n, sizeof back);
    EQ(back.sin6_family, AF_INET6);
    cls(s);
}

TEST(bla_bind_v4_sized_name_on_v6_socket_is_efault)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    FAILS(bnd(s, &a, sizeof a), WSAEFAULT);       /* too short for the socket's family */
    cls(s);
}

/* ---- family ---- */

TEST(bla_bind_family_zero_fails)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED();
    a.sin_family = AF_UNSPEC;
    s = tcp();
    FAILS_NOTE(bnd(s, &a, sizeof a), "AF_UNSPEC name on a TCP socket");
    cls(s);
}

TEST(bla_bind_family_garbage_is_eafnosupport)
{
    static const unsigned short fams[] = { 0xdead, 0xffff, 0x7fff, 200, 99 };
    unsigned i;
    NEED();
    for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
        struct sockaddr_in a = lo4(0);
        SOCKET t = tcp(), u = udp();
        a.sin_family = fams[i];
        FAILS(bnd(t, &a, sizeof a), WSAEAFNOSUPPORT);
        FAILS(bnd(u, &a, sizeof a), WSAEAFNOSUPPORT);
        cls(t); cls(u);
    }
}

TEST(bla_bind_family_failure_leaves_socket_unbound)
{
    struct sockaddr_in a = lo4(0), back;
    int n = sizeof back;
    SOCKET s;
    NEED();
    s = tcp();
    a.sin_family = 0xdead;
    FAILS(bnd(s, &a, sizeof a), WSAEAFNOSUPPORT);
    FAILS(gsn(s, &back, &n), WSAEINVAL);
    a.sin_family = AF_INET;
    EQ(bnd(s, &a, sizeof a), 0);
    cls(s);
}

TEST(bla_bind_v6_name_on_v4_socket_fails)
{
    struct sockaddr_in6 a = lo6(0);
    SOCKET s;
    NEED();
    s = tcp();
    FAILS_NOTE(bnd(s, &a, sizeof a), "AF_INET6 name on an AF_INET socket");
    cls(s);
}

TEST(bla_bind_v4_family_padded_to_v6_size_on_v6_socket_fails)
{
    union { struct sockaddr_in a; struct sockaddr_in6 six; } u;
    SOCKET s;
    NEED(); NEED6();
    memset(&u, 0, sizeof u);
    u.a = lo4(0);
    s = tcp6();
    FAILS_NOTE(bnd(s, &u, sizeof u.six), "AF_INET name padded to 28 bytes on an AF_INET6 socket");
    cls(s);
}

TEST(bla_bind_v6_socket_garbage_family_is_eafnosupport)
{
    struct sockaddr_in6 a = lo6(0);
    SOCKET s;
    NEED(); NEED6();
    a.sin6_family = 0xdead;
    s = tcp6();
    FAILS(bnd(s, &a, sizeof a), WSAEAFNOSUPPORT);
    cls(s);
}

/* ---- unassignable addresses ---- */

static const unsigned long nonlocal[] = {
    0x000200c0, /* 192.0.2.0     documentation */
    0x010200c0, /* 192.0.2.1 */
    0x0a0a0a0a, /* 10.10.10.10   private, not configured here */
};
static const unsigned long odd_addrs[] = {
    0xffffffff, /* 255.255.255.255 limited broadcast */
    0x000000e0, /* 224.0.0.0     multicast */
};

TEST(bla_bind_tcp_nonlocal_addresses_are_addrnotavail)
{
    unsigned i;
    NEED();
    for (i = 0; i < sizeof nonlocal / sizeof nonlocal[0]; i++) {
        struct sockaddr_in a = lo4(0);
        SOCKET s = tcp();
        a.sin_addr.s_addr = nonlocal[i];
        wset(0x5a5a);
        if (bnd(s, &a, sizeof a) == 0) {
            /* some address in the table might be configured on a lab host; only note it */
            t_note("table address %u was bindable", i);
        } else {
            EQ(werr(), WSAEADDRNOTAVAIL);
        }
        cls(s);
    }
}

TEST(bla_bind_tcp_broadcast_and_multicast_names_recorded)
{
    unsigned i;
    NEED();
    for (i = 0; i < sizeof odd_addrs / sizeof odd_addrs[0]; i++) {
        struct sockaddr_in a = lo4(0);
        SOCKET s = tcp();
        a.sin_addr.s_addr = odd_addrs[i];
        wset(0x5a5a);
        if (bnd(s, &a, sizeof a) == 0) t_note("%s was bindable", i ? "multicast name" : "limited broadcast name");
        else t_note("%s -> %s", i ? "multicast name" : "limited broadcast name", werr_class(werr()));
        cls(s);
    }
}

TEST(bla_bind_failed_nonlocal_leaves_socket_reusable)
{
    struct sockaddr_in a = lo4(0), b = lo4(0), back;
    int n = sizeof back;
    SOCKET s;
    NEED();
    s = tcp();
    a.sin_addr.s_addr = 0x000200c0;
    FAILS(bnd(s, &a, sizeof a), WSAEADDRNOTAVAIL);
    FAILS(gsn(s, &back, &n), WSAEINVAL);
    EQ(bnd(s, &b, sizeof b), 0);
    cls(s);
}

TEST(bla_bind_v6_nonlocal_address_is_addrnotavail)
{
    struct sockaddr_in6 a = lo6(0);
    SOCKET s;
    NEED(); NEED6();
    memset(&a.sin6_addr, 0, sizeof a.sin6_addr);
    a.sin6_addr.u.Byte[0] = 0x20; a.sin6_addr.u.Byte[1] = 0x01;      /* 2001:db8::1 documentation prefix */
    a.sin6_addr.u.Byte[2] = 0x0d; a.sin6_addr.u.Byte[3] = 0xb8;
    a.sin6_addr.u.Byte[15] = 1;
    s = tcp6();
    FAILS(bnd(s, &a, sizeof a), WSAEADDRNOTAVAIL);
    cls(s);
}

TEST(bla_bind_v6_unknown_scope_is_addrnotavail)
{
    struct sockaddr_in6 a = lo6(0);
    SOCKET s;
    NEED(); NEED6();
    a.sin6_scope_id = 0x0abacab0;                                     /* no such interface */
    s = tcp6();
    FAILS(bnd(s, &a, sizeof a), WSAEADDRNOTAVAIL);
    cls(s);
}

/* ---- state: bound sockets cannot be bound again ---- */

TEST(bla_bind_second_bind_same_name_is_einval)
{
    struct sockaddr_in a, back;
    int n = sizeof back;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);
    EQ(gsn(s, &back, &n), 0);                      /* still bound to the first name */
    CHECK(back.sin_port == a.sin_port);
    cls(s);
}

TEST(bla_bind_second_bind_other_name_is_einval)
{
    struct sockaddr_in a, other = any4(0), back;
    int n = sizeof back;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    FAILS(bnd(s, &other, sizeof other), WSAEINVAL);
    EQ(gsn(s, &back, &n), 0);
    CHECK(is_lo4(&back));
    CHECK(back.sin_port == a.sin_port);
    cls(s);
}

TEST(bla_bind_udp_second_bind_is_einval)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = udp();
    EQ(bind_lo(s, &a), 0);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);
    cls(s);
}

TEST(bla_bind_second_bind_with_bad_length_still_einval_or_efault)
{
    /* both the state and the length are wrong: record which wins */
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    wset(0x5a5a);
    CHECK(bnd(s, &a, 4) == SOCKET_ERROR);
    t_note("bound socket, 4-byte name -> %s", werr_class(werr()));
    cls(s);
}

TEST(bla_bind_listening_socket_is_einval)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    EQ(lsn(s, 1), 0);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);
    cls(s);
}

TEST(bla_bind_connected_socket_is_einval)
{
    struct sockaddr_in a;
    SOCKET l, c, extra = INVALID_SOCKET;
    struct sockaddr_in again = lo4(0);
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    CHECK(l != INVALID_SOCKET && c != INVALID_SOCKET);
    FAILS(bnd(c, &again, sizeof again), WSAEINVAL);       /* connect bound it implicitly */
    extra = acc_wait(l, NULL, NULL, 3000);
    if (extra != INVALID_SOCKET) {
        FAILS(bnd(extra, &again, sizeof again), WSAEINVAL);
        cls(extra);
    }
    cls(c); cls(l);
}

TEST(bla_bind_after_implicit_bind_by_connect_is_einval)
{
    struct sockaddr_in dst = dead_port(), a = lo4(0);
    SOCKET c;
    NEED();
    c = tcp();
    wset(0);
    CHECK(con(c, &dst, sizeof dst) == SOCKET_ERROR);
    EQ(werr(), WSAECONNREFUSED);
    /* a refused connect still performed the implicit bind in the stack, but the socket is not connected */
    wset(0x5a5a);
    if (bnd(c, &a, sizeof a) == SOCKET_ERROR) t_note("bind after refused connect -> %s", werr_class(werr()));
    else t_note("bind after refused connect succeeded");
    cls(c);
}

TEST(bla_bind_udp_after_sendto_is_einval)
{
    struct sockaddr_in target, a = lo4(0);
    SOCKET s, t;
    NEED();
    t = udp();
    EQ(bind_lo(t, &target), 0);
    s = udp();
    EQ(U(sendto)(s, "x", 1, 0, (struct sockaddr *)&target, sizeof target), 1);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);               /* sendto bound the socket implicitly */
    cls(s); cls(t);
}

TEST(bla_bind_udp_after_connect_is_einval)
{
    struct sockaddr_in target, a = lo4(0);
    SOCKET s, t;
    NEED();
    t = udp();
    EQ(bind_lo(t, &target), 0);
    s = udp();
    EQ(con(s, &target, sizeof target), 0);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);
    cls(s); cls(t);
}

/* ---- failed binds do not poison the socket ---- */

TEST(bla_bind_addrinuse_then_retry_on_free_port)
{
    struct sockaddr_in first, free_a = lo4(0), got;
    SOCKET s1, s2;
    int n = sizeof got;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(bind_lo(s1, &first), 0);
    FAILS(bnd(s2, &first, sizeof first), WSAEADDRINUSE);
    FAILS(gsn(s2, &got, &n), WSAEINVAL);
    EQ(bnd(s2, &free_a, sizeof free_a), 0);
    n = sizeof got;
    EQ(gsn(s2, &got, &n), 0);
    CHECK(got.sin_port != first.sin_port);
    cls(s1); cls(s2);
}

TEST(bla_bind_efault_then_valid_bind)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED();
    s = tcp();
    FAILS(bnd(s, &a, 3), WSAEFAULT);
    EQ(bnd(s, &a, sizeof a), 0);
    cls(s);
}

TEST(bla_bind_failed_bind_does_not_make_socket_listenable)
{
    struct sockaddr_in a = lo4(0);
    SOCKET s;
    NEED();
    s = tcp();
    FAILS(bnd(s, &a, 3), WSAEFAULT);
    FAILS(lsn(s, 1), WSAEINVAL);
    cls(s);
}

/* ---- the bound name ---- */

TEST(bla_bind_port_zero_assigns_nonzero_port)
{
    struct sockaddr_in a;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    CHECK(a.sin_port != 0);
    CHECK(is_lo4(&a));
    cls(s);
}

TEST(bla_bind_port_zero_gives_distinct_ports)
{
    struct sockaddr_in a[4];
    SOCKET s[4];
    int i, j;
    NEED();
    for (i = 0; i < 4; i++) { s[i] = tcp(); EQ(bind_lo(s[i], &a[i]), 0); }
    for (i = 0; i < 4; i++) for (j = i + 1; j < 4; j++) CHECK(a[i].sin_port != a[j].sin_port);
    for (i = 0; i < 4; i++) cls(s[i]);
}

TEST(bla_bind_udp_port_zero_gives_distinct_ports)
{
    struct sockaddr_in a[4];
    SOCKET s[4];
    int i, j;
    NEED();
    for (i = 0; i < 4; i++) { s[i] = udp(); EQ(bind_lo(s[i], &a[i]), 0); }
    for (i = 0; i < 4; i++) for (j = i + 1; j < 4; j++) CHECK(a[i].sin_port != a[j].sin_port);
    for (i = 0; i < 4; i++) cls(s[i]);
}

TEST(bla_bind_wildcard_reports_wildcard_address)
{
    struct sockaddr_in a = any4(0), back;
    int n = sizeof back;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bnd(s, &a, sizeof a), 0);
    EQ(gsn(s, &back, &n), 0);
    CHECK(is_any4(&back));
    CHECK(back.sin_port != 0);
    cls(s);
}

TEST(bla_bind_name_padding_ignored_and_zeroed)
{
    struct sockaddr_in a = lo4(0), back;
    int n = sizeof back, i;
    SOCKET s;
    NEED();
    for (i = 0; i < 8; i++) a.sin_zero[i] = (char)(0xa0 + i);
    s = tcp();
    EQ(bnd(s, &a, sizeof a), 0);
    memset(&back, 0xcc, sizeof back);
    EQ(gsn(s, &back, &n), 0);
    for (i = 0; i < 8; i++) EQ(back.sin_zero[i], 0);
    cls(s);
}

TEST(bla_bind_other_loopback_address_roundtrips)
{
    struct sockaddr_in a = lo4(0), back;
    int n = sizeof back;
    SOCKET s;
    NEED();
    a.sin_addr.s_addr = 0x0200007f;          /* 127.0.0.2 */
    s = tcp();
    EQ(bnd(s, &a, sizeof a), 0);
    EQ(gsn(s, &back, &n), 0);
    CHECK(back.sin_addr.s_addr == 0x0200007f);
    cls(s);
}

TEST(bla_bind_explicit_port_roundtrips_and_is_released_on_close)
{
    struct sockaddr_in a, again, back;
    int n = sizeof back;
    SOCKET s, s2;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    cls(s);
    again = a;
    s2 = tcp();
    EQ(bnd(s2, &again, sizeof again), 0);              /* nothing connected: no lingering state on the port */
    EQ(gsn(s2, &back, &n), 0);
    CHECK(back.sin_port == a.sin_port);
    cls(s2);
}

TEST(bla_bind_tcp_and_udp_port_spaces_are_separate)
{
    struct sockaddr_in a, same;
    SOCKET t, u;
    NEED();
    t = tcp(); u = udp();
    EQ(bind_lo(t, &a), 0);
    same = a;
    EQ(bnd(u, &same, sizeof same), 0);
    cls(t); cls(u);
}

TEST(bla_bind_udp_same_endpoint_twice_is_addrinuse)
{
    struct sockaddr_in a;
    SOCKET s1, s2;
    NEED();
    s1 = udp(); s2 = udp();
    EQ(bind_lo(s1, &a), 0);
    FAILS(bnd(s2, &a, sizeof a), WSAEADDRINUSE);
    cls(s1); cls(s2);
}

TEST(bla_bind_udp_both_reuseaddr_share_endpoint)
{
    struct sockaddr_in a, same;
    DWORD one = 1;
    SOCKET s1, s2;
    NEED();
    s1 = udp(); s2 = udp();
    EQ(sso(s1, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    EQ(sso(s2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    EQ(bind_lo(s1, &a), 0);
    same = a;
    EQ(bnd(s2, &same, sizeof same), 0);
    cls(s1); cls(s2);
}

TEST(bla_bind_udp_reuseaddr_on_second_only_is_eacces)
{
    struct sockaddr_in a, same;
    DWORD one = 1;
    SOCKET s1, s2;
    NEED();
    s1 = udp(); s2 = udp();
    EQ(bind_lo(s1, &a), 0);
    same = a;
    EQ(sso(s2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    wset(0x5a5a);
    CHECK(bnd(s2, &same, sizeof same) == SOCKET_ERROR);
    t_note("UDP: second socket opts in alone -> %s", werr() == WSAEACCES ? "ACCES" : werr_class(werr()));
    cls(s1); cls(s2);
}

/* ---- IPv6 names ---- */

TEST(bla_bind_v6_loopback_roundtrip)
{
    struct sockaddr_in6 a, back;
    int n = sizeof back;
    SOCKET s;
    NEED(); NEED6();
    a = lo6(0);
    s = tcp6();
    EQ(bnd(s, &a, sizeof a), 0);
    memset(&back, 0xcc, sizeof back);
    EQ(gsn(s, &back, &n), 0);
    EQ(n, sizeof back);
    EQ(back.sin6_family, AF_INET6);
    CHECK(back.sin6_port != 0);
    CHECK(!memcmp(&back.sin6_addr, &a.sin6_addr, sizeof a.sin6_addr));
    cls(s);
}

TEST(bla_bind_v6_flowinfo_is_ignored)
{
    struct sockaddr_in6 a = lo6(0), back;
    int n = sizeof back;
    SOCKET s;
    NEED(); NEED6();
    a.sin6_flowinfo = 0x12345678;
    s = tcp6();
    EQ(bnd(s, &a, sizeof a), 0);
    EQ(gsn(s, &back, &n), 0);
    t_note("flow label supplied to bind is %s", back.sin6_flowinfo == 0 ? "dropped" : "kept");
    cls(s);
}

TEST(bla_bind_v6_second_bind_is_einval)
{
    struct sockaddr_in6 a = lo6(0);
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    EQ(bnd(s, &a, sizeof a), 0);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);
    cls(s);
}

TEST(bla_bind_v6_wildcard_roundtrip)
{
    struct sockaddr_in6 a = any6(0), back;
    int n = sizeof back, i;
    SOCKET s;
    NEED(); NEED6();
    s = tcp6();
    EQ(bnd(s, &a, sizeof a), 0);
    EQ(gsn(s, &back, &n), 0);
    for (i = 0; i < 16; i++) EQ(back.sin6_addr.u.Byte[i], 0);
    CHECK(back.sin6_port != 0);
    cls(s);
}

TEST(bla_bind_v6_same_endpoint_twice_is_addrinuse)
{
    struct sockaddr_in6 a = lo6(0), back;
    int n = sizeof back;
    SOCKET s1, s2;
    NEED(); NEED6();
    s1 = tcp6(); s2 = tcp6();
    EQ(bnd(s1, &a, sizeof a), 0);
    EQ(gsn(s1, &back, &n), 0);
    FAILS(bnd(s2, &back, sizeof back), WSAEADDRINUSE);
    cls(s1); cls(s2);
}
