/* Address-conflict behaviour of bind() that is not about two plain listeners: what keeps a port occupied,
 * when it is released, and how SO_REUSEADDR / SO_EXCLUSIVEADDRUSE read back and interact with socket state.
 *
 * Checks are limited to outcomes that do not depend on the host's TCP/IP configuration; the rest is recorded.
 */
#include "bla.h"

static int getdw(SOCKET s, int opt, DWORD *v)
{
    int n = sizeof *v;
    *v = 0;
    return gso(s, SOL_SOCKET, opt, v, &n);
}

TEST(bla_reuse_option_defaults_and_roundtrip)
{
    DWORD one = 1, zero = 0, v;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(getdw(s, SO_REUSEADDR, &v), 0);          EQ(v, 0);
    EQ(getdw(s, SO_EXCLUSIVEADDRUSE, &v), 0);   EQ(v, 0);
    EQ(sso(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    EQ(getdw(s, SO_REUSEADDR, &v), 0);          EQ(v, 1);
    EQ(sso(s, SOL_SOCKET, SO_REUSEADDR, &zero, sizeof zero), 0);
    EQ(getdw(s, SO_REUSEADDR, &v), 0);          EQ(v, 0);
    EQ(sso(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one), 0);
    EQ(getdw(s, SO_EXCLUSIVEADDRUSE, &v), 0);   EQ(v, 1);
    EQ(sso(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &zero, sizeof zero), 0);
    EQ(getdw(s, SO_EXCLUSIVEADDRUSE, &v), 0);   EQ(v, 0);
    cls(s);
}

TEST(bla_reuse_option_nonzero_value_reads_back_nonzero)
{
    DWORD big = 0x1234, v;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(sso(s, SOL_SOCKET, SO_REUSEADDR, &big, sizeof big), 0);
    EQ(getdw(s, SO_REUSEADDR, &v), 0);
    CHECK(v != 0);
    t_note("SO_REUSEADDR set with 0x1234 reads back as 0x%x", (unsigned)v);
    cls(s);
}

TEST(bla_reuse_both_options_cannot_be_on_at_once)
{
    DWORD one = 1;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(sso(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one), 0);
    FAILS(sso(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), WSAEINVAL);
    cls(s);
}

TEST(bla_reuse_option_survives_bind)
{
    struct sockaddr_in a;
    DWORD one = 1, v;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(sso(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    EQ(bind_lo(s, &a), 0);
    EQ(getdw(s, SO_REUSEADDR, &v), 0);
    EQ(v, 1);
    EQ(lsn(s, 1), 0);
    EQ(getdw(s, SO_REUSEADDR, &v), 0);
    EQ(v, 1);
    cls(s);
}

TEST(bla_reuse_exclusive_after_bind_recorded)
{
    struct sockaddr_in a;
    DWORD one = 1, v;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    wset(0x5a5a);
    if (sso(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one) == 0) {
        getdw(s, SO_EXCLUSIVEADDRUSE, &v);
        t_note("SO_EXCLUSIVEADDRUSE after bind accepted, reads back %u", (unsigned)v);
    } else {
        t_note("SO_EXCLUSIVEADDRUSE after bind -> %s", werr_class(werr()));
    }
    cls(s);
}

TEST(bla_reuse_reuseaddr_after_bind_recorded)
{
    struct sockaddr_in a;
    DWORD one = 1, v;
    SOCKET s;
    NEED();
    s = tcp();
    EQ(bind_lo(s, &a), 0);
    wset(0x5a5a);
    if (sso(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0) {
        getdw(s, SO_REUSEADDR, &v);
        t_note("SO_REUSEADDR after bind accepted, reads back %u", (unsigned)v);
    } else {
        t_note("SO_REUSEADDR after bind -> %s", werr_class(werr()));
    }
    cls(s);
}

/* ---- port release ---- */

TEST(bla_reuse_port_stays_taken_while_bound_socket_open)
{
    struct sockaddr_in a, again;
    SOCKET s1, s2;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(bind_lo(s1, &a), 0);
    again = a;
    FAILS(bnd(s2, &again, sizeof again), WSAEADDRINUSE);
    cls(s1);
    EQ(bnd(s2, &again, sizeof again), 0);                /* released the moment the owner closes */
    cls(s2);
}

TEST(bla_reuse_port_taken_by_listener_released_on_close)
{
    struct sockaddr_in a, again;
    SOCKET l, s2;
    NEED();
    l = listener(&a, 1);
    s2 = tcp();
    again = a;
    FAILS(bnd(s2, &again, sizeof again), WSAEADDRINUSE);
    cls(l);
    EQ(bnd(s2, &again, sizeof again), 0);
    cls(s2);
}

TEST(bla_reuse_wildcard_blocks_second_wildcard_same_port)
{
    struct sockaddr_in w = any4(0), got;
    int n = sizeof got;
    SOCKET s1, s2;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(bnd(s1, &w, sizeof w), 0);
    EQ(gsn(s1, &got, &n), 0);
    FAILS(bnd(s2, &got, sizeof got), WSAEADDRINUSE);
    cls(s1); cls(s2);
}

TEST(bla_reuse_specific_blocks_same_specific_only)
{
    struct sockaddr_in a, other;
    SOCKET s1, s2;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(bind_lo(s1, &a), 0);
    other = a;
    other.sin_addr.s_addr = 0x0200007f;                  /* 127.0.0.2, same port */
    EQ(bnd(s2, &other, sizeof other), 0);                /* a different address on the same port is a different endpoint */
    cls(s1); cls(s2);
}

TEST(bla_reuse_connection_keeps_port_after_listener_close_recorded)
{
    struct sockaddr_in a, again;
    SOCKET l, c, s, n;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    CHECK(s != INVALID_SOCKET);
    cls(l);
    again = a;
    n = tcp();
    wset(0x5a5a);
    if (bnd(n, &again, sizeof again) == 0) t_note("rebind of a port with a live accepted connection succeeded");
    else t_note("rebind of a port with a live accepted connection -> %s", werr() == WSAEADDRINUSE ? "ADDRINUSE" : werr_class(werr()));
    cls(n);
    if (s != INVALID_SOCKET) cls(s);
    cls(c);
}

TEST(bla_reuse_connection_keeps_port_with_reuseaddr_recorded)
{
    struct sockaddr_in a, again;
    DWORD one = 1;
    SOCKET l, c, s, n;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    cls(l);
    again = a;
    n = tcp();
    EQ(sso(n, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    wset(0x5a5a);
    if (bnd(n, &again, sizeof again) == 0) {
        t_note("rebind with SO_REUSEADDR over a live connection succeeded");
        if (lsn(n, 1) == 0) t_note("and it can listen");
    } else {
        t_note("rebind with SO_REUSEADDR over a live connection -> %s", werr_class(werr()));
    }
    cls(n);
    if (s != INVALID_SOCKET) cls(s);
    cls(c);
}

TEST(bla_reuse_closed_client_port_rebind_recorded)
{
    struct sockaddr_in a, cn, again;
    SOCKET l, c, s, n;
    int len = sizeof cn;
    NEED();
    l = listener(&a, 1);
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    EQ(gsn(c, &cn, &len), 0);
    if (s != INVALID_SOCKET) cls(s);
    cls(c);                                              /* active closer: the endpoint may linger in TIME_WAIT */
    again = cn;
    n = tcp();
    wset(0x5a5a);
    if (bnd(n, &again, sizeof again) == 0) t_note("rebinding the closed client's port succeeded");
    else t_note("rebinding the closed client's port -> %s", werr() == WSAEADDRINUSE ? "ADDRINUSE" : werr_class(werr()));
    cls(n); cls(l);
}

/* ---- UDP ---- */

TEST(bla_reuse_udp_wildcard_then_specific_recorded)
{
    struct sockaddr_in w = any4(0), got, spec;
    int n = sizeof got;
    SOCKET s1, s2;
    NEED();
    s1 = udp(); s2 = udp();
    EQ(bnd(s1, &w, sizeof w), 0);
    EQ(gsn(s1, &got, &n), 0);
    spec = lo4(0);
    spec.sin_port = got.sin_port;
    wset(0x5a5a);
    if (bnd(s2, &spec, sizeof spec) == 0) t_note("UDP: specific address after wildcard on the same port succeeded");
    else t_note("UDP: specific address after wildcard on the same port -> %s", werr() == WSAEADDRINUSE ? "ADDRINUSE" : werr_class(werr()));
    cls(s1); cls(s2);
}

TEST(bla_reuse_udp_exclusive_blocks_reuseaddr_peer)
{
    struct sockaddr_in a, same;
    DWORD one = 1;
    SOCKET s1, s2;
    NEED();
    s1 = udp(); s2 = udp();
    EQ(sso(s1, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one), 0);
    EQ(bind_lo(s1, &a), 0);
    EQ(sso(s2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    same = a;
    wset(0x5a5a);
    CHECK(bnd(s2, &same, sizeof same) == SOCKET_ERROR);   /* an exclusive owner is never shared */
    t_note("UDP exclusive owner vs reuse peer -> %s", werr() == WSAEACCES ? "ACCES" : werr() == WSAEADDRINUSE ? "ADDRINUSE" : werr_class(werr()));
    cls(s1); cls(s2);
}

TEST(bla_reuse_tcp_exclusive_blocks_plain_peer)
{
    struct sockaddr_in a, same;
    DWORD one = 1;
    SOCKET s1, s2;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(sso(s1, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one), 0);
    EQ(bind_lo(s1, &a), 0);
    same = a;
    FAILS(bnd(s2, &same, sizeof same), WSAEADDRINUSE);
    cls(s1); cls(s2);
}

TEST(bla_reuse_tcp_exclusive_blocks_reuseaddr_peer)
{
    struct sockaddr_in a, same;
    DWORD one = 1;
    SOCKET s1, s2;
    NEED();
    s1 = tcp(); s2 = tcp();
    EQ(sso(s1, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one), 0);
    EQ(bind_lo(s1, &a), 0);
    EQ(sso(s2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one), 0);
    same = a;
    wset(0x5a5a);
    CHECK(bnd(s2, &same, sizeof same) == SOCKET_ERROR);
    t_note("TCP exclusive owner vs reuse peer -> %s", werr() == WSAEACCES ? "ACCES" : werr() == WSAEADDRINUSE ? "ADDRINUSE" : werr_class(werr()));
    cls(s1); cls(s2);
}

TEST(bla_reuse_exclusive_listener_accepts_normally)
{
    struct sockaddr_in a;
    DWORD one = 1;
    SOCKET l, c, s;
    NEED();
    l = tcp();
    EQ(sso(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one), 0);
    EQ(bind_lo(l, &a), 0);
    EQ(lsn(l, 1), 0);
    c = dial(&a);
    s = acc_wait(l, NULL, NULL, 3000);
    CHECK(c != INVALID_SOCKET && s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) cls(s);
    if (c != INVALID_SOCKET) cls(c);
    cls(l);
}
