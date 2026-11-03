/* lift_04: informational and structured socket options.
 * Measures: SO_PROTOCOL_INFOA/W argument validation and content for TCP/UDP over IPv4/IPv6,
 * IP_HDRINCL on non-raw sockets, SO_BSP_STATE contents and sizing (unbound, bound, connected),
 * IP_DONTFRAGMENT defaults per socket type, and IP_MULTICAST_TTL value widths. */
#include "l4.h"

/* ---- SO_PROTOCOL_INFO ---- */

TEST(protoinfo_invalid_socket_is_enotsock)
{
    WSAPROTOCOL_INFOA info; int sz = sizeof info;
    if (!ws_up()) return;
    lset(0);
    EQ(gso(INVALID_SOCKET, SOL_SOCKET, SO_PROTOCOL_INFOA, NULL, NULL), SOCKET_ERROR);
    EQ(lerr(), WSAENOTSOCK);
    lset(0);
    EQ(gso(INVALID_SOCKET, SOL_SOCKET, SO_PROTOCOL_INFOA, &info, &sz), SOCKET_ERROR);
    EQ(sz, sizeof info);             /* length untouched */
    EQ(lerr(), WSAENOTSOCK);
    ws_down();
}

/* A NULL buffer with a valid length is refused with WSAEFAULT and the length is rewritten to the
 * structure size. (A NULL length pointer is not exercised: it faults inside the call.) */
TEST(protoinfo_null_buffer_is_efault_and_reports_size)
{
    int sz = sizeof(WSAPROTOCOL_INFOA); SOCKET s;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sz = 0;
    lset(0);
    EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOA, NULL, &sz), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    EQ(sz, sizeof(WSAPROTOCOL_INFOA));
    sz = 0;
    lset(0);
    EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, NULL, &sz), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    t_note("wide variant leaves the length at %d", sz);   /* observed: not rewritten */
    cl(s); ws_down();
}

TEST(protoinfo_short_buffer_reports_required_size)
{
    WSAPROTOCOL_INFOA info; int sz = sizeof info / 2; SOCKET s;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    lset(0);
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &info, &sz), SOCKET_ERROR);
    EQ(lerr(), WSAEFAULT);
    EQ(sz, sizeof info);
    cl(s); ws_down();
}

TEST(protoinfo_oversized_buffer_length_is_kept)
{
    static WSAPROTOCOL_INFOA info[2]; int sz = sizeof info; SOCKET s;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, info, &sz), 0);
    EQ(sz, sizeof info);             /* a larger buffer: success, length not reduced */
    cl(s); ws_down();
}

static void protoinfo_for(int af, int type, int proto)
{
    SOCKET s; WSAPROTOCOL_INFOA ia; WSAPROTOCOL_INFOW iw; char name[WSAPROTOCOL_LEN + 1];
    int sz;
    if (!ws_up()) return;
    s = sk(af, type, proto);
    if (s == INVALID_SOCKET) { t_skip("family %d unavailable (%d)", af, lerr()); ws_down(); return; }
    ia.szProtocol[0] = 0; iw.szProtocol[0] = 0;
    sz = sizeof ia;
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &ia, &sz), 0);
    EQ(sz, sizeof ia);
    sz = sizeof iw;
    EQ(gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &iw, &sz), 0);
    EQ(sz, sizeof iw);
    CHECK(ia.szProtocol[0] != 0);
    CHECK(iw.szProtocol[0] != 0);
    WideCharToMultiByte(CP_ACP, 0, iw.szProtocol, -1, name, sizeof name, NULL, NULL);
    CHECK(!strcmp(ia.szProtocol, name));
    /* everything ahead of the protocol name is identical between the two layouts */
    CHECK(!memcmp(&ia, &iw, FIELD_OFFSET(WSAPROTOCOL_INFOA, szProtocol)));
    EQ(ia.iAddressFamily, af);
    EQ(ia.iSocketType, type);
    EQ(ia.iProtocol, proto);
    cl(s); ws_down();
}

TEST(protoinfo_tcp4) { protoinfo_for(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
TEST(protoinfo_udp4) { protoinfo_for(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
TEST(protoinfo_tcp6) { protoinfo_for(AF_INET6, SOCK_STREAM, IPPROTO_TCP); }
TEST(protoinfo_udp6) { protoinfo_for(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); }

/* ---- IP_HDRINCL on non-raw sockets ---- */

static void hdrincl_for(int af, int type, int proto)
{
    SOCKET s; int k, sz = sizeof k;
    if (!ws_up()) return;
    s = sk(af, type, proto);
    if (s == INVALID_SOCKET) { t_skip("family %d unavailable", af); ws_down(); return; }
    k = 1;
    SetLastError(0xdeadbeef);
    EQ(sso(s, IPPROTO_IP, IP_HDRINCL, &k, sz), SOCKET_ERROR);
    EQ(lerr(), WSAEINVAL);
    k = 99; SetLastError(0xdeadbeef);
    EQ(gso(s, IPPROTO_IP, IP_HDRINCL, &k, &sz), SOCKET_ERROR);
    EQ(lerr(), WSAEINVAL);
    EQ(k, 99);                       /* output untouched on failure */
    sz = sizeof k; k = 0; SetLastError(0xdeadbeef);
    EQ(sso(s, IPPROTO_IP, IP_HDRINCL, &k, sz), SOCKET_ERROR);   /* even clearing it is refused */
    EQ(lerr(), WSAEINVAL);
    cl(s); ws_down();
}
TEST(hdrincl_tcp4_rejected) { hdrincl_for(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
TEST(hdrincl_udp4_rejected) { hdrincl_for(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
TEST(hdrincl_tcp6_rejected) { hdrincl_for(AF_INET6, SOCK_STREAM, IPPROTO_TCP); }
TEST(hdrincl_udp6_rejected) { hdrincl_for(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); }

/* ---- SO_BSP_STATE ---- */

typedef union { CSADDR_INFO cs; char space[128]; } csbuf;

/* Pair whose connecting side is explicitly bound to loopback first. */
static int make_pair_bound(SOCKET *a, SOCKET *b)
{
    struct sockaddr_in addr, me; int len = sizeof addr;
    SOCKET l = make_listener(0, &addr);
    *a = *b = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *a = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    lo4(&me, 0);
    if (*a == INVALID_SOCKET || U(bind)(*a, (struct sockaddr *)&me, sizeof me) ||
        U(connect)(*a, (struct sockaddr *)&addr, sizeof addr)) { cl(l); return 0; }
    bound_socket(l);
    *b = U(accept)(l, (struct sockaddr *)&addr, &len);
    cl(l);
    return *b != INVALID_SOCKET;
}

TEST(bspstate_unbound_has_no_addresses)
{
    SOCKET s; csbuf b; int sz = sizeof b;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&b, 0x55, sizeof b);
    EQ(gso(s, SOL_SOCKET, SO_BSP_STATE, &b, &sz), 0);
    EQ(b.cs.LocalAddr.iSockaddrLength, 0);
    CHECK(b.cs.LocalAddr.lpSockaddr == NULL);
    EQ(b.cs.RemoteAddr.iSockaddrLength, 0);
    CHECK(b.cs.RemoteAddr.lpSockaddr == NULL);
    cl(s); ws_down();
}

TEST(bspstate_bound_has_local_only)
{
    SOCKET s; csbuf b; int sz = sizeof b; struct sockaddr_in a;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    lo4(&a, 0);
    EQ(U(bind)(s, (struct sockaddr *)&a, sizeof a), 0);
    EQ(gso(s, SOL_SOCKET, SO_BSP_STATE, &b, &sz), 0);
    CHECK(b.cs.LocalAddr.iSockaddrLength != 0);
    CHECK(b.cs.LocalAddr.lpSockaddr != NULL);
    EQ(b.cs.RemoteAddr.iSockaddrLength, 0);
    CHECK(b.cs.RemoteAddr.lpSockaddr == NULL);
    cl(s); ws_down();
}

TEST(bspstate_connected_pair_mirrors_addresses)
{
    SOCKET s, t; csbuf ca, cb; int sz = sizeof ca, alen = sizeof(struct sockaddr_in);
    struct sockaddr_in a, n;
    if (!ws_up()) return;
    if (!make_pair_bound(&s, &t)) { CHECK(0); ws_down(); return; }
    EQ(gso(s, SOL_SOCKET, SO_BSP_STATE, &ca, &sz), 0);
    sz = sizeof cb;
    EQ(gso(t, SOL_SOCKET, SO_BSP_STATE, &cb, &sz), 0);
    EQ(sz, sizeof cb);               /* the supplied length comes back unchanged */
    EQ(ca.cs.LocalAddr.iSockaddrLength, sizeof a);
    EQ(ca.cs.RemoteAddr.iSockaddrLength, sizeof a);
    CHECK(!memcmp(ca.cs.LocalAddr.lpSockaddr, cb.cs.RemoteAddr.lpSockaddr, sizeof a));
    CHECK(!memcmp(cb.cs.LocalAddr.lpSockaddr, ca.cs.RemoteAddr.lpSockaddr, sizeof a));
    EQ(ca.cs.iSocketType, SOCK_STREAM);
    EQ(cb.cs.iSocketType, SOCK_STREAM);
    EQ(ca.cs.iProtocol, IPPROTO_TCP);
    EQ(cb.cs.iProtocol, IPPROTO_TCP);
    /* the embedded addresses agree with getsockname / getpeername */
    alen = sizeof n;
    EQ(U(getpeername)(s, (struct sockaddr *)&n, &alen), 0);
    CHECK(!memcmp(&n, ca.cs.RemoteAddr.lpSockaddr, sizeof n));
    CHECK(!memcmp(&n, cb.cs.LocalAddr.lpSockaddr, sizeof n));
    alen = sizeof n;
    EQ(U(getsockname)(s, (struct sockaddr *)&n, &alen), 0);
    CHECK(!memcmp(&n, ca.cs.LocalAddr.lpSockaddr, sizeof n));
    CHECK(!memcmp(&n, cb.cs.RemoteAddr.lpSockaddr, sizeof n));
    cl(s); cl(t); ws_down();
}

/* Without an explicit bind the connecting side's recorded local address is the wildcard address
 * with the port the stack picked. */
TEST(bspstate_implicit_bind_reports_wildcard_address)
{
    SOCKET s, t; csbuf c; int sz = sizeof c, alen = sizeof(struct sockaddr_in);
    struct sockaddr_in *la, n;
    if (!ws_up()) return;
    if (!make_pair(&s, &t, 0)) { CHECK(0); ws_down(); return; }
    EQ(gso(s, SOL_SOCKET, SO_BSP_STATE, &c, &sz), 0);
    la = (struct sockaddr_in *)c.cs.LocalAddr.lpSockaddr;
    EQ(U(getsockname)(s, (struct sockaddr *)&n, &alen), 0);
    EQ(la->sin_family, AF_INET);
    EQ(la->sin_addr.s_addr, 0);
    EQ(la->sin_port, n.sin_port);
    cl(s); cl(t); ws_down();
}

TEST(bspstate_buffer_sizing)
{
    SOCKET s, t; csbuf c; int sz;
    if (!ws_up()) return;
    if (!make_pair(&s, &t, 0)) { CHECK(0); ws_down(); return; }
    /* a buffer holding only the bare structure is too small for the two addresses that follow it */
    sz = sizeof(CSADDR_INFO);
    SetLastError(0xdeadbeef);
    NE(gso(s, SOL_SOCKET, SO_BSP_STATE, &c, &sz), 0);
    EQ(sz, sizeof(CSADDR_INFO));
    EQ(lerr(), WSAEFAULT);
    /* structure plus two IPv4 socket addresses is exactly enough; one byte less is not */
    sz = sizeof(struct sockaddr) * 2 + sizeof(CSADDR_INFO);
    EQ(gso(s, SOL_SOCKET, SO_BSP_STATE, &c, &sz), 0);
    sz--;
    SetLastError(0xdeadbeef);
    NE(gso(s, SOL_SOCKET, SO_BSP_STATE, &c, &sz), 0);
    EQ(lerr(), WSAEFAULT);
    cl(s); cl(t); ws_down();
}

/* ---- IP_DONTFRAGMENT ---- */

static void dontfrag_for(int af, int level)
{
    SOCKET s; DWORD v; int sz = sizeof v;
    if (!ws_up()) return;

    /* datagram sockets start with the flag clear and treat any non-zero value as "on" */
    s = sk(af, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) { t_skip("family %d unavailable", af); ws_down(); return; }
    v = 0xdead;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 0);
    v = 1;
    EQ(sso(s, level, IP_DONTFRAGMENT, &v, sizeof v), 0);
    v = 0xdead;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 1);
    v = 0xdead;
    EQ(sso(s, level, IP_DONTFRAGMENT, &v, sizeof v), 0);
    v = 0;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 1);
    cl(s);

    /* stream sockets start with the flag set */
    s = sk(af, SOCK_STREAM, 0);
    v = 0xdead;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 1);
    v = 0;
    EQ(sso(s, level, IP_DONTFRAGMENT, &v, sizeof v), 0);
    v = 0xdead;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 0);
    cl(s);

    /* raw sockets need elevation; skip the raw part without it */
    s = sk(af, SOCK_RAW, 0);
    if (s == INVALID_SOCKET) { t_skip("raw sockets unavailable (%d)", lerr()); ws_down(); return; }
    v = 0xdead;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 0);
    v = 1;
    EQ(sso(s, level, IP_DONTFRAGMENT, &v, sizeof v), 0);
    v = 0xdead;
    EQ(gso(s, level, IP_DONTFRAGMENT, &v, &sz), 0);
    EQ(v, 1);
    cl(s); ws_down();
}
TEST(dontfragment_ipv4) { dontfrag_for(AF_INET, IPPROTO_IP); }
TEST(dontfragment_ipv6) { dontfrag_for(AF_INET6, IPPROTO_IPV6); }

/* ---- IP_MULTICAST_TTL widths ---- */

/* A write of 1..4 bytes stores exactly that many low bytes; the 4-byte read returns them zero-extended. */
TEST(multicast_ttl_value_widths)
{
    static const int vals[] = { (int)0xffffff0a, (int)0xffff000b, (int)0xff00000c, 0x0000000d };
    SOCKET s; int i, k, sz = sizeof k, ten = 10;
    if (!ws_up()) return;
    s = sk(AF_INET, SOCK_DGRAM, 0);
    EQ(sso(s, IPPROTO_IP, IP_MULTICAST_TTL, &ten, sizeof ten), 0);
    for (i = 0; i < 4; i++) {
        int want = i != 3 ? vals[i] & ((1 << ((i + 1) * 8)) - 1) : vals[i];
        sz = sizeof k;
        k = 0x7777;
        CHECKF(sso(s, IPPROTO_IP, IP_MULTICAST_TTL, &vals[i], i + 1) == 0, "width %d err %d", i + 1, lerr());
        CHECKF(gso(s, IPPROTO_IP, IP_MULTICAST_TTL, &k, &sz) == 0, "width %d get err %d", i + 1, lerr());
        CHECKF(k == want, "width %d: got 0x%x want 0x%x", i + 1, k, want);
    }
    cl(s); ws_down();
}
