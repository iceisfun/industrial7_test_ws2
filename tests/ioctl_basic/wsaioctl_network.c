/* Measures the network-facing WSAIoctl controls on loopback: SIO_UDP_CONNRESET / SIO_UDP_NETRESET behaviour,
 * SIO_RCVALL on a raw socket (elevated only), SIO_ROUTING_INTERFACE_QUERY and _CHANGE argument rules,
 * SIO_ADDRESS_LIST_SORT, SIO_GET_INTERFACE_LIST contents, SIO_ADDRESS_LIST_QUERY per family and the
 * non-blocking behaviour of the change-notification controls.  Facts about the machine's addresses are asserted
 * only as relations (loopback is present, every entry has the socket's family). */
#include "ib.h"

/* ---- SIO_UDP_CONNRESET ------------------------------------------------------------------------ */
/* Send one datagram to a closed loopback port; return the error of the following receive (bounded). */
static int ib_udp_send_to_dead_port(int connreset_mode)
{
    /* connreset_mode: -1 leave default, 0 disable, 1 enable */
    SOCKET u = ib_mk(K_UDP4), dead = ib_mk(K_UDP4);
    struct sockaddr_in a, da;
    int len = sizeof da, r, e;
    char b[8];
    DWORD tmo = 600;
    fd_set rf;
    struct timeval tv = {1, 0};
    if (u == INVALID_SOCKET || dead == INVALID_SOCKET) return -1000;
    ib_loop4(&a, 0); ib_loop4(&da, 0);
    U(bind)(u, (struct sockaddr *)&a, sizeof a);
    U(bind)(dead, (struct sockaddr *)&da, sizeof da);
    U(getsockname)(dead, (struct sockaddr *)&da, &len);
    ib_close(dead);
    if (connreset_mode >= 0) {
        DWORD v = (DWORD)connreset_mode;
        ib_res x = ib_io(u, IB_UDP_CONNRESET, &v, 4, NULL, 0, 1);
        if (!IB_OK(x)) { ib_close(u); return -1001; }
    }
    U(sendto)(u, "x", 1, 0, (struct sockaddr *)&da, sizeof da);
    FD_ZERO(&rf); FD_SET(u, &rf);
    U(select)(0, &rf, NULL, NULL, &tv);
    U(setsockopt)(u, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    r = U(recv)(u, b, sizeof b, 0);
    e = ib_err();
    ib_close(u);
    return r == SOCKET_ERROR ? e : 0;
}

IBTEST(ib_udp_connreset_default_reports_connreset_on_receive)
{
    int e = ib_udp_send_to_dead_port(-1);
    CHECKF(e == WSAECONNRESET, "err=%d", e);
}

IBTEST(ib_udp_connreset_enabled_reports_connreset_on_receive)
{
    int e = ib_udp_send_to_dead_port(1);
    CHECKF(e == WSAECONNRESET, "err=%d", e);
}

IBTEST(ib_udp_connreset_disabled_suppresses_the_report)
{
    /* With the report disabled the receive just times out (bounded by SO_RCVTIMEO). */
    int e = ib_udp_send_to_dead_port(0);
    CHECKF(e == WSAETIMEDOUT, "err=%d", e);
}

IBTEST(ib_udp_connreset_nonzero_values_enable)
{
    /* The input is a BOOL: any non-zero value turns the report on again. */
    SOCKET u = ib_mk(K_UDP4);
    DWORD v[3] = {0, 1, 0x100};
    unsigned i;
    REQUIRE(u != INVALID_SOCKET);
    for (i = 0; i < 3; ++i) {
        ib_res x = ib_io(u, IB_UDP_CONNRESET, &v[i], 4, NULL, 0, 1);
        CHECKF(IB_OK(x), "value %#lx: r=%d err=%d", v[i], x.r, x.err);
    }
    ib_close(u);
}

IBTEST(ib_udp_connreset_input_length_rules)
{
    SOCKET u = ib_mk(K_UDP4);
    DWORD v[4] = {0, 0, 0, 0};
    static const struct { unsigned len; int ok; } t[] = {{0, 0}, {1, 1}, {2, 1}, {4, 1}, {8, 1}, {16, 1}};
    unsigned i;
    REQUIRE(u != INVALID_SOCKET);
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        ib_res x = ib_io(u, IB_UDP_CONNRESET, v, t[i].len, NULL, 0, 1);
        if (t[i].ok) CHECKF(IB_OK(x), "len %u: r=%d err=%d", t[i].len, x.r, x.err);
        else CHECKF(IB_FAILS(x, WSAEFAULT), "len %u: r=%d err=%d", t[i].len, x.r, x.err);
    }
    ib_close(u);
}

IBTEST(ib_udp_connreset_byte_count_untouched)
{
    /* Unlike most controls this one does not store a byte count on success. */
    SOCKET u = ib_mk(K_UDP4);
    DWORD v = 1;
    ib_res x;
    REQUIRE(u != INVALID_SOCKET);
    x = ib_io(u, IB_UDP_CONNRESET, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x) && x.n == IB_UNSET, "n=%lu", x.n);
    x = ib_io(u, IB_UDP_NETRESET, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x) && x.n == IB_UNSET, "netreset n=%lu", x.n);
    ib_close(u);
}

IBTEST(ib_udp_connreset_netreset_rejected_on_streams)
{
    static const int kinds[] = {K_TCP4, K_LISTEN4, K_CONN4, K_TCP6};
    static const DWORD codes[] = {IB_UDP_CONNRESET, IB_UDP_NETRESET};
    unsigned i, j;
    for (i = 0; i < 4; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        if (s == INVALID_SOCKET) continue;
        for (j = 0; j < 2; ++j) {
            DWORD v = 1;
            ib_res x = ib_io(s, codes[j], &v, 4, NULL, 0, 1);
            CHECKF(IB_FAILS(x, WSAEINVAL), "kind %d code %#lx: r=%d err=%d", kinds[i], codes[j], x.r, x.err);
        }
        ib_close(s);
    }
}

IBTEST(ib_udp_connreset_ipv6_datagram_accepts)
{
    SOCKET u = ib_mk(K_UDP6);
    DWORD v = 0;
    ib_res x;
    if (u == INVALID_SOCKET) { t_skip("no IPv6 datagram socket"); return; }
    x = ib_io(u, IB_UDP_CONNRESET, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x), "r=%d err=%d", x.r, x.err);
    x = ib_io(u, IB_UDP_NETRESET, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x), "netreset r=%d err=%d", x.r, x.err);
    ib_close(u);
}

/* ---- SIO_RCVALL family (raw socket, elevation required) ------------------------------------------ */
static int ib_is_elevated(void)
{
    SOCKET r = ib_mk(K_RAW4);
    if (r == INVALID_SOCKET) return 0;
    ib_close(r);
    return 1;
}

IBTEST(ib_rcvall_requires_raw_socket)
{
    SOCKET t = ib_mk(K_TCP4), u = ib_mk(K_UDP4);
    DWORD v = RCVALL_ON;
    static const DWORD codes[] = {IB_RCVALL, IB_RCVALL_MCAST, IB_RCVALL_IGMP};
    unsigned i;
    REQUIRE(t != INVALID_SOCKET && u != INVALID_SOCKET);
    for (i = 0; i < 3; ++i) {
        ib_res x = ib_io(t, codes[i], &v, 4, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "tcp code %#lx: r=%d err=%d n=%lu", codes[i], x.r, x.err, x.n);
        x = ib_io(u, codes[i], &v, 4, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "udp code %#lx: r=%d err=%d n=%lu", codes[i], x.r, x.err, x.n);
    }
    ib_close(t); ib_close(u);
}

IBTEST(ib_rcvall_needs_bound_raw_socket_and_valid_mode)
{
    SOCKET r;
    struct sockaddr_in a;
    DWORD v;
    ib_res x;
    if (!ib_is_elevated()) { t_skip("raw sockets need elevation"); return; }
    r = ib_mk(K_RAW4);
    REQUIRE(r != INVALID_SOCKET);
    v = RCVALL_ON;
    x = ib_io(r, IB_RCVALL, &v, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "unbound: r=%d err=%d", x.r, x.err);
    ib_loop4(&a, 0);
    CHECK(U(bind)(r, (struct sockaddr *)&a, sizeof a) == 0);
    v = 7;
    x = ib_io(r, IB_RCVALL, &v, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "mode 7: r=%d err=%d", x.r, x.err);
    v = RCVALL_ON;
    x = ib_io(r, IB_RCVALL, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x), "on: r=%d err=%d", x.r, x.err);
    v = RCVALL_OFF;
    x = ib_io(r, IB_RCVALL, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x), "off: r=%d err=%d", x.r, x.err);
    v = RCVALL_SOCKETLEVELONLY;
    x = ib_io(r, IB_RCVALL, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x), "socket level only: r=%d err=%d", x.r, x.err);
    v = RCVALL_OFF;
    ib_io(r, IB_RCVALL, &v, 4, NULL, 0, 1);
    ib_close(r);
}

IBTEST(ib_rcvall_multicast_and_igmp_variants_accept_on_off)
{
    SOCKET r;
    struct sockaddr_in a;
    static const DWORD codes[] = {IB_RCVALL_MCAST, IB_RCVALL_IGMP};
    unsigned i;
    if (!ib_is_elevated()) { t_skip("raw sockets need elevation"); return; }
    r = ib_mk(K_RAW4);
    REQUIRE(r != INVALID_SOCKET);
    ib_loop4(&a, 0);
    CHECK(U(bind)(r, (struct sockaddr *)&a, sizeof a) == 0);
    for (i = 0; i < 2; ++i) {
        DWORD v = RCVALL_ON;
        ib_res x = ib_io(r, codes[i], &v, 4, NULL, 0, 1);
        CHECKF(IB_OK(x), "code %#lx on: r=%d err=%d", codes[i], x.r, x.err);
        v = RCVALL_OFF;
        x = ib_io(r, codes[i], &v, 4, NULL, 0, 1);
        CHECKF(IB_OK(x), "code %#lx off: r=%d err=%d", codes[i], x.r, x.err);
    }
    ib_close(r);
}

IBTEST(ib_rcvall_unix_socket_is_access_denied_variant)
{
    SOCKET s = ib_mk(K_UNIX);
    DWORD v = RCVALL_ON;
    ib_res x;
    if (s == INVALID_SOCKET) { t_skip("no AF_UNIX"); return; }
    x = ib_io(s, IB_RCVALL, &v, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEACCES) && x.n == 0, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(s);
}

/* ---- SIO_ROUTING_INTERFACE_QUERY ---------------------------------------------------------------- */
IBTEST(ib_routing_query_loopback_destination_returns_loopback_interface_address)
{
    IB_SOCK(u, K_UDP4);
    struct sockaddr_in dst, out;
    ib_res x;
    ib_loop4(&dst, 0);
    memset(&out, 0xcc, sizeof out);
    x = ib_io(u, IB_ROUTING_QUERY, &dst, sizeof dst, &out, sizeof out, 1);
    CHECKF(IB_OK(x) && x.n == sizeof out, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(out.sin_family == AF_INET);
    CHECK(out.sin_addr.s_addr == 0x0100007fu);
    CHECK(out.sin_port == 0);
    ib_close(u);
}

IBTEST(ib_routing_query_short_output_reports_required_size_and_fault)
{
    IB_SOCK(u, K_UDP4);
    struct sockaddr_in dst;
    unsigned char out[16];
    static const unsigned lens[] = {0, 4, 8, 15};
    unsigned i;
    ib_loop4(&dst, 0);
    for (i = 0; i < 4; ++i) {
        ib_res x = ib_io(u, IB_ROUTING_QUERY, &dst, sizeof dst, out, lens[i], 1);
        CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 16, "len %u: r=%d err=%d n=%lu", lens[i], x.r, x.err, x.n);
    }
    ib_close(u);
}

IBTEST(ib_routing_query_unspecified_destination_is_invalid)
{
    static const int kinds[] = {K_UDP4, K_TCP4};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        struct sockaddr_in dst, out;
        ib_res x;
        REQUIRE(s != INVALID_SOCKET);
        ib_loop4(&dst, 0);
        dst.sin_addr.s_addr = 0;
        x = ib_io(s, IB_ROUTING_QUERY, &dst, sizeof dst, &out, sizeof out, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == IB_UNSET, "kind %d: r=%d err=%d n=%lu", kinds[i], x.r, x.err, x.n);
        ib_close(s);
    }
}

IBTEST(ib_routing_query_stream_socket_with_loopback)
{
    IB_SOCK(t, K_TCP4);
    struct sockaddr_in dst, out;
    ib_res x;
    ib_loop4(&dst, 0);
    x = ib_io(t, IB_ROUTING_QUERY, &dst, sizeof dst, &out, sizeof out, 1);
    CHECKF(IB_OK(x) && x.n == sizeof out, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(out.sin_addr.s_addr == 0x0100007fu);
    ib_close(t);
}

IBTEST(ib_routing_query_family_must_match_socket)
{
    SOCKET u4 = ib_mk(K_UDP4), u6 = ib_mk(K_UDP6);
    struct sockaddr_in d4;
    struct sockaddr_in6 d6, o6;
    ib_res x;
    unsigned char out[32];
    REQUIRE(u4 != INVALID_SOCKET);
    if (u6 == INVALID_SOCKET) { ib_close(u4); t_skip("no IPv6"); return; }
    ib_loop4(&d4, 0);
    memset(&d6, 0, sizeof d6);
    d6.sin6_family = AF_INET6;
    d6.sin6_addr.u.Byte[15] = 1;
    x = ib_io(u4, IB_ROUTING_QUERY, &d6, sizeof d6, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEAFNOSUPPORT), "v6 destination on v4 socket: r=%d err=%d", x.r, x.err);
    x = ib_io(u6, IB_ROUTING_QUERY, &d4, sizeof d4, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "v4 destination on v6 socket: r=%d err=%d", x.r, x.err);
    memset(&o6, 0xcc, sizeof o6);
    x = ib_io(u6, IB_ROUTING_QUERY, &d6, sizeof d6, &o6, sizeof o6, 1);
    CHECKF(IB_OK(x) && x.n == sizeof o6, "v6 loopback: r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(o6.sin6_family == AF_INET6);
    CHECK(o6.sin6_addr.u.Byte[15] == 1);
    x = ib_io(u6, IB_ROUTING_QUERY, &d6, sizeof d6, out, 4, 1);
    CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == sizeof o6, "v6 short output: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u4); ib_close(u6);
}

/* ---- non-blocking behaviour of the change notifications ------------------------------------------ */
IBTEST(ib_routing_change_nonblocking_argument_rules)
{
    IB_SOCK(t, K_TCP4);
    struct sockaddr_in a;
    u_long one = 1;
    ib_res x;
    ib_loop4(&a, 0);
    U(ioctlsocket)(t, FIONBIO, &one);
    x = ib_io(t, IB_ROUTING_CHANGE, NULL, 0, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "no input: r=%d err=%d", x.r, x.err);
    x = ib_io(t, IB_ROUTING_CHANGE, &a, 8, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "short input: r=%d err=%d", x.r, x.err);
    x = ib_io(t, IB_ROUTING_CHANGE, &a, sizeof a, NULL, 0, 0);
    CHECKF(IB_FAILS(x, WSAEFAULT), "no byte count: r=%d err=%d", x.r, x.err);
    x = ib_io(t, IB_ROUTING_CHANGE, &a, sizeof a, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEWOULDBLOCK), "valid: r=%d err=%d", x.r, x.err);
    ib_close(t);
}

IBTEST(ib_routing_change_overlapped_pends_until_closed)
{
    IB_SOCK(t, K_TCP4);
    struct sockaddr_in a;
    WSAOVERLAPPED ov;
    DWORD n = IB_UNSET;
    int r;
    ib_loop4(&a, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ib_seterr(0);
    r = U(WSAIoctl)(t, IB_ROUTING_CHANGE, &a, sizeof a, NULL, 0, &n, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSA_IO_PENDING, "r=%d err=%d", r, ib_err());
    CHECK(WaitForSingleObject(ov.hEvent, 200) == WAIT_TIMEOUT);
    ib_close(t);
    CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);   /* closing the socket cancels the request */
    CHECK((NTSTATUS)ov.Internal == (NTSTATUS)0xC0000120);           /* STATUS_CANCELLED */
    CloseHandle(ov.hEvent);
}

IBTEST(ib_routing_change_overlapped_wrong_family_fails_immediately)
{
    SOCKET u6 = ib_mk(K_UDP6);
    struct sockaddr_in a;
    WSAOVERLAPPED ov;
    DWORD n = IB_UNSET;
    int r;
    if (u6 == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    ib_loop4(&a, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    r = U(WSAIoctl)(u6, IB_ROUTING_CHANGE, &a, sizeof a, NULL, 0, &n, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEINVAL, "r=%d err=%d", r, ib_err());
    CHECK(WaitForSingleObject(ov.hEvent, 0) == WAIT_TIMEOUT);
    CloseHandle(ov.hEvent);
    ib_close(u6);
}

IBTEST(ib_address_list_change_nonblocking_argument_rules)
{
    IB_SOCK(t, K_TCP4);
    unsigned char b[16];
    u_long one = 1;
    ib_res x;
    U(ioctlsocket)(t, FIONBIO, &one);
    x = ib_io(t, IB_ADDRLIST_CHANGE, NULL, 0, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEWOULDBLOCK), "plain: r=%d err=%d", x.r, x.err);
    x = ib_io(t, IB_ADDRLIST_CHANGE, b, sizeof b, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "with input: r=%d err=%d", x.r, x.err);
    x = ib_io(t, IB_ADDRLIST_CHANGE, NULL, 0, b, sizeof b, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "with output: r=%d err=%d", x.r, x.err);
    ib_close(t);
}

/* ---- SIO_ADDRESS_LIST_QUERY per family ----------------------------------------------------------- */
static void ib_check_list_family(SOCKET s, int family, int sockaddr_len, const char *what)
{
    union { SOCKET_ADDRESS_LIST l; char raw[2048]; } u;
    ib_res x = ib_io(s, IB_ADDRLIST_QUERY, NULL, 0, u.raw, sizeof u.raw, 1);
    int i;
    CHECKF(IB_OK(x), "%s: r=%d err=%d", what, x.r, x.err);
    if (!IB_OK(x)) return;
    for (i = 0; i < u.l.iAddressCount; ++i) {
        const SOCKADDR *sa = u.l.Address[i].lpSockaddr;
        CHECKF(sa->sa_family == family && u.l.Address[i].iSockaddrLength == sockaddr_len,
               "%s entry %d: family %d len %d", what, i, sa->sa_family, u.l.Address[i].iSockaddrLength);
        CHECKF((const char *)sa >= u.raw && (const char *)sa < u.raw + sizeof u.raw, "%s entry %d lies outside the buffer", what, i);
    }
}

IBTEST(ib_address_list_entries_match_socket_family)
{
    SOCKET a = ib_mk(K_UDP4), b = ib_mk(K_UDP6), c = ib_mk(K_TCP4), d = ib_mk(K_TCP6);
    REQUIRE(a != INVALID_SOCKET);
    ib_check_list_family(a, AF_INET, 16, "udp4");
    ib_check_list_family(c, AF_INET, 16, "tcp4");
    if (b != INVALID_SOCKET) ib_check_list_family(b, AF_INET6, 28, "udp6");
    if (d != INVALID_SOCKET) ib_check_list_family(d, AF_INET6, 28, "tcp6");
    ib_close(a); ib_close(c);
    if (b != INVALID_SOCKET) ib_close(b);
    if (d != INVALID_SOCKET) ib_close(d);
}

IBTEST(ib_address_list_unix_socket_has_empty_list)
{
    SOCKET s = ib_mk(K_UNIX);
    union { SOCKET_ADDRESS_LIST l; char raw[256]; } u;
    ib_res x;
    if (s == INVALID_SOCKET) { t_skip("no AF_UNIX"); return; }
    memset(u.raw, 0xcc, sizeof u.raw);
    x = ib_io(s, IB_ADDRLIST_QUERY, NULL, 0, u.raw, sizeof u.raw, 1);
    CHECKF(IB_OK(x) && x.n == 8 && u.l.iAddressCount == 0, "r=%d err=%d n=%lu count=%d", x.r, x.err, x.n, u.l.iAddressCount);
    x = ib_io(s, IB_ADDRLIST_QUERY, NULL, 0, u.raw, 4, 1);
    CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 8, "short: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(s);
}

IBTEST(ib_address_list_query_input_must_be_empty)
{
    IB_SOCK(u, K_UDP4);
    char in[16] = {0}, out[512];
    ib_res x;
    x = ib_io(u, IB_ADDRLIST_QUERY, in, 4, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "in4: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(u, IB_ADDRLIST_QUERY, in, 16, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "in16: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u);
}

/* ---- SIO_GET_INTERFACE_LIST ---------------------------------------------------------------------- */
IBTEST(ib_interface_list_loopback_entry_shape)
{
    IB_SOCK(u, K_UDP4);
    INTERFACE_INFO info[32];
    ib_res x = ib_io(u, IB_GET_IFLIST, NULL, 0, info, sizeof info, 1);
    unsigned i, n, found = 0;
    CHECKF(IB_OK(x) && x.n && x.n % sizeof(INTERFACE_INFO) == 0, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    n = x.n / sizeof(INTERFACE_INFO);
    for (i = 0; i < n; ++i) {
        if (!(info[i].iiFlags & IFF_LOOPBACK)) continue;
        ++found;
        CHECK(info[i].iiFlags & IFF_UP);
        CHECK(info[i].iiAddress.AddressIn.sin_addr.s_addr == 0x0100007fu);
        CHECK(info[i].iiNetmask.AddressIn.sin_addr.s_addr == 0x000000ffu);
        CHECK(!(info[i].iiFlags & IFF_BROADCAST));
    }
    CHECKF(found == 1, "loopback entries: %u", found);
    ib_close(u);
}

IBTEST(ib_interface_list_is_ipv4_only_and_rejects_ipv6_sockets)
{
    static const int kinds[] = {K_TCP6, K_UDP6};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        INTERFACE_INFO info[8];
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_GET_IFLIST, NULL, 0, info, sizeof info, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "kind %d: r=%d err=%d n=%lu", kinds[i], x.r, x.err, x.n);
        ib_close(s);
    }
}

IBTEST(ib_interface_list_works_on_streams_listeners_and_unbound_alike)
{
    static const int kinds[] = {K_TCP4, K_UDP4, K_LISTEN4, K_CONN4};
    unsigned i;
    DWORD first = 0;
    for (i = 0; i < 4; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        INTERFACE_INFO info[32];
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_GET_IFLIST, NULL, 0, info, sizeof info, 1);
        CHECKF(IB_OK(x), "kind %d: r=%d err=%d", kinds[i], x.r, x.err);
        if (!first) first = x.n;
        CHECKF(x.n == first, "kind %d: n=%lu vs %lu", kinds[i], x.n, first);
        ib_close(s);
    }
}

IBTEST(ib_interface_list_exact_fit_buffer)
{
    IB_SOCK(u, K_UDP4);
    INTERFACE_INFO info[32];
    ib_res x = ib_io(u, IB_GET_IFLIST, NULL, 0, info, sizeof info, 1), y;
    DWORD need;
    CHECK(IB_OK(x));
    need = x.n;
    y = ib_io(u, IB_GET_IFLIST, NULL, 0, info, need, 1);
    CHECKF(IB_OK(y) && y.n == need, "exact: r=%d err=%d n=%lu", y.r, y.err, y.n);
    y = ib_io(u, IB_GET_IFLIST, NULL, 0, info, need - 1, 1);
    CHECKF(IB_FAILS(y, WSAEFAULT) && y.n == 0, "one short: r=%d err=%d n=%lu", y.r, y.err, y.n);
    ib_close(u);
}

/* ---- SIO_ADDRESS_LIST_SORT ------------------------------------------------------------------------ */
/* Build a flat SOCKET_ADDRESS_LIST in buf: header, entries, then the sockaddrs they point to. */
typedef struct { const void *sa; int len; } ib_sa;
static unsigned ib_build_list(unsigned char *buf, const ib_sa *e, int count)
{
    SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)buf;
    unsigned off = (unsigned)(offsetof(SOCKET_ADDRESS_LIST, Address) + count * sizeof(SOCKET_ADDRESS));
    int i;
    l->iAddressCount = count;
    for (i = 0; i < count; ++i) {
        memcpy(buf + off, e[i].sa, e[i].len);
        l->Address[i].lpSockaddr = (LPSOCKADDR)(buf + off);
        l->Address[i].iSockaddrLength = e[i].len;
        off += (e[i].len + 7) & ~7u;
    }
    return off;
}

/* The sorted list is a permutation of the input entries; its sockaddr pointers still refer to the input. */
static int ib_sorted_is_permutation(const unsigned char *in, const unsigned char *out)
{
    const SOCKET_ADDRESS_LIST *a = (const SOCKET_ADDRESS_LIST *)in, *b = (const SOCKET_ADDRESS_LIST *)out;
    int i, j, found;
    if (a->iAddressCount != b->iAddressCount) return 0;
    for (i = 0; i < b->iAddressCount; ++i) {
        found = 0;
        for (j = 0; j < a->iAddressCount; ++j)
            if (b->Address[i].lpSockaddr == a->Address[j].lpSockaddr && b->Address[i].iSockaddrLength == a->Address[j].iSockaddrLength) found = 1;
        if (!found) return 0;
    }
    return 1;
}

IBTEST(ib_address_list_sort_loopback_entries)
{
    SOCKET u6 = ib_mk(K_UDP6), t6 = ib_mk(K_TCP6);
    struct sockaddr_in6 a6, b6;
    unsigned char in[512], out[512];
    ib_sa e[2];
    unsigned inl;
    ib_res x;
    SOCKET_ADDRESS_LIST *o = (SOCKET_ADDRESS_LIST *)out;
    if (u6 == INVALID_SOCKET || t6 == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    memset(&a6, 0, sizeof a6); memset(&b6, 0, sizeof b6);
    a6.sin6_family = AF_INET6; a6.sin6_addr.u.Byte[15] = 1;               /* ::1 */
    b6.sin6_family = AF_INET6; b6.sin6_addr.u.Byte[10] = 0xff; b6.sin6_addr.u.Byte[11] = 0xff;
    b6.sin6_addr.u.Byte[12] = 127; b6.sin6_addr.u.Byte[15] = 1;           /* ::ffff:127.0.0.1 */
    e[0].sa = &b6; e[0].len = sizeof b6;
    e[1].sa = &a6; e[1].len = sizeof a6;
    inl = ib_build_list(in, e, 2);
    memset(out, 0xcc, sizeof out);
    x = ib_io(u6, IB_ADDRLIST_SORT, in, inl, out, sizeof out, 1);
    /* the result holds only the header and the entry array: header 8 bytes + 16 per entry */
    CHECKF(IB_OK(x) && x.n == 40 && o->iAddressCount == 2, "r=%d err=%d n=%lu count=%d", x.r, x.err, x.n, o->iAddressCount);
    CHECK(ib_sorted_is_permutation(in, out));
    memset(out, 0xcc, sizeof out);
    x = ib_io(t6, IB_ADDRLIST_SORT, in, inl, out, sizeof out, 1);
    CHECKF(IB_OK(x) && x.n == 40 && o->iAddressCount == 2, "stream socket: r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(ib_sorted_is_permutation(in, out));
    /* single entry */
    memset(out, 0xcc, sizeof out);
    inl = ib_build_list(in, e + 1, 1);
    x = ib_io(u6, IB_ADDRLIST_SORT, in, inl, out, sizeof out, 1);
    CHECKF(IB_OK(x) && x.n == 24 && o->iAddressCount == 1, "one entry: r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(ib_sorted_is_permutation(in, out));
    x = ib_io(u6, IB_ADDRLIST_SORT, in, inl, out, 24, 1);
    CHECKF(IB_OK(x) && x.n == 24, "exact output: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(u6, IB_ADDRLIST_SORT, in, inl, out, 8, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "output too small: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(u6, IB_ADDRLIST_SORT, in, inl, out, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "no output: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u6); ib_close(t6);
}

IBTEST(ib_address_list_sort_is_ipv6_only)
{
    /* On an IPv4 socket the control is rejected whatever the list holds. */
    IB_SOCK(u, K_UDP4);
    struct sockaddr_in a;
    unsigned char in[256], out[256];
    ib_sa e[1];
    unsigned inl;
    ib_res x;
    ib_loop4(&a, 0);
    e[0].sa = &a; e[0].len = sizeof a;
    inl = ib_build_list(in, e, 1);
    x = ib_io(u, IB_ADDRLIST_SORT, in, inl, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "v4 entry on v4 socket: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u);
}

IBTEST(ib_address_list_sort_plain_ipv4_entry_on_ipv6_socket_is_invalid)
{
    IB_SOCK(u6, K_UDP6);
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
    unsigned char in[256], out[256];
    ib_sa e[2];
    unsigned inl;
    ib_res x;
    ib_loop4(&a4, 0);
    memset(&a6, 0, sizeof a6);
    a6.sin6_family = AF_INET6; a6.sin6_addr.u.Byte[15] = 1;
    e[0].sa = &a4; e[0].len = sizeof a4;
    e[1].sa = &a6; e[1].len = sizeof a6;
    inl = ib_build_list(in, e, 2);
    x = ib_io(u6, IB_ADDRLIST_SORT, in, inl, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u6);
}

IBTEST(ib_address_list_sort_argument_rules)
{
    IB_SOCK(u, K_UDP6);
    struct sockaddr_in6 a;
    unsigned char in[256], out[256];
    ib_sa e[1];
    unsigned inl;
    ib_res x;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    e[0].sa = &a; e[0].len = sizeof a;
    inl = ib_build_list(in, e, 1);
    x = ib_io(u, IB_ADDRLIST_SORT, in, inl, out, sizeof out, 0);
    CHECKF(IB_FAILS(x, WSAEFAULT), "no byte count: r=%d err=%d", x.r, x.err);
    x = ib_io(u, IB_ADDRLIST_SORT, in, 0, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "no input: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(u, IB_ADDRLIST_SORT, in, 3, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "3 byte input: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u);
}

IBTEST(ib_address_list_sort_empty_list)
{
    IB_SOCK(u, K_UDP6);
    unsigned char in[16] = {0}, out[256];
    SOCKET_ADDRESS_LIST *o = (SOCKET_ADDRESS_LIST *)out;
    ib_res x;
    memset(out, 0xcc, sizeof out);
    x = ib_io(u, IB_ADDRLIST_SORT, in, 8, out, sizeof out, 1);
    CHECKF(IB_OK(x) && x.n == 8 && o->iAddressCount == 0, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(u);
}

/* ---- calls before startup / after cleanup --------------------------------------------------------- */
CHILD(ib_ioctl_no_startup)
{
    /* No WSAStartup in this process: every winsock call reports WSANOTINITIALISED. */
    u_long v = 0;
    DWORD n = 0;
    int r, e1, e2, e3;
    r = U(ioctlsocket)(4, FIONBIO, &v);
    e1 = U(WSAGetLastError)();
    if (r != SOCKET_ERROR) return 11;
    r = U(WSAIoctl)(4, IB_FIONREAD, NULL, 0, &v, 4, &n, NULL, NULL);
    e2 = U(WSAGetLastError)();
    if (r != SOCKET_ERROR) return 12;
    r = U(WSAIoctl)(INVALID_SOCKET, IB_BASE_HANDLE, NULL, 0, &v, 4, &n, NULL, NULL);
    e3 = U(WSAGetLastError)();
    if (r != SOCKET_ERROR) return 13;
    return (e1 == WSANOTINITIALISED && e2 == WSANOTINITIALISED && e3 == WSANOTINITIALISED) ? 0 : 20;
}

IBTEST(ib_ioctl_before_startup_is_notinitialised)
{
    EXPECT_EQ(t_run_child("ib_ioctl_no_startup", "", 20000), 0);
}

CHILD(ib_ioctl_after_cleanup)
{
    WSADATA d;
    SOCKET s;
    u_long v = 0;
    int r, e;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 10;
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 11;
    if (U(WSACleanup)()) return 12;
    r = U(ioctlsocket)(s, FIONBIO, &v);
    e = U(WSAGetLastError)();
    if (r != SOCKET_ERROR) return 13;
    return e == WSANOTINITIALISED ? 0 : 20;
}

IBTEST(ib_ioctl_after_cleanup_is_notinitialised)
{
    EXPECT_EQ(t_run_child("ib_ioctl_after_cleanup", "", 20000), 0);
}
