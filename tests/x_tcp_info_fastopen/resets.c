/* Third-pass measurements: how an abortive close surfaces through the other notification paths (event select,
 * overlapped receive), what it does to the four-tuple afterwards, closing unconnected sockets with an abortive
 * linger setting, ephemeral-port distinctness with the port options on, and the bind matrix repeated for UDP
 * and IPv6. Waits are bounded and every socket is closed. */
#include "xt.h"

static xt_res set_linger(SOCKET s, u_short on, u_short secs)
{
    struct linger l; l.l_onoff = on; l.l_linger = secs;
    return xt_so(s, SOL_SOCKET, SO_LINGER, &l, sizeof l);
}
static void setm(SOCKET s, int m) { if (m == 1) xt_seti(s, SOL_SOCKET, SO_REUSEADDR, 1); if (m == 2) xt_seti(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1); }
static const char *const mname[3] = {"plain", "reuse", "excl"};

/* ---- notification of a reset ---------------------------------------------------------------------------------- */
static int close_error_via_events(int abortive)
{
    SOCKET c, a, l; WSAEVENT ev; WSANETWORKEVENTS ne; int err = -1;
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return -2; }
    ev = U(WSACreateEvent)();
    EQ(U(WSAEventSelect)(a, ev, FD_CLOSE | FD_READ), 0);
    if (abortive) EQ(set_linger(c, 1, 0).rc, 0);
    xt_close(c);
    if (U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0) {
        memset(&ne, 0, sizeof ne);
        EQ(U(WSAEnumNetworkEvents)(a, ev, &ne), 0);
        CHECK(ne.lNetworkEvents & FD_CLOSE);
        err = ne.iErrorCode[FD_CLOSE_BIT];
    }
    U(WSACloseEvent)(ev);
    xt_close(a); xt_close(l);
    return err;
}
TEST(rst_event_select_close_carries_connection_aborted_after_an_abortive_close)
{
    NEED();
    EQ(close_error_via_events(1), WSAECONNABORTED);  /* the receive path says reset, the event path says aborted */
}
TEST(rst_event_select_close_carries_no_error_after_a_graceful_close)
{
    NEED();
    EQ(close_error_via_events(0), 0);
}
TEST(rst_pending_overlapped_receive_completes_with_connection_reset)
{
    SOCKET c, a, l; WSAOVERLAPPED ov; WSABUF wb; char b[16]; DWORD got = 0, fl = 0, flags = 0; int rc, e;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    wb.buf = b; wb.len = sizeof b;
    rc = U(WSARecv)(a, &wb, 1, &got, &flags, &ov, NULL);
    e = rc ? U(WSAGetLastError)() : 0;
    EQ(rc, SOCKET_ERROR); EQ(e, WSA_IO_PENDING);
    EQ(set_linger(c, 1, 0).rc, 0);
    xt_close(c);
    EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
    EQ(U(WSAGetOverlappedResult)(a, &ov, &got, FALSE, &fl), FALSE);
    EQ(U(WSAGetLastError)(), WSAECONNRESET);
    U(WSACloseEvent)(ov.hEvent);
    xt_close(a); xt_close(l);
}
TEST(rst_pending_overlapped_receive_completes_with_zero_bytes_after_a_graceful_close)
{
    SOCKET c, a, l; WSAOVERLAPPED ov; WSABUF wb; char b[16]; DWORD got = 99, fl = 0, flags = 0; int rc, e;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    wb.buf = b; wb.len = sizeof b;
    rc = U(WSARecv)(a, &wb, 1, &got, &flags, &ov, NULL);
    e = rc ? U(WSAGetLastError)() : 0;
    EQ(rc, SOCKET_ERROR); EQ(e, WSA_IO_PENDING);
    xt_close(c);
    EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
    EQ(U(WSAGetOverlappedResult)(a, &ov, &got, FALSE, &fl), TRUE); EQ(got, 0);
    U(WSACloseEvent)(ov.hEvent);
    xt_close(a); xt_close(l);
}

/* ---- abortive close leaves no TIME_WAIT behind ------------------------------------------------------------------ */
TEST(rst_abortive_close_by_the_connecting_side_frees_the_four_tuple)
{
    SOCKET l, c, a, c2; u_short p, q = 0; int rc;
    NEED();
    EQ(xt_listen_lo(&l, &p, 4), 1);
    c = xt_tcp(); xt_seti(c, SOL_SOCKET, SO_REUSEADDR, 1);
    EQ(xt_bind_lo(c, &q), 0); EQ(xt_connect_lo(c, p), 0);
    a = xt_accept(l); CHECK(a != INVALID_SOCKET);
    EQ(set_linger(c, 1, 0).rc, 0);
    xt_close(c);
    { char b[4]; int r = U(recv)(a, b, 4, 0); EQ(r, SOCKET_ERROR); EQ(xt_wsaerr(), WSAECONNRESET); }
    xt_close(a);
    c2 = xt_tcp(); xt_seti(c2, SOL_SOCKET, SO_REUSEADDR, 1);
    EQ(xt_bind_lo(c2, &q), 0);
    rc = xt_connect_lo(c2, p);
    EQ(rc, 0);
    xt_close(c2); xt_close(l);
}
TEST(rst_closing_unconnected_sockets_with_an_abortive_setting_returns_zero)
{
    static const int kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN};
    unsigned k;
    NEED();
    for (k = 0; k < 3; k++) {
        xt_st st; const char *n = xt_state_name[kinds[k]]; int rc;
        if (!xt_mkstate(kinds[k], &st)) { t_skip("setup %s", n); return; }
        EQ(set_linger(st.s, 1, 0).rc, 0);
        rc = U(closesocket)(st.s);
        CHECKF(rc == 0, "%s: closesocket %d", n, rc);
        st.s = INVALID_SOCKET;
        xt_rmstate(&st);
    }
}

/* ---- ephemeral ports ----------------------------------------------------------------------------------------- */
TEST(ports_sixteen_wildcard_port_zero_binds_are_all_distinct_with_each_port_option)
{
    static const int opts[] = {0, XT_SO_RANDOMIZE_PORT, XT_SO_PORT_SCALABILITY};
    unsigned o;
    NEED();
    for (o = 0; o < 3; o++) {
        SOCKET s[16]; u_short pt[16]; int i, j, dup = 0;
        for (i = 0; i < 16; i++) {
            s[i] = xt_tcp(); pt[i] = 0;
            if (opts[o]) xt_seti(s[i], SOL_SOCKET, opts[o], 1);
            EQ(xt_bind_lo(s[i], &pt[i]), 0);
            CHECK(pt[i] != 0);
        }
        for (i = 0; i < 16; i++) for (j = i + 1; j < 16; j++) if (pt[i] == pt[j]) dup = 1;
        CHECKF(!dup, "option 0x%x: two sockets got one ephemeral port", opts[o]);
        for (i = 0; i < 16; i++) xt_close(s[i]);
    }
}

/* ---- bind matrix repeated for UDP and for IPv6 --------------------------------------------------------------- */
static int bind4(SOCKET s, DWORD host, u_short port, u_short *out)
{
    struct sockaddr_in a; int l = sizeof a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = port; a.sin_addr.s_addr = U(htonl)(host);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return U(WSAGetLastError)();
    if (out) { U(getsockname)(s, (struct sockaddr *)&a, &l); *out = a.sin_port; }
    return 0;
}
static int bind6(SOCKET s, int any, u_short port, u_short *out)
{
    struct sockaddr_in6 a; int l = sizeof a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = port;
    if (!any) a.sin6_addr.u.Byte[15] = 1;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return U(WSAGetLastError)();
    if (out) { U(getsockname)(s, (struct sockaddr *)&a, &l); *out = a.sin6_port; }
    return 0;
}
#define EIN WSAEADDRINUSE
#define EAC WSAEACCES
static const int mx_same[3][3]  = {{EIN, EAC, EIN}, {EIN, 0, EIN}, {EIN, EAC, EIN}};
static const int mx_wild_then_lo[3][3] = {{0, 0, 0}, {0, 0, 0}, {EAC, EAC, EAC}};
static const int mx_lo_then_wild[3][3] = {{0, 0, EIN}, {0, 0, EIN}, {0, 0, EIN}};
/* fam: 0 = UDP/IPv4, 1 = TCP/IPv6; a1/a2: 0 loopback, 1 wildcard */
static void matrix2(int fam, int a1, int a2, const int want[3][3])
{
    int m1, m2;
    for (m1 = 0; m1 < 3; m1++) for (m2 = 0; m2 < 3; m2++) {
        SOCKET s1, s2; u_short port = 0; int e1, e2;
        if (fam == 0) { s1 = xt_udp(); s2 = xt_udp(); }
        else {
            s1 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP); s2 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) { xt_close(s1); xt_close(s2); t_skip("no IPv6"); return; }
        }
        setm(s1, m1); setm(s2, m2);
        e1 = fam == 0 ? bind4(s1, a1 ? INADDR_ANY : INADDR_LOOPBACK, 0, &port) : bind6(s1, a1, 0, &port);
        if (e1) { xt_close(s1); xt_close(s2); t_skip("first bind failed (%d)", e1); return; }
        e2 = fam == 0 ? bind4(s2, a2 ? INADDR_ANY : INADDR_LOOPBACK, port, NULL) : bind6(s2, a2, port, NULL);
        CHECKF(e2 == want[m1][m2], "%s first %s/%s second %s/%s: err %d want %d", fam ? "tcp6" : "udp4", a1 ? "wildcard" : "loopback", mname[m1], a2 ? "wildcard" : "loopback", mname[m2], e2, want[m1][m2]);
        xt_close(s1); xt_close(s2);
    }
}
TEST(bindudp_loopback_then_loopback) { NEED(); matrix2(0, 0, 0, mx_same); }
TEST(bindudp_wildcard_then_wildcard) { NEED(); matrix2(0, 1, 1, mx_same); }
TEST(bindudp_wildcard_then_loopback) { NEED(); matrix2(0, 1, 0, mx_wild_then_lo); }
TEST(bindudp_loopback_then_wildcard) { NEED(); matrix2(0, 0, 1, mx_lo_then_wild); }
TEST(bindtcp6_wildcard_then_wildcard) { NEED(); matrix2(1, 1, 1, mx_same); }
TEST(bindtcp6_wildcard_then_loopback) { NEED(); matrix2(1, 1, 0, mx_wild_then_lo); }
TEST(bindtcp6_loopback_then_wildcard) { NEED(); matrix2(1, 0, 1, mx_lo_then_wild); }
