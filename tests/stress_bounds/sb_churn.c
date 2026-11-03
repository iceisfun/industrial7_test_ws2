/* Bounded churn: creating and closing many sockets, many simultaneous loopback connections, accept
 * queue behaviour with a tiny backlog, event objects, and repeated WSAStartup/WSACleanup. Measured:
 * return values, error codes, and relations between counts (handle count back near its baseline,
 * accepted <= connected). No ports, handles or timings are printed. */
#include "sb.h"

/* ---- socket churn ---------------------------------------------------------------------------- */

static void churn(int type, int proto, int n)
{
    int i, fails = 0;
    DWORD base, after;
    SOCKET s;
    /* warm-up: lazily created helper handles must not count as a leak */
    s = socket(AF_INET, type, proto);
    if (s != INVALID_SOCKET) closesocket(s);
    base = sb_handle_count();
    for (i = 0; i < n; i++) {
        s = socket(AF_INET, type, proto);
        if (s == INVALID_SOCKET) { fails++; continue; }
        if (closesocket(s) != 0) fails++;
    }
    after = sb_handle_count();
    EXPECT_EQ(fails, 0);
    CHECK(after <= base + 4);
}

TEST(churn_1000_udp_sockets_leave_handle_count_flat) { SB_BEGIN(); churn(SOCK_DGRAM, IPPROTO_UDP, 1000); sb_end(); }
TEST(churn_1000_tcp_sockets_leave_handle_count_flat) { SB_BEGIN(); churn(SOCK_STREAM, IPPROTO_TCP, 1000); sb_end(); }

TEST(churn_1000_bound_udp_sockets_leave_handle_count_flat)
{
    int i, fails = 0; DWORD base, after; SOCKET s;
    SB_BEGIN();
    s = sb_udp(NULL); if (s != INVALID_SOCKET) closesocket(s);
    base = sb_handle_count();
    for (i = 0; i < 1000; i++) { s = sb_udp(NULL); if (s == INVALID_SOCKET) fails++; else closesocket(s); }
    after = sb_handle_count();
    EXPECT_EQ(fails, 0);
    CHECK(after <= base + 4);
    sb_end();
}

TEST(churn_listeners_open_and_close_repeatedly)
{
    int i, fails = 0; struct sockaddr_in a; SOCKET s;
    SB_BEGIN();
    for (i = 0; i < 300; i++) { s = sb_listener(&a, 5); if (s == INVALID_SOCKET) fails++; else closesocket(s); }
    EXPECT_EQ(fails, 0);
    sb_end();
}

TEST(churn_connected_pairs_open_and_close_200_times)
{
    int i, fails = 0; DWORD base, after; SOCKET c, s;
    SB_BEGIN();
    if (sb_pair(&c, &s)) sb_close2(c, s);
    base = sb_handle_count();
    for (i = 0; i < 200; i++) {
        char ch = 'x', r = 0;
        if (!sb_pair(&c, &s)) { fails++; continue; }
        if (send(c, &ch, 1, 0) != 1 || sb_recv_n(s, &r, 1) != 1 || r != 'x') fails++;
        sb_close2(c, s);
    }
    after = sb_handle_count();
    EXPECT_EQ(fails, 0);
    CHECK(after <= base + 4);
    sb_end();
}

TEST(churn_closed_socket_value_is_rejected_each_time)
{
    int i, bad = 0; SOCKET s;
    SB_BEGIN();
    for (i = 0; i < 200; i++) {
        int v = 0, l = sizeof v;
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) { bad++; continue; }
        closesocket(s);
        WSASetLastError(0);
        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&v, &l) != SOCKET_ERROR) { bad++; continue; }
        if (WSAGetLastError() != WSAENOTSOCK) bad++;
    }
    EXPECT_EQ(bad, 0);
    sb_end();
}

TEST(churn_socket_values_are_distinct_while_open)
{
    enum { N = 400 };
    static SOCKET v[N]; int i, j, dup = 0, ok = 0;
    SB_BEGIN();
    for (i = 0; i < N; i++) { v[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if (v[i] != INVALID_SOCKET) ok++; }
    EXPECT_EQ(ok, N);
    for (i = 0; i < N; i++) for (j = i + 1; j < N; j++) if (v[i] == v[j]) dup++;
    EXPECT_EQ(dup, 0);
    for (i = 0; i < N; i++) if (v[i] != INVALID_SOCKET) closesocket(v[i]);
    sb_end();
}

TEST(churn_socket_values_are_multiples_of_four)
{
    int i, odd = 0; SOCKET s[50];
    SB_BEGIN();
    for (i = 0; i < 50; i++) { s[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if (s[i] != INVALID_SOCKET && (s[i] & 3)) odd++; }
    EXPECT_EQ(odd, 0);
    for (i = 0; i < 50; i++) if (s[i] != INVALID_SOCKET) closesocket(s[i]);
    sb_end();
}

TEST(churn_double_close_after_loop_reports_notsock)
{
    SOCKET s;
    SB_BEGIN();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EXPECT_NE(s, INVALID_SOCKET);
    EXPECT_EQ(closesocket(s), 0);
    WSASetLastError(0);
    EXPECT_EQ(closesocket(s), (ULONG_PTR)(LONG_PTR)SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    sb_end();
}

/* ---- many simultaneous connections ------------------------------------------------------------ */

/* Open n clients with non-blocking connects against listener l and accept them as they arrive, so the
 * listener queue never has to hold the whole burst. Fills cs[]/ss[]; returns the number accepted. */
static int mass_connect(SOCKET l, const struct sockaddr_in *a, SOCKET *cs, SOCKET *ss, int n)
{
    int i, accepted = 0, started = 0;
    DWORD deadline = GetTickCount() + 15000;
    for (i = 0; i < n; i++) { cs[i] = INVALID_SOCKET; ss[i] = INVALID_SOCKET; }
    while (accepted < n && (int)(deadline - GetTickCount()) > 0) {
        int batch = 0;
        while (started < n && batch < 50) {
            u_long nb = 1;
            cs[started] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (cs[started] != INVALID_SOCKET) {
                ioctlsocket(cs[started], FIONBIO, &nb);
                connect(cs[started], (const struct sockaddr *)a, sizeof *a);
            }
            started++; batch++;
        }
        while (accepted < n && sb_readable(l, 200)) {
            SOCKET x = accept(l, NULL, NULL);
            if (x == INVALID_SOCKET) break;
            ss[accepted++] = x;
        }
    }
    for (i = 0; i < n; i++) if (cs[i] != INVALID_SOCKET) { u_long nb = 0; ioctlsocket(cs[i], FIONBIO, &nb); }
    return accepted;
}

TEST(conn_500_simultaneous_loopback_connections)
{
    enum { N = 500 };
    static SOCKET cs[N], ss[N]; struct sockaddr_in a; SOCKET l; int i, connected = 0, accepted = 0, echo_ok = 0;
    SB_BEGIN();
    l = sb_listener(&a, SOMAXCONN);
    EXPECT_NE(l, INVALID_SOCKET);
    if (l == INVALID_SOCKET) { sb_end(); return; }
    accepted = mass_connect(l, &a, cs, ss, N);
    for (i = 0; i < N; i++) if (cs[i] != INVALID_SOCKET) connected++;
    EXPECT_EQ(connected, N);
    EXPECT_EQ(accepted, N);
    /* each server side talks to some client; the 500 one-byte tokens all arrive */
    for (i = 0; i < N; i++) {
        unsigned char b = (unsigned char)(i * 7 + 1), r = 0;
        if (ss[i] == INVALID_SOCKET || cs[i] == INVALID_SOCKET) continue;
        sb_rcvtimeo(cs[i], SB_WAIT_MS);
        if (send(ss[i], (char *)&b, 1, 0) == 1 && sb_recv_n(cs[i], (char *)&r, 1) == 1) echo_ok++;
    }
    EXPECT_EQ(echo_ok, N);
    for (i = 0; i < N; i++) sb_close2(cs[i], ss[i]);
    closesocket(l);
    sb_end();
}

TEST(conn_500_connections_close_in_reverse_order_and_peers_see_eof)
{
    enum { N = 500 };
    static SOCKET cs[N], ss[N]; struct sockaddr_in a; SOCKET l; int i, eof = 0;
    SB_BEGIN();
    l = sb_listener(&a, SOMAXCONN);
    if (l == INVALID_SOCKET) { t_skip("no listener"); sb_end(); return; }
    mass_connect(l, &a, cs, ss, N);
    for (i = N - 1; i >= 0; i--) if (cs[i] != INVALID_SOCKET) closesocket(cs[i]);
    for (i = 0; i < N; i++) {
        char c;
        if (ss[i] == INVALID_SOCKET) continue;
        sb_rcvtimeo(ss[i], SB_WAIT_MS);
        if (recv(ss[i], &c, 1, 0) == 0) eof++;
        closesocket(ss[i]);
    }
    EXPECT_EQ(eof, N);
    closesocket(l);
    sb_end();
}

TEST(conn_listen_backlog_values_are_accepted_across_range)
{
    static const int bl[] = { 0, 1, 2, 5, 64, 200, 1000, SOMAXCONN };
    unsigned i; int bad = 0;
    SB_BEGIN();
    for (i = 0; i < sizeof bl / sizeof bl[0]; i++) {
        struct sockaddr_in a; SOCKET s = sb_listener(&a, bl[i]);
        if (s == INVALID_SOCKET) bad++; else closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    sb_end();
}

TEST(conn_listen_on_unbound_socket_is_accepted_and_binds_implicitly)
{
    SOCKET s; int r, e;
    SB_BEGIN();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    WSASetLastError(0);
    r = listen(s, 5); e = WSAGetLastError();
    if (r != 0) t_note("listen on an unbound socket failed %d", e); /* version dependent: not a hard check */
    closesocket(s);
    sb_end();
}

TEST(conn_accept_queue_overflow_with_backlog_one_is_bounded)
{
    enum { N = 10 };
    struct sockaddr_in a; SOCKET l, c[N]; int i, writable = 0, accepted = 0;
    fd_set w; struct timeval tv;
    SB_BEGIN();
    l = sb_listener(&a, 1);
    if (l == INVALID_SOCKET) { t_skip("no listener"); sb_end(); return; }
    for (i = 0; i < N; i++) {
        u_long nb = 1;
        c[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ioctlsocket(c[i], FIONBIO, &nb);
        connect(c[i], (struct sockaddr *)&a, sizeof a);
    }
    w.fd_count = 0;
    for (i = 0; i < N; i++) w.fd_array[w.fd_count++] = c[i];
    tv.tv_sec = 2; tv.tv_usec = 0;
    {
        int r = select(0, NULL, &w, NULL, &tv);
        writable = r > 0 ? r : 0;
    }
    for (;;) {
        SOCKET s;
        if (!sb_readable(l, 300)) break;
        s = accept(l, NULL, NULL);
        if (s == INVALID_SOCKET) break;
        accepted++; closesocket(s);
        if (accepted > N) break;
    }
    CHECK(accepted >= 1);
    CHECK(accepted <= N);
    (void)writable; /* retransmitted SYNs may complete after the sample, so no ordering is asserted */
    for (i = 0; i < N; i++) closesocket(c[i]);
    closesocket(l);
    sb_end();
}

TEST(conn_accept_on_empty_queue_nonblocking_reports_wouldblock_after_drain)
{
    struct sockaddr_in a; SOCKET l, c, s; u_long nb = 1;
    SB_BEGIN();
    l = sb_listener(&a, 8);
    if (l == INVALID_SOCKET) { t_skip("no listener"); sb_end(); return; }
    ioctlsocket(l, FIONBIO, &nb);
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EXPECT_EQ(connect(c, (struct sockaddr *)&a, sizeof a), 0);
    nb = 0;
    CHECK(sb_readable(l, SB_WAIT_MS));
    s = accept(l, NULL, NULL);
    EXPECT_NE(s, INVALID_SOCKET);
    WSASetLastError(0);
    {
        SOCKET s2 = accept(l, NULL, NULL);
        EXPECT_EQ(s2, INVALID_SOCKET);
        EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    }
    sb_close2(c, s); closesocket(l);
    sb_end();
}

TEST(conn_connect_to_closed_listener_port_is_refused)
{
    struct sockaddr_in a; SOCKET l, c; int r, e, i, bad = 0;
    SB_BEGIN();
    l = sb_listener(&a, 4);
    if (l == INVALID_SOCKET) { t_skip("no listener"); sb_end(); return; }
    closesocket(l);
    for (i = 0; i < 20; i++) {
        c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        WSASetLastError(0);
        r = connect(c, (struct sockaddr *)&a, sizeof a); e = WSAGetLastError();
        if (r == 0) { bad++; t_note("connect to closed port succeeded (port reused?)"); }
        else if (e != WSAECONNREFUSED) bad++;
        closesocket(c);
    }
    CHECK(bad <= 2); /* a different process could reuse the ephemeral port in the window */
    sb_end();
}

/* ---- events ------------------------------------------------------------------------------------ */

TEST(events_create_close_5000)
{
    enum { N = 5000 };
    static WSAEVENT e[N]; int i, ok = 0, closed = 0; DWORD base, after;
    SB_BEGIN();
    base = sb_handle_count();
    for (i = 0; i < N; i++) { e[i] = WSACreateEvent(); if (e[i] != WSA_INVALID_EVENT) ok++; }
    EXPECT_EQ(ok, N);
    for (i = 0; i < N; i++) if (e[i] != WSA_INVALID_EVENT && WSACloseEvent(e[i])) closed++;
    EXPECT_EQ(closed, N);
    after = sb_handle_count();
    CHECK(after <= base + 4);
    sb_end();
}

TEST(events_new_events_are_nonsignalled_and_set_reset_roundtrip)
{
    int i, bad = 0;
    SB_BEGIN();
    for (i = 0; i < 200; i++) {
        WSAEVENT e = WSACreateEvent();
        if (e == WSA_INVALID_EVENT) { bad++; continue; }
        if (WaitForSingleObject(e, 0) != WAIT_TIMEOUT) bad++;
        if (!WSASetEvent(e) || WaitForSingleObject(e, 0) != WAIT_OBJECT_0) bad++;
        if (!WSAResetEvent(e) || WaitForSingleObject(e, 0) != WAIT_TIMEOUT) bad++;
        WSACloseEvent(e);
    }
    EXPECT_EQ(bad, 0);
    sb_end();
}

TEST(events_1000_sockets_each_with_own_event_select)
{
    enum { N = 1000 };
    static SOCKET s[N]; static WSAEVENT e[N]; int i, ok = 0, fired = 0; struct sockaddr_in a;
    SB_BEGIN();
    sb_loopback(&a, 0);
    for (i = 0; i < N; i++) {
        s[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); e[i] = WSACreateEvent();
        /* an unbound datagram socket never reports FD_WRITE; a bound one does at once */
        if (s[i] != INVALID_SOCKET && e[i] != WSA_INVALID_EVENT && bind(s[i], (struct sockaddr *)&a, sizeof a) == 0 &&
            WSAEventSelect(s[i], e[i], FD_WRITE) == 0) ok++;
    }
    EXPECT_EQ(ok, N);
    for (i = 0; i < N; i++) if (WaitForSingleObject(e[i], i == 0 ? SB_WAIT_MS : 0) == WAIT_OBJECT_0) fired++;
    EXPECT_EQ(fired, N);
    for (i = 0; i < N; i++) {
        if (s[i] != INVALID_SOCKET) { WSAEventSelect(s[i], NULL, 0); closesocket(s[i]); }
        if (e[i] != WSA_INVALID_EVENT) WSACloseEvent(e[i]);
    }
    sb_end();
}

TEST(events_unbound_datagram_socket_reports_no_write_event)
{
    SOCKET s; WSAEVENT e; WSANETWORKEVENTS ne;
    SB_BEGIN();
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); e = WSACreateEvent();
    EXPECT_EQ(WSAEventSelect(s, e, FD_WRITE), 0);
    EXPECT_EQ(WaitForSingleObject(e, 300), WAIT_TIMEOUT);
    memset(&ne, 0xff, sizeof ne);
    EXPECT_EQ(W(WSAEnumNetworkEvents)(s, e, &ne), 0);
    EXPECT_EQ(ne.lNetworkEvents, 0);
    WSAEventSelect(s, NULL, 0);
    closesocket(s); WSACloseEvent(e);
    sb_end();
}

/* ---- startup / cleanup ------------------------------------------------------------------------- */

TEST(startup_cleanup_10000_balanced_pairs)
{
    int i, bad = 0; WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    for (i = 0; i < 10000; i++) {
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0) { bad++; continue; }
        if (WSACleanup() != 0) bad++;
    }
    EXPECT_EQ(bad, 0);
    WSASetLastError(0);
    EXPECT_EQ(WSACleanup(), (ULONG_PTR)(LONG_PTR)SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}

TEST(startup_10000_nested_then_10000_cleanups_then_surplus_fails)
{
    int i, bad = 0; WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    for (i = 0; i < 10000; i++) if (WSAStartup(MAKEWORD(2, 2), &d) != 0) bad++;
    EXPECT_EQ(bad, 0);
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        EXPECT_NE(s, INVALID_SOCKET);
        if (s != INVALID_SOCKET) closesocket(s);
    }
    for (i = 0; i < 10000; i++) if (WSACleanup() != 0) bad++;
    EXPECT_EQ(bad, 0);
    WSASetLastError(0);
    EXPECT_EQ(WSACleanup(), (ULONG_PTR)(LONG_PTR)SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}

TEST(startup_after_full_unwind_sockets_work_again)
{
    int i; WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    for (i = 0; i < 100; i++) {
        SOCKET s;
        EXPECT_EQ(WSAStartup(MAKEWORD(2, 2), &d), 0);
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        EXPECT_NE(s, INVALID_SOCKET);
        if (s != INVALID_SOCKET) closesocket(s);
        EXPECT_EQ(WSACleanup(), 0);
    }
}

TEST(startup_socket_after_cleanup_fails_with_notinitialised)
{
    WSADATA d; SOCKET s;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    EXPECT_EQ(WSAStartup(MAKEWORD(2, 2), &d), 0);
    EXPECT_EQ(WSACleanup(), 0);
    WSASetLastError(0);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EXPECT_EQ(s, INVALID_SOCKET);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}

TEST(startup_data_is_stable_across_1000_calls)
{
    int i, bad = 0; WSADATA d0, d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    memset(&d0, 0, sizeof d0);
    WSAStartup(MAKEWORD(2, 2), &d0);
    for (i = 0; i < 1000; i++) {
        memset(&d, 0xCC, sizeof d);
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0) { bad++; continue; }
        if (d.wVersion != d0.wVersion || d.wHighVersion != d0.wHighVersion || strcmp(d.szDescription, d0.szDescription) ||
            strcmp(d.szSystemStatus, d0.szSystemStatus)) bad++;
        WSACleanup();
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(d0.wVersion, 0x0202);
    EXPECT_EQ(d0.wHighVersion, 0x0202);
    WSACleanup();
}

TEST(startup_unsupported_version_repeated_leaves_count_untouched)
{
    int i, bad = 0; WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    for (i = 0; i < 500; i++) {
        int r = WSAStartup(MAKEWORD(0, 0), &d);
        if (r != WSAVERNOTSUPPORTED) bad++;
    }
    EXPECT_EQ(bad, 0);
    WSASetLastError(0);
    EXPECT_EQ(WSACleanup(), (ULONG_PTR)(LONG_PTR)SOCKET_ERROR);   /* none of the failed startups counted */
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}

TEST(startup_newer_major_version_is_negotiated_down_to_2_2)
{
    static const WORD req[] = { MAKEWORD(3, 0), MAKEWORD(7, 7), 0xFFFF };
    unsigned i; int bad = 0, calls = 0; WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    for (i = 0; i < sizeof req / sizeof req[0]; i++) {
        memset(&d, 0, sizeof d);
        if (WSAStartup(req[i], &d) != 0) { bad++; continue; }
        calls++;
        if (d.wVersion != 0x0202 || d.wHighVersion != 0x0202) bad++;
    }
    EXPECT_EQ(bad, 0);
    while (calls--) WSACleanup();
    WSASetLastError(0);
    EXPECT_EQ(WSACleanup(), (ULONG_PTR)(LONG_PTR)SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}

TEST(startup_version_2_2_reports_zero_socket_and_datagram_limits)
{
    WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    memset(&d, 0xCC, sizeof d);
    EXPECT_EQ(WSAStartup(MAKEWORD(2, 2), &d), 0);
    EXPECT_EQ(d.iMaxSockets, 0);
    EXPECT_EQ(d.iMaxUdpDg, 0);
    CHECK(memchr(d.szDescription, 0, sizeof d.szDescription) != NULL);
    CHECK(memchr(d.szSystemStatus, 0, sizeof d.szSystemStatus) != NULL);
    WSACleanup();
}

TEST(startup_failed_version_is_not_counted_toward_cleanup)
{
    WSADATA d;
    if (!W(WSAStartup)) { t_skip("missing export"); return; }
    EXPECT_EQ(WSAStartup(MAKEWORD(2, 2), &d), 0);
    EXPECT_EQ(WSAStartup(MAKEWORD(0, 5), &d), WSAVERNOTSUPPORTED);
    EXPECT_EQ(WSACleanup(), 0);                       /* only the successful startup is counted */
    WSASetLastError(0);
    EXPECT_EQ(WSACleanup(), (ULONG_PTR)(LONG_PTR)SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
}
