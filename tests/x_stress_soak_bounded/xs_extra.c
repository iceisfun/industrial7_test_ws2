/* Additional bounded soak and error-path tests: many simultaneous sockets, address-in-use and refusal tables,
 * shutdown/reset statuses across many pairs, nested WSAStartup depth, event-select accept counting, WSAPoll with
 * a large array and concurrent create/close from many threads. Everything is loopback, ephemeral and bounded. */
#include "xs.h"

#define WSAPoll_(...) WSAPoll(__VA_ARGS__)

/* ---- many simultaneously open sockets ---------------------------------------------------------------------- */
static void many_open(int type, int proto, int n)
{
    SOCKET *s = calloc(n, sizeof *s);
    int i, j, made = 0, bad = 0;
    DWORD base, during, after;
    XS_BEGIN();
    { SOCKET w = socket(AF_INET, type, proto); closesocket(w); }
    base = xs_handles();
    for (i = 0; i < n; i++) { s[i] = socket(AF_INET, type, proto); if (s[i] != INVALID_SOCKET) made++; }
    during = xs_handles();
    EXPECT_EQ(made, n);
    /* spot-check distinctness against a sample (full pairwise would be quadratic) */
    for (i = 0; i < n; i += 97) for (j = 0; j < n; j++) if (j != i && s[i] == s[j]) bad++;
    EXPECT_EQ(bad, 0);
    CHECKF(during >= base + (DWORD)n, "handles base %lu during %lu for %d sockets", base, during, n);
    for (i = 0; i < n; i++) if (s[i] != INVALID_SOCKET) closesocket(s[i]);
    after = xs_handles();
    CHECKF(after <= base + 6, "handles base %lu after %lu", base, after);
    free(s);
    xs_end();
}
TEST(extra_3000_udp_sockets_open_at_once_raise_handles_by_at_least_3000) { many_open(SOCK_DGRAM, IPPROTO_UDP, 3000); }
TEST(extra_3000_tcp_sockets_open_at_once_raise_handles_by_at_least_3000) { many_open(SOCK_STREAM, IPPROTO_TCP, 3000); }

/* 500 listeners alive together get 500 distinct ports. */
TEST(extra_500_listeners_have_distinct_ephemeral_ports)
{
    enum { N = 500 };
    SOCKET *l = calloc(N, sizeof *l); unsigned short *port = calloc(N, sizeof *port); unsigned char *used = calloc(65536, 1);
    int i, ok = 0, dup = 0, zero = 0;
    XS_BEGIN();
    for (i = 0; i < N; i++) {
        struct sockaddr_in a;
        l[i] = xs_listener(&a, 2);
        if (l[i] == INVALID_SOCKET) continue;
        ok++;
        port[i] = a.sin_port;
        if (!port[i]) zero++;
        if (used[port[i]]) dup++; else used[port[i]] = 1;
    }
    EXPECT_EQ(ok, N);
    EXPECT_EQ(zero, 0);
    EXPECT_EQ(dup, 0);
    for (i = 0; i < N; i++) if (l[i] != INVALID_SOCKET) closesocket(l[i]);
    free(l); free(port); free(used);
    xs_end();
}

/* ---- address in use, refusal ------------------------------------------------------------------------------ */
static void inuse_table(int type, int proto, int exclusive_first)
{
    int i, bad = 0, badcode = 0;
    XS_BEGIN();
    for (i = 0; i < 200; i++) {
        struct sockaddr_in a; int len = sizeof a;
        SOCKET s1 = socket(AF_INET, type, proto), s2 = socket(AF_INET, type, proto);
        int r;
        xs_lo4(&a, 0);
        if (exclusive_first) { BOOL on = 1; setsockopt(s1, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof on); }
        if (bind(s1, (struct sockaddr *)&a, sizeof a) || getsockname(s1, (struct sockaddr *)&a, &len)) { bad++; }
        else {
            WSASetLastError(0);
            r = bind(s2, (struct sockaddr *)&a, sizeof a);
            if (r != SOCKET_ERROR) bad++;
            else if (WSAGetLastError() != WSAEADDRINUSE) badcode++;
        }
        closesocket(s1); closesocket(s2);
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(badcode, 0);
    xs_end();
}
TEST(extra_tcp_second_bind_same_port_is_addrinuse_200) { inuse_table(SOCK_STREAM, IPPROTO_TCP, 0); }
TEST(extra_udp_second_bind_same_port_is_addrinuse_200) { inuse_table(SOCK_DGRAM, IPPROTO_UDP, 0); }
TEST(extra_tcp_exclusive_first_bind_blocks_second_200) { inuse_table(SOCK_STREAM, IPPROTO_TCP, 1); }
TEST(extra_udp_exclusive_first_bind_blocks_second_200) { inuse_table(SOCK_DGRAM, IPPROTO_UDP, 1); }

/* A socket bound twice fails with WSAEINVAL the second time, every time. */
TEST(extra_bind_twice_on_one_socket_is_einval_200)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < 200; i++) {
        struct sockaddr_in a; SOCKET s = socket(AF_INET, (i & 1) ? SOCK_DGRAM : SOCK_STREAM, 0);
        xs_lo4(&a, 0);
        if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) bad++;
        WSASetLastError(0);
        xs_lo4(&a, 0);
        if (bind(s, (struct sockaddr *)&a, sizeof a) != SOCKET_ERROR || WSAGetLastError() != WSAEINVAL) bad++;
        closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}

/* listen on an unbound-then-listening, already-listening and connected socket. */
TEST(extra_listen_state_errors)
{
    struct sockaddr_in a; SOCKET l, c, s;
    XS_BEGIN();
    l = xs_listener(&a, 4);
    WSASetLastError(0);
    /* relisten is allowed and keeps working */
    EXPECT_EQ(listen(l, 8), 0);
    if (xs_pair(&c, &s)) {
        WSASetLastError(0);
        EXPECT_EQ(listen(c, 1), SOCKET_ERROR);
        EXPECT_EQ(WSAGetLastError(), WSAEISCONN);
        closesocket(c); closesocket(s);
    }
    { SOCKET d = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      struct sockaddr_in b; xs_lo4(&b, 0); bind(d, (struct sockaddr *)&b, sizeof b);
      WSASetLastError(0);
      EXPECT_EQ(listen(d, 1), SOCKET_ERROR);
      EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
      closesocket(d); }
    closesocket(l);
    xs_end();
}

/* connect to a closed loopback listener port is refused. The port was just released by a listener of this
 * process, so nothing else is expected to hold it. Each refusal costs a couple of seconds because the stack
 * retries the SYN, so only a few rounds are made. */
TEST(extra_connect_to_just_closed_listener_is_refused_4)
{
    int i, bad = 0, badcode = 0;
    XS_BEGIN();
    for (i = 0; i < 4; i++) {
        struct sockaddr_in a; SOCKET l = xs_listener(&a, 1), c;
        if (l == INVALID_SOCKET) { bad++; continue; }
        closesocket(l);
        c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        WSASetLastError(0);
        if (connect(c, (struct sockaddr *)&a, sizeof a) != SOCKET_ERROR) bad++;
        else if (WSAGetLastError() != WSAECONNREFUSED) badcode++;
        closesocket(c);
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(badcode, 0);
    xs_end();
}

/* ---- shutdown / reset over many pairs --------------------------------------------------------------------- */
TEST(extra_send_after_shutdown_send_is_eshutdown_200_pairs)
{
    int i, bad = 0, badcode = 0, eof = 0;
    XS_BEGIN();
    for (i = 0; i < 200; i++) {
        SOCKET c, s; char b;
        if (!xs_pair(&c, &s)) { bad++; continue; }
        if (shutdown(c, SD_SEND) != 0) bad++;
        WSASetLastError(0);
        if (send(c, "x", 1, 0) != SOCKET_ERROR) bad++;
        else if (WSAGetLastError() != WSAESHUTDOWN) badcode++;
        xs_rcvtimeo(s, XS_WAIT_MS);
        if (recv(s, &b, 1, 0) == 0) eof++;
        closesocket(c); closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(badcode, 0);
    EXPECT_EQ(eof, 200);
    xs_end();
}

TEST(extra_recv_after_peer_abort_is_econnreset_200_pairs)
{
    int i, bad = 0, badcode = 0, again = 0;
    XS_BEGIN();
    for (i = 0; i < 200; i++) {
        SOCKET c, s; char b; LINGER lg = { 1, 0 };
        if (!xs_pair(&c, &s)) { bad++; continue; }
        setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        closesocket(c);
        xs_rcvtimeo(s, XS_WAIT_MS);
        WSASetLastError(0);
        if (recv(s, &b, 1, 0) != SOCKET_ERROR) bad++;
        else if (WSAGetLastError() != WSAECONNRESET) badcode++;
        /* the reset is sticky: a second receive fails again */
        if (recv(s, &b, 1, 0) == SOCKET_ERROR) again++;
        closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(badcode, 0);
    EXPECT_EQ(again, 200);
    xs_end();
}

/* FIONREAD reports exactly the bytes queued on a stream once they have all arrived. */
TEST(extra_fionread_matches_queued_bytes_100_pairs)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < 100; i++) {
        SOCKET c, s; char buf[300]; u_long avail = 0; int n = 1 + i * 3;
        fd_set r; struct timeval tv = { 3, 0 };
        if (!xs_pair(&c, &s)) { bad++; continue; }
        memset(buf, 'q', sizeof buf);
        if (send(c, buf, n, 0) != n) bad++;
        r.fd_count = 1; r.fd_array[0] = s;
        if (select(0, &r, NULL, NULL, &tv) != 1) bad++;
        /* every byte of a small loopback send arrives together; poll until the count is complete */
        { int k; for (k = 0; k < 100; k++) { avail = 0; ioctlsocket(s, FIONREAD, &avail); if ((int)avail >= n) break; Sleep(10); } }
        if ((int)avail != n) bad++;
        closesocket(c); closesocket(s);
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}

/* UDP FIONREAD counts every byte queued on the socket (the sum over datagrams), and it shrinks by one
 * datagram per receive. */
TEST(extra_udp_fionread_is_total_queued_bytes)
{
    struct sockaddr_in ra; SOCKET rx, tx; u_long avail = 0; char buf[100]; int k;
    XS_BEGIN();
    rx = xs_udp(&ra); tx = xs_udp(NULL);
    memset(buf, 'u', sizeof buf);
    sendto(tx, buf, 10, 0, (struct sockaddr *)&ra, sizeof ra);
    sendto(tx, buf, 30, 0, (struct sockaddr *)&ra, sizeof ra);
    sendto(tx, buf, 20, 0, (struct sockaddr *)&ra, sizeof ra);
    for (k = 0; k < 100; k++) { avail = 0; ioctlsocket(rx, FIONREAD, &avail); if (avail >= 60) break; Sleep(10); }
    EXPECT_EQ(avail, 60);
    EXPECT_EQ(recv(rx, buf, sizeof buf, 0), 10);
    ioctlsocket(rx, FIONREAD, &avail);
    EXPECT_EQ(avail, 50);
    EXPECT_EQ(recv(rx, buf, sizeof buf, 0), 30);
    ioctlsocket(rx, FIONREAD, &avail);
    EXPECT_EQ(avail, 20);
    EXPECT_EQ(recv(rx, buf, sizeof buf, 0), 20);
    ioctlsocket(rx, FIONREAD, &avail);
    EXPECT_EQ(avail, 0);
    closesocket(rx); closesocket(tx);
    xs_end();
}

/* ---- WSAStartup nesting ------------------------------------------------------------------------------------ */
TEST(extra_wsastartup_nested_1000_deep_then_unwound)
{
    int i, bad = 0;
    WSADATA d;
    for (i = 0; i < 1000; i++) if (WSAStartup(MAKEWORD(2, 2), &d) != 0) bad++;
    EXPECT_EQ(bad, 0);
    { SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); CHECK(s != INVALID_SOCKET); if (s != INVALID_SOCKET) closesocket(s); }
    bad = 0;
    for (i = 0; i < 1000; i++) if (WSACleanup() != 0) bad++;
    EXPECT_EQ(bad, 0);
    /* the 1001st cleanup has nothing to undo */
    WSASetLastError(0);
    EXPECT_EQ(WSACleanup(), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSANOTINITIALISED);
    { SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); EXPECT_EQ(s, INVALID_SOCKET); if (s != INVALID_SOCKET) closesocket(s); }
}

/* ---- FD_ACCEPT counting with WSAEventSelect --------------------------------------------------------------- */
TEST(extra_eventselect_fd_accept_200_connections_exact)
{
    struct sockaddr_in a; SOCKET l; HANDLE ev; SOCKET cs[200]; int i, accepted = 0, rounds = 0, ok = 0, errs = 0;
    XS_BEGIN();
    l = xs_listener(&a, SOMAXCONN);
    ev = WSACreateEvent();
    EXPECT_EQ(WSAEventSelect(l, ev, FD_ACCEPT), 0);
    for (i = 0; i < 200; i++) {
        LINGER lg = { 1, 0 };
        cs[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        setsockopt(cs[i], SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
        if (connect(cs[i], (struct sockaddr *)&a, sizeof a) == 0) ok++;
    }
    EXPECT_EQ(ok, 200);
    while (accepted < 200 && rounds++ < 400) {
        WSANETWORKEVENTS ne;
        if (WaitForSingleObject(ev, XS_WAIT_MS) != WAIT_OBJECT_0) break;
        memset(&ne, 0, sizeof ne);
        if (W(WSAEnumNetworkEvents)(l, ev, &ne) != 0) { errs++; break; }
        if (!(ne.lNetworkEvents & FD_ACCEPT)) continue;
        if (ne.iErrorCode[FD_ACCEPT_BIT] != 0) errs++;
        for (;;) {
            SOCKET s = accept(l, NULL, NULL);
            if (s == INVALID_SOCKET) { if (WSAGetLastError() != WSAEWOULDBLOCK) errs++; break; }
            closesocket(s); accepted++;
        }
    }
    EXPECT_EQ(accepted, 200);
    EXPECT_EQ(errs, 0);
    /* queue empty: the event must not stay signalled with a pending FD_ACCEPT */
    { WSANETWORKEVENTS ne; memset(&ne, 0, sizeof ne);
      W(WSAEnumNetworkEvents)(l, ev, &ne);
      EXPECT_EQ(ne.lNetworkEvents & FD_ACCEPT, 0); }
    for (i = 0; i < 200; i++) closesocket(cs[i]);
    closesocket(l); WSACloseEvent(ev);
    xs_end();
}

/* ---- WSAPoll with a large array --------------------------------------------------------------------------- */
TEST(extra_wsapoll_1000_udp_sockets_exact_ready_set)
{
    enum { N = 1000 };
    SOCKET *s = calloc(N, sizeof *s); struct sockaddr_in *a = calloc(N, sizeof *a); WSAPOLLFD *p = calloc(N, sizeof *p);
    SOCKET tx; int i, made = 0, rc, wrong = 0, ready = 0;
    XS_BEGIN();
    tx = xs_udp(NULL);
    for (i = 0; i < N; i++) { s[i] = xs_udp(&a[i]); if (s[i] != INVALID_SOCKET) made++; }
    EXPECT_EQ(made, N);
    for (i = 0; i < N; i += 3) sendto(tx, "p", 1, 0, (struct sockaddr *)&a[i], sizeof a[i]);
    Sleep(80);
    for (i = 0; i < N; i++) { p[i].fd = s[i]; p[i].events = POLLRDNORM; p[i].revents = 0x7777; }
    rc = WSAPoll(p, N, 3000);
    for (i = 0; i < N; i++) {
        int want = (i % 3 == 0);
        if (want) ready++;
        if (((p[i].revents & POLLRDNORM) != 0) != want) wrong++;
        if (!want && p[i].revents != 0) wrong++;
    }
    EXPECT_EQ(rc, ready);
    EXPECT_EQ(wrong, 0);
    /* an entry holding a closed socket reports POLLNVAL and nothing else */
    closesocket(s[5]);
    for (i = 0; i < N; i++) p[i].revents = 0;
    rc = WSAPoll(p, N, 3000);
    EXPECT_EQ(p[5].revents, POLLNVAL);
    /* observed on Windows 10: the POLLNVAL entry is not part of the returned count */
    EXPECT_EQ(rc, ready);
    for (i = 0; i < N; i++) if (i != 5) closesocket(s[i]);
    closesocket(tx);
    free(s); free(a); free(p);
    xs_end();
}

TEST(extra_wsapoll_zero_entries_and_null_array_are_einval)
{
    WSAPOLLFD p;
    XS_BEGIN();
    memset(&p, 0, sizeof p);
    WSASetLastError(0);
    EXPECT_EQ(WSAPoll(&p, 0, 0), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0);
    EXPECT_EQ(WSAPoll(NULL, 0, 0), SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xs_end();
}

/* ---- concurrent create/close from many threads ------------------------------------------------------------ */
typedef struct { int type, proto, cycles, bad, notsock_bad; } cc_arg;
static DWORD cc_thread(void *p)
{
    cc_arg *a = (cc_arg *)p; int i;
    for (i = 0; i < a->cycles; i++) {
        SOCKET s = socket(AF_INET, a->type, a->proto);
        if (s == INVALID_SOCKET) { a->bad++; continue; }
        if (closesocket(s) != 0) a->bad++;
    }
    return 0;
}
static void concurrent_cc(int nthreads, int type, int proto)
{
    cc_arg args[32]; DWORD base, after; int i, bad = 0, done;
    XS_BEGIN();
    { SOCKET w = socket(AF_INET, type, proto); closesocket(w); }
    base = xs_handles();
    memset(args, 0, sizeof args);
    for (i = 0; i < nthreads; i++) { args[i].type = type; args[i].proto = proto; args[i].cycles = 500; }
    done = xs_run_threads(nthreads, cc_thread, args, sizeof args[0], 30000, NULL);
    for (i = 0; i < nthreads; i++) bad += args[i].bad;
    EXPECT_EQ(done, nthreads);
    EXPECT_EQ(bad, 0);
    after = xs_handles();
    CHECKF(after <= base + 6, "handles base %lu after %lu", base, after);
    xs_end();
}
TEST(extra_16_threads_create_close_500_each_tcp) { concurrent_cc(16, SOCK_STREAM, IPPROTO_TCP); }
TEST(extra_16_threads_create_close_500_each_udp) { concurrent_cc(16, SOCK_DGRAM, IPPROTO_UDP); }
TEST(extra_32_threads_create_close_500_each_udp) { concurrent_cc(32, SOCK_DGRAM, IPPROTO_UDP); }

/* Sockets created on one thread are usable and closable from another after the creator thread has exited. */
static DWORD maker_thread(void *p) { SOCKET *out = (SOCKET *)p; *out = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); return 0; }
TEST(extra_socket_outlives_creating_thread_100)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < 100; i++) {
        SOCKET s = INVALID_SOCKET; struct sockaddr_in a; int len = sizeof a;
        if (xs_run_threads(1, maker_thread, &s, 0, 5000, NULL) != 1 || s == INVALID_SOCKET) { bad++; continue; }
        xs_lo4(&a, 0);
        if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(s, (struct sockaddr *)&a, &len) != 0 || !a.sin_port) bad++;
        if (closesocket(s) != 0) bad++;
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}

/* WSAWaitForMultipleEvents accepts up to 64 events and rejects 65. */
TEST(extra_wait_for_multiple_events_64_ok_65_rejected)
{
    WSAEVENT ev[65]; int i; DWORD r;
    XS_BEGIN();
    for (i = 0; i < 65; i++) ev[i] = WSACreateEvent();
    W(WSASetEvent)(ev[63]);
    r = W(WSAWaitForMultipleEvents)(64, ev, FALSE, 1000, FALSE);
    EXPECT_EQ(r, WSA_WAIT_EVENT_0 + 63);
    WSASetLastError(0);
    r = W(WSAWaitForMultipleEvents)(65, ev, FALSE, 0, FALSE);
    EXPECT_EQ(r, WSA_WAIT_FAILED);
    EXPECT_EQ(WSAGetLastError(), WSA_INVALID_PARAMETER);
    WSASetLastError(0);
    r = W(WSAWaitForMultipleEvents)(0, ev, FALSE, 0, FALSE);
    EXPECT_EQ(r, WSA_WAIT_FAILED);
    EXPECT_EQ(WSAGetLastError(), WSA_INVALID_PARAMETER);
    for (i = 0; i < 65; i++) WSACloseEvent(ev[i]);
    xs_end();
}

/* WSAPoll of a lone closed socket: probe, only the revents of the entry is asserted. */
TEST(extra_wsapoll_single_closed_socket_reports_pollnval)
{
    SOCKET s; WSAPOLLFD p; int rc;
    XS_BEGIN();
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    closesocket(s);
    p.fd = s; p.events = POLLRDNORM; p.revents = 0;
    rc = WSAPoll(&p, 1, 0);
    t_note("lone closed entry: return value %d", rc);
    EXPECT_EQ(p.revents, POLLNVAL);
    xs_end();
}

/* ---- state errors across many sockets ---------------------------------------------------------------------- */
TEST(extra_accept_on_wrong_socket_kinds_200)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < 200; i++) {
        SOCKET t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        WSASetLastError(0);
        if (accept(t, NULL, NULL) != INVALID_SOCKET || WSAGetLastError() != WSAEINVAL) bad++;
        WSASetLastError(0);
        if (accept(u, NULL, NULL) != INVALID_SOCKET || WSAGetLastError() != WSAEOPNOTSUPP) bad++;
        closesocket(t); closesocket(u);
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}

TEST(extra_io_on_listener_is_enotconn_50)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < 50; i++) {
        struct sockaddr_in a; SOCKET l = xs_listener(&a, 2); char b[4] = "abc";
        if (l == INVALID_SOCKET) { bad++; continue; }
        xs_rcvtimeo(l, 300); xs_sndtimeo(l, 300);   /* bounds the call if a stack were to block instead of failing */
        WSASetLastError(0);
        if (recv(l, b, 4, 0) != SOCKET_ERROR || WSAGetLastError() != WSAENOTCONN) bad++;
        WSASetLastError(0);
        if (send(l, b, 3, 0) != SOCKET_ERROR || WSAGetLastError() != WSAENOTCONN) bad++;
        closesocket(l);
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}

TEST(extra_so_acceptconn_true_only_on_listeners_200)
{
    int i, bad = 0;
    XS_BEGIN();
    for (i = 0; i < 200; i++) {
        struct sockaddr_in a; SOCKET l = xs_listener(&a, 2), t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int v = -1, len = sizeof v;
        if (getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &len) != 0 || v == 0) bad++;
        v = -1; len = sizeof v;
        if (getsockopt(t, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &len) != 0 || v != 0) bad++;
        closesocket(l); closesocket(t);
    }
    EXPECT_EQ(bad, 0);
    xs_end();
}

/* A refused nonblocking connect reports FD_CONNECT with WSAECONNREFUSED through WSAEnumNetworkEvents. */
TEST(extra_eventselect_refused_connect_reports_fd_connect_error_50)
{
    int i, bad = 0, badcode = 0;
    XS_BEGIN();
    for (i = 0; i < 50; i++) {
        struct sockaddr_in a; SOCKET l = xs_listener(&a, 1), c; WSAEVENT ev = WSACreateEvent(); WSANETWORKEVENTS ne;
        if (l == INVALID_SOCKET) { bad++; continue; }
        closesocket(l);
        c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        WSAEventSelect(c, ev, FD_CONNECT);
        connect(c, (struct sockaddr *)&a, sizeof a);
        if (WaitForSingleObject(ev, XS_WAIT_MS) != WAIT_OBJECT_0) { bad++; }
        else {
            memset(&ne, 0, sizeof ne);
            if (W(WSAEnumNetworkEvents)(c, ev, &ne) != 0 || !(ne.lNetworkEvents & FD_CONNECT)) bad++;
            else if (ne.iErrorCode[FD_CONNECT_BIT] != WSAECONNREFUSED) badcode++;
        }
        closesocket(c); WSACloseEvent(ev);
    }
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(badcode, 0);
    xs_end();
}

/* Several threads close the same socket at once: probe, the outcome is recorded and only crash-freedom plus
 * "at least one close succeeded" is asserted. */
typedef struct { SOCKET s; volatile LONG ok, fail; HANDLE go; } mc_arg;
static DWORD mc_thread(void *p)
{
    mc_arg *a = (mc_arg *)p;
    WaitForSingleObject(a->go, 5000);
    if (closesocket(a->s) == 0) InterlockedIncrement(&a->ok); else InterlockedIncrement(&a->fail);
    return 0;
}
TEST(extra_concurrent_close_of_one_socket_never_all_fail)
{
    int round, none = 0, over = 0;
    XS_BEGIN();
    for (round = 0; round < 50; round++) {
        mc_arg a; HANDLE h[6]; int i;
        a.s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); a.ok = a.fail = 0; a.go = CreateEventW(NULL, TRUE, FALSE, NULL);
        for (i = 0; i < 6; i++) h[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mc_thread, &a, 0, NULL);
        SetEvent(a.go);
        for (i = 0; i < 6; i++) { WaitForSingleObject(h[i], 5000); CloseHandle(h[i]); }
        if (a.ok == 0) none++;
        if (a.ok + a.fail != 6) over++;
        CloseHandle(a.go);
    }
    EXPECT_EQ(none, 0);
    EXPECT_EQ(over, 0);
    xs_end();
}
