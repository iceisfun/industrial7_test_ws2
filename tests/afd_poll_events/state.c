/* Event-mask semantics of IOCTL_AFD_POLL driven through loopback connections.
 * Measures, step by step, which event bits are reported for a stream pair, an out-of-band byte, a datagram
 * socket, a listener with a backlog, a refused connect and a closing endpoint: the mask only ever filters
 * what is reported (except the local-close indication), reserved/QoS/route bits never show up, state bits
 * are level-triggered and polling consumes nothing. Positive transitions wait on a bounded poll; negative
 * ones are taken as zero-timeout snapshots after a local action so they are deterministic. */
#include "ap.h"

#define BASE_MASK_NOISE (APE_ABORT | APE_ACCEPT | APE_CONNECT_FAIL | APE_EXPEDITED | APE_QOS | APE_GROUP_QOS)

static void expect_flags(SOCKET s, ULONG mask, ULONG want, const char *what)
{
    ULONG got = ap_now_flags(s, mask);
    CHECKF(got == want, "%s: mask %#lx got %#lx want %#lx", what, (unsigned long)mask, (unsigned long)got, (unsigned long)want);
}

static void expect_idle(SOCKET s, ULONG mask, const char *what)
{
    CHECKF(ap_idle(s, mask), "%s: mask %#lx unexpectedly reports something", what, (unsigned long)mask);
}

/* ---- stream pair, step by step -------------------------------------------------- */

TEST(apev_tcp_lifecycle_levels)
{
    AP_BEGIN();
    SOCKET c, s; char buf[8];
    ap_pair(&c, &s);
    /* a fresh established pair: writable and connected, nothing else */
    expect_flags(c, APE_ALL, APE_SEND | APE_CONNECT, "client fresh");
    expect_flags(s, APE_ALL, APE_SEND | APE_CONNECT, "server fresh");
    expect_idle(c, APE_RECEIVE | APE_DISCONNECT | APE_ABORT | APE_EXPEDITED | APE_ACCEPT | APE_CONNECT_FAIL, "client fresh quiet bits");
    /* data from the server */
    ap_send_n(s, 5);
    CK_FLAGS(ap_wait_flags(c, APE_RECEIVE), APE_RECEIVE);
    expect_flags(c, APE_ALL, APE_RECEIVE | APE_SEND | APE_CONNECT, "client with data");
    /* reading part of it leaves the level up, reading the rest drops it */
    CHECK(X.recv(c, buf, 2, 0) == 2);
    expect_flags(c, APE_RECEIVE, APE_RECEIVE, "client partly read");
    CHECK(X.recv(c, buf, 8, 0) == 3);
    expect_idle(c, APE_RECEIVE, "client fully read");
    expect_flags(c, APE_ALL, APE_SEND | APE_CONNECT, "client drained");
    /* the server half-closes: the client sees a hang-up but is still connected and writable */
    CHECK(X.shutdown(s, SD_SEND) == 0);
    CK_FLAGS(ap_wait_flags(c, APE_DISCONNECT), APE_DISCONNECT);
    expect_flags(c, APE_ALL, APE_DISCONNECT | APE_SEND | APE_CONNECT, "client after FIN");
    expect_flags(s, APE_ALL, APE_SEND | APE_CONNECT, "server after own FIN");
    /* the client closes its half too: the server now hangs up as well */
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CK_FLAGS(ap_wait_flags(s, APE_DISCONNECT), APE_DISCONNECT);
    expect_flags(s, APE_ALL, APE_DISCONNECT | APE_SEND | APE_CONNECT, "server after peer FIN");
    ap_closeS(c); ap_closeS(s);
}

/* All sixteen subsets of the four level bits that are present on a server with queued data and a
 * received FIN come back exactly as asked; the quiet bits mixed into the mask add nothing. */
TEST(apev_mask_subsets_filter_exactly)
{
    AP_BEGIN();
    SOCKET c, s; ULONG sub;
    ap_pair(&c, &s);
    ap_send_n(c, 4);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CK_FLAGS(ap_wait_flags(s, APE_DISCONNECT), APE_DISCONNECT);
    CK_FLAGS(ap_wait_flags(s, APE_RECEIVE), APE_RECEIVE);
    for (sub = 1; sub < 16; sub++) {
        ULONG want = 0, mask;
        if (sub & 1) want |= APE_RECEIVE;
        if (sub & 2) want |= APE_SEND;
        if (sub & 4) want |= APE_DISCONNECT;
        if (sub & 8) want |= APE_CONNECT;
        mask = want | BASE_MASK_NOISE;
        expect_flags(s, mask, want, "subset");
    }
    ap_closeS(c); ap_closeS(s);
}

/* An empty mask asks for nothing: a ready socket reports nothing, immediately or at the deadline. */
TEST(apev_mask_zero_reports_nothing_while_ready)
{
    AP_BEGIN();
    SOCKET c, s; ap_res r;
    ap_pair(&c, &s);
    ap_send_n(s, 3);
    CK_FLAGS(ap_wait_flags(c, APE_RECEIVE), APE_RECEIVE);
    expect_idle(c, 0, "zero mask, immediate");
    ap_run1(c, 0, AP_REL_MS(80), &r);
    CK_ST(r.ret, APS_PENDING);
    CK_ST(r.ios, APS_TIMEOUT);
    CHECK(r.info == 16 && r.out.n == 0);
    ap_closeS(c); ap_closeS(s);
}

/* Bits that name QoS, routing and address-list changes, and other undefined bits, never fire from the
 * socket states that a loopback test can create. */
TEST(apev_reserved_bits_report_nothing)
{
    AP_BEGIN();
    const ULONG quiet = APE_QOS | APE_GROUP_QOS | APE_ROUTING | APE_ADDRLIST | 0x7fffe000u;
    struct sockaddr_in a, ua; SOCKET c, s, l, cl, fresh, u1, u2;
    ap_pair(&c, &s);
    l = ap_listener(&a, 1); cl = ap_dial(&a);
    fresh = ap_sock(SOCK_STREAM);
    u1 = ap_sock(SOCK_DGRAM); u2 = ap_sock(SOCK_DGRAM);
    memset(&ua, 0, sizeof(ua)); ua.sin_family = AF_INET; ua.sin_addr.s_addr = 0x0100007Fu;
    CHECK(X.bind(u1, (struct sockaddr *)&ua, sizeof(ua)) == 0);
    { int n = sizeof(ua); CHECK(X.getsockname(u1, (struct sockaddr *)&ua, &n) == 0); }
    CHECK(X.sendto(u2, "x", 1, 0, (struct sockaddr *)&ua, sizeof(ua)) == 1);
    CK_FLAGS(ap_wait_flags(u1, APE_RECEIVE), APE_RECEIVE);
    ap_send_n(c, 2);
    CK_FLAGS(ap_wait_flags(s, APE_RECEIVE), APE_RECEIVE);
    expect_idle(c, quiet, "connected client");
    expect_idle(s, quiet, "connected server with data");
    expect_idle(l, quiet, "listener with a queued connection");
    expect_idle(fresh, quiet, "fresh stream socket");
    expect_idle(u1, quiet, "datagram socket with a datagram");
    ap_closeS(c); ap_closeS(s); ap_closeS(l); ap_closeS(cl); ap_closeS(fresh); ap_closeS(u1); ap_closeS(u2);
}

/* A poll is an observation: repeating it, in any mask order, does not use up the state it saw, and the
 * data is still there to be received afterwards. */
TEST(apev_polling_does_not_consume_state)
{
    AP_BEGIN();
    SOCKET c, s; char buf[8]; int i;
    ap_pair(&c, &s);
    ap_send_n(c, 4);
    CK_FLAGS(ap_wait_flags(s, APE_RECEIVE), APE_RECEIVE);
    for (i = 0; i < 4; i++) {
        expect_flags(s, APE_RECEIVE, APE_RECEIVE, "repeat receive");
        expect_flags(s, APE_ALL, APE_RECEIVE | APE_SEND | APE_CONNECT, "repeat all");
        expect_flags(s, APE_SEND | APE_CONNECT, APE_SEND | APE_CONNECT, "repeat send/connect");
    }
    CHECK(X.recv(s, buf, 8, 0) == 4);
    expect_idle(s, APE_RECEIVE, "after recv");
    ap_closeS(c); ap_closeS(s);
}

/* An out-of-band byte raises only the expedited bit; the normal receive bit stays down until normal data
 * arrives, and receiving the urgent byte lowers its bit. */
TEST(apev_oob_byte_isolated_from_receive)
{
    AP_BEGIN();
    SOCKET c, s; char b = 0;
    ap_pair(&c, &s);
    CHECK(X.send(c, "u", 1, MSG_OOB) == 1);
    CK_FLAGS(ap_wait_flags(s, APE_EXPEDITED), APE_EXPEDITED);
    expect_flags(s, APE_RECEIVE | APE_EXPEDITED, APE_EXPEDITED, "urgent only");
    expect_idle(s, APE_RECEIVE, "urgent is not normal data");
    expect_flags(s, APE_ALL, APE_EXPEDITED | APE_SEND | APE_CONNECT, "urgent with baseline");
    ap_send_n(c, 2);
    CK_FLAGS(ap_wait_flags(s, APE_RECEIVE), APE_RECEIVE);
    expect_flags(s, APE_RECEIVE | APE_EXPEDITED, APE_RECEIVE | APE_EXPEDITED, "urgent and normal");
    CHECK(X.recv(s, &b, 1, MSG_OOB) == 1);
    expect_flags(s, APE_RECEIVE | APE_EXPEDITED, APE_RECEIVE, "urgent received");
    ap_closeS(c); ap_closeS(s);
}

/* ---- datagram sockets ------------------------------------------------------------- */

TEST(apev_udp_receive_level_follows_queue)
{
    AP_BEGIN();
    struct sockaddr_in a; int n = sizeof(a); SOCKET r, w; char buf[16];
    r = ap_sock(SOCK_DGRAM); w = ap_sock(SOCK_DGRAM);
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007Fu;
    CHECK(X.bind(r, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(X.getsockname(r, (struct sockaddr *)&a, &n) == 0);
    expect_flags(r, APE_ALL, APE_SEND, "bound, empty");
    CHECK(X.sendto(w, "one", 3, 0, (struct sockaddr *)&a, sizeof(a)) == 3);
    CHECK(X.sendto(w, "two", 3, 0, (struct sockaddr *)&a, sizeof(a)) == 3);
    CK_FLAGS(ap_wait_flags(r, APE_RECEIVE), APE_RECEIVE);
    expect_flags(r, APE_ALL, APE_RECEIVE | APE_SEND, "two queued");
    CHECK(X.recv(r, buf, sizeof(buf), 0) == 3);
    expect_flags(r, APE_RECEIVE, APE_RECEIVE, "one still queued");
    CHECK(X.recv(r, buf, sizeof(buf), 0) == 3);
    expect_idle(r, APE_RECEIVE, "queue empty");
    expect_flags(r, APE_ALL, APE_SEND, "empty again");
    ap_closeS(r); ap_closeS(w);
}

/* A datagram socket never reports stream-state bits. */
TEST(apev_udp_has_no_stream_bits)
{
    AP_BEGIN();
    SOCKET u = ap_sock(SOCK_DGRAM);
    expect_idle(u, APE_RECEIVE | APE_DISCONNECT | APE_ABORT | APE_ACCEPT | APE_EXPEDITED | APE_CONNECT_FAIL, "fresh datagram socket");
    expect_flags(u, APE_ALL, APE_SEND, "fresh datagram socket, all bits");
    ap_closeS(u);
}

/* ---- listener ------------------------------------------------------------------------ */

/* Accept readiness follows the queue of unaccepted connections, not the arrival of the last one. */
TEST(apev_listener_accept_level_over_backlog)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 5), c1, c2, s1, s2;
    expect_idle(l, APE_ALL, "no connection yet");
    c1 = ap_dial(&a); c2 = ap_dial(&a);
    CK_FLAGS(ap_wait_flags(l, APE_ACCEPT), APE_ACCEPT);
    s1 = X.accept(l, NULL, NULL);
    CHECK(s1 != INVALID_SOCKET);
    expect_flags(l, APE_ACCEPT, APE_ACCEPT, "one still queued");
    s2 = X.accept(l, NULL, NULL);
    CHECK(s2 != INVALID_SOCKET);
    expect_idle(l, APE_ALL, "queue drained");
    ap_closeS(s1); ap_closeS(s2); ap_closeS(c1); ap_closeS(c2); ap_closeS(l);
}

TEST(apev_listener_reports_only_accept)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c = ap_dial(&a);
    CK_FLAGS(ap_wait_flags(l, APE_ACCEPT), APE_ACCEPT);
    expect_flags(l, APE_ALL, APE_ACCEPT, "all bits");
    expect_flags(l, APE_ACCEPT | BASE_MASK_NOISE, APE_ACCEPT, "noise around accept");
    expect_idle(l, APE_RECEIVE | APE_SEND | APE_CONNECT | APE_DISCONNECT | APE_ABORT | APE_EXPEDITED | APE_CONNECT_FAIL, "everything but accept");
    ap_closeS(c); ap_closeS(l);
}

/* A queued poll whose mask leaves out the accept bit is not woken by an incoming connection. */
TEST(apev_listener_poll_without_accept_bit_ignores_connection)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_fill(&in, AP_REL_MS(400), 0, 1, &l, APE_RECEIVE | APE_SEND | APE_CONNECT | APE_DISCONNECT | APE_ABORT | APE_EXPEDITED);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)l, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    c = ap_dial(&a);
    CHECK(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_TIMEOUT);
    CHECK(io.Information == 16 && out.n == 0);
    CloseHandle(ev); ap_closeS(c); ap_closeS(l);
}

/* Closing a listener ends a pending accept poll with the close indication, not an accept. */
TEST(apev_listener_close_ends_accept_poll_with_close)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_fill(&in, AP_REL_MS(5000), 0, 1, &l, APE_ACCEPT);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)l, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    ap_closeS(l);
    CHECK(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(io.Information == AP_SZ(1));
    CHECK(out.n == 1 && out.e[0].h == l);
    CK_FLAGS(out.e[0].ev, APE_CLOSE);
    CK_ST(out.e[0].st, 0);
    CloseHandle(ev);
}

/* A non-blocking connect that completes shows up as the connect bit (and writability) on the client
 * and as an accept on the listener. */
TEST(apev_nonblocking_connect_completes_to_connect_and_send)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c = ap_sock(SOCK_STREAM), s; int r;
    ap_nonblock(c);
    r = X.connect(c, (struct sockaddr *)&a, sizeof(a));
    CHECK(r == 0 || X.WSAGetLastError() == WSAEWOULDBLOCK);
    CK_FLAGS(ap_wait_flags(c, APE_CONNECT), APE_CONNECT);
    CK_FLAGS(ap_wait_flags(c, APE_SEND), APE_SEND);
    expect_flags(c, APE_ALL, APE_SEND | APE_CONNECT, "client connected");
    CK_FLAGS(ap_wait_flags(l, APE_ACCEPT), APE_ACCEPT);
    s = X.accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    ap_closeS(s); ap_closeS(c); ap_closeS(l);
}

/* ---- refused connection ---------------------------------------------------------------- */

static SOCKET refused_client(void)
{
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c = ap_sock(SOCK_STREAM);
    ap_closeS(l);                                   /* nothing listens on that port any more */
    ap_nonblock(c);
    CHECK(X.connect(c, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR);
    return c;
}

static int wait_refused(SOCKET c)
{
    ap_res r;
    ap_run1(c, APE_CONNECT_FAIL, AP_REL_MS(10000), &r);
    if (r.hung || r.ios != 0 || r.out.n != 1) { t_skip("refusal not reported within the bound"); return 0; }
    return 1;
}

TEST(apev_refused_connect_is_level_with_status)
{
    AP_BEGIN();
    SOCKET c = refused_client(); int i;
    if (!wait_refused(c)) { ap_closeS(c); return; }
    for (i = 0; i < 3; i++) {
        ap_res r;
        ap_run1(c, APE_CONNECT_FAIL, 0, &r);
        CHECKF(r.ret == 0 && r.out.n == 1 && r.out.e[0].ev == APE_CONNECT_FAIL, "repeat %d", i);
        CK_ST(r.out.e[0].st, APS_REFUSED);
    }
    ap_closeS(c);
}

/* A failed connect is not "connected": the connect and writability bits stay down. */
TEST(apev_refused_connect_is_not_connected_or_writable)
{
    AP_BEGIN();
    SOCKET c = refused_client();
    if (!wait_refused(c)) { ap_closeS(c); return; }
    expect_idle(c, APE_CONNECT | APE_SEND, "failed connect, connect/send bits");
    expect_flags(c, APE_CONNECT_FAIL | APE_CONNECT | APE_SEND, APE_CONNECT_FAIL, "failed connect, combined");
    ap_closeS(c);
}

/* The status word belongs to the entry: the failed one carries the refusal, a healthy one carries 0. */
TEST(apev_status_is_per_entry)
{
    AP_BEGIN();
    SOCKET f = refused_client(), c, s; ap_res r; SOCKET hs[2]; ULONG m[2] = { APE_CONNECT_FAIL, APE_SEND };
    ap_pair(&c, &s);
    if (!wait_refused(f)) { ap_closeS(f); ap_closeS(c); ap_closeS(s); return; }
    hs[0] = f; hs[1] = c;
    ap_run((HANDLE)c, AP_REL_MS(2000), 0, 2, hs, m, 4000, &r);
    CK_ST(r.ret, APS_SUCCESS);
    CHECK(r.out.n == 2 && r.info == AP_SZ(2));
    CHECK(r.out.e[0].h == f && r.out.e[0].ev == APE_CONNECT_FAIL);
    CK_ST(r.out.e[0].st, APS_REFUSED);
    CHECK(r.out.e[1].h == c && r.out.e[1].ev == APE_SEND);
    CK_ST(r.out.e[1].st, 0);
    ap_closeS(f); ap_closeS(c); ap_closeS(s);
}

/* ---- local close ------------------------------------------------------------------------ */

/* The close indication is delivered whatever the entry's mask says, as long as the entry names the
 * endpoint that went away. */
TEST(apev_close_ignores_the_mask)
{
    AP_BEGIN();
    static const ULONG masks[] = { APE_RECEIVE, APE_ACCEPT | APE_CONNECT_FAIL | APE_ABORT | APE_DISCONNECT | APE_EXPEDITED, APE_QOS };
    size_t i;
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        SOCKET c, s; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
        ap_pair(&c, &s);
        ap_fill(&in, AP_REL_MS(5000), 0, 1, &c, masks[i]);
        memset(&out, 0, sizeof(out));
        CK_ST(ap_submit((HANDLE)s, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
        ap_closeS(c);
        CHECKF(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0, "mask %#lx: no completion", (unsigned long)masks[i]);
        CK_ST(io.Status, APS_SUCCESS);
        CHECK(out.n == 1 && out.e[0].h == c);
        CK_FLAGS(out.e[0].ev, APE_CLOSE);
        CK_ST(out.e[0].st, 0);
        CloseHandle(ev); ap_closeS(s);
    }
}

/* With several entries only the one whose endpoint closed is reported. */
TEST(apev_close_reports_only_the_closed_entry)
{
    AP_BEGIN();
    SOCKET a, b, c, d; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event(); SOCKET hs[2];
    ap_pair(&a, &b); ap_pair(&c, &d);
    hs[0] = a; hs[1] = c;
    ap_fill(&in, AP_REL_MS(5000), 0, 2, hs, APE_RECEIVE);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)b, ev, &io, &in, AP_SZ(2), &out, AP_SZ(2)), APS_PENDING);
    ap_closeS(c);
    CHECK(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(io.Information == AP_SZ(1));
    CHECK(out.n == 1 && out.e[0].h == c);
    CK_FLAGS(out.e[0].ev, APE_CLOSE);
    CloseHandle(ev); ap_closeS(a); ap_closeS(b); ap_closeS(d);
}

/* Closing one of two handles to the same endpoint is not the end of the endpoint: no indication, the
 * request runs to its own deadline. */
TEST(apev_close_of_one_duplicate_is_not_local_close)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE dup = NULL; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_pair(&c, &s);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    ap_fill(&in, AP_REL_MS(400), 0, 1, &c, APE_RECEIVE);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)s, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    ap_closeS(c);                                     /* the duplicate keeps the endpoint open */
    CHECK(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_TIMEOUT);
    CHECK(io.Information == 16 && out.n == 0);
    CloseHandle(dup); CloseHandle(ev); ap_closeS(s);
}

/* Closing an unrelated socket does not disturb a queued request. */
TEST(apev_close_of_unrelated_socket_leaves_poll_alone)
{
    AP_BEGIN();
    SOCKET c, s, other; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event();
    ap_pair(&c, &s); other = ap_sock(SOCK_STREAM);
    ap_fill(&in, AP_REL_MS(300), 0, 1, &c, APE_RECEIVE);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)c, ev, &io, &in, AP_SZ(1), &out, AP_SZ(1)), APS_PENDING);
    ap_closeS(other);
    CHECK(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_TIMEOUT);
    CHECK(out.n == 0);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

/* ---- reset and hang-up gating ------------------------------------------------------------ */

TEST(apev_reset_bit_only_when_asked_for)
{
    AP_BEGIN();
    SOCKET c, s;
    ap_pair(&c, &s);
    ap_rst_close(s);
    CK_FLAGS(ap_wait_flags(c, APE_ABORT), APE_ABORT);
    expect_flags(c, APE_ABORT, APE_ABORT, "reset, abort only");
    expect_flags(c, APE_ABORT | BASE_MASK_NOISE, APE_ABORT, "reset with noise");
    {
        ULONG got = ap_now_flags(c, APE_RECEIVE | APE_SEND | APE_DISCONNECT | APE_CONNECT | APE_ACCEPT | APE_EXPEDITED);
        CHECKF((got & APE_ABORT) == 0, "abort reported without being asked: %#lx", (unsigned long)got);
    }
    ap_closeS(c);
}

TEST(apev_hangup_bit_only_when_asked_for)
{
    AP_BEGIN();
    SOCKET c, s;
    ap_pair(&c, &s);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CK_FLAGS(ap_wait_flags(s, APE_DISCONNECT), APE_DISCONNECT);
    {
        ULONG got = ap_now_flags(s, APE_ALL & ~APE_DISCONNECT);
        CHECKF((got & APE_DISCONNECT) == 0, "hang-up reported without being asked: %#lx", (unsigned long)got);
        CK_FLAGS(got, APE_SEND | APE_CONNECT);
    }
    ap_closeS(c); ap_closeS(s);
}
