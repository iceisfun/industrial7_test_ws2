/* What the other end of a connection sees when an endpoint is closed: orderly end-of-stream, reset on unread
 * data, SO_LINGER variants, closing through each of the three handle routes, datagram peers, and the raw AFD
 * poll bits that the peer's endpoint reports afterwards (disconnect vs abort).
 */
#include "acc.h"

typedef struct { LONGLONG timeout; ULONG count; ULONG exclusive; struct { ULONG_PTR h; ULONG flags; LONG status; } e[1]; } pollin_t;

/* One zero-timeout AFD poll on s for `mask`; returns the event bits present (or 0xFFFFFFFF if the call failed). */
static ULONG poll_now(SOCKET s, ULONG mask)
{
    pollin_t pi; IO_STATUS_BLOCK io; HANDLE ev = acc_event(); LONG st;
    memset(&pi, 0, sizeof pi);
    pi.timeout = 0; pi.count = 1;
    pi.e[0].h = (ULONG_PTR)s; pi.e[0].flags = mask;
    memset(&io, 0, sizeof io);
    st = UN(NtDeviceIoControlFile)((HANDLE)s, ev, NULL, NULL, &io, AFD_IOCTL_POLL, &pi, sizeof pi, &pi, sizeof pi);
    if (st == ST_PENDING) { WaitForSingleObject(ev, ACC_WAIT); st = io.Status; }
    CloseHandle(ev);
    if (st != ST_SUCCESS) return 0xFFFFFFFFu;
    return pi.count ? pi.e[0].flags : 0;
}
#define ALLBITS (AFD_POLL_RECEIVE | 0x2 | AFD_POLL_SEND | AFD_POLL_DISC | AFD_POLL_ABORT | 0x100)

/* ---- orderly close ---------------------------------------------------------------------------------------- */
static void graceful_case(int how)
{
    char b[16]; int r, e = 0;
    UP();
    PAIR(c, s);
    CHECK(U(send)(c, "abc", 3, 0) == 3);
    acc_close(c, how);
    r = acc_recv(s, b, sizeof b, &e);
    EXPECT_EQ(r, 3);
    EXPECT_EQ(memcmp(b, "abc", 3), 0);
    EXPECT_EQ(acc_recv(s, b, sizeof b, &e), 0);        /* then end-of-stream */
    EXPECT_EQ(acc_recv(s, b, sizeof b, &e), 0);        /* and it stays that way */
    CLOSES(s);
}
TEST(cc_peer_graceful_closesocket) { graceful_case(CL_SOCKET); }
TEST(cc_peer_graceful_closehandle) { graceful_case(CL_HANDLE); }
TEST(cc_peer_graceful_ntclose)     { graceful_case(CL_NT); }

/* Sending toward a peer that closed orderly: the first send is accepted, the stack then learns of the reset. */
TEST(cc_peer_send_after_peer_close_eventually_fails)
{
    int i, e = 0, r = 0;
    UP();
    PAIR(c, s);
    CLOSES(s);
    for (i = 0; i < 50; i++) {
        r = U(send)(c, "x", 1, 0);
        if (r < 0) { e = WERR(); break; }
        Sleep(20);
    }
    CHECKF(r < 0, "sends kept succeeding");
    CHECKF(e == WSAECONNRESET || e == WSAECONNABORTED, "err %d", e);
    CLOSES(c);
}

/* ---- unread data turns a close into a reset ------------------------------------------------------------- */
static void unread_case(int how)
{
    char b[16]; int r, e = 0, i;
    UP();
    PAIR(c, s);
    CHECK(U(send)(s, "zzzz", 4, 0) == 4);
    for (i = 0; i < 100 && acc_avail(c) < 4; i++) Sleep(10);
    EXPECT_EQ(acc_avail(c), 4);
    acc_close(c, how);                    /* closed with 4 unread bytes in its receive queue */
    r = acc_recv(s, b, sizeof b, &e);
    CHECK(r < 0); EXPECT_EQ(e, WSAECONNRESET);
    CLOSES(s);
}
TEST(cc_peer_unread_data_close_resets_closesocket) { unread_case(CL_SOCKET); }
TEST(cc_peer_unread_data_close_resets_closehandle) { unread_case(CL_HANDLE); }
TEST(cc_peer_unread_data_close_resets_ntclose)     { unread_case(CL_NT); }

/* Data the closing side had already read leaves nothing unread: the close is orderly. */
TEST(cc_peer_read_all_data_then_close_is_orderly)
{
    char b[16]; int r, e = 0, i;
    UP();
    PAIR(c, s);
    CHECK(U(send)(s, "zzzz", 4, 0) == 4);
    for (i = 0; i < 100 && acc_avail(c) < 4; i++) Sleep(10);
    EXPECT_EQ(acc_recv(c, b, 4, &e), 4);
    CLOSES(c);
    r = acc_recv(s, b, sizeof b, &e);
    EXPECT_EQ(r, 0);
    CLOSES(s);
}

/* ---- SO_LINGER ---------------------------------------------------------------------------------------------- */
/* SO_LINGER is honoured by the closesocket path only (it performs the abortive disconnect itself before releasing
 * the handle); releasing the same endpoint with CloseHandle / NtClose is an ordinary orderly close. */
static void linger_close_case(int how, int want_reset)
{
    char b[16]; int r, e = 0;
    UP();
    PAIR(c, s);
    acc_linger(c, 1, 0);
    acc_close(c, how);
    r = acc_recv(s, b, sizeof b, &e);
    if (want_reset) { CHECK(r < 0); EXPECT_EQ(e, WSAECONNRESET); }
    else EXPECT_EQ(r, 0);
    CLOSES(s);
}
TEST(cc_linger_zero_resets_peer_closesocket)      { linger_close_case(CL_SOCKET, 1); }
TEST(cc_linger_zero_closehandle_is_orderly)       { linger_close_case(CL_HANDLE, 0); }
TEST(cc_linger_zero_ntclose_is_orderly)           { linger_close_case(CL_NT, 0); }

/* Data queued for the peer but not yet read is discarded by an abortive close: the peer sees only the reset. */
TEST(cc_linger_zero_discards_data_the_peer_has_not_read)
{
    char b[16]; int r, e = 0, i;
    UP();
    PAIR(c, s);
    CHECK(U(send)(c, "payload", 7, 0) == 7);
    for (i = 0; i < 100 && acc_avail(s) < 7; i++) Sleep(10);
    acc_rst_close(c);
    r = acc_recv(s, b, sizeof b, &e);
    CHECKF(r < 0 && e == WSAECONNRESET, "r=%d e=%d", r, e);
    CLOSES(s);
}

/* Linger on with a timeout is an orderly close: all queued data is delivered, then end-of-stream. */
TEST(cc_linger_timeout_close_delivers_data_then_eof)
{
    char b[64], big[8192]; int r, e = 0, got = 0;
    UP();
    PAIR(c, s);
    memset(big, 'q', sizeof big);
    CHECK(U(send)(c, big, sizeof big, 0) == (int)sizeof big);
    acc_linger(c, 1, 5);
    EXPECT_EQ(CLOSES(c), 0);
    while (got < (int)sizeof big && (r = acc_recv(s, b, sizeof b, &e)) > 0) got += r;
    EXPECT_EQ(got, (int)sizeof big);
    EXPECT_EQ(acc_recv(s, b, sizeof b, &e), 0);
    CLOSES(s);
}

/* The linger option reads back what was set, and is per endpoint (an accepted socket starts without it). */
TEST(cc_linger_readback_and_default)
{
    struct linger lg; int n = sizeof lg;
    UP();
    PAIR(c, s);
    memset(&lg, 0x7f, sizeof lg);
    CHECK(U(getsockopt)(c, SOL_SOCKET, SO_LINGER, (char *)&lg, &n) == 0);
    EXPECT_EQ(lg.l_onoff, 0);
    acc_linger(c, 1, 9);
    CHECK(U(getsockopt)(c, SOL_SOCKET, SO_LINGER, (char *)&lg, &n) == 0);
    EXPECT_EQ(lg.l_onoff, 1); EXPECT_EQ(lg.l_linger, 9);
    memset(&lg, 0x7f, sizeof lg);
    CHECK(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, &n) == 0);
    EXPECT_EQ(lg.l_onoff, 0);
    CLOSES(c); CLOSES(s);
}

/* Abortive close on a socket that was never connected, bound, or listening is silent and succeeds. */
TEST(cc_linger_zero_close_unconnected_succeeds)
{
    SOCKET a, b, l;
    UP();
    a = acc_sock(SOCK_STREAM); acc_linger(a, 1, 0);
    EXPECT_EQ(CLOSES(a), 0);
    b = acc_udp(NULL); acc_linger(b, 1, 0);       /* datagram: option refused, close still fine */
    EXPECT_EQ(CLOSES(b), 0);
    l = acc_listener(NULL); acc_linger(l, 1, 0);
    EXPECT_EQ(CLOSES(l), 0);
}

/* A listener closed with queued, never-accepted connections resets those clients. */
TEST(cc_peer_listener_close_resets_unaccepted_clients)
{
    struct sockaddr_in a; SOCKET l, c; char b[8]; int r, e = 0;
    UP();
    l = acc_listener(&a);
    REQUIRE(l != INVALID_SOCKET);
    c = acc_sock(SOCK_STREAM);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == 0);   /* completed by the stack, queued on the backlog */
    acc_timeo(c, ACC_WAIT);
    CLOSES(l);
    r = acc_recv(c, b, sizeof b, &e);
    CHECKF(r < 0 && e == WSAECONNRESET, "r=%d e=%d", r, e);
    CLOSES(c);
}

/* The same listener close does not disturb connections that were already accepted. */
TEST(cc_peer_listener_close_keeps_accepted_connection)
{
    struct sockaddr_in a; SOCKET l, c, s; char b[8]; int e = 0;
    UP();
    l = acc_listener(&a);
    REQUIRE(l != INVALID_SOCKET);
    c = acc_sock(SOCK_STREAM);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == 0);
    acc_timeo(l, ACC_WAIT);
    s = U(accept)(l, NULL, NULL);
    CLOSES(l);
    REQUIRE(s != INVALID_SOCKET);
    CHECK(U(send)(c, "ok", 2, 0) == 2);
    acc_timeo(s, ACC_WAIT);
    EXPECT_EQ(acc_recv(s, b, 8, &e), 2);
    CLOSES(c); CLOSES(s);
}

/* ---- half close and close ------------------------------------------------------------------------------- */
TEST(cc_peer_shutdown_send_then_close_one_eof)
{
    char b[8]; int e = 0;
    UP();
    PAIR(c, s);
    CHECK(U(shutdown)(c, SD_SEND) == 0);
    EXPECT_EQ(acc_recv(s, b, 8, &e), 0);
    CLOSES(c);
    EXPECT_EQ(acc_recv(s, b, 8, &e), 0);               /* the close adds nothing */
    CLOSES(s);
}

TEST(cc_peer_half_closed_peer_can_still_send)
{
    char b[8]; int e = 0;
    UP();
    PAIR(c, s);
    CHECK(U(shutdown)(c, SD_SEND) == 0);
    CHECK(U(send)(s, "back", 4, 0) == 4);
    EXPECT_EQ(acc_recv(c, b, 8, &e), 4);
    CLOSES(c); CLOSES(s);
}

/* After the endpoint is shut down for sending, its own send fails with WSAESHUTDOWN, and close is still fine. */
TEST(cc_peer_send_after_own_shutdown_is_eshutdown)
{
    PAIR(c, s);
    UP();
    CHECK(U(shutdown)(c, SD_SEND) == 0);
    WSETERR(0);
    CHECK(U(send)(c, "x", 1, 0) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAESHUTDOWN);
    EXPECT_EQ(CLOSES(c), 0);
    CLOSES(s);
}

/* ---- raw poll bits on the surviving side ------------------------------------------------------------------ */
TEST(cc_peer_poll_bits_after_orderly_close)
{
    ULONG f;
    UP();
    PAIR(c, s);
    CLOSES(c);
    Sleep(50);
    f = poll_now(s, ALLBITS);
    CHECKF(f != 0xFFFFFFFFu, "poll failed");
    CHECKF(f & AFD_POLL_DISC, "no disconnect bit: %#lx", (unsigned long)f);
    CHECKF(!(f & AFD_POLL_ABORT), "unexpected abort bit: %#lx", (unsigned long)f);
    CLOSES(s);
}

TEST(cc_peer_poll_bits_after_reset)
{
    ULONG f;
    UP();
    PAIR(c, s);
    acc_rst_close(c);
    Sleep(50);
    f = poll_now(s, ALLBITS);
    CHECKF(f != 0xFFFFFFFFu, "poll failed");
    CHECKF(f & AFD_POLL_ABORT, "no abort bit: %#lx", (unsigned long)f);
    CLOSES(s);
}

TEST(cc_peer_poll_bits_connected_idle)
{
    ULONG f;
    UP();
    PAIR(c, s);
    f = poll_now(s, ALLBITS);
    EXPECT_EQ(f, AFD_POLL_SEND);          /* writable, nothing to read, no disconnect */
    CLOSES(c); CLOSES(s);
}

/* ---- datagram peers ---------------------------------------------------------------------------------------- */
/* A connected datagram socket whose peer port was closed gets the unreachable indication as a receive error. */
TEST(cc_peer_udp_connected_closed_peer_reports_connreset)
{
    struct sockaddr_in pa; SOCKET a, b; char buf[8]; int e = 0, r, i;
    UP();
    a = acc_udp(NULL); b = acc_udp(&pa);
    REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET);
    CHECK(U(connect)(a, (struct sockaddr *)&pa, sizeof pa) == 0);
    CLOSES(b);
    acc_timeo(a, 2000);
    CHECK(U(send)(a, "x", 1, 0) == 1);
    r = acc_recv(a, buf, sizeof buf, &e);
    CHECKF(r < 0 && e == WSAECONNRESET, "r=%d e=%d", r, e);
    CLOSES(a);
}

/* With the connection-reset report disabled the same sequence just times out. */
TEST(cc_peer_udp_connreset_report_can_be_disabled)
{
    struct sockaddr_in pa; SOCKET a, b; char buf[8]; int e = 0, r; DWORD got = 0; BOOL off = FALSE;
    UP();
    a = acc_udp(NULL); b = acc_udp(&pa);
    REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET);
    CHECK(U(WSAIoctl)(a, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &got, NULL, NULL) == 0);
    CHECK(U(connect)(a, (struct sockaddr *)&pa, sizeof pa) == 0);
    CLOSES(b);
    acc_timeo(a, 400);
    CHECK(U(send)(a, "x", 1, 0) == 1);
    r = acc_recv(a, buf, sizeof buf, &e);
    CHECKF(r < 0 && e == WSAETIMEDOUT, "r=%d e=%d", r, e);
    CLOSES(a);
}

/* Closing a datagram socket never resets or ends anything for its former peer's own endpoint. */
TEST(cc_peer_udp_close_leaves_peer_usable)
{
    struct sockaddr_in pa, qa; SOCKET a, b, c; char buf[8]; int e = 0;
    UP();
    a = acc_udp(&pa); b = acc_udp(NULL); c = acc_udp(&qa);
    REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET && c != INVALID_SOCKET);
    CLOSES(b);
    acc_timeo(a, ACC_WAIT);
    CHECK(U(sendto)(c, "hi", 2, 0, (struct sockaddr *)&pa, sizeof pa) == 2);
    EXPECT_EQ(acc_recv(a, buf, 8, &e), 2);
    CLOSES(a); CLOSES(c);
}

/* ---- the endpoint is gone: every address is reusable at once ------------------------------------------- */
TEST(cc_peer_bound_port_released_by_close)
{
    struct sockaddr_in a, b; SOCKET s, t;
    UP();
    s = acc_udp(&a);
    REQUIRE(s != INVALID_SOCKET);
    CLOSES(s);
    t = acc_sock(SOCK_DGRAM);
    b = a;
    EXPECT_EQ(U(bind)(t, (struct sockaddr *)&b, sizeof b), 0);       /* the same datagram port binds again */
    CLOSES(t);
}

TEST(cc_peer_listener_port_released_by_close)
{
    struct sockaddr_in a; SOCKET l, m;
    UP();
    l = acc_listener(&a);
    REQUIRE(l != INVALID_SOCKET);
    CLOSES(l);
    m = acc_sock(SOCK_STREAM);
    EXPECT_EQ(U(bind)(m, (struct sockaddr *)&a, sizeof a), 0);
    EXPECT_EQ(U(listen)(m, 2), 0);
    CLOSES(m);
}

/* A bound-but-open endpoint keeps the address: a second bind without reuse fails with WSAEADDRINUSE. */
TEST(cc_peer_bound_port_held_while_open)
{
    struct sockaddr_in a; SOCKET s, t;
    UP();
    s = acc_udp(&a);
    REQUIRE(s != INVALID_SOCKET);
    t = acc_sock(SOCK_DGRAM);
    WSETERR(0);
    CHECK(U(bind)(t, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    EXPECT_EQ(WERR(), WSAEADDRINUSE);
    CLOSES(t); CLOSES(s);
}
