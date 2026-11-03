/* Measures ioctlsocket: the FIONBIO / FIONREAD / SIOCATMARK commands as seen through the classic u_long
 * argument, the effect of FIONBIO on later calls, datagram FIONREAD accounting, unknown commands, and invalid
 * socket arguments.  ioctlsocket is a wrapper that passes the same four bytes as input and output buffer,
 * so its failures are the failures of the underlying control. */
#include "ib.h"

static int ib_recv1(SOCKET s, int *err)
{
    char b[4];
    int r = U(recv)(s, b, 1, 0);
    *err = ib_err();
    return r;
}

static void ib_set_rcvtimeo(SOCKET s, DWORD ms)
{
    U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
}

/* ---- FIONBIO ------------------------------------------------------------------------------------ */
IBTEST(ib_ioctlsocket_fionbio_makes_recv_nonblocking)
{
    IB_PAIR(c, s);
    u_long v = 1;
    int r, e;
    ib_seterr((int)IB_UNSET);
    r = U(ioctlsocket)(c, FIONBIO, &v);
    CHECKF(r == 0, "r=%d err=%d", r, ib_err());
    CHECK(v == 1);                         /* the argument is not rewritten */
    r = ib_recv1(c, &e);
    CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "r=%d err=%d", r, e);
    ib_close(c); ib_close(s);
}

IBTEST(ib_ioctlsocket_fionbio_zero_restores_blocking)
{
    /* Blocking mode is observed through a bounded receive timeout: a blocking read times out (WSAETIMEDOUT),
     * a non-blocking read reports WSAEWOULDBLOCK. */
    IB_PAIR(c, s);
    u_long v = 1;
    int r, e;
    U(ioctlsocket)(c, FIONBIO, &v);
    v = 0;
    r = U(ioctlsocket)(c, FIONBIO, &v);
    CHECKF(r == 0, "r=%d err=%d", r, ib_err());
    ib_set_rcvtimeo(c, 200);
    r = ib_recv1(c, &e);
    CHECKF(r == SOCKET_ERROR && e == WSAETIMEDOUT, "r=%d err=%d", r, e);
    ib_close(c); ib_close(s);
}

IBTEST(ib_ioctlsocket_fionbio_any_nonzero_value_enables)
{
    static const u_long vals[] = {1, 2, 0x100, 0x80000000u, 0xffffffffu, 0x7fffffffu};
    unsigned i;
    IB_PAIR(c, s);
    for (i = 0; i < sizeof vals / sizeof *vals; ++i) {
        u_long v = 0;
        int r, e;
        U(ioctlsocket)(c, FIONBIO, &v);
        v = vals[i];
        r = U(ioctlsocket)(c, FIONBIO, &v);
        CHECKF(r == 0 && v == vals[i], "value %#lx: r=%d err=%d v=%#lx", vals[i], r, ib_err(), v);
        r = ib_recv1(c, &e);
        CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "value %#lx: r=%d err=%d", vals[i], r, e);
    }
    ib_close(c); ib_close(s);
}

IBTEST(ib_ioctlsocket_fionbio_listener_accept_wouldblock)
{
    IB_SOCK(l, K_LISTEN4);
    u_long v = 1;
    SOCKET a;
    CHECK(U(ioctlsocket)(l, FIONBIO, &v) == 0);
    ib_seterr((int)IB_UNSET);
    a = U(accept)(l, NULL, NULL);
    CHECKF(a == INVALID_SOCKET && ib_err() == WSAEWOULDBLOCK, "err=%d", ib_err());
    if (a != INVALID_SOCKET) ib_close(a);
    ib_close(l);
}

IBTEST(ib_ioctlsocket_fionbio_listener_accept_blocking_after_reset)
{
    /* With blocking mode restored, accept on an empty queue waits; bounded by a connection from a helper
     * socket arriving, so the call returns promptly with a valid socket. */
    IB_SOCK(l, K_LISTEN4);
    struct sockaddr_in a;
    int len = sizeof a;
    u_long v = 1;
    SOCKET c, got;
    U(ioctlsocket)(l, FIONBIO, &v);
    v = 0;
    CHECK(U(ioctlsocket)(l, FIONBIO, &v) == 0);
    U(getsockname)(l, (struct sockaddr *)&a, &len);
    c = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == 0);
    got = U(accept)(l, NULL, NULL);
    CHECK(got != INVALID_SOCKET);
    if (got != INVALID_SOCKET) ib_close(got);
    ib_close(c); ib_close(l);
}

IBTEST(ib_ioctlsocket_fionbio_datagram_recvfrom_wouldblock)
{
    IB_SOCK(u, K_UDP4);
    struct sockaddr_in a;
    char b[8];
    u_long v = 1;
    int r;
    ib_loop4(&a, 0);
    CHECK(U(bind)(u, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(U(ioctlsocket)(u, FIONBIO, &v) == 0);
    ib_seterr((int)IB_UNSET);
    r = U(recvfrom)(u, b, sizeof b, 0, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEWOULDBLOCK, "r=%d err=%d", r, ib_err());
    ib_close(u);
}

IBTEST(ib_ioctlsocket_fionbio_ipv6_and_unix_accept_it)
{
    static const int kinds[] = {K_TCP6, K_UDP6, K_UNIX};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        u_long v = 1;
        int r;
        if (s == INVALID_SOCKET) { t_note("kind %d unavailable", kinds[i]); continue; }
        r = U(ioctlsocket)(s, FIONBIO, &v);
        CHECKF(r == 0, "kind %d: r=%d err=%d", kinds[i], r, ib_err());
        ib_close(s);
    }
}

IBTEST(ib_ioctlsocket_fionbio_connect_wouldblock_then_completes)
{
    /* A non-blocking connect to a loopback listener completes (immediately, or after WSAEWOULDBLOCK once the
     * socket becomes writable); either way the socket ends up connected. */
    IB_SOCK(l, K_LISTEN4);
    struct sockaddr_in a;
    int len = sizeof a, r;
    u_long v = 1;
    SOCKET c = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP), got;
    fd_set w;
    struct timeval tv = {3, 0};
    U(getsockname)(l, (struct sockaddr *)&a, &len);
    U(ioctlsocket)(c, FIONBIO, &v);
    r = U(connect)(c, (struct sockaddr *)&a, sizeof a);
    CHECKF(r == 0 || (r == SOCKET_ERROR && ib_err() == WSAEWOULDBLOCK), "r=%d err=%d", r, ib_err());
    FD_ZERO(&w); FD_SET(c, &w);
    CHECK(U(select)(0, NULL, &w, NULL, &tv) == 1);
    got = U(accept)(l, NULL, NULL);
    CHECK(got != INVALID_SOCKET);
    if (got != INVALID_SOCKET) ib_close(got);
    ib_close(c); ib_close(l);
}

/* ---- FIONREAD / SIOCATMARK values -------------------------------------------------------------- */
IBTEST(ib_ioctlsocket_fionread_fresh_and_listening_sockets_report_zero)
{
    static const int kinds[] = {K_TCP4, K_LISTEN4, K_UDP4, K_TCP6, K_UDP6};
    unsigned i;
    for (i = 0; i < 5; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        u_long v = 0xdeadbeef;
        int r;
        if (s == INVALID_SOCKET) { t_note("kind %d unavailable", kinds[i]); continue; }
        r = U(ioctlsocket)(s, FIONREAD, &v);
        CHECKF(r == 0 && v == 0, "kind %d: r=%d err=%d v=%lu", kinds[i], r, ib_err(), v);
        ib_close(s);
    }
}

IBTEST(ib_ioctlsocket_fionread_datagrams_sum_all_queued_bytes)
{
    /* For a datagram socket the count is the total of all queued datagrams, not just the first one. */
    IB_SOCK(u, K_UDP4);
    SOCKET snd = ib_mk(K_UDP4);
    struct sockaddr_in a, b;
    int len = sizeof a;
    u_long v = 0xdeadbeef;
    char rb[16];
    int r;
    ib_loop4(&a, 0);
    ib_loop4(&b, 0);
    CHECK(U(bind)(u, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(U(getsockname)(u, (struct sockaddr *)&a, &len) == 0);
    CHECK(U(bind)(snd, (struct sockaddr *)&b, sizeof b) == 0);
    CHECK(U(sendto)(snd, "abc", 3, 0, (struct sockaddr *)&a, sizeof a) == 3);
    CHECK(U(sendto)(snd, "defghi", 6, 0, (struct sockaddr *)&a, sizeof a) == 6);
    {   /* wait (bounded) until both datagrams are queued */
        int tries;
        for (tries = 0; tries < 50; ++tries) {
            v = 0;
            U(ioctlsocket)(u, FIONREAD, &v);
            if (v >= 9) break;
            Sleep(20);
        }
    }
    CHECKF(v == 9, "queued bytes %lu", v);
    r = U(recvfrom)(u, rb, sizeof rb, 0, NULL, NULL);
    CHECK(r == 3);
    v = 0xdeadbeef;
    CHECK(U(ioctlsocket)(u, FIONREAD, &v) == 0);
    CHECKF(v == 6, "after one read: %lu", v);
    r = U(recvfrom)(u, rb, sizeof rb, 0, NULL, NULL);
    CHECK(r == 6);
    v = 0xdeadbeef;
    CHECK(U(ioctlsocket)(u, FIONREAD, &v) == 0);
    CHECKF(v == 0, "after both reads: %lu", v);
    ib_close(u); ib_close(snd);
}

IBTEST(ib_ioctlsocket_siocatmark_fresh_and_idle_stream_is_at_mark)
{
    static const int kinds[] = {K_TCP4, K_LISTEN4, K_TCP6};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        u_long v = 0xdeadbeef;
        int r;
        if (s == INVALID_SOCKET) { t_note("kind %d unavailable", kinds[i]); continue; }
        r = U(ioctlsocket)(s, SIOCATMARK, &v);
        CHECKF(r == 0 && v == 1, "kind %d: r=%d err=%d v=%lu", kinds[i], r, ib_err(), v);
        ib_close(s);
    }
}

IBTEST(ib_ioctlsocket_siocatmark_datagram_is_invalid)
{
    static const int kinds[] = {K_UDP4, K_UDP6};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        u_long v = 0xdeadbeef;
        int r;
        if (s == INVALID_SOCKET) { t_note("kind %d unavailable", kinds[i]); continue; }
        ib_seterr(0);
        r = U(ioctlsocket)(s, SIOCATMARK, &v);
        CHECKF(r == SOCKET_ERROR && ib_err() == WSAEINVAL, "kind %d: r=%d err=%d", kinds[i], r, ib_err());
        CHECK(v == 0xdeadbeef);
        ib_close(s);
    }
}

IBTEST(ib_ioctlsocket_fionread_with_pending_stream_data)
{
    IB_PAIR(c, s);
    u_long v = 0xdeadbeef;
    int tries;
    CHECK(U(send)(s, "hello", 5, 0) == 5);
    for (tries = 0; tries < 50; ++tries) {
        v = 0;
        U(ioctlsocket)(c, FIONREAD, &v);
        if (v >= 5) break;
        Sleep(20);
    }
    CHECKF(v == 5, "v=%lu", v);
    ib_close(c); ib_close(s);
}

IBTEST(ib_ioctlsocket_fionread_on_stream_after_peer_close)
{
    /* Data already queued stays visible after the peer closes; an empty queue after the close reads zero. */
    IB_PAIR(c, s);
    u_long v = 0xdeadbeef;
    int tries;
    CHECK(U(send)(s, "xy", 2, 0) == 2);
    ib_close(s);
    for (tries = 0; tries < 50; ++tries) {
        v = 0;
        U(ioctlsocket)(c, FIONREAD, &v);
        if (v >= 2) break;
        Sleep(20);
    }
    CHECKF(v == 2, "v=%lu", v);
    ib_close(c);
}

/* ---- unknown commands and invalid sockets ------------------------------------------------------- */
static const long ib_unknown_cmds[] = {
    0, 1, 0x12345, (long)0xdeadbeef, (long)FIOASYNC, (long)0x80047300 /* SIOCSHIWAT */,
    (long)0x40047301 /* SIOCGHIWAT */, (long)0x80047302 /* SIOCSLOWAT */, (long)0x40047303 /* SIOCGLOWAT */,
    (long)0x28000004 /* SIO_FLUSH */, (long)0x4800001e,
};

IBTEST(ib_ioctlsocket_unknown_commands_are_opnotsupp_and_leave_argument)
{
    IB_PAIR(c, s);
    unsigned i;
    for (i = 0; i < sizeof ib_unknown_cmds / sizeof *ib_unknown_cmds; ++i) {
        u_long v = 0xdeadbeef;
        int r;
        ib_seterr(0);
        r = U(ioctlsocket)(c, ib_unknown_cmds[i], &v);
        CHECKF(r == SOCKET_ERROR && ib_err() == WSAEOPNOTSUPP, "cmd %#lx: r=%d err=%d", ib_unknown_cmds[i], r, ib_err());
        CHECKF(v == 0xdeadbeef, "cmd %#lx: argument rewritten to %#lx", ib_unknown_cmds[i], v);
    }
    ib_close(c); ib_close(s);
}

IBTEST(ib_ioctlsocket_unknown_commands_on_datagram_and_listener)
{
    static const int kinds[] = {K_UDP4, K_LISTEN4};
    unsigned i, j;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        if (s == INVALID_SOCKET) continue;
        for (j = 0; j < 4; ++j) {
            u_long v = 0;
            int r;
            ib_seterr(0);
            r = U(ioctlsocket)(s, ib_unknown_cmds[j + 1], &v);
            CHECKF(r == SOCKET_ERROR && ib_err() == WSAEOPNOTSUPP, "kind %d cmd %#lx: r=%d err=%d", kinds[i],
                   ib_unknown_cmds[j + 1], r, ib_err());
        }
        ib_close(s);
    }
}

IBTEST(ib_ioctlsocket_invalid_socket_values_are_notsock)
{
    static const SOCKET bad[] = {INVALID_SOCKET, 0, 4, 0x1234, (SOCKET)0x7ffffffe};
    static const long cmds[] = {(long)FIONBIO, (long)FIONREAD, (long)SIOCATMARK, 0x12345};
    unsigned i, j;
    for (i = 0; i < sizeof bad / sizeof *bad; ++i)
        for (j = 0; j < 4; ++j) {
            u_long v = 0;
            int r;
            ib_seterr(0);
            r = U(ioctlsocket)(bad[i], cmds[j], &v);
            CHECKF(r == SOCKET_ERROR && ib_err() == WSAENOTSOCK, "sock %#llx cmd %#lx: r=%d err=%d",
                   (unsigned long long)bad[i], cmds[j], r, ib_err());
        }
}

IBTEST(ib_ioctlsocket_closed_socket_is_notsock)
{
    SOCKET s = ib_mk(K_TCP4);
    u_long v = 0;
    int r;
    REQUIRE(s != INVALID_SOCKET);
    ib_close(s);
    ib_seterr(0);
    r = U(ioctlsocket)(s, FIONBIO, &v);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAENOTSOCK, "r=%d err=%d", r, ib_err());
    ib_seterr(0);
    r = U(ioctlsocket)(s, FIONREAD, &v);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAENOTSOCK, "r=%d err=%d", r, ib_err());
}

IBTEST(ib_ioctlsocket_event_handle_is_not_a_socket)
{
    HANDLE h = CreateEventA(NULL, TRUE, FALSE, NULL);
    u_long v = 0;
    int r;
    ib_seterr(0);
    r = U(ioctlsocket)((SOCKET)h, FIONBIO, &v);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAENOTSOCK, "r=%d err=%d", r, ib_err());
    CloseHandle(h);
}

IBTEST(ib_ioctlsocket_error_is_visible_through_lasterror_too)
{
    /* WSAGetLastError and GetLastError are the same slot. */
    u_long v = 0;
    SetLastError(0);
    CHECK(U(ioctlsocket)(INVALID_SOCKET, FIONBIO, &v) == SOCKET_ERROR);
    EXPECT_ERR(WSAENOTSOCK);
}

/* ---- the same controls through WSAIoctl ----------------------------------------------------------- */
IBTEST(ib_wsaioctl_fionbio_input_value_semantics)
{
    IB_PAIR(c, s);
    DWORD vals[3] = {1, 0, 0x55};
    DWORD n;
    int i, e;
    for (i = 0; i < 3; ++i) {
        ib_res x = ib_io(c, IB_FIONBIO, &vals[i], 4, NULL, 0, 1);
        n = x.n;
        CHECKF(IB_OK(x) && n == 0, "value %lu: r=%d err=%d n=%lu", vals[i], x.r, x.err, n);
        if (vals[i]) {
            CHECK(ib_recv1(c, &e) == SOCKET_ERROR && e == WSAEWOULDBLOCK);
        } else {
            ib_set_rcvtimeo(c, 150);
            CHECK(ib_recv1(c, &e) == SOCKET_ERROR && e == WSAETIMEDOUT);
        }
    }
    ib_close(c); ib_close(s);
}

IBTEST(ib_wsaioctl_fionread_reports_four_bytes_and_ignores_input)
{
    IB_PAIR(c, s);
    DWORD in = 0x12345678, out = IB_UNSET;
    ib_res x = ib_io(c, IB_FIONREAD, &in, 4, &out, 4, 1);
    CHECKF(IB_OK(x) && x.n == 4 && out == 0, "r=%d err=%d n=%lu out=%lu", x.r, x.err, x.n, out);
    ib_close(c); ib_close(s);
}

IBTEST(ib_wsaioctl_fionread_oversized_output_writes_four_bytes_only)
{
    IB_PAIR(c, s);
    unsigned char out[16];
    ib_res x;
    memset(out, 0xcc, sizeof out);
    x = ib_io(c, IB_FIONREAD, NULL, 0, out, sizeof out, 1);
    CHECKF(IB_OK(x) && x.n == 4, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(out[4] == 0xcc && out[15] == 0xcc);
    ib_close(c); ib_close(s);
}

IBTEST(ib_wsaioctl_siocatmark_out_too_small_leaves_count_untouched)
{
    IB_PAIR(c, s);
    unsigned char out[4] = {0xcc, 0xcc, 0xcc, 0xcc};
    ib_res x = ib_io(c, IB_SIOCATMARK, NULL, 0, out, 3, 1);
    CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == IB_UNSET, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(out[0] == 0xcc);
    ib_close(c); ib_close(s);
}
