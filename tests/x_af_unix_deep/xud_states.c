/* Readiness and error behavior of an AF_UNIX stream socket across its life: fresh, bound, listening, a listener
 * with a connection waiting, connected idle, connected with data, peer half-closed, peer closed, peer reset,
 * locally shut down, and after a failed connect. One table row per state; each property (WSAPoll, select,
 * ioctl/option queries, event selection, plain I/O, names) is its own test that builds the state afresh. */
#include "xud.h"

enum { S_FRESH, S_BOUND, S_LISTEN, S_CONN, S_DATA, S_PEER_SD, S_PEER_CLOSED, S_PEER_RST, S_SELF_SD, S_FAILED, S_PENDING, S_COUNT };

struct st { SOCKET a, peer, lis; char path[MAX_PATH]; int n; };

/* Build state s. The socket under test is st->a. */
static int make(struct st *st, int s)
{
    SOCKADDR_UN ad;
    st->a = st->peer = st->lis = INVALID_SOCKET;
    x_addr(&ad, x_path("st.sock"));
    strcpy(st->path, ad.sun_path);
    if (!x_up()) return 0;
    if (s == S_FRESH) { st->a = x_sock(); return st->a != INVALID_SOCKET; }
    if (s == S_BOUND) { st->a = x_sock(); return st->a != INVALID_SOCKET && x_bind(st->a, &ad) == 0; }
    if (s == S_LISTEN) { st->a = x_sock(); return st->a != INVALID_SOCKET && x_bind(st->a, &ad) == 0 && U(listen)(st->a, 3) == 0; }
    if (s == S_FAILED) {
        st->a = x_sock();
        if (st->a == INVALID_SOCKET) return 0;
        x_blocking(st->a, FALSE);
        return x_connect(st->a, &ad) != 0 && x_err() == WSAECONNREFUSED;
    }
    st->lis = x_sock();
    if (st->lis == INVALID_SOCKET || x_bind(st->lis, &ad) || U(listen)(st->lis, 3)) return 0;
    if (s == S_PENDING) {
        st->peer = x_sock();
        x_blocking(st->peer, FALSE);
        x_connect(st->peer, &ad);
        {   /* the listener is readable once the connection is queued */
            int ok = x_readable(st->lis, 3000);
            st->a = st->lis; st->lis = INVALID_SOCKET;
            return ok;
        }
    }
    st->a = x_sock();
    x_blocking(st->a, FALSE);
    x_connect(st->a, &ad);
    st->peer = x_accept_wait(st->lis);
    if (st->peer == INVALID_SOCKET) return 0;
    x_blocking(st->a, TRUE);
    if (s == S_DATA) { U(send)(st->peer, "data", 4, 0); return x_readable(st->a, 3000); }
    if (s == S_PEER_SD) { U(shutdown)(st->peer, SD_SEND); return x_readable(st->a, 3000); }
    if (s == S_PEER_CLOSED) { U(closesocket)(st->peer); st->peer = INVALID_SOCKET; return x_readable(st->a, 3000); }
    if (s == S_PEER_RST) {
        LINGER lg = { 1, 0 };
        U(setsockopt)(st->peer, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg);
        U(closesocket)(st->peer);
        st->peer = INVALID_SOCKET;
        return x_readable(st->a, 3000);
    }
    if (s == S_SELF_SD) { U(shutdown)(st->a, SD_BOTH); return 1; }
    return 1;   /* S_CONN */
}
static void drop(struct st *st)
{
    if (st->a != INVALID_SOCKET) U(closesocket)(st->a);
    if (st->peer != INVALID_SOCKET) U(closesocket)(st->peer);
    if (st->lis != INVALID_SOCKET) U(closesocket)(st->lis);
    DeleteFileA(st->path);
}

static const char *state_names[S_COUNT] = { "fresh", "bound", "listening", "connected", "connected_with_data", "peer_half_closed",
    "peer_closed", "peer_reset", "self_shutdown_both", "failed_connect", "listener_with_pending" };

/* ---- WSAPoll ---- */
static const unsigned short poll_rw[S_COUNT]   = { 0, 0, 0, 0x10, 0x110, 0x12, 0x12, 0x13, 0x10, 0x13, 0x100 };
static const unsigned short poll_rd[S_COUNT]   = { 0, 0, 0, 0,    0x100, 0x02, 0x02, 0x03, 0,    0,    0x100 };
static const unsigned short poll_wr[S_COUNT]   = { 0, 0, 0, 0x10, 0x10,  0x12, 0x12, 0x13, 0x10, 0x13, 0 };
static const unsigned short poll_none[S_COUNT] = { 0, 0, 0, 0,    0,     0x02, 0x02, 0x03, 0,    0,    0 };

static unsigned short do_poll(SOCKET s, short ev, int *n)
{
    WSAPOLLFD p;
    p.fd = s; p.events = ev; p.revents = 0;
    *n = U(WSAPoll)(&p, 1, 0);
    return (unsigned short)p.revents;
}
static void poll_state(int s)
{
    struct st st;
    int n;
    UP();
    if (!make(&st, s)) { t_skip("cannot build state %s", state_names[s]); drop(&st); return; }
    XEQ(do_poll(st.a, POLLRDNORM | POLLWRNORM, &n), poll_rw[s]);   XEQ(n, poll_rw[s] != 0);
    XEQ(do_poll(st.a, POLLRDNORM, &n), poll_rd[s]);                 XEQ(n, poll_rd[s] != 0);
    XEQ(do_poll(st.a, POLLWRNORM, &n), poll_wr[s]);                 XEQ(n, poll_wr[s] != 0);
    XEQ(do_poll(st.a, 0, &n), poll_none[s]);                        XEQ(n, poll_none[s] != 0);
    XEQ(do_poll(st.a, POLLRDBAND, &n), poll_none[s]);               XEQ(n, poll_none[s] != 0);
    drop(&st);
}
#define PT(id, nm) TEST(xud_state_poll_##nm) { poll_state(id); }
PT(S_FRESH, fresh) PT(S_BOUND, bound) PT(S_LISTEN, listening) PT(S_CONN, connected) PT(S_DATA, connected_with_data)
PT(S_PEER_SD, peer_half_closed) PT(S_PEER_CLOSED, peer_closed) PT(S_PEER_RST, peer_reset) PT(S_SELF_SD, self_shutdown_both)
PT(S_FAILED, failed_connect) PT(S_PENDING, listener_with_pending)

/* ---- select ---- */
static const signed char sel[S_COUNT][3] = {
    { 0, 0, 0 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0, 1, 0 }, { 1, 1, 0 }, { 1, 1, 0 }, { 1, 1, 0 }, { 1, 1, 0 }, { 0, 1, 0 }, { 0, 0, 1 }, { 1, 0, 0 } };
static void select_state(int s)
{
    struct st st;
    fd_set r, w, x;
    struct timeval tv = { 0, 0 };
    int n;
    UP();
    if (!make(&st, s)) { t_skip("cannot build state %s", state_names[s]); drop(&st); return; }
    FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
    FD_SET(st.a, &r); FD_SET(st.a, &w); FD_SET(st.a, &x);
    n = U(select)(0, &r, &w, &x, &tv);
    XEQ(x_isset(st.a, &r), sel[s][0]);
    XEQ(x_isset(st.a, &w), sel[s][1]);
    XEQ(x_isset(st.a, &x), sel[s][2]);
    XEQ(n, sel[s][0] + sel[s][1] + sel[s][2]);
    drop(&st);
}
#define ST(id, nm) TEST(xud_state_select_##nm) { select_state(id); }
ST(S_FRESH, fresh) ST(S_BOUND, bound) ST(S_LISTEN, listening) ST(S_CONN, connected) ST(S_DATA, connected_with_data)
ST(S_PEER_SD, peer_half_closed) ST(S_PEER_CLOSED, peer_closed) ST(S_PEER_RST, peer_reset) ST(S_SELF_SD, self_shutdown_both)
ST(S_FAILED, failed_connect) ST(S_PENDING, listener_with_pending)

/* ---- queries that must not depend on the state, and those that do ---- */
static void query_state(int s)
{
    struct st st;
    u_long v;
    int so, l, ac;
    UP();
    if (!make(&st, s)) { t_skip("cannot build state %s", state_names[s]); drop(&st); return; }
    v = 77;
    XEQ(U(ioctlsocket)(st.a, FIONREAD, &v), 0);
    XEQ(v, s == S_DATA ? 4 : 0);
    v = 77;
    XEQ(U(ioctlsocket)(st.a, SIOCATMARK, &v), 0);
    XEQ(v, 1);                                  /* no out-of-band data exists, the stream is always at the mark */
    so = -1; l = sizeof so;
    XEQ(U(getsockopt)(st.a, SOL_SOCKET, SO_ERROR, (char *)&so, &l), 0);
    XEQ(so, 0);                                 /* even after reset and failure: the errors are returned by calls, not here */
    ac = -1; l = sizeof ac;
    XEQ(U(getsockopt)(st.a, SOL_SOCKET, SO_ACCEPTCONN, (char *)&ac, &l), 0);
    XEQ(ac, (s == S_LISTEN || s == S_PENDING) ? 1 : 0);
    drop(&st);
}
#define QT(id, nm) TEST(xud_state_query_##nm) { query_state(id); }
QT(S_FRESH, fresh) QT(S_BOUND, bound) QT(S_LISTEN, listening) QT(S_CONN, connected) QT(S_DATA, connected_with_data)
QT(S_PEER_SD, peer_half_closed) QT(S_PEER_CLOSED, peer_closed) QT(S_PEER_RST, peer_reset) QT(S_SELF_SD, self_shutdown_both)
QT(S_FAILED, failed_connect) QT(S_PENDING, listener_with_pending)

/* ---- event selection: events reported the moment the socket is registered ---- */
static const long ev_mask[S_COUNT] = { 0, 0, 0, 0x12, 0x13, 0x32, 0x32, 0x32, 0x12, 0x10, 0x08 };
static void events_state(int s)
{
    struct st st;
    WSAEVENT ev;
    WSANETWORKEVENTS ne;
    UP();
    if (!make(&st, s)) { t_skip("cannot build state %s", state_names[s]); drop(&st); return; }
    ev = U(WSACreateEvent)();
    XEQ(U(WSAEventSelect)(st.a, ev, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE), 0);
    WaitForSingleObject(ev, ev_mask[s] ? 3000 : 150);
    memset(&ne, 0, sizeof ne);
    XEQ(U(WSAEnumNetworkEvents)(st.a, ev, &ne), 0);
    XEQ(ne.lNetworkEvents, ev_mask[s]);
    XEQ(ne.iErrorCode[FD_READ_BIT], 0);
    XEQ(ne.iErrorCode[FD_WRITE_BIT], 0);
    XEQ(ne.iErrorCode[FD_ACCEPT_BIT], 0);
    XEQ(ne.iErrorCode[FD_CONNECT_BIT], s == S_FAILED ? WSAECONNREFUSED : 0);
    XEQ(ne.iErrorCode[FD_CLOSE_BIT], s == S_PEER_RST ? WSAECONNABORTED : 0);   /* a reset surfaces as an abort here */
    U(WSAEventSelect)(st.a, NULL, 0);
    U(WSACloseEvent)(ev);
    drop(&st);
}
#define ET(id, nm) TEST(xud_state_events_##nm) { events_state(id); }
ET(S_FRESH, fresh) ET(S_BOUND, bound) ET(S_LISTEN, listening) ET(S_CONN, connected) ET(S_DATA, connected_with_data)
ET(S_PEER_SD, peer_half_closed) ET(S_PEER_CLOSED, peer_closed) ET(S_PEER_RST, peer_reset) ET(S_SELF_SD, self_shutdown_both)
ET(S_FAILED, failed_connect) ET(S_PENDING, listener_with_pending)

/* ---- plain I/O: recv / send / shutdown(SD_SEND) results, nonblocking ---- */
struct io { int recv_r, recv_e, send_r, send_e, shut_r, shut_e; };
static const struct io io_rows[S_COUNT] = {
    /* fresh   */ { -1, WSAENOTCONN, -1, WSAENOTCONN, -1, WSAENOTCONN },
    /* bound   */ { -1, WSAENOTCONN, -1, WSAENOTCONN, -1, WSAENOTCONN },
    /* listen  */ { -1, WSAENOTCONN, -1, WSAENOTCONN, -1, WSAENOTCONN },
    /* conn    */ { -1, WSAEWOULDBLOCK, 1, 0, 0, 0 },
    /* data    */ { 4, 0, 1, 0, 0, 0 },
    /* peer_sd */ { 0, 0, 1, 0, 0, 0 },
    /* closed  */ { 0, 0, 1, 0, 0, 0 },
    /* reset   */ { -1, WSAECONNRESET, -1, WSAECONNRESET, 0, 0 },
    /* self_sd */ { -1, WSAESHUTDOWN, -1, WSAESHUTDOWN, 0, 0 },
    /* failed  */ { -1, WSAENOTCONN, -1, WSAENOTCONN, -1, WSAENOTCONN },
    /* pending */ { -1, WSAENOTCONN, -1, WSAENOTCONN, -1, WSAENOTCONN },
};
static void io_state(int s)
{
    struct st st;
    char b[16];
    int r;
    UP();
    if (!make(&st, s)) { t_skip("cannot build state %s", state_names[s]); drop(&st); return; }
    x_blocking(st.a, FALSE);
    r = U(recv)(st.a, b, sizeof b, 0);
    XEQ(r, io_rows[s].recv_r);
    if (r < 0) XEQ(x_err(), io_rows[s].recv_e);
    r = U(send)(st.a, "z", 1, 0);
    XEQ(r, io_rows[s].send_r);
    if (r < 0) XEQ(x_err(), io_rows[s].send_e);
    r = U(shutdown)(st.a, SD_SEND);
    XEQ(r, io_rows[s].shut_r);
    if (r < 0) XEQ(x_err(), io_rows[s].shut_e);
    drop(&st);
}
#define IT(id, nm) TEST(xud_state_io_##nm) { io_state(id); }
IT(S_FRESH, fresh) IT(S_BOUND, bound) IT(S_LISTEN, listening) IT(S_CONN, connected) IT(S_DATA, connected_with_data)
IT(S_PEER_SD, peer_half_closed) IT(S_PEER_CLOSED, peer_closed) IT(S_PEER_RST, peer_reset) IT(S_SELF_SD, self_shutdown_both)
IT(S_FAILED, failed_connect) IT(S_PENDING, listener_with_pending)

/* ---- names: getsockname / getpeername ---- */
static void names_state(int s)
{
    struct st st;
    SOCKADDR_UN g;
    int gl, r;
    int named = (s == S_BOUND || s == S_LISTEN || s == S_PENDING);
    int connected = (s >= S_CONN && s <= S_SELF_SD);
    UP();
    if (!make(&st, s)) { t_skip("cannot build state %s", state_names[s]); drop(&st); return; }
    memset(&g, 0x55, sizeof g); gl = (int)sizeof g;
    r = U(getsockname)(st.a, (struct sockaddr *)&g, &gl);
    if (s == S_FRESH) {
        XEQ(r, -1);
        XEQ(x_err(), WSAEINVAL);                         /* never bound, never connected: no name at all */
    } else if (named) {
        XEQ(r, 0);
        XEQ(gl, X_ADDR_BASE + (int)strlen(st.path) + 1);
        EXPECT_STR(g.sun_path, st.path);
    } else {
        XEQ(r, 0);                                       /* implicitly bound by connect: unnamed, full-size answer */
        XEQ(gl, 110);
        XEQ(g.sun_family, AF_UNIX);
        XEQ(g.sun_path[0], 0);
    }
    memset(&g, 0x55, sizeof g); gl = (int)sizeof g;
    r = U(getpeername)(st.a, (struct sockaddr *)&g, &gl);
    if (connected) {
        XEQ(r, 0);
        XEQ(gl, 110);
        XEQ(g.sun_family, AF_UNIX);
    } else {
        XEQ(r, -1);
        XEQ(x_err(), WSAENOTCONN);
    }
    drop(&st);
}
#define NT(id, nm) TEST(xud_state_names_##nm) { names_state(id); }
NT(S_FRESH, fresh) NT(S_BOUND, bound) NT(S_LISTEN, listening) NT(S_CONN, connected) NT(S_DATA, connected_with_data)
NT(S_PEER_SD, peer_half_closed) NT(S_PEER_CLOSED, peer_closed) NT(S_PEER_RST, peer_reset) NT(S_SELF_SD, self_shutdown_both)
NT(S_FAILED, failed_connect) NT(S_PENDING, listener_with_pending)
