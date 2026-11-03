/* What an accepted socket takes over from its listener, and how asynchronous notification behaves around accept.
 *
 * Measures: socket-level values set on the listener (and defaults that were not set) as seen on the accepted
 * socket; the protocol description of the accepted socket; WSAEventSelect and WSAAsyncSelect registrations
 * carried over to the accepted socket (same event object or window, same event mask) and replaceable
 * independently; FD_ACCEPT being raised again while further connections wait; a listener handle inherited by a
 * child process accepting there.
 */
#include "bla.h"

struct ctx { SOCKET l, c, s; struct sockaddr_in la; };

/* Make listener l with `setup` applied before bind, connect a client, accept. */
typedef void (*setup_fn)(SOCKET l);
static int mk(struct ctx *x, setup_fn setup)
{
    memset(x, 0, sizeof *x);
    x->c = x->s = INVALID_SOCKET;
    x->l = tcp();
    if (x->l == INVALID_SOCKET) return 0;
    if (setup) setup(x->l);
    if (bind_lo(x->l, &x->la) || lsn(x->l, 1)) return 0;
    x->c = dial(&x->la);
    if (x->c == INVALID_SOCKET) return 0;
    x->s = acc_wait(x->l, NULL, NULL, 3000);
    return x->s != INVALID_SOCKET;
}
static void done(struct ctx *x)
{
    if (x->s != INVALID_SOCKET) cls(x->s);
    if (x->c != INVALID_SOCKET) cls(x->c);
    if (x->l != INVALID_SOCKET) cls(x->l);
}
static int get_dw(SOCKET s, int lvl, int opt, DWORD *v)
{
    int n = sizeof *v;
    *v = 0;
    return gso(s, lvl, opt, v, &n);
}

/* ---- values not set on the listener stay at their defaults on the accepted socket ---- */

TEST(bla_inh_defaults_unchanged)
{
    struct ctx x;
    DWORD v;
    struct linger lg;
    int n = sizeof lg;
    NEED();
    CHECK(mk(&x, NULL));
    if (x.s != INVALID_SOCKET) {
        EQ(get_dw(x.s, SOL_SOCKET, SO_KEEPALIVE, &v), 0);   EQ(v, 0);
        EQ(get_dw(x.s, SOL_SOCKET, SO_OOBINLINE, &v), 0);   EQ(v, 0);
        EQ(get_dw(x.s, SOL_SOCKET, SO_REUSEADDR, &v), 0);   EQ(v, 0);
        EQ(get_dw(x.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &v), 0); EQ(v, 0);
        EQ(get_dw(x.s, IPPROTO_TCP, TCP_NODELAY, &v), 0);   EQ(v, 0);
        EQ(gso(x.s, SOL_SOCKET, SO_LINGER, &lg, &n), 0);    EQ(lg.l_onoff, 0);
    }
    done(&x);
}

TEST(bla_inh_type_and_protocol_info)
{
    struct ctx x;
    DWORD v;
    WSAPROTOCOL_INFOW pl, ps;
    int n;
    NEED();
    CHECK(mk(&x, NULL));
    if (x.s != INVALID_SOCKET) {
        EQ(get_dw(x.s, SOL_SOCKET, SO_TYPE, &v), 0);
        EQ(v, SOCK_STREAM);
        n = sizeof pl; EQ(gso(x.l, SOL_SOCKET, SO_PROTOCOL_INFOW, &pl, &n), 0);
        n = sizeof ps; EQ(gso(x.s, SOL_SOCKET, SO_PROTOCOL_INFOW, &ps, &n), 0);
        EQ(ps.iAddressFamily, AF_INET);
        EQ(ps.iSocketType, SOCK_STREAM);
        EQ(ps.iProtocol, IPPROTO_TCP);
        EQ(ps.iAddressFamily, pl.iAddressFamily);
        EQ(ps.iProtocol, pl.iProtocol);
        EQ(ps.dwServiceFlags1, pl.dwServiceFlags1);
        CHECK(!memcmp(&ps.ProviderId, &pl.ProviderId, sizeof ps.ProviderId));
    }
    done(&x);
}

static void set_dontlinger_off(SOCKET l) { BOOL off = FALSE; sso(l, SOL_SOCKET, SO_DONTLINGER, &off, sizeof off); }
TEST(bla_inh_linger_enabled_by_dontlinger_false)
{
    struct ctx x;
    struct linger lg;
    int n = sizeof lg;
    NEED();
    CHECK(mk(&x, set_dontlinger_off));
    if (x.s != INVALID_SOCKET) {
        EQ(gso(x.s, SOL_SOCKET, SO_LINGER, &lg, &n), 0);
        t_note("SO_DONTLINGER=FALSE on the listener gives accepted l_onoff=%d", lg.l_onoff);
    }
    done(&x);
}

static void set_ttl(SOCKET l) { DWORD t = 33; sso(l, IPPROTO_IP, IP_TTL, &t, sizeof t); }
TEST(bla_inh_ip_ttl_recorded)
{
    struct ctx x;
    DWORD v, lv;
    NEED();
    CHECK(mk(&x, set_ttl));
    if (x.s != INVALID_SOCKET) {
        EQ(get_dw(x.l, IPPROTO_IP, IP_TTL, &lv), 0);
        EQ(lv, 33);
        EQ(get_dw(x.s, IPPROTO_IP, IP_TTL, &v), 0);
        t_note("IP_TTL set on the listener is %s on the accepted socket", v == 33 ? "inherited" : "not inherited");
    }
    done(&x);
}

static void set_excl(SOCKET l) { DWORD one = 1; sso(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof one); }
TEST(bla_inh_exclusive_addr_use_recorded)
{
    struct ctx x;
    DWORD v;
    NEED();
    CHECK(mk(&x, set_excl));
    if (x.s != INVALID_SOCKET) {
        EQ(get_dw(x.l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &v), 0);
        EQ(v, 1);
        EQ(get_dw(x.s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &v), 0);
        t_note("SO_EXCLUSIVEADDRUSE is %s on the accepted socket", v ? "inherited" : "not inherited");
    }
    done(&x);
}

static void set_cond(SOCKET l) { DWORD one = 0; sso(l, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &one, sizeof one); }
TEST(bla_inh_accepted_socket_options_independent_of_listener)
{
    struct ctx x;
    DWORD one = 1, v;
    NEED();
    CHECK(mk(&x, set_cond));
    if (x.s != INVALID_SOCKET) {
        EQ(sso(x.s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one), 0);
        EQ(get_dw(x.l, SOL_SOCKET, SO_KEEPALIVE, &v), 0);
        EQ(v, 0);                                          /* changing the child never touches the parent */
        EQ(get_dw(x.s, SOL_SOCKET, SO_KEEPALIVE, &v), 0);
        EQ(v, 1);
    }
    done(&x);
}

/* ---- blocking mode ---- */

static void set_nonblocking(SOCKET l) { nbio(l, 1); }
static const char *recv_mode(SOCKET s)
{
    char b;
    int r;
    rcvto(s, 300);
    r = rcv(s, &b, 1);
    if (r != SOCKET_ERROR) return "returned data";
    return werr() == WSAEWOULDBLOCK ? "non-blocking" : werr() == WSAETIMEDOUT ? "blocking" : "other";
}

TEST(bla_inh_blocking_mode_of_default_listener)
{
    struct ctx x;
    NEED();
    CHECK(mk(&x, NULL));
    if (x.s != INVALID_SOCKET) {
        wset(0x5a5a);
        EQ(strcmp(recv_mode(x.s), "blocking"), 0);          /* nothing sent: the timed receive ends with WSAETIMEDOUT */
    }
    done(&x);
}

TEST(bla_inh_blocking_mode_of_nonblocking_listener_recorded)
{
    struct ctx x;
    struct sockaddr_in a;
    SOCKET l, c, s;
    NEED();
    l = tcp();
    EQ(bind_lo(l, &a), 0);
    EQ(lsn(l, 1), 0);
    EQ(nbio(l, 1), 0);
    c = dial(&a);
    CHECK(readable(l, 3000));
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        t_note("accepted from a non-blocking listener: socket is %s", recv_mode(s));
        cls(s);
    }
    cls(c); cls(l);
    (void)x;
}

/* ---- WSAEventSelect ---- */

typedef WSAEVENT (WSAAPI *wce_t)(void);
static WSAEVENT mkev(void) { return U(WSACreateEvent)(); }
static int evsel(SOCKET s, WSAEVENT e, long m) { return U(WSAEventSelect)(s, e, m); }
static long enumev(SOCKET s, WSAEVENT e, WSANETWORKEVENTS *ne)
{
    memset(ne, 0, sizeof *ne);
    if (U(WSAEnumNetworkEvents)(s, e, ne) != 0) return -1;
    return ne->lNetworkEvents;
}
static int signalled(WSAEVENT e, DWORD ms) { return WaitForSingleObject((HANDLE)e, ms) == WAIT_OBJECT_0; }

TEST(bla_inh_event_select_listener_fd_accept)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c;
    NEED();
    l = listener(&a, 5);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT), 0);
    CHECK(!signalled(ev, 100));                          /* no connection yet */
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    EQ(enumev(l, ev, &ne) & FD_ACCEPT, FD_ACCEPT);
    EQ(ne.iErrorCode[FD_ACCEPT_BIT], 0);
    EQ(evsel(l, ev, 0), 0);
    cls(c); cls(l);
    U(WSACloseEvent)(ev);
}

TEST(bla_inh_event_select_fd_accept_raised_again_while_connections_wait)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c1, c2, s;
    NEED();
    l = listener(&a, 5);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT), 0);
    c1 = dial(&a); c2 = dial(&a);
    CHECK(signalled(ev, 3000));
    EQ(enumev(l, ev, &ne) & FD_ACCEPT, FD_ACCEPT);       /* consumes the notification */
    ResetEvent((HANDLE)ev);                              /* whether a second notification is already raised is timing dependent */
    s = acc(l, NULL, NULL);                              /* one connection is still waiting: the event is armed again */
    CHECK(s != INVALID_SOCKET);
    CHECK(signalled(ev, 3000));
    EQ(enumev(l, ev, &ne) & FD_ACCEPT, FD_ACCEPT);
    if (s != INVALID_SOCKET) cls(s);
    s = acc(l, NULL, NULL);
    if (s != INVALID_SOCKET) cls(s);
    cls(c1); cls(c2); cls(l);
    U(WSACloseEvent)(ev);
}

TEST(bla_inh_event_select_accepted_socket_shares_event_and_mask)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT | FD_READ | FD_CLOSE), 0);
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    EQ(enumev(l, ev, &ne) & FD_ACCEPT, FD_ACCEPT);
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        ResetEvent((HANDLE)ev);
        EQ(snd(c, "x", 1), 1);
        CHECK(signalled(ev, 3000));                      /* the accepted socket reports through the listener's event */
        EQ(enumev(s, ev, &ne) & FD_READ, FD_READ);
        EQ(ne.iErrorCode[FD_READ_BIT], 0);
        cls(s);
    }
    cls(c); cls(l);
    U(WSACloseEvent)(ev);
}

TEST(bla_inh_event_select_accepted_socket_only_gets_listener_mask)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT), 0);                      /* no FD_READ in the mask */
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    enumev(l, ev, &ne);
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        ResetEvent((HANDLE)ev);
        EQ(snd(c, "x", 1), 1);
        CHECK(!signalled(ev, 400));                      /* a receive event was never requested */
        EQ(enumev(s, ev, &ne) & FD_READ, 0);
        cls(s);
    }
    cls(c); cls(l);
    U(WSACloseEvent)(ev);
}

TEST(bla_inh_event_select_accepted_socket_can_be_redirected)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev, ev2;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    ev = mkev(); ev2 = mkev();
    EQ(evsel(l, ev, FD_ACCEPT | FD_READ), 0);
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    enumev(l, ev, &ne);
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        EQ(evsel(s, ev2, FD_READ), 0);
        ResetEvent((HANDLE)ev); ResetEvent((HANDLE)ev2);
        EQ(snd(c, "x", 1), 1);
        CHECK(signalled(ev2, 3000));
        EQ(enumev(s, ev2, &ne) & FD_READ, FD_READ);
        CHECK(!signalled(ev, 200));                      /* the listener's event object is no longer used */
        cls(s);
    }
    cls(c); cls(l);
    U(WSACloseEvent)(ev); U(WSACloseEvent)(ev2);
}

TEST(bla_inh_event_select_accepted_socket_is_nonblocking)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT | FD_READ), 0);
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    enumev(l, ev, &ne);
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        t_note("accepted socket of an event-selecting listener is %s", recv_mode(s));
        cls(s);
    }
    cls(c); cls(l);
    U(WSACloseEvent)(ev);
}

TEST(bla_inh_event_select_cancelled_before_accept_not_inherited)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT | FD_READ), 0);
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    enumev(l, ev, &ne);
    EQ(evsel(l, ev, 0), 0);                              /* cancel on the listener before accepting */
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        ResetEvent((HANDLE)ev);
        EQ(snd(c, "x", 1), 1);
        CHECK(!signalled(ev, 400));
        cls(s);
    }
    cls(c); cls(l);
    U(WSACloseEvent)(ev);
}

TEST(bla_inh_event_select_fd_close_on_accepted_socket)
{
    struct sockaddr_in a;
    WSANETWORKEVENTS ne;
    WSAEVENT ev;
    SOCKET l, c, s;
    NEED();
    l = listener(&a, 1);
    ev = mkev();
    EQ(evsel(l, ev, FD_ACCEPT | FD_CLOSE), 0);
    c = dial(&a);
    CHECK(signalled(ev, 3000));
    enumev(l, ev, &ne);
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        ResetEvent((HANDLE)ev);
        cls(c); c = INVALID_SOCKET;
        CHECK(signalled(ev, 3000));
        EQ(enumev(s, ev, &ne) & FD_CLOSE, FD_CLOSE);
        EQ(ne.iErrorCode[FD_CLOSE_BIT], 0);              /* an orderly close, not a reset */
        cls(s);
    }
    if (c != INVALID_SOCKET) cls(c);
    cls(l);
    U(WSACloseEvent)(ev);
}

/* ---- WSAAsyncSelect with a message-only window ---- */

#define WM_BLA (WM_USER + 7)

static HWND mkwin(void)
{
    __typeof__(&CreateWindowExA) cw = UIN("user32.dll", CreateWindowExA);
    if (!cw) return NULL;
    return cw(0, "STATIC", "bla", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleA(NULL), NULL);
}
static void killwin(HWND h)
{
    __typeof__(&DestroyWindow) dw = UIN("user32.dll", DestroyWindow);
    if (dw && h) dw(h);
}
/* Wait up to ms for a WM_BLA message; returns 1 and fills wp/lp. */
static int pump(HWND h, DWORD ms, WPARAM *wp, LPARAM *lp)
{
    __typeof__(&PeekMessageA) pm = UIN("user32.dll", PeekMessageA);
    DWORD end = GetTickCount() + ms;
    MSG m;
    do {
        if (pm(&m, h, WM_BLA, WM_BLA, PM_REMOVE)) { *wp = m.wParam; *lp = m.lParam; return 1; }
        Sleep(10);
    } while ((int)(end - GetTickCount()) > 0);
    return 0;
}
static void drain(HWND h)
{
    __typeof__(&PeekMessageA) pm = UIN("user32.dll", PeekMessageA);
    MSG m;
    while (pm(&m, h, WM_BLA, WM_BLA, PM_REMOVE)) ;
}

TEST(bla_inh_async_select_listener_fd_accept_message)
{
    struct sockaddr_in a;
    HWND w;
    SOCKET l, c;
    WPARAM wp = 0;
    LPARAM lp = 0;
    NEED();
    w = mkwin();
    if (!w) { t_skip("no message-only window available"); return; }
    l = listener(&a, 1);
    EQ(U(WSAAsyncSelect)(l, w, WM_BLA, FD_ACCEPT), 0);
    c = dial(&a);
    CHECK(pump(w, 3000, &wp, &lp));
    CHECK(wp == (WPARAM)l);
    EQ(WSAGETSELECTEVENT(lp), FD_ACCEPT);
    EQ(WSAGETSELECTERROR(lp), 0);
    U(WSAAsyncSelect)(l, w, 0, 0);
    cls(c); cls(l);
    killwin(w);
}

TEST(bla_inh_async_select_accepted_socket_inherits_window_and_mask)
{
    struct sockaddr_in a;
    HWND w;
    SOCKET l, c, s;
    WPARAM wp = 0;
    LPARAM lp = 0;
    NEED();
    w = mkwin();
    if (!w) { t_skip("no message-only window available"); return; }
    l = listener(&a, 1);
    EQ(U(WSAAsyncSelect)(l, w, WM_BLA, FD_ACCEPT | FD_READ), 0);
    c = dial(&a);
    CHECK(pump(w, 3000, &wp, &lp));
    EQ(WSAGETSELECTEVENT(lp), FD_ACCEPT);
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    drain(w);
    if (s != INVALID_SOCKET) {
        int got = 0;
        EQ(snd(c, "x", 1), 1);
        for (;;) {
            if (!pump(w, 3000, &wp, &lp)) break;
            if (wp == (WPARAM)s && WSAGETSELECTEVENT(lp) == FD_READ) { got = 1; break; }
        }
        CHECK(got);                                       /* the accepted socket posts to the same window */
        cls(s);
    }
    U(WSAAsyncSelect)(l, w, 0, 0);
    cls(c); cls(l);
    killwin(w);
}

TEST(bla_inh_async_select_mask_without_read_not_inherited_as_read)
{
    struct sockaddr_in a;
    HWND w;
    SOCKET l, c, s;
    WPARAM wp = 0;
    LPARAM lp = 0;
    NEED();
    w = mkwin();
    if (!w) { t_skip("no message-only window available"); return; }
    l = listener(&a, 1);
    EQ(U(WSAAsyncSelect)(l, w, WM_BLA, FD_ACCEPT), 0);
    c = dial(&a);
    CHECK(pump(w, 3000, &wp, &lp));
    s = acc(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    drain(w);
    if (s != INVALID_SOCKET) {
        EQ(snd(c, "x", 1), 1);
        CHECK(!pump(w, 400, &wp, &lp));
        cls(s);
    }
    U(WSAAsyncSelect)(l, w, 0, 0);
    cls(c); cls(l);
    killwin(w);
}

/* ---- listener handle inherited by a child process ---- */

CHILD(accept_inherited)
{
    SOCKET l, s;
    WSADATA d;
    char b = 'K';
    if (argc < 2) return 2;
    if (!U(WSAStartup) || U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 3;
    l = (SOCKET)(ULONG_PTR)_strtoui64(argv[1], NULL, 16);
    s = acc_wait(l, NULL, NULL, 8000);
    if (s == INVALID_SOCKET) return 4;
    if (snd(s, &b, 1) != 1) return 5;
    cls(s);
    return 0;
}

TEST(bla_inh_listener_handle_inherited_by_child_accepts)
{
    struct sockaddr_in a;
    SOCKET l, c;
    PROCESS_INFORMATION pi;
    char args[64], b = 0;
    DWORD code = 0xffff;
    NEED();
    l = listener(&a, 1);
    CHECK(l != INVALID_SOCKET);
    CHECK(SetHandleInformation((HANDLE)l, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    sprintf(args, "%llx", (unsigned long long)l);
    memset(&pi, 0, sizeof pi);
    if (!t_spawn_child("accept_inherited", args, 0, NULL, NULL, NULL, TRUE, NULL, &pi)) {
        t_skip("could not start the child process");
        cls(l);
        return;
    }
    c = dial(&a);
    CHECK(c != INVALID_SOCKET);
    if (c != INVALID_SOCKET) {
        rcvto(c, 8000);
        EQ(rcv(c, &b, 1), 1);
        EQ(b, 'K');
        cls(c);
    }
    CHECK(WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0);
    GetExitCodeProcess(pi.hProcess, &code);
    EQ(code, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    cls(l);
}
