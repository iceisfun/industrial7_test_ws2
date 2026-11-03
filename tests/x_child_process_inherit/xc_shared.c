/* x_child_process_inherit / shared: one endpoint, two processes. Listeners shared between a parent and a child (the
 * accept queue is shared and ordered; each connection is accepted exactly once, also under a free race and also through
 * a protocol-info duplicate), listener lifetime while the other process holds it, state changes made by one process
 * (bind, listen, connect, socket options) that the other observes, and the connection data split between owners. */
#include "xc.h"

/* ---------------- accept queue ---------------- */
/* Accept n connections, read the id byte each client sent; the exit code packs the ids (3 bits each). */
CHILD(acc_n)
{
    SOCKET l = xc_arg_sock(argv, 1); int n = xc_arg_int(argv, 2), i; DWORD code = 0; char id;
    xc_child_up();
    for (i = 0; i < n; i++) {
        SOCKET a = xc_accept(l, XC_WAIT);
        if (a == INVALID_SOCKET) return 0x80000000u | code;
        xc_rcvtimeo(a, XC_WAIT);
        if (U(recv)(a, &id, 1, 0) != 1) { U(closesocket)(a); return 0x40000000u | code; }
        code |= (DWORD)(id & 7) << (3 * i);
        U(closesocket)(a);
    }
    return code;
}
static SOCKET queue_client(const struct sockaddr_in *la, char id)
{
    SOCKET c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    if (c == INVALID_SOCKET) return c;
    if (U(connect)(c, (struct sockaddr *)la, sizeof *la)) { xc_close(c); return INVALID_SOCKET; }
    xc_send(c, &id, 1);
    return c;
}
/* Accept one connection in this process and return the id byte it carries, or -1. */
static int accept_id(SOCKET l, int ms)
{
    SOCKET a = xc_accept(l, ms); char id; int r = -1;
    if (a == INVALID_SOCKET) return -1;
    xc_rcvtimeo(a, XC_WAIT);
    if (U(recv)(a, &id, 1, 0) == 1) r = id;
    xc_close(a);
    return r;
}
TEST(shared_listener_queue_is_fifo_and_split_between_processes)
{
    SOCKET l, cl[6]; struct sockaddr_in la; char arg[64]; HANDLE h[1]; DWORD code; int i;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    for (i = 0; i < 3; i++) cl[i] = queue_client(&la, (char)i);
    h[0] = H(l);
    code = xc_run("acc_n", XARGS(arg, "%llu 3", xc_u(l)), h, 1);
    XEQ(code, 0 | (1 << 3) | (2 << 6));               /* the child got connections 0,1,2 in arrival order */
    for (i = 3; i < 6; i++) cl[i] = queue_client(&la, (char)i);
    XEQ(accept_id(l, XC_WAIT), 3); XEQ(accept_id(l, XC_WAIT), 4); XEQ(accept_id(l, XC_WAIT), 5);
    CHECK(!xc_readable(l, 0));                        /* nothing was accepted twice, nothing is left over */
    for (i = 0; i < 6; i++) xc_close(cl[i]);
    xc_close(l);
}
TEST(shared_listener_parent_connections_before_child_not_lost_after_parent_close)
{
    SOCKET l, cl[3]; struct sockaddr_in la; char arg[64]; HANDLE h[1]; DWORD code; int i;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    for (i = 0; i < 3; i++) cl[i] = queue_client(&la, (char)(i + 3));
    h[0] = H(l);
    {
        HANDLE p = xc_spawn("acc_n", XARGS(arg, "%llu 3", xc_u(l)), h, 1, NULL);
        CHECK(p != NULL);
        xc_close(l);                                  /* the child owns the only handle now */
        code = xc_wait(p, XC_CHILD_TIMEOUT);
    }
    XEQ(code, 3 | (4 << 3) | (5 << 6));
    for (i = 0; i < 3; i++) xc_close(cl[i]);
}
/* Free race: both sides accept until idle. Invariant only: every id seen exactly once. */
CHILD(acc_idle)
{
    SOCKET l = xc_arg_sock(argv, 1); DWORD mask = 0; int dup = 0;
    xc_child_up();
    for (;;) {
        int id = accept_id(l, 1500);
        if (id < 0) break;
        if (mask & (1u << id)) dup = 1;
        mask |= 1u << id;
    }
    return (int)(mask | (dup ? 0x1000u : 0));
}
static void race_case(int use_dup)
{
    SOCKET l, cl[10]; struct sockaddr_in la; char arg[64]; HANDLE h[1], p; DWORD code, mine = 0, theirs; int i, id, rc = 0, e = 0, dup = 0;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    for (i = 0; i < 10; i++) cl[i] = queue_client(&la, (char)i);
    h[0] = H(l);
    if (use_dup) p = xc_spawn_blob("acc_idle_dup", "", l, NULL, 0, &rc, &e);
    else p = xc_spawn("acc_idle", XARGS(arg, "%llu", xc_u(l)), h, 1, NULL);
    CHECK(p != NULL); XEQ(rc, 0);
    for (;;) {
        id = accept_id(l, 1500);
        if (id < 0) break;
        if (mine & (1u << id)) dup = 1;
        mine |= 1u << id;
    }
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    theirs = code & 0x3ff;
    XEQ(code & ~0x3ffu, 0);                           /* no duplicate inside the child */
    XEQ(dup, 0);
    XEQ(mine & theirs, 0);                            /* nobody accepted the same connection */
    XEQ(mine | theirs, 0x3ff);                        /* and none was lost */
    for (i = 0; i < 10; i++) xc_close(cl[i]);
    xc_close(l);
}
CHILD(acc_idle_dup)
{
    WSAPROTOCOL_INFOW pi; SOCKET l; DWORD mask = 0; int dup = 0;
    xc_child_up();
    if (!xc_read_blob(argv, 1, &pi)) return 0x2000;
    l = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, OVLD);
    if (l == INVALID_SOCKET) return 0x4000;
    for (;;) {
        int id = accept_id(l, 1500);
        if (id < 0) break;
        if (mask & (1u << id)) dup = 1;
        mask |= 1u << id;
    }
    return (int)(mask | (dup ? 0x1000u : 0));
}
TEST(shared_listener_race_inherited_accepts_each_once)  { race_case(0); }
TEST(shared_listener_race_duplicated_accepts_each_once) { race_case(1); }

/* ---------------- listener lifetime ---------------- */
CHILD(accept_close_listener)
{
    SOCKET l = xc_arg_sock(argv, 1), a; unsigned fails = 0;
    xc_child_up();
    a = xc_accept(l, XC_WAIT);
    STEP(0, a != INVALID_SOCKET);
    STEP(1, U(closesocket)(l) == 0);                  /* the child's listener handle goes away */
    if (a != INVALID_SOCKET) { STEP(2, xc_send(a, "k", 1) == 1); U(closesocket)(a); }
    return (int)fails;
}
TEST(shared_listener_goes_away_with_last_handle)
{
    SOCKET l, c, c2; struct sockaddr_in la; char arg[64], b; HANDLE h[1], p; DWORD code;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(l);
    p = xc_spawn("accept_close_listener", XARGS(arg, "%llu", xc_u(l)), h, 1, NULL);
    CHECK(p != NULL);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    XEQ(xc_recv_n(c, &b, 1), 1); XEQ(b, 'k');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    c2 = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    CHECK(U(connect)(c2, (struct sockaddr *)&la, sizeof la) == 0);   /* the parent's handle still listens */
    xc_close(c2);
    xc_close(l);                                      /* last handle */
    c2 = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c2, (struct sockaddr *)&la, sizeof la), SOCKET_ERROR);
    XEQ(xc_werr(), WSAECONNREFUSED);
    xc_close(c2); xc_close(c);
}
TEST(shared_listener_refuses_after_both_close)
{
    SOCKET l, c; struct sockaddr_in la; char arg[64]; HANDLE h[1], p; DWORD code;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(l);
    p = xc_spawn("exit0", XARGS(arg, "%llu", xc_u(l)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(l);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), SOCKET_ERROR);
    XEQ(xc_werr(), WSAECONNREFUSED);
    xc_close(c);
}
CHILD(exit0) { return 0; }

/* ---------------- state set by one process, seen by the other ---------------- */
CHILD(bind_listen_in_child)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; struct sockaddr_in a = xc_lo(0); int al = sizeof a, i = 0, il = sizeof i;
    xc_child_up();
    STEP(0, U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0);
    STEP(1, U(listen)(s, 4) == 0);
    STEP(2, U(getsockopt)(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&i, &il) == 0 && i == 1);
    STEP(3, U(getsockname)(s, (struct sockaddr *)&a, &al) == 0);
    /* hand the port back through the exit code */
    return (int)(fails ? fails : (0x10000 | xc_port_of(&a)));
}
TEST(shared_bind_and_listen_in_child_state_seen_only_by_the_network)
{
    SOCKET s, c; struct sockaddr_in a; int al = sizeof a, i = 0, il = sizeof i; char arg[64]; HANDLE h[1]; DWORD code;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    h[0] = H(s);
    code = xc_run("bind_listen_in_child", XARGS(arg, "%llu", xc_u(s)), h, 1);
    CHECK(code & 0x10000);
    { struct sockaddr_in q; int ql = sizeof q; xc_setwerr(0);
      XEQ(U(getsockname)(s, (struct sockaddr *)&q, &ql), SOCKET_ERROR);   /* the binding is not visible through the parent's handle */
      XEQ(xc_werr(), WSAEINVAL); }
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&i, &il), 0);
    XEQ(i, 0);                                        /* and neither is the listening state */
    memset(&a, 0, sizeof a); a = xc_lo((unsigned short)(code & 0xffff));
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
    XEQ(xc_readable(s, XC_WAIT), 1);
    xc_close(c); xc_close(s);
}
CHILD(connect_in_child)
{
    SOCKET s = xc_arg_sock(argv, 1); struct sockaddr_in a = xc_lo((unsigned short)xc_arg_int(argv, 2));
    xc_child_up();
    return U(connect)(s, (struct sockaddr *)&a, sizeof a) == 0 ? 0 : (int)xc_e8(xc_werr());
}
TEST(shared_connect_in_child_parent_handle_still_sends)
{
    SOCKET l, s, a; struct sockaddr_in la; char arg[64], b; HANDLE h[1]; DWORD code;
    UP(); l = xc_listener(OVLD, &la); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (l == INVALID_SOCKET || s == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(s);
    code = xc_run("connect_in_child", XARGS(arg, "%llu %d", xc_u(s), xc_port_of(&la)), h, 1);
    XEQ(code, 0);
    { struct sockaddr_in q; int ql = sizeof q; xc_setwerr(0);
      XEQ(U(getpeername)(s, (struct sockaddr *)&q, &ql), SOCKET_ERROR);
      XEQ(xc_werr(), WSAENOTCONN); }                  /* the parent handle does not know it is connected */
    XEQ(xc_send(s, "p", 1), 1);
    a = xc_accept(l, XC_WAIT);
    CHECK(a != INVALID_SOCKET);
    xc_rcvtimeo(a, XC_WAIT);
    XEQ(xc_recv_n(a, &b, 1), 1); XEQ(b, 'p');
    xc_close(a); xc_close(s); xc_close(l);
}
/* connect() from the parent on an already child-connected socket is refused */
TEST(shared_second_connect_in_parent_after_child_connect_is_einval)
{
    SOCKET l, s; struct sockaddr_in la; char arg[64]; HANDLE h[1]; DWORD code;
    UP(); l = xc_listener(OVLD, &la); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (l == INVALID_SOCKET || s == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(s);
    code = xc_run("connect_in_child", XARGS(arg, "%llu %d", xc_u(s), xc_port_of(&la)), h, 1);
    XEQ(code, 0);
    xc_setwerr(0);
    XEQ(U(connect)(s, (struct sockaddr *)&la, sizeof la), SOCKET_ERROR);
    XEQ(xc_werr(), WSAEINVAL);                        /* the parent's view is a bound-less, not-connected socket */
    xc_close(s); xc_close(l);
}

struct opt { int level, name; int value; const char *tag; };
static const struct opt opts[] = {
    { SOL_SOCKET, SO_KEEPALIVE, 1, "keepalive" }, { IPPROTO_TCP, TCP_NODELAY, 1, "nodelay" },
    { SOL_SOCKET, SO_OOBINLINE, 1, "oobinline" }, { SOL_SOCKET, SO_RCVBUF, 32768, "rcvbuf" },
    { SOL_SOCKET, SO_SNDBUF, 32768, "sndbuf" },
};
CHILD(set_opt)
{
    SOCKET s = xc_arg_sock(argv, 1); int lv = xc_arg_int(argv, 2), nm = xc_arg_int(argv, 3), val = xc_arg_int(argv, 4);
    xc_child_up();
    return U(setsockopt)(s, lv, nm, (char *)&val, sizeof val) == 0 ? 0 : (int)xc_e8(xc_werr());
}
TEST(shared_option_set_in_child_visible_in_parent)
{
    unsigned i; UP();
    for (i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        SOCKET s = xc_make(AF_INET, SOCK_STREAM, OVLD); char arg[96]; HANDLE h[1]; int got = 0, gl = sizeof got;
        if (s == INVALID_SOCKET) { t_skip("socket"); return; }
        h[0] = H(s);
        XEQ(xc_run("set_opt", XARGS(arg, "%llu %d %d %d", xc_u(s), opts[i].level, opts[i].name, opts[i].value), h, 1), 0);
        XEQ(U(getsockopt)(s, opts[i].level, opts[i].name, (char *)&got, &gl), 0);
        t_note("%s: child set %d, parent reads %s", opts[i].tag, opts[i].value, got == opts[i].value ? "same" : got ? "changed" : "unset");
        if (opts[i].name == SO_KEEPALIVE || opts[i].name == TCP_NODELAY) XEQ(got != 0, 1);    /* kernel-held options are shared */
        else if (opts[i].name == SO_OOBINLINE) XEQ(got, 0);                                    /* process-local ones are not */
        else { int def = 0, dl = sizeof def; SOCKET f = xc_make(AF_INET, SOCK_STREAM, OVLD); U(getsockopt)(f, opts[i].level, opts[i].name, (char *)&def, &dl); XEQ(got, def); xc_close(f); }
        xc_close(s);
    }
}
CHILD(set_linger)
{
    SOCKET s = xc_arg_sock(argv, 1); struct linger l = { 1, 7 };
    xc_child_up();
    return U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l) == 0 ? 0 : 1;
}
TEST(shared_linger_set_in_child_not_seen_by_parent)
{
    SOCKET s; char arg[64]; HANDLE h[1]; struct linger l = {0, 0}; int ll = sizeof l;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    h[0] = H(s);
    XEQ(xc_run("set_linger", XARGS(arg, "%llu", xc_u(s)), h, 1), 0);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&l, &ll), 0);
    XEQ(l.l_onoff, 0);                                /* a process-local option */
    xc_close(s);
}
CHILD(set_nonblock)
{
    SOCKET s = xc_arg_sock(argv, 1); u_long v = 1;
    xc_child_up();
    return U(ioctlsocket)(s, FIONBIO, &v) == 0 ? 0 : 1;
}
TEST(shared_nonblocking_mode_set_in_child_applies_to_parent)
{
    SOCKET c, s; char arg[64], b; HANDLE h[1]; int r, e;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    xc_rcvtimeo(c, 300);
    h[0] = H(c);
    XEQ(xc_run("set_nonblock", XARGS(arg, "%llu", xc_u(c)), h, 1), 0);
    r = U(recv)(c, &b, 1, 0); e = xc_werr();
    XEQ(r, SOCKET_ERROR);
    XEQ(e, WSAEWOULDBLOCK);                           /* non-blocking mode is endpoint state, shared at once */
    xc_close(c); xc_close(s);
}
