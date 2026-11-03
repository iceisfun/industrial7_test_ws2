/* x_child_process_inherit / inherit: sockets inherited through CreateProcess. Handle values and endpoint identity
 * across the boundary, a shared receive queue for TCP and UDP, listeners used from a child, explicit handle lists
 * (which handles are visible in the child and which are refused at CreateProcess), the inheritable bit of
 * accepted and duplicated sockets, and kernel-level duplicates handed to a child. */
#include "xc.h"

/* ---------------- identity: the same handle value is the same endpoint ---------------- */
CHILD(tcp_state)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; int lp = xc_arg_int(argv, 2), pp = xc_arg_int(argv, 3);
    char ty;
    xc_child_up();
    STEP(0, xc_type_of(s) == SOCK_STREAM);
    STEP(1, xc_name_port(s, 0) == lp);
    STEP(2, xc_name_port(s, 1) == pp);
    STEP(3, xc_send(s, "k", 1) == 1);
    STEP(4, U(recv)(s, &ty, 1, 0) == 1 && ty == 'p');
    return (int)fails;
}
TEST(inh_tcp_endpoint_identity_in_child)
{
    SOCKET c, s; char a[96], b; DWORD code; HANDLE h[1];
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    {
        HANDLE p = xc_spawn("tcp_state", XARGS(a, "%llu %d %d", xc_u(c), xc_name_port(c, 0), xc_name_port(c, 1)), h, 1, NULL);
        CHECK(p != NULL);
        XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'k');
        XEQ(xc_send(s, "p", 1), 1);
        code = xc_wait(p, XC_CHILD_TIMEOUT);
    }
    XEQ(code, 0);
    xc_close(c); xc_close(s);
}

CHILD(three_handles)
{
    unsigned fails = 0; int i;
    xc_child_up();
    for (i = 0; i < 3; i++) {
        SOCKET s = xc_arg_sock(argv, 1 + i);
        STEP(i, xc_type_of(s) == (i == 1 ? SOCK_DGRAM : SOCK_STREAM));
        STEP(3 + i, xc_name_port(s, 0) == xc_arg_int(argv, 4 + i));
    }
    return (int)fails;
}
TEST(inh_handle_values_map_to_same_endpoints)
{
    SOCKET a, b, u; struct sockaddr_in aa, ba, ua; char arg[160]; HANDLE h[3]; DWORD code;
    UP();
    a = xc_listener(PLAIN, &aa); u = xc_bound(SOCK_DGRAM, PLAIN, &ua); b = xc_listener(PLAIN, &ba);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET || u == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(a); h[1] = H(u); h[2] = H(b);
    code = xc_run("three_handles", XARGS(arg, "%llu %llu %llu %d %d %d", xc_u(a), xc_u(u), xc_u(b), xc_port_of(&aa), xc_port_of(&ua), xc_port_of(&ba)), h, 3);
    XEQ(code, 0);
    xc_close(a); xc_close(b); xc_close(u);
}

/* Handle value validity and flags in the child: the handle table slot is the same and inheritable. */
CHILD(handle_info)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; DWORD f = 0;
    STEP(0, GetHandleInformation(H(s), &f));
    STEP(1, (f & HANDLE_FLAG_INHERIT) == (DWORD)xc_arg_int(argv, 2));
    STEP(2, GetFileType(H(s)) == FILE_TYPE_PIPE);
    STEP(3, (s & 3) == 0);
    return (int)fails;
}
TEST(inh_handle_info_matches_in_child)
{
    SOCKET s; char a[64]; HANDLE h[1]; DWORD code;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    h[0] = H(s);
    XEQ(xc_hflags(H(s)), HANDLE_FLAG_INHERIT);
    code = xc_run("handle_info", XARGS(a, "%llu %d", xc_u(s), HANDLE_FLAG_INHERIT), h, 1);
    XEQ(code, 0);
    xc_close(s);
}

/* ---------------- handle lists ---------------- */
CHILD(only_first)
{
    unsigned fails = 0; SOCKET a = xc_arg_sock(argv, 1), b = xc_arg_sock(argv, 2); int e;
    xc_child_up();
    STEP(0, xc_is_socket(a));
    xc_setwerr(0);
    STEP(1, !xc_is_socket(b));
    e = xc_werr();
    STEP(2, e == WSAENOTSOCK);
    STEP(3, !GetHandleInformation(H(b), &(DWORD){0}));
    return (int)fails;
}
TEST(inh_handle_list_excludes_other_inheritable_socket)
{
    SOCKET a = INVALID_SOCKET, b = INVALID_SOCKET; char arg[64]; HANDLE h[1]; DWORD code;
    UP(); a = xc_make(AF_INET, SOCK_DGRAM, PLAIN); b = xc_make(AF_INET, SOCK_DGRAM, PLAIN);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("socket"); return; }
    XEQ(xc_hflags(H(b)), HANDLE_FLAG_INHERIT);      /* inheritable, yet not listed */
    h[0] = H(a);
    code = xc_run("only_first", XARGS(arg, "%llu %llu", xc_u(a), xc_u(b)), h, 1);
    XEQ(code, 0);
    xc_close(a); xc_close(b);
}
TEST(inh_handle_list_noinherit_socket_refused)
{
    SOCKET s; HANDLE h[1], p; DWORD err = 0;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, NOINH);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    XEQ(xc_hflags(H(s)), 0);
    h[0] = H(s);
    p = xc_spawn("handle_info", "1 0", h, 1, &err);
    CHECK(p == NULL);
    XEQ(err, ERROR_INVALID_PARAMETER);
    if (p) xc_kill(p);
    xc_close(s);
}
TEST(inh_handle_list_flag_cleared_socket_refused)
{
    SOCKET s; HANDLE h[1], p; DWORD err = 0;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    CHECK(SetHandleInformation(H(s), HANDLE_FLAG_INHERIT, 0));
    h[0] = H(s);
    p = xc_spawn("handle_info", "1 0", h, 1, &err);
    CHECK(p == NULL);
    XEQ(err, ERROR_INVALID_PARAMETER);
    if (p) xc_kill(p);
    xc_close(s);
}
TEST(inh_handle_list_restored_flag_accepted)
{
    SOCKET s; char a[64]; HANDLE h[1]; DWORD code;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, NOINH);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    CHECK(SetHandleInformation(H(s), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    h[0] = H(s);
    code = xc_run("handle_info", XARGS(a, "%llu %d", xc_u(s), HANDLE_FLAG_INHERIT), h, 1);
    XEQ(code, 0);
    xc_close(s);
}
/* A closed handle value in the list fails the spawn; the socket stays unaffected. */
TEST(inh_handle_list_closed_socket_refused)
{
    SOCKET s; HANDLE h[1], p; DWORD err = 0;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    h[0] = H(s);
    xc_close(s);
    p = xc_spawn("handle_info", "1 0", h, 1, &err);
    CHECK(p == NULL);
    XEQ(err, ERROR_INVALID_PARAMETER);
    if (p) xc_kill(p);
}

/* ---------------- shared queues ---------------- */
CHILD(drain_then_ack)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; char b[8] = {0};
    xc_child_up();
    xc_rcvtimeo(s, XC_WAIT);
    STEP(0, xc_recv_n(s, b, 3) == 3 && !memcmp(b, "abc", 3));
    STEP(1, xc_send(s, "z", 1) == 1);
    return (int)fails;
}
TEST(inh_tcp_queued_data_consumed_by_child)
{
    SOCKET c, s; char a[64], b; DWORD code; HANDLE h[1], p;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(xc_send(s, "abc", 3), 3);                       /* queued before the child exists */
    h[0] = H(c);
    p = xc_spawn("drain_then_ack", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'z');           /* the child answered after draining */
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    CHECK(!xc_readable(c, 0));                          /* nothing is left for the parent's handle */
    xc_close(c); xc_close(s);
}
TEST(inh_tcp_parent_sends_after_spawn_child_receives)
{
    SOCKET c, s; char a[64], b; DWORD code; HANDLE h[1], p;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("drain_then_ack", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(xc_send(s, "abc", 3), 3);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'z');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c); xc_close(s);
}
CHILD(send_kid)
{
    SOCKET s = xc_arg_sock(argv, 1);
    xc_child_up();
    return xc_send(s, "kid", 3) == 3 ? 0 : 1;
}
TEST(inh_tcp_child_data_reaches_peer_after_parent_close)
{
    SOCKET c, s; char a[64]; DWORD code; HANDLE h[1], p;
    UP(); PAIR_OR_SKIP(c, s, SYNC);
    h[0] = H(c);
    p = xc_spawn("send_kid", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(c);                                        /* the child's copy keeps the connection open */
    CHECK(xc_expect(s, "kid"));
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(s);
}

/* UDP: one queue, one consumer. */
CHILD(udp_take)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; char b[16] = {0}; struct sockaddr_in f; int fl = sizeof f, r;
    xc_child_up(); xc_rcvtimeo(s, XC_WAIT);
    r = U(recvfrom)(s, b, sizeof b, 0, (struct sockaddr *)&f, &fl);
    STEP(0, r == 4 && !memcmp(b, "dgrm", 4));
    STEP(1, xc_port_of(&f) == xc_arg_int(argv, 2));
    STEP(2, fl == sizeof(struct sockaddr_in));
    return (int)fails;
}
TEST(inh_udp_datagram_consumed_by_child_only)
{
    SOCKET u, tx; struct sockaddr_in ua, ta; char a[64]; DWORD code; HANDLE h[1], p;
    UP(); u = xc_bound(SOCK_DGRAM, PLAIN, &ua); tx = xc_bound(SOCK_DGRAM, PLAIN, &ta);
    if (u == INVALID_SOCKET || tx == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(u);
    p = xc_spawn("udp_take", XARGS(a, "%llu %d", xc_u(u), xc_port_of(&ta)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(U(sendto)(tx, "dgrm", 4, 0, (struct sockaddr *)&ua, sizeof ua), 4);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    CHECK(!xc_readable(u, 0));
    xc_close(u); xc_close(tx);
}
CHILD(udp_send_to)
{
    SOCKET s = xc_arg_sock(argv, 1); struct sockaddr_in d = xc_lo((unsigned short)xc_arg_int(argv, 2));
    xc_child_up();
    return U(sendto)(s, "hello", 5, 0, (struct sockaddr *)&d, sizeof d) == 5 ? 0 : 1;
}
TEST(inh_udp_child_sendto_source_is_parent_binding)
{
    SOCKET u, rx; struct sockaddr_in ua, ra, from; int fl = sizeof from; char a[64], b[16] = {0}; HANDLE h[1], p; DWORD code;
    UP(); u = xc_bound(SOCK_DGRAM, PLAIN, &ua); rx = xc_bound(SOCK_DGRAM, PLAIN, &ra);
    if (u == INVALID_SOCKET || rx == INVALID_SOCKET) { t_skip("setup"); return; }
    xc_rcvtimeo(rx, XC_WAIT);
    h[0] = H(u);
    p = xc_spawn("udp_send_to", XARGS(a, "%llu %d", xc_u(u), xc_port_of(&ra)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(U(recvfrom)(rx, b, sizeof b, 0, (struct sockaddr *)&from, &fl), 5);
    CHECK(!memcmp(b, "hello", 5));
    XEQ(xc_port_of(&from), xc_port_of(&ua));
    XEQ(from.sin_addr.s_addr, 0x0100007fu);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(u); xc_close(rx);
}
/* A UDP socket connected in the parent keeps its default peer in the child. */
CHILD(udp_connected)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0;
    xc_child_up();
    STEP(0, xc_name_port(s, 1) == xc_arg_int(argv, 2));
    STEP(1, xc_send(s, "via", 3) == 3);
    return (int)fails;
}
TEST(inh_udp_connected_peer_kept_in_child)
{
    SOCKET u, peer; struct sockaddr_in pa; char a[64], b[8] = {0}; HANDLE h[1], p; DWORD code; struct sockaddr_in lo;
    UP(); u = xc_make(AF_INET, SOCK_DGRAM, PLAIN); peer = xc_bound(SOCK_DGRAM, PLAIN, &pa);
    if (u == INVALID_SOCKET || peer == INVALID_SOCKET) { t_skip("setup"); return; }
    xc_rcvtimeo(peer, XC_WAIT);
    lo = pa;
    XEQ(U(connect)(u, (struct sockaddr *)&lo, sizeof lo), 0);
    h[0] = H(u);
    p = xc_spawn("udp_connected", XARGS(a, "%llu %d", xc_u(u), xc_port_of(&pa)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(U(recv)(peer, b, sizeof b, 0), 3);
    CHECK(!memcmp(b, "via", 3));
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(u); xc_close(peer);
}

/* ---------------- listeners in a child ---------------- */
CHILD(accept_echo)
{
    SOCKET l = xc_arg_sock(argv, 1), s; unsigned fails = 0; char b[4] = {0}; struct sockaddr_in pa; int pl = sizeof pa;
    xc_child_up();
    s = xc_accept(l, XC_WAIT);
    STEP(0, s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return (int)fails;
    xc_rcvtimeo(s, XC_WAIT);
    STEP(1, U(getpeername)(s, (struct sockaddr *)&pa, &pl) == 0 && pa.sin_addr.s_addr == 0x0100007fu);
    STEP(2, xc_recv_n(s, b, 2) == 2 && !memcmp(b, "hi", 2));
    STEP(3, xc_send(s, "ok", 2) == 2);
    STEP(4, xc_name_port(s, 0) == xc_arg_int(argv, 2));   /* accepted on the listener's port */
    U(closesocket)(s);
    return (int)fails;
}
TEST(inh_listener_accepts_in_child)
{
    SOCKET l, c; struct sockaddr_in la; char a[64]; HANDLE h[1], p; DWORD code;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(l);
    p = xc_spawn("accept_echo", XARGS(a, "%llu %d", xc_u(l), xc_port_of(&la)), h, 1, NULL);
    CHECK(p != NULL);
    c = xc_make(AF_INET, SOCK_STREAM, OVLD); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    XEQ(xc_send(c, "hi", 2), 2);
    CHECK(xc_expect(c, "ok"));
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c); xc_close(l);
}
/* A pending connection (accepted nowhere yet) completes in the child after the parent closed its listener. */
TEST(inh_backlogged_connection_accepted_by_child_after_parent_close)
{
    SOCKET l, c; struct sockaddr_in la; char a[64]; HANDLE h[1], p; DWORD code;
    UP(); l = xc_listener(PLAIN, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);   /* queued in the backlog */
    h[0] = H(l);
    p = xc_spawn("accept_echo", XARGS(a, "%llu %d", xc_u(l), xc_port_of(&la)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(l);
    XEQ(xc_send(c, "hi", 2), 2);
    CHECK(xc_expect(c, "ok"));
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c);
}

/* ---------------- inheritable bit of derived sockets ---------------- */
struct fm { int lflags; const char *name; };
static void accepted_flag_case(int lflags, int use_wsaaccept)
{
    SOCKET l, c, s; struct sockaddr_in la;
    UP(); l = xc_listener(lflags, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(xc_readable(l, XC_WAIT));
    s = use_wsaaccept ? U(WSAAccept)(l, NULL, NULL, NULL, 0) : U(accept)(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        DWORD lf = xc_hflags(H(l)), sf = xc_hflags(H(s));
        t_note("listener flags %d: listener inherit=%lu accepted inherit=%lu", lflags, lf, sf);
        XEQ(sf, lf);                                     /* the accepted socket mirrors the listener */
        xc_close(s);
    }
    xc_close(c); xc_close(l);
}
TEST(inh_accepted_mirrors_plain_listener)       { accepted_flag_case(PLAIN, 0); }
TEST(inh_accepted_mirrors_sync_listener)        { accepted_flag_case(SYNC, 0); }
TEST(inh_accepted_mirrors_overlapped_listener)  { accepted_flag_case(OVLD, 0); }
TEST(inh_accepted_mirrors_noinherit_listener)   { accepted_flag_case(NOINH, 0); }
TEST(inh_accepted_mirrors_noinherit_ovl_listener) { accepted_flag_case(OVLD | NOINH, 0); }
TEST(inh_wsaaccept_mirrors_plain_listener)      { accepted_flag_case(PLAIN, 1); }
TEST(inh_wsaaccept_mirrors_noinherit_listener)  { accepted_flag_case(NOINH, 1); }

/* AcceptEx: the accept socket keeps the flags it was created with. */
static void acceptex_flag_case(int aflags)
{
    SOCKET l, a, c; struct sockaddr_in la; LPFN_ACCEPTEX fn = NULL; GUID g = WSAID_ACCEPTEX; DWORD n = 0, got = 0;
    char buf[2 * (sizeof(struct sockaddr_in) + 16)]; OVERLAPPED ov;
    UP(); l = xc_listener(OVLD, &la);
    a = xc_make(AF_INET, SOCK_STREAM, aflags);
    if (l == INVALID_SOCKET || a == INVALID_SOCKET) { t_skip("setup"); return; }
    if (U(WSAIoctl)(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL) || !fn) { t_skip("AcceptEx unavailable"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    CHECK(fn(l, a, buf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &got, &ov) || xc_werr() == ERROR_IO_PENDING);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    XEQ(WaitForSingleObject(ov.hEvent, XC_WAIT), WAIT_OBJECT_0);
    XEQ(xc_hflags(H(a)), aflags == (OVLD | NOINH) ? 0 : HANDLE_FLAG_INHERIT);
    CloseHandle(ov.hEvent);
    xc_close(c); xc_close(a); xc_close(l);
}
TEST(inh_acceptex_socket_keeps_inheritable_flag)   { acceptex_flag_case(OVLD); }
TEST(inh_acceptex_socket_keeps_noinherit_flag)     { acceptex_flag_case(OVLD | NOINH); }

/* ---------------- kernel-level duplicates ---------------- */
CHILD(use_dup)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0;
    xc_child_up();
    STEP(0, xc_type_of(s) == SOCK_STREAM);
    STEP(1, xc_send(s, "dup", 3) == 3);
    return (int)fails;
}
TEST(inh_duplicatehandle_makes_noinherit_socket_inheritable)
{
    SOCKET c, s; HANDLE d = NULL, h[1]; char a[64]; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD | NOINH);
    XEQ(xc_hflags(H(c)), 0);
    CHECK(DuplicateHandle(GetCurrentProcess(), H(c), GetCurrentProcess(), &d, 0, TRUE, DUPLICATE_SAME_ACCESS));
    XEQ(xc_hflags(d), HANDLE_FLAG_INHERIT);
    XEQ(xc_hflags(H(c)), 0);
    h[0] = d;
    code = xc_run("use_dup", XARGS(a, "%llu", (unsigned long long)(ULONG_PTR)d), h, 1);
    XEQ(code, 0);
    CHECK(xc_expect(s, "dup"));
    CloseHandle(d); xc_close(c); xc_close(s);
}
TEST(inh_duplicatehandle_copy_is_socket_in_parent)
{
    SOCKET c, s; HANDLE d = NULL;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    CHECK(DuplicateHandle(GetCurrentProcess(), H(c), GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK(d != H(c));
    XEQ(xc_type_of((SOCKET)(ULONG_PTR)d), SOCK_STREAM);
    XEQ(xc_name_port((SOCKET)(ULONG_PTR)d, 0), xc_name_port(c, 0));
    xc_close(c);                                         /* the copy is a second handle on the same endpoint */
    XEQ(xc_send((SOCKET)(ULONG_PTR)d, "x", 1), 1);
    CHECK(xc_expect(s, "x"));
    xc_close((SOCKET)(ULONG_PTR)d); xc_close(s);
}

/* ---------------- standard handles ---------------- */
CHILD(std_probe)
{
    HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE); unsigned fails = 0; DWORD f = 0;
    STEP(0, o != INVALID_HANDLE_VALUE && o != NULL);
    STEP(1, GetFileType(o) == FILE_TYPE_PIPE);
    STEP(2, GetHandleInformation(o, &f) && (f & HANDLE_FLAG_INHERIT));
    STEP(3, xc_is_socket((SOCKET)(ULONG_PTR)o) == 0);   /* before WSAStartup the call is refused */
    xc_child_up();
    STEP(4, xc_is_socket((SOCKET)(ULONG_PTR)o) == 1);
    return (int)fails;
}
TEST(inh_stdout_socket_is_a_socket_after_startup_in_child)
{
    SOCKET c, s; STARTUPINFOA si; PROCESS_INFORMATION pi; char cmd[1024]; DWORD code = 0xDEAD0000;
    UP(); PAIR_OR_SKIP(c, s, SYNC);
    memset(&si, 0, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = INVALID_HANDLE_VALUE; si.hStdOutput = H(c); si.hStdError = INVALID_HANDLE_VALUE;
    snprintf(cmd, sizeof cmd, "\"%s\" --child std_probe", t_self_path());
    if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        code = xc_wait(pi.hProcess, XC_CHILD_TIMEOUT);
    }
    XEQ(code, 0);
    xc_close(c); xc_close(s);
}
