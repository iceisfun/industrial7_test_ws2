/* x_child_process_inherit / more: inheritance through the inherit-all form of CreateProcess (no handle list), chains
 * of processes, several processes sharing one listener, socket queries made by a child on inherited handles,
 * event selection in a child, IPv6 and datagram sockets across a dying holder, and the edge cases of a
 * protocol-info blob (empty argument, a second use, a use by the wrong process, a damaged blob, the ANSI form). */
#include "xc.h"

/* Start a child with bInheritHandles TRUE and no handle list: every inheritable handle of this process is passed. */
static HANDLE xc_spawn_all(const char *name, const char *args)
{
    char cmd[2048]; STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    snprintf(cmd, sizeof cmd, "\"%s\" --child %s %s", t_self_path(), name, args ? args : "");
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) return NULL;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* ---------------- inherit-all: which sockets arrive ---------------- */
/* argv[2] is 'p' (the handle must be this very socket) or 'a' (the slot must not be a socket). */
CHILD(all_probe)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; int present = argv[2][0] == 'p', e;
    xc_child_up();
    xc_setwerr(0);
    if (present) {
        STEP(0, xc_type_of(s) == xc_arg_int(argv, 3));
    } else {
        STEP(1, !xc_is_socket(s));
        e = xc_werr();
        STEP(2, e == WSAENOTSOCK);
    }
    return (int)fails;
}
static void all_case(int af, int type, int flags, int clear_flag, int inherit_all, int want_present)
{
    SOCKET s; char a[64]; HANDLE p;
    UP(); s = xc_make(af, type, flags);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    if (clear_flag) CHECK(SetHandleInformation(H(s), HANDLE_FLAG_INHERIT, 0));
    XARGS(a, "%llu %c %d", xc_u(s), want_present ? 'p' : 'a', type);
    if (inherit_all) p = xc_spawn_all("all_probe", a);
    else p = xc_spawn("all_probe", a, NULL, 0, NULL);
    CHECK(p != NULL);
    XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
    xc_close(s);
}
TEST(all_plain_tcp_socket_arrives)              { all_case(AF_INET, SOCK_STREAM, PLAIN, 0, 1, 1); }
TEST(all_plain_udp_socket_arrives)              { all_case(AF_INET, SOCK_DGRAM, PLAIN, 0, 1, 1); }
TEST(all_overlapped_tcp_socket_arrives)         { all_case(AF_INET, SOCK_STREAM, OVLD, 0, 1, 1); }
TEST(all_sync_tcp_socket_arrives)               { all_case(AF_INET, SOCK_STREAM, SYNC, 0, 1, 1); }
TEST(all_noinherit_tcp_socket_absent)           { all_case(AF_INET, SOCK_STREAM, OVLD | NOINH, 0, 1, 0); }
TEST(all_noinherit_udp_socket_absent)           { all_case(AF_INET, SOCK_DGRAM, OVLD | NOINH, 0, 1, 0); }
TEST(all_noinherit_sync_socket_absent)          { all_case(AF_INET, SOCK_STREAM, SYNC | NOINH, 0, 1, 0); }
TEST(all_flag_cleared_socket_absent)            { all_case(AF_INET, SOCK_STREAM, PLAIN, 1, 1, 0); }
TEST(all_no_inheritance_requested_socket_absent) { all_case(AF_INET, SOCK_STREAM, PLAIN, 0, 0, 0); }
TEST(all_no_inheritance_requested_overlapped_absent) { all_case(AF_INET, SOCK_DGRAM, OVLD, 0, 0, 0); }
TEST(all_ipv6_tcp_socket_arrives)
{
    SOCKET s;
    UP(); s = xc_make(AF_INET6, SOCK_STREAM, PLAIN);
    if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; }
    xc_close(s);
    all_case(AF_INET6, SOCK_STREAM, PLAIN, 0, 1, 1);
}

/* ---------------- a chain of processes ---------------- */
CHILD(gen2)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0;
    xc_child_up();
    STEP(0, xc_type_of(s) == SOCK_STREAM);
    STEP(1, xc_send(s, "g2", 2) == 2);
    STEP(2, U(closesocket)(s) == 0);
    return (int)fails;
}
CHILD(gen1)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; HANDLE h[1], p; char a[64];
    xc_child_up();
    STEP(0, xc_hflags(H(s)) == HANDLE_FLAG_INHERIT);       /* an inherited handle stays inheritable */
    h[0] = H(s);
    p = xc_spawn("gen2", XARGS(a, "%llu", xc_u(s)), h, 1, NULL);
    STEP(1, p != NULL);
    STEP(2, U(closesocket)(s) == 0);                       /* the grandchild now holds the only other copy */
    if (p) STEP(3, xc_wait(p, XC_CHILD_TIMEOUT) == 0);
    return (int)fails;
}
TEST(chain_grandchild_holds_connection_after_parent_and_child_close)
{
    SOCKET c, s; char a[64], b; HANDLE h[1], p;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    p = xc_spawn("gen1", XARGS(a, "%llu", xc_u(c)), h, 1, NULL);
    CHECK(p != NULL);
    xc_close(c);
    CHECK(xc_expect(s, "g2"));
    XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
    XEQ(U(recv)(s, &b, 1, 0), 0);                          /* every handle was closed explicitly: orderly end */
    xc_close(s);
}

/* ---------------- several processes on one listener ---------------- */
CHILD(acc_many)
{
    SOCKET l = xc_arg_sock(argv, 1); DWORD mask = 0; int dup = 0;
    xc_child_up();
    for (;;) {
        SOCKET a = xc_accept(l, 1500); char id;
        if (a == INVALID_SOCKET) break;
        xc_rcvtimeo(a, XC_WAIT);
        if (U(recv)(a, &id, 1, 0) == 1) { if (mask & (1u << id)) dup = 1; mask |= 1u << id; }
        U(closesocket)(a);
    }
    return (int)(mask | (dup ? 0x1000u : 0));
}
static SOCKET qclient(const struct sockaddr_in *la, char id)
{
    SOCKET c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    if (c == INVALID_SOCKET) return c;
    if (U(connect)(c, (struct sockaddr *)la, sizeof *la)) { xc_close(c); return INVALID_SOCKET; }
    xc_send(c, &id, 1);
    return c;
}
TEST(many_two_children_share_listener_each_connection_once)
{
    SOCKET l, cl[8]; struct sockaddr_in la; char a[64]; HANDLE h[1], p1, p2; DWORD c1, c2; int i;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    for (i = 0; i < 8; i++) cl[i] = qclient(&la, (char)i);
    h[0] = H(l);
    p1 = xc_spawn("acc_many", XARGS(a, "%llu", xc_u(l)), h, 1, NULL);
    p2 = xc_spawn("acc_many", a, h, 1, NULL);
    CHECK(p1 && p2);
    c1 = xc_wait(p1, XC_CHILD_TIMEOUT); c2 = xc_wait(p2, XC_CHILD_TIMEOUT);
    XEQ(c1 & ~0xffu, 0); XEQ(c2 & ~0xffu, 0);            /* no duplicate seen inside either child */
    XEQ(c1 & c2, 0);                                      /* no connection accepted by both */
    XEQ(c1 | c2, 0xff);                                   /* none lost */
    XEQ(xc_readable(l, 0), 0);
    for (i = 0; i < 8; i++) xc_close(cl[i]);
    xc_close(l);
}

/* ---------------- queries in the child ---------------- */
CHILD(query_info)
{
    unsigned fails = 0; int k, rc;
    xc_child_up();
    for (k = 0; k < 3; k++) {
        SOCKET s = xc_arg_sock(argv, 1 + k); int ty = 0, tl = sizeof ty, ac = -1, al = sizeof ac; WSAPROTOCOL_INFOW pi; int pl = sizeof pi;
        STEP(k * 4, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl) == 0 && ty == (k == 1 ? SOCK_DGRAM : SOCK_STREAM));
        xc_setwerr(0);
        rc = U(getsockopt)(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&ac, &al);
        if (k == 1) { STEP(k * 4 + 1, rc == SOCKET_ERROR); STEP(12, xc_werr() == WSAENOPROTOOPT); }   /* datagram sockets have no listening state */
        else STEP(k * 4 + 1, rc == 0 && ac == (k == 2 ? 1 : 0));
        STEP(k * 4 + 2, U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &pl) == 0 && pl == sizeof pi && (int)pi.dwCatalogEntryId == xc_arg_int(argv, 4 + k));
    }
    return (int)fails;
}
TEST(query_child_sees_type_listening_state_and_catalog_entry)
{
    SOCKET c, s, u, l; WSAPROTOCOL_INFOW pc, pu, pl; int n = sizeof pc, i; char a[160]; HANDLE h[3];
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    u = xc_bound(SOCK_DGRAM, OVLD, NULL); l = xc_listener(OVLD, NULL);
    if (u == INVALID_SOCKET || l == INVALID_SOCKET) { t_skip("setup"); return; }
    XEQ(U(getsockopt)(c, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pc, &n), 0); i = sizeof pu;
    XEQ(U(getsockopt)(u, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pu, &i), 0); i = sizeof pl;
    XEQ(U(getsockopt)(l, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pl, &i), 0);
    h[0] = H(c); h[1] = H(u); h[2] = H(l);
    XEQ(xc_run("query_info", XARGS(a, "%llu %llu %llu %lu %lu %lu", xc_u(c), xc_u(u), xc_u(l), pc.dwCatalogEntryId, pu.dwCatalogEntryId, pl.dwCatalogEntryId), h, 3), 0);
    xc_close(c); xc_close(s); xc_close(u); xc_close(l);
}
CHILD(peek_only)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; u_long n = 0; char b[8] = {0};
    xc_child_up();
    STEP(0, U(ioctlsocket)(s, FIONREAD, &n) == 0 && n == 5);
    STEP(1, xc_readable(s, XC_WAIT));
    STEP(2, U(recv)(s, b, 5, MSG_PEEK) == 5 && !memcmp(b, "abcde", 5));
    return (int)fails;
}
TEST(query_child_peek_and_fionread_leave_data_for_parent)
{
    SOCKET c, s; char a[64], b[8] = {0}; HANDLE h[1]; u_long n = 0;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(xc_send(s, "abcde", 5), 5);
    h[0] = H(c);
    XEQ(xc_run("peek_only", XARGS(a, "%llu", xc_u(c)), h, 1), 0);
    XEQ(U(ioctlsocket)(c, FIONREAD, &n), 0);
    XEQ(n, 5);                                             /* the child consumed nothing */
    XEQ(xc_recv_n(c, b, 5), 5);
    CHECK(!memcmp(b, "abcde", 5));
    xc_close(c); xc_close(s);
}
CHILD(avail_after)
{
    SOCKET s = xc_arg_sock(argv, 1); char b[8];
    xc_child_up(); xc_rcvtimeo(s, XC_WAIT);
    return xc_recv_n(s, b, 3) == 3 ? 0 : 1;
}
TEST(query_fionread_in_parent_counts_what_child_left)
{
    SOCKET c, s; char a[64]; HANDLE h[1]; u_long n = 99;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(xc_send(s, "abcdefg", 7), 7);
    CHECK(xc_readable(c, XC_WAIT));
    h[0] = H(c);
    XEQ(xc_run("avail_after", XARGS(a, "%llu", xc_u(c)), h, 1), 0);
    XEQ(U(ioctlsocket)(c, FIONREAD, &n), 0);
    XEQ(n, 4);                                             /* the child took three of the seven queued bytes */
    xc_close(c); xc_close(s);
}

/* ---------------- event selection in the child ---------------- */
CHILD(evsel_read)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; WSAEVENT ev; WSANETWORKEVENTS ne;
    xc_child_up();
    ev = U(WSACreateEvent)();
    STEP(0, U(WSAEventSelect)(s, ev, FD_READ | FD_CLOSE) == 0);
    STEP(1, U(WSAWaitForMultipleEvents)(1, &ev, FALSE, XC_WAIT, FALSE) == WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne);
    STEP(2, U(WSAEnumNetworkEvents)(s, ev, &ne) == 0);
    STEP(3, (ne.lNetworkEvents & FD_READ) != 0 && ne.iErrorCode[FD_READ_BIT] == 0);
    STEP(4, (ne.lNetworkEvents & FD_CLOSE) == 0);
    U(WSACloseEvent)(ev);
    return (int)fails;
}
TEST(evsel_child_sees_fd_read_for_data_queued_by_peer)
{
    SOCKET c, s; char a[64]; HANDLE h[1];
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(xc_send(s, "x", 1), 1);
    h[0] = H(c);
    XEQ(xc_run("evsel_read", XARGS(a, "%llu", xc_u(c)), h, 1), 0);
    xc_close(c); xc_close(s);
}
CHILD(evsel_accept)
{
    SOCKET l = xc_arg_sock(argv, 1), x; unsigned fails = 0; WSAEVENT ev; WSANETWORKEVENTS ne;
    xc_child_up();
    ev = U(WSACreateEvent)();
    STEP(0, U(WSAEventSelect)(l, ev, FD_ACCEPT) == 0);
    STEP(1, U(WSAWaitForMultipleEvents)(1, &ev, FALSE, XC_WAIT, FALSE) == WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne);
    STEP(2, U(WSAEnumNetworkEvents)(l, ev, &ne) == 0);
    STEP(3, (ne.lNetworkEvents & FD_ACCEPT) != 0 && ne.iErrorCode[FD_ACCEPT_BIT] == 0);
    x = U(accept)(l, NULL, NULL);
    STEP(4, x != INVALID_SOCKET);
    xc_close(x);
    U(WSACloseEvent)(ev);
    return (int)fails;
}
TEST(evsel_child_sees_fd_accept_for_connection_queued_by_parent)
{
    SOCKET l, c; struct sockaddr_in la; char a[64]; HANDLE h[1];
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    h[0] = H(l);
    XEQ(xc_run("evsel_accept", XARGS(a, "%llu", xc_u(l)), h, 1), 0);
    xc_close(c); xc_close(l);
}

/* ---------------- datagram socket and a dying holder ---------------- */
CHILD(hold_udp) { Sleep(XC_CHILD_TIMEOUT); return 0; }
TEST(udp_holder_terminated_socket_keeps_working_in_parent)
{
    SOCKET u, tx; struct sockaddr_in ua, ta; char a[64], b[8] = {0}; HANDLE h[1], p;
    UP(); u = xc_bound(SOCK_DGRAM, PLAIN, &ua); tx = xc_bound(SOCK_DGRAM, PLAIN, &ta);
    if (u == INVALID_SOCKET || tx == INVALID_SOCKET) { t_skip("setup"); return; }
    xc_rcvtimeo(u, XC_WAIT);
    h[0] = H(u);
    p = xc_spawn("hold_udp", XARGS(a, "%llu", xc_u(u)), h, 1, NULL);
    CHECK(p != NULL);
    XEQ(U(sendto)(tx, "one", 3, 0, (struct sockaddr *)&ua, sizeof ua), 3);
    XEQ(U(recv)(u, b, sizeof b, 0), 3);
    xc_kill(p);                                            /* a datagram endpoint is not reset by a dying holder */
    XEQ(U(sendto)(tx, "two", 3, 0, (struct sockaddr *)&ua, sizeof ua), 3);
    XEQ(U(recv)(u, b, sizeof b, 0), 3);
    CHECK(!memcmp(b, "two", 3));
    xc_close(u); xc_close(tx);
}

/* ---------------- IPv6 ---------------- */
CHILD(v6_talk)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0; struct sockaddr_in6 n; int nl = sizeof n;
    xc_child_up();
    memset(&n, 0, sizeof n);
    STEP(0, U(getsockname)(s, (struct sockaddr *)&n, &nl) == 0 && n.sin6_family == AF_INET6 && nl == sizeof n);
    STEP(1, xc_send(s, "v6", 2) == 2);
    return (int)fails;
}
TEST(v6_inherited_connection_in_child)
{
    SOCKET l, c, s; struct sockaddr_in6 a; int al = sizeof a; char arg[64]; HANDLE h[1]; DWORD code;
    UP(); l = U(WSASocketW)(AF_INET6, SOCK_STREAM, 0, NULL, 0, OVLD);
    if (l == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; }
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    if (U(bind)(l, (struct sockaddr *)&a, sizeof a) || U(listen)(l, 2) || U(getsockname)(l, (struct sockaddr *)&a, &al)) { xc_close(l); t_skip("IPv6 loopback unavailable"); return; }
    c = U(WSASocketW)(AF_INET6, SOCK_STREAM, 0, NULL, 0, OVLD);
    if (U(connect)(c, (struct sockaddr *)&a, sizeof a)) { xc_close(c); xc_close(l); t_skip("IPv6 loopback unavailable"); return; }
    s = xc_accept(l, XC_WAIT);
    CHECK(s != INVALID_SOCKET);
    xc_rcvtimeo(s, XC_WAIT);
    h[0] = H(c);
    code = xc_run("v6_talk", XARGS(arg, "%llu", xc_u(c)), h, 1);
    XEQ(code, 0);
    CHECK(xc_expect(s, "v6"));
    xc_close(c); xc_close(s); xc_close(l);
}
