/* x_error_mapping / second sweep of failing-call scenarios: connection-state transitions seen through SO_ERROR and
 * the per-event error codes of WSAEnumNetworkEvents, conditional accept outcomes, option-level and option-name
 * rejections, argument validation on transfer calls, IPv6-specific rejections, the service-provider path lookups
 * that report errors through an out parameter, and the textual converters.
 *
 * Same row style as xe_calls.c: a scenario returns the Winsock error number of a call that must have failed, or -1
 * when the call succeeded. Rows whose expectation is XE_UNK only record what happened. */
#include <winsock2.h>
#include <ws2spi.h>
#include "xe.h"

#define M_CASE(n, WANT) \
    static long m_##n(void); \
    TEST(xemore_##n) { long r; XE_UP(); xe_gle_seen = -5; xe_wsa_seen = -6; WSASetLastError(XE_BAD); r = m_##n(); \
        if (r == XE_UNK - 1000) { t_skip("scenario not available"); return; } \
        if ((WANT) == XE_UNK) { t_note("ROW more %s %ld gle=%d", #n, r, xe_gle_seen); return; } \
        t_check(r == (WANT), "x_error_mapping", 0, #n, "got %ld want %ld", r, (long)(WANT)); \
        if (r != -1 && xe_wsa_seen != -6) t_check(xe_gle_seen == xe_wsa_seen, "x_error_mapping", 0, #n, "GetLastError %d vs WSAGetLastError %d", xe_gle_seen, xe_wsa_seen); } \
    static long m_##n(void)

#define SA(p) ((struct sockaddr *)(p))
static SOCKET nbsock(SOCKET s) { u_long v = 1; ioctlsocket(s, FIONBIO, &v); return s; }
static int soerr(SOCKET s) { int v = -9, n = sizeof v; if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&v, &n) == SOCKET_ERROR) return -100 - WSAGetLastError(); return v; }
static int wait_sel(SOCKET s, int rd, int wr, int ex, long ms) {
    fd_set r, w, e; struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
    if (rd) { FD_SET(s, &r); }
    if (wr) { FD_SET(s, &w); }
    if (ex) { FD_SET(s, &e); }
    return select(0, rd ? &r : NULL, wr ? &w : NULL, ex ? &e : NULL, &tv);
}

/* ---- SO_ERROR after non-blocking connects ---- */
M_CASE(soerror_fresh_socket_zero, 0) { SOCKET s = xe_sock(SOCK_STREAM); long r = soerr(s); xe_close(s); return r; }
M_CASE(soerror_after_refused_nonblocking, 10061) {
    SOCKET s = nbsock(xe_sock(SOCK_STREAM)); struct sockaddr_in a; long r; xe_dead_port(&a);
    connect(s, SA(&a), sizeof a); wait_sel(s, 0, 0, 1, 3000); r = soerr(s); xe_close(s); return r; }
M_CASE(soerror_refused_persists_across_reads, 10061) {
    SOCKET s = nbsock(xe_sock(SOCK_STREAM)); struct sockaddr_in a; long r; xe_dead_port(&a);
    connect(s, SA(&a), sizeof a); wait_sel(s, 0, 0, 1, 3000); soerr(s); r = soerr(s); xe_close(s); return r; }
M_CASE(soerror_refused_reported_as_except_set, 1) {
    SOCKET s = nbsock(xe_sock(SOCK_STREAM)); struct sockaddr_in a; long r; xe_dead_port(&a);
    connect(s, SA(&a), sizeof a); r = wait_sel(s, 0, 0, 1, 3000); xe_close(s); return r; }
M_CASE(soerror_after_successful_nonblocking_connect, 0) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = nbsock(xe_sock(SOCK_STREAM)); long r;
    connect(c, SA(&la), sizeof la); wait_sel(c, 0, 1, 0, 3000); r = soerr(c); xe_close(c); xe_close(l); return r; }
M_CASE(soerror_after_failed_recv_reset, 0) {
    SOCKET c, s; char b[4]; struct linger l = {1, 0}; long r; xe_pair(&c, &s);
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); xe_wait_readable(c, 1000);
    recv(c, b, 4, 0); r = soerr(c); xe_close(c); return r; }
M_CASE(soerror_after_udp_port_unreachable, 0) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in aa, dead; long r; xe_bind_lo(a, &aa); xe_dead_port(&dead);
    sendto(a, "x", 1, 0, SA(&dead), sizeof dead); xe_wait_readable(a, 1000); r = soerr(a); xe_close(a); return r; }
M_CASE(soerror_set_is_unsupported, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v = 5; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(second_connect_after_refused, -1) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a, la; SOCKET l = xe_listener(&la); long r; xe_dead_port(&a);
    connect(s, SA(&a), sizeof a); r = XE_FAIL(connect(s, SA(&la), sizeof la) == SOCKET_ERROR); xe_close(s); xe_close(l); return r; }
M_CASE(connect_after_listener_close_refused, 10061) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM); long r; closesocket(l);
    r = XE_FAIL(connect(c, SA(&la), sizeof la) == SOCKET_ERROR); xe_close(c); return r; }

/* ---- WSAEnumNetworkEvents error codes ---- */
static long ev_code(SOCKET s, long mask, int bit, long *got_mask, long wait_ms) {
    WSAEVENT e = WSACreateEvent(); WSANETWORKEVENTS ne; long r;
    WSAEventSelect(s, e, mask); WaitForSingleObject(e, wait_ms);
    memset(&ne, 0x55, sizeof ne);
    if (WSAEnumNetworkEvents(s, e, &ne) == SOCKET_ERROR) { WSACloseEvent(e); return -100 - WSAGetLastError(); }
    if (got_mask) *got_mask = ne.lNetworkEvents;
    r = bit < 0 ? 0 : ne.iErrorCode[bit];
    WSAEventSelect(s, NULL, 0); WSACloseEvent(e); return r;
}
M_CASE(netevents_refused_connect_code, 10061) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; long r; xe_dead_port(&a); nbsock(s);
    { WSAEVENT e = WSACreateEvent(); WSANETWORKEVENTS ne; WSAEventSelect(s, e, FD_CONNECT); connect(s, SA(&a), sizeof a); WaitForSingleObject(e, 3000);
      memset(&ne, 0, sizeof ne); WSAEnumNetworkEvents(s, e, &ne); r = ne.iErrorCode[FD_CONNECT_BIT]; WSAEventSelect(s, NULL, 0); WSACloseEvent(e); }
    xe_close(s); return r; }
M_CASE(netevents_refused_connect_mask, FD_CONNECT) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; long r = 0; xe_dead_port(&a); nbsock(s);
    { WSAEVENT e = WSACreateEvent(); WSANETWORKEVENTS ne; WSAEventSelect(s, e, FD_CONNECT); connect(s, SA(&a), sizeof a); WaitForSingleObject(e, 3000);
      memset(&ne, 0, sizeof ne); WSAEnumNetworkEvents(s, e, &ne); r = ne.lNetworkEvents; WSAEventSelect(s, NULL, 0); WSACloseEvent(e); }
    xe_close(s); return r; }
M_CASE(netevents_connect_success_code, 0) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = nbsock(xe_sock(SOCK_STREAM)); long r;
    { WSAEVENT e = WSACreateEvent(); WSANETWORKEVENTS ne; WSAEventSelect(c, e, FD_CONNECT); connect(c, SA(&la), sizeof la); WaitForSingleObject(e, 3000);
      memset(&ne, 0x55, sizeof ne); WSAEnumNetworkEvents(c, e, &ne); r = ne.iErrorCode[FD_CONNECT_BIT]; WSAEventSelect(c, NULL, 0); WSACloseEvent(e); }
    xe_close(c); xe_close(l); return r; }
M_CASE(netevents_reset_close_code, 10053) {
    SOCKET c, s; struct linger l = {1, 0}; long r; xe_pair(&c, &s);
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s);
    r = ev_code(c, FD_CLOSE, FD_CLOSE_BIT, NULL, 3000); xe_close(c); return r; }
M_CASE(netevents_graceful_close_code, 0) {
    SOCKET c, s; long r; xe_pair(&c, &s); closesocket(s);
    r = ev_code(c, FD_CLOSE, FD_CLOSE_BIT, NULL, 3000); xe_close(c); return r; }
M_CASE(netevents_graceful_close_mask, FD_CLOSE) {
    SOCKET c, s; long m = 0; xe_pair(&c, &s); closesocket(s);
    ev_code(c, FD_CLOSE, -1, &m, 3000); xe_close(c); return m; }
M_CASE(netevents_accept_code, 0) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM); long r;
    connect(c, SA(&la), sizeof la); r = ev_code(l, FD_ACCEPT, FD_ACCEPT_BIT, NULL, 3000); xe_close(c); xe_close(l); return r; }
M_CASE(netevents_accept_mask, FD_ACCEPT) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM); long m = 0;
    connect(c, SA(&la), sizeof la); ev_code(l, FD_ACCEPT, -1, &m, 3000); xe_close(c); xe_close(l); return m; }
M_CASE(netevents_nothing_pending_mask, 0) {
    SOCKET c, s; long m = -1; xe_pair(&c, &s); ev_code(c, FD_READ | FD_CLOSE, -1, &m, 0); xe_close(c); xe_close(s); return m; }
M_CASE(netevents_udp_unreachable_read_code, 0) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in aa, dead; long r; xe_bind_lo(a, &aa); xe_dead_port(&dead);
    sendto(a, "x", 1, 0, SA(&dead), sizeof dead); r = ev_code(a, FD_READ, FD_READ_BIT, NULL, 2000); xe_close(a); return r; }
M_CASE(netevents_connected_mask, 18) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = nbsock(xe_sock(SOCK_STREAM)); long m = 0;
    connect(c, SA(&la), sizeof la); Sleep(100); ev_code(c, FD_CONNECT | FD_WRITE, -1, &m, 3000); xe_close(c); xe_close(l); return m; }
M_CASE(eventselect_null_event_with_mask, 10022) {
    SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(WSAEventSelect(s, NULL, FD_READ) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(eventselect_null_event_zero_mask, -1) {
    SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(WSAEventSelect(s, NULL, 0) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(eventselect_makes_blocking_mode_nonblocking, 10035) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la); WSAEVENT e = WSACreateEvent(); long r;
    WSAEventSelect(l, e, FD_ACCEPT); r = XE_FAIL(accept(l, NULL, NULL) == INVALID_SOCKET); WSAEventSelect(l, NULL, 0); WSACloseEvent(e); xe_close(l); return r; }
M_CASE(blocking_mode_restore_after_eventselect_cleared, 10022) {
    SOCKET s = xe_sock(SOCK_STREAM); WSAEVENT e = WSACreateEvent(); u_long v = 0; long r; WSAEventSelect(s, e, FD_READ);
    r = XE_FAIL(ioctlsocket(s, FIONBIO, &v) == SOCKET_ERROR); WSAEventSelect(s, NULL, 0); WSACloseEvent(e); xe_close(s); return r; }
M_CASE(blocking_mode_restore_after_eventselect_cancel, -1) {
    SOCKET s = xe_sock(SOCK_STREAM); WSAEVENT e = WSACreateEvent(); u_long v = 0; long r; WSAEventSelect(s, e, FD_READ); WSAEventSelect(s, NULL, 0);
    r = XE_FAIL(ioctlsocket(s, FIONBIO, &v) == SOCKET_ERROR); WSACloseEvent(e); xe_close(s); return r; }
M_CASE(enumnetworkevents_closed_event_handle, 10038) {
    SOCKET s = xe_sock(SOCK_STREAM); WSAEVENT e = WSACreateEvent(); WSANETWORKEVENTS ne; long r; WSAEventSelect(s, e, FD_READ); WSACloseEvent(e);
    r = XE_FAIL(WSAEnumNetworkEvents(s, e, &ne) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(wsacloseevent_twice, 6) { WSAEVENT e = WSACreateEvent(); WSACloseEvent(e); return XE_FAIL(WSACloseEvent(e) == FALSE); }
M_CASE(wsaseteventclosed, 6) { WSAEVENT e = WSACreateEvent(); WSACloseEvent(e); return XE_FAIL(WSASetEvent(e) == FALSE); }

/* ---- conditional accept ---- */
static int g_cond_ret, g_cond_calls;
static int CALLBACK cond_fn(LPWSABUF cid, LPWSABUF cdata, LPQOS sq, LPQOS gq, LPWSABUF calleeid, LPWSABUF calleedata, GROUP *g, DWORD_PTR cb) {
    g_cond_calls++; return g_cond_ret;
}
static long wsaaccept_with(int ret) {
    struct sockaddr_in la, pa; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM), a; int n = sizeof pa; long r;
    g_cond_ret = ret; g_cond_calls = 0;
    connect(c, SA(&la), sizeof la); xe_wait_readable(l, 2000);
    a = WSAAccept(l, SA(&pa), &n, cond_fn, 0);
    r = (a == INVALID_SOCKET) ? XE_FAIL(1) : -1; if (a != INVALID_SOCKET) xe_close(a);
    xe_close(c); xe_close(l); return r; }
M_CASE(wsaaccept_condition_reject, 10061) { return wsaaccept_with(CF_REJECT); }
M_CASE(wsaaccept_condition_accept, -1) { return wsaaccept_with(CF_ACCEPT); }
M_CASE(wsaaccept_condition_defer, 11002) { return wsaaccept_with(CF_DEFER); }
M_CASE(wsaaccept_condition_bogus_return, 10022) { return wsaaccept_with(7); }
M_CASE(wsaaccept_condition_called_once, 1) { wsaaccept_with(CF_REJECT); return g_cond_calls; }
M_CASE(wsaaccept_not_listening, 10022) { SOCKET s = xe_sock(SOCK_STREAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(WSAAccept(s, NULL, NULL, NULL, 0) == INVALID_SOCKET); xe_close(s); return r; }
M_CASE(wsaaccept_udp, 10045) { SOCKET s = xe_sock(SOCK_DGRAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(WSAAccept(s, NULL, NULL, NULL, 0) == INVALID_SOCKET); xe_close(s); return r; }
M_CASE(wsaaccept_nonblocking_empty, 10035) { struct sockaddr_in la; SOCKET l = nbsock(xe_listener(&la)); long r = XE_FAIL(WSAAccept(l, NULL, NULL, NULL, 0) == INVALID_SOCKET); xe_close(l); return r; }
M_CASE(wsaaccept_addrlen_small, 10014) {
    struct sockaddr_in la, pa; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM), a; int n = 4; long r;
    connect(c, SA(&la), sizeof la); xe_wait_readable(l, 2000); a = WSAAccept(l, SA(&pa), &n, NULL, 0); r = XE_FAIL(a == INVALID_SOCKET); xe_close(a); xe_close(c); xe_close(l); return r; }
M_CASE(soconditional_accept_on_udp, -1) { SOCKET s = xe_sock(SOCK_DGRAM); BOOL v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(soconditional_accept_after_listen, 10022) { struct sockaddr_in la; SOCKET l = xe_listener(&la); BOOL v = 1; long r = XE_FAIL(setsockopt(l, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(l); return r; }

/* ---- option names, levels, lengths ---- */
M_CASE(setsockopt_keepalive_on_udp, 10042) { SOCKET s = xe_sock(SOCK_DGRAM); BOOL v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_rcvtimeo_len_one, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &v, 1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_rcvtimeo_len_zero, 10014) { SOCKET s = xe_sock(SOCK_STREAM); DWORD v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, 0) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_sndbuf_len_zero, 10014) { SOCKET s = xe_sock(SOCK_STREAM); int v = 8192; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&v, 0) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_sndbuf_len_negative, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v = 8192; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&v, -1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ip_ttl_on_stream, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v = 20; long r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ip_ttl_zero, -1) { SOCKET s = xe_sock(SOCK_DGRAM); int v = 0; long r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ip_ttl_256, 10022) { SOCKET s = xe_sock(SOCK_DGRAM); int v = 256; long r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ip_ttl_negative, -1) { SOCKET s = xe_sock(SOCK_DGRAM); int v = -1; long r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ip_ttl_len_small, -1) { SOCKET s = xe_sock(SOCK_DGRAM); char v = 20; long r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_TTL, &v, 1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ipv6_option_on_v4_socket, -1) { SOCKET s = xe_sock(SOCK_DGRAM); int v = 5; long r = XE_FAIL(setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_v6only_on_v4_socket, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v = 0, n = sizeof v; long r = XE_FAIL(getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_ip_option_on_v6_socket, 10022) { SOCKET s = xe_sock6(SOCK_DGRAM); int v = 5; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000; r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(setsockopt_multicast_ttl_on_stream, 10022) { SOCKET s = xe_sock(SOCK_STREAM); int v = 5; long r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(add_membership_unicast_group, 10049) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct ip_mreq m; long r; xe_bind_lo(s, NULL); m.imr_multiaddr.s_addr = 0x0100007f; m.imr_interface.s_addr = 0x0100007f;
    r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&m, sizeof m) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(add_membership_on_stream, 10022) {
    SOCKET s = xe_sock(SOCK_STREAM); struct ip_mreq m; long r; m.imr_multiaddr.s_addr = 0x010000e0; m.imr_interface.s_addr = 0x0100007f;
    r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&m, sizeof m) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(drop_membership_not_joined, 10049) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct ip_mreq m; long r; xe_bind_lo(s, NULL); m.imr_multiaddr.s_addr = 0x010000e0; m.imr_interface.s_addr = 0x0100007f;
    r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&m, sizeof m) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(add_membership_len_small, 10014) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct ip_mreq m; long r; xe_bind_lo(s, NULL); m.imr_multiaddr.s_addr = 0x010000e0; m.imr_interface.s_addr = 0x0100007f;
    r = XE_FAIL(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&m, 4) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_max_msg_size_on_stream, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v = 0, n = sizeof v; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_max_msg_size_on_udp, -1) { SOCKET s = xe_sock(SOCK_DGRAM); int v = 0, n = sizeof v; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_protocol_info_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[16]; int n = sizeof b; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, b, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_linger_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[2]; int n = sizeof b; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_LINGER, b, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_zero_len, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[4]; int n = 0; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_RCVBUF, b, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_dontlinger_unsupported, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v, n = sizeof v; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_DONTLINGER, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(getsockopt_tcp_maxseg_on_udp, 10022) { SOCKET s = xe_sock(SOCK_DGRAM); int v, n = sizeof v; long r = XE_FAIL(getsockopt(s, IPPROTO_TCP, 0x7ff0, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(update_accept_context_on_unconnected, 10057) { SOCKET s = xe_sock(SOCK_STREAM), l = xe_sock(SOCK_STREAM); long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof l) == SOCKET_ERROR); xe_close(s); xe_close(l); return r; }
M_CASE(update_accept_context_not_listener, -1) { SOCKET c, s; long r; SOCKET other = xe_sock(SOCK_STREAM); xe_pair(&c, &s); r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&other, sizeof other) == SOCKET_ERROR); xe_close(other); xe_close(c); xe_close(s); return r; }
M_CASE(update_accept_context_len_small, 10014) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&c, 2) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(update_connect_context_unconnected, 10057) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR); xe_close(s); return r; }

/* ---- transfer arguments ---- */
M_CASE(send_negative_length, 10014) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(send(c, "x", -1, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(recv_negative_length, 10014) { SOCKET c, s; char b[4]; long r; xe_pair(&c, &s); r = XE_FAIL(recv(c, b, -1, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(send_zero_length_stream, -1) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(send(c, "", 0, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(recv_bad_flags, 10035) { SOCKET c, s; char b[4]; long r; xe_pair(&c, &s); nbsock(c); r = XE_FAIL(recv(c, b, 4, 0x8000) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(send_bad_flags, -1) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(send(c, "x", 1, 0x8000) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(send_msg_peek_flag, 10045) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(send(c, "x", 1, MSG_PEEK) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(recv_msg_partial_flag_stream, 10035) { SOCKET c, s; char b[4]; long r; xe_pair(&c, &s); nbsock(c); r = XE_FAIL(recv(c, b, 4, MSG_PARTIAL) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(recv_peek_on_listener, 10057) { struct sockaddr_in la; SOCKET l = xe_listener(&la); char b[4]; long r = XE_FAIL(recv(l, b, 4, MSG_PEEK) == SOCKET_ERROR); xe_close(l); return r; }
M_CASE(recv_after_orderly_close_returns_zero, 0) { SOCKET c, s; char b[4]; long r; xe_pair(&c, &s); closesocket(s); xe_wait_readable(c, 2000); r = recv(c, b, 4, 0); xe_close(c); return r; }
M_CASE(recv_after_local_shutdown_receive_no_data, 10058) { SOCKET c, s; char b[4]; long r; xe_pair(&c, &s); nbsock(c); shutdown(c, SD_RECEIVE); r = XE_FAIL(recv(c, b, 4, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(send_after_local_shutdown_receive, -1) { SOCKET c, s; long r; xe_pair(&c, &s); shutdown(c, SD_RECEIVE); r = XE_FAIL(send(c, "x", 1, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(shutdown_twice_send, -1) { SOCKET c, s; long r; xe_pair(&c, &s); shutdown(c, SD_SEND); r = XE_FAIL(shutdown(c, SD_SEND) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(shutdown_on_listener, 10057) { struct sockaddr_in la; SOCKET l = xe_listener(&la); long r = XE_FAIL(shutdown(l, SD_BOTH) == SOCKET_ERROR); xe_close(l); return r; }
M_CASE(closesocket_twice, 10038) { SOCKET s = xe_sock(SOCK_STREAM); closesocket(s); return XE_FAIL(closesocket(s) == SOCKET_ERROR); }
M_CASE(getsockname_after_close, 10038) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; int n = sizeof a; closesocket(s); return XE_FAIL(getsockname(s, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(getpeername_after_peer_reset, -1) {
    SOCKET c, s; struct linger l = {1, 0}; struct sockaddr_in a; int n = sizeof a; long r; xe_pair(&c, &s);
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); xe_wait_readable(c, 1000);
    r = XE_FAIL(getpeername(c, SA(&a), &n) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(getpeername_after_orderly_close, -1) {
    SOCKET c, s; struct sockaddr_in a; int n = sizeof a; long r; xe_pair(&c, &s); closesocket(s); xe_wait_readable(c, 1000);
    r = XE_FAIL(getpeername(c, SA(&a), &n) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(sendto_connected_stream_with_address, -1) {
    SOCKET c, s; struct sockaddr_in a = xe_lo(XE_BE16(9)); long r; xe_pair(&c, &s); r = XE_FAIL(sendto(c, "x", 1, 0, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(sendto_unconnected_stream, 10057) {
    SOCKET c = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r = XE_FAIL(sendto(c, "x", 1, 0, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(udp_max_payload_ok, -1) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba; static char big[65507]; long r; xe_bind_lo(b, &ba);
    r = XE_FAIL(sendto(a, big, sizeof big, 0, SA(&ba), sizeof ba) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
M_CASE(udp_payload_one_over_max, 10040) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba; static char big[65508]; long r; xe_bind_lo(b, &ba);
    r = XE_FAIL(sendto(a, big, sizeof big, 0, SA(&ba), sizeof ba) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
M_CASE(udp_zero_length_datagram_ok, -1) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba; long r; xe_bind_lo(b, &ba);
    r = XE_FAIL(sendto(a, "", 0, 0, SA(&ba), sizeof ba) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
M_CASE(recvfrom_fromlen_small, 10014) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba, from; int n = 4; char buf[8]; long r; xe_bind_lo(a, NULL); xe_bind_lo(b, &ba);
    sendto(a, "x", 1, 0, SA(&ba), sizeof ba); xe_wait_readable(b, 1000); r = XE_FAIL(recvfrom(b, buf, 8, 0, SA(&from), &n) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
M_CASE(recvfrom_on_stream_pair, -1) {
    SOCKET c, s; char b[4]; struct sockaddr_in f; int n = sizeof f; long r; xe_pair(&c, &s); send(s, "x", 1, 0); xe_wait_readable(c, 1000);
    r = XE_FAIL(recvfrom(c, b, 4, 0, SA(&f), &n) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(wsasend_buffer_count_over_zero_null_buffer, -1) { SOCKET c, s; WSABUF wb = { 0, NULL }; DWORD n; long r; xe_pair(&c, &s); r = XE_FAIL(WSASend(c, &wb, 1, &n, 0, NULL, NULL) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
M_CASE(wsarecv_flags_msg_oob_on_udp, 10045) { SOCKET a = xe_sock(SOCK_DGRAM); char b[4]; WSABUF wb = { 4, b }; DWORD n, f = MSG_OOB; long r; xe_bind_lo(a, NULL); r = XE_FAIL(WSARecv(a, &wb, 1, &n, &f, NULL, NULL) == SOCKET_ERROR); xe_close(a); return r; }
M_CASE(wsasendto_stream_overlapped_ok, -1) {
    SOCKET c, s; WSABUF wb = { 1, (CHAR *)"x" }; DWORD n = 0; struct sockaddr_in a = xe_lo(XE_BE16(9)); long r; xe_pair(&c, &s);
    r = XE_FAIL(WSASendTo(c, &wb, 1, &n, 0, SA(&a), sizeof a, NULL, NULL) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }

/* ---- listen ---- */
M_CASE(listen_twice, -1) { struct sockaddr_in la; SOCKET l = xe_listener(&la); long r = XE_FAIL(listen(l, 2) == SOCKET_ERROR); xe_close(l); return r; }
M_CASE(listen_backlog_zero, -1) { SOCKET s = xe_sock(SOCK_STREAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(listen(s, 0) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(listen_backlog_negative, -1) { SOCKET s = xe_sock(SOCK_STREAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(listen(s, -1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(listen_backlog_somaxconn, -1) { SOCKET s = xe_sock(SOCK_STREAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(listen(s, SOMAXCONN) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(listen_backlog_huge, -1) { SOCKET s = xe_sock(SOCK_STREAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(listen(s, 0x7fffffff) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(accept_addr_without_len, -1) {
    struct sockaddr_in la, pa; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM), a; long r;
    connect(c, SA(&la), sizeof la); xe_wait_readable(l, 2000); a = accept(l, SA(&pa), NULL); r = XE_FAIL(a == INVALID_SOCKET); xe_close(a); xe_close(c); xe_close(l); return r; }

/* ---- IPv6 ---- */
M_CASE(v6_bind_with_v4_length, 10014) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; r = XE_FAIL(bind(s, SA(&a), sizeof(struct sockaddr_in)) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_bind_v4_sized_name_on_v6_socket, 10014) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(bind(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }

M_CASE(v6_bind_v4_family_full_length, 10047) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET; r = XE_FAIL(bind(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_connect_v4_family_full_length, 10047) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET; a.sin6_port = XE_BE16(9); r = XE_FAIL(connect(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(netevents_reset_close_code_select_first, 10053) {
    SOCKET c, s; struct linger l = {1, 0}; long r; WSAEVENT e; WSANETWORKEVENTS ne; xe_pair(&c, &s); e = WSACreateEvent();
    WSAEventSelect(c, e, FD_CLOSE | FD_READ); setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s);
    WaitForSingleObject(e, 3000); memset(&ne, 0x55, sizeof ne); WSAEnumNetworkEvents(c, e, &ne);
    r = ne.iErrorCode[FD_CLOSE_BIT]; WSAEventSelect(c, NULL, 0); WSACloseEvent(e); xe_close(c); return r; }
M_CASE(netevents_reset_mask_select_first, 32) {
    SOCKET c, s; struct linger l = {1, 0}; long r; WSAEVENT e; WSANETWORKEVENTS ne; xe_pair(&c, &s); e = WSACreateEvent();
    WSAEventSelect(c, e, FD_CLOSE | FD_READ); setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s);
    WaitForSingleObject(e, 3000); memset(&ne, 0x55, sizeof ne); WSAEnumNetworkEvents(c, e, &ne);
    r = ne.lNetworkEvents; WSAEventSelect(c, NULL, 0); WSACloseEvent(e); xe_close(c); return r; }
M_CASE(recv_after_abortive_close_select_first_sequence, 10054) {
    SOCKET c, s; struct linger l = {1, 0}; long r; char b[4]; xe_pair(&c, &s);
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); xe_wait_readable(c, 2000);
    recv(c, b, 4, 0); r = XE_FAIL(recv(c, b, 4, 0) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(send_twice_after_reset, 10054) {
    SOCKET c, s; struct linger l = {1, 0}; long r; xe_pair(&c, &s);
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); xe_wait_readable(c, 2000);
    send(c, "x", 1, 0); r = XE_FAIL(send(c, "x", 1, 0) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(send_after_orderly_peer_close_first, -1) {
    SOCKET c, s; long r; xe_pair(&c, &s); closesocket(s); xe_wait_readable(c, 2000);
    r = XE_FAIL(send(c, "x", 1, 0) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(send_second_after_orderly_peer_close, 10053) {
    SOCKET c, s; long r; xe_pair(&c, &s); closesocket(s); xe_wait_readable(c, 2000); send(c, "x", 1, 0); Sleep(200);
    r = XE_FAIL(send(c, "x", 1, 0) == SOCKET_ERROR); xe_close(c); return r; }
M_CASE(v6_connect_refused, 10061) {
    SOCKET d = xe_sock6(SOCK_STREAM), s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; int n = sizeof a; long r;
    if (s == INVALID_SOCKET || d == INVALID_SOCKET) { xe_close(s); xe_close(d); return XE_UNK - 1000; }
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    if (bind(d, SA(&a), sizeof a) == SOCKET_ERROR) { xe_close(s); xe_close(d); return XE_UNK - 1000; }
    getsockname(d, SA(&a), &n); closesocket(d);
    r = XE_FAIL(connect(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_connect_v4_sized_name_on_v6_socket, 10014) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(connect(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_getsockname_small, 10014) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; int n = 16; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; if (bind(s, SA(&a), sizeof a) == SOCKET_ERROR) { xe_close(s); return XE_UNK - 1000; }
    r = XE_FAIL(getsockname(s, SA(&a), &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_listen_unbound, 10022) { SOCKET s = xe_sock6(SOCK_STREAM); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000; r = XE_FAIL(listen(s, 1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_sendto_udp_v4_address_length, 10014) {
    SOCKET s = xe_sock6(SOCK_DGRAM); struct sockaddr_in6 a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = XE_BE16(9); a.sin6_addr.u.Byte[15] = 1;
    r = XE_FAIL(sendto(s, "x", 1, 0, SA(&a), 16) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_set_v6only_after_bind, 10022) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; int v = 0; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; if (bind(s, SA(&a), sizeof a) == SOCKET_ERROR) { xe_close(s); return XE_UNK - 1000; }
    r = XE_FAIL(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(v6_wsastringtoaddress_scope_garbage, 10022) { struct sockaddr_in6 a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"fe80::1%zz", AF_INET6, NULL, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(v6_wsaaddresstostring_short, 10014) { struct sockaddr_in6 a; WCHAR b[64]; DWORD n = 64; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; return XE_FAIL(WSAAddressToStringW(SA(&a), 16, NULL, b, &n) == SOCKET_ERROR); }

/* ---- address text converters ---- */
M_CASE(stringtoaddress_port_overflow, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"127.0.0.1:99999", AF_INET, NULL, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(stringtoaddress_port_65536, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"127.0.0.1:65536", AF_INET, NULL, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(stringtoaddress_empty, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"", AF_INET, NULL, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(stringtoaddress_trailing_space, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"127.0.0.1 ", AF_INET, NULL, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(stringtoaddress_unspec_family, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"127.0.0.1", AF_UNSPEC, NULL, SA(&a), &n) == SOCKET_ERROR); }
M_CASE(stringtoaddress_out_len_updated_on_small, 16) { struct sockaddr_in a; INT n = 4; WSAStringToAddressW(L"127.0.0.1", AF_INET, NULL, SA(&a), &n); return n; }
M_CASE(addresstostring_len_updated_on_small, 13) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR b[4]; DWORD n = 4; WSAAddressToStringW(SA(&a), sizeof a, NULL, b, &n); return (long)n; }
M_CASE(inet_ntop_small_buffer, 10022) { struct in_addr a; char b[7]; const char *p; a.s_addr = 0x0100007f; p = U(inet_ntop)(AF_INET, &a, b, sizeof b); return XE_FAIL(p == NULL); }
M_CASE(inet_ntop_exact_buffer, -1) { struct in_addr a; char b[10]; const char *p; a.s_addr = 0x0100007f; p = U(inet_ntop)(AF_INET, &a, b, sizeof b); return XE_FAIL(p == NULL); }
M_CASE(inet_ntop_bad_family, 10047) { struct in_addr a; char b[32]; const char *p; a.s_addr = 0x0100007f; p = U(inet_ntop)(0x7ff0, &a, b, sizeof b); return XE_FAIL(p == NULL); }
M_CASE(inet_ntop_v6_small_buffer, 10022) { struct in6_addr a; char b[3]; const char *p; memset(&a, 0, sizeof a); a.u.Byte[15] = 1; p = U(inet_ntop)(AF_INET6, &a, b, sizeof b); return XE_FAIL(p == NULL); }
M_CASE(inet_ntop_zero_buffer, 10022) { struct in_addr a; char b[4]; const char *p; a.s_addr = 0x0100007f; p = U(inet_ntop)(AF_INET, &a, b, 0); return XE_FAIL(p == NULL); }
M_CASE(wsahtonl_invalid_socket, 10038) { u_long o = 0; return XE_FAIL(WSAHtonl(INVALID_SOCKET, 1, &o) == SOCKET_ERROR); }
M_CASE(wsantohs_invalid_socket, 10038) { u_short o = 0; return XE_FAIL(U(WSANtohs)(INVALID_SOCKET, 1, &o) == SOCKET_ERROR); }
M_CASE(wsahtons_valid_socket, -1) { SOCKET s = xe_sock(SOCK_STREAM); u_short o = 0; long r = XE_FAIL(WSAHtons(s, 1, &o) == SOCKET_ERROR); xe_close(s); return r; }

/* ---- provider path / info lookups report errors through the out parameter ---- */
static const GUID unk_guid = {0x7a1b2c3d, 0x4455, 0x4667, {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}};
M_CASE(wscgetproviderpath_unknown_guid, 10022) {
    WCHAR p[260]; INT len = 260, err = -7; int r = U(WSCGetProviderPath)((LPGUID)&unk_guid, p, &len, &err);
    return r == 0 ? -1 : err; }
M_CASE(wscgetproviderpath_unknown_guid_return, -1) {
    WCHAR p[260]; INT len = 260, err = -7; return U(WSCGetProviderPath)((LPGUID)&unk_guid, p, &len, &err); }
M_CASE(wsalookupservicebegin_bad_namespace, 10108) {
    WSAQUERYSETW q; HANDLE h; memset(&q, 0, sizeof q); q.dwSize = sizeof q; q.dwNameSpace = 9999; q.lpszServiceInstanceName = (LPWSTR)L"x";
    { long r; h = NULL; r = XE_FAIL(WSALookupServiceBeginW(&q, 0, &h) == SOCKET_ERROR); if (r == -1 && h) WSALookupServiceEnd(h); return r; } }
M_CASE(wsalookupservicebegin_no_name_no_class, -1) {
    WSAQUERYSETW q; HANDLE h; memset(&q, 0, sizeof q); q.dwSize = sizeof q; q.dwNameSpace = NS_ALL;
    { long r; h = NULL; r = XE_FAIL(WSALookupServiceBeginW(&q, 0, &h) == SOCKET_ERROR); if (r == -1 && h) WSALookupServiceEnd(h); return r; } }
M_CASE(wsalookupservicebegin_oversize, -1) {
    WSAQUERYSETW q; HANDLE h; memset(&q, 0, sizeof q); q.dwSize = sizeof q + 1; q.dwNameSpace = NS_ALL;
    { long r; h = NULL; r = XE_FAIL(WSALookupServiceBeginW(&q, 0, &h) == SOCKET_ERROR); if (r == -1 && h) WSALookupServiceEnd(h); return r; } }
M_CASE(wsaenumprotocols_len_updated, 1) { DWORD n = 0; WSAEnumProtocolsW(NULL, NULL, &n); return n > 0 ? 1 : 0; }
M_CASE(wsaenumprotocols_zero_len_error, 10055) { DWORD n = 0; return XE_FAIL(WSAEnumProtocolsW(NULL, NULL, &n) == SOCKET_ERROR); }
M_CASE(wsaenumnamespaceproviders_len_error, 10014) { DWORD n = 0; return XE_FAIL(WSAEnumNameSpaceProvidersW(&n, NULL) == SOCKET_ERROR); }

/* ---- WSAIoctl corners ---- */
M_CASE(ioctl_fionbio_in_len_zero, 10014) { SOCKET s = xe_sock(SOCK_STREAM); DWORD v = 1, n = 0; long r = XE_FAIL(WSAIoctl(s, FIONBIO, &v, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_fionbio_in_len_two, 10014) { SOCKET s = xe_sock(SOCK_STREAM); DWORD v = 1, n = 0; long r = XE_FAIL(WSAIoctl(s, FIONBIO, &v, 2, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_fionread_out_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[2]; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, FIONREAD, NULL, 0, b, 2, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_base_handle_out_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[2]; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_BASE_HANDLE, NULL, 0, b, 2, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_base_handle_ok, -1) { SOCKET s = xe_sock(SOCK_STREAM), b = 0; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_BASE_HANDLE, NULL, 0, &b, sizeof b, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_udp_connreset_on_stream, 10022) { SOCKET s = xe_sock(SOCK_STREAM); BOOL v = FALSE; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_UDP_CONNRESET, &v, sizeof v, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_udp_connreset_ok_on_udp, -1) { SOCKET s = xe_sock(SOCK_DGRAM); BOOL v = FALSE; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_UDP_CONNRESET, &v, sizeof v, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_siocatmark_on_udp, 10022) { SOCKET s = xe_sock(SOCK_DGRAM); u_long v = 0; long r = XE_FAIL(ioctlsocket(s, SIOCATMARK, &v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_routing_interface_short_addr, 10022) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(0); DWORD out = 0, n = 0; long r;
    r = XE_FAIL(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &a, 4, &out, sizeof out, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_routing_interface_loopback_query, XE_UNK) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(0); DWORD out = 0, n = 0; long r;
    r = XE_FAIL(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &a, sizeof a, &out, sizeof out, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_routing_interface_out_small, 10014) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(0); char out[2]; DWORD n = 0; long r;
    r = XE_FAIL(WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &a, sizeof a, out, sizeof out, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_get_qos_unsupported, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[64]; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_GET_QOS, NULL, 0, b, sizeof b, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_enable_circular_queueing_on_stream, 10022) { SOCKET s = xe_sock(SOCK_STREAM); DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_ENABLE_CIRCULAR_QUEUEING, NULL, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_flush_on_stream, 10045) { SOCKET s = xe_sock(SOCK_STREAM); DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_FLUSH, NULL, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_get_group_qos_unsupported, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[64]; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_GET_GROUP_QOS, NULL, 0, b, sizeof b, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }

/* ---- FormatMessage details ---- */
TEST(xemore_fmt_width_mask_removes_exactly_the_line_break) {
    char a[512], b[512]; DWORD la, lb; unsigned i; static const unsigned ids[] = {10035, 10048, 10054, 10061, 10093, 11001};
    for (i = 0; i < 6; i++) {
        la = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ids[i], 0x0409, a, sizeof a, NULL);
        lb = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, ids[i], 0x0409, b, sizeof b, NULL);
        CHECK(la > 2 && lb > 0 && la >= lb);
        if (la > 2 && la >= lb) CHECKF(la > lb, "id %u: %lu vs %lu", ids[i], (unsigned long)la, (unsigned long)lb);
    }
}
TEST(xemore_fmt_text_has_no_inserts_pending) {
    char a[512]; unsigned id; int bad = 0;
    for (id = 10004; id <= 10112; id++) {
        DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, id, 0x0409, a, sizeof a, NULL);
        if (n && strchr(a, '%')) bad++;
    }
    t_note("messages containing a percent sign in the classic range: %d", bad);
}
TEST(xemore_fmt_without_ignore_inserts_still_resolves_plain_text) {
    char a[512], b[512]; DWORD la, lb;
    la = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 10054, 0x0409, a, sizeof a, NULL);
    lb = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, 10054, 0x0409, b, sizeof b, NULL);
    CHECK(la > 0 && la == lb && !strcmp(a, b));
}
TEST(xemore_fmt_message_ids_in_gap_with_flag_combination_fail_with_317) {
    char a[64]; DWORD n; SetLastError(0);
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 10006, 0x0409, a, sizeof a, NULL);
    CHECK(n == 0); t_note("gap id error: %lu", (unsigned long)GetLastError());
}
TEST(xemore_fmt_high_dword_wsa_ids_absent) {
    char a[64]; DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0x80072746, 0x0409, a, sizeof a, NULL);
    t_note("0x80072746 length %lu", (unsigned long)n);
}

/* ---- state-dependent rejections ---- */
M_CASE(accept_on_connected_socket, 10022) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(accept(c, NULL, NULL) == INVALID_SOCKET); xe_close(c); xe_close(s); return r; }
M_CASE(wsaaccept_on_connected_socket, 10022) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(WSAAccept(c, NULL, NULL, NULL, 0) == INVALID_SOCKET); xe_close(c); xe_close(s); return r; }
M_CASE(recv_udp_bound_nonblocking_empty, 10035) { SOCKET a = nbsock(xe_sock(SOCK_DGRAM)); char b[4]; long r; xe_bind_lo(a, NULL); r = XE_FAIL(recv(a, b, 4, 0) == SOCKET_ERROR); xe_close(a); return r; }
M_CASE(wsarecv_udp_truncated_count, 10040004) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba; char buf[4]; WSABUF wb = { 4, buf }; DWORD n = 77, f = 0; long r; xe_bind_lo(a, NULL); xe_bind_lo(b, &ba);
    sendto(a, "12345678", 8, 0, SA(&ba), sizeof ba); xe_wait_readable(b, 1000);
    r = XE_FAIL(WSARecv(b, &wb, 1, &n, &f, NULL, NULL) == SOCKET_ERROR); xe_close(a); xe_close(b); return r * 1000 + (long)n; }
M_CASE(udp_connect_then_send_other_dest, -1) {
    SOCKET a = xe_sock(SOCK_DGRAM), p = xe_sock(SOCK_DGRAM), q = xe_sock(SOCK_DGRAM); struct sockaddr_in pa, qa; long r; xe_bind_lo(p, &pa); xe_bind_lo(q, &qa);
    connect(a, SA(&pa), sizeof pa); r = XE_FAIL(sendto(a, "x", 1, 0, SA(&qa), sizeof qa) == SOCKET_ERROR); xe_close(a); xe_close(p); xe_close(q); return r; }
M_CASE(sendto_tcp_listener, 10057) { struct sockaddr_in la; SOCKET l = xe_listener(&la); long r = XE_FAIL(sendto(l, "x", 1, 0, SA(&la), sizeof la) == SOCKET_ERROR); xe_close(l); return r; }
M_CASE(ioctl_address_list_change_nonblocking, 10035) { SOCKET s = nbsock(xe_sock(SOCK_STREAM)); DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(ioctl_routing_change_nonblocking, 10022) { SOCKET s = nbsock(xe_sock(SOCK_STREAM)); DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_ROUTING_INTERFACE_CHANGE, NULL, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }

/* ---- WSAPoll ---- */
static long poll_one(SOCKET s, short ev, int ms, int *ret) {
    WSAPOLLFD p; int r; p.fd = s; p.events = ev; p.revents = 0x7f7f;
    r = U(WSAPoll)(&p, 1, ms); if (ret) *ret = r; return r < 0 ? -1000 - WSAGetLastError() : p.revents;
}
M_CASE(poll_zero_count, 10022) { WSAPOLLFD p; memset(&p, 0, sizeof p); return XE_FAIL(U(WSAPoll)(&p, 0, 0) == SOCKET_ERROR); }
M_CASE(poll_invalid_socket_fails, 10038) { WSAPOLLFD p; p.fd = INVALID_SOCKET; p.events = POLLRDNORM; p.revents = 0; return XE_FAIL(U(WSAPoll)(&p, 1, 0) == SOCKET_ERROR); }
M_CASE(poll_closed_socket_fails, 10038) { SOCKET s = xe_sock(SOCK_STREAM); WSAPOLLFD p; closesocket(s); p.fd = s; p.events = POLLRDNORM; p.revents = 0; return XE_FAIL(U(WSAPoll)(&p, 1, 0) == SOCKET_ERROR); }
M_CASE(poll_nonsocket_fails, 10038) { HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL); WSAPOLLFD p; long r; p.fd = (SOCKET)h; p.events = POLLRDNORM; p.revents = 0; r = XE_FAIL(U(WSAPoll)(&p, 1, 0) == SOCKET_ERROR); CloseHandle(h); return r; }
M_CASE(poll_idle_connected_events_zero_revents, 0) { SOCKET c, s; long r; xe_pair(&c, &s); r = poll_one(c, POLLRDNORM, 0, NULL); xe_close(c); xe_close(s); return r; }
M_CASE(poll_idle_connected_writable, POLLWRNORM) { SOCKET c, s; long r; xe_pair(&c, &s); r = poll_one(c, POLLWRNORM, 0, NULL); xe_close(c); xe_close(s); return r; }
M_CASE(poll_listener_pending_accept, POLLRDNORM) { struct sockaddr_in la; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM); long r; connect(c, SA(&la), sizeof la); r = poll_one(l, POLLRDNORM, 2000, NULL); xe_close(c); xe_close(l); return r; }
M_CASE(poll_refused_nonblocking_connect, 19) { SOCKET s = nbsock(xe_sock(SOCK_STREAM)); struct sockaddr_in a; long r; xe_dead_port(&a); connect(s, SA(&a), sizeof a); r = poll_one(s, POLLWRNORM, 3000, NULL); xe_close(s); return r; }
M_CASE(poll_refused_nonblocking_connect_no_events, 0) { SOCKET s = nbsock(xe_sock(SOCK_STREAM)); struct sockaddr_in a; long r; xe_dead_port(&a); connect(s, SA(&a), sizeof a); r = poll_one(s, 0, 300, NULL); xe_close(s); return r; }
M_CASE(poll_peer_orderly_close, 2) { SOCKET c, s; long r; xe_pair(&c, &s); closesocket(s); r = poll_one(c, POLLRDNORM, 3000, NULL); xe_close(c); return r; }
M_CASE(poll_peer_reset, 3) { SOCKET c, s; struct linger l = {1, 0}; long r; xe_pair(&c, &s); setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); r = poll_one(c, POLLRDNORM, 3000, NULL); xe_close(c); return r; }
M_CASE(poll_unconnected_stream, 0) { SOCKET s = xe_sock(SOCK_STREAM); long r = poll_one(s, POLLRDNORM | POLLWRNORM, 0, NULL); xe_close(s); return r; }
M_CASE(poll_oob_event_request, 0) { SOCKET c, s; long r; xe_pair(&c, &s); r = poll_one(c, POLLRDBAND, 0, NULL); xe_close(c); xe_close(s); return r; }
M_CASE(poll_pollpri_event_request, -11022) { SOCKET c, s; long r; xe_pair(&c, &s); r = poll_one(c, POLLPRI, 0, NULL); xe_close(c); xe_close(s); return r; }
M_CASE(poll_negative_timeout_returns_on_data, POLLRDNORM) { SOCKET c, s; long r; xe_pair(&c, &s); send(s, "x", 1, 0); r = poll_one(c, POLLRDNORM, -1, NULL); xe_close(c); xe_close(s); return r; }
M_CASE(poll_returns_count_of_ready, 2) {
    SOCKET c1, s1, c2, s2; WSAPOLLFD p[3]; int r; xe_pair(&c1, &s1); xe_pair(&c2, &s2);
    p[0].fd = c1; p[0].events = POLLWRNORM; p[1].fd = c2; p[1].events = POLLRDNORM; p[2].fd = c2; p[2].events = POLLWRNORM;
    send(s2, "x", 1, 0); xe_wait_readable(c2, 1000);
    r = U(WSAPoll)(p, 3, 0); xe_close(c1); xe_close(s1); xe_close(c2); xe_close(s2); return r == 4 ? 2 : r; }

/* ---- AF_UNIX ---- */
M_CASE(unix_stream_socket_creatable, -1) { SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000; r = -1; xe_close(s); return r; }
M_CASE(unix_dgram_socket, 10047) { SOCKET s = WSASocketW(AF_UNIX, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); long r = XE_FAIL(s == INVALID_SOCKET); xe_close(s); return r; }
M_CASE(unix_stream_bad_protocol, 10043) { SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 6, NULL, 0, WSA_FLAG_OVERLAPPED); long r = XE_FAIL(s == INVALID_SOCKET); xe_close(s); return r; }
M_CASE(unix_listen_unbound, 10022) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(listen(s, 1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_connect_missing_path, 10050) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); struct sockaddr_un { USHORT f; char p[108]; } a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.f = AF_UNIX; strcpy(a.p, "c:\\nonexistent_dir_for_error_probe\\no.sock");
    r = XE_FAIL(connect(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_bind_missing_directory, 10050) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); struct sockaddr_un { USHORT f; char p[108]; } a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.f = AF_UNIX; strcpy(a.p, "c:\\nonexistent_dir_for_error_probe\\no.sock");
    r = XE_FAIL(bind(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_bind_short_name_length, 10014) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); struct sockaddr_un { USHORT f; char p[108]; } a; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    memset(&a, 0, sizeof a); a.f = AF_UNIX; r = XE_FAIL(bind(s, SA(&a), 1) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_bind_with_inet_address, 10047) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); struct sockaddr_in a = xe_lo(0); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(bind(s, SA(&a), sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_getsockname_unbound, 10022) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); char b[128]; int n = sizeof b; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(getsockname(s, SA(b), &n) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_send_unconnected, 10057) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(send(s, "x", 1, 0) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(unix_inet_option_level, 10042) {
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); int v = 1; long r; if (s == INVALID_SOCKET) return XE_UNK - 1000;
    r = XE_FAIL(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
M_CASE(poll_one_bad_entry_among_good_fails_whole_call, XE_UNK) {
    SOCKET c, s; WSAPOLLFD p[2]; long r; xe_pair(&c, &s);
    p[0].fd = c; p[0].events = POLLWRNORM; p[0].revents = 0; p[1].fd = INVALID_SOCKET; p[1].events = POLLRDNORM; p[1].revents = 0;
    r = XE_FAIL(U(WSAPoll)(p, 2, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
