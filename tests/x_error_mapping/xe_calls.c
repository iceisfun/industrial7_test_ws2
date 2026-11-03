/* x_error_mapping / Winsock error numbers left by failing calls.
 *
 * One scenario per row: a call that must fail for one common reason, and the Winsock error number WSAGetLastError
 * reports. The failing call also leaves the same number in the thread's last-error slot (GetLastError), which every
 * row checks through XE_FAIL. Only deterministic loopback or argument-validation failures are used. */
#include "xe.h"

#define W_CASE(n, WANT) \
    static long c_##n(void); \
    TEST(xecall_##n) { long r; XE_UP(); xe_gle_seen = -5; xe_wsa_seen = -6; WSASetLastError(XE_BAD); r = c_##n(); \
        if (r == XE_UNK - 1000) { t_skip("scenario not available"); return; } \
        if ((WANT) == XE_UNK) { t_note("ROW call %s %ld gle=%d", #n, r, xe_gle_seen); return; } \
        t_check(r == (WANT), "x_error_mapping", 0, #n, "wsa got %ld want %ld", r, (long)(WANT)); \
        if (r != -1) t_check(xe_gle_seen == xe_wsa_seen, "x_error_mapping", 0, #n, "GetLastError %d vs WSAGetLastError %d", xe_gle_seen, xe_wsa_seen); } \
    static long c_##n(void)

/* ---- socket creation ---- */
W_CASE(socket_bad_family, 10047) { return XE_FAIL(socket(0x7ff0, SOCK_STREAM, 0) == INVALID_SOCKET); }
W_CASE(socket_bad_type, 10044) { return XE_FAIL(socket(AF_INET, 99, 0) == INVALID_SOCKET); }
W_CASE(socket_bad_protocol, 10043) { return XE_FAIL(socket(AF_INET, SOCK_STREAM, 250) == INVALID_SOCKET); }
W_CASE(socket_stream_with_udp, 10043) { return XE_FAIL(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == INVALID_SOCKET); }
W_CASE(socket_dgram_with_tcp, 10043) { return XE_FAIL(socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP) == INVALID_SOCKET); }
W_CASE(socket_family_unspec_nothing, 10022) { return XE_FAIL(socket(AF_UNSPEC, 0, 0) == INVALID_SOCKET); }
W_CASE(socket_family_unspec_type_only, 10022) { SOCKET s = socket(AF_UNSPEC, SOCK_STREAM, 0); long r = XE_FAIL(s == INVALID_SOCKET); xe_close(s); return r; }
W_CASE(socket_seqpacket_inet, 10044) { return XE_FAIL(socket(AF_INET, SOCK_SEQPACKET, 0) == INVALID_SOCKET); }
W_CASE(socket_rdm_inet, 10044) { return XE_FAIL(socket(AF_INET, SOCK_RDM, 0) == INVALID_SOCKET); }
W_CASE(socket_netbios_family_dgram_proto_zero, 10047) { return XE_FAIL(socket(AF_NETBIOS, SOCK_DGRAM, 0) == INVALID_SOCKET); }
W_CASE(wsasocket_bad_flags, 10041) { return XE_FAIL(WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, 0x00800000) == INVALID_SOCKET); }
W_CASE(wsasocket_bad_group, 10022) { return XE_FAIL(WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0x7fffffff, 0) == INVALID_SOCKET); }

/* ---- invalid socket handles ---- */
#define INV_ROW(n, call) W_CASE(n##_invalid_socket, XE_UNK) { char b[16]; struct sockaddr_in a = xe_lo(0); int l = sizeof a; (void)b; (void)a; (void)l; return call; }
INV_ROW(bind, XE_FAIL(bind(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR))
INV_ROW(listen, XE_FAIL(listen(INVALID_SOCKET, 1) == SOCKET_ERROR))
INV_ROW(connect, XE_FAIL(connect(INVALID_SOCKET, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR))
INV_ROW(accept, XE_FAIL(accept(INVALID_SOCKET, NULL, NULL) == INVALID_SOCKET))
INV_ROW(send, XE_FAIL(send(INVALID_SOCKET, "x", 1, 0) == SOCKET_ERROR))
INV_ROW(recv, XE_FAIL(recv(INVALID_SOCKET, b, 4, 0) == SOCKET_ERROR))
INV_ROW(sendto, XE_FAIL(sendto(INVALID_SOCKET, "x", 1, 0, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR))
INV_ROW(recvfrom, XE_FAIL(recvfrom(INVALID_SOCKET, b, 4, 0, (struct sockaddr *)&a, &l) == SOCKET_ERROR))
INV_ROW(shutdown, XE_FAIL(shutdown(INVALID_SOCKET, SD_BOTH) == SOCKET_ERROR))
INV_ROW(closesocket, XE_FAIL(closesocket(INVALID_SOCKET) == SOCKET_ERROR))
INV_ROW(getsockname, XE_FAIL(getsockname(INVALID_SOCKET, (struct sockaddr *)&a, &l) == SOCKET_ERROR))
INV_ROW(getpeername, XE_FAIL(getpeername(INVALID_SOCKET, (struct sockaddr *)&a, &l) == SOCKET_ERROR))
INV_ROW(getsockopt, XE_FAIL(getsockopt(INVALID_SOCKET, SOL_SOCKET, SO_TYPE, b, &l) == SOCKET_ERROR))
INV_ROW(setsockopt, XE_FAIL(setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_RCVBUF, b, 4) == SOCKET_ERROR))
INV_ROW(ioctlsocket, XE_FAIL(ioctlsocket(INVALID_SOCKET, FIONBIO, (u_long *)b) == SOCKET_ERROR))
INV_ROW(wsaioctl, XE_FAIL(WSAIoctl(INVALID_SOCKET, SIO_GET_EXTENSION_FUNCTION_POINTER, b, 4, b, 4, (DWORD *)&l, NULL, NULL) == SOCKET_ERROR))
INV_ROW(wsaeventselect, XE_FAIL(WSAEventSelect(INVALID_SOCKET, NULL, 0) == SOCKET_ERROR))
INV_ROW(wsarecv, XE_FAIL(WSARecv(INVALID_SOCKET, &(WSABUF){4, b}, 1, (DWORD *)&l, &(DWORD){0}, NULL, NULL) == SOCKET_ERROR))
INV_ROW(wsasend, XE_FAIL(WSASend(INVALID_SOCKET, &(WSABUF){1, "x"}, 1, (DWORD *)&l, 0, NULL, NULL) == SOCKET_ERROR))
INV_ROW(wsaaccept, XE_FAIL(WSAAccept(INVALID_SOCKET, NULL, NULL, NULL, 0) == INVALID_SOCKET))
INV_ROW(wsagetoverlappedresult, XE_FAIL(WSAGetOverlappedResult(INVALID_SOCKET, &(OVERLAPPED){0}, (DWORD *)&l, FALSE, &(DWORD){0}) == FALSE))
INV_ROW(select_one, XE_FAIL(({ fd_set f; f.fd_count = 1; f.fd_array[0] = INVALID_SOCKET; select(0, &f, NULL, NULL, &(struct timeval){0, 0}); }) == SOCKET_ERROR))

/* ---- non-socket handle ---- */
#define NS_ROW(n, call) W_CASE(n##_nonsocket, XE_UNK) { HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL); SOCKET s = (SOCKET)h; char b[16]; struct sockaddr_in a = xe_lo(0); int l = sizeof a; long r; (void)b; (void)a; (void)l; r = call; CloseHandle(h); return r; }
NS_ROW(bind, XE_FAIL(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR))
NS_ROW(listen, XE_FAIL(listen(s, 1) == SOCKET_ERROR))
NS_ROW(send, XE_FAIL(send(s, "x", 1, 0) == SOCKET_ERROR))
NS_ROW(getsockopt, XE_FAIL(getsockopt(s, SOL_SOCKET, SO_TYPE, b, &l) == SOCKET_ERROR))
NS_ROW(closesocket, XE_FAIL(closesocket(s) == SOCKET_ERROR))
NS_ROW(ioctlsocket, XE_FAIL(ioctlsocket(s, FIONBIO, (u_long *)b) == SOCKET_ERROR))

/* ---- bind ---- */
W_CASE(bind_namelen_short, 10014) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r = XE_FAIL(bind(s, (struct sockaddr *)&a, 8) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_namelen_zero, 10014) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r = XE_FAIL(bind(s, (struct sockaddr *)&a, 0) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_family_mismatch, 10047) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in6 a; long r; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; r = XE_FAIL(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_family_unspec, 10047) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r; a.sin_family = AF_UNSPEC; r = XE_FAIL(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_family_bogus, 10047) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r; a.sin_family = 0x7ff0; r = XE_FAIL(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_twice, 10022) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r; bind(s, (struct sockaddr *)&a, sizeof a); r = XE_FAIL(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_in_use, 10048) { SOCKET a = xe_sock(SOCK_STREAM), b = xe_sock(SOCK_STREAM); struct sockaddr_in la; long r; xe_bind_lo(a, &la); r = XE_FAIL(bind(b, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
W_CASE(bind_in_use_udp, 10048) { SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in la; long r; xe_bind_lo(a, &la); r = XE_FAIL(bind(b, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
W_CASE(bind_nonlocal_address, 10049) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r; a.sin_addr.s_addr = 0x010200c0; r = XE_FAIL(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(bind_exclusive_vs_reuse, 10013) {
    SOCKET a = xe_sock(SOCK_STREAM), b = xe_sock(SOCK_STREAM); struct sockaddr_in la; BOOL on = 1; long r;
    setsockopt(a, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&on, sizeof on); xe_bind_lo(a, &la);
    setsockopt(b, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
    r = XE_FAIL(bind(b, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
W_CASE(bind_after_connect, 10022) { SOCKET c, s; struct sockaddr_in a = xe_lo(0); long r; xe_pair(&c, &s); r = XE_FAIL(bind(c, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(bind_after_listen, 10022) { struct sockaddr_in la; SOCKET l = xe_listener(&la); long r; struct sockaddr_in a = xe_lo(0); r = XE_FAIL(bind(l, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(l); return r; }

/* ---- listen / accept ---- */
W_CASE(listen_unbound, 10022) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(listen(s, 4) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(listen_udp, 10045) { SOCKET s = xe_sock(SOCK_DGRAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(listen(s, 4) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(listen_connected, 10056) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(listen(c, 4) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(accept_not_listening, 10022) { SOCKET s = xe_sock(SOCK_STREAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(accept(s, NULL, NULL) == INVALID_SOCKET); xe_close(s); return r; }
W_CASE(accept_unbound, 10022) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(accept(s, NULL, NULL) == INVALID_SOCKET); xe_close(s); return r; }
W_CASE(accept_udp, 10045) { SOCKET s = xe_sock(SOCK_DGRAM); long r; xe_bind_lo(s, NULL); r = XE_FAIL(accept(s, NULL, NULL) == INVALID_SOCKET); xe_close(s); return r; }
W_CASE(accept_nonblocking_empty, 10035) { struct sockaddr_in la; SOCKET l = xe_listener(&la); u_long nb = 1; long r; ioctlsocket(l, FIONBIO, &nb); r = XE_FAIL(accept(l, NULL, NULL) == INVALID_SOCKET); xe_close(l); return r; }
W_CASE(accept_addrlen_small, 10014) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM), a; struct sockaddr_in pa; int n = 4; long r;
    connect(c, (struct sockaddr *)&la, sizeof la); xe_wait_readable(l, 1000);
    a = accept(l, (struct sockaddr *)&pa, &n); r = XE_FAIL(a == INVALID_SOCKET); xe_close(a); xe_close(c); xe_close(l); return r; }

/* ---- connect ---- */
W_CASE(connect_refused, 10061) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; long r; xe_dead_port(&a); r = XE_FAIL(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(connect_namelen_short, 10014) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r = XE_FAIL(connect(s, (struct sockaddr *)&a, 8) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(connect_family_mismatch, 10047) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in6 a; long r; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = XE_BE16(9); a.sin6_addr.u.Byte[15] = 1; r = XE_FAIL(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(connect_port_zero, 10049) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r = XE_FAIL(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(connect_any_address, 10049) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r; a.sin_addr.s_addr = 0; r = XE_FAIL(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(connect_twice_connected, 10056) { SOCKET c, s; struct sockaddr_in a; int n = sizeof a; long r; xe_pair(&c, &s); getpeername(c, (struct sockaddr *)&a, &n); r = XE_FAIL(connect(c, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(connect_on_listener, 10022) { struct sockaddr_in la; SOCKET l = xe_listener(&la); long r = XE_FAIL(connect(l, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR); xe_close(l); return r; }
W_CASE(connect_nonblocking_inprogress, 10035) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), c = xe_sock(SOCK_STREAM); u_long nb = 1; long r; ioctlsocket(c, FIONBIO, &nb);
    r = XE_FAIL(connect(c, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR); xe_wait_readable(l, 1000); xe_close(c); xe_close(l); return r; }
W_CASE(connect_udp_port_zero_succeeds, -1) { SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(0); long r = XE_FAIL(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaconnect_namelen_short, 10014) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r = XE_FAIL(WSAConnect(s, (struct sockaddr *)&a, 8, NULL, NULL, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }

/* ---- send / receive ---- */
W_CASE(send_unconnected, 10057) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(send(s, "x", 1, 0) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(recv_unconnected, 10057) { SOCKET s = xe_sock(SOCK_STREAM); char b[4]; long r = XE_FAIL(recv(s, b, 4, 0) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(send_on_listener, 10057) { struct sockaddr_in la; SOCKET l = xe_listener(&la); long r = XE_FAIL(send(l, "x", 1, 0) == SOCKET_ERROR); xe_close(l); return r; }
W_CASE(recv_on_listener, 10057) { struct sockaddr_in la; SOCKET l = xe_listener(&la); char b[4]; long r = XE_FAIL(recv(l, b, 4, 0) == SOCKET_ERROR); xe_close(l); return r; }
W_CASE(send_after_shutdown_send, 10058) { SOCKET c, s; long r; xe_pair(&c, &s); shutdown(c, SD_SEND); r = XE_FAIL(send(c, "x", 1, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(recv_after_shutdown_recv_with_data, 10053) { SOCKET c, s; char b[4]; long r; xe_pair(&c, &s); shutdown(c, SD_RECEIVE); send(s, "x", 1, 0); xe_wait_readable(c, 500); r = XE_FAIL(recv(c, b, 4, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(recv_after_reset, 10054) { SOCKET c, s; char b[4]; struct linger l = {1, 0}; long r; xe_pair(&c, &s); setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); xe_wait_readable(c, 1000); r = XE_FAIL(recv(c, b, 4, 0) == SOCKET_ERROR); xe_close(c); return r; }
W_CASE(send_after_reset, 10054) { SOCKET c, s; struct linger l = {1, 0}; long r; xe_pair(&c, &s); setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); xe_wait_readable(c, 1000); r = XE_FAIL(send(c, "x", 1, 0) == SOCKET_ERROR); xe_close(c); return r; }
W_CASE(recv_nonblocking_empty, 10035) { SOCKET c, s; char b[4]; u_long nb = 1; long r; xe_pair(&c, &s); ioctlsocket(c, FIONBIO, &nb); r = XE_FAIL(recv(c, b, 4, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(recv_timeout_expires, 10060) { SOCKET c, s; char b[4]; DWORD t = 100; long r; xe_pair(&c, &s); setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t); r = XE_FAIL(recv(c, b, 4, 0) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(recv_oob_on_udp, 10045) { SOCKET s = xe_sock(SOCK_DGRAM); char b[4]; long r; xe_bind_lo(s, NULL); r = XE_FAIL(recv(s, b, 4, MSG_OOB) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(send_oob_on_udp, 10045) { SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r = XE_FAIL(sendto(s, "x", 1, MSG_OOB, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(recv_oob_inline_enabled, 10022) { SOCKET c, s; char b[4]; BOOL on = 1; long r; xe_pair(&c, &s); setsockopt(c, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof on); r = XE_FAIL(recv(c, b, 4, MSG_OOB) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(recv_oob_none_pending, 10035) { SOCKET c, s; char b[4]; long r; u_long nb = 1; xe_pair(&c, &s); ioctlsocket(c, FIONBIO, &nb); r = XE_FAIL(recv(c, b, 4, MSG_OOB) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(sendto_too_large_udp, 10040) { static char big[70000]; SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in to = xe_lo(XE_BE16(9)); long r = XE_FAIL(sendto(a, big, sizeof big, 0, (struct sockaddr *)&to, sizeof to) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(sendto_port_zero_udp_succeeds, -1) { SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in to = xe_lo(0); long r = XE_FAIL(sendto(a, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(sendto_family_mismatch_udp, 10047) { SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in6 to; long r; memset(&to, 0, sizeof to); to.sin6_family = AF_INET6; to.sin6_port = XE_BE16(9); r = XE_FAIL(sendto(a, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(sendto_namelen_short_udp, 10014) { SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in to = xe_lo(XE_BE16(9)); long r = XE_FAIL(sendto(a, "x", 1, 0, (struct sockaddr *)&to, 8) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(send_udp_no_default_peer, 10057) { SOCKET a = xe_sock(SOCK_DGRAM); long r = XE_FAIL(send(a, "x", 1, 0) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(recvfrom_udp_unbound, 10022) { SOCKET a = xe_sock(SOCK_DGRAM); char b[4]; long r = XE_FAIL(recvfrom(a, b, 4, 0, NULL, NULL) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(recv_udp_truncated, 10040) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba; char buf[4]; long r;
    xe_bind_lo(a, NULL); xe_bind_lo(b, &ba); sendto(a, "12345678", 8, 0, (struct sockaddr *)&ba, sizeof ba); xe_wait_readable(b, 1000);
    r = XE_FAIL(recv(b, buf, 4, 0) == SOCKET_ERROR); xe_close(a); xe_close(b); return r; }
W_CASE(udp_port_unreachable_recvfrom, 10054) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in aa, dead; char b[4]; long r; xe_bind_lo(a, &aa); xe_dead_port(&dead);
    sendto(a, "x", 1, 0, (struct sockaddr *)&dead, sizeof dead); xe_wait_readable(a, 1000);
    r = XE_FAIL(recv(a, b, 4, 0) == SOCKET_ERROR); xe_close(a); return r; }
W_CASE(wsasend_zero_buffers, 10022) { SOCKET c, s; DWORD n; long r; xe_pair(&c, &s); r = XE_FAIL(WSASend(c, NULL, 0, &n, 0, NULL, NULL) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(wsarecv_zero_buffers, 10022) { SOCKET c, s; DWORD n, f = 0; long r; xe_pair(&c, &s); r = XE_FAIL(WSARecv(c, NULL, 0, &n, &f, NULL, NULL) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(wsarecv_nonblocking_empty, 10035) { SOCKET c, s; char b[4]; WSABUF wb = { 4, b }; DWORD n, f = 0; u_long nb = 1; long r; xe_pair(&c, &s); ioctlsocket(c, FIONBIO, &nb); r = XE_FAIL(WSARecv(c, &wb, 1, &n, &f, NULL, NULL) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(wsarecv_overlapped_pending, 997) {
    SOCKET c, s; char b[4]; WSABUF wb = { 4, b }; DWORD n, f = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    r = XE_FAIL(WSARecv(c, &wb, 1, &n, &f, &o, NULL) == SOCKET_ERROR);
    closesocket(c); WaitForSingleObject(o.hEvent, 2000); CloseHandle(o.hEvent); xe_close(s); return r; }
W_CASE(wsagetoverlappedresult_incomplete, 996) {
    SOCKET c, s; char b[4]; WSABUF wb = { 4, b }; DWORD n, f = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSARecv(c, &wb, 1, &n, &f, &o, NULL);
    r = XE_FAIL(WSAGetOverlappedResult(c, &o, &n, FALSE, &f) == FALSE);
    closesocket(c); WaitForSingleObject(o.hEvent, 2000); CloseHandle(o.hEvent); xe_close(s); return r; }

/* ---- shutdown / names / options ---- */
W_CASE(shutdown_unconnected, 10057) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(shutdown(s, SD_SEND) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(shutdown_bad_how, 10022) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(shutdown(c, 7) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(shutdown_negative_how, 10022) { SOCKET c, s; long r; xe_pair(&c, &s); r = XE_FAIL(shutdown(c, -1) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(shutdown_udp_unconnected_succeeds, -1) { SOCKET s = xe_sock(SOCK_DGRAM); long r = XE_FAIL(shutdown(s, SD_SEND) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getpeername_unconnected, 10057) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; int n = sizeof a; long r = XE_FAIL(getpeername(s, (struct sockaddr *)&a, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getpeername_udp_unconnected, 10057) { SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a; int n = sizeof a; long r = XE_FAIL(getpeername(s, (struct sockaddr *)&a, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getpeername_listener, 10057) { struct sockaddr_in la, a; SOCKET l = xe_listener(&la); int n = sizeof a; long r = XE_FAIL(getpeername(l, (struct sockaddr *)&a, &n) == SOCKET_ERROR); xe_close(l); return r; }
W_CASE(getpeername_buffer_small, 10014) { SOCKET c, s; struct sockaddr_in a; int n = 4; long r; xe_pair(&c, &s); r = XE_FAIL(getpeername(c, (struct sockaddr *)&a, &n) == SOCKET_ERROR); xe_close(c); xe_close(s); return r; }
W_CASE(getsockname_buffer_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; int n = 4; long r; xe_bind_lo(s, NULL); r = XE_FAIL(getsockname(s, (struct sockaddr *)&a, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getsockname_unbound, 10022) { SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a; int n = sizeof a; long r = XE_FAIL(getsockname(s, (struct sockaddr *)&a, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getsockopt_unknown_option, 10042) { SOCKET s = xe_sock(SOCK_STREAM); int v; int n = sizeof v; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, 0x7ff0, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getsockopt_unknown_level, 10022) { SOCKET s = xe_sock(SOCK_STREAM); int v; int n = sizeof v; long r = XE_FAIL(getsockopt(s, 0x7ff0, SO_TYPE, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getsockopt_buffer_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); int v; int n = 2; long r = XE_FAIL(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(getsockopt_tcp_nodelay_on_udp, 10022) { SOCKET s = xe_sock(SOCK_DGRAM); int v; int n = sizeof v; long r = XE_FAIL(getsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&v, &n) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_readonly_type, 10042) { SOCKET s = xe_sock(SOCK_STREAM); int v = SOCK_DGRAM; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_readonly_acceptconn, 10042) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_len_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, 2) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_unknown_option, 10042) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, 0x7ff0, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_broadcast_on_stream, 10042) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_nodelay_on_udp, 10022) { SOCKET s = xe_sock(SOCK_DGRAM); int v = 1; long r = XE_FAIL(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_linger_len_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&v, 2) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_reuse_and_exclusive_conflict, 10022) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&v, sizeof v); r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(setsockopt_exclusive_after_bind_succeeds, -1) { SOCKET s = xe_sock(SOCK_STREAM); int v = 1; long r; xe_bind_lo(s, NULL); r = XE_FAIL(setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&v, sizeof v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(ioctlsocket_bad_command, 10045) { SOCKET s = xe_sock(SOCK_STREAM); u_long v = 0; long r = XE_FAIL(ioctlsocket(s, (long)0x8004ffee, &v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(ioctlsocket_siocatmark_unconnected_succeeds, -1) { SOCKET s = xe_sock(SOCK_STREAM); u_long v = 0; long r = XE_FAIL(ioctlsocket(s, SIOCATMARK, &v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(ioctlsocket_fionread_unconnected_succeeds, -1) { SOCKET s = xe_sock(SOCK_STREAM); u_long v = 0; long r = XE_FAIL(ioctlsocket(s, FIONREAD, &v) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaioctl_bad_code, 10045) { SOCKET s = xe_sock(SOCK_STREAM); DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, 0x98000fee, NULL, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaioctl_extfn_bad_guid, 10022) { SOCKET s = xe_sock(SOCK_STREAM); GUID g = {0x12345678, 1, 2, {3, 4, 5, 6, 7, 8, 9, 10}}; void *p = 0; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p, sizeof p, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaioctl_extfn_out_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); GUID g = WSAID_CONNECTEX; char p[2]; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, p, sizeof p, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaioctl_extfn_in_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); GUID g = WSAID_CONNECTEX; void *p; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, 8, &p, sizeof p, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaioctl_keepalive_vals_in_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); DWORD v[2] = {1, 1}; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_KEEPALIVE_VALS, v, 8, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaioctl_address_list_query_small, 10014) { SOCKET s = xe_sock(SOCK_STREAM); char b[4]; DWORD n = 0; long r = XE_FAIL(WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, b, sizeof b, &n, NULL, NULL) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(select_empty_sets, 10022) { return XE_FAIL(select(0, NULL, NULL, NULL, &(struct timeval){0, 0}) == SOCKET_ERROR); }
W_CASE(select_zero_count_fdset, 10022) { fd_set f; FD_ZERO(&f); return XE_FAIL(select(0, &f, NULL, NULL, &(struct timeval){0, 0}) == SOCKET_ERROR); }
W_CASE(select_nonsocket_in_set, 10038) { fd_set f; HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL); long r; f.fd_count = 1; f.fd_array[0] = (SOCKET)h; r = XE_FAIL(select(0, &f, NULL, NULL, &(struct timeval){0, 0}) == SOCKET_ERROR); CloseHandle(h); return r; }
W_CASE(select_closed_socket_in_set, 10038) { fd_set f; SOCKET s = xe_sock(SOCK_STREAM); long r; closesocket(s); f.fd_count = 1; f.fd_array[0] = s; r = XE_FAIL(select(0, &f, NULL, NULL, &(struct timeval){0, 0}) == SOCKET_ERROR); return r; }

/* ---- events ---- */
W_CASE(wsacloseevent_null, 6) { return XE_FAIL(WSACloseEvent(NULL) == FALSE); }
W_CASE(wsasetevent_null, 6) { return XE_FAIL(WSASetEvent(NULL) == FALSE); }
W_CASE(wsaresetevent_null, 6) { return XE_FAIL(WSAResetEvent(NULL) == FALSE); }
W_CASE(wsawait_zero_events, 87) { return XE_FAIL(WSAWaitForMultipleEvents(0, NULL, FALSE, 0, FALSE) == WSA_WAIT_FAILED); }
W_CASE(wsawait_too_many_events, 87) { WSAEVENT e[65]; unsigned i; long r; for (i = 0; i < 65; i++) e[i] = WSACreateEvent(); r = XE_FAIL(WSAWaitForMultipleEvents(65, e, FALSE, 0, FALSE) == WSA_WAIT_FAILED); for (i = 0; i < 65; i++) WSACloseEvent(e[i]); return r; }
W_CASE(wsawait_null_array_entry, 6) { WSAEVENT e = NULL; return XE_FAIL(WSAWaitForMultipleEvents(1, &e, FALSE, 0, FALSE) == WSA_WAIT_FAILED); }
W_CASE(wsaeventselect_bad_event_flags, 10022) { SOCKET s = xe_sock(SOCK_STREAM); WSAEVENT e = WSACreateEvent(); long r = XE_FAIL(WSAEventSelect(s, e, 0x7fff0000) == SOCKET_ERROR); WSACloseEvent(e); xe_close(s); return r; }
W_CASE(wsaenumnetworkevents_nonsocket, 10038) { HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL); WSANETWORKEVENTS ne; long r = XE_FAIL(WSAEnumNetworkEvents((SOCKET)h, NULL, &ne) == SOCKET_ERROR); CloseHandle(h); return r; }
W_CASE(wsaasyncselect_bad_window, 10022) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(WSAAsyncSelect(s, (HWND)(ULONG_PTR)0x7fff0, 0x500, FD_READ) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaasyncselect_null_window, 10022) { SOCKET s = xe_sock(SOCK_STREAM); long r = XE_FAIL(WSAAsyncSelect(s, NULL, 0x500, FD_READ) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsacancelasyncrequest_bogus, 10022) { return XE_FAIL(WSACancelAsyncRequest((HANDLE)(ULONG_PTR)0x7777) == SOCKET_ERROR); }

/* ---- blocking hook ---- */
W_CASE(wsacancelblockingcall_none, 10045) { return XE_FAIL(WSACancelBlockingCall() == SOCKET_ERROR); }
W_CASE(wsaunhookblockinghook_none, 10045) { return XE_FAIL(WSAUnhookBlockingHook() == SOCKET_ERROR); }

/* ---- address strings / byte order / duplicates ---- */
W_CASE(wsastringtoaddress_garbage, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"not an address", AF_INET, NULL, (struct sockaddr *)&a, &n) == SOCKET_ERROR); }
W_CASE(wsastringtoaddress_bad_family, 10022) { struct sockaddr_in a; INT n = sizeof a; return XE_FAIL(WSAStringToAddressW(L"127.0.0.1", 0x7ff0, NULL, (struct sockaddr *)&a, &n) == SOCKET_ERROR); }
W_CASE(wsastringtoaddress_out_small, 10014) { struct sockaddr_in a; INT n = 4; return XE_FAIL(WSAStringToAddressW(L"127.0.0.1", AF_INET, NULL, (struct sockaddr *)&a, &n) == SOCKET_ERROR); }
W_CASE(wsaaddresstostring_out_small, 10014) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR b[4]; DWORD n = 4; return XE_FAIL(WSAAddressToStringW((struct sockaddr *)&a, sizeof a, NULL, b, &n) == SOCKET_ERROR); }
W_CASE(wsaaddresstostring_short_addr, 10014) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR b[64]; DWORD n = 64; return XE_FAIL(WSAAddressToStringW((struct sockaddr *)&a, 8, NULL, b, &n) == SOCKET_ERROR); }
W_CASE(wsaaddresstostring_bad_family, 10022) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR b[64]; DWORD n = 64; a.sin_family = 0x7ff0; return XE_FAIL(WSAAddressToStringW((struct sockaddr *)&a, sizeof a, NULL, b, &n) == SOCKET_ERROR); }
W_CASE(wsaduplicatesocket_bad_process, 10022) { SOCKET s = xe_sock(SOCK_STREAM); WSAPROTOCOL_INFOW pi; long r = XE_FAIL(WSADuplicateSocketW(s, 0xfffffff0, &pi) == SOCKET_ERROR); xe_close(s); return r; }
W_CASE(wsaenumprotocols_small, 10055) { char b[16]; DWORD n = sizeof b; return XE_FAIL(WSAEnumProtocolsW(NULL, (LPWSAPROTOCOL_INFOW)b, &n) == SOCKET_ERROR); }
W_CASE(wsaenumnamespaceproviders_small, 10014) { char b[16]; DWORD n = sizeof b; return XE_FAIL(WSAEnumNameSpaceProvidersW(&n, (LPWSANAMESPACE_INFOW)b) == SOCKET_ERROR); }
W_CASE(wsalookupserviceend_null, 6) { return XE_FAIL(WSALookupServiceEnd(NULL) == SOCKET_ERROR); }
W_CASE(wsalookupservicenext_null, 6) { char b[64]; DWORD n = sizeof b; return XE_FAIL(WSALookupServiceNextW(NULL, 0, &n, (LPWSAQUERYSETW)b) == SOCKET_ERROR); }
W_CASE(wsalookupservicebegin_bad_size, 87) { WSAQUERYSETW q; HANDLE h; memset(&q, 0, sizeof q); q.dwSize = 8; return XE_FAIL(WSALookupServiceBeginW(&q, 0, &h) == SOCKET_ERROR); }
W_CASE(wsagetserviceclassinfo_unknown, 10022) {
    GUID pg = {0x1a2b3c4d, 0x1111, 0x2222, {1,2,3,4,5,6,7,8}}; char b[256]; DWORD n = sizeof b;
    return XE_FAIL(WSAGetServiceClassInfoW(NULL, &pg, &n, (LPWSASERVICECLASSINFOW)b) == SOCKET_ERROR); }
W_CASE(wsaremoveserviceclass_unknown, 10065) { GUID g = {0x1a2b3c4d, 0x2222, 0x3333, {1,2,3,4,5,6,7,8}}; return XE_FAIL(WSARemoveServiceClass(&g) == SOCKET_ERROR); }

/* ---- extension functions (ConnectEx / TransmitFile / DisconnectEx) failing before any I/O is queued ---- */
static void *extfn(SOCKET s, GUID g) { void *p = NULL; DWORD n = 0; WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p, sizeof p, &n, NULL, NULL); return p; }
W_CASE(connectex_unbound, 10022) {
    SOCKET s = xe_sock(SOCK_STREAM); LPFN_CONNECTEX ce = (LPFN_CONNECTEX)extfn(s, (GUID)WSAID_CONNECTEX); struct sockaddr_in a = xe_lo(XE_BE16(9)); OVERLAPPED o; long r;
    if (!ce) { xe_close(s); return XE_UNK - 1000; }
    memset(&o, 0, sizeof o); r = XE_FAIL(ce(s, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, &o) == FALSE); xe_close(s); return r; }
W_CASE(connectex_namelen_short, 10049) {
    SOCKET s = xe_sock(SOCK_STREAM); LPFN_CONNECTEX ce = (LPFN_CONNECTEX)extfn(s, (GUID)WSAID_CONNECTEX); struct sockaddr_in a = xe_lo(XE_BE16(9)); OVERLAPPED o; long r;
    if (!ce) { xe_close(s); return XE_UNK - 1000; }
    xe_bind_lo(s, NULL); memset(&o, 0, sizeof o); r = XE_FAIL(ce(s, (struct sockaddr *)&a, 4, NULL, 0, NULL, &o) == FALSE); xe_close(s); return r; }
W_CASE(connectex_no_overlapped, 87) {
    SOCKET s = xe_sock(SOCK_STREAM); LPFN_CONNECTEX ce = (LPFN_CONNECTEX)extfn(s, (GUID)WSAID_CONNECTEX); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r;
    if (!ce) { xe_close(s); return XE_UNK - 1000; }
    xe_bind_lo(s, NULL); r = XE_FAIL(ce(s, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, NULL) == FALSE); xe_close(s); return r; }
W_CASE(transmitfile_unconnected, 10057) {
    SOCKET s = xe_sock(SOCK_STREAM); LPFN_TRANSMITFILE tf = (LPFN_TRANSMITFILE)extfn(s, (GUID)WSAID_TRANSMITFILE); OVERLAPPED o; long r;
    if (!tf) { xe_close(s); return XE_UNK - 1000; }
    memset(&o, 0, sizeof o); r = XE_FAIL(tf(s, NULL, 0, 0, &o, NULL, 0) == FALSE); xe_close(s); return r; }
W_CASE(disconnectex_no_overlapped_unconnected, 10057) {
    SOCKET s = xe_sock(SOCK_STREAM); LPFN_DISCONNECTEX de = (LPFN_DISCONNECTEX)extfn(s, (GUID)WSAID_DISCONNECTEX); long r;
    if (!de) { xe_close(s); return XE_UNK - 1000; }
    xe_bind_lo(s, NULL); r = XE_FAIL(de(s, NULL, 0, 0) == FALSE); xe_close(s); return r; }
W_CASE(acceptex_on_connected_socket, 10022) {
    SOCKET c, s; LPFN_ACCEPTEX ae; OVERLAPPED o; char b[64]; DWORD n; long r; SOCKET a = xe_sock(SOCK_STREAM);
    xe_pair(&c, &s); ae = (LPFN_ACCEPTEX)extfn(c, (GUID)WSAID_ACCEPTEX);
    if (!ae) { xe_close(a); xe_close(c); xe_close(s); return XE_UNK - 1000; }
    memset(&o, 0, sizeof o); r = XE_FAIL(ae(c, a, b, 0, 32, 32, &n, &o) == FALSE); xe_close(a); xe_close(c); xe_close(s); return r; }
W_CASE(acceptex_small_address_space, 10014) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), a = xe_sock(SOCK_STREAM); LPFN_ACCEPTEX ae = (LPFN_ACCEPTEX)extfn(l, (GUID)WSAID_ACCEPTEX); OVERLAPPED o; char b[64]; DWORD n; long r;
    if (!ae) { xe_close(a); xe_close(l); return XE_UNK - 1000; }
    memset(&o, 0, sizeof o); r = XE_FAIL(ae(l, a, b, 0, 4, 4, &n, &o) == FALSE); xe_close(a); xe_close(l); return r; }
