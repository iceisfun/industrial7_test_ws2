/* x_error_mapping / NTSTATUS -> Winsock translation.
 *
 * Each scenario brings a socket into one state and performs the failing operation twice on equivalent fresh state:
 * once as a raw AFD request (the NTSTATUS the driver completes with) and once through the Winsock call that rides on
 * it (the error number the application sees). Both numbers are checked, and the Win32 error that ntdll derives from
 * the NTSTATUS is checked as a third column. Mode 0 returns the NTSTATUS, mode 1 returns the Winsock error (0 when
 * the Winsock call succeeded), mode 2 is not used. XE_NA means the scenario has no counterpart on that side. */
#include "xe.h"

#define XE_NA (-3)
typedef ULONG (NTAPI *RtlNtStatusToDosError_t)(LONG);
static ULONG dos_of(LONG st) {
    RtlNtStatusToDosError_t f = (RtlNtStatusToDosError_t)t_proc_in("ntdll.dll", "RtlNtStatusToDosError");
    return f ? f(st) : 0xffffffff;
}
static long werr(int failed) { return failed ? (long)WSAGetLastError() : 0; }
static long st(xe_r r) { return (long)r.status; }

typedef struct { const char *name; long (*fn)(int); long long nt; long long wsa; long long dos; } nt_row;

static struct sockaddr_in some_dead(void) { struct sockaddr_in a; xe_dead_port(&a); return a; }

static long s_connect_refused(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = some_dead(); long r;
    if (m == 0) r = st(xe_afd_connect(s, &a)); else r = werr(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_bind_in_use(int m) {
    SOCKET a = xe_sock(SOCK_STREAM), b = xe_sock(SOCK_STREAM); struct sockaddr_in la; long r;
    xe_bind_lo(a, &la);
    if (m == 0) r = st(xe_afd_bind(b, &la, sizeof la)); else r = werr(bind(b, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR);
    xe_close(a); xe_close(b); return r;
}
static long s_bind_twice(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in la = xe_lo(0); long r;
    if (m == 0) { xe_afd_bind(s, &la, sizeof la); r = st(xe_afd_bind(s, &la, sizeof la)); }
    else { bind(s, (struct sockaddr *)&la, sizeof la); r = werr(bind(s, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR); }
    xe_close(s); return r;
}
static long s_bind_nonlocal(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r;
    a.sin_addr.s_addr = 0x010200c0; /* 192.0.2.1: documentation range, not assigned here */
    if (m == 0) r = st(xe_afd_bind(s, &a, sizeof a)); else r = werr(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_bind_nonlocal_udp(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(0); long r;
    a.sin_addr.s_addr = 0x010200c0;
    if (m == 0) r = st(xe_afd_bind(s, &a, sizeof a)); else r = werr(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_bind_v6_nonlocal(int m) {
    SOCKET s = xe_sock6(SOCK_STREAM); struct sockaddr_in6 a; long r;
    if (s == INVALID_SOCKET) return XE_NA;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[0] = 0x20; a.sin6_addr.u.Byte[1] = 0x01;
    a.sin6_addr.u.Byte[2] = 0x0d; a.sin6_addr.u.Byte[3] = 0xb8; a.sin6_addr.u.Byte[15] = 1;
    if (m == 0) r = st(xe_afd_bind(s, &a, sizeof a)); else r = werr(bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_bind_short(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r;
    if (m == 0) r = st(xe_afd_bind(s, &a, 8)); else r = werr(bind(s, (struct sockaddr *)&a, 8) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_listen_unbound(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); long r;
    if (m == 0) r = st(xe_afd_listen(s)); else r = werr(listen(s, 4) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_listen_udp(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); long r;
    xe_bind_lo(s, NULL);
    if (m == 0) r = st(xe_afd_listen(s)); else r = werr(listen(s, 4) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_listen_connected(int m) {
    SOCKET c, s; long r; xe_pair(&c, &s);
    if (m == 0) r = st(xe_afd_listen(c)); else r = werr(listen(c, 4) == SOCKET_ERROR);
    xe_close(c); xe_close(s); return r;
}
static long s_recv_unconnected(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); char b[8]; long r;
    if (m == 0) r = st(xe_afd_recv(s, b, 8, 0x20, 500)); else r = werr(recv(s, b, 8, 0) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_send_unconnected(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); long r;
    if (m == 0) r = st(xe_afd_send(s, "x", 1, 500)); else r = werr(send(s, "x", 1, 0) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_send_after_shutdown(int m) {
    SOCKET c, s; long r; xe_pair(&c, &s);
    if (m == 0) { xe_afd_disc(c, 1); r = st(xe_afd_send(c, "x", 1, 1000)); }
    else { shutdown(c, SD_SEND); r = werr(send(c, "x", 1, 0) == SOCKET_ERROR); }
    xe_close(c); xe_close(s); return r;
}
static long s_recv_after_recv_shutdown(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    if (m == 0) { xe_afd_disc(c, 2); send(s, "x", 1, 0); r = st(xe_afd_recv(c, b, 8, 0x20, 500)); }
    else { shutdown(c, SD_RECEIVE); send(s, "x", 1, 0); r = werr(recv(c, b, 8, 0) == SOCKET_ERROR); }
    xe_close(c); xe_close(s); return r;
}
static long s_recv_after_fin(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    xe_close(s); xe_wait_readable(c, 1000);
    if (m == 0) r = st(xe_afd_recv(c, b, 8, 0x20, 1000)); else r = werr(recv(c, b, 8, 0) == SOCKET_ERROR);
    xe_close(c); return r;
}
static void rst_close(SOCKET s) { struct linger l = {1, 0}; setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l); closesocket(s); }
static long s_recv_after_rst(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    rst_close(s); xe_wait_readable(c, 1000);
    if (m == 0) r = st(xe_afd_recv(c, b, 8, 0x20, 1000)); else r = werr(recv(c, b, 8, 0) == SOCKET_ERROR);
    xe_close(c); return r;
}
static long s_send_after_rst(int m) {
    SOCKET c, s; long r; xe_pair(&c, &s);
    rst_close(s); xe_wait_readable(c, 1000);
    if (m == 0) r = st(xe_afd_send(c, "x", 1, 1000)); else r = werr(send(c, "x", 1, 0) == SOCKET_ERROR);
    xe_close(c); return r;
}
static long s_udp_recv_unbound(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); char b[8]; long r;
    if (m == 0) {
        WSABUF wb = { 8, b }; struct { WSABUF *buf; ULONG count, afd, tdi, pad; void *addr; ULONG *alen; } d; struct sockaddr_in f; ULONG fl = sizeof f;
        memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.addr = &f; d.alen = &fl;
        r = st(xe_afd(s, XE_IOCTL_RECV_DG, &d, sizeof d, NULL, 0, 500));
    } else { int fl = 0; r = werr(recvfrom(s, b, 8, 0, NULL, &fl) == SOCKET_ERROR); }
    xe_close(s); return r;
}
static long dgram_recv_raw(SOCKET s, char *b, ULONG n, ULONG tdi, DWORD ms) {
    WSABUF wb = { n, b }; struct { WSABUF *buf; ULONG count, afd, tdi, pad; void *addr; ULONG *alen; } d; struct sockaddr_in f; ULONG fl = sizeof f;
    memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = tdi; d.addr = &f; d.alen = &fl;
    return st(xe_afd(s, XE_IOCTL_RECV_DG, &d, sizeof d, NULL, 0, ms));
}
static long s_udp_recv_too_small(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in aa, ba; char buf[4]; long r;
    xe_bind_lo(a, &aa); xe_bind_lo(b, &ba);
    sendto(a, "12345678", 8, 0, (struct sockaddr *)&ba, sizeof ba);
    xe_wait_readable(b, 1000);
    if (m == 0) r = dgram_recv_raw(b, buf, 4, 0x20, 1000);
    else { int fl = sizeof aa; r = werr(recvfrom(b, buf, 4, 0, (struct sockaddr *)&aa, &fl) == SOCKET_ERROR); }
    xe_close(a); xe_close(b); return r;
}
static long s_udp_port_unreachable(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in aa, dead = some_dead(); char buf[8]; long r;
    xe_bind_lo(a, &aa);
    sendto(a, "x", 1, 0, (struct sockaddr *)&dead, sizeof dead);
    xe_wait_readable(a, 1000);
    if (m == 0) r = dgram_recv_raw(a, buf, 8, 0x20, 1000);
    else { int fl = sizeof aa; r = werr(recvfrom(a, buf, 8, 0, (struct sockaddr *)&aa, &fl) == SOCKET_ERROR); }
    xe_close(a); return r;
}
static long send_dg_raw(SOCKET s, const void *p, ULONG n, const void *to, ULONG tolen) {
    WSABUF wb = { n, (CHAR *)p };
    struct { WSABUF *buf; ULONG count, afd; UCHAR rsv[0x48]; ULONG alen, pad2; const void *addr; } d;
    memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.alen = tolen; d.addr = to;
    return st(xe_afd(s, XE_IOCTL_SEND_DG, &d, sizeof d, NULL, 0, 1000));
}
static long s_udp_send_too_large(int m) {
    static char big[70000]; SOCKET a = xe_sock(SOCK_DGRAM), b = xe_sock(SOCK_DGRAM); struct sockaddr_in ba; long r;
    xe_bind_lo(a, NULL); xe_bind_lo(b, &ba);
    if (m == 0) r = send_dg_raw(a, big, sizeof big, &ba, sizeof ba);
    else r = werr(sendto(a, big, sizeof big, 0, (struct sockaddr *)&ba, sizeof ba) == SOCKET_ERROR);
    xe_close(a); xe_close(b); return r;
}
static long s_udp_send_port0(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in to = xe_lo(0); long r;
    xe_bind_lo(a, NULL);
    if (m == 0) r = send_dg_raw(a, "x", 1, &to, sizeof to);
    else r = werr(sendto(a, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == SOCKET_ERROR);
    xe_close(a); return r;
}
static long s_udp_send_wrong_family(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in6 to; long r;
    memset(&to, 0, sizeof to); to.sin6_family = AF_INET6; to.sin6_port = XE_BE16(9); to.sin6_addr.u.Byte[15] = 1;
    xe_bind_lo(a, NULL);
    if (m == 0) r = send_dg_raw(a, "x", 1, &to, sizeof to);
    else r = werr(sendto(a, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == SOCKET_ERROR);
    xe_close(a); return r;
}
static long s_udp_send_short_addr(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in to = xe_lo(XE_BE16(9)); long r;
    xe_bind_lo(a, NULL);
    if (m == 0) r = send_dg_raw(a, "x", 1, &to, 8);
    else r = werr(sendto(a, "x", 1, 0, (struct sockaddr *)&to, 8) == SOCKET_ERROR);
    xe_close(a); return r;
}
static long s_getpeername_unconnected(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); long r; struct sockaddr_in a; int n = sizeof a; UCHAR out[64];
    if (m == 0) r = st(xe_afd(s, XE_IOCTL_REMOTE, NULL, 0, out, sizeof out, 500));
    else r = werr(getpeername(s, (struct sockaddr *)&a, &n) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_getpeername_listening(int m) {
    struct sockaddr_in la; SOCKET s = xe_listener(&la); long r; struct sockaddr_in a; int n = sizeof a; UCHAR out[64];
    if (m == 0) r = st(xe_afd(s, XE_IOCTL_REMOTE, NULL, 0, out, sizeof out, 500));
    else r = werr(getpeername(s, (struct sockaddr *)&a, &n) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_accept_not_listening(int m) {
    SOCKET s = xe_sock(SOCK_STREAM), n = xe_sock(SOCK_STREAM); long r;
    if (m == 0) { UCHAR rq[16]; memset(rq, 0, sizeof rq); r = st(xe_afd(s, XE_IOCTL_ACCEPT, rq, sizeof rq, NULL, 0, 500)); }
    else r = werr(accept(s, NULL, NULL) == INVALID_SOCKET);
    xe_close(s); xe_close(n); return r;
}
static long s_shutdown_unconnected(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); long r;
    if (m == 0) r = st(xe_afd_disc(s, 1)); else r = werr(shutdown(s, SD_SEND) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_closed_handle(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); long r; closesocket(s);
    if (m == 0) r = st(xe_afd_send(s, "x", 1, 500)); else r = werr(send(s, "x", 1, 0) == SOCKET_ERROR);
    return r;
}
static long s_event_handle(int m) {
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL); long r;
    if (m == 0) r = st(xe_afd((SOCKET)e, XE_IOCTL_ADDR, NULL, 0, (UCHAR[64]){0}, 64, 500)); else r = werr(send((SOCKET)e, "x", 1, 0) == SOCKET_ERROR);
    CloseHandle(e); return r;
}
static long s_connect_when_connected(int m) {
    SOCKET c, s; struct sockaddr_in la; long r; SOCKET l = xe_listener(&la);
    c = xe_sock(SOCK_STREAM); connect(c, (struct sockaddr *)&la, sizeof la); xe_wait_readable(l, 1000);
    s = accept(l, NULL, NULL);
    if (m == 0) r = st(xe_afd_connect(c, &la)); else r = werr(connect(c, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR);
    xe_close(c); xe_close(s); xe_close(l); return r;
}
static long s_connect_listening(int m) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), t = xe_listener(&la); long r;
    SOCKET other = xe_sock(SOCK_STREAM); struct sockaddr_in lb; xe_close(other);
    (void)lb;
    if (m == 0) r = st(xe_afd_connect(l, &la)); else r = werr(connect(l, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR);
    xe_close(l); xe_close(t); return r;
}
static long s_connect_port0(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(0); long r;
    if (m == 0) r = st(xe_afd_connect(s, &a)); else r = werr(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_connect_any_addr(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r;
    a.sin_addr.s_addr = 0;
    if (m == 0) r = st(xe_afd_connect(s, &a)); else r = werr(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_connect_wrong_family(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in6 a; long r;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = XE_BE16(9); a.sin6_addr.u.Byte[15] = 1;
    if (m == 0) { UCHAR rq[0x18 + 28]; memset(rq, 0, sizeof rq); memcpy(rq + 0x18, &a, sizeof a); r = st(xe_afd(s, XE_IOCTL_CONNECT, rq, sizeof rq, NULL, 0, 2000)); }
    else r = werr(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_connect_short_addr(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = xe_lo(XE_BE16(9)); long r;
    if (m == 0) { UCHAR rq[0x18 + 8]; memset(rq, 0, sizeof rq); memcpy(rq + 0x18, &a, 8); r = st(xe_afd(s, XE_IOCTL_CONNECT, rq, sizeof rq, NULL, 0, 2000)); }
    else r = werr(connect(s, (struct sockaddr *)&a, 8) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_unknown_request(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); long r;
    if (m == 0) r = st(xe_afd(s, 0x12ffc, NULL, 0, NULL, 0, 500));
    else { u_long v = 0; r = werr(ioctlsocket(s, (long)0x8004ffee, &v) == SOCKET_ERROR); }
    xe_close(s); return r;
}
static long s_recv_nothing_pending(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    if (m == 0) r = st(xe_afd_recv(c, b, 8, 0x20, 200));
    else { u_long nb = 1; ioctlsocket(c, FIONBIO, &nb); r = werr(recv(c, b, 8, 0) == SOCKET_ERROR); }
    xe_close(c); xe_close(s); return r;
}
static long s_recv_timeout(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    if (m == 0) r = XE_NA;
    else { DWORD t = 100; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t); r = werr(recv(c, b, 8, 0) == SOCKET_ERROR); }
    xe_close(c); xe_close(s); return r;
}
static long s_recv_oob_on_udp(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); long r; char b[8]; struct sockaddr_in a; int n = sizeof a;
    xe_bind_lo(s, NULL);
    if (m == 0) r = dgram_recv_raw(s, b, 8, 0x40, 500);
    else r = werr(recvfrom(s, b, 8, MSG_OOB, (struct sockaddr *)&a, &n) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_recv_oob_inline(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    if (m == 0) r = XE_NA;
    else { BOOL on = 1; setsockopt(c, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof on); r = werr(recv(c, b, 8, MSG_OOB) == SOCKET_ERROR); }
    xe_close(c); xe_close(s); return r;
}
static long s_recv_oob_none(int m) {
    SOCKET c, s; long r; char b[8]; xe_pair(&c, &s);
    if (m == 0) r = st(xe_afd_recv(c, b, 8, 0x40, 300));
    else { u_long nb = 1; ioctlsocket(c, FIONBIO, &nb); r = werr(recv(c, b, 8, MSG_OOB) == SOCKET_ERROR); }
    xe_close(c); xe_close(s); return r;
}
static long s_exclusive_addr(int m) {
    SOCKET a = xe_sock(SOCK_STREAM), b = xe_sock(SOCK_STREAM); struct sockaddr_in la; long r; BOOL on = 1;
    if (m == 0) { xe_close(a); xe_close(b); return XE_NA; }
    setsockopt(a, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&on, sizeof on);
    xe_bind_lo(a, &la);
    setsockopt(b, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
    r = werr(bind(b, (struct sockaddr *)&la, sizeof la) == SOCKET_ERROR);
    xe_close(a); xe_close(b); return r;
}
static long s_udp_connect_port0(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); struct sockaddr_in a = xe_lo(0); long r;
    if (m == 0) r = st(xe_afd_connect(s, &a)); else r = werr(connect(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_udp_send_unbound_nodest(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); long r;
    if (m == 0) r = st(xe_afd_send(s, "x", 1, 500)); else r = werr(send(s, "x", 1, 0) == SOCKET_ERROR);
    xe_close(s); return r;
}
static long s_udp_recv_oversize_peek(int m) { return XE_NA; }

/* overlapped scenarios: m==0 gives OVERLAPPED.Internal, m==1 the WSAGetOverlappedResult error, m==2 kernel32 GetOverlappedResult error */
static long ov_finish(OVERLAPPED *o, SOCKET s, int m) {
    DWORD n = 0, fl = 0; BOOL ok;
    if (m == 0) return (long)o->Internal;
    ok = WSAGetOverlappedResult(s, o, &n, FALSE, &fl);
    if (m == 1) return ok ? 0 : (long)WSAGetLastError();
    ok = GetOverlappedResult((HANDLE)s, o, &n, FALSE);
    return ok ? 0 : (long)GetLastError();
}
static long ov_wait(OVERLAPPED *o, DWORD ms) { return WaitForSingleObject(o->hEvent, ms) == WAIT_OBJECT_0; }
static long s_ov_recv_closed_by_close(int m) {
    SOCKET c, s; char b[8]; WSABUF wb = { 8, b }; DWORD n, fl = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSARecv(c, &wb, 1, &n, &fl, &o, NULL);
    closesocket(c);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(s); return r;
}
static long s_ov_recv_cancelled(int m) {
    SOCKET c, s; char b[8]; WSABUF wb = { 8, b }; DWORD n, fl = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSARecv(c, &wb, 1, &n, &fl, &o, NULL);
    CancelIoEx((HANDLE)c, &o);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(c); xe_close(s); return r;
}
static long s_ov_recv_reset(int m) {
    SOCKET c, s; char b[8]; WSABUF wb = { 8, b }; DWORD n, fl = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSARecv(c, &wb, 1, &n, &fl, &o, NULL);
    rst_close(s);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(c); return r;
}
static long s_ov_send_after_reset(int m) {
    SOCKET c, s; WSABUF wb = { 1, "x" }; DWORD n; OVERLAPPED o; long r; xe_pair(&c, &s);
    rst_close(s); xe_wait_readable(c, 1000);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (WSASend(c, &wb, 1, &n, 0, &o, NULL) == 0) { r = 0; if (m == 0) r = (long)o.Internal; }
    else if (WSAGetLastError() != WSA_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(c); return r;
}
static long s_ov_connectex_refused(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = some_dead(), any = xe_lo(0); GUID g = WSAID_CONNECTEX; LPFN_CONNECTEX ce = NULL; DWORD n = 0;
    OVERLAPPED o; long r;
    bind(s, (struct sockaddr *)&any, sizeof any);
    WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &ce, sizeof ce, &n, NULL, NULL);
    if (!ce) { xe_close(s); return XE_NA; }
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ce(s, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, &o)) r = 0;
    else if (WSAGetLastError() != ERROR_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, s, m);
    CloseHandle(o.hEvent); xe_close(s); return r;
}
static long s_ov_connectex_unbound(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); struct sockaddr_in a = some_dead(); GUID g = WSAID_CONNECTEX; LPFN_CONNECTEX ce = NULL; DWORD n = 0;
    OVERLAPPED o; long r;
    WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &ce, sizeof ce, &n, NULL, NULL);
    if (!ce) { xe_close(s); return XE_NA; }
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ce(s, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, &o)) r = 0;
    else r = (m == 0) ? XE_NA : (long)WSAGetLastError();
    CloseHandle(o.hEvent); xe_close(s); return r;
}
static long s_ov_acceptex_not_listening(int m) {
    SOCKET l = xe_sock(SOCK_STREAM), a = xe_sock(SOCK_STREAM); GUID g = WSAID_ACCEPTEX; LPFN_ACCEPTEX ae = NULL; DWORD n = 0; char buf[64];
    OVERLAPPED o; long r;
    xe_bind_lo(l, NULL);
    WSAIoctl(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &ae, sizeof ae, &n, NULL, NULL);
    if (!ae) { xe_close(l); xe_close(a); return XE_NA; }
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ae(l, a, buf, 0, 32, 32, &n, &o)) r = 0;
    else if (WSAGetLastError() != ERROR_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, l, m);
    CloseHandle(o.hEvent); xe_close(l); xe_close(a); return r;
}
static long s_ov_disconnectex_unconnected(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); GUID g = WSAID_DISCONNECTEX; LPFN_DISCONNECTEX de = NULL; DWORD n = 0; OVERLAPPED o; long r;
    xe_bind_lo(s, NULL);
    WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &de, sizeof de, &n, NULL, NULL);
    if (!de) { xe_close(s); return XE_NA; }
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (de(s, &o, 0, 0)) r = 0;
    else if (WSAGetLastError() != ERROR_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, s, m);
    CloseHandle(o.hEvent); xe_close(s); return r;
}
static long s_ov_send_zero_buffers(int m) {
    SOCKET c, s; DWORD n = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (WSASend(c, NULL, 0, &n, 0, &o, NULL) == 0) r = 0;
    else r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    CloseHandle(o.hEvent); xe_close(c); xe_close(s); return r;
}
static long s_ov_recvfrom_unbound(int m) {
    SOCKET s = xe_sock(SOCK_DGRAM); char b[8]; WSABUF wb = { 8, b }; DWORD n, fl = 0; OVERLAPPED o; long r; struct sockaddr_in f; INT fln = sizeof f;
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (WSARecvFrom(s, &wb, 1, &n, &fl, (struct sockaddr *)&f, &fln, &o, NULL) == 0) r = 0;
    else if (WSAGetLastError() != WSA_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 500)) r = -9; else r = ov_finish(&o, s, m);
    CloseHandle(o.hEvent); xe_close(s); return r;
}


static void nt_run(const char *name, long (*fn)(int), long long wnt, long long wwsa, long long wdos) {
    long nt, w;
    nt = fn(0); w = fn(1);
    if (nt == XE_NA && w == XE_NA) { t_skip("scenario not available here"); return; }
    if (wnt == XE_UNK) { t_note("ROW nt %s nt=%08lx wsa=%ld dos=%lu", name, (unsigned long)nt, w, (unsigned long)(nt == XE_NA ? 0 : dos_of(nt))); return; }
    if (wnt != XE_NA) t_check(XE_ST(nt) == wnt, "x_error_mapping", 0, name, "%s: nt got %08lx want %08llx", name, (unsigned long)nt, (unsigned long long)wnt);
    if (wwsa != XE_NA) t_check(w == wwsa, "x_error_mapping", 0, name, "%s: wsa got %ld want %lld", name, w, wwsa);
    if (wdos != XE_NA && nt != XE_NA) t_check((long long)dos_of(nt) == wdos, "x_error_mapping", 0, name, "%s: dos got %lu want %lld", name, (unsigned long)dos_of(nt), wdos);
}
#define NT_CASE(n, NT, WSA, DOS) TEST(xemap_nt_##n) { XE_UP(); nt_run(#n, s_##n, NT, WSA, DOS); }
static void ov_run(const char *name, long (*fn)(int), long long a, long long b, long long c) {
    long x = fn(0), y = fn(1), z = fn(2);
    if (x == XE_NA) { t_skip("scenario not available here"); return; }
    if (a == XE_UNK) { t_note("ROW ov %s nt=%08lx wsa=%ld win32=%ld", name, (unsigned long)x, y, z); return; }
    t_check(XE_ST(x) == a, "x_error_mapping", 0, name, "%s: internal got %08lx want %08llx", name, (unsigned long)x, (unsigned long long)a);
    t_check(y == b, "x_error_mapping", 0, name, "%s: wsa got %ld want %lld", name, y, b);
    t_check(z == c, "x_error_mapping", 0, name, "%s: win32 got %ld want %lld", name, z, c);
}
#define OV_CASE(n, A, B, C) TEST(xemap_##n) { XE_UP(); ov_run(#n, s_##n, A, B, C); }
NT_CASE(connect_refused, 0xC0000236U, 10061, 1225)
NT_CASE(bind_in_use, 0xC0000043U, 10048, 32)
NT_CASE(bind_twice, 0xC0000238U, 10022, 1227)
NT_CASE(bind_nonlocal, 0xC0000207U, 10049, 1214)
NT_CASE(bind_nonlocal_udp, 0xC0000207U, 10049, 1214)
NT_CASE(bind_v6_nonlocal, 0xC0000207U, 10049, 1214)
NT_CASE(bind_short, 0xC0000141U, 10014, 59)
NT_CASE(listen_unbound, 0xC000000DU, 10022, 87)
NT_CASE(listen_udp, 0xC000000DU, 10045, 87)
NT_CASE(listen_connected, 0xC000000DU, 10056, 87)
NT_CASE(recv_unconnected, 0xC0000140U, 10057, 59)
NT_CASE(send_unconnected, 0xC0000140U, 10057, 59)
NT_CASE(send_after_shutdown, 0xC00000B0U, 10058, 233)
NT_CASE(recv_after_recv_shutdown, 0xC000013BU, 10053, 64)
NT_CASE(recv_after_fin, 0, 0, 0)
NT_CASE(recv_after_rst, 0xC000020DU, 10054, 64)
NT_CASE(send_after_rst, 0xC000020DU, 10054, 64)
NT_CASE(udp_recv_unbound, 0xC000000DU, 10022, 87)
NT_CASE(udp_recv_too_small, 0x80000005U, 10040, 234)
NT_CASE(udp_port_unreachable, 0xC000023FU, 10054, 1234)
NT_CASE(udp_send_too_large, 0xC0000206U, 10040, 1784)
NT_CASE(udp_send_port0, 0, 0, 0)
NT_CASE(udp_send_wrong_family, 0xC0000207U, 10047, 1214)
NT_CASE(udp_send_short_addr, 0xC0000141U, 10014, 59)
NT_CASE(getpeername_unconnected, 0xC0000140U, 10057, 59)
NT_CASE(getpeername_listening, 0xC0000140U, 10057, 59)
NT_CASE(accept_not_listening, 0xC000000DU, 10022, 87)
NT_CASE(shutdown_unconnected, 0xC000000DU, 10057, 87)
NT_CASE(closed_handle, 0xC0000024U, 10038, 6)
NT_CASE(event_handle, 0xC0000024U, 10038, 6)
NT_CASE(connect_when_connected, 0xC000000DU, 10056, 87)
NT_CASE(connect_listening, 0xC000000DU, 10022, 87)
NT_CASE(connect_port0, 0xC0000207U, 10049, 1214)
NT_CASE(connect_any_addr, 0xC0000207U, 10049, 1214)
NT_CASE(connect_wrong_family, 0xC000000DU, 10047, 87)
NT_CASE(connect_short_addr, 0xC0000141U, 10014, 59)
NT_CASE(unknown_request, 0xC0000010U, 10045, 1)
NT_CASE(recv_nothing_pending, 0x00000102U, 10035, 1460)
NT_CASE(recv_timeout, -3, 10060, -3)
NT_CASE(recv_oob_on_udp, 0xC00000BBU, 10045, 50)
NT_CASE(recv_oob_inline, -3, 10022, -3)
NT_CASE(recv_oob_none, 0x00000102U, 10035, 1460)
NT_CASE(exclusive_addr, -3, 10013, -3)
NT_CASE(udp_connect_port0, 0, 0, 0)
NT_CASE(udp_send_unbound_nodest, 0xC0000140U, 10057, 59)
OV_CASE(ov_recv_closed_by_close, 0xC0000241U, 10038, 1236)
OV_CASE(ov_recv_cancelled, 0xC0000120U, 995, 995)
OV_CASE(ov_recv_reset, 0xC000020DU, 10054, 64)
OV_CASE(ov_send_after_reset, 0x00000103U, 10054, 10054)
OV_CASE(ov_connectex_refused, 0xC0000236U, 10061, 1225)
OV_CASE(ov_acceptex_not_listening, 0x00000103U, 10022, 10022)
OV_CASE(ov_disconnectex_unconnected, 0x00000103U, 10057, 10057)
OV_CASE(ov_send_zero_buffers, 0x00000103U, 10022, 10022)
OV_CASE(ov_recvfrom_unbound, 0, 10022, 10022)

/* ---- more overlapped completions ---- */
static long ov_post_recv_udp(OVERLAPPED *o, SOCKET s, char *b, ULONG n, struct sockaddr_in *f) {
    WSABUF wb = { n, b }; DWORD got, fl = 0; INT fln = sizeof *f;
    memset(o, 0, sizeof *o); o->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    return WSARecvFrom(s, &wb, 1, &got, &fl, (struct sockaddr *)f, &fln, o, NULL);
}
static long s_ov_udp_unreachable(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in aa, dead, f; char b[8]; OVERLAPPED o; long r;
    xe_bind_lo(a, &aa); xe_dead_port(&dead);
    ov_post_recv_udp(&o, a, b, 8, &f);
    sendto(a, "x", 1, 0, (struct sockaddr *)&dead, sizeof dead);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, a, m);
    CloseHandle(o.hEvent); xe_close(a); return r;
}
static long s_ov_udp_truncated(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM), c = xe_sock(SOCK_DGRAM); struct sockaddr_in ca, f; char b[4]; OVERLAPPED o; long r;
    xe_bind_lo(a, NULL); xe_bind_lo(c, &ca);
    sendto(a, "12345678", 8, 0, (struct sockaddr *)&ca, sizeof ca);
    ov_post_recv_udp(&o, c, b, 4, &f);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(a); xe_close(c); return r;
}
static long s_ov_udp_cancelled(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in f; char b[4]; OVERLAPPED o; long r;
    xe_bind_lo(a, NULL); ov_post_recv_udp(&o, a, b, 4, &f);
    CancelIoEx((HANDLE)a, &o);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, a, m);
    CloseHandle(o.hEvent); xe_close(a); return r;
}
static long s_ov_udp_closed_by_close(int m) {
    SOCKET a = xe_sock(SOCK_DGRAM); struct sockaddr_in f; char b[4]; OVERLAPPED o; long r;
    xe_bind_lo(a, NULL); ov_post_recv_udp(&o, a, b, 4, &f);
    closesocket(a);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, a, m);
    CloseHandle(o.hEvent); return r;
}
static long s_ov_recv_orderly_close(int m) {
    SOCKET c, s; char b[8]; WSABUF wb = { 8, b }; DWORD n, fl = 0; OVERLAPPED o; long r; xe_pair(&c, &s);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSARecv(c, &wb, 1, &n, &fl, &o, NULL);
    closesocket(s);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(c); return r;
}
static long s_ov_recv_unconnected(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); char b[8]; WSABUF wb = { 8, b }; DWORD n, fl = 0; OVERLAPPED o; long r;
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (WSARecv(s, &wb, 1, &n, &fl, &o, NULL) == 0) r = 0;
    else if (WSAGetLastError() != WSA_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, s, m);
    CloseHandle(o.hEvent); xe_close(s); return r;
}
static long s_ov_ioctl_bad_code(int m) {
    SOCKET s = xe_sock(SOCK_STREAM); DWORD n = 0; OVERLAPPED o; long r;
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (WSAIoctl(s, 0x98000fee, NULL, 0, NULL, 0, &n, &o, NULL) == 0) r = 0;
    else if (WSAGetLastError() != WSA_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, s, m);
    CloseHandle(o.hEvent); xe_close(s); return r;
}
static long s_ov_acceptex_cancelled(int m) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), a = xe_sock(SOCK_STREAM); GUID g = WSAID_ACCEPTEX; LPFN_ACCEPTEX ae = NULL; DWORD n = 0; char buf[96];
    OVERLAPPED o; long r;
    WSAIoctl(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &ae, sizeof ae, &n, NULL, NULL);
    if (!ae) { xe_close(l); xe_close(a); return XE_NA; }
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ae(l, a, buf, 0, 32, 32, &n, &o);
    CancelIoEx((HANDLE)l, &o);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, l, m);
    CloseHandle(o.hEvent); xe_close(l); xe_close(a); return r;
}
static long s_ov_acceptex_closed_listener(int m) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la), a = xe_sock(SOCK_STREAM); GUID g = WSAID_ACCEPTEX; LPFN_ACCEPTEX ae = NULL; DWORD n = 0; char buf[96];
    OVERLAPPED o; long r;
    WSAIoctl(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &ae, sizeof ae, &n, NULL, NULL);
    if (!ae) { xe_close(l); xe_close(a); return XE_NA; }
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ae(l, a, buf, 0, 32, 32, &n, &o);
    closesocket(l);
    if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, l, m);
    CloseHandle(o.hEvent); xe_close(a); return r;
}
static long s_ov_send_peer_reset_second(int m) {
    SOCKET c, s; WSABUF wb = { 1, "x" }; DWORD n; OVERLAPPED o; long r; xe_pair(&c, &s);
    rst_close(s); xe_wait_readable(c, 1000); send(c, "x", 1, 0);
    memset(&o, 0, sizeof o); o.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (WSASend(c, &wb, 1, &n, 0, &o, NULL) == 0) { r = 0; if (m == 0) r = (long)o.Internal; }
    else if (WSAGetLastError() != WSA_IO_PENDING) r = (m == 0) ? (long)o.Internal : (long)WSAGetLastError();
    else if (!ov_wait(&o, 3000)) r = -9; else r = ov_finish(&o, c, m);
    CloseHandle(o.hEvent); xe_close(c); return r;
}
OV_CASE(ov_udp_unreachable, 0xc000023fU, 10054, 1234)
OV_CASE(ov_udp_truncated, 0x80000005U, 10040, 234)
OV_CASE(ov_udp_cancelled, 0xc0000120U, 995, 995)
OV_CASE(ov_udp_closed_by_close, 0xc0000120U, 10038, 995)
OV_CASE(ov_recv_orderly_close, 0x00000000U, 0, 0)
OV_CASE(ov_recv_unconnected, 0x00000103U, 10057, 10057)
OV_CASE(ov_ioctl_bad_code, 0xc00000bbU, 10045, 50)
OV_CASE(ov_acceptex_cancelled, 0xc0000120U, 995, 995)
OV_CASE(ov_acceptex_closed_listener, 0xc0000120U, 10038, 995)
OV_CASE(ov_send_peer_reset_second, 0x00000103U, 10054, 10054)
