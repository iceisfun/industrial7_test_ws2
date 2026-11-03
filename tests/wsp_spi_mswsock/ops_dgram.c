/* Datagram operations of the base provider through its procedure table, plus the two string conversion
 * entries (WSPAddressToString / WSPStringToAddress).
 *
 * Measures: sendto/recvfrom on loopback (source address, boundaries, truncation, zero-length datagrams,
 * peek), the wrong-state errors of unbound and unconnected datagram sockets, implicit binding by sendto,
 * address re-use rules, UDP specific ioctls, and the text <-> sockaddr conversions including the odd
 * ERROR_INVALID_PARAMETER (87) the provider reports for a family it has no helper for.
 */
#include "spi.h"

static int sp_sendto(SOCKET s, const void *b, int n, const struct sockaddr_in *to)
{
    WSABUF w; DWORD sent = 0; int e = 0;
    w.buf = (CHAR *)b; w.len = n;
    if (P.lpWSPSendTo(s, &w, 1, &sent, 0, (const struct sockaddr *)to, sizeof *to, NULL, NULL, NULL, &e) != 0) return -e - 1000000;
    return (int)sent;
}
static int sp_recvfrom(SOCKET s, void *b, int n, struct sockaddr_in *from, int *err)
{
    WSABUF w; DWORD got = 0, fl = 0; int e = 0, fl_len = sizeof *from, r;
    w.buf = (CHAR *)b; w.len = n;
    r = P.lpWSPRecvFrom(s, &w, 1, &got, &fl, (struct sockaddr *)from, from ? &fl_len : NULL, NULL, NULL, NULL, &e);
    if (err) *err = e;
    return r == 0 ? (int)got : -1;
}
/* Two bound loopback UDP sockets. */
static int udp_pair(SOCKET *a, SOCKET *b, struct sockaddr_in *na, struct sockaddr_in *nb)
{
    *a = sp_udp(); *b = sp_udp();
    if (*a == INVALID_SOCKET || *b == INVALID_SOCKET) return 0;
    if (sp_bind_lo(*a) != 0 || sp_bind_lo(*b) != 0) return 0;
    return sp_name(*a, na) == 0 && sp_name(*b, nb) == 0;
}
#define UDP_PAIR(a, b, na, nb) SOCKET a, b; struct sockaddr_in na, nb; \
    do { if (!udp_pair(&a, &b, &na, &nb)) { sp_close(a); sp_close(b); t_skip("udp pair unavailable"); return; } } while (0)

/* ---------------------------------------------------------------- datagram I/O */
TEST(udp_sendto_recvfrom_roundtrip)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        char buf[16] = {0}; struct sockaddr_in from; int e = 0, n;
        EXPECT_EQ(sp_sendto(a, "dgram", 5, &nb), 5);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        memset(&from, 0, sizeof from);
        n = sp_recvfrom(b, buf, sizeof buf, &from, &e);
        EXPECT_EQ(n, 5);
        CHECK(!memcmp(buf, "dgram", 5));
        EXPECT_EQ(from.sin_family, AF_INET);
        EXPECT_EQ(from.sin_port, na.sin_port);
        EXPECT_EQ(from.sin_addr.s_addr, 0x0100007Fu);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_datagram_boundaries_are_kept)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        char buf[16]; int e = 0;
        EXPECT_EQ(sp_sendto(a, "abc", 3, &nb), 3);
        EXPECT_EQ(sp_sendto(a, "defg", 4, &nb), 4);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        Sleep(50);
        EXPECT_EQ(sp_recvfrom(b, buf, sizeof buf, NULL, &e), 3);
        EXPECT_EQ(sp_recvfrom(b, buf, sizeof buf, NULL, &e), 4);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_zero_length_datagram)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        char buf[4]; int e = 0;
        EXPECT_EQ(sp_sendto(a, "", 0, &nb), 0);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        EXPECT_EQ(sp_recvfrom(b, buf, sizeof buf, NULL, &e), 0);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_truncated_receive_is_msgsize)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        char buf[4]; int e = 0;
        EXPECT_EQ(sp_sendto(a, "0123456789", 10, &nb), 10);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        EXPECT_EQ(sp_recvfrom(b, buf, 4, NULL, &e), -1);
        EXPECT_EQ(e, SE_MSGSIZE);
        CHECK(!memcmp(buf, "0123", 4));
        sp_close(a); sp_close(b);
    }
}
TEST(udp_truncated_datagram_is_consumed)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        char buf[4]; int e = 0;
        EXPECT_EQ(sp_sendto(a, "0123456789", 10, &nb), 10);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        (void)sp_recvfrom(b, buf, 4, NULL, &e);
        EXPECT_EQ(sp_readable(b, 100), 0);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_peek_does_not_consume)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        WSABUF w; DWORD got = 0, fl = MSG_PEEK; int e = 0; char buf[8];
        EXPECT_EQ(sp_sendto(a, "peek", 4, &nb), 4);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        w.buf = buf; w.len = sizeof buf;
        EXPECT_EQ(P.lpWSPRecvFrom(b, &w, 1, &got, &fl, NULL, NULL, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(got, 4);
        EXPECT_EQ(sp_recvfrom(b, buf, sizeof buf, NULL, &e), 4);
        EXPECT_EQ(sp_readable(b, 100), 0);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_sendto_binds_implicitly)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        SOCKET c = sp_udp(); struct sockaddr_in n;
        EXPECT_EQ(sp_name(c, &n), SOCKET_ERROR);   /* unbound: no name yet */
        EXPECT_EQ(sp_sendto(c, "x", 1, &nb), 1);
        EXPECT_EQ(sp_name(c, &n), 0);
        CHECK(n.sin_port != 0);
        sp_close(c); sp_close(a); sp_close(b);
    }
}
TEST(udp_recvfrom_unbound_socket_is_invalid)
{
    SOCKET s; char buf[4]; int e = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(sp_recvfrom(s, buf, sizeof buf, NULL, &e), -1);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(udp_recvfrom_nonblocking_empty)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        char buf[4]; int e = 0; u_long on = 1; DWORD n = 0;
        EXPECT_EQ(P.lpWSPIoctl(b, FIONBIO, &on, 4, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(sp_recvfrom(b, buf, sizeof buf, NULL, &e), -1);
        EXPECT_EQ(e, SE_WOULDBLOCK);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_sendto_invalid_socket)
{
    struct sockaddr_in to;
    SP_NEED();
    sp_v4(&to, 9);
    CHECK(sp_sendto(INVALID_SOCKET, "x", 1, &to) == -SE_NOTSOCK - 1000000);
}
TEST(udp_recvfrom_invalid_socket)
{
    char buf[4]; int e = 0;
    SP_NEED();
    EXPECT_EQ(sp_recvfrom(INVALID_SOCKET, buf, sizeof buf, NULL, &e), -1);
    EXPECT_EQ(e, SE_NOTSOCK);
}
TEST(udp_sendto_oversize_datagram)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        static char big[70000];
        EXPECT_EQ(sp_sendto(a, big, 65508, &nb), -SE_MSGSIZE - 1000000);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_sendto_short_address_length)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        WSABUF w; DWORD sent = 0; int e = 0;
        w.buf = "x"; w.len = 1;
        EXPECT_EQ(P.lpWSPSendTo(a, &w, 1, &sent, 0, (struct sockaddr *)&nb, 8, NULL, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_FAULT);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_connected_send_and_recv)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        int e = 0; char buf[8];
        EXPECT_EQ(P.lpWSPConnect(a, (struct sockaddr *)&nb, sizeof nb, NULL, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(P.lpWSPConnect(b, (struct sockaddr *)&na, sizeof na, NULL, NULL, NULL, NULL, &e), 0);
        CHECK(sp_send_all(a, "hi", 2));
        EXPECT_EQ(sp_readable(b, 5000), 1);
        EXPECT_EQ(sp_recv_some(b, buf, sizeof buf, &e), 2);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_send_on_unconnected_socket)
{
    SOCKET s; WSABUF w; DWORD sent = 0; int e = 0, r;
    SP_NEED();
    s = sp_udp();
    w.buf = "x"; w.len = 1;
    r = P.lpWSPSend(s, &w, 1, &sent, 0, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(e, SE_NOTCONN);
    sp_close(s);
}
TEST(udp_getpeername_before_and_after_connect)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        struct sockaddr_in p; int e = 0, l = sizeof p;
        EXPECT_EQ(P.lpWSPGetPeerName(a, (struct sockaddr *)&p, &l, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_NOTCONN);
        EXPECT_EQ(P.lpWSPConnect(a, (struct sockaddr *)&nb, sizeof nb, NULL, NULL, NULL, NULL, &e), 0);
        l = sizeof p;
        EXPECT_EQ(P.lpWSPGetPeerName(a, (struct sockaddr *)&p, &l, &e), 0);
        EXPECT_EQ(p.sin_port, nb.sin_port);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_bind_port_in_use)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        SOCKET c = sp_udp(); int e = 0;
        EXPECT_EQ(P.lpWSPBind(c, (struct sockaddr *)&na, sizeof na, &e), SOCKET_ERROR);
        EXPECT_EQ(e, WSAEADDRINUSE);
        sp_close(c); sp_close(a); sp_close(b);
    }
}
TEST(udp_reuseaddr_allows_shared_port)
{
    SP_NEED();
    {
        SOCKET a = sp_udp(), b = sp_udp(); struct sockaddr_in na; int on = 1, e = 0;
        EXPECT_EQ(P.lpWSPSetSockOpt(a, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, 4, &e), 0);
        EXPECT_EQ(P.lpWSPSetSockOpt(b, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, 4, &e), 0);
        EXPECT_EQ(sp_bind_lo(a), 0);
        EXPECT_EQ(sp_name(a, &na), 0);
        EXPECT_EQ(P.lpWSPBind(b, (struct sockaddr *)&na, sizeof na, &e), 0);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_fionread_is_next_datagram_size)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        u_long avail = 99; DWORD n = 0; int e = 0;
        EXPECT_EQ(sp_sendto(a, "123456", 6, &nb), 6);
        EXPECT_EQ(sp_readable(b, 5000), 1);
        Sleep(50);
        EXPECT_EQ(P.lpWSPIoctl(b, FIONREAD, NULL, 0, &avail, sizeof avail, &n, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(avail, 6);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_connreset_control_is_accepted)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        DWORD off = 0, n = 0; int e = 0;
        EXPECT_EQ(P.lpWSPIoctl(a, _WSAIOW(IOC_VENDOR, 12), &off, sizeof off, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_overlapped_recvfrom_fills_source)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        WSAOVERLAPPED ov; WSABUF w; DWORD got = 0, fl = 0, xfer = 0, xf = 0; int e = 0, fl_len = 16; char buf[8] = {0};
        struct sockaddr_in from;
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        memset(&from, 0, sizeof from);
        w.buf = buf; w.len = sizeof buf;
        EXPECT_EQ(P.lpWSPRecvFrom(b, &w, 1, &got, &fl, (struct sockaddr *)&from, &fl_len, &ov, NULL, NULL, &e), SOCKET_ERROR);
        EXPECT_EQ(e, SE_IOPENDING);
        EXPECT_EQ(sp_sendto(a, "wake", 4, &nb), 4);
        EXPECT_EQ(WaitForSingleObject(ov.hEvent, 5000), WAIT_OBJECT_0);
        e = 0;
        EXPECT_EQ(P.lpWSPGetOverlappedResult(b, &ov, &xfer, FALSE, &xf, &e), TRUE);
        EXPECT_EQ(xfer, 4);
        EXPECT_EQ(from.sin_port, na.sin_port);
        EXPECT_EQ(fl_len, 16);
        CloseHandle(ov.hEvent);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_eventselect_read_signals)
{
    SP_NEED();
    {
        UDP_PAIR(a, b, na, nb);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); int e = 0; WSANETWORKEVENTS ne;
        EXPECT_EQ(P.lpWSPEventSelect(b, ev, FD_READ, &e), 0);
        EXPECT_EQ(sp_sendto(a, "x", 1, &nb), 1);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(P.lpWSPEnumNetworkEvents(b, ev, &ne, &e), 0);
        EXPECT_EQ(ne.lNetworkEvents, FD_READ);
        P.lpWSPEventSelect(b, NULL, 0, &e);
        CloseHandle(ev);
        sp_close(a); sp_close(b);
    }
}
TEST(udp_v6_loopback_roundtrip)
{
    int e = 0; SOCKET a, b; struct sockaddr_in6 x, nb; int l = sizeof nb; WSABUF w; DWORD sent = 0, got = 0, fl = 0; char buf[8];
    SP_NEED();
    a = sp_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &e);
    if (a == INVALID_SOCKET) { t_skip("no IPv6 here"); return; }
    b = sp_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &e);
    sp_v6(&x, 0);
    EXPECT_EQ(P.lpWSPBind(b, (struct sockaddr *)&x, sizeof x, &e), 0);
    EXPECT_EQ(P.lpWSPGetSockName(b, (struct sockaddr *)&nb, &l, &e), 0);
    EXPECT_EQ(l, (int)sizeof nb);
    w.buf = "v6"; w.len = 2;
    EXPECT_EQ(P.lpWSPSendTo(a, &w, 1, &sent, 0, (struct sockaddr *)&nb, sizeof nb, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(b, 5000), 1);
    w.buf = buf; w.len = sizeof buf;
    EXPECT_EQ(P.lpWSPRecvFrom(b, &w, 1, &got, &fl, NULL, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(got, 2);
    sp_close(a); sp_close(b);
}
TEST(udp_v6_bind_wrong_length_for_family)
{
    int e = 0; SOCKET s; struct sockaddr_in6 x;
    SP_NEED();
    s = sp_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &e);
    if (s == INVALID_SOCKET) { t_skip("no IPv6 here"); return; }
    sp_v6(&x, 0);
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&x, 16, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(udp_v6_getsockname_length)
{
    int e = 0; SOCKET s; struct sockaddr_in6 x, n; int l = sizeof n;
    SP_NEED();
    s = sp_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &e);
    if (s == INVALID_SOCKET) { t_skip("no IPv6 here"); return; }
    sp_v6(&x, 0);
    EXPECT_EQ(P.lpWSPBind(s, (struct sockaddr *)&x, sizeof x, &e), 0);
    EXPECT_EQ(P.lpWSPGetSockName(s, (struct sockaddr *)&n, &l, &e), 0);
    EXPECT_EQ(l, 28);
    EXPECT_EQ(n.sin6_family, AF_INET6);
    EXPECT_EQ(n.sin6_addr.s6_addr[15], 1);
    sp_close(s);
}

/* ---------------------------------------------------------------- WSPAddressToString */
static int a2s(const void *sa, DWORD salen, WCHAR *out, DWORD *olen, int *err)
{
    *err = 0x5656;
    return P.lpWSPAddressToString((LPSOCKADDR)sa, salen, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), out, olen, err);
}
TEST(a2s_ipv4_with_port)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 80);
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), 0);
    EXPECT_WSTR(b, L"127.0.0.1:80");
    EXPECT_EQ(l, 13);
}
TEST(a2s_ipv4_without_port)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 0);
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), 0);
    EXPECT_WSTR(b, L"127.0.0.1");
    EXPECT_EQ(l, 10);
}
TEST(a2s_ipv4_other_values)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 65535);
    a.sin_addr.s_addr = 0x0807060Au;
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), 0);
    EXPECT_WSTR(b, L"10.6.7.8:65535");
}
TEST(a2s_ipv4_wildcard_and_broadcast)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 0);
    a.sin_addr.s_addr = 0;
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), 0);
    EXPECT_WSTR(b, L"0.0.0.0");
    l = 64;
    a.sin_addr.s_addr = 0xFFFFFFFFu;
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), 0);
    EXPECT_WSTR(b, L"255.255.255.255");
}
TEST(a2s_ipv4_buffer_too_small_reports_needed_length)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 5; int e;
    SP_NEED();
    sp_v4(&a, 80);
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    EXPECT_EQ(l, 13);
}
TEST(a2s_ipv4_exact_buffer)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 13; int e;
    SP_NEED();
    sp_v4(&a, 80);
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), 0);
    EXPECT_WSTR(b, L"127.0.0.1:80");
}
TEST(a2s_ipv4_one_short_of_exact)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 12; int e;
    SP_NEED();
    sp_v4(&a, 80);
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    EXPECT_EQ(l, 13);
}
TEST(a2s_ipv4_zero_length_buffer)
{
    struct sockaddr_in a; WCHAR b[4]; DWORD l = 0; int e;
    SP_NEED();
    sp_v4(&a, 0);
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    EXPECT_EQ(l, 10);
}
TEST(a2s_address_shorter_than_family_minimum)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 80);
    EXPECT_EQ(a2s(&a, 15, b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
}
TEST(a2s_unknown_family_reports_error_87)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 80);
    a.sin_family = 99;
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
}
TEST(a2s_unspecified_family_reports_error_87)
{
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v4(&a, 80);
    a.sin_family = AF_UNSPEC;
    EXPECT_EQ(a2s(&a, sizeof a, b, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
}
TEST(a2s_ipv6_loopback)
{
    struct sockaddr_in6 a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v6(&a, 0);
    if (a2s(&a, sizeof a, b, &l, &e) != 0) { t_skip("no IPv6 helper here (error %d)", e); return; }
    EXPECT_WSTR(b, L"::1");
    EXPECT_EQ(l, 4);
}
TEST(a2s_ipv6_with_port_is_bracketed)
{
    struct sockaddr_in6 a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v6(&a, 8080);
    if (a2s(&a, sizeof a, b, &l, &e) != 0) { t_skip("no IPv6 helper here (error %d)", e); return; }
    EXPECT_WSTR(b, L"[::1]:8080");
}
TEST(a2s_ipv6_short_sockaddr)
{
    struct sockaddr_in6 a; WCHAR b[64]; DWORD l = 64; int e;
    SP_NEED();
    sp_v6(&a, 0);
    if (a2s(&a, 16, b, &l, &e) == 0) { t_note("16-byte IPv6 address accepted"); return; }
    CHECK(e == SE_FAULT || e == ERROR_INVALID_PARAMETER);
}

/* ---------------------------------------------------------------- WSPStringToAddress */
static int s2a(const WCHAR *s, int af, void *out, int *len, int *err)
{
    *err = 0x5656;
    return P.lpWSPStringToAddress((LPWSTR)s, af, (LPWSAPROTOCOL_INFOW)sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP), (LPSOCKADDR)out, len, err);
}
TEST(s2a_ipv4_plain)
{
    struct sockaddr_in a; int l = sizeof a, e;
    SP_NEED();
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(s2a(L"1.2.3.4", AF_INET, &a, &l, &e), 0);
    EXPECT_EQ(l, 16);
    EXPECT_EQ(a.sin_family, AF_INET);
    EXPECT_EQ(a.sin_port, 0);
    EXPECT_EQ(a.sin_addr.s_addr, 0x04030201u);
}
TEST(s2a_ipv4_with_port)
{
    struct sockaddr_in a; int l = sizeof a, e;
    SP_NEED();
    EXPECT_EQ(s2a(L"127.0.0.1:8080", AF_INET, &a, &l, &e), 0);
    EXPECT_EQ(a.sin_port, sp_swap16(8080));
    EXPECT_EQ(a.sin_addr.s_addr, 0x0100007Fu);
}
TEST(s2a_ipv4_zeroes_the_reserved_tail)
{
    struct sockaddr_in a; int l = sizeof a, e, i;
    SP_NEED();
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(s2a(L"9.9.9.9", AF_INET, &a, &l, &e), 0);
    for (i = 0; i < 8; i++) EXPECT_EQ(a.sin_zero[i], 0);
}
TEST(s2a_ipv4_larger_buffer_reports_actual_size)
{
    struct sockaddr_storage st; int l = sizeof st, e;
    SP_NEED();
    EXPECT_EQ(s2a(L"1.2.3.4", AF_INET, &st, &l, &e), 0);
    EXPECT_EQ(l, 16);
}
TEST(s2a_ipv4_buffer_too_small)
{
    struct sockaddr_in a; int l = 8, e;
    SP_NEED();
    EXPECT_EQ(s2a(L"1.2.3.4", AF_INET, &a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    EXPECT_EQ(l, 28);   /* the size reported is the helper's largest address (IPv6), not the IPv4 size */
}
#define S2A_BAD(nm, str) \
TEST(s2a_ipv4_rejects_##nm) { struct sockaddr_in a; int l = sizeof a, e; SP_NEED(); \
    EXPECT_EQ(s2a(str, AF_INET, &a, &l, &e), SOCKET_ERROR); EXPECT_EQ(e, SE_INVAL); }
S2A_BAD(empty, L"")
S2A_BAD(letters, L"abc")
S2A_BAD(five_octets, L"1.2.3.4.5")
S2A_BAD(octet_over_255, L"256.1.1.1")
S2A_BAD(trailing_dot, L"1.2.3.4.")
S2A_BAD(port_without_number, L"1.2.3.4:")
S2A_BAD(port_over_65535, L"1.2.3.4:65536")
S2A_BAD(leading_space, L" 1.2.3.4")
S2A_BAD(trailing_space, L"1.2.3.4 ")
S2A_BAD(hostname, L"localhost")
S2A_BAD(brackets, L"[1.2.3.4]")

TEST(s2a_unknown_family_reports_error_87)
{
    struct sockaddr_in a; int l = sizeof a, e;
    SP_NEED();
    EXPECT_EQ(s2a(L"1.2.3.4", 99, &a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
}
TEST(s2a_unspecified_family_reports_error_87)
{
    struct sockaddr_in a; int l = sizeof a, e;
    SP_NEED();
    EXPECT_EQ(s2a(L"1.2.3.4", AF_UNSPEC, &a, &l, &e), SOCKET_ERROR);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
}
TEST(s2a_ipv6_loopback)
{
    struct sockaddr_in6 a; int l = sizeof a, e;
    SP_NEED();
    memset(&a, 0x77, sizeof a);
    if (s2a(L"::1", AF_INET6, &a, &l, &e) != 0) { t_skip("no IPv6 helper here (error %d)", e); return; }
    EXPECT_EQ(l, 28);
    EXPECT_EQ(a.sin6_family, AF_INET6);
    EXPECT_EQ(a.sin6_port, 0);
    EXPECT_EQ(a.sin6_addr.s6_addr[15], 1);
    EXPECT_EQ(a.sin6_addr.s6_addr[0], 0);
}
TEST(s2a_ipv6_with_port)
{
    struct sockaddr_in6 a; int l = sizeof a, e;
    SP_NEED();
    if (s2a(L"[::1]:80", AF_INET6, &a, &l, &e) != 0) { t_skip("no IPv6 helper here (error %d)", e); return; }
    EXPECT_EQ(a.sin6_port, sp_swap16(80));
}
TEST(s2a_ipv6_buffer_too_small)
{
    struct sockaddr_in6 a; int l = 16, e;
    SP_NEED();
    if (s2a(L"::1", AF_INET6, &a, &l, &e) == 0) { t_note("16 bytes were enough for an IPv6 address"); return; }
    CHECK(e == SE_FAULT || e == ERROR_INVALID_PARAMETER);
    if (e == SE_FAULT) EXPECT_EQ(l, 28);
}
TEST(s2a_ipv6_rejects_garbage)
{
    struct sockaddr_in6 a; int l = sizeof a, e;
    SP_NEED();
    if (s2a(L"1.2.3.4", AF_INET6, &a, &l, &e) == 0) { t_note("dotted quad accepted as IPv6"); return; }
    CHECK(e == SE_INVAL || e == ERROR_INVALID_PARAMETER);
    l = sizeof a;
    if (s2a(L":::", AF_INET6, &a, &l, &e) == 0) { CHECKF(0, ":::"); return; }
    CHECK(e == SE_INVAL || e == ERROR_INVALID_PARAMETER);
}
TEST(s2a_then_a2s_roundtrip)
{
    struct sockaddr_in a; int l = sizeof a, e; WCHAR b[64]; DWORD bl = 64;
    SP_NEED();
    EXPECT_EQ(s2a(L"172.16.254.3:4455", AF_INET, &a, &l, &e), 0);
    EXPECT_EQ(a2s(&a, sizeof a, b, &bl, &e), 0);
    EXPECT_WSTR(b, L"172.16.254.3:4455");
}
