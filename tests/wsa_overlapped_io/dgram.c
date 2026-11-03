/* wsa_overlapped_io / dgram: overlapped datagram I/O on loopback UDP.
 * Measures: WSASendTo / WSARecvFrom with source addresses, datagram boundaries across scatter-gather and
 * several outstanding requests, zero-length datagrams, truncation (WSAEMSGSIZE, Internal ==
 * STATUS_BUFFER_OVERFLOW, byte count, flags left untouched), the WSASendMsg export and the WSARecvMsg
 * extension function obtained through WSAIoctl (control data, MSG_CTRUNC), and parameter errors that are
 * reported before a request exists. */
#include "oio.h"

#ifndef MSG_TRUNC
#define MSG_TRUNC 0x0100
#define MSG_CTRUNC 0x0200
#endif
#ifndef IP_PKTINFO
#define IP_PKTINFO 19
#endif

static int udp_to(SOCKET s, const struct sockaddr_in *to, const void *p, int n)
{
    return U(sendto)(s, (const char *)p, n, 0, (const struct sockaddr *)to, sizeof *to);
}

/* Post an overlapped WSARecvFrom; addr/alen are filled on completion. */
static int post_from(SOCKET s, char *buf, ULONG len, struct sockaddr_in *from, INT *alen, WSAOVERLAPPED *o, DWORD *fl)
{
    WSABUF b = {len, buf};
    *alen = sizeof *from; *fl = 0;
    return U(WSARecvFrom)(s, &b, 1, NULL, fl, (struct sockaddr *)from, alen, o, NULL);
}

TEST(oio_udp_recvfrom_pending_reports_source)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[16]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl_sentinel(&o, ev);
    OEQ(post_from(a, buf, sizeof buf, &from, &alen, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    OEQ(o.Internal, OIO_STATUS_PENDING);
    OEQ(udp_to(b, &aa, "dgram", 5), 5);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 5); OEQ(f2, 0);
    OEQ(alen, sizeof(struct sockaddr_in));
    OEQ(from.sin_family, AF_INET); OEQ(from.sin_port, ba.sin_port); OEQ(from.sin_addr.s_addr, ba.sin_addr.s_addr);
    OEQ(o.InternalHigh, 5);
    CHECK(!memcmp(buf, "dgram", 5));
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_recvfrom_data_ready_inline_or_pending)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[16]; DWORD fl = 0, nb = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    udp_to(b, &aa, "ready", 5); Sleep(50);
    oio_ovl(&o, ev);
    WSABUF w = {sizeof buf, buf}; alen = sizeof from;
    int rc = U(WSARecvFrom)(a, &w, 1, &nb, &fl, (struct sockaddr *)&from, &alen, &o, NULL);
    if (rc == 0) { OEQ(nb, 5); OEQ(alen, sizeof from); OEQ(from.sin_port, ba.sin_port); }
    else { OEQ(rc, SOCKET_ERROR); OEQ(WERR(), WSA_IO_PENDING); }
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 5);
    oio_close2(a, b); CloseHandle(ev);
}

/* A datagram longer than the buffer: failure with WSAEMSGSIZE, the buffer holds the prefix, the byte count is
 * the buffer size, Internal is the overflow status, and
 * the flags variable is not asserted. */
TEST(oio_udp_truncated_overlapped_fails_msgsize)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes = 0, f2 = 0xdeadbeef;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl_sentinel(&o, ev);
    OEQ(post_from(a, buf, sizeof buf, &from, &alen, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    udp_to(b, &aa, "0123456789", 10);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_BUFFER_OVERFLOW); OEQ(o.InternalHigh, 4);
    OEQ(U(WSAGetOverlappedResult)(a, &o, &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSAEMSGSIZE);
    OEQ(bytes, 4);
    if (f2 != 0xdeadbeef) t_note("flags variable written after WSAEMSGSIZE");
    CHECK(!memcmp(buf, "0123", 4));
    oio_close2(a, b); CloseHandle(ev);
}

/* After a truncated datagram the next one is received normally (the remainder was discarded). */
TEST(oio_udp_truncation_discards_remainder)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    udp_to(b, &aa, "longer-than-buffer", 18);
    udp_to(b, &aa, "ok", 2);
    Sleep(100);
    for (int pass = 0; pass < 2; pass++) {
        oio_ovl(&o, ev); ResetEvent(ev);
        int rc = post_from(a, buf, sizeof buf, &from, &alen, &o, &fl);
        CHECK(rc == 0 || WERR() == WSA_IO_PENDING || WERR() == WSAEMSGSIZE);
        OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
        BOOL r = oio_finish(a, &o, &bytes, &f2, &err);
        if (pass == 0) { OEQ(r, FALSE); OEQ(err, WSAEMSGSIZE); }
        else { CHECK(r); OEQ(bytes, 2); CHECK(!memcmp(buf, "ok", 2)); }
    }
    oio_close2(a, b); CloseHandle(ev);
}

/* Truncation with a completion routine: the routine receives WSAEMSGSIZE. */
TEST(oio_udp_truncated_routine_gets_msgsize)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen = sizeof from; WSAOVERLAPPED o; char buf[2]; DWORD fl = 0;
    UP(); UDPAIR(a, b, aa, ba);
    oio_cr_reset(); oio_ovl(&o, NULL);
    WSABUF w = {sizeof buf, buf};
    OEQ(U(WSARecvFrom)(a, &w, 1, NULL, &fl, (struct sockaddr *)&from, &alen, &o, oio_cr), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    udp_to(b, &aa, "abcdef", 6);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.err, WSAEMSGSIZE);
    t_note("truncated datagram routine bytes: %lu", g_cr.bytes);
    oio_close2(a, b);
}

TEST(oio_udp_zero_length_datagram_roundtrip)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl(&o, ev);
    OEQ(post_from(a, buf, sizeof buf, &from, &alen, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    OEQ(udp_to(b, &aa, "", 0), 0);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 0);
    OEQ(from.sin_port, ba.sin_port);
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_sendto_overlapped_delivers)
{
    SOCKET a, b; struct sockaddr_in aa, ba; WSAOVERLAPPED o; char got[8]; DWORD nb = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl_sentinel(&o, ev);
    WSABUF w = {3, (CHAR *)"u-d"};
    int rc = U(WSASendTo)(a, &w, 1, &nb, 0, (struct sockaddr *)&ba, sizeof ba, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    if (rc == 0) OEQ(nb, 3);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 3);
    OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 3);
    OEQ(U(recv)(b, got, sizeof got, 0), 3);
    CHECK(!memcmp(got, "u-d", 3));
    oio_close2(a, b); CloseHandle(ev);
}

/* Gather send forms a single datagram; datagram boundaries are preserved on receive. */
TEST(oio_udp_gather_makes_one_datagram)
{
    SOCKET a, b; struct sockaddr_in aa, ba; WSAOVERLAPPED o; char got[16]; DWORD nb = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl(&o, ev);
    WSABUF w[4] = { {2, (CHAR *)"ab"}, {0, (CHAR *)""}, {3, (CHAR *)"cde"}, {1, (CHAR *)"f"} };
    int rc = U(WSASendTo)(a, w, 4, &nb, 0, (struct sockaddr *)&ba, sizeof ba, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 6);
    OEQ(U(recv)(b, got, sizeof got, 0), 6);
    CHECK(!memcmp(got, "abcdef", 6));
    u_long avail = 7;
    OEQ(U(ioctlsocket)(b, FIONREAD, &avail), 0); OEQ(avail, 0);
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_scatter_receive_splits_one_datagram)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen = sizeof from; WSAOVERLAPPED o; char x[2], y[3]; DWORD fl = 0, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    udp_to(b, &aa, "12345", 5); udp_to(b, &aa, "zz", 2); Sleep(100);
    oio_ovl(&o, ev);
    WSABUF w[2] = { {2, x}, {3, y} };
    int rc = U(WSARecvFrom)(a, w, 2, NULL, &fl, (struct sockaddr *)&from, &alen, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 5);
    CHECK(!memcmp(x, "12", 2)); CHECK(!memcmp(y, "345", 3));
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_two_recvfrom_one_datagram_each_in_order)
{
    SOCKET a, b; struct sockaddr_in aa, ba, f1, f2a; INT l1, l2; WSAOVERLAPPED o1, o2; char b1[8], b2[8]; DWORD fl, n1, n2, f2; int err;
    HANDLE e1 = oio_event(), e2 = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl(&o1, e1); oio_ovl(&o2, e2);
    post_from(a, b1, 8, &f1, &l1, &o1, &fl); post_from(a, b2, 8, &f2a, &l2, &o2, &fl);
    udp_to(b, &aa, "first", 5); udp_to(b, &aa, "2nd", 3);
    OEQ(oio_wait(e1, OIO_WAIT), WAIT_OBJECT_0); OEQ(oio_wait(e2, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o1, &n1, &f2, &err)); CHECK(oio_finish(a, &o2, &n2, &f2, &err));
    OEQ(n1, 5); OEQ(n2, 3);
    CHECK(!memcmp(b1, "first", 5)); CHECK(!memcmp(b2, "2nd", 3));
    oio_close2(a, b); CloseHandle(e1); CloseHandle(e2);
}

TEST(oio_udp_recvfrom_peek_keeps_datagram)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes, f2; int err;
    HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    udp_to(b, &aa, "peekme", 6); Sleep(50);
    for (int i = 0; i < 2; i++) {
        oio_ovl(&o, ev); ResetEvent(ev);
        WSABUF w = {sizeof buf, buf}; alen = sizeof from; fl = (i == 0) ? MSG_PEEK : 0;
        int rc = U(WSARecvFrom)(a, &w, 1, NULL, &fl, (struct sockaddr *)&from, &alen, &o, NULL);
        CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
        OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
        CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 6);
    }
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_recvfrom_cancel_aborts)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 3, f2; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl(&o, ev);
    post_from(a, buf, sizeof buf, &from, &alen, &o, &fl);
    CHECK(CancelIoEx((HANDLE)a, &o));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_CANCELLED);
    OEQ(U(WSAGetOverlappedResult)(a, &o, &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSA_OPERATION_ABORTED);
    udp_to(b, &aa, "after", 5); Sleep(50);
    OEQ(U(recv)(a, buf, sizeof buf, 0), 5);
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_close_with_pending_recvfrom_cancels)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; WSAOVERLAPPED o; char buf[8]; DWORD fl; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    oio_ovl(&o, ev);
    post_from(a, buf, sizeof buf, &from, &alen, &o, &fl);
    U(closesocket)(a);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_CANCELLED);
    U(closesocket)(b); CloseHandle(ev);
}

/* ---- parameter errors reported before a request exists ---------------------------------- */
TEST(oio_udp_sendto_unbound_no_destination_notconn)
{
    SOCKET a; WSAOVERLAPPED o; DWORD nb = 0; HANDLE ev = oio_event();
    UP();
    a = oio_sock(SOCK_DGRAM, IPPROTO_UDP); REQUIRE(a != INVALID_SOCKET);
    oio_ovl(&o, ev);
    WSABUF w = {1, (CHAR *)"x"};
    OEQ(U(WSASendTo)(a, &w, 1, &nb, 0, NULL, 0, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTCONN);
    U(closesocket)(a); CloseHandle(ev);
}

/* A NULL byte-count pointer together with a NULL OVERLAPPED is not a supported call shape: Windows
   dereferences the count and faults, so no test drives it. */

/* Source-address argument rules of WSARecvFrom: from and fromlen come as a pair, with a non-zero length. */
TEST(oio_udp_recvfrom_address_pair_rules)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; char buf[4]; DWORD fl, nb = 0; WSAOVERLAPPED o; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    WSABUF w = {sizeof buf, buf};
    oio_ovl_sentinel(&o, ev); fl = 0;
    OEQ(U(WSARecvFrom)(a, &w, 1, &nb, &fl, (struct sockaddr *)&from, NULL, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAEFAULT);
    OEQ(o.Internal, OIO_SENTINEL);
    alen = 0; fl = 0;
    OEQ(U(WSARecvFrom)(a, &w, 1, &nb, &fl, (struct sockaddr *)&from, &alen, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAEFAULT);
    alen = sizeof from; fl = 0;
    OEQ(U(WSARecvFrom)(a, &w, 1, &nb, &fl, NULL, &alen, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAEFAULT);
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_recvfrom_short_fromlen_efault)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; char buf[4]; DWORD fl = 0, nb = 0; WSAOVERLAPPED o; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    WSABUF w = {sizeof buf, buf};
    oio_ovl_sentinel(&o, ev);
    for (alen = 1; alen < (INT)sizeof(struct sockaddr_in); alen += 5) {
        INT l = alen; fl = 0;
        int rc = U(WSARecvFrom)(a, &w, 1, &nb, &fl, (struct sockaddr *)&from, &l, &o, NULL);
        t_check(rc == SOCKET_ERROR && WERR() == WSAEFAULT, __FILE__, __LINE__, "short fromlen", "fromlen %d rc %d err %d", alen, rc, WERR());
    }
    OEQ(o.Internal, OIO_SENTINEL);
    oio_close2(a, b); CloseHandle(ev);
}

/* Receive flags outside {OOB, PEEK, PARTIAL} are refused before any request is created. */
TEST(oio_udp_recvfrom_invalid_flags_opnotsupp)
{
    static const DWORD bad[] = { 0x4, 0x8, 0x10, 0x100, 0x10000 };
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen; char buf[4]; DWORD nb = 0; WSAOVERLAPPED o; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    WSABUF w = {sizeof buf, buf};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        DWORD fl = bad[i]; alen = sizeof from;
        oio_ovl_sentinel(&o, ev);
        int rc = U(WSARecvFrom)(a, &w, 1, &nb, &fl, (struct sockaddr *)&from, &alen, &o, NULL);
        t_check(rc == SOCKET_ERROR && WERR() == WSAEOPNOTSUPP, __FILE__, __LINE__, "bad recvfrom flag", "flag 0x%lx rc %d err %d", bad[i], rc, WERR());
        OEQ(o.Internal, OIO_SENTINEL);
    }
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_udp_sendto_invalid_socket_notsock)
{
    WSAOVERLAPPED o; DWORD nb = 0; struct sockaddr_in to = oio_lo(); UP();
    oio_ovl(&o, NULL);
    WSABUF w = {1, (CHAR *)"x"};
    OEQ(U(WSASendTo)(INVALID_SOCKET, &w, 1, &nb, 0, (struct sockaddr *)&to, sizeof to, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTSOCK);
    OEQ(U(WSARecvFrom)(INVALID_SOCKET, &w, 1, &nb, &nb, NULL, NULL, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTSOCK);
}

TEST(oio_udp_sendto_on_connected_socket_ignores_nothing_recorded)
{
    SOCKET a, b; struct sockaddr_in aa, ba; DWORD nb = 0; UP(); UDPAIR(a, b, aa, ba);
    OEQ(U(connect)(a, (struct sockaddr *)&ba, sizeof ba), 0);
    WSAOVERLAPPED o; HANDLE ev = oio_event(); oio_ovl(&o, ev);
    WSABUF w = {2, (CHAR *)"cs"};
    int rc = U(WSASendTo)(a, &w, 1, &nb, 0, NULL, 0, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    char got[4];
    fd_set r; struct timeval tv = {3, 0}; FD_ZERO(&r); FD_SET(b, &r);
    OEQ(U(select)(0, &r, NULL, NULL, &tv), 1);
    OEQ(U(recv)(b, got, 4, 0), 2);
    oio_close2(a, b); CloseHandle(ev);
}

/* ---- WSASendMsg / WSARecvMsg ------------------------------------------------------------- */
static LPFN_WSARECVMSG get_recvmsg(SOCKET s)
{
    GUID g = WSAID_WSARECVMSG; LPFN_WSARECVMSG f = NULL; DWORD n = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &n, NULL, NULL)) return NULL;
    return f;
}

TEST(oio_msg_extension_pointer_obtained)
{
    SOCKET a; DWORD n = 0; GUID g = WSAID_WSARECVMSG; LPFN_WSARECVMSG f = NULL; UP();
    a = oio_sock(SOCK_DGRAM, IPPROTO_UDP); REQUIRE(a != INVALID_SOCKET);
    OEQ(U(WSAIoctl)(a, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &n, NULL, NULL), 0);
    OEQ(n, sizeof f); CHECK(f != NULL);
    U(closesocket)(a);
}

TEST(oio_msg_recvmsg_overlapped_pends_and_reports_source)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; WSAOVERLAPPED o; char buf[16]; DWORD bytes = 0, f2, nb = 0; int err; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    LPFN_WSARECVMSG rm = get_recvmsg(a); REQUIRE(rm);
    WSABUF d = {sizeof buf, buf}; WSAMSG m; memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&from; m.namelen = sizeof from; m.lpBuffers = &d; m.dwBufferCount = 1;
    oio_ovl(&o, ev);
    OEQ(rm(a, &m, NULL, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    udp_to(b, &aa, "msg!", 4);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 4);
    OEQ(m.namelen, sizeof from); OEQ(from.sin_port, ba.sin_port); OEQ(m.dwFlags, 0);
    CHECK(!memcmp(buf, "msg!", 4));
    oio_close2(a, b); CloseHandle(ev);
}

/* Control buffer too small for the requested packet info: failure WSAEMSGSIZE, MSG_CTRUNC, overflow status. */
TEST(oio_msg_recvmsg_control_truncated)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; WSAOVERLAPPED o; char buf[16]; char ctl[1]; DWORD bytes = 0, f2 = 0xdeadbeef; HANDLE ev = oio_event();
    int on = 1;
    UP(); UDPAIR(a, b, aa, ba);
    LPFN_WSARECVMSG rm = get_recvmsg(a); REQUIRE(rm);
    REQUIRE(U(setsockopt)(a, IPPROTO_IP, IP_PKTINFO, (char *)&on, sizeof on) == 0);
    WSABUF d = {sizeof buf, buf}; WSAMSG m; memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&from; m.namelen = sizeof from; m.lpBuffers = &d; m.dwBufferCount = 1;
    m.Control.buf = ctl; m.Control.len = sizeof ctl;
    oio_ovl_sentinel(&o, ev);
    OEQ(rm(a, &m, NULL, &o, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    udp_to(b, &aa, "ctl", 3);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_BUFFER_OVERFLOW); OEQ(o.InternalHigh, 3);
    OEQ(U(WSAGetOverlappedResult)(a, &o, &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSAEMSGSIZE);
    OEQ(bytes, 3);
    if (f2 != 0xdeadbeef) t_note("flags variable written after control truncation");
    OEQ(m.dwFlags, MSG_CTRUNC);
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_msg_recvmsg_pktinfo_control_delivered)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; WSAOVERLAPPED o; char buf[16]; char ctl[128]; DWORD bytes = 0, f2; int err; HANDLE ev = oio_event();
    int on = 1;
    UP(); UDPAIR(a, b, aa, ba);
    LPFN_WSARECVMSG rm = get_recvmsg(a); REQUIRE(rm);
    REQUIRE(U(setsockopt)(a, IPPROTO_IP, IP_PKTINFO, (char *)&on, sizeof on) == 0);
    WSABUF d = {sizeof buf, buf}; WSAMSG m; memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&from; m.namelen = sizeof from; m.lpBuffers = &d; m.dwBufferCount = 1;
    m.Control.buf = ctl; m.Control.len = sizeof ctl;
    oio_ovl(&o, ev);
    OEQ(rm(a, &m, NULL, &o, NULL), SOCKET_ERROR);
    udp_to(b, &aa, "pi", 2);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 2);
    CHECK(m.Control.len >= sizeof(WSACMSGHDR) + sizeof(IN_PKTINFO));
    WSACMSGHDR *h = WSA_CMSG_FIRSTHDR(&m);
    REQUIRE(h != NULL);
    OEQ(h->cmsg_level, IPPROTO_IP); OEQ(h->cmsg_type, IP_PKTINFO);
    IN_PKTINFO *pi = (IN_PKTINFO *)WSA_CMSG_DATA(h);
    OEQ(pi->ipi_addr.s_addr, oio_lo().sin_addr.s_addr);
    oio_close2(a, b); CloseHandle(ev);
}

/* Data truncation through WSARecvMsg: recorded flag layout. */
TEST(oio_msg_recvmsg_data_truncated)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; WSAOVERLAPPED o; char buf[2]; DWORD bytes = 0, f2 = 0; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    LPFN_WSARECVMSG rm = get_recvmsg(a); REQUIRE(rm);
    WSABUF d = {sizeof buf, buf}; WSAMSG m; memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&from; m.namelen = sizeof from; m.lpBuffers = &d; m.dwBufferCount = 1;
    oio_ovl(&o, ev);
    OEQ(rm(a, &m, NULL, &o, NULL), SOCKET_ERROR);
    udp_to(b, &aa, "toolong", 7);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    OEQ(o.Internal, OIO_STATUS_BUFFER_OVERFLOW);
    OEQ(U(WSAGetOverlappedResult)(a, &o, &bytes, FALSE, &f2), FALSE);
    OEQ(WERR(), WSAEMSGSIZE);
    t_note("RecvMsg data truncation: msg.dwFlags 0x%lx", m.dwFlags);
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_msg_recvmsg_on_tcp_recorded)
{
    SOCKET c, s; UP(); PAIR(c, s);
    LPFN_WSARECVMSG rm = get_recvmsg(c);
    if (!rm) { t_note("no WSARecvMsg pointer for TCP socket (err %d)", WERR()); oio_close2(c, s); return; }
    char buf[4]; WSABUF d = {sizeof buf, buf}; WSAMSG m; memset(&m, 0, sizeof m);
    m.lpBuffers = &d; m.dwBufferCount = 1;
    WSAOVERLAPPED o; DWORD nb = 0; HANDLE ev = oio_event(); oio_ovl(&o, ev);
    oio_send(s, "t", 1); Sleep(50);
    int rc = rm(c, &m, &nb, &o, NULL);
    t_note("WSARecvMsg on TCP: rc %d err %d", rc, rc ? WERR() : 0);
    if (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING) { CancelIoEx((HANDLE)c, &o); oio_wait(ev, 1000); }
    oio_close2(c, s); CloseHandle(ev);
}

TEST(oio_msg_sendmsg_zero_socket_einval)
{
    WSAMSG m; DWORD nb = 0; UP();
    memset(&m, 0, sizeof m);
    OEQ(U(WSASendMsg)(0, &m, 0, &nb, NULL, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAEINVAL);
}

TEST(oio_msg_sendmsg_invalid_socket_notsock)
{
    WSAMSG m; DWORD nb = 0; UP();
    memset(&m, 0, sizeof m);
    OEQ(U(WSASendMsg)(INVALID_SOCKET, &m, 0, &nb, NULL, NULL), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTSOCK);
}

TEST(oio_msg_sendmsg_overlapped_udp_delivers)
{
    SOCKET a, b; struct sockaddr_in aa, ba; WSAOVERLAPPED o; WSABUF d[2] = { {2, (CHAR *)"sm"}, {3, (CHAR *)"sg!"} }; char got[8];
    DWORD nb = 0, bytes, f2; int err; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    WSAMSG m; memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&ba; m.namelen = sizeof ba; m.lpBuffers = d; m.dwBufferCount = 2;
    oio_ovl(&o, ev);
    int rc = U(WSASendMsg)(a, &m, 0, &nb, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(a, &o, &bytes, &f2, &err)); OEQ(bytes, 5);
    OEQ(U(recv)(b, got, sizeof got, 0), 5);
    CHECK(!memcmp(got, "smsg!", 5));
    oio_close2(a, b); CloseHandle(ev);
}

TEST(oio_msg_sendmsg_no_destination_recorded)
{
    SOCKET a; WSABUF d = {1, (CHAR *)"x"}; DWORD nb = 0; UP();
    a = oio_sock(SOCK_DGRAM, IPPROTO_UDP); REQUIRE(a != INVALID_SOCKET);
    WSAMSG m; memset(&m, 0, sizeof m);
    m.lpBuffers = &d; m.dwBufferCount = 1;
    int rc = U(WSASendMsg)(a, &m, 0, &nb, NULL, NULL);
    CHECK(rc == SOCKET_ERROR);
    t_note("WSASendMsg without destination on unconnected UDP: err %d", WERR());
    U(closesocket)(a);
}

TEST(oio_msg_sendmsg_with_routine_runs_alertable)
{
    SOCKET a, b; struct sockaddr_in aa, ba; WSAOVERLAPPED o; WSABUF d = {3, (CHAR *)"rtn"}; DWORD nb = 0; char got[4];
    UP(); UDPAIR(a, b, aa, ba);
    oio_cr_reset(); oio_ovl(&o, NULL);
    WSAMSG m; memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&ba; m.namelen = sizeof ba; m.lpBuffers = &d; m.dwBufferCount = 1;
    int rc = U(WSASendMsg)(a, &m, 0, &nb, &o, oio_cr);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    OEQ(SleepEx(OIO_WAIT, TRUE), WAIT_IO_COMPLETION);
    OEQ(g_cr.calls, 1); OEQ(g_cr.bytes, 3); OEQ(g_cr.err, 0);
    OEQ(U(recv)(b, got, sizeof got, 0), 3);
    oio_close2(a, b);
}

TEST(oio_msg_sendmsg_on_tcp_recorded)
{
    SOCKET c, s; WSABUF d = {2, (CHAR *)"tc"}; DWORD nb = 0; UP(); PAIR(c, s);
    WSAMSG m; memset(&m, 0, sizeof m);
    m.lpBuffers = &d; m.dwBufferCount = 1;
    int rc = U(WSASendMsg)(c, &m, 0, &nb, NULL, NULL);
    t_note("WSASendMsg on connected TCP: rc %d err %d bytes %lu", rc, rc ? WERR() : 0, nb);
    oio_close2(c, s);
}

/* Out-of-band is not a valid receive flag for a datagram socket's WSARecvFrom: WSAEOPNOTSUPP before any request. */
TEST(oio_udp_recvfrom_oob_flag_opnotsupp)
{
    SOCKET a, b; struct sockaddr_in aa, ba, from; INT alen = sizeof from; char buf[4]; DWORD fl = MSG_OOB, nb = 0; WSAOVERLAPPED o; HANDLE ev = oio_event();
    UP(); UDPAIR(a, b, aa, ba);
    WSABUF w = {sizeof buf, buf};
    oio_ovl_sentinel(&o, ev);
    int rc = U(WSARecvFrom)(a, &w, 1, &nb, &fl, (struct sockaddr *)&from, &alen, &o, NULL);
    t_check(rc == SOCKET_ERROR && WERR() == WSAEOPNOTSUPP, __FILE__, __LINE__, "OOB recvfrom", "rc %d err %d", rc, WERR());
    OEQ(o.Internal, OIO_SENTINEL);
    oio_close2(a, b); CloseHandle(ev);
}
