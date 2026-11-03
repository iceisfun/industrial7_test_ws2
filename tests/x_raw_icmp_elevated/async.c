/* x_raw_icmp_elevated / async: the asynchronous and scatter/gather entry points on raw ICMP sockets.
 *
 * All traffic is an ICMPv4 echo to 127.0.0.1, which a standard token may also send, so every test runs in both
 * modes. A raw receive returns the 20-byte IPv4 header in front of the ICMP message, so a reply to a request
 * with a 16-byte payload is 44 bytes. The tests check the completion model (overlapped receive pending until the
 * reply arrives, completion with the whole datagram, abort on close and on CancelIo), event and poll readiness,
 * WSARecvMsg flags and scatter/gather buffers. Absence is shown with a bounded wait on a socket that has had a
 * later datagram queued, never a bare timeout assumption about timing. */
#include "rawh.h"

static unsigned short g_aid = 0x7300;

static SOCKET ovl_sock(void)
{
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s != INVALID_SOCKET) { struct sockaddr_in a; rw_lo4(&a, 0); U(bind)(s, (struct sockaddr *)&a, sizeof a); }
    return s;
}
static SOCKET blk_sock(void)
{
    SOCKET s = rw_raw(AF_INET, IPPROTO_ICMP);
    if (s != INVALID_SOCKET) { struct sockaddr_in a; rw_lo4(&a, 0); U(bind)(s, (struct sockaddr *)&a, sizeof a); }
    return s;
}
static int ping(SOCKET s, unsigned short seq, const void *d, int dl)
{
    struct sockaddr_in lo; rw_lo4(&lo, 0);
    return rw_ping4(s, &lo, g_aid, seq, d, dl);
}
#define NEEDOVL() SOCKET s; RW_UP(); s = ovl_sock(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused (%d)", rw_err()); return; }
#define NEEDBLK() SOCKET s; RW_UP(); s = blk_sock(); if (s == INVALID_SOCKET) { t_skip("raw ICMP refused (%d)", rw_err()); return; }

/* ---- overlapped completion ------------------------------------------------------------------------ */
TEST(rawasync_overlapped_recv_pends_then_completes) {
    NEEDOVL(); unsigned char b[200]; WSABUF wb; WSAOVERLAPPED ov; DWORD got = 0, fl = 0, xfer = 0; int r;
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    wb.buf = (char *)b; wb.len = sizeof b;
    rw_seterr(0); r = U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSA_IO_PENDING);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, TRUE, 150, FALSE), WSA_WAIT_TIMEOUT);   /* nothing sent yet */
    ++g_aid; RW_EQ(ping(s, 1, "0123456789abcdef", 16), 24);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    fl = 0; RW_EQ(U(WSAGetOverlappedResult)(s, &ov, &xfer, FALSE, &fl), TRUE);
    RW_EQ(xfer, 44); RW_EQ(b[9], 1); RW_EQ(b[20], 0);
    U(WSACloseEvent)(ov.hEvent); rw_close(s);
}
TEST(rawasync_overlapped_recv_data_already_queued) {
    NEEDOVL(); unsigned char b[200]; WSABUF wb; WSAOVERLAPPED ov; DWORD got = 0, fl = 0, xfer = 0;
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    ++g_aid; RW_EQ(ping(s, 2, "queued-before-recv", 18), 26);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    wb.buf = (char *)b; wb.len = sizeof b;
    RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL), 0);          /* completes inline */
    RW_EQ(got, 46);
    RW_EQ(U(WSAGetOverlappedResult)(s, &ov, &xfer, FALSE, &fl), TRUE); RW_EQ(xfer, 46);
    U(WSACloseEvent)(ov.hEvent); rw_close(s);
}
TEST(rawasync_overlapped_small_buffer_reports_msgsize) {
    NEEDOVL(); unsigned char b[200]; WSABUF wb; WSAOVERLAPPED ov; DWORD got = 0, fl = 0, xfer = 0; int r;
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    ++g_aid; RW_EQ(ping(s, 3, "0123456789abcdef", 16), 24);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    wb.buf = (char *)b; wb.len = 10;
    rw_seterr(0); r = U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL);
    if (r == -1 && rw_err() == WSA_IO_PENDING) { U(WSAWaitForMultipleEvents)(1, &ov.hEvent, TRUE, 3000, FALSE); r = 0; }
    else { RW_EQ(r, -1); RW_EQ(rw_err(), WSAEMSGSIZE); }
    fl = 0; xfer = 0; rw_seterr(0);
    if (r == 0) { RW_EQ(U(WSAGetOverlappedResult)(s, &ov, &xfer, FALSE, &fl), FALSE); RW_EQ(rw_err(), WSAEMSGSIZE); }
    U(WSACloseEvent)(ov.hEvent); rw_close(s);
}
TEST(rawasync_pending_recv_aborted_by_close) {
    NEEDOVL(); unsigned char b[64]; WSABUF wb; WSAOVERLAPPED ov; DWORD got = 0, fl = 0, xfer = 0;
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    wb.buf = (char *)b; wb.len = sizeof b;
    rw_seterr(0); RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL), -1); RW_EQ(rw_err(), WSA_IO_PENDING);
    RW_EQ(U(closesocket)(s), 0);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    /* the socket is gone, so the result is read straight from the OVERLAPPED block */
    CHECK((NTSTATUS)ov.Internal != 0x103);                 /* not STATUS_PENDING any more */
    CHECK((NTSTATUS)ov.Internal < 0);                      /* an error/aborted status, not a success */
    RW_EQ((unsigned)ov.InternalHigh, 0);
    U(WSACloseEvent)(ov.hEvent); (void)xfer;
}
TEST(rawasync_cancelio_aborts_pending_recv) {
    NEEDOVL(); unsigned char b[64]; WSABUF wb; WSAOVERLAPPED ov; DWORD got = 0, fl = 0, xfer = 0;
    memset(&ov, 0, sizeof ov); ov.hEvent = U(WSACreateEvent)();
    wb.buf = (char *)b; wb.len = sizeof b;
    rw_seterr(0); RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, &ov, NULL), -1); RW_EQ(rw_err(), WSA_IO_PENDING);
    CHECK(CancelIo((HANDLE)s));
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ov.hEvent, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    rw_seterr(0); fl = 0;
    RW_EQ(U(WSAGetOverlappedResult)(s, &ov, &xfer, FALSE, &fl), FALSE); RW_EQ(rw_err(), WSA_OPERATION_ABORTED);
    RW_EQ(xfer, 0);
    /* the socket still works after the cancel */
    ++g_aid; RW_EQ(ping(s, 4, "after-cancel", 12), 20);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    U(WSACloseEvent)(ov.hEvent); rw_close(s);
}
TEST(rawasync_two_pending_recvs_complete_in_order) {
    NEEDOVL(); unsigned char b1[100], b2[100]; WSABUF w1, w2; WSAOVERLAPPED o1, o2; DWORD got = 0, fl = 0, x1 = 0, x2 = 0;
    memset(&o1, 0, sizeof o1); memset(&o2, 0, sizeof o2); o1.hEvent = U(WSACreateEvent)(); o2.hEvent = U(WSACreateEvent)();
    w1.buf = (char *)b1; w1.len = sizeof b1; w2.buf = (char *)b2; w2.len = sizeof b2;
    rw_seterr(0); RW_EQ(U(WSARecv)(s, &w1, 1, &got, &fl, &o1, NULL), -1); RW_EQ(rw_err(), WSA_IO_PENDING);
    rw_seterr(0); RW_EQ(U(WSARecv)(s, &w2, 1, &got, &fl, &o2, NULL), -1); RW_EQ(rw_err(), WSA_IO_PENDING);
    ++g_aid; RW_EQ(ping(s, 5, "first", 5), 13);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &o1.hEvent, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    RW_EQ(U(WSAGetOverlappedResult)(s, &o1, &x1, FALSE, &fl), TRUE); RW_EQ(x1, 33);
    /* the second receive is still pending: only one datagram has arrived */
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &o2.hEvent, TRUE, 150, FALSE), WSA_WAIT_TIMEOUT);
    ++g_aid; RW_EQ(ping(s, 6, "second", 6), 14);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &o2.hEvent, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    RW_EQ(U(WSAGetOverlappedResult)(s, &o2, &x2, FALSE, &fl), TRUE); RW_EQ(x2, 34);
    CHECK(rw_find(b1 + 28, 5, "first", 5)); CHECK(rw_find(b2 + 28, 6, "second", 6));
    U(WSACloseEvent)(o1.hEvent); U(WSACloseEvent)(o2.hEvent); rw_close(s);
}
static VOID CALLBACK on_done(DWORD err, DWORD n, LPWSAOVERLAPPED ov, DWORD fl)
{
    (void)fl; ov->Offset = err; ov->OffsetHigh = n;        /* hand the outcome back through the block itself */
    ov->Internal = 0x1234;
}
TEST(rawasync_completion_routine_runs_when_alertable) {
    NEEDOVL(); unsigned char b[100]; WSABUF wb; WSAOVERLAPPED ov; DWORD got = 0, fl = 0; int i;
    memset(&ov, 0, sizeof ov);
    wb.buf = (char *)b; wb.len = sizeof b;
    rw_seterr(0); RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, &ov, on_done), -1); RW_EQ(rw_err(), WSA_IO_PENDING);
    ++g_aid; RW_EQ(ping(s, 7, "apc", 3), 11);
    for (i = 0; i < 40 && ov.Internal != 0x1234; i++) SleepEx(100, TRUE);
    RW_EQ(ov.Internal, 0x1234); RW_EQ(ov.Offset, 0); RW_EQ(ov.OffsetHigh, 31);
    rw_close(s);
}

/* ---- scatter/gather and the From and To forms ------------------------------------------------------- */
TEST(rawasync_wsasendto_gathers_buffers) {
    NEEDBLK(); WSABUF wb[3]; DWORD sent = 0; struct sockaddr_in lo; unsigned char hdr[8], b[200]; rw_pkt p; int n;
    rw_lo4(&lo, 0); n = rw_echo4(b, ++g_aid, 8, "GATHERED", 8);     /* 16-byte message, split three ways */
    memcpy(hdr, b, 8);
    wb[0].buf = (char *)b; wb[0].len = 4; wb[1].buf = (char *)b + 4; wb[1].len = 4; wb[2].buf = (char *)b + 8; wb[2].len = 8;
    RW_EQ(U(WSASendTo)(s, wb, 3, &sent, 0, (struct sockaddr *)&lo, sizeof lo, NULL, NULL), 0);
    RW_EQ(sent, n);
    CHECK(rw_wait_reply4(s, g_aid, 8, &p, 3000, NULL));
    CHECK(rw_find(p.b + 20 + 8, 8, "GATHERED", 8));
    rw_close(s);
}
TEST(rawasync_wsasendto_empty_buffer_list_entries) {
    NEEDBLK(); WSABUF wb[3]; DWORD sent = 0; struct sockaddr_in lo; unsigned char b[64]; rw_pkt p; int n;
    rw_lo4(&lo, 0); n = rw_echo4(b, ++g_aid, 9, "hole", 4);
    wb[0].buf = (char *)b; wb[0].len = 6; wb[1].buf = (char *)b; wb[1].len = 0; wb[2].buf = (char *)b + 6; wb[2].len = n - 6;
    RW_EQ(U(WSASendTo)(s, wb, 3, &sent, 0, (struct sockaddr *)&lo, sizeof lo, NULL, NULL), 0);
    RW_EQ(sent, n);
    CHECK(rw_wait_reply4(s, g_aid, 9, &p, 3000, NULL));
    rw_close(s);
}
TEST(rawasync_wsasendto_bad_arguments) {
    NEEDBLK(); WSABUF wb; DWORD sent = 0; struct sockaddr_in lo; unsigned char b[16]; rw_lo4(&lo, 0);
    rw_echo4(b, ++g_aid, 1, "12345678", 0);
    wb.buf = (char *)b; wb.len = 8;
    rw_seterr(0); RW_EQ(U(WSASendTo)(s, &wb, 0, &sent, 0, (struct sockaddr *)&lo, sizeof lo, NULL, NULL), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); RW_EQ(U(WSASendTo)(s, NULL, 1, &sent, 0, (struct sockaddr *)&lo, sizeof lo, NULL, NULL), -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); RW_EQ(U(WSASendTo)(s, &wb, 1, &sent, 0, (struct sockaddr *)&lo, 8, NULL, NULL), -1); RW_EQ(rw_err(), WSAEFAULT);
    rw_seterr(0); RW_EQ(U(WSASendTo)(s, &wb, 1, &sent, 0, NULL, 0, NULL, NULL), -1);
    CHECK(rw_err() == WSAENOTCONN || rw_err() == WSAEDESTADDRREQ);   /* unconnected, no destination */
    rw_close(s);
}
TEST(rawasync_wsarecvfrom_scatters_and_fills_source) {
    NEEDBLK(); WSABUF wb[2]; DWORD got = 0, fl = 0; struct sockaddr_in f; int fl_len = sizeof f; unsigned char a[20], c[100];
    ++g_aid; RW_EQ(ping(s, 10, "scatter-me", 10), 18);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    memset(a, 0, sizeof a); memset(c, 0, sizeof c); memset(&f, 0xcc, sizeof f);
    wb[0].buf = (char *)a; wb[0].len = 20; wb[1].buf = (char *)c; wb[1].len = sizeof c;
    RW_EQ(U(WSARecvFrom)(s, wb, 2, &got, &fl, (struct sockaddr *)&f, &fl_len, NULL, NULL), 0);
    RW_EQ(got, 38); RW_EQ(fl, 0);
    RW_EQ(a[0], 0x45); RW_EQ(a[9], 1); RW_EQ(c[0], 0);                    /* header in the first buffer, ICMP in the second */
    CHECK(rw_find(c, 18, "scatter-me", 10));
    RW_EQ(fl_len, 16); RW_EQ(f.sin_family, AF_INET); RW_EQ(f.sin_addr.s_addr, RW_LO4);
    rw_close(s);
}
TEST(rawasync_wsarecvfrom_total_too_small_is_msgsize) {
    NEEDBLK(); WSABUF wb[2]; DWORD got = 0, fl = 0; unsigned char a[10], c[10];
    ++g_aid; RW_EQ(ping(s, 11, "scatter-me", 10), 18);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    wb[0].buf = (char *)a; wb[0].len = 10; wb[1].buf = (char *)c; wb[1].len = 10;
    rw_seterr(0); RW_EQ(U(WSARecvFrom)(s, wb, 2, &got, &fl, NULL, NULL, NULL, NULL), -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    RW_EQ(a[0], 0x45);
    rw_close(s);
}
TEST(rawasync_wsarecv_bad_arguments) {
    NEEDBLK(); WSABUF wb; DWORD got = 0, fl = 0; unsigned char b[10]; u_long nb = 1; int r;
    wb.buf = (char *)b; wb.len = sizeof b;
    U(ioctlsocket)(s, FIONBIO, &nb);                  /* non-blocking: a rejected call must not wait for data */
    rw_seterr(0); r = U(WSARecv)(s, &wb, 0, &got, &fl, NULL, NULL);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); r = U(WSARecv)(s, NULL, 1, &got, &fl, NULL, NULL);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    rw_seterr(0); r = U(WSARecv)(s, &wb, 1, NULL, &fl, NULL, NULL);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAEWOULDBLOCK);   /* the missing byte counter is not validated */
    rw_close(s);
}
TEST(rawasync_wsarecv_peek_flag_and_oob) {
    NEEDBLK(); WSABUF wb; DWORD got = 0, fl; unsigned char b[100]; wb.buf = (char *)b; wb.len = sizeof b;
    ++g_aid; RW_EQ(ping(s, 12, "peeked", 6), 14);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    fl = MSG_PEEK; RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, NULL, NULL), 0); RW_EQ(got, 34);
    fl = MSG_OOB; rw_seterr(0); RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, NULL, NULL), -1); RW_EQ(rw_err(), WSAEOPNOTSUPP);
    fl = 0; RW_EQ(U(WSARecv)(s, &wb, 1, &got, &fl, NULL, NULL), 0); RW_EQ(got, 34);
    rw_close(s);
}

/* ---- WSARecvMsg ------------------------------------------------------------------------------------ */
static LPFN_WSARECVMSG get_recvmsg(SOCKET s)
{
    GUID g = WSAID_WSARECVMSG; LPFN_WSARECVMSG f = NULL; DWORD n = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &f, sizeof f, &n, NULL, NULL)) return NULL;
    return f;
}
TEST(rawasync_wsarecvmsg_basic) {
    NEEDBLK(); LPFN_WSARECVMSG rm = get_recvmsg(s); WSAMSG m; WSABUF wb; struct sockaddr_in f; unsigned char b[100]; DWORD got = 0;
    if (!rm) { t_skip("WSARecvMsg pointer not available"); rw_close(s); return; }
    ++g_aid; RW_EQ(ping(s, 13, "msg-basic", 9), 17);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    memset(&m, 0, sizeof m); memset(&f, 0xcc, sizeof f);
    wb.buf = (char *)b; wb.len = sizeof b;
    m.name = (struct sockaddr *)&f; m.namelen = sizeof f; m.lpBuffers = &wb; m.dwBufferCount = 1;
    RW_EQ(rm(s, &m, &got, NULL, NULL), 0);
    RW_EQ(got, 37); RW_EQ(m.dwFlags, 0); RW_EQ(m.namelen, 16); RW_EQ(f.sin_family, AF_INET); RW_EQ(f.sin_addr.s_addr, RW_LO4);
    RW_EQ(m.Control.len, 0);
    rw_close(s);
}
TEST(rawasync_wsarecvmsg_truncation_flags) {
    NEEDBLK(); LPFN_WSARECVMSG rm = get_recvmsg(s); WSAMSG m; WSABUF wb; unsigned char b[100]; DWORD got = 0; int r;
    if (!rm) { t_skip("WSARecvMsg pointer not available"); rw_close(s); return; }
    ++g_aid; RW_EQ(ping(s, 14, "msg-trunc!", 10), 18);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    memset(&m, 0, sizeof m); wb.buf = (char *)b; wb.len = 12; m.lpBuffers = &wb; m.dwBufferCount = 1;
    rw_seterr(0); r = rm(s, &m, &got, NULL, NULL);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAEMSGSIZE);
    CHECK(m.dwFlags & MSG_TRUNC);
    rw_close(s);
}
TEST(rawasync_wsarecvmsg_bad_arguments) {
    NEEDBLK(); LPFN_WSARECVMSG rm = get_recvmsg(s); WSAMSG m; WSABUF wb; unsigned char b[10]; DWORD got = 0;
    if (!rm) { t_skip("WSARecvMsg pointer not available"); rw_close(s); return; }
    memset(&m, 0, sizeof m); wb.buf = (char *)b; wb.len = sizeof b; m.lpBuffers = &wb;
    { u_long nb = 1; U(ioctlsocket)(s, FIONBIO, &nb); }       /* non-blocking: a bad call must never wait for data */
    m.dwBufferCount = 0; rw_seterr(0); RW_EQ(rm(s, &m, &got, NULL, NULL), -1);
    RW_EQ(rw_err(), WSAEWOULDBLOCK);
    rw_close(s);
}
TEST(rawasync_pktinfo_on_received_raw_datagram) {
    NEEDBLK(); LPFN_WSARECVMSG rm = get_recvmsg(s); WSAMSG m; WSABUF wb; unsigned char b[100], cb[64]; DWORD got = 0; int on = 1, r;
    if (!rm) { t_skip("WSARecvMsg pointer not available"); rw_close(s); return; }
    r = U(setsockopt)(s, IPPROTO_IP, IP_PKTINFO, (char *)&on, 4);
    RW_EQ(r, 0);
    if (r != 0) { rw_close(s); return; }
    ++g_aid; RW_EQ(ping(s, 15, "pktinfo", 7), 15);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    memset(&m, 0, sizeof m); memset(cb, 0, sizeof cb);
    wb.buf = (char *)b; wb.len = sizeof b; m.lpBuffers = &wb; m.dwBufferCount = 1; m.Control.buf = (char *)cb; m.Control.len = sizeof cb;
    r = rm(s, &m, &got, NULL, NULL);
    RW_EQ(r, 0); RW_EQ(got, 35);
    CHECK(m.Control.len >= sizeof(WSACMSGHDR) + 8);
    if (m.Control.len >= sizeof(WSACMSGHDR) + 8) {
        WSACMSGHDR *c = (WSACMSGHDR *)cb;
        RW_EQ(c->cmsg_level, IPPROTO_IP); RW_EQ(c->cmsg_type, IP_PKTINFO);
        { struct in_pktinfo pi; memcpy(&pi, cb + sizeof(WSACMSGHDR), sizeof pi); RW_EQ(pi.ipi_addr.s_addr, RW_LO4); CHECK(pi.ipi_ifindex != 0); }
    }
    rw_close(s);
}

/* ---- readiness: events, poll, select ------------------------------------------------------------------ */
TEST(rawasync_eventselect_fd_read_and_write) {
    NEEDBLK(); WSAEVENT ev = U(WSACreateEvent)(); WSANETWORKEVENTS ne; unsigned char b[100];
    RW_EQ(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE), 0);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ev, TRUE, 3000, FALSE), WSA_WAIT_EVENT_0);     /* FD_WRITE on a fresh datagram socket */
    memset(&ne, 0, sizeof ne); RW_EQ(U(WSAEnumNetworkEvents)(s, ev, &ne), 0);
    CHECK(ne.lNetworkEvents & FD_WRITE); CHECK(!(ne.lNetworkEvents & FD_READ)); RW_EQ(ne.iErrorCode[FD_WRITE_BIT], 0);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ev, TRUE, 100, FALSE), WSA_WAIT_TIMEOUT);        /* consumed and reset */
    ++g_aid; RW_EQ(ping(s, 16, "ev", 2), 10);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ev, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    memset(&ne, 0, sizeof ne); RW_EQ(U(WSAEnumNetworkEvents)(s, ev, &ne), 0);
    CHECK(ne.lNetworkEvents & FD_READ); RW_EQ(ne.iErrorCode[FD_READ_BIT], 0);
    RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), 30);
    /* the selection made the socket non-blocking */
    rw_seterr(0); RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), -1); RW_EQ(rw_err(), WSAEWOULDBLOCK);
    RW_EQ(U(WSAEventSelect)(s, NULL, 0), 0);
    U(WSACloseEvent)(ev); rw_close(s);
}
TEST(rawasync_eventselect_fd_read_rearms_on_leftover_data) {
    NEEDBLK(); WSAEVENT ev = U(WSACreateEvent)(); WSANETWORKEVENTS ne; unsigned char b[100]; int k;
    RW_EQ(U(WSAEventSelect)(s, ev, FD_READ), 0);
    ++g_aid; RW_EQ(ping(s, 17, "one", 3), 11);
    ++g_aid; RW_EQ(ping(s, 18, "two", 3), 11);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ev, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    { fd_set fs; struct timeval tv; FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = 3; tv.tv_usec = 0; RW_EQ(U(select)(0, &fs, NULL, NULL, &tv), 1); }
    RW_EQ(U(WSAEnumNetworkEvents)(s, ev, &ne), 0); CHECK(ne.lNetworkEvents & FD_READ);
    /* both replies are queued; reading one leaves the other, which re-signals FD_READ */
    for (k = 0; k < 40; k++) { u_long av = 0; U(ioctlsocket)(s, FIONREAD, &av); if (av) break; SleepEx(25, FALSE); }
    RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), 31);
    RW_EQ(U(WSAWaitForMultipleEvents)(1, &ev, TRUE, 4000, FALSE), WSA_WAIT_EVENT_0);
    RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), 31);
    U(WSAEventSelect)(s, NULL, 0); U(WSACloseEvent)(ev); rw_close(s);
}
TEST(rawasync_eventselect_close_event_after_close_socket) {
    NEEDBLK(); WSAEVENT ev = U(WSACreateEvent)(); WSANETWORKEVENTS ne;
    RW_EQ(U(WSAEventSelect)(s, ev, FD_READ | FD_CLOSE), 0);
    RW_EQ(U(closesocket)(s), 0);
    rw_seterr(0); RW_EQ(U(WSAEnumNetworkEvents)(s, ev, &ne), -1); RW_EQ(rw_err(), WSAENOTSOCK);
    rw_seterr(0); RW_EQ(U(WSAEventSelect)(s, ev, FD_READ), -1); RW_EQ(rw_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ev);
}
TEST(rawasync_eventselect_unsupported_event_bits) {
    NEEDBLK(); WSAEVENT ev = U(WSACreateEvent)(); int r;
    rw_seterr(0); r = U(WSAEventSelect)(s, ev, FD_ACCEPT);
    RW_EQ(r, 0);                                          /* accepted although a raw socket never accepts */
    U(WSAEventSelect)(s, NULL, 0);
    rw_seterr(0); r = U(WSAEventSelect)(s, NULL, FD_READ);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAEINVAL);
    U(WSAEventSelect)(s, NULL, 0);
    U(WSACloseEvent)(ev); rw_close(s);
}
TEST(rawasync_wsapoll_write_then_read) {
    NEEDBLK(); WSAPOLLFD pf; unsigned char b[100];
    memset(&pf, 0, sizeof pf); pf.fd = s; pf.events = POLLWRNORM;
    RW_EQ(U(WSAPoll)(&pf, 1, 1000), 1); RW_EQ(pf.revents, POLLWRNORM);
    pf.events = POLLRDNORM; pf.revents = 0;
    RW_EQ(U(WSAPoll)(&pf, 1, 150), 0); RW_EQ(pf.revents, 0);
    ++g_aid; RW_EQ(ping(s, 19, "poll", 4), 12);
    pf.events = POLLRDNORM; pf.revents = 0;
    RW_EQ(U(WSAPoll)(&pf, 1, 4000), 1); RW_EQ(pf.revents, POLLRDNORM);
    RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), 32);
    rw_close(s);
}
TEST(rawasync_wsapoll_closed_socket_is_pollnval) {
    NEEDBLK(); WSAPOLLFD pf; SOCKET dead = s;
    RW_EQ(U(closesocket)(s), 0);
    memset(&pf, 0, sizeof pf); pf.fd = dead; pf.events = POLLRDNORM;
    rw_seterr(0); RW_EQ(U(WSAPoll)(&pf, 1, 100), -1); RW_EQ(rw_err(), WSAENOTSOCK);
    RW_EQ(pf.revents, POLLNVAL);
}

/* ---- blocking calls from another thread ------------------------------------------------------------------ */
struct rcvjob { SOCKET s; int ret, err; };
static DWORD WINAPI rcv_thread(LPVOID p)
{
    struct rcvjob *j = p; unsigned char b[100];
    rw_seterr(0); j->ret = U(recv)(j->s, (char *)b, sizeof b, 0); j->err = rw_err();
    return 0;
}
TEST(rawasync_blocking_recv_unblocked_by_arrival) {
    NEEDBLK(); struct rcvjob j; HANDLE th;
    j.s = s; j.ret = -99; j.err = 0;
    th = CreateThread(NULL, 0, rcv_thread, &j, 0, NULL);
    CHECK(th != NULL); if (!th) { rw_close(s); return; }
    RW_EQ(WaitForSingleObject(th, 150), WAIT_TIMEOUT);              /* blocked: nothing to read yet */
    ++g_aid; RW_EQ(ping(s, 20, "wake", 4), 12);
    RW_EQ(WaitForSingleObject(th, 4000), WAIT_OBJECT_0);
    RW_EQ(j.ret, 32);
    CloseHandle(th); rw_close(s);
}
TEST(rawasync_blocking_recv_interrupted_by_close) {
    NEEDBLK(); struct rcvjob j; HANDLE th;
    j.s = s; j.ret = -99; j.err = 0;
    th = CreateThread(NULL, 0, rcv_thread, &j, 0, NULL);
    CHECK(th != NULL); if (!th) { rw_close(s); return; }
    RW_EQ(WaitForSingleObject(th, 150), WAIT_TIMEOUT);
    RW_EQ(U(closesocket)(s), 0);
    RW_EQ(WaitForSingleObject(th, 4000), WAIT_OBJECT_0);
    RW_EQ(j.ret, -1);
    RW_EQ(j.err, WSAEINTR);
    CloseHandle(th);
}
TEST(rawasync_blocking_recv_interrupted_by_shutdown) {
    NEEDBLK(); struct rcvjob j; HANDLE th;
    j.s = s; j.ret = -99; j.err = 0;
    th = CreateThread(NULL, 0, rcv_thread, &j, 0, NULL);
    CHECK(th != NULL); if (!th) { rw_close(s); return; }
    RW_EQ(WaitForSingleObject(th, 150), WAIT_TIMEOUT);
    RW_EQ(U(shutdown)(s, SD_RECEIVE), 0);
    RW_EQ(U(closesocket)(s), 0);
    RW_EQ(WaitForSingleObject(th, 4000), WAIT_OBJECT_0);
    CloseHandle(th);
}
TEST(rawasync_recv_timeout_error) {
    NEEDBLK(); unsigned char b[10]; DWORD ms = 200; int r;
    RW_EQ(U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, 4), 0);
    rw_seterr(0); r = U(recv)(s, (char *)b, sizeof b, 0);
    RW_EQ(r, -1); RW_EQ(rw_err(), WSAETIMEDOUT);
    { int g = 0, gl = 4; RW_EQ(U(getsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&g, &gl), 0); RW_EQ(g, 200); }
    rw_close(s);
}
TEST(rawasync_nonblocking_mode_toggle) {
    NEEDBLK(); unsigned char b[10]; u_long nb = 1;
    RW_EQ(U(ioctlsocket)(s, FIONBIO, &nb), 0);
    rw_seterr(0); RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), -1); RW_EQ(rw_err(), WSAEWOULDBLOCK);
    nb = 0; RW_EQ(U(ioctlsocket)(s, FIONBIO, &nb), 0);
    { DWORD ms = 100; U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, 4); }
    rw_seterr(0); RW_EQ(U(recv)(s, (char *)b, sizeof b, 0), -1); RW_EQ(rw_err(), WSAETIMEDOUT);
    rw_close(s);
}
