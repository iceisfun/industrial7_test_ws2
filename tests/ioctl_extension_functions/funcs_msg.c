/* WSARecvMsg and WSASendMsg reached through the looked-up pointers, on loopback datagram sockets: message
 * header validation, flag masks, source address reporting, scatter/gather, peek, truncation.
 *
 * Facts from the provider: the receive path rejects a header whose name pointer and name length disagree about
 * being present, likewise the control buffer, and any flag bit except MSG_PEEK; the send path rejects every
 * flag bit except 0x1 0x4 0x40 0x8000 with WSAEOPNOTSUPP. */
#include "xf.h"

typedef INT (WINAPI *recvmsg_fn)(SOCKET, LPWSAMSG, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef INT (WINAPI *sendmsg_fn)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static recvmsg_fn get_rm(void) { GUID g = WSAID_WSARECVMSG; return (recvmsg_fn)xf_fn_udp(&g); }
static sendmsg_fn get_sm(void) { GUID g = WSAID_WSASENDMSG; return (sendmsg_fn)xf_fn_udp(&g); }
#define NEED_RM(f) recvmsg_fn f = get_rm(); do { if (!f) { t_skip("WSARecvMsg unavailable"); return; } } while (0)
#define NEED_SM(f) sendmsg_fn f = get_sm(); do { if (!f) { t_skip("WSASendMsg unavailable"); return; } } while (0)

/* Two bound loopback datagram sockets: rx (receiver) and tx (sender). */
struct dg { SOCKET rx, tx; struct sockaddr_in rxa, txa; };
static int dg_open(struct dg *d)
{
    int len = sizeof d->rxa;
    d->rx = d->tx = INVALID_SOCKET;
    if (!xf_up()) return 0;
    d->rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    d->tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (d->rx == INVALID_SOCKET || d->tx == INVALID_SOCKET) return 0;
    xf_loop4(&d->rxa); xf_loop4(&d->txa);
    if (bind(d->rx, (struct sockaddr *)&d->rxa, sizeof d->rxa) || getsockname(d->rx, (struct sockaddr *)&d->rxa, &len)) return 0;
    len = sizeof d->txa;
    if (bind(d->tx, (struct sockaddr *)&d->txa, sizeof d->txa) || getsockname(d->tx, (struct sockaddr *)&d->txa, &len)) return 0;
    return 1;
}
static void dg_close(struct dg *d)
{
    if (d->rx != INVALID_SOCKET) closesocket(d->rx);
    if (d->tx != INVALID_SOCKET) closesocket(d->tx);
}
#define DG(d) struct dg d; do { if (!dg_open(&d)) { dg_close(&d); t_skip("datagram sockets unavailable"); return; } } while (0)

static int send_to_rx(struct dg *d, const void *p, int n)
{
    return sendto(d->tx, (const char *)p, n, 0, (struct sockaddr *)&d->rxa, sizeof d->rxa);
}

static void msg_init(WSAMSG *m, struct sockaddr_in *name, int namelen, WSABUF *bufs, DWORD nb)
{
    memset(m, 0, sizeof *m);
    m->name = (LPSOCKADDR)name; m->namelen = namelen;
    m->lpBuffers = bufs; m->dwBufferCount = nb;
}

/* ---- WSARecvMsg ------------------------------------------------------------------------------------------------ */

TEST(xf_recvmsg_invalid_socket_is_notsock)
{
    WSAMSG m; WSABUF b; char buf[8]; DWORD n = 0;
    NEED_NET(); NEED_RM(rm);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECK(rm(INVALID_SOCKET, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_recvmsg_closed_socket_is_notsock)
{
    WSAMSG m; WSABUF b; char buf[8]; DWORD n = 0; SOCKET s;
    NEED_NET(); NEED_RM(rm);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    closesocket(s);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECK(rm(s, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_recvmsg_unbound_socket_is_einval)
{
    WSAMSG m; WSABUF b; char buf[8]; DWORD n = 0; SOCKET s;
    NEED_NET(); NEED_RM(rm);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    { u_long one = 1; ioctlsocket(s, FIONBIO, &one); }
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECK(rm(s, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    closesocket(s);
}
TEST(xf_recvmsg_reports_data_source_and_name_length)
{
    WSAMSG m; WSABUF b; char buf[32]; DWORD n = 0; struct sockaddr_in from; int r;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "hello msg", 9) == 9);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    memset(&from, 0, sizeof from);
    msg_init(&m, &from, sizeof from, &b, 1);
    m.dwFlags = 0;
    r = rm(d.rx, &m, &n, NULL, NULL);
    CHECKF(r == 0, "err=%d", WSAGetLastError());
    EXPECT_EQ(n, 9);
    CHECK(!memcmp(buf, "hello msg", 9));
    EXPECT_EQ(m.namelen, sizeof(struct sockaddr_in));
    EXPECT_EQ(from.sin_family, AF_INET);
    EXPECT_EQ(from.sin_port, d.txa.sin_port);
    EXPECT_EQ(from.sin_addr.s_addr, XF_LOOPBACK);
    EXPECT_EQ(m.dwFlags, 0);
    EXPECT_EQ(m.Control.len, 0);
    dg_close(&d);
}
TEST(xf_recvmsg_without_name_buffer_still_receives)
{
    WSAMSG m; WSABUF b; char buf[32]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "anon", 4) == 4);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == 0);
    EXPECT_EQ(n, 4);
    EXPECT_EQ(m.namelen, 0);
    dg_close(&d);
}
TEST(xf_recvmsg_scatters_across_buffers)
{
    WSAMSG m; WSABUF b[3]; char a[3], c[4], e[16]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "0123456789", 10) == 10);
    WAIT_READABLE(d.rx);
    b[0].buf = a; b[0].len = 3; b[1].buf = c; b[1].len = 4; b[2].buf = e; b[2].len = sizeof e;
    memset(e, 0, sizeof e);
    msg_init(&m, NULL, 0, b, 3);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == 0);
    EXPECT_EQ(n, 10);
    CHECK(!memcmp(a, "012", 3));
    CHECK(!memcmp(c, "3456", 4));
    CHECK(!memcmp(e, "789", 3));
    dg_close(&d);
}
TEST(xf_recvmsg_zero_length_datagram)
{
    WSAMSG m; WSABUF b; char buf[8]; DWORD n = 0xdeadbeef;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "", 0) == 0);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECKF(rm(d.rx, &m, &n, NULL, NULL) == 0, "err=%d", WSAGetLastError());
    EXPECT_EQ(n, 0);
    dg_close(&d);
}
TEST(xf_recvmsg_truncated_datagram_is_emsgsize)
{
    WSAMSG m; WSABUF b; char buf[4]; DWORD n = 0; int r;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "0123456789", 10) == 10);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    r = rm(d.rx, &m, &n, NULL, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEMSGSIZE);
    CHECK(!memcmp(buf, "0123", 4));
    EXPECT_EQ(n, 4);
    CHECK(m.dwFlags & MSG_TRUNC);
    CHECK(!xf_readable(d.rx, 150));          /* the rest of the datagram is discarded */
    dg_close(&d);
}
TEST(xf_recvmsg_peek_leaves_datagram_queued)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "peekaboo", 8) == 8);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    m.dwFlags = MSG_PEEK;
    CHECKF(rm(d.rx, &m, &n, NULL, NULL) == 0, "peek err=%d", WSAGetLastError());
    EXPECT_EQ(n, 8);
    CHECK(xf_readable(d.rx, 200));
    memset(buf, 0, sizeof buf);
    msg_init(&m, NULL, 0, &b, 1);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == 0);
    EXPECT_EQ(n, 8);
    CHECK(!memcmp(buf, "peekaboo", 8));
    CHECK(!xf_readable(d.rx, 150));
    dg_close(&d);
}
TEST(xf_recvmsg_flag_bits_other_than_peek_are_eopnotsupp)
{
    static const ULONG flags[] = {MSG_OOB, MSG_PARTIAL, MSG_PEEK | MSG_OOB, 0x4, 0x10, 0x100, 0x80000000};
    unsigned i; WSAMSG m; WSABUF b; char buf[16]; DWORD n; WSAOVERLAPPED ov;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "keep me", 7) == 7);
    WAIT_READABLE(d.rx);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        int r;
        b.buf = buf; b.len = sizeof buf; n = 0;
        msg_init(&m, NULL, 0, &b, 1);
        m.dwFlags = flags[i];
        WSASetLastError(0);
        r = rm(d.rx, &m, &n, &ov, NULL);     /* overlapped, so an accepted flag can never block the run */
        if (r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING) {
            CancelIo((HANDLE)d.rx);
            WaitForSingleObject(ov.hEvent, 2000);
            CHECKF(0, "flags 0x%lx accepted", flags[i]);
            break;
        }
        CHECKF(r == SOCKET_ERROR, "flags 0x%lx accepted", flags[i]);
        if (r != SOCKET_ERROR) break;
        CHECKF(WSAGetLastError() == WSAEOPNOTSUPP, "flags 0x%lx: error %d", flags[i], WSAGetLastError());
    }
    WSACloseEvent(ov.hEvent);
    dg_close(&d);
}
TEST(xf_recvmsg_name_pointer_without_length_is_efault)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0; struct sockaddr_in from;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "q", 1) == 1);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, &from, 0, &b, 1);
    WSASetLastError(0);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(xf_readable(d.rx, 200));
    dg_close(&d);
}
TEST(xf_recvmsg_name_length_without_pointer_is_efault)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "q", 1) == 1);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 16, &b, 1);
    WSASetLastError(0);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(xf_readable(d.rx, 200));
    dg_close(&d);
}
TEST(xf_recvmsg_control_pointer_without_length_is_efault)
{
    WSAMSG m; WSABUF b; char buf[16], ctl[32]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "q", 1) == 1);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    m.Control.buf = ctl; m.Control.len = 0;
    WSASetLastError(0);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(xf_readable(d.rx, 200));
    dg_close(&d);
}
TEST(xf_recvmsg_control_length_without_pointer_is_efault)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "q", 1) == 1);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    m.Control.buf = NULL; m.Control.len = 32;
    WSASetLastError(0);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(xf_readable(d.rx, 200));
    dg_close(&d);
}
TEST(xf_recvmsg_header_checks_precede_socket_state)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0; SOCKET s; int r;
    NEED_NET(); NEED_RM(rm);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);                  /* unbound: a valid header would give WSAEINVAL */
    { u_long one = 1; ioctlsocket(s, FIONBIO, &one); }   /* never block, whatever the stack decides */
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 16, &b, 1);                 /* malformed header */
    WSASetLastError(0);
    r = rm(s, &m, &n, NULL, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}
TEST(xf_recvmsg_nonblocking_without_data_is_wouldblock)
{
    WSAMSG m; WSABUF b; char buf[8]; DWORD n = 0; u_long one = 1;
    DG(d); NEED_RM(rm);
    CHECK(ioctlsocket(d.rx, FIONBIO, &one) == 0);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    dg_close(&d);
}
TEST(xf_recvmsg_overlapped_pends_then_completes_with_data)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0, fl = 0; WSAOVERLAPPED ov; struct sockaddr_in from; int r;
    DG(d); NEED_RM(rm);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    b.buf = buf; b.len = sizeof buf;
    memset(&from, 0, sizeof from);
    msg_init(&m, &from, sizeof from, &b, 1);
    WSASetLastError(0);
    r = rm(d.rx, &m, &n, &ov, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSA_IO_PENDING);
    CHECK(WaitForSingleObject(ov.hEvent, 150) == WAIT_TIMEOUT);
    CHECK(send_to_rx(&d, "later", 5) == 5);
    CHECK(xf_ov_wait(d.rx, &ov, &n, &fl, 5000));
    EXPECT_EQ(n, 5);
    CHECK(!memcmp(buf, "later", 5));
    EXPECT_EQ(from.sin_port, d.txa.sin_port);
    EXPECT_EQ(m.namelen, sizeof(struct sockaddr_in));
    WSACloseEvent(ov.hEvent);
    dg_close(&d);
}
TEST(xf_recvmsg_overlapped_cancelled_by_closing_socket)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0, fl = 0; WSAOVERLAPPED ov; int r;
    DG(d); NEED_RM(rm);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    r = rm(d.rx, &m, &n, &ov, NULL);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING);
    closesocket(d.rx);
    CHECK(WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
    SetLastError(0);
    CHECK(!WSAGetOverlappedResult(d.rx, &ov, &n, FALSE, &fl));
    d.rx = INVALID_SOCKET;
    WSACloseEvent(ov.hEvent);
    dg_close(&d);
}
TEST(xf_recvmsg_on_connected_stream_socket_is_einval)
{
    WSAMSG m; WSABUF b; char buf[8]; DWORD n = 0; int r;
    NEED_RM(rm);
    PAIR(p);
    CHECK(send(p.cli, "tcp", 3, 0) == 3);
    WAIT_READABLE(p.srv);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    r = rm(p.srv, &m, &n, NULL, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}
TEST(xf_recvmsg_two_datagrams_come_one_per_call)
{
    WSAMSG m; WSABUF b; char buf[16]; DWORD n = 0;
    DG(d); NEED_RM(rm);
    CHECK(send_to_rx(&d, "one", 3) == 3);
    CHECK(send_to_rx(&d, "twotwo", 6) == 6);
    WAIT_READABLE(d.rx);
    b.buf = buf; b.len = sizeof buf;
    msg_init(&m, NULL, 0, &b, 1);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == 0);
    EXPECT_EQ(n, 3);
    WAIT_READABLE(d.rx);
    msg_init(&m, NULL, 0, &b, 1);
    CHECK(rm(d.rx, &m, &n, NULL, NULL) == 0);
    EXPECT_EQ(n, 6);
    dg_close(&d);
}

/* ---- WSASendMsg -------------------------------------------------------------------------------------------------- */

TEST(xf_sendmsg_flag_bits_outside_the_allowed_mask_are_eopnotsupp)
{
    static const DWORD flags[] = {MSG_PEEK, 0x8, 0x10, 0x20, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000,
                                  0x10000, 0x80000000, 0xFFFFFFFF};
    unsigned i; WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "x";
    DG(d); NEED_SM(sm);
    b.buf = data; b.len = 1;
    for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
        WSASetLastError(0);
        CHECKF(sm(d.tx, &m, flags[i], &n, NULL, NULL) == SOCKET_ERROR, "flags 0x%lx accepted", flags[i]);
        CHECKF(WSAGetLastError() == WSAEOPNOTSUPP, "flags 0x%lx: error %d", flags[i], WSAGetLastError());
    }
    CHECK(!xf_readable(d.rx, 150));              /* nothing was sent */
    dg_close(&d);
}
TEST(xf_sendmsg_dontroute_flag_is_accepted)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "route", got[16];
    DG(d); NEED_SM(sm);
    b.buf = data; b.len = 5;
    msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
    WSASetLastError(0);
    CHECKF(sm(d.tx, &m, MSG_DONTROUTE, &n, NULL, NULL) == 0, "err=%d", WSAGetLastError());
    EXPECT_EQ(n, 5);
    WAIT_READABLE(d.rx);
    EXPECT_EQ(xf_recv(d.rx, got, sizeof got, 0), 5);
    dg_close(&d);
}
TEST(xf_sendmsg_flags_checked_before_socket_state)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "x"; SOCKET s;
    NEED_NET(); NEED_SM(sm);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);        /* wrong type and unconnected: still the flag error wins */
    REQUIRE(s != INVALID_SOCKET);
    b.buf = data; b.len = 1;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECK(sm(s, &m, MSG_PEEK, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
    closesocket(s);
}
TEST(xf_sendmsg_delivers_to_named_destination)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "named", got[16]; struct sockaddr_in from; int fl = sizeof from;
    DG(d); NEED_SM(sm);
    b.buf = data; b.len = 5;
    msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
    CHECKF(sm(d.tx, &m, 0, &n, NULL, NULL) == 0, "err=%d", WSAGetLastError());
    EXPECT_EQ(n, 5);
    WAIT_READABLE(d.rx);
    EXPECT_EQ(recvfrom(d.rx, got, sizeof got, 0, (struct sockaddr *)&from, &fl), 5);
    CHECK(!memcmp(got, data, 5));
    EXPECT_EQ(from.sin_port, d.txa.sin_port);
    dg_close(&d);
}
TEST(xf_sendmsg_connected_datagram_socket_needs_no_name)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "conn", got[16];
    DG(d); NEED_SM(sm);
    CHECK(connect(d.tx, (struct sockaddr *)&d.rxa, sizeof d.rxa) == 0);
    b.buf = data; b.len = 4;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECKF(sm(d.tx, &m, 0, &n, NULL, NULL) == 0, "err=%d", WSAGetLastError());
    WAIT_READABLE(d.rx);
    EXPECT_EQ(xf_recv(d.rx, got, sizeof got, 0), 4);
    dg_close(&d);
}
TEST(xf_sendmsg_unconnected_without_name_is_einval)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "x";
    DG(d); NEED_SM(sm);
    b.buf = data; b.len = 1;
    msg_init(&m, NULL, 0, &b, 1);
    WSASetLastError(0);
    CHECK(sm(d.tx, &m, 0, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    CHECK(!xf_readable(d.rx, 150));
    dg_close(&d);
}
TEST(xf_sendmsg_gathers_buffers_into_one_datagram)
{
    WSAMSG m; WSABUF b[3]; DWORD n = 0; char got[32];
    DG(d); NEED_SM(sm);
    b[0].buf = "ab"; b[0].len = 2; b[1].buf = ""; b[1].len = 0; b[2].buf = "cdef"; b[2].len = 4;
    msg_init(&m, &d.rxa, sizeof d.rxa, b, 3);
    CHECKF(sm(d.tx, &m, 0, &n, NULL, NULL) == 0, "err=%d", WSAGetLastError());
    EXPECT_EQ(n, 6);
    WAIT_READABLE(d.rx);
    EXPECT_EQ(xf_recv(d.rx, got, sizeof got, 0), 6);
    CHECK(!memcmp(got, "abcdef", 6));
    dg_close(&d);
}
TEST(xf_sendmsg_zero_length_datagram_is_delivered)
{
    WSAMSG m; WSABUF b; DWORD n = 99; char got[4];
    DG(d); NEED_SM(sm);
    b.buf = ""; b.len = 0;
    msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
    WSASetLastError(0);
    CHECKF(sm(d.tx, &m, 0, &n, NULL, NULL) == 0, "err=%d", WSAGetLastError());
    EXPECT_EQ(n, 0);
    WAIT_READABLE(d.rx);
    EXPECT_EQ(xf_recv(d.rx, got, sizeof got, 0), 0);
    dg_close(&d);
}
TEST(xf_sendmsg_name_pointer_without_length_is_efault)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "x";
    DG(d); NEED_SM(sm);
    b.buf = data; b.len = 1;
    msg_init(&m, &d.rxa, 0, &b, 1);
    WSASetLastError(0);
    CHECK(sm(d.tx, &m, 0, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    dg_close(&d);
}
TEST(xf_sendmsg_control_length_without_pointer_is_efault)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "x";
    DG(d); NEED_SM(sm);
    b.buf = data; b.len = 1;
    msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
    m.Control.len = 16; m.Control.buf = NULL;
    WSASetLastError(0);
    CHECK(sm(d.tx, &m, 0, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    dg_close(&d);
}
TEST(xf_sendmsg_large_datagram_over_limit_is_emsgsize)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char *big;
    DG(d); NEED_SM(sm);
    big = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 70000);
    REQUIRE(big);
    b.buf = big; b.len = 70000;                    /* larger than any UDP datagram */
    msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
    WSASetLastError(0);
    CHECK(sm(d.tx, &m, 0, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEMSGSIZE);
    HeapFree(GetProcessHeap(), 0, big);
    dg_close(&d);
}
TEST(xf_sendmsg_overlapped_completes_and_delivers)
{
    WSAMSG m; WSABUF b; DWORD n = 0, fl = 0; char data[] = "async", got[16]; WSAOVERLAPPED ov; int r;
    DG(d); NEED_SM(sm);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    b.buf = data; b.len = 5;
    msg_init(&m, &d.rxa, sizeof d.rxa, &b, 1);
    r = sm(d.tx, &m, 0, &n, &ov, NULL);
    CHECKF(r == 0 || WSAGetLastError() == WSA_IO_PENDING, "r=%d err=%d", r, WSAGetLastError());
    if (r != 0) CHECK(xf_ov_wait(d.tx, &ov, &n, &fl, 5000));
    EXPECT_EQ(n, 5);
    WAIT_READABLE(d.rx);
    EXPECT_EQ(xf_recv(d.rx, got, sizeof got, 0), 5);
    WSACloseEvent(ov.hEvent);
    dg_close(&d);
}
TEST(xf_sendmsg_to_ipv6_name_on_ipv4_socket_is_eafnosupport)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "x"; struct sockaddr_in6 a6;
    DG(d); NEED_SM(sm);
    memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6; a6.sin6_addr.u.Byte[15] = 1; a6.sin6_port = 0x0900;
    b.buf = data; b.len = 1;
    memset(&m, 0, sizeof m);
    m.name = (LPSOCKADDR)&a6; m.namelen = sizeof a6; m.lpBuffers = &b; m.dwBufferCount = 1;
    WSASetLastError(0);
    CHECK(sm(d.tx, &m, 0, &n, NULL, NULL) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEAFNOSUPPORT);
    dg_close(&d);
}
TEST(xf_sendmsg_and_recvmsg_round_trip_through_v6_loopback)
{
    WSAMSG m; WSABUF b; DWORD n = 0; char data[] = "six", got[16]; SOCKET rx, tx; struct sockaddr_in6 a, from; int len = sizeof a;
    NEED_NET(); NEED_SM(sm); NEED_RM(rm);
    if (!xf_ipv6_ok()) { t_skip("no IPv6"); return; }
    rx = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    tx = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(rx != INVALID_SOCKET && tx != INVALID_SOCKET);
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
    if (bind(rx, (struct sockaddr *)&a, sizeof a) || getsockname(rx, (struct sockaddr *)&a, &len)) {
        closesocket(rx); closesocket(tx); t_skip("IPv6 loopback bind unavailable"); return;
    }
    b.buf = data; b.len = 3;
    memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&a; m.namelen = sizeof a; m.lpBuffers = &b; m.dwBufferCount = 1;
    CHECKF(sm(tx, &m, 0, &n, NULL, NULL) == 0, "send err=%d", WSAGetLastError());
    WAIT_READABLE(rx);
    b.buf = got; b.len = sizeof got;
    memset(&from, 0, sizeof from);
    memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&from; m.namelen = sizeof from; m.lpBuffers = &b; m.dwBufferCount = 1;
    CHECKF(rm(rx, &m, &n, NULL, NULL) == 0, "recv err=%d", WSAGetLastError());
    EXPECT_EQ(n, 3);
    EXPECT_EQ(m.namelen, sizeof(struct sockaddr_in6));
    EXPECT_EQ(from.sin6_family, AF_INET6);
    closesocket(rx); closesocket(tx);
}
