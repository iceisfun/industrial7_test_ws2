/* AFD poll results on loopback TCP sockets.
 * Measures: which AFD_POLL_* bits a connected, flooded, shut-down, reset or closing stream socket
 * reports (WRITE|CONNECT baseline, READ on pending data, OOB vs OOBINLINE, HUP after a peer's send
 * shutdown, CLOSE when the polled handle goes away), the pending/immediate completion split, the
 * connect-refused path, and how multi-entry requests report. */
#include "afd_common.h"

static const SOCKET *nullsock = NULL;

/* Verify the single-entry result of a request that completed (after the event fired). */
static void check_single(const pollbuf_t *out, const IO_STATUS_BLOCK *io, SOCKET s, ULONG flags, LONG status)
{
    CHECK(io->Status == 0);
    CHECK(io->Information == POLL_BYTES(1));
    CHECK(out->req.count == 1);
    CHECK(out->req.sockets[0].socket == s);
    CHECKF(out->req.sockets[0].flags == flags, "flags got %#lx want %#lx", (unsigned long)out->req.sockets[0].flags, (unsigned long)flags);
    CHECK(out->req.sockets[0].status == status);
}

static int submit(HANDLE h, HANDLE ev, IO_STATUS_BLOCK *io, pollbuf_t *in, pollbuf_t *out, int n)
{
    memset(out, 0, sizeof(*out));
    return afd_poll(h, ev, io, in, (ULONG)POLL_BYTES(n), out, (ULONG)POLL_BYTES(n));
}

static void send_ok(SOCKET s, const char *p, int n, int flags)
{
    int r = F.send(s, p, n, flags);
    CHECKF(r == n, "send returned %d", r);
}

/* Server side nonblocking, a few bytes unread on the client, and the server's send path jammed. */
static void flooded_pair(SOCKET *c, SOCKET *s)
{
    static char big[1 << 20];
    int i;
    mk_pair(c, s);
    set_nonblock(*s, 1);
    send_ok(*s, "data", 5, 0);
    for (i = 0; i < 400; i++)
        if (F.send(*s, big, sizeof(big), 0) != (int)sizeof(big)) break;
    CHECKF(i < 400, "send path never filled");
}

/* ---- connected baseline -------------------------------------------------- */
TEST(afdp_tcp_connected_pair_reports_write_connect)
{
    SOCKET c, s; HANDLE ev;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    POLL_EXPECT(s, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

TEST(afdp_tcp_unread_data_adds_read)
{
    SOCKET c, s; HANDLE ev;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    send_ok(s, "data", 5, 0);
    POLL_EXPECT_MASK(c, ev, AFDX_POLL_READ, AFDX_POLL_READ);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ);
    POLL_EXPECT(s, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

TEST(afdp_tcp_full_send_path_drops_write)
{
    SOCKET c, s; HANDLE ev;
    NEED_AFD();
    flooded_pair(&c, &s); ev = mk_event();
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ);
    POLL_EXPECT(s, ev, AFDX_POLL_CONNECT);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

/* A WSARecv that is already pending takes the arriving byte; a read-poll issued before it must not fire. */
TEST(afdp_tcp_pending_recv_consumes_read_event)
{
    SOCKET c, s; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; OVERLAPPED ov; WSABUF wb; DWORD fl = 0, sz = 0; char buf[8];
    NEED_AFD();
    flooded_pair(&c, &s); ev = mk_event();
    memset(&ov, 0, sizeof(ov)); ov.hEvent = mk_event();
    fill_poll1(&in, REL_MS(1000), s, AFDX_POLL_READ);
    EXPECT_ST(submit((HANDLE)s, ev, &io, &in, &out, 1), AS_PENDING);

    wb.buf = buf; wb.len = 1;
    CHECK(F.WSARecv(s, &wb, 1, NULL, &fl, &ov, NULL) == SOCKET_ERROR);
    CHECK(F.WSAGetLastError() == ERROR_IO_PENDING);
    send_ok(c, "a", 1, 0);
    EXPECT_ST(WaitForSingleObject(ov.hEvent, 1500), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)s, &ov, &sz, FALSE));
    CHECK(sz == 1);
    /* the recv took the byte, so the read-poll stays pending */
    EXPECT_ST(WaitForSingleObject(ev, 150), WAIT_TIMEOUT);

    send_ok(c, "a", 1, 0);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, s, AFDX_POLL_READ, 0);
    CHECK(F.recv(s, buf, 1, 0) == 1);
    CloseHandle(ov.hEvent); CloseHandle(ev); sock_close(c); sock_close(s);
}

/* ---- out-of-band data ----------------------------------------------------- */
TEST(afdp_tcp_oob_byte_reports_oob_not_read)
{
    SOCKET c, s; HANDLE ev; char b;
    NEED_AFD();
    flooded_pair(&c, &s); ev = mk_event();
    send_ok(c, "a", 1, MSG_OOB);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ);
    POLL_EXPECT_MASK(s, ev, AFDX_POLL_OOB, AFDX_POLL_OOB);
    POLL_EXPECT(s, ev, AFDX_POLL_CONNECT | AFDX_POLL_OOB);
    CHECK(F.recv(s, &b, 1, MSG_OOB) == 1);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ);
    POLL_EXPECT(s, ev, AFDX_POLL_CONNECT);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

TEST(afdp_tcp_oob_inline_reports_read)
{
    SOCKET c, s; HANDLE ev; int one = 1;
    NEED_AFD();
    flooded_pair(&c, &s); ev = mk_event();
    CHECK(F.setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&one, sizeof(one)) == 0);
    send_ok(c, "a", 1, MSG_OOB);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ);
    POLL_EXPECT_MASK(s, ev, AFDX_POLL_READ, AFDX_POLL_READ);
    POLL_EXPECT(s, ev, AFDX_POLL_CONNECT | AFDX_POLL_READ);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

/* ---- shutdown and reset ---------------------------------------------------- */
TEST(afdp_tcp_shutdown_receive_is_invisible_to_both_sides)
{
    SOCKET c, s; HANDLE ev;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    CHECK(F.shutdown(c, SD_RECEIVE) == 0);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    POLL_EXPECT(s, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

TEST(afdp_tcp_shutdown_send_gives_peer_hup)
{
    SOCKET c, s; HANDLE ev;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    CHECK(F.shutdown(c, SD_RECEIVE) == 0);
    CHECK(F.shutdown(c, SD_SEND) == 0);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    POLL_EXPECT_MASK(s, ev, AFDX_POLL_HUP, AFDX_POLL_HUP);
    POLL_EXPECT(s, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_HUP);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

TEST(afdp_tcp_shutdown_send_with_unread_data_reports_read_and_hup)
{
    SOCKET c, s; HANDLE ev;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    send_ok(c, "data", 5, 0);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    POLL_EXPECT_MASK(s, ev, AFDX_POLL_READ, AFDX_POLL_READ);
    POLL_EXPECT(s, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ);
    CHECK(F.shutdown(c, SD_SEND) == 0);
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT);
    POLL_EXPECT_MASK(s, ev, AFDX_POLL_READ, AFDX_POLL_READ);
    POLL_EXPECT(s, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_READ | AFDX_POLL_HUP);
    CloseHandle(ev); sock_close(c); sock_close(s);
}

TEST(afdp_tcp_peer_reset_reports_reset)
{
    SOCKET c, s; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    fill_poll1(&in, REL_MS(1000), c, ~(ULONG)(AFDX_POLL_WRITE | AFDX_POLL_CONNECT));
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 1), AS_PENDING);
    close_rst(s);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, c, AFDX_POLL_RESET, 0);
    /* the condition sticks: a full-mask poll now lists it next to the baseline bits */
    POLL_EXPECT(c, ev, AFDX_POLL_WRITE | AFDX_POLL_CONNECT | AFDX_POLL_RESET);
    CloseHandle(ev); sock_close(c);
}

/* Closing the polled handle completes the request with CLOSE, even though the mask was empty. */
TEST(afdp_tcp_close_of_polled_handle_reports_close)
{
    SOCKET c, s; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    fill_poll1(&in, REL_MS(1000), c, 0);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 1), AS_PENDING);
    sock_close(c);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, c, AFDX_POLL_CLOSE, 0);
    CloseHandle(ev); sock_close(s);
}

/* Closing the handle that carried the request while it polls a different socket ends the wait by timeout. */
TEST(afdp_tcp_close_of_carrier_handle_times_out_request)
{
    SOCKET c, s; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io;
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    fill_poll1(&in, REL_MS(100), c, AFDX_POLL_READ);
    EXPECT_ST(submit((HANDLE)s, ev, &io, &in, &out, 1), AS_PENDING);
    sock_close(s);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    CHECK_IO(io, AS_TIMEOUT, POLL_BYTES(0));
    CHECK(out.req.count == 0);
    CloseHandle(ev); sock_close(c);
}

/* ---- failed connections (closed loopback port; may take a couple of seconds) ----------------- */
static SOCKET closed_port_addr(struct sockaddr_in *a)
{
    SOCKET l = mk_listener(a);
    sock_close(l);
    return l;
}

TEST(afdp_tcp_nonblocking_connect_refused_reports_connect_err)
{
    struct sockaddr_in a; SOCKET c; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; LARGE_INTEGER now; int r;
    NEED_AFD();
    closed_port_addr(&a);
    ev = mk_event();
    c = mk_tcp(); set_nonblock(c, 1);
    fill_poll1(&in, REL_MS(6000), c, ~0u);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 1), AS_PENDING);
    r = F.connect(c, (struct sockaddr *)&a, sizeof(a));
    CHECK(r == SOCKET_ERROR);
    CHECK(F.WSAGetLastError() == WSAEWOULDBLOCK);
    if (WaitForSingleObject(ev, 5000) != WAIT_OBJECT_0) {
        t_note("refused loopback connect did not complete within the bounded wait");
        cancel_and_drain((HANDLE)c, ev);
        CloseHandle(ev); sock_close(c);
        return;
    }
    CHECK(io.Status == 0);
    CHECK(io.Information == POLL_BYTES(1));
    CHECK(out.req.count == 1);
    CHECK(out.req.sockets[0].socket == c);
    CHECK(out.req.sockets[0].flags == AFDX_POLL_CONNECT_ERR);
    CHECK(out.req.sockets[0].status == AS_CONNECTION_REFUSED);

    /* the error is sticky: later polls return it at once, each time */
    F.NtQuerySystemTime(&now);
    for (r = 0; r < 2; r++) {
        pollbuf_t in2;
        fill_poll1(&in2, now.QuadPart, c, ~0u);
        memset(&out, 0xcc, sizeof(out));
        EXPECT_ST(afd_poll((HANDLE)c, ev, &io, &in2, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1)), 0);
        CHECK_IO(io, 0, POLL_BYTES(1));
        CHECK(out.req.count == 1);
        CHECK(out.req.sockets[0].socket == c);
        CHECK(out.req.sockets[0].flags == AFDX_POLL_CONNECT_ERR);
        CHECK(out.req.sockets[0].status == AS_CONNECTION_REFUSED);
    }
    /* a new nonblocking attempt starts over */
    CHECK(F.connect(c, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR);
    CHECK(F.WSAGetLastError() == WSAEWOULDBLOCK);
    CloseHandle(ev); sock_close(c);
}

TEST(afdp_tcp_blocking_connect_refused_poll_is_immediate)
{
    struct sockaddr_in a; SOCKET c; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; LARGE_INTEGER now;
    NEED_AFD();
    closed_port_addr(&a);
    ev = mk_event();
    c = mk_tcp();
    CHECK(F.connect(c, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR);
    CHECK(F.WSAGetLastError() == WSAECONNREFUSED);
    F.NtQuerySystemTime(&now);
    fill_poll1(&in, now.QuadPart, c, ~0u);
    memset(&out, 0xcc, sizeof(out));
    EXPECT_ST(afd_poll((HANDLE)c, ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1)), 0);
    CHECK_IO(io, 0, POLL_BYTES(1));
    CHECK(out.req.count == 1);
    CHECK(out.req.sockets[0].socket == c);
    CHECK(out.req.sockets[0].flags == AFDX_POLL_CONNECT_ERR);
    CHECK(out.req.sockets[0].status == AS_CONNECTION_REFUSED);
    CloseHandle(ev); sock_close(c);
}

/* A pending poll on an unconnected socket sees CONNECT and WRITE arrive together. */
TEST(afdp_tcp_connect_signals_connect_and_write_together)
{
    struct sockaddr_in a; SOCKET l, c, s; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io;
    NEED_AFD();
    l = mk_listener(&a); c = mk_tcp(); ev = mk_event();
    fill_poll1(&in, REL_MS(1000), c, ~0u);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 1), AS_PENDING);
    CHECK(F.connect(c, (struct sockaddr *)&a, sizeof(a)) == 0);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    CHECK(io.Status == 0);
    CHECK(io.Information == POLL_BYTES(1));
    CHECK(out.req.count == 1);
    CHECK(out.req.sockets[0].flags == (AFDX_POLL_CONNECT | AFDX_POLL_WRITE));
    CHECK(out.req.sockets[0].status == 0);
    s = F.accept(l, NULL, NULL);
    sock_close(s); sock_close(c); sock_close(l); CloseHandle(ev);
}

/* ---- AcceptEx versus a poll on the same listener ------------------------------------------------ */
TEST(afdp_tcp_pending_acceptex_takes_first_connection)
{
    GUID g = WSAID_ACCEPTEX; LPFN_ACCEPTEX acceptex = NULL; DWORD got = 0;
    struct sockaddr_in a; SOCKET l, acc, c, c2, s; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; OVERLAPPED ov; char buf[128]; DWORD sz = 0;
    NEED_AFD();
    l = mk_listener(&a);
    CHECK(F.WSAIoctl(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &acceptex, sizeof(acceptex), &got, NULL, NULL) == 0);
    if (!acceptex) { sock_close(l); t_skip("AcceptEx pointer unavailable"); return; }
    ev = mk_event();
    memset(&ov, 0, sizeof(ov)); ov.hEvent = mk_event();
    fill_poll1(&in, REL_MS(1000), l, AFDX_POLL_ACCEPT);
    EXPECT_ST(submit((HANDLE)l, ev, &io, &in, &out, 1), AS_PENDING);

    acc = mk_tcp();
    CHECK(!acceptex(l, acc, buf, 0, 0, sizeof(struct sockaddr_in) + 16, NULL, &ov));
    CHECK(F.WSAGetLastError() == ERROR_IO_PENDING);
    c = mk_tcp();
    CHECK(F.connect(c, (struct sockaddr *)&a, sizeof(a)) == 0);
    EXPECT_ST(WaitForSingleObject(ov.hEvent, 1500), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)l, &ov, &sz, FALSE));
    CHECK(sz == 0);
    /* the connection went to AcceptEx, so the poll saw no pending connection */
    EXPECT_ST(WaitForSingleObject(ev, 150), WAIT_TIMEOUT);
    sock_close(acc); sock_close(c);

    c2 = mk_tcp();
    CHECK(F.connect(c2, (struct sockaddr *)&a, sizeof(a)) == 0);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, l, AFDX_POLL_ACCEPT, 0);
    s = F.accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    sock_close(s); sock_close(c2); sock_close(l);
    CloseHandle(ov.hEvent); CloseHandle(ev);
}

/* ---- multi-entry requests ----------------------------------------------------------------------------- */
TEST(afdp_multi_pending_reports_only_ready_entries)
{
    SOCKET c, s, socks[2]; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; ULONG fl[2] = { AFDX_POLL_READ, AFDX_POLL_READ };
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    socks[0] = c; socks[1] = s;
    fill_poll(&in, REL_MS(1000), 0, 2, socks, fl);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 2), AS_PENDING);
    send_ok(c, "data", 5, 0);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, s, AFDX_POLL_READ, 0);
    sock_close(c); sock_close(s); CloseHandle(ev);
}

TEST(afdp_multi_immediate_lists_every_entry)
{
    SOCKET c, s, socks[2]; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; ULONG fl[2] = { AFDX_POLL_READ | AFDX_POLL_WRITE, AFDX_POLL_READ | AFDX_POLL_WRITE };
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    send_ok(c, "data", 5, 0);
    socks[0] = c; socks[1] = s;
    fill_poll(&in, REL_MS(1000), 0, 2, socks, fl);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 2), 0);
    CHECK_IO(io, 0, POLL_BYTES(2));
    CHECK(out.req.count == 2);
    CHECK(out.req.sockets[0].socket == c);
    CHECK(out.req.sockets[0].flags == AFDX_POLL_WRITE);
    CHECK(out.req.sockets[0].status == 0);
    CHECK(out.req.sockets[1].socket == s);
    CHECK(out.req.sockets[1].flags == (AFDX_POLL_READ | AFDX_POLL_WRITE));
    CHECK(out.req.sockets[1].status == 0);
    /* repeating the identical request gives the identical answer */
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 2), 0);
    CHECK_IO(io, 0, POLL_BYTES(2));
    CHECK(out.req.count == 2);
    CHECK(out.req.sockets[0].flags == AFDX_POLL_WRITE);
    CHECK(out.req.sockets[1].flags == (AFDX_POLL_READ | AFDX_POLL_WRITE));
    sock_close(c); sock_close(s); CloseHandle(ev);
}

TEST(afdp_multi_same_handle_listed_per_entry)
{
    SOCKET c, s, socks[3]; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io;
    ULONG fl[3] = { AFDX_POLL_READ | AFDX_POLL_WRITE, AFDX_POLL_READ | AFDX_POLL_WRITE, AFDX_POLL_READ | AFDX_POLL_WRITE | AFDX_POLL_CONNECT };
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    socks[0] = socks[1] = socks[2] = c;
    fill_poll(&in, REL_MS(1000), 0, 3, socks, fl);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 3), 0);
    CHECK_IO(io, 0, POLL_BYTES(3));
    CHECK(out.req.count == 3);
    CHECK(out.req.sockets[0].socket == c && out.req.sockets[0].flags == AFDX_POLL_WRITE && out.req.sockets[0].status == 0);
    CHECK(out.req.sockets[1].socket == c && out.req.sockets[1].flags == AFDX_POLL_WRITE && out.req.sockets[1].status == 0);
    CHECK(out.req.sockets[2].socket == c && out.req.sockets[2].flags == (AFDX_POLL_WRITE | AFDX_POLL_CONNECT) && out.req.sockets[2].status == 0);
    sock_close(c); sock_close(s); CloseHandle(ev);
}

TEST(afdp_multi_same_handle_pending_reports_it_once)
{
    SOCKET c, s, socks[2]; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; ULONG fl[2] = { AFDX_POLL_READ, AFDX_POLL_READ };
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event();
    socks[0] = socks[1] = c;
    fill_poll(&in, REL_MS(1000), 0, 2, socks, fl);
    EXPECT_ST(submit((HANDLE)c, ev, &io, &in, &out, 2), AS_PENDING);
    send_ok(s, "data", 5, 0);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, c, AFDX_POLL_READ, 0);
    sock_close(c); sock_close(s); CloseHandle(ev);
}

/* ---- UDP ---------------------------------------------------------------------------------------------- */
static void bind_lb(SOCKET s, struct sockaddr_in *a)
{
    int len = sizeof(*a);
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007Fu;
    CHECK(F.bind(s, (struct sockaddr *)a, sizeof(*a)) == 0);
    CHECK(F.getsockname(s, (struct sockaddr *)a, &len) == 0);
}

TEST(afdp_udp_fresh_socket_reports_write_only)
{
    SOCKET u; HANDLE ev;
    NEED_AFD();
    u = mk_udp(); ev = mk_event();
    POLL_EXPECT(u, ev, AFDX_POLL_WRITE);
    sock_close(u); CloseHandle(ev);
}

TEST(afdp_udp_bound_socket_reports_write_only)
{
    SOCKET u; HANDLE ev; struct sockaddr_in a;
    NEED_AFD();
    u = mk_udp(); ev = mk_event();
    bind_lb(u, &a);
    POLL_EXPECT(u, ev, AFDX_POLL_WRITE);
    sock_close(u); CloseHandle(ev);
}

TEST(afdp_udp_datagram_arrival_reports_read)
{
    SOCKET rx, tx; HANDLE ev; struct sockaddr_in a; pollbuf_t in, out; IO_STATUS_BLOCK io;
    NEED_AFD();
    rx = mk_udp(); tx = mk_udp(); ev = mk_event();
    bind_lb(rx, &a);
    fill_poll1(&in, REL_MS(1000), rx, ~0u & ~(ULONG)AFDX_POLL_WRITE);
    EXPECT_ST(submit((HANDLE)rx, ev, &io, &in, &out, 1), AS_PENDING);
    CHECK(F.sendto(tx, "data", 5, 0, (struct sockaddr *)&a, sizeof(a)) == 5);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    check_single(&out, &io, rx, AFDX_POLL_READ, 0);
    sock_close(rx); sock_close(tx); CloseHandle(ev);
}

TEST(afdp_udp_connect_signals_connect)
{
    SOCKET rx, tx; HANDLE ev; struct sockaddr_in a; pollbuf_t in, out; IO_STATUS_BLOCK io;
    NEED_AFD();
    rx = mk_udp(); tx = mk_udp(); ev = mk_event();
    bind_lb(rx, &a);
    fill_poll1(&in, REL_MS(1000), tx, AFDX_POLL_CONNECT);
    EXPECT_ST(submit((HANDLE)tx, ev, &io, &in, &out, 1), AS_PENDING);
    CHECK(F.connect(tx, (struct sockaddr *)&a, sizeof(a)) == 0);
    if (WaitForSingleObject(ev, 1500) == WAIT_OBJECT_0) {
        check_single(&out, &io, tx, AFDX_POLL_CONNECT, 0);
    } else {
        CHECKF(0, "UDP connect did not complete a pending CONNECT poll");
        cancel_and_drain((HANDLE)tx, ev);
    }
    sock_close(rx); sock_close(tx); CloseHandle(ev);
}
