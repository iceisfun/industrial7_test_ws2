/* Further AcceptEx / ConnectEx / TransmitFile / WSARecvEx cases reached through both the looked-up extension
 * pointers and the mswsock exports: the state of GetAcceptExSockaddrs before the export machinery has been
 * primed (checked in a fresh process), undersized AcceptEx address slots reported at completion, a queued accept
 * socket used twice, listener close and cancellation of a pending AcceptEx, the low-bit event convention that
 * suppresses completion-port packets, the state of a socket after TF_DISCONNECT, and peeking through WSARecvEx. */
#include "mx.h"

#define ADDR4 ((DWORD)(sizeof(struct sockaddr_in) + 16))
#define ST_BUFFER_TOO_SMALL 0xC0000023UL
#define ST_CANCELLED        0xC0000120UL

struct ex {
    struct mx_ext x;
    SOCKET lst;
    struct sockaddr_in addr;
    OVERLAPPED ov;
    unsigned char buf[512];
};

static int ex_open(struct ex *e)
{
    memset(e, 0, sizeof *e);
    e->lst = INVALID_SOCKET;
    if (!mx_up() || !mx_load_ext(&e->x)) return 0;
    e->lst = mx_listener(&e->addr, 8);
    e->ov.hEvent = mx_event();
    return e->lst != INVALID_SOCKET && e->ov.hEvent;
}

static void ex_close(struct ex *e)
{
    if (e->lst != INVALID_SOCKET) mx_abort(e->lst, &e->ov);
    if (e->ov.hEvent) CloseHandle(e->ov.hEvent);
}

#define EX(e) do { if (!ex_open(&(e))) { ex_close(&(e)); t_skip("fixture unavailable"); return; } } while (0)

static SOCKET ex_client(struct ex *e)
{
    SOCKET c = mx_tcp();
    CHECK(c != INVALID_SOCKET && mx_connect(c, (struct sockaddr *)&e->addr, sizeof e->addr) == 0);
    return c;
}

/* One AcceptEx on the chosen route (0 = looked-up pointer, 1 = mswsock export); returns 0 when it pends or
 * completes, otherwise the immediate error. */
static int ex_accept(struct ex *e, int route, SOCKET acc, DWORD rl, DWORD ll, DWORD rr, OVERLAPPED *ov)
{
    DWORD n = 0;
    LPFN_ACCEPTEX fn = route ? UIN("mswsock.dll", AcceptEx) : e->x.acceptex;
    BOOL r;
    ResetEvent(ov->hEvent);
    mx_WSASetLastError(0);
    r = fn(e->lst, acc, e->buf, rl, ll, rr, &n, ov);
    if (r) return 0;
    r = mx_WSAGetLastError();
    return r == ERROR_IO_PENDING ? 0 : (int)r;
}

/* ---- GetAcceptExSockaddrs before it has been primed ---------------------------------------------------- */

/* In a process that never called AcceptEx (or started Winsock) the exported helper has no provider function to
 * forward to; it reports an empty result instead of leaving the outputs alone. */
CHILD(gaes_unprimed)
{
    LPFN_GETACCEPTEXSOCKADDRS fn = UIN("mswsock.dll", GetAcceptExSockaddrs);
    unsigned char buf[128];
    struct sockaddr *l = (struct sockaddr *)(ULONG_PTR)1, *r = (struct sockaddr *)(ULONG_PTR)1;
    int ll = 77, rl = 77;
    memset(buf, 0x11, sizeof buf);
    if (!fn) return 2;
    fn(buf, 0, 32, 32, &l, &ll, &r, &rl);
    if (l != NULL || r != NULL || ll != 0 || rl != 0) return 3;
    fn(buf, 0, 32, 32, NULL, NULL, NULL, NULL);   /* no output pointer is required in this state */
    return 0;
}

TEST(extra_getacceptexsockaddrs_export_in_an_unprimed_process_returns_empty_outputs)
{
    DWORD rc = t_run_child("gaes_unprimed", "", 15000);
    MX_EQ(rc, 0);
}

/* ---- undersized address slots ------------------------------------------------------------------------- */

/* A local slot that is too small is not rejected up front: the call pends, and when a connection arrives the
 * request completes with a buffer-too-small status and zero bytes, leaving the connection in the listen queue. */
static void short_local_case(int route, DWORD ll)
{
    struct ex e;
    SOCKET acc, cli, extra;
    DWORD n = MX_POISON, err = 0;
    EX(e);
    acc = mx_tcp();
    MX_EQ(ex_accept(&e, route, acc, 0, ll, ADDR4, &e.ov), 0);
    cli = ex_client(&e);
    CHECK(WaitForSingleObject(e.ov.hEvent, 5000) == WAIT_OBJECT_0);
    CHECK(!mx_WSAGetOverlappedResult(e.lst, (LPWSAOVERLAPPED)&e.ov, &n, FALSE, &err));
    MX_EQ((ULONG)e.ov.Internal, ST_BUFFER_TOO_SMALL);
    MX_EQ(mx_WSAGetLastError(), WSAEFAULT);      /* the Winsock mapping of the status */
    SetLastError(0);
    CHECK(!GetOverlappedResult((HANDLE)e.lst, &e.ov, &n, FALSE));
    MX_EQ(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    MX_EQ(n, 0);
    extra = mx_accept_wait(e.lst);   /* the connection was not consumed */
    CHECK(extra != INVALID_SOCKET);
    if (extra != INVALID_SOCKET) mx_closesocket(extra);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ex_close(&e);
}
TEST(extra_acceptex_pointer_local_slot_of_3_fails_at_completion)  { short_local_case(0, 3); }
TEST(extra_acceptex_export_local_slot_of_3_fails_at_completion)   { short_local_case(1, 3); }
TEST(extra_acceptex_pointer_local_slot_of_20_fails_at_completion) { short_local_case(0, sizeof(struct sockaddr_in) + 4); }
TEST(extra_acceptex_export_local_slot_of_20_fails_at_completion)  { short_local_case(1, sizeof(struct sockaddr_in) + 4); }

/* The minimum slot is sizeof(sockaddr_in) + 16; one byte less still completes (the final length field of a
 * slot just needs to fit). */
TEST(extra_acceptex_slots_one_byte_under_the_documented_minimum_still_complete)
{
    struct ex e;
    SOCKET acc, cli;
    DWORD n = 0, err = 0;
    EX(e);
    acc = mx_tcp();
    MX_EQ(ex_accept(&e, 0, acc, 0, ADDR4 - 1, ADDR4 - 1, &e.ov), 0);
    cli = ex_client(&e);
    CHECK(mx_ov_done(e.lst, &e.ov, &n, 5000, &err));
    mx_closesocket(cli);
    mx_closesocket(acc);
    ex_close(&e);
}

TEST(extra_acceptex_zero_remote_slot_is_efault_on_both_routes)
{
    unsigned route;
    for (route = 0; route < 2; route++) {
        struct ex e;
        SOCKET acc;
        EX(e);
        acc = mx_tcp();
        MX_EQ(ex_accept(&e, (int)route, acc, 0, ADDR4, 0, &e.ov), WSAEFAULT);
        mx_closesocket(acc);
        ex_close(&e);
    }
}

/* ---- accept socket and listener lifecycle ------------------------------------------------------------- */

TEST(extra_acceptex_accept_socket_queued_twice_is_einval_and_first_call_survives)
{
    struct ex e;
    SOCKET acc, cli;
    OVERLAPPED ov2;
    DWORD n = 0, err = 0;
    EX(e);
    acc = mx_tcp();
    memset(&ov2, 0, sizeof ov2);
    ov2.hEvent = mx_event();
    MX_EQ(ex_accept(&e, 0, acc, 0, ADDR4, ADDR4, &e.ov), 0);
    MX_EQ(ex_accept(&e, 0, acc, 0, ADDR4, ADDR4, &ov2), WSAEINVAL);
    cli = ex_client(&e);
    CHECK(mx_ov_done(e.lst, &e.ov, &n, 5000, &err));
    mx_closesocket(cli);
    mx_closesocket(acc);
    CloseHandle(ov2.hEvent);
    ex_close(&e);
}

/* Closing the listener aborts every pending AcceptEx on it. */
TEST(extra_acceptex_pending_calls_are_aborted_when_the_listener_closes)
{
    struct ex e;
    SOCKET acc1, acc2;
    OVERLAPPED ov2;
    DWORD n = 0, err = 0;
    EX(e);
    acc1 = mx_tcp();
    acc2 = mx_tcp();
    memset(&ov2, 0, sizeof ov2);
    ov2.hEvent = mx_event();
    MX_EQ(ex_accept(&e, 0, acc1, 0, ADDR4, ADDR4, &e.ov), 0);
    {
        unsigned char b2[ADDR4 * 2];
        DWORD m = 0;
        CHECK(!e.x.acceptex(e.lst, acc2, b2, 0, ADDR4, ADDR4, &m, &ov2) && mx_WSAGetLastError() == ERROR_IO_PENDING);
        mx_closesocket(e.lst);
        CHECK(WaitForSingleObject(e.ov.hEvent, 5000) == WAIT_OBJECT_0);
        MX_EQ((ULONG)e.ov.Internal, ST_CANCELLED);
        CHECK(WaitForSingleObject(ov2.hEvent, 5000) == WAIT_OBJECT_0);
        MX_EQ((ULONG)ov2.Internal, ST_CANCELLED);
    }
    e.lst = INVALID_SOCKET;
    mx_closesocket(acc1);
    mx_closesocket(acc2);
    CloseHandle(ov2.hEvent);
    ex_close(&e);
}

/* CancelIoEx on a single request aborts just that request; the listener keeps working. */
TEST(extra_acceptex_cancelioex_aborts_one_request_and_listener_stays_usable)
{
    struct ex e;
    SOCKET acc1, acc2, cli;
    DWORD n = 0, err = 0;
    EX(e);
    acc1 = mx_tcp();
    acc2 = mx_tcp();
    MX_EQ(ex_accept(&e, 0, acc1, 0, ADDR4, ADDR4, &e.ov), 0);
    MX_EQ(CancelIoEx((HANDLE)e.lst, &e.ov), TRUE);
    CHECK(!mx_ov_done(e.lst, &e.ov, &n, 5000, &err));
    MX_EQ(err, ERROR_OPERATION_ABORTED);
    MX_EQ(ex_accept(&e, 0, acc2, 0, ADDR4, ADDR4, &e.ov), 0);
    cli = ex_client(&e);
    CHECK(mx_ov_done(e.lst, &e.ov, &n, 5000, &err));
    mx_closesocket(cli);
    mx_closesocket(acc1);
    mx_closesocket(acc2);
    ex_close(&e);
}

/* ---- low-bit event convention -------------------------------------------------------------------------- */

/* Setting the low bit of OVERLAPPED.hEvent keeps the completion off the port the socket is associated with. */
TEST(extra_acceptex_low_bit_event_suppresses_the_completion_port_packet)
{
    struct ex e;
    SOCKET acc, cli;
    HANDLE port, ev;
    DWORD got = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    EX(e);
    port = CreateIoCompletionPort((HANDLE)e.lst, NULL, 9, 0);
    CHECK(port != NULL);
    ev = e.ov.hEvent;
    e.ov.hEvent = (HANDLE)((ULONG_PTR)ev | 1);
    acc = mx_tcp();
    {
        DWORD m = 0;
        unsigned char b[ADDR4 * 2];
        BOOL r = e.x.acceptex(e.lst, acc, b, 0, ADDR4, ADDR4, &m, &e.ov);
        CHECK(r || mx_WSAGetLastError() == ERROR_IO_PENDING);
    }
    cli = ex_client(&e);
    CHECK(WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0);
    SetLastError(0);
    MX_EQ(GetQueuedCompletionStatus(port, &got, &key, &pov, 300), FALSE);
    MX_EQ(GetLastError(), WAIT_TIMEOUT);
    CHECK(pov == NULL);
    mx_closesocket(cli);
    mx_closesocket(acc);
    e.ov.hEvent = ev;
    CloseHandle(port);
    ex_close(&e);
}

TEST(extra_connectex_low_bit_event_suppresses_the_completion_port_packet)
{
    struct ex e;
    SOCKET c, srv;
    struct sockaddr_in any = mx_lo4();
    HANDLE port, ev = mx_event();
    OVERLAPPED ov;
    DWORD got = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    EX(e);
    c = mx_tcp();
    MX_EQ(mx_bind(c, (struct sockaddr *)&any, sizeof any), 0);
    port = CreateIoCompletionPort((HANDLE)c, NULL, 4, 0);
    CHECK(port != NULL);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = (HANDLE)((ULONG_PTR)ev | 1);
    {
        BOOL r = e.x.connectex(c, (struct sockaddr *)&e.addr, sizeof e.addr, NULL, 0, NULL, &ov);
        CHECK(r || mx_WSAGetLastError() == ERROR_IO_PENDING);
    }
    CHECK(WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0);
    srv = mx_accept_wait(e.lst);
    CHECK(srv != INVALID_SOCKET);
    SetLastError(0);
    MX_EQ(GetQueuedCompletionStatus(port, &got, &key, &pov, 300), FALSE);
    MX_EQ(GetLastError(), WAIT_TIMEOUT);
    if (srv != INVALID_SOCKET) mx_closesocket(srv);
    mx_closesocket(c);
    CloseHandle(port);
    CloseHandle(ev);
    ex_close(&e);
}

/* ---- sockets after TF_DISCONNECT ------------------------------------------------------------------------ */

/* A plain disconnect (no reuse) shuts the sending side: the data arrives, then end of stream, and a later send
 * on the transmitting socket is refused with the shutdown error. */
TEST(extra_transmitfile_tf_disconnect_without_reuse_ends_the_stream_and_blocks_sends)
{
    struct mx_ext x;
    HANDLE f;
    char b = 0;
    MX_PAIR(c, a);
    if (!mx_load_ext(&x)) { mx_closesocket(c); mx_closesocket(a); t_skip("extension functions not offered"); return; }
    f = mx_make_file("tf_disc.bin", 300, 5, GENERIC_READ | GENERIC_WRITE, 0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    {
        OVERLAPPED ov;
        DWORD n = 0, err = 0;
        memset(&ov, 0, sizeof ov);
        ov.hEvent = mx_event();
        CHECK(!x.transmitfile(c, f, 0, 0, &ov, NULL, TF_DISCONNECT) ? mx_WSAGetLastError() == ERROR_IO_PENDING : 1);
        CHECK(mx_ov_done(c, &ov, &n, 8000, &err));
        MX_EQ(n, 300);
        CloseHandle(ov.hEvent);
    }
    mx_expect_slice(a, 5, 0, 300);
    CHECK(mx_at_eof(a, 5000));
    MX_EQ(mx_send(c, &b, 1, 0), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAESHUTDOWN);
    CloseHandle(f);
    mx_closesocket(c);
    mx_closesocket(a);
}

/* ---- WSARecvEx peeking ------------------------------------------------------------------------------------ */

/* The flags word is output only for WSARecvEx: an input MSG_PEEK does not make the receive a peek, so the bytes
 * are consumed.  The queue depth is read with FIONREAD so a wrong expectation cannot block the test. */
TEST(extra_wsarecvex_ignores_an_input_peek_flag_and_consumes_the_data)
{
    int (WINAPI *fn)(SOCKET, char *, int, int *) = (void *)UIN("mswsock.dll", WSARecvEx);
    char a[8] = {0};
    int flags = MSG_PEEK;
    u_long left = 77;
    MX_PAIR(c, s);
    REQUIRE(fn);
    MX_EQ(mx_send(c, "peekme", 6, 0), 6);
    CHECK(mx_readable(s, 5000));
    MX_EQ(fn(s, a, 3, &flags), 3);
    CHECK(!memcmp(a, "pee", 3));
    MX_EQ(mx_ioctlsocket(s, FIONREAD, &left), 0);
    MX_EQ(left, 3);
    MX_EQ(flags, 0);
    mx_closesocket(c);
    mx_closesocket(s);
}

/* ---- probes: values recorded where the behaviour is not pinned down ------------------------------------ */

TEST(extra_transmitfile_on_datagram_and_listening_sockets_is_notconn)
{
    struct mx_ext x;
    SOCKET u, l;
    struct sockaddr_in a;
    OVERLAPPED ov;
    HANDLE f;
    BOOL ok;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    f = mx_make_file("tf_odd.bin", 10, 1, GENERIC_READ | GENERIC_WRITE, 0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    u = mx_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    mx_WSASetLastError(0);
    ok = x.transmitfile(u, f, 0, 0, &ov, NULL, 0);
    MX_EQ(ok, FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    mx_closesocket(u);
    l = mx_listener(&a, 1);
    mx_WSASetLastError(0);
    ok = x.transmitfile(l, f, 0, 0, &ov, NULL, 0);
    MX_EQ(ok, FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    mx_closesocket(l);
    CloseHandle(ov.hEvent);
    CloseHandle(f);
}

TEST(extra_update_accept_context_with_invalid_socket_is_notsock)
{
    struct ex e;
    SOCKET acc, cli, other;
    DWORD n = 0, err = 0;
    int r;
    EX(e);
    acc = mx_tcp();
    MX_EQ(ex_accept(&e, 0, acc, 0, ADDR4, ADDR4, &e.ov), 0);
    cli = ex_client(&e);
    CHECK(mx_ov_done(e.lst, &e.ov, &n, 5000, &err));
    other = mx_tcp();
    r = mx_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&other, sizeof other);
    t_note("update context with a never-listening socket: %d err %d", r, r ? mx_WSAGetLastError() : 0);
    {
        SOCKET bad = INVALID_SOCKET;
        MX_EQ(mx_setsockopt(acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&bad, sizeof bad), SOCKET_ERROR);
        MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
    }
    mx_closesocket(other);
    mx_closesocket(cli);
    mx_closesocket(acc);
    ex_close(&e);
}
