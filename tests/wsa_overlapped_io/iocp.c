/* wsa_overlapped_io / iocp: I/O completion ports with overlapped Winsock requests.
 * Measures: association rules (one port per handle), packet contents (bytes, key, OVERLAPPED pointer,
 * status via GetLastError / Internal), packets for immediate completions, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS,
 * the low-bit-of-hEvent suppression, abort packets after cancel, ordering and batch dequeue. */
#include "oio.h"

#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

typedef struct { BOOL ok; DWORD err, bytes; ULONG_PTR key; LPOVERLAPPED ov; } pkt;

/* Dequeue one packet; returns FALSE on timeout (nothing dequeued). */
static BOOL deq(HANDLE port, DWORD ms, pkt *p)
{
    p->bytes = 0xFFFFFFF0; p->key = 0xFFFFFFF0; p->ov = (LPOVERLAPPED)(ULONG_PTR)1;
    SetLastError(0);
    p->ok = GetQueuedCompletionStatus(port, &p->bytes, &p->key, &p->ov, ms);
    p->err = GetLastError();
    return p->ok || (p->ov != (LPOVERLAPPED)(ULONG_PTR)1 && p->ov != NULL);
}
#define NOPKT(port) do { pkt q_; BOOL g_ = deq(port, 150, &q_); CHECK(!g_); } while (0)

static HANDLE attach(SOCKET s, ULONG_PTR key, HANDLE port)
{
    return CreateIoCompletionPort((HANDLE)s, port, key, 0);
}

TEST(oio_iocp_associate_returns_port_and_rejects_second)
{
    SOCKET c, s; UP(); PAIR(c, s);
    HANDLE port = attach(c, 1, NULL);
    REQUIRE(port != NULL);
    HANDLE p2 = CreateIoCompletionPort((HANDLE)c, port, 2, 0);
    CHECK(p2 == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CloseHandle(port); oio_close2(c, s);
}

TEST(oio_iocp_recv_packet_contents)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; pkt p;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 0x1234, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "pkt", 3);
    CHECK(deq(port, OIO_WAIT, &p));
    CHECK(p.ok); OEQ(p.bytes, 3); OEQ(p.key, 0x1234); OEQ(p.ov, &o);
    OEQ(o.Internal, OIO_STATUS_SUCCESS); OEQ(o.InternalHigh, 3);
    NOPKT(port);
    CloseHandle(port); oio_close2(c, s);
}

/* Event and port both: the event is signalled as well as the packet queued. */
TEST(oio_iocp_event_and_packet_both_delivered)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; pkt p; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 7, NULL); REQUIRE(port);
    oio_ovl(&o, ev);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "b", 1);
    CHECK(deq(port, OIO_WAIT, &p)); OEQ(p.ov, &o);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CloseHandle(port); CloseHandle(ev); oio_close2(c, s);
}

TEST(oio_iocp_wsagetoverlappedresult_after_dequeue)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 0, f2 = 9; pkt p;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 7, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    oio_send(s, "four", 4);
    CHECK(deq(port, OIO_WAIT, &p));
    OEQ(U(WSAGetOverlappedResult)(c, p.ov, &bytes, FALSE, &f2), TRUE);
    OEQ(bytes, 4); OEQ(f2, 0);
    CloseHandle(port); oio_close2(c, s);
}

/* Without skip modes, a send that completes inline still queues a packet. */
TEST(oio_iocp_immediate_send_still_queues_packet)
{
    SOCKET c, s; WSAOVERLAPPED o; pkt p; DWORD nb = 0; char got[4];
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 9, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    WSABUF b = {2, (CHAR *)"hi"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    CHECK(rc == 0 || (rc == SOCKET_ERROR && WERR() == WSA_IO_PENDING));
    CHECK(deq(port, OIO_WAIT, &p));
    CHECK(p.ok); OEQ(p.bytes, 2); OEQ(p.key, 9); OEQ(p.ov, &o);
    U(recv)(s, got, 2, 0);
    CloseHandle(port); oio_close2(c, s);
}

/* With FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, an inline success produces no packet; a pending request does. */
TEST(oio_iocp_skip_on_success_inline_send_has_no_packet)
{
    SOCKET c, s; WSAOVERLAPPED o; pkt p; DWORD nb = 0; char got[4];
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 9, NULL); REQUIRE(port);
    REQUIRE(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    oio_ovl(&o, NULL);
    WSABUF b = {2, (CHAR *)"hi"};
    int rc = U(WSASend)(c, &b, 1, &nb, 0, &o, NULL);
    if (rc == 0) { OEQ(nb, 2); NOPKT(port); }
    else { OEQ(rc, SOCKET_ERROR); OEQ(WERR(), WSA_IO_PENDING); CHECK(deq(port, OIO_WAIT, &p)); OEQ(p.ov, &o); }
    U(recv)(s, got, 2, 0);
    CloseHandle(port); oio_close2(c, s);
}

TEST(oio_iocp_skip_on_success_inline_recv_has_no_packet)
{
    SOCKET c, s; WSAOVERLAPPED o; pkt p; DWORD nb = 0, fl = 0; char buf[8];
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 9, NULL); REQUIRE(port);
    REQUIRE(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    oio_send(s, "data", 4); Sleep(50);
    oio_ovl(&o, NULL);
    WSABUF b = {sizeof buf, buf};
    int rc = U(WSARecv)(c, &b, 1, &nb, &fl, &o, NULL);
    if (rc == 0) { OEQ(nb, 4); NOPKT(port); }
    else { OEQ(rc, SOCKET_ERROR); OEQ(WERR(), WSA_IO_PENDING); CHECK(deq(port, OIO_WAIT, &p)); }
    CloseHandle(port); oio_close2(c, s);
}

TEST(oio_iocp_skip_on_success_pending_recv_still_queues_packet)
{
    SOCKET c, s; WSAOVERLAPPED o; pkt p; DWORD fl; char buf[8];
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 5, NULL); REQUIRE(port);
    REQUIRE(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    oio_ovl(&o, NULL);
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "p", 1);
    CHECK(deq(port, OIO_WAIT, &p)); CHECK(p.ok); OEQ(p.bytes, 1); OEQ(p.ov, &o);
    CloseHandle(port); oio_close2(c, s);
}

/* A synchronous failure (no connection) produces no packet in either mode. */
TEST(oio_iocp_skip_on_success_sync_failure_no_packet)
{
    SOCKET u; WSAOVERLAPPED o; DWORD fl; char buf[4]; UP();
    u = oio_sock(SOCK_STREAM, IPPROTO_TCP); REQUIRE(u != INVALID_SOCKET);
    HANDLE port = attach(u, 1, NULL); REQUIRE(port);
    REQUIRE(SetFileCompletionNotificationModes((HANDLE)u, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    oio_ovl(&o, NULL);
    OEQ(oio_post_recv(u, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSAENOTCONN);
    NOPKT(port);
    CloseHandle(port); U(closesocket)(u);
}

TEST(oio_iocp_set_modes_accepts_defined_bits)
{
    SOCKET c, s; UP(); PAIR(c, s);
    HANDLE port = attach(c, 1, NULL); REQUIRE(port);
    CHECK(SetFileCompletionNotificationModes((HANDLE)c, 0));
    CHECK(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_SET_EVENT_ON_HANDLE));
    CHECK(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE));
    CloseHandle(port); oio_close2(c, s);
}

TEST(oio_iocp_set_modes_rejects_undefined_bits)
{
    SOCKET c, s; UP(); PAIR(c, s);
    SetLastError(0);
    BOOL r = SetFileCompletionNotificationModes((HANDLE)c, 0x80);
    t_note("undefined completion-mode bit: ret %d err %lu", (int)r, r ? 0UL : GetLastError());
    oio_close2(c, s);
}

/* The low bit of hEvent suppresses the packet; the request still completes and is queryable. */
TEST(oio_iocp_event_low_bit_suppresses_packet)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl, bytes = 0, f2; int err; HANDLE ev = oio_event();
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 3, NULL); REQUIRE(port);
    oio_ovl(&o, (HANDLE)((ULONG_PTR)ev | 1));
    OEQ(oio_post_recv(c, buf, sizeof buf, &o, &fl), SOCKET_ERROR);
    OEQ(WERR(), WSA_IO_PENDING);
    oio_send(s, "q", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    NOPKT(port);
    OEQ(U(WSAGetOverlappedResult)(c, &o, &bytes, FALSE, &f2), TRUE);
    OEQ(bytes, 1);
    CloseHandle(port); CloseHandle(ev); oio_close2(c, s);
}

/* Cancelling a request with CancelIoEx posts an abort packet: FALSE, ERROR_OPERATION_ABORTED, 0 bytes. */
TEST(oio_iocp_cancel_posts_aborted_packet)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; pkt p;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 0x55, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    CHECK(CancelIoEx((HANDLE)c, &o));
    CHECK(deq(port, OIO_WAIT, &p));
    OEQ(p.ok, FALSE); OEQ(p.err, ERROR_OPERATION_ABORTED); OEQ(p.bytes, 0); OEQ(p.key, 0x55); OEQ(p.ov, &o);
    OEQ(o.Internal, OIO_STATUS_CANCELLED);
    OEQ(U(WSAGetOverlappedResult)(c, &o, &p.bytes, FALSE, &fl), FALSE);
    OEQ(WERR(), WSA_OPERATION_ABORTED);
    CloseHandle(port); oio_close2(c, s);
}

/* Packets for several requests arrive in submission order, each with its own OVERLAPPED. */
TEST(oio_iocp_packet_order_matches_submission)
{
    SOCKET c, s; WSAOVERLAPPED o[4]; char b[4][1]; DWORD fl; pkt p;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 1, NULL); REQUIRE(port);
    for (int i = 0; i < 4; i++) { oio_ovl(&o[i], NULL); oio_post_recv(c, b[i], 1, &o[i], &fl); }
    oio_send(s, "WXYZ", 4);
    for (int i = 0; i < 4; i++) {
        CHECK(deq(port, OIO_WAIT, &p));
        OEQ(p.ov, &o[i]); OEQ(p.bytes, 1);
    }
    CHECK(b[0][0] == 'W' && b[1][0] == 'X' && b[2][0] == 'Y' && b[3][0] == 'Z');
    CloseHandle(port); oio_close2(c, s);
}

/* Two sockets on one port: each packet carries the key of its own socket. */
TEST(oio_iocp_keys_are_per_socket)
{
    SOCKET c1, s1, c2, s2; WSAOVERLAPPED o1, o2; char b1[2], b2[2]; DWORD fl; pkt p;
    UP(); PAIR(c1, s1); PAIR(c2, s2);
    HANDLE port = attach(c1, 0xA1, NULL); REQUIRE(port);
    HANDLE p2 = attach(c2, 0xB2, port); CHECK(p2 == port);
    oio_ovl(&o1, NULL); oio_ovl(&o2, NULL);
    oio_post_recv(c1, b1, 2, &o1, &fl); oio_post_recv(c2, b2, 2, &o2, &fl);
    oio_send(s2, "2", 1);
    CHECK(deq(port, OIO_WAIT, &p)); OEQ(p.key, 0xB2); OEQ(p.ov, &o2);
    oio_send(s1, "1", 1);
    CHECK(deq(port, OIO_WAIT, &p)); OEQ(p.key, 0xA1); OEQ(p.ov, &o1);
    CloseHandle(port); oio_close2(c1, s1); oio_close2(c2, s2);
}

/* Batch dequeue returns all queued completions with their entry fields. */
TEST(oio_iocp_getqueuedcompletionstatusex_batch)
{
    SOCKET c, s; WSAOVERLAPPED o[3]; char b[3][2]; DWORD fl; OVERLAPPED_ENTRY e[8]; ULONG n = 0;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 0x77, NULL); REQUIRE(port);
    for (int i = 0; i < 3; i++) { oio_ovl(&o[i], NULL); oio_post_recv(c, b[i], 2, &o[i], &fl); }
    oio_send(s, "aabbcc", 6);
    Sleep(150);
    CHECK(GetQueuedCompletionStatusEx(port, e, 8, &n, OIO_WAIT, FALSE));
    OEQ(n, 3);
    for (ULONG i = 0; i < n && i < 3; i++) {
        OEQ(e[i].lpOverlapped, &o[i]); OEQ(e[i].dwNumberOfBytesTransferred, 2); OEQ(e[i].lpCompletionKey, 0x77);
        OEQ(e[i].lpOverlapped->Internal, OIO_STATUS_SUCCESS);
    }
    CloseHandle(port); oio_close2(c, s);
}

/* Peer close: the pending receive packet is a success with zero bytes. */
TEST(oio_iocp_peer_close_packet_zero_bytes)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[8]; DWORD fl; pkt p;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 1, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    U(closesocket)(s);
    CHECK(deq(port, OIO_WAIT, &p)); CHECK(p.ok); OEQ(p.bytes, 0); OEQ(p.ov, &o);
    CloseHandle(port); U(closesocket)(c);
}

/* A gather send with a port: one packet for the whole call with the total byte count. */
TEST(oio_iocp_gather_send_single_packet_total_bytes)
{
    SOCKET c, s; WSAOVERLAPPED o; pkt p; char got[8];
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 1, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    WSABUF b[3] = { {2, (CHAR *)"ab"}, {0, (CHAR *)""}, {3, (CHAR *)"cde"} };
    int rc = U(WSASend)(c, b, 3, NULL, 0, &o, NULL);
    CHECK(rc == 0 || WERR() == WSA_IO_PENDING);
    CHECK(deq(port, OIO_WAIT, &p)); OEQ(p.bytes, 5); OEQ(p.ov, &o);
    NOPKT(port);
    U(recv)(s, got, 5, 0);
    CloseHandle(port); oio_close2(c, s);
}

/* Both ends attached to separate ports; each side's packets stay on its own port. */
TEST(oio_iocp_each_end_own_port)
{
    SOCKET c, s; WSAOVERLAPPED oc, os; char bc[4], bs[4]; DWORD fl; pkt p;
    UP(); PAIR(c, s);
    HANDLE pc = attach(c, 1, NULL), ps = attach(s, 2, NULL); REQUIRE(pc && ps);
    oio_ovl(&oc, NULL); oio_ovl(&os, NULL);
    oio_post_recv(c, bc, 4, &oc, &fl); oio_post_recv(s, bs, 4, &os, &fl);
    oio_send(s, "S", 1);
    CHECK(deq(pc, OIO_WAIT, &p)); OEQ(p.key, 1); OEQ(p.ov, &oc);
    NOPKT(ps);
    oio_send(c, "C", 1);
    CHECK(deq(ps, OIO_WAIT, &p)); OEQ(p.key, 2); OEQ(p.ov, &os);
    NOPKT(pc);
    CloseHandle(pc); CloseHandle(ps); oio_close2(c, s);
}

/* Pending request, port handle closed first, then the socket: no hang and no crash. */
TEST(oio_iocp_close_port_before_socket_with_pending_recv)
{
    SOCKET c, s; WSAOVERLAPPED o; char buf[4]; DWORD fl;
    UP(); PAIR(c, s);
    HANDLE port = attach(c, 1, NULL); REQUIRE(port);
    oio_ovl(&o, NULL);
    oio_post_recv(c, buf, sizeof buf, &o, &fl);
    CloseHandle(port);
    U(closesocket)(c); U(closesocket)(s);
    Sleep(50);
}

/* A completion routine request on a socket that is NOT attached to a port still works while another
 * socket is attached. */
TEST(oio_iocp_unattached_socket_unaffected_by_other_attachment)
{
    SOCKET c1, s1, c2, s2; WSAOVERLAPPED o; char buf[4]; DWORD fl, bytes, f2; int err; HANDLE ev = oio_event();
    UP(); PAIR(c1, s1); PAIR(c2, s2);
    HANDLE port = attach(c1, 1, NULL); REQUIRE(port);
    oio_ovl(&o, ev);
    oio_post_recv(c2, buf, 4, &o, &fl);
    oio_send(s2, "u", 1);
    OEQ(oio_wait(ev, OIO_WAIT), WAIT_OBJECT_0);
    CHECK(oio_finish(c2, &o, &bytes, &f2, &err));
    NOPKT(port);
    CloseHandle(port); CloseHandle(ev); oio_close2(c1, s1); oio_close2(c2, s2);
}

/* A socket created without WSA_FLAG_OVERLAPPED cannot join a port (recorded, not asserted). */
TEST(oio_iocp_nonoverlapped_socket_association)
{
    SOCKET c, s; UP(); PAIR_PLAIN(c, s);
    SetLastError(0);
    HANDLE port = CreateIoCompletionPort((HANDLE)c, NULL, 1, 0);
    t_note("associate non-overlapped socket: %s err %lu", port ? "accepted" : "rejected", port ? 0 : GetLastError());
    if (port) CloseHandle(port);
    oio_close2(c, s);
}
