/* Additional AFD data-path edge cases: handle-level failures of the raw requests, several connects to one
 * listener, an urgent-data request that stays queued, datagram receive with a scatter list, and datagram
 * peek requests that wait for a datagram.
 */
#include "csr.h"

static HANDLE new_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

TEST(csrx_unallocated_handle_is_invalid_handle) {
    CS_BEGIN();
    SOCKET s = (SOCKET)0x00fffff0;                         /* a handle value this process never received */
    char b[4];
    CS_R r = cs_recv(s, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_SYNC(r, CS_INVALID_HANDLE);
    r = cs_send(s, "x", 1, 0, 0);
    CHECK_SYNC(r, CS_INVALID_HANDLE);
    r = cs_disc(s, CS_DISC_SEND);
    CHECK_SYNC(r, CS_INVALID_HANDLE);
}
TEST(csrx_non_file_handle_is_type_mismatch) {
    CS_BEGIN();
    HANDLE ev = new_event();
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    char b[4]; WSABUF wb = { sizeof b, b };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL;
    LONG st = X.ioctl(ev, NULL, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0);
    CHECK_ST(st, 0xC0000024UL);                            /* an event is not a file object */
    CloseHandle(ev);
}
TEST(csrx_unknown_control_code_is_refused) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    UCHAR in[32]; memset(in, 0, sizeof in);
    CS_R r = cs_ioctl(c, 0x12ffbu, in, sizeof in, NULL, 0);
    CHECKF((ULONG)r.final != CS_SUCCESS && (ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT,
           "an unassigned control code was accepted: 0x%08lx", (unsigned long)r.final);
    t_note("unassigned AFD control code: 0x%08lx", (unsigned long)r.final);
    cs_close(c); cs_close(s);
}
TEST(csrx_two_connects_to_one_listener) {
    CS_BEGIN();
    struct sockaddr_in la, c1a, c2a, p1, p2; int n;
    SOCKET l = cs_listener(&la);
    SOCKET c1 = cs_sock(AF_INET, SOCK_STREAM), c2 = cs_sock(AF_INET, SOCK_STREAM);
    cs_bind_lo(c1, &c1a); cs_bind_lo(c2, &c2a);
    CHECK_ST(cs_connect(c1, &la, sizeof la).final, CS_SUCCESS);
    CHECK_ST(cs_connect(c2, &la, sizeof la).final, CS_SUCCESS);
    SOCKET a1 = INVALID_SOCKET, a2 = INVALID_SOCKET;
    if (cs_readable(l, CS_WAIT)) a1 = X.accept(l, NULL, NULL);
    if (cs_readable(l, CS_WAIT)) a2 = X.accept(l, NULL, NULL);
    CHECK(a1 != INVALID_SOCKET && a2 != INVALID_SOCKET);
    if (a1 != INVALID_SOCKET && a2 != INVALID_SOCKET) {
        n = sizeof p1; CHECK(X.getpeername(a1, (struct sockaddr *)&p1, &n) == 0);
        n = sizeof p2; CHECK(X.getpeername(a2, (struct sockaddr *)&p2, &n) == 0);
        CHECK(p1.sin_port == c1a.sin_port && p2.sin_port == c2a.sin_port);   /* accepted in connection order */
    }
    cs_close(a1); cs_close(a2); cs_close(c1); cs_close(c2); cs_close(l);
}
TEST(csrx_connect_completion_by_event_and_apc_free_submit) {
    CS_BEGIN();
    struct sockaddr_in la, ca;
    SOCKET l = cs_listener(&la), c = cs_sock(AF_INET, SOCK_STREAM);
    cs_bind_lo(c, &ca);
    UCHAR req[0x18 + sizeof la]; memset(req, 0, sizeof req); memcpy(req + 0x18, &la, sizeof la);
    HANDLE ev = new_event();
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_CONNECT, req, sizeof req, NULL, 0);
    CHECK_ST2(st, CS_PENDING, CS_SUCCESS);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 0);
    CloseHandle(ev);
    if (cs_readable(l, CS_WAIT)) cs_close(X.accept(l, NULL, NULL));
    cs_close(c); cs_close(l);
}
TEST(csrx_urgent_request_stays_queued_without_urgent_data) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = new_event();
    char buf[4]; WSABUF wb = { sizeof buf, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_EXPEDITED;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0), CS_PENDING);
    CHECK(X.send(s, "plain", 5, 0) == 5);                  /* ordinary data does not satisfy an urgent request */
    CHECK(cs_readable(c, CS_WAIT));
    CHECK(WaitForSingleObject(ev, 100) == WAIT_TIMEOUT);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_CANCELLED);
    char got[8] = {0};
    CHECK(X.recv(c, got, sizeof got, 0) == 5 && !memcmp(got, "plain", 5));
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrx_dgram_scatter_truncation_reports_overflow) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "abcdef", 6, 0, (struct sockaddr *)&aa, sizeof aa) == 6);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[8]; memset(buf, '.', sizeof buf);
    WSABUF wb[2] = { { 2, buf }, { 2, buf + 4 } };
    struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = wb; d.count = 2; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    CS_R r = cs_ioctl(a, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_ST(r.final, CS_BUFFER_OVERFLOW);
    CHECK(r.io.Information == 4);
    CHECK(!memcmp(buf, "ab..cd..", 8));
    cs_close(a); cs_close(b);
}
TEST(csrx_dgram_peek_waits_for_a_datagram_then_keeps_it) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    HANDLE ev = new_event();
    char buf[8] = {0}; WSABUF wb = { sizeof buf, buf }; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL | CS_TDI_PEEK; d.addr = &from; d.addrlen = &fl;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(a, ev, NULL, NULL, &io, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0), CS_PENDING);
    CHECK(X.sendto(b, "peeked", 6, 0, (struct sockaddr *)&aa, sizeof aa) == 6);
    CHECK(cs_await(a, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 6 && !memcmp(buf, "peeked", 6));
    char got[8] = {0};
    CHECK(cs_readable(a, CS_WAIT) && X.recv(a, got, sizeof got, 0) == 6 && !memcmp(got, "peeked", 6));
    CloseHandle(ev); cs_close(a); cs_close(b);
}
TEST(csrx_dgram_two_pended_receives_complete_in_order) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    HANDLE e1 = new_event(), e2 = new_event();
    char b1[8] = {0}, b2[8] = {0};
    WSABUF w1 = { sizeof b1, b1 }, w2 = { sizeof b2, b2 };
    struct sockaddr_in f1, f2; ULONG l1 = sizeof f1, l2 = sizeof f2;
    CS_RDG d1, d2; memset(&d1, 0, sizeof d1); memset(&d2, 0, sizeof d2);
    d1.buf = &w1; d1.count = 1; d1.tdi = CS_TDI_NORMAL; d1.addr = &f1; d1.addrlen = &l1;
    d2.buf = &w2; d2.count = 1; d2.tdi = CS_TDI_NORMAL; d2.addr = &f2; d2.addrlen = &l2;
    IO_STATUS_BLOCK i1, i2; memset(&i1, 0xAB, sizeof i1); memset(&i2, 0xAB, sizeof i2);
    CHECK_ST(cs_submit(a, e1, NULL, NULL, &i1, CS_IOCTL_RECV_DGRAM, &d1, sizeof d1, NULL, 0), CS_PENDING);
    CHECK_ST(cs_submit(a, e2, NULL, NULL, &i2, CS_IOCTL_RECV_DGRAM, &d2, sizeof d2, NULL, 0), CS_PENDING);
    CHECK(X.sendto(b, "one", 3, 0, (struct sockaddr *)&aa, sizeof aa) == 3);
    CHECK(WaitForSingleObject(e1, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(i1.Information == 3 && !memcmp(b1, "one", 3));
    CHECK(WaitForSingleObject(e2, 100) == WAIT_TIMEOUT);
    CHECK(X.sendto(b, "two", 3, 0, (struct sockaddr *)&aa, sizeof aa) == 3);
    CHECK(cs_await(a, e2, &i2, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(i2.Information == 3 && !memcmp(b2, "two", 3));
    CloseHandle(e1); CloseHandle(e2); cs_close(a); cs_close(b);
}
TEST(csrx_dgram_close_cancels_pended_receive) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    HANDLE ev = new_event();
    char buf[8]; WSABUF wb = { sizeof buf, buf }; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(a, ev, NULL, NULL, &io, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0), CS_PENDING);
    cs_close(a);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_CANCELLED);
    CHECK(io.Information == 0);
    CloseHandle(ev); cs_close(b);
}
TEST(csrx_dgram_receive_with_small_address_length_note) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "short", 5, 0, (struct sockaddr *)&aa, sizeof aa) == 5);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[8] = {0}; UCHAR from[32]; memset(from, 0, sizeof from); ULONG fl = 4;
    WSABUF wb = { sizeof buf, buf };
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL; d.addr = from; d.addrlen = &fl;
    CS_R r = cs_ioctl(a, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "receive with a short address area did not complete");
    t_note("datagram receive with a 4-byte address area: 0x%08lx", (unsigned long)r.final);
    cs_close(a); cs_close(b);
}
TEST(csrx_stream_request_on_bound_udp_with_data_note) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "dg", 2, 0, (struct sockaddr *)&aa, sizeof aa) == 2);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[8] = {0};
    CS_R r = cs_recv(a, buf, sizeof buf, CS_TDI_NORMAL, 0);
    CHECKF((ULONG)r.final != CS_TIMEOUT, "plain receive on a datagram socket did not complete");
    t_note("plain receive request on a datagram socket with a datagram queued: 0x%08lx info %llu",
           (unsigned long)r.final, (unsigned long long)r.io.Information);
    cs_close(a); cs_close(b);
}
TEST(csrx_receive_after_graceful_close_returns_buffered_data_first) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "tail", 4, 0) == 4);
    cs_close(s);                                           /* orderly close behind the data */
    CHECK(cs_readable(c, CS_WAIT));
    char b[8] = {0};
    CS_R r = cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 4);
    CHECK(!memcmp(b, "tail", 4));
    r = cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 0);
    cs_close(c);
}
TEST(csrx_send_after_close_of_peer_after_read_eof) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(s, SD_SEND) == 0);
    char b[4];
    CS_R r = cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 0);
    CHECK_DONE(cs_send(c, "reply", 5, 0, 0), CS_SUCCESS, 5);   /* the other direction is still open */
    char got[8] = {0};
    CHECK(cs_readable(s, CS_WAIT) && X.recv(s, got, sizeof got, 0) == 5 && !memcmp(got, "reply", 5));
    cs_close(c); cs_close(s);
}
