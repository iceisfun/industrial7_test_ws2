/* IOCTL_AFD_RECEIVE_DATAGRAM (0x1201b) and IOCTL_AFD_SEND_DATAGRAM (0x12023) on loopback UDP sockets.
 *
 * Receive request (40 bytes): buffer list, AFD flags, TDI flags, a buffer for the sender's address and a
 * pointer to its length. Send request (104 bytes): buffer list, AFD flags, destination length at +0x58 and a
 * pointer to the destination socket address at +0x60.
 *
 * Checks seen in the driver, in order: the endpoint must be a datagram endpoint (invalid parameter otherwise),
 * the receive/send shutdown flag (pipe-disconnected), the endpoint must be bound or connected (invalid
 * parameter), the request block must be complete, then the buffer list and the address are examined.
 */
#include "csr.h"

static HANDLE new_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

/* ===== receive ================================================================================================ */
TEST(csrdgr_tcp_socket_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char b[8]; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(c, b, sizeof b, &from, &fl, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrdgr_unbound_udp_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET u = cs_sock(AF_INET, SOCK_DGRAM);
    char b[8]; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(u, b, sizeof b, &from, &fl, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(u);
}
TEST(csrdgr_input_length_table) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    char buf[8]; WSABUF wb = { sizeof buf, buf }; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    static const ULONG lens[] = { 0, 8, 16, 24, 32, 39 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        CS_R r = cs_ioctl(a, CS_IOCTL_RECV_DGRAM, &d, lens[i], NULL, 0);
        CHECKF((ULONG)r.first == CS_INVALID_PARAMETER && (ULONG)r.final == CS_INVALID_PARAMETER,
               "input length %lu: 0x%08lx", lens[i], (unsigned long)r.first);
    }
    cs_close(a); cs_close(b);
}
TEST(csrdgr_receive_shutdown_is_pipe_disconnected) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_RECEIVE).final, CS_SUCCESS);
    char buf[8]; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_PIPE_DISCONNECTED);
    cs_close(a); cs_close(b);
}
TEST(csrdgr_receive_with_sender_address) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "hello", 5, 0, (struct sockaddr *)&aa, sizeof aa) == 5);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[16] = {0}; struct sockaddr_in from; memset(&from, 0xEE, sizeof from); ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 5);
    CHECK(!memcmp(buf, "hello", 5));
    CHECK(from.sin_family == AF_INET);
    CHECK(from.sin_port == ba.sin_port);
    CHECK(from.sin_addr.s_addr == ba.sin_addr.s_addr);
    CHECK(fl == sizeof from);
    cs_close(a); cs_close(b);
}
TEST(csrdgr_pended_receive_completes_on_arrival) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    HANDLE ev = new_event();
    char buf[16] = {0}; WSABUF wb = { sizeof buf, buf }; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(a, ev, NULL, NULL, &io, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0), CS_PENDING);
    CHECK(WaitForSingleObject(ev, 50) == WAIT_TIMEOUT);
    CHECK(X.sendto(b, "later", 5, 0, (struct sockaddr *)&aa, sizeof aa) == 5);
    CHECK(cs_await(a, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 5 && !memcmp(buf, "later", 5));
    CHECK(from.sin_port == ba.sin_port);
    CloseHandle(ev); cs_close(a); cs_close(b);
}
TEST(csrdgr_message_boundaries_are_kept) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "one", 3, 0, (struct sockaddr *)&aa, sizeof aa) == 3);
    CHECK(X.sendto(b, "three", 5, 0, (struct sockaddr *)&aa, sizeof aa) == 5);
    CHECK(X.sendto(b, "22", 2, 0, (struct sockaddr *)&aa, sizeof aa) == 2);
    static const struct { const char *t; ULONG n; } want[3] = { { "one", 3 }, { "three", 5 }, { "22", 2 } };
    for (int i = 0; i < 3; i++) {
        CHECK(cs_readable(a, CS_WAIT));
        char buf[16] = {0}; struct sockaddr_in from; ULONG fl = sizeof from;
        CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
        CHECK_DONE(r, CS_SUCCESS, want[i].n);
        CHECK(!memcmp(buf, want[i].t, want[i].n));
    }
    cs_close(a); cs_close(b);
}
TEST(csrdgr_zero_length_datagram) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "", 0, 0, (struct sockaddr *)&aa, sizeof aa) == 0);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[8]; memset(buf, 0x55, sizeof buf); struct sockaddr_in from; ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_DONE(r, CS_SUCCESS, 0);
    CHECK((unsigned char)buf[0] == 0x55);
    CHECK(from.sin_port == ba.sin_port);
    cs_close(a); cs_close(b);
}
TEST(csrdgr_truncation_reports_overflow_and_consumes) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "0123456789", 10, 0, (struct sockaddr *)&aa, sizeof aa) == 10);
    CHECK(X.sendto(b, "next", 4, 0, (struct sockaddr *)&aa, sizeof aa) == 4);
    CHECK(cs_readable(a, CS_WAIT));
    Sleep(20);
    char small[4] = {0}; struct sockaddr_in from; memset(&from, 0, sizeof from); ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(a, small, sizeof small, &from, &fl, CS_TDI_NORMAL);
    CHECK_ST(r.final, CS_BUFFER_OVERFLOW);
    CHECK(r.io.Information == 4);
    CHECK(!memcmp(small, "0123", 4));
    CHECK(from.sin_port == ba.sin_port);                   /* the sender is still reported */
    char buf[16] = {0};
    r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_DONE(r, CS_SUCCESS, 4);                          /* the truncated datagram is gone: next one follows */
    CHECK(!memcmp(buf, "next", 4));
    cs_close(a); cs_close(b);
}
TEST(csrdgr_peek_keeps_the_datagram) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "stay", 4, 0, (struct sockaddr *)&aa, sizeof aa) == 4);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[8] = {0}; struct sockaddr_in from; ULONG fl = sizeof from;
    for (int i = 0; i < 2; i++) {
        memset(buf, 0, sizeof buf);
        CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL | CS_TDI_PEEK);
        CHECK_DONE(r, CS_SUCCESS, 4);
        CHECK(!memcmp(buf, "stay", 4));
    }
    CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_DONE(r, CS_SUCCESS, 4);
    cs_close(a); cs_close(b);
}
TEST(csrdgr_scatter_list_receives_one_datagram) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "abcdef", 6, 0, (struct sockaddr *)&aa, sizeof aa) == 6);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[8]; memset(buf, '.', sizeof buf);
    WSABUF wb[3] = { { 2, buf }, { 0, buf + 5 }, { 4, buf + 3 } };
    struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = wb; d.count = 3; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    CS_R r = cs_ioctl(a, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_DONE(r, CS_SUCCESS, 6);
    CHECK(!memcmp(buf, "ab.cdef.", 8));
    cs_close(a); cs_close(b);
}
TEST(csrdgr_two_senders_are_told_apart) {
    CS_BEGIN();
    SOCKET a, b, c; struct sockaddr_in aa, ba, ca;
    cs_udp_pair(&a, &b, &aa, &ba);
    c = cs_sock(AF_INET, SOCK_DGRAM); cs_bind_lo(c, &ca);
    CHECK(X.sendto(b, "B", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    CHECK(X.sendto(c, "C", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    for (int i = 0; i < 2; i++) {
        CHECK(cs_readable(a, CS_WAIT));
        char buf[4] = {0}; struct sockaddr_in from; ULONG fl = sizeof from;
        CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
        CHECK_DONE(r, CS_SUCCESS, 1);
        CHECK(from.sin_port == (buf[0] == 'B' ? ba.sin_port : ca.sin_port));
    }
    cs_close(a); cs_close(b); cs_close(c);
}
TEST(csrdgr_null_buffer_list_is_accepted_as_empty_note) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "xyz", 3, 0, (struct sockaddr *)&aa, sizeof aa) == 3);
    CHECK(cs_readable(a, CS_WAIT));
    struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.count = 0; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    CS_R r = cs_ioctl(a, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0);
    CHECKF((ULONG)r.final != CS_INVALID_PARAMETER, "an empty buffer list was refused as invalid");
    t_note("datagram receive with no buffers: 0x%08lx info %llu", (unsigned long)r.final, (unsigned long long)r.io.Information);
    cs_close(a); cs_close(b);
}
TEST(csrdgr_cancel_pended_receive) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    HANDLE ev = new_event();
    char buf[8]; WSABUF wb = { sizeof buf, buf }; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(a, ev, NULL, NULL, &io, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)a, &cio), CS_SUCCESS);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_CANCELLED);
    CHECK(io.Information == 0);
    CloseHandle(ev); cs_close(a); cs_close(b);
}
TEST(csrdgr_icmp_port_unreachable_fails_a_later_receive) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    cs_close(b);                                           /* nothing listens at ba any more */
    CHECK(X.sendto(a, "knock", 5, 0, (struct sockaddr *)&ba, sizeof ba) == 5);
    CHECK(cs_readable(a, CS_WAIT));                        /* the error makes the socket readable */
    char buf[8]; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECKF((ULONG)r.final != CS_SUCCESS && (ULONG)r.final != CS_TIMEOUT, "receive after an ICMP error: 0x%08lx", (unsigned long)r.final);
    t_note("receive after ICMP port unreachable: 0x%08lx", (unsigned long)r.final);
    cs_close(a);
}

/* ===== send =================================================================================================== */
TEST(csrdgs_tcp_socket_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    struct sockaddr_in to = cs_lo4(BE16(9));
    CS_R r = cs_sendto(c, "x", 1, &to, sizeof to, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrdgs_unbound_udp_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET u = cs_sock(AF_INET, SOCK_DGRAM);
    struct sockaddr_in to = cs_lo4(BE16(9));
    CS_R r = cs_sendto(u, "x", 1, &to, sizeof to, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(u);
}
TEST(csrdgs_input_length_table) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    WSABUF wb = { 1, "x" };
    CS_SDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.addr = &ba; d.addrlen = sizeof ba;
    static const ULONG lens[] = { 0, 8, 0x28, 0x58, 0x60, 0x67 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        CS_R r = cs_ioctl(a, CS_IOCTL_SEND_DGRAM, &d, lens[i], NULL, 0);
        CHECKF((ULONG)r.first == CS_INVALID_PARAMETER && (ULONG)r.final == CS_INVALID_PARAMETER,
               "input length %lu: 0x%08lx", lens[i], (unsigned long)r.first);
    }
    cs_close(a); cs_close(b);
}
TEST(csrdgs_send_to_peer) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba, from; int n = sizeof from;
    cs_udp_pair(&a, &b, &aa, &ba);
    CS_R r = cs_sendto(a, "dgram", 5, &ba, sizeof ba, 0);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 5);
    char buf[16] = {0};
    CHECK(cs_readable(b, CS_WAIT));
    CHECK(X.recvfrom(b, buf, sizeof buf, 0, (struct sockaddr *)&from, &n) == 5 && !memcmp(buf, "dgram", 5));
    CHECK(from.sin_port == aa.sin_port);                   /* the datagram carries the sender's bound port */
    CHECK(from.sin_addr.s_addr == aa.sin_addr.s_addr);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_zero_length_datagram) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CS_R r = cs_sendto(a, "", 0, &ba, sizeof ba, 0);
    CHECK_DONE(r, CS_SUCCESS, 0);
    char buf[4];
    CHECK(cs_readable(b, CS_WAIT));
    CHECK(X.recv(b, buf, sizeof buf, 0) == 0);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_scatter_list_makes_one_datagram) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    WSABUF wb[3] = { { 2, "ab" }, { 0, NULL }, { 3, "cde" } };
    CS_SDG d; memset(&d, 0, sizeof d); d.buf = wb; d.count = 3; d.addr = &ba; d.addrlen = sizeof ba;
    CS_R r = cs_ioctl(a, CS_IOCTL_SEND_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_DONE(r, CS_SUCCESS, 5);
    char buf[16] = {0};
    CHECK(cs_readable(b, CS_WAIT) && X.recv(b, buf, sizeof buf, 0) == 5 && !memcmp(buf, "abcde", 5));
    cs_close(a); cs_close(b);
}
TEST(csrdgs_send_from_connected_socket_to_other_address) {
    CS_BEGIN();
    SOCKET a, b, c; struct sockaddr_in aa, ba, ca;
    cs_udp_pair(&a, &b, &aa, &ba);
    c = cs_sock(AF_INET, SOCK_DGRAM); cs_bind_lo(c, &ca);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CS_R r = cs_sendto(a, "hop", 3, &ca, sizeof ca, 0);
    CHECK_DONE(r, CS_SUCCESS, 3);
    char buf[8] = {0};
    CHECK(cs_readable(c, CS_WAIT) && X.recv(c, buf, sizeof buf, 0) == 3 && !memcmp(buf, "hop", 3));
    cs_close(a); cs_close(b); cs_close(c);
}
TEST(csrdgs_send_to_self) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CS_R r = cs_sendto(a, "me", 2, &aa, sizeof aa, 0);
    CHECK_DONE(r, CS_SUCCESS, 2);
    char buf[4] = {0}; struct sockaddr_in from; ULONG fl = sizeof from;
    CHECK(cs_readable(a, CS_WAIT));
    r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_DONE(r, CS_SUCCESS, 2);
    CHECK(from.sin_port == aa.sin_port);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_send_shutdown_does_not_block_datagram_sends) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_SEND).final, CS_SUCCESS);
    CS_R r = cs_sendto(a, "x", 1, &ba, sizeof ba, 0);          /* a datagram socket has no stream to end */
    CHECK_SYNC(r, CS_SUCCESS);
    CHECK(r.io.Information == 1);
    char buf[4] = {0};
    CHECK(cs_readable(b, CS_WAIT) && X.recv(b, buf, sizeof buf, 0) == 1 && buf[0] == 'x');
    cs_close(a); cs_close(b);
}
TEST(csrdgs_destination_shorter_than_two_bytes) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    for (ULONG len = 0; len < 2; len++) {
        CS_R r = cs_sendto(a, "x", 1, &ba, len, 0);
        CHECKF((ULONG)r.final == CS_INVALID_PARAMETER || (ULONG)r.final == CS_INVALID_ADDRESS,
               "destination length %lu: 0x%08lx", len, (unsigned long)r.final);
    }
    cs_close(a); cs_close(b);
}
TEST(csrdgs_destination_shorter_than_family_size) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    static const ULONG lens[] = { 2, 4, 8, 12, 15 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        CS_R r = cs_sendto(a, "x", 1, &ba, lens[i], 0);
        CHECKF((ULONG)r.final == CS_INVALID_ADDRESS || (ULONG)r.final == CS_INVALID_PARAMETER,
               "destination length %lu: 0x%08lx", lens[i], (unsigned long)r.final);
    }
    cs_close(a); cs_close(b);
}
TEST(csrdgs_destination_family_out_of_range) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    struct sockaddr_in to = ba;
    to.sin_family = 0x23;
    CS_R r = cs_sendto(a, "x", 1, &to, sizeof to, 0);
    CHECKF((ULONG)r.final == CS_INVALID_ADDRESS || (ULONG)r.final == CS_INVALID_PARAMETER, "family 0x23: 0x%08lx", (unsigned long)r.final);
    to.sin_family = 0xffff;
    r = cs_sendto(a, "x", 1, &to, sizeof to, 0);
    CHECKF((ULONG)r.final == CS_INVALID_ADDRESS || (ULONG)r.final == CS_INVALID_PARAMETER, "family 0xffff: 0x%08lx", (unsigned long)r.final);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_buffer_list_errors) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    WSABUF wb = { 1, "x" };
    CS_SDG d; memset(&d, 0, sizeof d); d.addr = &ba; d.addrlen = sizeof ba;
    d.buf = &wb; d.count = 0;
    CS_R r = cs_ioctl(a, CS_IOCTL_SEND_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    d.buf = NULL; d.count = 1;
    r = cs_ioctl(a, CS_IOCTL_SEND_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    d.buf = &wb; d.count = 0x10000000;
    r = cs_ioctl(a, CS_IOCTL_SEND_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_oversize_datagram_fails) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    ULONG n = 65508;                                       /* one byte more than a UDP payload can carry */
    char *p = (char *)VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { t_skip("no memory"); cs_close(a); cs_close(b); return; }
    CS_R r = cs_sendto(a, p, n, &ba, sizeof ba, 0);
    CHECKF((ULONG)r.final != CS_SUCCESS && (ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT,
           "oversize datagram: 0x%08lx", (unsigned long)r.final);
    t_note("datagram of 65508 bytes: 0x%08lx", (unsigned long)r.final);
    VirtualFree(p, 0, MEM_RELEASE);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_destination_port_zero_note) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    struct sockaddr_in to = cs_lo4(0);
    CS_R r = cs_sendto(a, "x", 1, &to, sizeof to, 0);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "send to port 0 did not complete");
    t_note("datagram to port 0: 0x%08lx", (unsigned long)r.final);
    cs_close(a); cs_close(b);
}
TEST(csrdgs_many_datagrams_arrive_in_order) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    for (int i = 0; i < 20; i++) {
        char ch = (char)('A' + i);
        CS_R r = cs_sendto(a, &ch, 1, &ba, sizeof ba, 0);
        CHECK_DONE(r, CS_SUCCESS, 1);
    }
    for (int i = 0; i < 20; i++) {
        char ch = 0;
        if (!cs_readable(b, CS_WAIT) || X.recv(b, &ch, 1, 0) != 1) { CHECK(0); break; }
        CHECK(ch == (char)('A' + i));
    }
    cs_close(a); cs_close(b);
}
TEST(csrdgs_v6_loopback_roundtrip) {
    CS_BEGIN();
    if (!cs_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET a = X.WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    SOCKET b = X.WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in6 la, lb; memset(&la, 0, sizeof la);
    la.sin6_family = AF_INET6; la.sin6_addr.u.Byte[15] = 1; lb = la;
    int n = sizeof la;
    CHECK(X.bind(a, (struct sockaddr *)&la, sizeof la) == 0 && X.getsockname(a, (struct sockaddr *)&la, &n) == 0);
    n = sizeof lb;
    CHECK(X.bind(b, (struct sockaddr *)&lb, sizeof lb) == 0 && X.getsockname(b, (struct sockaddr *)&lb, &n) == 0);
    CS_R r = cs_sendto(a, "six", 3, &lb, sizeof lb, 0);
    CHECK_DONE(r, CS_SUCCESS, 3);
    char buf[8] = {0};
    CHECK(cs_readable(b, CS_WAIT));
    struct sockaddr_in6 from; memset(&from, 0, sizeof from); ULONG fl = sizeof from;
    WSABUF wb = { sizeof buf, buf };
    CS_RDG d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL; d.addr = &from; d.addrlen = &fl;
    r = cs_ioctl(b, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0);
    CHECK_DONE(r, CS_SUCCESS, 3);
    CHECK(from.sin6_family == AF_INET6 && from.sin6_port == la.sin6_port);
    CHECK(fl == sizeof from);
    cs_close(a); cs_close(b);
}
