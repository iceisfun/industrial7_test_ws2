/* IOCTL_AFD_RECV on the raw socket handle: argument validation, asynchronous vs synchronous completion,
 * scatter buffers, nonblocking sockets, urgent data, peek, wait-all, orderly close, shutdown, datagram
 * truncation and cancellation by closing the socket.
 *
 * The request is a 24-byte block (buffer array pointer, buffer count, AFD-level flags, TDI-level flags).
 * Exactly one of the two "normal"/"urgent" bits of the TDI word must be present; a zero or doubled selection
 * is an invalid parameter and leaves the status block untouched. */
#include "afdx.h"

static LONG rx(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, AX_RECV *p, ULONG size) {
    return X.ioctl((HANDLE)s, ev, NULL, NULL, io, AX_IOCTL_RECV, p, size, NULL, 0);
}
static void setup_recv(AX_RECV *p, WSABUF *b, int nbuf, ULONG msg_flags) {
    memset(p, 0, sizeof *p);
    p->buffers = b; p->count = nbuf; p->msg_flags = msg_flags;
}
static void send5(SOCKET s, const char *txt) { CHECK(X.send(s, txt, 5, 0) == 5); }

/* A connected pair plus a manual-reset event and a one-buffer request over buf. */
typedef struct { SOCKET c, s; HANDLE ev; char buf[8]; WSABUF wb[2]; AX_RECV p; IO_STATUS_BLOCK io; } RX;
static void rx_open(RX *r) {
    memset(r, 0, sizeof *r);
    r->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&r->c, &r->s, WSA_FLAG_OVERLAPPED);
    memset(r->buf, 0xcc, sizeof r->buf);
    r->wb[0].len = sizeof r->buf; r->wb[0].buf = r->buf;
    setup_recv(&r->p, r->wb, 1, AX_MSG_NOT_OOB);
}
static void rx_close(RX *r) { afdx_close(r->c); afdx_close(r->s); CloseHandle(r->ev); }
static void two_buffers(RX *r) {          /* [0,2) and [3,7) of buf: byte 2 is a hole */
    r->wb[0].len = 2; r->wb[0].buf = r->buf;
    r->wb[1].len = 4; r->wb[1].buf = r->buf + 3;
    setup_recv(&r->p, r->wb, 2, AX_MSG_NOT_OOB);
}

TEST(afdrecv_listener_is_invalid_connection) {
    AFDX_BEGIN();
    SOCKET l; struct sockaddr_in a; IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_listener(&l, &a);
    FILL_IOSB(io, 0);
    /* a listening endpoint is not a data connection: rejected before the input block is even looked at */
    CHECK_ST(rx(l, ev, &io, NULL, 0), AX_STATUS_INVALID_CONNECTION);
    CHECK_IOSB(io, 0, 0);
    afdx_close(l); CloseHandle(ev);
}

TEST(afdrecv_missing_input_is_invalid_parameter) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    FILL_IOSB(r.io, 0);
    CHECK_ST(rx(r.c, r.ev, &r.io, NULL, 0), AX_STATUS_INVALID_PARAMETER);
    CHECK_IOSB(r.io, 0, 0);
    rx_close(&r);
}

TEST(afdrecv_short_input_is_invalid_parameter) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    FILL_IOSB(r.io, 0);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p - 1), AX_STATUS_INVALID_PARAMETER);
    CHECK_IOSB(r.io, 0, 0);
    rx_close(&r);
}

TEST(afdrecv_async_completes_when_data_arrives) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    r.io.Status = 0xdeadbeef; r.io.Information = 0xdeadbeef;
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_PENDING);
    /* a pending request has not touched the status block yet */
    CHECK_ST(r.io.Status, 0xdeadbeef);
    CHECK(r.io.Information == 0xdeadbeef);
    /* the request block and the buffer array are captured at submission and may go away */
    memset(&r.p, 0xcc, sizeof r.p);
    memset(r.wb, 0xcc, sizeof r.wb);
    send5(r.s, "data");
    CHECK(WaitForSingleObject(r.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(r.io, 0, 5);
    CHECK(!memcmp(r.buf, "data", 5));
    rx_close(&r);
}

TEST(afdrecv_scatter_into_two_buffers) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    two_buffers(&r);
    FILL_IOSB(r.io, 0);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_PENDING);
    CHECK_IOSB(r.io, 0, 0);
    send5(r.s, "data");
    CHECK(WaitForSingleObject(r.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(r.io, 0, 5);
    CHECK(!memcmp(r.buf, "da\xcc" "ta", 6));          /* hole byte untouched, then "ta\0" */
    rx_close(&r);
}

TEST(afdrecv_queued_data_completes_synchronously) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    two_buffers(&r);
    send5(r.s, "data");
    AFDX_WAIT_POLL(r.c, r.ev, AX_POLL_READ, AX_POLL_READ);
    FILL_IOSB(r.io, 0xcc);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_SUCCESS);
    CHECK_IOSB(r.io, 0, 5);
    CHECK(!memcmp(r.buf, "da\xcc" "ta", 6));
    rx_close(&r);
}

TEST(afdrecv_nonblocking_without_data_is_not_ready) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    afdx_set_blocking(r.c, 0);
    FILL_IOSB(r.io, 0);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_DEVICE_NOT_READY);
    CHECK_IOSB(r.io, AX_STATUS_DEVICE_NOT_READY, 0);
    rx_close(&r);
}

TEST(afdrecv_nonblocking_with_data_succeeds) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    afdx_set_blocking(r.c, 0);
    send5(r.s, "data");
    AFDX_WAIT_POLL(r.c, r.ev, AX_POLL_READ, AX_POLL_READ);
    FILL_IOSB(r.io, 0xcc);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_SUCCESS);
    CHECK_IOSB(r.io, 0, 5);
    CHECK(!memcmp(r.buf, "data", 5));
    rx_close(&r);
}

TEST(afdrecv_force_async_pends_on_nonblocking_socket) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    afdx_set_blocking(r.c, 0);
    r.p.recv_flags = AX_RECV_FORCE_ASYNC;
    FILL_IOSB(r.io, 0);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_PENDING);
    CHECK_IOSB(r.io, 0, 0);
    send5(r.s, "data");
    CHECK(WaitForSingleObject(r.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(r.io, 0, 5);
    CHECK(!memcmp(r.buf, "data", 5));
    rx_close(&r);
}

/* Urgent byte first, then ordinary data: the "normal only" request must skip the urgent byte. */
static void oob_then_data(RX *r) {
    CHECK(X.send(r->s, "a", 1, MSG_OOB) == 1);
    send5(r->s, "data");
    AFDX_WAIT_POLL(r->c, r->ev, AX_POLL_READ, AX_POLL_READ);
}

TEST(afdrecv_normal_request_skips_urgent_byte) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    oob_then_data(&r);
    FILL_IOSB(r.io, 0xcc);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_SUCCESS);
    CHECK_IOSB(r.io, 0, 5);
    CHECK(!memcmp(r.buf, "data", 5));
    rx_close(&r);
}

TEST(afdrecv_zero_message_class_is_invalid_parameter) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    r.p.msg_flags = 0;
    r.io.Status = 0xdeadbeef;
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_INVALID_PARAMETER);
    CHECK_ST(r.io.Status, 0xdeadbeef);               /* rejected synchronously: status block not written */
    rx_close(&r);
}

TEST(afdrecv_both_message_classes_is_invalid_parameter) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    r.p.msg_flags = AX_MSG_OOB | AX_MSG_NOT_OOB;
    r.io.Status = 0xdeadbeef;
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_INVALID_PARAMETER);
    CHECK_ST(r.io.Status, 0xdeadbeef);
    rx_close(&r);
}

TEST(afdrecv_urgent_request_returns_urgent_byte) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    oob_then_data(&r);
    /* drain the ordinary data so only the urgent byte remains */
    FILL_IOSB(r.io, 0xcc);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_SUCCESS);
    r.p.msg_flags = AX_MSG_OOB;
    memset(r.buf, 0xcc, sizeof r.buf);
    FILL_IOSB(r.io, 0xcc);
    LONG st = rx(r.c, r.ev, &r.io, &r.p, sizeof r.p);
    CHECK_ST(st, AX_STATUS_SUCCESS);
    if ((ULONG)st == AX_STATUS_PENDING) {            /* keep the run bounded if it did not complete inline */
        U(CancelIo)((HANDLE)r.c);
        WaitForSingleObject(r.ev, 1000);
    } else {
        CHECK_IOSB(r.io, 0, 1);
        CHECK(r.buf[0] == 'a');
    }
    rx_close(&r);
}

TEST(afdrecv_peek_does_not_consume) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    two_buffers(&r);
    r.p.msg_flags = AX_MSG_NOT_OOB | AX_MSG_PEEK;
    CHECK(X.send(r.s, "data", 4, 0) == 4);
    AFDX_WAIT_POLL(r.c, r.ev, AX_POLL_READ, AX_POLL_READ);
    for (int i = 0; i < 2; i++) {                    /* the same bytes show up twice */
        memset(r.buf, 0xcc, sizeof r.buf);
        FILL_IOSB(r.io, 0xcc);
        CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_SUCCESS);
        CHECK_IOSB(r.io, 0, 4);
        CHECK(!memcmp(r.buf, "da\xcc" "ta", 5));
    }
    rx_close(&r);
}

TEST(afdrecv_waitall_pends_until_buffers_full) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    two_buffers(&r);                                  /* room for 6 bytes */
    r.p.msg_flags = AX_MSG_NOT_OOB | AX_MSG_WAITALL;
    CHECK(X.send(r.s, "data", 4, 0) == 4);
    AFDX_WAIT_POLL(r.c, r.ev, AX_POLL_READ, AX_POLL_READ);
    FILL_IOSB(r.io, 0xcc);
    LONG st = rx(r.c, r.ev, &r.io, &r.p, sizeof r.p);
    CHECK_ST(st, AX_STATUS_PENDING);                  /* four bytes are not enough */
    if ((ULONG)st == AX_STATUS_PENDING) {
        CHECK(X.send(r.s, "s", 2, 0) == 2);
        CHECK(WaitForSingleObject(r.ev, AX_WAIT) == WAIT_OBJECT_0);
        CHECK_IOSB(r.io, 0, 6);
        CHECK(!memcmp(r.buf, "da\xcc" "tas", 6));
    }
    rx_close(&r);
}

TEST(afdrecv_peer_close_completes_with_zero_bytes) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    FILL_IOSB(r.io, 0xcc);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_PENDING);
    afdx_close(r.s); r.s = INVALID_SOCKET;
    CHECK(WaitForSingleObject(r.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(r.io, 0, 0);
    rx_close(&r);
}

TEST(afdrecv_after_shutdown_receive_is_pipe_disconnected) {
    AFDX_BEGIN();
    RX r; rx_open(&r);
    CHECK(X.shutdown(r.c, SD_RECEIVE) == 0);
    FILL_IOSB(r.io, 0);
    CHECK_ST(rx(r.c, r.ev, &r.io, &r.p, sizeof r.p), AX_STATUS_PIPE_DISCONNECTED);
    CHECK_IOSB(r.io, 0, 0);
    rx_close(&r);
}

/* ---- datagram sockets ---- */
typedef struct { SOCKET c, s; HANDLE ev; struct sockaddr_in addr; char buf[8]; WSABUF wb[2]; AX_RECV p; IO_STATUS_BLOCK io; } UX;
static void ux_open(UX *u, int bind_it) {
    memset(u, 0, sizeof *u);
    u->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    u->c = afdx_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSA_FLAG_OVERLAPPED);
    u->s = afdx_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSA_FLAG_OVERLAPPED);
    memset(u->buf, 0xcc, sizeof u->buf);
    u->wb[0].len = sizeof u->buf; u->wb[0].buf = u->buf;
    setup_recv(&u->p, u->wb, 1, AX_MSG_NOT_OOB);
    if (bind_it) {
        struct sockaddr_in a; int len = sizeof a;
        afdx_fill_sin(&a, LO4, 0);
        CHECK(X.bind(u->c, (struct sockaddr *)&a, sizeof a) == 0);
        CHECK(X.getsockname(u->c, (struct sockaddr *)&u->addr, &len) == 0);
    }
}
static void split_room(UX *u) {                   /* two buffers, 2 + 4 bytes, one hole byte between */
    u->wb[0].len = 2; u->wb[0].buf = u->buf;
    u->wb[1].len = 4; u->wb[1].buf = u->buf + 3;
    u->p.count = 2;
}
static void ux_close(UX *u) { afdx_close(u->c); afdx_close(u->s); CloseHandle(u->ev); }

TEST(afdrecv_datagram_unbound_is_invalid_parameter) {
    AFDX_BEGIN();
    UX u; ux_open(&u, 0);
    LONG st = rx(u.c, u.ev, &u.io, &u.p, sizeof u.p);
    CHECK_ST(st, AX_STATUS_INVALID_PARAMETER);
    if ((ULONG)st == AX_STATUS_PENDING) U(CancelIo)((HANDLE)u.c);
    ux_close(&u);
}

TEST(afdrecv_datagram_async_receive) {
    AFDX_BEGIN();
    UX u; ux_open(&u, 1);
    CHECK_ST(rx(u.c, u.ev, &u.io, &u.p, sizeof u.p), AX_STATUS_PENDING);
    CHECK(X.sendto(u.s, "data", 5, 0, (struct sockaddr *)&u.addr, sizeof u.addr) == 5);
    CHECK(WaitForSingleObject(u.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(u.io, 0, 5);
    CHECK(!memcmp(u.buf, "data", 5));
    ux_close(&u);
}

TEST(afdrecv_datagram_truncation_async) {
    AFDX_BEGIN();
    UX u; ux_open(&u, 1);
    split_room(&u);                                   /* a nine byte datagram into six bytes of room */
    CHECK_ST(rx(u.c, u.ev, &u.io, &u.p, sizeof u.p), AX_STATUS_PENDING);
    CHECK(X.sendto(u.s, "moredata", 9, 0, (struct sockaddr *)&u.addr, sizeof u.addr) == 9);
    CHECK(WaitForSingleObject(u.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(u.io, AX_STATUS_BUFFER_OVERFLOW, 6);
    CHECK(!memcmp(u.buf, "mo\xcc" "reda\xcc", 7));
    ux_close(&u);
}

TEST(afdrecv_datagram_truncation_sync) {
    AFDX_BEGIN();
    UX u; ux_open(&u, 1);
    split_room(&u);
    CHECK(X.sendto(u.s, "moredata", 9, 0, (struct sockaddr *)&u.addr, sizeof u.addr) == 9);
    AFDX_WAIT_POLL(u.c, u.ev, AX_POLL_READ, AX_POLL_READ);
    FILL_IOSB(u.io, 0);
    CHECK_ST(rx(u.c, u.ev, &u.io, &u.p, sizeof u.p), AX_STATUS_BUFFER_OVERFLOW);
    CHECK_IOSB(u.io, AX_STATUS_BUFFER_OVERFLOW, 6);
    CHECK(!memcmp(u.buf, "mo\xcc" "reda\xcc", 7));
    ux_close(&u);
}

TEST(afdrecv_closing_the_socket_cancels_pending_receive) {
    AFDX_BEGIN();
    UX u; ux_open(&u, 1);
    CHECK_ST(rx(u.c, u.ev, &u.io, &u.p, sizeof u.p), AX_STATUS_PENDING);
    afdx_close(u.c); u.c = INVALID_SOCKET;
    CHECK(WaitForSingleObject(u.ev, AX_WAIT) == WAIT_OBJECT_0);
    CHECK_IOSB(u.io, AX_STATUS_CANCELLED, 0);
    ux_close(&u);
}
