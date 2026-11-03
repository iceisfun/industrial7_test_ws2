/* IOCTL_AFD_SEND (0x1201f) on connected sockets: state and shutdown handling, request validation, scatter
 * lists, large sends that pend, cancellation, urgent data, and what a send reports once the connection is
 * reset or half closed.
 *
 * Order of checks seen in the driver: connected state (invalid-connection otherwise), then the per-direction
 * shutdown flags (pipe-disconnected, or local-disconnect after a local abort) and the reset flag, and only then
 * the request block (24 bytes minimum) and the buffer list (non-empty, non-NULL array, at most 0x0fffffff entries).
 */
#include "csr.h"

static HANDLE new_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

static CS_R send_list(SOCKET s, WSABUF *wb, ULONG count, ULONG tdi) {
    CS_DATA d; memset(&d, 0, sizeof d);
    d.buf = wb; d.count = count; d.tdi = tdi;
    return cs_ioctl(s, CS_IOCTL_SEND, &d, sizeof d, NULL, 0);
}
static int recv_exact(SOCKET s, char *buf, int want) {
    int got = 0;
    while (got < want) {
        if (!cs_readable(s, CS_WAIT)) break;
        int n = X.recv(s, buf + got, want - got, 0);
        if (n <= 0) break;
        got += n;
    }
    return got;
}

/* ---- state ---------------------------------------------------------------------------------------------- */
TEST(csrsend_fresh_tcp_is_invalid_connection) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    CS_R r = cs_send(s, "x", 1, 0, 0);
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(s);
}
TEST(csrsend_listener_is_invalid_connection) {
    CS_BEGIN();
    struct sockaddr_in a; SOCKET l = cs_listener(&a);
    CS_R r = cs_send(l, "x", 1, 0, 0);
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(l);
}
TEST(csrsend_unconnected_udp_is_invalid_connection) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CS_R r = cs_send(a, "x", 1, 0, 0);
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(a); cs_close(b);
}
TEST(csrsend_state_check_precedes_request_check) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    CS_R r = cs_ioctl(s, CS_IOCTL_SEND, NULL, 0, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(s);
}

/* ---- request validation ---------------------------------------------------------------------------------- */
TEST(csrsend_input_length_table) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char b[4] = "abc"; WSABUF wb = { 3, b };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1;
    static const ULONG lens[] = { 0, 1, 8, 16, 20, 23 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        CS_R r = cs_ioctl(c, CS_IOCTL_SEND, &d, lens[i], NULL, 0);
        CHECKF((ULONG)r.first == CS_INVALID_PARAMETER && (ULONG)r.final == CS_INVALID_PARAMETER,
               "input length %lu: 0x%08lx", lens[i], (unsigned long)r.first);
    }
    cs_close(c); cs_close(s);
}
TEST(csrsend_zero_buffer_count) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char b[2] = "a"; WSABUF wb = { 1, b };
    CS_R r = send_list(c, &wb, 0, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrsend_null_buffer_array) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = send_list(c, NULL, 1, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrsend_buffer_count_beyond_limit) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char b[2] = "a"; WSABUF wb = { 1, b };
    CS_R r = send_list(c, &wb, 0x10000000, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    r = send_list(c, &wb, 0xffffffff, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}

/* ---- ordinary sends ------------------------------------------------------------------------------------- */
TEST(csrsend_small_send_reports_length) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_send(c, "hello", 5, 0, 0);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 5);
    char b[8] = {0};
    CHECK(recv_exact(s, b, 5) == 5 && !memcmp(b, "hello", 5));
    cs_close(c); cs_close(s);
}
TEST(csrsend_scatter_with_empty_entries) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    WSABUF wb[4] = { { 2, "ab" }, { 0, NULL }, { 3, "cde" }, { 1, "f" } };
    CS_R r = send_list(c, wb, 4, 0);
    CHECK_DONE(r, CS_SUCCESS, 6);
    char b[8] = {0};
    CHECK(recv_exact(s, b, 6) == 6 && !memcmp(b, "abcdef", 6));
    cs_close(c); cs_close(s);
}
TEST(csrsend_zero_length_send_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_send(c, "", 0, 0, 0);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "zero-length send did not complete");
    t_note("zero-length send: 0x%08lx info %llu", (unsigned long)r.final, (unsigned long long)r.io.Information);
    CS_R w = cs_send(c, "k", 1, 0, 0);
    CHECK_DONE(w, CS_SUCCESS, 1);
    char b[2] = {0};
    CHECK(recv_exact(s, b, 1) == 1 && b[0] == 'k');
    cs_close(c); cs_close(s);
}
TEST(csrsend_sends_keep_order) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    for (int i = 0; i < 10; i++) {
        char ch = (char)('0' + i);
        CS_R r = cs_send(c, &ch, 1, 0, 0);
        CHECK_DONE(r, CS_SUCCESS, 1);
    }
    char b[16] = {0};
    CHECK(recv_exact(s, b, 10) == 10 && !memcmp(b, "0123456789", 10));
    cs_close(c); cs_close(s);
}
TEST(csrsend_both_directions_at_once) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_DONE(cs_send(c, "to-s", 4, 0, 0), CS_SUCCESS, 4);
    CHECK_DONE(cs_send(s, "to-c", 4, 0, 0), CS_SUCCESS, 4);
    char b1[8] = {0}, b2[8] = {0};
    CHECK(recv_exact(s, b1, 4) == 4 && !memcmp(b1, "to-s", 4));
    CHECK(recv_exact(c, b2, 4) == 4 && !memcmp(b2, "to-c", 4));
    cs_close(c); cs_close(s);
}
TEST(csrsend_urgent_flag_delivers_urgent_byte) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_send(c, "!", 1, 0x20, 0);                  /* expedited */
    CHECK_DONE(r, CS_SUCCESS, 1);
    char b = 0; int got = 0;
    u_long nb = 1; X.ioctlsocket(s, FIONBIO, &nb);
    for (int i = 0; i < 300 && !got; i++) {
        if (X.recv(s, &b, 1, MSG_OOB) == 1) got = 1; else Sleep(10);
    }
    CHECK(got && b == '!');
    cs_close(c); cs_close(s);
}
TEST(csrsend_on_connected_udp_reaches_peer) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CS_R r = cs_send(a, "udp!", 4, 0, 0);
    CHECK_DONE(r, CS_SUCCESS, 4);
    char buf[8] = {0};
    CHECK(cs_readable(b, CS_WAIT) && X.recv(b, buf, sizeof buf, 0) == 4 && !memcmp(buf, "udp!", 4));
    cs_close(a); cs_close(b);
}

/* ---- large sends ---------------------------------------------------------------------------------------- */
TEST(csrsend_large_send_pends_until_peer_drains) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    const ULONG total = 4u << 20;
    char *data = (char *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) { t_skip("no memory for the payload"); cs_close(c); cs_close(s); return; }
    for (ULONG i = 0; i < total; i++) data[i] = (char)(i * 13 + 1);
    HANDLE ev = new_event();
    WSABUF wb = { total, data };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_SEND, &d, sizeof d, NULL, 0);
    CHECK_ST2(st, CS_PENDING, CS_SUCCESS);                 /* far more than the socket buffers normally hold */
    static char buf[65536];
    ULONG got = 0, bad = 0;
    while (got < total) {
        if (!cs_readable(s, CS_WAIT)) break;
        int n = X.recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (int k = 0; k < n; k++) if (buf[k] != (char)((got + k) * 13 + 1)) { bad++; break; }
        got += n;
    }
    CHECK(got == total);
    CHECK(bad == 0);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == total);
    CloseHandle(ev);
    VirtualFree(data, 0, MEM_RELEASE);
    cs_close(c); cs_close(s);
}
TEST(csrsend_cancel_pended_send) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    const ULONG total = 4u << 20;
    char *data = (char *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) { t_skip("no memory for the payload"); cs_close(c); cs_close(s); return; }
    HANDLE ev = new_event();
    WSABUF wb = { total, data };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_SEND, &d, sizeof d, NULL, 0);
    CHECK_ST2(st, CS_PENDING, CS_SUCCESS);
    IO_STATUS_BLOCK cio;
    if ((ULONG)st == CS_PENDING) {
        CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
        CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
        CHECK_ST(io.Status, CS_CANCELLED);
        CHECK(io.Information < total);
    }
    CloseHandle(ev);
    cs_close(c); cs_close(s);
    VirtualFree(data, 0, MEM_RELEASE);
}
TEST(csrsend_close_completes_pended_send_as_cancelled) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    const ULONG total = 4u << 20;
    char *data = (char *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) { t_skip("no memory for the payload"); cs_close(c); cs_close(s); return; }
    HANDLE ev = new_event();
    WSABUF wb = { total, data };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_SEND, &d, sizeof d, NULL, 0);
    CHECK_ST2(st, CS_PENDING, CS_SUCCESS);
    if ((ULONG)st == CS_PENDING) {
        cs_close(c);
        c = INVALID_SOCKET;
        CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
        t_note("pended send when its socket is closed: 0x%08lx", (unsigned long)io.Status);
        CHECK((ULONG)io.Status != CS_PENDING);
    }
    CloseHandle(ev);
    cs_close(c); cs_close(s);
    VirtualFree(data, 0, MEM_RELEASE);
}

/* ---- shutdown, abort and reset -------------------------------------------------------------------------- */
TEST(csrsend_after_send_shutdown_is_pipe_disconnected) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CS_R r = cs_send(c, "x", 1, 0, 0);
    CHECK_SYNC(r, CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}
TEST(csrsend_shutdown_check_precedes_request_check) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CS_R r = cs_ioctl(c, CS_IOCTL_SEND, NULL, 0, NULL, 0);
    CHECK_SYNC(r, CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}
TEST(csrsend_receive_shutdown_does_not_block_sending) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(c, SD_RECEIVE) == 0);
    CS_R r = cs_send(c, "ok", 2, 0, 0);
    CHECK_DONE(r, CS_SUCCESS, 2);
    char b[4] = {0};
    CHECK(recv_exact(s, b, 2) == 2);
    cs_close(c); cs_close(s);
}
TEST(csrsend_still_works_after_peer_send_shutdown) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(s, SD_SEND) == 0);
    CS_R r = cs_send(c, "half", 4, 0, 0);
    CHECK_DONE(r, CS_SUCCESS, 4);
    char b[8] = {0};
    CHECK(recv_exact(s, b, 4) == 4 && !memcmp(b, "half", 4));
    cs_close(c); cs_close(s);
}
TEST(csrsend_after_peer_reset_is_connection_reset) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    cs_rst_close(s);
    CHECK(cs_readable(c, CS_WAIT));                        /* the reset has been processed */
    CS_R r = cs_send(c, "x", 1, 0, 0);
    CHECK_ST(r.final, CS_CONNECTION_RESET);
    CHECK(r.io.Information == 0);
    cs_close(c);
}
TEST(csrsend_into_closed_peer_fails_local_disconnect_on_second_send) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    cs_close(s);                                           /* orderly close: the first send is accepted */
    CS_R r = cs_send(c, "one", 3, 0, 0);
    CHECK_DONE(r, CS_SUCCESS, 3);
    CHECK(cs_readable(c, CS_WAIT));                        /* the peer's reset (or its FIN) arrived */
    r = cs_send(c, "two", 3, 0, 0);
    /* the peer answered the first segment with a reset: the next send fails at once, without a byte moved */
    CHECK_SYNC(r, CS_LOCAL_DISCONNECT);
    CHECK(r.io.Information == 0);
    CHECK_SYNC(cs_send(c, "three", 5, 0, 0), CS_LOCAL_DISCONNECT);       /* and it stays that way */
    cs_close(c);
}
TEST(csrsend_after_local_abort_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R d = cs_disc(c, CS_DISC_ABORTIVE);
    CHECKF((ULONG)d.final == CS_SUCCESS || (ULONG)d.final == CS_PENDING, "abortive disconnect: 0x%08lx", (unsigned long)d.final);
    CS_R r = cs_send(c, "x", 1, 0, 0);
    CHECKF((ULONG)r.final != CS_SUCCESS && (ULONG)r.final != CS_PENDING, "send after local abort succeeded");
    t_note("send after a local abortive disconnect: 0x%08lx", (unsigned long)r.final);
    cs_close(c); cs_close(s);
}
