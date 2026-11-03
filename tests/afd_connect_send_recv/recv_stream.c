/* IOCTL_AFD_RECEIVE (0x12017) on connected stream sockets: request validation, flag combinations, scatter
 * lists with empty entries, zero-length buffers, request queueing order, reset and graceful-close outcomes.
 *
 * Validation order observed in the driver, which the tests rely on: (1) the endpoint must be connected (a
 * stream socket that is not gives the invalid-connection status, a datagram socket the invalid-parameter
 * status), (2) the 24-byte request block must be complete, (3) exactly one of the "normal" and "urgent"
 * selectors must be present, (4) the buffer list must be non-empty with a non-NULL array. Wait-all is only
 * accepted together with the normal selector and nothing else.
 */
#include "csr.h"

static HANDLE new_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

/* a request over an arbitrary WSABUF list */
static CS_R recv_list(SOCKET s, WSABUF *wb, ULONG count, ULONG tdi) {
    CS_DATA d; memset(&d, 0, sizeof d);
    d.buf = wb; d.count = count; d.tdi = tdi;
    return cs_ioctl(s, CS_IOCTL_RECV, &d, sizeof d, NULL, 0);
}

/* ---- endpoint state -------------------------------------------------------------------------------------- */
TEST(csrrecv_fresh_tcp_socket_is_invalid_connection) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    char b[4];
    CS_R r = cs_recv(s, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(s);
}
TEST(csrrecv_bound_tcp_socket_is_invalid_connection) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in a; cs_bind_lo(s, &a);
    char b[4];
    CS_R r = cs_recv(s, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(s);
}
TEST(csrrecv_state_check_precedes_tdi_selector_check) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    char b[4];
    CS_R r = cs_recv(s, b, sizeof b, 0, 0);               /* no selector at all, and also not connected */
    CHECK_SYNC(r, CS_INVALID_CONNECTION);
    cs_close(s);
}
TEST(csrrecv_udp_unbound_state_check_precedes_selector_check) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_DGRAM);
    char b[4];
    CS_R r = cs_recv(s, b, sizeof b, 0, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(s);
}

/* ---- request block and buffer list ---------------------------------------------------------------------- */
TEST(csrrecv_input_length_table) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char buf[4]; WSABUF wb = { sizeof buf, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL;
    static const ULONG lens[] = { 0, 1, 8, 16, 20, 23 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        CS_R r = cs_ioctl(c, CS_IOCTL_RECV, &d, lens[i], NULL, 0);
        CHECKF((ULONG)r.first == CS_INVALID_PARAMETER && (ULONG)r.final == CS_INVALID_PARAMETER,
               "input length %lu: 0x%08lx", lens[i], (unsigned long)r.first);
    }
    cs_close(c); cs_close(s);
}
TEST(csrrecv_zero_buffer_count) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char buf[4]; WSABUF wb = { sizeof buf, buf };
    CS_R r = recv_list(c, &wb, 0, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrrecv_null_buffer_array) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = recv_list(c, NULL, 1, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrrecv_buffer_count_beyond_limit) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char buf[4]; WSABUF wb = { sizeof buf, buf };
    /* the count is refused before the array is touched: anything above 0x0fffffff entries */
    CS_R r = recv_list(c, &wb, 0x10000000, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    r = recv_list(c, &wb, 0xffffffff, CS_TDI_NORMAL);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrrecv_selector_table) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char buf[4];
    static const ULONG bad[] = { 0, CS_TDI_PEEK, 0x60, 0x80 | 0x60, 0x4000, 0x4060, 0x1 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        CS_R r = cs_recv(c, buf, sizeof buf, bad[i], 0);
        CHECKF((ULONG)r.first == CS_INVALID_PARAMETER && (ULONG)r.final == CS_INVALID_PARAMETER,
               "tdi flags 0x%lx: 0x%08lx", bad[i], (unsigned long)r.first);
    }
    cs_close(c); cs_close(s);
}
TEST(csrrecv_waitall_must_be_exactly_normal_waitall) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    char buf[4];
    /* urgent+waitall and normal+waitall+peek pass the selector test and are then refused as unsupported */
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_EXPEDITED | CS_TDI_WAITALL, 0);
    CHECK_SYNC(r, CS_NOT_SUPPORTED);
    r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL | CS_TDI_PEEK | CS_TDI_WAITALL, 0);
    CHECK_SYNC(r, CS_NOT_SUPPORTED);
    cs_close(c); cs_close(s);
}
TEST(csrrecv_unrelated_tdi_bits_are_ignored) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "hey", 3, 0) == 3);
    char buf[8] = {0};
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL | 0x1, 0);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 3);
    CHECK(!memcmp(buf, "hey", 3));
    cs_close(c); cs_close(s);
}

/* ---- zero-length and empty entries ------------------------------------------------------------------------- */
TEST(csrrecv_zero_length_buffer_with_queued_data) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "data", 4, 0) == 4);
    CHECK(cs_readable(c, CS_WAIT));
    char buf[1];
    CS_R r = cs_recv(c, buf, 0, CS_TDI_NORMAL, 0);
    /* nothing to copy into, data present: completes successfully with no bytes moved, and the data stays */
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(r.io.Information == 0);
    char got[8] = {0};
    CHECK(X.recv(c, got, sizeof got, 0) == 4 && !memcmp(got, "data", 4));
    cs_close(c); cs_close(s);
}
TEST(csrrecv_zero_length_buffer_pends_until_data_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = new_event();
    char buf[1]; WSABUF wb = { 0, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    LONG st = cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0);
    CHECK_ST(st, CS_PENDING);
    CHECK(WaitForSingleObject(ev, 50) == WAIT_TIMEOUT);
    CHECK(X.send(s, "z", 1, 0) == 1);
    CHECK(cs_await(c, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    t_note("zero-length receive completed by data: 0x%08lx info %llu", (unsigned long)io.Status, (unsigned long long)io.Information);
    char got[2] = {0};
    CHECK(X.recv(c, got, 1, 0) == 1 && got[0] == 'z');
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrrecv_empty_entry_in_the_middle_of_the_list) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "abcdef", 6, 0) == 6);
    CHECK(cs_readable(c, CS_WAIT));
    Sleep(20);
    char buf[8]; memset(buf, '.', sizeof buf);
    WSABUF wb[3] = { { 2, buf }, { 0, buf + 4 }, { 4, buf + 3 } };
    CS_R r = recv_list(c, wb, 3, CS_TDI_NORMAL);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(r.io.Information == 6);
    CHECK(!memcmp(buf, "ab.cdef.", 8));                   /* the empty entry takes nothing, the hole stays */
    cs_close(c); cs_close(s);
}
TEST(csrrecv_empty_entry_may_carry_null_pointer) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "wxyz", 4, 0) == 4);
    char buf[8] = {0};
    WSABUF wb[2] = { { 0, NULL }, { 4, buf } };
    CS_R r = recv_list(c, wb, 2, CS_TDI_NORMAL);
    CHECK_ASYNC_OK(r);
    CHECK_DONE(r, CS_SUCCESS, 4);
    CHECK(!memcmp(buf, "wxyz", 4));
    cs_close(c); cs_close(s);
}
TEST(csrrecv_all_entries_empty_list_is_accepted) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "q", 1, 0) == 1);
    CHECK(cs_readable(c, CS_WAIT));
    WSABUF wb[2] = { { 0, NULL }, { 0, NULL } };
    CS_R r = recv_list(c, wb, 2, CS_TDI_NORMAL);
    CHECK_ST(r.final, CS_SUCCESS);                         /* no room anywhere, data queued: success, nothing moved */
    CHECK(r.io.Information == 0);
    cs_close(c); cs_close(s);
}

/* ---- plain data movement -------------------------------------------------------------------------------- */
TEST(csrrecv_short_buffer_leaves_remainder) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "0123456789", 10, 0) == 10);
    CHECK(cs_readable(c, CS_WAIT));
    char buf[4];
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 4);                          /* a stream never reports overflow for a short buffer */
    CHECK(!memcmp(buf, "0123", 4));
    char rest[16] = {0};
    int n = X.recv(c, rest, sizeof rest, 0);
    CHECK(n == 6 && !memcmp(rest, "456789", 6));
    cs_close(c); cs_close(s);
}
TEST(csrrecv_exact_size_buffer) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "exact", 5, 0) == 5);
    CHECK(cs_readable(c, CS_WAIT));
    char buf[5];
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 5);
    CHECK(!memcmp(buf, "exact", 5));
    cs_close(c); cs_close(s);
}
TEST(csrrecv_peek_pended_completes_and_keeps_data) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = new_event();
    char buf[8] = {0}; WSABUF wb = { sizeof buf, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL | CS_TDI_PEEK;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0), CS_PENDING);
    CHECK(X.send(s, "peek", 4, 0) == 4);
    CHECK(cs_await(c, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 4 && !memcmp(buf, "peek", 4));
    char got[8] = {0};
    CHECK(X.recv(c, got, sizeof got, 0) == 4 && !memcmp(got, "peek", 4));
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrrecv_two_pending_requests_complete_in_order) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE e1 = new_event(), e2 = new_event();
    char b1[8] = {0}, b2[8] = {0};
    WSABUF w1 = { sizeof b1, b1 }, w2 = { sizeof b2, b2 };
    CS_DATA d1, d2; memset(&d1, 0, sizeof d1); memset(&d2, 0, sizeof d2);
    d1.buf = &w1; d1.count = 1; d1.tdi = CS_TDI_NORMAL;
    d2.buf = &w2; d2.count = 1; d2.tdi = CS_TDI_NORMAL;
    IO_STATUS_BLOCK i1, i2; memset(&i1, 0xAB, sizeof i1); memset(&i2, 0xAB, sizeof i2);
    CHECK_ST(cs_submit(c, e1, NULL, NULL, &i1, CS_IOCTL_RECV, &d1, sizeof d1, NULL, 0), CS_PENDING);
    CHECK_ST(cs_submit(c, e2, NULL, NULL, &i2, CS_IOCTL_RECV, &d2, sizeof d2, NULL, 0), CS_PENDING);
    CHECK(X.send(s, "abc", 3, 0) == 3);
    CHECK(WaitForSingleObject(e1, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(i1.Information == 3 && !memcmp(b1, "abc", 3));
    CHECK(WaitForSingleObject(e2, 100) == WAIT_TIMEOUT);       /* the later request keeps waiting */
    CHECK(X.send(s, "de", 2, 0) == 2);
    CHECK(cs_await(c, e2, &i2, CS_WAIT) == WAIT_OBJECT_0);
    CHECK(i2.Information == 2 && !memcmp(b2, "de", 2));
    CloseHandle(e1); CloseHandle(e2); cs_close(c); cs_close(s);
}
TEST(csrrecv_cancelled_request_does_not_lose_data) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = new_event();
    char buf[8]; WSABUF wb = { sizeof buf, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_CANCELLED);
    CHECK(io.Information == 0);
    CHECK(X.send(s, "late", 4, 0) == 4);
    char got[8] = {0};
    CHECK(cs_readable(c, CS_WAIT) && X.recv(c, got, sizeof got, 0) == 4 && !memcmp(got, "late", 4));
    CloseHandle(ev); cs_close(c); cs_close(s);
}

/* ---- inline urgent data -------------------------------------------------------------------------------- */
TEST(csrrecv_inline_mode_refuses_urgent_selector) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    int one = 1;
    CHECK(X.setsockopt(c, SOL_SOCKET, SO_OOBINLINE, (const char *)&one, sizeof one) == 0);
    char buf[4];
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_EXPEDITED, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c); cs_close(s);
}
TEST(csrrecv_inline_mode_delivers_urgent_byte_with_normal_data) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    int one = 1;
    CHECK(X.setsockopt(c, SOL_SOCKET, SO_OOBINLINE, (const char *)&one, sizeof one) == 0);
    CHECK(X.send(s, "ab", 2, 0) == 2);
    CHECK(cs_readable(c, CS_WAIT));
    CHECK(X.send(s, "c", 1, MSG_OOB) == 1);
    char buf[8] = {0}; ULONG got = 0;
    for (int i = 0; i < 20 && got < 3; i++) {
        CS_R r = cs_recv(c, buf + got, (ULONG)(sizeof buf - got), CS_TDI_NORMAL, 0);
        if ((ULONG)r.final != CS_SUCCESS || r.io.Information == 0) break;
        got += (ULONG)r.io.Information;
    }
    CHECK(got == 3 && !memcmp(buf, "abc", 3));
    cs_close(c); cs_close(s);
}

/* ---- end of stream and abort ---------------------------------------------------------------------------- */
TEST(csrrecv_data_then_fin_then_zero_repeats) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "bye", 3, 0) == 3);
    CHECK(X.shutdown(s, SD_SEND) == 0);
    char buf[8] = {0};
    ULONG got = 0;
    for (int i = 0; i < 4 && got < 3; i++) {
        CS_R r = cs_recv(c, buf + got, (ULONG)(sizeof buf - got), CS_TDI_NORMAL, 0);
        CHECK_ST(r.final, CS_SUCCESS);
        got += (ULONG)r.io.Information;
    }
    CHECK(got == 3 && !memcmp(buf, "bye", 3));
    for (int i = 0; i < 2; i++) {                          /* end of stream is sticky */
        CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);
        CHECK_ASYNC_OK(r);
        CHECK_DONE(r, CS_SUCCESS, 0);
    }
    cs_close(c); cs_close(s);
}
TEST(csrrecv_fin_completes_peek_request_with_zero) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(s, SD_SEND) == 0);
    char buf[4];
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL | CS_TDI_PEEK, 0);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(r.io.Information == 0);
    cs_close(c); cs_close(s);
}
TEST(csrrecv_after_reset_is_connection_reset) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    cs_rst_close(s);
    CHECK(cs_readable(c, CS_WAIT));
    char buf[4];
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);
    CHECK_ST(r.final, CS_CONNECTION_RESET);
    CHECK(r.io.Information == 0);
    r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);      /* and it stays reset */
    CHECK_ST(r.final, CS_CONNECTION_RESET);
    cs_close(c);
}
TEST(csrrecv_pending_request_fails_with_reset) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = new_event();
    char buf[8]; WSABUF wb = { sizeof buf, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0), CS_PENDING);
    cs_rst_close(s);
    CHECK(cs_await(c, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_CONNECTION_RESET);
    CHECK(io.Information == 0);
    CloseHandle(ev); cs_close(c);
}
TEST(csrrecv_reset_discards_unread_data_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "unread", 6, 0) == 6);
    CHECK(cs_readable(c, CS_WAIT));
    cs_rst_close(s);
    Sleep(50);
    char buf[16] = {0};
    CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);
    t_note("receive after unread data then reset: 0x%08lx info %llu", (unsigned long)r.final, (unsigned long long)r.io.Information);
    cs_close(c);
}
TEST(csrrecv_after_local_receive_shutdown_selector_check_comes_later) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(c, SD_RECEIVE) == 0);
    char buf[4];
    /* the shutdown state is examined before the selector word */
    CS_R r = cs_recv(c, buf, sizeof buf, 0, 0);
    CHECK_SYNC(r, CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}

/* ---- bulk transfer -------------------------------------------------------------------------------------- */
typedef struct { SOCKET s; ULONG total; } PUMP;
static DWORD WINAPI pump(LPVOID p) {
    PUMP *u = (PUMP *)p;
    static char chunk[8192];
    for (unsigned i = 0; i < sizeof chunk; i++) chunk[i] = (char)(i * 7 + 3);
    ULONG sent = 0;
    while (sent < u->total) {
        ULONG n = u->total - sent < sizeof chunk ? u->total - sent : (ULONG)sizeof chunk;
        int r = X.send(u->s, chunk, n, 0);
        if (r <= 0) break;
        sent += r;
    }
    X.shutdown(u->s, SD_SEND);
    return sent;
}
TEST(csrrecv_bulk_transfer_in_order) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    PUMP u = { s, 256 * 1024 };
    HANDLE th = U(CreateThread)(NULL, 0, pump, &u, 0, NULL);
    CHECK(th != NULL);
    static char buf[65536];
    ULONG got = 0, bad = 0;
    for (int i = 0; i < 4096; i++) {
        CS_R r = cs_recv(c, buf, sizeof buf, CS_TDI_NORMAL, 0);
        if ((ULONG)r.final != CS_SUCCESS) { bad++; break; }
        if (r.io.Information == 0) break;
        for (ULONG k = 0; k < r.io.Information; k++)
            if (buf[k] != (char)(((got + k) % 8192) * 7 + 3)) { bad++; break; }
        got += (ULONG)r.io.Information;
    }
    CHECK(got == u.total);
    CHECK(bad == 0);
    if (th) { WaitForSingleObject(th, CS_WAIT); CloseHandle(th); }
    cs_close(c); cs_close(s);
}

/* ---- datagram socket reached through the stream request ----------------------------------------------- */
TEST(csrrecv_datagram_socket_rejects_waitall) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    char buf[8];
    CS_R r = cs_recv(a, buf, sizeof buf, CS_TDI_NORMAL | CS_TDI_WAITALL, 0);
    CHECK_SYNC(r, CS_NOT_SUPPORTED);
    cs_close(a); cs_close(b);
}
TEST(csrrecv_datagram_socket_urgent_selector_note) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    char buf[8];
    CS_R r = cs_recv(a, buf, sizeof buf, CS_TDI_EXPEDITED, 0);
    if ((ULONG)r.first == CS_PENDING) { IO_STATUS_BLOCK c; X.cancel((HANDLE)a, &c); }
    CHECKF((ULONG)r.first == CS_NOT_SUPPORTED || (ULONG)r.first == CS_PENDING || (ULONG)r.first == CS_INVALID_PARAMETER,
           "urgent selector on UDP: 0x%08lx", (unsigned long)r.first);
    t_note("urgent selector on a datagram socket: first 0x%08lx", (unsigned long)r.first);
    cs_close(a); cs_close(b);
}
