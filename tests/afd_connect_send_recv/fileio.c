/* NtReadFile / NtWriteFile on the socket handle versus the explicit receive/send requests.
 *
 * The driver turns a plain read into a normal-data receive and a plain write into a send, so the same state
 * checks and the same status codes apply: an unconnected stream endpoint gives the invalid-connection status,
 * an unbound datagram endpoint the invalid-parameter status, a shut-down direction pipe-disconnected, a reset
 * connection connection-reset. The handles here are opened for overlapped use, so a byte offset must be
 * supplied (its value is ignored).
 */
#include "csr.h"

static CS_R fio(SOCKET s, int is_write, void *buf, ULONG len) {
    CS_R r; memset(&r, 0, sizeof r);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LARGE_INTEGER off; off.QuadPart = 0;
    memset(&r.io, 0xAB, sizeof r.io);
    if (is_write) r.first = X.write((HANDLE)s, ev, NULL, NULL, &r.io, buf, len, &off, NULL);
    else          r.first = X.read((HANDLE)s, ev, NULL, NULL, &r.io, buf, len, &off, NULL);
    if ((ULONG)r.first == CS_PENDING) {
        DWORD w = cs_await(s, ev, &r.io, CS_WAIT);
        r.final = (w == WAIT_OBJECT_0) ? r.io.Status : (LONG)CS_TIMEOUT;
    } else {
        r.final = r.first;
        if (((ULONG)r.first >> 30) == 3) { r.io.Status = r.first; r.io.Information = 0; }
    }
    CloseHandle(ev);
    return r;
}
#define rd(s, b, n) fio(s, 0, b, n)
#define wr(s, b, n) fio(s, 1, b, n)

/* ---- state checks match the explicit requests -------------------------------------------------------------- */
TEST(csrfile_read_on_fresh_tcp_is_invalid_connection) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM); char b[4];
    CHECK_SYNC(rd(s, b, sizeof b), CS_INVALID_CONNECTION);
    cs_close(s);
}
TEST(csrfile_write_on_fresh_tcp_is_invalid_connection) {
    CS_BEGIN();
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    CHECK_SYNC(wr(s, "x", 1), CS_INVALID_CONNECTION);
    cs_close(s);
}
TEST(csrfile_read_and_write_on_listener_are_invalid_connection) {
    CS_BEGIN();
    struct sockaddr_in a; SOCKET l = cs_listener(&a); char b[4];
    CHECK_SYNC(rd(l, b, sizeof b), CS_INVALID_CONNECTION);
    CHECK_SYNC(wr(l, "x", 1), CS_INVALID_CONNECTION);
    cs_close(l);
}
TEST(csrfile_read_on_unbound_udp_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET u = cs_sock(AF_INET, SOCK_DGRAM); char b[4];
    CHECK_SYNC(rd(u, b, sizeof b), CS_INVALID_PARAMETER);
    cs_close(u);
}
TEST(csrfile_write_on_unconnected_udp_is_invalid_connection) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_SYNC(wr(a, "x", 1), CS_INVALID_CONNECTION);
    cs_close(a); cs_close(b);
}
TEST(csrfile_write_after_send_shutdown_is_pipe_disconnected) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CHECK_SYNC(wr(c, "x", 1), CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}
TEST(csrfile_read_after_receive_shutdown_is_pipe_disconnected) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s); char b[4];
    CHECK(X.shutdown(c, SD_RECEIVE) == 0);
    CHECK_SYNC(rd(c, b, sizeof b), CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}
TEST(csrfile_read_and_write_after_peer_reset) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s); char b[4];
    cs_rst_close(s);
    CHECK(cs_readable(c, CS_WAIT));
    CS_R r = rd(c, b, sizeof b);
    CHECK_ST(r.final, CS_CONNECTION_RESET);
    r = wr(c, "x", 1);
    CHECK_ST(r.final, CS_CONNECTION_RESET);
    cs_close(c);
}
TEST(csrfile_read_after_udp_receive_shutdown_is_pipe_disconnected) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba; char buf[4];
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_RECEIVE).final, CS_SUCCESS);
    CHECK_SYNC(rd(a, buf, sizeof buf), CS_PIPE_DISCONNECTED);
    cs_close(a); cs_close(b);
}

/* ---- equivalence of data movement ------------------------------------------------------------------------- */
TEST(csrfile_write_then_explicit_receive) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R w = wr(c, "plain", 5);
    CHECK_ST2(w.first, CS_SUCCESS, CS_PENDING);
    CHECK_DONE(w, CS_SUCCESS, 5);
    CHECK(cs_readable(s, CS_WAIT));
    char b[8] = {0};
    CS_R r = cs_recv(s, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 5);
    CHECK(!memcmp(b, "plain", 5));
    cs_close(c); cs_close(s);
}
TEST(csrfile_explicit_send_then_read) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_DONE(cs_send(c, "mixed", 5, 0, 0), CS_SUCCESS, 5);
    char b[8] = {0};
    CHECK(cs_readable(s, CS_WAIT));
    CS_R r = rd(s, b, sizeof b);
    CHECK_DONE(r, CS_SUCCESS, 5);
    CHECK(!memcmp(b, "mixed", 5));
    cs_close(c); cs_close(s);
}
TEST(csrfile_read_pends_then_completes_with_data) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    char b[8] = {0};
    LARGE_INTEGER off; off.QuadPart = 0;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(X.read((HANDLE)c, ev, NULL, NULL, &io, b, sizeof b, &off, NULL), CS_PENDING);
    CHECK(X.send(s, "rd", 2, 0) == 2);
    CHECK(cs_await(c, ev, &io, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == 2 && !memcmp(b, "rd", 2));
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrfile_read_cancelled) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    char b[8];
    LARGE_INTEGER off; off.QuadPart = 0;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(X.read((HANDLE)c, ev, NULL, NULL, &io, b, sizeof b, &off, NULL), CS_PENDING);
    IO_STATUS_BLOCK cio;
    CHECK_ST(X.cancel((HANDLE)c, &cio), CS_SUCCESS);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_CANCELLED);
    CHECK(io.Information == 0);
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrfile_read_short_buffer_leaves_remainder) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "0123456789", 10, 0) == 10);
    CHECK(cs_readable(c, CS_WAIT));
    Sleep(20);
    char b[4];
    CS_R r = rd(c, b, sizeof b);
    CHECK_DONE(r, CS_SUCCESS, 4);
    char rest[16] = {0};
    CHECK(X.recv(c, rest, sizeof rest, 0) == 6 && !memcmp(rest, "456789", 6));
    cs_close(c); cs_close(s);
}
TEST(csrfile_read_at_end_of_stream_returns_zero) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.shutdown(s, SD_SEND) == 0);
    char b[4];
    CS_R r = rd(c, b, sizeof b);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(r.io.Information == 0);
    cs_close(c); cs_close(s);
}
TEST(csrfile_large_write_pends_and_reports_total) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    const ULONG total = 2u << 20;
    char *data = (char *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) { t_skip("no memory"); cs_close(c); cs_close(s); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LARGE_INTEGER off; off.QuadPart = 0;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST2(X.write((HANDLE)c, ev, NULL, NULL, &io, data, total, &off, NULL), CS_PENDING, CS_SUCCESS);
    static char sink[65536];
    ULONG got = 0;
    while (got < total && cs_readable(s, CS_WAIT)) { int n = X.recv(s, sink, sizeof sink, 0); if (n <= 0) break; got += n; }
    CHECK(got == total);
    CHECK(WaitForSingleObject(ev, CS_WAIT) == WAIT_OBJECT_0);
    CHECK_ST(io.Status, CS_SUCCESS);
    CHECK(io.Information == total);
    CloseHandle(ev); VirtualFree(data, 0, MEM_RELEASE); cs_close(c); cs_close(s);
}
TEST(csrfile_zero_length_read_and_write_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK(X.send(s, "d", 1, 0) == 1);
    CHECK(cs_readable(c, CS_WAIT));
    char b[1];
    CS_R r = rd(c, b, 0);
    t_note("NtReadFile of 0 bytes with data queued: 0x%08lx info %llu", (unsigned long)r.final, (unsigned long long)r.io.Information);
    CS_R w = wr(c, b, 0);
    t_note("NtWriteFile of 0 bytes: 0x%08lx info %llu", (unsigned long)w.final, (unsigned long long)w.io.Information);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)w.final != CS_PENDING, "zero-length transfer left pending");
    cs_close(c); cs_close(s);
}

/* ---- datagrams through read/write -------------------------------------------------------------------------- */
TEST(csrfile_read_of_datagram_truncates_with_overflow) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "0123456789", 10, 0, (struct sockaddr *)&aa, sizeof aa) == 10);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[4];
    CS_R r = rd(a, buf, sizeof buf);
    CHECK_ST(r.final, CS_BUFFER_OVERFLOW);
    CHECK(r.io.Information == 4);
    CHECK(!memcmp(buf, "0123", 4));
    cs_close(a); cs_close(b);
}
TEST(csrfile_write_on_connected_udp_and_read_at_peer) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CS_R w = wr(a, "dg", 2);
    CHECK_DONE(w, CS_SUCCESS, 2);
    CHECK(cs_readable(b, CS_WAIT));
    char buf[8] = {0};
    CS_R r = rd(b, buf, sizeof buf);
    CHECK_DONE(r, CS_SUCCESS, 2);
    CHECK(!memcmp(buf, "dg", 2));
    cs_close(a); cs_close(b);
}
TEST(csrfile_read_keeps_datagram_boundaries) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK(X.sendto(b, "aa", 2, 0, (struct sockaddr *)&aa, sizeof aa) == 2);
    CHECK(X.sendto(b, "bbb", 3, 0, (struct sockaddr *)&aa, sizeof aa) == 3);
    CHECK(cs_readable(a, CS_WAIT));
    Sleep(20);
    char buf[16] = {0};
    CS_R r = rd(a, buf, sizeof buf);
    CHECK_DONE(r, CS_SUCCESS, 2);
    r = rd(a, buf, sizeof buf);
    CHECK_DONE(r, CS_SUCCESS, 3);
    cs_close(a); cs_close(b);
}
