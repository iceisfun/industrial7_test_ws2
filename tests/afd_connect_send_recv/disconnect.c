/* IOCTL_AFD_PARTIAL_DISCONNECT (0x1202b, the driver's "disconnect" request): the 16-byte request holds a flag
 * word (1 send, 2 receive, 4 abortive, 8 unconnect-datagram) and a timeout.
 *
 * Observed contract: a block shorter than 16 bytes is an invalid parameter before anything else is looked at.
 * A stream endpoint must be connected (invalid parameter otherwise); the flags are then applied independently
 * and idempotently, unknown bits are ignored, and an empty flag word does nothing and succeeds. A datagram
 * endpoint accepts the request in any state and records the send/receive shutdown bits for its own sends and
 * receives; the unconnect bit returns a connected datagram endpoint to the bound state.
 */
#include "csr.h"

static CS_R disc_raw(SOCKET s, ULONG flags, LONGLONG timeout) {
    CS_DISC d; memset(&d, 0, sizeof d);
    d.flags = flags; d.timeout.QuadPart = timeout;
    return cs_ioctl(s, CS_IOCTL_PARTIAL_DISC, &d, sizeof d, NULL, 0);
}
static int eof_seen(SOCKET s) {                      /* winsock-level orderly end of stream */
    char b[4];
    if (!cs_readable(s, CS_WAIT)) return 0;
    return X.recv(s, b, sizeof b, 0) == 0;
}

/* ---- request shape --------------------------------------------------------------------------------------- */
TEST(csrdisc_input_length_table) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_DISC d; memset(&d, 0, sizeof d); d.flags = CS_DISC_SEND;
    static const ULONG lens[] = { 0, 1, 4, 8, 12, 15 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        CS_R r = cs_ioctl(c, CS_IOCTL_PARTIAL_DISC, &d, lens[i], NULL, 0);
        CHECKF((ULONG)r.first == CS_INVALID_PARAMETER && (ULONG)r.final == CS_INVALID_PARAMETER,
               "input length %lu: 0x%08lx", lens[i], (unsigned long)r.first);
    }
    char ch = 'k';
    CHECK_DONE(cs_send(c, &ch, 1, 0, 0), CS_SUCCESS, 1);   /* nothing was shut down by the failed requests */
    cs_close(c); cs_close(s);
}
TEST(csrdisc_short_input_on_datagram_socket) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CS_DISC d; memset(&d, 0, sizeof d); d.flags = CS_DISC_SEND;
    CS_R r = cs_ioctl(a, CS_IOCTL_PARTIAL_DISC, &d, 8, NULL, 0);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(a); cs_close(b);
}
TEST(csrdisc_output_buffer_is_ignored) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_DISC d; memset(&d, 0, sizeof d); d.flags = 0;
    char out[16];
    CS_R r = cs_ioctl(c, CS_IOCTL_PARTIAL_DISC, &d, sizeof d, out, sizeof out);
    CHECK_ASYNC_OK(r);
    CHECK_ST(r.final, CS_SUCCESS);
    cs_close(c); cs_close(s);
}

/* ---- state ---------------------------------------------------------------------------------------------- */
TEST(csrdisc_fresh_tcp_socket_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    CS_R r = disc_raw(c, CS_DISC_SEND, -1);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c);
}
TEST(csrdisc_bound_tcp_socket_is_invalid_parameter) {
    CS_BEGIN();
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    struct sockaddr_in a; cs_bind_lo(c, &a);
    CS_R r = disc_raw(c, CS_DISC_SEND | CS_DISC_RECEIVE, -1);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(c);
}
TEST(csrdisc_listener_is_invalid_parameter) {
    CS_BEGIN();
    struct sockaddr_in a; SOCKET l = cs_listener(&a);
    CS_R r = disc_raw(l, CS_DISC_SEND, -1);
    CHECK_SYNC(r, CS_INVALID_PARAMETER);
    cs_close(l);
}
TEST(csrdisc_empty_flags_succeed_and_change_nothing) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = disc_raw(c, 0, -1);
    CHECK_ASYNC_OK(r);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK_DONE(cs_send(c, "go", 2, 0, 0), CS_SUCCESS, 2);
    char b[4] = {0};
    CHECK(cs_readable(s, CS_WAIT) && X.recv(s, b, sizeof b, 0) == 2);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_unknown_flag_bits_are_ignored) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    static const ULONG bits[] = { 0x10, 0x100, 0x80000000u, 0xfffffff0u };
    for (unsigned i = 0; i < sizeof bits / sizeof *bits; i++) {
        CS_R r = disc_raw(c, bits[i], -1);
        CHECKF((ULONG)r.final == CS_SUCCESS, "flags 0x%lx: 0x%08lx", bits[i], (unsigned long)r.final);
    }
    CHECK_DONE(cs_send(c, "go", 2, 0, 0), CS_SUCCESS, 2);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_timeout_values_do_not_matter) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    static const LONGLONG t[] = { 0, -1, 1, -10000000LL, 0x7fffffffffffffffLL };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        CS_R r = disc_raw(c, 0, t[i]);
        CHECK_ST(r.final, CS_SUCCESS);
    }
    cs_close(c); cs_close(s);
}

/* ---- send side ------------------------------------------------------------------------------------------ */
TEST(csrdisc_send_flag_ends_the_stream_for_the_peer) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_disc(c, CS_DISC_SEND);
    CHECK_ASYNC_OK(r);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(eof_seen(s));
    cs_close(c); cs_close(s);
}
TEST(csrdisc_send_flag_flushes_queued_data_first) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_DONE(cs_send(c, "last words", 10, 0, 0), CS_SUCCESS, 10);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    char b[16] = {0};
    int got = 0;
    while (got < 10 && cs_readable(s, CS_WAIT)) { int n = X.recv(s, b + got, 10 - got, 0); if (n <= 0) break; got += n; }
    CHECK(got == 10 && !memcmp(b, "last words", 10));
    CHECK(eof_seen(s));
    cs_close(c); cs_close(s);
}
TEST(csrdisc_send_flag_blocks_local_sends) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    CS_R r = cs_send(c, "x", 1, 0, 0);
    CHECK_SYNC(r, CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_send_flag_keeps_receiving) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK(X.send(s, "back", 4, 0) == 4);
    char b[8] = {0};
    CS_R r = cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_DONE(r, CS_SUCCESS, 4);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_send_flag_twice_is_harmless) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK(eof_seen(s));
    cs_close(c); cs_close(s);
}
TEST(csrdisc_both_sides_send_flag_then_close_cleanly) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK_ST(cs_disc(s, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK(eof_seen(s));
    CHECK(eof_seen(c));
    cs_close(c); cs_close(s);
}

/* ---- receive side --------------------------------------------------------------------------------------- */
TEST(csrdisc_receive_flag_blocks_local_receives) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_disc(c, CS_DISC_RECEIVE);
    CHECK_ST(r.final, CS_SUCCESS);
    char b[4];
    r = cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_SYNC(r, CS_PIPE_DISCONNECTED);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_receive_flag_keeps_sending) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_RECEIVE).final, CS_SUCCESS);
    CHECK_DONE(cs_send(c, "out", 3, 0, 0), CS_SUCCESS, 3);
    char b[4] = {0};
    CHECK(cs_readable(s, CS_WAIT) && X.recv(s, b, sizeof b, 0) == 3);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_receive_flag_twice_is_harmless) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_RECEIVE).final, CS_SUCCESS);
    CHECK_ST(cs_disc(c, CS_DISC_RECEIVE).final, CS_SUCCESS);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_receive_flag_fails_pended_receive_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    char buf[8]; WSABUF wb = { sizeof buf, buf };
    CS_DATA d; memset(&d, 0, sizeof d); d.buf = &wb; d.count = 1; d.tdi = CS_TDI_NORMAL;
    IO_STATUS_BLOCK io; memset(&io, 0xAB, sizeof io);
    CHECK_ST(cs_submit(c, ev, NULL, NULL, &io, CS_IOCTL_RECV, &d, sizeof d, NULL, 0), CS_PENDING);
    CHECK_ST(cs_disc(c, CS_DISC_RECEIVE).final, CS_SUCCESS);
    DWORD w = WaitForSingleObject(ev, 500);
    t_note("pended receive when receive is shut down: wait %lu status 0x%08lx", (unsigned long)w, w == WAIT_OBJECT_0 ? (unsigned long)io.Status : 0ul);
    if (w != WAIT_OBJECT_0) cs_await(c, ev, &io, CS_WAIT);
    CloseHandle(ev); cs_close(c); cs_close(s);
}
TEST(csrdisc_both_flags_shut_both_directions) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_SEND | CS_DISC_RECEIVE).final, CS_SUCCESS);
    char b[4];
    CHECK_SYNC(cs_send(c, "x", 1, 0, 0), CS_PIPE_DISCONNECTED);
    CHECK_SYNC(cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0), CS_PIPE_DISCONNECTED);
    CHECK(eof_seen(s));
    cs_close(c); cs_close(s);
}

/* ---- abortive ------------------------------------------------------------------------------------------- */
TEST(csrdisc_abortive_resets_the_peer) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_disc(c, CS_DISC_ABORTIVE);
    CHECK_ASYNC_OK(r);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK(cs_readable(s, CS_WAIT));
    char b[4];
    r = cs_recv(s, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECK_ST(r.final, CS_CONNECTION_RESET);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_abortive_discards_unsent_state_but_peer_sees_reset_not_eof) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_ABORTIVE).final, CS_SUCCESS);
    CHECK(cs_readable(s, CS_WAIT));
    char b[4];
    int n = X.recv(s, b, sizeof b, 0);
    CHECK(n == SOCKET_ERROR);
    CHECK(X.WSAGetLastError() == WSAECONNRESET);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_local_side_after_abort_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_ABORTIVE).final, CS_SUCCESS);
    char b[4];
    CS_R r = cs_recv(c, b, sizeof b, CS_TDI_NORMAL, 0);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "receive after a local abort hung");
    t_note("local receive after abortive disconnect: 0x%08lx", (unsigned long)r.final);
    r = cs_disc(c, CS_DISC_SEND);
    t_note("second disconnect after an abort: 0x%08lx", (unsigned long)r.final);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_abortive_with_other_flags_still_aborts) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_ABORTIVE | CS_DISC_SEND | CS_DISC_RECEIVE).final, CS_SUCCESS);
    CHECK(cs_readable(s, CS_WAIT));
    char b[4];
    CHECK_ST(cs_recv(s, b, sizeof b, CS_TDI_NORMAL, 0).final, CS_CONNECTION_RESET);
    cs_close(c); cs_close(s);
}
TEST(csrdisc_unconnect_flag_on_stream_is_ignored_note) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CS_R r = cs_disc(c, CS_DISC_UNCONNECT);
    t_note("unconnect flag on a stream socket: 0x%08lx", (unsigned long)r.final);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "request did not complete");
    cs_close(c); cs_close(s);
}

/* ---- datagram sockets ---------------------------------------------------------------------------------- */
TEST(csrdisc_udp_unconnect_returns_to_bound_state) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba, peer; int n = sizeof peer;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CS_R r = cs_disc(a, CS_DISC_UNCONNECT);
    CHECK_ASYNC_OK(r);
    CHECK_ST(r.final, CS_SUCCESS);
    CHECK_SYNC(cs_send(a, "x", 1, 0, 0), CS_INVALID_CONNECTION);     /* no longer connected */
    cs_close(a); cs_close(b);
}
TEST(csrdisc_udp_unconnect_accepts_any_sender_again) {
    CS_BEGIN();
    SOCKET a, b, c; struct sockaddr_in aa, ba, ca;
    cs_udp_pair(&a, &b, &aa, &ba);
    c = cs_sock(AF_INET, SOCK_DGRAM); cs_bind_lo(c, &ca);
    CHECK_ST(cs_connect(a, &ba, sizeof ba).final, CS_SUCCESS);
    CHECK_ST(cs_disc(a, CS_DISC_UNCONNECT).final, CS_SUCCESS);
    CHECK(X.sendto(c, "any", 3, 0, (struct sockaddr *)&aa, sizeof aa) == 3);
    char buf[8] = {0};
    CHECK(cs_readable(a, CS_WAIT) && X.recv(a, buf, sizeof buf, 0) == 3 && !memcmp(buf, "any", 3));
    cs_close(a); cs_close(b); cs_close(c);
}
TEST(csrdisc_udp_flags_on_unconnected_socket_succeed) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_UNCONNECT).final, CS_SUCCESS);
    CHECK_ST(cs_disc(a, 0).final, CS_SUCCESS);
    cs_close(a); cs_close(b);
}
TEST(csrdisc_udp_abortive_leaves_both_directions_working) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_ABORTIVE).final, CS_SUCCESS);
    CS_R r = cs_sendto(a, "x", 1, &ba, sizeof ba, 0);          /* no connection to abort: both directions stay open */
    CHECK_SYNC(r, CS_SUCCESS);
    CHECK(r.io.Information == 1);
    CHECK(X.sendto(b, "y", 1, 0, (struct sockaddr *)&aa, sizeof aa) == 1);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[4]; struct sockaddr_in from; ULONG fl = sizeof from;
    r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_DONE(r, CS_SUCCESS, 1);
    cs_close(a); cs_close(b);
}
TEST(csrdisc_udp_send_shutdown_leaves_receive_working) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK(X.sendto(b, "in", 2, 0, (struct sockaddr *)&aa, sizeof aa) == 2);
    CHECK(cs_readable(a, CS_WAIT));
    char buf[4]; struct sockaddr_in from; ULONG fl = sizeof from;
    CS_R r = cs_recvfrom(a, buf, sizeof buf, &from, &fl, CS_TDI_NORMAL);
    CHECK_DONE(r, CS_SUCCESS, 2);
    cs_close(a); cs_close(b);
}
TEST(csrdisc_udp_receive_shutdown_leaves_send_working) {
    CS_BEGIN();
    SOCKET a, b; struct sockaddr_in aa, ba;
    cs_udp_pair(&a, &b, &aa, &ba);
    CHECK_ST(cs_disc(a, CS_DISC_RECEIVE).final, CS_SUCCESS);
    CHECK_DONE(cs_sendto(a, "out", 3, &ba, sizeof ba, 0), CS_SUCCESS, 3);
    char buf[4] = {0};
    CHECK(cs_readable(b, CS_WAIT) && X.recv(b, buf, sizeof buf, 0) == 3);
    cs_close(a); cs_close(b);
}
TEST(csrdisc_udp_unbound_socket_note) {
    CS_BEGIN();
    SOCKET u = cs_sock(AF_INET, SOCK_DGRAM);
    CS_R r = cs_disc(u, CS_DISC_SEND);
    t_note("partial disconnect on an unbound datagram socket: 0x%08lx", (unsigned long)r.final);
    CHECKF((ULONG)r.final != CS_PENDING && (ULONG)r.final != CS_TIMEOUT, "request did not complete");
    cs_close(u);
}

/* ---- interplay with winsock ------------------------------------------------------------------------------ */
TEST(csrdisc_winsock_shutdown_agrees_with_raw_flags) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_SEND).final, CS_SUCCESS);
    CHECK(X.send(c, "x", 1, 0) == SOCKET_ERROR);
    CHECK(X.WSAGetLastError() == WSAESHUTDOWN);
    CHECK(X.shutdown(c, SD_SEND) == 0 || X.shutdown(c, SD_SEND) == SOCKET_ERROR);   /* repeating is not a crash */
    cs_close(c); cs_close(s);
}
TEST(csrdisc_raw_receive_shutdown_makes_winsock_recv_fail) {
    CS_BEGIN();
    SOCKET c, s; cs_pair(&c, &s);
    CHECK_ST(cs_disc(c, CS_DISC_RECEIVE).final, CS_SUCCESS);
    char b[4];
    int n = X.recv(c, b, sizeof b, 0);
    CHECK(n == 0 || n == SOCKET_ERROR);
    t_note("winsock recv after a raw receive shutdown: %d / %d", n, n == SOCKET_ERROR ? X.WSAGetLastError() : 0);
    cs_close(c); cs_close(s);
}
