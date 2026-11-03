/* Connection teardown on TCP loopback pairs: shutdown() directions and the errors that follow, graceful
 * close versus reset (SO_LINGER zero, unread data at close), end-of-stream behaviour, half-closed
 * conversations and sends toward a peer that is gone. Measured: return values, WSAGetLastError and the
 * data that is or is not delivered. */
#include "ts.h"

/* ---- end of stream -------------------------------------------------------- */

TEST(td_recv_after_peer_close_returns_zero_repeatedly)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    closesocket(c);
    for (int i = 0; i < 4; i++) EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(td_recv_after_peer_close_nonblocking_returns_zero_not_wouldblock)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    closesocket(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    ts_nonblock(s, 1);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(td_data_then_eof_in_order)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "final", 5, 0), 5);
    closesocket(c);
    EXPECT_EQ(ts_recv_n(s, b, 5), 5);
    CHECK(!memcmp(b, "final", 5));
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(td_eof_is_visible_through_select_and_fionread)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    shutdown(c, SD_SEND);
    CHECK(ts_readable(s, TS_WAIT_MS));
    EXPECT_EQ(ts_fionread(s), 0);
    ts_close2(c, s);
}

TEST(td_zero_length_recv_after_eof_is_observed)
{
    SOCKET c, s; char b[2]; int r;
    NEED_PAIR(c, s);
    shutdown(c, SD_SEND);
    CHECK(ts_readable(s, TS_WAIT_MS));
    ts_nonblock(s, 1);
    r = recv(s, b, 0, 0);
    t_note("zero-length recv after FIN returned %d", r);
    ts_close2(c, s);
}

/* ---- shutdown ------------------------------------------------------------- */

TEST(td_shutdown_send_flushes_pending_data_before_fin)
{
    SOCKET c, s; ts_job rj = { 0 }; HANDLE th; char *buf = malloc(200000);
    NEED_PAIR(c, s);
    rj.s = s; rj.seed = 21; rj.chunk = 3000; rj.delay_ms = 0;
    th = ts_start(ts_reader, &rj);
    ts_fill(buf, 200000, 21, 0);
    EXPECT_EQ(ts_send_all(c, buf, 200000), 200000);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    CHECK(ts_join(th, 15000));
    EXPECT_EQ(rj.total, 200000);
    CHECK(rj.ok);
    free(buf);
    ts_close2(c, s);
}

TEST(td_shutdown_send_keeps_receive_direction_working)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(send(s, "back", 4, 0), 4);
    EXPECT_EQ(ts_recv_n(c, b, 4), 4);
    CHECK(!memcmp(b, "back", 4));
    ts_close2(c, s);
}

TEST(td_shutdown_send_peer_can_still_send_then_close_ends_both)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    EXPECT_EQ(send(s, "reply", 5, 0), 5);
    EXPECT_EQ(shutdown(s, SD_SEND), 0);
    EXPECT_EQ(ts_recv_n(c, b, 5), 5);
    EXPECT_EQ(recv(c, b, sizeof b, 0), 0);
    ts_close2(c, s);
}

TEST(td_shutdown_send_then_send_is_eshutdown_each_time)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    for (int i = 0; i < 3; i++) {
        WSASetLastError(0);
        EXPECT_EQ(send(c, "x", 1, 0), -1);
        EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    }
    ts_close2(c, s);
}

TEST(td_shutdown_send_zero_length_send_is_observed)
{
    SOCKET c, s; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    WSASetLastError(0);
    r = send(c, "x", 0, 0);
    t_note("zero-length send after SD_SEND returned %d err %d", r, r ? WSAGetLastError() : 0);
    ts_close2(c, s);
}

TEST(td_shutdown_send_wsasend_is_eshutdown)
{
    SOCKET c, s; WSABUF w; DWORD n = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    w.buf = "x"; w.len = 1;
    WSASetLastError(0);
    EXPECT_EQ(WSASend(c, &w, 1, &n, 0, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    ts_close2(c, s);
}

TEST(td_shutdown_receive_then_recv_is_eshutdown)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    for (int i = 0; i < 2; i++) {
        WSASetLastError(0);
        EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
        EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    }
    ts_close2(c, s);
}

TEST(td_shutdown_receive_nonblocking_recv_is_eshutdown)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    ts_close2(c, s);
}

TEST(td_shutdown_receive_peek_is_eshutdown)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    ts_close2(c, s);
}

TEST(td_shutdown_receive_wsarecv_is_eshutdown)
{
    SOCKET c, s; WSABUF w; DWORD n = 0, fl = 0; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    w.buf = b; w.len = sizeof b;
    WSASetLastError(0);
    EXPECT_EQ(WSARecv(s, &w, 1, &n, &fl, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    ts_close2(c, s);
}

TEST(td_shutdown_receive_leaves_sending_working)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    EXPECT_EQ(send(s, "out", 3, 0), 3);
    EXPECT_EQ(ts_recv_n(c, b, 3), 3);
    CHECK(!memcmp(b, "out", 3));
    ts_close2(c, s);
}

TEST(td_shutdown_both_blocks_both_directions)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_BOTH), 0);
    WSASetLastError(0);
    EXPECT_EQ(send(c, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    WSASetLastError(0);
    EXPECT_EQ(recv(c, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);       /* the peer sees an orderly FIN */
    ts_close2(c, s);
}

TEST(td_shutdown_both_with_queued_incoming_data)
{
    SOCKET c, s; char b[8]; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(s, "data", 4, 0), 4);
    EXPECT_EQ(ts_wait_queued(c, 4, TS_WAIT_MS), 4);
    EXPECT_EQ(shutdown(c, SD_BOTH), 0);
    WSASetLastError(0);
    r = recv(c, b, sizeof b, 0);
    t_note("recv after SD_BOTH with data queued: %d err %d", r, r < 0 ? WSAGetLastError() : 0);
    ts_close2(c, s);
}

TEST(td_shutdown_receive_with_queued_incoming_data)
{
    SOCKET c, s; char b[8]; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "data", 4, 0), 4);
    EXPECT_EQ(ts_wait_queued(s, 4, TS_WAIT_MS), 4);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    WSASetLastError(0);
    r = recv(s, b, sizeof b, 0);
    t_note("recv after SD_RECEIVE with data queued: %d err %d", r, r < 0 ? WSAGetLastError() : 0);
    ts_close2(c, s);
}

TEST(td_shutdown_receive_then_peer_send_still_succeeds)
{
    SOCKET c, s; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(s, SD_RECEIVE), 0);
    EXPECT_EQ(send(c, "ignored", 7, 0), 7);
    Sleep(100);
    WSASetLastError(0);
    r = send(c, "more", 4, 0);
    EXPECT_EQ(r, -1);   /* the peer answered the first segment with a reset */
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    ts_close2(c, s);
}

TEST(td_shutdown_after_peer_close_is_observed)
{
    SOCKET c, s; int r;
    NEED_PAIR(c, s);
    closesocket(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    WSASetLastError(0);
    r = shutdown(s, SD_SEND);
    t_note("shutdown(SD_SEND) after the peer closed: %d err %d", r, r ? WSAGetLastError() : 0);
    closesocket(s);
}

TEST(td_shutdown_send_after_reset_is_observed)
{
    SOCKET c, s; int r;
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    WSASetLastError(0);
    r = shutdown(s, SD_SEND);
    t_note("shutdown(SD_SEND) after a reset: %d err %d", r, r ? WSAGetLastError() : 0);
    closesocket(s);
}

TEST(td_shutdown_how_out_of_range_is_einval)
{
    static const int bad[] = { 3, 4, -1, 100 };
    SOCKET c, s;
    NEED_PAIR(c, s);
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        WSASetLastError(0);
        EXPECT_EQ(shutdown(c, bad[i]), -1);
        EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    }
    /* the failed calls did not shut anything down */
    EXPECT_EQ(send(c, "k", 1, 0), 1);
    ts_close2(c, s);
}

/* ---- graceful close versus reset ------------------------------------------- */

TEST(td_default_close_is_graceful_for_unsent_data)
{
    SOCKET c, s; ts_job rj = { 0 }; HANDLE th; char *buf = malloc(100000);
    NEED_PAIR(c, s);
    rj.s = s; rj.seed = 31; rj.chunk = 2048; rj.delay_ms = 1;
    th = ts_start(ts_reader, &rj);
    ts_fill(buf, 100000, 31, 0);
    EXPECT_EQ(ts_send_all(c, buf, 100000), 100000);
    closesocket(c);
    CHECK(ts_join(th, 20000));
    EXPECT_EQ(rj.total, 100000);
    EXPECT_EQ(rj.final_ret, 0);
    CHECK(rj.ok);
    free(buf);
    closesocket(s);
}

TEST(td_linger_zero_close_gives_connreset_on_recv)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    closesocket(s);
}

TEST(td_reset_error_is_sticky_for_recv)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    for (int i = 0; i < 3; i++) {
        WSASetLastError(0);
        EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
        EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    }
    closesocket(s);
}

TEST(td_reset_then_send_is_connreset)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(send(s, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    closesocket(s);
}

TEST(td_reset_then_peek_is_connreset)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    closesocket(s);
}

TEST(td_reset_then_wsarecv_is_connreset)
{
    SOCKET c, s; WSABUF w; DWORD n = 0xdead, fl = 0; char b[4];
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    w.buf = b; w.len = sizeof b;
    WSASetLastError(0);
    EXPECT_EQ(WSARecv(s, &w, 1, &n, &fl, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    closesocket(s);
}

TEST(td_reset_makes_socket_readable_and_writable_per_select)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    CHECK(ts_writable(s, TS_WAIT_MS));
    closesocket(s);
}

TEST(td_reset_getsockopt_error_is_observed)
{
    SOCKET c, s; char b[4]; int err = -1, len = sizeof err;
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    t_note("SO_ERROR before any call after a reset: %d", err);
    recv(s, b, sizeof b, 0);
    err = -1; len = sizeof err;
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len), 0);
    t_note("SO_ERROR after the failing recv: %d", err);
    closesocket(s);
}

TEST(td_reset_with_queued_data_is_observed)
{
    SOCKET c, s; char b[16]; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "queued", 6, 0), 6);
    EXPECT_EQ(ts_wait_queued(s, 6, TS_WAIT_MS), 6);
    ts_rst_close(c);
    Sleep(100);
    WSASetLastError(0);
    r = recv(s, b, sizeof b, 0);
    t_note("recv after reset with 6 bytes queued: %d err %d", r, r < 0 ? WSAGetLastError() : 0);
    CHECK(r == 6 || r == -1);
    closesocket(s);
}

TEST(td_close_with_unread_data_resets_the_peer)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "unread", 6, 0), 6);
    EXPECT_EQ(ts_wait_queued(s, 6, TS_WAIT_MS), 6);
    closesocket(s);                          /* data still unread: the stack aborts instead of FIN */
    CHECK(ts_readable(c, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(recv(c, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    closesocket(c);
}

TEST(td_close_with_no_unread_data_is_not_a_reset)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "read", 4, 0), 4);
    EXPECT_EQ(ts_recv_n(s, b, 4), 4);
    closesocket(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    EXPECT_EQ(recv(c, b, sizeof b, 0), 0);
    closesocket(c);
}

TEST(td_linger_on_with_timeout_close_is_graceful)
{
    SOCKET c, s; struct linger l = { 1, 10 }; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l), 0);
    EXPECT_EQ(send(c, "linger", 6, 0), 6);
    EXPECT_EQ(closesocket(c), 0);
    EXPECT_EQ(ts_recv_n(s, b, 6), 6);
    CHECK(!memcmp(b, "linger", 6));
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(td_linger_off_explicit_close_is_graceful)
{
    SOCKET c, s; struct linger l = { 0, 5 }; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l), 0);
    EXPECT_EQ(send(c, "plain", 5, 0), 5);
    closesocket(c);
    EXPECT_EQ(ts_recv_n(s, b, 5), 5);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(td_linger_zero_discards_unsent_data_or_resets_consistently)
{
    SOCKET c, s; char b[4]; int r;
    NEED_PAIR(c, s);
    ts_rst_close(c);
    CHECK(ts_readable(s, TS_WAIT_MS));
    r = recv(s, b, sizeof b, 0);
    EXPECT_EQ(r, -1);
    r = recv(s, b, sizeof b, 0);
    EXPECT_EQ(r, -1);
    closesocket(s);
}

TEST(td_linger_zero_after_shutdown_send_resets)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    ts_rst_close(c);
    Sleep(100);
    EXPECT_EQ(send(s, "x", 1, 0) == 1 || WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAECONNABORTED, 1);
    closesocket(s);
}

TEST(td_linger_zero_on_accepted_socket_resets_client)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_rst_close(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(recv(c, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    closesocket(c);
}

/* ---- sending toward a vanished peer ----------------------------------------- */

TEST(td_send_after_peer_graceful_close_eventually_fails)
{
    SOCKET c, s; int err = 0, first;
    NEED_PAIR(c, s);
    closesocket(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    first = send(c, "x", 1, 0);
    t_note("first send after the peer's FIN returned %d", first);
    for (int i = 0; i < 100 && !err; i++) {
        if (send(c, "x", 1, 0) < 0) err = WSAGetLastError();
        else Sleep(20);
    }
    CHECK(err == WSAECONNRESET || err == WSAECONNABORTED);
    t_note("send toward a closed peer failed with %s", err == WSAECONNRESET ? "ECONNRESET" : err == WSAECONNABORTED ? "ECONNABORTED" : "other");
    closesocket(c);
}

TEST(td_send_after_peer_graceful_close_error_repeats)
{
    SOCKET c, s; int err = 0, again = 0;
    NEED_PAIR(c, s);
    closesocket(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    for (int i = 0; i < 100 && !err; i++) {
        if (send(c, "x", 1, 0) < 0) err = WSAGetLastError();
        else Sleep(20);
    }
    CHECK(err != 0);
    WSASetLastError(0);
    if (send(c, "x", 1, 0) < 0) again = WSAGetLastError();
    CHECK(again == WSAECONNRESET || again == WSAECONNABORTED || again == WSAESHUTDOWN);
    t_note("second failing send: %d (first %d)", again, err);
    closesocket(c);
}

TEST(td_recv_after_failed_send_toward_closed_peer_is_observed)
{
    SOCKET c, s; char b[4]; int r, n = 0;
    NEED_PAIR(c, s);
    closesocket(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    EXPECT_EQ(recv(c, b, sizeof b, 0), 0);      /* the FIN is read first */
    for (int i = 0; i < 100 && send(c, "x", 1, 0) > 0; i++) { Sleep(20); n++; }
    r = recv(c, b, sizeof b, 0);
    t_note("recv after the reset caused by a send: %d err %d", r, r < 0 ? WSAGetLastError() : 0);
    closesocket(c);
}

TEST(td_blocking_large_send_to_reset_peer_fails_with_reset_or_abort)
{
    SOCKET c, s; char *buf = malloc(1 << 20); int r, e;
    NEED_PAIR(c, s);
    ts_rst_close(s);
    CHECK(ts_readable(c, TS_WAIT_MS));
    memset(buf, 7, 1 << 20);
    WSASetLastError(0);
    r = send(c, buf, 1 << 20, 0);
    e = WSAGetLastError();
    EXPECT_EQ(r, -1);
    CHECK(e == WSAECONNRESET || e == WSAECONNABORTED);
    free(buf);
    closesocket(c);
}

TEST(td_connect_refused_socket_cannot_send)
{
    struct sockaddr_in a; SOCKET l, c; NEED_NET();
    l = ts_listener(&a);
    REQUIRE(l != INVALID_SOCKET);
    closesocket(l);                       /* the port is now closed */
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(c != INVALID_SOCKET);
    WSASetLastError(0);
    EXPECT_EQ(connect(c, (struct sockaddr *)&a, sizeof a), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNREFUSED);
    WSASetLastError(0);
    EXPECT_EQ(send(c, "x", 1, 0), -1);
    CHECK(WSAGetLastError() != 0);
    closesocket(c);
}

/* ---- half-closed conversations ----------------------------------------------- */

TEST(td_half_closed_request_response)
{
    SOCKET c, s; char b[64]; int n;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "request", 7, 0), 7);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    n = 0;
    for (;;) { int r = recv(s, b + n, 64 - n, 0); if (r <= 0) { EXPECT_EQ(r, 0); break; } n += r; }
    EXPECT_EQ(n, 7);
    EXPECT_EQ(send(s, "response", 8, 0), 8);
    closesocket(s);
    n = 0;
    for (;;) { int r = recv(c, b + n, 64 - n, 0); if (r <= 0) { EXPECT_EQ(r, 0); break; } n += r; }
    EXPECT_EQ(n, 8);
    CHECK(!memcmp(b, "response", 8));
    closesocket(c);
}

TEST(td_half_closed_both_ways_in_sequence)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(shutdown(s, SD_SEND), 0);
    EXPECT_EQ(recv(c, b, sizeof b, 0), 0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    WSASetLastError(0);
    EXPECT_EQ(send(c, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    WSASetLastError(0);
    EXPECT_EQ(send(s, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    ts_close2(c, s);
}

TEST(td_half_closed_peer_names_remain_available)
{
    SOCKET c, s; struct sockaddr_in a; int len = sizeof a;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_BOTH), 0);
    EXPECT_EQ(W(getpeername)(c, (struct sockaddr *)&a, &len), 0);
    EXPECT_EQ(a.sin_addr.s_addr, 0x0100007FUL);
    ts_close2(c, s);
}

TEST(td_half_closed_bulk_response_after_request_fin)
{
    SOCKET c, s; ts_job rj = { 0 }, wj = { 0 }; HANDLE tr, tw; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "go", 2, 0), 2);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    EXPECT_EQ(ts_recv_n(s, b, 2), 2);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    rj.s = c; rj.seed = 41; rj.chunk = 4096;
    wj.s = s; wj.seed = 41; wj.total = 400000; wj.chunk = 8192;
    tr = ts_start(ts_reader, &rj);
    tw = ts_start(ts_writer, &wj);
    CHECK(ts_join(tw, 20000));
    shutdown(s, SD_SEND);
    CHECK(ts_join(tr, 20000));
    EXPECT_EQ(rj.total, 400000);
    CHECK(rj.ok && wj.ok);
    ts_close2(c, s);
}

TEST(td_accepted_socket_sees_client_fin_and_reply_works)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    closesocket(c);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(td_many_connections_close_cleanly)
{
    NEED_NET();
    for (int i = 0; i < 40; i++) {
        SOCKET c, s; char b[4];
        if (!ts_pair(&c, &s)) { CHECK(0); return; }
        EXPECT_EQ(send(c, "z", 1, 0), 1);
        if (i & 1) shutdown(c, SD_SEND);
        closesocket(c);
        EXPECT_EQ(recv(s, b, sizeof b, 0), 1);
        EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
        closesocket(s);
    }
}
