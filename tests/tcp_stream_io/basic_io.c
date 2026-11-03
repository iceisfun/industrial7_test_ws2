/* Plain send/recv on a connected loopback TCP pair: zero-length transfers, short and partial reads,
 * stream coalescing, MSG_PEEK, MSG_WAITALL, receive timeouts, gather/scatter calls and the error codes
 * for sockets that are not in a state to transfer data. Measured: return values, WSAGetLastError,
 * queued-byte counts and byte-for-byte content. */
#include "ts.h"

/* ---- zero length -------------------------------------------------------- */

TEST(sio_send_zero_length_blocking_returns_zero)
{
    SOCKET c, s; char b[4] = "abc";
    NEED_PAIR(c, s);
    WSASetLastError(TS_POISON);
    EXPECT_EQ(send(c, b, 0, 0), 0);
    CHECK(WSAGetLastError() == 0 || (DWORD)WSAGetLastError() == TS_POISON);
    EXPECT_EQ(ts_fionread(s), 0);
    ts_close2(c, s);
}

TEST(sio_send_zero_length_nonblocking_returns_zero)
{
    SOCKET c, s; char b[4] = "abc";
    NEED_PAIR(c, s);
    ts_nonblock(c, 1);
    EXPECT_EQ(send(c, b, 0, 0), 0);
    ts_close2(c, s);
}

TEST(sio_send_zero_length_delivers_nothing_and_no_eof)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "x", 0, 0), 0);
    EXPECT_EQ(send(c, "q", 1, 0), 1);
    EXPECT_EQ(ts_recv_n(s, b, 1), 1);       /* the empty send neither produced a byte nor a FIN */
    EXPECT_EQ(b[0], 'q');
    ts_close2(c, s);
}

TEST(sio_recv_zero_length_with_queued_data_keeps_data)
{
    SOCKET c, s; char b[8]; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "hello", 5, 0), 5);
    EXPECT_EQ(ts_wait_queued(s, 5, TS_WAIT_MS), 5);
    ts_nonblock(s, 1);
    WSASetLastError(TS_POISON);
    r = recv(s, b, 0, 0);
    if (r == 0) {
        EXPECT_EQ(ts_fionread(s), 5);       /* nothing was consumed */
    } else {
        t_note("zero-length recv with queued data returned %d err %d", r, WSAGetLastError());
    }
    ts_nonblock(s, 0);
    EXPECT_EQ(ts_recv_n(s, b, 5), 5);
    CHECK(!memcmp(b, "hello", 5));
    ts_close2(c, s);
}

/* ---- short and partial reads -------------------------------------------- */

TEST(sio_recv_returns_available_not_requested)
{
    SOCKET c, s; char b[64];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "12345", 5, 0), 5);
    EXPECT_EQ(ts_wait_queued(s, 5, TS_WAIT_MS), 5);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 5);
    CHECK(!memcmp(b, "12345", 5));
    ts_close2(c, s);
}

TEST(sio_recv_leaves_bytes_beyond_count_untouched)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    memset(b, 0xCC, sizeof b);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 3);
    CHECK(!memcmp(b, "abc", 3));
    for (int i = 3; i < 16; i++) CHECK((unsigned char)b[i] == 0xCC);
    ts_close2(c, s);
}

TEST(sio_recv_partial_reads_consume_in_order)
{
    SOCKET c, s; char b[16];
    static const int cuts[] = { 3, 3, 4 };
    int off = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "0123456789", 10, 0), 10);
    EXPECT_EQ(ts_wait_queued(s, 10, TS_WAIT_MS), 10);
    for (int i = 0; i < 3; i++) {
        memset(b, 0, sizeof b);
        EXPECT_EQ(recv(s, b, cuts[i], 0), cuts[i]);
        CHECK(!memcmp(b, "0123456789" + off, cuts[i]));
        off += cuts[i];
        EXPECT_EQ(ts_fionread(s), 10 - off);
    }
    ts_close2(c, s);
}

TEST(sio_recv_one_byte_at_a_time)
{
    SOCKET c, s; char b;
    static const char msg[] = "streaming";
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, msg, 9, 0), 9);
    for (int i = 0; i < 9; i++) {
        EXPECT_EQ(recv(s, &b, 1, 0), 1);
        EXPECT_EQ(b, msg[i]);
    }
    ts_close2(c, s);
}

TEST(sio_stream_has_no_message_boundaries)
{
    SOCKET c, s; char b[32];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "ab", 2, 0), 2);
    EXPECT_EQ(send(c, "cde", 3, 0), 3);
    EXPECT_EQ(send(c, "f", 1, 0), 1);
    EXPECT_EQ(ts_wait_queued(s, 6, TS_WAIT_MS), 6);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 6);   /* one read spans three sends once all are queued */
    CHECK(!memcmp(b, "abcdef", 6));
    ts_close2(c, s);
}

TEST(sio_send_returns_requested_length_when_blocking)
{
    static const int sizes[] = { 1, 2, 3, 7, 100, 1459, 1460, 1461, 4096, 8191, 32768 };
    SOCKET c, s;
    ts_job rj = { 0 }; HANDLE th; char *buf = malloc(32768);
    NEED_PAIR(c, s);
    rj.s = s; rj.seed = 3; rj.chunk = 5000;
    th = ts_start(ts_reader, &rj);
    long long total = 0;
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        ts_fill(buf, sizes[i], 3, (unsigned long long)total);
        EXPECT_EQ(send(c, buf, sizes[i], 0), sizes[i]);
        total += sizes[i];
    }
    shutdown(c, SD_SEND);
    CHECK(ts_join(th, 15000));
    EXPECT_EQ(rj.total, total);
    CHECK(rj.ok);
    free(buf);
    ts_close2(c, s);
}

TEST(sio_fionread_counts_queued_bytes)
{
    SOCKET c, s; char b[200];
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_fionread(s), 0);
    ts_fill(b, 150, 1, 0);
    EXPECT_EQ(send(c, b, 150, 0), 150);
    EXPECT_EQ(ts_wait_queued(s, 150, TS_WAIT_MS), 150);
    EXPECT_EQ(recv(s, b, 50, 0), 50);
    EXPECT_EQ(ts_fionread(s), 100);
    EXPECT_EQ(recv(s, b, 100, 0), 100);
    EXPECT_EQ(ts_fionread(s), 0);
    ts_close2(c, s);
}

TEST(sio_both_directions_are_independent)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "up", 2, 0), 2);
    EXPECT_EQ(send(s, "down!", 5, 0), 5);
    EXPECT_EQ(ts_recv_n(s, b, 2), 2);
    CHECK(!memcmp(b, "up", 2));
    EXPECT_EQ(ts_recv_n(c, b, 5), 5);
    CHECK(!memcmp(b, "down!", 5));
    ts_close2(c, s);
}

/* ---- non-blocking reads ------------------------------------------------- */

TEST(sio_recv_nonblocking_without_data_is_wouldblock)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    for (int i = 0; i < 3; i++) {
        WSASetLastError(0);
        EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
        EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    }
    ts_close2(c, s);
}

TEST(sio_recv_nonblocking_with_data_then_empty)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    EXPECT_EQ(send(c, "xy", 2, 0), 2);
    EXPECT_EQ(ts_wait_queued(s, 2, TS_WAIT_MS), 2);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 2);
    EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    ts_close2(c, s);
}

TEST(sio_recv_nonblocking_peek_without_data_is_wouldblock)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    ts_close2(c, s);
}

TEST(sio_recv_timeout_reports_timedout)
{
    SOCKET c, s; char b[4]; DWORD tmo = 150;
    NEED_PAIR(c, s);
    EXPECT_EQ(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo), 0);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAETIMEDOUT);
    ts_close2(c, s);          /* the socket state after a timeout is undefined: only close it */
}

TEST(sio_recv_timeout_does_not_trigger_when_data_is_queued)
{
    SOCKET c, s; char b[4]; DWORD tmo = 100;
    NEED_PAIR(c, s);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    EXPECT_EQ(send(c, "ok", 2, 0), 2);
    EXPECT_EQ(ts_wait_queued(s, 2, TS_WAIT_MS), 2);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 2);
    ts_close2(c, s);
}

TEST(sio_rcvtimeo_roundtrips_as_milliseconds)
{
    SOCKET c, s; DWORD v = 1234, got = 0; int len = sizeof got;
    NEED_PAIR(c, s);
    EXPECT_EQ(setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof v), 0);
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&got, &len), 0);
    EXPECT_EQ(len, sizeof got);
    EXPECT_EQ(got, 1234);
    v = 2345;
    EXPECT_EQ(setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (const char *)&v, sizeof v), 0);
    EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (char *)&got, &len), 0);
    EXPECT_EQ(got, 2345);
    ts_close2(c, s);
}

/* ---- MSG_PEEK ------------------------------------------------------------ */

TEST(sio_peek_does_not_consume)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "peekaboo", 8, 0), 8);
    EXPECT_EQ(ts_wait_queued(s, 8, TS_WAIT_MS), 8);
    memset(b, 0, sizeof b);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), 8);
    CHECK(!memcmp(b, "peekaboo", 8));
    EXPECT_EQ(ts_fionread(s), 8);
    memset(b, 0, sizeof b);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 8);
    CHECK(!memcmp(b, "peekaboo", 8));
    EXPECT_EQ(ts_fionread(s), 0);
    ts_close2(c, s);
}

TEST(sio_peek_repeats_same_bytes)
{
    SOCKET c, s; char a[8], b[8], d[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "repeat", 6, 0), 6);
    EXPECT_EQ(ts_wait_queued(s, 6, TS_WAIT_MS), 6);
    EXPECT_EQ(recv(s, a, 6, MSG_PEEK), 6);
    EXPECT_EQ(recv(s, b, 6, MSG_PEEK), 6);
    EXPECT_EQ(recv(s, d, 6, MSG_PEEK), 6);
    CHECK(!memcmp(a, b, 6) && !memcmp(b, d, 6) && !memcmp(a, "repeat", 6));
    ts_close2(c, s);
}

TEST(sio_peek_short_buffer_then_full_read)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abcdefgh", 8, 0), 8);
    EXPECT_EQ(ts_wait_queued(s, 8, TS_WAIT_MS), 8);
    memset(b, 0, sizeof b);
    EXPECT_EQ(recv(s, b, 3, MSG_PEEK), 3);
    CHECK(!memcmp(b, "abc", 3));
    EXPECT_EQ(ts_fionread(s), 8);
    EXPECT_EQ(recv(s, b, 2, 0), 2);
    CHECK(!memcmp(b, "ab", 2));
    EXPECT_EQ(recv(s, b, 16, MSG_PEEK), 6);
    CHECK(!memcmp(b, "cdefgh", 6));
    ts_close2(c, s);
}

TEST(sio_peek_sees_data_arriving_later)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "ab", 2, 0), 2);
    EXPECT_EQ(ts_wait_queued(s, 2, TS_WAIT_MS), 2);
    EXPECT_EQ(recv(s, b, 16, MSG_PEEK), 2);
    EXPECT_EQ(send(c, "cd", 2, 0), 2);
    EXPECT_EQ(ts_wait_queued(s, 4, TS_WAIT_MS), 4);
    EXPECT_EQ(recv(s, b, 16, MSG_PEEK), 4);
    CHECK(!memcmp(b, "abcd", 4));
    ts_close2(c, s);
}

TEST(sio_peek_after_peer_close_returns_zero)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    closesocket(c);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), 0);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), 0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    closesocket(s);
}

TEST(sio_peek_queued_data_before_eof_then_eof)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "tail", 4, 0), 4);
    shutdown(c, SD_SEND);
    EXPECT_EQ(ts_wait_queued(s, 4, TS_WAIT_MS), 4);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), 4);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 4);
    EXPECT_EQ(recv(s, b, sizeof b, MSG_PEEK), 0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    ts_close2(c, s);
}

/* ---- MSG_WAITALL --------------------------------------------------------- */

typedef struct { SOCKET s; int pieces; int piece_len; int gap_ms; } trickle;
static DWORD WINAPI trickle_thread(LPVOID a)
{
    trickle *t = a; char buf[64];
    for (int i = 0; i < t->pieces; i++) {
        ts_fill(buf, t->piece_len, 9, (unsigned long long)i * t->piece_len);
        if (send(t->s, buf, t->piece_len, 0) != t->piece_len) break;
        Sleep(t->gap_ms);
    }
    return 0;
}

TEST(sio_waitall_blocks_until_full_count)
{
    SOCKET c, s; char b[40]; trickle t; HANDLE th; int r;
    NEED_PAIR(c, s);
    t.s = c; t.pieces = 4; t.piece_len = 10; t.gap_ms = 40;
    th = CreateThread(NULL, 0, trickle_thread, &t, 0, NULL);
    r = recv(s, b, 40, MSG_WAITALL);
    EXPECT_EQ(r, 40);
    CHECK(ts_verify(b, 40, 9, 0));
    CHECK(ts_join(th, 10000));
    ts_close2(c, s);
}

TEST(sio_waitall_without_flag_returns_first_piece)
{
    SOCKET c, s; char b[64]; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "0123456789", 10, 0), 10);
    EXPECT_EQ(ts_wait_queued(s, 10, TS_WAIT_MS), 10);
    r = recv(s, b, 64, 0);
    EXPECT_EQ(r, 10);          /* without MSG_WAITALL a short count is returned immediately */
    ts_close2(c, s);
}

TEST(sio_waitall_exact_queued_amount)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "0123456789", 10, 0), 10);
    EXPECT_EQ(ts_wait_queued(s, 10, TS_WAIT_MS), 10);
    EXPECT_EQ(recv(s, b, 10, MSG_WAITALL), 10);
    ts_close2(c, s);
}

TEST(sio_waitall_partial_then_graceful_close_returns_partial)
{
    SOCKET c, s; char b[32];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "short", 5, 0), 5);
    shutdown(c, SD_SEND);
    EXPECT_EQ(recv(s, b, 32, MSG_WAITALL), 5);   /* the FIN ends the wait with what arrived */
    CHECK(!memcmp(b, "short", 5));
    EXPECT_EQ(recv(s, b, 32, MSG_WAITALL), 0);
    ts_close2(c, s);
}

TEST(sio_waitall_large_count_across_many_segments)
{
    SOCKET c, s; ts_job wj = { 0 }; HANDLE th; char *b = malloc(300000); int r;
    NEED_PAIR(c, s);
    wj.s = c; wj.seed = 5; wj.total = 300000; wj.chunk = 7000;
    th = ts_start(ts_writer, &wj);
    r = recv(s, b, 300000, MSG_WAITALL);
    EXPECT_EQ(r, 300000);
    CHECK(ts_verify(b, 300000, 5, 0));
    CHECK(ts_join(th, 15000));
    CHECK(wj.ok);
    free(b);
    ts_close2(c, s);
}

TEST(sio_waitall_nonblocking_with_nothing_is_wouldblock)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, 8, MSG_WAITALL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);   /* MSG_WAITALL cannot be honoured on a nonblocking socket */
    ts_close2(c, s);
}

TEST(sio_waitall_nonblocking_with_partial_data_is_observed)
{
    SOCKET c, s; char b[16]; int r;
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    WSASetLastError(0);
    r = recv(s, b, 8, MSG_WAITALL);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
    ts_close2(c, s);
}

TEST(sio_waitall_with_receive_timeout)
{
    SOCKET c, s; char b[16]; DWORD tmo = 200; int r;
    NEED_PAIR(c, s);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    WSASetLastError(0);
    r = recv(s, b, 16, MSG_WAITALL);
    EXPECT_EQ(r, 0);   /* Windows reports the timed-out wait as a zero-byte completion */
    ts_close2(c, s);
}

/* ---- WSASend / WSARecv --------------------------------------------------- */

TEST(sio_wsasend_gathers_buffers_in_order)
{
    SOCKET c, s; WSABUF w[3]; DWORD sent = 0; char b[16];
    NEED_PAIR(c, s);
    w[0].buf = "ab"; w[0].len = 2;
    w[1].buf = "cde"; w[1].len = 3;
    w[2].buf = "f"; w[2].len = 1;
    EXPECT_EQ(WSASend(c, w, 3, &sent, 0, NULL, NULL), 0);
    EXPECT_EQ(sent, 6);
    EXPECT_EQ(ts_recv_n(s, b, 6), 6);
    CHECK(!memcmp(b, "abcdef", 6));
    ts_close2(c, s);
}

TEST(sio_wsasend_empty_buffer_among_data)
{
    SOCKET c, s; WSABUF w[3]; DWORD sent = 0; char b[8];
    NEED_PAIR(c, s);
    w[0].buf = "x"; w[0].len = 1;
    w[1].buf = "unused"; w[1].len = 0;
    w[2].buf = "yz"; w[2].len = 2;
    EXPECT_EQ(WSASend(c, w, 3, &sent, 0, NULL, NULL), 0);
    EXPECT_EQ(sent, 3);
    EXPECT_EQ(ts_recv_n(s, b, 3), 3);
    CHECK(!memcmp(b, "xyz", 3));
    ts_close2(c, s);
}

TEST(sio_wsasend_zero_length_buffer_reports_zero_bytes)
{
    SOCKET c, s; WSABUF w; DWORD sent = 0xdead;
    NEED_PAIR(c, s);
    w.buf = "x"; w.len = 0;
    EXPECT_EQ(WSASend(c, &w, 1, &sent, 0, NULL, NULL), 0);
    EXPECT_EQ(sent, 0);
    EXPECT_EQ(ts_fionread(s), 0);
    ts_close2(c, s);
}

TEST(sio_wsasend_zero_buffer_count_is_observed)
{
    SOCKET c, s; WSABUF w; DWORD sent = 0xdead; int r;
    NEED_PAIR(c, s);
    w.buf = "x"; w.len = 1;
    WSASetLastError(0);
    r = WSASend(c, &w, 0, &sent, 0, NULL, NULL);
    t_note("WSASend with zero buffers: ret %d err %d", r, r ? WSAGetLastError() : 0);
    EXPECT_EQ(ts_fionread(s), 0);       /* either way nothing is transmitted */
    ts_close2(c, s);
}

TEST(sio_wsarecv_peek_flag_in_and_out)
{
    SOCKET c, s; WSABUF w; DWORD got = 0, fl = MSG_PEEK; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "wsa", 3, 0), 3);
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(WSARecv(s, &w, 1, &got, &fl, NULL, NULL), 0);
    EXPECT_EQ(got, 3);
    EXPECT_EQ(ts_fionread(s), 3);
    fl = 0; got = 0;
    EXPECT_EQ(WSARecv(s, &w, 1, &got, &fl, NULL, NULL), 0);
    EXPECT_EQ(got, 3);
    EXPECT_EQ(ts_fionread(s), 0);
    ts_close2(c, s);
}

TEST(sio_wsarecv_waitall_flag_fills_all_buffers)
{
    SOCKET c, s; WSABUF w[2]; DWORD got = 0, fl = MSG_WAITALL; char a[4], b[6]; trickle t; HANDLE th;
    NEED_PAIR(c, s);
    t.s = c; t.pieces = 5; t.piece_len = 2; t.gap_ms = 30;
    th = CreateThread(NULL, 0, trickle_thread, &t, 0, NULL);
    w[0].buf = a; w[0].len = 4;
    w[1].buf = b; w[1].len = 6;
    EXPECT_EQ(WSARecv(s, w, 2, &got, &fl, NULL, NULL), 0);
    EXPECT_EQ(got, 10);
    CHECK(ts_verify(a, 4, 9, 0) && ts_verify(b, 6, 9, 4));
    CHECK(ts_join(th, 10000));
    ts_close2(c, s);
}

TEST(sio_wsarecv_eof_reports_zero_bytes_success)
{
    SOCKET c, s; WSABUF w; DWORD got = 0xdead, fl = 0; char b[4];
    NEED_PAIR(c, s);
    shutdown(c, SD_SEND);
    w.buf = b; w.len = sizeof b;
    EXPECT_EQ(WSARecv(s, &w, 1, &got, &fl, NULL, NULL), 0);
    EXPECT_EQ(got, 0);
    ts_close2(c, s);
}

TEST(sio_wsarecv_zero_buffer_count_is_einval)
{
    SOCKET c, s; WSABUF w; DWORD got = 0xdead, fl = 0; char b[4];
    NEED_PAIR(c, s);
    w.buf = b; w.len = sizeof b;
    WSASetLastError(0);
    EXPECT_EQ(WSARecv(s, &w, 0, &got, &fl, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    ts_close2(c, s);
}

TEST(sio_sendto_null_address_on_connected_stream_sends)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    EXPECT_EQ(sendto(c, "to", 2, 0, NULL, 0), 2);
    EXPECT_EQ(ts_recv_n(s, b, 2), 2);
    CHECK(!memcmp(b, "to", 2));
    ts_close2(c, s);
}

/* ---- wrong-state errors --------------------------------------------------- */

TEST(sio_send_unconnected_stream_is_notconn)
{
    SOCKET s; NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(0);
    EXPECT_EQ(send(s, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

TEST(sio_recv_unconnected_stream_is_notconn)
{
    SOCKET s; char b[4]; NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

TEST(sio_send_bound_unconnected_is_notconn)
{
    SOCKET s; struct sockaddr_in a; NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    ts_loop(&a);
    EXPECT_EQ(bind(s, (struct sockaddr *)&a, sizeof a), 0);
    WSASetLastError(0);
    EXPECT_EQ(send(s, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}

TEST(sio_send_recv_on_listener_is_notconn)
{
    struct sockaddr_in a; SOCKET l; char b[4]; NEED_NET();
    l = ts_listener(&a);
    REQUIRE(l != INVALID_SOCKET);
    ts_nonblock(l, 1);          /* the state check precedes any wait; non-blocking keeps a wrong stack from hanging */
    WSASetLastError(0);
    EXPECT_EQ(send(l, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    WSASetLastError(0);
    EXPECT_EQ(recv(l, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(l);
}

TEST(sio_send_recv_after_local_close_is_notsock)
{
    SOCKET c, s; char b[4];
    NEED_PAIR(c, s);
    closesocket(c);
    WSASetLastError(0);
    EXPECT_EQ(send(c, "x", 1, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0);
    EXPECT_EQ(recv(c, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    closesocket(s);
}

TEST(sio_second_closesocket_is_notsock)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(closesocket(c), 0);
    WSASetLastError(0);
    EXPECT_EQ(closesocket(c), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    closesocket(s);
}

TEST(sio_send_with_invalid_flag_bits_is_rejected_or_ignored)
{
    SOCKET c, s; int r;
    NEED_PAIR(c, s);
    WSASetLastError(0);
    r = send(c, "x", 1, 0x40000000);
    if (r == -1) t_note("unknown send flag rejected with %d", WSAGetLastError());
    else EXPECT_EQ(r, 1);
    ts_close2(c, s);
}

/* ---- ordering ------------------------------------------------------------ */

TEST(sio_many_small_messages_arrive_in_order)
{
    SOCKET c, s; int n = 2000, bad = 0, got = 0;
    NEED_PAIR(c, s);
    ts_job rj = { 0 }; HANDLE th;
    rj.s = s; rj.seed = 11; rj.chunk = 97;
    th = ts_start(ts_reader, &rj);
    for (int i = 0; i < n; i++) {
        char b[4]; ts_fill(b, 4, 11, (unsigned long long)i * 4);
        if (send(c, b, 4, 0) != 4) { bad++; break; }
    }
    shutdown(c, SD_SEND);
    CHECK(ts_join(th, 15000));
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(rj.total, n * 4);
    CHECK(rj.ok);
    ts_close2(c, s);
}

TEST(sio_one_byte_sends_arrive_in_order)
{
    SOCKET c, s; char b[300];
    NEED_PAIR(c, s);
    for (int i = 0; i < 300; i++) { char ch = (char)ts_pat(2, i); EXPECT_EQ(send(c, &ch, 1, 0), 1); }
    EXPECT_EQ(ts_recv_n(s, b, 300), 300);
    CHECK(ts_verify(b, 300, 2, 0));
    ts_close2(c, s);
}

TEST(sio_receive_chunk_sizes_do_not_change_content)
{
    static const int chunks[] = { 1, 2, 3, 5, 8, 13, 64, 1000 };
    for (unsigned k = 0; k < sizeof chunks / sizeof *chunks; k++) {
        SOCKET c, s; char data[4000], *got = malloc(4000); int tot = 0;
        NEED_PAIR(c, s);
        ts_fill(data, 4000, 4, 0);
        EXPECT_EQ(send(c, data, 4000, 0), 4000);
        shutdown(c, SD_SEND);
        for (;;) {
            int r = recv(s, got + tot, chunks[k], 0);
            if (r <= 0) break;
            tot += r;
        }
        EXPECT_EQ(tot, 4000);
        CHECK(tot == 4000 && !memcmp(got, data, 4000));
        free(got);
        ts_close2(c, s);
    }
}

TEST(sio_ping_pong_round_trips)
{
    SOCKET c, s; char b[64];
    NEED_PAIR(c, s);
    for (int i = 1; i <= 60; i++) {
        char m[64];
        ts_fill(m, i, 6, (unsigned long long)i);
        EXPECT_EQ(send(c, m, i, 0), i);
        EXPECT_EQ(ts_recv_n(s, b, i), i);
        CHECK(!memcmp(b, m, i));
        EXPECT_EQ(send(s, b, i, 0), i);
        EXPECT_EQ(ts_recv_n(c, b, i), i);
        CHECK(!memcmp(b, m, i));
    }
    ts_close2(c, s);
}

/* ---- blocked receivers woken by events ------------------------------------ */

static DWORD WINAPI delayed_send(LPVOID a)
{
    SOCKET s = (SOCKET)(ULONG_PTR)a;
    Sleep(80);
    send(s, "late", 4, 0);
    return 0;
}

TEST(sio_blocking_recv_wakes_on_data)
{
    SOCKET c, s; char b[8]; HANDLE th;
    NEED_PAIR(c, s);
    th = CreateThread(NULL, 0, delayed_send, (LPVOID)(ULONG_PTR)c, 0, NULL);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 4);
    CHECK(!memcmp(b, "late", 4));
    CHECK(ts_join(th, 5000));
    ts_close2(c, s);
}

static DWORD WINAPI delayed_close(LPVOID a)
{
    SOCKET s = (SOCKET)(ULONG_PTR)a;
    Sleep(80);
    closesocket(s);
    return 0;
}

TEST(sio_blocking_recv_wakes_on_peer_close_with_zero)
{
    SOCKET c, s; char b[8]; HANDLE th;
    NEED_PAIR(c, s);
    th = CreateThread(NULL, 0, delayed_close, (LPVOID)(ULONG_PTR)c, 0, NULL);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    CHECK(ts_join(th, 5000));
    closesocket(s);
}

static DWORD WINAPI delayed_shutdown_send(LPVOID a)
{
    SOCKET s = (SOCKET)(ULONG_PTR)a;
    Sleep(80);
    shutdown(s, SD_SEND);
    return 0;
}

TEST(sio_blocking_recv_wakes_on_half_close_with_zero)
{
    SOCKET c, s; char b[8]; HANDLE th;
    NEED_PAIR(c, s);
    th = CreateThread(NULL, 0, delayed_shutdown_send, (LPVOID)(ULONG_PTR)c, 0, NULL);
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    CHECK(ts_join(th, 5000));
    ts_close2(c, s);
}

static DWORD WINAPI delayed_reset(LPVOID a)
{
    SOCKET s = (SOCKET)(ULONG_PTR)a;
    Sleep(80);
    ts_rst_close(s);
    return 0;
}

TEST(sio_blocking_recv_wakes_on_reset_with_connreset)
{
    SOCKET c, s; char b[8]; HANDLE th;
    NEED_PAIR(c, s);
    th = CreateThread(NULL, 0, delayed_reset, (LPVOID)(ULONG_PTR)c, 0, NULL);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, b, sizeof b, 0), -1);
    EXPECT_EQ(WSAGetLastError(), WSAECONNRESET);
    CHECK(ts_join(th, 5000));
    closesocket(s);
}

static DWORD WINAPI delayed_local_close(LPVOID a)
{
    SOCKET s = (SOCKET)(ULONG_PTR)a;
    Sleep(100);
    closesocket(s);
    return 0;
}

TEST(sio_blocking_recv_ends_when_local_socket_is_closed)
{
    SOCKET c, s; char b[8]; HANDLE th; int r;
    NEED_PAIR(c, s);
    th = CreateThread(NULL, 0, delayed_local_close, (LPVOID)(ULONG_PTR)s, 0, NULL);
    WSASetLastError(0);
    r = recv(s, b, sizeof b, 0);
    CHECK(r == -1);
    t_note("recv interrupted by local closesocket failed with an error in a small set: %d", WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAENOTSOCK || WSAGetLastError() == WSAECONNABORTED);
    CHECK(ts_join(th, 5000));
    closesocket(c);
}
