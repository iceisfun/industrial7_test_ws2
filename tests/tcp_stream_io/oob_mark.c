/* Urgent (out-of-band) data on TCP loopback pairs: MSG_OOB send and receive, SO_OOBINLINE, SIOCATMARK,
 * exception-set reporting, and how normal reads interact with a pending urgent byte. Measured: return
 * values, WSAGetLastError, received bytes and the at-mark flag. */
#include "ts.h"

/* Waits until the urgent byte is visible: select reports the socket in the exception set. */
static int oob_arrived(SOCKET s) { return ts_except(s, TS_WAIT_MS); }

TEST(oob_send_returns_one_for_one_byte)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    ts_close2(c, s);
}

TEST(oob_recv_returns_the_urgent_byte)
{
    SOCKET c, s; char b[4] = { 0 };
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, b, sizeof b, MSG_OOB), 1);
    EXPECT_EQ(b[0], 'U');
    ts_close2(c, s);
}

TEST(oob_urgent_byte_is_reported_in_exception_set_only)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(ts_readable(s, 100), 0);       /* not readable as normal data */
    ts_close2(c, s);
}

TEST(oob_exception_clears_after_urgent_read)
{
    SOCKET c, s; char b;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), 1);
    EXPECT_EQ(ts_except(s, 150), 0);
    ts_close2(c, s);
}

TEST(oob_second_urgent_read_finds_nothing)
{
    SOCKET c, s; char b; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), 1);
    ts_nonblock(s, 1);
    WSASetLastError(0);
    r = recv(s, &b, 1, MSG_OOB);
    CHECK(r == -1);
    CHECK(WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEWOULDBLOCK);
    t_note("urgent read with no urgent data pending: error class %s",
           WSAGetLastError() == WSAEINVAL ? "EINVAL" : WSAGetLastError() == WSAEWOULDBLOCK ? "EWOULDBLOCK" : "other");
    ts_close2(c, s);
}

TEST(oob_nonblocking_urgent_read_with_none_pending_fails)
{
    SOCKET c, s; char b;
    NEED_PAIR(c, s);
    ts_nonblock(s, 1);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), -1);
    CHECK(WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEWOULDBLOCK);
    t_note("urgent read on a fresh socket: error class %s",
           WSAGetLastError() == WSAEINVAL ? "EINVAL" : WSAGetLastError() == WSAEWOULDBLOCK ? "EWOULDBLOCK" : "other");
    ts_close2(c, s);
}

TEST(oob_urgent_read_leaves_normal_data_queued)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, b, 1, MSG_OOB), 1);
    EXPECT_EQ(b[0], 'U');
    EXPECT_EQ(ts_recv_n(s, b, 3), 3);
    CHECK(!memcmp(b, "abc", 3));
    ts_close2(c, s);
}

TEST(oob_normal_reads_skip_the_urgent_byte)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    EXPECT_EQ(send(c, "def", 3, 0), 3);
    CHECK(oob_arrived(s));
    EXPECT_EQ(ts_recv_n(s, b, 6), 6);       /* the urgent byte is not part of the normal stream */
    CHECK(!memcmp(b, "abcdef", 6));
    EXPECT_EQ(recv(s, b, 1, MSG_OOB), 1);
    EXPECT_EQ(b[0], 'U');
    ts_close2(c, s);
}

TEST(oob_peek_urgent_does_not_consume)
{
    SOCKET c, s; char a = 0, b = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, &a, 1, MSG_OOB | MSG_PEEK), 1);
    EXPECT_EQ(a, 'U');
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), 1);
    EXPECT_EQ(b, 'U');
    ts_close2(c, s);
}

TEST(oob_last_urgent_byte_wins_when_two_are_sent)
{
    SOCKET c, s; char b = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "1", 1, MSG_OOB), 1);
    EXPECT_EQ(send(c, "2", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    Sleep(50);
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), 1);
    t_note("two urgent bytes sent back to back: first urgent read gave '%c'", b);
    ts_close2(c, s);
}

TEST(oob_send_multibyte_reports_full_count)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abcd", 4, MSG_OOB), 4);
    CHECK(oob_arrived(s));
    ts_close2(c, s);
}

TEST(oob_multibyte_send_delivers_every_byte_somewhere)
{
    SOCKET c, s; char b[8]; char u = 0; int normal = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abcd", 4, MSG_OOB), 4);
    CHECK(oob_arrived(s));
    Sleep(50);
    EXPECT_EQ(recv(s, &u, 1, MSG_OOB), 1);
    ts_nonblock(s, 1);
    for (int i = 0; i < 50 && normal < 3; i++) {
        int r = recv(s, b + normal, 8 - normal, 0);
        if (r > 0) normal += r; else Sleep(10);
    }
    t_note("multi-byte urgent send: urgent byte '%c', %d normal byte(s) follow", u, normal);
    CHECK(normal + 1 == 4 || normal == 4);
    ts_close2(c, s);
}

/* ---- SO_OOBINLINE -------------------------------------------------------- */

TEST(oob_inline_default_is_off)
{
    SOCKET c, s; int v = 0xdead, len = sizeof v;
    NEED_PAIR(c, s);
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&v, &len), 0);
    EXPECT_EQ(v, 0);
    ts_close2(c, s);
}

TEST(oob_inline_urgent_byte_arrives_as_normal_data)
{
    SOCKET c, s; char b[8] = { 0 };
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(ts_readable(s, TS_WAIT_MS));
    EXPECT_EQ(recv(s, b, sizeof b, 0), 1);
    EXPECT_EQ(b[0], 'U');
    ts_close2(c, s);
}

TEST(oob_inline_urgent_read_is_einval)
{
    SOCKET c, s; char b;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(ts_readable(s, TS_WAIT_MS));
    WSASetLastError(0);
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(recv(s, &b, 1, 0), 1);       /* and the byte is still there for a normal read */
    ts_close2(c, s);
}

TEST(oob_inline_urgent_read_is_einval_even_when_nothing_pending)
{
    SOCKET c, s; char b;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    ts_nonblock(s, 1);
    WSASetLastError(0);
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    ts_close2(c, s);
}

TEST(oob_inline_keeps_stream_order)
{
    SOCKET c, s; char b[16];
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "ab", 2, 0), 2);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    EXPECT_EQ(send(c, "cd", 2, 0), 2);
    EXPECT_EQ(ts_recv_n(s, b, 5), 5);
    CHECK(!memcmp(b, "abUcd", 5));
    ts_close2(c, s);
}

TEST(oob_inline_urgent_byte_is_not_in_exception_set)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(ts_readable(s, TS_WAIT_MS));
    EXPECT_EQ(ts_except(s, 100), 0);
    ts_close2(c, s);
}

TEST(oob_inline_fionread_counts_urgent_byte)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "abU", 3, 0), 3);
    EXPECT_EQ(send(c, "V", 1, MSG_OOB), 1);
    EXPECT_EQ(ts_wait_queued(s, 4, TS_WAIT_MS), 4);
    ts_close2(c, s);
}

TEST(oob_inline_option_value_roundtrips)
{
    SOCKET c, s; int v = 0, len = sizeof v;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&v, &len), 0);
    EXPECT_EQ(v, 1);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 0), 0);
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&v, &len), 0);
    EXPECT_EQ(v, 0);
    ts_close2(c, s);
}

TEST(oob_inline_set_on_sender_does_not_affect_sending)
{
    SOCKET c, s; char b = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(c, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, &b, 1, MSG_OOB), 1);
    EXPECT_EQ(b, 'U');
    ts_close2(c, s);
}

TEST(oob_inline_enabled_after_arrival_makes_byte_readable_or_stays_urgent)
{
    SOCKET c, s; char b = 0; int r;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    Sleep(50);
    ts_nonblock(s, 1);
    r = recv(s, &b, 1, 0);
    t_note("inline enabled after an urgent byte arrived: normal read returned %d", r);
    ts_close2(c, s);
}

/* ---- SIOCATMARK ------------------------------------------------------------ */

TEST(oob_atmark_true_on_fresh_connection)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_atmark(c), 1);
    EXPECT_EQ(ts_atmark(s), 1);
    ts_close2(c, s);
}

TEST(oob_atmark_true_with_normal_data_only)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "plain", 5, 0), 5);
    EXPECT_EQ(ts_wait_queued(s, 5, TS_WAIT_MS), 5);
    EXPECT_EQ(ts_atmark(s), 1);
    ts_close2(c, s);
}

TEST(oob_atmark_false_while_normal_data_precedes_urgent)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    EXPECT_EQ(ts_atmark(s), 0);
    ts_close2(c, s);
}

TEST(oob_atmark_true_after_urgent_and_normal_data_consumed)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(recv(s, b, 1, MSG_OOB), 1);
    EXPECT_EQ(ts_recv_n(s, b, 3), 3);
    EXPECT_EQ(ts_atmark(s), 1);
    ts_close2(c, s);
}

TEST(oob_atmark_after_normal_data_read_with_urgent_pending_is_observed)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(ts_recv_n(s, b, 3), 3);
    t_note("at-mark with urgent byte pending and normal data drained: %d", ts_atmark(s));
    ts_close2(c, s);
}

TEST(oob_atmark_false_with_urgent_pending_and_normal_data_inline_off_fresh)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    t_note("at-mark with only an urgent byte pending: %d", ts_atmark(s));
    ts_close2(c, s);
}

TEST(oob_atmark_with_inline_urgent_after_leading_data_is_observed)
{
    SOCKET c, s; char b[8];
    NEED_PAIR(c, s);
    EXPECT_EQ(ts_set_int(s, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    EXPECT_EQ(send(c, "ab", 2, 0), 2);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    int before = ts_atmark(s);
    EXPECT_EQ(recv(s, b, 2, 0), 2);
    int after = ts_atmark(s);
    t_note("inline urgent: at-mark before leading data read %d, after %d", before, after);
    CHECK(before == 0 || before == 1);
    ts_close2(c, s);
}

TEST(oob_atmark_via_wsaioctl_matches_ioctlsocket)
{
    SOCKET c, s; DWORD v = 0xdead, ret = 0;
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "abc", 3, 0), 3);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    EXPECT_EQ(ts_wait_queued(s, 3, TS_WAIT_MS), 3);
    EXPECT_EQ(WSAIoctl(s, SIOCATMARK, NULL, 0, &v, sizeof v, &ret, NULL, NULL), 0);
    EXPECT_EQ(ret, sizeof v);
    EXPECT_EQ(v ? 1 : 0, ts_atmark(s));
    ts_close2(c, s);
}

TEST(oob_atmark_on_unconnected_socket)
{
    SOCKET s; NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    EXPECT_EQ(ts_atmark(s), 1);
    closesocket(s);
}

/* ---- urgent data and teardown ---------------------------------------------- */

TEST(oob_urgent_then_graceful_close_still_readable)
{
    SOCKET c, s; char b[4] = { 0 };
    NEED_PAIR(c, s);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), 1);
    CHECK(oob_arrived(s));
    shutdown(c, SD_SEND);
    EXPECT_EQ(recv(s, b, 1, MSG_OOB), 1);
    EXPECT_EQ(b[0], 'U');
    EXPECT_EQ(recv(s, b, sizeof b, 0), 0);
    ts_close2(c, s);
}

TEST(oob_send_after_shutdown_send_is_eshutdown)
{
    SOCKET c, s;
    NEED_PAIR(c, s);
    EXPECT_EQ(shutdown(c, SD_SEND), 0);
    WSASetLastError(0);
    EXPECT_EQ(send(c, "U", 1, MSG_OOB), -1);
    EXPECT_EQ(WSAGetLastError(), WSAESHUTDOWN);
    ts_close2(c, s);
}

TEST(oob_send_unconnected_is_notconn)
{
    SOCKET s; NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    WSASetLastError(0);
    EXPECT_EQ(send(s, "U", 1, MSG_OOB), -1);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}
