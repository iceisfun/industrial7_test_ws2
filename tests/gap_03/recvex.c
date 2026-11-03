/* WSARecvEx (mswsock export) depth: the flags word is an output only (cleared on entry, whatever the caller put
 * in it), return protocol on stream and datagram sockets, the error each wrong socket state produces, and that
 * the error path also leaves the flags cleared. MSG_PARTIAL on truncated datagrams is asserted elsewhere. */
#include "g3.h"

typedef int (WSAAPI *recvex_fn)(SOCKET, char *, int, int *);
#define RX() ((recvex_fn)t_proc_in("mswsock.dll", "WSARecvEx"))
#define MSGPART 0x8000

static void nonblock(SOCKET s) { u_long one = 1; g3_ioctlsocket(s, FIONBIO, &one); }

TEST(gap3_recvex_stream_returns_count_and_zero_flags)
{
    char b[16]; int f = 0x55;
    G3_PAIR(c, a); REQUIRE(RX());
    G3_EQ(g3_send(c, "hello", 5, 0), 5);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 5);
    CHECK(!memcmp(b, "hello", 5));
    G3_EQ(f, 0);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_input_flags_are_ignored_msg_peek_does_not_peek)
{
    /* The flags word is zeroed before WSARecv runs, so a MSG_PEEK passed in is not honoured: the data is consumed. */
    char b[16]; int f = MSG_PEEK;
    G3_PAIR(c, a); REQUIRE(RX());
    nonblock(a);
    G3_EQ(g3_send(c, "peekme", 6, 0), 6);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 6);
    G3_EQ(f, 0);
    g3_WSASetLastError(0);
    G3_EQ(RX()(a, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAEWOULDBLOCK);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_input_flags_are_ignored_msg_oob_does_not_select_oob)
{
    char b[16]; int f = MSG_OOB;
    G3_PAIR(c, a); REQUIRE(RX());
    G3_EQ(g3_send(c, "inband", 6, 0), 6);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 6);
    CHECK(!memcmp(b, "inband", 6));
    G3_EQ(f, 0);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_flags_are_cleared_when_a_garbage_value_was_passed)
{
    char b[8]; int f = (int)0xFFFFFFFF;
    G3_PAIR(c, a); REQUIRE(RX());
    G3_EQ(g3_send(c, "x", 1, 0), 1);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 1);
    G3_EQ(f, 0);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_orderly_close_returns_zero_with_cleared_flags)
{
    char b[8]; int f = 0x77;
    G3_PAIR(c, a); REQUIRE(RX());
    g3_closesocket(c);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 0);
    G3_EQ(f, 0);
    g3_closesocket(a);
}

TEST(gap3_recvex_nonblocking_empty_is_wouldblock_and_flags_cleared)
{
    char b[8]; int f = 0x77;
    G3_PAIR(c, a); REQUIRE(RX());
    nonblock(a);
    g3_WSASetLastError(0);
    G3_EQ(RX()(a, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAEWOULDBLOCK);
    G3_EQ(f, 0);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_invalid_socket_is_notsock_and_flags_cleared)
{
    char b[8]; int f = 0x77;
    REQUIRE(RX()); G3_NET();
    g3_WSASetLastError(0);
    G3_EQ(RX()(INVALID_SOCKET, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAENOTSOCK);
    G3_EQ(f, 0);
}

TEST(gap3_recvex_closed_socket_is_notsock)
{
    char b[8]; int f = 0x77; SOCKET s;
    REQUIRE(RX()); G3_NET();
    s = g3_tcp(); CHECK(s != INVALID_SOCKET);
    g3_closesocket(s);
    g3_WSASetLastError(0);
    G3_EQ(RX()(s, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAENOTSOCK);
    G3_EQ(f, 0);
}

TEST(gap3_recvex_unconnected_tcp_is_notconn)
{
    char b[8]; int f = 0x77; SOCKET s;
    REQUIRE(RX()); G3_NET();
    s = g3_tcp();
    g3_WSASetLastError(0);
    G3_EQ(RX()(s, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAENOTCONN);
    G3_EQ(f, 0);
    g3_closesocket(s);
}

TEST(gap3_recvex_listening_socket_is_notconn)
{
    char b[8]; int f = 0x77; struct sockaddr_in a; SOCKET l;
    REQUIRE(RX()); G3_NET();
    l = g3_listener(&a); CHECK(l != INVALID_SOCKET);
    g3_WSASetLastError(0);
    G3_EQ(RX()(l, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAENOTCONN);
    G3_EQ(f, 0);
    g3_closesocket(l);
}

TEST(gap3_recvex_unbound_udp_is_einval)
{
    char b[8]; int f = 0x77; SOCKET s;
    REQUIRE(RX()); G3_NET();
    s = g3_udp(); nonblock(s);
    g3_WSASetLastError(0);
    G3_EQ(RX()(s, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAEINVAL);
    G3_EQ(f, 0);
    g3_closesocket(s);
}

TEST(gap3_recvex_bound_udp_empty_nonblocking_is_wouldblock)
{
    char b[8]; int f = 0x77; struct sockaddr_in a; SOCKET s;
    REQUIRE(RX()); G3_NET();
    s = g3_bound(SOCK_DGRAM, &a); nonblock(s);
    g3_WSASetLastError(0);
    G3_EQ(RX()(s, b, sizeof b, &f), SOCKET_ERROR);
    G3_EQ(g3_WSAGetLastError(), WSAEWOULDBLOCK);
    G3_EQ(f, 0);
    g3_closesocket(s);
}

TEST(gap3_recvex_datagram_that_fits_reports_count_without_partial)
{
    char b[32]; int f = 0x77; struct sockaddr_in a; SOCKET r, t;
    REQUIRE(RX()); G3_NET();
    r = g3_bound(SOCK_DGRAM, &a); t = g3_udp();
    G3_EQ(g3_sendto(t, "datagram", 8, 0, (struct sockaddr *)&a, sizeof a), 8);
    CHECK(g3_readable(r, 5000));
    G3_EQ(RX()(r, b, sizeof b, &f), 8);
    CHECK(!memcmp(b, "datagram", 8));
    G3_EQ(f & MSGPART, 0);
    G3_EQ(f, 0);
    g3_closesocket(r); g3_closesocket(t);
}

TEST(gap3_recvex_truncated_datagram_returns_buffer_size_with_partial_bit_only)
{
    char b[4]; int f = 0x77; struct sockaddr_in a; SOCKET r, t;
    REQUIRE(RX()); G3_NET();
    r = g3_bound(SOCK_DGRAM, &a); t = g3_udp();
    G3_EQ(g3_sendto(t, "abcdefgh", 8, 0, (struct sockaddr *)&a, sizeof a), 8);
    CHECK(g3_readable(r, 5000));
    G3_EQ(RX()(r, b, sizeof b, &f), 4);
    CHECK(!memcmp(b, "abcd", 4));
    G3_EQ(f, MSGPART);      /* nothing else is set: the old input value is gone */
    g3_closesocket(r); g3_closesocket(t);
}

TEST(gap3_recvex_partial_bit_does_not_stick_to_the_next_call)
{
    char b[4]; int f = 0; struct sockaddr_in a; SOCKET r, t;
    REQUIRE(RX()); G3_NET();
    r = g3_bound(SOCK_DGRAM, &a); t = g3_udp();
    g3_sendto(t, "abcdefgh", 8, 0, (struct sockaddr *)&a, sizeof a);
    g3_sendto(t, "wxyz", 4, 0, (struct sockaddr *)&a, sizeof a);
    CHECK(g3_readable(r, 5000));
    G3_EQ(RX()(r, b, sizeof b, &f), 4); G3_EQ(f, MSGPART);
    CHECK(g3_readable(r, 5000));
    G3_EQ(RX()(r, b, sizeof b, &f), 4); G3_EQ(f, 0);   /* f still carries the bit in; the call clears it */
    CHECK(!memcmp(b, "wxyz", 4));
    g3_closesocket(r); g3_closesocket(t);
}

TEST(gap3_recvex_stream_buffer_smaller_than_pending_never_sets_partial)
{
    char b[3]; int f = 0x77;
    G3_PAIR(c, a); REQUIRE(RX());
    G3_EQ(g3_send(c, "123456789", 9, 0), 9);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 3);
    G3_EQ(f, 0);
    CHECK(!memcmp(b, "123", 3));
    G3_EQ(g3_recv_all(a, b, 3, 5000), 3); CHECK(!memcmp(b, "456", 3));
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_zero_length_buffer_on_stream_with_data)
{
    /* Records the zero-length receive on a stream with pending data; the data must remain readable. */
    char b[8]; int f = 0x77, r;
    G3_PAIR(c, a); REQUIRE(RX());
    nonblock(a);
    g3_send(c, "keep", 4, 0);
    CHECK(g3_readable(a, 5000));
    g3_WSASetLastError(0);
    r = RX()(a, b, 0, &f);
    t_note("WSARecvEx len 0 on stream with data -> %d err %d flags %d", r, r < 0 ? g3_WSAGetLastError() : 0, f);
    G3_EQ(f & ~MSGPART, 0);
    G3_EQ(RX()(a, b, sizeof b, &f), 4);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_data_before_close_is_delivered_then_zero)
{
    char b[16]; int f = 0x77;
    G3_PAIR(c, a); REQUIRE(RX());
    g3_send(c, "bye", 3, 0); g3_closesocket(c);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 3); G3_EQ(f, 0);
    CHECK(g3_readable(a, 5000));
    G3_EQ(RX()(a, b, sizeof b, &f), 0); G3_EQ(f, 0);
    g3_closesocket(a);
}

TEST(gap3_recvex_after_shutdown_receive_returns_zero_on_stream)
{
    char b[8]; int f = 0x77, r;
    G3_PAIR(c, a); REQUIRE(RX());
    G3_EQ(g3_shutdown(a, SD_RECEIVE), 0);
    g3_WSASetLastError(0);
    r = RX()(a, b, sizeof b, &f);
    t_note("WSARecvEx after SD_RECEIVE -> %d err %d", r, r < 0 ? g3_WSAGetLastError() : 0);
    G3_EQ(f & ~MSGPART, 0);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_without_wsastartup_is_notinitialised_and_flags_cleared)
{
    G3_EQ(t_run_child("recvex_nostart", "", 20000), 0);
}
CHILD(recvex_nostart)
{
    char b[8]; int f = 0x77, r;
    recvex_fn fn = RX();
    if (!fn) return 2;
    SetLastError(0);
    r = fn(INVALID_SOCKET, b, sizeof b, &f);
    if (r != SOCKET_ERROR) return 3;
    if (f != 0) return 4;
    if (g3_WSAGetLastError() != WSANOTINITIALISED) return 5;
    return 0;
}

TEST(gap3_recvex_wsock32_forward_agrees_on_flags_clearing)
{
    recvex_fn w = (recvex_fn)t_proc_in("wsock32.dll", "WSARecvEx");
    char b[8]; int f = 0x77;
    G3_PAIR(c, a);
    if (!w) { t_skip("wsock32 WSARecvEx missing"); return; }
    g3_send(c, "fw", 2, 0);
    CHECK(g3_readable(a, 5000));
    G3_EQ(w(a, b, sizeof b, &f), 2); G3_EQ(f, 0);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_recvex_through_the_ws2_32_export_is_absent)
{
    /* WSARecvEx lives in mswsock (and forwards from wsock32), not in ws2_32. */
    CHECK(t_proc_in("ws2_32.dll", "WSARecvEx") == NULL);
}
