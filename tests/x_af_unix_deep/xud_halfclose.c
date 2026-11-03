/* Half-close on AF_UNIX stream sockets: each direction ends independently. The sender's shutdown(SD_SEND)
 * becomes end of stream for the peer only after queued data, the shut-down direction rejects further sends with
 * WSAESHUTDOWN while the other keeps working, and the readiness a fully finished connection shows. */
#include "xud.h"

TEST(xud_hc_send_shutdown_gives_peer_zero_read)
{
    char b[8];
    TRIO(t, "hc1.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(recv)(t.srv, b, sizeof b, 0), 0);
    XEQ(U(recv)(t.srv, b, sizeof b, 0), 0);                 /* sticky */
    x_trio_close(&t);
}
TEST(xud_hc_other_direction_survives)
{
    char b[8] = { 0 };
    TRIO(t, "hc2.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(send)(t.srv, "abc", 3, 0), 3);
    XEQ(x_recv_n(t.cli, b, 3), 3);
    CHECK(!memcmp(b, "abc", 3));
    x_trio_close(&t);
}
TEST(xud_hc_send_after_own_shutdown_is_shutdown_error)
{
    TRIO(t, "hc3.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(send)(t.cli, "x", 1, 0), -1);
    XEQ(x_err(), WSAESHUTDOWN);
    XEQ(U(send)(t.cli, "x", 1, 0), -1);
    XEQ(x_err(), WSAESHUTDOWN);
    CHECK(!x_readable(t.srv, 100) || U(recv)(t.srv, (char[4]){ 0 }, 4, 0) == 0);   /* nothing but end of stream arrived */
    x_trio_close(&t);
}
TEST(xud_hc_recv_after_own_shutdown_both_is_shutdown_error)
{
    char b[4];
    TRIO(t, "hc4.sock");
    XEQ(U(shutdown)(t.cli, SD_BOTH), 0);
    XEQ(U(recv)(t.cli, b, sizeof b, 0), -1);
    XEQ(x_err(), WSAESHUTDOWN);
    x_trio_close(&t);
}
TEST(xud_hc_data_before_shutdown_is_delivered_first)
{
    char b[16];
    TRIO(t, "hc5.sock");
    XEQ(U(send)(t.cli, "payload", 7, 0), 7);
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(x_recv_n(t.srv, b, 7), 7);
    XEQ(U(recv)(t.srv, b, sizeof b, 0), 0);
    x_trio_close(&t);
}
TEST(xud_hc_both_directions_finished_poll_hup_and_wrnorm)
{
    WSAPOLLFD p;
    TRIO(t, "hc6.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(shutdown)(t.srv, SD_SEND), 0);
    p.fd = t.srv; p.events = POLLRDNORM | POLLWRNORM; p.revents = 0;
    XEQ(U(WSAPoll)(&p, 1, 1000), 1);
    XEQ((unsigned short)p.revents, POLLHUP | POLLWRNORM);
    p.fd = t.cli; p.revents = 0;
    XEQ(U(WSAPoll)(&p, 1, 1000), 1);
    XEQ((unsigned short)p.revents, POLLHUP | POLLWRNORM);
    x_trio_close(&t);
}
TEST(xud_hc_shutdown_receive_succeeds_and_keeps_send_open)
{
    char b[4] = { 0 };
    TRIO(t, "hc7.sock");
    XEQ(U(shutdown)(t.cli, SD_RECEIVE), 0);
    XEQ(U(send)(t.cli, "ok", 2, 0), 2);
    XEQ(x_recv_n(t.srv, b, 2), 2);
    x_trio_close(&t);
}
TEST(xud_hc_shutdown_both_twice_succeeds)
{
    TRIO(t, "hc8.sock");
    XEQ(U(shutdown)(t.cli, SD_BOTH), 0);
    XEQ(U(shutdown)(t.cli, SD_BOTH), 0);
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(shutdown)(t.cli, SD_RECEIVE), 0);
    x_trio_close(&t);
}
TEST(xud_hc_select_readable_for_eof_but_not_exception)
{
    fd_set r, x;
    struct timeval tv = { 2, 0 };
    TRIO(t, "hc9.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    FD_ZERO(&r); FD_ZERO(&x);
    FD_SET(t.srv, &r); FD_SET(t.srv, &x);
    XEQ(U(select)(0, &r, NULL, &x, &tv), 1);
    CHECK(x_isset(t.srv, &r));
    CHECK(!x_isset(t.srv, &x));
    x_trio_close(&t);
}
TEST(xud_hc_peer_close_then_local_shutdown_succeeds)
{
    TRIO(t, "hc10.sock");
    U(closesocket)(t.srv);
    t.srv = INVALID_SOCKET;
    CHECK(x_readable(t.cli, 3000));
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    XEQ(U(shutdown)(t.cli, SD_BOTH), 0);
    x_trio_close(&t);
}
TEST(xud_hc_fionread_zero_after_eof)
{
    u_long n = 99;
    TRIO(t, "hc11.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(ioctlsocket)(t.srv, FIONREAD, &n), 0);
    XEQ(n, 0);
    x_trio_close(&t);
}
TEST(xud_hc_wsarecv_flags_and_bytes_at_eof)
{
    WSABUF wb;
    char b[8];
    DWORD got = 77, fl = 0;
    TRIO(t, "hc12.sock");
    XEQ(U(shutdown)(t.cli, SD_SEND), 0);
    wb.buf = b; wb.len = sizeof b;
    XEQ(U(WSARecv)(t.srv, &wb, 1, &got, &fl, NULL, NULL), 0);   /* end of stream is success with zero bytes */
    XEQ(got, 0);
    x_trio_close(&t);
}
