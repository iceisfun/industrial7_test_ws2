/* Additional provider option and control-code checks: receive and send time-outs, IP level options,
 * base-handle and routing queries, the datagram connection-reset control, and a time-out driven receive.
 * Only behaviour that follows from the documented option semantics is a hard check; values that depend on
 * the machine's configuration are logged with t_note as relations.
 */
#include "spi.h"
#include <mswsock.h>

static int get_dw(SOCKET s, int lvl, int opt, DWORD *v, int *err)
{
    int l = sizeof *v, e = 0, r;
    *v = 0xDEADBEEFu;
    r = P.lpWSPGetSockOpt(s, lvl, opt, (char *)v, &l, &e);
    if (err) *err = e;
    return r;
}
static int set_dw(SOCKET s, int lvl, int opt, DWORD v, int *err)
{
    int e = 0, r = P.lpWSPSetSockOpt(s, lvl, opt, (const char *)&v, sizeof v, &e);
    if (err) *err = e;
    return r;
}

TEST(timeout_rcv_default_zero)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(get_dw(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    EXPECT_EQ(v, 0);
    sp_close(s);
}
TEST(timeout_snd_default_zero)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(get_dw(s, SOL_SOCKET, SO_SNDTIMEO, &v, &e), 0);
    EXPECT_EQ(v, 0);
    sp_close(s);
}
TEST(timeout_rcv_roundtrip)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(set_dw(s, SOL_SOCKET, SO_RCVTIMEO, 1500, &e), 0);
    EXPECT_EQ(get_dw(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    EXPECT_EQ(v, 1500);
    sp_close(s);
}
TEST(timeout_snd_roundtrip)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(set_dw(s, SOL_SOCKET, SO_SNDTIMEO, 2500, &e), 0);
    EXPECT_EQ(get_dw(s, SOL_SOCKET, SO_SNDTIMEO, &v, &e), 0);
    EXPECT_EQ(v, 2500);
    sp_close(s);
}
TEST(timeout_rcv_set_back_to_zero)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(set_dw(s, SOL_SOCKET, SO_RCVTIMEO, 900, &e), 0);
    EXPECT_EQ(set_dw(s, SOL_SOCKET, SO_RCVTIMEO, 0, &e), 0);
    EXPECT_EQ(get_dw(s, SOL_SOCKET, SO_RCVTIMEO, &v, &e), 0);
    EXPECT_EQ(v, 0);
    sp_close(s);
}
TEST(timeout_rcv_expires_with_timedout_error)
{
    SP_NEED();
    SP_PAIR(c, a);
    char b[4]; int e = 0, r;
    EXPECT_EQ(set_dw(c, SOL_SOCKET, SO_RCVTIMEO, 300, &e), 0);
    r = sp_recv_some(c, b, sizeof b, &e);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(e, WSAETIMEDOUT);
    sp_close(c); sp_close(a);
}
TEST(timeout_rcv_not_applied_when_data_waits)
{
    SP_NEED();
    SP_PAIR(c, a);
    char b[8]; int e = 0, r;
    EXPECT_EQ(set_dw(c, SOL_SOCKET, SO_RCVTIMEO, 1000, &e), 0);
    CHECK(sp_send_all(a, "xyz", 3));
    CHECK(sp_readable(c, 3000) == 1);
    r = sp_recv_some(c, b, sizeof b, &e);
    EXPECT_EQ(r, 3);
    sp_close(c); sp_close(a);
}

TEST(ip_ttl_roundtrip_udp)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(set_dw(s, IPPROTO_IP, IP_TTL, 33, &e), 0);
    EXPECT_EQ(get_dw(s, IPPROTO_IP, IP_TTL, &v, &e), 0);
    EXPECT_EQ(v, 33);
    sp_close(s);
}
TEST(ip_ttl_roundtrip_tcp)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(set_dw(s, IPPROTO_IP, IP_TTL, 77, &e), 0);
    EXPECT_EQ(get_dw(s, IPPROTO_IP, IP_TTL, &v, &e), 0);
    EXPECT_EQ(v, 77);
    sp_close(s);
}
TEST(ip_ttl_default_is_in_range)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(get_dw(s, IPPROTO_IP, IP_TTL, &v, &e), 0);
    CHECK(v >= 1 && v <= 255);
    sp_close(s);
}
TEST(ip_multicast_ttl_roundtrip_udp)
{
    SOCKET s; DWORD v; int e, r;
    SP_NEED();
    s = sp_udp();
    r = set_dw(s, IPPROTO_IP, IP_MULTICAST_TTL, 5, &e);
    if (r == 0) {
        get_dw(s, IPPROTO_IP, IP_MULTICAST_TTL, &v, &e);
        CHECK((v & 0xFF) == 5);
    } else t_note("IP_MULTICAST_TTL set refused");
    sp_close(s);
}
TEST(ip_tos_roundtrip_udp_is_logged)
{
    SOCKET s; DWORD v; int e;
    SP_NEED();
    s = sp_udp();
    if (set_dw(s, IPPROTO_IP, IP_TOS, 0x20, &e) == 0 && get_dw(s, IPPROTO_IP, IP_TOS, &v, &e) == 0)
        t_note("IP_TOS read-back equals written value: %d", (v & 0xFF) == 0x20);
    else t_note("IP_TOS not settable on this build");
    sp_close(s);
}

TEST(ioctl_base_handle_is_the_socket)
{
    SOCKET s, b = 0; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_tcp();
    r = P.lpWSPIoctl(s, SIO_BASE_HANDLE, NULL, 0, &b, sizeof b, &n, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(n, sizeof b);
    CHECK(b == s);
    sp_close(s);
}
TEST(ioctl_base_handle_short_output)
{
    SOCKET s; char tiny[2]; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_tcp();
    r = P.lpWSPIoctl(s, SIO_BASE_HANDLE, NULL, 0, tiny, sizeof tiny, &n, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    sp_close(s);
}
TEST(ioctl_routing_interface_loopback)
{
    SOCKET s; struct sockaddr_in d; DWORD idx = 0xFFFFFFFFu, n = 0; int e = 0, r;
    SP_NEED();
    s = sp_udp();
    sp_v4(&d, 9);
    r = P.lpWSPIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &d, sizeof d, &idx, sizeof idx, &n, NULL, NULL, NULL, &e);
    t_note("routing query to loopback succeeded: %d", r == 0);
    if (r == 0) EXPECT_EQ(n, sizeof idx);
    sp_close(s);
}
TEST(ioctl_routing_interface_short_input)
{
    SOCKET s; char in[4] = {0}; DWORD idx = 0, n = 0; int e = 0, r;
    SP_NEED();
    s = sp_udp();
    r = P.lpWSPIoctl(s, SIO_ROUTING_INTERFACE_QUERY, in, sizeof in, &idx, sizeof idx, &n, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    sp_close(s);
}
TEST(ioctl_address_list_query_reports_something)
{
    SOCKET s; char buf[1024]; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_udp();
    r = P.lpWSPIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, sizeof buf, &n, NULL, NULL, NULL, &e);
    if (r == 0) {
        SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)buf;
        CHECK(n >= sizeof(INT));
        t_note("address list has at least one entry: %d", l->iAddressCount >= 1);
    } else t_note("address list query refused");
    sp_close(s);
}
TEST(ioctl_address_list_query_tiny_buffer_reports_size)
{
    SOCKET s; char tiny[2]; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_udp();
    r = P.lpWSPIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, tiny, sizeof tiny, &n, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    CHECK(e == SE_FAULT || e == WSAEINVAL || e == WSAENOBUFS);
    sp_close(s);
}
TEST(ioctl_udp_connreset_on_udp)
{
    SOCKET s; BOOL f = FALSE; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_udp();
    r = P.lpWSPIoctl(s, SIO_UDP_CONNRESET, &f, sizeof f, NULL, 0, &n, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, 0);
    sp_close(s);
}
TEST(ioctl_unknown_code_is_refused)
{
    SOCKET s; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_tcp();
    r = P.lpWSPIoctl(s, 0x98765432u, NULL, 0, NULL, 0, &n, NULL, NULL, NULL, &e);
    EXPECT_EQ(r, SOCKET_ERROR);
    sp_close(s);
}
TEST(ioctl_fionread_unconnected_tcp)
{
    SOCKET s; u_long av = 99; DWORD n = 0; int e = 0, r;
    SP_NEED();
    s = sp_tcp();
    r = P.lpWSPIoctl(s, FIONREAD, NULL, 0, &av, sizeof av, &n, NULL, NULL, NULL, &e);
    if (r == 0) EXPECT_EQ(av, 0);
    else t_note("FIONREAD on unconnected stream refused");
    sp_close(s);
}
