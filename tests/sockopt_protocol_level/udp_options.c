/* IPPROTO_UDP socket options (UDP_NOCHECKSUM, UDP_SEND_MSG_SIZE, UDP_RECV_MAX_COALESCED_SIZE): defaults, value coding,
 * option-length protocol, state independence, and the errors for numbers the UDP level does not define. UDP_SEND_MSG_SIZE
 * is also exercised on the wire over loopback, where a large send is cut into datagrams of that size. */
#include "spl.h"

#define EINV WSAEINVAL
#define EFLT WSAEFAULT

static const struct spl_row nochk_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {-1, 0, 1}, {2, 0, 1}, {255, 0, 1}, {256, 0, 0}, {1000, 0, 1}, {65535, 0, 1},
    {0x7fffffff, 0, 1}, {(int)0x80000000, 0, 0}, {0x01000000, 0, 0}, {1, 0, 1},
};
/* Any 32-bit value is stored and returned unchanged. */
static const struct spl_row dword_rows[] = {
    {1000, 0, 1000}, {0, 0, 0}, {1, 0, 1}, {2, 0, 2}, {255, 0, 255}, {256, 0, 256}, {1472, 0, 1472}, {65507, 0, 65507},
    {65508, 0, 65508}, {65535, 0, 65535}, {65536, 0, 65536}, {0x7fffffff, 0, 0x7fffffff}, {(int)0x80000000, 0, (int)0x80000000}, {-1, 0, -1},
};

SPL_DEFTEST(udp_default_nochecksum_off,           spl_udp4, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 0xff, 0)
SPL_DEFTEST(udp_default_send_msg_size_zero,       spl_udp4, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 0xffffffff, 0)
SPL_DEFTEST(udp_default_recv_max_coalesced_zero,  spl_udp4, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 0xffffffff, 0)
SPL_DEFTEST(udp6_default_nochecksum_off,          spl_udp6, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 0xff, 0)
SPL_DEFTEST(udp6_default_send_msg_size_zero,      spl_udp6, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 0xffffffff, 0)
SPL_DEFTEST(udp6_default_recv_max_coalesced_zero, spl_udp6, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 0xffffffff, 0)

SPL_ROWTEST(udp_nochecksum_values,                spl_udp4, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 0xff, nochk_rows)
SPL_ROWTEST(udp6_nochecksum_values,               spl_udp6, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 0xff, nochk_rows)
SPL_ROWTEST(udp_send_msg_size_values,             spl_udp4, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 0xffffffff, dword_rows)
SPL_ROWTEST(udp6_send_msg_size_values,            spl_udp6, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 0xffffffff, dword_rows)
SPL_ROWTEST(udp_recv_max_coalesced_values,        spl_udp4, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 0xffffffff, dword_rows)
SPL_ROWTEST(udp6_recv_max_coalesced_values,       spl_udp6, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 0xffffffff, dword_rows)

/* Numbers the UDP level does not define fail with WSAEINVAL (not WSAENOPROTOOPT). */
SPL_REFUSETEST(udp_option_zero_invalid,           spl_udp4, SPL_LVL_UDP, 0, EINV)
SPL_REFUSETEST(udp_option_4_invalid,              spl_udp4, SPL_LVL_UDP, 4, EINV)
SPL_REFUSETEST(udp_option_5_invalid,              spl_udp4, SPL_LVL_UDP, 5, EINV)
SPL_REFUSETEST(udp_option_100_invalid,            spl_udp4, SPL_LVL_UDP, 100, EINV)
SPL_REFUSETEST(udp6_option_zero_invalid,          spl_udp6, SPL_LVL_UDP, 0, EINV)
SPL_REFUSETEST(udp6_option_4_invalid,             spl_udp6, SPL_LVL_UDP, 4, EINV)

TEST(udp_nochecksum_set_length_rules)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_udp4();
    spl_len_protocol(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 1, 1, EFLT);
    spl_close(s);
}
TEST(udp_dword_options_set_length_rules)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_udp4();
    spl_len_protocol(s, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 1200, 4, EFLT);
    spl_len_protocol(s, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 1200, 4, EFLT);
    spl_close(s);
}
TEST(udp_nochecksum_get_length_rules)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_udp4();
    spl_get_protocol(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 1, EFLT, 1, 1, 1);
    spl_close(s);
}
TEST(udp_dword_options_get_length_rules)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_udp4();
    spl_get_protocol(s, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 4, EFLT, 0, 4, 4);
    spl_get_protocol(s, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 4, EFLT, 0, 4, 4);
    spl_close(s);
}
TEST(udp_nochecksum_get_writes_one_byte)
{
    SOCKET s; int v = 0x7a7a7a7a, l = 4, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_get(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, &v, &l, &e), 0);
    SEQ(l, 1);
    SEQ((unsigned)v, 0x7a7a7a00u);
    spl_close(s);
}
TEST(udp_options_accepted_on_bound_and_connected_sockets)
{
    SOCKET s, d; u_short p = 0; struct sockaddr_in a; int e;
    if (!spl_up()) return;
    s = spl_udp4(); d = spl_udp4();
    spl_bind4(d, &p); spl_bind4(s, NULL);
    SEQ(spl_seti(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 1, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 1200, &e), 0);
    spl_loop4(&a); a.sin_port = p;
    SEQ(spl_connect(s, (struct sockaddr *)&a, sizeof a), 0);
    SEQ(spl_rb(s, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM) & 0xff, 1);
    SEQ(spl_rb(s, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE), 1200);
    SEQ(spl_seti(s, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 900, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 64000, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE), 64000);
    spl_close(s); spl_close(d);
}
TEST(udp_options_are_independent_per_socket)
{
    SOCKET a, b; int e;
    if (!spl_up()) return;
    a = spl_udp4(); b = spl_udp4();
    SEQ(spl_seti(a, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE, 777, &e), 0);
    SEQ(spl_seti(a, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM, 1, &e), 0);
    SEQ(spl_rb(b, SPL_LVL_UDP, SPL_UDP_SEND_MSG_SIZE), 0);
    SEQ(spl_rb(b, SPL_LVL_UDP, SPL_UDP_NOCHECKSUM) & 0xff, 0);
    spl_close(a); spl_close(b);
}
TEST(udp_level_options_on_ipv4_and_ipv6_datagram_sockets_agree)
{
    SOCKET a, b; int e, v;
    if (!spl_up()) return;
    a = spl_udp4(); b = spl_udp6();
    if (b == INVALID_SOCKET) { spl_close(a); t_skip("IPv6 unavailable"); return; }
    SEQ(spl_seti(a, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 5000, &e), 0);
    SEQ(spl_seti(b, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, 5000, &e), 0);
    SEQ(spl_geti(a, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, &v, &e), 0); SEQ(v, 5000);
    SEQ(spl_geti(b, SPL_LVL_UDP, SPL_UDP_RECV_MAX_COALESCED_SIZE, &v, &e), 0); SEQ(v, 5000);
    spl_close(a); spl_close(b);
}
