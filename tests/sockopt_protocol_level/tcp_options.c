/* IPPROTO_TCP socket options on stream sockets: defaults, value coding (boolean options look only at the low
 * byte, timer options are seconds stored as milliseconds with a clamp), refused values, option-length protocol,
 * options that the stack lets you change only before a connection exists, and the error the stack gives when a
 * TCP option is aimed at a datagram socket. Everything runs on loopback; no packets carry option data. */
#include "spl.h"

#define EINV WSAEINVAL
#define EFLT WSAEFAULT
#define ENOOPT WSAENOPROTOOPT
#define EOPNS WSAEOPNOTSUPP

/* ---- value tables ------------------------------------------------------------------------------------ */
/* Boolean options read their value from the first byte of the buffer. */
static const struct spl_row bool_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {-1, 0, 1}, {2, 0, 1}, {255, 0, 1}, {256, 0, 0}, {1000, 0, 1},
    {65535, 0, 1}, {0x7fffffff, 0, 1}, {(int)0x80000000, 0, 0}, {0x01000000, 0, 0}, {0x100, 0, 0}, {1, 0, 1},
};
/* Seconds, converted to milliseconds internally; larger values clamp to 4294967 s. */
static const struct spl_row secs_rows[] = {
    {1, 0, 1}, {0, EINV, 0}, {2, 0, 2}, {3600, 0, 3600}, {65535, 0, 65535}, {-1, 0, 4294967},
    {0x7fffffff, 0, 4294967}, {(int)0x80000000, 0, 4294967}, {4294967, 0, 4294967}, {4294968, 0, 4294967}, {7, 0, 7},
};
static const struct spl_row keepcnt_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {10, 0, 10}, {255, 0, 255}, {256, EINV, 0}, {-1, EINV, 0}, {1000, EINV, 0},
    {(int)0x80000000, EINV, 0}, {3, 0, 3},
};
static const struct spl_row maxrt_rows[] = {
    {1, 0, 1}, {0, 0, 0}, {5, 0, 5}, {256, 0, 256}, {1000, 0, 1000}, {65535, 0, 65535}, {-1, 0, -1}, {0, 0, 0},
    {0x7fffffff, 0, 4294966}, {(int)0x80000000, 0, 0},
};
static const struct spl_row cong_rows[] = {
    {0, 0, 0}, {1, 0, 1}, {2, 0, 2}, {3, 0, 3}, {4, 0, 4}, {5, 0, 5}, {10, EINV, 0}, {-1, EINV, 0}, {1000, EINV, 0}, {5, 0, 5},
};

/* ---- defaults ----------------------------------------------------------------------------------------- */
SPL_DEFTEST(tcp_default_nodelay,        spl_tcp4, SPL_LVL_TCP, TCP_NODELAY, 0xff, 0)
SPL_DEFTEST(tcp_default_expedited_1122, spl_tcp4, SPL_LVL_TCP, SPL_TCP_EXPEDITED_1122, 0xff, 0)
SPL_DEFTEST(tcp_default_keepalive_is_two_hours, spl_tcp4, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 0xffffffff, 7200)
SPL_DEFTEST(tcp_default_maxrt,          spl_tcp4, SPL_LVL_TCP, SPL_TCP_MAXRT, 0xffffffff, 0)
SPL_DEFTEST(tcp_default_stdurg,         spl_tcp4, SPL_LVL_TCP, SPL_TCP_STDURG, 0xff, 0)
SPL_DEFTEST(tcp_default_nourg,          spl_tcp4, SPL_LVL_TCP, SPL_TCP_NOURG, 0xff, 0)
SPL_DEFTEST(tcp_default_atmark,         spl_tcp4, SPL_LVL_TCP, SPL_TCP_ATMARK, 0xff, 0)
SPL_DEFTEST(tcp_default_nosynretries,   spl_tcp4, SPL_LVL_TCP, SPL_TCP_NOSYNRETRIES, 0xff, 0)
SPL_DEFTEST(tcp_default_timestamps,     spl_tcp4, SPL_LVL_TCP, SPL_TCP_TIMESTAMPS, 0xff, 0)
SPL_DEFTEST(tcp_default_congestion,     spl_tcp4, SPL_LVL_TCP, SPL_TCP_CONGESTION, 0xffffffff, 0)
SPL_DEFTEST(tcp_default_delay_fin_ack,  spl_tcp4, SPL_LVL_TCP, SPL_TCP_DELAY_FIN_ACK, 0xff, 0)
SPL_DEFTEST(tcp_default_maxrtms,        spl_tcp4, SPL_LVL_TCP, SPL_TCP_MAXRTMS, 0xffffffff, 0)
SPL_DEFTEST(tcp_default_fastopen,       spl_tcp4, SPL_LVL_TCP, SPL_TCP_FASTOPEN, 0xff, 0)
SPL_DEFTEST(tcp_default_keepcnt_is_ten, spl_tcp4, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 0xffffffff, 10)
SPL_DEFTEST(tcp_default_keepintvl_is_one_second, spl_tcp4, SPL_LVL_TCP, SPL_TCP_KEEPINTVL, 0xffffffff, 1)
SPL_DEFTEST(tcp_default_fail_connect_on_icmp_error, spl_tcp4, SPL_LVL_TCP, SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR, 0xff, 0)
SPL_DEFTEST(tcp6_default_nodelay,       spl_tcp6, SPL_LVL_TCP, TCP_NODELAY, 0xff, 0)
SPL_DEFTEST(tcp6_default_keepalive,     spl_tcp6, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 0xffffffff, 7200)
SPL_DEFTEST(tcp6_default_keepcnt,       spl_tcp6, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 0xffffffff, 10)
SPL_DEFTEST(tcp6_default_keepintvl,     spl_tcp6, SPL_LVL_TCP, SPL_TCP_KEEPINTVL, 0xffffffff, 1)

/* ---- boolean options: low byte decides ---------------------------------------------------------------- */
SPL_ROWTEST(tcp_nodelay_values,        spl_tcp4, SPL_LVL_TCP, TCP_NODELAY, 0xff, bool_rows)
SPL_ROWTEST(tcp_expedited_1122_values, spl_tcp4, SPL_LVL_TCP, SPL_TCP_EXPEDITED_1122, 0xff, bool_rows)
SPL_ROWTEST(tcp_stdurg_values,         spl_tcp4, SPL_LVL_TCP, SPL_TCP_STDURG, 0xff, bool_rows)
SPL_ROWTEST(tcp_nourg_values,          spl_tcp4, SPL_LVL_TCP, SPL_TCP_NOURG, 0xff, bool_rows)
SPL_ROWTEST(tcp_nosynretries_values,   spl_tcp4, SPL_LVL_TCP, SPL_TCP_NOSYNRETRIES, 0xff, bool_rows)
SPL_ROWTEST(tcp_timestamps_values,     spl_tcp4, SPL_LVL_TCP, SPL_TCP_TIMESTAMPS, 0xff, bool_rows)
SPL_ROWTEST(tcp_delay_fin_ack_values,  spl_tcp4, SPL_LVL_TCP, SPL_TCP_DELAY_FIN_ACK, 0xff, bool_rows)
SPL_ROWTEST(tcp_fastopen_values,       spl_tcp4, SPL_LVL_TCP, SPL_TCP_FASTOPEN, 0xff, bool_rows)
SPL_ROWTEST(tcp_fail_connect_on_icmp_error_values, spl_tcp4, SPL_LVL_TCP, SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR, 0xff, bool_rows)
SPL_ROWTEST(tcp6_nodelay_values,       spl_tcp6, SPL_LVL_TCP, TCP_NODELAY, 0xff, bool_rows)
SPL_ROWTEST(tcp6_fastopen_values,      spl_tcp6, SPL_LVL_TCP, SPL_TCP_FASTOPEN, 0xff, bool_rows)

/* ---- timer / counter options -------------------------------------------------------------------------- */
SPL_ROWTEST(tcp_keepalive_values,      spl_tcp4, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 0xffffffff, secs_rows)
SPL_ROWTEST(tcp_keepintvl_values,      spl_tcp4, SPL_LVL_TCP, SPL_TCP_KEEPINTVL, 0xffffffff, secs_rows)
SPL_ROWTEST(tcp_keepcnt_values,        spl_tcp4, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 0xffffffff, keepcnt_rows)
SPL_ROWTEST(tcp_maxrt_values,          spl_tcp4, SPL_LVL_TCP, SPL_TCP_MAXRT, 0xffffffff, maxrt_rows)
SPL_ROWTEST(tcp_congestion_values,     spl_tcp4, SPL_LVL_TCP, SPL_TCP_CONGESTION, 0xffffffff, cong_rows)
SPL_ROWTEST(tcp6_keepalive_values,     spl_tcp6, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 0xffffffff, secs_rows)
SPL_ROWTEST(tcp6_keepcnt_values,       spl_tcp6, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 0xffffffff, keepcnt_rows)
SPL_ROWTEST(tcp6_keepintvl_values,     spl_tcp6, SPL_LVL_TCP, SPL_TCP_KEEPINTVL, 0xffffffff, secs_rows)

/* ---- options the stack does not implement or refuses to set ------------------------------------------- */
SPL_REFUSETEST(tcp_maxseg_refused_when_unconnected, spl_tcp4, SPL_LVL_TCP, SPL_TCP_MAXSEG, ENOOPT)
SPL_REFUSETEST(tcp_offload_preference_unsupported,  spl_tcp4, SPL_LVL_TCP, SPL_TCP_OFFLOAD_PREF, ENOOPT)
SPL_REFUSETEST(tcp_option_zero_unsupported,         spl_tcp4, SPL_LVL_TCP, 0, ENOOPT)
SPL_REFUSETEST(tcp_option_20_unsupported,           spl_tcp4, SPL_LVL_TCP, 20, ENOOPT)
SPL_REFUSETEST(tcp_option_21_unsupported,           spl_tcp4, SPL_LVL_TCP, 21, ENOOPT)
SPL_REFUSETEST(tcp_option_22_unsupported,           spl_tcp4, SPL_LVL_TCP, 22, ENOOPT)
SPL_REFUSETEST(tcp_option_1000_unsupported,         spl_tcp4, SPL_LVL_TCP, 1000, ENOOPT)
SPL_REFUSETEST(tcp6_maxseg_refused_when_unconnected, spl_tcp6, SPL_LVL_TCP, SPL_TCP_MAXSEG, ENOOPT)

TEST(tcp_atmark_readable_but_not_settable)
{
    SOCKET s; int v, e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_geti(s, SPL_LVL_TCP, SPL_TCP_ATMARK, &v, &e), 0);
    SEQ(v & 0xff, 0);
    v = 1;
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_TCP, SPL_TCP_ATMARK, (char *)&v, 4), ENOOPT);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_ATMARK) & 0xff, 0);
    spl_close(s);
}
TEST(tcp_icmp_error_info_without_error)
{
    /* No ICMP error has been recorded on a fresh socket: reading the info is an invalid request, setting it is unsupported. */
    SOCKET s; int v = 0, l = 64, e; char buf[64];
    if (!spl_up()) return;
    s = spl_tcp4();
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, SPL_TCP_ICMP_ERROR_INFO, buf, &l), EINV);
    v = 1;
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_TCP, SPL_TCP_ICMP_ERROR_INFO, (char *)&v, 4), ENOOPT);
    (void)e;
    spl_close(s);
}
TEST(tcp_maxseg_readable_once_connected)
{
    SOCKET c, a, l;
    int v, e, v2;
    if (!spl_up()) return;
    if (!spl_pair(0, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    SEQ(spl_geti(c, SPL_LVL_TCP, SPL_TCP_MAXSEG, &v, &e), 0);
    SEQ(spl_geti(a, SPL_LVL_TCP, SPL_TCP_MAXSEG, &v2, &e), 0);
    CHECKF(v >= 536 && v <= 65535, "client mss %d", v);
    EXPECT_EQ(v, v2);   /* both ends of a loopback connection see the same segment size */
    v = 1400;
    SPL_FAILS(spl_setsockopt(c, SPL_LVL_TCP, SPL_TCP_MAXSEG, (char *)&v, 4), ENOOPT);
    t_note("loopback MSS = %d", v2);
    spl_close(c); spl_close(a); spl_close(l);
}

/* ---- option length protocol --------------------------------------------------------------------------- */
TEST(tcp_set_length_boolean_options)
{
    SOCKET s;
    static const int opts[] = {TCP_NODELAY, SPL_TCP_EXPEDITED_1122, SPL_TCP_STDURG, SPL_TCP_NOURG, SPL_TCP_NOSYNRETRIES,
                               SPL_TCP_TIMESTAMPS, SPL_TCP_DELAY_FIN_ACK, SPL_TCP_FASTOPEN, SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR};
    int i;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) spl_len_protocol(s, SPL_LVL_TCP, opts[i], 1, 1, EFLT);
    spl_close(s);
}
TEST(tcp_set_length_dword_options)
{
    SOCKET s;
    static const struct { int opt, val; } t[] = {{SPL_TCP_KEEPALIVE, 30}, {SPL_TCP_MAXRT, 30}, {SPL_TCP_CONGESTION, 2},
                                                {SPL_TCP_MAXRTMS, 30}, {SPL_TCP_KEEPCNT, 30}, {SPL_TCP_KEEPINTVL, 30}};
    int i;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i < (int)(sizeof t / sizeof t[0]); i++) spl_len_protocol(s, SPL_LVL_TCP, t[i].opt, t[i].val, 4, EFLT);
    spl_close(s);
}
TEST(tcp_get_length_boolean_options)
{
    SOCKET s;
    static const int opts[] = {TCP_NODELAY, SPL_TCP_EXPEDITED_1122, SPL_TCP_STDURG, SPL_TCP_NOURG, SPL_TCP_ATMARK, SPL_TCP_NOSYNRETRIES,
                               SPL_TCP_TIMESTAMPS, SPL_TCP_DELAY_FIN_ACK, SPL_TCP_FASTOPEN, SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR};
    int i;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) spl_get_protocol(s, SPL_LVL_TCP, opts[i], 1, EFLT, 1, 1, 1);
    spl_close(s);
}
TEST(tcp_get_length_dword_options)
{
    SOCKET s;
    static const int opts[] = {SPL_TCP_KEEPALIVE, SPL_TCP_MAXRT, SPL_TCP_CONGESTION, SPL_TCP_MAXRTMS, SPL_TCP_KEEPCNT, SPL_TCP_KEEPINTVL};
    int i;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) spl_get_protocol(s, SPL_LVL_TCP, opts[i], 4, EFLT, 0, 4, 4);
    spl_close(s);
}
TEST(tcp_get_zero_length_buffer_is_fault_even_for_unsupported_option)
{
    /* The buffer-size check comes before the option lookup. */
    SOCKET s; int v = 0, l = 0;
    if (!spl_up()) return;
    s = spl_tcp4();
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, SPL_TCP_MAXSEG, (char *)&v, &l), EFLT);
    l = 4;
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, SPL_TCP_MAXSEG, (char *)&v, &l), ENOOPT);
    spl_close(s);
}
TEST(tcp_set_unsupported_option_ignores_length)
{
    SOCKET s; int v = 1, l;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (l = 0; l <= 8; l++) {
        int r;
        spl_WSASetLastError(0);
        r = spl_setsockopt(s, SPL_LVL_TCP, SPL_TCP_MAXSEG, (char *)&v, l);
        CHECKF(r == SOCKET_ERROR && spl_WSAGetLastError() == ENOOPT, "len %d rc %d err %d", l, r, spl_WSAGetLastError());
    }
    spl_close(s);
}
TEST(tcp_set_extra_bytes_ignored_for_dword_options)
{
    /* Only the first four bytes of a longer buffer are consumed. */
    SOCKET s; char buf[8]; int e, v;
    if (!spl_up()) return;
    s = spl_tcp4();
    memset(buf, 0xee, sizeof buf); *(int *)buf = 77;
    SEQ(spl_set(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, buf, 8, &e), 0);
    SEQ(spl_geti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, &v, &e), 0);
    SEQ(v, 77);
    spl_close(s);
}
TEST(tcp_get_into_oversized_buffer_reports_actual_length)
{
    SOCKET s; char buf[32]; int l = 32, e;
    if (!spl_up()) return;
    s = spl_tcp4();
    memset(buf, 0x55, sizeof buf);
    SEQ(spl_get(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, buf, &l, &e), 0);
    SEQ(l, 4);
    SEQ((unsigned char)buf[4], 0x55);   /* bytes past the value are untouched */
    l = 32;
    memset(buf, 0x55, sizeof buf);
    SEQ(spl_get(s, SPL_LVL_TCP, TCP_NODELAY, buf, &l, &e), 0);
    SEQ(l, 1);
    SEQ((unsigned char)buf[1], 0x55);
    spl_close(s);
}
TEST(tcp_boolean_get_writes_only_first_byte)
{
    SOCKET s; int v = 0x12345678, e, l = 4;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_get(s, SPL_LVL_TCP, TCP_NODELAY, &v, &l, &e), 0);
    SEQ(l, 1);
    SEQ(v & 0xff, 0);
    SEQ((unsigned)v & 0xffffff00u, 0x12345600u);
    spl_close(s);
}

/* ---- state dependence ---------------------------------------------------------------------------------- */
/* Options that cannot change once a connection exists. */
static const int frozen_opts[] = {SPL_TCP_TIMESTAMPS, SPL_TCP_CONGESTION, SPL_TCP_FASTOPEN};
static const int thaw_opts[] = {TCP_NODELAY, SPL_TCP_KEEPALIVE, SPL_TCP_MAXRT, SPL_TCP_STDURG, SPL_TCP_NOURG,
                                SPL_TCP_NOSYNRETRIES, SPL_TCP_DELAY_FIN_ACK, SPL_TCP_KEEPCNT, SPL_TCP_KEEPINTVL,
                                SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR};
static void frozen_check(SOCKET s, const char *who)
{
    int i, e;
    for (i = 0; i < (int)(sizeof frozen_opts / sizeof frozen_opts[0]); i++) {
        int v = 1, r = spl_set(s, SPL_LVL_TCP, frozen_opts[i], &v, 4, &e);
        CHECKF(r == SOCKET_ERROR && e == EINV, "%s opt %d: rc %d err %d", who, frozen_opts[i], r, e);
    }
    for (i = 0; i < (int)(sizeof thaw_opts / sizeof thaw_opts[0]); i++) {
        int v = 1, r = spl_set(s, SPL_LVL_TCP, thaw_opts[i], &v, 4, &e);
        CHECKF(r == 0, "%s opt %d: rc %d err %d", who, thaw_opts[i], r, e);
    }
}
TEST(tcp_connected_client_freezes_timestamps_congestion_fastopen)
{
    SOCKET c, a, l;
    if (!spl_up()) return;
    if (!spl_pair(0, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    frozen_check(c, "client");
    spl_close(c); spl_close(a); spl_close(l);
}
TEST(tcp_accepted_socket_freezes_timestamps_congestion_fastopen)
{
    SOCKET c, a, l;
    if (!spl_up()) return;
    if (!spl_pair(0, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    frozen_check(a, "accepted");
    spl_close(c); spl_close(a); spl_close(l);
}
TEST(tcp6_connected_client_freezes_timestamps_congestion_fastopen)
{
    SOCKET c, a, l;
    if (!spl_up() || !spl_have6()) return;
    if (!spl_pair(1, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    frozen_check(c, "client6");
    spl_close(c); spl_close(a); spl_close(l);
}
TEST(tcp_bound_socket_still_accepts_every_option)
{
    SOCKET s; int i, e; u_short p = 0;
    if (!spl_up()) return;
    s = spl_tcp4(); SEQ(spl_bind4(s, &p), 0);
    for (i = 0; i < (int)(sizeof frozen_opts / sizeof frozen_opts[0]); i++) { int v = 1; SEQ(spl_set(s, SPL_LVL_TCP, frozen_opts[i], &v, 4, &e), 0); }
    for (i = 0; i < (int)(sizeof thaw_opts / sizeof thaw_opts[0]); i++) { int v = 1; SEQ(spl_set(s, SPL_LVL_TCP, thaw_opts[i], &v, 4, &e), 0); }
    spl_close(s);
}
TEST(tcp_listening_socket_accepts_every_option)
{
    SOCKET s; int i, e; u_short p = 0;
    if (!spl_up()) return;
    s = spl_tcp4(); SEQ(spl_bind4(s, &p), 0); SEQ(spl_listen(s, 2), 0);
    for (i = 0; i < (int)(sizeof frozen_opts / sizeof frozen_opts[0]); i++) { int v = 1; SEQ(spl_set(s, SPL_LVL_TCP, frozen_opts[i], &v, 4, &e), 0); }
    for (i = 0; i < (int)(sizeof thaw_opts / sizeof thaw_opts[0]); i++) { int v = 1; SEQ(spl_set(s, SPL_LVL_TCP, thaw_opts[i], &v, 4, &e), 0); }
    spl_close(s);
}
TEST(tcp_options_survive_shutdown)
{
    SOCKET c, a, l; int v, e;
    if (!spl_up()) return;
    if (!spl_pair(0, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    SEQ(spl_seti(c, SPL_LVL_TCP, TCP_NODELAY, 1, &e), 0);
    SEQ(spl_seti(c, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 4, &e), 0);
    SEQ(spl_shutdown(c, SD_SEND), 0);
    SEQ(spl_geti(c, SPL_LVL_TCP, TCP_NODELAY, &v, &e), 0); SEQ(v & 0xff, 1);
    SEQ(spl_geti(c, SPL_LVL_TCP, SPL_TCP_KEEPCNT, &v, &e), 0); SEQ(v, 4);
    SEQ(spl_seti(c, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 6, &e), 0);
    SEQ(spl_rb(c, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 6);
    SEQ(spl_shutdown(c, SD_BOTH), 0);
    SEQ(spl_seti(c, SPL_LVL_TCP, TCP_NODELAY, 0, &e), 0);
    SEQ(spl_rb(c, SPL_LVL_TCP, TCP_NODELAY) & 0xff, 0);
    spl_close(c); spl_close(a); spl_close(l);
}
TEST(tcp_pre_connect_options_carry_into_the_connection)
{
    SOCKET ls, cs; u_short p = 0; struct sockaddr_in d; SOCKET a; int e;
    if (!spl_up()) return;
    ls = spl_tcp4(); cs = spl_tcp4();
    spl_bind4(ls, &p); spl_listen(ls, 2);
    SEQ(spl_seti(cs, SPL_LVL_TCP, TCP_NODELAY, 1, &e), 0);
    SEQ(spl_seti(cs, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 1234, &e), 0);
    spl_loop4(&d); d.sin_port = p;
    SEQ(spl_connect(cs, (struct sockaddr *)&d, sizeof d), 0);
    a = spl_accept(ls, NULL, NULL);
    SEQ(spl_rb(cs, SPL_LVL_TCP, TCP_NODELAY) & 0xff, 1);
    SEQ(spl_rb(cs, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 1234);
    spl_close(a); spl_close(cs); spl_close(ls);
}

/* ---- wrong socket types / levels ------------------------------------------------------------------------ */
TEST(tcp_level_options_refused_on_udp_socket)
{
    SOCKET s; int i, e;
    static const int opts[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 20, 100};
    if (!spl_up()) return;
    s = spl_udp4();
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) {
        int v = 1, l = 4;
        SEQ(spl_get(s, SPL_LVL_TCP, opts[i], &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
        SEQ(spl_set(s, SPL_LVL_TCP, opts[i], &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    }
    spl_close(s);
}
TEST(tcp_level_options_refused_on_udp6_socket)
{
    SOCKET s; int i, e;
    static const int opts[] = {1, 3, 4, 15, 16, 17, 99};
    if (!spl_up()) return;
    s = spl_udp6();
    if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; }
    for (i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) {
        int v = 1, l = 4;
        SEQ(spl_get(s, SPL_LVL_TCP, opts[i], &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
        SEQ(spl_set(s, SPL_LVL_TCP, opts[i], &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    }
    spl_close(s);
}
TEST(tcp_level_options_refused_on_udp_short_buffers)
{
    /* A get with a zero-sized buffer is a fault before the level is looked at; a set is judged by level first. */
    SOCKET s; int v = 1, l = 0, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_get(s, SPL_LVL_TCP, TCP_NODELAY, &v, &l, &e), SOCKET_ERROR); SEQ(e, EFLT);
    l = 1;
    SEQ(spl_get(s, SPL_LVL_TCP, TCP_NODELAY, &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_set(s, SPL_LVL_TCP, TCP_NODELAY, &v, 0, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_set(s, SPL_LVL_TCP, TCP_NODELAY, &v, 1, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}
TEST(udp_level_options_refused_on_tcp_socket)
{
    SOCKET s; int i, e;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i <= 5; i++) {
        int v = 1, l = 4;
        SEQ(spl_get(s, SPL_LVL_UDP, i, &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
        SEQ(spl_set(s, SPL_LVL_UDP, i, &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    }
    spl_close(s);
}
TEST(tcp_unknown_protocol_levels_are_invalid)
{
    SOCKET s; int i, e;
    static const int lvls[] = {1, 2, 3, 4, 5, 7, 50, 58, 59, 255, 0x1234, -1};
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i < (int)(sizeof lvls / sizeof lvls[0]); i++) {
        int v = 1, l = 4;
        SEQ(spl_get(s, lvls[i], 1, &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
        SEQ(spl_set(s, lvls[i], 1, &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    }
    spl_close(s);
}
TEST(udp_unknown_protocol_levels_are_invalid)
{
    SOCKET s; int i, e;
    static const int lvls[] = {1, 2, 3, 4, 5, 7, 50, 58, 255, 0x1234, -1};
    if (!spl_up()) return;
    s = spl_udp4();
    for (i = 0; i < (int)(sizeof lvls / sizeof lvls[0]); i++) {
        int v = 1, l = 4;
        SEQ(spl_get(s, lvls[i], 1, &v, &l, &e), SOCKET_ERROR); SEQ(e, EINV);
        SEQ(spl_set(s, lvls[i], 1, &v, 4, &e), SOCKET_ERROR); SEQ(e, EINV);
    }
    spl_close(s);
}
TEST(tcp_options_on_closed_socket_are_notsock)
{
    SOCKET s; int v = 1, l = 4;
    if (!spl_up()) return;
    s = spl_tcp4(); spl_closesocket(s);
    SPL_FAILS(spl_getsockopt(s, SPL_LVL_TCP, TCP_NODELAY, (char *)&v, &l), WSAENOTSOCK);
    SPL_FAILS(spl_setsockopt(s, SPL_LVL_TCP, TCP_NODELAY, (char *)&v, 4), WSAENOTSOCK);
}

/* ---- interplay between related options ------------------------------------------------------------------ */
TEST(tcp_keepalive_and_keepidle_are_one_option)
{
    /* TCP_KEEPIDLE shares its number with TCP_KEEPALIVE. */
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPIDLE, 90, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 90);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 91, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPIDLE), 91);
    spl_close(s);
}
TEST(tcp_setting_keepalive_options_does_not_enable_so_keepalive)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_rb(s, SOL_SOCKET, SO_KEEPALIVE) & 0xff, 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 60, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 3, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPINTVL, 5, &e), 0);
    SEQ(spl_rb(s, SOL_SOCKET, SO_KEEPALIVE) & 0xff, 0);
    spl_close(s);
}
TEST(tcp_options_are_independent_per_socket)
{
    SOCKET a, b; int e;
    if (!spl_up()) return;
    a = spl_tcp4(); b = spl_tcp4();
    SEQ(spl_seti(a, SPL_LVL_TCP, TCP_NODELAY, 1, &e), 0);
    SEQ(spl_seti(a, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 2, &e), 0);
    SEQ(spl_rb(b, SPL_LVL_TCP, TCP_NODELAY) & 0xff, 0);
    SEQ(spl_rb(b, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 10);
    spl_close(a); spl_close(b);
}
TEST(tcp_refused_set_leaves_previous_value)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 8, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT, 300, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 8);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 500, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 0, &e), SOCKET_ERROR); SEQ(e, EINV);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 500);
    spl_close(s);
}

/* ---- TCP_MAXRT and TCP_MAXRTMS are two views of one timer ---------------------------------------------------- */
static const struct spl_row maxrtms_rows[] = {
    {30, 0, 30}, {20, 0, 20}, {19, EINV, 0}, {10, EINV, 0}, {1, EINV, 0}, {0, EINV, 0}, {255, 0, 255}, {256, 0, 256},
    {1999, 0, 1999}, {65535, 0, 65535}, {0x7fffffff, 0, 0x7fffffff}, {(int)0x80000000, 0, (int)0x80000000}, {-1, 0, -1}, {40, 0, 40},
};
SPL_ROWTEST(tcp_maxrtms_values, spl_tcp4, SPL_LVL_TCP, SPL_TCP_MAXRTMS, 0xffffffff, maxrtms_rows)
TEST(tcp_maxrt_is_seconds_view_of_maxrtms)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRT, 5, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS), 5000);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS, 7000, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRT), 7);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS, 1999, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRT), 1);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS, 20, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRT), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRT, 0, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS), 0);
    spl_close(s);
}
TEST(tcp_maxrt_minus_one_means_unlimited_in_both_units)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS, -1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRT), -1);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS, 100, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRT, -1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS), -1);
    spl_close(s);
}
TEST(tcp_maxrt_seconds_to_milliseconds_wraps_at_32_bits)
{
    /* The timer is kept in milliseconds in 32 bits: seconds * 1000 wraps. */
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRT, 4294967, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS), -296);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_MAXRT, 4294968, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRTMS), 704);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_MAXRT), 0);
    spl_close(s);
}

/* ---- remaining TCP-level facts -------------------------------------------------------------------------------- */
TEST(tcp_urgent_data_options_do_not_exclude_each_other)
{
    SOCKET s; int e;
    static const int opts[] = {SPL_TCP_EXPEDITED_1122, SPL_TCP_STDURG, SPL_TCP_NOURG};
    int i, j;
    if (!spl_up()) return;
    s = spl_tcp4();
    for (i = 0; i < 3; i++) for (j = 0; j < 3; j++) {
        SEQ(spl_seti(s, SPL_LVL_TCP, opts[i], 1, &e), 0);
        SEQ(spl_seti(s, SPL_LVL_TCP, opts[j], 1, &e), 0);
        SEQ(spl_rb(s, SPL_LVL_TCP, opts[i]) & 0xff, 1);
        SEQ(spl_rb(s, SPL_LVL_TCP, opts[j]) & 0xff, 1);
        SEQ(spl_seti(s, SPL_LVL_TCP, opts[i], 0, &e), 0);
        SEQ(spl_seti(s, SPL_LVL_TCP, opts[j], 0, &e), 0);
    }
    SEQ(spl_seti(s, SOL_SOCKET, SO_OOBINLINE, 1, &e), 0);
    for (i = 0; i < 3; i++) SEQ(spl_seti(s, SPL_LVL_TCP, opts[i], 1, &e), 0);
    spl_close(s);
}
TEST(tcp_options_accepted_again_after_failed_connect)
{
    /* A refused connection returns the socket to its unconnected state, so the connect-time-only options work again. */
    SOCKET l, s; u_short p = 0; struct sockaddr_in d; int e, r;
    if (!spl_up()) return;
    l = spl_tcp4(); spl_bind4(l, &p); spl_listen(l, 1); spl_close(l);   /* the port is now closed */
    s = spl_tcp4(); spl_loop4(&d); d.sin_port = p;
    r = spl_connect(s, (struct sockaddr *)&d, sizeof d);
    if (r == 0) { t_skip("something listens on the freed port"); spl_close(s); return; }
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_TIMESTAMPS, 1, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_FASTOPEN, 1, &e), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_CONGESTION, 1, &e), 0);
    spl_close(s);
}
TEST(tcp_fail_connect_on_icmp_error_connected_get_returns_nothing)
{
    /* Once connected, reading this option still succeeds but delivers no value. */
    SOCKET c, a, l; unsigned char b[8]; int len = 4, e, r;
    if (!spl_up()) return;
    if (!spl_pair(0, &c, &a, &l)) { t_skip("loopback pair failed"); return; }
    memset(b, 0x5a, sizeof b);
    r = spl_get(c, SPL_LVL_TCP, SPL_TCP_FAIL_CONNECT_ON_ICMP_ERROR, b, &len, &e);
    SEQ(r, 0);
    t_note("connected TCP_FAIL_CONNECT_ON_ICMP_ERROR get: optlen %d, first byte %02x", len, b[0]);
    spl_close(c); spl_close(a); spl_close(l);
}

/* ---- the keep-alive ioctl against the option set -------------------------------------------------------------- */
static int ka_ioctl(SOCKET s, int on, unsigned time_ms, unsigned intvl_ms)
{
    struct tcp_keepalive k; DWORD ret = 0;
    k.onoff = on; k.keepalivetime = time_ms; k.keepaliveinterval = intvl_ms;
    return spl_WSAIoctl(s, SIO_KEEPALIVE_VALS, &k, sizeof k, NULL, 0, &ret, NULL, NULL);
}
TEST(tcp_keepalive_vals_ioctl_sets_idle_and_interval_and_enables)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(ka_ioctl(s, 1, 30000, 5000), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 30);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPINTVL), 5);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPCNT), 10);          /* the probe count is not part of the ioctl */
    SEQ(spl_rb(s, SOL_SOCKET, SO_KEEPALIVE) & 0xff, 1);
    spl_close(s);
}
TEST(tcp_keepalive_vals_ioctl_off_disables_and_keeps_timers)
{
    SOCKET s;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(ka_ioctl(s, 1, 30000, 5000), 0);
    SEQ(ka_ioctl(s, 0, 7000, 2000), 0);
    SEQ(spl_rb(s, SOL_SOCKET, SO_KEEPALIVE) & 0xff, 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 30);        /* timers of an "off" request are ignored */
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPINTVL), 5);
    spl_close(s);
}
TEST(tcp_keepalive_vals_ioctl_zero_timers_read_back_zero)
{
    /* The ioctl accepts zero timers although the options themselves refuse zero. */
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(ka_ioctl(s, 1, 0, 0), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPINTVL), 0);
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 0, &e), SOCKET_ERROR); SEQ(e, EINV);
    spl_close(s);
}
TEST(tcp_keepalive_option_leaves_so_keepalive_alone)
{
    SOCKET s; int e;
    if (!spl_up()) return;
    s = spl_tcp4();
    SEQ(spl_seti(s, SOL_SOCKET, SO_KEEPALIVE, 1, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 7200);      /* turning keep-alive on does not touch the timers */
    SEQ(spl_seti(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE, 600, &e), 0);
    SEQ(spl_rb(s, SOL_SOCKET, SO_KEEPALIVE) & 0xff, 1);
    SEQ(spl_seti(s, SOL_SOCKET, SO_KEEPALIVE, 0, &e), 0);
    SEQ(spl_rb(s, SPL_LVL_TCP, SPL_TCP_KEEPALIVE), 600);
    spl_close(s);
}
TEST(udp_socket_has_no_so_keepalive)
{
    SOCKET s; int v = 0, l = 4, e;
    if (!spl_up()) return;
    s = spl_udp4();
    SEQ(spl_get(s, SOL_SOCKET, SO_KEEPALIVE, &v, &l, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    v = 1;
    SEQ(spl_set(s, SOL_SOCKET, SO_KEEPALIVE, &v, 4, &e), SOCKET_ERROR); SEQ(e, ENOOPT);
    spl_close(s);
}
