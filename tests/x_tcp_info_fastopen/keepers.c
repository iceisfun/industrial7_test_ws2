/* Timer, counter and boolean TCP options crossed with socket state. For every TCP state, each option row says
 * what a set of that value returns and what the option reads back afterwards (a refused set leaves the earlier
 * value). KEEPALIVE/KEEPINTVL are seconds (zero refused, large values clamp to 4294967), KEEPCNT is a byte-sized
 * count (zero accepted, 256 and above refused), MAXRT is seconds, MAXRTMS is milliseconds (zero and one refused),
 * and the boolean options look at the low byte. */
#include "xt.h"

static const int tcp_kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN, XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED};
#define NTCP ((int)(sizeof tcp_kinds / sizeof tcp_kinds[0]))
#define SAME (-2LL)
typedef struct { int val; int err; long long rb; } row;

static void run_option(int opt, const char *oname, const row *rows, int nrows, int first_state, int last_state)
{
    int k, i;
    for (k = first_state; k <= last_state; k++) for (i = 0; i < nrows; i++) {
        xt_st st; long long before = -1, v = -1; int e;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        xt_geti(st.s, IPPROTO_TCP, opt, &before);
        e = xt_seti(st.s, IPPROTO_TCP, opt, rows[i].val);
        CHECKF(e == rows[i].err, "%s %s set 0x%x: err %d want %d", xt_state_name[tcp_kinds[k]], oname, rows[i].val, e, rows[i].err);
        EQ(xt_geti(st.s, IPPROTO_TCP, opt, &v), 0);
        if (rows[i].rb == SAME) { CHECKF(v == before, "%s %s set 0x%x: read %lld, was %lld", xt_state_name[tcp_kinds[k]], oname, rows[i].val, v, before); }
        else { CHECKF(v == rows[i].rb, "%s %s set 0x%x: read %lld want %lld", xt_state_name[tcp_kinds[k]], oname, rows[i].val, v, rows[i].rb); }
        xt_rmstate(&st);
    }
}
static const row r_keepalive[] = {{0, WSAEINVAL, SAME}, {1, 0, 1}, {255, 0, 255}, {256, 0, 256}, {-1, 0, 4294967}, {7200, 0, 7200}, {4294967, 0, 4294967}};
static const row r_keepcnt[]   = {{0, 0, 0}, {1, 0, 1}, {255, 0, 255}, {256, WSAEINVAL, SAME}, {-1, WSAEINVAL, SAME}, {10, 0, 10}, {1000, WSAEINVAL, SAME}};
static const row r_keepintvl[] = {{0, WSAEINVAL, SAME}, {1, 0, 1}, {255, 0, 255}, {256, 0, 256}, {-1, 0, 4294967}, {3600, 0, 3600}};
static const row r_maxrt[]     = {{0, 0, 0}, {1, 0, 1}, {255, 0, 255}, {256, 0, 256}, {-1, 0, 4294967295LL}, {60, 0, 60}};
static const row r_maxrtms[]   = {{0, WSAEINVAL, SAME}, {1, WSAEINVAL, SAME}, {255, 0, 255}, {256, 0, 256}, {-1, 0, 4294967295LL}, {30000, 0, 30000}};
static const row r_bool[]      = {{0, 0, 0}, {1, 0, 1}, {255, 0, 1}, {256, 0, 0}, {-1, 0, 1}, {0x101, 0, 1}};

TEST(keepers_keepalive_idle_seconds_in_every_tcp_state) { NEED(); run_option(XT_TCP_KEEPALIVE, "KEEPALIVE", r_keepalive, 7, 0, NTCP - 1); }
TEST(keepers_keepcnt_in_every_tcp_state) { NEED(); run_option(XT_TCP_KEEPCNT, "KEEPCNT", r_keepcnt, 7, 0, NTCP - 1); }
TEST(keepers_keepintvl_seconds_in_every_tcp_state) { NEED(); run_option(XT_TCP_KEEPINTVL, "KEEPINTVL", r_keepintvl, 6, 0, NTCP - 1); }
TEST(keepers_maxrt_seconds_in_every_tcp_state) { NEED(); run_option(XT_TCP_MAXRT, "MAXRT", r_maxrt, 6, 0, NTCP - 1); }
TEST(keepers_maxrtms_milliseconds_in_every_tcp_state) { NEED(); run_option(XT_TCP_MAXRTMS, "MAXRTMS", r_maxrtms, 6, 0, NTCP - 1); }
TEST(keepers_nodelay_boolean_in_every_tcp_state) { NEED(); run_option(XT_TCP_NODELAY, "NODELAY", r_bool, 6, 0, NTCP - 1); }
TEST(keepers_delay_fin_ack_boolean_in_every_tcp_state) { NEED(); run_option(XT_TCP_DELAY_FIN_ACK, "DELAY_FIN_ACK", r_bool, 6, 0, NTCP - 1); }
TEST(keepers_nosynretries_boolean_in_every_tcp_state) { NEED(); run_option(XT_TCP_NOSYNRETRIES, "NOSYNRETRIES", r_bool, 6, 0, NTCP - 1); }
TEST(keepers_timestamps_boolean_before_connect_only)
{
    static const row refused[] = {{0, WSAEINVAL, SAME}, {1, WSAEINVAL, SAME}, {255, WSAEINVAL, SAME}, {-1, WSAEINVAL, SAME}};
    NEED();
    run_option(XT_TCP_TIMESTAMPS, "TIMESTAMPS", r_bool, 6, 0, 2);
    run_option(XT_TCP_TIMESTAMPS, "TIMESTAMPS", refused, 4, 3, NTCP - 1);
}
TEST(keepers_congestion_algorithm_before_connect_only)
{
    static const row open[] = {{0, 0, 0}, {1, 0, 1}, {2, 0, 2}, {3, 0, 3}, {4, 0, 4}, {5, 0, 5}, {255, WSAEINVAL, SAME}, {256, WSAEINVAL, SAME}, {-1, WSAEINVAL, SAME}};
    static const row frozen[] = {{0, WSAEINVAL, SAME}, {1, WSAEINVAL, SAME}, {5, WSAEINVAL, SAME}, {-1, WSAEINVAL, SAME}};
    NEED();
    run_option(XT_TCP_CONGESTION, "CONGESTION", open, 9, 0, 2);
    run_option(XT_TCP_CONGESTION, "CONGESTION", frozen, 4, 3, NTCP - 1);
}
TEST(keepers_connected_sockets_report_congestion_class_5)
{
    int k;
    NEED();
    for (k = 3; k < NTCP; k++) {
        xt_st st; long long v = -1;
        if (!xt_mkstate(tcp_kinds[k], &st)) { t_skip("setup %s", xt_state_name[tcp_kinds[k]]); return; }
        CHECKF(xt_geti(st.s, IPPROTO_TCP, XT_TCP_CONGESTION, &v) == 0 && v == 5, "%s: %lld", xt_state_name[tcp_kinds[k]], v);
        xt_rmstate(&st);
    }
}
TEST(keepers_fail_connect_on_icmp_error_is_stored_only_before_listen_and_connect)
{
    static const row open[] = {{0, 0, 0}, {1, 0, 1}, {255, 0, 1}, {256, 0, 0}, {-1, 0, 1}};
    static const row ignored[] = {{0, 0, 0}, {1, 0, 0}, {255, 0, 0}, {256, 0, 0}, {-1, 0, 0}};
    NEED();
    run_option(XT_TCP_FAIL_CONNECT, "FAIL_CONNECT_ON_ICMP_ERROR", open, 5, 0, 1);
    run_option(XT_TCP_FAIL_CONNECT, "FAIL_CONNECT_ON_ICMP_ERROR", ignored, 5, 2, NTCP - 1);
}
TEST(keepers_udp_socket_refuses_every_tcp_level_option_both_ways)
{
    static const int opts[] = {XT_TCP_NODELAY, XT_TCP_KEEPALIVE, XT_TCP_KEEPCNT, XT_TCP_KEEPINTVL, XT_TCP_MAXRT, XT_TCP_MAXRTMS,
        XT_TCP_FAIL_CONNECT, XT_TCP_TIMESTAMPS, XT_TCP_CONGESTION, XT_TCP_DELAY_FIN_ACK, XT_TCP_NOSYNRETRIES, XT_TCP_FASTOPEN};
    unsigned i; SOCKET s;
    NEED();
    s = xt_udp();
    for (i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        long long v;
        CHECKF(xt_seti(s, IPPROTO_TCP, opts[i], 1) == WSAEINVAL, "set option %d", opts[i]);
        CHECKF(xt_geti(s, IPPROTO_TCP, opts[i], &v) == WSAEINVAL, "get option %d", opts[i]);
    }
    xt_close(s);
}
TEST(keepers_sio_keepalive_vals_does_not_move_keepcnt)
{
    SOCKET c, a, l; struct tcp_keepalive k; DWORD ret; long long v;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_KEEPCNT, 7), 0);
    k.onoff = 1; k.keepalivetime = 20000; k.keepaliveinterval = 3000;
    { xt_res r = xt_io(c, SIO_KEEPALIVE_VALS, &k, sizeof k, NULL, 0); EQ(r.rc, 0); (void)ret; }
    EQ(xt_geti(c, IPPROTO_TCP, XT_TCP_KEEPCNT, &v), 0); EQ(v, 7);
    EQ(xt_geti(c, IPPROTO_TCP, XT_TCP_KEEPALIVE, &v), 0); EQ(v, 20);
    EQ(xt_geti(c, IPPROTO_TCP, XT_TCP_KEEPINTVL, &v), 0); EQ(v, 3);
    xt_close(c); xt_close(a); xt_close(l);
}
