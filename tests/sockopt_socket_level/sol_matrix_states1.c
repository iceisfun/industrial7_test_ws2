/* sockopt_socket_level: outcome of every SOL_SOCKET option on sockets in each connection state
 * (bound, listening, connected client, accepted, shut down, UDP bound, UDP connected): a read into a 4-byte buffer
 * and writes of 1 and 0. Expected outcomes come from observation of genuine Windows 10 22H2. */
#include "sol_snap.h"

static const struct snap_row s_DEBUG_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DEBUG_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DEBUG_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DEBUG_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DEBUG_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DEBUG_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DEBUG_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_debug)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_DEBUG, s_DEBUG_tbound, NELEM(s_DEBUG_tbound));
    snap_run(st_name[1], mk_state, 1, SO_DEBUG, s_DEBUG_tlisten, NELEM(s_DEBUG_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_DEBUG, s_DEBUG_tclient, NELEM(s_DEBUG_tclient));
    snap_run(st_name[3], mk_state, 3, SO_DEBUG, s_DEBUG_taccepted, NELEM(s_DEBUG_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_DEBUG, s_DEBUG_tshut, NELEM(s_DEBUG_tshut));
    snap_run(st_name[5], mk_state, 5, SO_DEBUG, s_DEBUG_ubound, NELEM(s_DEBUG_ubound));
    snap_run(st_name[6], mk_state, 6, SO_DEBUG, s_DEBUG_uclient, NELEM(s_DEBUG_uclient));
    ws_down();
}

static const struct snap_row s_ACCEPTCONN_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ACCEPTCONN_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_ACCEPTCONN_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ACCEPTCONN_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ACCEPTCONN_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ACCEPTCONN_ubound[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_ACCEPTCONN_uclient[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_acceptconn)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_ACCEPTCONN, s_ACCEPTCONN_tbound, NELEM(s_ACCEPTCONN_tbound));
    snap_run(st_name[1], mk_state, 1, SO_ACCEPTCONN, s_ACCEPTCONN_tlisten, NELEM(s_ACCEPTCONN_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_ACCEPTCONN, s_ACCEPTCONN_tclient, NELEM(s_ACCEPTCONN_tclient));
    snap_run(st_name[3], mk_state, 3, SO_ACCEPTCONN, s_ACCEPTCONN_taccepted, NELEM(s_ACCEPTCONN_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_ACCEPTCONN, s_ACCEPTCONN_tshut, NELEM(s_ACCEPTCONN_tshut));
    snap_run(st_name[5], mk_state, 5, SO_ACCEPTCONN, s_ACCEPTCONN_ubound, NELEM(s_ACCEPTCONN_ubound));
    snap_run(st_name[6], mk_state, 6, SO_ACCEPTCONN, s_ACCEPTCONN_uclient, NELEM(s_ACCEPTCONN_uclient));
    ws_down();
}

static const struct snap_row s_REUSEADDR_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_REUSEADDR_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_REUSEADDR_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_REUSEADDR_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_REUSEADDR_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_REUSEADDR_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_REUSEADDR_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_reuseaddr)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_REUSEADDR, s_REUSEADDR_tbound, NELEM(s_REUSEADDR_tbound));
    snap_run(st_name[1], mk_state, 1, SO_REUSEADDR, s_REUSEADDR_tlisten, NELEM(s_REUSEADDR_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_REUSEADDR, s_REUSEADDR_tclient, NELEM(s_REUSEADDR_tclient));
    snap_run(st_name[3], mk_state, 3, SO_REUSEADDR, s_REUSEADDR_taccepted, NELEM(s_REUSEADDR_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_REUSEADDR, s_REUSEADDR_tshut, NELEM(s_REUSEADDR_tshut));
    snap_run(st_name[5], mk_state, 5, SO_REUSEADDR, s_REUSEADDR_ubound, NELEM(s_REUSEADDR_ubound));
    snap_run(st_name[6], mk_state, 6, SO_REUSEADDR, s_REUSEADDR_uclient, NELEM(s_REUSEADDR_uclient));
    ws_down();
}

static const struct snap_row s_KEEPALIVE_tbound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_KEEPALIVE_tlisten[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_KEEPALIVE_tclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_KEEPALIVE_taccepted[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_KEEPALIVE_tshut[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_KEEPALIVE_ubound[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_KEEPALIVE_uclient[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_keepalive)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_KEEPALIVE, s_KEEPALIVE_tbound, NELEM(s_KEEPALIVE_tbound));
    snap_run(st_name[1], mk_state, 1, SO_KEEPALIVE, s_KEEPALIVE_tlisten, NELEM(s_KEEPALIVE_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_KEEPALIVE, s_KEEPALIVE_tclient, NELEM(s_KEEPALIVE_tclient));
    snap_run(st_name[3], mk_state, 3, SO_KEEPALIVE, s_KEEPALIVE_taccepted, NELEM(s_KEEPALIVE_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_KEEPALIVE, s_KEEPALIVE_tshut, NELEM(s_KEEPALIVE_tshut));
    snap_run(st_name[5], mk_state, 5, SO_KEEPALIVE, s_KEEPALIVE_ubound, NELEM(s_KEEPALIVE_ubound));
    snap_run(st_name[6], mk_state, 6, SO_KEEPALIVE, s_KEEPALIVE_uclient, NELEM(s_KEEPALIVE_uclient));
    ws_down();
}

static const struct snap_row s_DONTROUTE_tbound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_DONTROUTE_tlisten[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_DONTROUTE_tclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_DONTROUTE_taccepted[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_DONTROUTE_tshut[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_DONTROUTE_ubound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_DONTROUTE_uclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
TEST(sol_state_dontroute)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_DONTROUTE, s_DONTROUTE_tbound, NELEM(s_DONTROUTE_tbound));
    snap_run(st_name[1], mk_state, 1, SO_DONTROUTE, s_DONTROUTE_tlisten, NELEM(s_DONTROUTE_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_DONTROUTE, s_DONTROUTE_tclient, NELEM(s_DONTROUTE_tclient));
    snap_run(st_name[3], mk_state, 3, SO_DONTROUTE, s_DONTROUTE_taccepted, NELEM(s_DONTROUTE_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_DONTROUTE, s_DONTROUTE_tshut, NELEM(s_DONTROUTE_tshut));
    snap_run(st_name[5], mk_state, 5, SO_DONTROUTE, s_DONTROUTE_ubound, NELEM(s_DONTROUTE_ubound));
    snap_run(st_name[6], mk_state, 6, SO_DONTROUTE, s_DONTROUTE_uclient, NELEM(s_DONTROUTE_uclient));
    ws_down();
}

static const struct snap_row s_BROADCAST_tbound[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BROADCAST_tlisten[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BROADCAST_tclient[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BROADCAST_taccepted[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BROADCAST_tshut[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BROADCAST_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_BROADCAST_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_broadcast)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_BROADCAST, s_BROADCAST_tbound, NELEM(s_BROADCAST_tbound));
    snap_run(st_name[1], mk_state, 1, SO_BROADCAST, s_BROADCAST_tlisten, NELEM(s_BROADCAST_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_BROADCAST, s_BROADCAST_tclient, NELEM(s_BROADCAST_tclient));
    snap_run(st_name[3], mk_state, 3, SO_BROADCAST, s_BROADCAST_taccepted, NELEM(s_BROADCAST_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_BROADCAST, s_BROADCAST_tshut, NELEM(s_BROADCAST_tshut));
    snap_run(st_name[5], mk_state, 5, SO_BROADCAST, s_BROADCAST_ubound, NELEM(s_BROADCAST_ubound));
    snap_run(st_name[6], mk_state, 6, SO_BROADCAST, s_BROADCAST_uclient, NELEM(s_BROADCAST_uclient));
    ws_down();
}

static const struct snap_row s_USELOOPBACK_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_USELOOPBACK_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_USELOOPBACK_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_USELOOPBACK_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_USELOOPBACK_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_USELOOPBACK_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_USELOOPBACK_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_useloopback)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_USELOOPBACK, s_USELOOPBACK_tbound, NELEM(s_USELOOPBACK_tbound));
    snap_run(st_name[1], mk_state, 1, SO_USELOOPBACK, s_USELOOPBACK_tlisten, NELEM(s_USELOOPBACK_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_USELOOPBACK, s_USELOOPBACK_tclient, NELEM(s_USELOOPBACK_tclient));
    snap_run(st_name[3], mk_state, 3, SO_USELOOPBACK, s_USELOOPBACK_taccepted, NELEM(s_USELOOPBACK_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_USELOOPBACK, s_USELOOPBACK_tshut, NELEM(s_USELOOPBACK_tshut));
    snap_run(st_name[5], mk_state, 5, SO_USELOOPBACK, s_USELOOPBACK_ubound, NELEM(s_USELOOPBACK_ubound));
    snap_run(st_name[6], mk_state, 6, SO_USELOOPBACK, s_USELOOPBACK_uclient, NELEM(s_USELOOPBACK_uclient));
    ws_down();
}

static const struct snap_row s_LINGER_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_LINGER_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_LINGER_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_LINGER_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_LINGER_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_LINGER_ubound[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_LINGER_uclient[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_linger)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_LINGER, s_LINGER_tbound, NELEM(s_LINGER_tbound));
    snap_run(st_name[1], mk_state, 1, SO_LINGER, s_LINGER_tlisten, NELEM(s_LINGER_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_LINGER, s_LINGER_tclient, NELEM(s_LINGER_tclient));
    snap_run(st_name[3], mk_state, 3, SO_LINGER, s_LINGER_taccepted, NELEM(s_LINGER_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_LINGER, s_LINGER_tshut, NELEM(s_LINGER_tshut));
    snap_run(st_name[5], mk_state, 5, SO_LINGER, s_LINGER_ubound, NELEM(s_LINGER_ubound));
    snap_run(st_name[6], mk_state, 6, SO_LINGER, s_LINGER_uclient, NELEM(s_LINGER_uclient));
    ws_down();
}

static const struct snap_row s_OOBINLINE_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_OOBINLINE_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_OOBINLINE_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_OOBINLINE_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_OOBINLINE_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_OOBINLINE_ubound[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_OOBINLINE_uclient[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_oobinline)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_OOBINLINE, s_OOBINLINE_tbound, NELEM(s_OOBINLINE_tbound));
    snap_run(st_name[1], mk_state, 1, SO_OOBINLINE, s_OOBINLINE_tlisten, NELEM(s_OOBINLINE_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_OOBINLINE, s_OOBINLINE_tclient, NELEM(s_OOBINLINE_tclient));
    snap_run(st_name[3], mk_state, 3, SO_OOBINLINE, s_OOBINLINE_taccepted, NELEM(s_OOBINLINE_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_OOBINLINE, s_OOBINLINE_tshut, NELEM(s_OOBINLINE_tshut));
    snap_run(st_name[5], mk_state, 5, SO_OOBINLINE, s_OOBINLINE_ubound, NELEM(s_OOBINLINE_ubound));
    snap_run(st_name[6], mk_state, 6, SO_OOBINLINE, s_OOBINLINE_uclient, NELEM(s_OOBINLINE_uclient));
    ws_down();
}

static const struct snap_row s_DONTLINGER_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DONTLINGER_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DONTLINGER_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DONTLINGER_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DONTLINGER_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_DONTLINGER_ubound[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_DONTLINGER_uclient[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_dontlinger)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_DONTLINGER, s_DONTLINGER_tbound, NELEM(s_DONTLINGER_tbound));
    snap_run(st_name[1], mk_state, 1, SO_DONTLINGER, s_DONTLINGER_tlisten, NELEM(s_DONTLINGER_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_DONTLINGER, s_DONTLINGER_tclient, NELEM(s_DONTLINGER_tclient));
    snap_run(st_name[3], mk_state, 3, SO_DONTLINGER, s_DONTLINGER_taccepted, NELEM(s_DONTLINGER_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_DONTLINGER, s_DONTLINGER_tshut, NELEM(s_DONTLINGER_tshut));
    snap_run(st_name[5], mk_state, 5, SO_DONTLINGER, s_DONTLINGER_ubound, NELEM(s_DONTLINGER_ubound));
    snap_run(st_name[6], mk_state, 6, SO_DONTLINGER, s_DONTLINGER_uclient, NELEM(s_DONTLINGER_uclient));
    ws_down();
}

static const struct snap_row s_EXCLUSIVE_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_EXCLUSIVE_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_EXCLUSIVE_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_EXCLUSIVE_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_EXCLUSIVE_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_EXCLUSIVE_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_EXCLUSIVE_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_exclusive)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_tbound, NELEM(s_EXCLUSIVE_tbound));
    snap_run(st_name[1], mk_state, 1, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_tlisten, NELEM(s_EXCLUSIVE_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_tclient, NELEM(s_EXCLUSIVE_tclient));
    snap_run(st_name[3], mk_state, 3, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_taccepted, NELEM(s_EXCLUSIVE_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_tshut, NELEM(s_EXCLUSIVE_tshut));
    snap_run(st_name[5], mk_state, 5, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_ubound, NELEM(s_EXCLUSIVE_ubound));
    snap_run(st_name[6], mk_state, 6, SO_EXCLUSIVEADDRUSE, s_EXCLUSIVE_uclient, NELEM(s_EXCLUSIVE_uclient));
    ws_down();
}

static const struct snap_row s_SNDBUF_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDBUF_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDBUF_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDBUF_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDBUF_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDBUF_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDBUF_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_sndbuf)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_SNDBUF, s_SNDBUF_tbound, NELEM(s_SNDBUF_tbound));
    snap_run(st_name[1], mk_state, 1, SO_SNDBUF, s_SNDBUF_tlisten, NELEM(s_SNDBUF_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_SNDBUF, s_SNDBUF_tclient, NELEM(s_SNDBUF_tclient));
    snap_run(st_name[3], mk_state, 3, SO_SNDBUF, s_SNDBUF_taccepted, NELEM(s_SNDBUF_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_SNDBUF, s_SNDBUF_tshut, NELEM(s_SNDBUF_tshut));
    snap_run(st_name[5], mk_state, 5, SO_SNDBUF, s_SNDBUF_ubound, NELEM(s_SNDBUF_ubound));
    snap_run(st_name[6], mk_state, 6, SO_SNDBUF, s_SNDBUF_uclient, NELEM(s_SNDBUF_uclient));
    ws_down();
}

static const struct snap_row s_RCVBUF_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVBUF_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVBUF_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVBUF_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVBUF_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVBUF_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVBUF_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_rcvbuf)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_RCVBUF, s_RCVBUF_tbound, NELEM(s_RCVBUF_tbound));
    snap_run(st_name[1], mk_state, 1, SO_RCVBUF, s_RCVBUF_tlisten, NELEM(s_RCVBUF_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_RCVBUF, s_RCVBUF_tclient, NELEM(s_RCVBUF_tclient));
    snap_run(st_name[3], mk_state, 3, SO_RCVBUF, s_RCVBUF_taccepted, NELEM(s_RCVBUF_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_RCVBUF, s_RCVBUF_tshut, NELEM(s_RCVBUF_tshut));
    snap_run(st_name[5], mk_state, 5, SO_RCVBUF, s_RCVBUF_ubound, NELEM(s_RCVBUF_ubound));
    snap_run(st_name[6], mk_state, 6, SO_RCVBUF, s_RCVBUF_uclient, NELEM(s_RCVBUF_uclient));
    ws_down();
}

static const struct snap_row s_SNDLOWAT_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_SNDLOWAT_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_SNDLOWAT_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_SNDLOWAT_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_SNDLOWAT_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_SNDLOWAT_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_SNDLOWAT_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_sndlowat)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_SNDLOWAT, s_SNDLOWAT_tbound, NELEM(s_SNDLOWAT_tbound));
    snap_run(st_name[1], mk_state, 1, SO_SNDLOWAT, s_SNDLOWAT_tlisten, NELEM(s_SNDLOWAT_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_SNDLOWAT, s_SNDLOWAT_tclient, NELEM(s_SNDLOWAT_tclient));
    snap_run(st_name[3], mk_state, 3, SO_SNDLOWAT, s_SNDLOWAT_taccepted, NELEM(s_SNDLOWAT_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_SNDLOWAT, s_SNDLOWAT_tshut, NELEM(s_SNDLOWAT_tshut));
    snap_run(st_name[5], mk_state, 5, SO_SNDLOWAT, s_SNDLOWAT_ubound, NELEM(s_SNDLOWAT_ubound));
    snap_run(st_name[6], mk_state, 6, SO_SNDLOWAT, s_SNDLOWAT_uclient, NELEM(s_SNDLOWAT_uclient));
    ws_down();
}

static const struct snap_row s_RCVLOWAT_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_RCVLOWAT_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_RCVLOWAT_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_RCVLOWAT_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_RCVLOWAT_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_RCVLOWAT_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_RCVLOWAT_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_rcvlowat)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_RCVLOWAT, s_RCVLOWAT_tbound, NELEM(s_RCVLOWAT_tbound));
    snap_run(st_name[1], mk_state, 1, SO_RCVLOWAT, s_RCVLOWAT_tlisten, NELEM(s_RCVLOWAT_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_RCVLOWAT, s_RCVLOWAT_tclient, NELEM(s_RCVLOWAT_tclient));
    snap_run(st_name[3], mk_state, 3, SO_RCVLOWAT, s_RCVLOWAT_taccepted, NELEM(s_RCVLOWAT_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_RCVLOWAT, s_RCVLOWAT_tshut, NELEM(s_RCVLOWAT_tshut));
    snap_run(st_name[5], mk_state, 5, SO_RCVLOWAT, s_RCVLOWAT_ubound, NELEM(s_RCVLOWAT_ubound));
    snap_run(st_name[6], mk_state, 6, SO_RCVLOWAT, s_RCVLOWAT_uclient, NELEM(s_RCVLOWAT_uclient));
    ws_down();
}

static const struct snap_row s_SNDTIMEO_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDTIMEO_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDTIMEO_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDTIMEO_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDTIMEO_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDTIMEO_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_SNDTIMEO_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_sndtimeo)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_SNDTIMEO, s_SNDTIMEO_tbound, NELEM(s_SNDTIMEO_tbound));
    snap_run(st_name[1], mk_state, 1, SO_SNDTIMEO, s_SNDTIMEO_tlisten, NELEM(s_SNDTIMEO_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_SNDTIMEO, s_SNDTIMEO_tclient, NELEM(s_SNDTIMEO_tclient));
    snap_run(st_name[3], mk_state, 3, SO_SNDTIMEO, s_SNDTIMEO_taccepted, NELEM(s_SNDTIMEO_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_SNDTIMEO, s_SNDTIMEO_tshut, NELEM(s_SNDTIMEO_tshut));
    snap_run(st_name[5], mk_state, 5, SO_SNDTIMEO, s_SNDTIMEO_ubound, NELEM(s_SNDTIMEO_ubound));
    snap_run(st_name[6], mk_state, 6, SO_SNDTIMEO, s_SNDTIMEO_uclient, NELEM(s_SNDTIMEO_uclient));
    ws_down();
}

static const struct snap_row s_RCVTIMEO_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVTIMEO_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVTIMEO_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVTIMEO_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVTIMEO_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVTIMEO_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RCVTIMEO_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_rcvtimeo)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_RCVTIMEO, s_RCVTIMEO_tbound, NELEM(s_RCVTIMEO_tbound));
    snap_run(st_name[1], mk_state, 1, SO_RCVTIMEO, s_RCVTIMEO_tlisten, NELEM(s_RCVTIMEO_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_RCVTIMEO, s_RCVTIMEO_tclient, NELEM(s_RCVTIMEO_tclient));
    snap_run(st_name[3], mk_state, 3, SO_RCVTIMEO, s_RCVTIMEO_taccepted, NELEM(s_RCVTIMEO_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_RCVTIMEO, s_RCVTIMEO_tshut, NELEM(s_RCVTIMEO_tshut));
    snap_run(st_name[5], mk_state, 5, SO_RCVTIMEO, s_RCVTIMEO_ubound, NELEM(s_RCVTIMEO_ubound));
    snap_run(st_name[6], mk_state, 6, SO_RCVTIMEO, s_RCVTIMEO_uclient, NELEM(s_RCVTIMEO_uclient));
    ws_down();
}

static const struct snap_row s_ERROR_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ERROR_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ERROR_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ERROR_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ERROR_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ERROR_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_ERROR_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_error)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_ERROR, s_ERROR_tbound, NELEM(s_ERROR_tbound));
    snap_run(st_name[1], mk_state, 1, SO_ERROR, s_ERROR_tlisten, NELEM(s_ERROR_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_ERROR, s_ERROR_tclient, NELEM(s_ERROR_tclient));
    snap_run(st_name[3], mk_state, 3, SO_ERROR, s_ERROR_taccepted, NELEM(s_ERROR_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_ERROR, s_ERROR_tshut, NELEM(s_ERROR_tshut));
    snap_run(st_name[5], mk_state, 5, SO_ERROR, s_ERROR_ubound, NELEM(s_ERROR_ubound));
    snap_run(st_name[6], mk_state, 6, SO_ERROR, s_ERROR_uclient, NELEM(s_ERROR_uclient));
    ws_down();
}

static const struct snap_row s_TYPE_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_TYPE_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_TYPE_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_TYPE_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_TYPE_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_TYPE_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=02000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=2"},
};
static const struct snap_row s_TYPE_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=02000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=2"},
};
TEST(sol_state_type)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_TYPE, s_TYPE_tbound, NELEM(s_TYPE_tbound));
    snap_run(st_name[1], mk_state, 1, SO_TYPE, s_TYPE_tlisten, NELEM(s_TYPE_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_TYPE, s_TYPE_tclient, NELEM(s_TYPE_tclient));
    snap_run(st_name[3], mk_state, 3, SO_TYPE, s_TYPE_taccepted, NELEM(s_TYPE_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_TYPE, s_TYPE_tshut, NELEM(s_TYPE_tshut));
    snap_run(st_name[5], mk_state, 5, SO_TYPE, s_TYPE_ubound, NELEM(s_TYPE_ubound));
    snap_run(st_name[6], mk_state, 6, SO_TYPE, s_TYPE_uclient, NELEM(s_TYPE_uclient));
    ws_down();
}

static const struct snap_row s_BSP_tbound[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BSP_tlisten[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BSP_tclient[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BSP_taccepted[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BSP_tshut[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BSP_ubound[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_BSP_uclient[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_bsp)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_BSP_STATE, s_BSP_tbound, NELEM(s_BSP_tbound));
    snap_run(st_name[1], mk_state, 1, SO_BSP_STATE, s_BSP_tlisten, NELEM(s_BSP_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_BSP_STATE, s_BSP_tclient, NELEM(s_BSP_tclient));
    snap_run(st_name[3], mk_state, 3, SO_BSP_STATE, s_BSP_taccepted, NELEM(s_BSP_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_BSP_STATE, s_BSP_tshut, NELEM(s_BSP_tshut));
    snap_run(st_name[5], mk_state, 5, SO_BSP_STATE, s_BSP_ubound, NELEM(s_BSP_ubound));
    snap_run(st_name[6], mk_state, 6, SO_BSP_STATE, s_BSP_uclient, NELEM(s_BSP_uclient));
    ws_down();
}

static const struct snap_row s_GROUPID_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPID_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPID_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPID_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPID_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPID_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPID_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
TEST(sol_state_groupid)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_GROUP_ID, s_GROUPID_tbound, NELEM(s_GROUPID_tbound));
    snap_run(st_name[1], mk_state, 1, SO_GROUP_ID, s_GROUPID_tlisten, NELEM(s_GROUPID_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_GROUP_ID, s_GROUPID_tclient, NELEM(s_GROUPID_tclient));
    snap_run(st_name[3], mk_state, 3, SO_GROUP_ID, s_GROUPID_taccepted, NELEM(s_GROUPID_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_GROUP_ID, s_GROUPID_tshut, NELEM(s_GROUPID_tshut));
    snap_run(st_name[5], mk_state, 5, SO_GROUP_ID, s_GROUPID_ubound, NELEM(s_GROUPID_ubound));
    snap_run(st_name[6], mk_state, 6, SO_GROUP_ID, s_GROUPID_uclient, NELEM(s_GROUPID_uclient));
    ws_down();
}

static const struct snap_row s_GROUPPRI_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPPRI_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPPRI_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPPRI_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPPRI_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPPRI_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_GROUPPRI_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_grouppri)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_GROUP_PRIORITY, s_GROUPPRI_tbound, NELEM(s_GROUPPRI_tbound));
    snap_run(st_name[1], mk_state, 1, SO_GROUP_PRIORITY, s_GROUPPRI_tlisten, NELEM(s_GROUPPRI_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_GROUP_PRIORITY, s_GROUPPRI_tclient, NELEM(s_GROUPPRI_tclient));
    snap_run(st_name[3], mk_state, 3, SO_GROUP_PRIORITY, s_GROUPPRI_taccepted, NELEM(s_GROUPPRI_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_GROUP_PRIORITY, s_GROUPPRI_tshut, NELEM(s_GROUPPRI_tshut));
    snap_run(st_name[5], mk_state, 5, SO_GROUP_PRIORITY, s_GROUPPRI_ubound, NELEM(s_GROUPPRI_ubound));
    snap_run(st_name[6], mk_state, 6, SO_GROUP_PRIORITY, s_GROUPPRI_uclient, NELEM(s_GROUPPRI_uclient));
    ws_down();
}

static const struct snap_row s_MAXMSG_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXMSG_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXMSG_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXMSG_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXMSG_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXMSG_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
static const struct snap_row s_MAXMSG_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
TEST(sol_state_maxmsg)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_MAX_MSG_SIZE, s_MAXMSG_tbound, NELEM(s_MAXMSG_tbound));
    snap_run(st_name[1], mk_state, 1, SO_MAX_MSG_SIZE, s_MAXMSG_tlisten, NELEM(s_MAXMSG_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_MAX_MSG_SIZE, s_MAXMSG_tclient, NELEM(s_MAXMSG_tclient));
    snap_run(st_name[3], mk_state, 3, SO_MAX_MSG_SIZE, s_MAXMSG_taccepted, NELEM(s_MAXMSG_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_MAX_MSG_SIZE, s_MAXMSG_tshut, NELEM(s_MAXMSG_tshut));
    snap_run(st_name[5], mk_state, 5, SO_MAX_MSG_SIZE, s_MAXMSG_ubound, NELEM(s_MAXMSG_ubound));
    snap_run(st_name[6], mk_state, 6, SO_MAX_MSG_SIZE, s_MAXMSG_uclient, NELEM(s_MAXMSG_uclient));
    ws_down();
}

static const struct snap_row s_PIA_tbound[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
static const struct snap_row s_PIA_tlisten[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
static const struct snap_row s_PIA_tclient[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
static const struct snap_row s_PIA_taccepted[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
static const struct snap_row s_PIA_tshut[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
static const struct snap_row s_PIA_ubound[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
static const struct snap_row s_PIA_uclient[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
TEST(sol_state_pia)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_PROTOCOL_INFOA, s_PIA_tbound, NELEM(s_PIA_tbound));
    snap_run(st_name[1], mk_state, 1, SO_PROTOCOL_INFOA, s_PIA_tlisten, NELEM(s_PIA_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_PROTOCOL_INFOA, s_PIA_tclient, NELEM(s_PIA_tclient));
    snap_run(st_name[3], mk_state, 3, SO_PROTOCOL_INFOA, s_PIA_taccepted, NELEM(s_PIA_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_PROTOCOL_INFOA, s_PIA_tshut, NELEM(s_PIA_tshut));
    snap_run(st_name[5], mk_state, 5, SO_PROTOCOL_INFOA, s_PIA_ubound, NELEM(s_PIA_ubound));
    snap_run(st_name[6], mk_state, 6, SO_PROTOCOL_INFOA, s_PIA_uclient, NELEM(s_PIA_uclient));
    ws_down();
}

static const struct snap_row s_PIW_tbound[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_PIW_tlisten[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_PIW_tclient[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_PIW_taccepted[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_PIW_tshut[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_PIW_ubound[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
};
static const struct snap_row s_PIW_uclient[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_state_piw)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_PROTOCOL_INFOW, s_PIW_tbound, NELEM(s_PIW_tbound));
    snap_run(st_name[1], mk_state, 1, SO_PROTOCOL_INFOW, s_PIW_tlisten, NELEM(s_PIW_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_PROTOCOL_INFOW, s_PIW_tclient, NELEM(s_PIW_tclient));
    snap_run(st_name[3], mk_state, 3, SO_PROTOCOL_INFOW, s_PIW_taccepted, NELEM(s_PIW_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_PROTOCOL_INFOW, s_PIW_tshut, NELEM(s_PIW_tshut));
    snap_run(st_name[5], mk_state, 5, SO_PROTOCOL_INFOW, s_PIW_ubound, NELEM(s_PIW_ubound));
    snap_run(st_name[6], mk_state, 6, SO_PROTOCOL_INFOW, s_PIW_uclient, NELEM(s_PIW_uclient));
    ws_down();
}

static const struct snap_row s_CONDACC_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_CONDACC_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_CONDACC_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_CONDACC_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_CONDACC_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_CONDACC_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
static const struct snap_row s_CONDACC_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
};
TEST(sol_state_condacc)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_CONDITIONAL_ACCEPT, s_CONDACC_tbound, NELEM(s_CONDACC_tbound));
    snap_run(st_name[1], mk_state, 1, SO_CONDITIONAL_ACCEPT, s_CONDACC_tlisten, NELEM(s_CONDACC_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_CONDITIONAL_ACCEPT, s_CONDACC_tclient, NELEM(s_CONDACC_tclient));
    snap_run(st_name[3], mk_state, 3, SO_CONDITIONAL_ACCEPT, s_CONDACC_taccepted, NELEM(s_CONDACC_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_CONDITIONAL_ACCEPT, s_CONDACC_tshut, NELEM(s_CONDACC_tshut));
    snap_run(st_name[5], mk_state, 5, SO_CONDITIONAL_ACCEPT, s_CONDACC_ubound, NELEM(s_CONDACC_ubound));
    snap_run(st_name[6], mk_state, 6, SO_CONDITIONAL_ACCEPT, s_CONDACC_uclient, NELEM(s_CONDACC_uclient));
    ws_down();
}

static const struct snap_row s_PAUSEACC_tbound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PAUSEACC_tlisten[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PAUSEACC_tclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PAUSEACC_taccepted[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PAUSEACC_tshut[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PAUSEACC_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_PAUSEACC_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_pauseacc)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_PAUSE_ACCEPT, s_PAUSEACC_tbound, NELEM(s_PAUSEACC_tbound));
    snap_run(st_name[1], mk_state, 1, SO_PAUSE_ACCEPT, s_PAUSEACC_tlisten, NELEM(s_PAUSEACC_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_PAUSE_ACCEPT, s_PAUSEACC_tclient, NELEM(s_PAUSEACC_tclient));
    snap_run(st_name[3], mk_state, 3, SO_PAUSE_ACCEPT, s_PAUSEACC_taccepted, NELEM(s_PAUSEACC_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_PAUSE_ACCEPT, s_PAUSEACC_tshut, NELEM(s_PAUSEACC_tshut));
    snap_run(st_name[5], mk_state, 5, SO_PAUSE_ACCEPT, s_PAUSEACC_ubound, NELEM(s_PAUSEACC_ubound));
    snap_run(st_name[6], mk_state, 6, SO_PAUSE_ACCEPT, s_PAUSEACC_uclient, NELEM(s_PAUSEACC_uclient));
    ws_down();
}

static const struct snap_row s_COMPART_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_COMPART_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_COMPART_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_COMPART_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_COMPART_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=1"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=1"},
};
static const struct snap_row s_COMPART_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=1"},
};
static const struct snap_row s_COMPART_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_state_compart)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_COMPARTMENT_ID, s_COMPART_tbound, NELEM(s_COMPART_tbound));
    snap_run(st_name[1], mk_state, 1, SO_COMPARTMENT_ID, s_COMPART_tlisten, NELEM(s_COMPART_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_COMPARTMENT_ID, s_COMPART_tclient, NELEM(s_COMPART_tclient));
    snap_run(st_name[3], mk_state, 3, SO_COMPARTMENT_ID, s_COMPART_taccepted, NELEM(s_COMPART_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_COMPARTMENT_ID, s_COMPART_tshut, NELEM(s_COMPART_tshut));
    snap_run(st_name[5], mk_state, 5, SO_COMPARTMENT_ID, s_COMPART_ubound, NELEM(s_COMPART_ubound));
    snap_run(st_name[6], mk_state, 6, SO_COMPARTMENT_ID, s_COMPART_uclient, NELEM(s_COMPART_uclient));
    ws_down();
}

static const struct snap_row s_RANDPORT_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RANDPORT_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RANDPORT_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RANDPORT_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RANDPORT_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
static const struct snap_row s_RANDPORT_ubound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_RANDPORT_uclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
TEST(sol_state_randport)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_RANDOMIZE_PORT, s_RANDPORT_tbound, NELEM(s_RANDPORT_tbound));
    snap_run(st_name[1], mk_state, 1, SO_RANDOMIZE_PORT, s_RANDPORT_tlisten, NELEM(s_RANDPORT_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_RANDOMIZE_PORT, s_RANDPORT_tclient, NELEM(s_RANDPORT_tclient));
    snap_run(st_name[3], mk_state, 3, SO_RANDOMIZE_PORT, s_RANDPORT_taccepted, NELEM(s_RANDPORT_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_RANDOMIZE_PORT, s_RANDPORT_tshut, NELEM(s_RANDPORT_tshut));
    snap_run(st_name[5], mk_state, 5, SO_RANDOMIZE_PORT, s_RANDPORT_ubound, NELEM(s_RANDPORT_ubound));
    snap_run(st_name[6], mk_state, 6, SO_RANDOMIZE_PORT, s_RANDPORT_uclient, NELEM(s_RANDPORT_uclient));
    ws_down();
}

