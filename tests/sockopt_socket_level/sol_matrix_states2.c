/* sockopt_socket_level: outcome of every SOL_SOCKET option on sockets in each connection state
 * (bound, listening, connected client, accepted, shut down, UDP bound, UDP connected): a read into a 4-byte buffer
 * and writes of 1 and 0. Expected outcomes come from observation of genuine Windows 10 22H2. */
#include "sol_snap.h"

static const struct snap_row s_PORTSCAL_tbound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PORTSCAL_tlisten[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PORTSCAL_tclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PORTSCAL_taccepted[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PORTSCAL_tshut[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_PORTSCAL_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_PORTSCAL_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_portscal)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_PORT_SCALABILITY, s_PORTSCAL_tbound, NELEM(s_PORTSCAL_tbound));
    snap_run(st_name[1], mk_state, 1, SO_PORT_SCALABILITY, s_PORTSCAL_tlisten, NELEM(s_PORTSCAL_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_PORT_SCALABILITY, s_PORTSCAL_tclient, NELEM(s_PORTSCAL_tclient));
    snap_run(st_name[3], mk_state, 3, SO_PORT_SCALABILITY, s_PORTSCAL_taccepted, NELEM(s_PORTSCAL_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_PORT_SCALABILITY, s_PORTSCAL_tshut, NELEM(s_PORTSCAL_tshut));
    snap_run(st_name[5], mk_state, 5, SO_PORT_SCALABILITY, s_PORTSCAL_ubound, NELEM(s_PORTSCAL_ubound));
    snap_run(st_name[6], mk_state, 6, SO_PORT_SCALABILITY, s_PORTSCAL_uclient, NELEM(s_PORTSCAL_uclient));
    ws_down();
}

static const struct snap_row s_REUSEUNI_tbound[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_REUSEUNI_tlisten[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_REUSEUNI_tclient[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_REUSEUNI_taccepted[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_REUSEUNI_tshut[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
    {"s0", "r=-1 e=10022 | back r=0 len=1 v=5a5a5a00"},
};
static const struct snap_row s_REUSEUNI_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEUNI_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_reuseuni)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_REUSE_UNICASTPORT, s_REUSEUNI_tbound, NELEM(s_REUSEUNI_tbound));
    snap_run(st_name[1], mk_state, 1, SO_REUSE_UNICASTPORT, s_REUSEUNI_tlisten, NELEM(s_REUSEUNI_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_REUSE_UNICASTPORT, s_REUSEUNI_tclient, NELEM(s_REUSEUNI_tclient));
    snap_run(st_name[3], mk_state, 3, SO_REUSE_UNICASTPORT, s_REUSEUNI_taccepted, NELEM(s_REUSEUNI_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_REUSE_UNICASTPORT, s_REUSEUNI_tshut, NELEM(s_REUSEUNI_tshut));
    snap_run(st_name[5], mk_state, 5, SO_REUSE_UNICASTPORT, s_REUSEUNI_ubound, NELEM(s_REUSEUNI_ubound));
    snap_run(st_name[6], mk_state, 6, SO_REUSE_UNICASTPORT, s_REUSEUNI_uclient, NELEM(s_REUSEUNI_uclient));
    ws_down();
}

static const struct snap_row s_REUSEMC_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEMC_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEMC_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEMC_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEMC_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEMC_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_REUSEMC_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_reusemc)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_REUSE_MULTICASTPORT, s_REUSEMC_tbound, NELEM(s_REUSEMC_tbound));
    snap_run(st_name[1], mk_state, 1, SO_REUSE_MULTICASTPORT, s_REUSEMC_tlisten, NELEM(s_REUSEMC_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_REUSE_MULTICASTPORT, s_REUSEMC_tclient, NELEM(s_REUSEMC_tclient));
    snap_run(st_name[3], mk_state, 3, SO_REUSE_MULTICASTPORT, s_REUSEMC_taccepted, NELEM(s_REUSEMC_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_REUSE_MULTICASTPORT, s_REUSEMC_tshut, NELEM(s_REUSEMC_tshut));
    snap_run(st_name[5], mk_state, 5, SO_REUSE_MULTICASTPORT, s_REUSEMC_ubound, NELEM(s_REUSEMC_ubound));
    snap_run(st_name[6], mk_state, 6, SO_REUSE_MULTICASTPORT, s_REUSEMC_uclient, NELEM(s_REUSEMC_uclient));
    ws_down();
}

static const struct snap_row s_MAXDG_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXDG_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXDG_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXDG_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXDG_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXDG_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
static const struct snap_row s_MAXDG_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
TEST(sol_state_maxdg)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, 0x7009, s_MAXDG_tbound, NELEM(s_MAXDG_tbound));
    snap_run(st_name[1], mk_state, 1, 0x7009, s_MAXDG_tlisten, NELEM(s_MAXDG_tlisten));
    snap_run(st_name[2], mk_state, 2, 0x7009, s_MAXDG_tclient, NELEM(s_MAXDG_tclient));
    snap_run(st_name[3], mk_state, 3, 0x7009, s_MAXDG_taccepted, NELEM(s_MAXDG_taccepted));
    snap_run(st_name[4], mk_state, 4, 0x7009, s_MAXDG_tshut, NELEM(s_MAXDG_tshut));
    snap_run(st_name[5], mk_state, 5, 0x7009, s_MAXDG_ubound, NELEM(s_MAXDG_ubound));
    snap_run(st_name[6], mk_state, 6, 0x7009, s_MAXDG_uclient, NELEM(s_MAXDG_uclient));
    ws_down();
}

static const struct snap_row s_MAXPDG_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXPDG_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXPDG_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXPDG_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXPDG_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_MAXPDG_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
static const struct snap_row s_MAXPDG_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
TEST(sol_state_maxpdg)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, 0x700a, s_MAXPDG_tbound, NELEM(s_MAXPDG_tbound));
    snap_run(st_name[1], mk_state, 1, 0x700a, s_MAXPDG_tlisten, NELEM(s_MAXPDG_tlisten));
    snap_run(st_name[2], mk_state, 2, 0x700a, s_MAXPDG_tclient, NELEM(s_MAXPDG_tclient));
    snap_run(st_name[3], mk_state, 3, 0x700a, s_MAXPDG_taccepted, NELEM(s_MAXPDG_taccepted));
    snap_run(st_name[4], mk_state, 4, 0x700a, s_MAXPDG_tshut, NELEM(s_MAXPDG_tshut));
    snap_run(st_name[5], mk_state, 5, 0x700a, s_MAXPDG_ubound, NELEM(s_MAXPDG_ubound));
    snap_run(st_name[6], mk_state, 6, 0x700a, s_MAXPDG_uclient, NELEM(s_MAXPDG_uclient));
    ws_down();
}

static const struct snap_row s_UPDACC_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDACC_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDACC_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDACC_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDACC_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDACC_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDACC_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_updacc)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_tbound, NELEM(s_UPDACC_tbound));
    snap_run(st_name[1], mk_state, 1, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_tlisten, NELEM(s_UPDACC_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_tclient, NELEM(s_UPDACC_tclient));
    snap_run(st_name[3], mk_state, 3, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_taccepted, NELEM(s_UPDACC_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_tshut, NELEM(s_UPDACC_tshut));
    snap_run(st_name[5], mk_state, 5, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_ubound, NELEM(s_UPDACC_ubound));
    snap_run(st_name[6], mk_state, 6, SO_UPDATE_ACCEPT_CONTEXT, s_UPDACC_uclient, NELEM(s_UPDACC_uclient));
    ws_down();
}

static const struct snap_row s_CONTIME_tbound[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_CONTIME_tlisten[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_CONTIME_tclient[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=*"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=*"},
};
static const struct snap_row s_CONTIME_taccepted[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=*"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=*"},
};
static const struct snap_row s_CONTIME_tshut[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"s1", "r=-1 e=10042 | back r=0 len=4 v=*"},
    {"s0", "r=-1 e=10042 | back r=0 len=4 v=*"},
};
static const struct snap_row s_CONTIME_ubound[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
};
static const struct snap_row s_CONTIME_uclient[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
};
TEST(sol_state_contime)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_CONNECT_TIME, s_CONTIME_tbound, NELEM(s_CONTIME_tbound));
    snap_run(st_name[1], mk_state, 1, SO_CONNECT_TIME, s_CONTIME_tlisten, NELEM(s_CONTIME_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_CONNECT_TIME, s_CONTIME_tclient, NELEM(s_CONTIME_tclient));
    snap_run(st_name[3], mk_state, 3, SO_CONNECT_TIME, s_CONTIME_taccepted, NELEM(s_CONTIME_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_CONNECT_TIME, s_CONTIME_tshut, NELEM(s_CONTIME_tshut));
    snap_run(st_name[5], mk_state, 5, SO_CONNECT_TIME, s_CONTIME_ubound, NELEM(s_CONTIME_ubound));
    snap_run(st_name[6], mk_state, 6, SO_CONNECT_TIME, s_CONTIME_uclient, NELEM(s_CONTIME_uclient));
    ws_down();
}

static const struct snap_row s_UPDCONN_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDCONN_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDCONN_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDCONN_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDCONN_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDCONN_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_UPDCONN_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_updconn)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_tbound, NELEM(s_UPDCONN_tbound));
    snap_run(st_name[1], mk_state, 1, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_tlisten, NELEM(s_UPDCONN_tlisten));
    snap_run(st_name[2], mk_state, 2, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_tclient, NELEM(s_UPDCONN_tclient));
    snap_run(st_name[3], mk_state, 3, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_taccepted, NELEM(s_UPDCONN_taccepted));
    snap_run(st_name[4], mk_state, 4, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_tshut, NELEM(s_UPDCONN_tshut));
    snap_run(st_name[5], mk_state, 5, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_ubound, NELEM(s_UPDCONN_ubound));
    snap_run(st_name[6], mk_state, 6, SO_UPDATE_CONNECT_CONTEXT, s_UPDCONN_uclient, NELEM(s_UPDCONN_uclient));
    ws_down();
}

static const struct snap_row s_S8000_tbound[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_S8000_tlisten[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_S8000_tclient[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_S8000_taccepted[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_S8000_tshut[] = {
    {"g4", "r=-1 e=10042 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_S8000_ubound[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
static const struct snap_row s_S8000_uclient[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_state_s8000)
{
    NEED();
    snap_run(st_name[0], mk_state, 0, 0x8000, s_S8000_tbound, NELEM(s_S8000_tbound));
    snap_run(st_name[1], mk_state, 1, 0x8000, s_S8000_tlisten, NELEM(s_S8000_tlisten));
    snap_run(st_name[2], mk_state, 2, 0x8000, s_S8000_tclient, NELEM(s_S8000_tclient));
    snap_run(st_name[3], mk_state, 3, 0x8000, s_S8000_taccepted, NELEM(s_S8000_taccepted));
    snap_run(st_name[4], mk_state, 4, 0x8000, s_S8000_tshut, NELEM(s_S8000_tshut));
    snap_run(st_name[5], mk_state, 5, 0x8000, s_S8000_ubound, NELEM(s_S8000_ubound));
    snap_run(st_name[6], mk_state, 6, 0x8000, s_S8000_uclient, NELEM(s_S8000_uclient));
    ws_down();
}

