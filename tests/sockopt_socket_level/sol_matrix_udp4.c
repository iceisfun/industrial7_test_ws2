/* sockopt_socket_level: outcome matrix of every SOL_SOCKET option on a fresh IPv4 UDP socket.
 * Each table row is one operation (read with several buffer sizes, write with several values and lengths) and the
 * exact result: return value, last error, returned length and the bytes written. The expected outcomes come from
 * observation of genuine Windows 10 22H2; values that depend on system tuning end in "v=*". */
#include "sol_snap.h"

static const struct snap_row x_DEBUG_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0000000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100l1", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s1l2", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l3", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=0 e=0 | back r=0 len=4 v=1"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_matrix_udp4_debug) { NEED(); snap_run("udp4 SO_DEBUG", mk_fresh, K_UDP4, SO_DEBUG, x_DEBUG_udp4, NELEM(x_DEBUG_udp4)); ws_down(); }

static const struct snap_row x_ACCEPTCONN_udp4[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10042 len=1 v=aa"}, {"g2", "r=-1 e=10042 len=2 v=aaaa"},
    {"g8", "r=-1 e=10042 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_acceptconn) { NEED(); snap_run("udp4 SO_ACCEPTCONN", mk_fresh, K_UDP4, SO_ACCEPTCONN, x_ACCEPTCONN_udp4, NELEM(x_ACCEPTCONN_udp4)); ws_down(); }

static const struct snap_row x_REUSEADDR_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0000000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100l1", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s1l2", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l3", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=0 e=0 | back r=0 len=4 v=1"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_matrix_udp4_reuseaddr) { NEED(); snap_run("udp4 SO_REUSEADDR", mk_fresh, K_UDP4, SO_REUSEADDR, x_REUSEADDR_udp4, NELEM(x_REUSEADDR_udp4)); ws_down(); }

static const struct snap_row x_KEEPALIVE_udp4[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10042 len=1 v=aa"}, {"g2", "r=-1 e=10042 len=2 v=aaaa"},
    {"g8", "r=-1 e=10042 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_keepalive) { NEED(); snap_run("udp4 SO_KEEPALIVE", mk_fresh, K_UDP4, SO_KEEPALIVE, x_KEEPALIVE_udp4, NELEM(x_KEEPALIVE_udp4)); ws_down(); }

static const struct snap_row x_DONTROUTE_udp4[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=00aa"},
    {"g8", "r=0 e=0 len=1 v=00aaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"}, {"s100", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
    {"s1l1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"}, {"s100l1", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
    {"s1l2", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"}, {"s1l3", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s1l8", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"}, {"s1l0", "r=-1 e=10014 | back r=0 len=1 v=5a5a5a00"},
    {"snull", "r=-1 e=10014 | back r=0 len=1 v=5a5a5a00"}, {"s5", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
};
TEST(sol_matrix_udp4_dontroute) { NEED(); snap_run("udp4 SO_DONTROUTE", mk_fresh, K_UDP4, SO_DONTROUTE, x_DONTROUTE_udp4, NELEM(x_DONTROUTE_udp4)); ws_down(); }

static const struct snap_row x_BROADCAST_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0000000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100l1", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s1l2", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l3", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=0 e=0 | back r=0 len=4 v=1"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_matrix_udp4_broadcast) { NEED(); snap_run("udp4 SO_BROADCAST", mk_fresh, K_UDP4, SO_BROADCAST, x_BROADCAST_udp4, NELEM(x_BROADCAST_udp4)); ws_down(); }

static const struct snap_row x_USELOOPBACK_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_useloopback) { NEED(); snap_run("udp4 SO_USELOOPBACK", mk_fresh, K_UDP4, SO_USELOOPBACK, x_USELOOPBACK_udp4, NELEM(x_USELOOPBACK_udp4)); ws_down(); }

static const struct snap_row x_LINGER_udp4[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10042 len=1 v=aa"}, {"g2", "r=-1 e=10042 len=2 v=aaaa"},
    {"g8", "r=-1 e=10042 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_linger) { NEED(); snap_run("udp4 SO_LINGER", mk_fresh, K_UDP4, SO_LINGER, x_LINGER_udp4, NELEM(x_LINGER_udp4)); ws_down(); }

static const struct snap_row x_OOBINLINE_udp4[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10042 len=1 v=aa"}, {"g2", "r=-1 e=10042 len=2 v=aaaa"},
    {"g8", "r=-1 e=10042 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_oobinline) { NEED(); snap_run("udp4 SO_OOBINLINE", mk_fresh, K_UDP4, SO_OOBINLINE, x_OOBINLINE_udp4, NELEM(x_OOBINLINE_udp4)); ws_down(); }

static const struct snap_row x_DONTLINGER_udp4[] = {
    {"g4", "r=-1 e=10042 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10042 len=1 v=aa"}, {"g2", "r=-1 e=10042 len=2 v=aaaa"},
    {"g8", "r=-1 e=10042 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_dontlinger) { NEED(); snap_run("udp4 SO_DONTLINGER", mk_fresh, K_UDP4, SO_DONTLINGER, x_DONTLINGER_udp4, NELEM(x_DONTLINGER_udp4)); ws_down(); }

static const struct snap_row x_EXCLUSIVE_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0000000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100l1", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s1l2", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l3", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=0 e=0 | back r=0 len=4 v=1"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_matrix_udp4_exclusive) { NEED(); snap_run("udp4 SO_EXCLUSIVEADDRUSE", mk_fresh, K_UDP4, SO_EXCLUSIVEADDRUSE, x_EXCLUSIVE_udp4, NELEM(x_EXCLUSIVE_udp4)); ws_down(); }

static const struct snap_row x_SNDBUF_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"g1", "r=-1 e=10014 len=1 v=00"}, {"g2", "r=-1 e=10014 len=2 v=0000"},
    {"g8", "r=0 e=0 len=4 v=*"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"}, {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"},
    {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"},
    {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s100", "r=0 e=0 | back r=0 len=4 v=100"}, {"s1l1", "r=-1 e=10014 | back r=0 len=4 v=10000"},
    {"s100l1", "r=-1 e=10014 | back r=0 len=4 v=10000"}, {"s1l2", "r=-1 e=10014 | back r=0 len=4 v=10000"},
    {"s1l3", "r=-1 e=10014 | back r=0 len=4 v=10000"}, {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l0", "r=-1 e=10014 | back r=0 len=4 v=10000"}, {"snull", "r=-1 e=10014 | back r=0 len=4 v=10000"},
    {"s5", "r=0 e=0 | back r=0 len=4 v=5"},
};
TEST(sol_matrix_udp4_sndbuf) { NEED(); snap_run("udp4 SO_SNDBUF", mk_fresh, K_UDP4, SO_SNDBUF, x_SNDBUF_udp4, NELEM(x_SNDBUF_udp4)); ws_down(); }

static const struct snap_row x_RCVBUF_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=*"}, {"g1", "r=-1 e=10014 len=1 v=00"}, {"g2", "r=-1 e=10014 len=2 v=0000"},
    {"g8", "r=0 e=0 len=4 v=*"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"}, {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"},
    {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"},
    {"s1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s0", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s100", "r=0 e=0 | back r=0 len=4 v=100"}, {"s1l1", "r=-1 e=10014 | back r=0 len=4 v=10000"},
    {"s100l1", "r=-1 e=10014 | back r=0 len=4 v=10000"}, {"s1l2", "r=-1 e=10014 | back r=0 len=4 v=10000"},
    {"s1l3", "r=-1 e=10014 | back r=0 len=4 v=10000"}, {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l0", "r=-1 e=10014 | back r=0 len=4 v=10000"}, {"snull", "r=-1 e=10014 | back r=0 len=4 v=10000"},
    {"s5", "r=0 e=0 | back r=0 len=4 v=5"},
};
TEST(sol_matrix_udp4_rcvbuf) { NEED(); snap_run("udp4 SO_RCVBUF", mk_fresh, K_UDP4, SO_RCVBUF, x_RCVBUF_udp4, NELEM(x_RCVBUF_udp4)); ws_down(); }

static const struct snap_row x_SNDLOWAT_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_sndlowat) { NEED(); snap_run("udp4 SO_SNDLOWAT", mk_fresh, K_UDP4, SO_SNDLOWAT, x_SNDLOWAT_udp4, NELEM(x_SNDLOWAT_udp4)); ws_down(); }

static const struct snap_row x_RCVLOWAT_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_rcvlowat) { NEED(); snap_run("udp4 SO_RCVLOWAT", mk_fresh, K_UDP4, SO_RCVLOWAT, x_RCVLOWAT_udp4, NELEM(x_RCVLOWAT_udp4)); ws_down(); }

static const struct snap_row x_SNDTIMEO_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=00000000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=100"},
    {"s1l1", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s100l1", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l2", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s1l3", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=5"},
};
TEST(sol_matrix_udp4_sndtimeo) { NEED(); snap_run("udp4 SO_SNDTIMEO", mk_fresh, K_UDP4, SO_SNDTIMEO, x_SNDTIMEO_udp4, NELEM(x_SNDTIMEO_udp4)); ws_down(); }

static const struct snap_row x_RCVTIMEO_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=00000000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=100"},
    {"s1l1", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s100l1", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l2", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s1l3", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=5"},
};
TEST(sol_matrix_udp4_rcvtimeo) { NEED(); snap_run("udp4 SO_RCVTIMEO", mk_fresh, K_UDP4, SO_RCVTIMEO, x_RCVTIMEO_udp4, NELEM(x_RCVTIMEO_udp4)); ws_down(); }

static const struct snap_row x_ERROR_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=-1 e=10014 len=1 v=00"}, {"g2", "r=-1 e=10014 len=2 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0000000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=100"},
    {"s1l1", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s100l1", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l2", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s1l3", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=5"},
};
TEST(sol_matrix_udp4_error) { NEED(); snap_run("udp4 SO_ERROR", mk_fresh, K_UDP4, SO_ERROR, x_ERROR_udp4, NELEM(x_ERROR_udp4)); ws_down(); }

static const struct snap_row x_TYPE_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=02000000"}, {"g1", "r=-1 e=10014 len=1 v=00"}, {"g2", "r=-1 e=10014 len=2 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0200000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=2"}, {"s100", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"s1l1", "r=-1 e=10022 | back r=0 len=4 v=2"}, {"s100l1", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"s1l2", "r=-1 e=10022 | back r=0 len=4 v=2"}, {"s1l3", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"s1l8", "r=-1 e=10022 | back r=0 len=4 v=2"}, {"s1l0", "r=-1 e=10022 | back r=0 len=4 v=2"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=2"}, {"s5", "r=-1 e=10022 | back r=0 len=4 v=2"},
};
TEST(sol_matrix_udp4_type) { NEED(); snap_run("udp4 SO_TYPE", mk_fresh, K_UDP4, SO_TYPE, x_TYPE_udp4, NELEM(x_TYPE_udp4)); ws_down(); }

static const struct snap_row x_BSP_udp4[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=-1 e=10014 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_bsp) { NEED(); snap_run("udp4 SO_BSP_STATE", mk_fresh, K_UDP4, SO_BSP_STATE, x_BSP_udp4, NELEM(x_BSP_udp4)); ws_down(); }

static const struct snap_row x_GROUPID_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=00000000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=0"}, {"s100", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s1l1", "r=-1 e=10022 | back r=0 len=4 v=0"}, {"s100l1", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s1l2", "r=-1 e=10022 | back r=0 len=4 v=0"}, {"s1l3", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"s1l8", "r=-1 e=10022 | back r=0 len=4 v=0"}, {"s1l0", "r=-1 e=10022 | back r=0 len=4 v=0"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=-1 e=10022 | back r=0 len=4 v=0"},
};
TEST(sol_matrix_udp4_groupid) { NEED(); snap_run("udp4 SO_GROUP_ID", mk_fresh, K_UDP4, SO_GROUP_ID, x_GROUPID_udp4, NELEM(x_GROUPID_udp4)); ws_down(); }

static const struct snap_row x_GROUPPRI_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=00000000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=100"},
    {"s1l1", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s100l1", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l2", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s1l3", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=-1 e=10014 | back r=0 len=4 v=0"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=5"},
};
TEST(sol_matrix_udp4_grouppri) { NEED(); snap_run("udp4 SO_GROUP_PRIORITY", mk_fresh, K_UDP4, SO_GROUP_PRIORITY, x_GROUPPRI_udp4, NELEM(x_GROUPPRI_udp4)); ws_down(); }

static const struct snap_row x_MAXMSG_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=e3ff0000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s100", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s100l1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l2", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s1l3", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l8", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s1l0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=ffe3"}, {"s5", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
TEST(sol_matrix_udp4_maxmsg) { NEED(); snap_run("udp4 SO_MAX_MSG_SIZE", mk_fresh, K_UDP4, SO_MAX_MSG_SIZE, x_MAXMSG_udp4, NELEM(x_MAXMSG_udp4)); ws_down(); }

static const struct snap_row x_PIA_udp4[] = {
    {"g4", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"g1", "r=-1 e=10014 len=372 v=aa"},
    {"g2", "r=-1 e=10014 len=372 v=aaaa"}, {"g8", "r=-1 e=10014 len=372 v=aaaaaaaaaaaaaaaa"},
    {"g0", "r=-1 e=10014 len=372 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=372 v=aaaaaaaa"},
    {"s1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"}, {"s0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s100", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"}, {"s1l1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s100l1", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=372 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=372 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_pia) { NEED(); snap_run("udp4 SO_PROTOCOL_INFOA", mk_fresh, K_UDP4, SO_PROTOCOL_INFOA, x_PIA_udp4, NELEM(x_PIA_udp4)); ws_down(); }

static const struct snap_row x_PIW_udp4[] = {
    {"g4", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=-1 e=10014 len=8 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=4 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=4 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_piw) { NEED(); snap_run("udp4 SO_PROTOCOL_INFOW", mk_fresh, K_UDP4, SO_PROTOCOL_INFOW, x_PIW_udp4, NELEM(x_PIW_udp4)); ws_down(); }

static const struct snap_row x_CONDACC_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=00000000"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=0000"},
    {"g8", "r=0 e=0 len=4 v=0000000000000000"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=0"}, {"s100", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100l1", "r=0 e=0 | back r=0 len=4 v=0"},
    {"s1l2", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l3", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=0 e=0 | back r=0 len=4 v=1"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=0"}, {"s5", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_matrix_udp4_condacc) { NEED(); snap_run("udp4 SO_CONDITIONAL_ACCEPT", mk_fresh, K_UDP4, SO_CONDITIONAL_ACCEPT, x_CONDACC_udp4, NELEM(x_CONDACC_udp4)); ws_down(); }

static const struct snap_row x_PAUSEACC_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_pauseacc) { NEED(); snap_run("udp4 SO_PAUSE_ACCEPT", mk_fresh, K_UDP4, SO_PAUSE_ACCEPT, x_PAUSEACC_udp4, NELEM(x_PAUSEACC_udp4)); ws_down(); }

static const struct snap_row x_COMPART_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=01000000"}, {"g1", "r=-1 e=10014 len=0 v=aa"}, {"g2", "r=-1 e=10014 len=0 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=01000000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s0", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l1", "r=0 e=0 | back r=0 len=4 v=1"}, {"s100l1", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l2", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l3", "r=0 e=0 | back r=0 len=4 v=1"},
    {"s1l8", "r=0 e=0 | back r=0 len=4 v=1"}, {"s1l0", "r=0 e=0 | back r=0 len=4 v=1"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=1"}, {"s5", "r=0 e=0 | back r=0 len=4 v=1"},
};
TEST(sol_matrix_udp4_compart) { NEED(); snap_run("udp4 SO_COMPARTMENT_ID", mk_fresh, K_UDP4, SO_COMPARTMENT_ID, x_COMPART_udp4, NELEM(x_COMPART_udp4)); ws_down(); }

static const struct snap_row x_RANDPORT_udp4[] = {
    {"g4", "r=0 e=0 len=1 v=00aaaaaa"}, {"g1", "r=0 e=0 len=1 v=00"}, {"g2", "r=0 e=0 len=1 v=00aa"},
    {"g8", "r=0 e=0 len=1 v=00aaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s0", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"}, {"s100", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
    {"s1l1", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"}, {"s100l1", "r=0 e=0 | back r=0 len=1 v=5a5a5a00"},
    {"s1l2", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"}, {"s1l3", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
    {"s1l8", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"}, {"s1l0", "r=-1 e=10014 | back r=0 len=1 v=5a5a5a00"},
    {"snull", "r=-1 e=10014 | back r=0 len=1 v=5a5a5a00"}, {"s5", "r=0 e=0 | back r=0 len=1 v=5a5a5a01"},
};
TEST(sol_matrix_udp4_randport) { NEED(); snap_run("udp4 SO_RANDOMIZE_PORT", mk_fresh, K_UDP4, SO_RANDOMIZE_PORT, x_RANDPORT_udp4, NELEM(x_RANDPORT_udp4)); ws_down(); }

static const struct snap_row x_PORTSCAL_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_portscal) { NEED(); snap_run("udp4 SO_PORT_SCALABILITY", mk_fresh, K_UDP4, SO_PORT_SCALABILITY, x_PORTSCAL_udp4, NELEM(x_PORTSCAL_udp4)); ws_down(); }

static const struct snap_row x_REUSEUNI_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_reuseuni) { NEED(); snap_run("udp4 SO_REUSE_UNICASTPORT", mk_fresh, K_UDP4, SO_REUSE_UNICASTPORT, x_REUSEUNI_udp4, NELEM(x_REUSEUNI_udp4)); ws_down(); }

static const struct snap_row x_REUSEMC_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=0 e=0 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_reusemc) { NEED(); snap_run("udp4 SO_REUSE_MULTICASTPORT", mk_fresh, K_UDP4, SO_REUSE_MULTICASTPORT, x_REUSEMC_udp4, NELEM(x_REUSEMC_udp4)); ws_down(); }

static const struct snap_row x_MAXDG_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=e3ff0000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s100", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s100l1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l2", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s1l3", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l8", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s1l0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=ffe3"}, {"s5", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
TEST(sol_matrix_udp4_maxdg) { NEED(); snap_run("udp4 0x7009", mk_fresh, K_UDP4, 0x7009, x_MAXDG_udp4, NELEM(x_MAXDG_udp4)); ws_down(); }

static const struct snap_row x_MAXPDG_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=e3ff0000"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=e3ff0000aaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s100", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s100l1", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l2", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s1l3", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"s1l8", "r=-1 e=10022 | back r=0 len=4 v=ffe3"}, {"s1l0", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=ffe3"}, {"s5", "r=-1 e=10022 | back r=0 len=4 v=ffe3"},
};
TEST(sol_matrix_udp4_maxpdg) { NEED(); snap_run("udp4 0x700a", mk_fresh, K_UDP4, 0x700a, x_MAXPDG_udp4, NELEM(x_MAXPDG_udp4)); ws_down(); }

static const struct snap_row x_UPDACC_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10038 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_updacc) { NEED(); snap_run("udp4 SO_UPDATE_ACCEPT_CONTEXT", mk_fresh, K_UDP4, SO_UPDATE_ACCEPT_CONTEXT, x_UPDACC_udp4, NELEM(x_UPDACC_udp4)); ws_down(); }

static const struct snap_row x_CONTIME_udp4[] = {
    {"g4", "r=0 e=0 len=4 v=ffffffff"}, {"g1", "r=-1 e=10014 len=1 v=aa"}, {"g2", "r=-1 e=10014 len=2 v=aaaa"},
    {"g8", "r=0 e=0 len=4 v=ffffffffaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"s0", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"}, {"s100", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"s1l1", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"}, {"s100l1", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"s1l2", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"}, {"s1l3", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"s1l8", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"}, {"s1l0", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
    {"snull", "r=-1 e=10014 | back r=0 len=4 v=ffffffff"}, {"s5", "r=-1 e=10022 | back r=0 len=4 v=ffffffff"},
};
TEST(sol_matrix_udp4_contime) { NEED(); snap_run("udp4 SO_CONNECT_TIME", mk_fresh, K_UDP4, SO_CONNECT_TIME, x_CONTIME_udp4, NELEM(x_CONTIME_udp4)); ws_down(); }

static const struct snap_row x_UPDCONN_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10057 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_updconn) { NEED(); snap_run("udp4 SO_UPDATE_CONNECT_CONTEXT", mk_fresh, K_UDP4, SO_UPDATE_CONNECT_CONTEXT, x_UPDCONN_udp4, NELEM(x_UPDCONN_udp4)); ws_down(); }

static const struct snap_row x_S8000_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10042 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_s8000) { NEED(); snap_run("udp4 0x8000", mk_fresh, K_UDP4, 0x8000, x_S8000_udp4, NELEM(x_S8000_udp4)); ws_down(); }

static const struct snap_row x_B3_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b3) { NEED(); snap_run("udp4 3", mk_fresh, K_UDP4, 3, x_B3_udp4, NELEM(x_B3_udp4)); ws_down(); }

static const struct snap_row x_B5_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b5) { NEED(); snap_run("udp4 5", mk_fresh, K_UDP4, 5, x_B5_udp4, NELEM(x_B5_udp4)); ws_down(); }

static const struct snap_row x_B9_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b9) { NEED(); snap_run("udp4 9", mk_fresh, K_UDP4, 9, x_B9_udp4, NELEM(x_B9_udp4)); ws_down(); }

static const struct snap_row x_B200_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b200) { NEED(); snap_run("udp4 0x200", mk_fresh, K_UDP4, 0x200, x_B200_udp4, NELEM(x_B200_udp4)); ws_down(); }

static const struct snap_row x_B1234_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b1234) { NEED(); snap_run("udp4 0x1234", mk_fresh, K_UDP4, 0x1234, x_B1234_udp4, NELEM(x_B1234_udp4)); ws_down(); }

static const struct snap_row x_B3001_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b3001) { NEED(); snap_run("udp4 0x3001", mk_fresh, K_UDP4, 0x3001, x_B3001_udp4, NELEM(x_B3001_udp4)); ws_down(); }

static const struct snap_row x_B4000_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b4000) { NEED(); snap_run("udp4 0x4000", mk_fresh, K_UDP4, 0x4000, x_B4000_udp4, NELEM(x_B4000_udp4)); ws_down(); }

static const struct snap_row x_B7fff_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_b7fff) { NEED(); snap_run("udp4 0x7fff", mk_fresh, K_UDP4, 0x7fff, x_B7fff_udp4, NELEM(x_B7fff_udp4)); ws_down(); }

static const struct snap_row x_Bneg2_udp4[] = {
    {"g4", "r=-1 e=10022 len=0 v=aaaaaaaa"}, {"g1", "r=-1 e=10022 len=0 v=aa"}, {"g2", "r=-1 e=10022 len=0 v=aaaa"},
    {"g8", "r=-1 e=10022 len=0 v=aaaaaaaaaaaaaaaa"}, {"g0", "r=-1 e=10014 len=0 v=aaaaaaaa"},
    {"gneg", "r=-1 e=10014 len=-1 v=aaaaaaaa"}, {"gnullbuf", "r=-1 e=10014 len=4 v=aaaaaaaa"},
    {"gnulllen", "r=-1 e=10014 len=-9 v=aaaaaaaa"}, {"s1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s100l1", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l2", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l3", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"s1l8", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"}, {"s1l0", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
    {"snull", "r=-1 e=10014 | back r=-1 len=0 v=5a5a5a5a"}, {"s5", "r=-1 e=10022 | back r=-1 len=0 v=5a5a5a5a"},
};
TEST(sol_matrix_udp4_bneg2) { NEED(); snap_run("udp4 -2", mk_fresh, K_UDP4, -2, x_Bneg2_udp4, NELEM(x_Bneg2_udp4)); ws_down(); }

