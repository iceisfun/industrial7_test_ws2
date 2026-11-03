/* SIO_TCP_INFO on Windows 10: which socket states answer, the input version word, the output-size protocol for the
 * v0 (88 byte) and v1 (136 byte) layouts, the TCP state numbers across a connection's life, and the byte counters
 * after transfers of known size on loopback (exact), plus the fields that are zero on a healthy loopback path. */
#include "xt.h"

enum { E_FAULT = WSAEFAULT, E_INVAL = WSAEINVAL, E_NOTSUP = WSAEOPNOTSUPP, E_NOTSOCK = WSAENOTSOCK };
enum { TS_CLOSED = 0, TS_LISTEN = 1, TS_ESTAB = 4, TS_FIN_WAIT2 = 6, TS_CLOSE_WAIT = 7 };
#define V0_SIZE 88u
#define V1_SIZE 136u

static xt_res info(SOCKET s, DWORD ver, void *out, DWORD outlen) { return xt_io(s, XT_SIO_TCP_INFO, &ver, 4, out, outlen); }

/* ---- unconnected sockets refuse the control code whatever the version and the buffer -------------------- */
static void refuse_all(int kind)
{
    static const DWORD vers[] = {0, 1, 2, 0xffffffffu};
    static const DWORD outs[] = {0, 4, 87, 88, 136, 200};
    xt_st st; unsigned char buf[512]; int v, o;
    if (!xt_mkstate(kind, &st)) { t_skip("setup failed"); return; }
    for (v = 0; v < 4; v++) for (o = 0; o < 6; o++) {
        xt_res r = info(st.s, vers[v], buf, outs[o]);
        CHECKF(r.rc == SOCKET_ERROR && r.err == E_NOTSUP, "%s ver %u out %u: rc %d err %d", xt_state_name[kind], (unsigned)vers[v], (unsigned)outs[o], r.rc, r.err);
    }
    { xt_res r = xt_io(st.s, XT_SIO_TCP_INFO, NULL, 0, buf, V0_SIZE); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_NOTSUP); }
    { DWORD z = 0; xt_res r = xt_io(st.s, XT_SIO_TCP_INFO, &z, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_NOTSUP); }
    xt_rmstate(&st);
}
TEST(info_fresh_tcp_socket_not_supported) { NEED(); refuse_all(XS_FRESH); }
TEST(info_bound_tcp_socket_not_supported) { NEED(); refuse_all(XS_BOUND); }
TEST(info_listening_socket_not_supported) { NEED(); refuse_all(XS_LISTEN); }
TEST(info_udp_socket_not_supported) { NEED(); refuse_all(XS_UDP); }
TEST(info_closed_socket_is_notsock)
{
    SOCKET s; xt_res r; unsigned char buf[200];
    NEED();
    s = xt_tcp(); xt_close(s);
    r = info(s, 0, buf, V0_SIZE); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_NOTSOCK);
}
TEST(info_listener_stays_unsupported_after_it_accepted)
{
    SOCKET c, a, l; xt_res r; unsigned char buf[200];
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    r = info(l, 0, buf, V0_SIZE); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_NOTSUP);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- output-size protocol on connected sockets ------------------------------------------------------------ */
/* v0 needs at least 88 bytes and reports 88; v1 needs a buffer of exactly 136 bytes (larger buffers are refused
 * too) and reports 136. Wrong sizes are WSAEFAULT, not WSAEINVAL. */
static void v0_sizes(int kind)
{
    static const struct { DWORD out; int ok; } rows[] = {
        {0, 0}, {1, 0}, {4, 0}, {8, 0}, {80, 0}, {87, 0}, {88, 1}, {89, 1}, {96, 1}, {100, 1}, {135, 1}, {136, 1}, {200, 1}, {400, 1},
    };
    xt_st st; unsigned char buf[512]; unsigned i;
    if (!xt_mkstate(kind, &st)) { t_skip("setup failed"); return; }
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        xt_res r; memset(buf, 0xAA, sizeof buf);
        r = info(st.s, 0, buf, rows[i].out);
        if (rows[i].ok) { CHECKF(r.rc == 0 && r.ret == V0_SIZE, "%s v0 out %u: rc %d err %d ret %u", xt_state_name[kind], (unsigned)rows[i].out, r.rc, r.err, (unsigned)r.ret); }
        else { CHECKF(r.rc == SOCKET_ERROR && r.err == E_FAULT, "%s v0 out %u: rc %d err %d", xt_state_name[kind], (unsigned)rows[i].out, r.rc, r.err); }
    }
    xt_rmstate(&st);
}
static void v1_sizes(int kind)
{
    static const struct { DWORD out; int ok; } rows[] = {
        {0, 0}, {4, 0}, {87, 0}, {88, 0}, {89, 0}, {100, 0}, {128, 0}, {135, 0}, {136, 1},
        {137, 0}, {140, 0}, {144, 0}, {200, 0}, {400, 0},
    };
    xt_st st; unsigned char buf[512]; unsigned i;
    if (!xt_mkstate(kind, &st)) { t_skip("setup failed"); return; }
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        xt_res r = info(st.s, 1, buf, rows[i].out);
        if (rows[i].ok) { CHECKF(r.rc == 0 && r.ret == V1_SIZE, "%s v1 out %u: rc %d err %d ret %u", xt_state_name[kind], (unsigned)rows[i].out, r.rc, r.err, (unsigned)r.ret); }
        else { CHECKF(r.rc == SOCKET_ERROR && r.err == E_FAULT, "%s v1 out %u: rc %d err %d", xt_state_name[kind], (unsigned)rows[i].out, r.rc, r.err); }
    }
    xt_rmstate(&st);
}
TEST(info_v0_sizes_on_client) { NEED(); v0_sizes(XS_CLIENT); }
TEST(info_v0_sizes_on_accepted) { NEED(); v0_sizes(XS_ACCEPTED); }
TEST(info_v0_sizes_after_shutdown_send) { NEED(); v0_sizes(XS_SHUT_SEND); }
TEST(info_v0_sizes_after_peer_close) { NEED(); v0_sizes(XS_PEER_CLOSED); }
TEST(info_v1_sizes_on_client) { NEED(); v1_sizes(XS_CLIENT); }
TEST(info_v1_sizes_on_accepted) { NEED(); v1_sizes(XS_ACCEPTED); }
TEST(info_v1_sizes_after_shutdown_send) { NEED(); v1_sizes(XS_SHUT_SEND); }
TEST(info_v1_sizes_after_peer_close) { NEED(); v1_sizes(XS_PEER_CLOSED); }
TEST(info_struct_sizes_are_88_and_136)
{
    CHECK(sizeof(xt_info0) == V0_SIZE);
    CHECK(sizeof(xt_info1) == V1_SIZE);
}

/* ---- version word -------------------------------------------------------------------------------------------- */
TEST(info_unknown_versions_are_invalid_argument)
{
    static const DWORD vers[] = {2, 3, 4, 100, 0x10000, 0x80000000u, 0xffffffffu};
    SOCKET c, a, l; unsigned char buf[512]; unsigned i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    for (i = 0; i < sizeof vers / sizeof vers[0]; i++) {
        xt_res r = info(c, vers[i], buf, 4);
        CHECKF(r.rc == SOCKET_ERROR && r.err == E_INVAL, "ver %u small buffer: rc %d err %d", (unsigned)vers[i], r.rc, r.err);
        r = info(c, vers[i], buf, 88);
        CHECKF(r.rc == SOCKET_ERROR && r.err == E_INVAL, "ver %u 88: rc %d err %d", (unsigned)vers[i], r.rc, r.err);
        r = info(c, vers[i], buf, 136);
        CHECKF(r.rc == SOCKET_ERROR && r.err == E_INVAL, "ver %u 136: rc %d err %d", (unsigned)vers[i], r.rc, r.err);
        r = info(c, vers[i], buf, 400);
        CHECKF(r.rc == SOCKET_ERROR && r.err == E_INVAL, "ver %u 400: rc %d err %d", (unsigned)vers[i], r.rc, r.err);
    }
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_unknown_version_with_empty_output_is_fault)
{
    SOCKET c, a, l; DWORD v = 2; xt_res r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    r = xt_io(c, XT_SIO_TCP_INFO, &v, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_FAULT);
    v = 0xffffffffu;
    r = xt_io(c, XT_SIO_TCP_INFO, &v, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_FAULT);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_input_must_be_exactly_one_version_word_or_larger_than_it)
{
    SOCKET c, a, l; unsigned char buf[512]; DWORD in2[2] = {0, 0}; xt_res r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    r = xt_io(c, XT_SIO_TCP_INFO, NULL, 0, buf, 88); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_INVAL);
    r = xt_io(c, XT_SIO_TCP_INFO, in2, 1, buf, 88); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_INVAL);
    r = xt_io(c, XT_SIO_TCP_INFO, in2, 2, buf, 88); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_INVAL);
    r = xt_io(c, XT_SIO_TCP_INFO, in2, 3, buf, 88); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_INVAL);
    r = xt_io(c, XT_SIO_TCP_INFO, in2, 4, buf, 88); EQ(r.rc, 0); EQ(r.ret, 88);
    r = xt_io(c, XT_SIO_TCP_INFO, in2, 5, buf, 88); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_INVAL);
    r = xt_io(c, XT_SIO_TCP_INFO, in2, 8, buf, 88); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_INVAL);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_missing_output_buffer_is_fault_even_with_valid_version)
{
    SOCKET c, a, l; DWORD v; xt_res r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    for (v = 0; v < 2; v++) { r = xt_io(c, XT_SIO_TCP_INFO, &v, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_FAULT); }
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_failed_call_leaves_output_untouched)
{
    SOCKET c, a, l; unsigned char buf[200]; unsigned i; xt_res r; int same = 1;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(buf, 0x5A, sizeof buf);
    r = info(c, 0, buf, 80); EQ(r.rc, SOCKET_ERROR);
    r = info(c, 2, buf, 88); EQ(r.rc, SOCKET_ERROR);
    r = info(c, 1, buf, 135); EQ(r.rc, SOCKET_ERROR);
    for (i = 0; i < sizeof buf; i++) if (buf[i] != 0x5A) same = 0;
    CHECK(same);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_bytes_past_the_reported_length_are_not_written)
{
    SOCKET c, a, l; unsigned char buf[300]; unsigned i; int clean = 1; xt_res r;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(buf, 0x77, sizeof buf);
    r = info(c, 0, buf, 300); EQ(r.rc, 0); EQ(r.ret, 88);
    for (i = 88; i < sizeof buf; i++) if (buf[i] != 0x77) clean = 0;
    CHECK(clean);
    memset(buf, 0x77, sizeof buf);
    r = info(c, 1, buf, 136); EQ(r.rc, 0); EQ(r.ret, 136);
    for (i = 136; i < sizeof buf; i++) if (buf[i] != 0x77) clean = 0;
    CHECK(clean);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- TCP state numbering over a connection's life --------------------------------------------------------- */
static int state_of(SOCKET s, DWORD *st)
{
    xt_info0 i; xt_res r = info(s, 0, &i, sizeof i);
    *st = i.State;
    return r.rc == 0;
}
TEST(info_state_established_on_both_ends)
{
    SOCKET c, a, l; DWORD s1 = 99, s2 = 99;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    CHECK(state_of(c, &s1)); CHECK(state_of(a, &s2));
    EQ(s1, TS_ESTAB); EQ(s2, TS_ESTAB);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_state_after_send_shutdown_is_fin_wait2_and_close_wait)
{
    SOCKET c, a, l; DWORD s1 = 99, s2 = 99;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    U(shutdown)(c, SD_SEND);
    CHECK(xt_wait_state(c, TS_FIN_WAIT2, 3000));
    CHECK(xt_wait_state(a, TS_CLOSE_WAIT, 3000));
    CHECK(state_of(c, &s1)); CHECK(state_of(a, &s2));
    EQ(s1, TS_FIN_WAIT2); EQ(s2, TS_CLOSE_WAIT);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_state_close_wait_on_peer_close)
{
    SOCKET c, a, l; DWORD s1 = 99;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    xt_close(a);
    CHECK(xt_wait_state(c, TS_CLOSE_WAIT, 3000));
    CHECK(state_of(c, &s1)); EQ(s1, TS_CLOSE_WAIT);
    xt_close(c); xt_close(l);
}
TEST(info_state_closed_after_both_directions_shut_down)
{
    SOCKET c, a, l; DWORD s1 = 99, s2 = 99; char b[4];
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    U(shutdown)(c, SD_SEND);
    CHECK(xt_wait_state(a, TS_CLOSE_WAIT, 3000));
    U(shutdown)(a, SD_SEND);
    CHECK(xt_wait_state(a, TS_CLOSED, 3000));
    CHECK(xt_wait_state(c, TS_CLOSED, 3000));
    CHECK(state_of(c, &s1)); CHECK(state_of(a, &s2));
    EQ(s1, TS_CLOSED); EQ(s2, TS_CLOSED);
    /* the sockets still answer the control code (rc 0) and still read end-of-stream */
    EQ(U(recv)(c, b, 4, 0), 0); EQ(U(recv)(a, b, 4, 0), 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_state_does_not_move_when_queried)
{
    SOCKET c, a, l; DWORD s1 = 99; int i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    for (i = 0; i < 20; i++) { CHECK(state_of(c, &s1)); EQ(s1, TS_ESTAB); }
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- byte counters: exact on loopback -------------------------------------------------------------------- */
static void both(SOCKET c, SOCKET a, xt_info1 *ci, xt_info1 *ai)
{
    DWORD v = 1;
    xt_io(c, XT_SIO_TCP_INFO, &v, 4, ci, sizeof *ci);
    xt_io(a, XT_SIO_TCP_INFO, &v, 4, ai, sizeof *ai);
}
static char xbuf[300000];
/* counters are updated when the segment is acknowledged; wait (bounded) until the receiver has accounted for n */
static int wait_in(SOCKET s, ULONG64 n)
{
    int i;
    for (i = 0; i < 150; i++) {
        xt_info1 x; DWORD v = 1;
        if (xt_io(s, XT_SIO_TCP_INFO, &v, 4, &x, sizeof x).rc == 0 && x.b.BytesIn == n) return 1;
        Sleep(20);
    }
    return 0;
}
static int wait_out(SOCKET s, ULONG64 n)
{
    int i;
    for (i = 0; i < 150; i++) {
        xt_info1 x; DWORD v = 1;
        if (xt_io(s, XT_SIO_TCP_INFO, &v, 4, &x, sizeof x).rc == 0 && x.b.BytesOut == n) return 1;
        Sleep(20);
    }
    return 0;
}
TEST(info_counters_start_at_zero_on_a_new_connection)
{
    SOCKET c, a, l; xt_info1 ci, ai;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    both(c, a, &ci, &ai);
    EQ(ci.b.BytesOut, 0); EQ(ci.b.BytesIn, 0); EQ(ai.b.BytesOut, 0); EQ(ai.b.BytesIn, 0);
    EQ(ci.b.BytesInFlight, 0); EQ(ai.b.BytesInFlight, 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_counters_follow_a_table_of_transfer_sizes)
{
    static const int sizes[] = {1, 2, 10, 100, 1000, 1460, 4096, 5000, 20000, 1};
    SOCKET c, a, l; ULONG64 total = 0; unsigned i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'x', sizeof xbuf);
    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        int n = sizes[i];
        EQ(xt_send(c, xbuf, n), n);
        EQ(xt_recv_all(a, xbuf, n, 3000), n);
        total += n;
        CHECKF(wait_in(a, total), "step %u: receiver BytesIn never reached %llu", i, total);
        CHECKF(wait_out(c, total), "step %u: sender BytesOut never reached %llu", i, total);
        { xt_info1 ci, ai; both(c, a, &ci, &ai);
          EQ(ci.b.BytesOut, total); EQ(ai.b.BytesIn, total); EQ(ci.b.BytesIn, 0); EQ(ai.b.BytesOut, 0); }
    }
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_counters_are_per_direction)
{
    SOCKET c, a, l; xt_info1 ci, ai;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'y', sizeof xbuf);
    EQ(xt_send(c, xbuf, 3000), 3000);
    EQ(xt_send(a, xbuf, 777), 777);
    EQ(xt_recv_all(a, xbuf, 3000, 3000), 3000);
    EQ(xt_recv_all(c, xbuf, 777, 3000), 777);
    CHECK(wait_in(a, 3000)); CHECK(wait_in(c, 777));
    both(c, a, &ci, &ai);
    EQ(ci.b.BytesOut, 3000); EQ(ci.b.BytesIn, 777); EQ(ai.b.BytesOut, 777); EQ(ai.b.BytesIn, 3000);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_bytes_in_counts_arrival_not_application_reads)
{
    SOCKET c, a, l; xt_info1 ci, ai;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'z', sizeof xbuf);
    EQ(xt_send(c, xbuf, 10000), 10000);
    CHECK(wait_in(a, 10000)); /* nothing has been read yet */
    both(c, a, &ci, &ai);
    EQ(ai.b.BytesIn, 10000); EQ(ci.b.BytesOut, 10000);
    EQ(xt_recv_all(a, xbuf, 4000, 3000), 4000);
    both(c, a, &ci, &ai);
    EQ(ai.b.BytesIn, 10000);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_counters_large_transfer_receiver_exact)
{
    SOCKET c, a, l; ULONG64 total = 0; int i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'w', sizeof xbuf);
    for (i = 0; i < 6; i++) {
        int n = 150000, got;
        EQ(xt_send(c, xbuf, n), n);
        got = xt_recv_all(a, xbuf, n, 3000);
        EQ(got, n);
        total += n;
    }
    CHECK(wait_in(a, total));
    { xt_info1 ci, ai; both(c, a, &ci, &ai);
      /* the receiver counts payload exactly; the sender may count a few header bytes on multi-segment sends */
      EQ(ai.b.BytesIn, total); CHECK(ci.b.BytesOut >= total); CHECK(ci.b.BytesOut < total + 1000); }
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_counters_unchanged_by_queries_and_zero_byte_sends)
{
    SOCKET c, a, l; xt_info1 ci, ai; int i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(c, "hello", 5), 5);
    EQ(xt_recv_all(a, xbuf, 5, 3000), 5);
    CHECK(wait_in(a, 5));
    for (i = 0; i < 10; i++) both(c, a, &ci, &ai);
    EQ(ci.b.BytesOut, 5); EQ(ai.b.BytesIn, 5);
    EQ(xt_send(c, "", 0), 0);
    both(c, a, &ci, &ai);
    EQ(ci.b.BytesOut, 5); EQ(ai.b.BytesIn, 5);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_counters_survive_send_shutdown)
{
    SOCKET c, a, l; xt_info1 ci, ai;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(c, "abcdefgh", 8), 8);
    EQ(xt_recv_all(a, xbuf, 8, 3000), 8);
    CHECK(wait_in(a, 8));
    U(shutdown)(c, SD_SEND);
    CHECK(xt_wait_state(c, TS_FIN_WAIT2, 3000));
    both(c, a, &ci, &ai);
    EQ(ci.b.BytesOut, 8); EQ(ai.b.BytesIn, 8); EQ(ci.b.State, TS_FIN_WAIT2);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- fields that are zero on a healthy loopback connection ------------------------------------------------ */
TEST(info_loss_counters_are_zero_after_traffic)
{
    SOCKET c, a, l; xt_info1 ci, ai; int i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'r', sizeof xbuf);
    for (i = 0; i < 5; i++) { EQ(xt_send(c, xbuf, 30000), 30000); EQ(xt_recv_all(a, xbuf, 30000, 3000), 30000); }
    CHECK(wait_in(a, 150000));
    both(c, a, &ci, &ai);
    EQ(ci.b.BytesRetrans, 0); EQ(ai.b.BytesRetrans, 0);
    EQ(ci.b.FastRetrans, 0); EQ(ai.b.FastRetrans, 0);
    EQ(ci.b.DupAcksIn, 0); EQ(ai.b.DupAcksIn, 0);
    EQ(ci.b.TimeoutEpisodes, 0); EQ(ai.b.TimeoutEpisodes, 0);
    EQ(ci.b.SynRetrans, 0); EQ(ai.b.SynRetrans, 0);
    EQ(ci.b.BytesReordered, 0); EQ(ai.b.BytesReordered, 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_bytes_in_flight_is_zero_once_everything_is_acknowledged)
{
    SOCKET c, a, l; xt_info1 ci, ai;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'f', sizeof xbuf);
    EQ(xt_send(c, xbuf, 50000), 50000);
    EQ(xt_recv_all(a, xbuf, 50000, 3000), 50000);
    CHECK(wait_out(c, 50000));
    both(c, a, &ci, &ai);
    EQ(ci.b.BytesInFlight, 0); EQ(ai.b.BytesInFlight, 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_snd_limited_byte_accounts_are_bounded_by_bytes_out)
{
    SOCKET c, a, l; xt_info1 ci, ai;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    memset(xbuf, 'g', sizeof xbuf);
    EQ(xt_send(c, xbuf, 40000), 40000);
    EQ(xt_recv_all(a, xbuf, 40000, 3000), 40000);
    CHECK(wait_out(c, 40000));
    both(c, a, &ci, &ai);
    CHECK(ci.SndLimBytesRwin <= ci.b.BytesOut);
    CHECK(ci.SndLimBytesCwnd <= ci.b.BytesOut);
    CHECK(ci.SndLimBytesSnd <= ci.b.BytesOut + 1000);
    EQ(ai.b.BytesOut, 0);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- invariants of the sizing fields ---------------------------------------------------------------------- */
TEST(info_mss_is_positive_and_equal_on_both_ends)
{
    SOCKET c, a, l; xt_info0 ci, ai; DWORD v = 0;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ci, sizeof ci).rc, 0);
    EQ(xt_io(a, XT_SIO_TCP_INFO, &v, 4, &ai, sizeof ai).rc, 0);
    CHECK(ci.Mss > 0 && ci.Mss <= 65535);
    EQ(ci.Mss, ai.Mss);
    t_note("loopback MSS is 40 below the loopback MTU (65495 for the stock 65535 MTU)");
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_window_and_buffer_fields_are_nonzero_when_idle)
{
    SOCKET c, a, l; xt_info0 ci, ai; DWORD v = 0;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ci, sizeof ci); xt_io(a, XT_SIO_TCP_INFO, &v, 4, &ai, sizeof ai);
    CHECK(ci.Cwnd > 0); CHECK(ai.Cwnd > 0);
    CHECK(ci.RcvBuf > 0); CHECK(ai.RcvBuf > 0);
    CHECK(ci.RcvWnd > 0); CHECK(ai.RcvWnd > 0);
    CHECK(ci.SndWnd > 0); CHECK(ai.SndWnd > 0);
    CHECK(ci.RcvWnd <= ci.RcvBuf); CHECK(ai.RcvWnd <= ai.RcvBuf);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_min_rtt_never_exceeds_rtt_after_traffic)
{
    SOCKET c, a, l; xt_info0 ci; DWORD v = 0; int i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    for (i = 0; i < 5; i++) { EQ(xt_send(c, "ping", 4), 4); EQ(xt_recv_all(a, xbuf, 4, 3000), 4); }
    CHECK(wait_out(c, 20));
    xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ci, sizeof ci);
    CHECK(ci.MinRttUs <= ci.RttUs || ci.RttUs == 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_connection_time_does_not_run_backwards)
{
    SOCKET c, a, l; xt_info0 i1, i2; DWORD v = 0;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    xt_io(c, XT_SIO_TCP_INFO, &v, 4, &i1, sizeof i1);
    Sleep(250);
    xt_io(c, XT_SIO_TCP_INFO, &v, 4, &i2, sizeof i2);
    CHECK(i2.ConnectionTimeMs >= i1.ConnectionTimeMs);
    CHECK(i2.ConnectionTimeMs - i1.ConnectionTimeMs >= 100);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_v1_leading_fields_agree_with_v0)
{
    SOCKET c, a, l; xt_info0 i0; xt_info1 i1; DWORD v0 = 0, v1 = 1;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_send(c, "12345", 5), 5); EQ(xt_recv_all(a, xbuf, 5, 3000), 5); CHECK(wait_out(c, 5));
    xt_io(c, XT_SIO_TCP_INFO, &v0, 4, &i0, sizeof i0); xt_io(c, XT_SIO_TCP_INFO, &v1, 4, &i1, sizeof i1);
    EQ(i0.State, i1.b.State); EQ(i0.Mss, i1.b.Mss); EQ(i0.BytesOut, i1.b.BytesOut); EQ(i0.BytesIn, i1.b.BytesIn);
    EQ(i0.RcvBuf, i1.b.RcvBuf); EQ(i0.Timestamps, i1.b.Timestamps); EQ(i0.BytesRetrans, i1.b.BytesRetrans);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_connection_on_ipv6_loopback)
{
    SOCKET s6, c6, a6; struct sockaddr_in6 sa; int sl = sizeof sa; xt_info0 i; DWORD v = 0; xt_res r;
    NEED();
    s6 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s6 == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    memset(&sa, 0, sizeof sa); sa.sin6_family = AF_INET6; sa.sin6_addr.u.Byte[15] = 1;
    if (U(bind)(s6, (struct sockaddr *)&sa, sizeof sa) || U(getsockname)(s6, (struct sockaddr *)&sa, &sl) || U(listen)(s6, 2)) { xt_close(s6); t_skip("no IPv6 loopback"); return; }
    c6 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (U(connect)(c6, (struct sockaddr *)&sa, sizeof sa)) { xt_close(c6); xt_close(s6); t_skip("IPv6 connect failed"); return; }
    if (!xt_readable(s6, 3000)) { xt_close(c6); xt_close(s6); t_skip("IPv6 connection never arrived"); return; }
    a6 = xt_accept(s6);
    r = xt_io(c6, XT_SIO_TCP_INFO, &v, 4, &i, sizeof i);
    EQ(r.rc, 0); EQ(r.ret, 88); EQ(i.State, TS_ESTAB); CHECK(i.Mss > 0);
    EQ(xt_send(c6, "abc", 3), 3);
    EQ(xt_recv_all(a6, xbuf, 3, 3000), 3);
    CHECK(wait_in(a6, 3));
    xt_close(c6); xt_close(a6); xt_close(s6);
}

TEST(info_socket_after_refused_connect_not_supported)
{
    SOCKET t = xt_tcp(), q; u_short p = 0; int e, er; xt_info0 i; DWORD z = 0; xt_res r;
    NEED();
    EQ(xt_bind_lo(t, &p), 0); xt_close(t);
    q = xt_tcp();
    e = xt_connect_lo(q, p); er = e ? U(WSAGetLastError)() : 0;
    EQ(e, SOCKET_ERROR); EQ(er, WSAECONNREFUSED);
    r = xt_io(q, XT_SIO_TCP_INFO, &z, 4, &i, sizeof i);
    EQ(r.rc, SOCKET_ERROR); EQ(r.err, E_NOTSUP);
    xt_close(q);
}
TEST(info_null_bytes_returned_pointer_is_fault)
{
    SOCKET c, a, l; DWORD z = 0; unsigned char buf[200]; int rc;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    rc = U(WSAIoctl)(c, XT_SIO_TCP_INFO, &z, 4, buf, 88, NULL, NULL, NULL);
    EQ(rc, SOCKET_ERROR); EQ(U(WSAGetLastError)(), E_FAULT);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(info_ipv6_connection_reports_a_mss_20_below_the_ipv4_one)
{
    SOCKET s6, c6, a6, c, a, l; struct sockaddr_in6 sa; int sl = sizeof sa; xt_info0 i6, i4; DWORD v = 0;
    NEED();
    s6 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s6 == INVALID_SOCKET) { t_skip("no IPv6"); return; }
    memset(&sa, 0, sizeof sa); sa.sin6_family = AF_INET6; sa.sin6_addr.u.Byte[15] = 1;
    if (U(bind)(s6, (struct sockaddr *)&sa, sizeof sa) || U(getsockname)(s6, (struct sockaddr *)&sa, &sl) || U(listen)(s6, 2)) { xt_close(s6); t_skip("no IPv6 loopback"); return; }
    c6 = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (U(connect)(c6, (struct sockaddr *)&sa, sizeof sa)) { xt_close(c6); xt_close(s6); t_skip("IPv6 connect failed"); return; }
    if (!xt_readable(s6, 3000)) { xt_close(c6); xt_close(s6); t_skip("IPv6 connection never arrived"); return; }
    a6 = xt_accept(s6);
    if (!xt_pair(&c, &a, &l)) { xt_close(c6); xt_close(a6); xt_close(s6); t_skip("pair failed"); return; }
    EQ(xt_io(c6, XT_SIO_TCP_INFO, &v, 4, &i6, sizeof i6).rc, 0);
    EQ(xt_io(c, XT_SIO_TCP_INFO, &v, 4, &i4, sizeof i4).rc, 0);
    EQ(i4.Mss - i6.Mss, 20);
    xt_close(c6); xt_close(a6); xt_close(s6); xt_close(c); xt_close(a); xt_close(l);
}
