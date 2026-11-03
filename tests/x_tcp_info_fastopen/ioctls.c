/* The small TCP control codes of Windows 10: SIO_TCP_SET_ACK_FREQUENCY, SIO_TCP_SET_ICW, SIO_TCP_INITIAL_RTO and
 * SIO_LOOPBACK_FAST_PATH. For each: which socket states take it, which values and input lengths are refused and
 * with which WSA error. Datagram sockets answer all of them with WSAEOPNOTSUPP. */
#include "xt.h"

static const int tcp_kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN, XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED};
#define NTCP ((int)(sizeof tcp_kinds / sizeof tcp_kinds[0]))
#define FOR_TCP_STATES(st, n) { int k_; for (k_ = 0; k_ < NTCP; k_++) { xt_st st; const char *n = xt_state_name[tcp_kinds[k_]]; \
    if (!xt_mkstate(tcp_kinds[k_], &st)) { t_skip("setup %s", n); return; }
#define END_STATES(st) xt_rmstate(&st); } }

/* ---- SIO_TCP_SET_ACK_FREQUENCY: one byte, 0 or 1 -------------------------------------------------------------- */
TEST(ackfreq_zero_and_one_accepted_in_every_tcp_state)
{
    NEED();
    FOR_TCP_STATES(st, n)
        BYTE v;
        for (v = 0; v <= 1; v++) {
            xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, &v, 1, NULL, 0);
            CHECKF(r.rc == 0 && r.ret == 0, "%s value %u: rc %d err %d", n, v, r.rc, r.err);
        }
    END_STATES(st)
}
TEST(ackfreq_larger_values_are_invalid_argument)
{
    static const BYTE vals[] = {2, 3, 4, 8, 10, 20, 21, 100, 127, 128, 254, 255};
    NEED();
    FOR_TCP_STATES(st, n)
        unsigned i;
        for (i = 0; i < sizeof vals; i++) {
            xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, &vals[i], 1, NULL, 0);
            CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEINVAL, "%s value %u: rc %d err %d", n, vals[i], r.rc, r.err);
        }
    END_STATES(st)
}
TEST(ackfreq_empty_input_is_fault)
{
    NEED();
    FOR_TCP_STATES(st, n)
        BYTE v = 1;
        xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, &v, 0, NULL, 0);
        CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s len 0: rc %d err %d", n, r.rc, r.err);
        r = xt_io(st.s, XT_SIO_ACK_FREQ, NULL, 0, NULL, 0);
        CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s NULL: rc %d err %d", n, r.rc, r.err);
    END_STATES(st)
}
TEST(ackfreq_value_is_checked_before_output_buffer)
{
    NEED();
    FOR_TCP_STATES(st, n)
        BYTE v = 2, out[8];
        xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, &v, 1, out, sizeof out);
        CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEINVAL, "%s: rc %d err %d", n, r.rc, r.err);
    END_STATES(st)
}
TEST(ackfreq_udp_not_supported_whatever_the_input)
{
    SOCKET s; BYTE v = 1; xt_res r;
    NEED();
    s = xt_udp();
    r = xt_io(s, XT_SIO_ACK_FREQ, &v, 1, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    v = 200; r = xt_io(s, XT_SIO_ACK_FREQ, &v, 1, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    r = xt_io(s, XT_SIO_ACK_FREQ, NULL, 0, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    xt_close(s);
}
TEST(ackfreq_does_not_disturb_established_traffic)
{
    SOCKET c, a, l; BYTE v = 1; char b[8];
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_io(c, XT_SIO_ACK_FREQ, &v, 1, NULL, 0).rc, 0);
    EQ(xt_io(a, XT_SIO_ACK_FREQ, &v, 1, NULL, 0).rc, 0);
    EQ(xt_send(c, "12345678", 8), 8); EQ(xt_recv_all(a, b, 8, 3000), 8);
    EQ(xt_send(a, "abcdefgh", 8), 8); EQ(xt_recv_all(c, b, 8, 3000), 8);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- SIO_TCP_SET_ICW: level 0, 1 or 254 ------------------------------------------------------------------------ */
TEST(icw_levels_default_high_and_compat_accepted_in_every_tcp_state)
{
    static const DWORD ok[] = {0, 1, 254};
    NEED();
    FOR_TCP_STATES(st, n)
        unsigned i;
        for (i = 0; i < 3; i++) {
            xt_res r = xt_io(st.s, XT_SIO_SET_ICW, &ok[i], 4, NULL, 0);
            CHECKF(r.rc == 0 && r.ret == 0, "%s level %u: rc %d err %d", n, (unsigned)ok[i], r.rc, r.err);
        }
    END_STATES(st)
}
TEST(icw_other_levels_are_invalid_argument)
{
    static const DWORD bad[] = {2, 3, 4, 5, 100, 253, 255, 256, 0x10000, 0xffffffffu};
    NEED();
    FOR_TCP_STATES(st, n)
        unsigned i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            xt_res r = xt_io(st.s, XT_SIO_SET_ICW, &bad[i], 4, NULL, 0);
            CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEINVAL, "%s level %u: rc %d err %d", n, (unsigned)bad[i], r.rc, r.err);
        }
    END_STATES(st)
}
TEST(icw_udp_not_supported)
{
    SOCKET s; DWORD lv = 0; xt_res r;
    NEED();
    s = xt_udp();
    r = xt_io(s, XT_SIO_SET_ICW, &lv, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    lv = 2; r = xt_io(s, XT_SIO_SET_ICW, &lv, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    xt_close(s);
}

/* ---- SIO_LOOPBACK_FAST_PATH: only before a connection exists ---------------------------------------------------- */
TEST(loopback_fast_path_accepted_on_unconnected_tcp_states)
{
    static const int kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN};
    unsigned k;
    NEED();
    for (k = 0; k < 3; k++) {
        xt_st st; DWORD on = 1; xt_res r; unsigned char out[16]; const char *n = xt_state_name[kinds[k]];
        if (!xt_mkstate(kinds[k], &st)) { t_skip("setup %s", n); return; }
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 4, NULL, 0);  CHECKF(r.rc == 0 && r.ret == 0, "%s on: rc %d err %d", n, r.rc, r.err);
        on = 0; r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 4, NULL, 0); CHECKF(r.rc == 0, "%s off: rc %d err %d", n, r.rc, r.err);
        on = 1; r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 4, out, sizeof out); CHECKF(r.rc == 0 && r.ret == 0, "%s with output buffer: rc %d err %d", n, r.rc, r.err);
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 3, NULL, 0); CHECKF(r.rc == 0, "%s len 3: rc %d err %d", n, r.rc, r.err);
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 8, NULL, 0); CHECKF(r.rc == 0, "%s len 8: rc %d err %d", n, r.rc, r.err);
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 0, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s len 0: rc %d err %d", n, r.rc, r.err);
        xt_rmstate(&st);
    }
}
TEST(loopback_fast_path_refused_on_connected_sockets_and_udp)
{
    static const int kinds[] = {XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED, XS_UDP};
    unsigned k;
    NEED();
    for (k = 0; k < 6; k++) {
        xt_st st; DWORD on = 1; xt_res r; const char *n = xt_state_name[kinds[k]];
        if (!xt_mkstate(kinds[k], &st)) { t_skip("setup %s", n); return; }
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 4, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEOPNOTSUPP, "%s on: rc %d err %d", n, r.rc, r.err);
        on = 0; r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 4, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEOPNOTSUPP, "%s off: rc %d err %d", n, r.rc, r.err);
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 0, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEOPNOTSUPP, "%s len 0: rc %d err %d", n, r.rc, r.err);
        r = xt_io(st.s, XT_SIO_LOOPBACK_FAST, &on, 3, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEOPNOTSUPP, "%s len 3: rc %d err %d", n, r.rc, r.err);
        xt_rmstate(&st);
    }
}
TEST(loopback_fast_path_set_before_connect_keeps_the_connection_working)
{
    SOCKET l, c, a; u_short p; DWORD on = 1; char b[8];
    NEED();
    EQ(xt_listen_lo(&l, &p, 2), 1);
    EQ(xt_io(l, XT_SIO_LOOPBACK_FAST, &on, 4, NULL, 0).rc, 0);
    c = xt_tcp();
    EQ(xt_io(c, XT_SIO_LOOPBACK_FAST, &on, 4, NULL, 0).rc, 0);
    EQ(xt_connect_lo(c, p), 0);
    CHECK(xt_readable(l, 3000));
    a = xt_accept(l);
    EQ(xt_send(c, "fastpath", 8), 8); EQ(xt_recv_all(a, b, 8, 3000), 8);
    EQ(memcmp(b, "fastpath", 8), 0);
    xt_close(c); xt_close(a); xt_close(l);
}

/* ---- input length rules --------------------------------------------------------------------------------------- */
TEST(ackfreq_input_of_any_nonzero_length_uses_the_first_byte)
{
    NEED();
    FOR_TCP_STATES(st, n)
        BYTE b[8] = {1, 0, 0, 0, 0, 0, 0, 0}; unsigned len;
        for (len = 1; len <= 8; len++) {
            xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, b, len, NULL, 0);
            CHECKF(r.rc == 0, "%s len %u value 1: rc %d err %d", n, len, r.rc, r.err);
        }
        b[0] = 2; b[1] = 0;
        for (len = 1; len <= 8; len++) {
            xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, b, len, NULL, 0);
            CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEINVAL, "%s len %u value 2: rc %d err %d", n, len, r.rc, r.err);
        }
        { BYTE hi[8] = {0, 5, 5, 5, 5, 5, 5, 5}; xt_res r = xt_io(st.s, XT_SIO_ACK_FREQ, hi, 8, NULL, 0); CHECKF(r.rc == 0, "%s high bytes ignored", n); }
    END_STATES(st)
}
TEST(icw_input_shorter_than_a_dword_is_fault)
{
    NEED();
    FOR_TCP_STATES(st, n)
        DWORD lv = 1; unsigned len;
        for (len = 0; len < 4; len++) {
            xt_res r = xt_io(st.s, XT_SIO_SET_ICW, &lv, len, NULL, 0);
            CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s len %u: rc %d err %d", n, len, r.rc, r.err);
        }
        { DWORD big[2] = {1, 99}; xt_res r = xt_io(st.s, XT_SIO_SET_ICW, big, 8, NULL, 0); CHECKF(r.rc == 0, "%s len 8: rc %d err %d", n, r.rc, r.err); }
        { unsigned char out[8]; xt_res r = xt_io(st.s, XT_SIO_SET_ICW, &lv, 4, out, sizeof out); CHECKF(r.rc == 0 && r.ret == 0, "%s with output buffer", n); }
    END_STATES(st)
}

/* ---- SIO_TCP_INITIAL_RTO: before a connection exists, any 4+ byte parameter block ---------------------------------- */
TEST(initial_rto_parameter_matrix_accepted_on_unconnected_tcp_states)
{
    static const struct { USHORT rtt; UCHAR retx; } rows[] = {
        {0, 0}, {100, 0}, {300, 3}, {3000, 0}, {3001, 0}, {65535, 0}, {65535, 255}, {0, 254}, {500, 253}, {500, 1},
        {1, 1}, {100, 15}, {100, 16}, {100, 255}, {5, 0}, {4, 0}, {0, 1}, {0, 2}, {0, 255},
    };
    static const int kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN};
    unsigned k, i;
    NEED();
    for (k = 0; k < 3; k++) {
        xt_st st; const char *n = xt_state_name[kinds[k]];
        if (!xt_mkstate(kinds[k], &st)) { t_skip("setup %s", n); return; }
        for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
            BYTE blk[4]; xt_res r;
            memcpy(blk, &rows[i].rtt, 2); blk[2] = rows[i].retx; blk[3] = 0;
            r = xt_io(st.s, XT_SIO_INITIAL_RTO, blk, 4, NULL, 0);
            CHECKF(r.rc == 0 && r.ret == 0, "%s rtt %u retx %u: rc %d err %d", n, rows[i].rtt, rows[i].retx, r.rc, r.err);
        }
        xt_rmstate(&st);
    }
}
TEST(initial_rto_input_shorter_than_four_bytes_is_fault)
{
    static const int kinds[] = {XS_FRESH, XS_BOUND, XS_LISTEN};
    unsigned k, len;
    NEED();
    for (k = 0; k < 3; k++) {
        xt_st st; const char *n = xt_state_name[kinds[k]]; BYTE blk[8] = {100, 0, 3, 0, 0, 0, 0, 0};
        if (!xt_mkstate(kinds[k], &st)) { t_skip("setup %s", n); return; }
        for (len = 0; len < 4; len++) {
            xt_res r = xt_io(st.s, XT_SIO_INITIAL_RTO, blk, len, NULL, 0);
            CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s len %u: rc %d err %d", n, len, r.rc, r.err);
        }
        { xt_res r = xt_io(st.s, XT_SIO_INITIAL_RTO, NULL, 0, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s NULL", n); }
        { xt_res r = xt_io(st.s, XT_SIO_INITIAL_RTO, blk, 8, NULL, 0); CHECKF(r.rc == 0, "%s len 8: rc %d err %d", n, r.rc, r.err); }
        { BYTE out[16]; xt_res r = xt_io(st.s, XT_SIO_INITIAL_RTO, blk, 3, out, sizeof out); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEFAULT, "%s len 3 with output", n); }
        xt_rmstate(&st);
    }
}
TEST(initial_rto_refused_on_every_connected_state)
{
    static const int kinds[] = {XS_CLIENT, XS_ACCEPTED, XS_SHUT_SEND, XS_PEER_CLOSED, XS_ACC_PEER_CLOSED};
    unsigned k, len;
    NEED();
    for (k = 0; k < 5; k++) {
        xt_st st; const char *n = xt_state_name[kinds[k]]; BYTE blk[8] = {100, 0, 3, 0, 0, 0, 0, 0};
        if (!xt_mkstate(kinds[k], &st)) { t_skip("setup %s", n); return; }
        for (len = 0; len <= 8; len++) {
            xt_res r = xt_io(st.s, XT_SIO_INITIAL_RTO, blk, len, NULL, 0);
            CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEINVAL, "%s len %u: rc %d err %d", n, len, r.rc, r.err);
        }
        { xt_res r = xt_io(st.s, XT_SIO_INITIAL_RTO, NULL, 0, NULL, 0); CHECKF(r.rc == SOCKET_ERROR && r.err == WSAEINVAL, "%s NULL", n); }
        xt_rmstate(&st);
    }
}
TEST(initial_rto_udp_not_supported)
{
    SOCKET s; BYTE blk[4] = {100, 0, 3, 0}; xt_res r;
    NEED();
    s = xt_udp();
    r = xt_io(s, XT_SIO_INITIAL_RTO, blk, 4, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    r = xt_io(s, XT_SIO_INITIAL_RTO, blk, 2, NULL, 0); EQ(r.rc, SOCKET_ERROR); EQ(r.err, WSAEOPNOTSUPP);
    xt_close(s);
}
TEST(initial_rto_set_before_connect_does_not_disturb_a_loopback_connection)
{
    SOCKET l, c, a; u_short p; BYTE blk[4] = {200, 0, 1, 0}; char b[4];
    NEED();
    EQ(xt_listen_lo(&l, &p, 2), 1);
    c = xt_tcp();
    EQ(xt_io(c, XT_SIO_INITIAL_RTO, blk, 4, NULL, 0).rc, 0);
    EQ(xt_connect_lo(c, p), 0);
    CHECK(xt_readable(l, 3000)); a = xt_accept(l);
    EQ(xt_send(c, "rto!", 4), 4); EQ(xt_recv_all(a, b, 4, 3000), 4);
    EQ(xt_io(c, XT_SIO_INITIAL_RTO, blk, 4, NULL, 0).err, WSAEINVAL);
    xt_close(c); xt_close(a); xt_close(l);
}
