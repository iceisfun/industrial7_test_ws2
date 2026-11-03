/* Connect and disconnect data / options control codes, one literal code per row:
 *   set  0x1204b data  0x1204f options  0x12053 disc data  0x12057 disc options
 *   get  0x1205b data  0x1205f options  0x12063 disc data  0x12067 disc options
 *   size 0x1206b data  0x1206f options  0x12073 disc data  0x12077 disc options
 * The stream transport carries no connection-setup data, so the requests are validated and then the bytes
 * go nowhere. What is measured: which endpoint kinds accept each form, the sizes at which input and output
 * buffers are refused, how the optional 12-byte sequence record picks a queued connection on a listening
 * endpoint, and what a get reports. */
#include "g5.h"

typedef struct { const char *name; ULONG code; } row_t;
static const row_t k_set[] = { { "connect_data", 0x1204b }, { "connect_options", 0x1204f }, { "disconnect_data", 0x12053 }, { "disconnect_options", 0x12057 } };
static const row_t k_get[] = { { "connect_data", 0x1205b }, { "connect_options", 0x1205f }, { "disconnect_data", 0x12063 }, { "disconnect_options", 0x12067 } };
static const row_t k_size[] = { { "connect_data", 0x1206b }, { "connect_options", 0x1206f }, { "disconnect_data", 0x12073 }, { "disconnect_options", 0x12077 } };

enum { K_OPEN, K_BOUND, K_LISTEN, K_CONN, K_UDP, K_UDPB, K_COUNT };
static const char *const kname[K_COUNT] = { "open", "bound", "listening", "connected", "udp", "udp-bound" };
static SOCKET mk(int k, SOCKET *peer)
{
    SOCKET s = INVALID_SOCKET, p;
    *peer = INVALID_SOCKET;
    switch (k) {
    case K_OPEN: return g5_tcp();
    case K_BOUND: return g5_bound(SOCK_STREAM, NULL);
    case K_LISTEN: return g5_listener(NULL);
    case K_CONN: g5_pair(&s, &p); *peer = p; return s;
    case K_UDP: return g5_udp();
    case K_UDPB: return g5_bound(SOCK_DGRAM, NULL);
    }
    return s;
}
static int is_stream(int k) { return k <= K_CONN; }
static void done(SOCKET s, SOCKET p) { g5_close(s); g5_close(p); }

TEST(gap5_connopt_set_stream_kinds_accept_any_size)
{
    G5_BEGIN();
    static const ULONG sizes[] = { 0, 1, 8, 0x100, 0x101, 0x400 };
    for (int r = 0; r < 4; r++) for (int k = 0; k < K_COUNT; k++) {
        if (!is_stream(k)) continue;
        for (int i = 0; i < 6; i++) {
            SOCKET p, s = mk(k, &p); static unsigned char d[0x400];
            IO_STATUS_BLOCK io;
            memset(d, 0x5a, sizeof d);
            LONG st = g5_ctl(S(s), k_set[r].code, NULL, 0, sizes[i] ? d : NULL, sizes[i], &io, NULL);
            t_check(st == ST_SUCCESS, __FILE__, __LINE__, "set", "%s on %s, %lu bytes: 0x%08lx", k_set[r].name, kname[k], (unsigned long)sizes[i], (unsigned long)st);
            if (st == ST_SUCCESS) EXPECT_EQ(io.Information, 0);
            done(s, p);
        }
    }
}
TEST(gap5_connopt_set_datagram_kinds_refused)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) for (int k = K_UDP; k <= K_UDPB; k++) {
        SOCKET p, s = mk(k, &p); unsigned char d[8] = { 1 };
        LONG a = g5_ctl(S(s), k_set[r].code, NULL, 0, d, 8, NULL, NULL), b = g5_ctl(S(s), k_set[r].code, NULL, 0, NULL, 0, NULL, NULL);
        t_check(a == ST_INVALID_PARAMETER && b == ST_INVALID_PARAMETER, __FILE__, __LINE__, "set refused", "%s on %s: 0x%08lx 0x%08lx", k_set[r].name, kname[k], (unsigned long)a, (unsigned long)b);
        done(s, p);
    }
}
TEST(gap5_connopt_set_record_shorter_than_12_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 1, 4, 8, 11 };
    for (int r = 0; r < 4; r++) for (int i = 0; i < 4; i++) {
        SOCKET p, s = mk(K_LISTEN, &p); unsigned char in[16] = { 0 }, d[8] = { 1 };
        LONG st = g5_ctl(S(s), k_set[r].code, in, lens[i], d, 8, NULL, NULL);
        t_check(st == ST_INVALID_PARAMETER, __FILE__, __LINE__, "short record", "%s, %lu bytes: 0x%08lx", k_set[r].name, (unsigned long)lens[i], (unsigned long)st);
        done(s, p);
    }
}
TEST(gap5_connopt_set_record_without_such_connection_refused)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) for (int k = 0; k < K_COUNT; k++) {
        if (!is_stream(k)) continue;
        SOCKET p, s = mk(k, &p); unsigned char in[12] = { 0 }, d[8] = { 1 };
        in[0] = 0x77;
        LONG st = g5_ctl(S(s), k_set[r].code, in, 12, d, 8, NULL, NULL);
        t_check(st == ST_INVALID_PARAMETER, __FILE__, __LINE__, "unknown sequence", "%s on %s: 0x%08lx", k_set[r].name, kname[k], (unsigned long)st);
        done(s, p);
    }
}
TEST(gap5_connopt_set_record_selects_queued_connection)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        struct sockaddr_in a; SOCKET l = g5_bound(SOCK_STREAM, &a), c; ULONG seq = 0; unsigned char in[12] = { 0 }, d[8] = { 1 };
        EXPECT_NTS(g5_raw_listen(l, 4, 0), ST_SUCCESS);
        c = g5_connect_nb(&a);
        EXPECT_NTS(g5_wait_listen(l, 0x1200c, &seq, NULL), ST_SUCCESS);
        memcpy(in, &seq, 4);
        EXPECT_NTSV(g5_ctl(S(l), k_set[r].code, in, 12, d, 8, NULL, NULL), ST_SUCCESS, k_set[r].name);
        in[0] ^= 0x55;
        EXPECT_NTSV(g5_ctl(S(l), k_set[r].code, in, 12, d, 8, NULL, NULL), ST_INVALID_PARAMETER, "other sequence");
        g5_close(c); g5_close(l);
    }
}

TEST(gap5_connopt_get_stream_kinds_report_nothing_stored)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) for (int k = 0; k < K_COUNT; k++) {
        SOCKET p, s = mk(k, &p); unsigned char d[0x100]; IO_STATUS_BLOCK io;
        memset(d, 0x5a, sizeof d);
        LONG st = g5_ctl(S(s), k_get[r].code, NULL, 0, d, sizeof d, &io, NULL);
        t_check(st == ST_SUCCESS && io.Information == 0 && d[0] == 0x5a, __FILE__, __LINE__, "get empty", "%s on %s: 0x%08lx info %llu", k_get[r].name, kname[k], (unsigned long)st, (unsigned long long)io.Information);
        done(s, p);
    }
}
TEST(gap5_connopt_get_without_buffers_succeeds)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        SOCKET s = g5_tcp(); IO_STATUS_BLOCK io;
        EXPECT_NTSV(g5_ctl(S(s), k_get[r].code, NULL, 0, NULL, 0, &io, NULL), ST_SUCCESS, k_get[r].name);
        EXPECT_EQ(io.Information, 0);
        g5_close(s);
    }
}
TEST(gap5_connopt_get_record_shorter_than_12_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 1, 4, 11 };
    for (int r = 0; r < 4; r++) for (int i = 0; i < 3; i++) for (int k = 0; k < K_COUNT; k++) {
        SOCKET p, s = mk(k, &p); unsigned char in[16] = { 0 }, o[16];
        LONG st = g5_ctl(S(s), k_get[r].code, in, lens[i], o, sizeof o, NULL, NULL);
        t_check(st == ST_INVALID_PARAMETER, __FILE__, __LINE__, "short record", "%s on %s, %lu: 0x%08lx", k_get[r].name, kname[k], (unsigned long)lens[i], (unsigned long)st);
        done(s, p);
    }
}
TEST(gap5_connopt_get_record_without_such_connection_refused)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) for (int k = 0; k < K_COUNT; k++) {
        SOCKET p, s = mk(k, &p); unsigned char in[16] = { 0 }, o[16];
        in[0] = 0x66;
        LONG st = g5_ctl(S(s), k_get[r].code, in, 12, o, sizeof o, NULL, NULL);
        t_check(st == ST_INVALID_PARAMETER, __FILE__, __LINE__, "unknown sequence", "%s on %s: 0x%08lx", k_get[r].name, kname[k], (unsigned long)st);
        done(s, p);
    }
}
TEST(gap5_connopt_get_record_on_queued_connection_is_empty)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        struct sockaddr_in a; SOCKET l = g5_bound(SOCK_STREAM, &a), c; ULONG seq = 0; unsigned char in[12] = { 0 }, o[32]; IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_raw_listen(l, 4, 0), ST_SUCCESS);
        c = g5_connect_nb(&a);
        EXPECT_NTS(g5_wait_listen(l, 0x1200c, &seq, NULL), ST_SUCCESS);
        memcpy(in, &seq, 4);
        memset(o, 0x5a, sizeof o);
        EXPECT_NTSV(g5_ctl(S(l), k_get[r].code, in, 12, o, sizeof o, &io, NULL), ST_SUCCESS, k_get[r].name);
        EXPECT_EQ(io.Information, 0);                          /* nothing arrived with the connection */
        CHECK(o[0] == 0x5a);
        g5_close(c); g5_close(l);
    }
}
TEST(gap5_connopt_get_after_set_still_empty)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        SOCKET s = g5_tcp(); unsigned char d[8] = { 9, 9, 9, 9, 9, 9, 9, 9 }, o[8]; IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_ctl(S(s), k_set[r].code, NULL, 0, d, 8, NULL, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(S(s), k_get[r].code, NULL, 0, o, 8, &io, NULL), ST_SUCCESS);
        EXPECT_EQ(io.Information, 0);                          /* what is set is for sending, what is got is what arrived */
        g5_close(s);
    }
}

TEST(gap5_connopt_size_stream_kinds_accept)
{
    G5_BEGIN();
    static const ULONG vals[] = { 0, 1, 0x40, 0x400 };
    for (int r = 0; r < 4; r++) for (int k = 0; k < K_COUNT; k++) {
        if (!is_stream(k)) continue;
        for (int i = 0; i < 4; i++) {
            SOCKET p, s = mk(k, &p); ULONG v = vals[i]; IO_STATUS_BLOCK io;
            LONG st = g5_ctl(S(s), k_size[r].code, NULL, 0, &v, 4, &io, NULL);
            t_check(st == ST_SUCCESS, __FILE__, __LINE__, "size", "%s on %s, %lu: 0x%08lx", k_size[r].name, kname[k], (unsigned long)vals[i], (unsigned long)st);
            done(s, p);
        }
    }
}
TEST(gap5_connopt_size_short_output_is_ignored_on_stream_endpoints)
{
    G5_BEGIN();
    /* the size value is only read where the transport keeps connection data; the endpoints Winsock
     * creates do not, so an output of any length (even one too short to hold the value) succeeds */
    for (int r = 0; r < 4; r++) for (ULONG n = 0; n < 4; n++) {
        SOCKET s = g5_tcp(); unsigned char v[4] = { 0x10, 0, 0, 0 };
        LONG st = g5_ctl(S(s), k_size[r].code, NULL, 0, n ? v : NULL, n, NULL, NULL);
        t_check(st == ST_SUCCESS, __FILE__, __LINE__, "short size record", "%s, %lu bytes: 0x%08lx", k_size[r].name, (unsigned long)n, (unsigned long)st);
        g5_close(s);
    }
}
TEST(gap5_connopt_size_datagram_kinds_refused)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) for (int k = K_UDP; k <= K_UDPB; k++) {
        SOCKET p, s = mk(k, &p); ULONG v = 0x40;
        LONG st = g5_ctl(S(s), k_size[r].code, NULL, 0, &v, 4, NULL, NULL);
        t_check(st == ST_INVALID_PARAMETER, __FILE__, __LINE__, "size refused", "%s on %s: 0x%08lx", k_size[r].name, kname[k], (unsigned long)st);
        done(s, p);
    }
}
TEST(gap5_connopt_size_input_only_form_refused)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        SOCKET s = g5_tcp(); ULONG v = 0x40;
        EXPECT_NTSV(g5_ctl(S(s), k_size[r].code, &v, 4, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER, k_size[r].name);
        g5_close(s);
    }
}
TEST(gap5_connopt_size_does_not_create_readable_data)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        SOCKET s = g5_tcp(); ULONG v = 0x40; unsigned char o[0x80]; IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_ctl(S(s), k_size[r].code, NULL, 0, &v, 4, NULL, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(S(s), k_get[r].code, NULL, 0, o, sizeof o, &io, NULL), ST_SUCCESS);
        EXPECT_EQ(io.Information, 0);
        g5_close(s);
    }
}
TEST(gap5_connopt_size_record_form_on_queued_connection)
{
    G5_BEGIN();
    for (int r = 0; r < 4; r++) {
        struct sockaddr_in a; SOCKET l = g5_bound(SOCK_STREAM, &a), c; ULONG seq = 0; unsigned char in[12] = { 0 }; ULONG v = 0x20;
        EXPECT_NTS(g5_raw_listen(l, 4, 0), ST_SUCCESS);
        c = g5_connect_nb(&a);
        EXPECT_NTS(g5_wait_listen(l, 0x1200c, &seq, NULL), ST_SUCCESS);
        memcpy(in, &seq, 4);
        EXPECT_NTSV(g5_ctl(S(l), k_size[r].code, in, 12, &v, 4, NULL, NULL), ST_SUCCESS, k_size[r].name);
        g5_close(c); g5_close(l);
    }
}
TEST(gap5_connopt_codes_do_not_alias_across_forms)
{
    G5_BEGIN();
    /* the twelve codes are distinct requests: the same endpoint answers them with their own shape */
    SOCKET s = g5_tcp(); unsigned char o[8] = { 0 }; ULONG v = 8; IO_STATUS_BLOCK io;
    for (int r = 0; r < 4; r++) {
        EXPECT_NTS(g5_ctl(S(s), k_set[r].code, NULL, 0, o, 8, &io, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(S(s), k_get[r].code, NULL, 0, o, 8, &io, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(S(s), k_size[r].code, NULL, 0, &v, 4, &io, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(S(s), k_size[r].code, o, 4, NULL, 0, &io, NULL), ST_INVALID_PARAMETER);   /* a size request has no input form */
        EXPECT_NTS(g5_ctl(S(s), k_set[r].code, NULL, 0, o, 3, &io, NULL), ST_SUCCESS);
    }
    g5_close(s);
}
TEST(gap5_connopt_directly_opened_endpoint_accepts_set_get_size)
{
    G5_BEGIN();
    LONG st; HANDLE h = g5_open_ep(EK_TCP4, 1, &st);
    if (!h) { t_skip("endpoint cannot be opened directly (0x%08lx)", (unsigned long)st); return; }
    unsigned char d[8] = { 1 }; ULONG v = 8; IO_STATUS_BLOCK io;
    for (int r = 0; r < 4; r++) {
        EXPECT_NTS(g5_ctl(h, k_set[r].code, NULL, 0, d, 8, NULL, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(h, k_get[r].code, NULL, 0, d, 8, &io, NULL), ST_SUCCESS);
        EXPECT_NTS(g5_ctl(h, k_size[r].code, NULL, 0, &v, 4, NULL, NULL), ST_SUCCESS);
    }
    g5_close_h(h);
}
