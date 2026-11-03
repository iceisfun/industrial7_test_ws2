/* IOCTL_AFD_GET_INFORMATION (0x1207b) and IOCTL_AFD_SET_INFORMATION (0x1203b).
 *
 * Both take a 16-byte record { ULONG class; ULONG pad; union { BOOLEAN; ULONG; LONGLONG } value } and
 * differ in direction: GET needs the record as input AND an output record of at least 16 bytes (it echoes
 * the class and fills the value, Information = 16); SET needs only the input record. Anything shorter than
 * 16 bytes is buffer-too-small, an unsupported class is invalid-parameter. Which classes each direction
 * accepts depends on the endpoint kind; the SET matrix is a status table over the seven endpoint kinds
 * (see sweep.c for the legend) and the GET behavior is pinned class by class.
 */
#include "aio.h"

static LONG get_raw(SOCKET s, ULONG cls, ULONG inlen, ULONG outlen, aio_info_t *out, IO_STATUS_BLOCK *io)
{
    unsigned char in[64], ob[64];
    aio_info_t rec;
    LONG st;
    memset(in, 0, sizeof in); memset(ob, 0, sizeof ob);
    memset(&rec, 0, sizeof rec); rec.Class = cls;
    memcpy(in, &rec, sizeof rec);
    st = aio_ctl(s, IOC_GET_INFO, inlen ? in : NULL, inlen, outlen ? ob : NULL, outlen, io, NULL);
    if (out) memcpy(out, ob, sizeof *out);
    return st;
}

/* ---- length protocol ---------------------------------------------------------------------------- */
#define GI_LEN_TEST(name, inl, outl, want) \
    TEST(aio_gi_##name) { AIO_BEGIN(); int k; \
        for (k = AK_TCP; k <= AK_UDP; k++) { SOCKET s = aio_kind(k); IO_STATUS_BLOCK io; \
            EXPECT_NTS(get_raw(s, AI_MAX_SEND_SIZE, inl, outl, NULL, &io), want); \
            aio_close(s); } }
GI_LEN_TEST(in0_out16, 0, 16, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in4_out16, 4, 16, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in8_out16, 8, 16, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in15_out16, 15, 16, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in16_out0, 16, 0, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in16_out4, 16, 4, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in16_out8, 16, 8, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in16_out15, 16, 15, NTS_BUFFER_TOO_SMALL)
GI_LEN_TEST(in16_out16, 16, 16, NTS_SUCCESS)
GI_LEN_TEST(in32_out32, 32, 32, NTS_SUCCESS)
GI_LEN_TEST(in16_out32, 16, 32, NTS_SUCCESS)
GI_LEN_TEST(in32_out16, 32, 16, NTS_SUCCESS)

TEST(aio_gi_success_reports_16_bytes)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    IO_STATUS_BLOCK io;
    aio_info_t o;
    EXPECT_NTS(get_raw(s, AI_RECEIVE_WINDOW, 16, 16, &o, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 16);
    EXPECT_EQ(o.Class, AI_RECEIVE_WINDOW);   /* the class is echoed */
    EXPECT_EQ(o.Pad0, 0);
    aio_close(s);
}
TEST(aio_gi_larger_buffers_still_report_16_bytes)
{
    AIO_BEGIN();
    SOCKET s = aio_udp();
    IO_STATUS_BLOCK io;
    EXPECT_NTS(get_raw(s, AI_SEND_WINDOW, 32, 48, NULL, &io), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 16);
    aio_close(s);
}
TEST(aio_gi_failure_reports_no_output)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    IO_STATUS_BLOCK io;
    aio_info_t o;
    memset(&o, 0x77, sizeof o);
    EXPECT_NTS(get_raw(s, 99, 16, 16, &o, &io), NTS_INVALID_PARAMETER);
    EXPECT_EQ(io.Information, 0);
    aio_close(s);
}
TEST(aio_gi_input_padding_and_value_are_ignored)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    aio_info_t in, out;
    IO_STATUS_BLOCK io;
    memset(&in, 0xee, sizeof in); in.Class = AI_SENDS_PENDING;
    memset(&out, 0, sizeof out);
    EXPECT_NTS(aio_ctl(s, IOC_GET_INFO, &in, 16, &out, 16, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(out.Class, AI_SENDS_PENDING);
    EXPECT_EQ(out.V.Large, 0);
    aio_close(s);
}
TEST(aio_gi_in_place_buffer)
{
    /* the same 16 bytes serve as input and output */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    aio_info_t io_rec;
    memset(&io_rec, 0, sizeof io_rec); io_rec.Class = AI_MAX_PATH_SEND;
    EXPECT_NTS(aio_ctl(s, IOC_GET_INFO, &io_rec, 16, &io_rec, 16, NULL, NULL), NTS_SUCCESS);
    EXPECT_EQ(io_rec.Class, AI_MAX_PATH_SEND);
    EXPECT_EQ(io_rec.V.Ulong, 0xffffffffu);
    aio_close(s);
}

/* ---- unsupported classes ------------------------------------------------------------------------- */
/* GET knows classes 3..8, 10 and 14; SET's inline-mode (1), nonblocking (2) and circular-queue style
 * classes are not readable back. */
static const ULONG g_unknown_get[] = { 0, 1, 2, 9, 11, 12, 13, 15, 16, 17, 31, 255, 0x100, 0x10000, 0xfffffffe, 0xffffffff };
TEST(aio_gi_unsupported_classes_all_kinds)
{
    AIO_BEGIN();
    int k; unsigned i;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        for (i = 0; i < sizeof g_unknown_get / sizeof g_unknown_get[0]; i++) {
            IO_STATUS_BLOCK io;
            LONG st = get_raw(s, g_unknown_get[i], 16, 16, NULL, &io);
            t_check(st == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "unsupported class", "%s class %lu: got 0x%08lx", aio_kind_name[k], (unsigned long)g_unknown_get[i], (unsigned long)st);
            CHECK(io.Information == 0);
        }
        aio_close(s);
    }
}
#define GI_BAD_CLASS(n, c) TEST(aio_gi_class_##n##_unsupported) { AIO_BEGIN(); SOCKET s = aio_tcp(); \
    EXPECT_NTS(get_raw(s, c, 16, 16, NULL, NULL), NTS_INVALID_PARAMETER); aio_close(s); }
GI_BAD_CLASS(0, 0)
GI_BAD_CLASS(inline_mode, AI_INLINE_MODE)
GI_BAD_CLASS(nonblocking, AI_NONBLOCKING)
GI_BAD_CLASS(circular_queue, AI_CIRCULAR_QUEUE)
GI_BAD_CLASS(report_unreach, AI_REPORT_UNREACH)
GI_BAD_CLASS(12, 12)
GI_BAD_CLASS(13, 13)

/* ---- per-class values --------------------------------------------------------------------------- */
static ULONG gi_u32(int kind, ULONG cls, LONG *st)
{
    SOCKET s = aio_kind(kind);
    aio_info_t o;
    if (s == INVALID_SOCKET) { *st = 0x7eadbeef; return 0; }
    *st = aio_get_info(s, cls, &o);
    aio_close(s);
    return o.V.Ulong;
}

/* The largest single send: unlimited for streams, the IPv4 datagram payload limit for UDP and raw. */
TEST(aio_gi_max_send_size_tcp) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_TCP, AI_MAX_SEND_SIZE, &st); EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 0xffffffffu); }
TEST(aio_gi_max_send_size_udp) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_UDP, AI_MAX_SEND_SIZE, &st); EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 65507); }
TEST(aio_gi_max_send_size_raw) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_RAW, AI_MAX_SEND_SIZE, &st); if (st == 0x7eadbeef) { t_skip("raw socket unavailable"); return; } EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 65515); }
TEST(aio_gi_max_send_size_tcp_bound) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_TCP_BOUND, AI_MAX_SEND_SIZE, &st); EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 0xffffffffu); }
TEST(aio_gi_max_send_size_tcp_listening) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_TCP_LISTEN, AI_MAX_SEND_SIZE, &st); EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 0xffffffffu); }
TEST(aio_gi_max_send_size_tcp_connected) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_TCP_CONN, AI_MAX_SEND_SIZE, &st); EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 0xffffffffu); }
TEST(aio_gi_max_send_size_udp_bound) { AIO_BEGIN(); LONG st; ULONG v = gi_u32(AK_UDP_BOUND, AI_MAX_SEND_SIZE, &st); EXPECT_NTS(st, NTS_SUCCESS); EXPECT_EQ(v, 65507); }
TEST(aio_gi_max_send_size_matches_getsockopt)
{
    /* SO_MAX_MSG_SIZE reports the same limit through the provider */
    AIO_BEGIN();
    SOCKET s = aio_udp();
    int v = 0, n = sizeof v;
    aio_info_t o;
    EXPECT_NTS(aio_get_info(s, AI_MAX_SEND_SIZE, &o), NTS_SUCCESS);
    CHECK(W.getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&v, &n) == 0);
    EXPECT_EQ((ULONG)v, o.V.Ulong);
    aio_close(s);
}

/* The path variant is the same number on an endpoint with no route information. */
TEST(aio_gi_max_path_send_size_equals_max_send_size)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        aio_info_t a, b;
        if (s == INVALID_SOCKET) continue;
        EXPECT_NTS(aio_get_info(s, AI_MAX_SEND_SIZE, &a), NTS_SUCCESS);
        EXPECT_NTS(aio_get_info(s, AI_MAX_PATH_SEND, &b), NTS_SUCCESS);
        EXPECT_EQ(a.V.Ulong, b.V.Ulong);
        aio_close(s);
    }
}
TEST(aio_gi_sends_pending_is_zero_on_idle_endpoints)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        aio_info_t o;
        if (s == INVALID_SOCKET) continue;
        EXPECT_NTS(aio_get_info(s, AI_SENDS_PENDING, &o), NTS_SUCCESS);
        EXPECT_EQ(o.V.Large, 0);
        aio_close(s);
    }
}
TEST(aio_gi_sends_pending_zero_after_completed_send)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    aio_pair(&c, &s);
    CHECK(W.send(c, "abc", 3, 0) == 3);
    EXPECT_NTS(aio_get_info(c, AI_SENDS_PENDING, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Large, 0);
    aio_close(c); aio_close(s);
}

/* The window sizes are configuration-dependent defaults; what is fixed is that both exist, are identical
 * across endpoint kinds and are non-zero. */
TEST(aio_gi_receive_window_default_nonzero_and_uniform)
{
    AIO_BEGIN();
    int k; ULONG first = 0;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        aio_info_t o;
        if (s == INVALID_SOCKET) continue;
        EXPECT_NTS(aio_get_info(s, AI_RECEIVE_WINDOW, &o), NTS_SUCCESS);
        CHECK(o.V.Ulong != 0);
        if (!first) first = o.V.Ulong;
        else if (k != AK_TCP_CONN) EXPECT_EQ(o.V.Ulong, first);
        aio_close(s);
    }
    t_note("default receive window = %lu", (unsigned long)first);
}
TEST(aio_gi_send_window_default_nonzero_and_uniform)
{
    AIO_BEGIN();
    int k; ULONG first = 0;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        aio_info_t o;
        if (s == INVALID_SOCKET || k == AK_TCP_CONN) { aio_close(s); continue; }
        EXPECT_NTS(aio_get_info(s, AI_SEND_WINDOW, &o), NTS_SUCCESS);
        CHECK(o.V.Ulong != 0);
        if (!first) first = o.V.Ulong;
        else EXPECT_EQ(o.V.Ulong, first);
        aio_close(s);
    }
    t_note("default send window = %lu", (unsigned long)first);
}
TEST(aio_gi_connect_time_not_connected_is_all_ones)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s;
        aio_info_t o;
        if (k == AK_TCP_CONN) continue;
        s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        EXPECT_NTS(aio_get_info(s, AI_CONNECT_TIME, &o), NTS_SUCCESS);
        t_check(o.V.Ulong == 0xffffffffu, __FILE__, __LINE__, "unconnected connect time", "%s: 0x%lx", aio_kind_name[k], (unsigned long)o.V.Ulong);
        aio_close(s);
    }
}
TEST(aio_gi_connect_time_connected_counts_seconds)
{
    /* seconds since the connection was established: small right after connect, and never decreasing */
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t a, b;
    aio_pair(&c, &s);
    EXPECT_NTS(aio_get_info(c, AI_CONNECT_TIME, &a), NTS_SUCCESS);
    CHECK(a.V.Ulong < 30);
    EXPECT_NTS(aio_get_info(s, AI_CONNECT_TIME, &b), NTS_SUCCESS);
    CHECK(b.V.Ulong < 30);
    aio_close(c); aio_close(s);
}
TEST(aio_gi_connect_time_on_accepted_endpoint)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    aio_pair(&c, &s);
    EXPECT_NTS(aio_get_info(s, AI_CONNECT_TIME, &o), NTS_SUCCESS);
    CHECK(o.V.Ulong != 0xffffffffu);
    aio_close(c); aio_close(s);
}
TEST(aio_gi_connect_time_resets_after_close_of_peer_is_still_connected_value)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    aio_pair(&c, &s);
    aio_close(s);
    EXPECT_NTS(aio_get_info(c, AI_CONNECT_TIME, &o), NTS_SUCCESS);
    CHECK(o.V.Ulong < 30);   /* the peer closing does not make the local endpoint unconnected */
    aio_close(c);
}
TEST(aio_gi_group_id_and_type_zero_for_ungrouped)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        aio_info_t o;
        if (s == INVALID_SOCKET) continue;
        EXPECT_NTS(aio_get_info(s, AI_GROUP_ID_TYPE, &o), NTS_SUCCESS);
        EXPECT_EQ(o.V.Large, 0);
        aio_close(s);
    }
}

/* Delivery status needs a transport-bound endpoint: a bound datagram socket or a connected stream. */
TEST(aio_gi_delivery_status_unbound_endpoints_refused)
{
    AIO_BEGIN();
    static const int kinds[] = { AK_TCP, AK_UDP, AK_RAW, AK_TCP_BOUND, AK_TCP_LISTEN };
    unsigned i;
    for (i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        SOCKET s = aio_kind(kinds[i]);
        aio_info_t o;
        if (s == INVALID_SOCKET) continue;
        t_check(aio_get_info(s, AI_DELIVERY_STATUS, &o) == NTS_INVALID_DEVICE_REQ, __FILE__, __LINE__, "delivery status refused", "%s", aio_kind_name[kinds[i]]);
        aio_close(s);
    }
}
TEST(aio_gi_delivery_status_bound_udp)
{
    AIO_BEGIN();
    SOCKET s = aio_bound(SOCK_DGRAM);
    aio_info_t o;
    EXPECT_NTS(aio_get_info(s, AI_DELIVERY_STATUS, &o), NTS_SUCCESS);
    EXPECT_EQ(o.Class, AI_DELIVERY_STATUS);
    EXPECT_EQ(o.V.Large, 0);
    aio_close(s);
}
TEST(aio_gi_delivery_status_connected_tcp)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    aio_pair(&c, &s);
    EXPECT_NTS(aio_get_info(c, AI_DELIVERY_STATUS, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Large, 0);   /* nothing undelivered while the peer is up */
    aio_close(c); aio_close(s);
}

TEST(aio_gi_delivery_status_changes_after_peer_closes)
{
    /* once the peer has closed, the stream reports a non-zero delivery status */
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    DWORD t0 = GetTickCount();
    aio_pair(&c, &s);
    aio_close(s);
    do {
        EXPECT_NTS(aio_get_info(c, AI_DELIVERY_STATUS, &o), NTS_SUCCESS);
        if (o.V.Large) break;
        Sleep(10);
    } while (GetTickCount() - t0 < 3000);
    CHECK(o.V.Large != 0);
    t_note("delivery status after the peer closed: %lld", (long long)o.V.Large);
    aio_close(c);
}

/* ---- SET_INFORMATION: length protocol ---------------------------------------------------------- */
static LONG set_raw(SOCKET s, ULONG cls, ULONGLONG val, ULONG inlen)
{
    unsigned char in[64];
    aio_info_t rec;
    memset(in, 0, sizeof in);
    memset(&rec, 0, sizeof rec); rec.Class = cls; rec.V.Large = (LONGLONG)val;
    memcpy(in, &rec, sizeof rec);
    return aio_ctl(s, IOC_SET_INFO, inlen ? in : NULL, inlen, NULL, 0, NULL, NULL);
}
#define SI_LEN_TEST(name, len, want) \
    TEST(aio_si_##name) { AIO_BEGIN(); int k; \
        for (k = AK_TCP; k <= AK_UDP; k++) { SOCKET s = aio_kind(k); \
            EXPECT_NTS(set_raw(s, AI_NONBLOCKING, 1, len), want); aio_close(s); } }
SI_LEN_TEST(in0, 0, NTS_BUFFER_TOO_SMALL)
SI_LEN_TEST(in1, 1, NTS_BUFFER_TOO_SMALL)
SI_LEN_TEST(in4, 4, NTS_BUFFER_TOO_SMALL)
SI_LEN_TEST(in8, 8, NTS_BUFFER_TOO_SMALL)
SI_LEN_TEST(in12, 12, NTS_BUFFER_TOO_SMALL)
SI_LEN_TEST(in15, 15, NTS_BUFFER_TOO_SMALL)
SI_LEN_TEST(in16, 16, NTS_SUCCESS)
SI_LEN_TEST(in17, 17, NTS_SUCCESS)
SI_LEN_TEST(in64, 64, NTS_SUCCESS)

TEST(aio_si_length_checked_before_class)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    EXPECT_NTS(set_raw(s, 99, 0, 8), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(set_raw(s, 99, 0, 16), NTS_INVALID_PARAMETER);
    aio_close(s);
}
TEST(aio_si_output_buffer_is_ignored)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    aio_info_t in; unsigned char out[32];
    memset(&in, 0, sizeof in); in.Class = AI_NONBLOCKING; in.V.Ulong = 1;
    memset(out, 0x5a, sizeof out);
    EXPECT_NTS(aio_ctl(s, IOC_SET_INFO, &in, 16, out, 32, NULL, NULL), NTS_SUCCESS);
    CHECK(out[0] == 0x5a);   /* nothing is written back */
    aio_close(s);
}
TEST(aio_si_information_is_zero)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    aio_info_t in; IO_STATUS_BLOCK io;
    memset(&in, 0, sizeof in); in.Class = AI_NONBLOCKING;
    EXPECT_NTS(aio_ctl(s, IOC_SET_INFO, &in, 16, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    aio_close(s);
}

/* ---- SET_INFORMATION class matrix -------------------------------------------------------------- */
/* One string per endpoint kind (tcp udp raw tcp-bound tcp-listening udp-bound tcp-connected), the value
 * written is 1. Letters as in sweep.c; I = invalid-device-state (0xC0000184). */
static LONG si_letter(char c)
{
    switch (c) {
    case 'S': return NTS_SUCCESS;
    case 'P': return NTS_INVALID_PARAMETER;
    case 'I': return (LONG)0xC0000184;
    case 'N': return NTS_NOT_SUPPORTED;
    }
    return 0x7eadbeef;
}
static void si_class(ULONG cls, const char *row)
{
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        LONG st, want = si_letter(row[k]);
        if (s == INVALID_SOCKET) continue;
        st = set_raw(s, cls, 1, 16);
        t_check(st == want, __FILE__, __LINE__, "SET_INFORMATION status", "class %lu on %s: got 0x%08lx want 0x%08lx", (unsigned long)cls, aio_kind_name[k], (unsigned long)st, (unsigned long)want);
        aio_close(s);
    }
}
/*           class  tcp     udp  raw  tcp-bound  tcp-listen  udp-bound  tcp-conn */
#define SI_ROWS(X) \
    X(0,  "PPPPPPP") \
    X(1,  "SPPSSPS") \
    X(2,  "SSSSSSS") \
    X(3,  "PPPPPPP") \
    X(4,  "PPPPPPP") \
    X(5,  "PPPPPPP") \
    X(6,  "SSSSSSS") \
    X(7,  "SSSSSSS") \
    X(8,  "PPPPPPP") \
    X(9,  "PSSPPSP") \
    X(10, "PPPPPPP") \
    X(11, "PSSPPSP") \
    X(12, "PSSPPSP") \
    X(13, "PPPPPPP") \
    X(14, "PPPPPPP") \
    X(15, "IIIIISS") \
    X(16, "PPPPPPP") \
    X(17, "PPPPPPP")
#define X(c, row) TEST(aio_si_class_##c##_matrix) { AIO_BEGIN(); si_class(c, row); }
SI_ROWS(X)
#undef X
TEST(aio_si_unknown_classes_invalid_parameter)
{
    AIO_BEGIN();
    static const ULONG cls[] = { 18, 19, 31, 64, 255, 256, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff };
    unsigned i;
    SOCKET s = aio_tcp(), u = aio_udp();
    for (i = 0; i < sizeof cls / sizeof cls[0]; i++) {
        t_check(set_raw(s, cls[i], 1, 16) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "tcp unknown class", "class 0x%lx", (unsigned long)cls[i]);
        t_check(set_raw(u, cls[i], 1, 16) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "udp unknown class", "class 0x%lx", (unsigned long)cls[i]);
    }
    aio_close(s); aio_close(u);
}
TEST(aio_si_class_value_does_not_change_status)
{
    /* values are not validated for the flag-like classes */
    AIO_BEGIN();
    static const ULONGLONG vals[] = { 0, 1, 2, 0xff, 0x100, 0xffffffffull, 0x100000000ull, 0xffffffffffffffffull };
    unsigned i;
    SOCKET s = aio_tcp();
    for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        t_check(set_raw(s, AI_NONBLOCKING, vals[i], 16) == NTS_SUCCESS, __FILE__, __LINE__, "nonblocking value", "0x%llx", vals[i]);
        t_check(set_raw(s, AI_INLINE_MODE, vals[i], 16) == NTS_SUCCESS, __FILE__, __LINE__, "inline value", "0x%llx", vals[i]);
        t_check(set_raw(s, AI_RECEIVE_WINDOW, vals[i], 16) == NTS_SUCCESS, __FILE__, __LINE__, "recv window value", "0x%llx", vals[i]);
        t_check(set_raw(s, AI_SEND_WINDOW, vals[i], 16) == NTS_SUCCESS, __FILE__, __LINE__, "send window value", "0x%llx", vals[i]);
    }
    aio_close(s);
}

/* ---- SET then GET round trips ------------------------------------------------------------------ */
TEST(aio_si_send_window_round_trip_on_connected_stream)
{
    AIO_BEGIN();
    static const ULONG vals[] = { 1, 0x1234, 0x4000, 0x20000, 0x7fffffff };
    unsigned i;
    SOCKET c, s;
    aio_pair(&c, &s);
    for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        aio_info_t o;
        EXPECT_NTS(set_raw(c, AI_SEND_WINDOW, vals[i], 16), NTS_SUCCESS);
        EXPECT_NTS(aio_get_info(c, AI_SEND_WINDOW, &o), NTS_SUCCESS);
        t_check(o.V.Ulong == vals[i], __FILE__, __LINE__, "send window read back", "set 0x%lx got 0x%lx", (unsigned long)vals[i], (unsigned long)o.V.Ulong);
    }
    aio_close(c); aio_close(s);
}
TEST(aio_si_send_window_zero_reads_back_zero_on_connected_stream)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    aio_pair(&c, &s);
    EXPECT_NTS(set_raw(c, AI_SEND_WINDOW, 0, 16), NTS_SUCCESS);
    EXPECT_NTS(aio_get_info(c, AI_SEND_WINDOW, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Ulong, 0);
    aio_close(c); aio_close(s);
}
TEST(aio_si_send_window_uses_low_32_bits)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    aio_pair(&c, &s);
    EXPECT_NTS(set_raw(c, AI_SEND_WINDOW, 0x100000000ull + 0x4321, 16), NTS_SUCCESS);
    EXPECT_NTS(aio_get_info(c, AI_SEND_WINDOW, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Ulong, 0x4321);
    aio_close(c); aio_close(s);
}
TEST(aio_si_send_window_on_peer_is_independent)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t a, b;
    aio_pair(&c, &s);
    EXPECT_NTS(aio_get_info(s, AI_SEND_WINDOW, &a), NTS_SUCCESS);
    EXPECT_NTS(set_raw(c, AI_SEND_WINDOW, 0x2468, 16), NTS_SUCCESS);
    EXPECT_NTS(aio_get_info(s, AI_SEND_WINDOW, &b), NTS_SUCCESS);
    EXPECT_EQ(a.V.Ulong, b.V.Ulong);
    aio_close(c); aio_close(s);
}
TEST(aio_si_windows_on_unconnected_do_not_change_reported_defaults)
{
    /* an endpoint that is not connected keeps reporting the system default */
    AIO_BEGIN();
    int k;
    for (k = AK_TCP; k <= AK_UDP; k++) {
        SOCKET s = aio_kind(k);
        aio_info_t before, after;
        EXPECT_NTS(aio_get_info(s, AI_SEND_WINDOW, &before), NTS_SUCCESS);
        EXPECT_NTS(set_raw(s, AI_SEND_WINDOW, 0x1234, 16), NTS_SUCCESS);
        EXPECT_NTS(aio_get_info(s, AI_SEND_WINDOW, &after), NTS_SUCCESS);
        EXPECT_EQ(before.V.Ulong, after.V.Ulong);
        EXPECT_NTS(aio_get_info(s, AI_RECEIVE_WINDOW, &before), NTS_SUCCESS);
        EXPECT_NTS(set_raw(s, AI_RECEIVE_WINDOW, 0x1234, 16), NTS_SUCCESS);
        EXPECT_NTS(aio_get_info(s, AI_RECEIVE_WINDOW, &after), NTS_SUCCESS);
        EXPECT_EQ(before.V.Ulong, after.V.Ulong);
        aio_close(s);
    }
}
TEST(aio_si_failed_set_leaves_state)
{
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t a, b;
    aio_pair(&c, &s);
    EXPECT_NTS(set_raw(c, AI_SEND_WINDOW, 0x3000, 16), NTS_SUCCESS);
    EXPECT_NTS(set_raw(c, 99, 0x9999, 16), NTS_INVALID_PARAMETER);
    EXPECT_NTS(set_raw(c, AI_SEND_WINDOW, 0x9999, 8), NTS_BUFFER_TOO_SMALL);
    EXPECT_NTS(aio_get_info(c, AI_SEND_WINDOW, &a), NTS_SUCCESS);
    EXPECT_EQ(a.V.Ulong, 0x3000);
    (void)b;
    aio_close(c); aio_close(s);
}
TEST(aio_si_socket_options_set_the_windows_through_the_provider)
{
    /* SO_SNDBUF on a connected stream is carried to the endpoint as the send window */
    AIO_BEGIN();
    SOCKET c, s;
    aio_info_t o;
    int v = 0x5000;
    aio_pair(&c, &s);
    CHECK(W.setsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *)&v, sizeof v) == 0);
    EXPECT_NTS(aio_get_info(c, AI_SEND_WINDOW, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Ulong, 0x5000);
    aio_close(c); aio_close(s);
}

/* ---- inline mode: OOB data delivered with the normal stream --------------------------------- */
static int recv_all_for(SOCKET s, char *buf, int cap, int want, int ms)
{
    int got = 0;
    DWORD t0 = GetTickCount();
    aio_nonblock(s, 1);
    while (got < want && GetTickCount() - t0 < (DWORD)ms) {
        int n = W.recv(s, buf + got, cap - got, 0);
        if (n > 0) got += n;
        else if (n == 0) break;
        else Sleep(10);
    }
    return got;
}
TEST(aio_si_inline_mode_delivers_urgent_byte_in_stream)
{
    AIO_BEGIN();
    SOCKET c, s;
    char buf[16];
    int got;
    aio_pair(&c, &s);
    EXPECT_NTS(set_raw(s, AI_INLINE_MODE, 1, 16), NTS_SUCCESS);
    CHECK(W.send(c, "X", 1, MSG_OOB) == 1);
    CHECK(W.send(c, "N", 1, 0) == 1);
    memset(buf, 0, sizeof buf);
    got = recv_all_for(s, buf, sizeof buf, 2, 3000);
    EXPECT_EQ(got, 2);
    CHECK(!memcmp(buf, "XN", 2));
    aio_close(c); aio_close(s);
}
TEST(aio_si_inline_mode_off_keeps_urgent_byte_out_of_stream)
{
    AIO_BEGIN();
    SOCKET c, s;
    char buf[16];
    int got;
    aio_pair(&c, &s);
    CHECK(W.send(c, "X", 1, MSG_OOB) == 1);
    CHECK(W.send(c, "N", 1, 0) == 1);
    memset(buf, 0, sizeof buf);
    got = recv_all_for(s, buf, sizeof buf, 2, 700);
    EXPECT_EQ(got, 1);
    CHECK(buf[0] == 'N');
    aio_close(c); aio_close(s);
}
TEST(aio_si_inline_mode_set_then_cleared)
{
    AIO_BEGIN();
    SOCKET c, s;
    char buf[16];
    int got;
    aio_pair(&c, &s);
    EXPECT_NTS(set_raw(s, AI_INLINE_MODE, 1, 16), NTS_SUCCESS);
    EXPECT_NTS(set_raw(s, AI_INLINE_MODE, 0, 16), NTS_SUCCESS);
    CHECK(W.send(c, "X", 1, MSG_OOB) == 1);
    CHECK(W.send(c, "N", 1, 0) == 1);
    memset(buf, 0, sizeof buf);
    got = recv_all_for(s, buf, sizeof buf, 2, 700);
    EXPECT_EQ(got, 1);
    aio_close(c); aio_close(s);
}
TEST(aio_si_oobinline_option_sets_inline_mode_in_the_provider)
{
    AIO_BEGIN();
    SOCKET c, s;
    char buf[16];
    int got, on = 1;
    aio_pair(&c, &s);
    CHECK(W.setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof on) == 0);
    CHECK(W.send(c, "X", 1, MSG_OOB) == 1);
    CHECK(W.send(c, "N", 1, 0) == 1);
    memset(buf, 0, sizeof buf);
    got = recv_all_for(s, buf, sizeof buf, 2, 3000);
    EXPECT_EQ(got, 2);
    aio_close(c); aio_close(s);
}
