/* Connect / disconnect data and options (0x1204b .. 0x12077), the unaccepted-connection query (0x120a7)
 * and the quality-of-service pair (0x12094 / 0x12098).
 *
 * The data/option requests exist for transports that carry user data in connection setup; the TCP
 * transport used by every stream endpoint does not, so the requests are validated and then dropped:
 *  - SET_x with the bytes in the output buffer succeeds on stream endpoints and is invalid-parameter on
 *    datagram and raw ones; an input buffer (a connection sequence number) is only meaningful on a
 *    listening endpoint that has such a connection;
 *  - GET_x always succeeds with Information 0 (nothing is ever stored);
 *  - SIZE_x (reserve receive space) succeeds on stream endpoints and is invalid-parameter elsewhere.
 * Quality of service is a fixed 0x58-byte exchange.
 */
#include "aio.h"
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

static const struct { const char *name; ULONG code; } k_set[] = {
    { "connect_data", IOC_SET_CONN_DATA }, { "connect_options", IOC_SET_CONN_OPT },
    { "disconnect_data", IOC_SET_DISC_DATA }, { "disconnect_options", IOC_SET_DISC_OPT },
};
static const struct { const char *name; ULONG code; } k_get[] = {
    { "connect_data", IOC_GET_CONN_DATA }, { "connect_options", IOC_GET_CONN_OPT },
    { "disconnect_data", IOC_GET_DISC_DATA }, { "disconnect_options", IOC_GET_DISC_OPT },
};
static const struct { const char *name; ULONG code; } k_size[] = {
    { "connect_data", IOC_SIZE_CONN_DATA }, { "connect_options", IOC_SIZE_CONN_OPT },
    { "disconnect_data", IOC_SIZE_DISC_DATA }, { "disconnect_options", IOC_SIZE_DISC_OPT },
};

/* ---- SET ---------------------------------------------------------------------------------------- */
#define SET_TEST(i, nm) \
    TEST(aio_connopt_set_##nm##_stream_endpoints_accept_data) { AIO_BEGIN(); int k; \
        for (k = 0; k < AK_COUNT; k++) { SOCKET s; unsigned char d[0x180]; \
            if (k == AK_UDP || k == AK_RAW || k == AK_UDP_BOUND) continue; \
            s = aio_kind(k); if (s == INVALID_SOCKET) continue; memset(d, 0x5a, sizeof d); \
            t_check(aio_ctl(s, k_set[i].code, NULL, 0, d, 8, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "set data", "%s 8 bytes", aio_kind_name[k]); \
            t_check(aio_ctl(s, k_set[i].code, NULL, 0, d, 0x100, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "set data", "%s 256 bytes", aio_kind_name[k]); \
            t_check(aio_ctl(s, k_set[i].code, NULL, 0, d, 0x180, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "set data", "%s 384 bytes", aio_kind_name[k]); \
            t_check(aio_ctl(s, k_set[i].code, NULL, 0, NULL, 0, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "set data", "%s empty", aio_kind_name[k]); \
            aio_close(s); } } \
    TEST(aio_connopt_set_##nm##_datagram_and_raw_refused) { AIO_BEGIN(); int k; \
        for (k = AK_UDP; k <= AK_RAW; k++) { SOCKET s = aio_kind(k); unsigned char d[16]; \
            if (s == INVALID_SOCKET) continue; memset(d, 1, sizeof d); \
            t_check(aio_ctl(s, k_set[i].code, NULL, 0, d, 8, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "set data refused", "%s", aio_kind_name[k]); \
            t_check(aio_ctl(s, k_set[i].code, NULL, 0, NULL, 0, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "set empty refused", "%s", aio_kind_name[k]); \
            aio_close(s); } \
        { SOCKET s = aio_bound(SOCK_DGRAM); unsigned char d[16]; memset(d, 1, sizeof d); \
          EXPECT_NTS(aio_ctl(s, k_set[i].code, NULL, 0, d, 8, NULL, NULL), NTS_INVALID_PARAMETER); aio_close(s); } } \
    TEST(aio_connopt_set_##nm##_input_buffer_needs_matching_connection) { AIO_BEGIN(); \
        SOCKET s = aio_tcp(); unsigned char in[16], d[8]; memset(in, 0, sizeof in); memset(d, 1, sizeof d); \
        EXPECT_NTS(aio_ctl(s, k_set[i].code, in, 16, d, 8, NULL, NULL), NTS_INVALID_PARAMETER); \
        EXPECT_NTS(aio_ctl(s, k_set[i].code, in, 12, d, 8, NULL, NULL), NTS_INVALID_PARAMETER); \
        EXPECT_NTS(aio_ctl(s, k_set[i].code, in, 11, d, 8, NULL, NULL), NTS_INVALID_PARAMETER); \
        EXPECT_NTS(aio_ctl(s, k_set[i].code, in, 1, d, 8, NULL, NULL), NTS_INVALID_PARAMETER); \
        EXPECT_NTS(aio_ctl(s, k_set[i].code, in, 256, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER); \
        aio_close(s); } \
    TEST(aio_connopt_set_##nm##_information_is_zero) { AIO_BEGIN(); SOCKET s = aio_tcp(); unsigned char d[8]; IO_STATUS_BLOCK io; \
        memset(d, 1, sizeof d); EXPECT_NTS(aio_ctl(s, k_set[i].code, NULL, 0, d, 8, &io, NULL), NTS_SUCCESS); EXPECT_EQ(io.Information, 0); aio_close(s); }
SET_TEST(0, connect_data)
SET_TEST(1, connect_options)
SET_TEST(2, disconnect_data)
SET_TEST(3, disconnect_options)

/* ---- GET ---------------------------------------------------------------------------------------- */
#define GET_TEST(i, nm) \
    TEST(aio_connopt_get_##nm##_nothing_stored) { AIO_BEGIN(); int k; \
        for (k = 0; k < AK_COUNT; k++) { SOCKET s = aio_kind(k); unsigned char d[0x100]; IO_STATUS_BLOCK io; \
            if (s == INVALID_SOCKET) continue; memset(d, 0x5a, sizeof d); \
            t_check(aio_ctl(s, k_get[i].code, NULL, 0, d, sizeof d, &io, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "get data", "%s", aio_kind_name[k]); \
            t_check(io.Information == 0, __FILE__, __LINE__, "get data information", "%s: %llu", aio_kind_name[k], (unsigned long long)io.Information); \
            CHECK(d[0] == 0x5a); \
            aio_close(s); } } \
    TEST(aio_connopt_get_##nm##_without_buffers) { AIO_BEGIN(); SOCKET s = aio_tcp(); IO_STATUS_BLOCK io; \
        EXPECT_NTS(aio_ctl(s, k_get[i].code, NULL, 0, NULL, 0, &io, NULL), NTS_SUCCESS); EXPECT_EQ(io.Information, 0); aio_close(s); } \
    TEST(aio_connopt_get_##nm##_with_input_refused) { AIO_BEGIN(); int k; \
        for (k = 0; k < AK_COUNT; k++) { SOCKET s = aio_kind(k); unsigned char in[16], d[16]; \
            if (s == INVALID_SOCKET) continue; memset(in, 0, sizeof in); \
            t_check(aio_ctl(s, k_get[i].code, in, 16, d, 16, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "get with sequence input", "%s", aio_kind_name[k]); \
            t_check(aio_ctl(s, k_get[i].code, in, 4, d, 4, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "get with short input", "%s", aio_kind_name[k]); \
            aio_close(s); } } \
    TEST(aio_connopt_get_##nm##_after_set_still_empty) { AIO_BEGIN(); SOCKET s = aio_tcp(); unsigned char d[8], o[8]; IO_STATUS_BLOCK io; \
        memset(d, 0x11, sizeof d); \
        EXPECT_NTS(aio_ctl(s, k_set[i].code, NULL, 0, d, 8, NULL, NULL), NTS_SUCCESS); \
        EXPECT_NTS(aio_ctl(s, k_get[i].code, NULL, 0, o, 8, &io, NULL), NTS_SUCCESS); EXPECT_EQ(io.Information, 0); aio_close(s); }
GET_TEST(0, connect_data)
GET_TEST(1, connect_options)
GET_TEST(2, disconnect_data)
GET_TEST(3, disconnect_options)

/* ---- SIZE --------------------------------------------------------------------------------------- */
#define SIZE_TEST(i, nm) \
    TEST(aio_connopt_size_##nm##_stream_endpoints) { AIO_BEGIN(); int k; \
        for (k = 0; k < AK_COUNT; k++) { SOCKET s; ULONG sz = 0x40; \
            if (k == AK_UDP || k == AK_RAW || k == AK_UDP_BOUND) continue; \
            s = aio_kind(k); if (s == INVALID_SOCKET) continue; \
            t_check(aio_ctl(s, k_size[i].code, NULL, 0, &sz, 4, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "size request", "%s", aio_kind_name[k]); \
            sz = 0; t_check(aio_ctl(s, k_size[i].code, NULL, 0, &sz, 4, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "size zero", "%s", aio_kind_name[k]); \
            aio_close(s); } } \
    TEST(aio_connopt_size_##nm##_datagram_and_raw_refused) { AIO_BEGIN(); int k; \
        for (k = AK_UDP; k <= AK_RAW; k++) { SOCKET s = aio_kind(k); ULONG sz = 0x40; \
            if (s == INVALID_SOCKET) continue; \
            t_check(aio_ctl(s, k_size[i].code, NULL, 0, &sz, 4, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "size refused", "%s", aio_kind_name[k]); \
            aio_close(s); } } \
    TEST(aio_connopt_size_##nm##_input_form_refused) { AIO_BEGIN(); SOCKET s = aio_tcp(); ULONG sz = 0x40; \
        EXPECT_NTS(aio_ctl(s, k_size[i].code, &sz, 4, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER); aio_close(s); } \
    TEST(aio_connopt_size_##nm##_does_not_create_readable_data) { AIO_BEGIN(); SOCKET s = aio_tcp(); ULONG sz = 0x40; unsigned char o[0x80]; IO_STATUS_BLOCK io; \
        EXPECT_NTS(aio_ctl(s, k_size[i].code, NULL, 0, &sz, 4, NULL, NULL), NTS_SUCCESS); \
        EXPECT_NTS(aio_ctl(s, k_get[i].code, NULL, 0, o, sizeof o, &io, NULL), NTS_SUCCESS); EXPECT_EQ(io.Information, 0); aio_close(s); }
SIZE_TEST(0, connect_data)
SIZE_TEST(1, connect_options)
SIZE_TEST(2, disconnect_data)
SIZE_TEST(3, disconnect_options)

/* ---- unaccepted connection data (0x120a7) -------------------------------------------------------- */
TEST(aio_unaccepted_requires_input_record)
{
    AIO_BEGIN();
    SOCKET l = aio_listener(NULL);
    unsigned char d[16];
    EXPECT_NTS(aio_ctl(l, IOC_GET_UNACCEPTED, NULL, 0, d, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(l, IOC_GET_UNACCEPTED, d, 11, d, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close(l);
}
TEST(aio_unaccepted_unknown_sequence_invalid_parameter)
{
    AIO_BEGIN();
    SOCKET l = aio_listener(NULL);
    unsigned char in[16], d[16];
    memset(in, 0, sizeof in); in[0] = 0x77;
    EXPECT_NTS(aio_ctl(l, IOC_GET_UNACCEPTED, in, 12, d, 16, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close(l);
}
TEST(aio_unaccepted_all_endpoint_kinds_refuse_zero_sequence)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        unsigned char in[16], d[16];
        if (s == INVALID_SOCKET) continue;
        memset(in, 0, sizeof in);
        t_check(aio_ctl(s, IOC_GET_UNACCEPTED, in, 12, d, 16, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "unaccepted query", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_unaccepted_pending_connection_has_no_connect_data)
{
    /* take the sequence number of a queued connection with WAIT_FOR_LISTEN, then ask for its connect data */
    AIO_BEGIN();
    struct sockaddr_in a;
    SOCKET l = aio_listener(&a), c = aio_tcp();
    unsigned char resp[64], in[16], d[64];
    IO_STATUS_BLOCK io;
    LONG st;
    memset(resp, 0, sizeof resp);
    CHECK(W.connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    st = aio_ctl(l, IOC_WAIT_FOR_LISTEN, NULL, 0, resp, sizeof resp, &io, NULL);
    if (st != NTS_SUCCESS) {
        t_note("WAIT_FOR_LISTEN on the listener returned 0x%08lx; scenario not available", (unsigned long)st);
    } else {
        memset(in, 0, sizeof in);
        memcpy(in, resp, 4);   /* sequence number first */
        memset(d, 0x5a, sizeof d);
        st = aio_ctl(l, IOC_GET_UNACCEPTED, in, 12, d, sizeof d, &io, NULL);
        t_note("GET_UNACCEPTED_CONNECT_DATA for a queued connection: 0x%08lx information %llu", (unsigned long)st, (unsigned long long)io.Information);
        CHECK(st == NTS_SUCCESS);
        EXPECT_EQ(io.Information, 0);
    }
    aio_close(c); aio_close(l);
}

/* ---- quality of service ------------------------------------------------------------------------- */
/* The default QOS is "best effort, everything unspecified": two 32-byte flow specs whose first five
 * fields and last two fields are 0xffffffff (not specified) and whose service type is 1, followed by an
 * empty provider-specific buffer; the request transfers 0x58 bytes, the last 8 being zero. */
static void default_qos(unsigned char *q)
{
    int i;
    memset(q, 0, 0x58);
    for (i = 0; i < 2; i++) {
        unsigned char *f = q + i * 32;
        memset(f, 0xff, 32);
        memset(f + 20, 0, 4);
        f[20] = 1;          /* ServiceType = SERVICETYPE_BESTEFFORT */
    }
}
TEST(aio_qos_get_default_bytes)
{
    AIO_BEGIN();
    int k;
    unsigned char want[0x58], got[0x58];
    default_qos(want);
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        IO_STATUS_BLOCK io;
        if (s == INVALID_SOCKET) continue;
        memset(got, 0xee, sizeof got);
        t_check(aio_ctl(s, IOC_GET_QOS, NULL, 0, got, sizeof got, &io, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "get qos", "%s", aio_kind_name[k]);
        t_check(io.Information == 0x58, __FILE__, __LINE__, "qos information", "%s: %llu", aio_kind_name[k], (unsigned long long)io.Information);
        t_check(!memcmp(got, want, sizeof got), __FILE__, __LINE__, "default qos bytes", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_qos_get_buffer_sizes)
{
    AIO_BEGIN();
    static const ULONG lens[] = { 0, 1, 0x4f, 0x50, 0x57 };
    SOCKET s = aio_tcp();
    unsigned char b[0x200];
    unsigned i;
    IO_STATUS_BLOCK io;
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        memset(b, 0xee, sizeof b);
        t_check(aio_ctl(s, IOC_GET_QOS, NULL, 0, lens[i] ? b : NULL, lens[i], &io, NULL) == NTS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "short qos buffer", "len %lu", (unsigned long)lens[i]);
        CHECK(b[0] == 0xee);
    }
    EXPECT_NTS(aio_ctl(s, IOC_GET_QOS, NULL, 0, b, 0x58, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0x58);
    EXPECT_NTS(aio_ctl(s, IOC_GET_QOS, NULL, 0, b, 0x59, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0x58);
    EXPECT_NTS(aio_ctl(s, IOC_GET_QOS, NULL, 0, b, 0x200, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0x58);
    CHECK(b[0x58] == 0xee);   /* nothing is written past the 0x58 bytes */
    aio_close(s);
}
TEST(aio_qos_get_ignores_input)
{
    AIO_BEGIN();
    SOCKET s = aio_udp();
    unsigned char in[0x58], got[0x58], want[0x58];
    default_qos(want);
    memset(in, 0x99, sizeof in);
    EXPECT_NTS(aio_ctl(s, IOC_GET_QOS, in, sizeof in, got, sizeof got, NULL, NULL), NTS_SUCCESS);
    CHECK(!memcmp(got, want, 0x50));
    t_note("QOS bytes 0x50..0x57 with a dirty input buffer: %02x%02x%02x%02x%02x%02x%02x%02x", got[0x50], got[0x51], got[0x52], got[0x53], got[0x54], got[0x55], got[0x56], got[0x57]);
    aio_close(s);
}
TEST(aio_qos_get_has_empty_provider_specific_buffer)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char got[0x58];
    ULONG len; ULONGLONG ptr;
    EXPECT_NTS(aio_ctl(s, IOC_GET_QOS, NULL, 0, got, sizeof got, NULL, NULL), NTS_SUCCESS);
    memcpy(&len, got + 0x40, 4); memcpy(&ptr, got + 0x48, 8);
    EXPECT_EQ(len, 0);
    EXPECT_EQ(ptr, 0);
    aio_close(s);
}
TEST(aio_qos_set_buffer_sizes)
{
    AIO_BEGIN();
    static const ULONG lens[] = { 0, 1, 0x4f, 0x50, 0x57 };
    SOCKET s = aio_tcp();
    unsigned char q[0x200];
    unsigned i;
    IO_STATUS_BLOCK io;
    default_qos(q);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++)
        t_check(aio_ctl(s, IOC_SET_QOS, lens[i] ? q : NULL, lens[i], NULL, 0, &io, NULL) == NTS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "short qos input", "len %lu", (unsigned long)lens[i]);
    EXPECT_NTS(aio_ctl(s, IOC_SET_QOS, q, 0x58, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    EXPECT_NTS(aio_ctl(s, IOC_SET_QOS, q, 0x200, NULL, 0, &io, NULL), NTS_SUCCESS);
    aio_close(s);
}
TEST(aio_qos_set_accepted_on_every_endpoint_kind)
{
    AIO_BEGIN();
    int k;
    unsigned char q[0x58];
    default_qos(q);
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_SET_QOS, q, sizeof q, NULL, 0, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "set qos", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_qos_set_is_not_stored)
{
    /* a changed QOS is announced to waiters but never retained: the next GET still returns the default */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char q[0x58], got[0x58], want[0x58];
    default_qos(want);
    memset(q, 0x21, sizeof q);
    EXPECT_NTS(aio_ctl(s, IOC_SET_QOS, q, sizeof q, NULL, 0, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl(s, IOC_GET_QOS, NULL, 0, got, sizeof got, NULL, NULL), NTS_SUCCESS);
    CHECK(!memcmp(got, want, sizeof got));
    aio_close(s);
}
TEST(aio_qos_set_output_buffer_ignored)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char q[0x58], o[0x58];
    default_qos(q); memset(o, 0x44, sizeof o);
    EXPECT_NTS(aio_ctl(s, IOC_SET_QOS, q, sizeof q, o, sizeof o, NULL, NULL), NTS_SUCCESS);
    aio_close(s);
}
TEST(aio_qos_sio_get_qos_matches_default_flowspecs)
{
    /* the provider's SIO_GET_QOS answers with the same two flow specs */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char want[0x58], out[0x100];
    DWORD ret = 0;
    int r;
    default_qos(want);
    memset(out, 0xee, sizeof out);
    r = W.WSAIoctl(s, SIO_GET_QOS, NULL, 0, out, sizeof out, &ret, NULL, NULL);
    if (r != 0) { t_note("SIO_GET_QOS on a fresh stream socket failed with %d", W.WSAGetLastError()); aio_close(s); return; }
    EXPECT_EQ(ret, 0x50);
    CHECK(!memcmp(out, want, 0x40));
    aio_close(s);
}
TEST(aio_qos_set_announces_change_to_qos_waiters)
{
    /* a non-default QOS raises the QOS network event (FD_QOS) on the endpoint */
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    WSANETWORKEVENTS ne;
    unsigned char q[0x58];
    __typeof__(&WSAEventSelect) sel = U(WSAEventSelect);
    __typeof__(&WSAEnumNetworkEvents) en = U(WSAEnumNetworkEvents);
    if (!sel || !en) { t_skip("event select exports unavailable"); aio_close(s); return; }
    CHECK(sel(s, ev, FD_QOS) == 0);
    memset(q, 0x21, sizeof q);
    EXPECT_NTS(aio_ctl(s, IOC_SET_QOS, q, sizeof q, NULL, 0, NULL, NULL), NTS_SUCCESS);
    if (WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0) {
        memset(&ne, 0, sizeof ne);
        CHECK(en(s, ev, &ne) == 0);
        t_note("network events after non-default SET_QOS = 0x%lx", (unsigned long)ne.lNetworkEvents);
        CHECK(ne.lNetworkEvents & FD_QOS);
    } else {
        t_note("no event raised by SET_QOS");
    }
    sel(s, NULL, 0);
    CloseHandle(ev);
    aio_close(s);
}
TEST(aio_qos_set_default_does_not_raise_event)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    unsigned char q[0x58];
    __typeof__(&WSAEventSelect) sel = U(WSAEventSelect);
    if (!sel) { t_skip("WSAEventSelect unavailable"); aio_close(s); return; }
    CHECK(sel(s, ev, FD_QOS) == 0);
    default_qos(q);
    EXPECT_NTS(aio_ctl(s, IOC_SET_QOS, q, sizeof q, NULL, 0, NULL, NULL), NTS_SUCCESS);
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);
    sel(s, NULL, 0);
    CloseHandle(ev);
    aio_close(s);
}
