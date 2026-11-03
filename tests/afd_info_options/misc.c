/* The remaining small requests of the information family: NO_OPERATION (0x1209f), EVENT_SELECT (0x12087),
 * ENUM_NETWORK_EVENTS (0x1208b), VALIDATE_GROUP (0x120a0), PARTIAL_DISCONNECT (0x1202b), SQM (0x12117),
 * and the minimal forms of TRANSMIT_FILE (0x1207f) and TRANSMIT_PACKETS (0x120c3).
 */
#include "aio.h"
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

/* ---- NO_OPERATION: completes with a caller-chosen status ------------------------------------------ */
/* The request has no effect on the endpoint. An input record of at least 16 bytes { ULONG status; ...;
 * information at offset 8 } makes it complete with that status and information (a status that is not a
 * plain completion code is refused); anything shorter is ignored. */
static LONG noop_rec(SOCKET s, ULONG status, ULONGLONG info, ULONG inlen, IO_STATUS_BLOCK *io, LONG *first)
{
    ULONGLONG rec[2];
    rec[0] = status; rec[1] = info;
    return aio_ctl(s, IOC_NO_OPERATION, inlen ? rec : NULL, inlen, NULL, 0, io, first);
}
TEST(aio_noop_succeeds_on_every_kind_without_buffers)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        IO_STATUS_BLOCK io;
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_NO_OPERATION, NULL, 0, NULL, 0, &io, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "no-op", "%s", aio_kind_name[k]);
        t_check(io.Information == 0, __FILE__, __LINE__, "no-op information", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_noop_short_input_is_ignored)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[16];
    int n;
    memset(b, 0xff, sizeof b);   /* would be an invalid status if it were read */
    for (n = 1; n < 16; n++) EXPECT_NTS(aio_ctl(s, IOC_NO_OPERATION, b, n, NULL, 0, NULL, NULL), NTS_SUCCESS);
    aio_close(s);
}
TEST(aio_noop_output_buffer_is_ignored)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[32];
    memset(b, 0xff, sizeof b);
    EXPECT_NTS(aio_ctl(s, IOC_NO_OPERATION, NULL, 0, b, 32, NULL, NULL), NTS_SUCCESS);
    CHECK(b[0] == 0xff);
    aio_close(s);
}
TEST(aio_noop_zero_status_record)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    IO_STATUS_BLOCK io;
    LONG first = 1;
    EXPECT_NTS(noop_rec(s, 0, 0, 16, &io, &first), NTS_SUCCESS);
    EXPECT_EQ(first, 0);
    EXPECT_EQ(io.Information, 0);
    aio_close(s);
}
TEST(aio_noop_zero_status_information_is_passed_through)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    IO_STATUS_BLOCK io;
    EXPECT_NTS(noop_rec(s, 0, 0x1234, 16, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0x1234);
    aio_close(s);
}
TEST(aio_noop_chosen_failure_statuses)
{
    /* the chosen status comes back as the request's result */
    AIO_BEGIN();
    static const ULONG chosen[] = { 0xC0000001, 0xC0000023, 0xC0000120, 0x80000005, 0xC0000010 };
    unsigned i;
    for (i = 0; i < sizeof chosen / sizeof chosen[0]; i++) {
        SOCKET s = aio_tcp();
        IO_STATUS_BLOCK io;
        LONG first = 0;
        LONG st = noop_rec(s, chosen[i], 0x1234, 16, &io, &first);
        t_check(st == (LONG)chosen[i], __FILE__, __LINE__, "no-op chosen status", "chose 0x%08lx got 0x%08lx", (unsigned long)chosen[i], (unsigned long)st);
        t_check(first == NTS_PENDING, __FILE__, __LINE__, "no-op chosen status is asynchronous", "chose 0x%08lx submit 0x%08lx", (unsigned long)chosen[i], (unsigned long)first);
        t_check(io.Information == 0x1234, __FILE__, __LINE__, "no-op chosen information", "chose 0x%08lx information 0x%llx", (unsigned long)chosen[i], (unsigned long long)io.Information);
        aio_close(s);
    }
}
TEST(aio_noop_invalid_status_values_refused)
{
    /* only error and warning style codes are accepted as the chosen status */
    AIO_BEGIN();
    static const ULONG bad[] = { 0xffffffffu, 0x103, 0x40000000, 0x7fffffff, 0x00000001 };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SOCKET s = aio_tcp();
        LONG st = noop_rec(s, bad[i], 0x1234, 16, NULL, NULL);
        t_check(st == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "no-op invalid status", "chose 0x%08lx got 0x%08lx", (unsigned long)bad[i], (unsigned long)st);
        aio_close(s);
    }
}

/* ---- EVENT_SELECT / ENUM_NETWORK_EVENTS -------------------------------------------------------- */
TEST(aio_evsel_length_protocol)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    ULONGLONG rec[2] = { 0, 0 };
    EXPECT_NTS(aio_ctl(s, IOC_EVENT_SELECT, NULL, 0, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(s, IOC_EVENT_SELECT, rec, 8, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(s, IOC_EVENT_SELECT, rec, 15, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(s, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL), NTS_SUCCESS);
    aio_close(s);
}
TEST(aio_evsel_mask_without_event_invalid_parameter)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        ULONGLONG rec[2] = { 0, 1 };
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "mask without event", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_evsel_bad_event_handle_invalid_handle)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    ULONGLONG rec[2] = { 0x7777, 0 };
    EXPECT_NTS(aio_ctl(s, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL), NTS_INVALID_HANDLE);
    rec[0] = (ULONGLONG)(ULONG_PTR)s;   /* a socket is not an event */
    EXPECT_NTS(aio_ctl(s, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL), (LONG)0xC0000024);   /* object type mismatch */
    aio_close(s);
}
TEST(aio_evsel_clear_with_null_event_and_zero_mask)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        ULONGLONG rec[2] = { 0, 0 };
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "clear select", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_evsel_event_signalled_when_event_already_pending)
{
    /* selecting write readiness on a connected stream signals the event at once */
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ULONGLONG rec[2];
    aio_pair(&c, &s);
    rec[0] = (ULONGLONG)(ULONG_PTR)ev; rec[1] = 0x4;   /* AFD_POLL_SEND */
    EXPECT_NTS(aio_ctl(c, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL), NTS_SUCCESS);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    rec[0] = 0; rec[1] = 0;
    EXPECT_NTS(aio_ctl(c, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL), NTS_SUCCESS);
    CloseHandle(ev);
    aio_close(c); aio_close(s);
}
TEST(aio_enum_events_output_size)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        unsigned char b[0x80]; IO_STATUS_BLOCK io;
        if (s == INVALID_SOCKET) continue;
        t_check(aio_ctl(s, IOC_ENUM_EVENTS, NULL, 0, NULL, 0, &io, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "enum no buffer", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_ENUM_EVENTS, NULL, 0, b, 0x37, &io, NULL) == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "enum 0x37", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_ENUM_EVENTS, NULL, 0, b, 0x38, &io, NULL) == NTS_SUCCESS && io.Information == 0x38, __FILE__, __LINE__, "enum 0x38", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_ENUM_EVENTS, NULL, 0, b, 0x80, &io, NULL) == NTS_SUCCESS && io.Information == 0x38, __FILE__, __LINE__, "enum 0x80", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_enum_events_fresh_endpoint_reports_nothing)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    ULONG b[14];
    memset(b, 0xee, sizeof b);
    EXPECT_NTS(aio_ctl(s, IOC_ENUM_EVENTS, NULL, 0, b, sizeof b, NULL, NULL), NTS_SUCCESS);
    EXPECT_EQ(b[0], 0);   /* no event bits */
    aio_close(s);
}
TEST(aio_enum_events_reports_connect_and_clears)
{
    AIO_BEGIN();
    struct sockaddr_in a;
    SOCKET l = aio_listener(&a), c = aio_tcp();
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    ULONGLONG rec[2];
    ULONG out1[14], out2[14];
    rec[0] = (ULONGLONG)(ULONG_PTR)ev; rec[1] = 0x40 | 0x4;   /* connect + send */
    EXPECT_NTS(aio_ctl(c, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL), NTS_SUCCESS);
    CHECK(W.connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    memset(out1, 0, sizeof out1); memset(out2, 0xee, sizeof out2);
    EXPECT_NTS(aio_ctl(c, IOC_ENUM_EVENTS, NULL, 0, out1, sizeof out1, NULL, NULL), NTS_SUCCESS);
    CHECK(out1[0] & 0x40);
    EXPECT_NTS(aio_ctl(c, IOC_ENUM_EVENTS, NULL, 0, out2, sizeof out2, NULL, NULL), NTS_SUCCESS);
    CHECK(!(out2[0] & 0x40));   /* reading the events clears them */
    rec[0] = 0; rec[1] = 0;
    aio_ctl(c, IOC_EVENT_SELECT, rec, 16, NULL, 0, NULL, NULL);
    CloseHandle(ev);
    aio_close(c); aio_close(l);
}

/* ---- VALIDATE_GROUP --------------------------------------------------------------------------- */
TEST(aio_group_short_input_buffer_too_small)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        unsigned char b[64];
        if (s == INVALID_SOCKET) continue;
        memset(b, 0, sizeof b);
        t_check(aio_ctl(s, IOC_VALIDATE_GROUP, NULL, 0, NULL, 0, NULL, NULL) == NTS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "group no input", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_VALIDATE_GROUP, b, 15, NULL, 0, NULL, NULL) == NTS_BUFFER_TOO_SMALL, __FILE__, __LINE__, "group 15", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_group_unknown_group_invalid_parameter)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[64];
    memset(b, 0, sizeof b);
    EXPECT_NTS(aio_ctl(s, IOC_VALIDATE_GROUP, b, 16, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(s, IOC_VALIDATE_GROUP, b, 64, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    b[0] = 0x2b; b[1] = 0x77;   /* a group id nobody created */
    EXPECT_NTS(aio_ctl(s, IOC_VALIDATE_GROUP, b, 16, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close(s);
}

/* ---- PARTIAL_DISCONNECT ----------------------------------------------------------------------- */
TEST(aio_partial_disconnect_state_rules)
{
    /* needs a connection for streams; datagram and raw endpoints accept it in any state */
    AIO_BEGIN();
    ULONGLONG rec[2] = { 0, 0 };
    int k;
    static const char want[AK_COUNT + 1] = "PSSPPSS";   /* P invalid-parameter, S success per kind */
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s = aio_kind(k);
        LONG st;
        if (s == INVALID_SOCKET) continue;
        st = aio_ctl(s, IOC_PARTIAL_DISC, rec, 16, NULL, 0, NULL, NULL);
        t_check(st == (want[k] == 'S' ? NTS_SUCCESS : NTS_INVALID_PARAMETER), __FILE__, __LINE__, "partial disconnect", "%s: got 0x%08lx", aio_kind_name[k], (unsigned long)st);
        aio_close(s);
    }
}
TEST(aio_partial_disconnect_short_input)
{
    AIO_BEGIN();
    SOCKET c, s;
    ULONGLONG rec[2] = { 0, 0 };
    aio_pair(&c, &s);
    EXPECT_NTS(aio_ctl(c, IOC_PARTIAL_DISC, rec, 8, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(c, IOC_PARTIAL_DISC, NULL, 0, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close(c); aio_close(s);
}

/* ---- SQM: telemetry request, accepted or refused depending on configuration ------------------- */
TEST(aio_sqm_never_fails_with_anything_but_device_request)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    unsigned char b[0x100];
    LONG st;
    memset(b, 0, sizeof b);
    st = aio_ctl(s, IOC_SQM, NULL, 0, NULL, 0, NULL, NULL);
    CHECK(st == NTS_SUCCESS || st == NTS_INVALID_DEVICE_REQ);
    st = aio_ctl(s, IOC_SQM, b, 0x100, NULL, 0, NULL, NULL);
    CHECK(st == NTS_SUCCESS || st == NTS_INVALID_DEVICE_REQ);
    aio_close(s);
}

/* ---- TRANSMIT_FILE minimal --------------------------------------------------------------------- */
typedef struct {
    LONGLONG Offset;
    LONGLONG WriteLength;
    ULONG SendPacketLength; ULONG pad0;
    HANDLE File;
    void *Head; ULONG HeadLength; ULONG pad1;
    void *Tail; ULONG TailLength; ULONG Flags;
} tf_t;   /* 64 bytes */

static void tf_expect_len(const char *what, ULONG len, LONG want)
{
    SOCKET c, s;
    tf_t t;
    unsigned char buf[256];
    LONG st;
    aio_pair(&c, &s);
    memset(buf, 0, sizeof buf); memset(&t, 0, sizeof t);
    st = aio_ctl(c, IOC_TRANSMIT_FILE, buf, len, NULL, 0, NULL, NULL);
    t_check(st == want, __FILE__, __LINE__, what, "input length %lu: got 0x%08lx want 0x%08lx", (unsigned long)len, (unsigned long)st, (unsigned long)want);
    aio_close(c); aio_close(s);
}
TEST(aio_tfile_short_input_invalid_parameter)
{
    AIO_BEGIN();
    tf_expect_len("short", 0, NTS_INVALID_PARAMETER);
    tf_expect_len("short", 8, NTS_INVALID_PARAMETER);
    tf_expect_len("short", 48, NTS_INVALID_PARAMETER);
    tf_expect_len("short", 63, NTS_INVALID_PARAMETER);
    tf_expect_len("exact", 64, NTS_SUCCESS);
    tf_expect_len("long", 128, NTS_SUCCESS);
}
TEST(aio_tfile_unconnected_invalid_connection)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s;
        unsigned char b[64];
        if (k == AK_TCP_CONN) continue;
        s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        memset(b, 0, sizeof b);
        t_check(aio_ctl(s, IOC_TRANSMIT_FILE, b, 64, NULL, 0, NULL, NULL) == NTS_INVALID_CONNECTION, __FILE__, __LINE__, "transmit-file on unconnected", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_tfile_invalid_flag_combinations)
{
    AIO_BEGIN();
    static const ULONG bad[] = { 0x08, 0x40, 0x80, 0x100, 0x30, 0x38, 0x80000000u, 0xffffffffu };
    unsigned i;
    SOCKET c, s;
    aio_pair(&c, &s);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        tf_t t; LONG st;
        memset(&t, 0, sizeof t); t.Flags = bad[i];
        st = aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL);
        t_check(st == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "transmit-file flags", "flags 0x%lx: got 0x%08lx", (unsigned long)bad[i], (unsigned long)st);
    }
    aio_close(c); aio_close(s);
}
TEST(aio_tfile_negative_offset_with_file_invalid_parameter)
{
    AIO_BEGIN();
    SOCKET c, s;
    tf_t t;
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t);
    t.Offset = -1;
    t.File = (HANDLE)(ULONG_PTR)4;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close(c); aio_close(s);
}
TEST(aio_tfile_head_and_tail_without_file)
{
    /* no file handle: the head and tail buffers alone are sent, in that order */
    AIO_BEGIN();
    SOCKET c, s;
    tf_t t;
    char head[] = "head-", tail[] = "-tail", got[32];
    IO_STATUS_BLOCK io;
    LONG st;
    int n, total = 0;
    DWORD t0;
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t);
    t.Head = head; t.HeadLength = 5; t.Tail = tail; t.TailLength = 5;
    st = aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL);
    EXPECT_NTS(st, NTS_SUCCESS);
    EXPECT_EQ(io.Information, 10);   /* bytes handed to the transport */
    memset(got, 0, sizeof got);
    t0 = GetTickCount();
    aio_nonblock(s, 1);
    while (total < 10 && GetTickCount() - t0 < 3000) {
        n = W.recv(s, got + total, (int)sizeof got - total - 1, 0);
        if (n > 0) total += n; else Sleep(10);
    }
    EXPECT_EQ(total, 10);
    CHECK(!memcmp(got, "head--tail", 10));
    aio_close(c); aio_close(s);
}

/* ---- TRANSMIT_PACKETS minimal --------------------------------------------------------------------- */
typedef struct { ULONG Flags; ULONG Length; union { struct { LONGLONG Offset; HANDLE File; } f; void *Buffer; } u; } tpe_t;   /* 24 bytes */
typedef struct { tpe_t *Array; ULONG Count; ULONG SendSize; ULONG Flags; ULONG pad; } tp_t;                                  /* 24 bytes */

TEST(aio_tpkts_unconnected_invalid_connection_before_validation)
{
    AIO_BEGIN();
    int k;
    for (k = 0; k < AK_COUNT; k++) {
        SOCKET s;
        unsigned char b[32];
        if (k == AK_TCP_CONN) continue;
        s = aio_kind(k);
        if (s == INVALID_SOCKET) continue;
        memset(b, 0, sizeof b);
        t_check(aio_ctl(s, IOC_TRANSMIT_PKTS, NULL, 0, NULL, 0, NULL, NULL) == NTS_INVALID_CONNECTION, __FILE__, __LINE__, "packets, no input", "%s", aio_kind_name[k]);
        t_check(aio_ctl(s, IOC_TRANSMIT_PKTS, b, 32, NULL, 0, NULL, NULL) == NTS_INVALID_CONNECTION, __FILE__, __LINE__, "packets, zero input", "%s", aio_kind_name[k]);
        aio_close(s);
    }
}
TEST(aio_tpkts_connected_argument_validation)
{
    AIO_BEGIN();
    SOCKET c, s;
    tp_t t; tpe_t e;
    char data[] = "x";
    aio_pair(&c, &s);
    memset(&e, 0, sizeof e); e.Flags = 1; e.Length = 1; e.u.Buffer = data;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, NULL, 0, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, 23, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    memset(&t, 0, sizeof t);
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);   /* null array */
    t.Array = &e; t.Count = 0;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);   /* zero elements */
    t.Count = 0xaaaaaab;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);   /* too many */
    t.Count = 1; t.Flags = 0x08;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    t.Flags = 0x30;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    t.Flags = 0x40;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    aio_close(c); aio_close(s);
}
TEST(aio_tpkts_invalid_element_flags)
{
    AIO_BEGIN();
    static const ULONG bad[] = { 0, 3, 8, 0x10, 0x100, 0x80000000u };
    unsigned i;
    SOCKET c, s;
    char data[] = "x";
    aio_pair(&c, &s);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        tp_t t; tpe_t e; LONG st;
        memset(&e, 0, sizeof e); e.Flags = bad[i]; e.Length = 1; e.u.Buffer = data;
        memset(&t, 0, sizeof t); t.Array = &e; t.Count = 1;
        st = aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL);
        t_check(st == NTS_INVALID_PARAMETER, __FILE__, __LINE__, "element flags", "flags 0x%lx: got 0x%08lx", (unsigned long)bad[i], (unsigned long)st);
    }
    aio_close(c); aio_close(s);
}
TEST(aio_tpkts_memory_elements_delivered_in_order)
{
    AIO_BEGIN();
    SOCKET c, s;
    tp_t t; tpe_t e[3];
    char a[] = "ab", b[] = "cde", d[] = "f", got[32];
    IO_STATUS_BLOCK io;
    LONG st;
    int n, total = 0;
    DWORD t0;
    aio_pair(&c, &s);
    memset(e, 0, sizeof e);
    e[0].Flags = 1; e[0].Length = 2; e[0].u.Buffer = a;
    e[1].Flags = 1; e[1].Length = 3; e[1].u.Buffer = b;
    e[2].Flags = 1 | 4; e[2].Length = 1; e[2].u.Buffer = d;   /* memory element, end of packet */
    memset(&t, 0, sizeof t); t.Array = e; t.Count = 3;
    st = aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, &io, NULL);
    EXPECT_NTS(st, NTS_SUCCESS);
    EXPECT_EQ(io.Information, 6);
    memset(got, 0, sizeof got);
    t0 = GetTickCount();
    aio_nonblock(s, 1);
    while (total < 6 && GetTickCount() - t0 < 3000) {
        n = W.recv(s, got + total, (int)sizeof got - total - 1, 0);
        if (n > 0) total += n; else Sleep(10);
    }
    EXPECT_EQ(total, 6);
    CHECK(!memcmp(got, "abcdef", 6));
    aio_close(c); aio_close(s);
}
