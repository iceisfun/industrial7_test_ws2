/* The AFD control-code table, asserted exactly.
 *
 * Every control code the driver registers (73 slots, 0x12003 .. 0x12123) is sent to a fresh endpoint of
 * seven kinds in six request shapes, and the resulting NTSTATUS is compared with the table below. One
 * row per code, one string per endpoint kind, one letter per request shape:
 *
 *   kinds   (strings, in order)  tcp  udp  raw  tcp-bound  tcp-listening  udp-bound  tcp-connected
 *   shapes  (letters, in order)  0: no buffers            1: 16 zero bytes in + 16 out
 *                                2: 64 zero bytes in + out  3: 256 in, no out
 *                                4: no in, 256 out        5: 4 in + 4 out
 *   letters S success  P invalid-parameter  D invalid-device-request  T buffer-too-small
 *           C invalid-connection  O buffer-overflow  V access-violation (a NULL pointer inside the zeroed
 *           request)  H invalid-handle  A invalid-address-component  B address-already-associated
 *           N not-supported  2 invalid-parameter-2  X 0xC000023B  W request stays pending (the table
 *           cell is "would block": the test cancels it)  Q success or invalid-device-request.
 *
 * The statuses come from the driver's per-code handlers (length checks first, then endpoint-state checks);
 * the table is the observable result of the whole dispatch and is the strongest conformance artifact of
 * this area. A cell can be wrong only if a handler's validation order differs.
 */
#include "aio.h"

#define ROWS(X) \
    X(bind, 0x12003, "PAAPPP", "PAAPPP", "PAAPPP", "PBBPPP", "PBBPPP", "PBBPPP", "PBBPPP")\
    X(connect, 0x12007, "PPPPPP", "PPPPPP", "PPPPPP", "PPAAPP", "PPPPPP", "PPAAPP", "PPPPPP")\
    X(start_listen, 0x1200b, "PPPPPP", "PPPPPP", "PPPPPP", "PSSSPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(wait_for_listen, 0x1200c, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PWWPWP", "PPPPPP", "PPPPPP")\
    X(accept, 0x12010, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PHHHPP", "PPPPPP", "PPPPPP")\
    X(recv, 0x12017, "CCCCCC", "PPPPPP", "PPPPPP", "CCCCCC", "CCCCCC", "PPPPPP", "PPPPPP")\
    X(recv_datagram, 0x1201b, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPNNPP", "PPPPPP")\
    X(send, 0x1201f, "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "PPPPPP")\
    X(send_datagram, 0x12023, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(poll, 0x12024, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(partial_disconnect, 0x1202b, "PPPPPP", "PSSSPP", "PSSSPP", "PPPPPP", "PPPPPP", "PSSSPP", "PSSSPP")\
    X(get_address, 0x1202f, "PPPPPP", "PPPPPP", "PPPPPP", "PSSPST", "PSSPST", "PSSPST", "PSSPST")\
    X(query_receive_info, 0x12033, "TSSTST", "TSSTST", "TSSTST", "TSSTST", "TSSTST", "TSSTST", "TSSTST")\
    X(query_handles, 0x12037, "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT")\
    X(set_information, 0x1203b, "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT")\
    X(get_remote_address, 0x1203f, "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "TSSTST")\
    X(get_context, 0x12043, "OOOOSO", "OOOOSO", "OOOOSO", "OOOOSO", "OOOOSO", "OOOOSO", "OOOOSO")\
    X(set_context, 0x12047, "SPPSPP", "SPPSPP", "SPPSPP", "SPPSPP", "SPPSPP", "SPPSPP", "SPPSPP")\
    X(set_connect_data, 0x1204b, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(set_connect_options, 0x1204f, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(set_disconnect_data, 0x12053, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(set_disconnect_options, 0x12057, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(get_connect_data, 0x1205b, "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP")\
    X(get_connect_options, 0x1205f, "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP")\
    X(get_disconnect_data, 0x12063, "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP")\
    X(get_disconnect_options, 0x12067, "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP", "SPPPSP")\
    X(size_connect_data, 0x1206b, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(size_connect_options, 0x1206f, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(size_disconnect_data, 0x12073, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(size_disconnect_options, 0x12077, "SPPPSP", "PPPPPP", "PPPPPP", "SPPPSP", "SPPPSP", "PPPPPP", "SPPPSP")\
    X(get_information, 0x1207b, "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT", "TPPTTT")\
    X(transmit_file, 0x1207f, "PPCCPP", "PPCCPP", "PPCCPP", "PPCCPP", "PPCCPP", "PPCCPP", "PPSSPP")\
    X(super_accept, 0x12083, "VPPPVP", "VPPPVP", "VPPPVP", "VPPPVP", "VTTTVT", "VPPPVP", "VPPPVP")\
    X(event_select, 0x12087, "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP")\
    X(enum_network_events, 0x1208b, "PPHPSP", "PPHPSP", "PPHPSP", "PPHPSP", "PPHPSP", "PPHPSP", "PPHPSP")\
    X(defer_accept, 0x1208c, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(wait_for_listen_lifo, 0x12090, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PWWPWP", "PPPPPP", "PPPPPP")\
    X(set_qos, 0x12094, "TTTSTT", "TTTSTT", "TTTSTT", "TTTSTT", "TTTSTT", "TTTSTT", "TTTSTT")\
    X(get_qos, 0x12098, "TTTTST", "TTTTST", "TTTTST", "TTTTST", "TTTTST", "TTTTST", "TTTTST")\
    X(no_operation, 0x1209f, "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS")\
    X(validate_group, 0x120a0, "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT", "TPPPTT")\
    X(get_unaccepted_connect_data, 0x120a7, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(routing_interface_query, 0x120ab, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(routing_interface_change, 0x120ac, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(address_list_query, 0x120b3, "PSSPPS", "PSSPPS", "PSSPPS", "PSSPPS", "PSSPPS", "PSSPPS", "PSSPPS")\
    X(address_list_change, 0x120b4, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(connect_alt, 0x120bb, "PPPPPP", "PPPPPP", "PPPPPP", "PPAAPP", "PPPPPP", "PPAAPP", "PPPPPP")\
    X(tli_control, 0x120bf, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(transmit_packets, 0x120c3, "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "CCCCCC", "PPPPPP")\
    X(super_connect, 0x120c7, "PPPPPP", "PPPPPP", "PPPPPP", "PAAAPP", "PPPPPP", "PPPPPP", "PXXXPP")\
    X(super_disconnect, 0x120cb, "VCCCVC", "VCCCVC", "VCCCVC", "VCCCVC", "VCCCVC", "VCCCVC", "VSSSVS")\
    X(recv_datagram_alt, 0x120cf, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPVVPP", "PPPPPP")\
    X(send_message, 0x120d3, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_cement_endpoint, 0x120d7, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_set_events, 0x120db, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_reset_events, 0x120df, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_connect, 0x120e2, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_complete_accept, 0x120e7, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_complete_request, 0x120eb, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_complete_io, 0x120ef, "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP", "PSSSPP")\
    X(san_refresh_endpoint, 0x120f3, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_get_physical_addr, 0x120f7, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_acquire_context, 0x120fb, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_transfer_context, 0x120ff, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(san_get_service_pid, 0x12103, "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH")\
    X(san_set_service_process, 0x12107, "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH")\
    X(san_provider_change, 0x1210b, "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH", "HHHHHH")\
    X(san_addr_list_change, 0x1210c, "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP", "PPPPPP")\
    X(unbind, 0x12113, "PPPPPP", "PNNNPP", "PNNNPP", "PSSSPP", "PPPPPP", "PNNNPP", "PPPPPP")\
    X(sqm, 0x12117, "QQQQQQ", "QQQQQQ", "QQQQQQ", "QQQQQQ", "QQQQQQ", "QQQQQQ", "QQQQQQ")\
    X(rio, 0x1211b, "2DDD2D", "2DDD2D", "2DDD2D", "2DDD2D", "2DDD2D", "2DDD2D", "2DDD2D")\
    X(socket_transfer_begin, 0x1211f, "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS")\
    X(socket_transfer_end, 0x12123, "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS", "SSSSSS")

static const ULONG shape_in[6]  = { 0, 16, 64, 256, 0, 4 };
static const ULONG shape_out[6] = { 0, 16, 64, 0, 256, 4 };

static LONG letter_status(char c)
{
    switch (c) {
    case 'S': return NTS_SUCCESS;
    case 'P': return NTS_INVALID_PARAMETER;
    case 'D': return NTS_INVALID_DEVICE_REQ;
    case 'T': return NTS_BUFFER_TOO_SMALL;
    case 'C': return NTS_INVALID_CONNECTION;
    case 'O': return NTS_BUFFER_OVERFLOW;
    case 'V': return NTS_ACCESS_VIOLATION;
    case 'H': return NTS_INVALID_HANDLE;
    case 'A': return (LONG)0xC0000207;
    case 'B': return (LONG)0xC0000238;
    case 'N': return NTS_NOT_SUPPORTED;
    case '2': return (LONG)0xC00000F0;
    case 'X': return (LONG)0xC000023B;
    case 'W': return NTS_TIMEOUT_LOCAL;
    }
    return 0x7eadbeef;
}

static void sweep_code(ULONG code, const char *const row[7])
{
    int kind, shape;
    DWORD saved = aio_wait_ms;
    aio_wait_ms = 300;
    for (kind = 0; kind < 7; kind++) {
        for (shape = 0; shape < 6; shape++) {
            unsigned char in[256], out[256];
            SOCKET s = aio_kind(kind);
            LONG st, want;
            char c = row[kind][shape];
            if (s == INVALID_SOCKET || s == 0) {
                if (kind == 2) { t_note("raw socket unavailable (not elevated?), raw column skipped"); break; }
                CHECKF(0, "cannot create a %s endpoint", aio_kind_name[kind]);
                continue;
            }
            memset(in, 0, sizeof in); memset(out, 0, sizeof out);
            st = aio_ctl(s, code, shape_in[shape] ? in : NULL, shape_in[shape],
                         shape_out[shape] ? out : NULL, shape_out[shape], NULL, NULL);
            if (c == 'Q') {
                t_check(st == NTS_SUCCESS || st == NTS_INVALID_DEVICE_REQ, __FILE__, __LINE__, "success or invalid-device-request",
                        "code 0x%05lx %s shape %d: got 0x%08lx", (unsigned long)code, aio_kind_name[kind], shape, (unsigned long)st);
            } else {
                want = letter_status(c);
                t_check(st == want, __FILE__, __LINE__, "status matches table",
                        "code 0x%05lx %s shape %d: got 0x%08lx want 0x%08lx", (unsigned long)code, aio_kind_name[kind], shape,
                        (unsigned long)st, (unsigned long)want);
            }
            aio_close(s);
        }
    }
    aio_wait_ms = saved;
}

#define X(name, code, a, b, c, d, e, f, g) \
    TEST(aio_sweep_##name) { AIO_BEGIN(); static const char *const row[7] = { a, b, c, d, e, f, g }; sweep_code(code, row); }
ROWS(X)
#undef X

/* Every code of the table, in slot order, to prove the rows above cover the whole table and that the
 * slot index is bits 2..11 of the code. */
#define X(name, code, a, b, c, d, e, f, g) code,
static const ULONG row_codes[] = { ROWS(X) };
#undef X
#define NROWS ((int)(sizeof row_codes / sizeof row_codes[0]))

TEST(aio_sweep_table_has_73_slots) { EXPECT_EQ(NROWS, 73); }
TEST(aio_sweep_codes_strictly_increasing_and_device_type_0x12) {
    int i;
    for (i = 0; i < NROWS; i++) {
        CHECKF((row_codes[i] >> 12) == 0x12, "row %d device type", i);
        if (i) CHECKF(row_codes[i] > row_codes[i - 1], "row %d order", i);
        CHECKF((row_codes[i] >> 2 & 0x3ff) >= (unsigned)i, "row %d slot index", i);
    }
}

static int is_row_code(ULONG code)
{
    int i;
    for (i = 0; i < NROWS; i++) if (row_codes[i] == code) return 1;
    return 0;
}

/* Any code of device type 0x12 that is not exactly a registered value completes at once with
 * invalid-device-request: slots past the end, holes, and neighbours differing in the method bits. */
TEST(aio_sweep_unregistered_codes_refused)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    ULONG fn, method;
    int refused = 0;
    for (fn = 0; fn < 0x400 + 8; fn++) {
        for (method = 0; method < 4; method++) {
            ULONG code = 0x12000u | (fn << 2) | method;
            LONG first = 0, st;
            if (is_row_code(code)) continue;
            st = aio_ctl(s, code, NULL, 0, NULL, 0, NULL, &first);
            if (st != NTS_INVALID_DEVICE_REQ || first != NTS_INVALID_DEVICE_REQ) {
                t_check(0, __FILE__, __LINE__, "unregistered code refused", "code 0x%05lx st 0x%08lx first 0x%08lx", (unsigned long)code, (unsigned long)st, (unsigned long)first);
            } else refused++;
        }
    }
    CHECK(refused > 4000);
    aio_close(s);
}
/* The full code must equal the registered value: changing the device type field (bits 16..31) of a
 * registered code makes the request invalid even though the slot index is unchanged. */
TEST(aio_sweep_other_device_types_refused)
{
    AIO_BEGIN();
    SOCKET s = aio_tcp();
    static const ULONG types[] = { 0x0000, 0x0002, 0x0003, 0x0012, 0x0022, 0x8001, 0xffff };
    int i;
    unsigned t;
    for (i = 0; i < NROWS; i++)
        for (t = 0; t < sizeof types / sizeof types[0]; t++) {
            ULONG code = (types[t] << 16) | (row_codes[i] & 0xffffu);
            EXPECT_NTS(aio_ctl(s, code, NULL, 0, NULL, 0, NULL, NULL), NTS_INVALID_DEVICE_REQ);
        }
    aio_close(s);
}

/* ---- the same table through other call forms ------------------------------------------------------- */
typedef struct { const char *name; ULONG code; const char *const *row; } sweep_row_t;
#define X(name, code, a, b, c, d, e, f, g) { #name, code, (const char *const[7]){ a, b, c, d, e, f, g } },
static const sweep_row_t g_rows[] = { ROWS(X) };
#undef X

/* Submit without an event or APC on the handle, finishing a pended request by cancelling it. */
static LONG ctl_no_event(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, LONG *first)
{
    IO_STATUS_BLOCK io, c;
    LONG st;
    int i;
    io.Status = (LONG)0xcccccccc; io.Information = 0;
    st = W.ioctl((HANDLE)s, NULL, NULL, NULL, &io, code, in, inl, out, outl);
    if (first) *first = st;
    if (st != NTS_PENDING) return st;
    Sleep(50);
    if (io.Status != (LONG)0xcccccccc && io.Status != 0x103) return io.Status;
    W.cancel((HANDLE)s, &c);
    for (i = 0; i < 100 && (io.Status == (LONG)0xcccccccc || io.Status == 0x103); i++) Sleep(10);
    return NTS_TIMEOUT_LOCAL;
}
static void sweep_other_form(int kind, int sync_handle)
{
    unsigned r;
    for (r = 0; r < sizeof g_rows / sizeof g_rows[0]; r++) {
        int shape;
        for (shape = 0; shape < 6; shape++) {
            unsigned char in[256], out[256];
            SOCKET s;
            LONG st, want;
            char c = g_rows[r].row[kind][shape];
            if (sync_handle) s = W.WSASocketW(AF_INET, kind == AK_UDP ? SOCK_DGRAM : SOCK_STREAM, 0, NULL, 0, 0);
            else s = aio_kind(kind);
            if (s == INVALID_SOCKET) { CHECKF(0, "cannot create endpoint"); return; }
            if (sync_handle && c == 'W') { aio_close(s); continue; }   /* would block forever */
            memset(in, 0, sizeof in); memset(out, 0, sizeof out);
            st = sync_handle
                ? W.ioctl((HANDLE)s, NULL, NULL, NULL, &(IO_STATUS_BLOCK){ 0 }, g_rows[r].code, shape_in[shape] ? in : NULL, shape_in[shape], shape_out[shape] ? out : NULL, shape_out[shape])
                : ctl_no_event(s, g_rows[r].code, shape_in[shape] ? in : NULL, shape_in[shape], shape_out[shape] ? out : NULL, shape_out[shape], NULL);
            if (c == 'Q') want = st; else want = letter_status(c);
            if (c == 'Q') CHECK(st == NTS_SUCCESS || st == NTS_INVALID_DEVICE_REQ);
            else t_check(st == want, __FILE__, __LINE__, "status matches table", "%s code 0x%05lx shape %d: got 0x%08lx want 0x%08lx", g_rows[r].name, (unsigned long)g_rows[r].code, shape, (unsigned long)st, (unsigned long)want);
            aio_close(s);
        }
    }
}
TEST(aio_sweep_no_event_form_tcp) { AIO_BEGIN(); aio_wait_ms = 300; sweep_other_form(AK_TCP, 0); }
TEST(aio_sweep_no_event_form_udp) { AIO_BEGIN(); aio_wait_ms = 300; sweep_other_form(AK_UDP, 0); }
TEST(aio_sweep_synchronous_handle_tcp) { AIO_BEGIN(); sweep_other_form(AK_TCP, 1); }
TEST(aio_sweep_synchronous_handle_udp) { AIO_BEGIN(); sweep_other_form(AK_UDP, 1); }

/* An IPv6 endpoint of each type answers the whole table exactly like its IPv4 counterpart. */
static void sweep_v6(int type, int proto, int kind4)
{
    unsigned r;
    SOCKET probe = W.WSASocketW(AF_INET6, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (probe == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; }
    aio_close(probe);
    aio_wait_ms = 300;
    for (r = 0; r < sizeof g_rows / sizeof g_rows[0]; r++) {
        int shape;
        for (shape = 0; shape < 6; shape++) {
            unsigned char in[256], out[256];
            SOCKET s6 = W.WSASocketW(AF_INET6, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED);
            SOCKET s4 = aio_kind(kind4);
            LONG a, b;
            memset(in, 0, sizeof in); memset(out, 0, sizeof out);
            a = aio_ctl(s6, g_rows[r].code, shape_in[shape] ? in : NULL, shape_in[shape], shape_out[shape] ? out : NULL, shape_out[shape], NULL, NULL);
            b = aio_ctl(s4, g_rows[r].code, shape_in[shape] ? in : NULL, shape_in[shape], shape_out[shape] ? out : NULL, shape_out[shape], NULL, NULL);
            t_check(a == b, __FILE__, __LINE__, "v6 matches v4", "%s shape %d: v6 0x%08lx v4 0x%08lx", g_rows[r].name, shape, (unsigned long)a, (unsigned long)b);
            aio_close(s6); aio_close(s4);
        }
    }
}
TEST(aio_sweep_ipv6_tcp_matches_ipv4) { AIO_BEGIN(); sweep_v6(SOCK_STREAM, IPPROTO_TCP, AK_TCP); }
TEST(aio_sweep_ipv6_udp_matches_ipv4) { AIO_BEGIN(); sweep_v6(SOCK_DGRAM, IPPROTO_UDP, AK_UDP); }
