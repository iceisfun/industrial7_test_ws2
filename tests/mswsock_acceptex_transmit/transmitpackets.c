/* TransmitPackets: the flag word, the element-type word and element-count limits, the NULL array, file
 * elements (negative or out-of-range offsets, bad handles, repeated handle), long element lists, send-size
 * values, the queue shared with TransmitFile on one socket, completion delivery, and socket reuse.  Success
 * paths of single memory and file elements and the basic socket-state errors are asserted in other areas. */
#include "mx.h"

typedef char tp_element_is_24_bytes[sizeof(TRANSMIT_PACKETS_ELEMENT) == 24 ? 1 : -1];

#define FSZ 4000u
#define SEED 11u
#define QUIET_MS 150

struct tp {
    struct mx_ext x;
    SOCKET c, a;
    HANDLE f;
};

static int tp_open(struct tp *t, DWORD size)
{
    memset(t, 0, sizeof *t);
    t->c = t->a = INVALID_SOCKET;
    t->f = INVALID_HANDLE_VALUE;
    if (!mx_up() || !mx_load_ext(&t->x) || !t->x.transmitpackets || !mx_pair(&t->c, &t->a)) return 0;
    t->f = mx_make_file("tp_data.bin", size, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    return t->f != INVALID_HANDLE_VALUE;
}

static void tp_close(struct tp *t)
{
    if (t->f != INVALID_HANDLE_VALUE) CloseHandle(t->f);
    if (t->c != INVALID_SOCKET) mx_closesocket(t->c);
    if (t->a != INVALID_SOCKET) mx_closesocket(t->a);
}

#define TP(t, size) \
    do { if (!tp_open(&(t), (size))) { tp_close(&(t)); t_skip("TransmitPackets fixture unavailable"); return; } } while (0)

static TRANSMIT_PACKETS_ELEMENT el_mem(const void *p, DWORD len, DWORD extra)
{
    TRANSMIT_PACKETS_ELEMENT e;
    memset(&e, 0, sizeof e);
    e.dwElFlags = TP_ELEMENT_MEMORY | extra;
    e.cLength = len;
    e.pBuffer = (PVOID)p;
    return e;
}

static TRANSMIT_PACKETS_ELEMENT el_file(HANDLE h, LONGLONG off, DWORD len, DWORD extra)
{
    TRANSMIT_PACKETS_ELEMENT e;
    memset(&e, 0, sizeof e);
    e.dwElFlags = TP_ELEMENT_FILE | extra;
    e.cLength = len;
    e.nFileOffset.QuadPart = off;
    e.hFile = h;
    return e;
}

/* A call that must fail synchronously with `err` and put nothing on the wire. */
static void tp_expect_reject(struct tp *t, TRANSMIT_PACKETS_ELEMENT *el, DWORD n, DWORD send, DWORD flags, int err, const char *what)
{
    mx_WSASetLastError(0);
    t_check(t->x.transmitpackets(t->c, el, n, send, NULL, flags) == FALSE && mx_WSAGetLastError() == err, __FILE__, __LINE__,
            what, "n %lu flags 0x%lx: error %d want %d", n, flags, mx_WSAGetLastError(), err);
}

TEST(transmitpackets_pointer_is_identical_across_sockets)
{
    SOCKET s1, s2;
    GUID g = WSAID_TRANSMITPACKETS;
    NEED_NET();
    s1 = mx_tcp(); s2 = mx_tcp();
    if (!mx_ext_lookup(s1, g)) { mx_closesocket(s1); mx_closesocket(s2); t_skip("TransmitPackets not offered"); return; }
    CHECK(mx_ext_lookup(s1, g) == mx_ext_lookup(s2, g));
    mx_closesocket(s1); mx_closesocket(s2);
}

/* ---- flag word ------------------------------------------------------------------------------------------------ */

TEST(transmitpackets_reserved_and_exclusive_flags_are_einval_and_send_nothing)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e;
    DWORD bad[40], nbad = 0;
    int bit;
    unsigned i;
    TP(t, FSZ);
    e = el_mem("zz", 2, 0);
    for (bit = 3; bit < 32; bit++) {
        if (bit == 4 || bit == 5) continue;
        bad[nbad++] = 1UL << bit;
    }
    bad[nbad++] = TP_USE_SYSTEM_THREAD | TP_USE_KERNEL_APC;
    bad[nbad++] = 0xFFFFFFFFUL;
    for (i = 0; i < nbad; i++) tp_expect_reject(&t, &e, 1, 0, bad[i], WSAEINVAL, "flags rejected");
    CHECK(mx_quiet(t.a, QUIET_MS));
    MX_EQ(mx_send(t.c, "ok", 2, 0), 2);
    mx_expect_bytes(t.a, "ok", 2);
    tp_close(&t);
}

TEST(transmitpackets_valid_flag_values_deliver_the_elements)
{
    static const DWORD ok[] = { 0, 4, TP_USE_SYSTEM_THREAD, TP_USE_KERNEL_APC, TP_USE_SYSTEM_THREAD | 4, TP_USE_KERNEL_APC | 4 };
    struct tp t;
    unsigned i;
    TP(t, FSZ);
    for (i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        TRANSMIT_PACKETS_ELEMENT e[2];
        e[0] = el_mem("<", 1, 0);
        e[1] = el_file(t.f, 0, 100, 0);
        t_check(t.x.transmitpackets(t.c, e, 2, 0, NULL, ok[i]), __FILE__, __LINE__, "flags accepted", "flags 0x%lx err %d", ok[i], mx_WSAGetLastError());
        mx_expect_bytes(t.a, "<", 1);
        mx_expect_slice(t.a, SEED, 0, 100);
    }
    tp_close(&t);
}

/* ---- element type word --------------------------------------------------------------------------------------- */

/* The type is a two-bit selector (1 memory, 2 file) plus the end-of-packet bit 4. Zero, both, and any bit
 * of 8 or above are invalid. */
TEST(transmitpackets_invalid_element_types_are_einval_at_any_position)
{
    static const DWORD bad[] = { 0, 3, 7, 8, 9, 0xA, 0xC, 0x10, 0x11, 0x100 | 1, 0x80000001UL, 0xFFFFFFFFUL };
    struct tp t;
    unsigned i, pos;
    TP(t, FSZ);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) for (pos = 0; pos < 2; pos++) {
        TRANSMIT_PACKETS_ELEMENT e[2];
        e[0] = el_mem("a", 1, 0);
        e[1] = el_mem("b", 1, 0);
        e[pos].dwElFlags = bad[i];
        mx_WSASetLastError(0);
        t_check(t.x.transmitpackets(t.c, e, 2, 0, NULL, 0) == FALSE && mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__,
                "element flags rejected", "type 0x%lx at %u: error %d", bad[i], pos, mx_WSAGetLastError());
    }
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

TEST(transmitpackets_all_valid_type_words_are_accepted)
{
    static const DWORD mem[] = { TP_ELEMENT_MEMORY, TP_ELEMENT_MEMORY | TP_ELEMENT_EOP };
    static const DWORD fil[] = { TP_ELEMENT_FILE, TP_ELEMENT_FILE | TP_ELEMENT_EOP };
    struct tp t;
    unsigned i;
    TP(t, FSZ);
    for (i = 0; i < 2; i++) {
        TRANSMIT_PACKETS_ELEMENT e[2];
        e[0] = el_mem("M", 1, 0);
        e[0].dwElFlags = mem[i];
        e[1] = el_file(t.f, 10, 20, 0);
        e[1].dwElFlags = fil[i];
        CHECK(t.x.transmitpackets(t.c, e, 2, 0, NULL, 0));
        mx_expect_bytes(t.a, "M", 1);
        mx_expect_slice(t.a, SEED, 10, 20);
    }
    tp_close(&t);
}

/* ---- element count and array ---------------------------------------------------------------------------------- */

TEST(transmitpackets_zero_count_is_einval)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e;
    TP(t, FSZ);
    e = el_mem("x", 1, 0);
    tp_expect_reject(&t, &e, 0, 0, 0, WSAEINVAL, "zero elements");
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

TEST(transmitpackets_null_array_is_einval_for_any_count)
{
    static const DWORD counts[] = { 0, 1, 2, 100 };
    struct tp t;
    unsigned i;
    TP(t, FSZ);
    for (i = 0; i < 4; i++) tp_expect_reject(&t, NULL, counts[i], 0, 0, WSAEINVAL, "NULL array");
    tp_close(&t);
}

/* The element count is capped just above 178 million; larger counts fail before the array is read. */
TEST(transmitpackets_count_above_the_limit_is_einval_without_reading_the_array)
{
    static const DWORD counts[] = { 0xAAAAAABUL, 0xAAAAAACUL, 0x10000000UL, 0x7FFFFFFFUL, 0x80000000UL, 0xFFFFFFFFUL };
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e;
    unsigned i;
    TP(t, FSZ);
    e = el_mem("x", 1, 0);
    for (i = 0; i < sizeof counts / sizeof counts[0]; i++) tp_expect_reject(&t, &e, counts[i], 0, 0, WSAEINVAL, "count over limit");
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

TEST(transmitpackets_count_smaller_than_the_array_ignores_the_rest)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e[3];
    TP(t, FSZ);
    e[0] = el_mem("one", 3, 0);
    e[1] = el_mem("two", 3, 0);
    e[2] = el_mem("three", 5, 0);
    CHECK(t.x.transmitpackets(t.c, e, 2, 0, NULL, 0));
    mx_expect_bytes(t.a, "onetwo", 6);
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

/* An invalid element late in the list voids the whole call: nothing from the earlier elements is sent. */
TEST(transmitpackets_late_invalid_element_sends_nothing_at_all)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e[4];
    TP(t, FSZ);
    e[0] = el_mem("alpha", 5, 0);
    e[1] = el_file(t.f, 0, 50, 0);
    e[2] = el_mem("beta", 4, 0);
    e[3] = el_mem("gamma", 5, 0);
    e[3].dwElFlags = 0;
    tp_expect_reject(&t, e, 4, 0, 0, WSAEINVAL, "late bad element");
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

/* ---- file elements ---------------------------------------------------------------------------------------------- */

/* Out-of-range file offsets: negative ones, and one past the end when the length is "rest of file", fail as a
 * plain Win32 invalid parameter (87); an explicit length starting past the end fails as a Winsock invalid
 * argument. Nothing is sent in either case. */
TEST(transmitpackets_out_of_range_file_offsets_fail_without_sending)
{
    static const struct { const char *what; LONGLONG off; DWORD len; int err; } rows[] = {
        { "offset -1, length 10", -1, 10, ERROR_INVALID_PARAMETER },
        { "offset -1, whole file", -1, 0, ERROR_INVALID_PARAMETER },
        { "most negative offset, length 10", (LONGLONG)1 << 63, 10, ERROR_INVALID_PARAMETER },
        { "offset size+1, whole file", FSZ + 1, 0, ERROR_INVALID_PARAMETER },
        { "offset 2^40, whole file", (LONGLONG)1 << 40, 0, ERROR_INVALID_PARAMETER },
        { "offset size+1, length 10", FSZ + 1, 10, WSAEINVAL },
    };
    unsigned i;
    struct tp t;
    TP(t, FSZ);
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        TRANSMIT_PACKETS_ELEMENT e = el_file(t.f, rows[i].off, rows[i].len, 0);
        mx_WSASetLastError(0);
        t_check(t.x.transmitpackets(t.c, &e, 1, 0, NULL, 0) == FALSE && mx_WSAGetLastError() == rows[i].err, __FILE__, __LINE__,
                rows[i].what, "error %d want %d", mx_WSAGetLastError(), rows[i].err);
    }
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

TEST(transmitpackets_offset_at_the_end_with_zero_length_sends_nothing_for_that_element)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e[3];
    BOOL r;
    TP(t, FSZ);
    e[0] = el_mem("[", 1, 0);
    e[1] = el_file(t.f, FSZ, 0, 0);
    e[2] = el_mem("]", 1, 0);
    mx_WSASetLastError(0);
    r = t.x.transmitpackets(t.c, e, 3, 0, NULL, 0);
    CHECK(r);
    mx_expect_bytes(t.a, "[]", 2);
    tp_close(&t);
}

TEST(transmitpackets_file_element_length_zero_sends_from_offset_to_the_end)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e;
    TP(t, FSZ);
    e = el_file(t.f, 3000, 0, 0);
    CHECK(t.x.transmitpackets(t.c, &e, 1, 0, NULL, 0));
    mx_expect_slice(t.a, SEED, 3000, FSZ - 3000);
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

TEST(transmitpackets_bad_file_handles_are_invalid_handle_and_send_nothing)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e[2];
    HANDLE dead, ev;
    TP(t, FSZ);
    dead = mx_make_file("tp_dead.bin", 20, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    CloseHandle(dead);
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    e[0] = el_mem("pre", 3, 0);
    e[1] = el_file(dead, 0, 10, 0);
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitpackets(t.c, e, 2, 0, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), ERROR_INVALID_HANDLE);
    e[1] = el_file(INVALID_HANDLE_VALUE, 0, 10, 0);
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitpackets(t.c, e, 2, 0, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), ERROR_INVALID_HANDLE);
    e[1] = el_file(ev, 0, 10, 0);
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitpackets(t.c, e, 2, 0, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), ERROR_INVALID_HANDLE);   /* wrong object type */
    CHECK(mx_quiet(t.a, QUIET_MS));
    CloseHandle(ev);
    tp_close(&t);
}

TEST(transmitpackets_one_file_handle_used_by_many_elements)
{
    enum { N = 40 };
    TRANSMIT_PACKETS_ELEMENT e[N];
    struct tp t;
    struct mx_sink k;
    int i, total = 0, pos = 0, bad = 0;
    TP(t, FSZ);
    for (i = 0; i < N; i++) {
        DWORD off = (DWORD)((i * 97) % 3000), len = 20 + (DWORD)i;
        e[i] = el_file(t.f, off, len, 0);
        total += (int)len;
    }
    mx_sink_start(&k, t.a, total);
    CHECK(t.x.transmitpackets(t.c, e, N, 0, NULL, 0));
    MX_EQ(mx_sink_join(&k), total);
    for (i = 0; i < N && k.got == total; i++) {
        DWORD j, off = (DWORD)((i * 97) % 3000), len = 20 + (DWORD)i;
        for (j = 0; j < len; j++) if (k.buf[pos + j] != mx_pat(off + j, SEED)) bad++;
        pos += (int)len;
    }
    MX_EQ(bad, 0);
    mx_sink_free(&k);
    tp_close(&t);
}

TEST(transmitpackets_file_elements_from_two_different_files_interleave_correctly)
{
    struct tp t;
    HANDLE g;
    TRANSMIT_PACKETS_ELEMENT e[4];
    TP(t, FSZ);
    g = mx_make_file("tp_other.bin", 500, SEED + 5, GENERIC_READ | GENERIC_WRITE, 0);
    e[0] = el_file(t.f, 0, 10, 0);
    e[1] = el_file(g, 0, 10, 0);
    e[2] = el_file(t.f, 10, 10, 0);
    e[3] = el_file(g, 10, 10, 0);
    CHECK(t.x.transmitpackets(t.c, e, 4, 0, NULL, 0));
    mx_expect_slice(t.a, SEED, 0, 10);
    mx_expect_slice(t.a, SEED + 5, 0, 10);
    mx_expect_slice(t.a, SEED, 10, 10);
    mx_expect_slice(t.a, SEED + 5, 10, 10);
    CloseHandle(g);
    tp_close(&t);
}

/* ---- memory elements ----------------------------------------------------------------------------------------------- */

TEST(transmitpackets_zero_length_memory_element_contributes_nothing)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e[3];
    TP(t, FSZ);
    e[0] = el_mem("A", 1, 0);
    e[1] = el_mem("zzzz", 0, 0);
    e[2] = el_mem("B", 1, 0);
    CHECK(t.x.transmitpackets(t.c, e, 3, 0, NULL, 0));
    mx_expect_bytes(t.a, "AB", 2);
    CHECK(mx_quiet(t.a, QUIET_MS));
    tp_close(&t);
}

TEST(transmitpackets_two_thousand_small_elements_arrive_in_order)
{
    enum { N = 2000 };
    TRANSMIT_PACKETS_ELEMENT *e = (TRANSMIT_PACKETS_ELEMENT *)HeapAlloc(GetProcessHeap(), 0, N * sizeof *e);
    unsigned char *data = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, N * 5);
    struct tp t;
    struct mx_sink k;
    int i, bad = 0;
    TP(t, FSZ);
    for (i = 0; i < N; i++) {
        int j;
        for (j = 0; j < 5; j++) data[i * 5 + j] = (unsigned char)(i * 5 + j + (i >> 8));
        e[i] = el_mem(data + i * 5, 5, (i % 7 == 0) ? TP_ELEMENT_EOP : 0);
    }
    mx_sink_start(&k, t.a, N * 5);
    CHECK(t.x.transmitpackets(t.c, e, N, 0, NULL, 0));
    MX_EQ(mx_sink_join(&k), N * 5);
    for (i = 0; i < N * 5 && k.got == N * 5; i++) if (k.buf[i] != data[i]) bad++;
    MX_EQ(bad, 0);
    mx_sink_free(&k);
    HeapFree(GetProcessHeap(), 0, e);
    HeapFree(GetProcessHeap(), 0, data);
    tp_close(&t);
}

/* The send size only chunks the transfer; every value leaves the stream identical. */
TEST(transmitpackets_send_size_values_do_not_change_the_stream)
{
    static const DWORD sizes[] = { 0, 1, 7, 1000, 0x10000, 0x7FFFFFFFUL, 0x80000000UL, 0xFFFFFFFFUL };
    struct tp t;
    unsigned i;
    TP(t, FSZ);
    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        TRANSMIT_PACKETS_ELEMENT e[2];
        e[0] = el_mem("hdr", 3, 0);
        e[1] = el_file(t.f, 0, 600, 0);
        t_check(t.x.transmitpackets(t.c, e, 2, sizes[i], NULL, 0), __FILE__, __LINE__, "send size accepted", "size 0x%lx err %d", sizes[i], mx_WSAGetLastError());
        mx_expect_bytes(t.a, "hdr", 3);
        mx_expect_slice(t.a, SEED, 0, 600);
    }
    tp_close(&t);
}

/* ---- overlapped delivery and queueing ------------------------------------------------------------------------------ */

TEST(transmitpackets_overlapped_completion_through_a_port)
{
    struct tp t;
    TRANSMIT_PACKETS_ELEMENT e[2];
    OVERLAPPED ov;
    HANDLE port;
    DWORD got = MX_POISON;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    int err;
    TP(t, FSZ);
    port = CreateIoCompletionPort((HANDLE)t.c, NULL, 0x61, 0);
    CHECK(port != NULL);
    memset(&ov, 0, sizeof ov);
    e[0] = el_mem("head", 4, 0);
    e[1] = el_file(t.f, 0, 1000, 0);
    err = t.x.transmitpackets(t.c, e, 2, 0, &ov, 0) ? 0 : mx_WSAGetLastError();
    t_check(err == 0 || err == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", err);
    CHECK(GetQueuedCompletionStatus(port, &got, &key, &pov, 5000));
    MX_EQ(key, 0x61);
    CHECK(pov == &ov);
    MX_EQ(got, 1004);   /* the byte count is the total of all elements */
    mx_expect_bytes(t.a, "head", 4);
    mx_expect_slice(t.a, SEED, 0, 1000);
    CloseHandle(port);
    tp_close(&t);
}

/* One socket runs one transmit operation at a time: a second submission waits its turn, even across
 * TransmitPackets and TransmitFile, and the bytes stay in submission order. */
TEST(transmitpackets_then_transmitfile_on_one_socket_keep_submission_order)
{
    enum { BIG = 200 * 1024 };
    struct tp t;
    HANDLE big;
    TRANSMIT_PACKETS_ELEMENT e;
    OVERLAPPED ov1, ov2;
    struct mx_sink k;
    DWORD n = 0, err = 0;
    int e1, e2;
    TP(t, FSZ);
    big = mx_make_file("tp_big.bin", BIG, SEED + 2, GENERIC_READ | GENERIC_WRITE, 0);
    e = el_file(big, 0, 0, 0);
    mx_sink_start(&k, t.a, BIG + FSZ);
    memset(&ov1, 0, sizeof ov1); ov1.hEvent = mx_event();
    memset(&ov2, 0, sizeof ov2); ov2.hEvent = mx_event();
    e1 = t.x.transmitpackets(t.c, &e, 1, 0, &ov1, 0) ? 0 : mx_WSAGetLastError();
    e2 = t.x.transmitfile(t.c, t.f, 0, 0, &ov2, NULL, 0) ? 0 : mx_WSAGetLastError();
    t_check((e1 == 0 || e1 == ERROR_IO_PENDING) && (e2 == 0 || e2 == ERROR_IO_PENDING), __FILE__, __LINE__, "both post", "e1 %d e2 %d", e1, e2);
    CHECK(mx_ov_done(t.c, &ov1, &n, 15000, &err));
    CHECK(mx_ov_done(t.c, &ov2, &n, 15000, &err));
    MX_EQ(mx_sink_join(&k), BIG + FSZ);
    {
        int i, bad = 0;
        for (i = 0; i < BIG + (int)FSZ && k.got == BIG + (int)FSZ; i += 211) {
            unsigned char want = i < BIG ? mx_pat((DWORD)i, SEED + 2) : mx_pat((DWORD)(i - BIG), SEED);
            if (k.buf[i] != want) bad++;
        }
        MX_EQ(bad, 0);
    }
    mx_sink_free(&k);
    CloseHandle(ov1.hEvent); CloseHandle(ov2.hEvent); CloseHandle(big);
    tp_close(&t);
}

/* ---- socket state ----------------------------------------------------------------------------------------------------- */

TEST(transmitpackets_bad_flags_on_unconnected_socket_report_notconn_first)
{
    struct mx_ext x;
    SOCKET s;
    TRANSMIT_PACKETS_ELEMENT e;
    BOOL r;
    NEED_NET();
    if (!mx_load_ext(&x) || !x.transmitpackets) { t_skip("TransmitPackets not offered"); return; }
    s = mx_tcp();
    e = el_mem("x", 1, 0);
    mx_WSASetLastError(0);
    r = x.transmitpackets(s, &e, 1, 0, NULL, 0x08);
    /* Unlike TransmitFile, the connection state is examined before the flag word. */
    MX_EQ(r, FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    mx_WSASetLastError(0);
    r = x.transmitpackets(s, &e, 1, 0, NULL, 0);
    MX_EQ(r, FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    mx_closesocket(s);
}

TEST(transmitpackets_disconnect_and_reuse_lets_the_accepted_socket_take_a_new_acceptex)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, c1, c2, acc;
    TRANSMIT_PACKETS_ELEMENT e;
    OVERLAPPED ov;
    unsigned char buf[128];
    DWORD n = 0, err = 0;
    NEED_NET();
    if (!mx_load_ext(&x) || !x.transmitpackets) { t_skip("TransmitPackets not offered"); return; }
    lst = mx_listener(&addr, 4);
    c1 = mx_tcp();
    CHECK(mx_connect(c1, (struct sockaddr *)&addr, sizeof addr) == 0);
    acc = mx_accept_wait(lst);
    e = el_mem("bye", 3, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    {
        int e0 = x.transmitpackets(acc, &e, 1, 0, &ov, TP_DISCONNECT | TP_REUSE_SOCKET) ? 0 : mx_WSAGetLastError();
        t_check(e0 == 0 || e0 == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", e0);
    }
    mx_expect_bytes(c1, "bye", 3);
    CHECK(mx_at_eof(c1, 5000));
    mx_shutdown(c1, SD_SEND);   /* the reuse disconnect finishes only after the peer closes its side too */
    CHECK(mx_ov_done(acc, &ov, &n, 8000, &err));
    ResetEvent(ov.hEvent);
    ov.Internal = ov.InternalHigh = 0;
    x.acceptex(lst, acc, buf, 4, 32, 32, &n, &ov);
    c2 = mx_tcp();
    CHECK(mx_connect(c2, (struct sockaddr *)&addr, sizeof addr) == 0);
    MX_EQ(mx_send(c2, "more", 4, 0), 4);
    CHECK(mx_ov_done(lst, &ov, &n, 5000, &err));
    MX_EQ(n, 4);
    CloseHandle(ov.hEvent);
    mx_closesocket(c1); mx_closesocket(c2); mx_closesocket(acc); mx_closesocket(lst);
}
