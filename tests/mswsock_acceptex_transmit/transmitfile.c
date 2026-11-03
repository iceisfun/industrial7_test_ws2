/* TransmitFile: the flag word bit by bit, ordering of the flag check against socket state, byte-count and
 * start-offset limits, file-handle failures, files with extra head/tail text, queued overlapped calls,
 * synchronous calls on sockets created without overlapped capability, large transfers, a peer that goes away,
 * reuse of a socket after TF_REUSE_SOCKET, and the exported entry point versus the looked-up pointer.  Basic
 * cases (invalid socket, unconnected, whole file, head and tail, plain offsets) are asserted in other areas. */
#include "mx.h"

#define TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS 150
#define FSZ 5000u
#define SEED 7u

struct tf {
    struct mx_ext x;
    SOCKET c, a;
    HANDLE f;
};

static int tf_open(struct tf *t, DWORD size)
{
    memset(t, 0, sizeof *t);
    t->c = t->a = INVALID_SOCKET;
    t->f = INVALID_HANDLE_VALUE;
    if (!mx_up() || !mx_load_ext(&t->x) || !mx_pair(&t->c, &t->a)) return 0;
    t->f = mx_make_file("tf_data.bin", size, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    return t->f != INVALID_HANDLE_VALUE;
}

static void tf_close(struct tf *t)
{
    if (t->f != INVALID_HANDLE_VALUE) CloseHandle(t->f);
    if (t->c != INVALID_SOCKET) mx_closesocket(t->c);
    if (t->a != INVALID_SOCKET) mx_closesocket(t->a);
}

#define TF(t, size) \
    do { if (!tf_open(&(t), (size))) { tf_close(&(t)); t_skip("TransmitFile fixture unavailable"); return; } } while (0)

static void tf_rewind(struct tf *t) { SetFilePointer(t->f, 0, NULL, FILE_BEGIN); }

/* Overlapped TransmitFile and a bounded wait. Returns the call's success; *err gets the error of a failure
 * (either the immediate one or that of the completion); *bytes the completion count. */
static int tf_ov(struct tf *t, DWORD off, DWORD count, DWORD per, TRANSMIT_FILE_BUFFERS *b, DWORD flags, DWORD *bytes, DWORD *err)
{
    OVERLAPPED ov;
    int ok;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    ov.Offset = off;
    mx_WSASetLastError(0);
    ok = t->x.transmitfile(t->c, t->f, count, per, &ov, b, flags) ? 1 : 0;
    if (!ok) {
        int e = mx_WSAGetLastError();
        if (e == ERROR_IO_PENDING) ok = mx_ov_done(t->c, &ov, bytes, 8000, err);
        else { *err = (DWORD)e; if (bytes) *bytes = 0; }
    } else {
        if (bytes) *bytes = (DWORD)ov.InternalHigh;
        *err = 0;
    }
    CloseHandle(ov.hEvent);
    return ok;
}

TEST(transmitfile_pointer_is_identical_across_sockets)
{
    SOCKET s1, s2;
    GUID g = WSAID_TRANSMITFILE;
    NEED_NET();
    s1 = mx_tcp(); s2 = mx_tcp();
    CHECK(mx_ext_lookup(s1, g) != NULL);
    CHECK(mx_ext_lookup(s1, g) == mx_ext_lookup(s2, g));
    mx_closesocket(s1); mx_closesocket(s2);
}

/* ---- flag word ------------------------------------------------------------------------------------------------ */

/* Bits 3 and 6..31 are reserved; TF_USE_SYSTEM_THREAD and TF_USE_KERNEL_APC are mutually exclusive. All are
 * rejected with WSAEINVAL before anything is sent, and the socket stays usable. */
TEST(transmitfile_reserved_and_exclusive_flag_bits_are_einval_and_send_nothing)
{
    struct tf t;
    int bit;
    DWORD bad[40], nbad = 0;
    unsigned i;
    TF(t, FSZ);
    for (bit = 3; bit < 32; bit++) {
        if (bit == 4 || bit == 5) continue;
        bad[nbad++] = 1UL << bit;
    }
    bad[nbad++] = TF_USE_SYSTEM_THREAD | TF_USE_KERNEL_APC;
    bad[nbad++] = TF_USE_SYSTEM_THREAD | TF_USE_KERNEL_APC | TF_WRITE_BEHIND;
    bad[nbad++] = 0xFFFFFFFFUL;
    for (i = 0; i < nbad; i++) {
        mx_WSASetLastError(0);
        tf_rewind(&t);
        t_check(t.x.transmitfile(t.c, t.f, 0, 0, NULL, NULL, bad[i]) == FALSE && mx_WSAGetLastError() == WSAEINVAL,
                __FILE__, __LINE__, "flags rejected", "flags 0x%lx err %d", bad[i], mx_WSAGetLastError());
    }
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    MX_EQ(mx_send(t.c, "ok", 2, 0), 2);
    mx_expect_bytes(t.a, "ok", 2);
    tf_close(&t);
}

/* Each valid worker/behaviour flag, alone and in the permitted pairs, sends the file intact. */
TEST(transmitfile_valid_flag_values_send_the_file_intact)
{
    static const DWORD ok[] = { 0, TF_WRITE_BEHIND, TF_USE_SYSTEM_THREAD, TF_USE_KERNEL_APC,
                                TF_USE_SYSTEM_THREAD | TF_WRITE_BEHIND, TF_USE_KERNEL_APC | TF_WRITE_BEHIND };
    unsigned i;
    struct tf t;
    TF(t, FSZ);
    for (i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        tf_rewind(&t);
        t_check(t.x.transmitfile(t.c, t.f, 0, 0, NULL, NULL, ok[i]), __FILE__, __LINE__, "valid flags accepted",
                "flags 0x%lx err %d", ok[i], mx_WSAGetLastError());
        mx_expect_slice(t.a, SEED, 0, FSZ);
    }
    tf_close(&t);
}

TEST(transmitfile_overlapped_with_each_worker_flag_completes_with_the_file_size)
{
    static const DWORD ok[] = { 0, TF_USE_SYSTEM_THREAD, TF_USE_KERNEL_APC };
    unsigned i;
    struct tf t;
    TF(t, FSZ);
    for (i = 0; i < 3; i++) {
        DWORD n = 0, err = 0;
        CHECK(tf_ov(&t, 0, 0, 0, NULL, ok[i], &n, &err));
        t_check(n == FSZ, __FILE__, __LINE__, "byte count", "flags 0x%lx bytes %lu", ok[i], n);
        mx_expect_slice(t.a, SEED, 0, FSZ);
    }
    tf_close(&t);
}

/* The flag word is validated before the connection state is looked at. */
TEST(transmitfile_bad_flags_on_unconnected_socket_report_einval_not_notconn)
{
    struct mx_ext x;
    SOCKET s;
    HANDLE f;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    s = mx_tcp();
    f = mx_make_file("tf_unc.bin", 100, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    mx_WSASetLastError(0);
    MX_EQ(x.transmitfile(s, f, 0, 0, NULL, NULL, 0x08), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAEINVAL);
    mx_WSASetLastError(0);
    MX_EQ(x.transmitfile(s, f, 0, 0, NULL, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTCONN);
    CloseHandle(f);
    mx_closesocket(s);
}

/* ---- byte counts and offsets ----------------------------------------------------------------------------------- */

/* A byte count larger than what the file can supply (from the current position) fails as an invalid argument and
 * nothing is sent. */
TEST(transmitfile_byte_count_beyond_the_file_size_is_einval)
{
    static const DWORD counts[] = { FSZ + 1, 100000, 0x7FFFFFF0UL, 0x7FFFFFFFUL };
    unsigned i;
    struct tf t;
    TF(t, FSZ);
    for (i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        tf_rewind(&t);
        mx_WSASetLastError(0);
        MX_EQ(t.x.transmitfile(t.c, t.f, counts[i], 0, NULL, NULL, 0), FALSE);
        t_check(mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__, "count rejected", "count 0x%lx error %d", counts[i], mx_WSAGetLastError());
    }
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

/* A count of 2 GiB or more is over the 31-bit limit: it fails as a plain Win32 invalid parameter (87), a different
 * error space from the Winsock one above. */
TEST(transmitfile_byte_count_with_the_top_bit_set_is_invalid_parameter)
{
    static const DWORD counts[] = { 0x80000000UL, 0x80000001UL, 0xFFFFFFFEUL, 0xFFFFFFFFUL };
    unsigned i;
    struct tf t;
    TF(t, FSZ);
    for (i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        tf_rewind(&t);
        mx_WSASetLastError(0);
        MX_EQ(t.x.transmitfile(t.c, t.f, counts[i], 0, NULL, NULL, 0), FALSE);
        t_check(mx_WSAGetLastError() == ERROR_INVALID_PARAMETER, __FILE__, __LINE__, "count rejected", "count 0x%lx error %d", counts[i], mx_WSAGetLastError());
    }
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

/* Without a file handle the byte count is ignored, whatever its value. */
TEST(transmitfile_byte_count_is_ignored_without_a_file)
{
    TRANSMIT_FILE_BUFFERS b;
    struct tf t;
    TF(t, FSZ);
    b.Head = "H1"; b.HeadLength = 2; b.Tail = "T1"; b.TailLength = 2;
    CHECK(t.x.transmitfile(t.c, NULL, 0xFFFFFFFFUL, 0, NULL, &b, 0));
    mx_expect_bytes(t.a, "H1T1", 4);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

TEST(transmitfile_negative_start_offset_is_einval)
{
    OVERLAPPED ov;
    struct tf t;
    TF(t, FSZ);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    ov.Offset = 0;
    ov.OffsetHigh = 0x80000000UL;
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitfile(t.c, t.f, 0, 0, &ov, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAEINVAL);
    CloseHandle(ov.hEvent);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

/* With a count of zero the transfer length is "rest of the file", so an offset beyond the end has no
 * meaning and is rejected. The failure is reported as a plain Win32 code (87), not as a Winsock error. */
TEST(transmitfile_start_offset_beyond_the_end_with_whole_file_request_is_invalid_parameter)
{
    DWORD n = 0, err = 0;
    struct tf t;
    TF(t, FSZ);
    MX_EQ(tf_ov(&t, FSZ + 1, 0, 0, NULL, 0, &n, &err), 0);
    MX_EQ(err, ERROR_INVALID_PARAMETER);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

TEST(transmitfile_start_offset_at_the_end_with_whole_file_request_sends_only_head_and_tail)
{
    DWORD n = 0, err = 0;
    int ok;
    TRANSMIT_FILE_BUFFERS b;
    struct tf t;
    TF(t, FSZ);
    b.Head = "H"; b.HeadLength = 1; b.Tail = "T"; b.TailLength = 1;
    ok = tf_ov(&t, FSZ, 0, 0, &b, 0, &n, &err);
    CHECK(ok);
    MX_EQ(n, 2);
    mx_expect_bytes(t.a, "HT", 2);
    tf_close(&t);
}

TEST(transmitfile_offset_with_explicit_count_sends_that_window)
{
    DWORD n = 0, err = 0;
    struct tf t;
    TF(t, FSZ);
    CHECK(tf_ov(&t, 1234, 700, 0, NULL, 0, &n, &err));
    MX_EQ(n, 700);
    mx_expect_slice(t.a, SEED, 1234, 700);
    tf_close(&t);
}

TEST(transmitfile_zero_length_file_sends_only_head_and_tail)
{
    TRANSMIT_FILE_BUFFERS b;
    struct tf t;
    TF(t, 0);
    b.Head = "<<"; b.HeadLength = 2; b.Tail = ">>"; b.TailLength = 2;
    CHECK(t.x.transmitfile(t.c, t.f, 0, 0, NULL, &b, 0));
    mx_expect_bytes(t.a, "<<>>", 4);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

TEST(transmitfile_nothing_at_all_overlapped_completes_without_bytes)
{
    OVERLAPPED ov;
    DWORD n = MX_POISON, err = 0;
    int e;
    struct tf t;
    TF(t, 10);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    e = t.x.transmitfile(t.c, NULL, 0, 0, &ov, NULL, 0) ? 0 : mx_WSAGetLastError();
    t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", e);
    CHECK(mx_ov_done(t.c, &ov, &n, 5000, &err));
    MX_EQ(n, 0);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    CloseHandle(ov.hEvent);
    tf_close(&t);
}

/* ---- file handle problems --------------------------------------------------------------------------------------- */

TEST(transmitfile_closed_file_handle_is_invalid_handle_and_sends_nothing)
{
    struct tf t;
    HANDLE dead;
    DWORD e;
    TF(t, FSZ);
    dead = mx_make_file("tf_dead.bin", 50, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    CloseHandle(dead);
    SetLastError(0);
    MX_EQ(t.x.transmitfile(t.c, dead, 0, 0, NULL, NULL, 0), FALSE);
    e = (DWORD)mx_WSAGetLastError();
    MX_EQ(e, ERROR_INVALID_HANDLE);   /* a file-object failure surfaces as the plain Win32 code */
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

TEST(transmitfile_invalid_handle_value_is_invalid_handle)
{
    struct tf t;
    TF(t, FSZ);
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitfile(t.c, INVALID_HANDLE_VALUE, 0, 0, NULL, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), ERROR_INVALID_HANDLE);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

TEST(transmitfile_event_handle_is_invalid_handle)
{
    struct tf t;
    HANDLE ev;
    TF(t, FSZ);
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitfile(t.c, ev, 0, 0, NULL, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), ERROR_INVALID_HANDLE);   /* wrong object type */
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    CloseHandle(ev);
    tf_close(&t);
}

TEST(transmitfile_write_only_file_handle_is_access_denied)
{
    struct tf t;
    HANDLE wo;
    TF(t, FSZ);
    wo = mx_make_file("tf_wo.bin", 200, SEED, GENERIC_WRITE, 0);
    CHECK(wo != INVALID_HANDLE_VALUE);
    mx_WSASetLastError(0);
    MX_EQ(t.x.transmitfile(t.c, wo, 0, 0, NULL, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), ERROR_ACCESS_DENIED);   /* the file must be open for reading */
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    CloseHandle(wo);
    tf_close(&t);
}

/* A failed call leaves the connection fine: the next good call works. */
TEST(transmitfile_failure_does_not_poison_the_connection)
{
    struct tf t;
    TF(t, FSZ);
    MX_EQ(t.x.transmitfile(t.c, t.f, 0, 0, NULL, NULL, 0x08), FALSE);
    tf_rewind(&t);
    CHECK(t.x.transmitfile(t.c, t.f, 0, 0, NULL, NULL, 0));
    mx_expect_slice(t.a, SEED, 0, FSZ);
    tf_close(&t);
}

/* ---- overlapped queueing and socket kinds ------------------------------------------------------------------------ */

#define BIGSZ (256u * 1024u)

TEST(transmitfile_two_overlapped_calls_deliver_in_submission_order)
{
    OVERLAPPED ov1, ov2;
    HANDLE f2;
    struct mx_sink k;
    DWORD n = 0, err = 0;
    int e1, e2;
    struct tf t;
    TF(t, BIGSZ);
    f2 = mx_make_file("tf_second.bin", BIGSZ, SEED + 1, GENERIC_READ | GENERIC_WRITE, 0);
    mx_sink_start(&k, t.a, (int)(2 * BIGSZ));
    memset(&ov1, 0, sizeof ov1); ov1.hEvent = mx_event();
    memset(&ov2, 0, sizeof ov2); ov2.hEvent = mx_event();
    e1 = t.x.transmitfile(t.c, t.f, 0, 0, &ov1, NULL, 0) ? 0 : mx_WSAGetLastError();
    e2 = t.x.transmitfile(t.c, f2, 0, 0, &ov2, NULL, 0) ? 0 : mx_WSAGetLastError();
    t_check((e1 == 0 || e1 == ERROR_IO_PENDING) && (e2 == 0 || e2 == ERROR_IO_PENDING), __FILE__, __LINE__, "both post", "e1 %d e2 %d", e1, e2);
    CHECK(mx_ov_done(t.c, &ov1, &n, 15000, &err));
    CHECK(mx_ov_done(t.c, &ov2, &n, 15000, &err));
    MX_EQ(mx_sink_join(&k), 2 * BIGSZ);
    {
        DWORD i, bad1 = 0, bad2 = 0;
        for (i = 0; i < BIGSZ && k.got == (int)(2 * BIGSZ); i += 4093) {
            if (k.buf[i] != mx_pat(i, SEED)) bad1++;
            if (k.buf[BIGSZ + i] != mx_pat(i, SEED + 1)) bad2++;
        }
        MX_EQ(bad1, 0);
        MX_EQ(bad2, 0);
    }
    mx_sink_free(&k);
    CloseHandle(ov1.hEvent); CloseHandle(ov2.hEvent); CloseHandle(f2);
    tf_close(&t);
}

TEST(transmitfile_large_file_with_head_and_tail_arrives_intact)
{
    TRANSMIT_FILE_BUFFERS b;
    struct mx_sink k;
    int total = (int)BIGSZ * 4 + 12;
    struct tf t;
    HANDLE big;
    TF(t, 10);
    big = mx_make_file("tf_big.bin", BIGSZ * 4, SEED + 3, GENERIC_READ | GENERIC_WRITE, 0);
    b.Head = "HEAD-HEAD-"; b.HeadLength = 10; b.Tail = "TL"; b.TailLength = 2;
    mx_sink_start(&k, t.a, total);
    CHECK(t.x.transmitfile(t.c, big, 0, 16384, NULL, &b, 0));
    MX_EQ(mx_sink_join(&k), total);
    CHECK(k.got == total && !memcmp(k.buf, "HEAD-HEAD-", 10));
    CHECK(k.got == total && !memcmp(k.buf + total - 2, "TL", 2));
    {
        int i, bad = 0;
        for (i = 0; i < (int)BIGSZ * 4 && k.got == total; i += 997) if (k.buf[10 + i] != mx_pat(i, SEED + 3)) bad++;
        MX_EQ(bad, 0);
    }
    mx_sink_free(&k);
    CloseHandle(big);
    tf_close(&t);
}

TEST(transmitfile_synchronous_call_on_a_socket_without_overlapped_capability)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, c, a;
    HANDLE f;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 2);
    c = mx_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    CHECK(c != INVALID_SOCKET);
    CHECK(mx_connect(c, (struct sockaddr *)&addr, sizeof addr) == 0);
    a = mx_accept_wait(lst);
    f = mx_make_file("tf_nov.bin", FSZ, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    CHECK(x.transmitfile(c, f, 0, 0, NULL, NULL, 0));
    mx_expect_slice(a, SEED, 0, FSZ);
    CloseHandle(f);
    mx_closesocket(c); mx_closesocket(a); mx_closesocket(lst);
}

TEST(transmitfile_overlapped_completion_through_a_port_names_the_overlapped)
{
    OVERLAPPED ov;
    HANDLE port;
    DWORD got = MX_POISON;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = NULL;
    int e;
    struct tf t;
    TF(t, FSZ);
    port = CreateIoCompletionPort((HANDLE)t.c, NULL, 0x31, 0);
    CHECK(port != NULL);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = NULL;   /* no event: the port is the only completion channel */
    e = t.x.transmitfile(t.c, t.f, 0, 0, &ov, NULL, 0) ? 0 : mx_WSAGetLastError();
    t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", e);
    CHECK(GetQueuedCompletionStatus(port, &got, &key, &pov, 5000));
    MX_EQ(key, 0x31);
    CHECK(pov == &ov);
    MX_EQ(got, FSZ);
    mx_expect_slice(t.a, SEED, 0, FSZ);
    CloseHandle(port);
    tf_close(&t);
}

/* ---- peer failure ------------------------------------------------------------------------------------------------- */

TEST(transmitfile_to_a_peer_that_closed_fails_instead_of_hanging)
{
    struct tf t;
    HANDLE big;
    DWORD n = 0, err = 0;
    int ok;
    TF(t, 10);
    big = mx_make_file("tf_gone.bin", 8u * 1024u * 1024u, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    mx_closesocket(t.a);
    t.a = INVALID_SOCKET;
    {
        HANDLE keep = t.f;
        t.f = big;
        ok = tf_ov(&t, 0, 0, 0, NULL, 0, &n, &err);
        t.f = keep;
    }
    CHECK(!ok);
    t_note("TransmitFile to a closed peer: error %lu", err);
    CloseHandle(big);
    tf_close(&t);
}

/* ---- reuse --------------------------------------------------------------------------------------------------------- */

TEST(transmitfile_disconnect_and_reuse_lets_the_accepted_socket_take_a_new_acceptex)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, c1, c2, acc;
    HANDLE f;
    OVERLAPPED ov;
    unsigned char buf[128];
    DWORD n = 0, err = 0;
    char got[4] = {0};
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 4);
    c1 = mx_tcp();
    CHECK(mx_connect(c1, (struct sockaddr *)&addr, sizeof addr) == 0);
    acc = mx_accept_wait(lst);
    f = mx_make_file("tf_reuse.bin", 100, SEED, GENERIC_READ | GENERIC_WRITE, 0);
    /* A reuse disconnect finishes only after the peer has closed its side too, so run it overlapped. */
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    {
        int e0 = x.transmitfile(acc, f, 0, 0, &ov, NULL, TF_DISCONNECT | TF_REUSE_SOCKET) ? 0 : mx_WSAGetLastError();
        t_check(e0 == 0 || e0 == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", e0);
    }
    mx_expect_slice(c1, SEED, 0, 100);
    CHECK(mx_at_eof(c1, 5000));
    mx_shutdown(c1, SD_SEND);
    CHECK(mx_ov_done(acc, &ov, &n, 8000, &err));
    ResetEvent(ov.hEvent);
    ov.Internal = ov.InternalHigh = 0;
    x.acceptex(lst, acc, buf, 4, 32, 32, &n, &ov);
    c2 = mx_tcp();
    CHECK(mx_connect(c2, (struct sockaddr *)&addr, sizeof addr) == 0);
    MX_EQ(mx_send(c2, "next", 4, 0), 4);
    CHECK(mx_ov_done(lst, &ov, &n, 5000, &err));
    MX_EQ(n, 4);
    CHECK(!memcmp(buf, "next", 4));
    (void)got;
    CloseHandle(ov.hEvent); CloseHandle(f);
    mx_closesocket(c1); mx_closesocket(c2); mx_closesocket(acc); mx_closesocket(lst);
}

/* ---- the export versus the pointer ---------------------------------------------------------------------------------- */

TEST(transmitfile_export_with_invalid_socket_fails_before_dispatch)
{
    LPFN_TRANSMITFILE fn = UIN("mswsock.dll", TransmitFile);
    OVERLAPPED ov;
    NEED_NET();
    REQUIRE(fn);
    memset(&ov, 0, sizeof ov);
    ov.Internal = MX_POISON;
    mx_WSASetLastError(0);
    MX_EQ(fn(INVALID_SOCKET, NULL, 0, 0, &ov, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
    MX_EQ((ULONG)ov.Internal, MX_POISON);
}

TEST(transmitfile_export_sends_file_head_and_tail_like_the_pointer)
{
    LPFN_TRANSMITFILE fn = UIN("mswsock.dll", TransmitFile);
    TRANSMIT_FILE_BUFFERS b;
    struct tf t;
    TF(t, FSZ);
    REQUIRE(fn);
    b.Head = "[["; b.HeadLength = 2; b.Tail = "]]"; b.TailLength = 2;
    CHECK(fn(t.c, t.f, 0, 0, NULL, &b, 0));
    mx_expect_bytes(t.a, "[[", 2);
    mx_expect_slice(t.a, SEED, 0, FSZ);
    mx_expect_bytes(t.a, "]]", 2);
    tf_rewind(&t);
    CHECK(t.x.transmitfile(t.c, t.f, 0, 0, NULL, &b, 0));
    mx_expect_bytes(t.a, "[[", 2);
    mx_expect_slice(t.a, SEED, 0, FSZ);
    mx_expect_bytes(t.a, "]]", 2);
    tf_close(&t);
}

TEST(transmitfile_export_and_pointer_report_the_same_failures_on_a_live_socket)
{
    LPFN_TRANSMITFILE fn = UIN("mswsock.dll", TransmitFile);
    struct tf t;
    unsigned route;
    TF(t, FSZ);
    REQUIRE(fn);
    for (route = 0; route < 2; route++) {
        LPFN_TRANSMITFILE f = route ? fn : t.x.transmitfile;
        mx_WSASetLastError(0);
        t_check(f(t.c, t.f, 0, 0, NULL, NULL, 0x30) == FALSE && mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__,
                "exclusive worker flags rejected", "route %u err %d", route, mx_WSAGetLastError());
        mx_WSASetLastError(0);
        t_check(f(t.c, t.f, 0, 0, NULL, NULL, 0x40) == FALSE && mx_WSAGetLastError() == WSAEINVAL, __FILE__, __LINE__,
                "flag rejected", "route %u err %d", route, mx_WSAGetLastError());
    }
    tf_close(&t);
}

TEST(transmitfile_wsock32_forwarder_sends_data)
{
    LPFN_TRANSMITFILE fn = UIN("wsock32.dll", TransmitFile);
    struct tf t;
    TF(t, FSZ);
    REQUIRE(fn);
    CHECK(fn(t.c, t.f, 1000, 0, NULL, NULL, 0));
    mx_expect_slice(t.a, SEED, 0, 1000);
    tf_close(&t);
}

TEST(transmitfile_synchronous_call_leaves_the_file_pointer_where_it_was)
{
    struct tf t;
    LONG pos;
    TF(t, FSZ);
    SetFilePointer(t.f, 100, NULL, FILE_BEGIN);
    CHECK(t.x.transmitfile(t.c, t.f, 300, 0, NULL, NULL, 0));
    mx_expect_slice(t.a, SEED, 100, 300);
    pos = (LONG)SetFilePointer(t.f, 0, NULL, FILE_CURRENT);
    MX_EQ(pos, 100);   /* the synchronous call reads at the current position but does not move the pointer */
    tf_close(&t);
}

/* An offset/count window between a head and a tail buffer: the stream is head, window, tail. */
TEST(transmitfile_window_between_head_and_tail_buffers)
{
    TRANSMIT_FILE_BUFFERS b;
    DWORD n = 0, err = 0;
    struct tf t;
    TF(t, FSZ);
    b.Head = "HH"; b.HeadLength = 2; b.Tail = "TTT"; b.TailLength = 3;
    CHECK(tf_ov(&t, 1234, 700, 0, &b, 0, &n, &err));
    t_note("completion byte count for head 2 + window 700 + tail 3: %lu", n);
    mx_expect_bytes(t.a, "HH", 2);
    mx_expect_slice(t.a, SEED, 1234, 700);
    mx_expect_bytes(t.a, "TTT", 3);
    CHECK(mx_quiet(t.a, TF_BAD_FLAGS_SENT_NOTHING_WAIT_MS));
    tf_close(&t);
}

/* TF_USE_KERNEL_APC may depend on the initiating thread being alertable for long transfers; both waiting styles
 * are tried and the outcome recorded (the data itself is always verified when it arrives). */
TEST(transmitfile_kernel_apc_long_transfer_recorded)
{
    enum { LONGSZ = 192 * 1024 };
    int style;
    for (style = 0; style < 2; style++) {
        struct tf t;
        HANDLE big;
        OVERLAPPED ov;
        struct mx_sink k;
        DWORD wr;
        int e;
        if (!tf_open(&t, 10)) { tf_close(&t); t_skip("fixture"); return; }
        big = mx_make_file("tf_apc.bin", LONGSZ, SEED + 9, GENERIC_READ | GENERIC_WRITE, 0);
        mx_sink_start(&k, t.a, LONGSZ);
        memset(&ov, 0, sizeof ov);
        ov.hEvent = mx_event();
        e = t.x.transmitfile(t.c, big, 0, 0, &ov, NULL, TF_USE_KERNEL_APC) ? 0 : mx_WSAGetLastError();
        t_check(e == 0 || e == ERROR_IO_PENDING, __FILE__, __LINE__, "posts", "error %d", e);
        wr = style ? WaitForSingleObjectEx(ov.hEvent, 8000, TRUE) : WaitForSingleObject(ov.hEvent, 8000);
        t_note("TF_USE_KERNEL_APC, 192 KiB, %s wait: wait result %lu, %d bytes delivered", style ? "alertable" : "plain", wr, mx_sink_join(&k));
        if (wr != WAIT_OBJECT_0) mx_abort(t.c, &ov);
        else if (k.got == LONGSZ) {
            int i, bad = 0;
            for (i = 0; i < LONGSZ; i += 509) if (k.buf[i] != mx_pat((DWORD)i, SEED + 9)) bad++;
            MX_EQ(bad, 0);
        }
        mx_sink_free(&k);
        CloseHandle(ov.hEvent);
        CloseHandle(big);
        tf_close(&t);
    }
}
