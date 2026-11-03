/* TransmitPackets and TransmitFile reached through the looked-up pointers: element handling, send sizes,
 * disconnect flags, error codes, synchronous versus overlapped completion. Data is verified byte for byte on the
 * receiving socket. Synchronous calls on a blocking socket wait for completion inside the call. */
#include "xf.h"

typedef BOOL (WINAPI *tp_fn)(SOCKET, LPTRANSMIT_PACKETS_ELEMENT, DWORD, DWORD, LPOVERLAPPED, DWORD);
typedef BOOL (WINAPI *tf_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);

static tp_fn get_tp(void) { GUID g = WSAID_TRANSMITPACKETS; return (tp_fn)xf_fn(&g); }
static tf_fn get_tf(void) { GUID g = WSAID_TRANSMITFILE;    return (tf_fn)xf_fn(&g); }
#define NEED_TP(f) tp_fn f = get_tp(); do { if (!f) { t_skip("TransmitPackets unavailable"); return; } } while (0)
#define NEED_TF(f) tf_fn f = get_tf(); do { if (!f) { t_skip("TransmitFile unavailable"); return; } } while (0)

#define FLEN 5000
static char fdata[FLEN];

/* A scratch file with known contents (byte i derived from i); returns an open read handle or invalid. */
static HANDLE make_file(int overlapped)
{
    char path[MAX_PATH]; HANDLE h; DWORD n; int i;
    for (i = 0; i < FLEN; i++) fdata[i] = (char)('a' + (i * 5 + i / 97) % 26);
    t_tmpfile(path, sizeof path, overlapped ? "xf_tp_ov.bin" : "xf_tp.bin");
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return h;
    if (!WriteFile(h, fdata, FLEN, &n, NULL) || n != FLEN) { CloseHandle(h); return INVALID_HANDLE_VALUE; }
    if (overlapped) {                       /* reopen the finished file for asynchronous reads */
        CloseHandle(h);
        h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        return h;
    }
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    return h;
}

static void el_mem(TRANSMIT_PACKETS_ELEMENT *e, const void *p, ULONG len)
{
    memset(e, 0, sizeof *e);
    e->dwElFlags = TP_ELEMENT_MEMORY;
    e->cLength = len;
    e->pBuffer = (PVOID)p;
}
static void el_file(TRANSMIT_PACKETS_ELEMENT *e, HANDLE h, ULONG64 off, ULONG len)
{
    memset(e, 0, sizeof *e);
    e->dwElFlags = TP_ELEMENT_FILE;
    e->cLength = len;
    e->nFileOffset.QuadPart = (LONGLONG)off;
    e->hFile = h;
}

/* Expects exactly `want` on s next (and optionally nothing more). */
static void expect_stream(SOCKET s, const void *want, int len)
{
    char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, len + 16);
    int got;
    if (!buf) { CHECK(0); return; }
    got = xf_read_all(s, buf, len);
    CHECKF(got == len, "received %d of %d bytes", got, len);
    if (got == len) CHECK(!memcmp(buf, want, len));
    HeapFree(GetProcessHeap(), 0, buf);
}
static void expect_quiet(SOCKET s) { CHECK(!xf_readable(s, 150)); }


/* Bounded-wait wrappers: the disconnect flavours are issued overlapped from a helper thread, so that a stack that
 * blocks inside the call cannot hang the run. They return 1 when the operation completed successfully (inline or
 * after the wait), else 0 with the error stored. A call that never returns is abandoned (reported as failure). */
struct bcall {
    tf_fn tf; tp_fn tp; SOCKET s; HANDLE f; DWORD n, per, flags; TRANSMIT_FILE_BUFFERS *tb;
    TRANSMIT_PACKETS_ELEMENT *e; int ok, err;
};
static DWORD WINAPI bcall_thread(LPVOID arg)
{
    struct bcall *c = (struct bcall *)arg;
    WSAOVERLAPPED ov; DWORD got = 0, fl = 0; int r;
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    WSASetLastError(0);
    r = c->tf ? c->tf(c->s, c->f, c->n, c->per, &ov, c->tb, c->flags) : c->tp(c->s, c->e, c->n, c->per, &ov, c->flags);
    if (!r && WSAGetLastError() == ERROR_IO_PENDING) {
        r = (int)xf_ov_wait(c->s, &ov, &got, &fl, 6000);
        c->err = r ? 0 : WSAGetLastError();
    } else c->err = r ? 0 : WSAGetLastError();
    c->ok = r;
    WSACloseEvent(ov.hEvent);
    return 0;
}
static int bcall_run(struct bcall *c, int *err)
{
    HANDLE h = CreateThread(NULL, 0, bcall_thread, c, 0, NULL);
    if (!h) { *err = -1; return 0; }
    if (WaitForSingleObject(h, 12000) != WAIT_OBJECT_0) { CloseHandle(h); *err = -2; return 0; }
    CloseHandle(h);
    *err = c->err;
    return c->ok;
}
static int tf_bounded(tf_fn tf, SOCKET s, HANDLE f, DWORD n, DWORD per, TRANSMIT_FILE_BUFFERS *tb, DWORD flags, int *err)
{
    static struct bcall c;
    memset(&c, 0, sizeof c);
    c.tf = tf; c.s = s; c.f = f; c.n = n; c.per = per; c.tb = tb; c.flags = flags;
    return bcall_run(&c, err);
}
static int tp_bounded(tp_fn tp, SOCKET s, TRANSMIT_PACKETS_ELEMENT *e, DWORD cnt, DWORD per, DWORD flags, int *err)
{
    static struct bcall c;
    memset(&c, 0, sizeof c);
    c.tp = tp; c.s = s; c.e = e; c.n = cnt; c.per = per; c.flags = flags;
    return bcall_run(&c, err);
}

/* ---- TransmitPackets ------------------------------------------------------------------------------------- */

TEST(xf_tpackets_invalid_socket_is_notsock)
{
    TRANSMIT_PACKETS_ELEMENT e;
    NEED_NET(); NEED_TP(tp);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    CHECK(!tp(INVALID_SOCKET, &e, 1, 0, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_tpackets_closed_socket_is_notsock)
{
    TRANSMIT_PACKETS_ELEMENT e; SOCKET s;
    NEED_NET(); NEED_TP(tp);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    closesocket(s);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    CHECK(!tp(s, &e, 1, 0, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}
TEST(xf_tpackets_unconnected_stream_socket_is_notconn)
{
    TRANSMIT_PACKETS_ELEMENT e; SOCKET s;
    NEED_NET(); NEED_TP(tp);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    CHECK(!tp(s, &e, 1, 0, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(s);
}
TEST(xf_tpackets_listening_socket_is_enotconn)
{
    TRANSMIT_PACKETS_ELEMENT e; SOCKET l; struct sockaddr_in a;
    NEED_NET(); NEED_TP(tp);
    l = xf_listener(&a, 1);
    REQUIRE(l != INVALID_SOCKET);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    CHECK(!tp(l, &e, 1, 0, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(l);
}
TEST(xf_tpackets_datagram_socket_is_enotconn)
{
    TRANSMIT_PACKETS_ELEMENT e; SOCKET u;
    NEED_NET(); NEED_TP(tp);
    u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(u != INVALID_SOCKET);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    CHECK(!tp(u, &e, 1, 0, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(u);
}
TEST(xf_tpackets_single_memory_element)
{
    TRANSMIT_PACKETS_ELEMENT e;
    NEED_TP(tp);
    PAIR(p);
    el_mem(&e, "single element", 14);
    WSASetLastError(0);
    CHECKF(tp(p.cli, &e, 1, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, "single element", 14);
    expect_quiet(p.srv);
    xf_pair_close(&p);
}
TEST(xf_tpackets_memory_elements_are_concatenated_in_order)
{
    TRANSMIT_PACKETS_ELEMENT e[4];
    NEED_TP(tp);
    PAIR(p);
    el_mem(&e[0], "AAAA", 4); el_mem(&e[1], "bb", 2); el_mem(&e[2], "CCCCCC", 6); el_mem(&e[3], "d", 1);
    CHECKF(tp(p.cli, e, 4, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, "AAAAbbCCCCCCd", 13);
    expect_quiet(p.srv);
    xf_pair_close(&p);
}
TEST(xf_tpackets_whole_file_when_length_is_zero)
{
    TRANSMIT_PACKETS_ELEMENT e; HANDLE f;
    NEED_TP(tp);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    el_file(&e, f, 0, 0);
    CHECKF(tp(p.cli, &e, 1, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, fdata, FLEN);
    expect_quiet(p.srv);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tpackets_file_range)
{
    static const struct { ULONG64 off; ULONG len; } r[] = {{0, 1}, {1, 100}, {1000, 2000}, {FLEN - 10, 10}, {FLEN - 1, 1}, {4096, 904}};
    unsigned i;
    NEED_TP(tp);
    for (i = 0; i < sizeof r / sizeof r[0]; i++) {
        TRANSMIT_PACKETS_ELEMENT e; HANDLE f;
        PAIR(p);
        f = make_file(0);
        REQUIRE(f != INVALID_HANDLE_VALUE);
        el_file(&e, f, r[i].off, r[i].len);
        CHECKF(tp(p.cli, &e, 1, 0, NULL, 0), "range %u: err=%d", i, WSAGetLastError());
        expect_stream(p.srv, fdata + r[i].off, (int)r[i].len);
        expect_quiet(p.srv);
        CloseHandle(f);
        xf_pair_close(&p);
    }
}
TEST(xf_tpackets_file_from_offset_to_end_when_length_is_zero)
{
    TRANSMIT_PACKETS_ELEMENT e; HANDLE f;
    NEED_TP(tp);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    el_file(&e, f, 3000, 0);
    CHECKF(tp(p.cli, &e, 1, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, fdata + 3000, FLEN - 3000);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tpackets_mixed_memory_and_file_elements)
{
    TRANSMIT_PACKETS_ELEMENT e[4]; HANDLE f; char want[64 + FLEN]; size_t n = 0;
    NEED_TP(tp);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    el_mem(&e[0], "<head>", 6); el_file(&e[1], f, 10, 20); el_mem(&e[2], "<mid>", 5); el_file(&e[3], f, 0, 0);
    memcpy(want + n, "<head>", 6); n += 6;
    memcpy(want + n, fdata + 10, 20); n += 20;
    memcpy(want + n, "<mid>", 5); n += 5;
    memcpy(want + n, fdata, FLEN); n += FLEN;
    CHECKF(tp(p.cli, e, 4, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, want, (int)n);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tpackets_same_file_twice_reads_independently_of_file_pointer)
{
    TRANSMIT_PACKETS_ELEMENT e[2]; HANDLE f; char want[200];
    NEED_TP(tp);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    SetFilePointer(f, 777, NULL, FILE_BEGIN);       /* a stray file position must not matter */
    el_file(&e[0], f, 5, 50); el_file(&e[1], f, 5, 50);
    memcpy(want, fdata + 5, 50); memcpy(want + 50, fdata + 5, 50);
    CHECKF(tp(p.cli, e, 2, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, want, 100);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tpackets_send_size_does_not_change_the_stream)
{
    static const DWORD sizes[] = {1, 7, 100, 1460, 4096, 100000};
    unsigned i;
    NEED_TP(tp);
    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        TRANSMIT_PACKETS_ELEMENT e; HANDLE f;
        PAIR(p);
        f = make_file(0);
        REQUIRE(f != INVALID_HANDLE_VALUE);
        el_file(&e, f, 0, 0);
        CHECKF(tp(p.cli, &e, 1, sizes[i], NULL, 0), "send size %lu: err=%d", sizes[i], WSAGetLastError());
        expect_stream(p.srv, fdata, FLEN);
        CloseHandle(f);
        xf_pair_close(&p);
    }
}
TEST(xf_tpackets_large_memory_element)
{
    enum { N = 300000 };
    char *out = (char *)HeapAlloc(GetProcessHeap(), 0, N); TRANSMIT_PACKETS_ELEMENT e; int i;
    NEED_TP(tp);
    REQUIRE(out);
    for (i = 0; i < N; i++) out[i] = (char)(i * 7 + (i >> 8));
    {
        PAIR(p);
        el_mem(&e, out, N);
        /* the receiver drains in a thread-free way: the kernel buffers more than the loopback window only partly,
         * so use a overlapped call and drain meanwhile */
        {
            WSAOVERLAPPED ov; char *in = (char *)HeapAlloc(GetProcessHeap(), 0, N); int got = 0;
            memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
            if (!tp(p.cli, &e, 1, 0, &ov, 0) && WSAGetLastError() != ERROR_IO_PENDING) CHECKF(0, "err=%d", WSAGetLastError());
            if (in) { got = xf_read_all(p.srv, in, N); CHECKF(got == N, "received %d", got); if (got == N) CHECK(!memcmp(in, out, N)); HeapFree(GetProcessHeap(), 0, in); }
            { DWORD n, fl; CHECK(xf_ov_wait(p.cli, &ov, &n, &fl, 8000)); }
            WSACloseEvent(ov.hEvent);
        }
        xf_pair_close(&p);
    }
    HeapFree(GetProcessHeap(), 0, out);
}
TEST(xf_tpackets_zero_elements_is_einval)
{
    TRANSMIT_PACKETS_ELEMENT e; int r;
    NEED_TP(tp);
    PAIR(p);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    r = tp(p.cli, &e, 0, 0, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}
TEST(xf_tpackets_null_array_with_zero_count_is_einval)
{
    int r;
    NEED_TP(tp);
    PAIR(p);
    WSASetLastError(0);
    r = tp(p.cli, NULL, 0, 0, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}
TEST(xf_tpackets_element_without_type_flags_is_einval)
{
    TRANSMIT_PACKETS_ELEMENT e; int r;
    NEED_TP(tp);
    PAIR(p);
    el_mem(&e, "x", 1);
    e.dwElFlags = 0;
    WSASetLastError(0);
    r = tp(p.cli, &e, 1, 0, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}
TEST(xf_tpackets_end_of_packet_flag_does_not_change_stream_content)
{
    TRANSMIT_PACKETS_ELEMENT e[2];
    NEED_TP(tp);
    PAIR(p);
    el_mem(&e[0], "left", 4); e[0].dwElFlags |= TP_ELEMENT_EOP;
    el_mem(&e[1], "right", 5);
    CHECKF(tp(p.cli, e, 2, 0, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, "leftright", 9);
    xf_pair_close(&p);
}
TEST(xf_tpackets_invalid_file_handle_is_error_invalid_handle)
{
    TRANSMIT_PACKETS_ELEMENT e; int r;
    NEED_TP(tp);
    PAIR(p);
    el_file(&e, INVALID_HANDLE_VALUE, 0, 10);
    WSASetLastError(0);
    r = tp(p.cli, &e, 1, 0, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), ERROR_INVALID_HANDLE);
    xf_pair_close(&p);
}
TEST(xf_tpackets_file_offset_past_end_is_einval)
{
    TRANSMIT_PACKETS_ELEMENT e; HANDLE f; int r;
    NEED_TP(tp);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    el_file(&e, f, FLEN + 100, 10);
    WSASetLastError(0);
    r = tp(p.cli, &e, 1, 0, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tpackets_disconnect_flag_ends_the_stream_after_data)
{
    TRANSMIT_PACKETS_ELEMENT e; char b[16];
    NEED_TP(tp);
    PAIR(p);
    el_mem(&e, "last words", 10);
    { int er = 0; CHECKF(tp_bounded(tp, p.cli, &e, 1, 0, TP_DISCONNECT, &er), "err=%d", er); }
    expect_stream(p.srv, "last words", 10);
    WAIT_READABLE(p.srv);
    EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);
    xf_pair_close(&p);
}
TEST(xf_tpackets_disconnect_and_reuse_completes_after_peer_closes)
{
    TRANSMIT_PACKETS_ELEMENT e; char b[16]; WSAOVERLAPPED ov; DWORD n = 0, fl = 0; int r;
    NEED_TP(tp);
    PAIR(p);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    el_mem(&e, "bye", 3);
    WSASetLastError(0);
    r = tp(p.cli, &e, 1, 0, &ov, TP_DISCONNECT | TP_REUSE_SOCKET);
    CHECKF(r || WSAGetLastError() == WSA_IO_PENDING, "r=%d err=%d", r, WSAGetLastError());
    expect_stream(p.srv, "bye", 3);
    WAIT_READABLE(p.srv);
    EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);        /* the end of stream is visible at once ... */
    closesocket(p.srv); p.srv = INVALID_SOCKET;           /* ... the request finishes once the peer closed too */
    CHECKF(r || xf_ov_wait(p.cli, &ov, &n, &fl, 8000), "completion error %d", WSAGetLastError());
    WSACloseEvent(ov.hEvent);
    xf_pair_close(&p);
}
TEST(xf_tpackets_overlapped_completes_with_data_delivered)
{
    TRANSMIT_PACKETS_ELEMENT e[2]; WSAOVERLAPPED ov; DWORD n = 0, fl = 0; int r;
    NEED_TP(tp);
    PAIR(p);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    el_mem(&e[0], "over", 4); el_mem(&e[1], "lapped", 6);
    WSASetLastError(0);
    r = tp(p.cli, e, 2, 0, &ov, 0);
    CHECKF(r || WSAGetLastError() == ERROR_IO_PENDING, "r=%d err=%d", r, WSAGetLastError());
    expect_stream(p.srv, "overlapped", 10);
    CHECK(xf_ov_wait(p.cli, &ov, &n, &fl, 5000));
    t_note("TransmitPackets overlapped byte count: %s", n == 10 ? "total payload" : n == 0 ? "zero" : "other");
    WSACloseEvent(ov.hEvent);
    xf_pair_close(&p);
}
TEST(xf_tpackets_overlapped_on_unconnected_socket_fails_synchronously_or_at_completion)
{
    TRANSMIT_PACKETS_ELEMENT e; WSAOVERLAPPED ov; SOCKET s; int r;
    NEED_NET(); NEED_TP(tp);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    r = tp(s, &e, 1, 0, &ov, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    WSACloseEvent(ov.hEvent);
    closesocket(s);
}
TEST(xf_tpackets_after_peer_closed_eventually_fails)
{
    TRANSMIT_PACKETS_ELEMENT e; char big[65536]; int i, failed = 0;
    NEED_TP(tp);
    PAIR(p);
    memset(big, 'z', sizeof big);
    closesocket(p.srv); p.srv = INVALID_SOCKET;
    el_mem(&e, big, sizeof big);
    for (i = 0; i < 20 && !failed; i++) {
        WSASetLastError(0);
        if (!tp(p.cli, &e, 1, 0, NULL, 0)) {
            int err = WSAGetLastError();
            failed = 1;
            CHECKF(err == WSAECONNRESET || err == WSAECONNABORTED || err == WSAESHUTDOWN, "error %d", err);
        }
    }
    CHECK(failed);
    xf_pair_close(&p);
}
TEST(xf_tpackets_after_shutdown_send_is_einval)
{
    TRANSMIT_PACKETS_ELEMENT e;
    NEED_TP(tp);
    PAIR(p);
    CHECK(shutdown(p.cli, SD_SEND) == 0);
    el_mem(&e, "x", 1);
    WSASetLastError(0);
    CHECK(!tp(p.cli, &e, 1, 0, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}

/* ---- TransmitFile -------------------------------------------------------------------------------------------- */

TEST(xf_tfile_disconnect_flag_ends_the_stream_after_data)
{
    TRANSMIT_FILE_BUFFERS tb; char b[16]; char head[] = "H";
    NEED_TF(tf);
    PAIR(p);
    memset(&tb, 0, sizeof tb); tb.Head = head; tb.HeadLength = 1;
    { int er = 0; CHECKF(tf_bounded(tf, p.cli, NULL, 0, 0, &tb, TF_DISCONNECT, &er), "err=%d", er); }
    expect_stream(p.srv, "H", 1);
    WAIT_READABLE(p.srv);
    EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);
    xf_pair_close(&p);
}
TEST(xf_tfile_disconnect_with_file_sends_everything_first)
{
    HANDLE f; char b[8];
    NEED_TF(tf);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    { int er = 0; CHECKF(tf_bounded(tf, p.cli, f, 0, 0, NULL, TF_DISCONNECT, &er), "err=%d", er); }
    expect_stream(p.srv, fdata, FLEN);
    WAIT_READABLE(p.srv);
    EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tfile_disconnect_and_reuse_completes_after_peer_closes)
{
    char b[8]; TRANSMIT_FILE_BUFFERS tb; char head[] = "z"; WSAOVERLAPPED ov; DWORD n = 0, fl = 0; int r;
    NEED_TF(tf);
    PAIR(p);
    memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
    memset(&tb, 0, sizeof tb); tb.Head = head; tb.HeadLength = 1;
    WSASetLastError(0);
    r = tf(p.cli, NULL, 0, 0, &ov, &tb, TF_DISCONNECT | TF_REUSE_SOCKET);
    CHECKF(r || WSAGetLastError() == WSA_IO_PENDING, "r=%d err=%d", r, WSAGetLastError());
    expect_stream(p.srv, "z", 1);
    WAIT_READABLE(p.srv);
    EXPECT_EQ(xf_recv(p.srv, b, sizeof b, 0), 0);
    closesocket(p.srv); p.srv = INVALID_SOCKET;
    CHECKF(r || xf_ov_wait(p.cli, &ov, &n, &fl, 8000), "completion error %d", WSAGetLastError());
    WSACloseEvent(ov.hEvent);
    xf_pair_close(&p);
}
TEST(xf_tfile_bytes_per_send_variants_do_not_change_stream)
{
    static const DWORD sizes[] = {1, 100, 1460, 4999, 5000, 5001, 100000};
    unsigned i;
    NEED_TF(tf);
    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        HANDLE f;
        PAIR(p);
        f = make_file(0);
        REQUIRE(f != INVALID_HANDLE_VALUE);
        CHECKF(tf(p.cli, f, 0, sizes[i], NULL, NULL, 0), "per-send %lu: err=%d", sizes[i], WSAGetLastError());
        expect_stream(p.srv, fdata, FLEN);
        CloseHandle(f);
        xf_pair_close(&p);
    }
}
TEST(xf_tfile_byte_count_larger_than_file_is_einval)
{
    HANDLE f; int r;
    NEED_TF(tf);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    WSASetLastError(0);
    r = tf(p.cli, f, FLEN + 500, 0, NULL, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tfile_starts_at_current_file_pointer)
{
    HANDLE f;
    NEED_TF(tf);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    SetFilePointer(f, 1234, NULL, FILE_BEGIN);
    CHECKF(tf(p.cli, f, 0, 0, NULL, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, fdata + 1234, FLEN - 1234);
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tfile_invalid_file_handle_is_error_invalid_handle)
{
    int r;
    NEED_TF(tf);
    PAIR(p);
    WSASetLastError(0);
    r = tf(p.cli, INVALID_HANDLE_VALUE, 10, 0, NULL, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), ERROR_INVALID_HANDLE);
    xf_pair_close(&p);
}
TEST(xf_tfile_non_file_handle_is_error_invalid_handle)
{
    int r; HANDLE ev;
    NEED_TF(tf);
    PAIR(p);
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(ev);
    WSASetLastError(0);
    r = tf(p.cli, ev, 10, 0, NULL, NULL, 0);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), ERROR_INVALID_HANDLE);
    CloseHandle(ev);
    xf_pair_close(&p);
}
TEST(xf_tfile_head_only_and_tail_only)
{
    TRANSMIT_FILE_BUFFERS tb; char head[] = "HEAD", tail[] = "TAIL";
    NEED_TF(tf);
    PAIR(p);
    memset(&tb, 0, sizeof tb); tb.Head = head; tb.HeadLength = 4;
    CHECK(tf(p.cli, NULL, 0, 0, NULL, &tb, 0));
    expect_stream(p.srv, "HEAD", 4);
    memset(&tb, 0, sizeof tb); tb.Tail = tail; tb.TailLength = 4;
    CHECK(tf(p.cli, NULL, 0, 0, NULL, &tb, 0));
    expect_stream(p.srv, "TAIL", 4);
    xf_pair_close(&p);
}
TEST(xf_tfile_buffers_with_lengths_zero_send_nothing)
{
    TRANSMIT_FILE_BUFFERS tb; char head[] = "unused";
    NEED_TF(tf);
    PAIR(p);
    memset(&tb, 0, sizeof tb); tb.Head = head; tb.HeadLength = 0; tb.Tail = head; tb.TailLength = 0;
    CHECK(tf(p.cli, NULL, 0, 0, NULL, &tb, 0));
    expect_quiet(p.srv);
    xf_pair_close(&p);
}
TEST(xf_tfile_two_calls_append)
{
    HANDLE f;
    NEED_TF(tf);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(tf(p.cli, f, 100, 0, NULL, NULL, 0));
    CHECK(tf(p.cli, f, 100, 0, NULL, NULL, 0));      /* continues from the advanced file pointer or restarts; either way 200 bytes */
    {
        char b[200];
        EXPECT_EQ(xf_read_all(p.srv, b, 200), 200);
        CHECK(!memcmp(b, fdata, 100));
    }
    CloseHandle(f);
    xf_pair_close(&p);
}
TEST(xf_tfile_undefined_flag_bit_is_einval)
{
    int r;
    NEED_TF(tf);
    PAIR(p);
    WSASetLastError(0);
    r = tf(p.cli, NULL, 0, 0, NULL, NULL, 0x80000000);
    CHECK(!r);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}
TEST(xf_tfile_after_shutdown_send_is_einval)
{
    TRANSMIT_FILE_BUFFERS tb; char head[] = "x";
    NEED_TF(tf);
    PAIR(p);
    CHECK(shutdown(p.cli, SD_SEND) == 0);
    memset(&tb, 0, sizeof tb); tb.Head = head; tb.HeadLength = 1;
    WSASetLastError(0);
    CHECK(!tf(p.cli, NULL, 0, 0, NULL, &tb, 0));
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    xf_pair_close(&p);
}
TEST(xf_tfile_overlapped_file_handle_synchronous_socket_call)
{
    HANDLE f;
    NEED_TF(tf);
    PAIR(p);
    f = make_file(1);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    {
        WSAOVERLAPPED ov; int r; DWORD n = 0, fl = 0;
        memset(&ov, 0, sizeof ov); ov.hEvent = WSACreateEvent();
        r = tf(p.cli, f, 0, 0, &ov, NULL, 0);
        CHECKF(r || WSAGetLastError() == ERROR_IO_PENDING, "r=%d err=%d", r, WSAGetLastError());
        expect_stream(p.srv, fdata, FLEN);
        CHECK(xf_ov_wait(p.cli, &ov, &n, &fl, 5000));
        EXPECT_EQ(n, FLEN);
        WSACloseEvent(ov.hEvent);
    }
    CloseHandle(f);
    xf_pair_close(&p);
}

/* ---- where a file element starts reading ------------------------------------------------------------------------ */
/* Recorded: how the element offset interacts with the file pointer, and what a zero length means. */
static int tp_probe(HANDLE f, ULONG64 off, ULONG len, long filepos, char *out, int cap)
{
    TRANSMIT_PACKETS_ELEMENT e; tp_fn tp = get_tp(); int er = 0, got;
    struct xf_pair p;
    if (!tp || !xf_pair_open(&p)) { xf_pair_close(&p); return -3; }
    SetFilePointer(f, filepos, NULL, FILE_BEGIN);
    el_file(&e, f, off, len);
    if (!tp_bounded(tp, p.cli, &e, 1, 0, 0, &er)) { xf_pair_close(&p); return -1 - 100 * er; }
    shutdown(p.cli, SD_SEND);
    got = xf_read_all(p.srv, out, cap);
    xf_pair_close(&p);
    return got;
}
TEST(xf_tpackets_file_element_offset_versus_file_pointer)
{
    char out[FLEN + 16]; HANDLE f; int n;
    NEED_NET();
    REQUIRE(get_tp());
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    n = tp_probe(f, 100, 20, 0, out, sizeof out);
    EXPECT_EQ(n, 20);
    CHECK(n == 20 && !memcmp(out, fdata + 100, 20));
    n = tp_probe(f, 100, 20, 3000, out, sizeof out);          /* a non-zero offset ignores the file pointer */
    EXPECT_EQ(n, 20);
    CHECK(n == 20 && !memcmp(out, fdata + 100, 20));
    n = tp_probe(f, 0, 20, 3000, out, sizeof out);            /* offset zero means "at the current file pointer" */
    EXPECT_EQ(n, 20);
    CHECK(n == 20 && !memcmp(out, fdata + 3000, 20));
    CloseHandle(f);
}
TEST(xf_tpackets_file_element_zero_length_meaning)
{
    char out[FLEN + 16]; HANDLE f; int n;
    NEED_NET();
    REQUIRE(get_tp());
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    n = tp_probe(f, 0, 0, 0, out, sizeof out);
    EXPECT_EQ(n, FLEN);                                    /* whole file when offset and length are zero and the pointer is at the start */
    n = tp_probe(f, 100, 0, 0, out, sizeof out);               /* zero length: everything from the offset to the end */
    EXPECT_EQ(n, FLEN - 100);
    CHECK(n == FLEN - 100 && !memcmp(out, fdata + 100, FLEN - 100));
    n = tp_probe(f, 0, 0, 1000, out, sizeof out);               /* offset zero starts at the file pointer */
    EXPECT_EQ(n, FLEN - 1000);
    CHECK(n == FLEN - 1000 && !memcmp(out, fdata + 1000, FLEN - 1000));
    CloseHandle(f);
}
TEST(xf_tfile_zero_byte_count_sends_to_end_of_file)
{
    HANDLE f;
    NEED_TF(tf);
    PAIR(p);
    f = make_file(0);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECKF(tf(p.cli, f, 0, 0, NULL, NULL, 0), "err=%d", WSAGetLastError());
    expect_stream(p.srv, fdata, FLEN);
    CloseHandle(f);
    xf_pair_close(&p);
}
