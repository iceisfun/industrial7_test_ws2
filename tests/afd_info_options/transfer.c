/* IOCTL_AFD_TRANSMIT_FILE (0x1207f) and IOCTL_AFD_TRANSMIT_PACKETS (0x120c3) with real file data.
 *
 * Minimal forms are in misc.c; here the file path is exercised: whole file, a range, a head and a tail,
 * the disconnect flag, and the handle validation. The request completes once the transport accepted the
 * bytes and reports their count (head + file range + tail) in Information.
 */
#include "aio.h"
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

typedef struct {
    LONGLONG Offset;
    LONGLONG WriteLength;
    ULONG SendPacketLength; ULONG pad0;
    HANDLE File;
    void *Head; ULONG HeadLength; ULONG pad1;
    void *Tail; ULONG TailLength; ULONG Flags;
} tf_t;

typedef struct { ULONG Flags; ULONG Length; union { struct { LONGLONG Offset; HANDLE File; } f; void *Buffer; } u; } tpe_t;
typedef struct { tpe_t *Array; ULONG Count; ULONG SendSize; ULONG Flags; ULONG pad; } tp_t;

#define FILE_BYTES 5000

/* A scratch file of FILE_BYTES bytes: byte i has the value (i * 13 + 5) & 0xff. */
static HANDLE make_file(void)
{
    char path[MAX_PATH];
    unsigned char *data = HeapAlloc(GetProcessHeap(), 0, FILE_BYTES);
    DWORD wr = 0;
    HANDLE h;
    int i;
    for (i = 0; i < FILE_BYTES; i++) data[i] = (unsigned char)(i * 13 + 5);
    t_tmpfile(path, sizeof path, "aio_transmit.bin");
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h != INVALID_HANDLE_VALUE) { WriteFile(h, data, FILE_BYTES, &wr, NULL); SetFilePointer(h, 0, NULL, FILE_BEGIN); }
    HeapFree(GetProcessHeap(), 0, data);
    return h;
}
static void expect_stream(SOCKET s, const unsigned char *want, int n, const char *what)
{
    unsigned char *got = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n + 64);
    int total = 0;
    DWORD t0 = GetTickCount();
    aio_nonblock(s, 1);
    while (total < n + 1 && GetTickCount() - t0 < 4000) {
        int r = W.recv(s, (char *)got + total, n + 64 - total, 0);
        if (r > 0) total += r;
        else if (r == 0) break;
        else if (total >= n && GetTickCount() - t0 > 400) break;
        else Sleep(5);
    }
    t_check(total == n, __FILE__, __LINE__, what, "received %d bytes want %d", total, n);
    if (total == n) t_check(!memcmp(got, want, n), __FILE__, __LINE__, what, "payload differs");
    HeapFree(GetProcessHeap(), 0, got);
}
static void expected_file(unsigned char *out, int off, int len)
{
    int i;
    for (i = 0; i < len; i++) out[i] = (unsigned char)((off + i) * 13 + 5);
}

TEST(aio_tfile_whole_file)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    unsigned char want[FILE_BYTES];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, FILE_BYTES);
    expected_file(want, 0, FILE_BYTES);
    expect_stream(s, want, FILE_BYTES, "whole file");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tfile_write_length_limits_the_range)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    unsigned char want[300];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f; t.WriteLength = 300;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 300);
    expected_file(want, 0, 300);
    expect_stream(s, want, 300, "length-limited file");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tfile_offset_and_length)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    unsigned char want[200];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f; t.Offset = 1234; t.WriteLength = 200;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 200);
    expected_file(want, 1234, 200);
    expect_stream(s, want, 200, "file range");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tfile_offset_only_sends_the_rest)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    unsigned char want[FILE_BYTES];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f; t.Offset = 4000;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 1000);
    expected_file(want, 4000, 1000);
    expect_stream(s, want, 1000, "file tail range");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tfile_head_file_tail_order)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    char head[] = "HEAD", tail[] = "TAIL";
    unsigned char want[8 + 64];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f; t.WriteLength = 64;
    t.Head = head; t.HeadLength = 4; t.Tail = tail; t.TailLength = 4;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 72);
    memcpy(want, head, 4); expected_file(want + 4, 0, 64); memcpy(want + 68, tail, 4);
    expect_stream(s, want, 72, "head file tail");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tfile_send_packet_length_does_not_change_the_bytes)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    unsigned char want[FILE_BYTES];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f; t.SendPacketLength = 512;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, FILE_BYTES);
    expected_file(want, 0, FILE_BYTES);
    expect_stream(s, want, FILE_BYTES, "packet-size file");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tfile_disconnect_flag_closes_the_stream)
{
    AIO_BEGIN();
    SOCKET c, s;
    tf_t t;
    char head[] = "bye";
    char buf[16];
    int total = 0, r = -1;
    DWORD t0 = GetTickCount();
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.Head = head; t.HeadLength = 3; t.Flags = 1;   /* disconnect after sending */
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL), NTS_SUCCESS);
    aio_nonblock(s, 1);
    while (GetTickCount() - t0 < 4000) {
        r = W.recv(s, buf + total, (int)sizeof buf - total, 0);
        if (r > 0) total += r;
        else if (r == 0) break;
        else Sleep(5);
    }
    EXPECT_EQ(total, 3);
    EXPECT_EQ(r, 0);   /* orderly end of stream after the data */
    aio_close(c); aio_close(s);
}
TEST(aio_tfile_flags_without_effect_on_data)
{
    /* write-behind and the two worker-selection bits do not alter what is sent */
    AIO_BEGIN();
    static const ULONG flags[] = { 0x04, 0x10, 0x20, 0x14, 0x24 };
    unsigned i;
    for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        SOCKET c, s;
        tf_t t;
        char head[] = "hello";
        aio_pair(&c, &s);
        memset(&t, 0, sizeof t); t.Head = head; t.HeadLength = 5; t.Flags = flags[i];
        t_check(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL) == NTS_SUCCESS, __FILE__, __LINE__, "transmit flags", "flags 0x%lx", (unsigned long)flags[i]);
        expect_stream(s, (const unsigned char *)"hello", 5, "flag variant");
        aio_close(c); aio_close(s);
    }
}
TEST(aio_tfile_bad_file_handles)
{
    AIO_BEGIN();
    SOCKET c, s;
    tf_t t;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = (HANDLE)(ULONG_PTR)0x7776;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_HANDLE);
    t.File = ev;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL), (LONG)0xC0000024);
    CloseHandle(ev); aio_close(c); aio_close(s);
}
TEST(aio_tfile_offset_beyond_end_of_file)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tf_t t;
    IO_STATUS_BLOCK io;
    LONG st;
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.File = f; t.Offset = FILE_BYTES + 100;
    st = aio_ctl(c, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, &io, NULL);
    EXPECT_NTS(st, NTS_INVALID_PARAMETER);
    aio_close(c); aio_close(s);
    CloseHandle(f);
}
TEST(aio_tfile_not_available_on_datagram_or_listening_endpoints)
{
    AIO_BEGIN();
    tf_t t;
    SOCKET u = aio_bound(SOCK_DGRAM), l = aio_listener(NULL);
    char head[] = "x";
    memset(&t, 0, sizeof t); t.Head = head; t.HeadLength = 1;
    EXPECT_NTS(aio_ctl(u, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_CONNECTION);
    EXPECT_NTS(aio_ctl(l, IOC_TRANSMIT_FILE, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_CONNECTION);
    aio_close(u); aio_close(l);
}

/* ---- TRANSMIT_PACKETS with file elements --------------------------------------------------------- */
TEST(aio_tpkts_file_element)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tp_t t; tpe_t e[3];
    char a[] = "<<", z[] = ">>";
    IO_STATUS_BLOCK io;
    unsigned char want[2 + 100 + 2];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(e, 0, sizeof e);
    e[0].Flags = 1; e[0].Length = 2; e[0].u.Buffer = a;
    e[1].Flags = 2; e[1].Length = 100; e[1].u.f.Offset = 700; e[1].u.f.File = f;   /* file element */
    e[2].Flags = 1 | 4; e[2].Length = 2; e[2].u.Buffer = z;
    memset(&t, 0, sizeof t); t.Array = e; t.Count = 3;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 104);
    memcpy(want, a, 2); expected_file(want + 2, 700, 100); memcpy(want + 102, z, 2);
    expect_stream(s, want, 104, "packets with file");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tpkts_file_element_zero_length_means_to_end)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tp_t t; tpe_t e;
    IO_STATUS_BLOCK io;
    unsigned char want[FILE_BYTES];
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&e, 0, sizeof e);
    e.Flags = 2; e.Length = 0; e.u.f.Offset = 4500; e.u.f.File = f;
    memset(&t, 0, sizeof t); t.Array = &e; t.Count = 1;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 500);
    expected_file(want, 4500, 500);
    expect_stream(s, want, 500, "file to end");
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tpkts_file_element_bad_offset_or_handle)
{
    AIO_BEGIN();
    SOCKET c, s;
    HANDLE f = make_file();
    tp_t t; tpe_t e;
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create the scratch file"); return; }
    aio_pair(&c, &s);
    memset(&t, 0, sizeof t); t.Array = &e; t.Count = 1;
    memset(&e, 0, sizeof e); e.Flags = 2; e.Length = 10; e.u.f.Offset = -5; e.u.f.File = f;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    memset(&e, 0, sizeof e); e.Flags = 2; e.Length = 10; e.u.f.File = (HANDLE)(ULONG_PTR)0x7776;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_HANDLE);
    CloseHandle(f); aio_close(c); aio_close(s);
}
TEST(aio_tpkts_send_size_does_not_change_the_bytes)
{
    AIO_BEGIN();
    SOCKET c, s;
    tp_t t; tpe_t e;
    char data[300];
    int i;
    for (i = 0; i < 300; i++) data[i] = (char)(i + 1);
    aio_pair(&c, &s);
    memset(&e, 0, sizeof e); e.Flags = 1; e.Length = 300; e.u.Buffer = data;
    memset(&t, 0, sizeof t); t.Array = &e; t.Count = 1; t.SendSize = 64;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_SUCCESS);
    expect_stream(s, (unsigned char *)data, 300, "send size");
    aio_close(c); aio_close(s);
}
TEST(aio_tpkts_disconnect_flag_closes_the_stream)
{
    AIO_BEGIN();
    SOCKET c, s;
    tp_t t; tpe_t e;
    char data[] = "end", buf[16];
    int total = 0, r = -1;
    DWORD t0 = GetTickCount();
    aio_pair(&c, &s);
    memset(&e, 0, sizeof e); e.Flags = 1 | 4; e.Length = 3; e.u.Buffer = data;
    memset(&t, 0, sizeof t); t.Array = &e; t.Count = 1; t.Flags = 1;
    EXPECT_NTS(aio_ctl(c, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_SUCCESS);
    aio_nonblock(s, 1);
    while (GetTickCount() - t0 < 4000) {
        r = W.recv(s, buf + total, (int)sizeof buf - total, 0);
        if (r > 0) total += r; else if (r == 0) break; else Sleep(5);
    }
    EXPECT_EQ(total, 3);
    EXPECT_EQ(r, 0);
    aio_close(c); aio_close(s);
}
TEST(aio_tpkts_datagram_endpoints_refused)
{
    AIO_BEGIN();
    SOCKET u = aio_bound(SOCK_DGRAM);
    tp_t t; tpe_t e;
    char data[] = "x";
    memset(&e, 0, sizeof e); e.Flags = 1; e.Length = 1; e.u.Buffer = data;
    memset(&t, 0, sizeof t); t.Array = &e; t.Count = 1;
    EXPECT_NTS(aio_ctl(u, IOC_TRANSMIT_PKTS, &t, sizeof t, NULL, 0, NULL, NULL), NTS_INVALID_CONNECTION);
    aio_close(u);
}
