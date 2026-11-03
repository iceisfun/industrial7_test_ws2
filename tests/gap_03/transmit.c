/* TransmitFile (mswsock export) depth: byte-exact stream contents for matrices of head/tail buffer lengths and
 * file sizes, offset/count windows selected through OVERLAPPED.Offset, the per-send chunk argument (any value
 * delivers the same stream), TF_DISCONNECT end of stream at the peer, TF_WRITE_BEHIND, read-only file handles,
 * and ordering against ordinary sends. Every run ends with SD_SEND on the sender and a read to end of stream,
 * so "nothing extra was sent" is established without timing. */
#include "g3.h"

#ifndef TF_DISCONNECT
#define TF_DISCONNECT 1
#define TF_REUSE_SOCKET 2
#define TF_WRITE_BEHIND 4
#endif
typedef BOOL (WINAPI *tf_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
#define TFN() ((tf_fn)t_proc_in("mswsock.dll", "TransmitFile"))

#define MAXSTREAM 40000

static unsigned char pat(unsigned i, unsigned seed) { return (unsigned char)(i * 7u + seed * 13u + 3u); }

static HANDLE make_file(const char *leaf, DWORD size, DWORD access)
{
    char path[MAX_PATH]; HANDLE h; DWORD w, i; unsigned char *buf;
    t_tmpfile(path, sizeof path, leaf);
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return h;
    buf = (unsigned char *)LocalAlloc(LMEM_FIXED, size ? size : 1);
    for (i = 0; i < size; i++) buf[i] = pat(i, 1);
    if (size) WriteFile(h, buf, size, &w, NULL);
    LocalFree(buf);
    CloseHandle(h);
    h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return h;
}

/* Drain a peer to end of stream (bounded waits). Returns bytes read, -1 on a socket error. */
static int drain(SOCKET a, unsigned char *buf, int cap)
{
    int got = 0;
    for (;;) {
        int r;
        if (!g3_readable(a, 5000)) return -2;
        r = g3_recv(a, (char *)buf + got, cap - got, 0);
        if (r < 0) return -1;
        if (r == 0) return got;
        got += r;
        if (got >= cap) return got;
    }
}

struct run { DWORD fsize; DWORD off; DWORD count; DWORD per; DWORD head; DWORD tail; DWORD flags; int use_ov; int no_file; };

/* Runs one TransmitFile and checks the full delivered stream against head + file window + tail. */
static void run_case(const struct run *r, const char *what)
{
    static unsigned char head[300], tail[300], got[MAXSTREAM], want[MAXSTREAM];
    SOCKET c, a; HANDLE f = INVALID_HANDLE_VALUE; TRANSMIT_FILE_BUFFERS b; BOOL ok; int n; DWORD i, wl = 0, win;
    tf_fn tf = TFN();
    if (!tf) { t_skip("TransmitFile missing"); return; }
    G3_NET();
    if (!g3_pair(&c, &a)) { t_skip("loopback pair unavailable"); return; }
    if (!r->no_file) { f = make_file("g3_tf.bin", r->fsize, GENERIC_READ); if (f == INVALID_HANDLE_VALUE) { t_skip("temp file"); g3_closesocket(c); g3_closesocket(a); return; } }
    for (i = 0; i < r->head; i++) head[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < r->tail; i++) tail[i] = (unsigned char)(0x50 + i);
    memset(&b, 0, sizeof b);
    b.Head = r->head ? head : NULL; b.HeadLength = r->head; b.Tail = r->tail ? tail : NULL; b.TailLength = r->tail;
    memcpy(want, head, r->head); wl = r->head;
    if (!r->no_file) {
        win = r->count ? r->count : (r->fsize > r->off ? r->fsize - r->off : 0);
        for (i = 0; i < win; i++) want[wl + i] = pat(r->off + i, 1);
        wl += win;
    }
    memcpy(want + wl, tail, r->tail); wl += r->tail;

    if (r->use_ov) {
        OVERLAPPED ov; memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL); ov.Offset = r->off;
        g3_WSASetLastError(0);
        ok = tf(c, f, r->count, r->per, &ov, (r->head || r->tail) ? &b : NULL, r->flags);
        if (!ok && g3_WSAGetLastError() == WSA_IO_PENDING) {
            DWORD xfer = 0;
            ok = WaitForSingleObject(ov.hEvent, 8000) == WAIT_OBJECT_0 && GetOverlappedResult((HANDLE)c, &ov, &xfer, FALSE);
            if (ok) t_check(xfer == wl, __FILE__, __LINE__, "completion byte count", "%s: got %lu want %lu", what, xfer, wl);
        }
        CloseHandle(ov.hEvent);
    } else {
        if (f != INVALID_HANDLE_VALUE && r->off) SetFilePointer(f, (LONG)r->off, NULL, FILE_BEGIN);
        ok = tf(c, f, r->count, r->per, NULL, (r->head || r->tail) ? &b : NULL, r->flags);
    }
    if (r->no_file) {
        /* a transmit without a file handle is refused with an invalid-handle error, even with buffers */
        t_check(!ok && g3_WSAGetLastError() == 6, __FILE__, __LINE__, "no-file transmit refused with invalid handle", "%s: ok=%d err %d", what, (int)ok, g3_WSAGetLastError());
        g3_closesocket(c); g3_closesocket(a);
        return;
    }
    t_check(ok, __FILE__, __LINE__, "TransmitFile succeeded", "%s: err %d", what, g3_WSAGetLastError());
    if (ok) {
        if (!(r->flags & TF_DISCONNECT)) g3_shutdown(c, SD_SEND);
        n = drain(a, got, sizeof got);
        t_check(n == (int)wl, __FILE__, __LINE__, "stream length", "%s: got %d want %lu", what, n, wl);
        if (n == (int)wl) t_check(!memcmp(got, want, wl), __FILE__, __LINE__, "stream bytes", "%s: content differs", what);
    }
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_transmitfile_head_tail_by_file_size_matrix_sync)
{
    static const DWORD sizes[] = { 0, 1, 2, 511, 4096, 9000 };
    static const DWORD lens[] = { 0, 1, 100, 300 };
    unsigned s, h, t;
    for (s = 0; s < sizeof sizes / sizeof *sizes; s++)
        for (h = 0; h < 4; h++)
            for (t = 0; t < 4; t++) {
                struct run r; char w[64];
                memset(&r, 0, sizeof r);
                r.fsize = sizes[s]; r.head = lens[h]; r.tail = lens[t];
                wsprintfA(w, "sync size=%lu head=%lu tail=%lu", sizes[s], lens[h], lens[t]);
                run_case(&r, w);
            }
}

TEST(gap3_transmitfile_head_tail_by_file_size_matrix_overlapped)
{
    static const DWORD sizes[] = { 0, 1, 700, 8192 };
    static const DWORD lens[] = { 0, 3, 250 };
    unsigned s, h, t;
    for (s = 0; s < 4; s++)
        for (h = 0; h < 3; h++)
            for (t = 0; t < 3; t++) {
                struct run r; char w[64];
                memset(&r, 0, sizeof r);
                r.fsize = sizes[s]; r.head = lens[h]; r.tail = lens[t]; r.use_ov = 1;
                wsprintfA(w, "overlapped size=%lu head=%lu tail=%lu", sizes[s], lens[h], lens[t]);
                run_case(&r, w);
            }
}

TEST(gap3_transmitfile_buffers_only_no_file_matrix)
{
    static const DWORD lens[] = { 0, 1, 17, 300 };
    unsigned h, t;
    for (h = 0; h < 4; h++)
        for (t = 0; t < 4; t++) {
            struct run r; char w[64];
            memset(&r, 0, sizeof r);
            r.no_file = 1; r.head = lens[h]; r.tail = lens[t];
            wsprintfA(w, "no file head=%lu tail=%lu", lens[h], lens[t]);
            run_case(&r, w);
        }
}

TEST(gap3_transmitfile_overlapped_offset_count_window_matrix)
{
    /* OVERLAPPED.Offset selects the start; a non-zero count limits the window, zero means to end of file. */
    static const struct { DWORD off, count; } w[] = {
        { 0, 0 }, { 0, 1 }, { 1, 0 }, { 1, 1 }, { 100, 0 }, { 100, 900 }, { 2047, 1 }, { 2047, 0 },
        { 4095, 1 }, { 4095, 0 }, { 3000, 1096 }, { 1, 4095 }, { 0, 4096 },
    };
    unsigned i;
    for (i = 0; i < sizeof w / sizeof *w; i++) {
        struct run r; char s[64];
        memset(&r, 0, sizeof r);
        r.fsize = 4096; r.off = w[i].off; r.count = w[i].count; r.use_ov = 1;
        wsprintfA(s, "window off=%lu count=%lu", w[i].off, w[i].count);
        run_case(&r, s);
    }
}

TEST(gap3_transmitfile_sync_uses_the_current_file_pointer)
{
    static const DWORD offs[] = { 0, 1, 777, 2048, 3999 };
    unsigned i;
    for (i = 0; i < sizeof offs / sizeof *offs; i++) {
        struct run r; char s[64];
        memset(&r, 0, sizeof r);
        r.fsize = 4000; r.off = offs[i];
        wsprintfA(s, "pointer at %lu", offs[i]);
        run_case(&r, s);
    }
}

TEST(gap3_transmitfile_per_send_chunk_size_never_changes_the_stream)
{
    static const DWORD per[] = { 0, 1, 7, 512, 1000, 4096, 5000, 100000 };
    unsigned i;
    for (i = 0; i < sizeof per / sizeof *per; i++) {
        struct run r; char s[64];
        memset(&r, 0, sizeof r);
        r.fsize = 5000; r.per = per[i]; r.head = 10; r.tail = 10;
        wsprintfA(s, "sync per-send=%lu", per[i]);
        run_case(&r, s);
        r.use_ov = 1;
        wsprintfA(s, "overlapped per-send=%lu", per[i]);
        run_case(&r, s);
    }
}

TEST(gap3_transmitfile_per_send_with_explicit_count_window)
{
    static const DWORD per[] = { 1, 100, 3000 };
    unsigned i;
    for (i = 0; i < 3; i++) {
        struct run r; char s[64];
        memset(&r, 0, sizeof r);
        r.fsize = 6000; r.off = 250; r.count = 2500; r.per = per[i]; r.use_ov = 1;
        wsprintfA(s, "window with per-send=%lu", per[i]);
        run_case(&r, s);
    }
}

TEST(gap3_transmitfile_write_behind_flag_delivers_everything)
{
    struct run r; memset(&r, 0, sizeof r);
    r.fsize = 3000; r.head = 5; r.tail = 5; r.flags = TF_WRITE_BEHIND;
    run_case(&r, "sync write-behind");
    r.use_ov = 1;
    run_case(&r, "overlapped write-behind");
}

TEST(gap3_transmitfile_disconnect_flag_gives_the_peer_end_of_stream_after_the_data)
{
    struct run r; memset(&r, 0, sizeof r);
    r.fsize = 2500; r.head = 4; r.tail = 4; r.flags = TF_DISCONNECT;
    run_case(&r, "sync disconnect");
    r.use_ov = 1;
    run_case(&r, "overlapped disconnect");
}

TEST(gap3_transmitfile_disconnect_without_file_is_refused)
{
    struct run r; memset(&r, 0, sizeof r);
    r.no_file = 1; r.head = 20; r.flags = TF_DISCONNECT;
    run_case(&r, "disconnect, buffers only");
}

TEST(gap3_transmitfile_read_only_file_handle_is_enough)
{
    struct run r; memset(&r, 0, sizeof r);
    r.fsize = 1234;
    run_case(&r, "read-only handle (make_file opens GENERIC_READ)");
}

TEST(gap3_transmitfile_stream_order_with_plain_sends_is_preserved)
{
    SOCKET c, a; HANDLE f; tf_fn tf = TFN(); TRANSMIT_FILE_BUFFERS b; unsigned char got[600]; int n, i;
    G3_PAIR(c0, a0);
    c = c0; a = a0;
    if (!tf) { t_skip("TransmitFile missing"); return; }
    f = make_file("g3_ord.bin", 300, GENERIC_READ);
    if (f == INVALID_HANDLE_VALUE) { t_skip("temp file"); g3_closesocket(c); g3_closesocket(a); return; }
    memset(&b, 0, sizeof b);
    G3_EQ(g3_send(c, "<<", 2, 0), 2);
    CHECK(tf(c, f, 0, 0, NULL, NULL, 0));
    G3_EQ(g3_send(c, ">>", 2, 0), 2);
    g3_shutdown(c, SD_SEND);
    n = drain(a, got, sizeof got);
    G3_EQ(n, 304);
    CHECK(got[0] == '<' && got[1] == '<' && got[302] == '>' && got[303] == '>');
    for (i = 0; i < 300; i++) if (got[2 + i] != pat((unsigned)i, 1)) { CHECKF(0, "byte %d differs", i); break; }
    CloseHandle(f);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_transmitfile_two_files_back_to_back_concatenate)
{
    SOCKET c, a; HANDLE f1, f2; tf_fn tf = TFN(); unsigned char got[2000]; int n, i, bad = 0;
    G3_PAIR(c0, a0);
    c = c0; a = a0;
    if (!tf) { t_skip("TransmitFile missing"); return; }
    f1 = make_file("g3_a.bin", 700, GENERIC_READ); f2 = make_file("g3_b.bin", 900, GENERIC_READ);
    if (f1 == INVALID_HANDLE_VALUE || f2 == INVALID_HANDLE_VALUE) { t_skip("temp file"); g3_closesocket(c); g3_closesocket(a); return; }
    CHECK(tf(c, f1, 0, 0, NULL, NULL, 0));
    CHECK(tf(c, f2, 0, 0, NULL, NULL, 0));
    g3_shutdown(c, SD_SEND);
    n = drain(a, got, sizeof got);
    G3_EQ(n, 1600);
    for (i = 0; i < 700; i++) if (got[i] != pat((unsigned)i, 1)) bad++;
    for (i = 0; i < 900; i++) if (got[700 + i] != pat((unsigned)i, 1)) bad++;
    G3_EQ(bad, 0);
    CloseHandle(f1); CloseHandle(f2);
    g3_closesocket(c); g3_closesocket(a);
}

TEST(gap3_transmitfile_zeroed_buffers_struct_is_the_same_as_no_buffers)
{
    /* A TRANSMIT_FILE_BUFFERS whose lengths are zero is the same as passing no buffers at all. */
    SOCKET c, a; HANDLE f; tf_fn tf = TFN(); TRANSMIT_FILE_BUFFERS b; unsigned char g[400]; int n;
    G3_PAIR(c0, a0);
    c = c0; a = a0;
    if (!tf) { t_skip("TransmitFile missing"); return; }
    f = make_file("g3_z.bin", 200, GENERIC_READ);
    if (f == INVALID_HANDLE_VALUE) { t_skip("temp file"); g3_closesocket(c); g3_closesocket(a); return; }
    memset(&b, 0, sizeof b);
    CHECK(tf(c, f, 0, 0, NULL, &b, 0));
    g3_shutdown(c, SD_SEND);
    n = drain(a, g, sizeof g);
    G3_EQ(n, 200);
    CloseHandle(f);
    g3_closesocket(c); g3_closesocket(a);
}
