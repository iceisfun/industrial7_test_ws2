/* socket_handle_semantics / rw: a socket handle is a File object, so the kernel32 file I/O entry points work on
 * it. Measures ReadFile / WriteFile / ReadFileEx / WriteFileEx on connected, unconnected, listening and datagram
 * sockets, the split between overlapped sockets (an OVERLAPPED is mandatory) and synchronous sockets (it is not),
 * GetFileType, and the file APIs that have no meaning on a socket and must fail the same way on every kind. */
#include "sh.h"

/* ---------------- GetFileType ---------------- */

/* The AFD device object reports device type 0x11, which GetFileType maps to FILE_TYPE_PIPE. */
static void filetype_for(int type, int flags)
{
    SOCKET s;
    UP();
    s = sh_make(type, flags);
    CHECK(s != INVALID_SOCKET);
    SET_ERR(0);
    EQ(GetFileType((HANDLE)s), FILE_TYPE_PIPE);
    sh_closes(s);
}
TEST(shs_filetype_tcp_plain)       { filetype_for(SOCK_STREAM, PLAIN); }
TEST(shs_filetype_tcp_sync)        { filetype_for(SOCK_STREAM, SYNC); }
TEST(shs_filetype_tcp_overlapped)  { filetype_for(SOCK_STREAM, OVLD); }
TEST(shs_filetype_tcp_noinherit)   { filetype_for(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT); }
TEST(shs_filetype_udp_plain)       { filetype_for(SOCK_DGRAM, PLAIN); }
TEST(shs_filetype_udp_sync)        { filetype_for(SOCK_DGRAM, SYNC); }

TEST(shs_filetype_accepted_and_listener)
{
    SOCKET c, s, l;
    struct sockaddr_in a;
    UP();
    l = sh_listener(PLAIN, &a);
    CHECK(l != INVALID_SOCKET);
    EQ(GetFileType((HANDLE)l), FILE_TYPE_PIPE);
    sh_closes(l);
    PAIR(c, s, PLAIN);
    EQ(GetFileType((HANDLE)c), FILE_TYPE_PIPE);
    EQ(GetFileType((HANDLE)s), FILE_TYPE_PIPE);
    sh_closes(c); sh_closes(s);
}

TEST(shs_filetype_duplicated_handle)
{
    SOCKET c, s;
    HANDLE d;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)c, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CHECK(d != NULL);
    if (d) { EQ(GetFileType(d), FILE_TYPE_PIPE); CloseHandle(d); }
    sh_closes(c); sh_closes(s);
}

/* An invalid handle yields FILE_TYPE_UNKNOWN with ERROR_INVALID_HANDLE (not NO_ERROR, which would mean a real
 * unknown device type). */
TEST(shs_filetype_invalid_handles)
{
    static const ULONG_PTR bad[] = { 0, (ULONG_PTR)-1, 0x7ffffffc, 0x1234 };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0);
        EQ(GetFileType((HANDLE)bad[i]), FILE_TYPE_UNKNOWN);
        EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
}

TEST(shs_filetype_closed_socket)
{
    SOCKET s;
    UP();
    s = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(s);
    SET_ERR(0);
    EQ(GetFileType((HANDLE)s), FILE_TYPE_UNKNOWN);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

/* Not an error condition: a real handle of unknown device type would set no error, a socket never does. */
TEST(shs_filetype_leaves_no_error)
{
    SOCKET s;
    UP();
    s = sh_make(SOCK_STREAM, PLAIN);
    SET_ERR(0x5151);
    CHECK(GetFileType((HANDLE)s) == FILE_TYPE_PIPE);
    EXPECT_ERR(0x5151);
    sh_closes(s);
}

/* ---------------- synchronous sockets: plain ReadFile / WriteFile ---------------- */

TEST(shs_sync_write_then_recv)
{
    SOCKET c, s; DWORD n = 0, e; char b[16] = {0};
    UP(); PAIR(c, s, SYNC);
    CHECK(sh_wf((HANDLE)c, "hello", 5, &n, NULL));
    EQ(n, 5);
    EQ(sh_recv_all(s, b, 5), 5);
    EXPECT_STR(b, "hello");
    sh_closes(c); sh_closes(s);
}

TEST(shs_sync_send_then_readfile)
{
    SOCKET c, s; DWORD n = 0, e = 0; char b[16] = {0};
    UP(); PAIR(c, s, SYNC);
    EQ(sh_send(c, "abcdef", 6), 6);
    CHECK(sh_readable(s, SH_WAIT));
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 6);
    EXPECT_STR(b, "abcdef");
    sh_closes(c); sh_closes(s);
}

/* A short read leaves the remainder queued for the next read of either kind. */
TEST(shs_sync_partial_read_leaves_rest)
{
    SOCKET c, s; DWORD n = 0, e = 0; char b[16] = {0};
    UP(); PAIR(c, s, SYNC);
    EQ(sh_send(c, "0123456789", 10), 10);
    CHECK(sh_readable(s, SH_WAIT));
    CHECK(sh_readfile((HANDLE)s, b, 4, &n, &e));
    EQ(n, 4);
    EQ(memcmp(b, "0123", 4), 0);
    memset(b, 0, sizeof b);
    EQ(sh_recv(s, b, 16), 6);
    EXPECT_STR(b, "456789");
    sh_closes(c); sh_closes(s);
}

/* ReadFile returns what is available, not what was asked for. */
TEST(shs_sync_read_returns_available_only)
{
    SOCKET c, s; DWORD n = 0, e = 0; char b[64];
    UP(); PAIR(c, s, SYNC);
    sh_send(c, "xyz", 3);
    CHECK(sh_readable(s, SH_WAIT));
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 3);
    sh_closes(c); sh_closes(s);
}

TEST(shs_sync_write_zero_length_succeeds)
{
    SOCKET c, s; DWORD n = 77;
    UP(); PAIR(c, s, SYNC);
    SET_ERR(0);
    CHECK(sh_wf((HANDLE)c, "x", 0, &n, NULL));
    EQ(n, 0);
    /* nothing was queued for the peer */
    CHECK(!sh_readable(s, 200));
    sh_closes(c); sh_closes(s);
}

TEST(shs_sync_read_zero_length_succeeds)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[4];
    UP(); PAIR(c, s, SYNC);
    sh_send(c, "q", 1);
    CHECK(sh_readable(s, SH_WAIT));
    CHECK(sh_readfile((HANDLE)s, b, 0, &n, &e));
    EQ(n, 0);
    /* the byte is still there */
    EQ(sh_recv(s, b, 1), 1);
    sh_closes(c); sh_closes(s);
}

/* Orderly close by the peer is end of file: TRUE with zero bytes (a pipe would fail with ERROR_BROKEN_PIPE). */
TEST(shs_sync_read_after_peer_close_is_eof)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[4];
    UP(); PAIR(c, s, SYNC);
    sh_closes(c);
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 0);
    /* repeatable */
    n = 77;
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 0);
    sh_closes(s);
}

TEST(shs_sync_read_after_peer_shutdown_send_is_eof)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[4];
    UP(); PAIR(c, s, SYNC);
    EQ(U(shutdown)(c, SD_SEND), 0);
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 0);
    /* the other direction is still open */
    DWORD w = 0;
    CHECK(sh_wf((HANDLE)s, "k", 1, &w, NULL));
    EQ(sh_recv(c, b, 1), 1);
    sh_closes(c); sh_closes(s);
}

/* Data queued before the close is delivered before the end of file. */
TEST(shs_sync_data_then_eof_via_readfile)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[16];
    UP(); PAIR(c, s, SYNC);
    sh_send(c, "tail", 4);
    sh_closes(c);
    CHECK(sh_readable(s, SH_WAIT));
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 4);
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(n, 0);
    sh_closes(s);
}

/* Writing to a peer that has closed: the first write is accepted, once the reset arrives writes fail with
 * ERROR_NETNAME_DELETED. */
TEST(shs_sync_write_after_peer_close_eventually_resets)
{
    SOCKET c, s; DWORD n = 0, e = 0; int failed = 0, i;
    UP(); PAIR(c, s, SYNC);
    sh_closes(s);
    for (i = 0; i < 40 && !failed; i++) {
        BOOL r;
        SET_ERR(0);
        r = sh_wf((HANDLE)c, "q", 1, &n, NULL);
        if (!r) { failed = 1; e = GetLastError(); break; }
        Sleep(50);
    }
    CHECK(failed);
    if (failed) EQ(e, ERROR_NETNAME_DELETED);
    sh_closes(c);
}

/* Not connected / listening: STATUS_INVALID_CONNECTION, reported as ERROR_UNEXP_NET_ERR. */
TEST(shs_sync_unconnected_write_fails)
{
    SOCKET u; DWORD n = 77, e;
    UP(); u = sh_make(SOCK_STREAM, SYNC);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)u, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_UNEXP_NET_ERR);
    sh_closes(u);
}
TEST(shs_sync_unconnected_read_fails)
{
    SOCKET u; DWORD n = 77, e = 0; char b[4];
    UP(); u = sh_make(SOCK_STREAM, SYNC);
    CHECK(!sh_readfile((HANDLE)u, b, sizeof b, &n, &e));
    EQ(e, ERROR_UNEXP_NET_ERR);
    sh_closes(u);
}
TEST(shs_sync_listener_write_fails)
{
    SOCKET l; DWORD n = 77;
    UP(); l = sh_listener(SYNC, NULL);
    CHECK(l != INVALID_SOCKET);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)l, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_UNEXP_NET_ERR);
    sh_closes(l);
}
TEST(shs_sync_listener_read_fails)
{
    SOCKET l; DWORD n = 77, e = 0; char b[4];
    UP(); l = sh_listener(SYNC, NULL);
    CHECK(!sh_readfile((HANDLE)l, b, sizeof b, &n, &e));
    EQ(e, ERROR_UNEXP_NET_ERR);
    sh_closes(l);
}

/* Large transfer through WriteFile / ReadFile with contents verified. */
TEST(shs_sync_bulk_transfer_integrity)
{
    enum { N = 30000 };
    static char tx[N], rx[N];
    SOCKET c, s; DWORD n = 0, e = 0; int got = 0, i;
    UP(); PAIR(c, s, SYNC);
    for (i = 0; i < N; i++) tx[i] = (char)(i * 7 + 3);
    CHECK(sh_wf((HANDLE)c, tx, N, &n, NULL));
    EQ(n, N);
    while (got < N) {
        if (!sh_readable(s, SH_WAIT)) break;
        if (!sh_readfile((HANDLE)s, rx + got, N - got, &n, &e) || n == 0) break;
        got += (int)n;
    }
    EQ(got, N);
    CHECK(memcmp(tx, rx, N) == 0);
    sh_closes(c); sh_closes(s);
}

/* send(), sh_wf() and a second send() form one ordered byte stream. */
TEST(shs_sync_mixed_send_and_writefile_ordered)
{
    SOCKET c, s; DWORD n = 0; char b[16] = {0};
    UP(); PAIR(c, s, SYNC);
    sh_send(c, "AA", 2);
    CHECK(sh_wf((HANDLE)c, "BB", 2, &n, NULL));
    sh_send(c, "CC", 2);
    EQ(sh_recv_all(s, b, 6), 6);
    EXPECT_STR(b, "AABBCC");
    sh_closes(c); sh_closes(s);
}

TEST(shs_sync_byte_at_a_time_readfile)
{
    SOCKET c, s; DWORD n = 0, e = 0; char b[4] = {0}; int i;
    UP(); PAIR(c, s, SYNC);
    sh_send(c, "wxyz", 4);
    CHECK(sh_readable(s, SH_WAIT));
    for (i = 0; i < 4; i++) {
        CHECK(sh_readfile((HANDLE)s, b + i, 1, &n, &e));
        EQ(n, 1);
    }
    EQ(memcmp(b, "wxyz", 4), 0);
    sh_closes(c); sh_closes(s);
}

/* ReadFile on a stream socket does not honour message boundaries: two sends read back as one. */
TEST(shs_sync_two_sends_one_read)
{
    SOCKET c, s; DWORD n = 0, e = 0; char b[16] = {0};
    UP(); PAIR(c, s, SYNC);
    sh_send(c, "ab", 2); sh_send(c, "cd", 2);
    Sleep(100);
    CHECK(sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    t_note("two sends read back in one ReadFile: %d", n == 4);
    CHECK(n >= 2 && n <= 4);
    sh_closes(c); sh_closes(s);
}

/* Datagram sockets: connected UDP accepts WriteFile; a too-small ReadFile truncates with ERROR_MORE_DATA and
 * the datagram's remainder is discarded. */
static int udp_pair(SOCKET *rx, SOCKET *tx, int flags)
{
    struct sockaddr_in a = sh_lo(0);
    int n = sizeof a;
    *rx = sh_make(SOCK_DGRAM, flags); *tx = sh_make(SOCK_DGRAM, flags);
    if (*rx == INVALID_SOCKET || *tx == INVALID_SOCKET) return 0;
    if (U(bind)(*rx, (struct sockaddr *)&a, sizeof a) || U(getsockname)(*rx, (struct sockaddr *)&a, &n)) return 0;
    if (U(connect)(*tx, (struct sockaddr *)&a, sizeof a)) return 0;
    return 1;
}
TEST(shs_sync_udp_writefile_readfile)
{
    SOCKET rx, tx; DWORD n = 0, e = 0; char b[16] = {0};
    UP();
    if (!udp_pair(&rx, &tx, SYNC)) { t_skip("udp pair"); return; }
    CHECK(sh_wf((HANDLE)tx, "datagram", 8, &n, NULL));
    EQ(n, 8);
    CHECK(sh_readable(rx, SH_WAIT));
    CHECK(sh_readfile((HANDLE)rx, b, sizeof b, &n, &e));
    EQ(n, 8);
    EXPECT_STR(b, "datagram");
    sh_closes(rx); sh_closes(tx);
}
TEST(shs_sync_udp_short_read_is_more_data)
{
    SOCKET rx, tx; DWORD n = 0, e = 0; char b[16] = {0};
    UP();
    if (!udp_pair(&rx, &tx, SYNC)) { t_skip("udp pair"); return; }
    sh_wf((HANDLE)tx, "datagram", 8, &n, NULL);
    CHECK(sh_readable(rx, SH_WAIT));
    CHECK(!sh_readfile((HANDLE)rx, b, 3, &n, &e));
    EQ(e, ERROR_MORE_DATA);
    EQ(n, 3);
    EQ(memcmp(b, "dat", 3), 0);
    /* the rest of that datagram is gone */
    CHECK(!sh_readable(rx, 200));
    sh_closes(rx); sh_closes(tx);
}
TEST(shs_sync_udp_boundaries_kept)
{
    SOCKET rx, tx; DWORD n = 0, e = 0; char b[16] = {0};
    UP();
    if (!udp_pair(&rx, &tx, SYNC)) { t_skip("udp pair"); return; }
    sh_wf((HANDLE)tx, "one", 3, &n, NULL);
    sh_wf((HANDLE)tx, "three", 5, &n, NULL);
    CHECK(sh_readable(rx, SH_WAIT));
    CHECK(sh_readfile((HANDLE)rx, b, sizeof b, &n, &e));
    EQ(n, 3);
    Sleep(100);
    CHECK(sh_readfile((HANDLE)rx, b, sizeof b, &n, &e));
    EQ(n, 5);
    sh_closes(rx); sh_closes(tx);
}
TEST(shs_sync_udp_zero_length_datagram)
{
    SOCKET rx, tx; DWORD n = 77, e = 0; char b[16];
    UP();
    if (!udp_pair(&rx, &tx, SYNC)) { t_skip("udp pair"); return; }
    CHECK(sh_wf((HANDLE)tx, "x", 0, &n, NULL));
    EQ(n, 0);
    CHECK(sh_readable(rx, SH_WAIT));        /* a zero-length datagram is delivered */
    sh_closes(rx); sh_closes(tx);
}

TEST(shs_sync_unconnected_udp_write_fails)
{
    SOCKET u; DWORD n = 77;
    UP(); u = sh_make(SOCK_DGRAM, SYNC);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)u, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_UNEXP_NET_ERR);
    sh_closes(u);
}

/* ---------------- overlapped sockets: an OVERLAPPED is mandatory ---------------- */

/* socket() and WSA_FLAG_OVERLAPPED sockets are asynchronous handles; the kernel then insists on an explicit
 * byte offset, which ReadFile/WriteFile only supply when an OVERLAPPED is passed. */
static void ovl_null_overlapped(int flags)
{
    SOCKET c, s; DWORD n = 77, e = 0; char b[8];
    UP(); PAIR(c, s, flags);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)c, "hello", 5, &n, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EQ(n, 0);
    /* nothing went out */
    CHECK(!sh_readable(s, 200));
    sh_send(c, "z", 1);
    CHECK(sh_readable(s, SH_WAIT));
    CHECK(!sh_readfile((HANDLE)s, b, sizeof b, &n, &e));
    EQ(e, ERROR_INVALID_PARAMETER);
    /* and the byte is still queued */
    EQ(sh_recv(s, b, 1), 1);
    sh_closes(c); sh_closes(s);
}
TEST(shs_ovl_plain_socket_null_overlapped_rejected)     { ovl_null_overlapped(PLAIN); }
TEST(shs_ovl_flagged_socket_null_overlapped_rejected)   { ovl_null_overlapped(OVLD); }
TEST(shs_ovl_noinherit_overlapped_null_overlapped_rejected) { ovl_null_overlapped(OVLD | WSA_FLAG_NO_HANDLE_INHERIT); }

/* The offset requirement is checked before the socket state: a not-connected socket gives the same error. */
TEST(shs_ovl_null_overlapped_checked_before_state)
{
    SOCKET u, l; DWORD n = 77, e = 0; char b[4];
    UP();
    u = sh_make(SOCK_STREAM, PLAIN);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)u, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(!sh_readfile((HANDLE)u, b, sizeof b, &n, &e));
    EQ(e, ERROR_INVALID_PARAMETER);
    l = sh_listener(PLAIN, NULL);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)l, "q", 1, &n, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sh_closes(u); sh_closes(l);
}

TEST(shs_ovl_zero_length_null_overlapped_rejected)
{
    SOCKET c, s; DWORD n = 77;
    UP(); PAIR(c, s, PLAIN);
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)c, "x", 0, &n, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sh_closes(c); sh_closes(s);
}

TEST(shs_ovl_datagram_null_overlapped_rejected)
{
    SOCKET rx, tx; DWORD n = 77;
    UP();
    if (!udp_pair(&rx, &tx, PLAIN)) { t_skip("udp pair"); return; }
    SET_ERR(0);
    CHECK(!sh_wf((HANDLE)tx, "x", 1, &n, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sh_closes(rx); sh_closes(tx);
}

/* WriteFile with an OVERLAPPED completes inline when the send buffer has room. */
TEST(shs_ovl_writefile_completes_inline)
{
    SOCKET c, s; DWORD n = 0; OVERLAPPED o; HANDLE ev = sh_event(); char b[8] = {0};
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(sh_wf((HANDLE)c, "inline", 6, &n, &o));
    EQ(n, 6);
    EQ32(o.InternalHigh, 6);
    EQ32(o.Internal, 0);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
    EQ(sh_recv_all(s, b, 6), 6);
    EXPECT_STR(b, "inline");
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* ReadFile with an OVERLAPPED and nothing queued pends; data then completes it. */
TEST(shs_ovl_readfile_pends_then_completes)
{
    SOCKET c, s; DWORD n = 0; OVERLAPPED o; HANDLE ev = sh_event(); char b[16] = {0};
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    EXPECT_ERR(ERROR_IO_PENDING);
    sh_send(c, "late", 4);
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EQ(n, 4);
    EQ32(o.Internal, 0);
    EQ32(o.InternalHigh, 4);
    EQ(memcmp(b, "late", 4), 0);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* With data already queued the read completes inline. */
TEST(shs_ovl_readfile_data_ready_inline)
{
    SOCKET c, s; DWORD n = 0; OVERLAPPED o; HANDLE ev = sh_event(); char b[16] = {0};
    UP(); PAIR(c, s, PLAIN);
    sh_send(c, "ready", 5);
    CHECK(sh_readable(s, SH_WAIT));
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    EQ(n, 5);
    EQ(memcmp(b, "ready", 5), 0);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* The Offset / OffsetHigh fields are ignored for sockets, whatever they hold. */
TEST(shs_ovl_offsets_ignored)
{
    static const DWORD offs[][2] = { {0,0}, {0x1234,0x77}, {0xffffffff,0xffffffff}, {1,0} };
    for (int i = 0; i < 4; i++) {
        SOCKET c, s; DWORD n = 0; OVERLAPPED o; HANDLE ev = sh_event(); char b[8] = {0};
        UP(); PAIR(c, s, PLAIN);
        sh_ovl(&o, ev); o.Offset = offs[i][0]; o.OffsetHigh = offs[i][1];
        SET_ERR(0);
        CHECK(sh_wf((HANDLE)c, "off", 3, &n, &o));
        EQ(n, 3);
        EQ(sh_recv_all(s, b, 3), 3);
        EXPECT_STR(b, "off");
        CloseHandle(ev); sh_closes(c); sh_closes(s);
    }
}

/* A zero-byte overlapped read pends until data arrives (it is a readiness wait) and can be cancelled. */
TEST(shs_ovl_zero_length_read_pends)
{
    SOCKET c, s; DWORD n = 0; OVERLAPPED o; HANDLE ev = sh_event(); char b[4];
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(!sh_rf((HANDLE)s, b, 0, &n, &o));
    EXPECT_ERR(ERROR_IO_PENDING);
    EQ(WaitForSingleObject(ev, 300), WAIT_TIMEOUT);
    CHECK(CancelIoEx((HANDLE)s, &o));
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    SET_ERR(0);
    CHECK(!GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* A pending read completes successfully with zero bytes when the peer closes gracefully. */
TEST(shs_ovl_pending_read_peer_close_is_eof)
{
    SOCKET c, s; DWORD n = 77; OVERLAPPED o; HANDLE ev = sh_event(); char b[4];
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    EXPECT_ERR(ERROR_IO_PENDING);
    sh_closes(c);
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EQ(n, 0);
    EQ32(o.Internal, 0);
    CloseHandle(ev); sh_closes(s);
}

/* Cancelling a pending ReadFile completes it with STATUS_CANCELLED / ERROR_OPERATION_ABORTED. */
TEST(shs_ovl_cancelled_read_status)
{
    SOCKET c, s; DWORD n = 77; OVERLAPPED o; HANDLE ev = sh_event(); char b[4];
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    CHECK(CancelIo((HANDLE)s));
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    EQ32(o.Internal, 0xC0000120);
    EQ32(o.InternalHigh, 0);
    SET_ERR(0);
    CHECK(!GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* GetOverlappedResult(bWait=FALSE) on a still-pending read: ERROR_IO_INCOMPLETE. */
TEST(shs_ovl_incomplete_result)
{
    SOCKET c, s; DWORD n = 77; OVERLAPPED o; HANDLE ev = sh_event(); char b[4];
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    SET_ERR(0);
    CHECK(!GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EXPECT_ERR(ERROR_IO_INCOMPLETE);
    CancelIoEx((HANDLE)s, &o);
    sh_wait(ev);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* An OVERLAPPED handed to a synchronous socket is accepted and the call completes in line. */
TEST(shs_ovl_overlapped_on_sync_socket_completes_inline)
{
    SOCKET c, s; DWORD n = 0; OVERLAPPED o; HANDLE ev = sh_event(); char b[8] = {0};
    UP(); PAIR(c, s, SYNC);
    sh_ovl(&o, ev);
    SET_ERR(0);
    CHECK(sh_wf((HANDLE)c, "abc", 3, &n, &o));
    EQ(n, 3);
    EQ(sh_recv_all(s, b, 3), 3);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}

/* ---------------- ReadFileEx / WriteFileEx ---------------- */

static volatile LONG g_apc_count;
static volatile DWORD g_apc_err, g_apc_bytes;
static VOID CALLBACK apc_cb(DWORD err, DWORD bytes, LPOVERLAPPED o)
{
    g_apc_err = err; g_apc_bytes = bytes;
    InterlockedIncrement(&g_apc_count);
}
static int apc_wait(void)
{
    DWORD t0 = GetTickCount();
    while (g_apc_count == 0 && GetTickCount() - t0 < SH_WAIT) SleepEx(50, TRUE);
    return g_apc_count != 0;
}

TEST(shs_ex_writefileex_apc_delivered)
{
    SOCKET c, s; OVERLAPPED o; char b[8] = {0};
    UP(); PAIR(c, s, OVLD);
    sh_ovl(&o, NULL); g_apc_count = 0;
    SET_ERR(0);
    CHECK(WriteFileEx((HANDLE)c, "hey", 3, &o, apc_cb));
    CHECK(apc_wait());
    EQ(g_apc_err, 0);
    EQ(g_apc_bytes, 3);
    EQ(sh_recv_all(s, b, 3), 3);
    sh_closes(c); sh_closes(s);
}

TEST(shs_ex_readfileex_apc_delivered_on_data)
{
    SOCKET c, s; OVERLAPPED o; char b[8] = {0};
    UP(); PAIR(c, s, OVLD);
    sh_ovl(&o, NULL); g_apc_count = 0;
    SET_ERR(0);
    CHECK(ReadFileEx((HANDLE)s, b, sizeof b, &o, apc_cb));
    EQ(g_apc_count, 0);
    sh_send(c, "abc", 3);
    CHECK(apc_wait());
    EQ(g_apc_err, 0);
    EQ(g_apc_bytes, 3);
    EQ(memcmp(b, "abc", 3), 0);
    sh_closes(c); sh_closes(s);
}

TEST(shs_ex_readfileex_cancel_delivers_aborted)
{
    SOCKET c, s; OVERLAPPED o; char b[8];
    UP(); PAIR(c, s, OVLD);
    sh_ovl(&o, NULL); g_apc_count = 0;
    CHECK(ReadFileEx((HANDLE)s, b, sizeof b, &o, apc_cb));
    CHECK(CancelIoEx((HANDLE)s, &o));
    CHECK(apc_wait());
    EQ(g_apc_err, ERROR_OPERATION_ABORTED);
    EQ(g_apc_bytes, 0);
    sh_closes(c); sh_closes(s);
}

TEST(shs_ex_readfileex_peer_close_delivers_eof)
{
    SOCKET c, s; OVERLAPPED o; char b[8];
    UP(); PAIR(c, s, OVLD);
    sh_ovl(&o, NULL); g_apc_count = 0;
    CHECK(ReadFileEx((HANDLE)s, b, sizeof b, &o, apc_cb));
    sh_closes(c);
    CHECK(apc_wait());
    EQ(g_apc_err, 0);
    EQ(g_apc_bytes, 0);
    sh_closes(s);
}

/* The APC is queued to the thread that issued the request, not to another thread. */
static DWORD WINAPI ex_issuer(LPVOID p) { return 0; }
TEST(shs_ex_apc_not_delivered_until_alertable)
{
    SOCKET c, s; OVERLAPPED o; char b[8];
    UP(); PAIR(c, s, OVLD);
    sh_ovl(&o, NULL); g_apc_count = 0;
    CHECK(ReadFileEx((HANDLE)s, b, sizeof b, &o, apc_cb));
    sh_send(c, "n", 1);
    Sleep(400);
    EQ(g_apc_count, 0);            /* non-alertable sleep: the APC stays queued */
    CHECK(apc_wait());
    EQ(g_apc_count, 1);
    sh_closes(c); sh_closes(s);
}

TEST(shs_ex_sync_socket_behaviour_recorded)
{
    SOCKET c, s; OVERLAPPED o;
    UP(); PAIR(c, s, SYNC);
    sh_ovl(&o, NULL); g_apc_count = 0;
    SET_ERR(0);
    BOOL r = WriteFileEx((HANDLE)c, "hey", 3, &o, apc_cb);
    t_note("WriteFileEx on a synchronous socket: ret %d err %lu", r, r ? 0 : GetLastError());
    SleepEx(300, TRUE);
    sh_closes(c); sh_closes(s);
}

/* ---------------- file APIs that a socket does not implement ---------------- */

/* Each of these reaches AFD as an unsupported information class or request and comes back as
 * ERROR_INVALID_FUNCTION, for every kind of socket. */
#define NOFILE(name, ...) \
    TEST(shs_nofile_##name) { SOCKET s[3]; int i; UP(); \
        s[0] = sh_make(SOCK_STREAM, PLAIN); s[1] = sh_make(SOCK_DGRAM, PLAIN); s[2] = sh_make(SOCK_STREAM, SYNC); \
        for (i = 0; i < 3; i++) { HANDLE h = (HANDLE)s[i]; SET_ERR(0); __VA_ARGS__; EXPECT_ERR(ERROR_INVALID_FUNCTION); sh_closes(s[i]); } }

NOFILE(getfileinformationbyhandle, { BY_HANDLE_FILE_INFORMATION bi; CHECK(!GetFileInformationByHandle(h, &bi)); })
/* Position queries are answered by the I/O manager itself for synchronous handles, so only the overlapped
 * kinds are refused (see shs_nofile_position_on_sync_socket). */
#define NOFILE_OVL(name, ...) \
    TEST(shs_nofile_##name) { SOCKET s[2]; int i; UP(); \
        s[0] = sh_make(SOCK_STREAM, PLAIN); s[1] = sh_make(SOCK_DGRAM, OVLD); \
        for (i = 0; i < 2; i++) { HANDLE h = (HANDLE)s[i]; SET_ERR(0); __VA_ARGS__; EXPECT_ERR(ERROR_INVALID_FUNCTION); sh_closes(s[i]); } }
NOFILE_OVL(setfilepointerex,       { LARGE_INTEGER z, o2; z.QuadPart = 0; CHECK(!SetFilePointerEx(h, z, &o2, FILE_CURRENT)); })
NOFILE_OVL(setfilepointer,         { CHECK(SetFilePointer(h, 0, NULL, FILE_CURRENT) == INVALID_SET_FILE_POINTER); })
TEST(shs_nofile_position_on_sync_socket)
{
    SOCKET s = INVALID_SOCKET; LARGE_INTEGER z, o2;
    UP(); s = sh_make(SOCK_STREAM, SYNC);
    z.QuadPart = 0;
    SET_ERR(0);
    BOOL r = SetFilePointerEx((HANDLE)s, z, &o2, FILE_CURRENT);
    CHECK(r);                           /* answered by the I/O manager's own file position */
    EQ(o2.QuadPart, 0);
    sh_closes(s);
}
NOFILE(getfilesizeex,              { LARGE_INTEGER li; CHECK(!GetFileSizeEx(h, &li)); })
NOFILE(getfilesize,                { CHECK(GetFileSize(h, NULL) == INVALID_FILE_SIZE); })

NOFILE(flushfilebuffers,           { CHECK(!FlushFileBuffers(h)); })
NOFILE(lockfile,                   { CHECK(!LockFile(h, 0, 0, 1, 0)); })
NOFILE(seteofile,                  { CHECK(!SetEndOfFile(h)); })
NOFILE(getfiletime,                { FILETIME ft; CHECK(!GetFileTime(h, &ft, NULL, NULL)); })
NOFILE(finalpathname,              { WCHAR w[300]; CHECK(GetFinalPathNameByHandleW(h, w, 300, 0) == 0); })
NOFILE(ex_basic,                   { char b[64]; CHECK(!GetFileInformationByHandleEx(h, FileBasicInfo, b, sizeof b)); })
NOFILE(ex_standard,                { char b[64]; CHECK(!GetFileInformationByHandleEx(h, FileStandardInfo, b, sizeof b)); })
NOFILE(ex_name,                    { char b[512]; CHECK(!GetFileInformationByHandleEx(h, FileNameInfo, b, sizeof b)); })
NOFILE(devicecontrol_foreign_code, { DWORD r; CHECK(!DeviceIoControl(h, 0x00220003, NULL, 0, NULL, 0, &r, NULL)); })
