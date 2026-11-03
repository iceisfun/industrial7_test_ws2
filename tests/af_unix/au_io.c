/* AF_UNIX stream sockets: data transfer. State errors for send/recv, stream semantics (peek, wait-all,
 * scatter/gather, partial reads), size sweeps in both directions, flow control on a non-blocking sender,
 * orderly shutdown and close behaviour, reset behaviour. Transfers are pumped with non-blocking calls
 * and bounded loops so a missing byte can never hang a test. */
#include "au.h"

/* Move n bytes from a to b (pattern seeded), reading them back on b. Returns bytes verified. */
static int pump(SOCKET a, SOCKET b, int n, unsigned seed)
{
    char *out = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1), *in = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1);
    int sent = 0, got = 0, i, good = 0, idle = 0;
    DWORD t0 = GetTickCount();
    for (i = 0; i < n; i++) out[i] = (char)((i * 131 + seed) ^ (i >> 8));
    au_blocking(a, FALSE); au_blocking(b, FALSE);
    while ((sent < n || got < n) && GetTickCount() - t0 < 8000) {
        int progress = 0, r;
        if (sent < n) {
            int c = n - sent > 8192 ? 8192 : n - sent;
            r = U(send)(a, out + sent, c, 0);
            if (r > 0) { sent += r; progress = 1; }
        }
        if (got < n) {
            r = U(recv)(b, in + got, n - got, 0);
            if (r > 0) { got += r; progress = 1; }
        }
        if (!progress) { Sleep(1); if (++idle > 5000) break; } else idle = 0;
    }
    for (i = 0; i < got; i++) if (in[i] == out[i]) good++;
    au_blocking(a, TRUE); au_blocking(b, TRUE);
    HeapFree(GetProcessHeap(), 0, out); HeapFree(GetProcessHeap(), 0, in);
    return good == n && got == n ? n : -1;
}

/* ---- state errors ------------------------------------------------------------------------------ */
TEST(afu_io_send_unconnected_is_notconn)
{
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(send)(s, "x", 1, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
}

TEST(afu_io_recv_unconnected_is_notconn)
{
    char b[4];
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(recv)(s, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
}

TEST(afu_io_send_recv_on_bound_unconnected_is_notconn)
{
    char b[4];
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "io_bound.sock", NULL), 0);
    au_seterr(0);
    AU_EQ(U(send)(s, "x", 1, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    au_seterr(0);
    AU_EQ(U(recv)(s, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
    au_unlink_leaf("io_bound.sock");
}

TEST(afu_io_send_recv_on_listener_is_notconn)
{
    char b[4];
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "io_lis.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    au_seterr(0);
    AU_EQ(U(send)(s, "x", 1, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    au_seterr(0);
    AU_EQ(U(recv)(s, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
    au_unlink_leaf("io_lis.sock");
}

TEST(afu_io_send_null_buffer_nonzero_len_is_fault)
{
    TRIO(t, "io_nullbuf.sock");
    au_seterr(0);
    AU_EQ(U(send)(t.cli, NULL, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    au_seterr(0);
    AU_EQ(U(recv)(t.cli, NULL, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    au_trio_close(&t);
}

TEST(afu_io_send_zero_bytes)
{
    int r;
    TRIO(t, "io_zero.sock");
    au_seterr(0);
    r = U(send)(t.cli, "", 0, 0);
    AU_EQ(r, 0);
    au_trio_close(&t);
}

/* ---- basic stream behaviour ------------------------------------------------------------------- */
TEST(afu_io_roundtrip_one_byte_each_way)
{
    char b = 0;
    TRIO(t, "io_1b.sock");
    AU_EQ(U(send)(t.cli, "Q", 1, 0), 1);
    AU_EQ(U(recv)(t.srv, &b, 1, 0), 1);
    AU_EQ(b, 'Q');
    AU_EQ(U(send)(t.srv, "R", 1, 0), 1);
    AU_EQ(U(recv)(t.cli, &b, 1, 0), 1);
    AU_EQ(b, 'R');
    au_trio_close(&t);
}

TEST(afu_io_stream_not_message_boundaries)
{
    /* Two sends can be read with any split: reading byte by byte returns all 6 bytes in order. */
    char b[8] = {0};
    int i;
    TRIO(t, "io_stream.sock");
    AU_EQ(U(send)(t.cli, "abc", 3, 0), 3);
    AU_EQ(U(send)(t.cli, "def", 3, 0), 3);
    for (i = 0; i < 6; i++) AU_EQ(U(recv)(t.srv, b + i, 1, 0), 1);
    CHECK(!memcmp(b, "abcdef", 6));
    au_trio_close(&t);
}

TEST(afu_io_recv_smaller_buffer_keeps_rest)
{
    char b[8] = {0};
    TRIO(t, "io_rest.sock");
    AU_EQ(U(send)(t.cli, "0123456789", 10, 0), 10);
    AU_EQ(au_recv_n(t.srv, b, 4), 4);
    CHECK(!memcmp(b, "0123", 4));
    AU_EQ(au_recv_n(t.srv, b, 6), 6);
    CHECK(!memcmp(b, "456789", 6));
    au_trio_close(&t);
}

TEST(afu_io_recv_returns_available_not_requested)
{
    char b[64] = {0};
    int r;
    TRIO(t, "io_avail.sock");
    AU_EQ(U(send)(t.cli, "hello", 5, 0), 5);
    AU_EQ(au_readable(t.srv, 3000), 1);
    r = U(recv)(t.srv, b, sizeof(b), 0);
    AU_EQ(r, 5);
    CHECK(!memcmp(b, "hello", 5));
    au_trio_close(&t);
}

TEST(afu_io_peek_does_not_consume)
{
    char b[8] = {0}, c[8] = {0};
    TRIO(t, "io_peek.sock");
    AU_EQ(U(send)(t.cli, "peekme", 6, 0), 6);
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(U(recv)(t.srv, b, 6, MSG_PEEK), 6);
    AU_EQ(U(recv)(t.srv, b, 6, MSG_PEEK), 6);
    AU_EQ(U(recv)(t.srv, c, 6, 0), 6);
    CHECK(!memcmp(b, "peekme", 6));
    CHECK(!memcmp(c, "peekme", 6));
    au_trio_close(&t);
}

TEST(afu_io_peek_smaller_than_pending)
{
    char b[4] = {0};
    TRIO(t, "io_peek2.sock");
    AU_EQ(U(send)(t.cli, "ABCDEFGH", 8, 0), 8);
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(U(recv)(t.srv, b, 3, MSG_PEEK), 3);
    CHECK(!memcmp(b, "ABC", 3));
    memset(b, 0, 4);
    AU_EQ(au_recv_n(t.srv, b, 3), 3);
    CHECK(!memcmp(b, "ABC", 3));
    au_trio_close(&t);
}

TEST(afu_io_waitall_returns_full_request)
{
    char b[16] = {0};
    TRIO(t, "io_waitall.sock");
    AU_EQ(U(send)(t.cli, "0123456789", 10, 0), 10);
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(U(recv)(t.srv, b, 10, MSG_WAITALL), 10);
    CHECK(!memcmp(b, "0123456789", 10));
    au_trio_close(&t);
}

TEST(afu_io_waitall_with_short_data_at_shutdown)
{
    char b[16] = {0};
    TRIO(t, "io_waitpart.sock");
    AU_EQ(U(send)(t.cli, "abcd", 4, 0), 4);
    AU_EQ(U(shutdown)(t.cli, SD_SEND), 0);
    {
        int r1 = U(recv)(t.srv, b, 10, MSG_WAITALL), r2;
        AU_OBS("WAITALL 10 bytes with 4 queued then SD_SEND", "first %d", r1);
        r2 = U(recv)(t.srv, b + (r1 > 0 ? r1 : 0), 10, 0);
        AU_OBS("following plain recv", "%d", r2);
        CHECK(r1 >= 0 && r2 >= 0);
    }
    au_trio_close(&t);
}

TEST(afu_io_nonblocking_recv_empty_is_wouldblock)
{
    char b[4];
    TRIO(t, "io_nb.sock");
    au_blocking(t.srv, FALSE);
    au_seterr(0);
    AU_EQ(U(recv)(t.srv, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEWOULDBLOCK);
    au_trio_close(&t);
}

TEST(afu_io_recv_timeout_expires)
{
    char b[4];
    DWORD t0, dt;
    TRIO(t, "io_rcvto.sock");
    au_rcvtimeo(t.srv, 200);
    au_seterr(0);
    t0 = GetTickCount();
    AU_EQ(U(recv)(t.srv, b, 4, 0), SOCKET_ERROR);
    dt = GetTickCount() - t0;
    AU_EQ(au_err(), WSAETIMEDOUT);
    CHECK(dt < 3000);
    au_trio_close(&t);
}

TEST(afu_io_recv_timeout_connection_still_usable)
{
    char b[4] = {0};
    TRIO(t, "io_rcvto2.sock");
    au_rcvtimeo(t.srv, 100);
    AU_EQ(U(recv)(t.srv, b, 4, 0), SOCKET_ERROR);
    AU_EQ(U(send)(t.cli, "ok", 2, 0), 2);
    au_rcvtimeo(t.srv, 3000);
    AU_EQ(U(recv)(t.srv, b, 2, 0), 2);
    CHECK(!memcmp(b, "ok", 2));
    au_trio_close(&t);
}

/* ---- scatter / gather -------------------------------------------------------------------------- */
TEST(afu_io_wsasend_gathers_buffers)
{
    WSABUF bufs[3];
    DWORD sent = 0;
    char b[16] = {0};
    TRIO(t, "io_gather.sock");
    bufs[0].buf = (CHAR *)"AAA"; bufs[0].len = 3;
    bufs[1].buf = (CHAR *)"BB"; bufs[1].len = 2;
    bufs[2].buf = (CHAR *)"C"; bufs[2].len = 1;
    AU_EQ(U(WSASend)(t.cli, bufs, 3, &sent, 0, NULL, NULL), 0);
    AU_EQ(sent, 6);
    AU_EQ(au_recv_n(t.srv, b, 6), 6);
    CHECK(!memcmp(b, "AAABBC", 6));
    au_trio_close(&t);
}

TEST(afu_io_wsarecv_scatters_buffers)
{
    WSABUF bufs[2];
    DWORD got = 0, flags = 0;
    char x[4] = {0}, y[8] = {0};
    TRIO(t, "io_scatter.sock");
    AU_EQ(U(send)(t.cli, "1234567", 7, 0), 7);
    AU_EQ(au_readable(t.srv, 3000), 1);
    bufs[0].buf = x; bufs[0].len = 4;
    bufs[1].buf = y; bufs[1].len = 8;
    AU_EQ(U(WSARecv)(t.srv, bufs, 2, &got, &flags, NULL, NULL), 0);
    AU_EQ(got, 7);
    CHECK(!memcmp(x, "1234", 4));
    CHECK(!memcmp(y, "567", 3));
    au_trio_close(&t);
}

TEST(afu_io_wsasend_zero_buffers_is_inval)
{
    DWORD sent = 0;
    TRIO(t, "io_nobufs.sock");
    au_seterr(0);
    AU_EQ(U(WSASend)(t.cli, NULL, 0, &sent, 0, NULL, NULL), SOCKET_ERROR);
    CHECKF(au_err() == WSAEINVAL || au_err() == WSAEFAULT, "err %d", au_err());
    au_trio_close(&t);
}

TEST(afu_io_wsarecv_zero_buffers_is_inval)
{
    DWORD got = 0, flags = 0;
    TRIO(t, "io_nobufs2.sock");
    au_seterr(0);
    AU_EQ(U(WSARecv)(t.cli, NULL, 0, &got, &flags, NULL, NULL), SOCKET_ERROR);
    CHECKF(au_err() == WSAEINVAL || au_err() == WSAEFAULT, "err %d", au_err());
    au_trio_close(&t);
}

TEST(afu_io_wsarecv_flags_out_after_plain_recv)
{
    WSABUF b;
    DWORD got = 0, flags = 0xffff;
    char x[8] = {0};
    TRIO(t, "io_flags.sock");
    AU_EQ(U(send)(t.cli, "zz", 2, 0), 2);
    AU_EQ(au_readable(t.srv, 3000), 1);
    b.buf = x; b.len = 8;
    flags = 0;
    AU_EQ(U(WSARecv)(t.srv, &b, 1, &got, &flags, NULL, NULL), 0);
    AU_EQ(flags, 0);
    au_trio_close(&t);
}

/* ---- addresses on stream send/recv ------------------------------------------------------------- */
TEST(afu_io_sendto_null_address_acts_as_send)
{
    char b[8] = {0};
    TRIO(t, "io_sendto.sock");
    AU_EQ(U(sendto)(t.cli, "st", 2, 0, NULL, 0), 2);
    AU_EQ(au_recv_n(t.srv, b, 2), 2);
    CHECK(!memcmp(b, "st", 2));
    au_trio_close(&t);
}

TEST(afu_io_sendto_with_address_on_connected_socket)
{
    SOCKADDR_UN other;
    char b[8] = {0};
    int r;
    TRIO(t, "io_sendto2.sock");
    au_addr_leaf(&other, "io_other.sock");
    au_seterr(0);
    r = U(sendto)(t.cli, "st", 2, 0, (struct sockaddr *)&other, sizeof(other));
    AU_EQ(r, 2);
    AU_EQ(au_recv_n(t.srv, b, 2), 2);
    CHECK(!memcmp(b, "st", 2));
    au_trio_close(&t);
}

TEST(afu_io_recvfrom_reports_source)
{
    SOCKADDR_UN from;
    int fl = sizeof(from), r;
    char b[8];
    TRIO(t, "io_from.sock");
    AU_EQ(U(send)(t.srv, "x", 1, 0), 1);
    AU_EQ(au_readable(t.cli, 3000), 1);
    memset(&from, 0x55, sizeof(from));
    r = U(recvfrom)(t.cli, b, sizeof(b), 0, (struct sockaddr *)&from, &fl);
    AU_EQ(r, 1);
    AU_EQ(fl, (int)sizeof(SOCKADDR_UN));
    au_trio_close(&t);
}

/* ---- flags ------------------------------------------------------------------------------------- */
TEST(afu_io_send_oob_flag)
{
    int r;
    TRIO(t, "io_oob.sock");
    au_seterr(0);
    r = U(send)(t.cli, "!", 1, MSG_OOB);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    au_trio_close(&t);
}

TEST(afu_io_recv_oob_flag_without_data)
{
    char b[4];
    int r;
    TRIO(t, "io_oobr.sock");
    au_blocking(t.srv, FALSE);
    au_seterr(0);
    r = U(recv)(t.srv, b, 4, MSG_OOB);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEWOULDBLOCK);
    au_trio_close(&t);
}

TEST(afu_io_recv_unknown_flag_bits)
{
    char b[4];
    int r;
    TRIO(t, "io_badflag.sock");
    au_blocking(t.srv, FALSE);
    au_seterr(0);
    r = U(recv)(t.srv, b, 4, 0x4000);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEOPNOTSUPP);
    au_trio_close(&t);
}

TEST(afu_io_send_unknown_flag_bits)
{
    int r;
    TRIO(t, "io_badflag2.sock");
    au_seterr(0);
    r = U(send)(t.cli, "x", 1, 0x4000);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEOPNOTSUPP);
    au_trio_close(&t);
}

/* ---- size sweeps ------------------------------------------------------------------------------ */
static void sweep(int n, int dir, const char *leaf)
{
    struct au_trio t;
    int r;
    if (!au_up()) return;
    if (!au_trio_open(&t, leaf)) return;
    r = dir ? pump(t.srv, t.cli, n, (unsigned)n) : pump(t.cli, t.srv, n, (unsigned)n + 7);
    CHECKF(r == n, "pump %d returned %d", n, r);
    au_trio_close(&t);
}
#define SWEEP(n) \
    TEST(afu_io_sweep_c2s_##n) { sweep(n, 0, "sw_c2s_" #n ".sock"); } \
    TEST(afu_io_sweep_s2c_##n) { sweep(n, 1, "sw_s2c_" #n ".sock"); }
SWEEP(1) SWEEP(2) SWEEP(7) SWEEP(255) SWEEP(256) SWEEP(1500) SWEEP(4095) SWEEP(4096) SWEEP(4097)
SWEEP(8191) SWEEP(8192) SWEEP(8193) SWEEP(16384) SWEEP(65535) SWEEP(65536) SWEEP(65537) SWEEP(262144) SWEEP(1048576)

TEST(afu_io_bidirectional_interleaved)
{
    int i;
    TRIO(t, "io_inter.sock");
    for (i = 0; i < 20; i++) {
        AU_EQ(pump(t.cli, t.srv, 100 + i, i), 100 + i);
        AU_EQ(pump(t.srv, t.cli, 200 + i, i + 50), 200 + i);
    }
    au_trio_close(&t);
}

TEST(afu_io_many_small_sends_arrive_in_order)
{
    char b[512], w[512];
    int i, got;
    TRIO(t, "io_small.sock");
    for (i = 0; i < 200; i++) { char c = (char)i; AU_EQ(U(send)(t.cli, &c, 1, 0), 1); }
    got = au_recv_n(t.srv, b, 200);
    AU_EQ(got, 200);
    for (i = 0; i < 200; i++) w[i] = (char)i;
    CHECK(!memcmp(b, w, 200));
    au_trio_close(&t);
}

/* ---- flow control ------------------------------------------------------------------------------ */
TEST(afu_io_nonblocking_send_eventually_wouldblock)
{
    static char chunk[16384];
    long total = 0;
    int r, blocked = 0;
    TRIO(t, "io_flow.sock");
    memset(chunk, 'f', sizeof(chunk));
    au_blocking(t.cli, FALSE);
    while (total < 64L * 1024 * 1024) {
        r = U(send)(t.cli, chunk, sizeof(chunk), 0);
        if (r == SOCKET_ERROR) { blocked = (au_err() == WSAEWOULDBLOCK); break; }
        total += r;
    }
    CHECK(blocked);
    CHECK(total > 0);
    au_trio_close(&t);
}

TEST(afu_io_flow_writable_again_after_drain)
{
    static char chunk[16384], sink[65536];
    long total = 0, drained = 0;
    int r;
    TRIO(t, "io_drain.sock");
    memset(chunk, 'd', sizeof(chunk));
    au_blocking(t.cli, FALSE); au_blocking(t.srv, FALSE);
    while (total < 64L * 1024 * 1024) {
        r = U(send)(t.cli, chunk, sizeof(chunk), 0);
        if (r == SOCKET_ERROR) break;
        total += r;
    }
    if (au_writable(t.cli, 100)) { AU_OBS("select write when full", "reports writable"); }
    while (drained < total) {
        r = U(recv)(t.srv, sink, sizeof(sink), 0);
        if (r <= 0) { if (au_readable(t.srv, 500)) continue; break; }
        drained += r;
    }
    AU_EQ(drained, total);
    CHECK(au_writable(t.cli, 3000));
    AU_EQ(U(send)(t.cli, "z", 1, 0), 1);
    au_trio_close(&t);
}

/* ---- shutdown ---------------------------------------------------------------------------------- */
TEST(afu_io_shutdown_send_gives_peer_eof)
{
    char b[4];
    TRIO(t, "io_shsend.sock");
    AU_EQ(U(shutdown)(t.cli, SD_SEND), 0);
    AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    au_trio_close(&t);
}

TEST(afu_io_shutdown_send_other_direction_still_works)
{
    char b[4] = {0};
    TRIO(t, "io_shhalf.sock");
    AU_EQ(U(shutdown)(t.cli, SD_SEND), 0);
    AU_EQ(U(send)(t.srv, "hi", 2, 0), 2);
    AU_EQ(au_recv_n(t.cli, b, 2), 2);
    CHECK(!memcmp(b, "hi", 2));
    au_trio_close(&t);
}

TEST(afu_io_shutdown_send_flushes_pending_data_first)
{
    char b[16] = {0};
    TRIO(t, "io_shflush.sock");
    AU_EQ(U(send)(t.cli, "payload", 7, 0), 7);
    AU_EQ(U(shutdown)(t.cli, SD_SEND), 0);
    AU_EQ(au_recv_n(t.srv, b, 7), 7);
    CHECK(!memcmp(b, "payload", 7));
    AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    au_trio_close(&t);
}

TEST(afu_io_send_after_shutdown_send_is_shutdown)
{
    TRIO(t, "io_shsend2.sock");
    AU_EQ(U(shutdown)(t.cli, SD_SEND), 0);
    au_seterr(0);
    AU_EQ(U(send)(t.cli, "x", 1, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAESHUTDOWN);
    au_trio_close(&t);
}

TEST(afu_io_send_after_shutdown_both_is_shutdown)
{
    TRIO(t, "io_shboth.sock");
    AU_EQ(U(shutdown)(t.cli, SD_BOTH), 0);
    au_seterr(0);
    AU_EQ(U(send)(t.cli, "x", 1, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAESHUTDOWN);
    au_trio_close(&t);
}

TEST(afu_io_shutdown_twice_send)
{
    int r;
    TRIO(t, "io_sh2.sock");
    AU_EQ(U(shutdown)(t.cli, SD_SEND), 0);
    au_seterr(0);
    r = U(shutdown)(t.cli, SD_SEND);
    AU_EQ(r, 0);
    au_trio_close(&t);
}

TEST(afu_io_shutdown_receive_then_recv)
{
    char b[4];
    int r;
    TRIO(t, "io_shrecv.sock");
    AU_EQ(U(shutdown)(t.cli, SD_RECEIVE), 0);
    au_seterr(0);
    r = U(recv)(t.cli, b, 4, 0);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAESHUTDOWN);
    au_trio_close(&t);
}

TEST(afu_io_shutdown_receive_send_still_works)
{
    char b[4] = {0};
    TRIO(t, "io_shrecv2.sock");
    AU_EQ(U(shutdown)(t.cli, SD_RECEIVE), 0);
    AU_EQ(U(send)(t.cli, "go", 2, 0), 2);
    AU_EQ(au_recv_n(t.srv, b, 2), 2);
    CHECK(!memcmp(b, "go", 2));
    au_trio_close(&t);
}

TEST(afu_io_shutdown_invalid_how)
{
    TRIO(t, "io_shbad.sock");
    au_seterr(0);
    AU_EQ(U(shutdown)(t.cli, 3), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    au_seterr(0);
    AU_EQ(U(shutdown)(t.cli, -1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    au_trio_close(&t);
}

TEST(afu_io_shutdown_unconnected_is_notconn)
{
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(shutdown)(s, SD_BOTH), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
}

TEST(afu_io_shutdown_listener_is_notconn)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "io_shlis.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    au_seterr(0);
    AU_EQ(U(shutdown)(s, SD_BOTH), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
    au_unlink_leaf("io_shlis.sock");
}

TEST(afu_io_shutdown_both_then_peer_sees_eof)
{
    char b[4];
    TRIO(t, "io_shboth2.sock");
    AU_EQ(U(shutdown)(t.srv, SD_BOTH), 0);
    AU_EQ(U(recv)(t.cli, b, 4, 0), 0);
    au_trio_close(&t);
}

/* ---- close ------------------------------------------------------------------------------------- */
TEST(afu_io_close_delivers_pending_then_eof)
{
    char b[16] = {0};
    TRIO(t, "io_closeflush.sock");
    AU_EQ(U(send)(t.cli, "last words", 10, 0), 10);
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    AU_EQ(au_recv_n(t.srv, b, 10), 10);
    CHECK(!memcmp(b, "last words", 10));
    AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    au_trio_close(&t);
}

TEST(afu_io_close_makes_peer_readable_with_eof)
{
    char b[4];
    TRIO(t, "io_closesel.sock");
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    au_trio_close(&t);
}

TEST(afu_io_eof_is_sticky)
{
    char b[4];
    int i;
    TRIO(t, "io_eof.sock");
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    for (i = 0; i < 4; i++) AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    au_trio_close(&t);
}

TEST(afu_io_send_to_closed_peer_eventually_fails)
{
    int i, r = 0, err = 0;
    TRIO(t, "io_sendclosed.sock");
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    for (i = 0; i < 40; i++) {
        r = U(send)(t.cli, "x", 1, 0);
        if (r == SOCKET_ERROR) { err = au_err(); break; }
        Sleep(25);
    }
    CHECK(r == SOCKET_ERROR);
    AU_EQ(err, WSAECONNRESET);
    au_trio_close(&t);
}

TEST(afu_io_abortive_close_resets_peer)
{
    struct linger lg = { 1, 0 };
    char b[4];
    int r;
    TRIO(t, "io_rst.sock");
    AU_EQ(U(setsockopt)(t.cli, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg)), 0);
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    AU_EQ(au_readable(t.srv, 3000), 1);
    au_seterr(0);
    r = U(recv)(t.srv, b, 4, 0);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNRESET);
    au_trio_close(&t);
}

TEST(afu_io_accepted_survives_listener_close)
{
    char b[4] = {0};
    TRIO(t, "io_lisgone.sock");
    U(closesocket)(t.lis); t.lis = INVALID_SOCKET;
    AU_EQ(U(send)(t.cli, "ok", 2, 0), 2);
    AU_EQ(au_recv_n(t.srv, b, 2), 2);
    CHECK(!memcmp(b, "ok", 2));
    au_trio_close(&t);
}

TEST(afu_io_connection_survives_socket_file_deletion)
{
    char b[4] = {0};
    TRIO(t, "io_filegone.sock");
    if (!DeleteFileA(t.path)) { AU_OBS("delete live socket file", "error %lu", GetLastError()); au_trio_close(&t); return; }
    AU_EQ(U(send)(t.cli, "ok", 2, 0), 2);
    AU_EQ(au_recv_n(t.srv, b, 2), 2);
    AU_EQ(U(send)(t.srv, "ko", 2, 0), 2);
    AU_EQ(au_recv_n(t.cli, b, 2), 2);
    CHECK(!memcmp(b, "ko", 2));
    au_trio_close(&t);
}

TEST(afu_io_unaccepted_client_sees_close_of_listener)
{
    SOCKADDR_UN a;
    SOCKET c;
    char b[4];
    int r;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "io_pendclose.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(au_readable(lis, 3000), 1);
    U(closesocket)(lis);
    au_blocking(c, TRUE);
    au_rcvtimeo(c, 3000);
    au_seterr(0);
    r = U(recv)(c, b, 4, 0);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNRESET);
    U(closesocket)(c);
    au_unlink_leaf("io_pendclose.sock");
}

/* Blocking recv in another thread released by closing the socket. */
struct rv { SOCKET s; int ret, err; };
static DWORD WINAPI rv_thread(LPVOID p)
{
    struct rv *r = (struct rv *)p;
    char b[4];
    r->ret = U(recv)(r->s, b, 4, 0);
    r->err = r->ret < 0 ? au_err() : 0;
    return 0;
}
TEST(afu_io_close_releases_blocked_recv)
{
    struct rv r;
    HANDLE th;
    DWORD w;
    TRIO(t, "io_blockclose.sock");
    au_rcvtimeo(t.srv, 0);
    r.s = t.srv; r.ret = -2; r.err = 0;
    th = CreateThread(NULL, 0, rv_thread, &r, 0, NULL);
    if (!th) { t_skip("thread"); au_trio_close(&t); return; }
    Sleep(200);
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    w = WaitForSingleObject(th, 5000);
    CHECK(w == WAIT_OBJECT_0);
    if (w != WAIT_OBJECT_0) { U(shutdown)(t.cli, SD_BOTH); U(closesocket)(t.cli); t.cli = INVALID_SOCKET; WaitForSingleObject(th, 3000); }
    else AU_OBS("recv released by closesocket", "ret %d err %d", r.ret, r.err);
    CloseHandle(th);
    au_trio_close(&t);
}

TEST(afu_io_shutdown_releases_blocked_recv)
{
    struct rv r;
    HANDLE th;
    DWORD w;
    TRIO(t, "io_blocksh.sock");
    au_rcvtimeo(t.srv, 0);
    r.s = t.srv; r.ret = -2; r.err = 0;
    th = CreateThread(NULL, 0, rv_thread, &r, 0, NULL);
    if (!th) { t_skip("thread"); au_trio_close(&t); return; }
    Sleep(200);
    U(shutdown)(t.cli, SD_SEND);
    w = WaitForSingleObject(th, 5000);
    CHECK(w == WAIT_OBJECT_0);
    if (w != WAIT_OBJECT_0) { U(closesocket)(t.cli); t.cli = INVALID_SOCKET; WaitForSingleObject(th, 3000); }
    CloseHandle(th);
    AU_EQ(r.ret, 0);
    au_trio_close(&t);
}

TEST(afu_io_blocking_recv_woken_by_send)
{
    struct rv r;
    HANDLE th;
    DWORD w;
    TRIO(t, "io_wake.sock");
    au_rcvtimeo(t.srv, 0);
    r.s = t.srv; r.ret = -2; r.err = 0;
    th = CreateThread(NULL, 0, rv_thread, &r, 0, NULL);
    if (!th) { t_skip("thread"); au_trio_close(&t); return; }
    Sleep(100);
    U(send)(t.cli, "w", 1, 0);
    w = WaitForSingleObject(th, 5000);
    CHECK(w == WAIT_OBJECT_0);
    if (w != WAIT_OBJECT_0) { U(closesocket)(t.srv); t.srv = INVALID_SOCKET; WaitForSingleObject(th, 3000); }
    CloseHandle(th);
    AU_EQ(r.ret, 1);
    au_trio_close(&t);
}

