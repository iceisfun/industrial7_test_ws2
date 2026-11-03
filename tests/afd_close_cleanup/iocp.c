/* Completion-port association of an endpoint at the NT level (FileCompletionInformation) and the packets that
 * come back: status, key, apc context, information, plus the notification-mode flags and what survives when the
 * port or the endpoint is closed first.
 */
#include "acc.h"

typedef struct { HANDLE Port; ULONG_PTR Key; } compl_info_t;

static LONG assoc(HANDLE file, HANDLE port, ULONG_PTR key, ULONG len, IO_STATUS_BLOCK *io)
{
    compl_info_t ci; IO_STATUS_BLOCK local;
    ci.Port = port; ci.Key = key;
    if (!io) io = &local;
    memset(io, 0xAB, sizeof *io);
    return UN(NtSetInformationFile)(file, io, &ci, len, FI_Completion);
}

TEST(cc_iocp_nt_associate_ok_then_second_refused)
{
    SOCKET s; HANDLE p; IO_STATUS_BLOCK io;
    UP();
    s = acc_sock(SOCK_STREAM); p = acc_port();
    REQUIRE(p);
    EXPECT_ST(assoc((HANDLE)s, p, 1, sizeof(compl_info_t), &io), ST_SUCCESS);
    EXPECT_ST(assoc((HANDLE)s, p, 2, sizeof(compl_info_t), &io), ST_INVALID_PARAMETER);
    CLOSES(s); CloseHandle(p);
}

TEST(cc_iocp_nt_length_protocol)
{
    SOCKET s; HANDLE p;
    UP();
    s = acc_sock(SOCK_STREAM); p = acc_port();
    REQUIRE(p);
    EXPECT_ST(assoc((HANDLE)s, p, 1, 0, NULL), ST_INFO_MISMATCH);
    EXPECT_ST(assoc((HANDLE)s, p, 1, 8, NULL), ST_INFO_MISMATCH);
    EXPECT_ST(assoc((HANDLE)s, p, 1, 15, NULL), ST_INFO_MISMATCH);
    EXPECT_ST(assoc((HANDLE)s, p, 1, 16, NULL), ST_SUCCESS);       /* exact size takes */
    CLOSES(s); CloseHandle(p);
}

TEST(cc_iocp_nt_bad_port_handles)
{
    SOCKET s; HANDLE ev, p, weak = NULL;
    UP();
    s = acc_sock(SOCK_STREAM); ev = acc_event(); p = acc_port();
    REQUIRE(p && ev);
    EXPECT_ST(assoc((HANDLE)s, NULL, 1, 16, NULL), ST_INVALID_HANDLE);
    EXPECT_ST(assoc((HANDLE)s, (HANDLE)(ULONG_PTR)0x7ffc, 1, 16, NULL), ST_INVALID_HANDLE);
    EXPECT_ST(assoc((HANDLE)s, ev, 1, 16, NULL), ST_TYPE_MISMATCH);      /* an event is not a port */
    EXPECT_ST(assoc((HANDLE)s, (HANDLE)s, 1, 16, NULL), ST_TYPE_MISMATCH);
    /* a port handle lacking IO_COMPLETION_MODIFY_STATE */
    CHECK(DuplicateHandle(GetCurrentProcess(), p, GetCurrentProcess(), &weak, SYNCHRONIZE, FALSE, 0));
    EXPECT_ST(assoc((HANDLE)s, weak, 1, 16, NULL), ST_ACCESS_DENIED);
    /* none of the failures associated anything: a real association still works */
    EXPECT_ST(assoc((HANDLE)s, p, 1, 16, NULL), ST_SUCCESS);
    CloseHandle(weak); CloseHandle(ev); CloseHandle(p); CLOSES(s);
}

TEST(cc_iocp_nt_invalid_file_handle)
{
    HANDLE p;
    UP();
    p = acc_port();
    REQUIRE(p);
    EXPECT_ST(assoc(NULL, p, 1, 16, NULL), ST_INVALID_HANDLE);
    EXPECT_ST(assoc((HANDLE)(ULONG_PTR)0x7ffc, p, 1, 16, NULL), ST_INVALID_HANDLE);
    EXPECT_ST(assoc(p, p, 1, 16, NULL), ST_TYPE_MISMATCH);          /* not a file object */
    CloseHandle(p);
}

/* Non-overlapped endpoint: the association is refused. */
TEST(cc_iocp_nt_sync_endpoint_refused)
{
    SOCKET s; HANDLE p;
    UP();
    s = acc_sock_sync(SOCK_STREAM); p = acc_port();
    REQUIRE(p);
    EXPECT_ST(assoc((HANDLE)s, p, 1, 16, NULL), ST_INVALID_PARAMETER);
    CLOSES(s); CloseHandle(p);
}

/* Each endpoint flavour takes an association. */
static void kind_case(int kind)
{
    SOCKET s = INVALID_SOCKET, o = INVALID_SOCKET; HANDLE p;
    UP();
    p = acc_port();
    REQUIRE(p);
    if (kind == 0) s = acc_sock(SOCK_STREAM);
    else if (kind == 1) s = acc_sock(SOCK_DGRAM);
    else if (kind == 2) s = acc_listener(NULL);
    else { PAIR(c, sv); s = c; o = sv; }
    REQUIRE(s != INVALID_SOCKET);
    EXPECT_ST(assoc((HANDLE)s, p, 9, 16, NULL), ST_SUCCESS);
    EXPECT_ST(assoc((HANDLE)s, p, 9, 16, NULL), ST_INVALID_PARAMETER);
    CLOSES(s); if (o != INVALID_SOCKET) CLOSES(o);
    CloseHandle(p);
}
TEST(cc_iocp_nt_associate_tcp_unbound)  { kind_case(0); }
TEST(cc_iocp_nt_associate_udp)          { kind_case(1); }
TEST(cc_iocp_nt_associate_listener)     { kind_case(2); }
TEST(cc_iocp_nt_associate_connected)    { kind_case(3); }

/* Association is per file object: an accepted socket does not inherit the listener's port. */
TEST(cc_iocp_accepted_socket_not_associated)
{
    struct sockaddr_in a; SOCKET l, c, s; HANDLE p;
    UP();
    l = acc_listener(&a); p = acc_port();
    REQUIRE(l != INVALID_SOCKET && p);
    EXPECT_ST(assoc((HANDLE)l, p, 1, 16, NULL), ST_SUCCESS);
    c = acc_sock(SOCK_STREAM);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof a) == 0);
    acc_timeo(l, ACC_WAIT);
    s = U(accept)(l, NULL, NULL);
    REQUIRE(s != INVALID_SOCKET);
    EXPECT_ST(assoc((HANDLE)s, p, 2, 16, NULL), ST_SUCCESS);
    CLOSES(s); CLOSES(c); CLOSES(l); CloseHandle(p);
}

/* ---- delivered packets ------------------------------------------------------------------------------------- */
/* A 64-bit key and the apc context given to NtReadFile come back unchanged. */
TEST(cc_iocp_packet_key_and_apc_context_roundtrip)
{
    PAIR(c, s);
    HANDLE p, ev; IO_STATUS_BLOCK iosb, rio; char buf[8]; ULONG_PTR key = 0, apc = 0; LONG st;
    UP();
    p = acc_port(); ev = acc_event();
    REQUIRE(p);
    EXPECT_ST(assoc((HANDLE)c, p, (ULONG_PTR)0x1122334455667788ull, 16, NULL), ST_SUCCESS);
    memset(&iosb, 0, sizeof iosb);
    { LARGE_INTEGER off; off.QuadPart = 0;
    st = UN(NtReadFile)((HANDLE)c, NULL, NULL, (void *)(ULONG_PTR)0xA5A5A5, &iosb, buf, 4, &off, NULL); }
    EXPECT_ST(st, ST_PENDING);
    CHECK(U(send)(s, "wxyz", 4, 0) == 4);
    EXPECT_ST(acc_remove(p, &key, &apc, &rio, ACC_WAIT), ST_SUCCESS);
    EXPECT_EQ(key, (ULONG_PTR)0x1122334455667788ull);
    EXPECT_EQ(apc, 0xA5A5A5);
    EXPECT_EQ(rio.Status, ST_SUCCESS);
    EXPECT_EQ(rio.Information, 4);
    EXPECT_EQ(iosb.Status, ST_SUCCESS);
    EXPECT_EQ(iosb.Information, 4);
    EXPECT_EQ(memcmp(buf, "wxyz", 4), 0);
    CloseHandle(ev); CloseHandle(p); CLOSES(c); CLOSES(s);
}

/* Winsock overlapped receive: the apc context is the OVERLAPPED pointer, key per association, Information the
 * byte count, and GetQueuedCompletionStatus agrees. */
TEST(cc_iocp_winsock_recv_packet_fields)
{
    PAIR(c, s);
    HANDLE p; OVERLAPPED ov, *got = NULL; char buf[8]; WSABUF wb; DWORD fl = 0, n = 0; ULONG_PTR key = 0;
    UP();
    p = acc_port();
    REQUIRE(p);
    CHECK(CreateIoCompletionPort((HANDLE)c, p, 0x77, 0) == p);
    acc_ov_init(&ov, NULL);
    wb.buf = buf; wb.len = 8;
    CHECK(U(WSARecv)(c, &wb, 1, NULL, &fl, &ov, NULL) == SOCKET_ERROR && WERR() == WSA_IO_PENDING);
    CHECK(U(send)(s, "abc", 3, 0) == 3);
    CHECK(GetQueuedCompletionStatus(p, &n, &key, &got, ACC_WAIT));
    EXPECT_EQ(n, 3); EXPECT_EQ(key, 0x77); CHECK(got == &ov);
    EXPECT_ST(OV_STATUS(&ov), ST_SUCCESS);
    CloseHandle(p); CLOSES(c); CLOSES(s);
}

/* A request aborted by the close is reported by GetQueuedCompletionStatus as a failed dequeue that still hands
 * back the OVERLAPPED, with ERROR_CONNECTION_ABORTED for a connected stream. */
TEST(cc_iocp_close_abort_reported_as_failed_dequeue)
{
    pend_t p; HANDLE port; OVERLAPPED *got = NULL; DWORD n = 77, err; ULONG_PTR key = 0; BOOL r;
    UP();
    port = acc_port();
    REQUIRE(port);
    if (!acc_pend_start(&p, OP_RECV_TCP, port, 0x31)) { t_skip("could not queue"); acc_pend_done(&p); CloseHandle(port); return; }
    CLOSES(p.target); p.target = INVALID_SOCKET;
    SetLastError(0);
    r = GetQueuedCompletionStatus(port, &n, &key, &got, ACC_WAIT);
    err = GetLastError();
    CHECK(!r); CHECK(got == &p.ov); EXPECT_EQ(key, 0x31); EXPECT_EQ(n, 0);
    EXPECT_EQ(err, ERROR_CONNECTION_ABORTED);
    CloseHandle(port); acc_pend_done(&p);
}

TEST(cc_iocp_cancelled_udp_reported_operation_aborted)
{
    pend_t p; HANDLE port; OVERLAPPED *got = NULL; DWORD n = 77, err; ULONG_PTR key = 0; BOOL r;
    UP();
    port = acc_port();
    REQUIRE(port);
    if (!acc_pend_start(&p, OP_RECV_UDP, port, 0x32)) { t_skip("could not queue"); acc_pend_done(&p); CloseHandle(port); return; }
    CHECK(CancelIoEx((HANDLE)p.target, NULL));
    SetLastError(0);
    r = GetQueuedCompletionStatus(port, &n, &key, &got, ACC_WAIT);
    err = GetLastError();
    CHECK(!r); CHECK(got == &p.ov); EXPECT_EQ(err, ERROR_OPERATION_ABORTED);
    CloseHandle(port); acc_pend_done(&p);
}

/* A packet already queued survives closing the endpoint that produced it. */
TEST(cc_iocp_queued_packet_outlives_endpoint)
{
    pend_t p; HANDLE port; ULONG_PTR key = 0, apc = 0; IO_STATUS_BLOCK io;
    UP();
    port = acc_port();
    REQUIRE(port);
    if (!acc_pend_start(&p, OP_RECV_TCP, port, 0x41)) { t_skip("could not queue"); acc_pend_done(&p); CloseHandle(port); return; }
    CHECK(U(send)(p.other, "k", 1, 0) == 1);
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    CLOSES(p.target); p.target = INVALID_SOCKET;
    EXPECT_ST(acc_remove(port, &key, &apc, &io, ACC_WAIT), ST_SUCCESS);
    EXPECT_EQ(key, 0x41); EXPECT_EQ(io.Information, 1); EXPECT_EQ(apc, (ULONG_PTR)&p.ov);
    EXPECT_ST(acc_remove(port, &key, &apc, &io, 50), ST_TIMEOUT);
    CloseHandle(port); acc_pend_done(&p);
}

/* Closing the port first: the request still completes on its own and the endpoint closes cleanly. */
TEST(cc_iocp_port_closed_before_completion)
{
    pend_t p; HANDLE port;
    UP();
    port = acc_port();
    REQUIRE(port);
    if (!acc_pend_start(&p, OP_RECV_TCP, port, 0x42)) { t_skip("could not queue"); acc_pend_done(&p); CloseHandle(port); return; }
    CloseHandle(port);
    CHECK(U(send)(p.other, "k", 1, 0) == 1);
    CHECK(acc_pend_wait(&p, ACC_WAIT));
    EXPECT_ST(OV_STATUS(&p.ov), ST_SUCCESS);
    EXPECT_EQ(p.ov.InternalHigh, 1);
    acc_pend_done(&p);
}

/* Nothing outstanding means an empty port: a zero-timeout remove reports the timeout status. */
TEST(cc_iocp_fresh_port_is_empty)
{
    HANDLE p; ULONG_PTR key, apc; IO_STATUS_BLOCK io; LARGE_INTEGER zero;
    UP();
    p = acc_port();
    REQUIRE(p);
    zero.QuadPart = 0;
    EXPECT_ST(UN(NtRemoveIoCompletion)(p, &key, &apc, &io, &zero), ST_TIMEOUT);
    CloseHandle(p);
}

/* Completions of two different endpoints sharing one port carry their own keys. */
TEST(cc_iocp_two_endpoints_one_port_keys)
{
    pend_t a, b; HANDLE port; int seen_a = 0, seen_b = 0, i;
    UP();
    port = acc_port();
    REQUIRE(port);
    if (!acc_pend_start(&a, OP_RECV_UDP, port, 0xA1) || !acc_pend_start(&b, OP_RECV_UDP, port, 0xB2)) {
        t_skip("could not queue"); acc_pend_done(&a); acc_pend_done(&b); CloseHandle(port); return;
    }
    CLOSES(a.target); a.target = INVALID_SOCKET;
    CLOSES(b.target); b.target = INVALID_SOCKET;
    for (i = 0; i < 2; i++) {
        ULONG_PTR key = 0, apc = 0; IO_STATUS_BLOCK io;
        EXPECT_ST(acc_remove(port, &key, &apc, &io, ACC_WAIT), ST_SUCCESS);
        if (key == 0xA1) { seen_a++; EXPECT_EQ(apc, (ULONG_PTR)&a.ov); }
        if (key == 0xB2) { seen_b++; EXPECT_EQ(apc, (ULONG_PTR)&b.ov); }
    }
    EXPECT_EQ(seen_a, 1); EXPECT_EQ(seen_b, 1);
    CloseHandle(port); acc_pend_done(&a); acc_pend_done(&b);
}

/* ---- FileIoCompletionNotificationInformation ------------------------------------------------------------ */
static LONG notif_set(HANDLE h, ULONG flags, ULONG len)
{
    IO_STATUS_BLOCK io; ULONG f = flags;
    memset(&io, 0xAB, sizeof io);
    return UN(NtSetInformationFile)(h, &io, &f, len, FI_IoCompletionNotification);
}
static ULONG notif_get(HANDLE h)
{
    IO_STATUS_BLOCK io; ULONG f = 0xFFFFFFFFu;
    UN(NtQueryInformationFile)(h, &io, &f, 4, FI_IoCompletionNotification);
    return f;
}

TEST(cc_iocp_notification_flags_set_and_read)
{
    SOCKET s;
    UP();
    s = acc_sock(SOCK_STREAM);
    EXPECT_EQ(notif_get((HANDLE)s), 0);
    EXPECT_ST(notif_set((HANDLE)s, 1, 4), ST_SUCCESS);
    EXPECT_EQ(notif_get((HANDLE)s), 1);
    EXPECT_ST(notif_set((HANDLE)s, 2, 4), ST_SUCCESS);
    EXPECT_EQ(notif_get((HANDLE)s), 3);                  /* flags accumulate */
    CLOSES(s);
}

TEST(cc_iocp_notification_length_and_fast_io_bit)
{
    SOCKET s;
    UP();
    s = acc_sock(SOCK_STREAM);
    EXPECT_ST(notif_set((HANDLE)s, 1, 0), ST_INFO_MISMATCH);
    EXPECT_ST(notif_set((HANDLE)s, 1, 3), ST_INFO_MISMATCH);
    EXPECT_ST(notif_set((HANDLE)s, 4, 4), ST_SUCCESS);        /* skip-user-event-on-fast-io is a defined bit */
    EXPECT_EQ(notif_get((HANDLE)s), 4);
    CLOSES(s);
}

/* Skip-on-success: an overlapped send that completes inline posts no packet; with the flag off it does. */
TEST(cc_iocp_skip_on_success_inline_send)
{
    PAIR(c, s);
    HANDLE p; OVERLAPPED ov; WSABUF wb; ULONG_PTR key, apc; IO_STATUS_BLOCK io; DWORD n = 0;
    UP();
    p = acc_port();
    REQUIRE(p);
    CreateIoCompletionPort((HANDLE)c, p, 5, 0);
    acc_ov_init(&ov, NULL);
    wb.buf = "hello"; wb.len = 5;
    CHECK(U(WSASend)(c, &wb, 1, &n, 0, &ov, NULL) == 0);
    EXPECT_ST(acc_remove(p, &key, &apc, &io, ACC_WAIT), ST_SUCCESS);       /* no skip flag: packet posted */
    EXPECT_ST(notif_set((HANDLE)c, 1, 4), ST_SUCCESS);
    acc_ov_init(&ov, NULL);
    CHECK(U(WSASend)(c, &wb, 1, &n, 0, &ov, NULL) == 0);
    EXPECT_ST(acc_remove(p, &key, &apc, &io, 100), ST_TIMEOUT);             /* flag set: inline success, no packet */
    CloseHandle(p); CLOSES(c); CLOSES(s);
}

/* The flag does not suppress the packet for a cancelled or otherwise non-success completion. */
TEST(cc_iocp_skip_on_success_does_not_hide_cancel)
{
    pend_t p; HANDLE port; ULONG_PTR key, apc; IO_STATUS_BLOCK io;
    UP();
    port = acc_port();
    REQUIRE(port);
    if (!acc_pend_start(&p, OP_RECV_UDP, port, 0x55)) { t_skip("could not queue"); acc_pend_done(&p); CloseHandle(port); return; }
    EXPECT_ST(notif_set((HANDLE)p.target, 1, 4), ST_SUCCESS);
    CLOSES(p.target); p.target = INVALID_SOCKET;
    EXPECT_ST(acc_remove(port, &key, &apc, &io, ACC_WAIT), ST_SUCCESS);
    EXPECT_EQ(io.Status, ST_CANCELLED);
    CloseHandle(port); acc_pend_done(&p);
}
