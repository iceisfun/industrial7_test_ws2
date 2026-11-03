/* Overlapped I/O and I/O completion ports on AF_UNIX stream sockets: completion packets for receive, send,
 * end of stream and cancellation (key, byte count, status), AcceptEx and ConnectEx completions, address-buffer
 * handling, and the association rules of the port. */
#include "xud.h"

static HANDLE new_port(void) { return CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); }

struct pkt { BOOL ok; DWORD bytes; ULONG_PTR key; LPOVERLAPPED ov; DWORD err; };
static struct pkt get(HANDLE port, DWORD ms)
{
    struct pkt p;
    p.bytes = 0xdead; p.key = 0xdead; p.ov = NULL; p.err = 0;
    SetLastError(0);
    p.ok = GetQueuedCompletionStatus(port, &p.bytes, &p.key, &p.ov, ms);
    p.err = p.ok ? 0 : GetLastError();
    return p;
}

TEST(xud_iocp_associate_returns_the_port)
{
    HANDLE port, r;
    TRIO(t, "ic1.sock");
    port = new_port();
    r = CreateIoCompletionPort((HANDLE)t.cli, port, 7, 0);
    XEQ(r, port);
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_associate_twice_is_invalid_parameter)
{
    HANDLE port, p2, r;
    TRIO(t, "ic2.sock");
    port = new_port(); p2 = new_port();
    XEQ(CreateIoCompletionPort((HANDLE)t.cli, port, 7, 0), port);
    SetLastError(0);
    r = CreateIoCompletionPort((HANDLE)t.cli, port, 8, 0);       /* same port, other key */
    XEQ(r, 0);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0);
    r = CreateIoCompletionPort((HANDLE)t.cli, p2, 7, 0);         /* other port */
    XEQ(r, 0);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CloseHandle(port); CloseHandle(p2);
    x_trio_close(&t);
}
TEST(xud_iocp_empty_port_times_out_with_wait_timeout)
{
    HANDLE port = new_port();
    struct pkt p = get(port, 50);
    XEQ(p.ok, 0);
    XEQ(p.err, WAIT_TIMEOUT);
    XEQ(p.ov, 0);
    CloseHandle(port);
}
TEST(xud_iocp_pending_recv_completes_with_key_and_count)
{
    HANDLE port;
    char buf[16];
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0, fl = 0;
    struct pkt p;
    TRIO(t, "ic3.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.srv, port, 222, 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    XEQ(U(WSARecv)(t.srv, &wb, 1, &n, &fl, &ov, NULL), -1);
    XEQ(x_err(), WSA_IO_PENDING);
    p = get(port, 100);
    XEQ(p.ok, 0);                                                /* nothing before data arrives */
    XEQ(p.err, WAIT_TIMEOUT);
    XEQ(U(send)(t.cli, "hello", 5, 0), 5);
    p = get(port, 3000);
    XEQ(p.ok, 1);
    XEQ(p.bytes, 5);
    XEQ(p.key, 222);
    XEQ(p.ov, &ov);
    XEQ(ov.Internal, 0);                                         /* STATUS_SUCCESS */
    XEQ(ov.InternalHigh, 5);
    CHECK(!memcmp(buf, "hello", 5));
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_immediate_send_still_queues_a_packet)
{
    HANDLE port;
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0;
    struct pkt p;
    TRIO(t, "ic4.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.cli, port, 111, 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = "abc"; wb.len = 3;
    XEQ(U(WSASend)(t.cli, &wb, 1, &n, 0, &ov, NULL), 0);         /* completed inline ... */
    XEQ(n, 3);
    p = get(port, 3000);                                         /* ... and the port gets its packet anyway */
    XEQ(p.ok, 1);
    XEQ(p.bytes, 3);
    XEQ(p.key, 111);
    XEQ(p.ov, &ov);
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_data_already_waiting_recv_completes_inline_and_queues)
{
    HANDLE port;
    char buf[16];
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0, fl = 0;
    struct pkt p;
    TRIO(t, "ic5.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.srv, port, 5, 0);
    XEQ(U(send)(t.cli, "ready", 5, 0), 5);
    CHECK(x_readable(t.srv, 3000));
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    XEQ(U(WSARecv)(t.srv, &wb, 1, &n, &fl, &ov, NULL), 0);
    XEQ(n, 5);
    p = get(port, 3000);
    XEQ(p.ok, 1);
    XEQ(p.bytes, 5);
    XEQ(p.ov, &ov);
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_end_of_stream_completes_with_zero_bytes_success)
{
    HANDLE port;
    char buf[16];
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0, fl = 0;
    struct pkt p;
    TRIO(t, "ic6.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.cli, port, 111, 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    XEQ(U(WSARecv)(t.cli, &wb, 1, &n, &fl, &ov, NULL), -1);
    XEQ(x_err(), WSA_IO_PENDING);
    XEQ(U(shutdown)(t.srv, SD_SEND), 0);
    p = get(port, 3000);
    XEQ(p.ok, 1);                                                /* end of stream is a success with no bytes */
    XEQ(p.bytes, 0);
    XEQ(p.key, 111);
    XEQ(p.ov, &ov);
    XEQ(ov.Internal, 0);
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_close_with_pending_recv_completes_aborted)
{
    HANDLE port;
    char buf[16];
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0, fl = 0;
    struct pkt p;
    TRIO(t, "ic7.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.srv, port, 222, 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    XEQ(U(WSARecv)(t.srv, &wb, 1, &n, &fl, &ov, NULL), -1);
    XEQ(x_err(), WSA_IO_PENDING);
    XEQ(U(closesocket)(t.srv), 0);
    t.srv = INVALID_SOCKET;
    p = get(port, 3000);
    XEQ(p.ok, 0);
    XEQ(p.err, ERROR_CONNECTION_ABORTED);                        /* closing a connected socket aborts the receive */
    XEQ(p.key, 222);
    XEQ(p.ov, &ov);
    XEQ(ov.Internal, 0xc0000241);                                /* STATUS_CONNECTION_ABORTED */
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_close_after_send_shutdown_with_pending_recv_completes_cancelled)
{
    HANDLE port;
    char buf[16];
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0, fl = 0;
    struct pkt p;
    TRIO(t, "ic7b.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.srv, port, 222, 0);
    XEQ(U(shutdown)(t.srv, SD_SEND), 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    XEQ(U(WSARecv)(t.srv, &wb, 1, &n, &fl, &ov, NULL), -1);
    XEQ(x_err(), WSA_IO_PENDING);
    XEQ(U(closesocket)(t.srv), 0);
    t.srv = INVALID_SOCKET;
    p = get(port, 3000);
    XEQ(p.ok, 0);
    XEQ(p.err, ERROR_OPERATION_ABORTED);                         /* a half-closed socket is torn down by cancellation instead */
    XEQ(p.ov, &ov);
    XEQ(ov.Internal, 0xc0000120);                                /* STATUS_CANCELLED */
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_cancelioex_completes_aborted)
{
    HANDLE port;
    char buf[16];
    WSABUF wb;
    WSAOVERLAPPED ov;
    DWORD n = 0, fl = 0;
    struct pkt p;
    TRIO(t, "ic8.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.srv, port, 222, 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = buf; wb.len = sizeof buf;
    XEQ(U(WSARecv)(t.srv, &wb, 1, &n, &fl, &ov, NULL), -1);
    XEQ(x_err(), WSA_IO_PENDING);
    XEQ(CancelIoEx((HANDLE)t.srv, &ov), TRUE);
    p = get(port, 3000);
    XEQ(p.ok, 0);
    XEQ(p.err, ERROR_OPERATION_ABORTED);
    XEQ(p.ov, &ov);
    /* the socket is still connected and works */
    XEQ(U(send)(t.cli, "after", 5, 0), 5);
    XEQ(x_recv_n(t.srv, buf, 5), 5);
    CloseHandle(port);
    x_trio_close(&t);
}
TEST(xud_iocp_two_sockets_two_keys_one_port)
{
    HANDLE port;
    char b1[8], b2[8];
    WSABUF w1, w2;
    WSAOVERLAPPED o1, o2;
    DWORD n = 0, fl = 0;
    struct pkt p1, p2;
    TRIO(t, "ic9a.sock");
    {
        struct x_trio u;
        if (!x_trio_open(&u, "ic9b.sock")) { x_trio_close(&t); return; }
        port = new_port();
        CreateIoCompletionPort((HANDLE)t.srv, port, 1001, 0);
        CreateIoCompletionPort((HANDLE)u.srv, port, 2002, 0);
        memset(&o1, 0, sizeof o1); memset(&o2, 0, sizeof o2);
        w1.buf = b1; w1.len = 8; w2.buf = b2; w2.len = 8;
        XEQ(U(WSARecv)(t.srv, &w1, 1, &n, &fl, &o1, NULL), -1);
        XEQ(U(WSARecv)(u.srv, &w2, 1, &n, &fl, &o2, NULL), -1);
        XEQ(U(send)(u.cli, "B", 1, 0), 1);
        p1 = get(port, 3000);
        XEQ(p1.key, 2002);                                       /* the second socket's data arrived first */
        XEQ(p1.ov, &o2);
        XEQ(U(send)(t.cli, "AA", 2, 0), 2);
        p2 = get(port, 3000);
        XEQ(p2.key, 1001);
        XEQ(p2.ov, &o1);
        XEQ(p2.bytes, 2);
        CloseHandle(port);
        x_trio_close(&u);
    }
    x_trio_close(&t);
}
TEST(xud_iocp_postqueued_packet_and_socket_packets_share_order)
{
    HANDLE port;
    WSAOVERLAPPED ov;
    struct pkt p;
    WSABUF wb;
    DWORD n = 0;
    TRIO(t, "ic10.sock");
    port = new_port();
    CreateIoCompletionPort((HANDLE)t.cli, port, 9, 0);
    memset(&ov, 0, sizeof ov);
    wb.buf = "q"; wb.len = 1;
    PostQueuedCompletionStatus(port, 11, 99, (LPOVERLAPPED)&ov.Pointer);
    XEQ(U(WSASend)(t.cli, &wb, 1, &n, 0, &ov, NULL), 0);
    p = get(port, 1000);
    XEQ(p.key, 99);                                              /* FIFO across both sources */
    XEQ(p.bytes, 11);
    p = get(port, 1000);
    XEQ(p.key, 9);
    CloseHandle(port);
    x_trio_close(&t);
}

/* ---- AcceptEx / ConnectEx on a port ---- */
static void *ext(SOCKET s, GUID g)
{
    void *fn = NULL;
    DWORD n = 0;
    if (U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL)) return NULL;
    return fn;
}
#define ADDR_SLOT (sizeof(SOCKADDR_UN) + 16)

TEST(xud_iocp_acceptex_connectex_both_complete_on_the_port)
{
    SOCKET l, c, as;
    SOCKADDR_UN a, ub;
    LPFN_ACCEPTEX AcceptEx;
    LPFN_CONNECTEX ConnectEx;
    HANDLE port;
    char ab[2 * ADDR_SLOT + 16], got[8] = { 0 };
    WSAOVERLAPPED oa, oc;
    DWORD rcv = 0, sent = 0;
    struct pkt p1, p2;
    UP();
    l = x_sock(); c = x_sock();
    if (l == INVALID_SOCKET || c == INVALID_SOCKET) return;
    AcceptEx = ext(l, (GUID)WSAID_ACCEPTEX);
    ConnectEx = ext(c, (GUID)WSAID_CONNECTEX);
    if (!AcceptEx || !ConnectEx) { t_skip("extension functions missing"); U(closesocket)(l); U(closesocket)(c); return; }
    x_addr(&a, x_path("ic11.sock"));
    XEQ(x_bind(l, &a), 0);
    XEQ(U(listen)(l, 2), 0);
    port = new_port();
    CreateIoCompletionPort((HANDLE)l, port, 1, 0);
    CreateIoCompletionPort((HANDLE)c, port, 2, 0);
    as = x_sock();
    memset(&oa, 0, sizeof oa); memset(&oc, 0, sizeof oc);
    XEQ(AcceptEx(l, as, ab, 0, ADDR_SLOT, ADDR_SLOT, &rcv, &oa), FALSE);
    XEQ(x_err(), ERROR_IO_PENDING);
    memset(&ub, 0, sizeof ub); ub.sun_family = AF_UNIX;
    XEQ(x_bind_len(c, &ub, X_ADDR_BASE), 0);                     /* ConnectEx needs a bound socket: unnamed bind */
    XEQ(ConnectEx(c, (struct sockaddr *)&a, sizeof a, "hey", 3, &sent, &oc), FALSE);
    XEQ(x_err(), ERROR_IO_PENDING);
    p1 = get(port, 3000);
    p2 = get(port, 3000);
    {   /* one packet per operation, whichever order they arrive */
        struct pkt *pa = (p1.ov == &oa) ? &p1 : &p2, *pc = (p1.ov == &oa) ? &p2 : &p1;
        XEQ(pa->ov, &oa);
        XEQ(pa->ok, 1);
        XEQ(pa->key, 1);
        XEQ(pa->bytes, 0);                                       /* AcceptEx without receive data: no bytes */
        XEQ(pc->ov, &oc);
        XEQ(pc->ok, 1);
        XEQ(pc->key, 2);
        XEQ(pc->bytes, 3);                                       /* ConnectEx reports the data it sent */
    }
    XEQ(x_recv_n(as, got, 3), 3);
    CHECK(!memcmp(got, "hey", 3));
    XEQ(U(setsockopt)(as, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof l), 0);
    XEQ(U(setsockopt)(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), 0);
    {
        SOCKADDR_UN g;
        int gl = (int)sizeof g;
        XEQ(U(getsockname)(as, (struct sockaddr *)&g, &gl), 0);
        XEQ(gl, X_ADDR_BASE + (int)strlen(a.sun_path) + 1);      /* the accepted socket carries the listener's name */
        EXPECT_STR(g.sun_path, a.sun_path);
        gl = (int)sizeof g;
        XEQ(U(getpeername)(c, (struct sockaddr *)&g, &gl), 0);
        XEQ(gl, 110);
        EXPECT_STR(g.sun_path, a.sun_path);
    }
    CloseHandle(port);
    U(closesocket)(as); U(closesocket)(c); U(closesocket)(l);
    DeleteFileA(a.sun_path);
}
TEST(xud_iocp_connectex_missing_path_fails_synchronously)
{
    SOCKET c;
    SOCKADDR_UN m, ub;
    LPFN_CONNECTEX ConnectEx;
    WSAOVERLAPPED ov;
    HANDLE port;
    struct pkt p;
    UP();
    c = x_sock();
    if (c == INVALID_SOCKET) return;
    ConnectEx = ext(c, (GUID)WSAID_CONNECTEX);
    if (!ConnectEx) { t_skip("ConnectEx missing"); U(closesocket)(c); return; }
    port = new_port();
    CreateIoCompletionPort((HANDLE)c, port, 2, 0);
    memset(&ub, 0, sizeof ub); ub.sun_family = AF_UNIX;
    XEQ(x_bind_len(c, &ub, X_ADDR_BASE), 0);
    x_addr(&m, x_path("ic12_missing.sock"));
    memset(&ov, 0, sizeof ov);
    XEQ(ConnectEx(c, (struct sockaddr *)&m, sizeof m, NULL, 0, NULL, &ov), FALSE);
    XEQ(x_err(), WSAECONNREFUSED);                               /* not ERROR_IO_PENDING: the failure is immediate */
    p = get(port, 200);
    XEQ(p.ok, 0);
    XEQ(p.err, WAIT_TIMEOUT);                                    /* a synchronous failure queues no packet */
    CloseHandle(port);
    U(closesocket)(c);
}
TEST(xud_iocp_acceptex_on_non_listening_socket_is_inval)
{
    SOCKET s, as;
    LPFN_ACCEPTEX AcceptEx;
    char ab[2 * ADDR_SLOT + 16];
    WSAOVERLAPPED ov;
    DWORD rcv = 0;
    UP();
    s = x_sock(); as = x_sock();
    if (s == INVALID_SOCKET || as == INVALID_SOCKET) return;
    AcceptEx = ext(s, (GUID)WSAID_ACCEPTEX);
    if (!AcceptEx) { t_skip("AcceptEx missing"); U(closesocket)(s); U(closesocket)(as); return; }
    memset(&ov, 0, sizeof ov);
    XEQ(AcceptEx(s, as, ab, 0, ADDR_SLOT, ADDR_SLOT, &rcv, &ov), FALSE);
    XEQ(x_err(), WSAEINVAL);
    U(closesocket)(as); U(closesocket)(s);
}
TEST(xud_iocp_acceptex_address_length_table)
{
    SOCKET l, as;
    SOCKADDR_UN a;
    LPFN_ACCEPTEX AcceptEx;
    char ab[1024];
    WSAOVERLAPPED ov;
    DWORD rcv = 0;
    static const DWORD lens[] = { 0, 10, 15, 16, 17, 100, 125, 126 };
    unsigned i;
    UP();
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        BOOL ok;
        l = x_sock(); as = x_sock();
        if (l == INVALID_SOCKET || as == INVALID_SOCKET) return;
        AcceptEx = ext(l, (GUID)WSAID_ACCEPTEX);
        x_addr(&a, x_path("ic13.sock"));
        if (!AcceptEx || x_bind(l, &a) || U(listen)(l, 1)) { t_skip("setup failed"); U(closesocket)(as); U(closesocket)(l); DeleteFileA(a.sun_path); return; }
        memset(&ov, 0, sizeof ov);
        ok = AcceptEx(l, as, ab, 0, lens[i], lens[i], &rcv, &ov);
        XEQ(ok, FALSE);
        XEQ(x_err(), lens[i] == 0 ? WSAEFAULT : ERROR_IO_PENDING);   /* sizes are not validated against the address type when queued */
        CancelIoEx((HANDLE)l, NULL);
        Sleep(50);
        U(closesocket)(as); U(closesocket)(l);
        DeleteFileA(a.sun_path);
    }
}
TEST(xud_iocp_getacceptexsockaddrs_parses_unix_addresses)
{
    SOCKET l, c, as;
    SOCKADDR_UN a;
    LPFN_ACCEPTEX AcceptEx;
    LPFN_GETACCEPTEXSOCKADDRS Parse;
    char ab[2 * ADDR_SLOT + 16];
    WSAOVERLAPPED ov;
    DWORD rcv = 0, tr = 0, fl = 0;
    struct sockaddr *loc = NULL, *rem = NULL;
    int ll = 0, rl = 0;
    UP();
    l = x_sock(); c = x_sock(); as = x_sock();
    if (l == INVALID_SOCKET || c == INVALID_SOCKET || as == INVALID_SOCKET) return;
    AcceptEx = ext(l, (GUID)WSAID_ACCEPTEX);
    Parse = ext(l, (GUID)WSAID_GETACCEPTEXSOCKADDRS);
    x_addr(&a, x_path("ic14.sock"));
    if (!AcceptEx || !Parse || x_bind(l, &a) || U(listen)(l, 1)) { t_skip("setup failed"); goto out; }
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    XEQ(AcceptEx(l, as, ab, 0, ADDR_SLOT, ADDR_SLOT, &rcv, &ov), FALSE);
    XEQ(x_err(), ERROR_IO_PENDING);
    x_blocking(c, FALSE);
    x_connect(c, &a);
    CHECK(U(WSAGetOverlappedResult)(l, &ov, &tr, TRUE, &fl));
    memset(ab, 0x77, 0);
    Parse(ab, 0, ADDR_SLOT, ADDR_SLOT, &loc, &ll, &rem, &rl);
    XEQ(ll, 110);
    XEQ(rl, 110);
    CHECK(loc != NULL && rem != NULL);
    if (loc) { XEQ(loc->sa_family, AF_UNIX); EXPECT_STR(((SOCKADDR_UN *)loc)->sun_path, a.sun_path); }
    if (rem) XEQ(rem->sa_family, AF_UNIX);
    CloseHandle(ov.hEvent);
out:
    U(closesocket)(as); U(closesocket)(c); U(closesocket)(l);
    DeleteFileA(a.sun_path);
}
