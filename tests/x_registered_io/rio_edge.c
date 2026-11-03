/* Additional Registered I/O edge cases: which classic Winsock calls a registered-I/O socket still serves, which
 * memory protections can be registered, receive-side descriptor ranges, extra ReceiveEx arguments, and completion
 * queue behaviour when resized while it holds entries or is closed while armed.
 *
 * Measured on Windows 10. On a registered-I/O UDP socket the overlapped transfer calls, select, WSAEventSelect and
 * WSADuplicateSocket fail with WSAENOTSOCK (WSAPoll returns SOCKET_ERROR with the same error and POLLNVAL in
 * revents) while option queries, SIO_BASE_HANDLE and the extension-pointer lookups keep working. Registration
 * accepts only memory that is committed and writable in every page: read/write and execute/read/write private
 * memory and read/write or copy-on-write mapped views, but not read-only, write-copy, execute-only, execute/read,
 * guard or no-access pages. A receive whose descriptor lies outside its registration is accepted at queuing time
 * and completes when a datagram arrives, with WSAEINVAL; a zero-length descriptor completes with WSAEMSGSIZE. */
#include "rio.h"

TEST(rio_edge_udp_classic_calls_are_enotsock)
{
    NEED_RIO(t);
    struct sockaddr_in a, f; SOCKET s = rio_ubind(&a); char tmp[16]; WSABUF wb = {sizeof tmp, tmp};
    DWORD got = 0, fl = 0; int l = sizeof f, r; OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    WSASetLastError(0); r = W(WSASend)(s, &wb, 1, &got, 0, &ov, NULL); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); r = W(WSASendTo)(s, &wb, 1, &got, 0, (struct sockaddr *)&a, sizeof a, &ov, NULL); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); r = W(WSARecvFrom)(s, &wb, 1, &got, &fl, (struct sockaddr *)&f, &l, &ov, NULL); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    {
        fd_set set; struct timeval tv = {0, 0};
        FD_ZERO(&set); FD_SET(s, &set);
        WSASetLastError(0); r = W(select)(0, NULL, &set, NULL, &tv); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
        FD_ZERO(&set); FD_SET(s, &set);
        WSASetLastError(0); r = W(select)(0, &set, NULL, NULL, &tv); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    }
    {
        WSAPOLLFD pf; pf.fd = s; pf.events = POLLWRNORM; pf.revents = 0;
        WSASetLastError(0); r = W(WSAPoll)(&pf, 1, 0); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
        EXPECT_EQ(pf.revents, POLLNVAL);
    }
    {
        WSAEVENT ev = W(WSACreateEvent)();
        WSASetLastError(0); r = W(WSAEventSelect)(s, ev, FD_READ); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
        W(WSACloseEvent)(ev);
    }
    {
        WSAPROTOCOL_INFOW pi;
        WSASetLastError(0); r = W(WSADuplicateSocketW)(s, GetCurrentProcessId(), &pi); EXPECT_EQ(r, -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    }
    closesocket(s);
}
TEST(rio_edge_udp_queries_still_served)
{
    NEED_RIO(t);
    SOCKET s = rio_ubind(NULL); int v = 0, l, r;
    l = sizeof v; r = getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&v, &l); EXPECT_EQ(r, 0); EXPECT_EQ(v, SOCK_DGRAM);
    l = sizeof v; r = getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&v, &l); EXPECT_EQ(r, 0); EXPECT_EQ(v, 65507);
    v = 65536; EXPECT_EQ(setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, sizeof v), 0);
    v = 0; l = sizeof v; r = getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, &l); EXPECT_EQ(r, 0); EXPECT_EQ(v, 65536);
    v = 17; EXPECT_EQ(setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, sizeof v), 0);
    v = 0; l = sizeof v; r = getsockopt(s, IPPROTO_IP, IP_TTL, (char *)&v, &l); EXPECT_EQ(r, 0); EXPECT_EQ(v, 17);
    {
        WSAPROTOCOL_INFOW pi; l = sizeof pi; memset(&pi, 0, sizeof pi);
        r = getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l);
        EXPECT_EQ(r, 0); EXPECT_EQ(pi.iAddressFamily, AF_INET); EXPECT_EQ(pi.iSocketType, SOCK_DGRAM); EXPECT_EQ(pi.iProtocol, IPPROTO_UDP);
    }
    {
        SOCKET bh = 0; DWORD n = 0;
        r = WSAIoctl(s, SIO_BASE_HANDLE, NULL, 0, &bh, sizeof bh, &n, NULL, NULL);
        EXPECT_EQ(r, 0); CHECK(bh == s); EXPECT_EQ(n, sizeof bh);
    }
    {
        BOOL on = TRUE; DWORD n = 0;
        EXPECT_EQ(WSAIoctl(s, SIO_UDP_CONNRESET, &on, sizeof on, NULL, 0, &n, NULL, NULL), 0);
    }
    {
        GUID g1 = WSAID_WSARECVMSG, g2 = WSAID_CONNECTEX; void *fp = NULL; DWORD n = 0;
        EXPECT_EQ(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g1, sizeof g1, &fp, sizeof fp, &n, NULL, NULL), 0); CHECK(fp != NULL);
        fp = NULL;
        EXPECT_EQ(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g2, sizeof g2, &fp, sizeof fp, &n, NULL, NULL), 0); CHECK(fp != NULL);
    }
    closesocket(s);
}
TEST(rio_edge_tcp_classic_split)
{
    NEED_RIO(t);
    struct sockaddr_in la, pn; int l = sizeof la, pl = sizeof pn, r, v = 1, vl = sizeof v;
    SOCKET ls = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL), c = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL), s;
    char tmp[4]; GUID g = WSAID_ACCEPTEX; void *fp = NULL; DWORD n = 0; LINGER lg = {1, 0};
    rio_loop4(&la);
    CHECK(!bind(ls, (struct sockaddr *)&la, sizeof la)); getsockname(ls, (struct sockaddr *)&la, &l); CHECK(!listen(ls, 1));
    EXPECT_EQ(WSAIoctl(ls, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fp, sizeof fp, &n, NULL, NULL), 0); CHECK(fp != NULL);
    EXPECT_EQ(connect(c, (struct sockaddr *)&la, sizeof la), 0);
    s = accept(ls, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    r = W(getpeername)(c, (struct sockaddr *)&pn, &pl); EXPECT_EQ(r, 0); EXPECT_EQ(pn.sin_port, la.sin_port);
    WSASetLastError(0); EXPECT_EQ(send(c, "x", 1, 0), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); EXPECT_EQ(recv(s, tmp, 1, 0), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    EXPECT_EQ(setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&v, sizeof v), 0);
    v = 0; EXPECT_EQ(getsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char *)&v, &vl), 0); EXPECT_NE(v, 0);
    EXPECT_EQ(setsockopt(c, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg), 0);
    v = 5; vl = sizeof v; EXPECT_EQ(getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&v, &vl), 0); EXPECT_EQ(v, 0);
    closesocket(s); closesocket(c); closesocket(ls);
}

/* Which page protections RIORegisterBuffer accepts. */
TEST(rio_edge_register_protection_matrix)
{
    NEED_RIO(t);
    static const struct { const char *n; DWORD prot; int ok; } m[] = {
        {"read/write", PAGE_READWRITE, 1}, {"execute/read/write", PAGE_EXECUTE_READWRITE, 1},
        {"no access", PAGE_NOACCESS, 0}, {"read only", PAGE_READONLY, 0}, {"write copy", PAGE_WRITECOPY, 0},
        {"execute only", PAGE_EXECUTE, 0}, {"execute/read", PAGE_EXECUTE_READ, 0}, {"execute/write copy", PAGE_EXECUTE_WRITECOPY, 0},
        {"read/write guard", PAGE_READWRITE | PAGE_GUARD, 0},
    };
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        char *b = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, m[i].prot); RIO_BUFFERID id;
        if (!b) { t_note("protection %s unavailable", m[i].n); continue; }
        WSASetLastError(0);
        id = t->RegisterBuffer(b, 0x1000);
        if (m[i].ok) { CHECKF(id != RIO_INVALID_BUFFERID, "%s: err %d", m[i].n, WSAGetLastError()); if (id != RIO_INVALID_BUFFERID) t->DeregisterBuffer(id); }
        else { CHECKF(id == RIO_INVALID_BUFFERID, "%s accepted", m[i].n); EXPECT_EQ(WSAGetLastError(), WSAEFAULT); }
        VirtualFree(b, 0, MEM_RELEASE);
    }
}
TEST(rio_edge_register_mapped_views_and_mixed_protections)
{
    NEED_RIO(t);
    HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x2000, NULL);
    char *rw, *ro, *cw, *b; RIO_BUFFERID id; DWORD old;
    if (!m) { t_skip("file mapping unavailable"); return; }
    rw = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0); ro = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0); cw = MapViewOfFile(m, FILE_MAP_COPY, 0, 0, 0);
    if (!rw || !ro || !cw) { t_skip("MapViewOfFile"); return; }
    id = t->RegisterBuffer(rw, 0x1000); CHECK(id != RIO_INVALID_BUFFERID); if (id != RIO_INVALID_BUFFERID) t->DeregisterBuffer(id);
    id = t->RegisterBuffer(cw, 0x1000); CHECK(id != RIO_INVALID_BUFFERID); if (id != RIO_INVALID_BUFFERID) t->DeregisterBuffer(id);
    WSASetLastError(0); id = t->RegisterBuffer(ro, 0x1000); CHECK(id == RIO_INVALID_BUFFERID); EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    UnmapViewOfFile(rw); UnmapViewOfFile(ro); UnmapViewOfFile(cw); CloseHandle(m);
    /* A range is accepted when every page is writable, even if the pages differ in protection. */
    b = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    VirtualProtect(b + 0x1000, 0x1000, PAGE_READONLY, &old);
    WSASetLastError(0); id = t->RegisterBuffer(b, 0x2000); CHECK(id == RIO_INVALID_BUFFERID); EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    id = t->RegisterBuffer(b, 0x1000); CHECK(id != RIO_INVALID_BUFFERID); if (id != RIO_INVALID_BUFFERID) t->DeregisterBuffer(id);
    VirtualProtect(b + 0x1000, 0x1000, PAGE_EXECUTE_READWRITE, &old);
    id = t->RegisterBuffer(b, 0x2000); CHECK(id != RIO_INVALID_BUFFERID); if (id != RIO_INVALID_BUFFERID) t->DeregisterBuffer(id);
    VirtualFree(b, 0, MEM_RELEASE);
}

/* Receive descriptors outside the registration are accepted when queued and fail when a datagram arrives. */
TEST(rio_edge_receive_descriptor_range_matrix)
{
    static const struct { const char *n; ULONG off, len; LONG status; ULONG bytes; } m[] = {
        {"exactly to the end", 0x1ff00, 0x100, 0, 5}, {"length past the end", 0x1ff00, 0x200, WSAEINVAL, 0},
        {"offset past the end", 0x30000, 1, WSAEINVAL, 0}, {"offset plus length wraps", 0xfffffff0, 0x20, WSAEINVAL, 0},
        {"zero length at the end", 0x20000, 0, WSAEMSGSIZE, 0}, {"zero length", 0, 0, WSAEMSGSIZE, 0},
    };
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIORES rr[2];
        NEED_PAIR(p, t, 2);
        RIO_BUF d = {p.id, m[i].off, m[i].len};
        memcpy(p.mem, "hello", 5);
        CHECKF(t->Receive(p.rb, &d, 1, 0, RQC(i)), "%s: refused at queuing, err %d", m[i].n, WSAGetLastError());
        CHECK(pair_send(&p, 0, 5, 77, 0));
        EXPECT_EQ(rio_wait(t, p.cqb, rr, 2, 1), 1);
        CHECKF(rr[0].Status == m[i].status && rr[0].BytesTransferred == m[i].bytes, "%s: status %ld bytes %lu", m[i].n, rr[0].Status, rr[0].BytesTransferred);
        EXPECT_EQ(rr[0].RequestContext, RQV(i));
        pair_close(&p);
    }
}
TEST(rio_edge_receiveex_control_and_flags_buffers_are_accepted)
{
    RIORES rr[2];
    NEED_PAIR(p, t, 2);
    RIO_BUF d = {p.id, PR_RECV, 16}, ctlb = {p.id, 0x10400, 64}, fb = {p.id, 0x10500, 4};
    memcpy(p.mem, "hello", 5);
    CHECK(t->ReceiveEx(p.rb, &d, 1, NULL, NULL, &ctlb, NULL, 0, RQC(1)));
    CHECK(t->ReceiveEx(p.rb, &d, 1, NULL, NULL, NULL, &fb, 0, RQC(2)));
    CHECK(pair_send(&p, 0, 5, 77, 0)); CHECK(pair_send(&p, 0, 5, 78, 0));
    EXPECT_EQ(rio_wait(t, p.cqb, rr, 2, 2), 2);
    for (int i = 0; i < 2; i++) { EXPECT_EQ(rr[i].Status, 0); EXPECT_EQ(rr[i].BytesTransferred, 5); EXPECT_EQ(rr[i].RequestContext, RQV(1 + i)); }
    pair_close(&p);
}

/* Completion queue resize and close with state attached. */
TEST(rio_edge_resize_cq_keeps_queued_completions)
{
    RIORES rr[8];
    NEED_PAIR(p, t, 2);
    memcpy(p.mem, "abc", 3);
    for (int i = 0; i < 3; i++) {
        CHECK(pair_recv(&p, PR_RECV + i * 16, 8, RQV(i), 0));
        CHECK(pair_send(&p, 0, 3, 50 + i, 0));
        EXPECT_EQ(rio_wait(t, p.cqa, rr, 8, 1), 1);
        Sleep(20);
    }
    CHECK(t->ResizeCompletionQueue(p.cqb, 4));     /* exactly the reservations: 2 + 2 */
    CHECK(t->ResizeCompletionQueue(p.cqb, 40));
    EXPECT_EQ(t->DequeueCompletion(p.cqb, rr, 8), 3);
    for (int i = 0; i < 3; i++) { EXPECT_EQ(rr[i].RequestContext, RQV(i)); EXPECT_EQ(rr[i].Status, 0); EXPECT_EQ(rr[i].BytesTransferred, 3); }
    pair_close(&p);
}
TEST(rio_edge_close_of_an_armed_queue_signals_nothing)
{
    NEED_RIO(t);
    HANDLE ev = CreateEventA(NULL, 0, 0, NULL); RIO_NOTIF nn; RIO_CQ q;
    memset(&nn, 0, sizeof nn); nn.Type = RIO_EVENT_COMPLETION; nn.u.Event.EventHandle = ev;
    q = t->CreateCompletionQueue(4, &nn);
    EXPECT_EQ(t->Notify(q), 0);
    t->CloseCompletionQueue(q);
    EXPECT_EQ(WaitForSingleObject(ev, 150), WAIT_TIMEOUT);
    CloseHandle(ev);
}
