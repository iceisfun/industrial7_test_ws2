/* Sockets for Registered I/O: WSASocket with WSA_FLAG_REGISTERED_IO, which socket kinds accept the flag, what the
 * flag changes for the classic socket calls, and which sockets can get a request queue.
 *
 * Measured on Windows 10: the flag is accepted for IPv4/IPv6 TCP and UDP, with or without WSA_FLAG_OVERLAPPED;
 * raw sockets, AF_UNIX and flag bits outside the known set fail with WSAEINVAL. A request queue can only be made
 * for a socket that carries the flag (WSAEOPNOTSUPP otherwise). On a registered-I/O socket the classic data
 * transfer calls (recv, recvfrom, send, sendto, WSARecv) fail with WSAENOTSOCK and ioctlsocket
 * FIONBIO/FIONREAD with WSAEOPNOTSUPP, while bind, connect, shutdown, setsockopt, getsockopt and getsockname
 * keep working. An accepted socket inherits the capability from a registered-I/O listener only. */
#include "rio.h"

TEST(rio_socket_flag_accepted_matrix)
{
    NEED_RIO(t);
    static const struct { const char *n; int af, type, proto; DWORD fl; } k[] = {
        {"udp4 rio+ovl", AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL}, {"udp4 rio only", AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSA_FLAG_REGISTERED_IO},
        {"tcp4 rio+ovl", AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL}, {"tcp4 rio only", AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_REGISTERED_IO},
        {"udp6 rio+ovl", AF_INET6, SOCK_DGRAM, IPPROTO_UDP, RIO_FL}, {"tcp6 rio+ovl", AF_INET6, SOCK_STREAM, IPPROTO_TCP, RIO_FL},
        {"udp4 rio+noinherit", AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL | WSA_FLAG_NO_HANDLE_INHERIT},
        {"udp4 proto 0", AF_INET, SOCK_DGRAM, 0, RIO_FL}, {"tcp4 proto 0", AF_INET, SOCK_STREAM, 0, RIO_FL},
    };
    for (unsigned i = 0; i < sizeof k / sizeof *k; i++) {
        SOCKET s = rio_sock(k[i].af, k[i].type, k[i].proto, k[i].fl);
        CHECKF(s != INVALID_SOCKET, "%s: err %d", k[i].n, WSAGetLastError());
        if (s == INVALID_SOCKET) continue;
        RIO_CQ cq = t->CreateCompletionQueue(2, NULL);
        RIO_RQ rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
        CHECKF(rq != NULL, "%s: request queue, err %d", k[i].n, WSAGetLastError());
        closesocket(s);
        t->CloseCompletionQueue(cq);
    }
}
TEST(rio_socket_flag_rejected_matrix)
{
    NEED_RIO(t);
    static const struct { const char *n; int af, type, proto; DWORD fl; int err; } k[] = {
        {"multipoint root", AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL | WSA_FLAG_MULTIPOINT_C_ROOT, WSAEINVAL},
        {"unknown bit 0x200", AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL | 0x200, WSAEINVAL},
        {"unknown bit 0x400", AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0x400, WSAEINVAL},
        {"unknown bit 0x80000000", AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL | 0x80000000, WSAEINVAL},
        {"af_unix stream", AF_UNIX, SOCK_STREAM, 0, RIO_FL, WSAEINVAL},
        {"seqpacket", AF_INET, SOCK_SEQPACKET, 0, RIO_FL, WSAESOCKTNOSUPPORT},
        {"rdm", AF_INET, SOCK_RDM, 0, RIO_FL, WSAESOCKTNOSUPPORT},
    };
    for (unsigned i = 0; i < sizeof k / sizeof *k; i++) {
        SOCKET s;
        WSASetLastError(0);
        s = rio_sock(k[i].af, k[i].type, k[i].proto, k[i].fl);
        CHECKF(s == INVALID_SOCKET, "%s: unexpectedly created", k[i].n);
        if (s != INVALID_SOCKET) { closesocket(s); continue; }
        CHECKF(WSAGetLastError() == k[i].err, "%s: got %d want %d", k[i].n, WSAGetLastError(), k[i].err);
    }
}
TEST(rio_socket_raw_socket_refuses_the_flag)
{
    NEED_RIO(t);
    SOCKET plain = rio_sock(AF_INET, SOCK_RAW, IPPROTO_ICMP, WSA_FLAG_OVERLAPPED), s;
    if (plain == INVALID_SOCKET) { t_skip("raw sockets need an elevated token here"); return; }
    closesocket(plain);
    WSASetLastError(0);
    s = rio_sock(AF_INET, SOCK_RAW, IPPROTO_ICMP, RIO_FL);
    CHECK(s == INVALID_SOCKET);
    if (s != INVALID_SOCKET) closesocket(s); else EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
}
TEST(rio_socket_af_unix_works_without_the_flag)
{
    NEED_RIO(t);
    SOCKET u = rio_sock(AF_UNIX, SOCK_STREAM, 0, WSA_FLAG_OVERLAPPED);
    if (u == INVALID_SOCKET) { t_skip("AF_UNIX unavailable"); return; }
    closesocket(u);
}

TEST(rio_socket_request_queue_needs_the_flag)
{
    NEED_RIO(t);
    static const DWORD fl[] = {0, WSA_FLAG_OVERLAPPED, WSA_FLAG_NO_HANDLE_INHERIT};
    RIO_CQ cq = t->CreateCompletionQueue(2, NULL);
    for (unsigned i = 0; i < 3; i++) {
        SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, fl[i]);
        RIO_RQ rq;
        CHECK(s != INVALID_SOCKET);
        WSASetLastError(0);
        rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
        CHECKF(rq == NULL, "flags 0x%lx", fl[i]); EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
        closesocket(s);
    }
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        WSASetLastError(0);
        CHECK(t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
        closesocket(s);
    }
    t->CloseCompletionQueue(cq);
}
TEST(rio_socket_classic_transfer_calls_fail_with_enotsock)
{
    NEED_RIO(t);
    struct sockaddr_in a; SOCKET s = rio_ubind(&a); char tmp[16]; WSABUF wb = {sizeof tmp, tmp}; DWORD got = 0, fl = 0;
    CHECK(s != INVALID_SOCKET);
    WSASetLastError(0); EXPECT_EQ(recv(s, tmp, sizeof tmp, 0), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); EXPECT_EQ(recvfrom(s, tmp, sizeof tmp, 0, NULL, NULL), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); EXPECT_EQ(sendto(s, "ab", 2, 0, (struct sockaddr *)&a, sizeof a), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); EXPECT_EQ(send(s, "ab", 2, 0), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); EXPECT_EQ(WSARecv(s, &wb, 1, &got, &fl, NULL, NULL), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    closesocket(s);
}
TEST(rio_socket_classic_transfer_calls_still_fail_with_a_request_queue)
{
    NEED_RIO(t);
    struct sockaddr_in a; SOCKET s = rio_ubind(&a); char tmp[16];
    RIO_CQ cq = t->CreateCompletionQueue(2, NULL);
    RIO_RQ rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
    CHECK(rq != NULL);
    WSASetLastError(0); EXPECT_EQ(recv(s, tmp, sizeof tmp, 0), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0); EXPECT_EQ(sendto(s, "ab", 2, 0, (struct sockaddr *)&a, sizeof a), -1); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    closesocket(s); t->CloseCompletionQueue(cq);
}
TEST(rio_socket_ioctlsocket_is_unsupported)
{
    NEED_RIO(t);
    SOCKET s = rio_ubind(NULL); u_long v = 1;
    WSASetLastError(0); EXPECT_EQ(ioctlsocket(s, FIONBIO, &v), -1); EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
    WSASetLastError(0); EXPECT_EQ(ioctlsocket(s, FIONREAD, &v), -1); EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
    closesocket(s);
}
TEST(rio_socket_setup_calls_keep_working)
{
    NEED_RIO(t);
    struct sockaddr_in a, x; int l = sizeof x, v = 1, gv = 0, gl = sizeof gv;
    SOCKET s = rio_ubind(&a);
    CHECK(s != INVALID_SOCKET);
    EXPECT_EQ(setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&v, sizeof v), 0);
    EXPECT_EQ(getsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&gv, &gl), 0); EXPECT_EQ(gv, 1);
    EXPECT_EQ(getsockname(s, (struct sockaddr *)&x, &l), 0); EXPECT_EQ(x.sin_port, a.sin_port);
    WSASetLastError(0); EXPECT_EQ(bind(s, (struct sockaddr *)&a, sizeof a), -1); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);   /* already bound */
    EXPECT_EQ(connect(s, (struct sockaddr *)&a, sizeof a), 0);
    EXPECT_EQ(shutdown(s, SD_BOTH), 0);
    EXPECT_EQ(closesocket(s), 0);
}
TEST(rio_socket_ipv6_udp_gets_a_request_queue)
{
    NEED_RIO(t);
    SOCKET s = rio_sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, RIO_FL); struct sockaddr_in6 x;
    RIO_CQ cq; RIO_RQ rq;
    CHECK(s != INVALID_SOCKET);
    memset(&x, 0, sizeof x); x.sin6_family = AF_INET6; x.sin6_addr.s6_addr[15] = 1;
    if (bind(s, (struct sockaddr *)&x, sizeof x)) { closesocket(s); t_skip("IPv6 loopback unavailable"); return; }
    cq = t->CreateCompletionQueue(2, NULL);
    rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
    CHECK(rq != NULL);
    closesocket(s); t->CloseCompletionQueue(cq);
}
TEST(rio_socket_accepted_socket_inherits_from_rio_listener)
{
    NEED_RIO(t);
    struct sockaddr_in la; int l = sizeof la;
    SOCKET ls = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL), c = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL), s;
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); RIO_RQ rq;
    rio_loop4(&la);
    CHECK(!bind(ls, (struct sockaddr *)&la, sizeof la)); getsockname(ls, (struct sockaddr *)&la, &l); CHECK(!listen(ls, 1));
    EXPECT_EQ(connect(c, (struct sockaddr *)&la, sizeof la), 0);
    s = accept(ls, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
    CHECKF(rq != NULL, "err %d", WSAGetLastError());
    closesocket(s); closesocket(c); closesocket(ls); t->CloseCompletionQueue(cq);
}
TEST(rio_socket_accepted_socket_from_plain_listener_has_no_rio)
{
    NEED_RIO(t);
    struct sockaddr_in la; int l = sizeof la;
    SOCKET ls = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED), c = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL), s;
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL);
    rio_loop4(&la);
    CHECK(!bind(ls, (struct sockaddr *)&la, sizeof la)); getsockname(ls, (struct sockaddr *)&la, &l); CHECK(!listen(ls, 1));
    EXPECT_EQ(connect(c, (struct sockaddr *)&la, sizeof la), 0);
    s = accept(ls, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
    closesocket(s); closesocket(c); closesocket(ls); t->CloseCompletionQueue(cq);
}
