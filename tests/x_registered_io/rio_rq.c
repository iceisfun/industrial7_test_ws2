/* Request queues: RIOCreateRequestQueue and RIOResizeRequestQueue, and the completion-queue capacity accounting
 * they take part in.
 *
 * Measured on Windows 10. Arguments are (socket, maxOutstandingReceive, maxReceiveDataBuffers,
 * maxOutstandingSend, maxSendDataBuffers, receiveCQ, sendCQ, socketContext). Both data-buffer counts must be
 * exactly 1 (WSAEINVAL otherwise, whatever the queue depths); at least one queue depth must be non-zero; both
 * completion queues must be non-NULL (WSAEINVAL). Each request queue reserves maxOutstandingReceive slots in the
 * receive CQ and maxOutstandingSend slots in the send CQ (the same CQ for both adds the two); when a CQ cannot
 * hold the reservation the call fails with WSAENOBUFS. A socket can have one request queue (a second attempt is
 * WSAEFAULT). Resizing a request queue below what is outstanding, or a CQ below its reservations, is
 * WSAETOOMANYREFS. */
#include "rio.h"

static SOCKET fresh(void) { return rio_ubind(NULL); }

TEST(rio_rq_argument_matrix)
{
    NEED_RIO(t);
    static const struct { const char *n; ULONG a, b, c, d; int err; } m[] = {
        {"1,1,1,1", 1, 1, 1, 1, 0}, {"0,1,1,1", 0, 1, 1, 1, 0}, {"1,1,0,1", 1, 1, 0, 1, 0}, {"4,1,4,1", 4, 1, 4, 1, 0},
        {"0,0,0,0", 0, 0, 0, 0, WSAEINVAL}, {"0,1,0,1", 0, 1, 0, 1, WSAEINVAL},
        {"0,0,1,1", 0, 0, 1, 1, WSAEINVAL}, {"1,1,0,0", 1, 1, 0, 0, WSAEINVAL}, {"1,0,1,1", 1, 0, 1, 1, WSAEINVAL}, {"1,1,1,0", 1, 1, 1, 0, WSAEINVAL},
        {"1,0,1,0", 1, 0, 1, 0, WSAEINVAL}, {"1,2,1,2", 1, 2, 1, 2, WSAEINVAL}, {"1,3,1,1", 1, 3, 1, 1, WSAEINVAL}, {"1,1,1,3", 1, 1, 1, 3, WSAEINVAL},
        {"0,2,1,1", 0, 2, 1, 1, WSAEINVAL}, {"2,2,2,2", 2, 2, 2, 2, WSAEINVAL}, {"1,0x7fffffff,1,1", 1, 0x7fffffff, 1, 1, WSAEINVAL},
    };
    RIO_CQ cq = t->CreateCompletionQueue(16, NULL);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        SOCKET s = fresh(); RIO_RQ rq;
        WSASetLastError(0);
        rq = t->CreateRequestQueue(s, m[i].a, m[i].b, m[i].c, m[i].d, cq, cq, NULL);
        if (m[i].err) { CHECKF(rq == NULL, "(%s)", m[i].n); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else CHECKF(rq != NULL, "(%s) err %d", m[i].n, WSAGetLastError());
        closesocket(s);
    }
    t->CloseCompletionQueue(cq);
}
TEST(rio_rq_null_completion_queues_are_einval)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(8, NULL);
    for (int i = 0; i < 3; i++) {
        SOCKET s = fresh(); RIO_RQ rq;
        WSASetLastError(0);
        rq = t->CreateRequestQueue(s, 1, 1, 1, 1, i == 1 ? cq : NULL, i == 0 ? cq : NULL, NULL);
        CHECKF(rq == NULL, "variant %d", i); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
        closesocket(s);
    }
    t->CloseCompletionQueue(cq);
}
TEST(rio_rq_invalid_socket_is_enotsock)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL);
    HANDLE ev = CreateEventA(NULL, 0, 0, NULL);
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue(INVALID_SOCKET, 1, 1, 1, 1, cq, cq, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue((SOCKET)ev, 1, 1, 1, 1, cq, cq, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);   /* a non-socket handle */
    CloseHandle(ev); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_closed_socket_is_enotsock)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL);
    SOCKET s = fresh();
    closesocket(s);
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    t->CloseCompletionQueue(cq);
}
TEST(rio_rq_unbound_and_unconnected_sockets_accept_a_queue)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(8, NULL);
    SOCKET u = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL), c = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL);
    CHECK(t->CreateRequestQueue(u, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    CHECK(t->CreateRequestQueue(c, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    closesocket(u); closesocket(c); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_listening_socket_accepts_a_queue)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(8, NULL);
    SOCKET ls = rio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL); struct sockaddr_in a;
    rio_loop4(&a); CHECK(!bind(ls, (struct sockaddr *)&a, sizeof a)); CHECK(!listen(ls, 1));
    CHECK(t->CreateRequestQueue(ls, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    closesocket(ls); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_second_queue_on_same_socket_is_efault)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(16, NULL); SOCKET s = fresh();
    RIO_RQ a = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL), b;
    CHECK(a != NULL);
    WSASetLastError(0);
    b = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
    CHECK(b == NULL); EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_success_leaves_error_state_alone)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); SOCKET s = fresh(); RIO_RQ rq;
    WSASetLastError(0x1234);
    rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
    CHECK(rq != NULL); EXPECT_EQ(WSAGetLastError(), 0x1234);
    closesocket(s); t->CloseCompletionQueue(cq);
}

/* Completion-queue capacity: CQ size, depths, shared or separate CQs. */
TEST(rio_rq_capacity_matrix_single_cq)
{
    NEED_RIO(t);
    static const struct { ULONG cqsz, a, c; int err; } m[] = {
        {4, 2, 2, 0}, {4, 3, 2, WSAENOBUFS}, {4, 2, 3, WSAENOBUFS}, {4, 4, 0, 0}, {4, 5, 0, WSAENOBUFS}, {4, 0, 4, 0}, {4, 0, 5, WSAENOBUFS},
        {2, 1, 1, 0}, {2, 2, 1, WSAENOBUFS}, {1, 1, 1, WSAENOBUFS}, {1, 1, 0, 0}, {1, 0, 1, 0}, {1, 0, 2, WSAENOBUFS},
        {16, 1000, 1, WSAENOBUFS}, {16, 0xffffffff, 1, WSAENOBUFS}, {16, 8, 8, 0},
    };
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIO_CQ cq = t->CreateCompletionQueue(m[i].cqsz, NULL); SOCKET s = fresh(); RIO_RQ rq;
        WSASetLastError(0);
        rq = t->CreateRequestQueue(s, m[i].a, 1, m[i].c, 1, cq, cq, NULL);
        if (m[i].err) { CHECKF(rq == NULL, "cq %lu depths %lu/%lu", m[i].cqsz, m[i].a, m[i].c); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else CHECKF(rq != NULL, "cq %lu depths %lu/%lu err %d", m[i].cqsz, m[i].a, m[i].c, WSAGetLastError());
        closesocket(s); t->CloseCompletionQueue(cq);
    }
}
TEST(rio_rq_capacity_with_separate_queues)
{
    NEED_RIO(t);
    RIO_CQ r = t->CreateCompletionQueue(2, NULL), sd = t->CreateCompletionQueue(1, NULL);
    SOCKET s1 = fresh(), s2 = fresh(), s3 = fresh();
    CHECK(t->CreateRequestQueue(s1, 2, 1, 1, 1, r, sd, NULL) != NULL);   /* 2 receives fit in r, 1 send fits in sd */
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue(s2, 1, 1, 2, 1, r, sd, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);   /* r is now full */
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue(s3, 0, 1, 1, 1, r, sd, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);   /* sd is full too */
    closesocket(s1); closesocket(s2); closesocket(s3); t->CloseCompletionQueue(r); t->CloseCompletionQueue(sd);
}
TEST(rio_rq_capacity_is_shared_between_sockets)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); SOCKET s1 = fresh(), s2 = fresh(), s3 = fresh();
    CHECK(t->CreateRequestQueue(s1, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    CHECK(t->CreateRequestQueue(s2, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    WSASetLastError(0);
    CHECK(t->CreateRequestQueue(s3, 1, 1, 1, 1, cq, cq, NULL) == NULL); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);
    closesocket(s1); closesocket(s2); closesocket(s3); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_capacity_comes_back_when_the_socket_closes)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(2, NULL); SOCKET s = fresh();
    CHECK(t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    closesocket(s);
    /* The release happens when the closed socket's queue is torn down, which is not synchronous with
     * closesocket: retry for a bounded time and require that the reservation does come back. */
    {
        RIO_RQ rq = NULL;
        for (int i = 0; i < 400 && !rq; i++) {
            s = fresh();
            rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
            if (!rq) { closesocket(s); Sleep(5); }
        }
        CHECK(rq != NULL);
    }
    closesocket(s); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_failed_creation_reserves_nothing)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(2, NULL); SOCKET s = fresh();
    for (int i = 0; i < 5; i++) { CHECK(t->CreateRequestQueue(s, 3, 1, 3, 1, cq, cq, NULL) == NULL); }
    CHECK(t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    closesocket(s); t->CloseCompletionQueue(cq);
}

TEST(rio_rq_resize_cq_below_reservations_is_etoomanyrefs)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); SOCKET s1 = fresh(), s2 = fresh();
    CHECK(t->CreateRequestQueue(s1, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    CHECK(t->CreateRequestQueue(s2, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    WSASetLastError(0); CHECK(!t->ResizeCompletionQueue(cq, 3)); EXPECT_EQ(WSAGetLastError(), WSAETOOMANYREFS);
    WSASetLastError(0); CHECK(!t->ResizeCompletionQueue(cq, 1)); EXPECT_EQ(WSAGetLastError(), WSAETOOMANYREFS);
    CHECK(t->ResizeCompletionQueue(cq, 4));      /* exactly the reservations */
    CHECK(t->ResizeCompletionQueue(cq, 40));
    closesocket(s1); closesocket(s2); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_resize_rq_matrix)
{
    NEED_RIO(t);
    static const struct { ULONG a, c; int err; } m[] = {
        {2, 2, 0}, {0, 1, 0}, {1, 0, 0}, {1, 1, 0}, {0, 0, WSAEINVAL}, {4, 4, 0}, {5, 4, WSAENOBUFS}, {4, 5, WSAENOBUFS}, {100000, 1, WSAENOBUFS}, {1, 100000, WSAENOBUFS},
    };
    RIO_CQ cq = t->CreateCompletionQueue(8, NULL); SOCKET s = fresh();
    RIO_RQ rq = t->CreateRequestQueue(s, 1, 1, 1, 1, cq, cq, NULL);
    CHECK(rq != NULL);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        BOOL r;
        WSASetLastError(0);
        r = t->ResizeRequestQueue(rq, m[i].a, m[i].c);
        if (m[i].err) { CHECKF(!r, "resize %lu,%lu", m[i].a, m[i].c); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else CHECKF(r, "resize %lu,%lu err %d", m[i].a, m[i].c, WSAGetLastError());
    }
    closesocket(s); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_resize_null_queue_is_einval)
{
    NEED_RIO(t);
    WSASetLastError(0);
    CHECK(!t->ResizeRequestQueue(NULL, 1, 1)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
}
TEST(rio_rq_resize_grows_into_free_capacity_only)
{
    NEED_RIO(t);
    RIO_CQ cq = t->CreateCompletionQueue(4, NULL); SOCKET s1 = fresh(), s2 = fresh();
    RIO_RQ a = t->CreateRequestQueue(s1, 1, 1, 1, 1, cq, cq, NULL);
    CHECK(t->CreateRequestQueue(s2, 1, 1, 1, 1, cq, cq, NULL) != NULL);
    WSASetLastError(0); CHECK(!t->ResizeRequestQueue(a, 2, 2)); EXPECT_EQ(WSAGetLastError(), WSAENOBUFS);   /* cq is full */
    CHECK(t->ResizeCompletionQueue(cq, 6));
    CHECK(t->ResizeRequestQueue(a, 2, 2));                       /* now 2+2 for a, 1+1 for b = 6 */
    CHECK(t->ResizeRequestQueue(a, 0, 1));
    CHECK(t->ResizeRequestQueue(a, 1, 0));
    CHECK(t->ResizeCompletionQueue(cq, 3));                      /* 1 + 2 reserved */
    closesocket(s1); closesocket(s2); t->CloseCompletionQueue(cq);
}
TEST(rio_rq_resize_below_outstanding_is_etoomanyrefs)
{
    NEED_PAIR(p, t, 2);
    RIO_BUF b = {p.id, PR_RECV, 16};
    CHECK(t->Receive(p.rb, &b, 1, 0, RQC(1))); CHECK(t->Receive(p.rb, &b, 1, 0, RQC(2)));
    WSASetLastError(0);
    CHECK(!t->ResizeRequestQueue(p.rb, 1, 2)); EXPECT_EQ(WSAGetLastError(), WSAETOOMANYREFS);
    CHECK(t->ResizeRequestQueue(p.rb, 2, 2));
    CHECK(t->ResizeRequestQueue(p.rb, 3, 2));
    pair_close(&p);
}
