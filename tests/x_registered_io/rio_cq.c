/* Completion queues: RIOCreateCompletionQueue, RIOResizeCompletionQueue, RIOCloseCompletionQueue,
 * RIODequeueCompletion on idle queues, and the notification descriptor checks.
 *
 * Measured on Windows 10. Creation returns NULL (RIO_INVALID_CQ) and sets: WSAEINVAL for size 0 or a size at or
 * above 0x7fffffff, an unknown notification type, or an IOCP descriptor without an OVERLAPPED; WSAEFAULT for an
 * event descriptor without a usable event handle and an IOCP descriptor without a port handle. A NULL
 * notification pointer makes a polling queue. RIODequeueCompletion on an empty queue (or with an array size of
 * zero) returns 0, and 0 for a NULL queue. RIONotify returns its error code directly (0 on success): WSAEINVAL
 * for a NULL or polling queue, WSAEALREADY when the queue is already armed. RIOResizeCompletionQueue returns
 * FALSE with WSAEINVAL for NULL and for sizes 0 / 0x7fffffff. */
#include "rio.h"

TEST(rio_cq_size_matrix)
{
    NEED_RIO(t);
    static const struct { DWORD sz; int err; } m[] = {
        {0, WSAEINVAL}, {1, 0}, {2, 0}, {3, 0}, {16, 0}, {1000, 0}, {0x10000, 0}, {0x100000, 0},
        {0x7fffffff, WSAEINVAL}, {0x80000000, WSAEINVAL}, {0xffffffff, WSAEINVAL},
    };
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIO_CQ q;
        WSASetLastError(0);
        q = t->CreateCompletionQueue(m[i].sz, NULL);
        if (m[i].err) { CHECKF(q == NULL, "size 0x%lx", m[i].sz); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else { CHECKF(q != NULL, "size 0x%lx", m[i].sz); if (q) t->CloseCompletionQueue(q); }
    }
}
TEST(rio_cq_event_descriptor_matrix)
{
    NEED_RIO(t);
    HANDLE ev = CreateEventA(NULL, 0, 0, NULL), cp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    HANDLE dead = CreateEventA(NULL, 0, 0, NULL);   /* closed at once: a handle value that names nothing */
    static const struct { const char *n; int which; BOOL reset; int err; } m[] = {
        {"valid event", 0, FALSE, 0}, {"valid event, NotifyReset", 0, TRUE, 0}, {"valid event, NotifyReset=2", 0, 2, 0},
        {"NULL event handle", 1, FALSE, WSAEFAULT}, {"INVALID_HANDLE_VALUE", 2, FALSE, WSAEFAULT},
        {"closed handle", 3, FALSE, WSAEFAULT}, {"completion port as event", 4, FALSE, WSAEFAULT},
    };
    CloseHandle(dead);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIO_NOTIF n; RIO_CQ q;
        HANDLE h = m[i].which == 0 ? ev : m[i].which == 1 ? NULL : m[i].which == 2 ? INVALID_HANDLE_VALUE : m[i].which == 3 ? dead : cp;
        memset(&n, 0, sizeof n); n.Type = RIO_EVENT_COMPLETION; n.u.Event.EventHandle = h; n.u.Event.NotifyReset = m[i].reset;
        WSASetLastError(0);
        q = t->CreateCompletionQueue(4, &n);
        if (m[i].err) { CHECKF(q == NULL, "%s", m[i].n); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else { CHECKF(q != NULL, "%s", m[i].n); if (q) t->CloseCompletionQueue(q); }
    }
    CloseHandle(ev); CloseHandle(cp);
}
TEST(rio_cq_iocp_descriptor_matrix)
{
    NEED_RIO(t);
    HANDLE cp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); OVERLAPPED ov;
    static const struct { const char *n; int h, ovp; int err; } m[] = {
        {"valid", 1, 1, 0}, {"NULL overlapped", 1, 0, WSAEINVAL}, {"NULL port handle", 0, 1, WSAEFAULT},
    };
    memset(&ov, 0, sizeof ov);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIO_NOTIF n; RIO_CQ q;
        memset(&n, 0, sizeof n); n.Type = RIO_IOCP_COMPLETION;
        n.u.Iocp.IocpHandle = m[i].h ? cp : NULL; n.u.Iocp.CompletionKey = (PVOID)1; n.u.Iocp.Overlapped = m[i].ovp ? &ov : NULL;
        WSASetLastError(0);
        q = t->CreateCompletionQueue(4, &n);
        if (m[i].err) { CHECKF(q == NULL, "%s", m[i].n); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else { CHECKF(q != NULL, "%s", m[i].n); if (q) t->CloseCompletionQueue(q); }
    }
    CloseHandle(cp);
}
TEST(rio_cq_unknown_notification_type_is_einval)
{
    NEED_RIO(t);
    HANDLE ev = CreateEventA(NULL, 0, 0, NULL);
    static const int types[] = {0, 3, 4, 0x100, -1};
    for (unsigned i = 0; i < sizeof types / sizeof *types; i++) {
        RIO_NOTIF n; RIO_CQ q;
        memset(&n, 0, sizeof n); n.Type = types[i]; n.u.Event.EventHandle = ev;
        WSASetLastError(0);
        q = t->CreateCompletionQueue(4, &n);
        CHECKF(q == NULL, "type %d", types[i]); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
        if (q) t->CloseCompletionQueue(q);
    }
    CloseHandle(ev);
}
TEST(rio_cq_failure_leaves_no_queue_behind)
{
    NEED_RIO(t);
    /* Failed creations must not consume anything: a long run of them followed by a good one still works. */
    for (int i = 0; i < 100; i++) { RIO_CQ q = t->CreateCompletionQueue(0, NULL); CHECK(q == NULL); }
    { RIO_CQ q = t->CreateCompletionQueue(1, NULL); CHECK(q != NULL); if (q) t->CloseCompletionQueue(q); }
}
TEST(rio_cq_many_queues_coexist)
{
    NEED_RIO(t);
    RIO_CQ q[64]; int n;
    for (n = 0; n < 64; n++) { q[n] = t->CreateCompletionQueue(2, NULL); if (!q[n]) break; }
    EXPECT_EQ(n, 64);
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++) if (q[i] == q[j]) CHECK(q[i] != q[j]);
    for (int i = 0; i < n; i++) t->CloseCompletionQueue(q[i]);
}
TEST(rio_cq_create_close_cycle)
{
    NEED_RIO(t);
    for (int i = 0; i < 200; i++) {
        RIO_CQ q = t->CreateCompletionQueue(8, NULL);
        if (!q) { CHECK(q != NULL); break; }
        t->CloseCompletionQueue(q);
    }
}
TEST(rio_cq_success_leaves_error_state_alone)
{
    NEED_RIO(t);
    RIO_CQ q; WSASetLastError(0x1234);
    q = t->CreateCompletionQueue(4, NULL);
    CHECK(q != NULL); EXPECT_EQ(WSAGetLastError(), 0x1234);
    t->CloseCompletionQueue(q);
}

TEST(rio_cq_dequeue_empty_returns_zero)
{
    NEED_RIO(t);
    RIO_CQ q = t->CreateCompletionQueue(4, NULL); RIORES r[4]; memset(r, 0xCD, sizeof r);
    EXPECT_EQ(t->DequeueCompletion(q, r, 4), 0);
    EXPECT_EQ(t->DequeueCompletion(q, r, 1), 0);
    EXPECT_EQ(t->DequeueCompletion(q, r, 0), 0);
    EXPECT_EQ(t->DequeueCompletion(q, NULL, 0), 0);
    EXPECT_EQ((ULONG)r[0].Status, 0xCDCDCDCD);   /* nothing written */
    t->CloseCompletionQueue(q);
}
TEST(rio_cq_dequeue_null_queue_returns_zero)
{
    NEED_RIO(t);
    RIORES r[2];
    EXPECT_EQ(t->DequeueCompletion(NULL, r, 2), 0);
    EXPECT_EQ(t->DequeueCompletion(NULL, r, 0), 0);
}
TEST(rio_cq_notify_on_polling_queue_is_einval)
{
    NEED_RIO(t);
    RIO_CQ q = t->CreateCompletionQueue(4, NULL);
    EXPECT_EQ(t->Notify(q), WSAEINVAL);
    EXPECT_EQ(t->Notify(q), WSAEINVAL);
    t->CloseCompletionQueue(q);
}
TEST(rio_cq_notify_null_queue_is_einval)
{
    NEED_RIO(t);
    EXPECT_EQ(t->Notify(NULL), WSAEINVAL);
}
TEST(rio_cq_notify_twice_is_ealready)
{
    NEED_RIO(t);
    HANDLE ev = CreateEventA(NULL, 0, 0, NULL); RIO_NOTIF n; RIO_CQ q; RIORES r[2];
    memset(&n, 0, sizeof n); n.Type = RIO_EVENT_COMPLETION; n.u.Event.EventHandle = ev;
    q = t->CreateCompletionQueue(4, &n);
    EXPECT_EQ(t->Notify(q), 0);
    EXPECT_EQ(t->Notify(q), WSAEALREADY);
    EXPECT_EQ(t->Notify(q), WSAEALREADY);
    EXPECT_EQ(t->DequeueCompletion(q, r, 2), 0);   /* dequeuing an empty queue does not disarm it */
    EXPECT_EQ(t->Notify(q), WSAEALREADY);
    t->CloseCompletionQueue(q); CloseHandle(ev);
}
TEST(rio_cq_notify_on_iocp_queue_arms_without_packet)
{
    NEED_RIO(t);
    HANDLE cp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); OVERLAPPED ov, *po = NULL; RIO_NOTIF n; RIO_CQ q;
    DWORD nb; ULONG_PTR key;
    memset(&ov, 0, sizeof ov); memset(&n, 0, sizeof n);
    n.Type = RIO_IOCP_COMPLETION; n.u.Iocp.IocpHandle = cp; n.u.Iocp.CompletionKey = (PVOID)7; n.u.Iocp.Overlapped = &ov;
    q = t->CreateCompletionQueue(4, &n);
    EXPECT_EQ(t->Notify(q), 0);
    EXPECT_EQ(t->Notify(q), WSAEALREADY);
    CHECK(!GetQueuedCompletionStatus(cp, &nb, &key, &po, 200));   /* nothing completed, so no packet */
    EXPECT_EQ(GetLastError(), WAIT_TIMEOUT);
    t->CloseCompletionQueue(q); CloseHandle(cp);
}

TEST(rio_cq_resize_matrix_on_idle_queue)
{
    NEED_RIO(t);
    static const struct { DWORD sz; int err; } m[] = {
        {0, WSAEINVAL}, {1, 0}, {4, 0}, {2, 0}, {8, 0}, {64, 0}, {1000, 0}, {1, 0}, {0x7fffffff, WSAEINVAL}, {0xffffffff, WSAEINVAL},
    };
    RIO_CQ q = t->CreateCompletionQueue(4, NULL);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        BOOL r;
        WSASetLastError(0);
        r = t->ResizeCompletionQueue(q, m[i].sz);
        if (m[i].err) { CHECKF(!r, "size 0x%lx", m[i].sz); EXPECT_EQ(WSAGetLastError(), m[i].err); }
        else CHECKF(r, "size 0x%lx err %d", m[i].sz, WSAGetLastError());
    }
    t->CloseCompletionQueue(q);
}
TEST(rio_cq_resize_null_queue_is_einval)
{
    NEED_RIO(t);
    WSASetLastError(0);
    CHECK(!t->ResizeCompletionQueue(NULL, 4)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
}
TEST(rio_cq_close_null_queue_is_harmless)
{
    NEED_RIO(t);
    t->CloseCompletionQueue(NULL);
    CHECK(1);
}
TEST(rio_cq_close_with_unread_completions)
{
    RIORES rr[2];
    NEED_PAIR(p, t, 2);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    memcpy(p.mem, "abc", 3);
    CHECK(pair_send(&p, PR_SEND, 3, RQV(2), 0));
    Sleep(100);
    /* leave both completions unread and tear the fixture down: must not hang or crash */
    pair_close(&p);
    (void)rr;
}
